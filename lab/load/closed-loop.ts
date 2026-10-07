/**
 * Closed-loop HTTP load engine for the BA0 field levels. SEPARATE from the open-loop Field Lab engine (`engine.ts`), which is untouched and
 * keeps its rate-with-a-concurrency-cap semantics: this engine's unit of load is the WORKER.
 *
 *   N workers means at most N logical requests in flight. A worker sends its next request only after the previous one SETTLED (a response, a
 *   timeout, a reset). There are no automatic retries, no pipelining, and no request ever starts while its predecessor on the same worker is
 *   unsettled. `inFlight` and `maxInFlightObserved` are exact counters of the engine's own logical requests; connection reuse is counted
 *   separately (new versus reused sockets) and never changes logical concurrency.
 *
 * Transport failures STOP the generator (a timeout, a reset, a refusal, a DNS or TLS error): the run ends with the reason recorded and no further
 * request is sent. A response status NEVER decides anything here: a 4xx or 5xx (a deliberate defense shed included) is an HTTP observation,
 * counted and reported, never a failure of the generator and never proof of what the server did.
 *
 * Like the open-loop engine it can only send what `authorizeRun` produced (branded `AuthorizedRequest`s), re-checks the target authorization
 * before every request, never follows a redirect, caps response bytes, and enforces a strict dispatch deadline plus a bounded drain, a per-run
 * request ceiling and a pacing ceiling. Ceilings are per process, not campaign-wide.
 */
import http from "node:http";
import https from "node:https";
import { LagMonitor } from "../../defense/core/telemetry";
import { HARD_CEILINGS } from "../policy/workloads";
import { isAuthorizedRequest, type AuthorizedRequest, type AuthorizedRun, type TargetMethod } from "../policy/target-policy";
import { summarizeLatencies, type LatencySummary } from "../policy/thresholds";
import { syntheticSubmissionBody, type Outcome } from "./engine";
import { BA0_FIELD_C2_V1 } from "../defense/field-thresholds";
import { n2ExerciseSpec, OverlapMeter, type GeneratorN2Measurement } from "../defense/n2-measurement";

export const CLOSED_LOOP_SETUP_ALLOWANCE_MS = 2_000;
export const CLOSED_LOOP_DRAIN_GRACE_MS = 2_000;

/** Outcomes that mean the TRANSPORT failed (nothing, or nothing usable, came back). A status code is never one of them. */
export const TRANSPORT_FAILURES: ReadonlySet<Outcome> = new Set<Outcome>(["timeout", "conn_refused", "conn_reset", "dns", "tls", "body_too_large", "aborted", "other_error"]);

export type ClosedLoopSend = {
  outcome: Outcome;
  status: number | null;
  latencyMs: number;
  bodyBytesReceived: number;
  wireBytesSent: number;
  wireBytesReceived: number;
  /** true when the request reused a connection, false when it opened one; null when no socket was ever assigned. */
  reusedSocket: boolean | null;
};

export type ClosedLoopSendOptions = { timeoutMs: number; body?: string; agent: http.Agent; signal?: AbortSignal };

function classifyError(error: NodeJS.ErrnoException): Outcome {
  switch (error.code) {
    case "ECONNREFUSED": return "conn_refused";
    case "ECONNRESET": case "EPIPE": case "ECONNABORTED": return "conn_reset";
    case "ENOTFOUND": case "EAI_AGAIN": return "dns";
    case "ERR_TLS_CERT_ALTNAME_INVALID": case "CERT_HAS_EXPIRED": case "DEPTH_ZERO_SELF_SIGNED_CERT": case "UNABLE_TO_VERIFY_LEAF_SIGNATURE": return "tls";
    case "ETIMEDOUT": return "timeout";
    default: return "other_error";
  }
}

/** The one place a socket is opened. Throws if the request was not issued by the policy. Never retries. */
export function sendClosedLoop(request: AuthorizedRequest, run: AuthorizedRun, options: ClosedLoopSendOptions): Promise<ClosedLoopSend> {
  if (!isAuthorizedRequest(request)) throw new Error("refusing to send a request the policy did not authorize");
  run.assertStillAuthorized();
  if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > HARD_CEILINGS.maxRequestTimeoutMs) throw new Error("timeout outside the hard ceiling");
  const started = performance.now();
  const transport = request.scheme === "https" ? https : http;
  const headers: Record<string, string> = { "user-agent": "limitmark-lab/1", accept: "text/html,application/json;q=0.9,*/*;q=0.1", "accept-encoding": "identity" };
  const body = request.method === "POST" ? options.body ?? "" : undefined;
  if (body !== undefined) {
    headers["content-type"] = "application/x-www-form-urlencoded";
    headers["content-length"] = String(Buffer.byteLength(body));
    // The demo handler requires an Origin equal to the (configured) demo origin.
    headers.origin = `${request.scheme}://${request.host}:${request.port}`;
  }
  return new Promise((resolve) => {
    let settled = false;
    let reused: boolean | null = null;
    let wireStartWritten = 0;
    let wireStartRead = 0;
    let socketRef: import("node:net").Socket | null = null;
    let bodyBytes = 0;
    const finish = (outcome: Outcome, status: number | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      resolve({
        outcome, status, latencyMs: performance.now() - started, bodyBytesReceived: bodyBytes, reusedSocket: reused,
        wireBytesSent: socketRef ? Math.max(0, socketRef.bytesWritten - wireStartWritten) : 0, wireBytesReceived: socketRef ? Math.max(0, socketRef.bytesRead - wireStartRead) : 0,
      });
    };
    const req = transport.request({
      method: request.method, hostname: request.host.replace(/^\[|\]$/g, ""), port: request.port, path: request.path, headers, agent: options.agent,
    }, (response) => {
      const status = response.statusCode ?? 0;
      response.on("data", (chunk: Buffer) => {
        bodyBytes += chunk.length;
        if (bodyBytes > HARD_CEILINGS.maxResponseBytes) { req.destroy(); finish("body_too_large", status); }
      });
      response.on("end", () => {
        if (status >= 300 && status < 400) {
          const location = response.headers.location;
          const allowed = typeof location === "string" && run.wouldAuthorizeUrl(location, request.method as TargetMethod);
          finish(allowed ? "redirect" : "redirect_refused", status);
        } else finish(status >= 500 ? "http_5xx" : status >= 400 ? "http_4xx" : "ok", status);
      });
      response.on("error", (error: NodeJS.ErrnoException) => finish(classifyError(error), status));
      response.on("aborted", () => finish("conn_reset", status));
    });
    req.on("socket", (socket) => {
      socketRef = socket;
      reused = req.reusedSocket;
      wireStartWritten = socket.bytesWritten;
      wireStartRead = socket.bytesRead;
    });
    const timer = setTimeout(() => { req.destroy(); finish("timeout", null); }, options.timeoutMs);
    const onAbort = () => { req.destroy(); finish("aborted", null); };
    if (options.signal?.aborted) onAbort(); else options.signal?.addEventListener("abort", onAbort, { once: true });
    req.on("error", (error: NodeJS.ErrnoException) => finish(classifyError(error), null));
    if (body !== undefined) req.write(body);
    req.end();
  });
}

export type ClosedLoopStopKind = "completed" | "deadline" | "total_ceiling" | "transport_failure" | "authorization_expired" | "operator_abort" | "in_flight_exceeded";

export type ClosedLoopResult = {
  workers: number;
  attempted: number;
  responses: number;
  transportFailures: number;
  outcomes: Record<string, number>;
  statuses: Record<string, number>;
  perFixture: Record<string, { attempted: number; responses: number; transportFailures: number }>;
  latencyMs: LatencySummary;
  wireBytesSent: number;
  wireBytesReceived: number;
  bodyBytesReceived: number;
  concurrency: { planned: number; inFlightNow: number; maxInFlightObserved: number };
  connections: { new: number; reused: number };
  schedule: { paced: number; lagMs: LatencySummary };
  generatorHealth: { eldP50Ms: number; eldP99Ms: number; eldMaxMs: number; cpuUserMs: number; cpuSystemMs: number; rssMb: number };
  startedAt: string;
  endedAt: string;
  wallClockSeconds: number;
  stop: { kind: ClosedLoopStopKind; detail: string | null };
  /** Constants of this engine, recorded so the report states them rather than implying them. */
  retries: 0;
  pipelining: false;
  n2?: GeneratorN2Measurement;
};

export type ClosedLoopOptions = {
  run: AuthorizedRun;
  /** Operator abort (SIGINT): ends the run with `operator_abort`. */
  signal?: AbortSignal;
  /** Test seam; defaults to the real sender. */
  send?: typeof sendClosedLoop;
  /** The generator stops on the first transport failure (always true for the first field level, N = 1). */
  stopOnTransportFailure?: boolean;
};

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const roundMs = (value: number): number => Math.round(value * 100) / 100;

export async function executeClosedLoop(options: ClosedLoopOptions): Promise<ClosedLoopResult> {
  const { run } = options;
  const send = options.send ?? sendClosedLoop;
  const stopOnTransport = options.stopOnTransportFailure ?? true;
  if (run.workload.engine !== "http-closed-loop" || run.workload.fixtures === undefined) throw new Error("not a closed-loop workload");
  const phase = run.limits.phases[0];
  const workers = phase.concurrency;
  const intervalMs = 1000 / phase.ratePerSecond;
  const fixtures = run.workload.fixtures.map((fixture) => ({ id: fixture.id, request: run.authorizeRequest(fixture.method, fixture.path) }));

  let stop: { kind: ClosedLoopStopKind; detail: string | null } = { kind: "completed", detail: null };
  const stopWith = (kind: ClosedLoopStopKind, detail: string | null): void => { if (stop.kind === "completed") stop = { kind, detail }; };
  const wallStart = performance.now();
  const overlap = run.workload.id === "ba0-l7-pressure-c2" ? new OverlapMeter(n2ExerciseSpec(BA0_FIELD_C2_V1)) : undefined;
  let firstDispatchMs: number | null = null; let lastDispatchMs: number | null = null; let lastSettlementMs: number | null = null;
  const phaseEnd = wallStart + phase.durationSeconds * 1000;
  const startedAt = new Date();
  const dispatchDeadline = wallStart + run.limits.maxDurationSeconds * 1000 + CLOSED_LOOP_SETUP_ALLOWANCE_MS;
  const hardStop = new AbortController();
  const hardStopTimer = setTimeout(() => {
    if (overlap) stopWith("deadline", null);
    hardStop.abort();
  }, run.limits.maxDurationSeconds * 1000 + CLOSED_LOOP_SETUP_ALLOWANCE_MS + CLOSED_LOOP_DRAIN_GRACE_MS);
  const onCallerAbort = () => { if (stop.kind === "completed") stop = { kind: "operator_abort", detail: null }; hardStop.abort(); };
  if (options.signal?.aborted) onCallerAbort(); else options.signal?.addEventListener("abort", onCallerAbort, { once: true });

  const agent = new http.Agent({ keepAlive: true, maxSockets: workers, maxTotalSockets: workers, maxFreeSockets: workers, scheduling: "fifo" });
  const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: workers, maxTotalSockets: workers, maxFreeSockets: workers, scheduling: "fifo" });
  const lag = new LagMonitor();
  const cpuStart = process.cpuUsage();

  let attempted = 0; let responses = 0; let transportFailures = 0; let inFlight = 0; let maxInFlight = 0;
  let wireSent = 0; let wireReceived = 0; let bodyReceived = 0; let newSockets = 0; let reusedSockets = 0; let paced = 0;
  const outcomes: Record<string, number> = {};
  const statuses: Record<string, number> = {};
  const perFixture: Record<string, { attempted: number; responses: number; transportFailures: number }> = Object.fromEntries(fixtures.map((fixture) => [fixture.id, { attempted: 0, responses: 0, transportFailures: 0 }]));
  const latencies: number[] = [];
  const lags: number[] = [];
  let cursor = 0;
  let nextSlot = performance.now();

  const stopped = (): boolean => stop.kind !== "completed" || hardStop.signal.aborted;

  async function worker(): Promise<void> {
    while (!stopped()) {
      // Slots share one aggregate schedule. Overdue sleepers can start together; the finite burst is bounded by workers.
      const now = performance.now();
      // The level's duration is the normal end (the run is "completed"); the dispatch deadline is only the backstop against a stuck schedule.
      if (now >= phaseEnd) return;
      if (now >= dispatchDeadline) { stopWith("deadline", null); return; }
      const slot = Math.max(now, nextSlot);
      nextSlot = slot + intervalMs;
      if (slot > now) { paced++; await sleep(slot - now); if (stopped()) return; }
      if (performance.now() >= phaseEnd) return;
      if (performance.now() >= dispatchDeadline) { stopWith("deadline", null); return; }
      if (attempted >= run.limits.maxTotalRequests) { stopWith("total_ceiling", null); return; }
      try { run.assertStillAuthorized(); } catch { stopWith("authorization_expired", null); return; }
      const index = cursor++ % fixtures.length;
      const fixture = fixtures[index];
      attempted++;
      inFlight++;
      if (overlap) {
        const at = performance.now() - wallStart;
        firstDispatchMs ??= at; lastDispatchMs = at;
        overlap.change(at, inFlight, true);
      }
      if (inFlight > maxInFlight) maxInFlight = inFlight;
      lags.push(Math.max(0, performance.now() - slot));
      if (inFlight > workers) stopWith("in_flight_exceeded", `${inFlight} in flight with ${workers} workers`);
      perFixture[fixture.id].attempted++;
      let result: ClosedLoopSend;
      try {
        result = await send(fixture.request, run, {
          timeoutMs: phase.timeoutMs, body: fixture.request.method === "POST" ? syntheticSubmissionBody() : undefined,
          agent: fixture.request.scheme === "https" ? (httpsAgent as unknown as http.Agent) : agent, signal: hardStop.signal,
        });
      } catch (error) {
        // The sender refuses (an unauthorized request or an expired authorization) before opening a socket: nothing was attempted on the wire.
        inFlight--;
        if (overlap) { lastSettlementMs = performance.now() - wallStart; overlap.change(lastSettlementMs, inFlight); }
        attempted--;
        perFixture[fixture.id].attempted--;
        stopWith("authorization_expired", error instanceof Error ? error.name : "error");
        return;
      }
      inFlight--;
      if (overlap) { lastSettlementMs = performance.now() - wallStart; overlap.change(lastSettlementMs, inFlight); }
      latencies.push(result.latencyMs);
      wireSent += result.wireBytesSent; wireReceived += result.wireBytesReceived; bodyReceived += result.bodyBytesReceived;
      if (result.reusedSocket === true) reusedSockets++; else if (result.reusedSocket === false) newSockets++;
      outcomes[result.outcome] = (outcomes[result.outcome] ?? 0) + 1;
      if (result.status !== null) { statuses[String(result.status)] = (statuses[String(result.status)] ?? 0) + 1; responses++; perFixture[fixture.id].responses++; }
      if (TRANSPORT_FAILURES.has(result.outcome)) {
        transportFailures++;
        perFixture[fixture.id].transportFailures++;
        if (hardStop.signal.aborted && stop.kind === "operator_abort") return;
        if (stopOnTransport) { stopWith("transport_failure", result.outcome); return; }
      }
    }
  }

  try {
    await Promise.all(Array.from({ length: workers }, () => worker()));
  } finally {
    clearTimeout(hardStopTimer);
    options.signal?.removeEventListener("abort", onCallerAbort);
    agent.destroy();
    httpsAgent.destroy();
  }
  const loopLag = lag.take();
  lag.stop();
  const cpu = process.cpuUsage(cpuStart);
  const round = (value: number) => Math.round(value * 100) / 100;
  return {
    workers, attempted, responses, transportFailures, outcomes, statuses, perFixture, latencyMs: summarizeLatencies(latencies),
    wireBytesSent: wireSent, wireBytesReceived: wireReceived, bodyBytesReceived: bodyReceived,
    concurrency: { planned: workers, inFlightNow: inFlight, maxInFlightObserved: maxInFlight },
    connections: { new: newSockets, reused: reusedSockets },
    schedule: { paced, lagMs: summarizeLatencies(lags) },
    generatorHealth: { eldP50Ms: roundMs(loopLag.p50), eldP99Ms: roundMs(loopLag.p99), eldMaxMs: roundMs(loopLag.max), cpuUserMs: Math.round(cpu.user / 1000), cpuSystemMs: Math.round(cpu.system / 1000), rssMb: Math.round(process.memoryUsage.rss() / 1_048_576) },
    startedAt: startedAt.toISOString(), endedAt: new Date().toISOString(), wallClockSeconds: round((performance.now() - wallStart) / 1000),
    stop, retries: 0, pipelining: false,
    ...(overlap ? { n2: { elapsedMs: performance.now() - wallStart, firstDispatchMs, lastDispatchMs, lastSettlementMs, exposure: overlap.snapshot() } } : {}),
  };
}
