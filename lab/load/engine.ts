/**
 * Bounded HTTP load engine. It can only send what `authorizeRun` produced:
 * `AuthorizedRequest` objects are branded and tracked in a WeakSet, so this module cannot
 * be handed an arbitrary URL. Redirects are never followed. Bodies are streamed and
 * discarded (counted, capped), never stored.
 *
 * Bounds enforced here in addition to the policy: per-phase rate (token bucket, burst of 1
 * interval), per-phase in-flight cap (excess scheduled sends are DROPPED and counted, never
 * queued), a global request cap, a global wall-clock deadline, a per-request timeout and a
 * response-size cap.
 */
import http from "node:http";
import https from "node:https";
import { randomBytes } from "node:crypto";
import { HARD_CEILINGS, type PhaseSpec } from "../policy/workloads";
import {
  isAuthorizedRequest, type AuthorizedRequest, type AuthorizedRun, type TargetMethod,
} from "../policy/target-policy";
import {
  evaluateStop, ruleFor, summarizeLatencies,
  type HttpThresholds, type PhaseStats, type StopState,
} from "../policy/thresholds";

export type Outcome =
  | "ok" | "http_4xx" | "http_5xx" | "redirect" | "redirect_refused"
  | "timeout" | "conn_refused" | "conn_reset" | "dns" | "tls" | "body_too_large" | "other_error";

export type RequestResult = { outcome: Outcome; status: number | null; latencyMs: number; bytes: number };

export type SendOptions = { timeoutMs: number; body?: string; agent: http.Agent };

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

/** The one place a socket is opened. Throws if the request was not issued by the policy. */
export function sendAuthorized(
  request: AuthorizedRequest,
  run: AuthorizedRun,
  options: SendOptions,
): Promise<RequestResult> {
  if (!isAuthorizedRequest(request)) throw new Error("refusing to send a request the policy did not authorize");
  if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > HARD_CEILINGS.maxRequestTimeoutMs) {
    throw new Error("timeout outside the hard ceiling");
  }
  const started = performance.now();
  const transport = request.scheme === "https" ? https : http;
  const headers: Record<string, string> = {
    "user-agent": "limitmark-lab/1",
    accept: "text/html,application/json;q=0.9,*/*;q=0.1",
    "accept-encoding": "identity",
  };
  const body = request.method === "POST" ? options.body ?? "" : undefined;
  if (body !== undefined) {
    headers["content-type"] = "application/x-www-form-urlencoded";
    headers["content-length"] = String(Buffer.byteLength(body));
    // The demo handler requires an Origin equal to the (configured) demo origin.
    headers.origin = `${request.scheme}://${request.host}:${request.port}`;
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = (outcome: Outcome, status: number | null, bytes: number) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ outcome, status, latencyMs: performance.now() - started, bytes });
    };
    const req = transport.request({
      method: request.method,
      hostname: request.host.replace(/^\[|\]$/g, ""),
      port: request.port,
      path: request.path,
      headers,
      agent: options.agent,
    }, (response) => {
      const status = response.statusCode ?? 0;
      let bytes = 0;
      response.on("data", (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > HARD_CEILINGS.maxResponseBytes) { req.destroy(); finish("body_too_large", status, bytes); }
      });
      response.on("end", () => {
        if (status >= 300 && status < 400) {
          const location = response.headers.location;
          const allowed = typeof location === "string" && run.wouldAuthorizeUrl(location, request.method as TargetMethod);
          finish(allowed ? "redirect" : "redirect_refused", status, bytes);
        } else {
          finish(status >= 500 ? "http_5xx" : status >= 400 ? "http_4xx" : "ok", status, bytes);
        }
      });
      response.on("error", (error: NodeJS.ErrnoException) => finish(classifyError(error), status, bytes));
      response.on("aborted", () => finish("conn_reset", status, bytes));
    });
    const timer = setTimeout(() => { req.destroy(); finish("timeout", null, 0); }, options.timeoutMs);
    req.on("error", (error: NodeJS.ErrnoException) => finish(classifyError(error), null, 0));
    if (body !== undefined) req.write(body);
    req.end();
  });
}

const FAILURE_OUTCOMES = new Set<Outcome>(["http_5xx", "http_4xx", "redirect_refused", "timeout", "conn_refused", "conn_reset", "dns", "tls", "body_too_large", "other_error"]);
export function isFailure(outcome: Outcome): boolean { return FAILURE_OUTCOMES.has(outcome); }

/** Synthetic form body for the demo-submission workload. Contains no real data. */
export function syntheticSubmissionBody(): string {
  const token = randomBytes(32).toString("base64url");
  const fields: Record<string, string> = {
    name: "Lab Synthetic", email: "lab@example.test", company: "Synthetic Co", service: "web",
    system: "synthetic lab system", objective: "synthetic lab objective", environment: "staging",
    authority: "authorized", protection: "unknown", provider: "", notes: "",
    submissionToken: token,
  };
  return new URLSearchParams(fields).toString();
}

export type RunProgress = { phase: string; attempted: number; failed: number };

export type EngineResult = {
  phases: PhaseStats[];
  stopReason: string | null;
  aborted: boolean;
  totalAttempted: number;
  wallClockSeconds: number;
};

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export type EngineOptions = {
  run: AuthorizedRun;
  thresholds: HttpThresholds;
  /** Test seam; defaults to the real sender. */
  send?: typeof sendAuthorized;
  onProgress?: (progress: RunProgress) => void;
  signal?: AbortSignal;
  /** Failure workloads: invoked at the start of each phase (e.g. to kill or start a lab-managed process). */
  onPhaseStart?: (phase: PhaseSpec) => Promise<void> | void;
  /** Failure workloads: observe each result with its offset from the start of the run. */
  onResult?: (phase: string, result: RequestResult, atMs: number) => void;
  /** Failure workloads: end a phase early (never extends it). */
  shouldEndPhase?: (phase: string) => boolean;
};

export async function executeHttpWorkload(options: EngineOptions): Promise<EngineResult> {
  const { run, thresholds } = options;
  const send = options.send ?? sendAuthorized;
  const { limits } = run;
  const requests: { request: AuthorizedRequest; body?: string }[] = [];
  for (const method of run.workload.methods) for (const path of run.workload.paths) requests.push({ request: run.authorizeRequest(method, path) });

  const deadline = performance.now() + limits.maxDurationSeconds * 1000 + 2_000;
  const state: StopState = { measured: 0, failed: 0, consecutiveFailures: 0, latenciesMs: [] };
  const phases: PhaseStats[] = [];
  let totalAttempted = 0;
  let stopReason: string | null = null;
  let cursor = 0;
  const wallStart = performance.now();

  for (const phase of limits.phases) {
    if (stopReason || options.signal?.aborted) break;
    await options.onPhaseStart?.(phase);
    const rule = ruleFor(thresholds, phase.name);
    const agent = new http.Agent({ keepAlive: true, maxSockets: phase.concurrency, maxFreeSockets: phase.concurrency });
    const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: phase.concurrency, maxFreeSockets: phase.concurrency });
    const latencies: number[] = [];
    const outcomes: Record<string, number> = {};
    const statuses: Record<string, number> = {};
    let attempted = 0, succeeded = 0, failed = 0, dropped = 0, bytes = 0, inFlight = 0;
    const pending = new Set<Promise<void>>();
    const startedAt = new Date();
    const phaseEnd = performance.now() + phase.durationSeconds * 1000;
    const intervalMs = 1000 / phase.ratePerSecond;
    let nextSend = performance.now();

    while (performance.now() < phaseEnd && !stopReason && !options.signal?.aborted && !options.shouldEndPhase?.(phase.name)) {
      const now = performance.now();
      if (now > deadline) { stopReason = "global deadline reached"; break; }
      if (now < nextSend) { await sleep(Math.min(nextSend - now, 5)); continue; }
      nextSend += intervalMs;
      // Never accumulate a backlog: if we fell behind, skip forward.
      if (nextSend < now - intervalMs) nextSend = now + intervalMs;
      if (totalAttempted >= limits.maxTotalRequests) { stopReason = "total request ceiling reached"; break; }
      if (inFlight >= phase.concurrency) { dropped++; continue; }
      const item = requests[cursor++ % requests.length];
      totalAttempted++; attempted++; inFlight++;
      const task = send(item.request, run, {
        timeoutMs: phase.timeoutMs,
        body: item.request.method === "POST" ? syntheticSubmissionBody() : undefined,
        agent: item.request.scheme === "https" ? (httpsAgent as unknown as http.Agent) : agent,
      }).then((result) => {
        inFlight--;
        options.onResult?.(phase.name, result, performance.now() - wallStart);
        latencies.push(result.latencyMs);
        bytes += result.bytes;
        outcomes[result.outcome] = (outcomes[result.outcome] ?? 0) + 1;
        if (result.status !== null) statuses[String(result.status)] = (statuses[String(result.status)] ?? 0) + 1;
        const failure = isFailure(result.outcome);
        if (failure) failed++; else succeeded++;
        if (rule === "measured") {
          state.measured++;
          state.latenciesMs.push(result.latencyMs);
          if (failure) { state.failed++; state.consecutiveFailures++; } else state.consecutiveFailures = 0;
          const reason = evaluateStop(thresholds, state);
          if (reason && !stopReason) stopReason = `STOP threshold: ${reason}`;
        }
        options.onProgress?.({ phase: phase.name, attempted, failed });
      });
      pending.add(task);
      task.finally(() => pending.delete(task));
    }
    // In-flight requests are bounded by their own timeout; wait for them.
    await Promise.all(pending);
    agent.destroy(); httpsAgent.destroy();
    phases.push({
      name: phase.name,
      startedAt: startedAt.toISOString(),
      endedAt: new Date().toISOString(),
      planned: { durationSeconds: phase.durationSeconds, ratePerSecond: phase.ratePerSecond, concurrency: phase.concurrency, timeoutMs: phase.timeoutMs },
      attempted, succeeded, failed, outcomes, statuses,
      droppedByConcurrencyCap: dropped, bytesReceived: bytes,
      latencyMs: summarizeLatencies(latencies),
    });
  }
  return {
    phases, stopReason, aborted: Boolean(options.signal?.aborted),
    totalAttempted, wallClockSeconds: Math.round((performance.now() - wallStart)) / 1000,
  };
}

export type WarmupResult = { path: string; outcome: Outcome; latencyMs: number };

/**
 * Cold-start warm-up for lab-managed local runs: one GET per distinct GET path (at most
 * HARD_CEILINGS.maxWarmupRequests), reported separately so cold-start latency is recorded
 * but does not distort the measured phases.
 */
export async function warmUp(run: AuthorizedRun): Promise<WarmupResult[]> {
  const results: WarmupResult[] = [];
  if (!run.workload.methods.includes("GET")) return results;
  const agent = new http.Agent({ keepAlive: false, maxSockets: 1 });
  try {
    for (const path of run.workload.paths.slice(0, HARD_CEILINGS.maxWarmupRequests)) {
      const result = await sendAuthorized(run.authorizeRequest("GET", path), run, { timeoutMs: HARD_CEILINGS.maxRequestTimeoutMs, agent });
      results.push({ path, outcome: result.outcome, latencyMs: Math.round(result.latencyMs * 100) / 100 });
    }
  } finally { agent.destroy(); }
  return results;
}
