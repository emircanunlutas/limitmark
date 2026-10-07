/** Isolated finite paired scheduler. The historical closed-loop worker scheduler is unchanged. */
import http from "node:http";
import https from "node:https";
import { LagMonitor } from "../../defense/core/telemetry";
import { SALVO_SPEC, pairFixtureLatencies, pairSummaries, type SalvoPair } from "../defense/salvo-spec";
import { syntheticSubmissionBody } from "./engine";
import { sendClosedLoop, TRANSPORT_FAILURES, type ClosedLoopOptions, type ClosedLoopResult, type ClosedLoopStopKind } from "./closed-loop";

export type SalvoClock = { now(): number; wall(): Date; sleep(ms: number, signal: AbortSignal): Promise<void> };
const liveClock: SalvoClock = {
  now: () => performance.now(), wall: () => new Date(),
  sleep: (ms, signal) => new Promise((resolve) => {
    if (signal.aborted) { resolve(); return; }
    const done = () => { clearTimeout(timer); signal.removeEventListener("abort", done); resolve(); };
    const timer = setTimeout(done, ms);
    signal.addEventListener("abort", done, { once: true });
  }),
};

export async function executeSalvo(options: ClosedLoopOptions): Promise<ClosedLoopResult> {
  const { run } = options; const spec = SALVO_SPEC; const clock = options.salvoClock ?? liveClock;
  const send = options.send ?? sendClosedLoop; const phase = run.limits.phases[0];
  if (run.workload.engine !== "http-closed-loop" || run.workload.id !== "ba0-l7-pressure-c2-salvo"
    || phase.durationSeconds !== 60 || phase.ratePerSecond !== 25 || phase.concurrency !== 2 || phase.timeoutMs !== 5000
    || run.limits.maxTotalRequests !== 1500 || run.limits.maxDurationSeconds !== 60
    || run.limits.maxConcurrency !== 2 || run.limits.maxRequestsPerSecond !== 25 || run.workload.fixtures?.length !== 4) throw new Error("salvo requires exact reviewed limits");
  const fixtures = run.workload.fixtures.map((fixture) => ({ ...fixture, request: run.authorizeRequest(fixture.method, fixture.path) }));
  const agent = new http.Agent({ keepAlive: true, maxSockets: 2, maxTotalSockets: 2, maxFreeSockets: 2, scheduling: "fifo" });
  const tlsAgent = new https.Agent({ keepAlive: true, maxSockets: 2, maxTotalSockets: 2, maxFreeSockets: 2, scheduling: "fifo" });
  const origin = clock.now(); const startedAt = clock.wall(); const elapsed = () => clock.now() - origin;
  const abort = new AbortController(); const watchdog = new AbortController();
  let stop: ClosedLoopResult["stop"] = { kind: "completed", detail: null }; let stopLatchedMs: number | null = null;
  const stopWith = (kind: ClosedLoopStopKind, detail: string | null = null) => {
    if (stop.kind === "completed") { stop = { kind, detail }; stopLatchedMs = elapsed(); }
    abort.abort();
  };
  const onAbort = () => stopWith("operator_abort");
  if (options.signal?.aborted) onAbort(); else options.signal?.addEventListener("abort", onAbort, { once: true });
  // Every wake is followed by a monotonic not-before recheck, including full-duration completion and watchdogs.
  async function until(at: number, signal: AbortSignal): Promise<void> {
    while (!signal.aborted && elapsed() < at) await clock.sleep(at - elapsed(), signal);
  }
  const deadline = until(spec.maxElapsedMs, watchdog.signal).then(() => { if (!watchdog.signal.aborted) stopWith("deadline"); });
  const lag = new LagMonitor(); const cpuStart = process.cpuUsage();
  const pairs: SalvoPair[] = [];
  const perFixture = Object.fromEntries(fixtures.map((f) => [f.id, { attempted: 0, responses: 0, transportFailures: 0 }]));
  const outcomes: Record<string, number> = {}; const statuses: Record<string, number> = {};
  let attempted = 0; let responses = 0; let transportFailures = 0; let inFlight = 0; let maxInFlight = 0;
  let newSockets = 0; let reusedSockets = 0; let wireSent = 0; let wireReceived = 0; let contentReceived = 0; let paced = 0;
  let firstDispatchMs: number | null = null; let lastDispatchMs: number | null = null; let lastSettlementMs: number | null = null;

  async function dispatch(pair: SalvoPair, slot: 0 | 1, body: string | undefined): Promise<void> {
    if (abort.signal.aborted) return;
    const fixture = fixtures[(pair.index % 2) * 2 + slot];
    try { run.assertStillAuthorized(); } catch { stopWith("authorization_expired"); return; }
    const planned = pair.index * spec.periodMs; const at = elapsed();
    if (at < planned || at >= planned + spec.dispatchLatenessExclusiveMs || at >= spec.durationMs) { stopWith("schedule_incomplete", "dispatch_lateness"); return; }
    if (attempted >= run.limits.maxTotalRequests) { stopWith("total_ceiling"); return; }
    pair.startsMs[slot] = at; firstDispatchMs ??= at; lastDispatchMs = at;
    attempted++; perFixture[fixture.id].attempted++; inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
    try {
      const result = await send(fixture.request, run, {
        timeoutMs: phase.timeoutMs, body,
        agent: fixture.request.scheme === "https" ? tlsAgent as unknown as http.Agent : agent, signal: abort.signal,
      });
      pair.settledMs[slot] = elapsed(); lastSettlementMs = Math.max(lastSettlementMs ?? 0, pair.settledMs[slot]!);
      wireSent += result.wireBytesSent; wireReceived += result.wireBytesReceived; contentReceived += result.bodyBytesReceived;
      if (result.reusedSocket === true) reusedSockets++; else if (result.reusedSocket === false) newSockets++;
      outcomes[result.outcome] = (outcomes[result.outcome] ?? 0) + 1;
      if (result.status !== null) { responses++; perFixture[fixture.id].responses++; statuses[String(result.status)] = (statuses[String(result.status)] ?? 0) + 1; }
      if (TRANSPORT_FAILURES.has(result.outcome)) { transportFailures++; perFixture[fixture.id].transportFailures++; stopWith("transport_failure", result.outcome); }
    } catch {
      attempted--; perFixture[fixture.id].attempted--; stopWith("authorization_expired");
    } finally { inFlight--; }
  }

  try {
    for (let index = 0; index < spec.pairs && !abort.signal.aborted; index++) {
      paced++; await until(index * spec.periodMs, abort.signal);
      if (abort.signal.aborted) break;
      if (inFlight !== 0) { stopWith("schedule_incomplete", "previous_pair_active"); break; }
      const pair: SalvoPair = { index, startsMs: [null, null], settledMs: [null, null] }; pairs.push(pair);
      const inquiry = index % 2 === 1 ? syntheticSubmissionBody() : undefined;
      // Both functions reach send() before either response is awaited. There is no independent worker pacing timer.
      const a = dispatch(pair, 0, undefined); const b = dispatch(pair, 1, inquiry);
      const pairDone = Promise.all([a, b]);
      if (index + 1 < spec.pairs) {
        const nextRelease = new AbortController();
        const watch = until((index + 1) * spec.periodMs, nextRelease.signal).then(() => {
          if (!nextRelease.signal.aborted && inFlight > 0) stopWith("schedule_incomplete", "previous_pair_active");
        });
        await pairDone;
        // A late watchdog callback may run after a late settlement. Source timestamps still prove the missed release.
        if (lastSettlementMs !== null && lastSettlementMs > (index + 1) * spec.periodMs) stopWith("schedule_incomplete", "previous_pair_active");
        nextRelease.abort(); await watch;
      } else await pairDone;
    }
    if (!abort.signal.aborted) {
      if (pairs.length !== spec.pairs || attempted !== 1500 || inFlight !== 0) stopWith("schedule_incomplete", "schedule_not_exhausted");
      else {
        await until(spec.durationMs, abort.signal);
        // Authorization covers the entire reviewed phase and final drain, including the wait after the last response.
        if (!abort.signal.aborted) {
          try { run.assertStillAuthorized(); } catch { stopWith("authorization_expired"); }
        }
      }
    }
  } finally {
    watchdog.abort(); await deadline;
    options.signal?.removeEventListener("abort", onAbort); agent.destroy(); tlsAgent.destroy();
  }
  const health = lag.take(); lag.stop(); const cpu = process.cpuUsage(cpuStart); const ms = elapsed();
  const summaries = pairSummaries(pairs);
  return {
    workers: 2, attempted, responses, transportFailures, outcomes, statuses, perFixture, latencyMs: summaries.latencyMs,
    wireBytesSent: wireSent, wireBytesReceived: wireReceived, bodyBytesReceived: contentReceived,
    concurrency: { planned: 2, inFlightNow: inFlight, maxInFlightObserved: maxInFlight }, connections: { new: newSockets, reused: reusedSockets },
    schedule: { paced, lagMs: summaries.lagMs },
    generatorHealth: { eldP50Ms: health.p50, eldP99Ms: health.p99, eldMaxMs: health.max, cpuUserMs: Math.round(cpu.user / 1000), cpuSystemMs: Math.round(cpu.system / 1000), rssMb: Math.round(process.memoryUsage.rss() / 1_048_576) },
    startedAt: startedAt.toISOString(), endedAt: clock.wall().toISOString(), wallClockSeconds: Math.round(ms / 10) / 100,
    stop, retries: 0, pipelining: false,
    salvo: { elapsedMs: ms, firstDispatchMs, lastDispatchMs, lastSettlementMs, stopLatchedMs, pairs,
      fixtureLatencyMs: pairFixtureLatencies(pairs) },
  };
}
