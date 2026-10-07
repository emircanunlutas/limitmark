import assert from "node:assert/strict";
import { test } from "node:test";
import { HARD_CEILINGS, WORKLOADS, plannedEnvelope, validateWorkloadCatalogue, type WorkloadSpec } from "../lab/policy/workloads";
import {
  THRESHOLD_SETS, evaluateHttpPass, evaluateStop, selectThresholdSet, thresholdSetFingerprint, summarizeLatencies, type PhaseStats,
} from "../lab/policy/thresholds";
import { evaluateRecovery } from "../lab/failure/recovery";
import { HARNESS_BOUNDS, backendKilledDuringCreates, sameTokenSameFingerprint, outboxCompetingWorkers } from "../lab/concurrency/harness";

// These tables are the REVIEWED numbers. Changing a ceiling is a deliberate code change that must
// update this test in the same diff.
const REVIEWED = {
  "connectivity-baseline": { requestsPerSecond: 2, concurrency: 1, durationSeconds: 30, totalRequests: 60 },
  "latency-measurement": { requestsPerSecond: 5, concurrency: 2, durationSeconds: 60, totalRequests: 300 },
  "controlled-concurrency": { requestsPerSecond: 40, concurrency: 16, durationSeconds: 100, totalRequests: 4000 },
  burst: { requestsPerSecond: 100, concurrency: 50, durationSeconds: 30, totalRequests: 1200 },
  "sustained-soak": { requestsPerSecond: 20, concurrency: 20, durationSeconds: 900, totalRequests: 18000 },
  "timeout-behaviour": { requestsPerSecond: 2, concurrency: 1, durationSeconds: 55, totalRequests: 110 },
  "demo-submission-post": { requestsPerSecond: 5, concurrency: 4, durationSeconds: 30, totalRequests: 150 },
  "app-restart": { requestsPerSecond: 4, concurrency: 1, durationSeconds: 80, totalRequests: 340 },
  "postgres-outage": { requestsPerSecond: 2, concurrency: 1, durationSeconds: 85, totalRequests: 170 },
  // The BA0 first external L7 level (closed loop, N = 1, remote-only). A higher level is a new reviewed entry here, never a flag.
  "ba0-l7-pressure-c1": { requestsPerSecond: 25, concurrency: 1, durationSeconds: 60, totalRequests: 1500 },
  "ba0-l7-pressure-c2": { requestsPerSecond: 25, concurrency: 2, durationSeconds: 60, totalRequests: 1500 },
} as const;

test("the hard ceilings are pinned", () => {
  assert.deepEqual({ ...HARD_CEILINGS }, {
    maxRequestsPerSecond: 100, maxConcurrency: 50, maxDurationSeconds: 900, maxTotalRequests: 20_000, maxRequestTimeoutMs: 10_000, maxResponseBytes: 1_048_576, maxWarmupRequests: 3,
  });
  assert.ok(Object.isFrozen(HARD_CEILINGS));
});

test("every workload has exactly the reviewed finite ceilings, and its phases fit inside them", () => {
  assert.deepEqual(Object.keys(WORKLOADS).sort(), Object.keys(REVIEWED).sort());
  for (const [id, expected] of Object.entries(REVIEWED)) {
    const workload = WORKLOADS[id as keyof typeof WORKLOADS];
    assert.deepEqual({ ...workload.ceilings }, expected, id);
    const planned = plannedEnvelope(workload);
    assert.ok(planned.requestsPerSecond <= expected.requestsPerSecond, `${id} rate`);
    assert.ok(planned.concurrency <= expected.concurrency, `${id} concurrency`);
    assert.ok(planned.durationSeconds <= expected.durationSeconds, `${id} duration`);
    assert.ok(planned.totalRequests <= expected.totalRequests, `${id} total`);
    assert.ok(expected.requestsPerSecond <= HARD_CEILINGS.maxRequestsPerSecond);
    assert.ok(expected.concurrency <= HARD_CEILINGS.maxConcurrency);
    assert.ok(expected.durationSeconds <= HARD_CEILINGS.maxDurationSeconds);
    assert.ok(expected.totalRequests <= HARD_CEILINGS.maxTotalRequests);
  }
  assert.deepEqual(validateWorkloadCatalogue(), []);
  assert.ok(Object.isFrozen(WORKLOADS) && Object.isFrozen(WORKLOADS.burst) && Object.isFrozen(WORKLOADS.burst.phases));
});

test("the catalogue validator catches a workload that exceeds its ceilings or the hard ceilings", () => {
  type Mutable = { phases: Record<string, number>[] | unknown[]; ceilings: Record<string, number>; methods: string[]; paths: string[] };
  const clone = (mutate: (workload: Mutable) => void): Record<string, WorkloadSpec> => {
    const copy = structuredClone(WORKLOADS.burst) as unknown as Mutable;
    mutate(copy);
    return { burst: copy as unknown as WorkloadSpec };
  };
  const phase = (w: Mutable, index: number) => (w.phases as Record<string, number>[])[index];
  assert.ok(validateWorkloadCatalogue(clone((w) => { phase(w, 1).ratePerSecond = 101; })).length > 0);
  assert.ok(validateWorkloadCatalogue(clone((w) => { phase(w, 1).concurrency = 51; })).length > 0);
  assert.ok(validateWorkloadCatalogue(clone((w) => { phase(w, 2).durationSeconds = 600; })).length > 0);
  assert.ok(validateWorkloadCatalogue(clone((w) => { w.ceilings.requestsPerSecond = 1000; })).length > 0);
  assert.ok(validateWorkloadCatalogue(clone((w) => { phase(w, 0).timeoutMs = 60_000; })).length > 0);
  assert.ok(validateWorkloadCatalogue(clone((w) => { phase(w, 0).ratePerSecond = 0; })).length > 0);
  assert.ok(validateWorkloadCatalogue(clone((w) => { w.methods = ["POST"]; w.paths = ["/"]; })).length > 0);
  assert.ok(validateWorkloadCatalogue(clone((w) => { w.phases = []; })).length > 0);
});

test("POST appears only in the demo submission workload and the BA0 closed-loop level, and only on the one reviewed path; failure workloads are local-only", () => {
  for (const workload of Object.values(WORKLOADS)) {
    if (workload.methods.includes("POST")) {
      assert.ok(["demo-submission-post", "ba0-l7-pressure-c1", "ba0-l7-pressure-c2"].includes(workload.id), workload.id);
      if (workload.fixtures === undefined) assert.deepEqual([...workload.paths], ["/api/public-inquiries"]);
      else assert.deepEqual(workload.fixtures.filter((fixture) => fixture.method === "POST").map((fixture) => fixture.path), ["/api/public-inquiries"]);
    }
    for (const path of workload.paths) assert.doesNotMatch(path, /cron|admin|\/v1/);
    if (workload.engine.startsWith("managed")) assert.equal(workload.localOnly, true, workload.id);
  }
});

// -------------------------------------------------------------------- thresholds
function stats(name: string, attempted: number, failed: number, p95: number, p99: number): PhaseStats {
  return {
    name, startedAt: "x", endedAt: "y", planned: { durationSeconds: 1, ratePerSecond: 1, concurrency: 1, timeoutMs: 1 },
    attempted, succeeded: attempted - failed, failed, outcomes: {}, statuses: {}, droppedByConcurrencyCap: 0, bytesReceived: 0,
    latencyMs: { count: attempted, min: 1, mean: 1, p50: 1, p90: 1, p95, p99, max: p99 },
  };
}

test("threshold sets are named, versioned and fingerprinted; any change changes the hash", () => {
  const local = THRESHOLD_SETS["local-loopback-v1"];
  const fingerprint = thresholdSetFingerprint(local);
  assert.deepEqual([fingerprint.id, fingerprint.version], ["local-loopback-v1", 1]);
  assert.match(fingerprint.sha256, /^[0-9a-f]{64}$/);
  assert.equal(thresholdSetFingerprint(local).sha256, fingerprint.sha256);
  const mutated = structuredClone(local);
  mutated.http.burst.pass.maxP99Ms += 1;
  assert.notEqual(thresholdSetFingerprint(mutated).sha256, fingerprint.sha256);
  assert.notEqual(thresholdSetFingerprint(THRESHOLD_SETS["field-remote-v1"]).sha256, fingerprint.sha256);
});

test("a remote target must name its threshold set; unknown sets are refused", () => {
  assert.throws(() => selectThresholdSet(undefined, "lab-remote"), /explicit/);
  assert.equal(selectThresholdSet(undefined, "lab-local").id, "local-loopback-v1");
  assert.equal(selectThresholdSet("field-remote-v1", "lab-remote").id, "field-remote-v1");
  assert.throws(() => selectThresholdSet("nope", "lab-local"), /unknown threshold set/);
  assert.throws(() => selectThresholdSet("__proto__", "lab-local"), /unknown threshold set/);
});

test("PASS evaluation fails on error rate, latency and too few samples; STOP triggers on consecutive failures, error rate and p99", () => {
  const t = THRESHOLD_SETS["local-loopback-v1"].http["latency-measurement"];
  assert.equal(evaluateHttpPass(t, [stats("latency", 100, 0, 10, 20)]).result, "PASS");
  assert.equal(evaluateHttpPass(t, [stats("latency", 100, 5, 10, 20)]).result, "FAIL");
  assert.equal(evaluateHttpPass(t, [stats("latency", 100, 0, t.pass.maxP95Ms + 1, 20)]).result, "FAIL");
  assert.equal(evaluateHttpPass(t, [stats("latency", 100, 0, 10, t.pass.maxP99Ms + 1)]).result, "FAIL");
  assert.equal(evaluateHttpPass(t, [stats("latency", t.pass.minSamples - 1, 0, 1, 1)]).result, "FAIL");
  assert.equal(evaluateStop(t, { measured: 10, failed: 10, consecutiveFailures: t.stop.consecutiveFailures, latenciesMs: [] }) !== null, true);
  assert.equal(evaluateStop(t, { measured: t.stop.afterSamples, failed: t.stop.afterSamples, consecutiveFailures: 0, latenciesMs: [] }) !== null, true);
  assert.equal(evaluateStop(t, { measured: t.stop.afterSamples - 1, failed: t.stop.afterSamples - 1, consecutiveFailures: 1, latenciesMs: [] }), null);
  assert.equal(evaluateStop(t, { measured: t.stop.afterSamples, failed: 0, consecutiveFailures: 0, latenciesMs: Array(t.stop.afterSamples).fill(t.stop.p99Ms + 1) }) !== null, true);
  assert.equal(evaluateStop(t, { measured: t.stop.afterSamples, failed: 0, consecutiveFailures: 0, latenciesMs: Array(t.stop.afterSamples).fill(5) }), null);
});

test("timeout-behaviour tolerates client timeouts but requires a fully healthy probe afterwards", () => {
  const t = THRESHOLD_SETS["local-loopback-v1"].http["timeout-behaviour"];
  const base = [stats("timeout-1ms", 20, 20, 1, 1), stats("timeout-5ms", 20, 15, 5, 5)];
  assert.equal(evaluateHttpPass(t, [...base, stats("health-probe", 5, 0, 3, 3)]).result, "PASS");
  assert.equal(evaluateHttpPass(t, [...base, stats("health-probe", 5, 1, 3, 3)]).result, "FAIL");
  assert.equal(evaluateHttpPass(t, [...base, stats("health-probe", 0, 0, 0, 0)]).result, "FAIL");
});

test("recovery verdicts: bounded failure, real outage, in-time recovery; never-recovered is STOP", () => {
  const set = THRESHOLD_SETS["local-loopback-v1"].recovery["app-restart"];
  const phases = (downFail: number) => [stats("steady-before", 10, 0, 1, 1), stats("down", 20, downFail, 1, 1), stats("steady-after", 10, 0, 1, 1)];
  const observe = (over: Partial<Parameters<typeof evaluateRecovery>[1]>) => evaluateRecovery(set, {
    phases: phases(20), recoverySeconds: 1, maxProbeDurationDownMs: 5, downPhase: "down", recoveryPhase: "recovery", steadyPhases: ["steady-before", "steady-after"], ...over,
  });
  assert.equal(observe({}).result, "PASS");
  assert.equal(observe({ recoverySeconds: set.maxRecoverySeconds + 1 }).result, "FAIL");
  assert.equal(observe({ recoverySeconds: null }).result, "STOP");
  assert.equal(observe({ phases: phases(0) }).result, "FAIL");
  assert.equal(observe({ maxProbeDurationDownMs: set.maxProbeDurationMs + 1 }).result, "FAIL");
  assert.equal(observe({ phases: [stats("steady-before", 10, 2, 1, 1), stats("down", 20, 20, 1, 1), stats("steady-after", 10, 0, 1, 1)] }).result, "FAIL");
});

test("latency summaries use nearest-rank percentiles", () => {
  const s = summarizeLatencies(Array.from({ length: 100 }, (_, i) => i + 1));
  assert.deepEqual([s.p50, s.p95, s.p99, s.min, s.max], [50, 95, 99, 1, 100]);
  assert.equal(summarizeLatencies([]).count, 0);
});

// -------------------------------------------------------------------- concurrency harness bounds
test("the concurrency harness bounds are pinned and enforced before any database access", async () => {
  assert.deepEqual({ ...HARNESS_BOUNDS }, { maxWorkers: 32, maxRounds: 20, maxJobs: 200, maxWallClockSeconds: 120 });
  const stub = new Proxy({}, { get() { throw new Error("database touched"); } }) as never;
  await assert.rejects(sameTokenSameFingerprint(stub, 21, 16), /outside harness bound/);
  await assert.rejects(sameTokenSameFingerprint(stub, 20, 33), /outside harness bound/);
  await assert.rejects(sameTokenSameFingerprint(stub, 0, 4), /outside harness bound/);
  await assert.rejects(sameTokenSameFingerprint(stub, 1.5, 4), /outside harness bound/);
  await assert.rejects(outboxCompetingWorkers(stub, 201, 8), /outside harness bound/);
  await assert.rejects(outboxCompetingWorkers(stub, 100, 33), /outside harness bound/);
  await assert.rejects(backendKilledDuringCreates(stub, 33, 5), /outside harness bound/);
  await assert.rejects(backendKilledDuringCreates(stub, 16, 21), /outside harness bound/);
});
