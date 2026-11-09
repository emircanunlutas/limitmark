import assert from "node:assert/strict";
import test from "node:test";
import { BROWSE_AND_SUBMIT_STEPS, LATENCY_MEASUREMENTS_REQUIRED, evaluateCanaryContract } from "../lab/m1/canary-contract";
import { evaluateObservationCompleteness } from "../lab/m1/observation-completeness";

const ACTIONS = ["profile_view"] as const;
type S = { phase: string; journey: number; step: string; status: number | null; ok: boolean; timedOut: boolean; failed: boolean; challenged: boolean; latencyMs: number };
const journeyOf = (phase: string, journey: number, names: readonly string[] = [...BROWSE_AND_SUBMIT_STEPS, ...ACTIONS], latency = 20): S[] =>
  names.map((step) => ({ phase, journey, step, status: 200, ok: true, timedOut: false, failed: false, challenged: false, latencyMs: latency }));
const good = (): S[] => [...journeyOf("baseline", 1), ...journeyOf("baseline", 2), ...journeyOf("window", 1, undefined, 60), ...journeyOf("window", 2, undefined, 80), ...journeyOf("recovery", 1)];
const run = (steps: unknown, operationalActions: readonly string[] = ACTIONS) => evaluateCanaryContract({ steps, operationalActions });

test("canary contract: a complete 100 percent run passes, reports baseline and attack percentiles separately, sets no latency threshold and never qualifies", () => {
  const result = run(good());
  assert.equal(result.outcome, "PASS"); assert.deepEqual(result.reasons, []);
  assert.equal(result.latencyThresholds, "UNSET_OWNER_DECISION"); assert.equal(result.qualification, "UNREACHABLE");
  assert.deepEqual([result.latency.baseline!.p50, result.latency.window!.p50, result.latency.window!.p95, result.latency.window!.p99, result.latency.recovery!.p99], [20, 60, 80, 80, 20]);
  assert.ok(LATENCY_MEASUREMENTS_REQUIRED.length >= 5);
});

test("canary contract: each unexpected 429, challenge, timeout, transport failure, HTTP error or false rejection fails the run", () => {
  const mutate = (change: Partial<S>): ReturnType<typeof run> => { const steps = good(); Object.assign(steps[14]!, change); return run(steps); };
  const cases: [Partial<S>, string][] = [
    [{ status: 429, ok: false }, "m1.canary.unexpected_429"], [{ challenged: true, ok: false }, "m1.canary.challenge_observed"], [{ timedOut: true, ok: false, status: null }, "m1.canary.timeout_observed"],
    [{ failed: true, ok: false, status: null }, "m1.canary.transport_failure"], [{ status: 500, ok: false }, "m1.canary.http_error"], [{ status: 403, ok: false }, "m1.canary.false_rejection"],
    [{ status: 503, ok: false }, "m1.canary.false_rejection"],
  ];
  for (const [change, reason] of cases) { const result = mutate(change); assert.equal(result.outcome, "REJECT", JSON.stringify(change)); assert.ok(result.reasons.includes(reason), `${JSON.stringify(change)}: ${result.reasons.join(",")}`); }
  // a failure in the recovery phase and one in the attack window both count (the contract covers all phases)
  const recovery = good(); Object.assign(recovery[recovery.length - 1]!, { ok: false, status: 502 });
  assert.ok(run(recovery).reasons.includes("m1.canary.recovery_journey_failed"));
});

test("canary contract: a journey missing a required step, a duplicated step, an unknown phase or an unobserved phase cannot pass", () => {
  const skipped = good().filter((step) => !(step.phase === "window" && step.journey === 2 && step.step === "submit"));
  assert.ok(run(skipped).reasons.includes("m1.canary.required_step_missing")); assert.equal(run(skipped).outcome, "REJECT");
  const duplicated = [...good(), ...journeyOf("baseline", 1, ["home"])];
  assert.equal(run(duplicated).outcome, "REJECT");
  assert.ok(run([...good(), ...journeyOf("warmup", 1)]).reasons.includes("m1.canary.unknown_phase"));
  const noRecovery = good().filter((step) => step.phase !== "recovery");
  const result = run(noRecovery); assert.equal(result.outcome, "INCOMPLETE"); assert.ok(result.reasons.includes("m1.canary.recovery_not_observed"));
});

test("canary contract: operational actions the owner has not named leave the run INCOMPLETE (never PASS); malformed input is ERROR", () => {
  const unspecified = evaluateCanaryContract({ steps: good().map((step) => ({ ...step })), operationalActions: [] });
  assert.equal(unspecified.outcome, "INCOMPLETE"); assert.deepEqual(unspecified.openItems, ["m1.canary.operational_actions_unspecified"]);
  assert.equal(run("nope").outcome, "ERROR"); assert.equal(run([{ phase: "baseline" }]).outcome, "ERROR");
  assert.equal(run([{ ...good()[0]!, latencyMs: -1 }]).outcome, "ERROR");
});

// ---- observation completeness
const T0 = 1_000_000;
const receipts = (n: number) => Array.from({ length: n }, (_, i) => ({ seq: i + 1, requestId: `r${i + 1}` }));
const steps = (n: number, okFrom = 1) => Array.from({ length: n }, (_, i) => ({ requestId: `r${i + 1}`, ok: i + 1 >= okFrom }));
const declaration = (n: number, extra: Record<string, unknown> = {}) => ({ receiptCount: n, lastSeq: n, coverageStartMs: T0 - 10, coverageEndMs: T0 + 1000 + 10, heartbeatsMs: [T0 + 100, T0 + 200, T0 + 300, T0 + 400, T0 + 500, T0 + 600, T0 + 700, T0 + 800, T0 + 900], ...extra });
const complete = (over: Record<string, unknown> = {}) => evaluateObservationCompleteness({ receipts: receipts(5), declaration: declaration(5), canarySteps: steps(5), canaryPlannedSteps: 5, runWindow: { startMs: T0, endMs: T0 + 1000 }, maxHeartbeatGapMs: 150, ...over } as never);

test("observation completeness: a gapless, declared, covered, heartbeat-continuous observation passes and never qualifies", () => {
  const result = complete(); assert.equal(result.outcome, "PASS"); assert.deepEqual(result.reasons, []); assert.equal(result.qualification, "UNREACHABLE");
});

test("observation completeness: nothing is silently tolerated (sequence gap, count mismatch, coverage, heartbeat gap, missing canary steps, unreceipted success)", () => {
  const gap = receipts(5).filter((r) => r.seq !== 3);
  assert.ok(complete({ receipts: gap, declaration: declaration(4, { lastSeq: 5 }) }).reasons.includes("m1.complete.receipt_sequence_gap"));
  assert.ok(complete({ declaration: declaration(6) }).reasons.includes("m1.complete.declared_receipt_count_mismatch"));
  assert.ok(complete({ declaration: declaration(5, { lastSeq: 4 }) }).reasons.includes("m1.complete.declared_last_sequence_mismatch"));
  assert.ok(complete({ declaration: declaration(5, { coverageStartMs: T0 + 1 }) }).reasons.includes("m1.complete.collector_window_not_covering_run"));
  assert.ok(complete({ declaration: declaration(5, { coverageEndMs: T0 + 999 }) }).reasons.includes("m1.complete.collector_window_not_covering_run"));
  assert.ok(complete({ declaration: declaration(5, { heartbeatsMs: [T0 + 100, T0 + 700] }) }).reasons.includes("m1.complete.heartbeat_gap_exceeded"));
  assert.ok(complete({ declaration: declaration(5, { heartbeatsMs: [] }) }).reasons.includes("m1.complete.no_heartbeats"));
  assert.ok(complete({ canarySteps: steps(4), canaryPlannedSteps: 5 }).reasons.includes("m1.complete.canary_steps_missing"));
  assert.ok(complete({ receipts: receipts(5).slice(0, 4), declaration: declaration(4) }).reasons.includes("m1.complete.canary_success_without_origin_receipt"));
  for (const over of [{ declaration: declaration(5, { heartbeatsMs: [T0 + 100] }) }, { receipts: receipts(4), declaration: declaration(4) }]) assert.equal(complete(over).outcome, "REJECT");
});

test("observation completeness: a request that never reached the origin needs no receipt only when it did not succeed; an unset gap limit or plan is INCOMPLETE; malformed input is ERROR", () => {
  const shed = [{ requestId: "r1", ok: false }, ...steps(5).slice(1)];
  assert.equal(complete({ canarySteps: shed, receipts: receipts(5).slice(1).map((r, i) => ({ seq: i + 1, requestId: r.requestId })), declaration: declaration(4) }).outcome, "PASS");
  const unset = complete({ maxHeartbeatGapMs: null }); assert.equal(unset.outcome, "INCOMPLETE"); assert.deepEqual(unset.reasons, ["m1.complete.heartbeat_gap_limit_unset"]);
  assert.equal(complete({ canaryPlannedSteps: null }).outcome, "INCOMPLETE");
  assert.equal(complete({ receipts: null }).outcome, "ERROR"); assert.equal(complete({ declaration: null }).outcome, "ERROR"); assert.equal(complete({ canarySteps: [{ requestId: 1 }] }).outcome, "ERROR");
  assert.equal(complete({ runWindow: { startMs: T0, endMs: T0 } }).outcome, "ERROR");
});
