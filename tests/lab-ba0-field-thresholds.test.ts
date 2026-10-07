import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { requiredLedgerCapacity } from "../defense/core/lanes";
import { BA0_FIELD_V1, BUDGET_CONSTANTS, ba0FieldFingerprint, evaluateBudgetGates, failedGates, type Ba0FieldThresholds } from "../lab/defense/field-thresholds";
import { WORKLOADS } from "../lab/policy/workloads";

const root = path.join(__dirname, "..");
const mutate = (change: (copy: Ba0FieldThresholds) => void): Ba0FieldThresholds => { const copy = structuredClone(BA0_FIELD_V1) as Ba0FieldThresholds; change(copy); return copy; };

test("ba0-field-v1 is exactly the reviewed provisional N=1 parameter set, and is labelled as such", () => {
  const t = BA0_FIELD_V1;
  assert.equal(t.id, "ba0-field-v1");
  assert.equal(t.calibration, "provisional-uncalibrated");
  assert.match(t.status, /not production defaults/);
  assert.deepEqual({ ...t.level, fixtureCycle: undefined }, { id: "ba0-l7-c1", workers: 1, durationSeconds: 60, maxRequestsPerSecond: 25, maxTotalRequests: 1_500, requestTimeoutMs: 5_000, maxResponseBytes: 1_048_576, fixtureCycle: undefined });
  assert.deepEqual(t.level.fixtureCycle.map((entry) => `${entry.method} ${entry.path}`), ["GET /", "GET /gizlilik", "GET /test-talep-et", "POST /api/public-inquiries"]);
  assert.deepEqual(t.l2, {
    filterBits: 2 ** 23, filterHashes: 7, epochMs: 60_000, credited: { capacity: 10, refillPerSecond: 2 }, unverified: { capacity: 3, refillPerSecond: 1 }, maxUses: 3, ledgerCapacity: 512,
    stage: { timeoutMs: 50, maxConcurrent: 64 },
  });
  assert.deepEqual(t.channel, { queueCap: 16_384, windowCap: 8_192 });
  assert.deepEqual(t.collector, { maxRequests: 4_000, maxEventsPerRecord: 32, maxJournalBytes: 48 * 1_048_576, maxAnomalies: 200 });
  assert.deepEqual(t.allowedShed, [{ class: "mutation", lane: "unverified", reason: "lane_budget" }]);
  assert.deepEqual(t.window, { startSlackMs: 20_000, hardDeadlineMs: 90_000, quiescenceMs: 5_000, setupAllowanceMs: 2_000, drainAllowanceMs: 2_000 });
  assert.equal(t.canary.baselineJourneys, 12);
  assert.equal(t.canary.gapMs, 4_000);
  assert.equal(t.canary.residualJourneys, 3);
  assert.equal(t.canary.recoveryJourneys, 6);
  assert.equal(t.canary.jcrMinimum, 1);
  assert.deepEqual(t.telemetry, { tickMs: 1_000, ringTicks: 120, gapToleranceMs: 2_500 });
  assert.deepEqual(t.ceilings, { hostCpuBusyPct: 80, hostCpuTicks: 3, memAvailablePct: 15, planeEldP99Ms: 250, planeEldTicks: 3, rssMb: 512, fdPct: 70 });
  assert.equal(t.stop.hardCapMs, 45_000);
  assert.ok(Object.isFrozen(t));
});

test("the parameter set is fingerprinted: any change changes the hash, and the hash is stable", () => {
  const fingerprint = ba0FieldFingerprint();
  assert.deepEqual([fingerprint.id, fingerprint.version], ["ba0-field-v1", 1]);
  assert.match(fingerprint.sha256, /^[0-9a-f]{64}$/);
  assert.equal(ba0FieldFingerprint().sha256, fingerprint.sha256);
  assert.notEqual(ba0FieldFingerprint(mutate((copy) => { copy.l2.unverified.refillPerSecond = 2; })).sha256, fingerprint.sha256);
  assert.notEqual(ba0FieldFingerprint(mutate((copy) => { copy.level.maxTotalRequests = 1_499; })).sha256, fingerprint.sha256);
});

test("the workload catalogue and the parameter set agree about the level (the generator and the server run the same level)", () => {
  const workload = WORKLOADS["ba0-l7-pressure-c1"];
  const phase = workload.phases[0];
  assert.equal(workload.engine, "http-closed-loop");
  assert.equal(workload.remoteOnly, true);
  assert.equal(phase.concurrency, BA0_FIELD_V1.level.workers);
  assert.equal(phase.ratePerSecond, BA0_FIELD_V1.level.maxRequestsPerSecond);
  assert.equal(phase.durationSeconds, BA0_FIELD_V1.level.durationSeconds);
  assert.equal(phase.timeoutMs, BA0_FIELD_V1.level.requestTimeoutMs);
  assert.deepEqual({ ...workload.ceilings }, { requestsPerSecond: 25, concurrency: 1, durationSeconds: 60, totalRequests: 1_500 });
  assert.deepEqual(workload.fixtures?.map((fixture) => ({ method: fixture.method, path: fixture.path })), BA0_FIELD_V1.level.fixtureCycle.map((entry) => ({ method: entry.method, path: entry.path })));
});

test("every budget gate passes for ba0-field-v1, and the gates state the numbers they compared", () => {
  const gates = evaluateBudgetGates(BA0_FIELD_V1, 3_600_000);
  assert.deepEqual(failedGates(gates), []);
  for (const gate of gates) assert.match(gate.detail, /\d/, gate.id);
  const ids = gates.map((gate) => gate.id);
  for (const required of ["recovery.quiet_derived", "l2.ledger_capacity", "l2.bloom_fill_ceiling", "l2.bloom_fpr_ceiling", "journal.budget", "memory.total_budget", "channel.absorbs_stall", "hop.replay_capacity", "target.remaining_lifetime", "external.decisions_cover_level"]) assert.ok(ids.includes(required), required);
});

test("D4: the recovery quiet interval is DERIVED from the parameter set (2 x epoch + settle margin = 135 s), never a constant", () => {
  assert.equal(BA0_FIELD_V1.recovery.quietMs, 2 * BA0_FIELD_V1.l2.epochMs + BA0_FIELD_V1.recovery.settleMarginMs);
  assert.equal(BA0_FIELD_V1.recovery.quietMs, 135_000);
  assert.equal(BA0_FIELD_V1.recovery.settleMarginMs, 15_000);
  // a quiet interval that is not 2 x epoch + margin is refused, whichever number is edited
  assert.ok(failedGates(evaluateBudgetGates(mutate((copy) => { copy.recovery.quietMs = 6_000; }), null)).includes("recovery.quiet_derived"), "the Slice-3 six-second constant");
  assert.ok(failedGates(evaluateBudgetGates(mutate((copy) => { copy.l2.epochMs = 120_000; }), null)).includes("recovery.quiet_derived"), "an epoch change without its recovery change");
  assert.ok(failedGates(evaluateBudgetGates(mutate((copy) => { copy.recovery.settleMarginMs = 1_000; copy.recovery.quietMs = 2 * copy.l2.epochMs + 1_000; }), null)).includes("recovery.margin_covers_inflight"), "a margin too short to cover a PB lifetime plus an egress timeout");
  // the field runner reads the derived value, and never the Slice-3 constant
  const runner = readFileSync(path.join(root, "lab", "defense", "ba0-field-run.ts"), "utf8");
  assert.match(runner, /t\.recovery\.quietMs/);
  assert.doesNotMatch(runner, /recoverySettleMs|collapse-thresholds|6_000/);
});

test("the budget gates catch the failures they exist to catch, before any public bind", () => {
  const failing = (change: (copy: Ba0FieldThresholds) => void, id: string, remaining: number | null = null) => assert.ok(failedGates(evaluateBudgetGates(mutate(change), remaining)).includes(id), id);
  failing((copy) => { copy.l2.ledgerCapacity = requiredLedgerCapacity(10, 2, 60_000) - 1; }, "l2.ledger_capacity");
  failing((copy) => { copy.l2.filterBits = 2 ** 13; }, "l2.bloom_fill_ceiling");
  failing((copy) => { copy.l2.filterBits = 2 ** 11; }, "l2.bloom_fpr_ceiling");
  failing((copy) => { copy.collector.maxJournalBytes = 1_048_576; }, "journal.budget");
  failing((copy) => { copy.channel.queueCap = 1_000; copy.channel.windowCap = 500; }, "channel.absorbs_stall");
  failing((copy) => { copy.channel.windowCap = copy.channel.queueCap + 1; }, "channel.window_within_queue");
  failing((copy) => { copy.hop.replayCapacity = 100; }, "hop.replay_capacity");
  failing((copy) => { copy.external.maxDecisions = 100; }, "external.decisions_cover_level");
  failing((copy) => { copy.external.maxActive = 100_000; copy.external.maxOrphans = 100_000; }, "external.state_memory");
  failing((copy) => { copy.external.maxTraces = 100_000; }, "external.trace_memory");
  failing((copy) => { copy.level.maxTotalRequests = 1_501; }, "level.total_equals_duration_times_rate");
  failing((copy) => { (copy.level as { workers: number }).workers = 2; }, "level.n_equals_one");
  failing((copy) => { copy.window.hardDeadlineMs = 60_000; }, "level.window_covers_generator");
  failing((copy) => { copy.level.requestTimeoutMs = 1_000; }, "level.request_timeout_within_boundary_chain");
  failing((copy) => { copy.telemetry.gapToleranceMs = 1_000; }, "telemetry.cadence");
  failing((copy) => { copy.stop.drainMs = 60_000; }, "stop.steps_fit_hard_cap");
  failing((copy) => { copy.allowedShed = [{ class: "mutation", lane: "unverified", reason: "lane_budget" }, { class: "open", lane: "open", reason: "evaluator_saturation" }]; }, "workload.allowed_shed_closed");
  failing(() => undefined, "target.remaining_lifetime", 60_000);
});

test("the Bloom gate states the worst case: every request of the level is a render, plus every canary render", () => {
  const bloom = evaluateBudgetGates(BA0_FIELD_V1, null).find((gate) => gate.id === "l2.bloom_fill_ceiling")!;
  assert.match(bloom.detail, /worst-case fill/);
  assert.ok(BUDGET_CONSTANTS.maxPlaneEventsPerRequest >= 10, "the per-request event bounds are conservative upper bounds");
});
