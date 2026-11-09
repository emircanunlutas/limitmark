import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { BROWSE_AND_SUBMIT_STEPS, evaluateCanaryContract } from "../lab/m1/canary-contract";
import { evaluateLatencyAgainstThresholds, validateOwnerThresholds, type OwnerCanaryThresholds } from "../lab/m1/canary-thresholds";
import { runCli } from "../lab/m1/cli";

const template = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "infra", "m1", "canary-thresholds.template.json"), "utf8")) as OwnerCanaryThresholds;
const fixed = (): OwnerCanaryThresholds => ({
  schema: "m1-canary-thresholds-v1", approval: { approvedBy: "owner", approvedAt: "2026-11-20T10:00:00Z", reference: "decision-O-5" }, baselineMeasurementIds: ["b1", "b2", "b3"],
  maxLatencyMs: { baseline: { p50: 10, p95: 20, p99: 30 }, window: { p50: 50, p95: 100, p99: 200 }, recovery: { p50: 20, p95: 40, p99: 60 } }, maxRecoveryTimeToBaselineMs: 5_000, maxHeartbeatGapMs: 1_000, operationalActions: ["profile_view"],
});
const steps = (latency = 20) => (["baseline", "window", "recovery"] as const).flatMap((phase) => [1, 2].flatMap((journey) => [...BROWSE_AND_SUBMIT_STEPS, "profile_view"].map((step) => ({ phase, journey, step, status: 200, ok: true, timedOut: false, failed: false, challenged: false, latencyMs: latency }))));

test("the shipped template sets no number: every threshold is null, so the record is UNSET and latency is NOT_EVALUATED", () => {
  const status = validateOwnerThresholds(template);
  assert.equal(status.status, "UNSET"); assert.equal(status.digest, null);
  for (const field of ["approval.approvedBy", "baselineMeasurementIds", "maxLatencyMs.window.p95", "maxRecoveryTimeToBaselineMs", "maxHeartbeatGapMs", "operationalActions"]) assert.ok(status.missing.includes(field), field);
  const canary = evaluateCanaryContract({ steps: steps(), operationalActions: ["profile_view"] });
  assert.equal(canary.outcome, "PASS", "the 100 percent journey requirement is unaffected by thresholds");
  assert.deepEqual(evaluateLatencyAgainstThresholds(canary, template), { outcome: "NOT_EVALUATED", reasons: ["m1.latency.thresholds_unset"] });
});

test("a fixed record needs approval, three distinct baseline measurements, ordered positive percentiles for every phase, a recovery time, a heartbeat limit and named actions", () => {
  assert.equal(validateOwnerThresholds(fixed()).status, "FIXED"); assert.match(validateOwnerThresholds(fixed()).digest!, /^[0-9a-f]{64}$/u);
  const cases: [(t: OwnerCanaryThresholds) => void, string][] = [
    [(t) => { t.baselineMeasurementIds = ["b1", "b2"]; }, "m1.thresholds.baseline_needs_three_distinct_measurements"], [(t) => { t.baselineMeasurementIds = ["b1", "b1", "b2"]; }, "m1.thresholds.baseline_needs_three_distinct_measurements"],
    [(t) => { t.maxLatencyMs.window.p95 = 10; }, "m1.thresholds.window_percentiles_not_ordered"], [(t) => { t.maxLatencyMs.recovery.p50 = -1; }, "m1.thresholds.recovery.p50_not_positive"],
    [(t) => { t.maxHeartbeatGapMs = 0; }, "m1.thresholds.heartbeat_gap_not_positive"], [(t) => { t.approval.approvedAt = "yesterday-ish"; }, "m1.thresholds.approvedAt_not_a_date"],
    [(t) => { t.operationalActions = [""]; }, "m1.thresholds.operational_action_invalid"], [(t) => { (t as unknown as { maxRecoveryTimeToBaselineMs: unknown }).maxRecoveryTimeToBaselineMs = "5"; }, "m1.thresholds.recovery_time_not_positive"],
  ];
  for (const [mutate, reason] of cases) { const t = fixed(); mutate(t); const s = validateOwnerThresholds(t); assert.equal(s.status, "INVALID", reason); assert.ok(s.problems.includes(reason), `${reason}: ${s.problems.join(",")}`); }
  const unapproved = fixed(); unapproved.approval.approvedBy = null; assert.equal(validateOwnerThresholds(unapproved).status, "UNSET");
  for (const bad of [null, [], "x", { schema: "other" }, { ...fixed(), maxLatencyMs: null }]) assert.equal(validateOwnerThresholds(bad).status, "INVALID");
});

test("with a FIXED record the measured window and recovery percentiles are compared; the 100 percent journey requirement still decides first", () => {
  assert.equal(evaluateLatencyAgainstThresholds(evaluateCanaryContract({ steps: steps(20), operationalActions: ["profile_view"] }), fixed()).outcome, "PASS");
  const slow = evaluateLatencyAgainstThresholds(evaluateCanaryContract({ steps: steps(150), operationalActions: ["profile_view"] }), fixed());
  assert.equal(slow.outcome, "REJECT"); assert.ok(slow.reasons.includes("m1.latency.window.p95_exceeds_owner_threshold"));
  const failedStep = steps(); failedStep[20] = { ...failedStep[20]!, status: 429, ok: false };
  assert.equal(evaluateCanaryContract({ steps: failedStep, operationalActions: ["profile_view"] }).outcome, "REJECT", "an unexpected 429 fails regardless of any latency record");
});

test("CLI: thresholds exits 20 for the template, 0 for a fixed record, 10 for an invalid one; canary exits 0 only for a complete 100 percent journey set and never decides latency without a FIXED record", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "m1-canary-cli-"));
  try {
    const write = (name: string, value: unknown): string => { const file = path.join(dir, name); fs.writeFileSync(file, JSON.stringify(value)); return file; };
    const run = async (args: string[]) => { const lines: string[] = []; const code = await runCli(args, { stdout: (l) => lines.push(l) }); return { code, out: JSON.parse(lines[0]!) as { outcome: string; reasons: string[] } }; };
    assert.equal((await run(["thresholds", "--file", write("template.json", template)])).code, 20);
    assert.equal((await run(["thresholds", "--file", write("fixed.json", fixed())])).code, 0);
    assert.equal((await run(["thresholds", "--file", write("bad.json", { ...fixed(), maxHeartbeatGapMs: -5 })])).code, 10);
    assert.equal((await run(["thresholds", "--file", path.join(dir, "missing.json")])).code, 30);
    fs.writeFileSync(path.join(dir, "canary-results.json"), JSON.stringify({ steps: steps() }));
    assert.equal((await run(["canary", "--observer-dir", dir, "--operational-action", "profile_view"])).code, 0);
    assert.equal((await run(["canary", "--observer-dir", dir])).code, 20, "operational actions not named: INCOMPLETE");
    assert.equal((await run(["canary", "--observer-dir", dir, "--operational-action", "profile_view", "--thresholds", write("t2.json", template)])).code, 20, "latency not decided is not a pass");
    assert.equal((await run(["canary", "--observer-dir", dir, "--operational-action", "profile_view", "--thresholds", write("t3.json", fixed())])).code, 0);
    const bad = steps(); bad[3] = { ...bad[3]!, challenged: true, ok: false };
    fs.writeFileSync(path.join(dir, "canary-results.json"), JSON.stringify({ steps: bad }));
    assert.equal((await run(["canary", "--observer-dir", dir, "--operational-action", "profile_view"])).code, 10);
    fs.writeFileSync(path.join(dir, "canary-results.json"), "not json");
    assert.equal((await run(["canary", "--observer-dir", dir, "--operational-action", "profile_view"])).code, 30);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
