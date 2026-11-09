import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { evaluateObservation, OBSERVATION_LIMITATIONS, type ObservationInput } from "../lab/m1/observation-check";
import { readObservation, runObservation, type FrontFaults } from "../lab/m1/observation/run";

// Independent observation prototype: four separate loopback processes (canary, stand-in for the server under test, origin receipt collector, origin fixture). The observer's evidence
// lives in a directory of its own. Separate local processes are not independent organizational custody, and the evaluator says so.

const identity = { runId: "run-a", campaignId: "campaign-a" };
const dirs: string[] = [];
const observerDir = (): string => { const dir = fs.mkdtempSync(path.join(os.tmpdir(), "m1-observer-")); dirs.push(dir); return dir; };
test.after(() => { for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true }); });

async function observe(faults: FrontFaults = {}): Promise<ObservationInput & { files: ReturnType<typeof readObservation>; dir: string }> {
  const dir = observerDir();
  const files = await runObservation({ observerDirectory: dir, ...identity, faults });
  const read = readObservation(files);
  return { identity, canary: read.canary, receipts: read.receipts, meta: read.meta, files: read, dir };
}
const clone = <T,>(value: T): T => structuredClone(value);
const reasons = (input: ObservationInput): string[] => evaluateObservation(input).reasons;
type Canary = { steps: { requestId: string; ok: boolean; status: number | null; latencyMs: number; phase: string }[]; runId: string; campaignId: string; timeoutMs: number; plan: unknown };

test("clean run: every journey succeeds, every success has exactly one origin receipt, the five processes are distinct, and the limits are stated", async () => {
  const run = await observe();
  const result = evaluateObservation(run);
  assert.deepEqual([result.outcome, result.reasons], ["PASS", []]);
  const s = result.summary!;
  assert.deepEqual([s.journeys, s.journeysSucceeded, s.successRate, s.steps, s.originReceipts, s.timeouts, s.falseRejects, s.rateLimits, s.challenges, s.recovery.residualRestrictions], [7, 7, 1, 42, 42, 0, 0, 0, 0, 0]);
  assert.ok(s.latencyMs.p50 !== null && s.latencyMs.p95 !== null && s.latencyMs.p99 !== null && s.latencyMs.baselineP95 !== null);
  assert.deepEqual(result.limitations, OBSERVATION_LIMITATIONS);
  assert.ok(s.notCoveredActions.includes("payment") && !s.coveredSteps.includes("payment"));
  const meta = run.meta as { processes: Record<string, number>; loopbackOnly: boolean; custody: string };
  assert.equal(new Set(Object.values(meta.processes)).size, 5, "canary, stand-in, collector, origin and harness are five distinct processes");
  assert.ok(meta.loopbackOnly && /NOT independent organizational custody/u.test(meta.custody));
  assert.ok(!run.dir.includes("artifacts"), "the observer's evidence is outside every SUT evidence directory");
});

test("faults at the server under test are measured independently by the canary and corroborated or contradicted by the origin collector", async () => {
  const dropped = await observe({ drop: ["window.2.submit"] });
  const drop = evaluateObservation(dropped);
  assert.equal(drop.outcome, "REJECT");
  assert.ok(drop.reasons.includes("m1.obs.journey_success_below_minimum") && drop.summary!.falseRejects === 1 && drop.summary!.httpErrors === 1);
  assert.ok(!drop.reasons.includes("m1.obs.canary_success_without_origin_receipt"), "an honest 503 is not a contradiction: the origin never saw it");

  const faked = await observe({ fake: ["window.1.submit"] });
  assert.ok(reasons(faked).includes("m1.obs.canary_success_without_origin_receipt"), "success contradicted by the origin: the stand-in answered 200 without forwarding");

  const duplicated = await observe({ duplicate: ["baseline.1.submit"] });
  assert.ok(reasons(duplicated).includes("m1.obs.duplicate_origin_receipt"), "a request the origin received twice");

  const limited = await observe({ rateLimit: ["window.1.home"], challenge: ["window.2.faq"] });
  const l = evaluateObservation(limited);
  assert.equal(l.outcome, "REJECT");
  assert.deepEqual([l.summary!.rateLimits, l.summary!.challenges, l.summary!.falseRejects], [1, 1, 2]);
  const residual = await observe({ drop: ["recovery.2.home"] });
  assert.ok(reasons(residual).includes("m1.obs.recovery_incomplete"));
});

test("evidence tampering after the run: missing, duplicated, foreign-campaign, foreign-run, unattributed and replayed-identity records are never PASS", async () => {
  const run = await observe();
  const receipts = run.receipts as { requestId: string; runId: string; campaignId: string; method: string; path: string; seq: number }[];
  const check = (label: string, change: (input: { canary: Canary; receipts: typeof receipts; meta: Record<string, unknown> }) => void, expected: string): void => {
    const input = { canary: clone(run.canary) as Canary, receipts: clone(receipts), meta: clone(run.meta) as Record<string, unknown> };
    change(input);
    const found = reasons({ identity, canary: input.canary, receipts: input.receipts, meta: input.meta });
    assert.ok(found.includes(expected), `${label}: ${found.join(",")}`);
  };
  check("missing origin receipt", (i) => { i.receipts.splice(10, 1); }, "m1.obs.canary_success_without_origin_receipt");
  check("all origin receipts gone", (i) => { i.receipts.length = 0; }, "m1.obs.canary_success_without_origin_receipt");
  check("duplicate receipt", (i) => { i.receipts.push({ ...i.receipts[3] }); }, "m1.obs.duplicate_origin_receipt");
  check("foreign campaign receipt", (i) => { i.receipts[5].campaignId = "campaign-b"; }, "m1.obs.foreign_campaign_receipt");
  check("foreign run receipt", (i) => { i.receipts[5].runId = "run-b"; }, "m1.obs.foreign_run_receipt");
  check("unattributed receipt", (i) => { i.receipts.push({ ...i.receipts[0], requestId: "nobody.9.home", seq: 99 }); }, "m1.obs.unattributed_origin_receipt");
  check("receipt without identity", (i) => { (i.receipts[2] as unknown as Record<string, unknown>).runId = null; }, "m1.obs.receipt_without_identity");
  check("receipt for a different request", (i) => { i.receipts[4].path = "/elsewhere"; }, "m1.obs.receipt_request_mismatch");
  check("replayed canary request identity", (i) => { i.canary.steps[7].requestId = i.canary.steps[1].requestId; }, "m1.obs.canary_request_id_replayed");
  check("canary of another run", (i) => { i.canary.runId = "run-b"; }, "m1.obs.canary_run_mismatch");
  check("canary of another campaign", (i) => { i.canary.campaignId = "campaign-b"; }, "m1.obs.canary_campaign_mismatch");
  check("canary success claimed for a request the stand-in never delivered", (i) => { i.canary.steps[0].ok = true; i.receipts.splice(0, 1); }, "m1.obs.canary_success_without_origin_receipt");
  check("weakened canary timeout", (i) => { i.canary.timeoutMs = 60_000; }, "m1.obs.canary_timeout_not_pinned");
  check("processes collapsed into one", (i) => { (i.meta.processes as Record<string, number>).originFixture = (i.meta.processes as Record<string, number>).canary; }, "m1.obs.processes_not_separate");
  check("latency inflated in the window", (i) => { for (const step of i.canary.steps) if (step.phase === "window") step.latencyMs = 5_000; }, "m1.obs.window_latency_exceeds_rule");
});

test("missing or malformed observer evidence is ERROR, never PASS", async () => {
  const run = await observe();
  assert.equal(evaluateObservation({ identity, canary: undefined, receipts: run.receipts, meta: run.meta }).outcome, "ERROR");
  assert.equal(evaluateObservation({ identity, canary: run.canary, receipts: null, meta: run.meta }).outcome, "ERROR");
  assert.equal(evaluateObservation({ identity, canary: run.canary, receipts: run.receipts, meta: undefined }).outcome, "ERROR");
  assert.equal(evaluateObservation({ identity: null, canary: run.canary, receipts: run.receipts, meta: run.meta }).outcome, "ERROR");
  const truncated = clone(run.canary) as Canary; truncated.steps.length -= 3;
  assert.deepEqual(reasons({ identity, canary: truncated, receipts: run.receipts, meta: run.meta }), ["m1.obs.canary_results_incomplete"]);
  assert.equal(evaluateObservation({ identity, canary: { schema: "m1-canary-results-v1", steps: [{}] }, receipts: [], meta: run.meta }).outcome, "ERROR");
  assert.equal(evaluateObservation({ identity, canary: run.canary, receipts: [{ seq: "x" }], meta: run.meta }).outcome, "ERROR");
  assert.equal(evaluateObservation(null as unknown as ObservationInput).outcome, "ERROR");
});

test("the arrangement is loopback-only: no non-loopback address or external host appears in its sources", () => {
  for (const file of ["fixture-site.ts", "origin-collector.ts", "fixture-front.ts", "canary.ts", "run.ts"]) {
    const text = fs.readFileSync(path.join(__dirname, "..", "lab", "m1", "observation", file), "utf8").replace(/\/\*[\s\S]*?\*\//gu, "").replace(/\/\/.*$/gmu, "");
    assert.equal(/https?:\/\/(?!127\.0\.0\.1|fixture\.invalid)|0\.0\.0\.0/u.test(text), false, file);
    for (const match of text.matchAll(/listen\(0, "([^"]+)"/gu)) assert.equal(match[1], "127.0.0.1", file);
  }
});
