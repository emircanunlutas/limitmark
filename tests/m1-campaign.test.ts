import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { BASE_VERDICT_VALID } from "../lab/defense/m1-status-contract";
import type { RepeatabilityRun } from "../lab/defense/m1-repeatability";
import { evaluateRepeatability } from "../lab/defense/m1-repeatability";
import { evaluateLocalCampaign, m1LocalCampaign, CAMPAIGN_BLOCKERS, type CampaignRun } from "../lab/m1/campaign";
import type { M1Identity } from "../lab/m1/identity";
import { testRoot } from "./support/m1-world";

// Criterion 7 integration: three independently identified, LOCALLY_CONSISTENT runs, then the UNCHANGED repeatability rules. LOCAL_REPEATABILITY_PASS is not a qualified campaign.

const GIT = "a".repeat(40); const PARAMS = "b".repeat(64); const WORKLOAD = "c".repeat(64);
function facts(n: number, overrides: Partial<RepeatabilityRun> = {}): RepeatabilityRun {
  return {
    serverRunId: `run-${n}`, generatorRunId: `gen-${n}`, campaignId: `campaign-${n}`, levelId: "ba0-l7-c1", gitSha: GIT, paramsFingerprintSha256: PARAMS, workloadFingerprintSha256: WORKLOAD, workers: 1,
    windowOpenedAt: `2026-11-09T1${n}:00:00.000Z`, windowClosedAt: `2026-11-09T1${n}:01:00.000Z`, baseVerdict: BASE_VERDICT_VALID, shedReasonCounts: { "mutation.unverified.lane_budget": 20 + n }, externalAccepted: 100, status503Total: 20 + n, ...overrides,
  };
}
function identity(n: number, overrides: Partial<M1Identity> = {}): M1Identity {
  return { runId: `run-${n}`, campaignId: `campaign-${n}`, levelId: "ba0-l7-c1", gitSha: GIT, paramsSha256: PARAMS, paramsId: "ba0-field-v1", paramsVersion: 1, workloadSha256: WORKLOAD, finalizationSha256: `${n}`.repeat(64), ...overrides };
}
const components = { overlay: "PASS", tally: "PASS", receipts: "PASS", observation: "PASS", provenance: "PASS" } as const;
function run(n: number, accept: Partial<CampaignRun["acceptance"]> = {}, repeat: Partial<RepeatabilityRun> | null = {}): CampaignRun {
  return { acceptance: { outcome: "LOCALLY_CONSISTENT", identity: identity(n), components: { ...components }, ...accept }, repeat: repeat === null ? null : facts(n, repeat) };
}
const three = (...overrides: Partial<CampaignRun>[]): CampaignRun[] => [1, 2, 3].map((n, i) => ({ ...run(n), ...(overrides[i] ?? {}) }));
const evaluate = (runs: CampaignRun[]) => { const result = evaluateLocalCampaign(runs); assert.notEqual(result.outcome as string, "QUALIFIED"); assert.equal(result.qualification.reachable, false); return result; };

test("control: the unchanged repeatability evaluator passes on these facts, and three locally consistent runs give LOCAL_REPEATABILITY_PASS (not qualification)", () => {
  assert.equal(evaluateRepeatability([facts(1), facts(2), facts(3)]).outcome, "PASS");
  const result = evaluate(three());
  assert.deepEqual([result.outcome, result.reasons], ["LOCAL_REPEATABILITY_PASS", []]);
  assert.equal(result.freshState, "process_counters_reconciled_from_zero_per_run");
  assert.ok(CAMPAIGN_BLOCKERS.includes("three_local_runs_are_not_a_remote_qualification_campaign") && CAMPAIGN_BLOCKERS.includes("machine_freshness_not_provable_from_evidence"));
});

test("every per-run acceptance condition is required before repeatability is even consulted", () => {
  for (const [label, outcome, expected] of [["rejected run", "REJECT", "REJECT"], ["incomplete run", "INCOMPLETE", "INCOMPLETE"], ["errored run", "ERROR", "ERROR"]] as const) {
    const runs = three(); runs[1] = run(2, { outcome });
    const result = evaluate(runs);
    assert.equal(result.outcome, expected, label);
    assert.equal(result.repeatability, null, `${label}: repeatability not consulted`);
  }
  const noReceipts = three(); noReceipts[0] = run(1, { components: { ...components, receipts: "FAIL" } });
  assert.deepEqual(evaluate(noReceipts).reasons, ["m1.campaign.run1.receipts_not_passed"]);
  assert.equal(evaluate(three({ acceptance: { outcome: "QUALIFIED" as never, identity: identity(1), components } })).outcome, "ERROR", "an unrecognized acceptance outcome is never trusted");
  assert.equal(evaluate([run(1), run(2), run(3, {}, null)]).outcome, "ERROR", "missing repeatability facts");
});

test("exactly three runs: fewer is INCOMPLETE, more is ERROR", () => {
  assert.equal(evaluate([run(1), run(2)]).outcome, "INCOMPLETE");
  assert.equal(evaluate([]).outcome, "INCOMPLETE");
  assert.equal(evaluate([run(1), run(2), run(3), run(4)]).outcome, "ERROR");
  assert.equal(evaluateLocalCampaign(null as unknown as CampaignRun[]).outcome, "ERROR");
});

test("one invalid run and one substituted run: the campaign is rejected and cannot be qualified", () => {
  const invalid = three(); invalid[2] = run(3, {}, { baseVerdict: "INVALID" });
  assert.ok(evaluate(invalid).reasons.includes("m1.repeat.base_verdict_not_valid"));
  // substituted: the accepted identity belongs to another run than the repeatability facts it is combined with
  const substituted = three(); substituted[1] = run(2, { identity: identity(9) });
  assert.ok(evaluate(substituted).reasons.includes("m1.campaign.run2.facts_not_bound_to_accepted_identity"));
  // a package counted twice (the same finalization submitted as two runs)
  const doubled = three(); doubled[2] = run(3, { identity: identity(3, { finalizationSha256: identity(1).finalizationSha256 }) });
  assert.ok(evaluate(doubled).reasons.includes("m1.campaign.runs_not_distinct_packages"));
  const sameRun = three(); sameRun[2] = run(1);
  assert.equal(evaluate(sameRun).outcome, "REJECT");
});

test("the existing repeatability rules are preserved exactly: shed share +/-5 points, shed reasons, windows, commit, parameters, fixture, level, distinct campaigns", () => {
  const cases: [string, Partial<RepeatabilityRun>, string][] = [
    ["shed share", { status503Total: 40 }, "m1.repeat.shed_share_outside_tolerance"], ["shed reasons", { shedReasonCounts: { "mutation.unverified.other": 20 } }, "m1.repeat.shed_reason_sets_differ"],
    ["windows overlap", { windowOpenedAt: "2026-11-09T11:00:30.000Z", windowClosedAt: "2026-11-09T11:02:00.000Z" }, "m1.repeat.windows_overlap"],
    ["commit", { gitSha: "d".repeat(40) }, "m1.repeat.commit_differs"], ["level", { levelId: "ba0-l7-c2" }, "m1.repeat.level_differs"], ["campaign reuse", { campaignId: "campaign-1" }, "m1.repeat.campaign_ids_not_distinct"],
  ];
  for (const [label, override, reason] of cases) {
    const runs = three(); runs[1] = run(2, {}, override);
    const result = evaluate(runs);
    assert.equal(result.outcome, "REJECT", label);
    assert.ok(result.reasons.includes(reason) || result.reasons.some((entry) => entry.startsWith("m1.campaign.run2.facts_not_bound")), `${label}: ${result.reasons.join(",")}`);
  }
});

test("through the IO wrapper a missing or unusable run is ERROR (never a pass) and the artifact claims no qualification", () => {
  const root = testRoot("campaign");
  try {
    const outcome = m1LocalCampaign({ runs: [1, 2, 3].map((n) => ({ serverId: `20260101T00000${n}Z-nothing-00000${n}`, acceptanceId: `20260101T00000${n}Z-nothing-00000${n}`, reportPath: path.join(root, "missing", "generator-report.json") })) }, root);
    assert.equal(outcome.result.outcome, "ERROR");
    const artifact = JSON.parse(fs.readFileSync(path.join(root, outcome.evidenceId, "m1-campaign.json"), "utf8")) as { qualification: { reachable: boolean }; claims: Record<string, string>; campaign: { outcome: string } };
    assert.deepEqual([artifact.campaign.outcome, artifact.qualification.reachable, artifact.claims.machineFreshness], ["ERROR", false, "not_provable_from_evidence"]);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("a qualified campaign has no code path", () => {
  const text = fs.readFileSync(path.join(__dirname, "..", "lab", "m1", "campaign.ts"), "utf8").replace(/\/\*[\s\S]*?\*\//gu, "").replace(/\/\/.*$/gmu, "");
  assert.equal(/QUALIFIED/u.test(text.replace(/"QUALIFIED"/gu, "")), false);
  assert.equal(/finish\("QUALIFIED/u.test(text), false);
  assert.equal(/export type CampaignOutcome = "LOCAL_REPEATABILITY_PASS" \| "REJECT" \| "ERROR" \| "INCOMPLETE"/u.test(text), true);
});
