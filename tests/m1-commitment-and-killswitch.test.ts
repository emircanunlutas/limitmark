import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";
import { PARAMETERS_DIGEST, buildCommitment, evaluateFreshness, type CommitmentInput } from "../lab/m1/commitment";

const require_ = createRequire(import.meta.url);
const { decide, maxRunCost } = require_("../infra/m1/killswitch/decide.js") as {
  decide: (message: unknown, now: number, instances: unknown[], config: Record<string, unknown>) => { action: string; reason: string; targets: { name: string }[] };
  maxRunCost: (input: Record<string, unknown>) => { bounded: boolean; usd: number | null; tryAmount: number | null; reason: string };
};

const H = 3_600_000; const A0 = 1_800_000_000_000;
const base = (run: number, over: Partial<CommitmentInput> = {}): CommitmentInput => ({
  campaignId: "m1-c1", runId: `run-${run}`, commit: "a".repeat(40), treeClean: true, parametersId: "ba0-field-v1", parametersDigest: PARAMETERS_DIGEST, fixtureDigest: "b".repeat(64),
  target: { ipv4: "10.10.0.5", authorizedFromMs: A0 + run * 3 * H - H, authorizedUntilMs: A0 + run * 3 * H + 2 * H },
  window: { startMs: A0 + run * 3 * H, endMs: A0 + run * 3 * H + 5 * 60_000 },
  instance: { id: `inst-${run}`, createdMs: A0 + run * 3 * H - 30 * 60_000, imageId: "img-1", bootId: `boot-${run}` },
  counters: { admitted: 0, shed: 0, forwarded: 0 }, canaryThresholdsFixed: true, retentionDays: 30, previousTeardownMs: run === 1 ? null : A0 + (run - 1) * 3 * H + 30 * 60_000, ...over,
});
const built = (run: number, over: Partial<CommitmentInput> = {}) => { const r = buildCommitment(base(run, over)); assert.equal(r.outcome, "VALID", r.reasons.join(",")); return { commitment: r.commitment!, digest: r.digest! }; };

test("commitment: a consistent, code-pinned, clean, fresh, zero-counter commitment is VALID with a stable digest", () => {
  const a = buildCommitment(base(1)); const b = buildCommitment(base(1));
  assert.equal(a.outcome, "VALID"); assert.equal(a.digest, b.digest); assert.match(a.digest!, /^[0-9a-f]{64}$/u);
  assert.notEqual(buildCommitment(base(1, { runId: "run-x" })).digest, a.digest);
});

test("commitment: each inconsistency is refused (dirty tree, unpinned parameters, window outside the authorization, non-zero counters, stale instance, unfixed thresholds)", () => {
  const cases: [Partial<CommitmentInput>, string][] = [
    [{ treeClean: false }, "m1.commit.tree_not_clean"], [{ commit: "xyz" }, "m1.commit.commit_not_a_sha"], [{ parametersDigest: "c".repeat(64) }, "m1.commit.parameters_not_code_pinned"],
    [{ parametersId: "ba0-field-c2-v1" }, "m1.commit.parameters_not_code_pinned"], [{ campaignId: "x".repeat(32) }, "m1.commit.campaign_id_invalid"], [{ target: { ipv4: "example.test", authorizedFromMs: A0, authorizedUntilMs: A0 + H } }, "m1.commit.target_not_ipv4_literal"],
    [{ target: { ipv4: "10.10.0.5", authorizedFromMs: A0, authorizedUntilMs: A0 + 73 * H } }, "m1.commit.target_authorization_exceeds_72h"],
    [{ window: { startMs: A0 + 3 * H, endMs: A0 + 3 * H + 5 * 60_000 }, target: { ipv4: "10.10.0.5", authorizedFromMs: A0, authorizedUntilMs: A0 + 3 * H + 10 * 60_000 } }, "m1.commit.window_leaves_less_than_target_min_remaining"],
    [{ counters: { admitted: 1 } }, "m1.commit.counters_not_zero"], [{ counters: {} }, "m1.commit.counters_not_zero"], [{ canaryThresholdsFixed: false }, "m1.commit.canary_thresholds_not_fixed"],
    [{ instance: { id: "i", createdMs: A0 + 10 * H, imageId: "img", bootId: "b" } }, "m1.commit.instance_not_created_before_run"],
    [{ previousTeardownMs: A0 + 10 * H }, "m1.commit.instance_not_created_after_previous_teardown"],
  ];
  for (const [change, reason] of cases) { const r = buildCommitment(base(2, change)); assert.equal(r.outcome, "INVALID", reason); assert.ok(r.reasons.includes(reason), `${reason}: ${r.reasons.join(",")}`); assert.equal(r.digest, null); }
});

test("freshness: three distinct, ordered, non-overlapping runs are FRESH; a reused instance, boot, run id, commit change, overlap or missing teardown is NOT_FRESH", () => {
  assert.equal(evaluateFreshness([built(1), built(2), built(3)]).outcome, "FRESH");
  assert.ok(evaluateFreshness([built(1), built(2, { instance: { ...base(2).instance, id: "inst-1" } })]).reasons.includes("m1.fresh.instance_reused"));
  assert.ok(evaluateFreshness([built(1), built(2, { instance: { ...base(2).instance, bootId: "boot-1" } })]).reasons.includes("m1.fresh.boot_reused"));
  assert.ok(evaluateFreshness([built(1), built(2, { runId: "run-1" })]).reasons.includes("m1.fresh.run_id_reused"));
  assert.ok(evaluateFreshness([built(1), built(2, { commit: "d".repeat(40) })]).reasons.includes("m1.fresh.commit_changed"));
  assert.ok(evaluateFreshness([built(1), built(2, { window: { startMs: base(1).window.endMs - 1000, endMs: base(1).window.endMs + 60_000 }, target: { ipv4: "10.10.0.5", authorizedFromMs: A0, authorizedUntilMs: A0 + 6 * H }, instance: { ...base(2).instance, createdMs: base(1).window.startMs - 1000 }, previousTeardownMs: base(1).window.startMs - 2000 })]).reasons.includes("m1.fresh.windows_overlap"));
  assert.ok(evaluateFreshness([built(1), built(2, { previousTeardownMs: null })]).reasons.includes("m1.fresh.previous_teardown_not_recorded"));
  assert.equal(evaluateFreshness([]).outcome, "NOT_FRESH");
});

// ---- kill switch decision logic
const inst = (name: string, ageMin: number, labels: Record<string, string> = { purpose: "m1-qualification", campaign: "m1-c1" }) => ({ name, project: "p", createdMs: A0 - ageMin * 60_000, labels });
const cfg = { campaignId: "m1-c1", runMaxSeconds: 7200, stopFraction: 0.8 };

test("kill switch: the reaper deletes only labeled instances past the maximum lifetime plus grace; it never selects an unlabeled or other-campaign instance", () => {
  const fleet = [inst("old", 130), inst("young", 20), inst("unlabeled", 500, {}), inst("other", 500, { purpose: "m1-qualification", campaign: "other" }), inst("not-m1", 500, { purpose: "prod", campaign: "m1-c1" })];
  const d = decide({ kind: "reaper" }, A0, fleet, cfg);
  assert.deepEqual([d.action, d.reason, d.targets.map((t) => t.name)], ["delete", "ttl-exceeded", ["old"]]);
  assert.equal(decide({ kind: "reaper" }, A0, [inst("young", 20)], cfg).action, "none");
  assert.equal(decide({ kind: "reaper" }, A0, [inst("edge", 124)], cfg).action, "none", "inside the 5 minute grace");
});

test("kill switch: a budget message at or above the stop fraction deletes every labeled instance; below it, nothing; malformed messages do nothing", () => {
  const fleet = [inst("a", 1), inst("b", 2), inst("x", 2, {})];
  assert.deepEqual(decide({ costAmount: 2400, budgetAmount: 3000 }, A0, fleet, cfg).targets.map((t) => t.name), ["a", "b"]);
  assert.equal(decide({ costAmount: 3000, budgetAmount: 3000 }, A0, fleet, cfg).action, "delete");
  assert.equal(decide({ costAmount: 2399, budgetAmount: 3000 }, A0, fleet, cfg).action, "none");
  for (const bad of [null, {}, { costAmount: "1", budgetAmount: 3000 }, { costAmount: 1, budgetAmount: 0 }, { kind: "other" }, { costAmount: NaN, budgetAmount: 3000 }]) assert.equal(decide(bad, A0, fleet, cfg).action, "none", JSON.stringify(bad));
});

test("cost bound: with the planned fleet, the provider-enforced lifetime and the level's request ceiling the structural maximum is far below the per-run budget; missing inputs are NOT bounded", () => {
  // ASSUMED prices (not verified against a current price list): e2-standard-2 0.10 USD/h, e2-small 0.04 USD/h, 40 TRY per USD, egress 0.12 USD/GB, level ceiling 1,500 requests x 1 MiB = 1.5 GB
  const plan = { vms: [{ count: 2, usdPerHour: 0.10 }, { count: 2, usdPerHour: 0.04 }], hours: 2, egressGb: 1.5, usdPerGb: 0.12, storageUsd: 0.5, tryPerUsd: 40, runBudgetTry: 750 };
  const result = maxRunCost(plan);
  assert.equal(result.bounded, true); assert.ok(result.tryAmount! < 750 / 5, `max ${result.tryAmount} TRY`);
  assert.equal(maxRunCost({ ...plan, hours: 400 }).bounded, false, "an unbounded lifetime would exceed the budget");
  assert.equal(maxRunCost({ ...plan, tryPerUsd: 0 }).bounded, false);
  assert.equal(maxRunCost({ ...plan, vms: [] }).bounded, false);
  assert.equal(maxRunCost({ ...plan, egressGb: Number.NaN }).bounded, false);
});
