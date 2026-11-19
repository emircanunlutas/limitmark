import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { assessCostBound, decide, executeDeletes, maxRunCost, maxRunCostWithRate, settle, type CostComponent, type KillConfig, type KillInstance } from "../infra/m1/killswitch/decide.js";

// Review of the TTL reaper and budget stop. Pure decision logic and the deletion/settle helpers, exercised with fakes only: no cloud call, no deletion, no billing change.
// This establishes what the AUTOMATION does under failure; it does not establish that the deployed function works (nothing is deployed) and it does not make spending "strictly bounded".

const NOW = 1_800_000_000_000; const MIN = 60_000;
const cfg: KillConfig = { campaignId: "m1-c1", runId: "run-1", runMaxSeconds: 7200, stopFraction: 0.8 };
const ours = { purpose: "m1-qualification", campaign: "m1-c1", run: "run-1" };
const inst = (name: string, ageMin: number, labels: unknown = ours): KillInstance => ({ name, project: "p", createdMs: NOW - ageMin * MIN, labels: labels as Record<string, string> });
const names = (d: { targets: { name: string }[] }): string[] => d.targets.map((t) => t.name);
const budget = (fraction: number, displayName = "m1-c1-campaign") => ({ costAmount: fraction * 1000, budgetAmount: 1000, budgetDisplayName: displayName });

test("selection: only instances carrying BOTH exact labels are ever selected; missing, empty, wrong-typed or foreign labels are never deleted", () => {
  const fleet: KillInstance[] = [
    inst("ours-a", 1), inst("ours-b", 1, { ...ours, run: "run-0" }),
    { ...inst("no-labels", 1), labels: undefined as unknown as Record<string, string> }, inst("null-labels", 1, null), inst("empty-labels", 1, {}), inst("array-labels", 1, ["purpose"]),
    inst("purpose-only", 1, { purpose: "m1-qualification" }), inst("campaign-only", 1, { campaign: "m1-c1" }),
    inst("other-campaign", 1, { purpose: "m1-qualification", campaign: "m1-c2" }), inst("other-purpose", 1, { purpose: "production", campaign: "m1-c1" }),
    inst("case-variant", 1, { purpose: "M1-QUALIFICATION", campaign: "m1-c1" }), inst("number-label", 1, { purpose: 1, campaign: 1 }),
    { ...inst("x", 1), name: undefined as unknown as string },
  ];
  assert.deepEqual(names(decide(budget(0.9), NOW, fleet, cfg)), ["ours-a", "ours-b"]);
  assert.deepEqual(names(decide(budget(0.9, "m1-c1-run1-run"), NOW, fleet, cfg)), ["ours-a"], "the run-scoped budget selects only the run label");
  assert.deepEqual(names(decide(budget(0.9, "m1-c1-run1-run"), NOW, fleet, { ...cfg, runId: "" })), [], "a run-scoped stop without a run id selects nothing rather than everything");
  assert.deepEqual(names(decide({ kind: "reaper" }, NOW, fleet.map((i) => ({ ...i, createdMs: NOW - 500 * MIN })), cfg)), ["ours-a", "ours-b"]);
  for (const bad of [null, undefined, {}, [], "x", { kind: "other" }, { costAmount: -1, budgetAmount: 10 }, { costAmount: Infinity, budgetAmount: 10 }, { costAmount: 1, budgetAmount: Infinity }, { costAmount: "5", budgetAmount: 10 }]) assert.equal(decide(bad, NOW, fleet, cfg).action, "none", JSON.stringify(bad));
});

test("partial deletion failure: one failing or hanging target never prevents the others, and every outcome is reported", async () => {
  const targets = ["a", "b", "c", "d"].map((name) => ({ name, project: "p" }));
  const outcome = await executeDeletes(targets, async (t) => {
    if (t.name === "b") throw new Error("delete-503");
    if (t.name === "c") return new Promise(() => undefined); // a delayed API answer that never arrives
    return t.name === "d" ? "gone" : "deleted";
  }, { timeoutMs: 30 });
  assert.deepEqual(outcome.deleted, ["a"]); assert.deepEqual(outcome.alreadyGone, ["d"]);
  assert.deepEqual(outcome.failed, [{ name: "b", reason: "delete-503" }, { name: "c", reason: "timeout" }]);
});

test("repeated execution: running the same stop again is harmless (already-gone targets are successes, an empty fleet is a no-op)", async () => {
  const alive = new Set(["a", "b"]);
  const remove = async (t: { name: string }): Promise<"deleted" | "gone"> => { if (!alive.has(t.name)) return "gone"; alive.delete(t.name); return "deleted"; };
  const targets = [{ name: "a", project: "p" }, { name: "b", project: "p" }];
  assert.deepEqual((await executeDeletes(targets, remove, { timeoutMs: 100 })).deleted, ["a", "b"]);
  const second = await executeDeletes(targets, remove, { timeoutMs: 100 });
  assert.deepEqual([second.deleted, second.alreadyGone, second.failed], [[], ["a", "b"], []]);
  assert.equal(decide(budget(0.95), NOW, [], cfg).action, "delete", "the decision itself is stateless");
  assert.deepEqual((await executeDeletes([], remove, { timeoutMs: 100 })).failed, []);
});

test("usage that continues after a stop request: settle reports survivors (and a recreated instance) instead of success, and polls with the injected clock", async () => {
  let polls = 0; const sleeps: number[] = [];
  const draining = async (): Promise<KillInstance[]> => (++polls < 3 ? [inst("slow-delete", 1)] : []);
  const ok = await settle(draining, cfg, { attempts: 6, intervalMs: 5000, runScoped: false, nowMs: () => NOW, sleep: async (ms) => { sleeps.push(ms); } });
  assert.deepEqual([ok.remaining, ok.attempts, sleeps], [[], 3, [5000, 5000]]);
  const stuck = await settle(async () => [inst("never-dies", 1), inst("foreign", 1, { purpose: "production", campaign: "m1-c1" })], cfg, { attempts: 3, intervalMs: 1, runScoped: false, nowMs: () => NOW, sleep: async () => undefined });
  assert.deepEqual(stuck.remaining, ["never-dies"], "only ours remain; the foreign instance is not ours and is ignored");
  let n = 0; // something re-creates a labeled instance after the first clean poll: the next poll sees it
  const recreated = await settle(async () => (++n === 1 ? [] : [inst("recreated", 0)]), cfg, { attempts: 1, intervalMs: 1, runScoped: false, nowMs: () => NOW, sleep: async () => undefined });
  assert.deepEqual(recreated.remaining, [], "one attempt, one clean poll: the caller decides how many polls it needs; this helper never claims more than it saw");
  assert.deepEqual((await settle(async () => [inst("x", 1, { ...ours, run: "run-9" })], cfg, { attempts: 1, intervalMs: 1, runScoped: true, nowMs: () => NOW, sleep: async () => undefined })).remaining, [], "run-scoped: another run's instance is not this run's survivor");
});

test("missing price inputs and exchange-rate uncertainty are NOT bounded", () => {
  const plan = { vms: [{ count: 2, usdPerHour: 0.1 }, { count: 2, usdPerHour: 0.04 }], hours: 2, egressGb: 1.5, usdPerGb: 0.12, storageUsd: 0.5, runBudgetTry: 750 };
  assert.equal(maxRunCost({ ...plan, tryPerUsd: 40 }).bounded, true);
  for (const broken of [{ usdPerHour: undefined }, { hours: undefined }, { egressGb: undefined }, { usdPerGb: undefined }, { storageUsd: undefined }, { runBudgetTry: undefined }]) {
    const input = { ...plan, tryPerUsd: 40, ...broken } as never as Parameters<typeof maxRunCost>[0];
    if ("usdPerHour" in broken) input.vms = [{ count: 1, usdPerHour: undefined as unknown as number }];
    assert.equal(maxRunCost(input).bounded, false, JSON.stringify(broken));
  }
  assert.equal(maxRunCostWithRate(plan, null).reason, "exchange-rate-missing");
  assert.equal(maxRunCostWithRate(plan, { high: 45, verified: false }).bounded, false, "an unverified rate never yields a bound");
  assert.equal(maxRunCostWithRate(plan, { high: 45, verified: false }).reason, "exchange-rate-not-verified");
  assert.equal(maxRunCostWithRate(plan, { high: 45, verified: true }).bounded, true);
  assert.equal(maxRunCostWithRate(plan, { high: 4_000, verified: true }).bounded, false, "a worst-case rate beyond the budget is not bounded");
  assert.equal(maxRunCostWithRate({ ...plan, hours: 1000 }, { high: 45, verified: true }).bounded, false);
});

test("cost enforcement ledger: the planned components are NOT strictly bounded today; estimates, alerts and unverified automation do not count as a bound", () => {
  const ledger = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "infra", "m1", "cost-ledger.json"), "utf8")) as { components: CostComponent[] };
  const today = assessCostBound(ledger.components);
  assert.equal(today.strictlyBounded, false);
  assert.ok(today.unverified.length === ledger.components.length, "every component is unverified");
  assert.ok(today.unverified.some((u) => u.name.startsWith("network egress") && u.reason === "not-enforced"));
  assert.ok(today.unverified.some((u) => u.name.startsWith("provider budget alerts") && u.reason === "no-estimate"));
  assert.ok(today.residual.some((r) => r.name.startsWith("evidence bucket")) && today.residual.some((r) => r.name.startsWith("persistent disks")), "residual charges after shutdown are listed");
  // even with everything marked verified, a component with no enforcement (or only an alert) keeps the answer false
  const allVerified = ledger.components.map((c) => ({ ...c, verified: true }));
  assert.equal(assessCostBound(allVerified).strictlyBounded, false);
  // only when EVERY component is a verified provider limit or automated stop with an estimate is it bounded
  const strong = ledger.components.filter((c) => c.enforcement === "provider_limit").map((c) => ({ ...c, verified: true }));
  assert.equal(assessCostBound(strong).strictlyBounded, true);
  assert.equal(assessCostBound([]).strictlyBounded, false);
  assert.equal(assessCostBound([{ ...strong[0]!, estimatedUsd: null }]).strictlyBounded, false);
  assert.equal(assessCostBound([{ ...strong[0]!, verified: false }]).strictlyBounded, false);
});
