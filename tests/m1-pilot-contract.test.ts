import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assessCostBound, maxRunCostWithRate, type CostComponent } from "../infra/m1/killswitch/decide";
import { runCli } from "../lab/m1/cli";
import { CLEANUP_CATEGORIES, PILOT_CONTRACT, evaluatePilotResults } from "../lab/m1/pilot";

// The pilot contract is evaluated, never executed here: these tests prove that a recorded pilot result cannot be a PILOT_PASS unless it is complete, ordered and clean, and that the
// pilot cost ledger does not claim a spending cap. Nothing is provisioned and no traffic is generated.

const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const T0 = Date.parse("2026-11-12T10:00:00Z"); const iso = (min: number): string => new Date(T0 + min * 60_000).toISOString().replace(/\.\d{3}Z$/u, "Z");
function complete(): Record<string, unknown> {
  return {
    schema: "m1-pilot-results-v1", runId: "pilot-r1", commit: "a".repeat(40), authorizationSha256: "b".repeat(64), trafficProfile: "smoke", observationProfile: "REMOTE_PRIVATE", attackTraffic: false, qualificationWorkload: false,
    checks: PILOT_CONTRACT.map((def, i) => ({ id: def.id, status: "PASS", observedAt: iso(i * 5), evidence: def.evidenceKinds.map((kind) => ({ kind, ref: kind === "real-budget-delivery-status" ? "not-verified" : `gs://pilot/${def.id}/${kind}.json` })) })),
    cleanup: { verifiedAt: iso(120), remainingDisposableResources: [], inventory: Object.fromEntries(CLEANUP_CATEGORIES.map((c) => [c, { remaining: 0 }])) },
  };
}

test("the contract is exactly the ten required checks, in order, each with required evidence kinds and no attack traffic", () => {
  assert.deepEqual(PILOT_CONTRACT.map((c) => c.id), ["vm_creation_and_expiry", "private_dns", "generator_to_target", "canary_to_target", "target_to_collector", "evidence_bucket_permissions", "iap_access", "ttl_reaper", "budget_stop", "resource_cleanup"]);
  for (const c of PILOT_CONTRACT) { assert.ok(c.evidenceKinds.length >= 1, c.id); assert.ok(c.probe.length > 20 && c.passWhen.length > 20, c.id); }
  const text = JSON.stringify(PILOT_CONTRACT).toLowerCase();
  for (const forbidden of ["ba0_field", "salvo", "flood", "load test"]) assert.ok(!text.includes(forbidden), forbidden);
});

test("a complete, ordered, clean record is PILOT_PASS; the verdict is not a qualification and is deterministic", () => {
  const a = evaluatePilotResults(complete()); const b = evaluatePilotResults(complete());
  assert.deepEqual([a.outcome, a.reasons], ["PILOT_PASS", []]); assert.deepEqual(a, b);
  assert.equal(a.checks.length, 10); assert.ok(a.checks.every((c) => c.status === "PASS"));
});

test("a missing check, missing evidence kind, bad timestamp or non-PASS status is INCOMPLETE; a recorded FAIL is REJECT", () => {
  const without = complete(); (without.checks as { id: string }[]).splice(3, 1);
  const r1 = evaluatePilotResults(without); assert.equal(r1.outcome, "INCOMPLETE"); assert.ok(r1.reasons.includes("m1.pilot.check_missing.canary_to_target"));
  const kind = complete(); ((kind.checks as { id: string; evidence: unknown[] }[]).find((c) => c.id === "evidence_bucket_permissions")!).evidence.pop();
  assert.equal(evaluatePilotResults(kind).outcome, "INCOMPLETE");
  const time = complete(); (time.checks as { observedAt: string }[])[2]!.observedAt = "soon"; assert.equal(evaluatePilotResults(time).outcome, "INCOMPLETE");
  const status = complete(); (status.checks as { status: string }[])[1]!.status = "SKIPPED"; assert.equal(evaluatePilotResults(status).outcome, "INCOMPLETE");
  const empty = complete(); ((empty.checks as { evidence: { ref: string }[] }[])[0]!).evidence[0]!.ref = ""; assert.equal(evaluatePilotResults(empty).outcome, "INCOMPLETE");
  const failed = complete(); (failed.checks as { status: string }[])[6]!.status = "FAIL"; const r2 = evaluatePilotResults(failed); assert.equal(r2.outcome, "REJECT"); assert.ok(r2.reasons.includes("m1.pilot.check_failed.iap_access"));
});

test("teardown: resources left behind or a cleanup that did not happen last are REJECT; a missing cleanup record is INCOMPLETE", () => {
  const left = complete(); (left.cleanup as { remainingDisposableResources: string[] }).remainingDisposableResources = ["disk/orphan-1"];
  const r1 = evaluatePilotResults(left); assert.equal(r1.outcome, "REJECT"); assert.ok(r1.reasons.includes("m1.pilot.resources_remain_after_teardown"));
  const early = complete(); ((early.checks as { id: string; observedAt: string }[]).find((c) => c.id === "resource_cleanup")!).observedAt = iso(-30);
  const r2 = evaluatePilotResults(early); assert.equal(r2.outcome, "REJECT"); assert.ok(r2.reasons.includes("m1.pilot.cleanup_not_last"));
  const none = complete(); delete none.cleanup; assert.equal(evaluatePilotResults(none).outcome, "INCOMPLETE");
  const nullList = complete(); nullList.cleanup = { verifiedAt: iso(120), remainingDisposableResources: null }; assert.equal(evaluatePilotResults(nullList).outcome, "INCOMPLETE");
});

test("scope: attack traffic, a qualification workload, a non-smoke profile, a non-pilot run id, unknown or duplicated checks, foreign schema are never PILOT_PASS", () => {
  for (const [edit, reason] of [
    [(r: Record<string, unknown>) => { r.attackTraffic = true; }, "m1.pilot.attack_traffic_not_excluded"], [(r: Record<string, unknown>) => { r.qualificationWorkload = true; }, "m1.pilot.qualification_workload_not_excluded"],
    [(r: Record<string, unknown>) => { r.trafficProfile = "ba0-field"; }, "m1.pilot.traffic_profile_not_smoke"], [(r: Record<string, unknown>) => { r.runId = "run-1"; }, "m1.pilot.run_id_not_a_pilot_id"],
    [(r: Record<string, unknown>) => { r.commit = "short"; }, "m1.pilot.commit_missing"], [(r: Record<string, unknown>) => { r.authorizationSha256 = ""; }, "m1.pilot.authorization_digest_missing"],
    [(r: Record<string, unknown>) => { (r.checks as unknown[]).push({ id: "qualification_run", status: "PASS" }); }, "m1.pilot.check_unknown.qualification_run"],
    [(r: Record<string, unknown>) => { (r.checks as unknown[]).push(clone((r.checks as unknown[])[0])); }, "m1.pilot.check_duplicated.vm_creation_and_expiry"],
  ] as [(r: Record<string, unknown>) => void, string][]) { const r = complete(); edit(r); const v = evaluatePilotResults(r); assert.equal(v.outcome, "REJECT", reason); assert.ok(v.reasons.includes(reason), `${reason}: ${v.reasons.join(",")}`); }
  assert.equal(evaluatePilotResults({ ...complete(), schema: "other" }).outcome, "ERROR");
  for (const bad of [null, [], "x", 3]) assert.equal(evaluatePilotResults(bad).outcome, "ERROR");
  assert.equal(evaluatePilotResults({ ...complete(), checks: "x" }).outcome, "ERROR");
});

test("budget stop: the record must say whether a REAL budget notification was verified; any other claim is refused", () => {
  const r = complete(); (((r.checks as { id: string; evidence: { kind: string; ref: string }[] }[]).find((c) => c.id === "budget_stop")!).evidence.find((e) => e.kind === "real-budget-delivery-status")!).ref = "assumed-fine";
  assert.equal(evaluatePilotResults(r).outcome, "INCOMPLETE");
});

test("CLI pilot: PILOT_PASS exits 0, INCOMPLETE 20, REJECT 10, unreadable 30; the shipped template is never a pass", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "m1-pilot-cli-"));
  try {
    const write = (name: string, v: unknown): string => { const f = path.join(dir, name); fs.writeFileSync(f, JSON.stringify(v)); return f; };
    const run = async (file: string) => { const lines: string[] = []; const code = await runCli(["pilot", "--results", file], { stdout: (l) => lines.push(l) }); return { code, out: JSON.parse(lines[0]!) as { outcome: string; details: { qualification: string } } }; };
    const ok = await run(write("ok.json", complete())); assert.deepEqual([ok.code, ok.out.outcome, ok.out.details.qualification], [0, "PILOT_PASS", "not_applicable"]);
    const partial = complete(); (partial.checks as unknown[]).pop(); assert.equal((await run(write("partial.json", partial))).code, 20);
    const failed = complete(); (failed.checks as { status: string }[])[0]!.status = "FAIL"; assert.equal((await run(write("failed.json", failed))).code, 10);
    assert.equal((await run(path.join(dir, "absent.json"))).code, 30);
    const template = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "infra", "m1", "templates", "pilot-results.template.json"), "utf8")) as Record<string, unknown>; delete template._comment;
    assert.notEqual((await run(write("template.json", template))).code, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("pilot cost ledger: every enforcement row is unverified, so it is NOT strictly bounded; the structural estimate fits the proposed 150 TRY maximum under the assumed prices, and says so as an assumption", () => {
  const ledger = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "infra", "m1", "pilot-cost-ledger.json"), "utf8")) as { components: CostComponent[]; assumptions: Record<string, number> };
  const assessed = assessCostBound(ledger.components);
  assert.equal(assessed.strictlyBounded, false); assert.ok(assessed.unverified.length >= 6);
  assert.ok(ledger.components.every((c) => c.verified === false));
  const estimateTry = assessed.estimatedUsd * ledger.assumptions["try per usd (high case)"]!;
  assert.ok(estimateTry < 150, `estimate ${estimateTry}`);
  const bound = maxRunCostWithRate({ vms: [{ count: 2, usdPerHour: 0.1 }, { count: 2, usdPerHour: 0.04 }], hours: 2, egressGb: 0.01, usdPerGb: 0.12, storageUsd: 0.5, runBudgetTry: 150 }, { high: 45, verified: false });
  assert.equal(bound.bounded, false, "an unverified exchange rate is never a bound");
  assert.ok(ledger.components.some((c) => /orphaned disks/u.test(c.residualAfterStop)) && ledger.components.some((c) => c.enforcement === "alert"));
});

test("the pilot record must declare the REMOTE_PRIVATE observation profile: absent is INCOMPLETE, any other is REJECT", () => {
  const absent = complete(); delete absent.observationProfile; assert.equal(evaluatePilotResults(absent).outcome, "INCOMPLETE");
  for (const profile of ["LOCAL_LOOPBACK", "PUBLIC", ""]) { const r = complete(); r.observationProfile = profile; const v = evaluatePilotResults(r); assert.equal(v.outcome, "REJECT", profile); assert.ok(v.reasons.includes("m1.pilot.observation_profile_not_remote_private")); }
});

test("cleanup inventory: every category must be listed; a remaining resource fails unless it is a bucket inside retention or a project pending deletion with a stated reason; budgets are not retainable", () => {
  const withEntry = (category: string, entry: unknown): Record<string, unknown> => { const r = complete(); ((r.cleanup as { inventory: Record<string, unknown> }).inventory)[category] = entry; return r; };
  const gone = complete(); delete (gone.cleanup as { inventory?: unknown }).inventory; assert.equal(evaluatePilotResults(gone).outcome, "INCOMPLETE");
  const partial = complete(); delete ((partial.cleanup as { inventory: Record<string, unknown> }).inventory).billing_budgets; const p = evaluatePilotResults(partial); assert.equal(p.outcome, "INCOMPLETE"); assert.ok(p.reasons.includes("m1.pilot.cleanup_inventory_category_missing.billing_budgets"));
  for (const bad of [{ remaining: -1 }, { remaining: 1.5 }, { remaining: "0" }, null]) assert.equal(evaluatePilotResults(withEntry("disks", bad)).outcome, "INCOMPLETE");
  for (const category of ["instances", "disks", "scheduler_jobs", "functions", "eventarc_triggers", "billing_budgets", "firewall_rules"]) { const v = evaluatePilotResults(withEntry(category, { remaining: 1, retained: "I would like to keep it" })); assert.equal(v.outcome, "REJECT", category); assert.ok(v.reasons.includes(`m1.pilot.cleanup_resource_remains.${category}`)); }
  assert.equal(evaluatePilotResults(withEntry("buckets", { remaining: 1, retained: "evidence inside the 30 day retention" })).outcome, "PILOT_PASS");
  assert.equal(evaluatePilotResults(withEntry("projects", { remaining: 4, retained: "pending provider deletion" })).outcome, "PILOT_PASS");
  assert.equal(evaluatePilotResults(withEntry("projects", { remaining: 4 })).outcome, "REJECT", "retained needs a reason");
});
