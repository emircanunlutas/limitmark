import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalJson } from "../lab/evidence/manifest";
import { runCli } from "../lab/m1/cli";
import { validateOwnerThresholds, type OwnerCanaryThresholds } from "../lab/m1/canary-thresholds";
import { PARAMETERS_DIGEST } from "../lab/m1/commitment";
import { evaluatePreflight, parseVariables, type GitProbe, type PreflightInput, type PreflightMode } from "../lab/m1/preflight";

// The preflight is a read-only go/no-go. These tests use CONSISTENT TEST DATA that exists only here: it proves the gate's logic, it is not a real plan input and is never evidence
// that a real plan is ready. The real Terraform sources are read from the repository so the structural scan is exercised against what will actually be planned.

const NOW = Date.parse("2026-11-10T12:00:00Z"); const iso = (offsetMs: number): string => new Date(NOW + offsetMs).toISOString().replace(/\.\d{3}Z$/u, "Z");
const SHA = "a".repeat(40); const sha = (value: unknown): string => createHash("sha256").update(canonicalJson(value)).digest("hex");
const REPO = path.join(__dirname, ".."); const tfDir = path.join(REPO, "infra", "m1");
const terraform: Record<string, string> = Object.fromEntries(fs.readdirSync(tfDir).filter((n) => n.endsWith(".tf")).map((n) => [n, fs.readFileSync(path.join(tfDir, n), "utf8")]));
const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const fixedThresholds = (): OwnerCanaryThresholds => ({
  schema: "m1-canary-thresholds-v1", approval: { approvedBy: "owner", approvedAt: "2026-11-09T10:00:00Z", reference: "decision-O-5" }, baselineMeasurementIds: ["b1", "b2", "b3"],
  maxLatencyMs: { baseline: { p50: 10, p95: 20, p99: 30 }, window: { p50: 50, p95: 100, p99: 200 }, recovery: { p50: 20, p95: 40, p99: 60 } }, maxRecoveryTimeToBaselineMs: 5_000, maxHeartbeatGapMs: 1_000, operationalActions: ["profile_view"],
});

function build(mode: PreflightMode) {
  const pilot = mode === "pilot";
  const tfvars: Record<string, unknown> = {
    folder_id: "123456789012", billing_account: "0A1B2C-3D4E5F-6A7B8C", project_prefix: "m1lab", campaign_id: pilot ? "pilot-c1" : "camp-c1", run_id: pilot ? "pilot-r1" : "run-r1", plane_port: 9443,
    authorized_target_cidr: "10.10.0.10/32", authorized_generator_cidr: "10.20.0.10/32", canary_cidr: "10.30.0.10/32", collector_cidr: "10.30.0.11/32",
    target_image: "projects/img-proj-one/global/images/target-v1", generator_image: "projects/img-proj-one/global/images/generator-v1", observer_image: "projects/img-proj-two/global/images/observer-v1",
    operators_group: "group:ops-team@lab.test", observers_group: "group:obs-team@lab.test", custodian_group: "group:cust-team@lab.test",
    create_vms: false, run_max_seconds: 7200, budget_currency: "TRY", run_budget: pilot ? 150 : 750, campaign_budget: pilot ? 150 : 3000, retention_days: 30, lock_retention: false,
  };
  const cost = {
    schema: "m1-cost-inputs-v1", priceSource: { name: "provider price list", checkedAt: iso(-3_600_000) }, fx: { tryPerUsdHigh: 45, checkedAt: iso(-3_600_000), source: "central bank daily rate", verified: true },
    vms: [{ role: "std", count: 2, usdPerHour: 0.1 }, { role: "small", count: 2, usdPerHour: 0.04 }], hours: 2, egressGb: 0.01, usdPerGb: 0.12, storageUsd: 0.5,
  };
  const thresholds = pilot ? undefined : fixedThresholds();
  const authorization: Record<string, unknown> = {
    schema: "m1-authorization-v1", mode, lane: "PRIVATE-LANE", publicIngress: false, approval: { approvedBy: "owner", approvedAt: iso(-3_600_000), expiresAt: iso(24 * 3_600_000), reference: "GO-1" },
    commit: SHA, parametersId: "ba0-field-v1", parametersDigest: PARAMETERS_DIGEST, campaignId: tfvars.campaign_id, runId: tfvars.run_id,
    targetCidr: tfvars.authorized_target_cidr, generatorCidr: tfvars.authorized_generator_cidr, canaryCidr: tfvars.canary_cidr, collectorCidr: tfvars.collector_cidr,
    budgetTry: { run: tfvars.run_budget, campaign: tfvars.campaign_budget }, acknowledgesUnverifiedSpendCap: true, tfvarsSha256: sha(tfvars), costInputsSha256: sha(cost),
    thresholdsSha256: thresholds ? validateOwnerThresholds(thresholds).digest : null, privateLaneAcceptedAsExternalGenerator: pilot ? null : true, retentionLockApproved: false,
  };
  const git: GitProbe = { sha: SHA, trackedChanges: 0, untracked: 0 };
  const input: PreflightInput = { mode, nowMs: NOW, git, expectedCommit: null, authorization, tfvars, cost, thresholds, loadProblems: [], terraform };
  return input;
}
/** mutates the base, then keeps the owner's digests consistent unless the test is about a post-approval change */
function variant(mode: PreflightMode, mutate: (i: PreflightInput & { authorization: Record<string, unknown>; tfvars: Record<string, unknown>; cost: Record<string, unknown> }) => void, rebind = false): ReturnType<typeof evaluatePreflight> {
  const input = clone(build(mode)) as PreflightInput & { authorization: Record<string, unknown>; tfvars: Record<string, unknown>; cost: Record<string, unknown> };
  input.terraform = terraform; mutate(input);
  if (rebind) { input.authorization.tfvarsSha256 = sha(input.tfvars); input.authorization.costInputsSha256 = sha(input.cost); }
  return evaluatePreflight(input);
}
const outcomeOf = (r: ReturnType<typeof evaluatePreflight>, reason?: string): string => { if (reason !== undefined) assert.ok(r.reasons.includes(reason), `${reason} not in ${r.reasons.join(",")}`); return r.outcome; };

test("the real variables.tf has the owner-decision variables without defaults, and the explicit-statement list in the gate is a subset of what is declared", () => {
  const declared = parseVariables(terraform["variables.tf"]!);
  const required = declared.filter((d) => !d.hasDefault).map((d) => d.name).sort();
  assert.deepEqual(required, ["authorized_generator_cidr", "authorized_target_cidr", "billing_account", "campaign_id", "canary_cidr", "collector_cidr", "custodian_group", "folder_id", "generator_image", "observer_image", "observers_group", "operators_group", "plane_port", "project_prefix", "run_id", "target_image"]);
  for (const name of ["run_budget", "campaign_budget", "run_max_seconds", "budget_currency", "retention_days", "lock_retention", "create_vms"]) assert.ok(declared.some((d) => d.name === name && d.hasDefault), name);
});

test("consistent inputs PASS in both modes, are deterministic, and say plainly that nothing is authorized or capped by the gate", () => {
  for (const mode of ["pilot", "campaign"] as const) {
    const first = evaluatePreflight(build(mode)); const second = evaluatePreflight(build(mode));
    assert.equal(first.outcome, "PASS", first.reasons.join(","));
    assert.deepEqual(first, second);
    assert.ok(first.limitations.some((l) => l.includes("does not prove a spending cap")));
    assert.equal(first.checks.length, 13);
  }
});

test("a missing authorization or an unknown cost can never produce PASS", () => {
  assert.equal(outcomeOf(variant("pilot", (i) => { (i as { authorization: unknown }).authorization = undefined; }), "m1.preflight.authorization_not_supplied"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { (i as { cost: unknown }).cost = undefined; }), "m1.preflight.cost_inputs_not_supplied"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.cost.fx = { tryPerUsdHigh: null, checkedAt: iso(0), source: "x-rate", verified: false }; }, true), "m1.preflight.exchange_rate_unknown"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { (i.cost.vms as { usdPerHour: unknown }[])[0]!.usdPerHour = null; }, true), "m1.preflight.vm_prices_unknown"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.authorization.approval = { approvedBy: null, approvedAt: null, expiresAt: null, reference: null }; }), "m1.preflight.authorization_not_approved_by_owner"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.authorization.acknowledgesUnverifiedSpendCap = false; }), "m1.preflight.owner_has_not_acknowledged_that_spending_is_not_hard_capped"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.authorization.budgetTry = { run: null, campaign: null }; }), "m1.preflight.owner_budget_not_stated"), "INCOMPLETE");
});

test("exchange-rate and price freshness: unverified or stale is INCOMPLETE, a timestamp from the future or malformed is ERROR", () => {
  assert.equal(outcomeOf(variant("pilot", (i) => { (i.cost.fx as { verified: boolean }).verified = false; }, true), "m1.preflight.exchange_rate_not_verified"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { (i.cost.fx as { checkedAt: string }).checkedAt = iso(-25 * 3_600_000); }, true), "m1.preflight.exchange_rate_stale"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { (i.cost.priceSource as { checkedAt: string }).checkedAt = iso(-48 * 3_600_000); }, true), "m1.preflight.prices_stale"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { (i.cost.fx as { checkedAt: string }).checkedAt = iso(3_600_000); }, true), "m1.preflight.exchange_rate_time_in_future"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { (i.cost.fx as { checkedAt: string }).checkedAt = "yesterday"; }, true), "m1.preflight.exchange_rate_time_malformed"), "ERROR");
});

test("cost and budget limits: over the run budget, above the planning ceilings, hours below the enforced lifetime, wrong fleet size and a currency other than TRY are ERROR", () => {
  assert.equal(outcomeOf(variant("pilot", (i) => { (i.cost.fx as { tryPerUsdHigh: number }).tryPerUsdHigh = 500; }, true)), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.authorization.budgetTry = { run: 751, campaign: 3000 }; i.tfvars.run_budget = 751; i.tfvars.campaign_budget = 3000; }, true), "m1.preflight.run_budget_above_planning_ceiling"), "ERROR");
  assert.equal(outcomeOf(variant("campaign", (i) => { i.authorization.budgetTry = { run: 750, campaign: 3001 }; i.tfvars.campaign_budget = 3001; }, true), "m1.preflight.campaign_budget_above_planning_ceiling"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.cost.hours = 1; }, true), "m1.preflight.cost_hours_below_the_enforced_vm_lifetime"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { (i.cost.vms as { count: number }[])[0]!.count = 3; }, true), "m1.preflight.vm_count_is_not_the_fixed_fleet_of_four"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.budget_currency = "USD"; }, true), "m1.preflight.budget_currency_not_try"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.run_budget = 200; }, true), "m1.preflight.tfvars_run_budget_differs_from_authorization"), "ERROR");
  const campaign = variant("campaign", (i) => { i.authorization.budgetTry = { run: 750, campaign: 100 }; i.tfvars.campaign_budget = 100; }, true);
  assert.equal(outcomeOf(campaign, "m1.preflight.estimated_total_cost_above_campaign_budget"), "ERROR");
});

test("TTL and budget configuration: lifetime out of range or shorter than the run plus the target minimum, and defaults that would silently decide budget or retention, are refused", () => {
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.run_max_seconds = 30_000; }, true), "m1.preflight.run_max_seconds_out_of_range"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.run_max_seconds = 600; }, true), "m1.preflight.run_max_seconds_out_of_range"), "ERROR");
  for (const name of ["run_budget", "campaign_budget", "run_max_seconds", "retention_days", "lock_retention", "create_vms", "budget_currency"]) assert.equal(outcomeOf(variant("pilot", (i) => { delete i.tfvars[name]; }, true), `m1.preflight.tfvars_must_state.${name}`), "INCOMPLETE", name);
});

test("approval is bound to the exact values: a changed tfvars, cost or thresholds file after approval, an expired or future approval and a mismatched commit are ERROR", () => {
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.plane_port = 9444; }), "m1.preflight.tfvars_differ_from_what_the_owner_approved"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { (i.cost.vms as { usdPerHour: number }[])[0]!.usdPerHour = 0.01; }), "m1.preflight.cost_inputs_differ_from_what_the_owner_approved"), "ERROR");
  assert.equal(outcomeOf(variant("campaign", (i) => { const t = i.thresholds as OwnerCanaryThresholds; t.maxLatencyMs.window.p95 = 101; }), "m1.preflight.thresholds_differ_from_what_the_owner_approved"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { (i.authorization.approval as { expiresAt: string }).expiresAt = iso(-1000); }), "m1.preflight.authorization_expired"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { (i.authorization.approval as { approvedAt: string }).approvedAt = iso(1000); }), "m1.preflight.authorization_approved_in_the_future"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { (i.authorization.approval as { expiresAt: string }).expiresAt = iso(100 * 3_600_000); }), "m1.preflight.authorization_window_exceeds_72h"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.authorization.mode = "campaign"; }), "m1.preflight.authorization_mode_differs"), "ERROR");
});

test("git: tracked changes, a head that is not the authorized or expected commit are ERROR; untracked files are INCOMPLETE (run from a clean worktree); no authorized commit is INCOMPLETE", () => {
  assert.equal(outcomeOf(variant("pilot", (i) => { i.git = { sha: SHA, trackedChanges: 2, untracked: 0 }; }), "m1.preflight.git_tracked_changes"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.git = { sha: "b".repeat(40), trackedChanges: 0, untracked: 0 }; }), "m1.preflight.head_differs_from_authorized_commit"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.expectedCommit = "c".repeat(40); }), "m1.preflight.head_differs_from_expected_commit"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.git = { sha: SHA, trackedChanges: 0, untracked: 3 }; }), "m1.preflight.git_untracked_files_present_use_a_clean_worktree"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.authorization.commit = "__OWNER_REQUIRED__"; }), "m1.preflight.commit_not_pinned_in_authorization"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.git = null; }), "m1.preflight.git_state_unreadable"), "ERROR");
});

test("pinned parameters must be the code's: a different id or digest is ERROR, an absent pin is INCOMPLETE", () => {
  assert.equal(outcomeOf(variant("pilot", (i) => { i.authorization.parametersDigest = "0".repeat(64); }), "m1.preflight.parameters_digest_differs_from_code"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.authorization.parametersId = "ba0-field-c2-v1"; }), "m1.preflight.parameters_id_differs_from_code"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { delete i.authorization.parametersDigest; }), "m1.preflight.parameters_not_pinned_in_authorization"), "INCOMPLETE");
});

test("terraform variables and network scope: placeholders and unset owner decisions are INCOMPLETE; unknown keys, bad ports, addresses outside their ranges, mismatches with the authorization are ERROR", () => {
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.folder_id = "__OWNER_REQUIRED__"; }, true), "m1.preflight.tfvars_unset.folder_id"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.operators_group = "REPLACE_ME"; }, true), "m1.preflight.tfvars_unset.operators_group"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { delete i.tfvars.plane_port; }, true), "m1.preflight.tfvars_unset.plane_port"), "INCOMPLETE");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars._comment = "leftover"; }, true), "m1.preflight.tfvars_unknown_variable._comment"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.plane_port = 443; }, true), "m1.preflight.plane_port_invalid"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.authorized_target_cidr = "10.10.0.0/24"; i.authorization.targetCidr = "10.10.0.0/24"; }, true), "m1.preflight.authorized_target_cidr_invalid"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.authorized_target_cidr = "10.10.0.11/32"; }, true), "m1.preflight.authorized_target_cidr_differs_from_authorization"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.collector_cidr = i.tfvars.canary_cidr; i.authorization.collectorCidr = i.authorization.canaryCidr; }, true), "m1.preflight.collector_equals_canary"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.campaign_id = "other"; }, true), "m1.preflight.campaign_id_differs_from_authorization"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.run_id = "run-1"; i.authorization.runId = "run-1"; }, true), "m1.preflight.pilot_run_id_must_start_with_pilot-"), "ERROR");
  assert.equal(outcomeOf(variant("campaign", (i) => { i.tfvars.run_id = "pilot-9"; i.authorization.runId = "pilot-9"; }, true), "m1.preflight.campaign_run_id_must_not_be_a_pilot_id"), "ERROR");
});

test("identities and custody: groups must be distinct group principals, images pinned resources (never a family) and different from each other, billing account and folder well formed, retention lock never in a pilot", () => {
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.observers_group = i.tfvars.operators_group; }, true), "m1.preflight.custody_groups_not_distinct"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.custodian_group = "user:person@lab.test"; }, true), "m1.preflight.custodian_group_malformed_or_not_a_group"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.target_image = "projects/img-proj-one/global/images/family/stable"; }, true), "m1.preflight.target_image_not_a_pinned_image_resource"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.observer_image = i.tfvars.target_image; }, true), "m1.preflight.images_not_distinct"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.billing_account = "not-a-billing-id"; }, true), "m1.preflight.billing_account_malformed"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.folder_id = "folders/12"; }, true), "m1.preflight.folder_id_malformed"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.lock_retention = true; }, true), "m1.preflight.retention_lock_not_allowed_in_a_pilot"), "ERROR");
  assert.equal(outcomeOf(variant("campaign", (i) => { i.tfvars.lock_retention = true; }, true), "m1.preflight.retention_lock_not_approved_by_owner"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.tfvars.retention_days = 7; }, true), "m1.preflight.retention_below_30_days"), "ERROR");
});

test("lane: only the private lane, and public ingress is refused outright; a campaign also needs the owner's decision on the private-lane external-generator question", () => {
  assert.equal(outcomeOf(variant("pilot", (i) => { i.authorization.publicIngress = true; }), "m1.preflight.public_ingress_must_be_false"), "ERROR");
  assert.equal(outcomeOf(variant("pilot", (i) => { i.authorization.lane = "PUBLIC-INGRESS"; }), "m1.preflight.lane_must_be_private_lane"), "ERROR");
  assert.equal(outcomeOf(variant("campaign", (i) => { i.authorization.privateLaneAcceptedAsExternalGenerator = null; }), "m1.preflight.owner_has_not_decided_private_lane_counts_as_external_generator"), "INCOMPLETE");
});

test("campaign needs a FIXED canary thresholds record and a heartbeat limit; a pilot does not (no qualification evidence is evaluated)", () => {
  assert.equal(outcomeOf(variant("campaign", (i) => { i.thresholds = undefined; }), "m1.preflight.canary_thresholds_unset"), "INCOMPLETE");
  const unsetRecord = JSON.parse(fs.readFileSync(path.join(tfDir, "canary-thresholds.template.json"), "utf8")) as unknown;
  const unset = variant("campaign", (i) => { i.thresholds = unsetRecord; i.authorization.thresholdsSha256 = null; });
  assert.equal(unset.outcome, "INCOMPLETE"); assert.ok(unset.reasons.includes("m1.preflight.heartbeat_limit_not_fixed_by_owner"));
  assert.equal(outcomeOf(variant("campaign", (i) => { (i.thresholds as OwnerCanaryThresholds).maxHeartbeatGapMs = -1; i.authorization.thresholdsSha256 = null; }), "m1.preflight.canary_thresholds_invalid"), "ERROR");
  assert.equal(evaluatePreflight(build("pilot")).checks.find((c) => c.id === "heartbeat_limit")!.status, "PASS");
});

test("terraform structure: each construct the isolation and cost story relies on is required, an external IP or an unlocked-default change is ERROR, unreadable sources are INCOMPLETE", () => {
  const scan = (edit: (files: Record<string, string>) => void): ReturnType<typeof evaluatePreflight> => { const files = { ...terraform }; edit(files); const input = build("pilot"); input.terraform = files; return evaluatePreflight(input); };
  assert.equal(outcomeOf(scan((f) => { f["compute.tf"] = f["compute.tf"]!.replaceAll("max_run_duration", "max_duration_x"); }), "m1.preflight.terraform_missing.max_run_duration"), "ERROR");
  assert.equal(outcomeOf(scan((f) => { f["compute.tf"] = f["compute.tf"]!.replaceAll("termination_action", "termination_x"); }), "m1.preflight.terraform_missing.termination_action_delete"), "ERROR");
  assert.equal(outcomeOf(scan((f) => { f["compute.tf"] += '\nresource "x" "y" { access_config { } }\n'; }), "m1.preflight.terraform_external_ip_present"), "ERROR");
  assert.equal(outcomeOf(scan((f) => { f["variables.tf"] = f["variables.tf"]!.replace(/(variable "lock_retention"[\s\S]*?default\s*=\s*)false/u, "$1true"); }), "m1.preflight.lock_retention_default_not_false"), "ERROR");
  assert.equal(outcomeOf(scan((f) => { f["killswitch.tf"] = f["killswitch.tf"]!.replace('"*/5 * * * *"', '"0 * * * *"'); }), "m1.preflight.terraform_missing.ttl_reaper_schedule"), "ERROR");
  const absent = build("pilot"); absent.terraform = null; assert.equal(evaluatePreflight(absent).outcome, "INCOMPLETE");
});

test("CLI: exit 0 for PASS, 20 for INCOMPLETE, 30 for ERROR and unreadable inputs; one deterministic JSON line; nothing is written and nothing is marked provisioned", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "m1-preflight-cli-"));
  try {
    const input = build("pilot") as PreflightInput & { authorization: Record<string, unknown> };
    const write = (name: string, value: unknown): string => { const file = path.join(dir, name); fs.writeFileSync(file, JSON.stringify(value)); return file; };
    const files = { authorization: write("auth.json", input.authorization), tfvars: write("vars.json", input.tfvars), cost: write("cost.json", input.cost) };
    const run = async (args: string[]) => { const lines: string[] = []; const code = await runCli(args, { stdout: (l) => lines.push(l), now: new Date(NOW), git: () => ({ sha: SHA, trackedChanges: 0, untracked: 0 }) }); assert.equal(lines.length, 1); return { code, out: JSON.parse(lines[0]!) as { outcome: string; details: { provisioned: boolean; checks: unknown[] }; reasons: string[] } }; };
    const base = ["preflight", "--mode", "pilot", "--authorization", files.authorization, "--tfvars", files.tfvars, "--cost", files.cost];
    const before = fs.readdirSync(dir).sort().join();
    const pass = await run(base); assert.deepEqual([pass.code, pass.out.outcome, pass.out.details.provisioned], [0, "PASS", false]);
    assert.deepEqual(await run(base), pass, "deterministic");
    assert.equal((await run(["preflight", "--mode", "pilot", "--tfvars", files.tfvars, "--cost", files.cost])).code, 20, "no authorization supplied");
    assert.equal((await run(["preflight", "--mode", "pilot", "--authorization", files.authorization, "--tfvars", files.tfvars])).code, 20, "no cost supplied");
    assert.equal((await run(["preflight", "--mode", "campaign", ...base.slice(3)])).code, 30, "a pilot authorization is not a campaign authorization");
    fs.writeFileSync(path.join(dir, "broken.json"), "{not json");
    const broken = await run(["preflight", "--mode", "pilot", "--authorization", path.join(dir, "broken.json"), "--tfvars", files.tfvars, "--cost", files.cost]);
    assert.equal(broken.code, 30); assert.ok(broken.out.reasons.includes("m1.preflight.authorization_unreadable_or_not_json"));
    assert.equal((await run(["preflight", "--mode", "pilot", "--authorization", path.join(dir, "absent.json"), "--tfvars", files.tfvars, "--cost", files.cost])).code, 30);
    assert.equal((await run([...base, "--commit", "d".repeat(40)])).code, 30, "expected commit differs from head");
    const lines: string[] = []; assert.equal(await runCli(["preflight", "--mode", "weekly"], { stdout: (l) => lines.push(l) }), 64);
    assert.equal(await runCli(["preflight", "--mode", "pilot", "--bogus", "x"], { stdout: (l) => lines.push(l) }), 64);
    assert.equal(fs.readdirSync(dir).filter((n) => n !== "broken.json").sort().join(), before, "no file was created or removed by the preflight");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("the shipped templates are INCOMPLETE, never PASS: every owner value is an unset placeholder (the _comment key must be removed from a real copy)", () => {
  const read = (name: string): Record<string, unknown> => JSON.parse(fs.readFileSync(path.join(tfDir, "templates", name), "utf8")) as Record<string, unknown>;
  const strip = (o: Record<string, unknown>): Record<string, unknown> => { const { _comment, ...rest } = o; void _comment; return rest; };
  const input: PreflightInput = { mode: "pilot", nowMs: NOW, git: { sha: SHA, trackedChanges: 0, untracked: 0 }, expectedCommit: null, authorization: strip(read("authorization.template.json")), tfvars: strip(read("tfvars.template.json")), cost: strip(read("cost-inputs.template.json")), thresholds: undefined, loadProblems: [], terraform };
  const result = evaluatePreflight(input);
  assert.notEqual(result.outcome, "PASS");
  for (const c of ["authorization", "cost", "terraform_variables", "identities"]) assert.notEqual(result.checks.find((x) => x.id === c)!.status, "PASS", c);
  assert.ok(result.reasons.includes("m1.preflight.tfvars_unset.folder_id"));
  const withComment = evaluatePreflight({ ...input, tfvars: read("tfvars.template.json") });
  assert.equal(withComment.outcome, "ERROR"); assert.ok(withComment.reasons.includes("m1.preflight.tfvars_unknown_variable._comment"));
});
