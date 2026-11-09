/**
 * Infrastructure PILOT contract: the minimal, disposable smoke test that must pass on real infrastructure BEFORE any qualification traffic is attempted. It generates no attack
 * traffic and runs no BA0_FIELD_V1 workload; every probe is a single connection or API call. This module only DEFINES the contract and EVALUATES a recorded result file; it
 * executes nothing, contacts nothing, and its verdict is never a qualification (`PILOT_PASS` is a different thing from `PASS`/`QUALIFIED`).
 *
 * A result is trusted only as far as it is complete: every check present exactly once, PASS, timestamped, with evidence references of each required kind, bound to a pilot run id,
 * and followed by a cleanup record that lists no remaining resource. A missing check, a FAIL, or leftover resources can never produce PILOT_PASS.
 */
export const PILOT_SCHEMA = "m1-pilot-results-v1";
export type PilotCheckDefinition = { id: string; title: string; probe: string; passWhen: string; evidenceKinds: readonly string[]; costRelevant: boolean };

export const PILOT_CONTRACT: readonly PilotCheckDefinition[] = [
  { id: "vm_creation_and_expiry", title: "VM creation and provider-enforced expiry", probe: "create_vms=true with a SHORT run_max_seconds sandbox override (never below the 1800 s validation: use the minimum) and observe the instances disappear without any our-code action; repeat with the reaper disabled", passWhen: "all four instances exist after apply, carry both labels, and are DELETED by the provider at max_run_duration", evidenceKinds: ["instance-list-after-create", "instance-list-after-expiry"], costRelevant: true },
  { id: "private_dns", title: "Private DNS for Google APIs", probe: "from each VM, resolve storage.googleapis.com and the restricted VIP name", passWhen: "answers are inside the restricted VIP range 199.36.153.4/30 and nothing resolves to a public address", evidenceKinds: ["dns-answers-per-vm"], costRelevant: false },
  { id: "generator_to_target", title: "Generator to target connectivity", probe: "one TCP connect from the generator to target:plane_port, one from a non-allowed address", passWhen: "the connect from the generator /32 succeeds and the connect from any other source is refused or times out", evidenceKinds: ["tcp-connect-allowed", "tcp-connect-denied"], costRelevant: false },
  { id: "canary_to_target", title: "Canary to target connectivity", probe: "one TCP connect from the canary to target:plane_port; one from the collector /32", passWhen: "canary succeeds, collector is refused", evidenceKinds: ["tcp-connect-allowed", "tcp-connect-denied"], costRelevant: false },
  { id: "target_to_collector", title: "Target to collector connectivity", probe: "one TCP connect from the target to collector:collector_port; one from the generator", passWhen: "target succeeds, generator is refused", evidenceKinds: ["tcp-connect-allowed", "tcp-connect-denied"], costRelevant: false },
  { id: "evidence_bucket_permissions", title: "Evidence bucket permissions", probe: "write a marker object under a/, b/, c/ with the matching principal; try overwrite, delete, cross-prefix write and a read from A and B", passWhen: "each principal can create under its own prefix only; overwrite, delete, cross-prefix write and A/B reads are denied; the custodian can read all", evidenceKinds: ["object-create-allowed", "object-overwrite-denied", "object-delete-denied", "cross-prefix-denied", "custodian-read-allowed"], costRelevant: false },
  { id: "iap_access", title: "IAP-only access", probe: "gcloud IAP tunnel to one VM as an operator; attempt direct SSH to the private address and from the generator", passWhen: "the IAP tunnel works for the authorized group only and every other path is refused", evidenceKinds: ["iap-ssh-allowed", "direct-ssh-denied"], costRelevant: false },
  { id: "ttl_reaper", title: "TTL reaper", probe: "create one extra labeled instance with an old createdMs surrogate (a sandbox-only label timestamp) plus one UNLABELED instance; invoke the reaper", passWhen: "the labeled expired instance is deleted, the unlabeled instance and the evidence project are untouched, and a second invocation changes nothing", evidenceKinds: ["reaper-invocation-log", "instance-list-before-after"], costRelevant: true },
  { id: "budget_stop", title: "Budget-stop behavior", probe: "publish a synthetic budget notification at 80 percent (and a malformed one) to the stop topic; separately record whether a REAL budget notification reached the topic", passWhen: "the synthetic message deletes only labeled instances and reports success, the malformed message deletes nothing; delivery of a real budget notification is recorded as verified or NOT verified (billing data lags: not expected within the pilot)", evidenceKinds: ["function-log-synthetic-stop", "function-log-malformed-ignored", "real-budget-delivery-status"], costRelevant: true },
  { id: "resource_cleanup", title: "Complete resource cleanup", probe: "create_vms=false apply, then list every resource of the three disposable projects (instances, disks, addresses, routers, functions, topics, jobs) and the evidence project", passWhen: "no instance, disk or address remains in the disposable projects; remaining campaign-level resources are exactly the documented list; the owner confirms the teardown", evidenceKinds: ["resource-inventory-after-teardown", "owner-teardown-confirmation"], costRelevant: true },
] as const;

/**
 * Teardown inventory: every category of resource the stack creates must be listed with the number remaining AFTER teardown. Only a bucket still inside its retention period and a project
 * in the provider's pending-deletion state may be retained (with a stated reason); anything else remaining is a failed cleanup. A missing category is INCOMPLETE, never clean.
 */
export const CLEANUP_CATEGORIES = ["instances", "disks", "addresses", "firewall_rules", "networks_and_peerings", "routers", "dns_zones", "scheduler_jobs", "functions", "eventarc_triggers", "pubsub_topics", "service_accounts", "buckets", "billing_budgets", "projects"] as const;
const RETAINABLE = new Set<string>(["buckets", "projects"]);

export type PilotOutcome = "PILOT_PASS" | "INCOMPLETE" | "REJECT" | "ERROR";
export type PilotEvaluation = { outcome: PilotOutcome; reasons: string[]; checks: { id: string; status: "PASS" | "FAIL" | "MISSING" | "INVALID" }[] };

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u;
const at = (v: unknown): number | null => (typeof v === "string" && ISO.test(v) && Number.isFinite(Date.parse(v)) ? Date.parse(v) : null);

export function evaluatePilotResults(value: unknown): PilotEvaluation {
  const reasons: string[] = []; const checks: PilotEvaluation["checks"] = [];
  if (!isRecord(value)) return { outcome: "ERROR", reasons: ["m1.pilot.not_an_object"], checks };
  if (value.schema !== PILOT_SCHEMA) return { outcome: "ERROR", reasons: ["m1.pilot.schema_unexpected"], checks };
  if (typeof value.runId !== "string" || !/^pilot-[A-Za-z0-9._-]{1,57}$/u.test(value.runId)) reasons.push("m1.pilot.run_id_not_a_pilot_id");
  if (typeof value.commit !== "string" || !/^[0-9a-f]{40}$/u.test(value.commit)) reasons.push("m1.pilot.commit_missing");
  if (typeof value.authorizationSha256 !== "string" || !/^[0-9a-f]{64}$/u.test(value.authorizationSha256)) reasons.push("m1.pilot.authorization_digest_missing");
  if (value.trafficProfile !== "smoke") reasons.push("m1.pilot.traffic_profile_not_smoke");
  if (value.attackTraffic !== false) reasons.push("m1.pilot.attack_traffic_not_excluded");
  // the pilot verifies the private-lane topology the observers will use; it must declare REMOTE_PRIVATE (the profile itself is judged later, from the commitment, by the observation check)
  if (value.observationProfile === undefined) reasons.push("m1.pilot.observation_profile_missing"); else if (value.observationProfile !== "REMOTE_PRIVATE") reasons.push("m1.pilot.observation_profile_not_remote_private");
  if (value.qualificationWorkload !== false) reasons.push("m1.pilot.qualification_workload_not_excluded");
  const list = Array.isArray(value.checks) ? value.checks : null;
  if (list === null) return { outcome: "ERROR", reasons: [...reasons, "m1.pilot.checks_missing"], checks };
  const known = new Set(PILOT_CONTRACT.map((c) => c.id));
  const seen = new Map<string, Record<string, unknown>>();
  for (const entry of list) {
    if (!isRecord(entry) || typeof entry.id !== "string") { reasons.push("m1.pilot.check_malformed"); continue; }
    if (!known.has(entry.id)) { reasons.push(`m1.pilot.check_unknown.${entry.id}`); continue; }
    if (seen.has(entry.id)) { reasons.push(`m1.pilot.check_duplicated.${entry.id}`); continue; }
    seen.set(entry.id, entry);
  }
  let latestOtherMs = 0; let cleanupMs: number | null = null; let incomplete = reasons.includes("m1.pilot.observation_profile_missing"); let failed = false;
  for (const def of PILOT_CONTRACT) {
    const entry = seen.get(def.id);
    if (entry === undefined) { checks.push({ id: def.id, status: "MISSING" }); reasons.push(`m1.pilot.check_missing.${def.id}`); incomplete = true; continue; }
    if (entry.status === "FAIL") { checks.push({ id: def.id, status: "FAIL" }); reasons.push(`m1.pilot.check_failed.${def.id}`); failed = true; continue; }
    const observed = at(entry.observedAt); const evidence = Array.isArray(entry.evidence) ? entry.evidence : [];
    const kinds = new Set(evidence.filter((e) => isRecord(e) && typeof e.kind === "string" && typeof e.ref === "string" && e.ref.length > 0).map((e) => (e as { kind: string }).kind));
    const missingKinds = def.evidenceKinds.filter((k) => !kinds.has(k));
    if (entry.status !== "PASS" || observed === null || missingKinds.length > 0) {
      checks.push({ id: def.id, status: "INVALID" });
      if (entry.status !== "PASS") reasons.push(`m1.pilot.check_status_invalid.${def.id}`);
      if (observed === null) reasons.push(`m1.pilot.check_time_invalid.${def.id}`);
      for (const k of missingKinds) reasons.push(`m1.pilot.evidence_missing.${def.id}.${k}`);
      incomplete = true; continue;
    }
    // the budget-stop check must not claim a REAL budget delivery it did not record
    if (def.id === "budget_stop") { const status = evidence.find((e) => isRecord(e) && e.kind === "real-budget-delivery-status") as { ref: string } | undefined; if (status && !["verified", "not-verified"].includes(status.ref)) { reasons.push("m1.pilot.real_budget_delivery_status_must_be_verified_or_not-verified"); incomplete = true; checks.push({ id: def.id, status: "INVALID" }); continue; } }
    checks.push({ id: def.id, status: "PASS" });
    if (def.id === "resource_cleanup") cleanupMs = observed; else latestOtherMs = Math.max(latestOtherMs, observed);
  }
  // teardown must be the last thing that happened and must list nothing left behind
  const cleanup = isRecord(value.cleanup) ? value.cleanup : null;
  if (cleanup === null || !Array.isArray(cleanup.remainingDisposableResources) || at(cleanup.verifiedAt) === null) { reasons.push("m1.pilot.cleanup_record_missing"); incomplete = true; }
  else if (cleanup.remainingDisposableResources.length > 0) { reasons.push("m1.pilot.resources_remain_after_teardown"); failed = true; }
  const inventory = cleanup !== null && isRecord(cleanup.inventory) ? cleanup.inventory : null;
  if (inventory === null) { reasons.push("m1.pilot.cleanup_inventory_missing"); incomplete = true; }
  else for (const category of CLEANUP_CATEGORIES) {
    const entry = inventory[category];
    if (!isRecord(entry) || typeof entry.remaining !== "number" || !Number.isInteger(entry.remaining) || entry.remaining < 0) { reasons.push(`m1.pilot.cleanup_inventory_category_missing.${category}`); incomplete = true; }
    else if (entry.remaining > 0 && !(RETAINABLE.has(category) && typeof entry.retained === "string" && entry.retained.length > 0)) { reasons.push(`m1.pilot.cleanup_resource_remains.${category}`); failed = true; }
  }
  if (cleanupMs !== null && cleanupMs < latestOtherMs) { reasons.push("m1.pilot.cleanup_not_last"); failed = true; }
  const structural = reasons.some((r) => !r.startsWith("m1.pilot.check_missing.") && !r.startsWith("m1.pilot.evidence_missing.") && !r.startsWith("m1.pilot.check_status_invalid.") && !r.startsWith("m1.pilot.check_time_invalid.") && !r.startsWith("m1.pilot.check_failed.") && !r.startsWith("m1.pilot.real_budget_delivery_status") && r !== "m1.pilot.observation_profile_missing" && r !== "m1.pilot.cleanup_record_missing" && !r.startsWith("m1.pilot.cleanup_inventory") && !r.startsWith("m1.pilot.cleanup_resource_remains") && r !== "m1.pilot.resources_remain_after_teardown" && r !== "m1.pilot.cleanup_not_last");
  const outcome: PilotOutcome = structural || failed ? "REJECT" : incomplete ? "INCOMPLETE" : "PILOT_PASS";
  return { outcome, reasons: [...new Set(reasons)].sort(), checks };
}
