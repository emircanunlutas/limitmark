/**
 * M1 preflight gate: ONE local, read-only go/no-go over everything that must be true BEFORE a real Terraform plan, a pilot or a campaign. It provisions nothing, contacts
 * nothing and never writes: every input is a file the caller names, and the only side effect of the CLI wrapper is one line of JSON on stdout.
 *
 * Outcomes:  PASS        every check passed;
 *            INCOMPLETE  something is missing, unset, a placeholder, unverified or stale (never a PASS);
 *            ERROR       something is malformed, contradictory, over a limit, or unreadable.
 * A missing authorization or an unknown cost can therefore never produce PASS. PASS means "the inputs are complete and consistent", it does not authorize anything by itself and it
 * does not prove spending is capped (provider-side enforcement stays unverified until the pilot has run).
 *
 * Modes: `pilot` = infrastructure-only smoke test (no attack traffic, no BA0_FIELD_V1 workload; canary thresholds and heartbeat limit are not applicable);
 *        `campaign` = the qualification path (canary thresholds FIXED, heartbeat limit set, three-run budget).
 */
import { createHash } from "node:crypto";
import { canonicalJson } from "../evidence/manifest";
import { BA0_FIELD_V1 } from "../defense/field-thresholds";
import { MAX_REMOTE_TARGET_LIFETIME_HOURS } from "../policy/target-policy";
import { maxRunCostWithRate } from "../../infra/m1/killswitch/decide";
import { BROWSE_AND_SUBMIT_STEPS } from "./canary-contract";
import { PARAMETERS_DIGEST } from "./commitment";
import { validateOwnerThresholds } from "./canary-thresholds";

export type PreflightMode = "pilot" | "campaign";
export type PreflightStatus = "PASS" | "INCOMPLETE" | "ERROR";
export type Check = { id: string; status: PreflightStatus; reasons: string[] };
export type GitProbe = { sha: string; trackedChanges: number; untracked: number } | null;
export type VariableDecl = { name: string; hasDefault: boolean };
export type PreflightInput = {
  mode: PreflightMode; nowMs: number; git: GitProbe; expectedCommit: string | null;
  /** parsed JSON of each file, or `undefined` when the file was not supplied; `loadProblems` lists files that were unreadable or not JSON */
  authorization: unknown; tfvars: unknown; cost: unknown; thresholds: unknown; loadProblems: string[];
  /** contents of infra/m1/*.tf by file name (null: not readable) */
  terraform: Record<string, string> | null;
};
export type PreflightResult = { outcome: PreflightStatus; checks: Check[]; reasons: string[]; digests: Record<string, string | null>; limitations: string[] };

export const PLANNING_CEILING_TRY = { run: 750, campaign: 3000 } as const;
export const MAX_RATE_AGE_MS = 24 * 3_600_000;
export const AUTHORIZATION_SCHEMA = "m1-authorization-v1"; export const COST_SCHEMA = "m1-cost-inputs-v1";
const CHECK_IDS = ["git", "level_parameters", "terraform_structure", "terraform_variables", "network_scope", "authorization", "cost", "budget_ttl", "canary_journey", "heartbeat_limit", "evidence_custody", "identities", "ingress_lane"] as const;
const FORBIDDEN_PORTS = [22, 80, 443, 3000, 5432, 55416, 55417];

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const sha256 = (value: unknown): string => createHash("sha256").update(canonicalJson(value)).digest("hex");
const PLACEHOLDER = /(__.*__|owner[_ -]?required|replace[_ -]?me|changeme|dummy|placeholder|todo|tbd|example\.|your[_-])/iu;
/** unset = absent, null, empty, or an obvious placeholder */
const unset = (v: unknown): boolean => v === undefined || v === null || (typeof v === "string" && (v.trim() === "" || PLACEHOLDER.test(v)));
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u;
const time = (v: unknown): number | null => (typeof v === "string" && ISO.test(v) && Number.isFinite(Date.parse(v)) ? Date.parse(v) : null);

class Collector {
  readonly incomplete: string[] = []; readonly error: string[] = [];
  constructor(readonly id: string) {}
  missing(reason: string): void { this.incomplete.push(reason); }
  bad(reason: string): void { this.error.push(reason); }
  done(): Check { return { id: this.id, status: this.error.length > 0 ? "ERROR" : this.incomplete.length > 0 ? "INCOMPLETE" : "PASS", reasons: [...new Set([...this.error, ...this.incomplete])].sort() }; }
}

/** variables declared in variables.tf, and whether each has a default (an owner decision has none) */
export function parseVariables(source: string): VariableDecl[] {
  const out: VariableDecl[] = []; const header = /variable\s+"([a-z0-9_]+)"\s*\{/gu; let m: RegExpExecArray | null;
  while ((m = header.exec(source)) !== null) {
    let depth = 1; let i = header.lastIndex; const start = i;
    for (; i < source.length && depth > 0; i++) { if (source[i] === "{") depth++; else if (source[i] === "}") depth--; }
    const body = source.slice(start, i - 1); let d = 0; let top = "";
    for (const ch of body) { if (ch === "{") d++; else if (ch === "}") d--; else if (d === 0) top += ch; }
    out.push({ name: m[1]!, hasDefault: /(^|\n)\s*default\s*=/u.test(top) });
  }
  return out;
}

const OCTET = "(?:[2-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-3])";
const cidrOf = (net: string): RegExp => new RegExp(`^10[.]${net}[.]0[.]${OCTET}/32$`, "u");
const CIDRS: Record<string, [RegExp, string]> = { authorized_target_cidr: [cidrOf("10"), "authorizationTarget"], authorized_generator_cidr: [cidrOf("20"), "authorizationGenerator"], canary_cidr: [cidrOf("30"), "authorizationCanary"], collector_cidr: [cidrOf("30"), "authorizationCollector"] };
const IMAGE = /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/global\/images\/[a-z]([-a-z0-9]*[a-z0-9])?$/u;
const GROUP = /^group:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}$/u;

export function evaluatePreflight(input: PreflightInput): PreflightResult {
  const checks: Check[] = []; const limitations = [
    "PASS means complete and consistent inputs only: it authorizes nothing and does not prove a spending cap (provider-side enforcement is unverified until a pilot has exercised it)",
    "no credential, plan, apply or network access was used", "Terraform was not run by this command",
  ];
  const auth = isRecord(input.authorization) ? input.authorization : null; const vars = isRecord(input.tfvars) ? input.tfvars : null; const cost = isRecord(input.cost) ? input.cost : null;
  const digests: Record<string, string | null> = { authorization: auth ? sha256(auth) : null, tfvars: vars ? sha256(vars) : null, costInputs: cost ? sha256(cost) : null, thresholds: input.thresholds !== undefined ? sha256(input.thresholds) : null, parameters: PARAMETERS_DIGEST };
  const campaign = input.mode === "campaign";
  const authText = (name: string): string | null => (auth !== null && typeof auth[name] === "string" && !unset(auth[name]) ? (auth[name] as string) : null);

  // ---- git
  { const c = new Collector("git");
    if (input.git === null) c.bad("m1.preflight.git_state_unreadable");
    else {
      if (!/^[0-9a-f]{40}$/u.test(input.git.sha)) c.bad("m1.preflight.git_head_unknown");
      if (input.git.trackedChanges > 0) c.bad("m1.preflight.git_tracked_changes");
      if (input.git.untracked > 0) c.missing("m1.preflight.git_untracked_files_present_use_a_clean_worktree");
      const pinned = authText("commit");
      if (pinned === null) c.missing("m1.preflight.commit_not_pinned_in_authorization");
      else if (!/^[0-9a-f]{40}$/u.test(pinned)) c.bad("m1.preflight.authorization_commit_malformed");
      else if (pinned !== input.git.sha) c.bad("m1.preflight.head_differs_from_authorized_commit");
      if (input.expectedCommit !== null && input.expectedCommit !== input.git.sha) c.bad("m1.preflight.head_differs_from_expected_commit");
    }
    checks.push(c.done()); }

  // ---- code-pinned level parameters
  { const c = new Collector("level_parameters");
    const pinnedId = authText("parametersId"); const pinnedDigest = authText("parametersDigest");
    if (pinnedId === null || pinnedDigest === null) c.missing("m1.preflight.parameters_not_pinned_in_authorization");
    else { if (pinnedId !== BA0_FIELD_V1.id) c.bad("m1.preflight.parameters_id_differs_from_code"); if (pinnedDigest !== PARAMETERS_DIGEST) c.bad("m1.preflight.parameters_digest_differs_from_code"); }
    checks.push(c.done()); }

  // ---- terraform structure (static scan of infra/m1/*.tf: the constructs the cost and isolation story relies on)
  const declared = input.terraform?.["variables.tf"] !== undefined ? parseVariables(input.terraform["variables.tf"]) : null;
  { const c = new Collector("terraform_structure");
    if (input.terraform === null || declared === null) c.missing("m1.preflight.terraform_sources_unreadable");
    else {
      const files = input.terraform;
      // each construct is required in the file that is supposed to hold it (a mention in another file does not count)
      const need: [string, string, RegExp][] = [["max_run_duration", "compute.tf", /max_run_duration\s*\{/u], ["termination_action_delete", "compute.tf", /termination_action\s*=\s*"DELETE"/u],
        ["ttl_reaper_schedule", "killswitch.tf", /resource\s+"google_cloud_scheduler_job"[\s\S]*?schedule\s*=\s*"\*\/5 \* \* \* \*"/u], ["run_budget", "killswitch.tf", /resource\s+"google_billing_budget"\s+"run"/u], ["campaign_budget", "killswitch.tf", /resource\s+"google_billing_budget"\s+"campaign"/u],
        ["retention_policy", "evidence.tf", /retention_policy\s*\{/u], ["bucket_versioning", "evidence.tf", /versioning\s*\{/u], ["prevent_destroy", "evidence.tf", /prevent_destroy\s*=\s*true/u], ["cpu_quota", "projects.tf", /resource\s+"google_service_usage_consumer_quota_override"/u]];
      for (const [name, file, pattern] of need) if (!pattern.test(files[file] ?? "")) c.bad(`m1.preflight.terraform_missing.${name}`);
      const all = Object.entries(files).filter(([n]) => n.endsWith(".tf")).map(([, text]) => text).join(String.fromCharCode(10));
      if (/access_config\s*\{/u.test(all)) c.bad("m1.preflight.terraform_external_ip_present");
      const lock = declared.find((v) => v.name === "lock_retention"); const lockDefault = /variable\s+"lock_retention"[\s\S]*?default\s*=\s*(\w+)/u.exec(input.terraform["variables.tf"]!)?.[1];
      if (lock === undefined || lockDefault !== "false") c.bad("m1.preflight.lock_retention_default_not_false");
    }
    checks.push(c.done()); }

  // ---- terraform variable completeness and validity
  { const c = new Collector("terraform_variables");
    if (declared === null) c.missing("m1.preflight.terraform_variables_undeclared");
    else if (input.tfvars === undefined) c.missing("m1.preflight.tfvars_not_supplied");
    else if (vars === null) c.bad("m1.preflight.tfvars_not_an_object");
    else {
      const names = new Set(declared.map((d) => d.name));
      for (const key of Object.keys(vars)) if (!names.has(key)) c.bad(`m1.preflight.tfvars_unknown_variable.${key}`);
      for (const d of declared) if (!d.hasDefault && unset(vars[d.name])) c.missing(`m1.preflight.tfvars_unset.${d.name}`);
      // values whose DEFAULT would silently decide budget, lifetime or retention must be stated by the owner
      for (const explicit of ["run_budget", "campaign_budget", "run_max_seconds", "budget_currency", "retention_days", "lock_retention", "create_vms"]) if (vars[explicit] === undefined) c.missing(`m1.preflight.tfvars_must_state.${explicit}`);
      const str = (n: string): string | null => (typeof vars[n] === "string" && !unset(vars[n]) ? (vars[n] as string) : null);
      const prefix = str("project_prefix"); if (prefix !== null && !/^[a-z][a-z0-9]{3,11}$/u.test(prefix)) c.bad("m1.preflight.project_prefix_invalid");
      const cid = str("campaign_id"); if (cid !== null && !/^[a-z0-9-]{1,31}$/u.test(cid)) c.bad("m1.preflight.campaign_id_invalid");
      const rid = str("run_id"); if (rid !== null && !/^[A-Za-z0-9._-]{1,63}$/u.test(rid)) c.bad("m1.preflight.run_id_invalid");
      if (rid !== null) { if (input.mode === "pilot" && !rid.startsWith("pilot-")) c.bad("m1.preflight.pilot_run_id_must_start_with_pilot-"); if (campaign && rid.startsWith("pilot-")) c.bad("m1.preflight.campaign_run_id_must_not_be_a_pilot_id"); }
      const port = vars.plane_port; if (port !== undefined && port !== null && !unset(port)) { if (typeof port !== "number" || !Number.isInteger(port) || FORBIDDEN_PORTS.includes(port) || port <= 1023 || port >= 65536) c.bad("m1.preflight.plane_port_invalid"); }
      for (const [name, [pattern]] of Object.entries(CIDRS)) { const v = str(name); if (v !== null && !pattern.test(v)) c.bad(`m1.preflight.${name}_invalid`); }
      if (str("collector_cidr") !== null && str("collector_cidr") === str("canary_cidr")) c.bad("m1.preflight.collector_equals_canary");
      for (const flag of ["create_vms", "lock_retention"]) if (vars[flag] !== undefined && typeof vars[flag] !== "boolean") c.bad(`m1.preflight.${flag}_not_boolean`);
    }
    checks.push(c.done()); }

  // ---- target and network scope (tfvars <-> authorization)
  { const c = new Collector("network_scope");
    if (auth === null || vars === null) c.missing("m1.preflight.scope_needs_authorization_and_tfvars");
    else {
      const pairs: [string, string][] = [["authorized_target_cidr", "targetCidr"], ["authorized_generator_cidr", "generatorCidr"], ["canary_cidr", "canaryCidr"], ["collector_cidr", "collectorCidr"]];
      for (const [variable, field] of pairs) {
        if (unset(auth[field])) c.missing(`m1.preflight.authorization_unset.${field}`);
        else if (typeof auth[field] !== "string" || !CIDRS[variable]![0].test(auth[field] as string)) c.bad(`m1.preflight.authorization_${field}_invalid`);
        else if (!unset(vars[variable]) && vars[variable] !== auth[field]) c.bad(`m1.preflight.${variable}_differs_from_authorization`);
      }
      const set = [auth.targetCidr, auth.generatorCidr, auth.canaryCidr, auth.collectorCidr].filter((x) => typeof x === "string");
      if (new Set(set).size !== set.length) c.bad("m1.preflight.scope_addresses_not_distinct");
      if (!unset(auth.campaignId) && !unset(vars.campaign_id) && auth.campaignId !== vars.campaign_id) c.bad("m1.preflight.campaign_id_differs_from_authorization");
      if (!unset(auth.runId) && !unset(vars.run_id) && auth.runId !== vars.run_id) c.bad("m1.preflight.run_id_differs_from_authorization");
    }
    checks.push(c.done()); }

  // ---- owner authorization
  { const c = new Collector("authorization");
    if (input.authorization === undefined) c.missing("m1.preflight.authorization_not_supplied");
    else if (auth === null) c.bad("m1.preflight.authorization_not_an_object");
    else {
      if (auth.schema !== AUTHORIZATION_SCHEMA) c.bad("m1.preflight.authorization_schema_unexpected");
      if (auth.mode !== input.mode) c.bad("m1.preflight.authorization_mode_differs");
      const approval = isRecord(auth.approval) ? auth.approval : null;
      if (approval === null || unset(approval.approvedBy) || unset(approval.reference)) c.missing("m1.preflight.authorization_not_approved_by_owner");
      else {
        const from = time(approval.approvedAt); const until = time(approval.expiresAt);
        if (from === null || until === null) c.bad("m1.preflight.authorization_times_malformed");
        else {
          if (from > input.nowMs) c.bad("m1.preflight.authorization_approved_in_the_future");
          if (until <= input.nowMs) c.bad("m1.preflight.authorization_expired");
          if (until <= from) c.bad("m1.preflight.authorization_window_inverted");
          else if (until - from > MAX_REMOTE_TARGET_LIFETIME_HOURS * 3_600_000) c.bad("m1.preflight.authorization_window_exceeds_72h");
        }
      }
      if (auth.acknowledgesUnverifiedSpendCap !== true) c.missing("m1.preflight.owner_has_not_acknowledged_that_spending_is_not_hard_capped");
      if (vars !== null && !unset(auth.tfvarsSha256)) { if (auth.tfvarsSha256 !== digests.tfvars) c.bad("m1.preflight.tfvars_differ_from_what_the_owner_approved"); } else c.missing("m1.preflight.tfvars_digest_not_approved");
      if (cost !== null && !unset(auth.costInputsSha256)) { if (auth.costInputsSha256 !== digests.costInputs) c.bad("m1.preflight.cost_inputs_differ_from_what_the_owner_approved"); } else c.missing("m1.preflight.cost_digest_not_approved");
      if (campaign) { if (input.thresholds === undefined || unset(auth.thresholdsSha256)) c.missing("m1.preflight.thresholds_digest_not_approved"); else if (auth.thresholdsSha256 !== validateOwnerThresholds(input.thresholds).digest) c.bad("m1.preflight.thresholds_differ_from_what_the_owner_approved"); }
    }
    checks.push(c.done()); }

  // ---- cost estimate, price and exchange-rate freshness
  let runCostTry: number | null = null;
  { const c = new Collector("cost");
    if (input.cost === undefined) c.missing("m1.preflight.cost_inputs_not_supplied");
    else if (cost === null) c.bad("m1.preflight.cost_inputs_not_an_object");
    else {
      if (cost.schema !== COST_SCHEMA) c.bad("m1.preflight.cost_schema_unexpected");
      const fx = isRecord(cost.fx) ? cost.fx : null; const prices = isRecord(cost.priceSource) ? cost.priceSource : null;
      if (fx === null || typeof fx.tryPerUsdHigh !== "number" || !(fx.tryPerUsdHigh > 0) || unset(fx.source)) c.missing("m1.preflight.exchange_rate_unknown");
      else {
        if (fx.verified !== true) c.missing("m1.preflight.exchange_rate_not_verified");
        const at = time(fx.checkedAt); if (at === null) c.bad("m1.preflight.exchange_rate_time_malformed"); else if (at > input.nowMs) c.bad("m1.preflight.exchange_rate_time_in_future"); else if (input.nowMs - at > MAX_RATE_AGE_MS) c.missing("m1.preflight.exchange_rate_stale");
      }
      if (prices === null || unset(prices.name)) c.missing("m1.preflight.price_source_unknown");
      else { const at = time(prices.checkedAt); if (at === null) c.bad("m1.preflight.price_time_malformed"); else if (at > input.nowMs) c.bad("m1.preflight.price_time_in_future"); else if (input.nowMs - at > MAX_RATE_AGE_MS) c.missing("m1.preflight.prices_stale"); }
      const vms = Array.isArray(cost.vms) ? cost.vms : null;
      const numeric = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v) && v >= 0;
      if (vms === null || vms.length === 0 || !vms.every((v) => isRecord(v) && Number.isInteger(v.count) && (v.count as number) > 0 && numeric(v.usdPerHour) && (v.usdPerHour as number) > 0)) c.missing("m1.preflight.vm_prices_unknown");
      else if (vms.reduce((s, v) => s + (v as { count: number }).count, 0) !== 4) c.bad("m1.preflight.vm_count_is_not_the_fixed_fleet_of_four");
      if (!numeric(cost.hours) || !numeric(cost.egressGb) || !numeric(cost.usdPerGb) || !numeric(cost.storageUsd) || (cost.hours as number) <= 0) c.missing("m1.preflight.cost_quantities_unknown");
      else if (vars !== null && typeof vars.run_max_seconds === "number" && (cost.hours as number) < vars.run_max_seconds / 3600) c.bad("m1.preflight.cost_hours_below_the_enforced_vm_lifetime");
      const budget = auth !== null && isRecord(auth.budgetTry) ? auth.budgetTry : null;
      const runBudget = budget !== null && typeof budget.run === "number" ? budget.run : null;
      if (c.error.length === 0 && c.incomplete.length === 0 && fx !== null && vms !== null) {
        const bound = maxRunCostWithRate({ vms: vms as { count: number; usdPerHour: number }[], hours: cost.hours as number, egressGb: cost.egressGb as number, usdPerGb: cost.usdPerGb as number, storageUsd: cost.storageUsd as number, runBudgetTry: runBudget ?? PLANNING_CEILING_TRY.run }, { high: fx.tryPerUsdHigh as number, verified: fx.verified === true });
        if (bound.tryAmount !== null) runCostTry = bound.tryAmount;
        if (!bound.bounded) { if (bound.reason === "exchange-rate-not-verified" || bound.reason === "exchange-rate-missing") c.missing(`m1.preflight.cost_${bound.reason}`); else c.bad(`m1.preflight.cost_over_budget_or_unbounded.${bound.reason}`); }
      }
    }
    checks.push(c.done()); }

  // ---- budget and TTL configuration (tfvars, authorization, cost together)
  { const c = new Collector("budget_ttl");
    const budget = auth !== null && isRecord(auth.budgetTry) ? auth.budgetTry : null;
    const run = budget?.run; const total = budget?.campaign;
    if (typeof run !== "number" || typeof total !== "number" || !(run > 0) || !(total > 0)) c.missing("m1.preflight.owner_budget_not_stated");
    else {
      if (run > PLANNING_CEILING_TRY.run) c.bad("m1.preflight.run_budget_above_planning_ceiling"); if (total > PLANNING_CEILING_TRY.campaign) c.bad("m1.preflight.campaign_budget_above_planning_ceiling");
      if (run > total) c.bad("m1.preflight.run_budget_above_campaign_budget");
      if (vars !== null) { if (typeof vars.run_budget === "number" && vars.run_budget !== run) c.bad("m1.preflight.tfvars_run_budget_differs_from_authorization"); if (typeof vars.campaign_budget === "number" && vars.campaign_budget !== total) c.bad("m1.preflight.tfvars_campaign_budget_differs_from_authorization"); }
      if (runCostTry !== null) { const runs = campaign ? 3 : 1; if (runCostTry > run) c.bad("m1.preflight.estimated_run_cost_above_run_budget"); if (runCostTry * runs > total) c.bad("m1.preflight.estimated_total_cost_above_campaign_budget"); }
    }
    if (vars !== null) {
      if (vars.budget_currency !== undefined && vars.budget_currency !== "TRY") c.bad("m1.preflight.budget_currency_not_try");
      const ttl = vars.run_max_seconds;
      if (ttl !== undefined) { if (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl < 1800 || ttl > 14400) c.bad("m1.preflight.run_max_seconds_out_of_range"); else if (ttl * 1000 < BA0_FIELD_V1.targetMinRemainingMs + 60_000) c.bad("m1.preflight.ttl_shorter_than_run_plus_target_min_remaining"); }
    }
    checks.push(c.done()); }

  // ---- canary journey configuration
  { const c = new Collector("canary_journey");
    if ((BROWSE_AND_SUBMIT_STEPS as readonly string[]).join() !== "home,asset,faq,form,submit,thanks") c.bad("m1.preflight.canary_steps_changed");
    if (BA0_FIELD_V1.canary.jcrMinimum !== 1) c.bad("m1.preflight.canary_journey_completion_not_100_percent");
    if (!(BA0_FIELD_V1.canary.timeoutMs > 0)) c.bad("m1.preflight.canary_timeout_invalid");
    if (campaign) {
      const status = input.thresholds === undefined ? null : validateOwnerThresholds(input.thresholds);
      if (status === null || status.status === "UNSET") c.missing("m1.preflight.canary_thresholds_unset"); else if (status.status === "INVALID") c.bad("m1.preflight.canary_thresholds_invalid");
    }
    checks.push(c.done()); }

  // ---- observer heartbeat limit (verifier-side, from the owner's thresholds record)
  { const c = new Collector("heartbeat_limit");
    if (!campaign) { /* not applicable to an infrastructure-only pilot: no qualification evidence is evaluated */ }
    else {
      const status = input.thresholds === undefined ? null : validateOwnerThresholds(input.thresholds);
      if (status === null || status.status !== "FIXED") c.missing("m1.preflight.heartbeat_limit_not_fixed_by_owner");
      else if (!(isRecord(input.thresholds) && typeof input.thresholds.maxHeartbeatGapMs === "number" && input.thresholds.maxHeartbeatGapMs > 0)) c.bad("m1.preflight.heartbeat_limit_invalid");
    }
    checks.push(c.done()); }

  // ---- evidence custody
  { const c = new Collector("evidence_custody");
    if (vars === null) c.missing("m1.preflight.custody_needs_tfvars");
    else {
      const groups = ["operators_group", "observers_group", "custodian_group"].map((n) => vars[n]);
      if (groups.some((g) => unset(g))) c.missing("m1.preflight.custody_groups_unset");
      else if (new Set(groups).size !== 3) c.bad("m1.preflight.custody_groups_not_distinct");
      if (typeof vars.retention_days === "number" && (!Number.isInteger(vars.retention_days) || vars.retention_days < 30)) c.bad("m1.preflight.retention_below_30_days");
      if (vars.lock_retention === true) { if (input.mode === "pilot") c.bad("m1.preflight.retention_lock_not_allowed_in_a_pilot"); else if (auth === null || auth.retentionLockApproved !== true) c.bad("m1.preflight.retention_lock_not_approved_by_owner"); }
    }
    checks.push(c.done()); }

  // ---- required infrastructure identities
  { const c = new Collector("identities");
    if (vars === null) c.missing("m1.preflight.identities_need_tfvars");
    else {
      for (const name of ["folder_id", "billing_account", "operators_group", "observers_group", "custodian_group", "target_image", "generator_image", "observer_image"]) if (unset(vars[name])) c.missing(`m1.preflight.identity_unset.${name}`);
      if (!unset(vars.folder_id) && !/^[0-9]{6,20}$/u.test(String(vars.folder_id))) c.bad("m1.preflight.folder_id_malformed");
      if (!unset(vars.billing_account) && !/^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$/u.test(String(vars.billing_account))) c.bad("m1.preflight.billing_account_malformed");
      for (const g of ["operators_group", "observers_group", "custodian_group"]) if (!unset(vars[g]) && !GROUP.test(String(vars[g]))) c.bad(`m1.preflight.${g}_malformed_or_not_a_group`);
      const images = ["target_image", "generator_image", "observer_image"].map((n) => vars[n]);
      for (const [i, n] of ["target_image", "generator_image", "observer_image"].entries()) { const v = images[i]; if (!unset(v) && (typeof v !== "string" || !IMAGE.test(v))) c.bad(`m1.preflight.${n}_not_a_pinned_image_resource`); }
      const present = images.filter((v) => !unset(v)); if (new Set(present).size !== present.length) c.bad("m1.preflight.images_not_distinct");
    }
    checks.push(c.done()); }

  // ---- lane: a private-lane pilot or campaign only; public ingress is a separate, unapproved category
  { const c = new Collector("ingress_lane");
    if (auth === null) c.missing("m1.preflight.lane_needs_authorization");
    else {
      if (auth.lane !== "PRIVATE-LANE") c.bad("m1.preflight.lane_must_be_private_lane"); if (auth.publicIngress !== false) c.bad("m1.preflight.public_ingress_must_be_false");
      if (campaign && auth.privateLaneAcceptedAsExternalGenerator !== true) c.missing("m1.preflight.owner_has_not_decided_private_lane_counts_as_external_generator");
    }
    checks.push(c.done()); }

  const reasons = [...input.loadProblems];
  for (const c of checks) reasons.push(...c.reasons);
  const complete = CHECK_IDS.every((id) => checks.some((c) => c.id === id));
  const outcome: PreflightStatus = input.loadProblems.length > 0 || checks.some((c) => c.status === "ERROR") || !complete ? "ERROR" : checks.some((c) => c.status === "INCOMPLETE") ? "INCOMPLETE" : "PASS";
  return { outcome, checks, reasons: [...new Set(reasons)].sort(), digests, limitations };
}
