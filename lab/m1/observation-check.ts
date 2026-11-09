/**
 * Evaluator for the independent observation prototype (pure; never throws). It combines what the CANARY process measured on its own clock with what the ORIGIN RECEIPT
 * COLLECTOR recorded at arrival, bound to one run identity. The pinned canary parameters of BA0_FIELD_V1 are used as they are (jcrMinimum, timeoutMs, window latency rule); only
 * the number of journeys is scaled for a local fixture, and that is reported.
 *
 * What this can and cannot show (always reported as limitations): the canary, the stand-in for the server under test, the origin receipt collector and the origin fixture are
 * separate LOCAL processes started by one operator on one host. That separation catches faults and fakes between processes; it is not independent organizational custody, and the
 * fixture site is not the defense plane. Only the journey steps the fixture implements are exercised; nothing else is reported as covered.
 */
import { BA0_FIELD_V1 } from "../defense/field-thresholds";
import { REMOTE_LIMITATIONS, evaluateRemoteProfile, type ExpectedObservation, type ObservationProfile } from "./observation-profile";

export const OBSERVATION_CONTRACT = "m1-observation-check-v1";
export const OBSERVATION_LIMITATIONS = ["separate_local_processes_not_independent_custody", "stand_in_is_not_the_defense_plane", "journey_covers_fixture_steps_only", "challenges_observed_by_header_and_status_only"];
export const COVERED_STEPS = ["home", "asset", "faq", "form", "submit", "thanks"];
export const NOT_COVERED_ACTIONS = ["login", "payment", "account_changes", "search_backend", "file_upload"];

export type ObservationInput = { identity: { runId: string; campaignId: string } | null; canary: unknown; receipts: unknown[] | null; meta: unknown;
  /** collector closing declaration (identity evidence for REMOTE_PRIVATE) */ declaration?: unknown;
  /** what the VERIFIER expects (from the verified pre-run commitment); absent means the local loopback profile. The result file never selects its own profile. */ expected?: ExpectedObservation | null };
export type ObservationSummary = {
  journeys: number; journeysSucceeded: number; successRate: number; steps: number; httpErrors: number; timeouts: number; transportFailures: number; falseRejects: number; challenges: number; rateLimits: number;
  latencyMs: { p50: number | null; p95: number | null; p99: number | null; baselineP95: number | null }; recovery: { journeys: number; succeeded: number; residualRestrictions: number };
  originReceipts: number; coveredSteps: string[]; notCoveredActions: string[];
};
export type ObservationResult = { contract: typeof OBSERVATION_CONTRACT; outcome: "PASS" | "REJECT" | "ERROR"; reasons: string[]; summary: ObservationSummary | null; limitations: string[]; profile?: ObservationProfile };

type Step = { phase: "baseline" | "window" | "recovery"; journey: number; step: string; requestId: string; method: string; path: string; status: number | null; ok: boolean; timedOut: boolean; failed: boolean; challenged: boolean; latencyMs: number };
type Receipt = { seq: number; requestId: string | null; runId: string | null; campaignId: string | null; method: string | null; path: string | null };

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const str = (value: unknown): value is string => typeof value === "string" && value.length > 0;
const nullableStr = (value: unknown): value is string | null => value === null || typeof value === "string";
const result = (outcome: ObservationResult["outcome"], reasons: string[], summary: ObservationSummary | null = null): ObservationResult => ({ contract: OBSERVATION_CONTRACT, outcome, reasons: [...new Set(reasons)], summary, limitations: OBSERVATION_LIMITATIONS });
const percentile = (values: number[], p: number): number | null => { if (values.length === 0) return null; const sorted = [...values].sort((a, b) => a - b); return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]; };

function readStep(value: unknown): Step | null {
  if (!isRecord(value)) return null;
  const v = value;
  if (!(v.phase === "baseline" || v.phase === "window" || v.phase === "recovery") || !isCount(v.journey) || !str(v.step) || !str(v.requestId) || !str(v.method) || !str(v.path)) return null;
  if (!(v.status === null || isCount(v.status)) || typeof v.ok !== "boolean" || typeof v.timedOut !== "boolean" || typeof v.failed !== "boolean" || typeof v.challenged !== "boolean" || typeof v.latencyMs !== "number" || !Number.isFinite(v.latencyMs) || v.latencyMs < 0) return null;
  return v as unknown as Step;
}
function readReceipt(value: unknown): Receipt | null {
  if (!isRecord(value) || !isCount(value.seq) || !nullableStr(value.requestId) || !nullableStr(value.runId) || !nullableStr(value.campaignId) || !nullableStr(value.method) || !nullableStr(value.path)) return null;
  return value as unknown as Receipt;
}

/** Judges the evidence under the profile the verifier expects; remote results carry the remote limitations and the profile. */
export function evaluateObservation(input: ObservationInput): ObservationResult {
  const base = evaluateObservationCore(input);
  const profile: ObservationProfile = (input as ObservationInput | null)?.expected?.profile ?? "LOCAL_LOOPBACK";
  return profile === "REMOTE_PRIVATE" ? { ...base, profile, limitations: [...base.limitations.filter((l) => l !== "separate_local_processes_not_independent_custody"), "observation_profile_remote_private_selected_by_verified_commitment", ...REMOTE_LIMITATIONS] } : { ...base, profile };
}

function evaluateObservationCore(input: ObservationInput): ObservationResult {
  try {
    if (input.identity === null) return result("ERROR", ["m1.obs.identity_missing"]);
    if (!isRecord(input.canary) || input.canary.schema !== "m1-canary-results-v1" || !Array.isArray(input.canary.steps)) return result("ERROR", ["m1.obs.canary_results_missing"]);
    if (input.receipts === null) return result("ERROR", ["m1.obs.origin_receipts_unavailable"]);
    const steps = input.canary.steps.map(readStep);
    if (steps.some((step) => step === null)) return result("ERROR", ["m1.obs.canary_results_malformed"]);
    const all = steps as Step[];
    const receipts = input.receipts.map(readReceipt);
    if (receipts.some((receipt) => receipt === null)) return result("ERROR", ["m1.obs.origin_receipts_malformed"]);
    const got = receipts as Receipt[];
    const plan = input.canary.plan;
    if (!isRecord(plan) || !isCount(plan.baseline) || !isCount(plan.window) || !isCount(plan.recovery) || all.length !== (plan.baseline + plan.window + plan.recovery) * COVERED_STEPS.length) return result("ERROR", ["m1.obs.canary_results_incomplete"]);
    if (!isRecord(input.meta)) return result("ERROR", ["m1.obs.process_metadata_missing"]);
    // ---- profile: chosen by the verifier; the file's own claim must MATCH it and can never select it
    const claimedProfile = input.meta.profile === undefined ? "LOCAL_LOOPBACK" : input.meta.profile;
    const expected = input.expected ?? null;
    if (claimedProfile !== "LOCAL_LOOPBACK" && claimedProfile !== "REMOTE_PRIVATE") return result("ERROR", ["m1.obs.profile_unknown"]);
    if (claimedProfile === "REMOTE_PRIVATE" && expected === null) return result("ERROR", ["m1.obs.remote_profile_without_environment_commitment"]);
    const wanted = expected?.profile ?? "LOCAL_LOOPBACK";
    const remote = wanted === "REMOTE_PRIVATE";
    if (!remote && claimedProfile === wanted && !isRecord(input.meta.processes)) return result("ERROR", ["m1.obs.process_metadata_missing"]);
    const profileReasons: string[] = [];
    if (claimedProfile !== wanted) profileReasons.push("m1.obs.profile_mismatch");
    else if (remote) {
      const checked = evaluateRemoteProfile({ meta: input.meta, canary: input.canary, declaration: input.declaration, expected: expected! });
      if (checked.missing.length > 0) return result("ERROR", checked.missing);
      profileReasons.push(...checked.reasons);
    }

    const reasons: string[] = [...profileReasons];
    // ---- identity of the observer's own evidence
    if (input.canary.runId !== input.identity.runId) reasons.push("m1.obs.canary_run_mismatch");
    if (input.canary.campaignId !== input.identity.campaignId) reasons.push("m1.obs.canary_campaign_mismatch");
    if (input.meta.runId !== input.identity.runId || input.meta.campaignId !== input.identity.campaignId || (!remote && input.meta.loopbackOnly !== true)) reasons.push("m1.obs.meta_identity_mismatch");
    if (!remote && isRecord(input.meta.processes)) {
      const pids = Object.values(input.meta.processes as Record<string, unknown>);
      if (pids.length < 5 || !pids.every((pid) => isCount(pid) && pid > 0) || new Set(pids).size !== pids.length) reasons.push("m1.obs.processes_not_separate");
    }
    if (input.canary.timeoutMs !== BA0_FIELD_V1.canary.timeoutMs) reasons.push("m1.obs.canary_timeout_not_pinned");

    // ---- request identities: unique on the canary side (a reused id is a replay), unique and owned by this run on the origin side
    const ids = new Set<string>();
    for (const step of all) { if (ids.has(step.requestId)) reasons.push("m1.obs.canary_request_id_replayed"); ids.add(step.requestId); }
    const byId = new Map<string, Receipt[]>();
    for (const receipt of got) {
      if (receipt.requestId === null || receipt.runId === null || receipt.campaignId === null) { reasons.push("m1.obs.receipt_without_identity"); continue; }
      if (receipt.runId !== input.identity.runId) reasons.push("m1.obs.foreign_run_receipt");
      if (receipt.campaignId !== input.identity.campaignId) reasons.push("m1.obs.foreign_campaign_receipt");
      byId.set(receipt.requestId, [...(byId.get(receipt.requestId) ?? []), receipt]);
    }
    for (const [id, list] of byId) {
      if (list.length > 1) reasons.push("m1.obs.duplicate_origin_receipt");
      if (!ids.has(id)) reasons.push("m1.obs.unattributed_origin_receipt");
    }
    for (const step of all) {
      const list = byId.get(step.requestId) ?? [];
      if (step.ok && list.length === 0) reasons.push("m1.obs.canary_success_without_origin_receipt");
      for (const receipt of list) if (receipt.method !== step.method || receipt.path !== step.path) reasons.push("m1.obs.receipt_request_mismatch");
    }

    // ---- measured behavior (pinned parameters)
    const journeyKey = (step: Step): string => `${step.phase}.${step.journey}`;
    const journeys = new Map<string, Step[]>();
    for (const step of all) journeys.set(journeyKey(step), [...(journeys.get(journeyKey(step)) ?? []), step]);
    const succeeded = [...journeys.values()].filter((list) => list.every((step) => step.ok)).length;
    const rate = journeys.size === 0 ? 0 : succeeded / journeys.size;
    if (rate < BA0_FIELD_V1.canary.jcrMinimum) reasons.push("m1.obs.journey_success_below_minimum");
    const recoveryJourneys = [...journeys.entries()].filter(([key]) => key.startsWith("recovery.")).map(([, list]) => list);
    const recoverySucceeded = recoveryJourneys.filter((list) => list.every((step) => step.ok)).length;
    if (recoveryJourneys.length === 0) reasons.push("m1.obs.recovery_not_observed");
    else if (recoverySucceeded < recoveryJourneys.length) reasons.push("m1.obs.recovery_incomplete");
    const latency = (phase: Step["phase"]): number[] => all.filter((step) => step.phase === phase && step.status !== null).map((step) => step.latencyMs);
    const windowLatency = latency("window"); const baselineP95 = percentile(latency("baseline"), 95); const windowP95 = percentile(windowLatency, 95);
    if (baselineP95 === null || windowP95 === null) reasons.push("m1.obs.latency_not_measurable");
    else if (windowP95 > baselineP95 * BA0_FIELD_V1.canary.windowLatency.p95Factor + BA0_FIELD_V1.canary.windowLatency.p95AddedMs) reasons.push("m1.obs.window_latency_exceeds_rule");
    const timeouts = all.filter((step) => step.timedOut).length;
    if (timeouts > 0) reasons.push("m1.obs.timeouts_observed");
    const summary: ObservationSummary = {
      journeys: journeys.size, journeysSucceeded: succeeded, successRate: rate, steps: all.length, httpErrors: all.filter((step) => step.status !== null && step.status >= 400).length, timeouts,
      transportFailures: all.filter((step) => step.failed).length, falseRejects: all.filter((step) => step.status === 403 || step.status === 429 || step.status === 503).length,
      challenges: all.filter((step) => step.challenged).length, rateLimits: all.filter((step) => step.status === 429).length,
      latencyMs: { p50: percentile(windowLatency, 50), p95: windowP95, p99: percentile(windowLatency, 99), baselineP95 },
      recovery: { journeys: recoveryJourneys.length, succeeded: recoverySucceeded, residualRestrictions: recoveryJourneys.length - recoverySucceeded }, originReceipts: got.length,
      coveredSteps: COVERED_STEPS, notCoveredActions: NOT_COVERED_ACTIONS,
    };
    return result(reasons.length === 0 ? "PASS" : "REJECT", reasons, summary);
  } catch { return result("ERROR", ["m1.obs.evaluation_failed"]); }
}
