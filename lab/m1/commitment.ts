/**
 * Pre-run commitment and fresh-instance evidence for the first authorized remote M1 campaign. Pure; never throws; local and additive (no verdict, parameter or pinned file
 * changes, and it never makes a run QUALIFIED).
 *
 * The controller (principal A) builds this BEFORE any traffic and writes it to its create-only evidence prefix; an observer countersigns its digest; the custodian seals it.
 * `buildCommitment` refuses an inconsistent commitment; `evaluateFreshness` is the verifier's cross-run check: a run is only fresh if its instance and boot are new,
 * it was created after the previous run's teardown, and every process counter started from zero. Distinct ids alone are not evidence of a fresh machine; the cloud instance
 * id, creation timestamp, image id and boot id are what is bound here (machine freshness beyond that remains an unproven blocker, see M1-CAMPAIGN-TRUST-CLOSURE.md).
 */
import { createHash } from "node:crypto";
import { canonicalJson } from "../evidence/manifest";
import { BA0_FIELD_V1 } from "../defense/field-thresholds";
import { MAX_REMOTE_TARGET_LIFETIME_HOURS } from "../policy/target-policy";

export const COMMITMENT_SCHEMA = "m1-prerun-commitment-v1";
export const PARAMETERS_DIGEST = createHash("sha256").update(canonicalJson(BA0_FIELD_V1)).digest("hex");

export type CommitmentInput = {
  campaignId: string; runId: string; commit: string; treeClean: boolean; parametersId: string; parametersDigest: string; fixtureDigest: string;
  target: { ipv4: string; authorizedFromMs: number; authorizedUntilMs: number };
  window: { startMs: number; endMs: number };
  instance: { id: string; createdMs: number; imageId: string; bootId: string };
  counters: Record<string, number>;
  canaryThresholdsFixed: boolean; retentionDays: number; previousTeardownMs: number | null;
};
export type Commitment = CommitmentInput & { schema: typeof COMMITMENT_SCHEMA };
export type CommitmentResult = { outcome: "VALID" | "INVALID"; reasons: string[]; commitment: Commitment | null; digest: string | null };

const HEX40 = /^[0-9a-f]{40}$/u; const HEX64 = /^[0-9a-f]{64}$/u; const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/u;
const isTime = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value > 0;
const nonEmpty = (value: unknown): value is string => typeof value === "string" && value.length > 0 && value.length <= 128;

export function buildCommitment(input: CommitmentInput): CommitmentResult {
  const invalid = (reasons: string[]): CommitmentResult => ({ outcome: "INVALID", reasons: [...new Set(reasons)], commitment: null, digest: null });
  try {
    const reasons: string[] = [];
    if (!/^[a-z0-9-]{1,31}$/u.test(input.campaignId)) reasons.push("m1.commit.campaign_id_invalid");
    if (!nonEmpty(input.runId) || !/^[a-z0-9-]+$/u.test(input.runId)) reasons.push("m1.commit.run_id_invalid");
    if (!HEX40.test(input.commit)) reasons.push("m1.commit.commit_not_a_sha");
    if (input.treeClean !== true) reasons.push("m1.commit.tree_not_clean");
    if (input.parametersId !== BA0_FIELD_V1.id || input.parametersDigest !== PARAMETERS_DIGEST) reasons.push("m1.commit.parameters_not_code_pinned");
    if (!HEX64.test(input.fixtureDigest)) reasons.push("m1.commit.fixture_digest_invalid");
    if (!IPV4.test(input.target.ipv4)) reasons.push("m1.commit.target_not_ipv4_literal");
    if (!isTime(input.target.authorizedFromMs) || !isTime(input.target.authorizedUntilMs) || input.target.authorizedUntilMs <= input.target.authorizedFromMs) reasons.push("m1.commit.target_authorization_window_invalid");
    else if (input.target.authorizedUntilMs - input.target.authorizedFromMs > MAX_REMOTE_TARGET_LIFETIME_HOURS * 3_600_000) reasons.push("m1.commit.target_authorization_exceeds_72h");
    if (!isTime(input.window.startMs) || !isTime(input.window.endMs) || input.window.endMs <= input.window.startMs) reasons.push("m1.commit.run_window_invalid");
    else {
      if (input.window.startMs < input.target.authorizedFromMs) reasons.push("m1.commit.window_before_authorization");
      if (input.window.endMs + BA0_FIELD_V1.targetMinRemainingMs > input.target.authorizedUntilMs) reasons.push("m1.commit.window_leaves_less_than_target_min_remaining");
    }
    if (!nonEmpty(input.instance.id) || !nonEmpty(input.instance.imageId) || !nonEmpty(input.instance.bootId) || !isTime(input.instance.createdMs)) reasons.push("m1.commit.instance_facts_missing");
    else if (input.instance.createdMs >= input.window.startMs) reasons.push("m1.commit.instance_not_created_before_run");
    if (input.previousTeardownMs !== null && (!isTime(input.previousTeardownMs) || input.instance.createdMs <= input.previousTeardownMs)) reasons.push("m1.commit.instance_not_created_after_previous_teardown");
    const counters = Object.values(input.counters);
    if (counters.length === 0 || !counters.every((value) => value === 0)) reasons.push("m1.commit.counters_not_zero");
    if (input.canaryThresholdsFixed !== true) reasons.push("m1.commit.canary_thresholds_not_fixed");
    if (!Number.isSafeInteger(input.retentionDays) || input.retentionDays < 1) reasons.push("m1.commit.retention_invalid");
    if (reasons.length > 0) return invalid(reasons);
    const commitment: Commitment = { schema: COMMITMENT_SCHEMA, ...input };
    return { outcome: "VALID", reasons: [], commitment, digest: createHash("sha256").update(canonicalJson(commitment)).digest("hex") };
  } catch { return invalid(["m1.commit.evaluation_failed"]); }
}

export type FreshnessResult = { outcome: "FRESH" | "NOT_FRESH"; reasons: string[] };
/** Cross-run check for one campaign: every run has its own instance, boot, run id and commitment digest, and runs do not overlap. */
export function evaluateFreshness(runs: readonly { commitment: Commitment; digest: string }[]): FreshnessResult {
  const reasons: string[] = [];
  const unique = (values: string[]) => new Set(values).size === values.length;
  if (runs.length === 0) return { outcome: "NOT_FRESH", reasons: ["m1.fresh.no_runs"] };
  if (!unique(runs.map((r) => r.commitment.instance.id))) reasons.push("m1.fresh.instance_reused");
  if (!unique(runs.map((r) => r.commitment.instance.bootId))) reasons.push("m1.fresh.boot_reused");
  if (!unique(runs.map((r) => r.commitment.runId))) reasons.push("m1.fresh.run_id_reused");
  if (!unique(runs.map((r) => r.digest))) reasons.push("m1.fresh.commitment_reused");
  if (new Set(runs.map((r) => r.commitment.campaignId)).size !== 1) reasons.push("m1.fresh.campaign_mixed");
  if (new Set(runs.map((r) => r.commitment.commit)).size !== 1) reasons.push("m1.fresh.commit_changed");
  const ordered = [...runs].sort((a, b) => a.commitment.window.startMs - b.commitment.window.startMs);
  for (let i = 1; i < ordered.length; i++) {
    const previous = ordered[i - 1]!.commitment; const current = ordered[i]!.commitment;
    if (current.window.startMs < previous.window.endMs) reasons.push("m1.fresh.windows_overlap");
    if (current.instance.createdMs <= previous.window.endMs) reasons.push("m1.fresh.instance_created_before_previous_run_ended");
    if (current.previousTeardownMs === null || current.previousTeardownMs < previous.window.endMs) reasons.push("m1.fresh.previous_teardown_not_recorded");
  }
  return { outcome: reasons.length === 0 ? "FRESH" : "NOT_FRESH", reasons: [...new Set(reasons)] };
}
