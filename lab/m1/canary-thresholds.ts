/**
 * Owner-approved canary latency thresholds: the RECORD in which they are fixed before a campaign, and its validator. This module SETS NO NUMBER. Every value in the shipped template
 * is null; the record is UNSET until the owner fills it from baseline measurements (procedure: M1-ENVIRONMENT-PREPARATION.md section 3 and M1-CANARY-BASELINE-PROCEDURE in the
 * readiness report) and approves it. Pure; never throws.
 *
 * `evaluateLatencyAgainstThresholds` is inert while the record is UNSET: it returns NOT_EVALUATED, which a qualification gate must treat as "latency not decided", never as a pass.
 * The pinned BA0_FIELD_V1 window rule (lab/m1/observation-check.ts) is a separate, already-defined rule and is not changed or replaced by this record.
 */
import { createHash } from "node:crypto";
import { canonicalJson } from "../evidence/manifest";
import type { CanaryContractResult } from "./canary-contract";

export const THRESHOLDS_SCHEMA = "m1-canary-thresholds-v1";
const PHASES = ["baseline", "window", "recovery"] as const;
type Triple = { p50: number | null; p95: number | null; p99: number | null };
export type OwnerCanaryThresholds = {
  schema: typeof THRESHOLDS_SCHEMA;
  approval: { approvedBy: string | null; approvedAt: string | null; reference: string | null };
  /** Evidence ids of the baseline measurement runs the numbers below were derived from (at least three separate fresh instances). */
  baselineMeasurementIds: string[];
  /** Maximum acceptable percentiles (ms) per phase. The owner chooses them from the measured baseline and its run-to-run spread. */
  maxLatencyMs: Record<(typeof PHASES)[number], Triple>;
  maxRecoveryTimeToBaselineMs: number | null;
  maxHeartbeatGapMs: number | null;
  operationalActions: string[];
};
export type ThresholdsStatus = { status: "UNSET" | "FIXED" | "INVALID"; missing: string[]; problems: string[]; digest: string | null };

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const positive = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value > 0;

export function validateOwnerThresholds(value: unknown): ThresholdsStatus {
  const invalid = (problems: string[]): ThresholdsStatus => ({ status: "INVALID", missing: [], problems, digest: null });
  try {
    if (!isRecord(value) || value.schema !== THRESHOLDS_SCHEMA || !isRecord(value.approval) || !isRecord(value.maxLatencyMs) || !Array.isArray(value.baselineMeasurementIds) || !Array.isArray(value.operationalActions)) return invalid(["m1.thresholds.shape"]);
    const t = value as unknown as OwnerCanaryThresholds;
    const missing: string[] = []; const problems: string[] = [];
    for (const key of ["approvedBy", "approvedAt", "reference"] as const) if (t.approval[key] === null) missing.push(`approval.${key}`); else if (typeof t.approval[key] !== "string" || t.approval[key] === "") problems.push(`m1.thresholds.approval.${key}`);
    if (t.approval.approvedAt !== null && Number.isNaN(Date.parse(String(t.approval.approvedAt)))) problems.push("m1.thresholds.approvedAt_not_a_date");
    if (t.baselineMeasurementIds.length === 0) missing.push("baselineMeasurementIds");
    else if (new Set(t.baselineMeasurementIds).size !== t.baselineMeasurementIds.length || t.baselineMeasurementIds.length < 3 || t.baselineMeasurementIds.some((id) => typeof id !== "string" || id === "")) problems.push("m1.thresholds.baseline_needs_three_distinct_measurements");
    for (const phase of PHASES) {
      const triple = t.maxLatencyMs[phase];
      if (!isRecord(triple)) { problems.push(`m1.thresholds.${phase}_missing`); continue; }
      for (const percentile of ["p50", "p95", "p99"] as const) if (triple[percentile] === null) missing.push(`maxLatencyMs.${phase}.${percentile}`); else if (!positive(triple[percentile])) problems.push(`m1.thresholds.${phase}.${percentile}_not_positive`);
      if (positive(triple.p50) && positive(triple.p95) && positive(triple.p99) && !(triple.p50 <= triple.p95 && triple.p95 <= triple.p99)) problems.push(`m1.thresholds.${phase}_percentiles_not_ordered`);
    }
    if (t.maxRecoveryTimeToBaselineMs === null) missing.push("maxRecoveryTimeToBaselineMs"); else if (!positive(t.maxRecoveryTimeToBaselineMs)) problems.push("m1.thresholds.recovery_time_not_positive");
    if (t.maxHeartbeatGapMs === null) missing.push("maxHeartbeatGapMs"); else if (!positive(t.maxHeartbeatGapMs)) problems.push("m1.thresholds.heartbeat_gap_not_positive");
    if (t.operationalActions.length === 0) missing.push("operationalActions"); else if (t.operationalActions.some((a) => typeof a !== "string" || a === "")) problems.push("m1.thresholds.operational_action_invalid");
    if (problems.length > 0) return invalid(problems);
    if (missing.length > 0) return { status: "UNSET", missing, problems: [], digest: null };
    return { status: "FIXED", missing: [], problems: [], digest: createHash("sha256").update(canonicalJson(t)).digest("hex") };
  } catch { return invalid(["m1.thresholds.evaluation_failed"]); }
}

export type LatencyEvaluation = { outcome: "PASS" | "REJECT" | "NOT_EVALUATED"; reasons: string[] };
/** Compares the MEASURED attack-window and recovery percentiles of a canary contract result with the owner-fixed maxima. Inert unless the record is FIXED. */
export function evaluateLatencyAgainstThresholds(canary: Pick<CanaryContractResult, "latency">, thresholds: unknown): LatencyEvaluation {
  const status = validateOwnerThresholds(thresholds);
  if (status.status !== "FIXED") return { outcome: "NOT_EVALUATED", reasons: [status.status === "UNSET" ? "m1.latency.thresholds_unset" : "m1.latency.thresholds_invalid"] };
  const t = thresholds as OwnerCanaryThresholds; const reasons: string[] = [];
  for (const phase of ["window", "recovery"] as const) {
    const measured = canary.latency[phase];
    if (measured === undefined || measured.p50 === null || measured.p95 === null || measured.p99 === null) { reasons.push(`m1.latency.${phase}_not_measured`); continue; }
    for (const percentile of ["p50", "p95", "p99"] as const) if (measured[percentile]! > t.maxLatencyMs[phase][percentile]!) reasons.push(`m1.latency.${phase}.${percentile}_exceeds_owner_threshold`);
  }
  return { outcome: reasons.length === 0 ? "PASS" : "REJECT", reasons };
}
