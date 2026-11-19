/**
 * One evaluation of an observer directory, shared by the result writer (lab/m1/results.ts) and the acceptance recomputation (lab/m1/acceptance.ts) so the two can never
 * differ. It runs the UNCHANGED `evaluateObservation` (identity binding, request correlation, journey success, latency rule, origin attribution) and then the explicit
 * completeness check (`evaluateObservationCompleteness`: gapless receipts, collector declaration, covered window, heartbeats). The observation PASSES only if both pass.
 *
 * The heartbeat-gap limit comes from the VERIFIER when supplied (remote runs: the owner-set value recorded in the pre-run commitment). Only when the verifier supplies none does
 * the check fall back to the limit the observer's own meta file records, and that is reported as a limitation (an observer must not be the sole author of its own tolerance).
 * With neither, the observation is unavailable (the run is INCOMPLETE), never passed.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { evaluateObservation, type ObservationResult } from "./observation-check";
import type { ExpectedObservation } from "./observation-profile";
import { evaluateObservationCompleteness, type CompletenessResult } from "./observation-completeness";
import { readObservation, type ObservationFiles } from "./observation/run";

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const readJson = (file: string): unknown => { try { return JSON.parse(readFileSync(file, "utf8")); } catch { return undefined; } };

export const observerFiles = (observerDirectory: string): ObservationFiles => ({
  canaryFile: path.join(observerDirectory, "canary-results.json"), receiptsFile: path.join(observerDirectory, "origin-receipts.ndjson"),
  metaFile: path.join(observerDirectory, "observation-meta.json"), declarationFile: path.join(observerDirectory, "collector-declaration.json"),
});

export type ObservationBundle = {
  result: ObservationResult; completeness: CompletenessResult | null;
  /** true when no heartbeat-gap limit exists anywhere: the caller must treat the observation as unavailable (INCOMPLETE). */
  limitMissing: boolean; limitSource: "verifier" | "observer-meta" | "none";
};

export function evaluateObservationFiles(identity: { runId: string; campaignId: string }, observerDirectory: string, verifierMaxHeartbeatGapMs: number | null | undefined, expected: ExpectedObservation | null = null): ObservationBundle {
  const files = observerFiles(observerDirectory);
  const read = readObservation(files);
  const declaration = readJson(files.declarationFile);
  const base = evaluateObservation({ identity, canary: read.canary, receipts: read.receipts, meta: read.meta, declaration, expected });
  const meta = isRecord(read.meta) ? read.meta : {};
  const metaLimit = isRecord(meta.completeness) && typeof meta.completeness.maxHeartbeatGapMs === "number" ? meta.completeness.maxHeartbeatGapMs : null;
  const verifierLimit = typeof verifierMaxHeartbeatGapMs === "number" && Number.isFinite(verifierMaxHeartbeatGapMs) && verifierMaxHeartbeatGapMs > 0 ? verifierMaxHeartbeatGapMs : null;
  const limit = verifierLimit ?? metaLimit; const limitSource = verifierLimit !== null ? "verifier" : metaLimit !== null ? "observer-meta" : "none";
  const canary = isRecord(read.canary) ? read.canary : {};
  const plan = isRecord(canary.plan) ? canary.plan : null;
  const planned = plan !== null && [plan.baseline, plan.window, plan.recovery].every((n) => typeof n === "number") ? ((plan.baseline as number) + (plan.window as number) + (plan.recovery as number)) * 6 : null;
  const window = isRecord(meta.runWindow) && typeof meta.runWindow.startMs === "number" && typeof meta.runWindow.endMs === "number" ? { startMs: meta.runWindow.startMs, endMs: meta.runWindow.endMs } : { startMs: 0, endMs: 0 };
  const completeness = evaluateObservationCompleteness({ receipts: read.receipts, declaration, canarySteps: canary.steps, canaryPlannedSteps: planned, runWindow: window, maxHeartbeatGapMs: limit });
  // the declaration must be bound to THIS run and campaign (cross-run substitution of a collector declaration)
  const bound = isRecord(declaration) && declaration.runId === identity.runId && declaration.campaignId === identity.campaignId;
  const reasons = [...base.reasons];
  let outcome = base.outcome;
  if (completeness.outcome !== "PASS") { reasons.push(...completeness.reasons); outcome = outcome === "ERROR" || completeness.outcome === "ERROR" || completeness.outcome === "INCOMPLETE" ? "ERROR" : "REJECT"; }
  if (completeness.outcome !== "ERROR" && !bound) { reasons.push("m1.complete.declaration_not_bound_to_run"); outcome = outcome === "ERROR" ? "ERROR" : "REJECT"; }
  const limitations = [...base.limitations, ...(limitSource === "observer-meta" ? ["heartbeat_gap_limit_set_by_the_observer_not_the_verifier"] : [])];
  return { result: { ...base, outcome, reasons: [...new Set(reasons)], limitations }, completeness, limitMissing: limit === null, limitSource };
}
