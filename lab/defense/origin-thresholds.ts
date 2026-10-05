/**
 * BA0 Slice 2 threshold set `ba0-origin-local-v1`: named, versioned and fingerprinted (the SHA-256 of its canonical JSON is recorded in the
 * evidence). Every number is PROVISIONAL and uncalibrated, chosen for a loopback run with fixed counts.
 *
 * Slice 2 can only conclude APP-NON-BYPASS-VALID or INVALID. It never concludes a defense-qualification PASS, and APP-NON-BYPASS-VALID
 * says nothing about network or transport isolation: that is explicitly `not_measured`.
 */
import { createHash } from "node:crypto";
import { canonicalJson } from "../policy/thresholds";
import { BA0_LOCAL_V1, type Ba0Thresholds } from "./thresholds";

export type Ba0OriginThresholds = {
  id: "ba0-origin-local-v1";
  version: 1;
  description: string;
  calibration: "provisional-uncalibrated";
  journeys: { baselinePerLane: number; postDirectPerLane: number };
  jcr: { minimum: number };
  latencyEnvelope: Ba0Thresholds["latencyEnvelope"];
  timing: Ba0Thresholds["timing"];
  collector: Ba0Thresholds["collector"];
  channel: Ba0Thresholds["channel"];
  composer: Ba0Thresholds["composer"];
  hop: { pbLifetimeMs: number; baLifetimeMs: number; skewMs: number; replayCapacity: number; bodyDeadlineMs: number; forwardTimeoutMs: number };
  corpus: { semantic: number; direct: number };
};

export const BA0_ORIGIN_LOCAL_V1: Ba0OriginThresholds = Object.freeze({
  id: "ba0-origin-local-v1",
  version: 1,
  description: "BA0 Slice 2 loopback run: application non-bypass only, fixed counts, no load ramp, no external traffic. Network non-bypass is not measured.",
  calibration: "provisional-uncalibrated",
  journeys: { baselinePerLane: 20, postDirectPerLane: 10 },
  jcr: { minimum: 1 },
  latencyEnvelope: BA0_LOCAL_V1.latencyEnvelope,
  timing: BA0_LOCAL_V1.timing,
  collector: BA0_LOCAL_V1.collector,
  channel: BA0_LOCAL_V1.channel,
  composer: BA0_LOCAL_V1.composer,
  hop: { pbLifetimeMs: 5_000, baLifetimeMs: 2_000, skewMs: 1_000, replayCapacity: 4_096, bodyDeadlineMs: 3_000, forwardTimeoutMs: 4_000 },
  corpus: { semantic: 18, direct: 110 },
}) as Ba0OriginThresholds;

export function ba0OriginFingerprint(set: Ba0OriginThresholds = BA0_ORIGIN_LOCAL_V1): { id: string; version: number; sha256: string } {
  return { id: set.id, version: set.version, sha256: createHash("sha256").update(canonicalJson(set)).digest("hex") };
}

export type OriginVerdictInput = {
  anomalyTotal: number;
  /** Slice-1 plane-side identities (over the Slice-1 lanes) and the Slice-2 origin identities. */
  identitiesOk: boolean;
  originIdentitiesOk: boolean;
  jcr: { phase: string; lane: string; rate: number }[];
  latencyOk: boolean;
  parityMismatches: number;
  /** Slice-1 corpus, semantic corpus, direct corpus: violations of the exact per-case expectation. */
  corpusViolations: number;
  semanticViolations: number;
  directViolations: number;
  corpusCount: number;
  expectedCorpusCount: number;
  semanticCount: number;
  directCount: number;
  positiveControlsOk: boolean;
  lineageComplete: boolean;
  mutationReconciled: boolean;
  countersReconciled: boolean;
};

export type OriginVerdict = "APP-NON-BYPASS-VALID" | "INVALID";

/**
 * The only two conclusions Slice 2 may reach. APP-NON-BYPASS-VALID requires EVERY condition below: a missing lineage, an unreconciled
 * identity, a failed positive control, a mutation that does not reconcile three ways, or a single anomaly makes the run INVALID with
 * every reason listed.
 */
export function decideOriginVerdict(thresholds: Ba0OriginThresholds, input: OriginVerdictInput): { verdict: OriginVerdict; reasons: string[] } {
  const reasons: string[] = [];
  if (input.anomalyTotal > 0) reasons.push("ledger_anomalies_present");
  if (!input.identitiesOk) reasons.push("accounting_identity_failed");
  if (!input.originIdentitiesOk) reasons.push("origin_identity_failed");
  for (const entry of input.jcr) if (entry.rate < thresholds.jcr.minimum) reasons.push(`jcr_below_minimum:${entry.lane}.${entry.phase}`);
  if (input.jcr.length === 0) reasons.push("jcr_not_measured");
  if (!input.latencyOk) reasons.push("latency_envelope_exceeded");
  if (input.parityMismatches > 0) reasons.push("protected_control_parity_mismatch");
  if (input.corpusCount !== input.expectedCorpusCount) reasons.push("corpus_count_mismatch");
  if (input.corpusViolations > 0) reasons.push("corpus_expectation_violated");
  if (input.semanticCount !== thresholds.corpus.semantic) reasons.push("semantic_count_mismatch");
  if (input.semanticViolations > 0) reasons.push("semantic_expectation_violated");
  if (input.directCount !== thresholds.corpus.direct) reasons.push("direct_count_mismatch");
  if (input.directViolations > 0) reasons.push("direct_expectation_violated");
  if (!input.positiveControlsOk) reasons.push("positive_control_failed");
  if (!input.lineageComplete) reasons.push("lineage_incomplete");
  if (!input.mutationReconciled) reasons.push("mutation_not_reconciled");
  if (!input.countersReconciled) reasons.push("counters_not_reconciled");
  return { verdict: reasons.length === 0 ? "APP-NON-BYPASS-VALID" : "INVALID", reasons };
}
