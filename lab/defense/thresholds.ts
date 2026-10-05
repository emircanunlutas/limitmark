/**
 * BA0 threshold set `ba0-local-v1`: named, versioned and fingerprinted (the SHA-256 of its canonical JSON is recorded in the evidence).
 *
 * Every number here is PROVISIONAL and uncalibrated, chosen for a loopback baseline. The latency envelope in particular is an
 * initial absolute-plus-relative bound with a stated floor below which the ratio is meaningless; it is a measurement aid, not a
 * product invariant, and changing any value changes the recorded fingerprint.
 *
 * Slice 1 can only conclude BASELINE-VALID or INVALID. It never concludes a defense-qualification PASS.
 */
import { createHash } from "node:crypto";
import { canonicalJson, summarizeLatencies, type LatencySummary } from "../policy/thresholds";

export type Ba0Thresholds = {
  id: "ba0-local-v1";
  version: 1;
  description: string;
  calibration: "provisional-uncalibrated";
  journeys: { baselinePerLane: number; postCorpusPerLane: number };
  /** Journey Completion Rate required per lane and phase. 1 = every journey must complete all five steps. */
  jcr: { minimum: number };
  latencyEnvelope: {
    id: "ba0-latency-prov-v1";
    status: "provisional";
    /** Protected p95 may exceed control p95 by at most this many milliseconds... */
    maxAddedP95Ms: number;
    maxAddedP99Ms: number;
    /** ...and, when control p95 is at least `relativeFloorMs`, by at most this factor. */
    maxRelativeP95Factor: number;
    relativeFloorMs: number;
  };
  timing: { clientTimeoutMs: number; drainTimeoutMs: number; finTimeoutMs: number; settleMs: number; stallDeadlineMs: number };
  collector: { maxRequests: number; maxEventsPerRecord: number; maxJournalBytes: number };
  channel: { queueCap: number; windowCap: number };
  composer: { timeoutMs: number; maxConcurrent: number };
};

export const BA0_LOCAL_V1: Ba0Thresholds = Object.freeze({
  id: "ba0-local-v1",
  version: 1,
  description: "BA0 Slice 1 loopback baseline: application plane only, fixed counts, no load ramp, no external traffic.",
  calibration: "provisional-uncalibrated",
  journeys: { baselinePerLane: 20, postCorpusPerLane: 10 },
  jcr: { minimum: 1 },
  latencyEnvelope: { id: "ba0-latency-prov-v1", status: "provisional", maxAddedP95Ms: 75, maxAddedP99Ms: 150, maxRelativeP95Factor: 8, relativeFloorMs: 10 },
  timing: { clientTimeoutMs: 5_000, drainTimeoutMs: 5_000, finTimeoutMs: 5_000, settleMs: 300, stallDeadlineMs: 400 },
  collector: { maxRequests: 5_000, maxEventsPerRecord: 32, maxJournalBytes: 8 * 1_048_576 },
  channel: { queueCap: 4_096, windowCap: 2_048 },
  composer: { timeoutMs: 250, maxConcurrent: 64 },
}) as Ba0Thresholds;

export function ba0Fingerprint(set: Ba0Thresholds = BA0_LOCAL_V1): { id: string; version: number; sha256: string } {
  return { id: set.id, version: set.version, sha256: createHash("sha256").update(canonicalJson(set)).digest("hex") };
}

export type LatencyComparison = {
  ok: boolean;
  control: LatencySummary;
  protected: LatencySummary;
  addedP95Ms: number;
  addedP99Ms: number;
  /** Null when control p95 is below the floor, where a ratio is not meaningful. */
  relativeP95: number | null;
  reasons: string[];
};

export function compareLatency(envelope: Ba0Thresholds["latencyEnvelope"], controlMs: readonly number[], protectedMs: readonly number[]): LatencyComparison {
  const control = summarizeLatencies(controlMs);
  const guarded = summarizeLatencies(protectedMs);
  const round = (value: number) => Math.round(value * 100) / 100;
  const addedP95Ms = round(guarded.p95 - control.p95);
  const addedP99Ms = round(guarded.p99 - control.p99);
  const relativeP95 = control.p95 >= envelope.relativeFloorMs ? round(guarded.p95 / control.p95) : null;
  const reasons: string[] = [];
  if (control.count === 0 || guarded.count === 0) reasons.push("latency_samples_missing");
  if (addedP95Ms > envelope.maxAddedP95Ms) reasons.push("latency_added_p95_exceeded");
  if (addedP99Ms > envelope.maxAddedP99Ms) reasons.push("latency_added_p99_exceeded");
  if (relativeP95 !== null && relativeP95 > envelope.maxRelativeP95Factor) reasons.push("latency_relative_p95_exceeded");
  return { ok: reasons.length === 0, control, protected: guarded, addedP95Ms, addedP99Ms, relativeP95, reasons };
}

export type VerdictInput = {
  anomalyTotal: number;
  identitiesOk: boolean;
  jcr: { phase: string; lane: string; rate: number }[];
  latencyOk: boolean;
  parityMismatches: number;
  corpusViolations: number;
  corpusCount: number;
  expectedCorpusCount: number;
};

export type Ba0Verdict = "BASELINE-VALID" | "INVALID";

/** The only two conclusions Slice 1 may reach. INVALID carries every reason, not just the first. */
export function decideVerdict(thresholds: Ba0Thresholds, input: VerdictInput): { verdict: Ba0Verdict; reasons: string[] } {
  const reasons: string[] = [];
  if (input.anomalyTotal > 0) reasons.push("ledger_anomalies_present");
  if (!input.identitiesOk) reasons.push("accounting_identity_failed");
  for (const entry of input.jcr) if (entry.rate < thresholds.jcr.minimum) reasons.push(`jcr_below_minimum:${entry.lane}.${entry.phase}`);
  if (input.jcr.length === 0) reasons.push("jcr_not_measured");
  if (!input.latencyOk) reasons.push("latency_envelope_exceeded");
  if (input.parityMismatches > 0) reasons.push("protected_control_parity_mismatch");
  if (input.corpusCount !== input.expectedCorpusCount) reasons.push("corpus_count_mismatch");
  if (input.corpusViolations > 0) reasons.push("corpus_expectation_violated");
  return { verdict: reasons.length === 0 ? "BASELINE-VALID" : "INVALID", reasons };
}
