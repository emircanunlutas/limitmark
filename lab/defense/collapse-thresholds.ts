/**
 * BA0 Slice 3 threshold set `ba0-collapse-local-v1`: named, versioned and fingerprinted (the SHA-256 of its canonical JSON is recorded in
 * the evidence). Every number is PROVISIONAL and uncalibrated, chosen for a loopback run with fixed counts and bounded concurrency.
 *
 * The L2 time constants are COMPRESSED for the lab (a two-second generation instead of minutes) and the filter is SCALED DOWN (2^13 bits
 * instead of the production-sized 2^23) so that a fixed-count render flood can walk the whole false-positive curve. The semantics are
 * identical and unit-tested on an injected clock; the scale and compression are stated in the evidence, never hidden.
 *
 * Slice 3 can only conclude LAYER-DIVERSITY-VALID or INVALID. It never concludes a defense-qualification PASS.
 */
import { createHash } from "node:crypto";
import type { L2Params } from "../../defense/plane/l2-protocol";
import { canonicalJson } from "../policy/thresholds";
import { BA0_ORIGIN_LOCAL_V1, type Ba0OriginThresholds } from "./origin-thresholds";

export type Ba0CollapseThresholds = {
  id: "ba0-collapse-local-v1";
  version: 1;
  description: string;
  calibration: "provisional-uncalibrated";
  journeys: {
    baselinePerLane: number;
    /** Canary journeys run concurrently with each hostile pressure phase, per cycle. */
    pressurePerCycle: number;
    /** Canary journeys issued immediately after pressure ends (residual denial). */
    afterPressure: number;
    /** Canary journeys after the recovery wait. */
    recovery: number;
    /** Minimum gap between protected journeys (a legitimate user's rate is far below the credited refill). */
    gapMs: number;
  };
  jcr: { minimum: number };
  latencyEnvelope: Ba0OriginThresholds["latencyEnvelope"];
  /** Looser, provisional envelope for the pressure phase only. */
  pressureLatencyEnvelope: Ba0OriginThresholds["latencyEnvelope"];
  timing: Ba0OriginThresholds["timing"];
  collector: { maxRequests: number; maxEventsPerRecord: number; maxJournalBytes: number };
  channel: Ba0OriginThresholds["channel"];
  composer: Ba0OriginThresholds["composer"];
  hop: Ba0OriginThresholds["hop"];
  l2: L2Params;
  fixtures: {
    f1: { count: number; concurrency: number };
    f2: { credits: number; postsPerCredit: number };
    f3: { journeys: number; postsPerCredit: number };
    f4: { renders: number; concurrency: number; fabricatedProbe: number };
    /** The forced fixture repeated this many times in the C1 burst. */
    forcedBurst: number;
    c2Fabricated: number;
  };
  cycles: { count: number; recoverySettleMs: number; attenuationTolerance: number };
};

const L2_LAB: L2Params = {
  filterBits: 2 ** 13, filterHashes: 7, epochMs: 2_000,
  credited: { capacity: 16, refillPerSecond: 8 },
  unverified: { capacity: 3, refillPerSecond: 1 },
  maxUses: 3,
  // requiredLedgerCapacity(16, 8, 2000) = 16 + ceil(8*2*2) + 1 = 49
  ledgerCapacity: 64,
  stage: { timeoutMs: 50, maxConcurrent: 64 },
};

export const BA0_COLLAPSE_LOCAL_V1: Ba0CollapseThresholds = Object.freeze({
  id: "ba0-collapse-local-v1",
  version: 1,
  description: "BA0 Slice 3 loopback run: journey-lanes L2 behind L1, reference/normal/collapse arms, fixed counts, bounded concurrency, no external traffic.",
  calibration: "provisional-uncalibrated",
  journeys: { baselinePerLane: 12, pressurePerCycle: 6, afterPressure: 3, recovery: 4, gapMs: 250 },
  jcr: { minimum: 1 },
  latencyEnvelope: BA0_ORIGIN_LOCAL_V1.latencyEnvelope,
  pressureLatencyEnvelope: { id: "ba0-latency-prov-v1", status: "provisional", maxAddedP95Ms: 250, maxAddedP99Ms: 500, maxRelativeP95Factor: 8, relativeFloorMs: 10 },
  timing: BA0_ORIGIN_LOCAL_V1.timing,
  collector: { maxRequests: 20_000, maxEventsPerRecord: 32, maxJournalBytes: 48 * 1_048_576 },
  channel: { queueCap: 16_384, windowCap: 8_192 },
  composer: BA0_ORIGIN_LOCAL_V1.composer,
  hop: BA0_ORIGIN_LOCAL_V1.hop,
  l2: L2_LAB,
  fixtures: {
    f1: { count: 200, concurrency: 8 },
    f2: { credits: 2, postsPerCredit: 8 },
    f3: { journeys: 16, postsPerCredit: 3 },
    f4: { renders: 2_500, concurrency: 8, fabricatedProbe: 200 },
    forcedBurst: 12,
    c2Fabricated: 6,
  },
  cycles: { count: 3, recoverySettleMs: 6_000, attenuationTolerance: 0.05 },
}) as Ba0CollapseThresholds;

export function ba0CollapseFingerprint(set: Ba0CollapseThresholds = BA0_COLLAPSE_LOCAL_V1): { id: string; version: number; sha256: string } {
  return { id: set.id, version: set.version, sha256: createHash("sha256").update(canonicalJson(set)).digest("hex") };
}

export type Gate = { id: string; ok: boolean; detail: string };
export type CollapseVerdict = "LAYER-DIVERSITY-VALID" | "INVALID";

/** The only two conclusions Slice 3 may reach. INVALID carries every failed gate, not just the first. */
export function decideCollapseVerdict(input: { gates: readonly Gate[]; anomalyTotal: number }): { verdict: CollapseVerdict; reasons: string[] } {
  const reasons: string[] = [];
  if (input.anomalyTotal > 0) reasons.push("ledger_anomalies_present");
  for (const gate of input.gates) if (!gate.ok) reasons.push(`gate_failed:${gate.id}`);
  if (input.gates.length === 0) reasons.push("no_gates_evaluated");
  return { verdict: reasons.length === 0 ? "LAYER-DIVERSITY-VALID" : "INVALID", reasons };
}
