import { createHash } from "node:crypto";
import { CreditFilter } from "../../defense/core/credit-filter";
import {
  JourneyLanes, TokenBucket, UNIT, UseLedger, creditTagOf, extractSubmissionToken, operationClassOf,
  type LaneDecision, type LanesConfig, type OperationClass,
} from "../../defense/core/lanes";
import type { LayerRequest } from "../../defense/core/types";
import { BA0_FIELD_V1 } from "../../lab/defense/field-thresholds";

/**
 * EXPERIMENTAL, VERSIONED "V2 shadow" model of per-class credited ceilings (Approach A in docs/BA0_L2_FAIRNESS_ARCHITECTURE_DECISION.md).
 *
 * Nothing here is production code and nothing here enforces anything. It lives under tests/ and imports defense/ read-only. It has two parts:
 *
 *  - `V2Model`: a complete, independent re-statement of the L2 decision with ONE additional restriction (a per-class ceiling) between
 *    classification and the global credited take. It has its own filter, use ledger and buckets, so its state is what a V2 plane would
 *    have, not a function of V1's drained bucket. With `enforce: false` it must equal V1 exactly (a differential test pins that).
 *  - `ShadowedLanes`: runs the REAL `JourneyLanes` (V1) as the only decider and feeds the same request stream to any number of V2 models,
 *    returning their verdicts as data. It calls exactly `v1.decide` and `v1.enroll` on V1, nothing else (a test pins that too).
 *
 * V1 capacity, refill and K are taken from BA0_FIELD_V1.l2 and are never raised: V2 only adds a restriction, so the credited bucket is still
 * the sole exposure bound. Every parameter below that is NOT a V1 parameter is an assumption of this study.
 */
export const V2_VERSION = "l2-v2-shadow-experimental-1";
export const FIELD_L2 = BA0_FIELD_V1.l2;

/** The network-class hint. Always UNTRUSTED input: `peer` is the only source a safe policy enforces on. */
export type ClassHint =
  | { source: "peer"; id: string }             // derived from the connected peer address by the plane itself (not forgeable past the handshake; rotatable)
  | { source: "forwarded"; id: string }        // taken from a header: attacker-controlled unless a trusted hop is proven (not assumed here)
  | { source: "declared_shared"; id: string }  // operator-declared proxy/CDN/shared infrastructure: the class says nothing about the sender
  | { source: "missing" };                     // no usable hint

export type V2Params = {
  /** false: the model never sheds on a class ceiling (must equal V1). */
  enforce: boolean;
  /** Fixed number of class buckets (state is O(S); no allocation per request, nothing to exhaust). */
  classBuckets: number;
  classCapacity: number;
  /** phi x the credited refill. 1/8 of 2/s = 0.25/s. */
  classRefillPerSecond: number;
  /** null: enforce always. Otherwise enforce only while the V2 global credited level is below gate x capacity ("under contention"). */
  gate: number | null;
  /** UNSAFE counterexample switch: enforce on forwarded-header hints too. A safe policy keeps this false. */
  trustForwarded: boolean;
  key: Buffer;
};
export const V2_BASE: V2Params = Object.freeze({
  enforce: true, classBuckets: 1024, classCapacity: 2, classRefillPerSecond: FIELD_L2.credited.refillPerSecond / 8, gate: null, trustForwarded: false, key: Buffer.alloc(32, 5),
});
export const V2_VARIANTS = {
  off: { ...V2_BASE, enforce: false },
  always: { ...V2_BASE },
  gated: { ...V2_BASE, gate: 0.5 },
  /** POST-HOC candidate: chosen from an exploratory sweep AFTER the pre-registered run failed H2 for `gated`; validated only on the held-out matrix. */
  gated_low: { ...V2_BASE, gate: 0.25 },
  always_trustfwd: { ...V2_BASE, trustForwarded: true },
  gated_trustfwd: { ...V2_BASE, gate: 0.5, trustForwarded: true },
} as const satisfies Record<string, V2Params>;
export type V2VariantName = keyof typeof V2_VARIANTS;
/** Exploratory parameter variants (registered by name by a study script; never part of the pre-registered hypotheses). */
export const EXPLORATORY = new Map<string, V2Params>();
export function variantParams(name: string): V2Params {
  const params = (V2_VARIANTS as Record<string, V2Params>)[name] ?? EXPLORATORY.get(name);
  if (!params) throw new Error(`unknown V2 variant ${name}`);
  return params;
}

export type V2Decision = {
  class: OperationClass; lane: "open" | "credited" | "unverified" | null; outcome: "admitted" | "shed" | "error";
  reason?: "lane_budget" | "class_ceiling" | "ledger_full"; creditTag?: string; dt?: number; lvl?: number; lseq?: number;
  /** The class the decision was ENFORCED on, or null when the hint was exempt (missing, declared shared, or an untrusted forwarded one). */
  enforcedClass: number | null;
  hintSource: ClassHint["source"];
};

export type V2Stats = {
  creditedAdmitted: number; creditedShedGlobal: number; classShed: number; unverifiedAdmitted: number; unverifiedShed: number; errors: number;
  /** Class sheds by the hint source of the shed request. A safe policy must show only `peer` here. */
  classShedBySource: Record<string, number>;
  exemptBySource: Record<string, number>;
  /** Credited-eligible requests by peer class id (for the degenerate-topology flag). */
  peerRequestsByClass: Map<string, number>;
  classesShed: number;
};

export class V2Model {
  private readonly filter: CreditFilter;
  private readonly credited: TokenBucket;
  private readonly unverified: TokenBucket;
  private readonly ledger: UseLedger;
  private readonly classBuckets = new Map<number, TokenBucket>();
  private readonly shedClasses = new Set<number>();
  private readonly counters: V2Stats = {
    creditedAdmitted: 0, creditedShedGlobal: 0, classShed: 0, unverifiedAdmitted: 0, unverifiedShed: 0, errors: 0,
    classShedBySource: {}, exemptBySource: {}, peerRequestsByClass: new Map(), classesShed: 0,
  };

  constructor(private readonly config: LanesConfig, readonly params: V2Params) {
    this.filter = new CreditFilter({ bits: config.filterBits, hashes: config.filterHashes, epochMs: config.epochMs, mono: config.mono, key: config.key });
    this.credited = new TokenBucket(config.credited.capacity, config.credited.refillPerSecond, config.mono);
    this.unverified = new TokenBucket(config.unverified.capacity, config.unverified.refillPerSecond, config.mono);
    this.ledger = new UseLedger(config.ledgerCapacity, config.maxUses);
  }

  /** Identical to JourneyLanes.enroll, on this model's own filter and ledger. */
  enroll(token: string): void {
    const digest = this.filter.digest(token);
    const epoch = this.filter.advance();
    if (this.ledger.committed(digest.toString("base64url"), epoch) !== undefined) return;
    if (this.filter.hasInActive(digest)) return;
    this.filter.insert(digest);
  }

  private classIndex(id: string): number {
    return createHash("sha256").update(this.params.key).update(id, "utf8").digest().readUInt32LE(0) % this.params.classBuckets;
  }
  private bucketFor(index: number): TokenBucket {
    let bucket = this.classBuckets.get(index);
    if (bucket === undefined) { bucket = new TokenBucket(this.params.classCapacity, this.params.classRefillPerSecond, this.config.mono); this.classBuckets.set(index, bucket); }
    return bucket;
  }
  /** The enforcement class of a hint, or null when the policy must not enforce on it. Untrusted sources never produce a class. */
  private enforcementClass(hint: ClassHint): number | null {
    if (hint.source === "peer" || (hint.source === "forwarded" && this.params.trustForwarded)) return this.classIndex(hint.id);
    return null;
  }

  decide(request: LayerRequest, hint: ClassHint): V2Decision {
    const cls = operationClassOf(request.method, request.target);
    const base = { class: cls, hintSource: hint.source, enforcedClass: null as number | null };
    if (cls === "open") return { ...base, lane: "open", outcome: "admitted" };
    const epoch = this.filter.advance();
    this.ledger.maybePurge(epoch);
    let digest: Buffer | null = null; let key = ""; let used: number | undefined;
    if (cls === "mutation") {
      const token = extractSubmissionToken(request);
      if (token !== null) {
        digest = this.filter.digest(token);
        if (this.filter.has(digest)) { key = digest.toString("base64url"); used = this.ledger.committed(key, epoch); } else digest = null;
      }
    }
    const credited = digest !== null && (used === undefined || used < this.config.maxUses);
    if (!credited) {
      const taken = this.unverified.take();
      if (!taken.ok) { this.counters.unverifiedShed++; return { ...base, lane: "unverified", outcome: "shed", reason: "lane_budget", dt: taken.dt, lvl: taken.lvl, lseq: taken.lseq }; }
      this.counters.unverifiedAdmitted++;
      return { ...base, lane: "unverified", outcome: "admitted", dt: taken.dt, lvl: taken.lvl, lseq: taken.lseq };
    }
    if (used === undefined && !this.ledger.canAllocate(epoch)) { this.counters.errors++; return { ...base, lane: null, outcome: "error", reason: "ledger_full" }; }

    // --- V2 addition: the class ceiling. CHECK both levels, then TAKE both, in this one synchronous function: a class shed consumes no global token and no use.
    const classIndex = this.enforcementClass(hint);
    if (hint.source === "peer") this.counters.peerRequestsByClass.set(hint.id, (this.counters.peerRequestsByClass.get(hint.id) ?? 0) + 1);
    if (classIndex === null) this.counters.exemptBySource[hint.source] = (this.counters.exemptBySource[hint.source] ?? 0) + 1;
    const meter = classIndex === null ? null : this.bucketFor(classIndex);
    const underContention = this.params.gate === null || this.credited.levelUnits() < this.params.gate * this.config.credited.capacity * UNIT;
    if (this.params.enforce && meter !== null && underContention && meter.levelUnits() < UNIT) {
      this.counters.classShed++;
      this.counters.classShedBySource[hint.source] = (this.counters.classShedBySource[hint.source] ?? 0) + 1;
      if (!this.shedClasses.has(classIndex as number)) { this.shedClasses.add(classIndex as number); this.counters.classesShed++; }
      return { ...base, enforcedClass: classIndex, lane: "credited", outcome: "shed", reason: "class_ceiling" };
    }
    const taken = this.credited.take();
    if (!taken.ok) { this.counters.creditedShedGlobal++; return { ...base, enforcedClass: classIndex, lane: "credited", outcome: "shed", reason: "lane_budget", dt: taken.dt, lvl: taken.lvl, lseq: taken.lseq }; }
    this.ledger.commit(key, epoch);
    if (meter !== null) meter.take(); // the meter always records what a class was admitted; it only SHEDS when enforcement is on and contended
    this.counters.creditedAdmitted++;
    return { ...base, enforcedClass: classIndex, lane: "credited", outcome: "admitted", creditTag: creditTagOf(digest as Buffer), dt: taken.dt, lvl: taken.lvl, lseq: taken.lseq };
  }

  stats(): V2Stats { return { ...this.counters, classShedBySource: { ...this.counters.classShedBySource }, exemptBySource: { ...this.counters.exemptBySource } }; }
  ledgerSnapshot() { return this.ledger.snapshot(); }
  creditedSnapshot() { return this.credited.snapshot(); }
}

export type ShadowVerdict = { v1: LaneDecision; shadow: Record<string, V2Decision> };

/** V1 decides; every V2 model only OBSERVES the same stream. V1 is touched through `decide` and `enroll`, exactly as the plane touches it. */
export class ShadowedLanes {
  readonly v1: JourneyLanes;
  private readonly models: ReadonlyMap<string, V2Model>;
  constructor(config: LanesConfig, variants: Readonly<Record<string, V2Params>>) {
    this.v1 = new JourneyLanes(config);
    this.models = new Map(Object.entries(variants).map(([name, params]) => [name, new V2Model(config, params)]));
  }
  enroll(token: string): void {
    this.v1.enroll(token);
    for (const model of this.models.values()) model.enroll(token);
  }
  decide(request: LayerRequest, hint: ClassHint): ShadowVerdict {
    const v1 = this.v1.decide(request);
    const shadow: Record<string, V2Decision> = {};
    for (const [name, model] of this.models) shadow[name] = model.decide(request, hint);
    return { v1, shadow };
  }
  model(name: string): V2Model { const model = this.models.get(name); if (!model) throw new Error(`no such V2 variant ${name}`); return model; }
}

export function laneConfig(mono: () => number): LanesConfig {
  return {
    filterBits: FIELD_L2.filterBits, filterHashes: FIELD_L2.filterHashes, epochMs: FIELD_L2.epochMs, credited: FIELD_L2.credited, unverified: FIELD_L2.unverified,
    maxUses: FIELD_L2.maxUses, ledgerCapacity: FIELD_L2.ledgerCapacity, mono, key: Buffer.alloc(32, 7),
  };
}
