import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { CreditFilter } from "../../defense/core/credit-filter";
import {
  JourneyLanes, TokenBucket, UNIT, UseLedger, extractSubmissionToken, operationClassOf, type LanesConfig,
} from "../../defense/core/lanes";
import type { LayerRequest } from "../../defense/core/types";
import { V2Model, variantParams } from "./l2-v2-shadow";

/**
 * EXPERIMENTAL, RESEARCH-ONLY models for the L2 alternatives study (docs/BA0_L2_V2_ALTERNATIVES_EVALUATION.md), versioned
 * `l2-alt-research-experimental-1`. Nothing here is production code, nothing is enforced, and `defense/` is imported read-only.
 *
 * Every policy sits in the SAME place: after V1's classification (a credited request is a mutation with a genuine Bloom-filter credit that still
 * has uses left) and before the credited take. A policy may only RESTRICT or PARTITION; the credited capacity and refill are never raised, so the
 * sum of the credited buckets stays 10 @ 2/s (the V1 exposure bound), a refusal consumes no token and no ledger use (P1/P3), and
 * unverified/open handling is V1's, unchanged. Each policy has its own filter, ledger and buckets: it is a counterfactual decider, not a
 * function of V1's drained state.
 *
 * Identities available to an arbiter are all UNTRUSTED and none identifies a human: the credit token (free to mint), a session label (free to
 * create), the peer network class (rotatable at an unknown cost) and nothing else.
 */
export const ALT_VERSION = "l2-alt-research-experimental-1";

export type Attestation = { id: string; exp: number; mac: string };
export type Ctx = { klass: string; session: string; token: string; att: Attestation | null; instance: number | null };
export type Out = { admitted: boolean; lane: "open" | "credited" | "unverified" | null; reason?: string; via?: "reserved" | "general" | "borrowed" };

export interface Decider {
  enroll(token: string): void;
  decide(request: LayerRequest, ctx: Ctx): Out;
  /** Local deterministic issuer only: ask for an attestation for this network class. */
  issue?(klass: string): Attestation | null;
  counters(): Record<string, number>;
}

// ---------------------------------------------------------------------------
// Attestation kit: single-use, signed, expiring; the verifier keeps a bounded spent set and FAILS CLOSED to the ordinary path when it is full
// ---------------------------------------------------------------------------

export class AttestationAuthority {
  constructor(private readonly key: Buffer) {}
  private mac(id: string, exp: number): string { return createHmac("sha256", this.key).update(`${id}|${exp}`).digest("hex").slice(0, 32); }
  issue(id: string, nowMs: number, ttlMs = 60_000): Attestation { const exp = nowMs + ttlMs; return { id, exp, mac: this.mac(id, exp) }; }
  verify(a: Attestation, nowMs: number): boolean {
    if (!(a.exp > nowMs)) return false;
    const expected = Buffer.from(this.mac(a.id, a.exp)), got = Buffer.from(a.mac);
    return expected.length === got.length && timingSafeEqual(expected, got);
  }
}

export class SpentSet {
  private readonly spent = new Map<string, number>();
  constructor(private readonly capacity = 512) {}
  has(id: string): boolean { return this.spent.has(id); }
  /** Room for one more entry after purging expired ones? When false the caller must fail closed to the ordinary path BEFORE taking a token. */
  canAdd(now: number): boolean {
    if (this.spent.size >= this.capacity) for (const [k, e] of this.spent) if (e <= now) this.spent.delete(k);
    return this.spent.size < this.capacity;
  }
  add(id: string, exp: number, now: number): boolean {
    if (this.spent.size >= this.capacity) for (const [k, e] of this.spent) if (e <= now) this.spent.delete(k);
    if (this.spent.size >= this.capacity) return false;
    this.spent.set(id, exp);
    return true;
  }
  get size(): number { return this.spent.size; }
}

// ---------------------------------------------------------------------------
// Max-min fair-share allocator (fixed memory, work-conserving)
// ---------------------------------------------------------------------------

/** Water level L with sum(min(d_i, L)) = total, or Infinity when total demand fits (nobody is restricted: V1 behaviour). */
export function waterLevel(demands: readonly number[], total: number): number {
  let sum = 0; for (const d of demands) sum += d;
  if (sum <= total) return Infinity;
  const sorted = [...demands].sort((a, b) => a - b);
  let remaining = total;
  for (let i = 0; i < sorted.length; i++) {
    const share = remaining / (sorted.length - i);
    if (sorted[i] <= share) remaining -= sorted[i]; else return share;
  }
  return Infinity;
}

export type FairKey = "token" | "session" | "class" | "hier";
export type FairParams = { key: FairKey; slots: number; tauMs: number; recomputeMs: number; bucketCap: number };
export const FAIR_BASE = Object.freeze({ slots: 1024, tauMs: 10_000, recomputeMs: 250, bucketCap: 2 });

class Table {
  readonly demand: Float64Array; readonly tDemand: Float64Array; readonly lvl: Float64Array; readonly tLvl: Float64Array;
  readonly init: Uint8Array; readonly rate: Float64Array; readonly grp: Int32Array;
  constructor(readonly slots: number, private readonly cap: number, private readonly tau: number, private readonly salt: Buffer) {
    this.demand = new Float64Array(slots); this.tDemand = new Float64Array(slots); this.lvl = new Float64Array(slots); this.tLvl = new Float64Array(slots);
    this.init = new Uint8Array(slots); this.rate = new Float64Array(slots).fill(Infinity); this.grp = new Int32Array(slots).fill(-1);
  }
  index(key: string): number { return createHash("sha256").update(this.salt).update(key, "utf8").digest().readUInt32LE(0) % this.slots; }
  touch(i: number, now: number): void {
    if (!this.init[i]) { this.init[i] = 1; this.lvl[i] = this.cap; this.tLvl[i] = now; this.demand[i] = 0; this.tDemand[i] = now; }
    this.demand[i] = this.demand[i] * Math.exp(-(now - this.tDemand[i]) / this.tau) + 1; this.tDemand[i] = now;
  }
  rateOf(i: number, now: number): number { return (this.demand[i] * Math.exp(-(now - this.tDemand[i]) / this.tau)) / (this.tau / 1000); }
  private refill(i: number, now: number): void {
    const r = this.rate[i];
    this.lvl[i] = r === Infinity ? this.cap : Math.min(this.cap, this.lvl[i] + (r * (now - this.tLvl[i])) / 1000);
    this.tLvl[i] = now;
  }
  allow(i: number, now: number): boolean { this.refill(i, now); return this.lvl[i] >= 1; }
  charge(i: number): void { this.lvl[i] -= 1; }
}

export class FairShare {
  private readonly sessions: Table; private readonly groups: Table | null;
  private lastRecompute = -Infinity;
  constructor(readonly params: FairParams, private readonly refillTotal: number, salt: Buffer) {
    this.sessions = new Table(params.slots, params.bucketCap, params.tauMs, salt);
    this.groups = params.key === "hier" ? new Table(params.slots, params.bucketCap, params.tauMs, Buffer.concat([salt, Buffer.from("g")])) : null;
  }
  private keys(ctx: Ctx): { s: string; g: string | null } {
    switch (this.params.key) {
      case "token": return { s: ctx.token, g: null };
      case "session": return { s: ctx.session, g: null };
      case "class": return { s: ctx.klass, g: null };
      case "hier": return { s: `${ctx.klass}|${ctx.session}`, g: ctx.klass };
    }
  }
  /** Registers the attempt as DEMAND (attempts count, admitted or not) and returns the slot handles. */
  attempt(ctx: Ctx, now: number): { s: number; g: number } {
    const k = this.keys(ctx);
    const s = this.sessions.index(k.s);
    this.sessions.touch(s, now);
    let g = -1;
    if (this.groups !== null && k.g !== null) { g = this.groups.index(k.g); this.groups.touch(g, now); this.sessions.grp[s] = g; }
    this.recompute(now);
    return { s, g };
  }
  allow(h: { s: number; g: number }, now: number): boolean {
    if (!this.sessions.allow(h.s, now)) return false;
    return this.groups === null || this.groups.allow(h.g, now);
  }
  charge(h: { s: number; g: number }): void { this.sessions.charge(h.s); if (this.groups !== null) this.groups.charge(h.g); }

  private recompute(now: number): void {
    if (now - this.lastRecompute < this.params.recomputeMs) return;
    this.lastRecompute = now;
    const R = this.refillTotal, t = this.sessions;
    const active: number[] = [];
    for (let i = 0; i < t.slots; i++) if (t.init[i] && t.rateOf(i, now) > 0.01) active.push(i);
    if (this.groups === null) {
      const L = waterLevel(active.map((i) => t.rateOf(i, now)), R);
      for (let i = 0; i < t.slots; i++) if (t.init[i]) t.rate[i] = L;
      return;
    }
    const G = this.groups;
    const groupDemand = new Map<number, number>();
    for (const i of active) groupDemand.set(t.grp[i], (groupDemand.get(t.grp[i]) ?? 0) + t.rateOf(i, now));
    const L1 = waterLevel([...groupDemand.values()], R);
    const L2 = new Map<number, number>();
    for (const [g, dg] of groupDemand) {
      const allocation = L1 === Infinity ? Infinity : Math.min(dg, L1);
      L2.set(g, allocation === Infinity ? Infinity : waterLevel(active.filter((i) => t.grp[i] === g).map((i) => t.rateOf(i, now)), allocation));
    }
    for (let g = 0; g < G.slots; g++) if (G.init[g]) G.rate[g] = L1;
    for (let i = 0; i < t.slots; i++) if (t.init[i]) t.rate[i] = L2.get(t.grp[i]) ?? Infinity;
  }
  /** Current estimate of total attempted credited demand (requests per second) over the active set. */
  totalDemand(now: number): number { let sum = 0; for (let i = 0; i < this.sessions.slots; i++) if (this.sessions.init[i]) sum += this.sessions.rateOf(i, now); return sum; }
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

export type PoolParams = {
  /** Fraction of the V1 credited capacity AND refill that is carved out for attested requests (sum of both buckets = V1). */
  reserve: number;
  /** A non-attested request may take a reserved token only while the reserved bucket is FULL (its refill would otherwise be lost). */
  overflow: boolean;
  issuer: "ext" | "ldi";
  /** Verifier instances: the reserved bucket and the spent set are partitioned; the general bucket is shared (simplification, stated in the document). */
  instances: number;
  /** Ideal coordination: one spent set for all instances (a shared store). false = per-instance spent sets (no coordination). */
  sharedSpent: boolean;
};
export type Policy =
  | { kind: "fair"; fair: FairParams }
  | { kind: "thin"; tauMs: number }
  | { kind: "pool"; pool: PoolParams };

const mulberry32 = (seed: number) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

/** Local deterministic issuer: the only rule available without an external signal is a rate rule, keyed by the (rotatable) network class. */
const LDI = Object.freeze({ perClassCapacity: 1, perClassRefillPerSecond: 0.1, slots: 1024 });

export class AltModel implements Decider {
  private readonly filter: CreditFilter;
  private readonly ledger: UseLedger;
  private readonly unverified: TokenBucket;
  private readonly credited: TokenBucket | null;           // fair / thin
  private readonly general: TokenBucket | null;            // pool
  private readonly reserved: TokenBucket[] = [];           // pool, one per instance
  private readonly spent: SpentSet[] = [];
  private readonly authority: AttestationAuthority;
  private readonly fair: FairShare | null;
  private readonly thin: { fair: FairShare; rnd: () => number } | null;
  private readonly ldiClass = new Map<number, TokenBucket>();
  private readonly ldiGlobal: TokenBucket | null;
  private readonly reservedAdmitsById = new Map<string, number>();
  private issued = 0;
  private readonly c: Record<string, number> = {
    creditedAdmitted: 0, creditedShedGlobal: 0, entityShed: 0, unverifiedAdmitted: 0, unverifiedShed: 0, errors: 0,
    attestedAttempts: 0, attestationInvalid: 0, attestationReplayRefused: 0, attestationSpentSetFull: 0, reservedAdmitted: 0, generalAdmitted: 0, borrowedAdmitted: 0, ldiRefused: 0, ldiIssued: 0,
  };

  constructor(private readonly config: LanesConfig, readonly policy: Policy, seed: number) {
    this.filter = new CreditFilter({ bits: config.filterBits, hashes: config.filterHashes, epochMs: config.epochMs, mono: config.mono, key: config.key });
    this.ledger = new UseLedger(config.ledgerCapacity, config.maxUses);
    this.unverified = new TokenBucket(config.unverified.capacity, config.unverified.refillPerSecond, config.mono);
    this.authority = new AttestationAuthority(Buffer.alloc(32, 9));
    const salt = Buffer.alloc(32, 3);
    this.credited = null; this.general = null; this.fair = null; this.thin = null; this.ldiGlobal = null;
    if (policy.kind === "pool") {
      const p = policy.pool, cap = config.credited.capacity, rate = config.credited.refillPerSecond;
      const rc = Math.round(cap * p.reserve), rr = Math.round(rate * p.reserve * 1000) / 1000;
      if (rc < p.instances || rc % p.instances !== 0) throw new Error("reserved capacity must split into whole tokens per instance");
      this.general = new TokenBucket(cap - rc, Math.round((rate - rr) * 1000) / 1000, config.mono);
      for (let i = 0; i < p.instances; i++) { this.reserved.push(new TokenBucket(rc / p.instances, Math.round((rr / p.instances) * 1000) / 1000, config.mono)); this.spent.push(new SpentSet()); }
      if (p.issuer === "ldi") this.ldiGlobal = new TokenBucket(Math.max(1, rc), rr, config.mono);
    } else {
      this.credited = new TokenBucket(config.credited.capacity, config.credited.refillPerSecond, config.mono);
      if (policy.kind === "fair") this.fair = new FairShare(policy.fair, config.credited.refillPerSecond, salt);
      else this.thin = { fair: new FairShare({ ...FAIR_BASE, key: "class", tauMs: policy.tauMs }, config.credited.refillPerSecond, salt), rnd: mulberry32(seed ^ 0x51ed) };
    }
  }

  authorityForTests(): AttestationAuthority { return this.authority; }
  /** The harness plays the external issuer through this (the verifier shares only the verification key with it). */
  mint(id: string, nowMs: number): Attestation { return this.authority.issue(id, nowMs); }

  enroll(token: string): void {
    const digest = this.filter.digest(token);
    const epoch = this.filter.advance();
    if (this.ledger.committed(digest.toString("base64url"), epoch) !== undefined) return;
    if (this.filter.hasInActive(digest)) return;
    this.filter.insert(digest);
  }

  issue(klass: string): Attestation | null {
    if (this.policy.kind !== "pool" || this.ldiGlobal === null) return null;
    const idx = createHash("sha256").update("ldi").update(klass, "utf8").digest().readUInt32LE(0) % LDI.slots;
    let bucket = this.ldiClass.get(idx);
    if (bucket === undefined) { bucket = new TokenBucket(LDI.perClassCapacity, LDI.perClassRefillPerSecond, this.config.mono); this.ldiClass.set(idx, bucket); }
    // check both, then take both
    if (bucket.levelUnits() < UNIT || this.ldiGlobal.levelUnits() < UNIT) { this.c.ldiRefused++; return null; }
    bucket.take(); this.ldiGlobal.take(); this.c.ldiIssued++;
    return this.authority.issue(`ldi-${this.issued++}`, Math.floor(this.config.mono()));
  }

  decide(request: LayerRequest, ctx: Ctx): Out {
    const cls = operationClassOf(request.method, request.target);
    if (cls === "open") return { admitted: true, lane: "open" };
    const now = Math.floor(this.config.mono());
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
      if (!taken.ok) { this.c.unverifiedShed++; return { admitted: false, lane: "unverified", reason: "lane_budget" }; }
      this.c.unverifiedAdmitted++;
      return { admitted: true, lane: "unverified" };
    }
    if (used === undefined && !this.ledger.canAllocate(epoch)) { this.c.errors++; return { admitted: false, lane: null, reason: "ledger_full" }; }

    const policy = this.policy;
    if (policy.kind === "pool") return this.decidePool(policy.pool, ctx, key, epoch, now);

    if (policy.kind === "fair" && this.fair !== null) {
      const h = this.fair.attempt(ctx, now);
      if (!this.fair.allow(h, now)) { this.c.entityShed++; return { admitted: false, lane: "credited", reason: "entity_ceiling" }; }
      const taken = (this.credited as TokenBucket).take();
      if (!taken.ok) { this.c.creditedShedGlobal++; return { admitted: false, lane: "credited", reason: "lane_budget" }; }
      this.fair.charge(h); this.ledger.commit(key, epoch); this.c.creditedAdmitted++;
      return { admitted: true, lane: "credited", via: "general" };
    }
    if (policy.kind === "thin" && this.thin !== null) {
      this.thin.fair.attempt(ctx, now);
      const demand = this.thin.fair.totalDemand(now), R = this.config.credited.refillPerSecond;
      if (demand > R && this.thin.rnd() >= R / demand) { this.c.entityShed++; return { admitted: false, lane: "credited", reason: "thinned" }; }
      const taken = (this.credited as TokenBucket).take();
      if (!taken.ok) { this.c.creditedShedGlobal++; return { admitted: false, lane: "credited", reason: "lane_budget" }; }
      this.ledger.commit(key, epoch); this.c.creditedAdmitted++;
      return { admitted: true, lane: "credited", via: "general" };
    }
    throw new Error("unreachable policy");
  }

  private decidePool(p: PoolParams, ctx: Ctx, key: string, epoch: number, now: number): Out {
    const inst = ctx.instance ?? createHash("sha256").update(ctx.token).digest().readUInt32LE(0) % p.instances;
    const general = this.general as TokenBucket, reserved = this.reserved[inst], spent = this.spent[p.sharedSpent ? 0 : inst];
    let attOk = false;
    if (ctx.att !== null) {
      this.c.attestedAttempts++;
      if (!this.authority.verify(ctx.att, now)) this.c.attestationInvalid++;
      else if (spent.has(ctx.att.id)) this.c.attestationReplayRefused++;
      else if (!spent.canAdd(now)) this.c.attestationSpentSetFull++; // fail closed: treated as an ordinary request
      else attOk = true;
    }
    if (attOk && ctx.att !== null) {
      const taken = reserved.take();
      if (taken.ok) {
        spent.add(ctx.att.id, ctx.att.exp, now);
        this.reservedAdmitsById.set(ctx.att.id, (this.reservedAdmitsById.get(ctx.att.id) ?? 0) + 1);
        this.ledger.commit(key, epoch); this.c.creditedAdmitted++; this.c.reservedAdmitted++;
        return { admitted: true, lane: "credited", via: "reserved" };
      }
    }
    // ordinary path (also the fallback of an attested request whose reserved bucket is empty: the attestation stays unspent)
    const g = general.take();
    if (g.ok) { this.ledger.commit(key, epoch); this.c.creditedAdmitted++; this.c.generalAdmitted++; return { admitted: true, lane: "credited", via: "general" }; }
    if (p.overflow && reserved.levelUnits() >= reserved.capacity * UNIT) {
      const b = reserved.take();
      if (b.ok) { this.ledger.commit(key, epoch); this.c.creditedAdmitted++; this.c.borrowedAdmitted++; return { admitted: true, lane: "credited", via: "borrowed" }; }
    }
    this.c.creditedShedGlobal++;
    return { admitted: false, lane: "credited", reason: "lane_budget" };
  }

  counters(): Record<string, number> {
    let doubleSpends = 0, distinct = 0;
    for (const n of this.reservedAdmitsById.values()) { distinct++; if (n > 1) doubleSpends += n - 1; }
    return { ...this.c, doubleSpends, distinctAttestationsSpent: distinct, spentSetSizeMax: Math.max(0, ...this.spent.map((s) => s.size)) };
  }
  creditedBound(): { general: number; reserved: number } | null { return this.general ? { general: this.general.capacity, reserved: this.reserved.reduce((a, b) => a + b.capacity, 0) } : null; }
}

// ---------------------------------------------------------------------------
// Adapters for the two baselines, so every variant is driven through one interface
// ---------------------------------------------------------------------------

export class V1Decider implements Decider {
  readonly lanes: JourneyLanes;
  private c = { creditedAdmitted: 0, creditedShedGlobal: 0, entityShed: 0, unverifiedAdmitted: 0, unverifiedShed: 0, errors: 0 };
  constructor(config: LanesConfig) { this.lanes = new JourneyLanes(config); }
  enroll(token: string): void { this.lanes.enroll(token); }
  decide(request: LayerRequest): Out {
    const d = this.lanes.decide(request);
    const admitted = d.outcome === "admitted";
    if (d.lane === "credited") { if (admitted) this.c.creditedAdmitted++; else this.c.creditedShedGlobal++; }
    if (d.lane === "unverified") { if (admitted) this.c.unverifiedAdmitted++; else this.c.unverifiedShed++; }
    return { admitted, lane: d.lane, reason: d.shedReason, via: "general" };
  }
  counters(): Record<string, number> { return { ...this.c }; }
}

/** Approach A (previously evaluated) as a baseline, through its own V2Model. */
export class ApproachADecider implements Decider {
  private readonly model: V2Model;
  private c = { creditedAdmitted: 0, creditedShedGlobal: 0, entityShed: 0, unverifiedAdmitted: 0, unverifiedShed: 0, errors: 0 };
  constructor(config: LanesConfig, variant: string) { this.model = new V2Model(config, variantParams(variant)); }
  enroll(token: string): void { this.model.enroll(token); }
  decide(request: LayerRequest, ctx: Ctx): Out {
    const d = this.model.decide(request, { source: "peer", id: ctx.klass });
    const admitted = d.outcome === "admitted";
    if (d.lane === "credited") { if (admitted) this.c.creditedAdmitted++; else if (d.reason === "class_ceiling") this.c.entityShed++; else this.c.creditedShedGlobal++; }
    if (d.lane === "unverified") { if (admitted) this.c.unverifiedAdmitted++; else this.c.unverifiedShed++; }
    return { admitted, lane: d.lane, reason: d.reason, via: "general" };
  }
  counters(): Record<string, number> { return { ...this.c }; }
}
