/**
 * Slice 3: the L2 `a7.journey-lanes` mechanism. Pure state machines on an injected monotonic clock: no I/O, no timers, no globals.
 *
 * L1 judges the SHAPE of one request. L2 judges two things L1 cannot: (a) whether a mutation request carries a submission token that this
 * plane itself delivered to a client recently (journey provenance, a cross-request signal), and (b) how much mutation work each lane has
 * already been admitted for (a global budget). Provenance only SELECTS the lane; the budgets are the bound. The sender is never an input.
 *
 *   class      open      the four exact GET page routes. No budget, no state.
 *              mutation  POST /api/public-inquiries
 *              unknown   anything else L1 might wrongly pass: handled as unverified work, never rejected by a second route list
 *   lane       open | credited | unverified
 *   outcome    admitted | shed | error | degraded
 *
 * Invariants (locked by the Slice-3 design closure):
 *   P1  no spill: a credited request whose bucket is empty is SHED (lane=credited, reason=lane_budget). It never touches the unverified
 *       bucket, and an unverified request never touches the credited bucket. Classification happens BEFORE any bucket is read.
 *   P2  a token's use record is retained until the filter generation that could hold its genuine enrollment is gone:
 *       purge only when epoch >= firstCreditedEpoch + 2. Expiry therefore never resets a token's K-use allowance while genuine
 *       membership is still possible. The ledger is sized from the credited-admission bound at construction; full fails closed.
 *   P3  no refunds: a mutation decision is ONE synchronous function with no await. Once it takes a bucket token and a use, neither is
 *       ever returned, whatever happens downstream. There is no refund, rollback or decrement anywhere in this file (a static test pins it).
 */
import { createHash } from "node:crypto";
import type { LayerRequest } from "./types";
import { CreditFilter, type FilterStats } from "./credit-filter";
import { FORM_ROUTE_TARGETS } from "./enrollment";

export const OPERATION_CLASSES = ["open", "mutation", "unknown"] as const;
export type OperationClass = (typeof OPERATION_CLASSES)[number];
export const LANES = ["open", "credited", "unverified"] as const;
export type Lane2 = (typeof LANES)[number];
export const L2_OUTCOMES = ["admitted", "shed", "error", "degraded"] as const;
export type L2Outcome = (typeof L2_OUTCOMES)[number];
export const SHED_REASONS = ["lane_budget", "evaluator_saturation"] as const;
export type ShedReason = (typeof SHED_REASONS)[number];
export const L2_ERROR_KINDS = ["throw", "timeout", "invalid_verdict", "ledger_full"] as const;
export type L2ErrorKind = (typeof L2_ERROR_KINDS)[number];

export const MUTATION_TARGET = "/api/public-inquiries";
const OPEN_TARGETS: ReadonlySet<string> = new Set(["/", "/gizlilik", "/test-talep-et/tesekkurler", ...FORM_ROUTE_TARGETS]);

/** Closed, exact-match classification. It rejects nothing: an unrecognised request is `unknown`, which is quarantined, not refused here. */
export function operationClassOf(method: string, target: string): OperationClass {
  if (method === "GET" && OPEN_TARGETS.has(target)) return "open";
  if (method === "POST" && target === MUTATION_TARGET) return "mutation";
  return "unknown";
}

/** What a decision records (and what the lifecycle carries). */
export type LaneDecision = {
  class: OperationClass;
  lane: Lane2 | null;
  outcome: L2Outcome;
  shedReason?: ShedReason;
  errorKind?: L2ErrorKind;
  /** 16-character tag of the keyed credit digest, on a credited decision only. */
  creditTag?: string;
  /** Set (by the stage) when a decision that consumed a bucket token and a use was discarded: the consumption stays, it is accounted here. */
  spent?: Lane2;
  /** Set (by the stage) when a discarded decision had taken a bucket decision on this lane that was itself a shed: nothing was consumed, but the bucket's decision number advanced. */
  touched?: Lane2;
  /** The consuming bucket's own clock (ms, floor), its level in micro-tokens after the decision, and its per-bucket decision number. */
  dt?: number;
  lvl?: number;
  lseq?: number;
  basis?: "simulated";
  shadow?: string;
};

export const proceeds = (decision: LaneDecision): boolean => decision.outcome === "admitted" || decision.outcome === "degraded";

/** The closed validity matrix of (class, lane, outcome). Anything outside it is an invalid decision. */
export function isValidDecision(decision: LaneDecision): boolean {
  const { lane, outcome } = decision;
  if (decision.class === "open") return lane === "open" && (outcome === "admitted" || outcome === "degraded");
  if (lane === "credited" || lane === "unverified") return outcome === "admitted" || (outcome === "shed" && decision.shedReason === "lane_budget");
  if (lane === null) return (outcome === "shed" && decision.shedReason === "evaluator_saturation") || (outcome === "error" && decision.errorKind !== undefined);
  return false;
}

/**
 * What an L2 FAILURE becomes. degraded is a subset of normal: only a class whose healthy decision is an unconditional admit may degrade,
 * and a degraded decision is never an `admitted` one. Mutation and unknown never degrade: they are shed or error.
 */
export type L2Failure = "saturation" | "throw" | "timeout" | "invalid_verdict";
export function failureDecision(cls: OperationClass, failure: L2Failure): LaneDecision {
  if (cls === "open") return { class: "open", lane: "open", outcome: "degraded" };
  if (failure === "saturation") return { class: cls, lane: null, outcome: "shed", shedReason: "evaluator_saturation" };
  return { class: cls, lane: null, outcome: "error", errorKind: failure };
}

// ---------------------------------------------------------------------------
// Token bucket: exact integer arithmetic, no refund
// ---------------------------------------------------------------------------

/** One token is UNIT micro-tokens. A refill rate of r tokens/second adds r*1000 micro-tokens per millisecond (an integer). */
export const UNIT = 1_000_000;

export type BucketSnapshot = { capacity: number; levelUnits: number; takes: number; admitted: number; shed: number };

export class TokenBucket {
  private level: number;
  private lastMs: number;
  private readonly capacityUnits: number;
  private readonly refillPerMs: number;
  private takes = 0;
  private admittedCount = 0;
  private shedCount = 0;

  constructor(readonly capacity: number, readonly refillPerSecond: number, private readonly mono: () => number) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) throw new Error("bucket capacity must be a positive integer");
    if (!Number.isFinite(refillPerSecond) || refillPerSecond <= 0 || !Number.isInteger(refillPerSecond * 1000)) throw new Error("refill must be positive with at most three decimals per second");
    this.capacityUnits = capacity * UNIT;
    this.refillPerMs = refillPerSecond * 1000;
    this.level = this.capacityUnits;
    this.lastMs = Math.floor(mono());
  }

  private refill(): number {
    const now = Math.floor(this.mono());
    if (now > this.lastMs) { this.level = Math.min(this.capacityUnits, this.level + (now - this.lastMs) * this.refillPerMs); this.lastMs = now; }
    return this.lastMs;
  }

  /** Takes one token if there is one. The ONLY way a level goes down; nothing ever adds a token back except the passage of time. */
  take(): { ok: boolean; dt: number; lvl: number; lseq: number } {
    const dt = this.refill();
    this.takes++;
    const ok = this.level >= UNIT;
    if (ok) { this.level -= UNIT; this.admittedCount++; } else this.shedCount++;
    return { ok, dt, lvl: this.level, lseq: this.takes };
  }

  levelUnits(): number { this.refill(); return this.level; }
  snapshot(): BucketSnapshot { return { capacity: this.capacity, levelUnits: this.levelUnits(), takes: this.takes, admitted: this.admittedCount, shed: this.shedCount }; }
}

// ---------------------------------------------------------------------------
// Use ledger: K uses per genuinely enrolled token, retained for the whole filter-generation lifecycle
// ---------------------------------------------------------------------------

export type LedgerSnapshot = { size: number; capacity: number; highWater: number; committedLive: number; allocated: number; purged: number; fullRefusals: number; stateViolations: number };

export class UseLedger {
  private readonly entries = new Map<string, { committed: number; firstEpoch: number }>();
  private lastPurgeEpoch = 0;
  private highWater = 0;
  private allocated = 0;
  private purgedCount = 0;
  private fullRefusals = 0;
  private violations = 0;

  constructor(readonly capacity: number, readonly maxUses: number) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) throw new Error("ledger capacity must be a positive integer");
    if (!Number.isSafeInteger(maxUses) || maxUses < 1) throw new Error("maxUses must be a positive integer");
  }

  /** Uses already committed for the token, or undefined when there is no live record. A record past its epoch window is treated as absent. */
  committed(key: string, epoch: number): number | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (epoch >= entry.firstEpoch + 2) return undefined;
    return entry.committed;
  }

  /** P2: removes only records whose epoch window ended (epoch >= firstEpoch + 2). Scans at most once per epoch unless the ledger is full. */
  purge(epoch: number): void {
    this.lastPurgeEpoch = epoch;
    for (const [key, entry] of this.entries) if (epoch >= entry.firstEpoch + 2) { this.entries.delete(key); this.purgedCount++; }
  }

  maybePurge(epoch: number): void { if (epoch !== this.lastPurgeEpoch) this.purge(epoch); }

  /** True when a NEW record can be allocated (purging aged-out records first when full). A full ledger is refused, never evicted. */
  canAllocate(epoch: number): boolean {
    if (this.entries.size < this.capacity) return true;
    this.purge(epoch);
    if (this.entries.size < this.capacity) return true;
    this.fullRefusals++;
    return false;
  }

  /** Consumes one use. Permanent: there is no inverse. Allocates the record on a token's first credited admission. */
  commit(key: string, epoch: number): void {
    const entry = this.entries.get(key);
    if (entry && epoch < entry.firstEpoch + 2) {
      if (entry.committed >= this.maxUses) { this.violations++; return; }
      entry.committed++;
      return;
    }
    if (entry) { this.entries.delete(key); this.purgedCount++; }
    this.entries.set(key, { committed: 1, firstEpoch: epoch });
    this.allocated++;
    if (this.entries.size > this.highWater) this.highWater = this.entries.size;
  }

  snapshot(): LedgerSnapshot {
    let live = 0;
    for (const entry of this.entries.values()) live += entry.committed;
    return { size: this.entries.size, capacity: this.capacity, highWater: this.highWater, committedLive: live, allocated: this.allocated, purged: this.purgedCount, fullRefusals: this.fullRefusals, stateViolations: this.violations };
  }
}

/** The ledger capacity the credited-admission bound requires: entries alive span at most two epochs of credited admissions. */
export function requiredLedgerCapacity(creditedCapacity: number, creditedRefillPerSecond: number, epochMs: number): number {
  return creditedCapacity + Math.ceil((creditedRefillPerSecond * 2 * epochMs) / 1000) + 1;
}

// ---------------------------------------------------------------------------
// Token extraction: no decoding, exactly one well-formed field
// ---------------------------------------------------------------------------

const TOKEN_FIELD = "submissionToken=";
const TOKEN_VALUE = /^[A-Za-z0-9_-]{43}$/;

/** The one submission token of a complete urlencoded body, or null (absent, duplicated, percent-encoded or malformed). Linear, no decoding. */
export function extractSubmissionToken(request: LayerRequest): string | null {
  if (request.method !== "POST" || request.bodyStatus !== "complete" || request.body === null) return null;
  const text = Buffer.from(request.body.buffer, request.body.byteOffset, request.body.byteLength).toString("latin1");
  let found: string | null = null;
  let from = 0;
  while (from <= text.length) {
    const end = text.indexOf("&", from);
    const stop = end < 0 ? text.length : end;
    if (text.startsWith(TOKEN_FIELD, from)) {
      if (found !== null) return null;
      const value = text.slice(from + TOKEN_FIELD.length, stop);
      if (!TOKEN_VALUE.test(value)) return null;
      found = value;
    }
    if (end < 0) break;
    from = end + 1;
  }
  return found;
}

// ---------------------------------------------------------------------------
// The mechanism
// ---------------------------------------------------------------------------

export type LanesConfig = {
  filterBits: number;
  filterHashes: number;
  /** Generation length = the guaranteed credit lifetime. */
  epochMs: number;
  credited: { capacity: number; refillPerSecond: number };
  unverified: { capacity: number; refillPerSecond: number };
  /** Uses per genuinely enrolled token. */
  maxUses: number;
  ledgerCapacity: number;
  mono: () => number;
  /** Test seam: a fixed filter key. */
  key?: Buffer;
};

export type LanesSnapshot = {
  epoch: number;
  credited: BucketSnapshot;
  unverified: BucketSnapshot;
  filter: FilterStats;
  poisoned: boolean;
  ledger: LedgerSnapshot;
  decisions: Record<string, number>;
  spentOnDiscard: { credited: number; unverified: number };
  /** Hash of the quiescence-relevant state (capacities, levels, popcounts, ledger size): equal to the initial digest after a full recovery. */
  digest: string;
};

export const creditTagOf = (digest: Buffer): string => createHash("sha256").update(`cr:${digest.toString("base64url")}`).digest("base64url").slice(0, 16);

export class JourneyLanes {
  readonly filter: CreditFilter;
  private readonly credited: TokenBucket;
  private readonly unverified: TokenBucket;
  private readonly ledger: UseLedger;
  private readonly decisionCounts = new Map<string, number>();
  private readonly spent = { credited: 0, unverified: 0 };

  constructor(readonly config: LanesConfig) {
    const needed = requiredLedgerCapacity(config.credited.capacity, config.credited.refillPerSecond, config.epochMs);
    if (config.ledgerCapacity < needed) throw new Error(`ledger capacity ${config.ledgerCapacity} is below the credited-admission bound ${needed}`);
    this.filter = new CreditFilter({ bits: config.filterBits, hashes: config.filterHashes, epochMs: config.epochMs, mono: config.mono, key: config.key });
    this.credited = new TokenBucket(config.credited.capacity, config.credited.refillPerSecond, config.mono);
    this.unverified = new TokenBucket(config.unverified.capacity, config.unverified.refillPerSecond, config.mono);
    this.ledger = new UseLedger(config.ledgerCapacity, config.maxUses);
  }

  /**
   * ONE synchronous decision (no await). Classification first, from state only; then exactly one lane's bucket is touched.
   * Never throws for a well-formed request; the stage still guards it.
   */
  decide(request: LayerRequest): LaneDecision {
    const cls = operationClassOf(request.method, request.target);
    if (cls === "open") return { class: "open", lane: "open", outcome: "admitted" };

    // --- classify: credited only for a mutation whose token is a genuine-looking member with uses left
    const epoch = this.filter.advance();
    this.ledger.maybePurge(epoch);
    let digest: Buffer | null = null;
    let key = "";
    let used: number | undefined;
    if (cls === "mutation") {
      const token = extractSubmissionToken(request);
      if (token !== null) {
        digest = this.filter.digest(token);
        if (this.filter.has(digest)) { key = digest.toString("base64url"); used = this.ledger.committed(key, epoch); }
        else digest = null;
      }
    }
    const credited = digest !== null && (used === undefined || used < this.config.maxUses);

    if (!credited) {
      const taken = this.unverified.take();
      if (!taken.ok) return { class: cls, lane: "unverified", outcome: "shed", shedReason: "lane_budget", dt: taken.dt, lvl: taken.lvl, lseq: taken.lseq };
      return { class: cls, lane: "unverified", outcome: "admitted", dt: taken.dt, lvl: taken.lvl, lseq: taken.lseq };
    }

    // --- credited: a NEW record needs a free ledger slot BEFORE anything is consumed; full is fail-closed
    if (used === undefined && !this.ledger.canAllocate(epoch)) return { class: cls, lane: null, outcome: "error", errorKind: "ledger_full" };
    const taken = this.credited.take();
    if (!taken.ok) return { class: cls, lane: "credited", outcome: "shed", shedReason: "lane_budget", dt: taken.dt, lvl: taken.lvl, lseq: taken.lseq };
    this.ledger.commit(key, epoch);
    return { class: cls, lane: "credited", outcome: "admitted", creditTag: creditTagOf(digest as Buffer), dt: taken.dt, lvl: taken.lvl, lseq: taken.lseq };
  }

  /**
   * Enrollment (after the response was delivered): returns the tag, or "already_enrolled".
   *
   *  - A token that has already been USED credited (it has a live ledger record) is genuine and consumed: it is never refreshed, so a
   *    replayed or stale observation cannot extend a credit past the retention its use record is pinned to (P2).
   *  - A token already in the ACTIVE generation needs nothing: its bits live exactly as long as an enrollment now would.
   *  - Otherwise it is inserted. In particular a token that merely tests positive through the PREVIOUS generation (a false positive, or an
   *    unused earlier enrollment) is still inserted: those bits are about to age out, so skipping would lose a genuine credit inside its
   *    guaranteed window. Re-inserting an unused credit can extend it by at most one epoch and cannot reopen any use.
   */
  enroll(token: string): { ok: true; creditTag: string } | { ok: false; reason: "already_enrolled" } {
    const digest = this.filter.digest(token);
    const epoch = this.filter.advance();
    if (this.ledger.committed(digest.toString("base64url"), epoch) !== undefined) return { ok: false, reason: "already_enrolled" };
    if (this.filter.hasInActive(digest)) return { ok: false, reason: "already_enrolled" };
    this.filter.insert(digest);
    return { ok: true, creditTag: creditTagOf(digest) };
  }

  /** Counts a FINAL decision (including failure-generated ones) so the aggregate counters can be reconciled against the lifecycle. */
  record(decision: LaneDecision): void {
    const key = `${decision.class}.${decision.lane ?? "none"}.${decision.outcome}`;
    this.decisionCounts.set(key, (this.decisionCounts.get(key) ?? 0) + 1);
    if (decision.spent) this.spent[decision.spent === "credited" ? "credited" : "unverified"]++;
  }

  snapshot(): LanesSnapshot {
    const filter = this.filter.stats();
    // Observation first applies the same aged-out purge a decision would (P2 epoch rule): a quiescent ledger reads as empty.
    this.ledger.maybePurge(filter.epoch);
    const credited = this.credited.snapshot();
    const unverified = this.unverified.snapshot();
    const ledger = this.ledger.snapshot();
    const digest = createHash("sha256").update(JSON.stringify({
      c: [credited.capacity, credited.levelUnits], u: [unverified.capacity, unverified.levelUnits], f: filter.popcount, l: ledger.size,
    })).digest("hex").slice(0, 16);
    return {
      epoch: filter.epoch, credited, unverified, filter, poisoned: filter.fprEstimate > 0.01, ledger,
      decisions: Object.fromEntries([...this.decisionCounts.entries()].sort()), spentOnDiscard: { ...this.spent }, digest,
    };
  }
}
