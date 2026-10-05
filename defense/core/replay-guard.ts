/**
 * Slice 2: single-use replay state for a hop verifier.
 *
 *   UNSEEN --reserve()--> RESERVED --commit()--> COMMITTED     (admitted)
 *                             \--burn()--------> BURNED        (any failure)
 *
 * - `reserve` is SYNCHRONOUS (no await between the lookup and the insert), so two requests presenting the same id can never both see
 *   UNSEEN, and it runs before any asynchronous work (the body read). Reserving several ids is all-or-nothing.
 * - A ticket that is not committed is BURNED: a timeout, an abort, a digest mismatch, an exception all leave the id burned until its
 *   retention ends. COMMITTED and BURNED are indistinguishable to a later presenter: both are `replayed`.
 * - No unexpired entry is ever evicted. Entries are purged only after their retention elapsed (monotonic clock); a RESERVED entry is
 *   never purged. At capacity `reserve` fails closed with `full` and creates nothing.
 * - Only verified proofs reach `reserve`, so an unauthenticated sender cannot fill the set.
 * - Fencing: a verifier refuses any proof issued before its own start (`ClockFence.fenceMs`), which closes the replay-across-restart
 *   window without persisting anything. The clock-step detector compares the wall/monotonic offset at start with now.
 *
 * Pure: no I/O, no timers; time is injected.
 */
export type ReplayEntryState = "RESERVED" | "COMMITTED" | "BURNED";
export type ReserveRequest = { key: string; retainMs: number };
export type ReserveResult = { ok: true; ticket: ReplayTicket } | { ok: false; reason: "replayed" | "full" };

export type ReplayStats = {
  reserved: number;
  committed: number;
  burned: number;
  replayRejected: number;
  capacityRejected: number;
  purged: number;
  /** Currently RESERVED (in flight). Must be 0 at finalization. */
  open: number;
  size: number;
  highWater: number;
  stateViolations: number;
};

type Entry = { state: ReplayEntryState; retainUntil: number };

export class ReplayTicket {
  private settled = false;
  constructor(private readonly guard: ReplayGuard, private readonly keys: readonly string[]) {}
  get isSettled(): boolean { return this.settled; }
  commit(): void { this.settle("COMMITTED"); }
  burn(): void { this.settle("BURNED"); }
  private settle(next: "COMMITTED" | "BURNED"): void {
    if (this.settled) { this.guard.violation(this.keys); return; }
    this.settled = true;
    this.guard.transition(this.keys, next);
  }
}

export class ReplayGuard {
  private readonly entries = new Map<string, Entry>();
  private lastPurge = Number.NEGATIVE_INFINITY;
  private counters = { reserved: 0, committed: 0, burned: 0, replayRejected: 0, capacityRejected: 0, purged: 0, open: 0, highWater: 0, stateViolations: 0 };

  constructor(private readonly capacity: number, private readonly mono: () => number) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) throw new Error("replay capacity must be a positive integer");
  }

  /** Atomic and synchronous. All-or-nothing across `requests`. */
  reserve(requests: readonly ReserveRequest[]): ReserveResult {
    const now = this.mono();
    if (now - this.lastPurge >= 250 || this.entries.size + requests.length > this.capacity) this.purge(now);
    for (const request of requests) {
      if (this.entries.has(request.key)) { this.counters.replayRejected++; return { ok: false, reason: "replayed" }; }
    }
    if (new Set(requests.map((request) => request.key)).size !== requests.length) { this.counters.replayRejected++; return { ok: false, reason: "replayed" }; }
    if (this.entries.size + requests.length > this.capacity) { this.counters.capacityRejected++; return { ok: false, reason: "full" }; }
    for (const request of requests) this.entries.set(request.key, { state: "RESERVED", retainUntil: now + request.retainMs });
    this.counters.reserved += requests.length;
    this.counters.open += requests.length;
    if (this.entries.size > this.counters.highWater) this.counters.highWater = this.entries.size;
    return { ok: true, ticket: new ReplayTicket(this, requests.map((request) => request.key)) };
  }

  /** Internal to ReplayTicket. */
  transition(keys: readonly string[], next: "COMMITTED" | "BURNED"): void {
    for (const key of keys) {
      const entry = this.entries.get(key);
      if (!entry || entry.state !== "RESERVED") { this.counters.stateViolations++; continue; }
      entry.state = next;
      this.counters.open--;
      if (next === "COMMITTED") this.counters.committed++; else this.counters.burned++;
    }
  }

  /** A second transition on a ticket is a bug: the ids are burned (never released) and the violation is counted. */
  violation(keys: readonly string[]): void {
    this.counters.stateViolations++;
    for (const key of keys) {
      const entry = this.entries.get(key);
      if (entry && entry.state === "COMMITTED") { entry.state = "BURNED"; this.counters.committed--; this.counters.burned++; }
    }
  }

  /** The state of an id, or UNSEEN. Diagnostic and test use. */
  stateOf(key: string): ReplayEntryState | "UNSEEN" { return this.entries.get(key)?.state ?? "UNSEEN"; }

  stats(): ReplayStats { return { ...this.counters, size: this.entries.size }; }

  /**
   * Removes only entries whose retention elapsed, and never a RESERVED one. Retention differs per namespace, so insertion order is not
   * expiry order and the whole set is scanned; it is bounded by `capacity` and scanned at most every 250 ms unless the set is full.
   */
  private purge(now: number): void {
    this.lastPurge = now;
    for (const [key, entry] of this.entries) {
      if (entry.retainUntil > now || entry.state === "RESERVED") continue;
      this.entries.delete(key);
      this.counters.purged++;
    }
  }
}

/** Verifier-start fence and wall/monotonic step detection. Time is injected so tests need no real waiting. */
export class ClockFence {
  readonly fenceMs: number;
  private readonly startOffset: number;
  constructor(private readonly wall: () => number, private readonly mono: () => number, private readonly stepThresholdMs = 250) {
    this.fenceMs = wall();
    this.startOffset = this.fenceMs - mono();
  }
  /** The wall clock moved relative to the monotonic clock by more than the threshold since this verifier started. */
  stepDetected(): boolean { return Math.abs(this.wall() - this.mono() - this.startOffset) > this.stepThresholdMs; }
  stepMs(): number { return Math.round(this.wall() - this.mono() - this.startOffset); }
}
