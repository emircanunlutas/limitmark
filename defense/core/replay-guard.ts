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
 * - Expiry horizon (EH): retention is measured on the MONOTONIC clock but a proof's validity window is on the WALL clock, so a wall step
 *   backward can reopen the window of an id whose entry has already been purged. Every entry therefore records `windowEndMs` (the last
 *   wall instant at which a proof presenting it is still inside its window). When an entry is purged the guard raises a high-water
 *   `horizon` to that value, and a new reservation is accepted only if the caller's wall sample is STRICTLY greater than the horizon.
 *   Single use, in one process lifetime and whatever the clocks do: a replay either finds its entry (replayed) or its entry was purged,
 *   which made horizon >= its windowEnd; the caller's window check (wall <= windowEnd) and this gate (wall > horizon) then cannot both
 *   pass for the same wall sample. This needs no monotonic assumption about either clock for SAFETY (the monotonic clock only decides how
 *   soon an entry is purged), and the horizon never decreases. The 250 ms purge throttle cannot weaken it: an entry past its retention that
 *   has not been purged yet is still present and is refused as replayed, and the horizon is raised in the same step that deletes it.
 *   Non-finite clock values and non-safe-integer window ends are refused (nothing is created). Restart is NOT covered: the horizon, like
 *   the entries, lives in this process only.
 *
 * Pure: no I/O, no timers; time is injected.
 */
export type ReplayEntryState = "RESERVED" | "COMMITTED" | "BURNED";
export type ReserveRequest = { key: string; retainMs: number; windowEndMs: number };
export type ReserveResult = { ok: true; ticket: ReplayTicket } | { ok: false; reason: "replayed" | "full" | "horizon" };

export type ReplayStats = {
  reserved: number;
  committed: number;
  burned: number;
  replayRejected: number;
  capacityRejected: number;
  /** Reservations refused because the wall sample was not strictly after the expiry horizon (or a clock/window value was not usable). */
  horizonRejected: number;
  purged: number;
  /** Currently RESERVED (in flight). Must be 0 at finalization. */
  open: number;
  size: number;
  highWater: number;
  stateViolations: number;
};

type Entry = { state: ReplayEntryState; retainUntil: number; windowEnd: number };

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
  /** Highest `windowEnd` of any entry ever purged. Only ever raised. */
  private horizon = Number.NEGATIVE_INFINITY;
  private counters = { reserved: 0, committed: 0, burned: 0, replayRejected: 0, capacityRejected: 0, horizonRejected: 0, purged: 0, open: 0, highWater: 0, stateViolations: 0 };

  constructor(private readonly capacity: number, private readonly mono: () => number) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) throw new Error("replay capacity must be a positive integer");
  }

  /**
   * Atomic and synchronous. All-or-nothing across `requests`. `wallMs` must be the SAME wall sample the caller used for the proof-window
   * check; it is accepted only if it is finite and strictly greater than the expiry horizon.
   */
  reserve(requests: readonly ReserveRequest[], wallMs: number): ReserveResult {
    const now = this.mono();
    // A non-finite monotonic reading cannot date an entry or a purge: refuse before touching any state.
    if (!Number.isFinite(now)) { this.counters.horizonRejected++; return { ok: false, reason: "horizon" }; }
    if (now - this.lastPurge >= 250 || this.entries.size + requests.length > this.capacity) this.purge(now);
    for (const request of requests) {
      if (this.entries.has(request.key)) { this.counters.replayRejected++; return { ok: false, reason: "replayed" }; }
    }
    if (new Set(requests.map((request) => request.key)).size !== requests.length) { this.counters.replayRejected++; return { ok: false, reason: "replayed" }; }
    if (this.entries.size + requests.length > this.capacity) { this.counters.capacityRejected++; return { ok: false, reason: "full" }; }
    // Expiry-horizon gate. Written as a negated comparison so NaN, +/-Infinity and a missing value all refuse.
    if (!(Number.isFinite(wallMs) && wallMs > this.horizon) || !requests.every((request) => Number.isSafeInteger(request.windowEndMs))) {
      this.counters.horizonRejected++;
      return { ok: false, reason: "horizon" };
    }
    for (const request of requests) this.entries.set(request.key, { state: "RESERVED", retainUntil: now + request.retainMs, windowEnd: request.windowEndMs });
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
   * Removes only entries whose retention elapsed, and never a RESERVED one. Every deleted entry raises the expiry horizon to its `windowEnd`. Retention differs per namespace, so insertion order is not
   * expiry order and the whole set is scanned; it is bounded by `capacity` and scanned at most every 250 ms unless the set is full.
   */
  private purge(now: number): void {
    this.lastPurge = now;
    for (const [key, entry] of this.entries) {
      if (entry.retainUntil > now || entry.state === "RESERVED") continue;
      if (entry.windowEnd > this.horizon) this.horizon = entry.windowEnd;
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
