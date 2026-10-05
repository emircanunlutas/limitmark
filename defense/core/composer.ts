/**
 * Layer composer: runs one layer with its own deadline and its own bounded concurrency (bulkhead) and turns EVERY way it can go
 * wrong into an explicit outcome (`reject`, `shed` or `error`). Nothing a layer does is thrown past the composer, and nothing
 * disappears: the caller always receives exactly one `LayerOutcome`.
 *
 * Failure policy (Slice 1): fail closed. A layer exception, a missed deadline or a malformed verdict is an explicit `error`
 * outcome, and the caller must refuse the request. There is no code path that turns an error into a pass.
 *
 * LIMITATION, stated plainly: the deadline is a deadline on the VERDICT, not preemption. JavaScript cannot interrupt synchronous
 * CPU work, so a layer that spins synchronously blocks the whole process and its timer cannot fire until it returns. What the
 * deadline does guarantee is that a verdict that arrives late (a hung promise, or a synchronous overrun that finished after the
 * deadline) is DISCARDED and recorded as `error: timeout`, never used. The protection against expensive synchronous work is
 * therefore not this timer; it is the strict size bounds the front and L1 apply BEFORE any expensive parsing (see a7-shape-gate).
 */
import type { FailurePolicy, Layer, LayerErrorKind, LayerOutcome, LayerRequest, LayerVerdict } from "./types";
import { FAILURE_POLICIES, REJECT_REASONS } from "./types";

export type ComposerOptions = {
  /** Deadline for the layer's verdict, in milliseconds. */
  timeoutMs: number;
  /** Bulkhead: how many evaluations of this layer may be running (or abandoned and still unsettled) at once. */
  maxConcurrent: number;
  failurePolicy: FailurePolicy;
  /** An abandoned (timed-out, still unsettled) evaluation stops counting against the bulkhead after this long. */
  reclaimAfterMs?: number;
};

export type ComposerStats = {
  evaluated: number;
  pass: number;
  reject: number;
  shed: number;
  error: Record<LayerErrorKind, number>;
  inFlight: number;
  inFlightHighWater: number;
  abandoned: number;
  abandonedReclaimed: number;
  /** Verdicts that completed after their deadline and were discarded. */
  lateVerdictsDiscarded: number;
};

const REJECT_SET: ReadonlySet<string> = new Set(REJECT_REASONS);

function validVerdict(value: unknown): value is LayerVerdict {
  if (typeof value !== "object" || value === null) return false;
  const kind = (value as { kind?: unknown }).kind;
  if (kind === "pass") return true;
  return kind === "reject" && typeof (value as { reason?: unknown }).reason === "string" && REJECT_SET.has((value as { reason: string }).reason);
}

export class LayerComposer {
  private readonly options: Required<ComposerOptions>;
  private inFlight = 0;
  private abandonedLive = 0;
  private readonly counters: ComposerStats = {
    evaluated: 0, pass: 0, reject: 0, shed: 0, error: { throw: 0, timeout: 0, invalid_verdict: 0 },
    inFlight: 0, inFlightHighWater: 0, abandoned: 0, abandonedReclaimed: 0, lateVerdictsDiscarded: 0,
  };

  constructor(private readonly layer: Layer, options: ComposerOptions) {
    // Anything but the one supported policy is refused at construction: there is no configuration that makes an error a pass.
    if (!FAILURE_POLICIES.includes(options.failurePolicy)) throw new Error("unsupported failure policy: only fail_closed exists");
    for (const [name, value] of [["timeoutMs", options.timeoutMs], ["maxConcurrent", options.maxConcurrent]] as const) {
      if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
    }
    this.options = { ...options, reclaimAfterMs: options.reclaimAfterMs ?? options.timeoutMs * 4 };
  }

  get layerId(): string { return this.layer.id; }

  /** Number of evaluations currently counted against the bulkhead (running plus abandoned-and-unsettled). */
  get occupancy(): number { return this.inFlight + this.abandonedLive; }

  stats(): ComposerStats {
    return { ...this.counters, error: { ...this.counters.error }, inFlight: this.inFlight };
  }

  async run(request: LayerRequest): Promise<LayerOutcome> {
    this.counters.evaluated++;
    if (this.occupancy >= this.options.maxConcurrent) { this.counters.shed++; return { kind: "shed" }; }
    this.inFlight++;
    if (this.inFlight > this.counters.inFlightHighWater) this.counters.inFlightHighWater = this.inFlight;
    const startedAt = performance.now();
    let settled = false;
    let timedOut = false;
    let abandonedCounted = false;
    let timer: NodeJS.Timeout | undefined;
    let reclaimTimer: NodeJS.Timeout | undefined;

    const evaluation = new Promise<LayerVerdict>((resolve, reject) => {
      try { Promise.resolve(this.layer.evaluate(request)).then(resolve, reject); } catch (error) { reject(error); }
    });
    evaluation.then(() => undefined, () => undefined).finally(() => {
      settled = true;
      if (abandonedCounted) { abandonedCounted = false; this.abandonedLive--; }
      if (reclaimTimer) clearTimeout(reclaimTimer);
    });

    const deadline = new Promise<"deadline">((resolve) => {
      timer = setTimeout(() => resolve("deadline"), this.options.timeoutMs);
    });

    let outcome: LayerOutcome;
    try {
      const winner = await Promise.race([evaluation.then((verdict) => ({ verdict }), (error: unknown) => ({ error })), deadline]);
      if (winner === "deadline") {
        timedOut = true;
        outcome = { kind: "error", errorKind: "timeout" };
      } else if ("error" in winner) {
        outcome = { kind: "error", errorKind: "throw" };
      } else if (!validVerdict(winner.verdict)) {
        outcome = { kind: "error", errorKind: "invalid_verdict" };
      } else if (performance.now() - startedAt > this.options.timeoutMs) {
        // A synchronous overrun cannot be interrupted, but its verdict arrived after the deadline: it is not used.
        this.counters.lateVerdictsDiscarded++;
        outcome = { kind: "error", errorKind: "timeout" };
      } else {
        outcome = winner.verdict.kind === "pass" ? { kind: "pass" } : { kind: "reject", reason: winner.verdict.reason };
      }
    } finally {
      if (timer) clearTimeout(timer);
      this.inFlight--;
      if (timedOut && !settled) {
        // Still running somewhere: keep counting it against the bulkhead (bounded by the reclaim timer) so a hung layer cannot be
        // hammered with unbounded new work.
        this.abandonedLive++;
        abandonedCounted = true;
        this.counters.abandoned++;
        reclaimTimer = setTimeout(() => {
          if (abandonedCounted) { abandonedCounted = false; this.abandonedLive--; this.counters.abandonedReclaimed++; }
        }, this.options.reclaimAfterMs);
        reclaimTimer.unref();
      }
    }

    if (outcome.kind === "pass") this.counters.pass++;
    else if (outcome.kind === "reject") this.counters.reject++;
    else if (outcome.kind === "error") this.counters.error[outcome.errorKind]++;
    return outcome;
  }
}
