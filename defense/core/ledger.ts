/**
 * Correlated request lifecycle model and the bounded event channel.
 *
 * Authoritative measurement does NOT live in the Defense Plane. The plane only EMITS lifecycle events (this file's
 * `BoundedEventChannel`); the collector (outside the plane's process) owns the ledger, the validation of every request's lifecycle and
 * the accounting. This file holds the pure parts both sides share: the event vocabulary, the lifecycle automaton, the lifecycle
 * validator and the plane-side bounded emitter. It performs no I/O of its own.
 *
 * Lifecycle of one harness request (the nonce is unique and opaque; it is a measurement key, never a security signal):
 *
 *   SENT (harness)
 *   -> INGRESS_ACCEPTED -> L1_ENTERED -> exactly one of L1_PASSED | L1_REJECTED | L1_SHED | L1_ERROR      (plane)
 *   -> when L1_PASSED: EGRESS_ATTEMPTED -> EGRESS_RESPONDED | EGRESS_FAILED                                (plane)
 *   -> ORIGIN_RECEIVED -> ORIGIN_COMPLETED | ORIGIN_ABORTED                                                (origin, independent)
 *   -> INGRESS_RESPONDED | INGRESS_ABORTED (plane terminal) -> CLIENT_COMPLETED (harness)
 *
 * A layer PASS is not origin delivery: the origin observations are reconciled independently against the plane's egress events.
 */
import type { LayerErrorKind, Lane, RejectReason, RejectStage } from "./types";
import { REJECT_STATUS } from "./types";

// ---------------------------------------------------------------------------
// Event vocabulary
// ---------------------------------------------------------------------------

export const PLANE_EVENT_KINDS = [
  "INGRESS_ACCEPTED", "L1_ENTERED", "L1_PASSED", "L1_REJECTED", "L1_SHED", "L1_ERROR",
  "EGRESS_ATTEMPTED", "EGRESS_RESPONDED", "EGRESS_FAILED", "INGRESS_RESPONDED", "INGRESS_ABORTED",
] as const;
export type PlaneEventKind = (typeof PLANE_EVENT_KINDS)[number];

export const EGRESS_ERROR_KINDS = ["refused", "reset", "timeout", "error"] as const;
export type EgressErrorKind = (typeof EGRESS_ERROR_KINDS)[number];

export type TerminalOutcome = "rejected" | "shed" | "error" | "proxied" | "egress_failed" | "client_aborted";
export const TERMINAL_OUTCOMES: readonly TerminalOutcome[] = ["rejected", "shed", "error", "proxied", "egress_failed", "client_aborted"];

/** An event the plane produced. `seq` is global and gapless per plane process; the collector detects gaps. */
export type PlaneEvent = {
  seq: number;
  /** Null only for an event that has no request to attribute to (a connection the HTTP parser refused). */
  nonce: string | null;
  kind: PlaneEventKind | "PARSER_REJECTED";
  /** Milliseconds on the plane's own monotonic clock. Never compared with another process's clock. */
  t: number;
  reason?: RejectReason;
  stage?: RejectStage;
  errorKind?: LayerErrorKind;
  status?: number;
  egressError?: EgressErrorKind;
  /** INGRESS_ACCEPTED: how many spoofable internal/forwarding headers the front removed. */
  stripped?: number;
  /** INGRESS_ACCEPTED: the request carried no usable nonce, so the front minted one. Always an anomaly for a harness run. */
  uncorrelated?: boolean;
  /** PARSER_REJECTED: the HTTP parser's error code (closed list in the front). */
  code?: string;
};

export type OriginEventKind = "ORIGIN_RECEIVED" | "ORIGIN_COMPLETED" | "ORIGIN_ABORTED";
export type OriginEvent = {
  instance: Lane;
  nonce: string | null;
  kind: OriginEventKind;
  /** The plane's EGRESS_ATTEMPTED sequence number as relayed by the front, or null (direct path). */
  hop: number | null;
  status?: number;
  /** Count of spoofable headers that reached the origin. Must be 0 on the protected path. */
  spoofed?: number;
};

export type HarnessEventKind = "SENT" | "CLIENT_COMPLETED";
export type ClientResultKind = "response" | "reset" | "timeout" | "error";
export type HarnessEvent = {
  kind: HarnessEventKind;
  result?: ClientResultKind;
  status?: number;
  /** The plane's outcome header, when the response carried one. */
  outcomeHeader?: string;
};

export type ExpectedLane = "protected" | "control" | "pre_ingress";

// ---------------------------------------------------------------------------
// Anomalies: every way a lifecycle can be wrong. A single one makes the run INVALID.
// ---------------------------------------------------------------------------

export const ANOMALY_CODES = [
  "duplicate_terminal", "duplicate_event", "duplicate_nonce_sent", "duplicate_sequence",
  "missing_transition", "impossible_order", "ingress_loss", "disappeared_after_ingress", "unresolved_at_finalization",
  "sent_without_completion", "duplicate_origin_processing", "origin_without_l1_pass", "origin_lane_mismatch",
  "origin_hop_mismatch", "origin_status_mismatch", "plane_status_mismatch", "client_status_mismatch", "outcome_header_mismatch",
  "plane_event_on_unexpected_lane", "unknown_nonce", "event_before_sent", "uncorrelated_ingress", "late_event_after_finalization",
  "event_channel_loss", "plane_crashed", "plane_not_finalized", "journal_overflow", "ledger_capacity_exceeded",
  "parser_reject_unreconciled", "origin_spoofed_header_seen", "corpus_expectation_violated",
] as const;
export type AnomalyCode = (typeof ANOMALY_CODES)[number];
export type Anomaly = { code: AnomalyCode; nonce: string | null; detail: string };

// ---------------------------------------------------------------------------
// Lifecycle automaton (plane stream)
// ---------------------------------------------------------------------------

const RANK: Readonly<Record<PlaneEventKind, number>> = {
  INGRESS_ACCEPTED: 1, L1_ENTERED: 2, L1_PASSED: 3, L1_REJECTED: 3, L1_SHED: 3, L1_ERROR: 3,
  EGRESS_ATTEMPTED: 4, EGRESS_RESPONDED: 5, EGRESS_FAILED: 5, INGRESS_RESPONDED: 6, INGRESS_ABORTED: 6,
};

/** The only legal successor events. Everything else is a violation, classified by `classifyViolation`. */
export const NEXT_PLANE_KINDS: Readonly<Record<PlaneEventKind | "START", readonly PlaneEventKind[]>> = {
  START: ["INGRESS_ACCEPTED"],
  INGRESS_ACCEPTED: ["L1_ENTERED"],
  L1_ENTERED: ["L1_PASSED", "L1_REJECTED", "L1_SHED", "L1_ERROR"],
  L1_PASSED: ["EGRESS_ATTEMPTED"],
  L1_REJECTED: ["INGRESS_RESPONDED", "INGRESS_ABORTED"],
  L1_SHED: ["INGRESS_RESPONDED", "INGRESS_ABORTED"],
  L1_ERROR: ["INGRESS_RESPONDED", "INGRESS_ABORTED"],
  EGRESS_ATTEMPTED: ["EGRESS_RESPONDED", "EGRESS_FAILED"],
  EGRESS_RESPONDED: ["INGRESS_RESPONDED", "INGRESS_ABORTED"],
  EGRESS_FAILED: ["INGRESS_RESPONDED", "INGRESS_ABORTED"],
  INGRESS_RESPONDED: [],
  INGRESS_ABORTED: [],
};

function classifyViolation(previous: PlaneEventKind | "START", kind: PlaneEventKind, seen: ReadonlySet<PlaneEventKind>): AnomalyCode {
  if (previous === "INGRESS_RESPONDED" || previous === "INGRESS_ABORTED") return "duplicate_terminal";
  if (seen.has(kind)) return "duplicate_event";
  const from = previous === "START" ? 0 : RANK[previous];
  return RANK[kind] <= from ? "impossible_order" : "missing_transition";
}

export const LAYER_VERDICT_KINDS: readonly PlaneEventKind[] = ["L1_PASSED", "L1_REJECTED", "L1_SHED", "L1_ERROR"];

// ---------------------------------------------------------------------------
// Lifecycle validation
// ---------------------------------------------------------------------------

export type LifecycleView = {
  nonce: string;
  expected: ExpectedLane;
  harness: readonly HarnessEvent[];
  plane: readonly PlaneEvent[];
  origin: readonly OriginEvent[];
};

export function planeStatusFor(view: LifecycleView): number | null {
  const verdict = view.plane.find((event) => LAYER_VERDICT_KINDS.includes(event.kind as PlaneEventKind));
  if (!verdict) return null;
  if (verdict.kind === "L1_REJECTED") return verdict.reason ? REJECT_STATUS[verdict.reason] : null;
  if (verdict.kind === "L1_SHED" || verdict.kind === "L1_ERROR") return 503;
  const failed = view.plane.find((event) => event.kind === "EGRESS_FAILED");
  if (failed) return failed.egressError === "timeout" ? 504 : 502;
  const responded = view.plane.find((event) => event.kind === "EGRESS_RESPONDED");
  return responded?.status ?? null;
}

/** The single terminal outcome of a request as the plane saw it, or null when the plane stream is not terminal yet. */
export function terminalOutcome(plane: readonly PlaneEvent[]): TerminalOutcome | null {
  if (plane.some((event) => event.kind === "INGRESS_ABORTED")) return "client_aborted";
  if (!plane.some((event) => event.kind === "INGRESS_RESPONDED")) return null;
  if (plane.some((event) => event.kind === "L1_REJECTED")) return "rejected";
  if (plane.some((event) => event.kind === "L1_SHED")) return "shed";
  if (plane.some((event) => event.kind === "L1_ERROR")) return "error";
  if (plane.some((event) => event.kind === "EGRESS_FAILED")) return "egress_failed";
  if (plane.some((event) => event.kind === "EGRESS_RESPONDED")) return "proxied";
  return null;
}

const OUTCOME_HEADER_VALUE: Readonly<Record<TerminalOutcome, string>> = {
  rejected: "rejected", shed: "shed", error: "error", proxied: "proxied", egress_failed: "egress_failed", client_aborted: "client_aborted",
};

/**
 * Validates one request's lifecycle. Per-source ordering rules are always checked; rules that relate two sources (plane vs origin
 * vs client), which arrive on different channels and so in no fixed order, are checked only when `final` is true.
 */
export function validateLifecycle(view: LifecycleView, final: boolean): Anomaly[] {
  const found: Anomaly[] = [];
  const add = (code: AnomalyCode, detail: string) => found.push({ code, nonce: view.nonce, detail });

  // --- harness stream: SENT first, at most one CLIENT_COMPLETED after it
  const sent = view.harness.filter((event) => event.kind === "SENT").length;
  const completed = view.harness.filter((event) => event.kind === "CLIENT_COMPLETED");
  if (sent !== 1 || view.harness[0]?.kind !== "SENT") add("duplicate_event", "SENT");
  if (completed.length > 1) add("duplicate_terminal", "CLIENT_COMPLETED");
  if (final && completed.length === 0) add("sent_without_completion", "CLIENT_COMPLETED");

  // --- plane stream: legal transitions in sequence order
  if (view.expected !== "protected") {
    if (view.plane.length > 0) add("plane_event_on_unexpected_lane", view.expected);
  } else {
    let previous: PlaneEventKind | "START" = "START";
    const seen = new Set<PlaneEventKind>();
    let lastSeq = -1;
    for (const event of view.plane) {
      const kind = event.kind as PlaneEventKind;
      if (event.seq <= lastSeq) add("impossible_order", `seq ${event.kind}`);
      lastSeq = event.seq;
      if (!NEXT_PLANE_KINDS[previous].includes(kind)) add(classifyViolation(previous, kind, seen), `${previous}>${kind}`);
      seen.add(kind);
      previous = kind;
    }
    if (final) {
      if (view.plane.length === 0) add("ingress_loss", "no plane event");
      else if (previous !== "INGRESS_RESPONDED" && previous !== "INGRESS_ABORTED") {
        add("disappeared_after_ingress", previous);
        add("unresolved_at_finalization", previous);
      }
    }
    if (view.plane.some((event) => event.uncorrelated)) add("uncorrelated_ingress", "minted nonce");
    // The plane may report one verdict only.
    if (view.plane.filter((event) => LAYER_VERDICT_KINDS.includes(event.kind as PlaneEventKind)).length > 1) add("duplicate_terminal", "layer verdict");
  }

  // --- origin stream: independent observation of the same request
  const received = view.origin.filter((event) => event.kind === "ORIGIN_RECEIVED");
  const finished = view.origin.filter((event) => event.kind === "ORIGIN_COMPLETED" || event.kind === "ORIGIN_ABORTED");
  if (received.length > 1) add("duplicate_origin_processing", "ORIGIN_RECEIVED");
  if (finished.length > 1) add("duplicate_terminal", "origin completion");
  if (view.origin.length > 0 && view.origin[0].kind !== "ORIGIN_RECEIVED") add("impossible_order", "origin completion before receipt");
  const wantedInstance: Lane | null = view.expected === "protected" ? "protected" : view.expected === "control" ? "control" : null;
  for (const event of view.origin) if (wantedInstance !== event.instance) { add("origin_lane_mismatch", event.instance); break; }
  if (view.origin.some((event) => (event.spoofed ?? 0) > 0)) add("origin_spoofed_header_seen", "proxied");

  if (!final) return found;

  // --- cross-source reconciliation (final only)
  const attempted = view.plane.find((event) => event.kind === "EGRESS_ATTEMPTED");
  if (received.length > 0 && view.expected === "protected") {
    if (!attempted) add("origin_without_l1_pass", "origin received without EGRESS_ATTEMPTED");
    else if (received[0].hop !== attempted.seq) add("origin_hop_mismatch", `${received[0].hop}`);
  }
  if (received.length > 0 && view.expected === "pre_ingress") add("origin_without_l1_pass", "origin received a pre-ingress rejection");
  if (view.expected === "control") {
    if (received.length === 0) add("missing_transition", "ORIGIN_RECEIVED");
    else if (finished.length === 0) add("missing_transition", "ORIGIN_COMPLETED");
  }
  if (view.expected === "protected") {
    const responded = view.plane.find((event) => event.kind === "EGRESS_RESPONDED");
    if (responded) {
      if (received.length === 0) add("missing_transition", "ORIGIN_RECEIVED");
      else if (finished.length === 0) add("missing_transition", "ORIGIN_COMPLETED");
      else if (finished[0].kind === "ORIGIN_COMPLETED" && finished[0].status !== responded.status) add("origin_status_mismatch", `${finished[0].status}>${responded.status}`);
    }
    const planeStatus = planeStatusFor(view);
    const responseEvent = view.plane.find((event) => event.kind === "INGRESS_RESPONDED");
    if (responseEvent && planeStatus !== null && responseEvent.status !== planeStatus) add("plane_status_mismatch", `${responseEvent.status}!=${planeStatus}`);
    const client = completed[0];
    if (client && client.result === "response" && responseEvent && client.status !== responseEvent.status) add("client_status_mismatch", `${client.status}!=${responseEvent.status}`);
    const outcome = terminalOutcome(view.plane);
    if (client?.result === "response" && client.outcomeHeader !== undefined && outcome && OUTCOME_HEADER_VALUE[outcome] !== client.outcomeHeader) add("outcome_header_mismatch", `${client.outcomeHeader}!=${outcome}`);
  }
  return found;
}

// ---------------------------------------------------------------------------
// Plane-side bounded event channel
// ---------------------------------------------------------------------------

export type EventFrame = { type: "events"; events: PlaneEvent[]; dropped: number };
export interface FrameTransport { send(frame: EventFrame): void }

export type ChannelStats = {
  emitted: number;
  dropped: number;
  sent: number;
  received: number;
  queued: number;
  unacknowledged: number;
  queueHighWater: number;
  lastSeq: number;
};

export type ChannelOptions = { queueCap?: number; windowCap?: number; maxFrameEvents?: number; flushIntervalMs?: number };

/**
 * Bounded, asynchronous emitter with flow control. Properties:
 *  - memory is bounded: at most `queueCap` events wait here and at most `windowCap` events are sent-but-unacknowledged;
 *  - the hot path never does durable or blocking I/O: `emit` is an array push, frames go out on a timer or when a frame fills;
 *  - an event that does not fit is DROPPED, never blocked on, and counted. Its sequence number is still consumed, so the collector
 *    sees a gap and the cumulative `dropped` counter: loss is explicit and makes the run INVALID, it never becomes silence.
 */
export class BoundedEventChannel {
  private readonly queue: PlaneEvent[] = [];
  private readonly queueCap: number;
  private readonly windowCap: number;
  private readonly maxFrameEvents: number;
  private readonly flushIntervalMs: number;
  private timer: NodeJS.Timeout | null = null;
  private waiters: (() => void)[] = [];
  private nextSeq = 1;
  private emittedCount = 0;
  private droppedCount = 0;
  private sentCount = 0;
  private receivedCount = 0;
  private highWater = 0;

  constructor(private readonly transport: FrameTransport, options: ChannelOptions = {}) {
    this.queueCap = options.queueCap ?? 4096;
    this.windowCap = options.windowCap ?? 2048;
    this.maxFrameEvents = options.maxFrameEvents ?? 256;
    this.flushIntervalMs = options.flushIntervalMs ?? 5;
    for (const [name, value] of [["queueCap", this.queueCap], ["windowCap", this.windowCap], ["maxFrameEvents", this.maxFrameEvents]] as const) {
      if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
    }
  }

  /** Records one event; returns its sequence number. Never throws and never blocks. */
  emit(event: Omit<PlaneEvent, "seq" | "t"> & { t?: number }): number {
    const seq = this.nextSeq++;
    this.emittedCount++;
    if (this.queue.length >= this.queueCap) { this.droppedCount++; return seq; }
    this.queue.push({ ...event, seq, t: event.t ?? performance.now() });
    if (this.queue.length > this.highWater) this.highWater = this.queue.length;
    if (this.queue.length >= this.maxFrameEvents) this.flush(); else this.schedule();
    return seq;
  }

  /** The collector's cumulative count of events it has received. */
  acknowledge(receivedTotal: number): void {
    if (Number.isSafeInteger(receivedTotal) && receivedTotal > this.receivedCount && receivedTotal <= this.sentCount) this.receivedCount = receivedTotal;
    this.flush();
    this.settle();
  }

  flush(): void {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    while (this.queue.length > 0 && this.sentCount - this.receivedCount < this.windowCap) {
      const room = this.windowCap - (this.sentCount - this.receivedCount);
      const events = this.queue.splice(0, Math.min(this.maxFrameEvents, room));
      this.sentCount += events.length;
      this.transport.send({ type: "events", events, dropped: this.droppedCount });
    }
    if (this.queue.length > 0) this.schedule();
  }

  private schedule(): void {
    if (this.timer) return;
    this.timer = setTimeout(() => { this.timer = null; this.flush(); }, this.flushIntervalMs);
    this.timer.unref();
  }

  private settle(): void {
    if (this.queue.length === 0 && this.sentCount === this.receivedCount) { const waiting = this.waiters; this.waiters = []; for (const wake of waiting) wake(); }
  }

  /** Resolves true when every emitted (non-dropped) event has been acknowledged by the collector, false on timeout. */
  async drain(timeoutMs: number): Promise<boolean> {
    this.flush();
    if (this.queue.length === 0 && this.sentCount === this.receivedCount) return true;
    return new Promise<boolean>((resolve) => {
      const timeout = setTimeout(() => { this.waiters = this.waiters.filter((w) => w !== wake); resolve(false); }, timeoutMs);
      const wake = () => { clearTimeout(timeout); resolve(true); };
      this.waiters.push(wake);
    });
  }

  stats(): ChannelStats {
    return {
      emitted: this.emittedCount, dropped: this.droppedCount, sent: this.sentCount, received: this.receivedCount,
      queued: this.queue.length, unacknowledged: this.sentCount - this.receivedCount, queueHighWater: this.highWater, lastSeq: this.nextSeq - 1,
    };
  }
}
