/**
 * Plane-side OUTCOME COUNTERS (observation only).
 *
 * An independent, bounded, plane-local tally derived from the very events the plane already emits. It exists so that a measurement can
 * cross-check the collector's ledger with a second count that does NOT travel over the (droppable) event channel: any difference
 * between the two is an UNEXPLAINED difference, reported, never absorbed.
 *
 * Guarantees (each pinned by tests/defense-outcome-counters.test.ts):
 *   - It decides nothing. No layer, lane, gate, composer or front branch ever reads it.
 *   - `observe` NEVER throws and never mutates its input; a fault is counted in `faults` and the request proceeds exactly as before.
 *   - Fixed memory: every key space is a CLOSED enum (reject reasons, event kinds, lanes, outcomes, egress error kinds, a closed
 *     list of response statuses plus one "other" bucket). An unknown value goes to `unknown`, never into a new key. No request content,
 *     no address, no header, no token, no nonce is ever read or stored.
 *   - Disabled (the default: the front is not given a counter) means no allocation and no wrapper at all.
 */
import { EGRESS_ERROR_KINDS, PLANE_EVENT_KINDS } from "../../defense/core/ledger";
import { ALL_REJECT_REASONS } from "../../defense/core/types";

// Closed lists restated HERE (not imported from ./lanes) because the legacy Slice-1/2 plane's module graph must contain no L2 code; a test
// pins every list below to the authoritative one in ./lanes.
export const COUNTED_CLASSES = ["open", "mutation", "unknown"] as const;
export const COUNTED_LANES = ["open", "credited", "unverified", "none"] as const;
export const COUNTED_L2_OUTCOMES = ["admitted", "shed", "error", "degraded"] as const;
export const COUNTED_SHED_REASONS = ["lane_budget", "evaluator_saturation"] as const;
export const COUNTED_L2_ERROR_KINDS = ["throw", "timeout", "invalid_verdict", "ledger_full"] as const;

/** Evidence keys must not contain words such as "body", "header" or "token" (the evidence scanner), and the reject reasons do. Reasons are therefore
 * keyed by their position in the closed list: `r00`, `r01`, ... Position is pinned by a test; `REJECT_REASON_KEY` maps a reason to its key. */
export const REJECT_REASON_KEY: Readonly<Record<string, string>> = Object.freeze(Object.fromEntries(ALL_REJECT_REASONS.map((reason, index) => [reason, `r${String(index).padStart(2, "0")}`])));

/** Closed list of response statuses the plane can produce or relay in the reviewed compositions; anything else is `other`. */
export const COUNTED_STATUSES = [200, 204, 301, 302, 303, 304, 400, 403, 404, 405, 408, 413, 414, 415, 417, 429, 431, 500, 502, 503, 504] as const;
export type StatusBucket = `${(typeof COUNTED_STATUSES)[number]}` | "other";
const STATUS_SET: ReadonlySet<number> = new Set(COUNTED_STATUSES);
export const STATUS_BUCKETS: readonly StatusBucket[] = [...COUNTED_STATUSES.map((s) => `${s}` as StatusBucket), "other"];

export type OutcomeSnapshot = {
  version: 1;
  /** Count per plane event kind (the per-layer received / passed / rejected / shed / error / forwarded / responded view). */
  events: Record<string, number>;
  /** L1 and semantic and lane reject reasons (closed list). */
  rejectReasons: Record<string, number>;
  /** L2 decisions keyed `class.lane.outcome` over closed enums (lane `none` when classification never ran). */
  l2Decisions: Record<string, number>;
  l2ShedReasons: Record<string, number>;
  l2ErrorKinds: Record<string, number>;
  /** Origin delivery from the plane's side. */
  egressFailures: Record<string, number>;
  egressResponseStatus: Record<string, number>;
  /** What the client was finally answered with (INGRESS_RESPONDED). */
  clientResponseStatus: Record<string, number>;
  /** Values outside a closed list (should be zero) and observer faults (should be zero). */
  unknown: number;
  faults: number;
};

const zeroed = (keys: readonly string[]): Record<string, number> => { const out: Record<string, number> = Object.create(null); for (const key of keys) out[key] = 0; return out; };
const REASONS: ReadonlySet<string> = new Set(ALL_REJECT_REASONS);
const KINDS: ReadonlySet<string> = new Set([...PLANE_EVENT_KINDS, "PARSER_REJECTED"]);
const EXTRA_KINDS = ["PARSER_REJECTED"];

export type CountedEvent = {
  kind?: unknown; reason?: unknown; errorKind?: unknown; status?: unknown; egressError?: unknown;
  class?: unknown; lane?: unknown; outcome?: unknown; shedReason?: unknown; l2ErrorKind?: unknown;
};

export class OutcomeCounters {
  private readonly events = zeroed([...PLANE_EVENT_KINDS, ...EXTRA_KINDS]);
  private readonly rejectReasons = zeroed(Object.values(REJECT_REASON_KEY));
  private readonly l2Decisions: Record<string, number>;
  private readonly l2ShedReasons = zeroed(COUNTED_SHED_REASONS);
  private readonly l2ErrorKinds = zeroed(COUNTED_L2_ERROR_KINDS);
  private readonly egressFailures = zeroed(EGRESS_ERROR_KINDS);
  private readonly egressResponseStatus = zeroed(STATUS_BUCKETS);
  private readonly clientResponseStatus = zeroed(STATUS_BUCKETS);
  private unknown = 0;
  private faults = 0;
  /** Test seam: a fault injected into the tally (never set outside tests). */
  private readonly injectedFault: (() => void) | undefined;

  constructor(options: { injectedFault?: () => void } = {}) {
    const keys: string[] = [];
    for (const klass of COUNTED_CLASSES) for (const lane of COUNTED_LANES) for (const outcome of COUNTED_L2_OUTCOMES) keys.push(`${klass}.${lane}.${outcome}`);
    this.l2Decisions = zeroed(keys);
    this.injectedFault = options.injectedFault;
  }

  private bump(table: Record<string, number>, key: unknown): void {
    if (typeof key === "string" && Object.hasOwn(table, key)) table[key]++; else this.unknown++;
  }

  private status(table: Record<string, number>, value: unknown): void {
    const bucket = typeof value === "number" && STATUS_SET.has(value) ? `${value}` : "other";
    table[bucket]++;
  }

  /** Tallies one plane event. Never throws; a fault is counted and swallowed. */
  observe(event: CountedEvent): void {
    try {
      this.injectedFault?.();
      const kind = event.kind;
      if (typeof kind !== "string" || !KINDS.has(kind)) { this.unknown++; return; }
      this.events[kind]++;
      switch (kind) {
        case "L1_REJECTED": if (typeof event.reason === "string" && REASONS.has(event.reason)) this.rejectReasons[REJECT_REASON_KEY[event.reason]]++; else this.unknown++; break;
        case "L2_DECIDED": {
          const lane = event.lane === null || event.lane === undefined ? "none" : event.lane;
          const key = `${String(event.class)}.${String(lane)}.${String(event.outcome)}`;
          this.bump(this.l2Decisions, key);
          if (event.shedReason !== undefined) this.bump(this.l2ShedReasons, event.shedReason);
          if (event.l2ErrorKind !== undefined) this.bump(this.l2ErrorKinds, event.l2ErrorKind);
          break;
        }
        case "EGRESS_FAILED": this.bump(this.egressFailures, event.egressError); break;
        case "EGRESS_RESPONDED": this.status(this.egressResponseStatus, event.status); break;
        case "INGRESS_RESPONDED": this.status(this.clientResponseStatus, event.status); break;
        default: break;
      }
    } catch {
      this.faults++;
    }
  }

  snapshot(): OutcomeSnapshot {
    return {
      version: 1, events: { ...this.events }, rejectReasons: { ...this.rejectReasons }, l2Decisions: { ...this.l2Decisions },
      l2ShedReasons: { ...this.l2ShedReasons }, l2ErrorKinds: { ...this.l2ErrorKinds }, egressFailures: { ...this.egressFailures },
      egressResponseStatus: { ...this.egressResponseStatus }, clientResponseStatus: { ...this.clientResponseStatus },
      unknown: this.unknown, faults: this.faults,
    };
  }
}

/** Wraps an event emitter so that every event is tallied BEFORE it is handed on. The tally never throws and never alters the event; the wrapped
 * emitter's return value (the sequence number) is passed through untouched. Without a counter, callers simply do not wrap (identity). */
export function countingEmit<E extends CountedEvent, R>(counters: OutcomeCounters, emit: (event: E) => R): (event: E) => R {
  return (event) => { counters.observe(event); return emit(event); };
}

/** A plane tick extended with the outcome tally. Declared HERE, as an intersection, so the historical tick type (and every file pinned to it) is untouched. */
export type WithOutcomes<Tick> = Tick & { outcomes: OutcomeSnapshot | null };
