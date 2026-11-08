/**
 * Per-event-kind LEDGER (observation only, additive). Counts every plane event the collector ingests, by kind, at the one point all of them pass.
 *
 * WHY HERE AND NOT FROM THE JOURNAL ALONE. The collector's journal records the events of requests the collector owns (the canary) and the anonymous
 * parser events. The events of REMOTE-lane requests are taken by the external reducer BEFORE the journal append (collector.ts, ingestFrame), and the
 * reducer's aggregate counters do not include `L2_ENROLLED` / `L2_ENROLL_SKIPPED`. Both files are byte-pinned. The collector's existing
 * `observePlaneEvents` hook is called for every event before either branch, so it is the only place a complete per-kind count can be taken without
 * touching a pinned file. The journal and the reducer counters remain independent records: the criterion 9 check compares this ledger with them.
 *
 * It decides nothing, mutates nothing it is given, never throws, and keeps O(#kinds) memory. Events carry a gapless per-plane-process sequence number
 * (`PlaneEvent.seq`), which this ledger uses as its integrity anchor:
 *   - a sequence number that does not increase (a repeat or a reorder) is counted as `duplicatesOrReordered` and the event is NOT counted again;
 *   - a jump is counted as `missingSeqs` (events lost between the plane and the collector) and the ranges are kept (bounded);
 *   - a kind outside the closed vocabulary is `unsupported` (its sequence number still advances the anchor, it is not counted as a kind);
 *   - an event without a valid shape is `malformed`.
 * Completeness is claimed only as strongly as these checks plus the plane's own final channel stats (emitted / dropped / lastSeq) allow.
 */
import { PLANE_EVENT_KINDS } from "../../defense/core/ledger";

export const KIND_LEDGER_SCHEMA = "ba0-kind-ledger-v1";
/** The closed vocabulary: the plane's kinds plus the parser rejection the plane reports without a request. */
export const KIND_LEDGER_KINDS: readonly string[] = Object.freeze([...PLANE_EVENT_KINDS, "PARSER_REJECTED"]);
const KIND_SET: ReadonlySet<string> = new Set(KIND_LEDGER_KINDS);
const MAX_GAP_RANGES = 16;

export type KindLedgerArtifact = {
  schema: typeof KIND_LEDGER_SCHEMA;
  counts: Record<string, number>;
  total: number;
  firstSeq: number | null;
  lastSeq: number;
  missingSeqs: number;
  gapRanges: [number, number][];
  gapRangesTruncated: boolean;
  duplicatesOrReordered: number;
  unsupported: number;
  malformed: number;
  anonymous: number;
  /** The collector's own bookkeeping at the time of the snapshot (independent of this ledger). */
  collector: { received: number; lastSeq: number; droppedReported: number };
};

export class EventKindLedger {
  private readonly counts: Record<string, number> = Object.create(null);
  private total = 0;
  private firstSeq: number | null = null;
  private lastSeq = 0;
  private missingSeqs = 0;
  private readonly gapRanges: [number, number][] = [];
  private gapRangesTruncated = false;
  private duplicatesOrReordered = 0;
  private unsupported = 0;
  private malformed = 0;
  private anonymous = 0;

  constructor() { for (const kind of KIND_LEDGER_KINDS) this.counts[kind] = 0; }

  /** Tallies one event. Never throws; anything that is not a well-formed event is `malformed`. */
  observe(event: unknown): void {
    try {
      if (typeof event !== "object" || event === null || Array.isArray(event)) { this.malformed++; return; }
      const { seq, kind, nonce } = event as { seq?: unknown; kind?: unknown; nonce?: unknown };
      if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 1 || typeof kind !== "string" || !(nonce === null || typeof nonce === "string")) { this.malformed++; return; }
      if (seq <= this.lastSeq) { this.duplicatesOrReordered++; return; }
      if (this.firstSeq === null) this.firstSeq = seq;
      if (seq > this.lastSeq + 1) {
        this.missingSeqs += seq - this.lastSeq - 1;
        if (this.gapRanges.length < MAX_GAP_RANGES) this.gapRanges.push([this.lastSeq + 1, seq - 1]); else this.gapRangesTruncated = true;
      }
      this.lastSeq = seq;
      if (!KIND_SET.has(kind)) { this.unsupported++; return; }
      this.counts[kind]++;
      this.total++;
      if (nonce === null) this.anonymous++;
    } catch {
      this.malformed++;
    }
  }

  artifact(collector: { received: number; lastSeq: number; droppedReported: number }): KindLedgerArtifact {
    return {
      schema: KIND_LEDGER_SCHEMA, counts: { ...this.counts }, total: this.total, firstSeq: this.firstSeq, lastSeq: this.lastSeq, missingSeqs: this.missingSeqs,
      gapRanges: this.gapRanges.map(([from, to]) => [from, to] as [number, number]), gapRangesTruncated: this.gapRangesTruncated, duplicatesOrReordered: this.duplicatesOrReordered,
      unsupported: this.unsupported, malformed: this.malformed, anonymous: this.anonymous,
      collector: { received: collector.received, lastSeq: collector.lastSeq, droppedReported: collector.droppedReported },
    };
  }
}
