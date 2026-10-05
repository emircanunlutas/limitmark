/**
 * BA0 collector: the AUTHORITATIVE ledger. It runs in the harness process, outside the Defense Plane's failure domain.
 *
 * Failure semantics (also documented in defense/README.md):
 *  - survives a Defense Plane crash: every harness event (SENT, CLIENT_COMPLETED), every origin observation, and every plane event the
 *    collector had already received. The append-only journal is flushed asynchronously on a timer and at close, never per request.
 *  - may be lost: plane events that were still in the plane's queue or in flight on the IPC pipe when it died. They are never
 *    silently absent: the harness's own SENT records have no plane lifecycle, the event stream has a sequence gap, the plane never
 *    reports FIN, and the child's exit is observed. Each of those is an anomaly and any anomaly makes the run INVALID.
 *  - bounded memory: at most `maxRequests` records and `maxEventsPerRecord` events per record are kept, and the journal stops at
 *    `maxJournalBytes` (overflow is itself an anomaly). The plane-side queue is bounded by BoundedEventChannel.
 *  - evidence refers to requests by a sequential record id (r1, r2, ...), never by the nonce.
 */
import { createHash } from "node:crypto";
import { createWriteStream, type WriteStream } from "node:fs";
import {
  validateLifecycle, terminalOutcome, type Anomaly, type AnomalyCode, type ClientResultKind, type EventFrame, type ExpectedLane, type HarnessEvent,
  type LifecycleView, type OriginEvent, type PlaneEvent, type TerminalOutcome,
} from "../../defense/core/ledger";
import type { PlaneAdvisory } from "../../defense/plane/protocol";
import type { ChannelStats } from "../../defense/core/ledger";
import { assertEvidenceSafe } from "../evidence/redact";

export type RequestClass = "canary" | "hostile";
export type RequestMeta = { lane: ExpectedLane; phase: string; cls: RequestClass; scenario: string; journey: number | null; step: number | null; method: "GET" | "POST" | "OTHER" };

export type LedgerRecord = {
  rid: string;
  nonce: string;
  meta: RequestMeta;
  harness: HarnessEvent[];
  plane: PlaneEvent[];
  origin: OriginEvent[];
  latencyMs: number | null;
};

export type CollectorLimits = { maxRequests: number; maxEventsPerRecord: number; maxJournalBytes: number; maxAnomalies: number };
export const DEFAULT_COLLECTOR_LIMITS: CollectorLimits = { maxRequests: 20_000, maxEventsPerRecord: 32, maxJournalBytes: 8 * 1_048_576, maxAnomalies: 200 };

export type JournalSummary = { lines: number; bytes: number; sha256: string; overflow: boolean };

/** Bounded, append-only NDJSON evidence. Entries are scanned by the evidence redactor before they are kept; writes are batched. */
class Journal {
  private readonly stream: WriteStream;
  private readonly hash = createHash("sha256");
  private buffer: string[] = [];
  private bytes = 0;
  private lines = 0;
  private overflowed = false;
  private readonly timer: NodeJS.Timeout;

  constructor(filePath: string, private readonly maxBytes: number, flushMs = 50) {
    this.stream = createWriteStream(filePath, { flags: "wx" });
    this.timer = setInterval(() => this.flush(), flushMs);
    this.timer.unref();
  }

  append(entry: Record<string, unknown>): void {
    if (this.overflowed) return;
    assertEvidenceSafe(entry, "$journal");
    const line = `${JSON.stringify(entry)}\n`;
    if (this.bytes + line.length > this.maxBytes) { this.overflowed = true; return; }
    this.bytes += line.length;
    this.lines++;
    this.buffer.push(line);
  }

  get overflow(): boolean { return this.overflowed; }

  private flush(): void {
    if (this.buffer.length === 0) return;
    const chunk = this.buffer.join("");
    this.buffer = [];
    this.hash.update(chunk);
    this.stream.write(chunk);
  }

  async close(): Promise<JournalSummary> {
    clearInterval(this.timer);
    this.flush();
    await new Promise<void>((resolve, reject) => { this.stream.end((error?: Error | null) => (error ? reject(error) : resolve())); });
    return { lines: this.lines, bytes: this.bytes, sha256: this.hash.digest("hex"), overflow: this.overflowed };
  }
}

export type PlaneFin = { drained: boolean; channel: ChannelStats; advisory: PlaneAdvisory };

export class Collector {
  private readonly records = new Map<string, LedgerRecord>();
  private readonly anomalyList: Anomaly[] = [];
  private anomalyCount = 0;
  private lastSeq = 0;
  private planeEventsReceived = 0;
  private planeDroppedReported = 0;
  private readonly parserRejects = new Map<string, number>();
  private frozen = false;
  private lateEvents = 0;
  private planeCrashed: string | null = null;
  private fin: PlaneFin | null = null;
  private nextRid = 1;
  private capacityExceeded = false;
  private readonly journal: Journal | null;

  constructor(journalPath: string | null, private readonly limits: CollectorLimits = DEFAULT_COLLECTOR_LIMITS) {
    this.journal = journalPath === null ? null : new Journal(journalPath, limits.maxJournalBytes);
  }

  // ---- anomalies

  anomaly(code: AnomalyCode, nonce: string | null, detail: string): void {
    this.anomalyCount++;
    if (this.anomalyList.length < this.limits.maxAnomalies) this.anomalyList.push({ code, nonce: nonce === null ? null : (this.records.get(nonce)?.rid ?? "unknown"), detail });
  }

  // ---- harness events

  /** Registers a request BEFORE it is dispatched. Returns false when capacity is exhausted (the run is then INVALID). */
  sent(nonce: string, meta: RequestMeta): boolean {
    if (this.frozen) { this.lateEvents++; this.anomaly("late_event_after_finalization", null, "SENT"); return false; }
    if (this.records.has(nonce)) { this.anomaly("duplicate_nonce_sent", nonce, "SENT"); return false; }
    if (this.records.size >= this.limits.maxRequests) {
      if (!this.capacityExceeded) { this.capacityExceeded = true; this.anomaly("ledger_capacity_exceeded", null, `maxRequests ${this.limits.maxRequests}`); }
      return false;
    }
    const record: LedgerRecord = { rid: `r${this.nextRid++}`, nonce, meta, harness: [{ kind: "SENT" }], plane: [], origin: [], latencyMs: null };
    this.records.set(nonce, record);
    this.journal?.append({ src: "h", rid: record.rid, k: "SENT", lane: meta.lane, phase: meta.phase, cls: meta.cls, scn: meta.scenario, j: meta.journey, st: meta.step, m: meta.method });
    return true;
  }

  clientCompleted(nonce: string, outcome: { result: ClientResultKind; status?: number; outcomeHeader?: string; latencyMs: number }): void {
    const record = this.records.get(nonce);
    if (this.frozen) { this.lateEvents++; this.anomaly("late_event_after_finalization", nonce, "CLIENT_COMPLETED"); return; }
    if (!record) { this.anomaly("unknown_nonce", null, "CLIENT_COMPLETED"); return; }
    if (record.harness.length >= this.limits.maxEventsPerRecord) return;
    record.harness.push({ kind: "CLIENT_COMPLETED", result: outcome.result, status: outcome.status, outcomeHeader: outcome.outcomeHeader });
    record.latencyMs = outcome.latencyMs;
    this.journal?.append({ src: "h", rid: record.rid, k: "CLIENT_COMPLETED", result: outcome.result, status: outcome.status ?? null, outcome: outcome.outcomeHeader ?? null, ms: Math.round(outcome.latencyMs * 100) / 100 });
  }

  // ---- plane events (event channel)

  /** Ingests one frame from the plane; returns the cumulative number of plane events received, for the acknowledgement. */
  ingestFrame(frame: EventFrame): number {
    this.planeDroppedReported = Math.max(this.planeDroppedReported, frame.dropped);
    for (const event of frame.events) {
      this.planeEventsReceived++;
      if (event.seq <= this.lastSeq) this.anomaly("duplicate_sequence", event.nonce, `seq ${event.seq}`);
      else if (event.seq > this.lastSeq + 1) this.anomaly("event_channel_loss", event.nonce, `gap of ${event.seq - this.lastSeq - 1} before seq ${event.seq}`);
      this.lastSeq = Math.max(this.lastSeq, event.seq);
      if (this.frozen) { this.lateEvents++; this.anomaly("late_event_after_finalization", event.nonce, event.kind); continue; }
      if (event.nonce === null) {
        const code = event.code ?? "unknown";
        this.parserRejects.set(code, (this.parserRejects.get(code) ?? 0) + 1);
        this.journal?.append({ src: "p", seq: event.seq, k: event.kind, code });
        continue;
      }
      const record = this.records.get(event.nonce);
      if (!record) { this.anomaly(event.uncorrelated ? "uncorrelated_ingress" : "unknown_nonce", null, event.kind); continue; }
      if (record.plane.length >= this.limits.maxEventsPerRecord) { this.anomaly("ledger_capacity_exceeded", event.nonce, "events per record"); continue; }
      record.plane.push(event);
      this.journal?.append({
        src: "p", rid: record.rid, seq: event.seq, k: event.kind, reason: event.reason ?? null, stage: event.stage ?? null, err: event.errorKind ?? null,
        status: event.status ?? null, egress: event.egressError ?? null, stripped: event.stripped ?? null, uncorr: event.uncorrelated ?? null,
      });
    }
    return this.planeEventsReceived;
  }

  // ---- origin observations (collected in-process, independently of the plane)

  ingestOrigin(event: OriginEvent): void {
    if (this.frozen) { this.lateEvents++; this.anomaly("late_event_after_finalization", event.nonce, event.kind); return; }
    const record = event.nonce === null ? undefined : this.records.get(event.nonce);
    if (!record) { this.anomaly("unknown_nonce", null, event.kind); return; }
    if (record.origin.length >= this.limits.maxEventsPerRecord) { this.anomaly("ledger_capacity_exceeded", event.nonce, "events per record"); return; }
    record.origin.push(event);
    this.journal?.append({ src: "o", rid: record.rid, k: event.kind, inst: event.instance, hop: event.hop, status: event.status ?? null, spoofed: event.spoofed ?? null });
  }

  // ---- plane lifecycle (process level)

  planeExited(detail: string): void { if (this.planeCrashed === null && this.fin === null) this.planeCrashed = detail; }
  planeFinished(fin: PlaneFin): void { this.fin = fin; }

  freeze(): void { this.frozen = true; }
  get isFrozen(): boolean { return this.frozen; }

  // ---- reads

  *allRecords(): IterableIterator<LedgerRecord> { yield* this.records.values(); }
  recordFor(nonce: string): LedgerRecord | undefined { return this.records.get(nonce); }
  get size(): number { return this.records.size; }
  get channel(): { received: number; lastSeq: number; droppedReported: number; fin: PlaneFin | null; crashed: string | null; late: number } {
    return { received: this.planeEventsReceived, lastSeq: this.lastSeq, droppedReported: this.planeDroppedReported, fin: this.fin, crashed: this.planeCrashed, late: this.lateEvents };
  }
  parserRejectedByCode(): Record<string, number> { return Object.fromEntries([...this.parserRejects.entries()].sort()); }
  parserRejectedTotal(): number { let total = 0; for (const count of this.parserRejects.values()) total += count; return total; }

  /** Final validation of every lifecycle plus the channel-level checks. Pure over the current state; call after `freeze()`. */
  finalize(): { anomalies: Anomaly[]; anomalyTotal: number } {
    const found: Anomaly[] = [];
    for (const record of this.records.values()) {
      const view: LifecycleView = { nonce: record.nonce, expected: record.meta.lane, harness: record.harness, plane: record.plane, origin: record.origin };
      for (const anomaly of validateLifecycle(view, true)) found.push({ ...anomaly, nonce: record.rid });
    }
    const channel = this.channel;
    if (channel.crashed !== null) found.push({ code: "plane_crashed", nonce: null, detail: channel.crashed });
    else if (channel.fin === null) found.push({ code: "plane_not_finalized", nonce: null, detail: "no FIN from the plane" });
    else {
      const stats = channel.fin.channel;
      if (!channel.fin.drained) found.push({ code: "event_channel_loss", nonce: null, detail: "plane could not drain its queue" });
      if (stats.dropped > 0 || channel.droppedReported > 0) found.push({ code: "event_channel_loss", nonce: null, detail: `plane dropped ${Math.max(stats.dropped, channel.droppedReported)} events` });
      if (stats.lastSeq !== channel.lastSeq) found.push({ code: "event_channel_loss", nonce: null, detail: `plane last seq ${stats.lastSeq}, collector last seq ${channel.lastSeq}` });
      if (stats.emitted !== channel.received + stats.dropped) found.push({ code: "event_channel_loss", nonce: null, detail: `plane emitted ${stats.emitted}, collector received ${channel.received}` });
    }
    if (this.journal?.overflow) found.push({ code: "journal_overflow", nonce: null, detail: `journal reached ${this.limits.maxJournalBytes} bytes` });
    if (this.lateEvents > 0) found.push({ code: "late_event_after_finalization", nonce: null, detail: `${this.lateEvents} events after the ledger froze` });
    const all = [...this.anomalyList, ...found];
    return { anomalies: all.slice(0, this.limits.maxAnomalies), anomalyTotal: this.anomalyCount + found.length };
  }

  async closeJournal(): Promise<JournalSummary | null> { return this.journal ? this.journal.close() : null; }

  /** Derived per-request terminal outcome (plane view); used by the accounting, never stored as a counter. */
  static terminalOf(record: LedgerRecord): TerminalOutcome | null { return terminalOutcome(record.plane); }
}
