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
  validateLifecycle, terminalOutcome, type Anomaly, type AnomalyCode, type AppEvent, type BoundaryEvent, type ClientResultKind, type EventFrame, type ExpectedLane,
  type HarnessEvent, type LifecycleView, type OriginEvent, type PlaneEvent, type TerminalOutcome,
} from "../../defense/core/ledger";
import { validateOriginLineage } from "../../defense/core/lineage";
import { validateL2Lifecycle } from "../../defense/core/l2-lifecycle";
import type { PlaneAdvisory } from "../../defense/plane/protocol";
import type { BoundaryStats } from "../../defense/boundary/protocol";
import type { AppFinStats } from "../../defense/origin/app-protocol";
import type { ChannelStats } from "../../defense/core/ledger";
import { assertEvidenceSafe } from "../evidence/redact";
import type { ExternalReducer } from "./external-reducer";

export type RequestClass = "canary" | "hostile";
export type RequestMeta = { lane: ExpectedLane; phase: string; cls: RequestClass; scenario: string; journey: number | null; step: number | null; method: "GET" | "POST" | "OTHER" };

export type LedgerRecord = {
  rid: string;
  nonce: string;
  meta: RequestMeta;
  harness: HarnessEvent[];
  plane: PlaneEvent[];
  origin: OriginEvent[];
  /** Slice 2 only: the Origin Boundary's and the Protected App's own streams for this request. Empty in a Slice-1 run. */
  boundary: BoundaryEvent[];
  app: AppEvent[];
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
export type BoundaryFin = { drained: boolean; channel: ChannelStats; stats: BoundaryStats };
export type AppFin = { drained: boolean; channel: ChannelStats; stats: AppFinStats };

/** Per-process stream integrity (Slice 2): the same checks the plane stream gets, for each additional child process. */
class StreamState<F> {
  lastSeq = 0;
  received = 0;
  droppedReported = 0;
  crashed: string | null = null;
  fin: F | null = null;
  readonly anonymous = new Map<string, number>();
}

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
  private originStreams = false;
  private laneStreams = false;
  private readonly boundaryStream = new StreamState<BoundaryFin>();
  private readonly appStream = new StreamState<AppFin>();
  /** Field qualification only: the bounded lane for REMOTE-peer requests. Absent in every Slice-1/2/3 run, which behaves exactly as before. */
  private external: ExternalReducer | null = null;

  constructor(journalPath: string | null, private readonly limits: CollectorLimits = DEFAULT_COLLECTOR_LIMITS) {
    this.journal = journalPath === null ? null : new Journal(journalPath, limits.maxJournalBytes);
  }

  // ---- anomalies

  anomaly(code: AnomalyCode, nonce: string | null, detail: string): void {
    this.anomalyCount++;
    if (this.anomalyList.length < this.limits.maxAnomalies) this.anomalyList.push({ code, nonce: nonce === null ? null : (this.records.get(nonce)?.rid ?? "unknown"), detail });
  }

  /** Field qualification: external-lane anomalies, already tagged with the request's evidence id (never its nonce). */
  externalAnomaly(code: AnomalyCode, rid: string | null, detail: string): void {
    this.anomalyCount++;
    if (this.anomalyList.length < this.limits.maxAnomalies) this.anomalyList.push({ code, nonce: rid, detail });
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
    const record: LedgerRecord = { rid: `r${this.nextRid++}`, nonce, meta, harness: [{ kind: "SENT" }], plane: [], origin: [], boundary: [], app: [], latencyMs: null };
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
      if (!record) {
        // An external-lane request (a remote peer; the plane minted its nonce) is owned by the reducer. Everything else is as it always was.
        if (this.external?.ingestPlane(event)) continue;
        this.anomaly(event.uncorrelated ? "uncorrelated_ingress" : "unknown_nonce", null, event.kind);
        continue;
      }
      if (record.plane.length >= this.limits.maxEventsPerRecord) { this.anomaly("ledger_capacity_exceeded", event.nonce, "events per record"); continue; }
      record.plane.push(event);
      this.journal?.append({
        src: "p", rid: record.rid, seq: event.seq, k: event.kind, reason: event.reason ?? null, stage: event.stage ?? null, err: event.errorKind ?? null,
        status: event.status ?? null, egress: event.egressError ?? null, stripped: event.stripped ?? null, uncorr: event.uncorrelated ?? null,
        // Slice 3 fields appear only on events that carry them, so a Slice-1/2 journal is byte-for-byte what it was.
        ...(event.class !== undefined ? { cls2: event.class, lane: event.lane ?? null, out: event.outcome ?? null } : {}),
        ...(event.shedReason !== undefined ? { shed: event.shedReason } : {}),
        ...(event.l2ErrorKind !== undefined ? { l2err: event.l2ErrorKind } : {}),
        ...(event.spent !== undefined ? { spent: event.spent } : {}),
        ...(event.touched !== undefined ? { touched: event.touched } : {}),
        ...(event.creditTag !== undefined ? { ctag: event.creditTag } : {}),
        ...(event.dt !== undefined ? { dt: event.dt, lvl: event.lvl ?? null, lseq: event.lseq ?? null } : {}),
        ...(event.basis !== undefined ? { basis: event.basis, shadow: event.shadow ?? null } : {}),
        ...(event.skipReason !== undefined ? { skip: event.skipReason } : {}),
        ...(event.fill !== undefined ? { fill: event.fill } : {}),
        ...(event.failStage !== undefined ? { fstage: event.failStage } : {}),
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

  // ---- Slice 2: the Origin Boundary's and the Protected App's streams (each its own process, its own gapless sequence)

  /** Turns on the boundary/app checks. A Slice-1 run never calls this, so every Slice-1 rule stays exactly as it was. */
  enableOriginStreams(): void { this.originStreams = true; }

  /** Slice 3: the plane composition has L2, so every protected request is validated with the L2 automaton and the L2 rules. */
  enableLaneStreams(): void { this.laneStreams = true; }

  /** Field qualification: routes requests from remote peers to the bounded external lane. Call once, before any traffic. */
  enableExternalLane(reducer: ExternalReducer): void { this.external = reducer; }
  get externalLane(): ExternalReducer | null { return this.external; }

  ingestBoundaryFrame(frame: EventFrame<BoundaryEvent>): number {
    const stream = this.boundaryStream;
    stream.droppedReported = Math.max(stream.droppedReported, frame.dropped);
    for (const event of frame.events) {
      stream.received++;
      if (event.seq <= stream.lastSeq) this.anomaly("duplicate_sequence", event.nonce, `boundary seq ${event.seq}`);
      else if (event.seq > stream.lastSeq + 1) this.anomaly("boundary_channel_loss", event.nonce, `gap of ${event.seq - stream.lastSeq - 1} before seq ${event.seq}`);
      stream.lastSeq = Math.max(stream.lastSeq, event.seq);
      if (this.frozen) { this.lateEvents++; this.anomaly("late_event_after_finalization", event.nonce, event.kind); continue; }
      if (event.nonce === null) {
        stream.anonymous.set(event.kind, (stream.anonymous.get(event.kind) ?? 0) + 1);
        this.journal?.append({ src: "b", seq: event.seq, k: event.kind, code: event.code ?? null });
        continue;
      }
      const record = this.records.get(event.nonce);
      if (!record) {
        // A downstream event may beat the plane's ingress here (separate pipes): the reducer holds it until the ingress claims it.
        if (this.external?.ingestBoundary(event)) continue;
        this.anomaly("unknown_nonce", null, event.kind);
        continue;
      }
      if (record.boundary.length >= this.limits.maxEventsPerRecord) { this.anomaly("ledger_capacity_exceeded", event.nonce, "events per record"); continue; }
      record.boundary.push(event);
      this.journal?.append({ src: "b", rid: record.rid, seq: event.seq, k: event.kind, reason: event.reason ?? null, hop: event.hop ?? null, pb: event.pbTag ?? null, ba: event.baTag ?? null, status: event.status ?? null, fwd: event.forwardError ?? null });
    }
    return stream.received;
  }

  ingestAppFrame(frame: EventFrame<AppEvent>): number {
    const stream = this.appStream;
    stream.droppedReported = Math.max(stream.droppedReported, frame.dropped);
    for (const event of frame.events) {
      stream.received++;
      if (event.seq <= stream.lastSeq) this.anomaly("duplicate_sequence", event.nonce, `app seq ${event.seq}`);
      else if (event.seq > stream.lastSeq + 1) this.anomaly("app_channel_loss", event.nonce, `gap of ${event.seq - stream.lastSeq - 1} before seq ${event.seq}`);
      stream.lastSeq = Math.max(stream.lastSeq, event.seq);
      if (this.frozen) { this.lateEvents++; this.anomaly("late_event_after_finalization", event.nonce, event.kind); continue; }
      const record = event.nonce === null ? undefined : this.records.get(event.nonce);
      if (!record) {
        if (this.external?.ingestApp(event)) continue;
        // An unattributable refusal is counted (bounded: one counter per kind); an unattributable ADMISSION is an anomaly by itself.
        if (event.kind === "APP_REFUSED") { stream.anonymous.set(event.kind, (stream.anonymous.get(event.kind) ?? 0) + 1); this.journal?.append({ src: "a", seq: event.seq, k: event.kind, reason: event.reason ?? null }); }
        else this.anomaly("unknown_nonce", null, event.kind);
        continue;
      }
      if (record.app.length >= this.limits.maxEventsPerRecord) { this.anomaly("ledger_capacity_exceeded", event.nonce, "events per record"); continue; }
      record.app.push(event);
      // Slice-1 origin rules still apply to an admitted request: derive the legacy events they read (pure mapping, nothing new is decided here).
      const nonce = record.nonce;
      if (event.kind === "APP_ADMITTED") record.origin.push({ instance: "protected", nonce, kind: "ORIGIN_RECEIVED", hop: event.hop ?? null, spoofed: event.spoofed ?? 0 });
      else if (event.kind === "APP_COMPLETED") record.origin.push({ instance: "protected", nonce, kind: "ORIGIN_COMPLETED", hop: event.hop ?? null, status: event.status });
      else if (event.kind === "APP_ABORTED") record.origin.push({ instance: "protected", nonce, kind: "ORIGIN_ABORTED", hop: event.hop ?? null });
      this.journal?.append({ src: "a", rid: record.rid, seq: event.seq, k: event.kind, reason: event.reason ?? null, hop: event.hop ?? null, pb: event.pbTag ?? null, ba: event.baTag ?? null, status: event.status ?? null, spoofed: event.spoofed ?? null });
    }
    return stream.received;
  }

  boundaryExited(detail: string): void { if (this.boundaryStream.crashed === null && this.boundaryStream.fin === null) this.boundaryStream.crashed = detail; }
  boundaryFinished(fin: BoundaryFin): void { this.boundaryStream.fin = fin; }
  appExited(detail: string): void { if (this.appStream.crashed === null && this.appStream.fin === null) this.appStream.crashed = detail; }
  appFinished(fin: AppFin): void { this.appStream.fin = fin; }
  get boundaryInfo(): { received: number; lastSeq: number; droppedReported: number; fin: BoundaryFin | null; crashed: string | null; anonymous: Record<string, number> } {
    const s = this.boundaryStream;
    return { received: s.received, lastSeq: s.lastSeq, droppedReported: s.droppedReported, fin: s.fin, crashed: s.crashed, anonymous: Object.fromEntries(s.anonymous) };
  }
  get appInfo(): { received: number; lastSeq: number; droppedReported: number; fin: AppFin | null; crashed: string | null; anonymous: Record<string, number> } {
    const s = this.appStream;
    return { received: s.received, lastSeq: s.lastSeq, droppedReported: s.droppedReported, fin: s.fin, crashed: s.crashed, anonymous: Object.fromEntries(s.anonymous) };
  }

  // ---- plane lifecycle (process level)

  planeExited(detail: string): void { if (this.planeCrashed === null && this.fin === null) this.planeCrashed = detail; }
  planeFinished(fin: PlaneFin): void { this.fin = fin; }

  freeze(): void { this.frozen = true; }
  get isFrozen(): boolean { return this.frozen; }
  /** Anomalies recorded so far (finalization adds the end-of-run checks). The field runner watches it live. */
  get anomalyTotalSoFar(): number { return this.anomalyCount; }

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
    // Requests still open in the external lane are reduced (an unresolved one is an anomaly) and every unclaimed downstream event is flagged.
    this.external?.finalize();
    const found: Anomaly[] = [];
    for (const record of this.records.values()) {
      const view: LifecycleView = {
        nonce: record.nonce, expected: record.meta.lane, harness: record.harness, plane: record.plane, origin: record.origin,
        ...(this.originStreams ? { boundary: record.boundary, app: record.app } : {}),
        ...(this.laneStreams ? { l2: true } : {}),
      };
      for (const anomaly of validateLifecycle(view, true)) found.push({ ...anomaly, nonce: record.rid });
      for (const anomaly of validateOriginLineage(view, true)) found.push({ ...anomaly, nonce: record.rid });
      for (const anomaly of validateL2Lifecycle(view, true)) found.push({ ...anomaly, nonce: record.rid });
    }
    if (this.originStreams) {
      const check = (name: "boundary" | "app", state: StreamState<BoundaryFin | AppFin>) => {
        const fin = state.fin;
        const [crashed, notFinal, loss] = name === "boundary"
          ? (["boundary_crashed", "boundary_not_finalized", "boundary_channel_loss"] as const)
          : (["app_crashed", "app_not_finalized", "app_channel_loss"] as const);
        if (state.crashed !== null) found.push({ code: crashed, nonce: null, detail: state.crashed });
        else if (fin === null) found.push({ code: notFinal, nonce: null, detail: `no FIN from the ${name}` });
        else {
          if (!fin.drained) found.push({ code: loss, nonce: null, detail: `${name} could not drain its queue` });
          if (fin.channel.dropped > 0 || state.droppedReported > 0) found.push({ code: loss, nonce: null, detail: `${name} dropped ${Math.max(fin.channel.dropped, state.droppedReported)} events` });
          if (fin.channel.lastSeq !== state.lastSeq) found.push({ code: loss, nonce: null, detail: `${name} last seq ${fin.channel.lastSeq}, collector last seq ${state.lastSeq}` });
          if (fin.channel.emitted !== state.received + fin.channel.dropped) found.push({ code: loss, nonce: null, detail: `${name} emitted ${fin.channel.emitted}, collector received ${state.received}` });
        }
      };
      check("boundary", this.boundaryStream);
      check("app", this.appStream);
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
