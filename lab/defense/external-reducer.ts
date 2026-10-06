/**
 * Field qualification: the EXTERNAL lane of the collector. External requests (a REMOTE peer; the plane minted the nonce) have no harness
 * registration, so the Slice-1/2/3 rule "every plane event must belong to a request the harness SENT" cannot apply to them. This reducer
 * gives them their own lifecycle, bounded in memory, without weakening any rule:
 *
 *   - exact COUNTERS are derived from the correlated, sequence-numbered event streams (never from a process's self-reported counters);
 *   - per-request state is TRANSIENT: it lives from INGRESS_ACCEPTED until the plane and the downstream hops have terminated (or a grace
 *     elapsed), is validated with the SAME validators a protected request gets, then reduced to counters and dropped;
 *   - what is retained is bounded and explicit: every L2 decision tuple (the bucket replay needs all of them, capped at the hard request
 *     ceiling), a capped set of traces (every anomaly, every mutation, the first few of each shed kind, a head sample), and a ring of
 *     recently closed nonces so a late event is flagged instead of silently re-opening a request.
 *
 * Nothing that was fatal stays quiet: a Boundary or App event no plane ingress ever claims (a bypass), a plane that never terminates a
 * request, a lifecycle the validators reject, a sequence gap (the collector's own check) and every cap overflow are all anomalies.
 *
 * Downstream events (Boundary, App) arrive on their own IPC pipes and may beat the plane's INGRESS_ACCEPTED here: they wait in a bounded
 * orphan table and are claimed when the ingress arrives; an orphan that is never claimed is an anomaly (or, for a refusal, an anonymous
 * count, exactly as the unreduced collector treats a refusal it cannot attribute).
 */
import {
  terminalOutcomeL2, validateLifecycle,
  type Anomaly, type AnomalyCode, type AppEvent, type BoundaryEvent, type LifecycleView, type OriginEvent, type PlaneEvent,
} from "../../defense/core/ledger";
import { validateL2Lifecycle } from "../../defense/core/l2-lifecycle";
import { validateOriginLineage } from "../../defense/core/lineage";
import type { LaneDecision } from "../../defense/core/lanes";
import { realDecision } from "./lane-accounting";

export type ExternalLimits = {
  /** Requests whose lifecycle is still open. */
  maxActive: number;
  /** Nonces with downstream events but no plane ingress yet. */
  maxOrphans: number;
  /** Recently closed nonces remembered so a late event is flagged. */
  recentRing: number;
  /** Retained full traces. */
  maxTraces: number;
  /** Retained L2 decision events (the bucket replay needs all of them). */
  maxDecisions: number;
  /** Traces kept unconditionally from the start, and per shed/error kind. */
  headTraces: number;
  perKindTraces: number;
  /** How long after the plane's terminal event the downstream hops may take to report before the request is reduced as it stands. */
  downstreamGraceMs: number;
  /** How long a downstream event may wait for its plane ingress. */
  orphanGraceMs: number;
  /** Events kept per stream per request. */
  maxEventsPerStream: number;
};

export const DEFAULT_EXTERNAL_LIMITS: ExternalLimits = Object.freeze({
  maxActive: 1_024, maxOrphans: 1_024, recentRing: 4_096, maxTraces: 2_000, maxDecisions: 20_000, headTraces: 200, perKindTraces: 10,
  downstreamGraceMs: 5_000, orphanGraceMs: 10_000, maxEventsPerStream: 32,
});

/** The shed a workload expects: only a refusal by the L2 budget of this class and lane, with this reason, counts as an expected defense shed. */
export type AllowedShed = { class: string; lane: string; reason: string };

export type ExternalCounters = {
  accepted: number;
  strippedHeaders: number;
  reduced: number;
  terminal: Record<string, number>;
  l1: { entered: number; passed: number; rejected: number; shed: number; error: number };
  l1RejectedByReason: Record<string, number>;
  l2: { entered: number; decided: number; byKey: Record<string, number>; shedByReason: Record<string, number>; classes: Record<string, number> };
  egress: { attempted: number; responded: number; failed: number; failedByKind: Record<string, number>; /** Failures before the Boundary was ever contacted: canonicalization or proof signing. */ failedAtProof: number };
  proofsIssued: number;
  boundary: { arrived: number; admitted: number; rejected: number; appProofsIssued: number; relayed: number; forwardResponded: number; forwardFailed: number; responded: number; aborted: number };
  app: { admitted: number; refused: number; executed: number; mutated: number; completed: number; aborted: number };
  /** The plane's own response status to the remote client, exactly as the plane's INGRESS_RESPONDED recorded it. */
  statusHistogram: Record<string, number>;
  /** D6: a 503 is an expected defense shed ONLY when the server-side record proves it (see `attributeShed`). */
  status503: { total: number; expectedShed: number; unexplained: number; byCause: Record<string, number> };
  status5xxOther: number;
  clientAborted: number;
  mutatedByLane: Record<string, number>;
  traces: { retained: number; droppedByCap: number };
  decisions: { retained: number; droppedByCap: number };
  overflow: { active: number; orphans: number };
};

export type ExternalTrace = {
  rid: string;
  reason: string;
  plane: PlaneEvent[];
  boundary: BoundaryEvent[];
  app: AppEvent[];
};

type Active = {
  rid: string;
  nonce: string;
  plane: PlaneEvent[];
  boundary: BoundaryEvent[];
  app: AppEvent[];
  origin: OriginEvent[];
  openedAt: number;
  terminalAt: number | null;
};

type Orphan = { boundary: BoundaryEvent[]; app: AppEvent[]; firstAt: number };

const zero = (): ExternalCounters => ({
  accepted: 0, strippedHeaders: 0, reduced: 0, terminal: {},
  l1: { entered: 0, passed: 0, rejected: 0, shed: 0, error: 0 }, l1RejectedByReason: {},
  l2: { entered: 0, decided: 0, byKey: {}, shedByReason: {}, classes: {} },
  egress: { attempted: 0, responded: 0, failed: 0, failedByKind: {}, failedAtProof: 0 }, proofsIssued: 0,
  boundary: { arrived: 0, admitted: 0, rejected: 0, appProofsIssued: 0, relayed: 0, forwardResponded: 0, forwardFailed: 0, responded: 0, aborted: 0 },
  app: { admitted: 0, refused: 0, executed: 0, mutated: 0, completed: 0, aborted: 0 },
  statusHistogram: {}, status503: { total: 0, expectedShed: 0, unexplained: 0, byCause: {} }, status5xxOther: 0, clientAborted: 0, mutatedByLane: {},
  traces: { retained: 0, droppedByCap: 0 }, decisions: { retained: 0, droppedByCap: 0 }, overflow: { active: 0, orphans: 0 },
});

const bump = (table: Record<string, number>, key: string, by = 1): void => { table[key] = (table[key] ?? 0) + by; };

export type ReducerOptions = {
  limits?: Partial<ExternalLimits>;
  allowedShed: readonly AllowedShed[];
  /** A monotonic clock in ms (injected for tests). */
  now?: () => number;
  /** Reports one anomaly to the collector. `rid` is the request's evidence id (never the nonce) or null. */
  report: (code: AnomalyCode, rid: string | null, detail: string) => void;
};

/**
 * The cause of one 503 the plane sent a remote client, from the SERVER-SIDE record only. `expected` is true only for an L2 decision with
 * outcome `shed`, an allowed (class, lane, reason), and no egress attempt: a refusal the plane made locally and the Boundary never saw.
 * Anything else (an L1 shed or error, an L2 saturation or error, a 503 proxied from downstream) is `unexplained`.
 */
export function attributeShed(plane: readonly PlaneEvent[], allowed: readonly AllowedShed[]): { expected: boolean; cause: string } {
  if (plane.some((event) => event.kind === "L1_SHED")) return { expected: false, cause: "l1_shed" };
  if (plane.some((event) => event.kind === "L1_ERROR")) return { expected: false, cause: "l1_error" };
  const decided = plane.find((event) => event.kind === "L2_DECIDED");
  const attempted = plane.some((event) => event.kind === "EGRESS_ATTEMPTED");
  if (decided) {
    const real = realDecision(decided);
    if (decided.basis === "simulated") return { expected: false, cause: "l2_simulated" };
    if (real.outcome === "shed") {
      const reason = decided.shedReason ?? "none";
      const match = allowed.some((entry) => entry.class === decided.class && entry.lane === real.lane && entry.reason === reason);
      if (attempted) return { expected: false, cause: "l2_shed_with_egress" };
      return match ? { expected: true, cause: `l2_shed_${real.lane}_${reason}` } : { expected: false, cause: `l2_shed_other_${real.lane}_${reason}` };
    }
    if (real.outcome === "error") return { expected: false, cause: "l2_error" };
  }
  if (attempted) return { expected: false, cause: "proxied_503" };
  return { expected: false, cause: "other" };
}

export class ExternalReducer {
  private readonly limits: ExternalLimits;
  private readonly now: () => number;
  private readonly active = new Map<string, Active>();
  private readonly orphans = new Map<string, Orphan>();
  private readonly recent = new Set<string>();
  private readonly recentOrder: string[] = [];
  private readonly counterState: ExternalCounters = zero();
  private readonly traceList: ExternalTrace[] = [];
  private readonly decisionList: PlaneEvent[] = [];
  private readonly firstOfKind = new Map<string, number>();
  private headCount = 0;
  private nextRid = 1;
  private readonly refusalsAnonymous: Record<string, number> = {};
  private finalized = false;

  constructor(private readonly options: ReducerOptions) {
    this.limits = { ...DEFAULT_EXTERNAL_LIMITS, ...(options.limits ?? {}) };
    this.now = options.now ?? (() => performance.now());
  }

  // ---- ownership

  owns(nonce: string): boolean { return this.active.has(nonce); }
  /** True when the nonce was an external request that has already been reduced. */
  wasClosed(nonce: string): boolean { return this.recent.has(nonce); }
  get activeCount(): number { return this.active.size; }
  /** Recently closed nonces currently remembered (bounded by `recentRing`). */
  get recentCount(): number { return this.recent.size; }
  get orphanCount(): number { return this.orphans.size; }

  // ---- plane stream

  /**
   * Opens a request from its INGRESS_ACCEPTED (the only event that may), or appends to one already open. Returns false when the event was
   * not consumed (an event of an unknown external nonce): the collector then treats it as it always did.
   */
  ingestPlane(event: PlaneEvent): boolean {
    const nonce = event.nonce;
    if (nonce === null) return false;
    if (event.kind === "INGRESS_ACCEPTED" && event.ingress === "external") {
      if (this.active.has(nonce) || this.recent.has(nonce)) { this.options.report("external_duplicate_nonce", this.active.get(nonce)?.rid ?? null, "INGRESS_ACCEPTED"); return true; }
      if (this.active.size >= this.limits.maxActive) {
        this.counterState.overflow.active++;
        this.options.report("external_state_overflow", null, `active requests ${this.limits.maxActive}`);
        return true;
      }
      const record: Active = { rid: `x${this.nextRid++}`, nonce, plane: [event], boundary: [], app: [], origin: [], openedAt: this.now(), terminalAt: null };
      this.active.set(nonce, record);
      this.counterState.accepted++;
      this.counterState.strippedHeaders += event.stripped ?? 0;
      const orphan = this.orphans.get(nonce);
      if (orphan) {
        this.orphans.delete(nonce);
        for (const held of orphan.boundary) this.append(record, "boundary", held);
        for (const held of orphan.app) this.append(record, "app", held);
      }
      return true;
    }
    const record = this.active.get(nonce);
    if (!record) {
      if (this.recent.has(nonce)) { this.options.report("external_late_event", null, event.kind); return true; }
      return false;
    }
    this.append(record, "plane", event);
    if ((event.kind === "INGRESS_RESPONDED" || event.kind === "INGRESS_ABORTED") && record.terminalAt === null) record.terminalAt = this.now();
    this.tryComplete(record, false);
    return true;
  }

  // ---- downstream streams (Boundary, App)

  /** A Boundary event for a nonce. Held as an orphan when no plane ingress has claimed the nonce yet. Returns false when the reducer cannot hold it. */
  ingestBoundary(event: BoundaryEvent): boolean { return this.ingestDownstream(event.nonce, "boundary", event); }
  ingestApp(event: AppEvent): boolean { return this.ingestDownstream(event.nonce, "app", event); }

  private ingestDownstream(nonce: string | null, stream: "boundary" | "app", event: BoundaryEvent | AppEvent): boolean {
    if (nonce === null) return false;
    const record = this.active.get(nonce);
    if (record) {
      this.append(record, stream, event);
      this.tryComplete(record, false);
      return true;
    }
    if (this.recent.has(nonce)) { this.options.report("external_late_event", null, event.kind); return true; }
    const held = this.orphans.get(nonce);
    if (held) { (stream === "boundary" ? held.boundary : held.app).push(event as never); return true; }
    if (this.orphans.size >= this.limits.maxOrphans) {
      this.counterState.overflow.orphans++;
      this.options.report("external_state_overflow", null, `orphans ${this.limits.maxOrphans}`);
      return true;
    }
    this.orphans.set(nonce, { boundary: stream === "boundary" ? [event as BoundaryEvent] : [], app: stream === "app" ? [event as AppEvent] : [], firstAt: this.now() });
    return true;
  }

  private append(record: Active, stream: "plane" | "boundary" | "app", event: PlaneEvent | BoundaryEvent | AppEvent): void {
    const list = record[stream] as (PlaneEvent | BoundaryEvent | AppEvent)[];
    if (list.length >= this.limits.maxEventsPerStream) { this.options.report("ledger_capacity_exceeded", record.rid, `${stream} events per request`); return; }
    list.push(event);
    if (stream === "app") {
      // The same pure mapping the unreduced collector uses to derive the legacy origin events the Slice-1 validator reads.
      const app = event as AppEvent;
      if (app.kind === "APP_ADMITTED") record.origin.push({ instance: "protected", nonce: record.nonce, kind: "ORIGIN_RECEIVED", hop: app.hop ?? null, spoofed: app.spoofed ?? 0 });
      else if (app.kind === "APP_COMPLETED") record.origin.push({ instance: "protected", nonce: record.nonce, kind: "ORIGIN_COMPLETED", hop: app.hop ?? null, status: app.status });
      else if (app.kind === "APP_ABORTED") record.origin.push({ instance: "protected", nonce: record.nonce, kind: "ORIGIN_ABORTED", hop: app.hop ?? null });
    }
  }

  // ---- completion

  private downstreamSatisfied(record: Active): boolean {
    const attempted = record.plane.some((event) => event.kind === "EGRESS_ATTEMPTED");
    if (!attempted) return true;
    // A canonicalization or signing failure never reaches the Boundary.
    if (record.plane.some((event) => event.kind === "EGRESS_FAILED" && event.failStage !== undefined)) return true;
    // A refused connection never reached the Boundary: there is nothing downstream to wait for.
    if (record.plane.some((event) => event.kind === "EGRESS_FAILED" && event.egressError === "refused")) return true;
    const boundaryTerminal = record.boundary.some((event) => event.kind === "BOUNDARY_RESPONDED" || event.kind === "BOUNDARY_ABORTED");
    if (!boundaryTerminal) return false;
    if (!record.boundary.some((event) => event.kind === "BOUNDARY_FORWARD_RESPONDED")) return true;
    return record.app.some((event) => event.kind === "APP_COMPLETED" || event.kind === "APP_ABORTED" || event.kind === "APP_REFUSED");
  }

  private tryComplete(record: Active, final: boolean): void {
    if (record.terminalAt === null) return;
    if (this.downstreamSatisfied(record) || final || this.now() - record.terminalAt >= this.limits.downstreamGraceMs) this.reduce(record);
  }

  /** Reduces every request whose downstream grace has elapsed and flags orphans nobody claimed in time. Cheap: bounded by the caps. */
  sweep(): void {
    const now = this.now();
    for (const record of [...this.active.values()]) if (record.terminalAt !== null && now - record.terminalAt >= this.limits.downstreamGraceMs) this.reduce(record);
    for (const [nonce, orphan] of [...this.orphans.entries()]) {
      if (now - orphan.firstAt < this.limits.orphanGraceMs) continue;
      this.orphans.delete(nonce);
      this.reportOrphan(orphan);
    }
  }

  private reportOrphan(orphan: Orphan): void {
    const boundaryRefusal = orphan.boundary.length > 0 && orphan.app.length === 0
      && orphan.boundary.every((event) => event.kind === "BOUNDARY_ARRIVED" || event.kind === "BOUNDARY_REJECTED" || event.kind === "BOUNDARY_RESPONDED" || event.kind === "BOUNDARY_ABORTED")
      && orphan.boundary.some((event) => event.kind === "BOUNDARY_REJECTED");
    const appRefusal = orphan.boundary.length === 0 && orphan.app.length > 0 && orphan.app.every((event) => event.kind === "APP_REFUSED");
    const refusalOnly = boundaryRefusal || appRefusal;
    if (refusalOnly) { bump(this.refusalsAnonymous, "refused"); return; }
    this.options.report("external_unclaimed_downstream", null, [...orphan.boundary.map((event) => event.kind), ...orphan.app.map((event) => event.kind)].slice(0, 4).join(","));
  }

  // ---- reduction

  private reduce(record: Active): void {
    if (!this.active.delete(record.nonce)) return;
    const view: LifecycleView = { nonce: record.nonce, expected: "external", harness: [], plane: record.plane, origin: record.origin, boundary: record.boundary, app: record.app, l2: true };
    // The lineage validator is pinned byte for byte; an external request has exactly a protected request's chain, so it is judged as one.
    const lineageView: LifecycleView = { ...view, expected: "protected" };
    const found: Anomaly[] = [...validateLifecycle(view, true), ...validateOriginLineage(lineageView, true), ...validateL2Lifecycle(view, true)];
    for (const anomaly of found) this.options.report(anomaly.code, record.rid, anomaly.detail);
    const unresolved = record.terminalAt === null;
    if (unresolved) this.options.report("external_unresolved", record.rid, record.plane[record.plane.length - 1]?.kind ?? "none");
    this.count(record, found.length > 0 || unresolved);
    this.remember(record.nonce);
  }

  private remember(nonce: string): void {
    this.recent.add(nonce);
    this.recentOrder.push(nonce);
    while (this.recentOrder.length > this.limits.recentRing) this.recent.delete(this.recentOrder.shift() as string);
  }

  private count(record: Active, anomalous: boolean): void {
    const c = this.counterState;
    c.reduced++;
    const plane = record.plane;
    const kinds = new Set(plane.map((event) => event.kind));
    const first = (kind: string) => plane.find((event) => event.kind === kind);
    if (kinds.has("L1_ENTERED")) c.l1.entered++;
    if (kinds.has("L1_PASSED")) c.l1.passed++;
    if (kinds.has("L1_SHED")) c.l1.shed++;
    if (kinds.has("L1_ERROR")) c.l1.error++;
    const rejected = first("L1_REJECTED");
    if (rejected) { c.l1.rejected++; bump(c.l1RejectedByReason, rejected.reason ?? "unknown"); }
    if (kinds.has("L2_ENTERED")) c.l2.entered++;
    const decided = first("L2_DECIDED");
    if (decided) {
      c.l2.decided++;
      const real = realDecision(decided);
      bump(c.l2.byKey, `${decided.class}.${real.lane}.${real.outcome}`);
      bump(c.l2.classes, decided.class ?? "none");
      if (real.outcome === "shed") bump(c.l2.shedByReason, `${decided.class}.${real.lane}.${decided.shedReason ?? "none"}`);
      this.keepDecision(decided);
    }
    if (kinds.has("EGRESS_ATTEMPTED")) c.egress.attempted++;
    if (kinds.has("EGRESS_RESPONDED")) c.egress.responded++;
    const failed = first("EGRESS_FAILED");
    if (failed) { c.egress.failed++; bump(c.egress.failedByKind, failed.egressError ?? "unknown"); if (failed.failStage !== undefined) c.egress.failedAtProof++; }
    if (kinds.has("PROOF_ISSUED")) c.proofsIssued++;
    const outcome = terminalOutcomeL2(plane) ?? "unresolved";
    bump(c.terminal, outcome);
    if (outcome === "client_aborted") c.clientAborted++;
    const responded = first("INGRESS_RESPONDED");
    if (responded?.status !== undefined) {
      bump(c.statusHistogram, String(responded.status));
      if (responded.status === 503) {
        const attribution = attributeShed(plane, this.options.allowedShed);
        c.status503.total++;
        if (attribution.expected) c.status503.expectedShed++; else c.status503.unexplained++;
        bump(c.status503.byCause, attribution.cause);
      } else if (responded.status >= 500) c.status5xxOther++;
    }
    for (const event of record.boundary) {
      const b = c.boundary;
      if (event.kind === "BOUNDARY_ARRIVED") b.arrived++;
      else if (event.kind === "BOUNDARY_ADMITTED") b.admitted++;
      else if (event.kind === "BOUNDARY_REJECTED") b.rejected++;
      else if (event.kind === "APP_PROOF_ISSUED") b.appProofsIssued++;
      else if (event.kind === "BOUNDARY_FORWARDED") b.relayed++;
      else if (event.kind === "BOUNDARY_FORWARD_RESPONDED") b.forwardResponded++;
      else if (event.kind === "BOUNDARY_FORWARD_FAILED") b.forwardFailed++;
      else if (event.kind === "BOUNDARY_RESPONDED") b.responded++;
      else if (event.kind === "BOUNDARY_ABORTED") b.aborted++;
    }
    let mutated = false;
    for (const event of record.app) {
      const a = c.app;
      if (event.kind === "APP_ADMITTED") a.admitted++;
      else if (event.kind === "APP_REFUSED") a.refused++;
      else if (event.kind === "APP_EXECUTED") a.executed++;
      else if (event.kind === "APP_MUTATED") { a.mutated++; mutated = true; }
      else if (event.kind === "APP_COMPLETED") a.completed++;
      else if (event.kind === "APP_ABORTED") a.aborted++;
    }
    if (mutated) bump(c.mutatedByLane, decided ? realDecision(decided).lane : "none");
    this.keepTrace(record, anomalous, mutated, decided, outcome);
  }

  private keepDecision(event: PlaneEvent): void {
    if (this.decisionList.length >= this.limits.maxDecisions) { this.counterState.decisions.droppedByCap++; this.options.report("external_state_overflow", null, `decisions ${this.limits.maxDecisions}`); return; }
    this.decisionList.push(event);
    this.counterState.decisions.retained = this.decisionList.length;
  }

  private keepTrace(record: Active, anomalous: boolean, mutated: boolean, decided: PlaneEvent | undefined, outcome: string): void {
    const real = decided ? realDecision(decided) : null;
    const kind = `${outcome}.${real ? `${decided?.class}.${real.lane}.${real.outcome}` : "no_l2"}`;
    const seen = this.firstOfKind.get(kind) ?? 0;
    let reason: string | null = null;
    if (anomalous) reason = "anomaly";
    else if (mutated) reason = "mutation";
    else if (seen < this.limits.perKindTraces) reason = "first_of_kind";
    else if (this.headCount < this.limits.headTraces) reason = "head";
    if (seen < this.limits.perKindTraces) this.firstOfKind.set(kind, seen + 1);
    if (reason === null) return;
    if (reason === "head") this.headCount++;
    if (this.traceList.length >= this.limits.maxTraces) { this.counterState.traces.droppedByCap++; return; }
    this.traceList.push({ rid: record.rid, reason, plane: record.plane, boundary: record.boundary, app: record.app });
    this.counterState.traces.retained = this.traceList.length;
  }

  // ---- finalization and reads

  /** Reduces every request still open (an unresolved one is an anomaly) and flags every unclaimed orphan. Idempotent. */
  finalize(): void {
    if (this.finalized) return;
    this.finalized = true;
    for (const record of [...this.active.values()]) this.reduce(record);
    for (const orphan of [...this.orphans.values()]) this.reportOrphan(orphan);
    this.orphans.clear();
  }

  counters(): ExternalCounters {
    const c = this.counterState;
    return JSON.parse(JSON.stringify(c)) as ExternalCounters;
  }
  traces(): readonly ExternalTrace[] { return this.traceList; }
  /** Every L2 decision event of an external request: the input to the bucket replay. */
  decisions(): readonly PlaneEvent[] { return this.decisionList; }
  anonymousRefusals(): Record<string, number> { return { ...this.refusalsAnonymous }; }
  /** The decision of a plane L2 event as the lane module's value type (for callers that replay buckets). */
  static decisionOf(event: PlaneEvent): Pick<LaneDecision, "class" | "lane" | "outcome"> | null {
    return event.class === undefined || event.lane === undefined || event.outcome === undefined ? null : { class: event.class, lane: event.lane, outcome: event.outcome };
  }
}
