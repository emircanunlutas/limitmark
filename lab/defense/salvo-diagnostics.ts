/**
 * BA0 N2 salvo per-request DIAGNOSTICS (schema ba0-salvo-diagnostics-v1). Observation only.
 *
 * These structures are SIBLINGS of `salvo.pairs`: nothing here is read by `derivePairs`, `reconcileSalvo`, `SALVO_SPEC` or any qualification
 * identity, and nothing here reaches the Defense Plane. The server recorder subscribes to the plane event stream the collector already
 * receives (the same stream `SalvoServerObserver` consumes); it adds no event, no header, no timer, no I/O and no await. All state is bounded by
 * `SALVO_DIAGNOSTIC_LIMITS`. A request is identified by its arrival ordinal and the plane's own event sequence numbers, never by its nonce.
 *
 * What an observation is NOT: the server timestamps are the plane's ingress-accepted and response-terminal events, i.e. when the plane's HTTP
 * layer parsed the request and when it finished the response. They are not the instant a packet reached the NIC, and the server cannot see
 * which generator pair/slot a request belongs to. The pair index and slot recorded here are derived from the arrival ordinal exactly as the
 * existing `salvo.pairs` records are.
 */
import type { PlaneEvent } from "../../defense/core/ledger";
import { SALVO_SPEC } from "./salvo-spec";

export const SALVO_DIAGNOSTICS_SCHEMA = "ba0-salvo-diagnostics-v1" as const;

export const SALVO_DIAGNOSTIC_LIMITS = Object.freeze({
  /** One observation per request of the reviewed level; the 1,501st external ingress is counted in `overflow` and not stored. */
  maxRequests: SALVO_SPEC.pairs * SALVO_SPEC.requestsPerPair,
  /** Worst-case pretty-printed JSON size of one server observation / one generator observation (a test pins both against real worst cases). */
  serverRecordJsonBytes: 640,
  generatorRecordJsonBytes: 300,
  /** Accounting estimate of one live record (object, strings, flags array) and one nonce-index entry. Estimates, not heap proofs. */
  recordMemoryBytes: 512,
  nonceIndexBytes: 128,
});

// ---- bounded vocabularies. Kept local so the strict parser needs no runtime import of the defense core; a test pins them against it.
export const DIAG_CLASSES = ["open", "mutation", "unknown"] as const;
export const DIAG_L1 = ["passed", "rejected", "shed", "error", "none"] as const;
export const DIAG_L2 = ["admitted", "shed", "error", "degraded", "none"] as const;
export const DIAG_LANES = ["open", "credited", "unverified", "none"] as const;
export const DIAG_SHED = ["lane_budget", "evaluator_saturation", "none"] as const;
export const DIAG_FINAL = ["responded", "aborted", "pending"] as const;
/** dup_id: the plane-minted correlation key was seen twice. dup_event: a one-per-request event repeated. seq_order/time_order: a request's own
 *  events were not strictly increasing in sequence / not non-decreasing in time. late_event: a recorded kind arrived after the terminal event. */
export const DIAG_FLAGS = ["dup_id", "dup_event", "seq_order", "time_order", "late_event"] as const;

export type DiagClass = (typeof DIAG_CLASSES)[number];
export type DiagL1 = (typeof DIAG_L1)[number];
export type DiagL2 = (typeof DIAG_L2)[number];
export type DiagLane = (typeof DIAG_LANES)[number];
export type DiagShed = (typeof DIAG_SHED)[number];
export type DiagFinal = (typeof DIAG_FINAL)[number];
export type DiagFlag = (typeof DIAG_FLAGS)[number];

export type SalvoServerObservation = {
  /** Evidence id of the request: `x` plus (ordinal + 1). Equal to the external reducer's trace id while no duplicate or overflow occurred. */
  rid: string;
  /** Zero-based arrival ordinal among external ingress events (the same counter that defines `salvo.pairs`). */
  ord: number;
  pair: number;
  /** Arrival slot: ord modulo 2. This is INGRESS OBSERVATION order, not the generator's dispatch slot. */
  slot: 0 | 1;
  /** Operation class the plane decided (from L2_DECIDED); `unknown` also when the request never reached L2. */
  cls: DiagClass;
  l1: DiagL1;
  l2: DiagL2;
  lane: DiagLane;
  shed: DiagShed;
  /** An EGRESS_ATTEMPTED event was observed for this request. */
  egress: boolean;
  fin: DiagFinal;
  status: number | null;
  /** The plane's global event sequence numbers of the request's INGRESS_ACCEPTED and terminal events. */
  inSeq: number;
  outSeq: number | null;
  /** Plane monotonic milliseconds relative to the first external ingress event (the origin the pair records use). */
  inMs: number;
  outMs: number | null;
  flags: DiagFlag[];
};

export const SERVER_COUNTER_KEYS = ["observed", "recorded", "overflow", "duplicateIds", "duplicateEvents", "orderViolations", "ambiguousEvents",
  "unattributedEvents", "simulatedDecisions", "faults"] as const;
export type ServerDiagnosticCounters = Record<(typeof SERVER_COUNTER_KEYS)[number], number>;

export const SERVER_PROVENANCE = Object.freeze({
  clock: "plane.monotonic", unit: "ms", zero: "first.external.ingress", seq: "plane.event.seq", order: "arrival.ordinal", source: "plane.events.only",
});
export const GENERATOR_PROVENANCE = Object.freeze({
  clock: "generator.monotonic", unit: "ms", zero: "salvo.scheduler.start", start: "scheduler.before.send", handoff: "http.request.finish", settled: "send.promise.settled",
});

export type ServerSalvoDiagnostics = {
  schema: typeof SALVO_DIAGNOSTICS_SCHEMA;
  side: "server";
  provenance: typeof SERVER_PROVENANCE;
  capacity: { maxRequests: number };
  counters: ServerDiagnosticCounters;
  requests: SalvoServerObservation[];
};

export type GeneratorSalvoObservation = {
  pair: number;
  /** The scheduler's DISPATCH slot: 0 is the first send of the pair, 1 the second. Even pairs: two reads. Odd pairs: slot 1 is the mutation. */
  slot: 0 | 1;
  /** Logical start: taken immediately before the sender is invoked. It precedes socket assignment and any transmission. */
  startMs: number;
  /** Node `finish` event of the request: its final bytes were handed to the OS for transmission. null when never observed. NOT receipt. */
  handoffMs: number | null;
  /** The scheduler observed the sender's promise settle. null while unsettled (aborted/partial campaigns). */
  settledMs: number | null;
  status: number | null;
};

export type GeneratorSalvoDiagnostics = {
  schema: typeof SALVO_DIAGNOSTICS_SCHEMA;
  side: "generator";
  provenance: typeof GENERATOR_PROVENANCE;
  capacity: { maxRequests: number };
  requests: GeneratorSalvoObservation[];
};

type Item = { obs: SalvoServerObservation; lastSeq: number; lastT: number };

const ONE_PER_REQUEST: ReadonlySet<PlaneEvent["kind"]> = new Set(["L1_PASSED", "L1_REJECTED", "L1_SHED", "L1_ERROR", "L2_DECIDED", "EGRESS_ATTEMPTED", "INGRESS_RESPONDED", "INGRESS_ABORTED"]);
const L1_OF: Readonly<Record<string, DiagL1>> = { L1_PASSED: "passed", L1_REJECTED: "rejected", L1_SHED: "shed", L1_ERROR: "error" };

/** Records one bounded observation per external request from the plane event stream. Never throws, never blocks, never retains a nonce longer than the run. */
export class SalvoRequestRecorder {
  private readonly items: Item[] = [];
  private readonly byNonce = new Map<string, number>();
  private origin: number | null = null;
  private ordinal = 0;
  private overflow = 0;
  private duplicateIds = 0;
  private duplicateEvents = 0;
  private orderViolations = 0;
  private ambiguousEvents = 0;
  private unattributedEvents = 0;
  private simulatedDecisions = 0;
  private faults = 0;

  observe(event: PlaneEvent): void {
    try { this.record(event); } catch { this.faults++; }
  }

  private record(event: PlaneEvent): void {
    const nonce = event.nonce;
    if (nonce === null) return;
    if (event.kind === "INGRESS_ACCEPTED") { if (event.ingress === "external") this.ingress(event, nonce); return; }
    const index = this.byNonce.get(nonce);
    // Canary (protected-lane) events also pass through this stream; they are not external requests and are only counted.
    if (index === undefined) { this.unattributedEvents++; return; }
    const item = this.items[index];
    // A reused key cannot be attributed to one request. Never fabricate an association: count the event and attach it to nothing.
    if (item.obs.flags.includes("dup_id")) { this.ambiguousEvents++; return; }
    this.attach(item, event);
  }

  private ingress(event: PlaneEvent, nonce: string): void {
    this.origin ??= event.t;
    const ord = this.ordinal++;
    if (ord >= SALVO_DIAGNOSTIC_LIMITS.maxRequests) { this.overflow++; return; }
    const flags: DiagFlag[] = [];
    const prior = this.byNonce.get(nonce);
    if (prior === undefined) this.byNonce.set(nonce, ord);
    else {
      flags.push("dup_id"); this.duplicateIds++;
      const first = this.items[prior].obs;
      if (!first.flags.includes("dup_id")) first.flags.push("dup_id");
    }
    this.items.push({
      lastSeq: event.seq, lastT: event.t,
      obs: { rid: `x${ord + 1}`, ord, pair: Math.floor(ord / 2), slot: (ord % 2) as 0 | 1, cls: "unknown", l1: "none", l2: "none", lane: "none", shed: "none",
        egress: false, fin: "pending", status: null, inSeq: event.seq, outSeq: null, inMs: event.t - this.origin, outMs: null, flags },
    });
  }

  private attach(item: Item, event: PlaneEvent): void {
    const o = item.obs;
    const flag = (name: DiagFlag) => { if (!o.flags.includes(name)) { o.flags.push(name); if (name === "dup_event") this.duplicateEvents++; else this.orderViolations++; } };
    if (event.seq <= item.lastSeq) flag("seq_order");
    if (event.t < item.lastT) flag("time_order");
    item.lastSeq = Math.max(item.lastSeq, event.seq); item.lastT = Math.max(item.lastT, event.t);
    if (!ONE_PER_REQUEST.has(event.kind)) return;
    if (o.fin !== "pending") { flag("late_event"); return; }
    switch (event.kind) {
      case "L1_PASSED": case "L1_REJECTED": case "L1_SHED": case "L1_ERROR":
        if (o.l1 !== "none") flag("dup_event"); else o.l1 = L1_OF[event.kind];
        break;
      case "L2_DECIDED":
        if (o.l2 !== "none") { flag("dup_event"); break; }
        o.cls = event.class ?? "unknown"; o.l2 = event.outcome ?? "none"; o.lane = event.lane ?? "none"; o.shed = event.shedReason ?? "none";
        if (event.basis === "simulated") this.simulatedDecisions++;
        break;
      case "EGRESS_ATTEMPTED":
        if (o.egress) flag("dup_event"); else o.egress = true;
        break;
      case "INGRESS_RESPONDED": case "INGRESS_ABORTED":
        o.fin = event.kind === "INGRESS_RESPONDED" ? "responded" : "aborted";
        o.status = event.kind === "INGRESS_RESPONDED" && Number.isInteger(event.status) ? event.status! : null;
        o.outSeq = event.seq; o.outMs = event.t - this.origin!;
        break;
      default: break;
    }
  }

  snapshot(): ServerSalvoDiagnostics {
    const counters: ServerDiagnosticCounters = {
      observed: this.ordinal, recorded: this.items.length, overflow: this.overflow, duplicateIds: this.duplicateIds, duplicateEvents: this.duplicateEvents,
      orderViolations: this.orderViolations, ambiguousEvents: this.ambiguousEvents, unattributedEvents: this.unattributedEvents,
      simulatedDecisions: this.simulatedDecisions, faults: this.faults,
    };
    return {
      schema: SALVO_DIAGNOSTICS_SCHEMA, side: "server", provenance: SERVER_PROVENANCE, capacity: { maxRequests: SALVO_DIAGNOSTIC_LIMITS.maxRequests },
      counters, requests: this.items.map(({ obs }) => ({ ...obs, flags: [...obs.flags] })),
    };
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------------
// Strict parsers. The offline check never trusts a half-valid structure: it is either exactly this schema or it is reported malformed.
// ---------------------------------------------------------------------------------------------------------------------------------------
export type Parsed<T> = { ok: true; value: T } | { ok: false; reason: string };

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const sameKeys = (v: Record<string, unknown>, keys: readonly string[]) => { const k = Object.keys(v); return k.length === keys.length && keys.every((key) => Object.hasOwn(v, key)); };
const num = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v) && v >= 0;
const int = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const oneOf = <T extends string>(list: readonly T[], v: unknown): v is T => typeof v === "string" && (list as readonly string[]).includes(v);
const statusOk = (v: unknown) => v === null || (typeof v === "number" && Number.isInteger(v) && v >= 100 && v <= 599);
const sameObject = (a: unknown, b: Record<string, string>) => isObject(a) && sameKeys(a, Object.keys(b)) && Object.entries(b).every(([k, v]) => a[k] === v);

const SERVER_KEYS = ["rid", "ord", "pair", "slot", "cls", "l1", "l2", "lane", "shed", "egress", "fin", "status", "inSeq", "outSeq", "inMs", "outMs", "flags"] as const;
const GENERATOR_KEYS = ["pair", "slot", "startMs", "handoffMs", "settledMs", "status"] as const;

export function parseServerDiagnostics(value: unknown): Parsed<ServerSalvoDiagnostics> {
  const bad = (reason: string): Parsed<ServerSalvoDiagnostics> => ({ ok: false, reason });
  if (!isObject(value) || !sameKeys(value, ["schema", "side", "provenance", "capacity", "counters", "requests"])) return bad("top_level_keys");
  if (value.schema !== SALVO_DIAGNOSTICS_SCHEMA || value.side !== "server") return bad("schema");
  if (!sameObject(value.provenance, SERVER_PROVENANCE)) return bad("provenance");
  if (!isObject(value.capacity) || !sameKeys(value.capacity, ["maxRequests"]) || value.capacity.maxRequests !== SALVO_DIAGNOSTIC_LIMITS.maxRequests) return bad("capacity");
  const counters = value.counters;
  if (!isObject(counters) || !sameKeys(counters, SERVER_COUNTER_KEYS) || !SERVER_COUNTER_KEYS.every((k) => int(counters[k]))) return bad("counters");
  const requests = value.requests;
  if (!Array.isArray(requests) || requests.length > SALVO_DIAGNOSTIC_LIMITS.maxRequests) return bad("requests");
  for (let i = 0; i < requests.length; i++) {
    const r = requests[i] as unknown;
    if (!isObject(r) || !sameKeys(r, SERVER_KEYS)) return bad(`record_${i}_keys`);
    const fin = r.fin;
    const ok = r.ord === i && r.pair === Math.floor(i / 2) && r.slot === i % 2 && r.rid === `x${i + 1}`
      && oneOf(DIAG_CLASSES, r.cls) && oneOf(DIAG_L1, r.l1) && oneOf(DIAG_L2, r.l2) && oneOf(DIAG_LANES, r.lane) && oneOf(DIAG_SHED, r.shed)
      && typeof r.egress === "boolean" && oneOf(DIAG_FINAL, fin) && statusOk(r.status) && int(r.inSeq) && num(r.inMs)
      && Array.isArray(r.flags) && r.flags.length <= DIAG_FLAGS.length && r.flags.every((f) => oneOf(DIAG_FLAGS, f))
      && (fin === "pending" ? r.outSeq === null && r.outMs === null && r.status === null
        : int(r.outSeq) && num(r.outMs) && (fin === "aborted" ? r.status === null : r.status !== null));
    if (!ok) return bad(`record_${i}_values`);
  }
  return { ok: true, value: value as unknown as ServerSalvoDiagnostics };
}

export function parseGeneratorDiagnostics(value: unknown): Parsed<GeneratorSalvoDiagnostics> {
  const bad = (reason: string): Parsed<GeneratorSalvoDiagnostics> => ({ ok: false, reason });
  if (!isObject(value) || !sameKeys(value, ["schema", "side", "provenance", "capacity", "requests"])) return bad("top_level_keys");
  if (value.schema !== SALVO_DIAGNOSTICS_SCHEMA || value.side !== "generator") return bad("schema");
  if (!sameObject(value.provenance, GENERATOR_PROVENANCE)) return bad("provenance");
  if (!isObject(value.capacity) || !sameKeys(value.capacity, ["maxRequests"]) || value.capacity.maxRequests !== SALVO_DIAGNOSTIC_LIMITS.maxRequests) return bad("capacity");
  const requests = value.requests;
  if (!Array.isArray(requests) || requests.length > SALVO_DIAGNOSTIC_LIMITS.maxRequests) return bad("requests");
  const seen = new Set<number>();
  for (let i = 0; i < requests.length; i++) {
    const r = requests[i] as unknown;
    if (!isObject(r) || !sameKeys(r, GENERATOR_KEYS)) return bad(`record_${i}_keys`);
    const key = (r.pair as number) * 2 + (r.slot as number);
    if (!(int(r.pair) && r.pair < SALVO_SPEC.pairs && (r.slot === 0 || r.slot === 1) && num(r.startMs) && (r.handoffMs === null || num(r.handoffMs))
      && (r.settledMs === null || num(r.settledMs)) && statusOk(r.status)) || seen.has(key)) return bad(`record_${i}_values`);
    seen.add(key);
  }
  return { ok: true, value: value as unknown as GeneratorSalvoDiagnostics };
}
