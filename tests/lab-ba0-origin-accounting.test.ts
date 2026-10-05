import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ORACLE_HOP_BASE, validateLifecycle, type AnomalyCode, type AppEvent, type AppEventKind, type BoundaryEvent, type BoundaryEventKind, type ExpectedLane, type HarnessEvent,
  type LifecycleView, type OriginEvent, type PlaneEvent, type PlaneEventKind,
} from "../defense/core/ledger";
import { protectedLineageComplete, validateOriginLineage } from "../defense/core/lineage";
import { OB_REASONS } from "../defense/core/types";
import type { AppCounters } from "../defense/origin/synthetic-origin";
import { Collector, DEFAULT_COLLECTOR_LIMITS, type AppFin, type BoundaryFin, type LedgerRecord, type RequestMeta } from "../lab/defense/collector";
import type { JourneyResult } from "../lab/defense/canary";
import { deriveOriginAccounting, type OriginAccountingInput } from "../lab/defense/origin-accounting";
import { BA0_ORIGIN_LOCAL_V1, ba0OriginFingerprint, decideOriginVerdict, type OriginVerdictInput } from "../lab/defense/origin-thresholds";
import type { ChannelStats } from "../defense/core/ledger";

// ---------------------------------------------------------------------------
// Event builders
// ---------------------------------------------------------------------------

let seq = 0;
const PB = "pbtag0000000000a";
const BA = "batag0000000000a";
const pe = (kind: PlaneEventKind, extra: Partial<PlaneEvent> = {}): PlaneEvent => ({ seq: ++seq, nonce: "n", kind, t: 0, ...extra });
const be = (kind: BoundaryEventKind, extra: Partial<BoundaryEvent> = {}): BoundaryEvent => ({ seq: ++seq, nonce: "n", kind, t: 0, ...extra });
const ae = (kind: AppEventKind, extra: Partial<AppEvent> = {}): AppEvent => ({ seq: ++seq, nonce: "n", kind, t: 0, ...extra });
const harness = (status = 200): HarnessEvent[] => [{ kind: "SENT" }, { kind: "CLIENT_COMPLETED", result: "response", status, outcomeHeader: "proxied" }];

type Chain = { plane: PlaneEvent[]; boundary: BoundaryEvent[]; app: AppEvent[] };
/** A clean protected request: plane -> proof -> boundary admit -> BA -> app admit -> execute [-> mutate] -> complete. */
function cleanProtected(options: { mutate?: boolean; pb?: string; ba?: string } = {}): Chain {
  const pb = options.pb ?? PB; const ba = options.ba ?? BA;
  const plane = [pe("INGRESS_ACCEPTED", { stripped: 0 }), pe("L1_ENTERED"), pe("L1_PASSED")];
  const attempted = pe("EGRESS_ATTEMPTED");
  plane.push(attempted, pe("PROOF_ISSUED", { pbTag: pb }));
  const hop = attempted.seq;
  const boundary = [be("BOUNDARY_ARRIVED"), be("BOUNDARY_ADMITTED", { hop, pbTag: pb }), be("APP_PROOF_ISSUED", { hop, pbTag: pb, baTag: ba }), be("BOUNDARY_FORWARDED", { hop, pbTag: pb, baTag: ba }), be("BOUNDARY_FORWARD_RESPONDED", { status: 200 }), be("BOUNDARY_RESPONDED", { status: 200 })];
  const app = [ae("APP_ADMITTED", { hop, pbTag: pb, baTag: ba, spoofed: 0 }), ae("APP_EXECUTED", { hop, pbTag: pb, baTag: ba })];
  if (options.mutate) app.push(ae("APP_MUTATED", { hop, pbTag: pb, baTag: ba }));
  app.push(ae("APP_COMPLETED", { hop, pbTag: pb, baTag: ba, status: 200 }));
  plane.push(pe("EGRESS_RESPONDED", { status: 200 }), pe("INGRESS_RESPONDED", { status: 200 }));
  return { plane, boundary, app };
}

const origins = (app: AppEvent[]): OriginEvent[] => app.flatMap((event): OriginEvent[] => event.kind === "APP_ADMITTED" ? [{ instance: "protected", nonce: "n", kind: "ORIGIN_RECEIVED", hop: event.hop ?? null, spoofed: event.spoofed ?? 0 }]
    : event.kind === "APP_COMPLETED" ? [{ instance: "protected", nonce: "n", kind: "ORIGIN_COMPLETED", hop: event.hop ?? null, status: event.status }] : []);
const view = (expected: ExpectedLane, chain: Partial<Chain>, overrides: Partial<LifecycleView> = {}): LifecycleView => ({
  nonce: "n", expected, harness: harness(), plane: chain.plane ?? [], origin: origins(chain.app ?? []), boundary: chain.boundary ?? [], app: chain.app ?? [], ...overrides,
});
const lineageCodes = (v: LifecycleView): AnomalyCode[] => [...new Set(validateOriginLineage(v, true).map((anomaly) => anomaly.code))].sort();
const allCodes = (v: LifecycleView): AnomalyCode[] => [...new Set([...validateLifecycle(v, true), ...validateOriginLineage(v, true)].map((anomaly) => anomaly.code))].sort();

// ---------------------------------------------------------------------------
// Lineage: every way the chain can be wrong is an anomaly
// ---------------------------------------------------------------------------

test("a complete protected lineage, with or without a mutation, has no anomaly and counts as complete", () => {
  for (const mutate of [false, true]) {
    const chain = cleanProtected({ mutate });
    assert.deepEqual(allCodes(view("protected", chain)), [], `mutate=${mutate}`);
    assert.equal(protectedLineageComplete(view("protected", chain)), true);
  }
});

test("a Slice-1 view (no boundary or app streams) is untouched by the lineage rules", () => {
  assert.deepEqual(validateOriginLineage({ nonce: "n", expected: "protected", harness: harness(), plane: [], origin: [] }, true), []);
});

test("an application admission, execution or mutation WITHOUT the full lineage is an anomaly, whichever link is missing", () => {
  const without = (drop: (chain: Chain) => Chain) => drop(cleanProtected({ mutate: true }));
  const cases: [string, Chain, AnomalyCode[]][] = [
    ["no boundary admission", without((c) => ({ ...c, boundary: c.boundary.filter((event) => event.kind !== "BOUNDARY_ADMITTED") })), ["app_admit_without_lineage", "app_execution_without_lineage", "app_mutation_without_lineage"]],
    ["no app proof issued", without((c) => ({ ...c, boundary: c.boundary.filter((event) => event.kind !== "APP_PROOF_ISSUED") })), ["app_admit_without_lineage", "app_execution_without_lineage", "app_mutation_without_lineage"]],
    ["no plane proof", without((c) => ({ ...c, plane: c.plane.filter((event) => event.kind !== "PROOF_ISSUED") })), ["app_admit_without_lineage", "app_execution_without_lineage", "app_mutation_without_lineage"]],
    ["the BA tag differs between boundary and app", without((c) => ({ ...c, app: c.app.map((event) => (event.baTag ? { ...event, baTag: "other00000000000" } : event)) })), ["app_admit_without_lineage", "app_execution_without_lineage", "app_mutation_without_lineage"]],
    ["the app saw a different PB tag", without((c) => ({ ...c, app: c.app.map((event) => (event.pbTag ? { ...event, pbTag: "other00000000000" } : event)) })), ["app_admit_without_lineage", "app_execution_without_lineage", "app_mutation_without_lineage"]],
    ["the app saw a different hop", without((c) => ({ ...c, app: c.app.map((event) => (event.hop ? { ...event, hop: event.hop + 100 } : event)) })), ["app_admit_without_lineage", "app_execution_without_lineage", "app_mutation_without_lineage"]],
  ];
  for (const [label, chain, expected] of cases) {
    const codes = lineageCodes(view("protected", chain));
    for (const code of expected) assert.ok(codes.includes(code), `${label}: ${code} in ${codes.join(",")}`);
    assert.equal(protectedLineageComplete(view("protected", chain)), false, label);
  }
  const executeOnly = cleanProtected();
  executeOnly.app = executeOnly.app.filter((event) => event.kind !== "APP_ADMITTED");
  assert.ok(lineageCodes(view("protected", executeOnly)).includes("app_execution_without_lineage"), "an execution with no admission");
  const mutateOnly = cleanProtected({ mutate: true });
  mutateOnly.app = mutateOnly.app.filter((event) => event.kind !== "APP_EXECUTED");
  assert.ok(lineageCodes(view("protected", mutateOnly)).includes("app_mutation_without_lineage"), "a mutation with no execution");
});

test("the boundary side of the chain is checked against what the plane really issued", () => {
  const rejected = cleanProtected();
  rejected.boundary = [be("BOUNDARY_ARRIVED"), be("BOUNDARY_REJECTED", { reason: "ob.signature_invalid" }), be("BOUNDARY_RESPONDED", { status: 403 })];
  rejected.app = [];
  assert.ok(lineageCodes(view("protected", rejected)).includes("boundary_rejected_plane_egress"));
  const mismatched = cleanProtected();
  mismatched.boundary = mismatched.boundary.map((event) => (event.kind === "BOUNDARY_ADMITTED" ? { ...event, pbTag: "other00000000000" } : event));
  assert.ok(lineageCodes(view("protected", mismatched)).includes("boundary_hop_mismatch"));
  const unadmitted = cleanProtected();
  unadmitted.boundary = []; unadmitted.app = [];
  assert.ok(lineageCodes(view("protected", unadmitted)).includes("plane_egress_not_admitted"));
  const unsigned = cleanProtected();
  unsigned.plane = unsigned.plane.filter((event) => event.kind !== "PROOF_ISSUED");
  assert.ok(lineageCodes(view("protected", unsigned)).includes("missing_transition"), "an egress attempt with neither a proof nor a failure");
  const refused = cleanProtected();
  refused.app = [ae("APP_REFUSED", { reason: "ob.lineage_mismatch" })];
  assert.ok(lineageCodes(view("protected", refused)).includes("app_refused_boundary_admitted"));
  const undecided = cleanProtected();
  undecided.boundary = [be("BOUNDARY_ARRIVED")]; undecided.app = [];
  assert.ok(lineageCodes(view("protected", undecided)).includes("boundary_decision_missing"));
  const noTerminal = cleanProtected();
  noTerminal.boundary = noTerminal.boundary.slice(0, -1);
  assert.ok(lineageCodes(view("protected", noTerminal)).includes("unresolved_at_finalization"));
  const unresolvedApp = cleanProtected();
  unresolvedApp.app = unresolvedApp.app.slice(0, -1);
  assert.ok(lineageCodes(view("protected", unresolvedApp)).includes("unresolved_at_finalization"));
  const statusMismatch = cleanProtected();
  statusMismatch.app = statusMismatch.app.map((event) => (event.kind === "APP_COMPLETED" ? { ...event, status: 500 } : event));
  assert.ok(lineageCodes(view("protected", statusMismatch)).includes("origin_status_mismatch"));
});

test("each hop stream is its own automaton: duplicates, reordering and a second terminal are anomalies", () => {
  const dupBoundary = cleanProtected();
  dupBoundary.boundary.push(be("BOUNDARY_RESPONDED", { status: 200 }));
  assert.ok(lineageCodes(view("protected", dupBoundary)).includes("duplicate_terminal"));
  const reordered = cleanProtected();
  reordered.app = [reordered.app[1], reordered.app[0], reordered.app[2]];
  assert.ok(lineageCodes(view("protected", reordered)).some((code) => code === "impossible_order" || code === "missing_transition"));
  const twoAdmits = cleanProtected();
  twoAdmits.app = [twoAdmits.app[0], { ...twoAdmits.app[0], seq: ++seq }, ...twoAdmits.app.slice(1)];
  assert.ok(lineageCodes(view("protected", twoAdmits)).length > 0);
  const twoMutations = cleanProtected({ mutate: true });
  twoMutations.app.splice(3, 0, ae("APP_MUTATED", { hop: twoMutations.app[0].hop }));
  assert.ok(lineageCodes(view("protected", twoMutations)).includes("duplicate_event"));
});

test("DIRECT LANES: a refused direct attempt that is admitted, executed or mutated is an anomaly (the run would be INVALID)", () => {
  const admitted = cleanProtected();
  assert.ok(lineageCodes(view("direct_boundary_rejected", { boundary: admitted.boundary, app: [] })).includes("direct_not_rejected"));
  assert.ok(lineageCodes(view("direct_boundary_rejected", { boundary: [], app: admitted.app })).includes("direct_app_execution"));
  assert.ok(lineageCodes(view("direct_app_rejected", { boundary: [], app: cleanProtected({ mutate: true }).app })).includes("direct_app_mutation"));
  assert.ok(lineageCodes(view("direct_app_rejected", { boundary: [be("BOUNDARY_ARRIVED")], app: [] })).includes("boundary_lane_mismatch"));
  const refusal: Chain = { plane: [], boundary: [be("BOUNDARY_ARRIVED"), be("BOUNDARY_REJECTED", { reason: "ob.proof_missing" }), be("BOUNDARY_RESPONDED", { status: 403 })], app: [] };
  assert.deepEqual(allCodes(view("direct_boundary_rejected", refusal)), []);
  const appRefusal: Chain = { plane: [], boundary: [], app: [ae("APP_REFUSED", { reason: "ob.proof_missing" })] };
  assert.deepEqual(allCodes(view("direct_app_rejected", appRefusal)), []);
  // the Slice-1 origin rule is a second net on the same lanes
  assert.ok(allCodes(view("direct_app_rejected", { boundary: [], app: admitted.app })).includes("origin_lane_mismatch"));
});

test("POSITIVE CONTROLS are separate lanes: they need their own lineage, live in the oracle hop range, and never satisfy a protected lineage", () => {
  const hop = ORACLE_HOP_BASE + 1;
  const boundaryControl: Chain = {
    plane: [],
    boundary: [be("BOUNDARY_ARRIVED"), be("BOUNDARY_ADMITTED", { hop, pbTag: PB }), be("APP_PROOF_ISSUED", { hop, pbTag: PB, baTag: BA }), be("BOUNDARY_FORWARDED"), be("BOUNDARY_FORWARD_RESPONDED", { status: 200 }), be("BOUNDARY_RESPONDED", { status: 200 })],
    app: [ae("APP_ADMITTED", { hop, pbTag: PB, baTag: BA, spoofed: 0 }), ae("APP_EXECUTED", { hop }), ae("APP_COMPLETED", { hop, status: 200 })],
  };
  assert.deepEqual(allCodes(view("positive_control_boundary", boundaryControl)), []);
  const appControl: Chain = { plane: [], boundary: [], app: [ae("APP_ADMITTED", { hop, pbTag: PB, baTag: BA, spoofed: 0 }), ae("APP_EXECUTED", { hop }), ae("APP_COMPLETED", { hop, status: 200 })] };
  assert.deepEqual(allCodes(view("positive_control_app", appControl)), []);
  // a control that was not admitted with a complete lineage failed
  assert.ok(lineageCodes(view("positive_control_boundary", { plane: [], boundary: boundaryControl.boundary.slice(0, 1), app: [] })).includes("positive_control_failed"));
  assert.ok(lineageCodes(view("positive_control_app", { plane: [], boundary: [], app: [] })).includes("positive_control_failed"));
  // hop ranges are disjoint: neither lane can borrow the other's identifiers
  const planeRange = { ...boundaryControl, app: boundaryControl.app.map((event) => (event.hop ? { ...event, hop: 5 } : event)) };
  assert.ok(lineageCodes(view("positive_control_boundary", planeRange)).includes("hop_range_violation"));
  const oracleInProtected = cleanProtected();
  oracleInProtected.boundary = oracleInProtected.boundary.map((event) => (event.hop ? { ...event, hop: ORACLE_HOP_BASE + 5 } : event));
  assert.ok(lineageCodes(view("protected", oracleInProtected)).includes("hop_range_violation"));
  // and a control carries no plane events
  assert.ok(allCodes(view("positive_control_boundary", { ...boundaryControl, plane: [pe("INGRESS_ACCEPTED")] })).includes("plane_event_on_unexpected_lane"));
  assert.equal(protectedLineageComplete(view("positive_control_boundary", boundaryControl)), false, "a control never counts as a complete PROTECTED lineage");
});

test("control and pre-ingress lanes have no boundary or app stream", () => {
  for (const lane of ["control", "pre_ingress"] as const) assert.ok(lineageCodes(view(lane, { boundary: [be("BOUNDARY_ARRIVED")], app: [] })).includes("boundary_lane_mismatch"), lane);
});

// ---------------------------------------------------------------------------
// The collector's two additional streams
// ---------------------------------------------------------------------------

const meta = (lane: ExpectedLane, scenario = "t", method: RequestMeta["method"] = "GET"): RequestMeta => ({ lane, phase: "baseline", cls: "canary", scenario, journey: 1, step: 1, method });
const N = (index: number) => String(index).padStart(22, "x");
const channel = (emitted: number, lastSeq = emitted, dropped = 0): ChannelStats => ({ emitted, dropped, sent: emitted - dropped, received: emitted - dropped, queued: 0, unacknowledged: 0, queueHighWater: 1, lastSeq });

test("the boundary and app streams get the same integrity checks as the plane's: gaps, loss, crash, missing FIN, late events", () => {
  const boundaryFin = (c: ChannelStats, drained = true): BoundaryFin => ({ drained, channel: c, stats: {} as BoundaryFin["stats"] });
  const appFin = (c: ChannelStats, drained = true): AppFin => ({ drained, channel: c, stats: {} as AppFin["stats"] });
  const fresh = () => { const collector = new Collector(null, DEFAULT_COLLECTOR_LIMITS); collector.enableOriginStreams(); collector.sent(N(1), meta("direct_boundary_rejected")); return collector; };
  const bev = (s: number, kind: BoundaryEventKind, extra: Partial<BoundaryEvent> = {}): BoundaryEvent => ({ seq: s, nonce: N(1), kind, t: 0, ...extra });
  const aev = (s: number, kind: AppEventKind, extra: Partial<AppEvent> = {}): AppEvent => ({ seq: s, nonce: N(1), kind, t: 0, ...extra });
  const codes = (collector: Collector) => collector.finalize().anomalies.map((anomaly) => anomaly.code);

  const gap = fresh();
  gap.ingestBoundaryFrame({ type: "events", dropped: 0, events: [bev(1, "BOUNDARY_ARRIVED"), bev(4, "BOUNDARY_REJECTED", { reason: "ob.proof_missing" })] });
  assert.ok(codes(gap).includes("boundary_channel_loss"));
  const appGap = fresh();
  appGap.ingestAppFrame({ type: "events", dropped: 0, events: [aev(1, "APP_REFUSED", { reason: "ob.proof_missing" }), aev(5, "APP_REFUSED", { reason: "ob.proof_missing" })] });
  assert.ok(codes(appGap).includes("app_channel_loss"));
  const dup = fresh();
  dup.ingestBoundaryFrame({ type: "events", dropped: 0, events: [bev(1, "BOUNDARY_ARRIVED"), bev(1, "BOUNDARY_ARRIVED")] });
  assert.ok(codes(dup).includes("duplicate_sequence"));

  const crashed = fresh();
  crashed.boundaryExited("boundary exited unexpectedly: code none signal SIGKILL");
  crashed.appExited("app exited unexpectedly");
  assert.ok(codes(crashed).includes("boundary_crashed") && codes(crashed).includes("app_crashed"));
  const unfinished = fresh();
  assert.ok(codes(unfinished).includes("boundary_not_finalized") && codes(unfinished).includes("app_not_finalized"));

  for (const bad of [boundaryFin(channel(5, 5, 2)), boundaryFin(channel(5, 7)), boundaryFin(channel(5), false)]) {
    const collector = fresh();
    collector.boundaryFinished(bad);
    collector.appFinished(appFin(channel(0)));
    assert.ok(codes(collector).includes("boundary_channel_loss"), JSON.stringify(bad.channel));
  }
  const clean = fresh();
  clean.ingestBoundaryFrame({ type: "events", dropped: 0, events: [bev(1, "BOUNDARY_ARRIVED"), bev(2, "BOUNDARY_REJECTED", { reason: "ob.proof_missing" }), bev(3, "BOUNDARY_RESPONDED", { status: 403 })] });
  clean.boundaryFinished(boundaryFin(channel(3)));
  clean.appFinished(appFin(channel(0)));
  clean.planeFinished({ drained: true, channel: channel(0), advisory: {} as never });
  clean.clientCompleted(N(1), { result: "response", status: 403, latencyMs: 1 });
  clean.freeze();
  assert.deepEqual(codes(clean), []);

  const late = fresh();
  late.freeze();
  late.ingestBoundaryFrame({ type: "events", dropped: 0, events: [bev(1, "BOUNDARY_ARRIVED")] });
  late.ingestAppFrame({ type: "events", dropped: 0, events: [aev(1, "APP_REFUSED", { reason: "ob.proof_missing" })] });
  assert.ok(codes(late).includes("late_event_after_finalization"));
});

test("admitted app events become the legacy origin events the Slice-1 rules read; refusals do not, and anonymous refusals are only counted", () => {
  const collector = new Collector(null, DEFAULT_COLLECTOR_LIMITS);
  collector.enableOriginStreams();
  collector.sent(N(1), meta("protected"));
  collector.ingestAppFrame({ type: "events", dropped: 0, events: [
    { seq: 1, t: 0, nonce: N(1), kind: "APP_ADMITTED", hop: 9, pbTag: PB, baTag: BA, spoofed: 0 }, { seq: 2, t: 0, nonce: N(1), kind: "APP_EXECUTED", hop: 9 },
    { seq: 3, t: 0, nonce: N(1), kind: "APP_COMPLETED", hop: 9, status: 200 }, { seq: 4, t: 0, nonce: null, kind: "APP_REFUSED", reason: "ob.proof_missing" },
    { seq: 5, t: 0, nonce: N(77), kind: "APP_ADMITTED", hop: 1 },
  ] });
  const record = collector.recordFor(N(1))!;
  assert.deepEqual(record.origin.map((event) => event.kind), ["ORIGIN_RECEIVED", "ORIGIN_COMPLETED"]);
  assert.equal(record.app.length, 3);
  assert.deepEqual(collector.appInfo.anonymous, { APP_REFUSED: 1 });
  assert.ok(collector.finalize().anomalies.some((anomaly) => anomaly.code === "unknown_nonce"), "an admission nobody registered is an anomaly by itself");
});

// ---------------------------------------------------------------------------
// Accounting identities
// ---------------------------------------------------------------------------

const zeroByReason = () => Object.fromEntries(OB_REASONS.map((reason) => [reason, 0]));
function record(rid: number, lane: ExpectedLane, chain: Partial<Chain>, scenario = "t", status = 200): LedgerRecord {
  return { rid: `r${rid}`, nonce: `n${rid}`, meta: meta(lane, scenario, "GET"), harness: harness(status), plane: chain.plane ?? [], origin: origins(chain.app ?? []), boundary: chain.boundary ?? [], app: chain.app ?? [], latencyMs: 1 };
}
const refusal = (reason: (typeof OB_REASONS)[number]): Chain => ({ plane: [], boundary: [be("BOUNDARY_ARRIVED"), be("BOUNDARY_REJECTED", { reason }), be("BOUNDARY_RESPONDED", { status: 403 })], app: [] });
const appRefusal = (reason: (typeof OB_REASONS)[number]): Chain => ({ plane: [], boundary: [], app: [ae("APP_REFUSED", { reason })] });
const control = (hop: number, app: boolean): Chain => {
  const app2 = [ae("APP_ADMITTED", { hop, pbTag: PB, baTag: BA, spoofed: 0 }), ae("APP_EXECUTED", { hop }), ae("APP_COMPLETED", { hop, status: 200 })];
  return app ? { plane: [], boundary: [], app: app2 } : {
    plane: [], app: app2,
    boundary: [be("BOUNDARY_ARRIVED"), be("BOUNDARY_ADMITTED", { hop, pbTag: PB }), be("APP_PROOF_ISSUED", { hop, pbTag: PB, baTag: BA }), be("BOUNDARY_FORWARDED"), be("BOUNDARY_FORWARD_RESPONDED", { status: 200 }), be("BOUNDARY_RESPONDED", { status: 200 })],
  };
};
const journeyOf = (lane: "protected" | "control", ok: boolean): JourneyResult => ({ lane, phase: "baseline", journey: 1, completed: ok, steps: [0, 1, 2, 3, 4].map((step) => ({ step: step + 1, name: "homepage", ok: step === 3 ? ok : true, failure: null, status: 200, latencyMs: 1, bodyDigest: "", headerNames: [] })) });

/** A fully consistent run: two protected requests (one mutates), one control, one direct refusal at each gate, and the three positive controls. */
type MutableInput = Omit<OriginAccountingInput, "records"> & { records: LedgerRecord[] };
function consistent(): MutableInput {
  const hop1 = ORACLE_HOP_BASE + 1; const hop2 = ORACLE_HOP_BASE + 2;
  const get = cleanProtected();
  const post = cleanProtected({ mutate: true, pb: "pbtag0000000000b", ba: "batag0000000000b" });
  const records: LedgerRecord[] = [
    record(1, "protected", get), record(2, "protected", post, "journey_valid_post"),
    record(3, "direct_boundary_rejected", refusal("ob.proof_missing")), record(4, "direct_app_rejected", appRefusal("ob.proof_missing")),
    record(5, "positive_control_boundary", control(hop1, false)), record(6, "positive_control_app", control(hop2, true)),
  ];
  const all = records;
  const count = (stream: "boundary" | "app", kind: string) => all.reduce((total, r) => total + r[stream].filter((event) => event.kind === kind).length, 0);
  const reasons = zeroByReason();
  for (const r of all) for (const event of r.boundary) if (event.kind === "BOUNDARY_REJECTED" && event.reason) reasons[event.reason]++;
  const appReasons = zeroByReason();
  for (const r of all) for (const event of r.app) if (event.kind === "APP_REFUSED" && event.reason) appReasons[event.reason]++;
  const replay = (reserved: number, committed: number, burned = 0) => ({ reserved, committed, burned, replayRejected: 0, capacityRejected: 0, purged: 0, open: 0, size: reserved, highWater: reserved, stateViolations: 0 });
  const boundary: BoundaryFin = {
    drained: true, channel: channel(1),
    stats: {
      arrived: count("boundary", "BOUNDARY_ARRIVED"), admitted: count("boundary", "BOUNDARY_ADMITTED"), rejected: count("boundary", "BOUNDARY_REJECTED"), rejectedByReason: reasons,
      appProofsIssued: count("boundary", "APP_PROOF_ISSUED"), relayed: count("boundary", "BOUNDARY_FORWARDED"), forwardResponded: count("boundary", "BOUNDARY_FORWARD_RESPONDED"), forwardFailed: 0,
      forwardFailedByKind: { refused: 0, reset: 0, timeout: 0, error: 0 }, responded: count("boundary", "BOUNDARY_RESPONDED"), aborted: 0, parserRejected: 0, protocolRefused: 0,
      replay: replay(count("boundary", "BOUNDARY_ADMITTED"), count("boundary", "BOUNDARY_ADMITTED")), contentReadsStarted: 0, contentBytesRead: 0, clockStepMs: 0, clockStep: false,
    },
  };
  const admitted = count("app", "APP_ADMITTED");
  const counters: AppCounters = {
    admitted, refused: count("app", "APP_REFUSED"), executed: count("app", "APP_EXECUTED"), stateMutations: count("app", "APP_MUTATED"), parserRejected: 0, protocolRefused: 0, refusedByReason: appReasons,
  };
  const app: AppFin = {
    drained: true, channel: channel(1),
    stats: {
      counters, served: { received: admitted, completed: count("app", "APP_COMPLETED"), aborted: 0, overloaded: 0, activeHighWater: 1, spoofedHeadersSeen: 0 },
      guard: { replay: replay(admitted * 2, admitted * 2), contentReadsStarted: 0, contentBytesRead: 0, clockStepMs: 0, clockStep: false },
    },
  };
  return {
    records, journeys: [journeyOf("protected", true), journeyOf("protected", true), journeyOf("control", true)].slice(0, 2).map((journey, index) => (index === 1 ? { ...journey, lane: "protected" } : journey)) as JourneyResult[],
    boundary, app, controlCounters: { admitted: 0, refused: 0, executed: 0, stateMutations: 0, parserRejected: 0, protocolRefused: 0, refusedByReason: zeroByReason() },
    boundaryAnonymous: {}, appAnonymous: {}, hop: { issued: 2, signFailures: 0, droppedUnbound: 0 }, expected: { positiveControls: 2, parserCases: 0, droppedUnbound: 0 },
  };
}
const failing = (input: MutableInput) => deriveOriginAccounting(input).identities.filter((identity) => !identity.ok).map((identity) => identity.id);

test("a fully consistent run: every o2 identity holds and the counts are derived from the records", () => {
  // two protected journeys were attempted, only the second counts as a successful valid_post submission
  const input = consistent();
  input.journeys = [journeyOf("protected", true)];
  input.controlCounters.stateMutations = 0;
  const report = deriveOriginAccounting(input);
  assert.deepEqual(report.identities.filter((identity) => !identity.ok), []);
  assert.equal(report.identitiesOk, true);
  assert.deepEqual(report.plane, { attempted: 2, proofIssued: 2, signFailures: 0 });
  assert.equal(report.lineage.complete, 2);
  assert.equal(report.lineage.appAdmitsWithoutLineage, 0);
  assert.deepEqual(report.mutation, { clientObserved: 1, ledgerCorrelated: 1, appAuthoritative: 1, perRecordViolations: 0, controlClient: 0, controlApp: 0 });
  assert.deepEqual(report.positiveControls, { sent: 2, admitted: 2, executed: 2, mutated: 0 });
  assert.equal(report.direct.appExecutionsOnRejectedLanes, 0);
});

test("positive controls are accounted apart: dropping one from the expectation fails its own identity and no protected identity moves", () => {
  const input = consistent();
  input.journeys = [journeyOf("protected", true)];
  const baseline = deriveOriginAccounting(input);
  const protectedIds = (report: ReturnType<typeof deriveOriginAccounting>) => report.identities.filter((identity) => /plane|proof_issued|boundary_admitted|app_proof|app_admitted|lineage|mutation_client|mutation_ledger/.test(identity.id)).map((identity) => `${identity.id}:${identity.left}:${identity.right}`);
  input.expected.positiveControls = 3;
  const report = deriveOriginAccounting(input);
  assert.deepEqual(report.identities.filter((identity) => !identity.ok).map((identity) => identity.id), ["o2.positive_controls_admitted_equals_expected"]);
  assert.deepEqual(protectedIds(report), protectedIds(baseline), "the protected identities are computed over lane `protected` only");
  // removing the controls entirely does not change a single protected identity either
  const without = consistent();
  without.journeys = [journeyOf("protected", true)];
  without.records = without.records.filter((r) => r.meta.lane !== "positive_control_boundary" && r.meta.lane !== "positive_control_app");
  assert.deepEqual(protectedIds(deriveOriginAccounting(without)), protectedIds(baseline));
});

test("NEGATIVE CONTROLS: every kind of corruption makes a specific identity fail", () => {
  const base = () => { const input = consistent(); input.journeys = [journeyOf("protected", true)]; return input; };
  // a protected request that loses its boundary admission, while the app still admitted it
  const noAdmit = base(); noAdmit.records[0] = record(1, "protected", { ...cleanProtected(), boundary: cleanProtected().boundary.filter((event) => event.kind !== "BOUNDARY_ADMITTED") });
  assert.ok(failing(noAdmit).includes("o2.proof_issued_equals_boundary_admitted"));
  assert.ok(failing(noAdmit).includes("o2.lineage_complete_equals_app_admitted"));
  assert.ok(failing(noAdmit).includes("o2.app_admits_without_lineage_is_zero"));
  // the app's own execution counter exceeds what the ledger attributes (an unregistered or mis-tagged execution)
  const unattributed = base(); unattributed.app!.stats.counters.executed += 1;
  assert.ok(failing(unattributed).includes("o2.app_executions_equal_attributed"));
  assert.ok(failing(unattributed).includes("o2.app_counters_equal_ledger"));
  const unattributedMutation = base(); unattributedMutation.app!.stats.counters.stateMutations += 1;
  assert.ok(failing(unattributedMutation).includes("o2.mutation_ledger_equals_app"));
  assert.ok(failing(unattributedMutation).includes("o2.app_mutations_equal_attributed"));
  // client success without a correlated mutation, and a mutation without client success
  const clientOnly = base(); clientOnly.journeys = [journeyOf("protected", true), journeyOf("protected", true)];
  assert.ok(failing(clientOnly).includes("o2.mutation_client_equals_ledger"));
  const ledgerOnly = base(); ledgerOnly.journeys = [journeyOf("protected", false)];
  assert.ok(failing(ledgerOnly).includes("o2.mutation_client_equals_ledger"));
  const lostResponse = base(); lostResponse.records[1] = { ...lostResponse.records[1], harness: harness(502) };
  assert.ok(failing(lostResponse).includes("o2.mutation_per_record_agreement"), "the app mutated but the client saw a failure");
  // a direct refused lane that reached the application
  const direct = base(); direct.records[2] = record(3, "direct_boundary_rejected", control(5, false));
  for (const id of ["o2.direct_boundary_sent_equals_refused_plus_parser", "o2.direct_app_admissions_is_zero", "o2.direct_app_executions_is_zero"]) assert.ok(failing(direct).includes(id), id);
  const directMutation = base(); directMutation.records[3] = record(4, "direct_app_rejected", { plane: [], boundary: [], app: [ae("APP_ADMITTED", { hop: 3 }), ae("APP_EXECUTED"), ae("APP_MUTATED"), ae("APP_COMPLETED", { status: 200 })] });
  assert.ok(failing(directMutation).includes("o2.direct_app_mutations_is_zero"));
  // independent counters that disagree with the events
  const boundaryCounter = base(); boundaryCounter.boundary!.stats.rejected += 1;
  assert.ok(failing(boundaryCounter).includes("o2.boundary_counters_equal_ledger"));
  const reasonCounter = base(); reasonCounter.app!.stats.counters.refusedByReason["ob.replayed"] = 1;
  assert.ok(failing(reasonCounter).includes("o2.app_counters_equal_ledger"));
  // replay state left open, a settle violation, a clock step, and anonymous decisions
  const openReservation = base(); openReservation.boundary!.stats.replay.open = 1;
  assert.ok(failing(openReservation).includes("o2.boundary_replay_state_closed"));
  const violation = base(); violation.app!.stats.guard.replay.stateViolations = 1;
  assert.ok(failing(violation).includes("o2.replay_state_violations_is_zero"));
  const clock = base(); clock.boundary!.stats.clockStep = true;
  assert.ok(failing(clock).includes("o2.clock_step_absent"));
  const anonymous = base(); anonymous.boundaryAnonymous = { BOUNDARY_REJECTED: 1 };
  assert.ok(failing(anonymous).includes("o2.no_anonymous_decisions"));
  const bodyRead = base(); bodyRead.boundary!.stats.contentReadsStarted = 99;
  assert.ok(failing(bodyRead).includes("o2.body_reads_only_after_reservation"));
  // plane counters
  const planeCounter = base(); planeCounter.hop = { issued: 5, signFailures: 0, droppedUnbound: 0 };
  assert.ok(failing(planeCounter).includes("o2.plane_proof_counter_equals_ledger"));
  const dropped = base(); dropped.hop = { issued: 2, signFailures: 0, droppedUnbound: 3 };
  assert.ok(failing(dropped).includes("o2.dropped_unbound_matches_corpus"));
  // a missing FIN means the independent counters cannot be trusted at all
  const noFin = base(); noFin.app = null;
  assert.ok(failing(noFin).length > 0);
});

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

const good = (): OriginVerdictInput => ({
  anomalyTotal: 0, identitiesOk: true, originIdentitiesOk: true, jcr: [{ phase: "baseline", lane: "protected", rate: 1 }, { phase: "post_direct", lane: "protected", rate: 1 }], latencyOk: true,
  parityMismatches: 0, corpusViolations: 0, semanticViolations: 0, directViolations: 0, corpusCount: 55, expectedCorpusCount: 55, semanticCount: 18, directCount: 110,
  positiveControlsOk: true, lineageComplete: true, mutationReconciled: true, countersReconciled: true,
});

test("APP-NON-BYPASS-VALID needs EVERY condition: a single missing lineage, identity, control, mutation or counter makes the run INVALID with its reason", () => {
  assert.deepEqual(decideOriginVerdict(BA0_ORIGIN_LOCAL_V1, good()), { verdict: "APP-NON-BYPASS-VALID", reasons: [] });
  const breaks: [Partial<OriginVerdictInput>, string][] = [
    [{ anomalyTotal: 1 }, "ledger_anomalies_present"], [{ identitiesOk: false }, "accounting_identity_failed"], [{ originIdentitiesOk: false }, "origin_identity_failed"],
    [{ jcr: [{ phase: "baseline", lane: "protected", rate: 0.99 }] }, "jcr_below_minimum:protected.baseline"], [{ jcr: [] }, "jcr_not_measured"], [{ latencyOk: false }, "latency_envelope_exceeded"],
    [{ parityMismatches: 1 }, "protected_control_parity_mismatch"], [{ corpusCount: 54 }, "corpus_count_mismatch"], [{ corpusViolations: 1 }, "corpus_expectation_violated"],
    [{ semanticCount: 17 }, "semantic_count_mismatch"], [{ semanticViolations: 1 }, "semantic_expectation_violated"], [{ directCount: 109 }, "direct_count_mismatch"],
    [{ directViolations: 1 }, "direct_expectation_violated"], [{ positiveControlsOk: false }, "positive_control_failed"], [{ lineageComplete: false }, "lineage_incomplete"],
    [{ mutationReconciled: false }, "mutation_not_reconciled"], [{ countersReconciled: false }, "counters_not_reconciled"],
  ];
  for (const [change, reason] of breaks) {
    const verdict = decideOriginVerdict(BA0_ORIGIN_LOCAL_V1, { ...good(), ...change });
    assert.equal(verdict.verdict, "INVALID", reason);
    assert.ok(verdict.reasons.includes(reason), `${reason} in ${verdict.reasons.join(",")}`);
  }
  const everything = decideOriginVerdict(BA0_ORIGIN_LOCAL_V1, { ...good(), ...Object.assign({}, ...breaks.map(([change]) => change)) });
  assert.equal(everything.verdict, "INVALID");
  assert.ok(everything.reasons.length >= breaks.length - 2, "every reason is listed, not just the first");
});

test("Slice 2 can only conclude APP-NON-BYPASS-VALID or INVALID, never PASS, and its threshold set is named and fingerprinted", () => {
  for (const input of [good(), { ...good(), anomalyTotal: 5 }, { ...good(), lineageComplete: false }]) assert.ok(["APP-NON-BYPASS-VALID", "INVALID"].includes(decideOriginVerdict(BA0_ORIGIN_LOCAL_V1, input).verdict));
  assert.equal(BA0_ORIGIN_LOCAL_V1.id, "ba0-origin-local-v1");
  assert.equal(BA0_ORIGIN_LOCAL_V1.calibration, "provisional-uncalibrated");
  assert.equal(ba0OriginFingerprint().sha256.length, 64);
  assert.notEqual(ba0OriginFingerprint({ ...BA0_ORIGIN_LOCAL_V1, hop: { ...BA0_ORIGIN_LOCAL_V1.hop, pbLifetimeMs: 4_000 } }).sha256, ba0OriginFingerprint().sha256, "changing any value changes the recorded fingerprint");
  assert.deepEqual(BA0_ORIGIN_LOCAL_V1.corpus, { semantic: 18, direct: 110 });
  assert.ok(BA0_ORIGIN_LOCAL_V1.hop.pbLifetimeMs <= 5_000 && BA0_ORIGIN_LOCAL_V1.hop.baLifetimeMs <= 2_000);
});
