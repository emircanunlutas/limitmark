import assert from "node:assert/strict";
import { test } from "node:test";
import type { AnomalyCode, PlaneEvent } from "../defense/core/ledger";
import { ExternalReducer, attributeShed, type AllowedShed, type ExternalLimits } from "../lab/defense/external-reducer";
import { ExternalEventFactory, feed } from "../lab/defense/field-selftest";
import { BA0_FIELD_V1 } from "../lab/defense/field-thresholds";
import { assertEvidenceSafe } from "../lab/evidence/redact";
import { compactTrace } from "../lab/defense/field-evidence";

const ALLOWED: AllowedShed[] = [{ class: "mutation", lane: "unverified", reason: "lane_budget" }];

function rig(limits: Partial<ExternalLimits> = {}) {
  const anomalies: { code: AnomalyCode; rid: string | null; detail: string }[] = [];
  const clock = { now: 0 };
  const reducer = new ExternalReducer({ limits, allowedShed: ALLOWED, now: () => clock.now, report: (code, rid, detail) => anomalies.push({ code, rid, detail }) });
  return { reducer, anomalies, clock, factory: new ExternalEventFactory(BA0_FIELD_V1.l2) };
}

test("a clean proxied request is joined from three streams, validated, reduced to exact counters and dropped", () => {
  const { reducer, anomalies, factory } = rig();
  feed(reducer, factory.lifecycle("get_proxied"));
  assert.deepEqual(anomalies, []);
  const c = reducer.counters();
  assert.equal(c.accepted, 1);
  assert.equal(c.reduced, 1);
  assert.equal(reducer.activeCount, 0, "the transient state is gone");
  assert.equal(c.terminal.proxied, 1);
  assert.deepEqual(c.l1, { entered: 1, passed: 1, rejected: 0, shed: 0, error: 0 });
  assert.deepEqual({ entered: c.l2.entered, decided: c.l2.decided }, { entered: 1, decided: 1 });
  assert.equal(c.l2.classes.open, 1);
  assert.deepEqual({ attempted: c.egress.attempted, responded: c.egress.responded, failed: c.egress.failed }, { attempted: 1, responded: 1, failed: 0 });
  assert.equal(c.proofsIssued, 1);
  assert.deepEqual(c.boundary, { arrived: 1, admitted: 1, rejected: 0, appProofsIssued: 1, relayed: 1, forwardResponded: 1, forwardFailed: 0, responded: 1, aborted: 0 });
  assert.deepEqual(c.app, { admitted: 1, refused: 0, executed: 1, mutated: 0, completed: 1, aborted: 0 });
  assert.deepEqual(c.statusHistogram, { "200": 1 });
});

test("downstream events may arrive before the plane's ingress, after it, or between: the join does not depend on the order of the three pipes", () => {
  for (const downstreamFirst of [false, true]) {
    const { reducer, anomalies, factory } = rig();
    for (let index = 0; index < 5; index++) feed(reducer, factory.lifecycle("post_mutated"), downstreamFirst);
    assert.deepEqual(anomalies, [], `downstreamFirst ${downstreamFirst}`);
    assert.equal(reducer.counters().reduced, 5);
    assert.equal(reducer.orphanCount, 0);
  }
});

test("every outcome kind is counted exactly: L1 reject, L2 budget shed, a mutation, an egress failure, a proxied 503", () => {
  const { reducer, factory } = rig();
  for (const kind of ["l1_rejected", "post_mutated", "post_mutated", "post_mutated", "post_shed", "post_shed", "get_egress_failed", "get_503_proxied", "get_proxied"] as const) feed(reducer, factory.lifecycle(kind));
  const c = reducer.counters();
  assert.equal(c.accepted, 9);
  assert.equal(c.l1.rejected, 1);
  assert.deepEqual(c.l1RejectedByReason, { "a7.path_not_allowed": 1 });
  assert.equal(c.terminal.rejected, 1);
  assert.equal(c.terminal.l2_shed, 2);
  assert.equal(c.terminal.egress_failed, 1);
  assert.equal(c.terminal.proxied, 5);
  assert.equal(c.app.mutated, 3);
  assert.deepEqual(c.mutatedByLane, { unverified: 3 });
  assert.equal(c.egress.failed, 1);
  assert.equal(c.egress.failedByKind.refused, 1);
  assert.deepEqual(c.statusHistogram, { "200": 4, "404": 1, "502": 1, "503": 3 });
  assert.equal(c.status5xxOther, 1, "the 502");
  assert.deepEqual({ total: c.status503.total, expectedShed: c.status503.expectedShed, unexplained: c.status503.unexplained }, { total: 3, expectedShed: 2, unexplained: 1 });
  assert.deepEqual(c.status503.byCause, { "l2_shed_unverified_lane_budget": 2, proxied_503: 1 });
  assert.deepEqual(c.l2.shedByReason, { "mutation.unverified.lane_budget": 2 });
});

test("D6: a 503 is an expected defense shed ONLY when the server-side record proves an allowed L2 budget shed with no egress", () => {
  const ev = (event: Partial<PlaneEvent> & Pick<PlaneEvent, "kind">): PlaneEvent => ({ nonce: "n", seq: 1, t: 0, ...event });
  const decided = (extra: Partial<PlaneEvent>) => ev({ kind: "L2_DECIDED", class: "mutation", lane: "unverified", outcome: "shed", shedReason: "lane_budget", dt: 0, lvl: 0, lseq: 1, ...extra });
  assert.deepEqual(attributeShed([decided({})], ALLOWED), { expected: true, cause: "l2_shed_unverified_lane_budget" });
  const cases: [string, PlaneEvent[], string][] = [
    ["an L1 shed", [ev({ kind: "L1_SHED" })], "l1_shed"],
    ["an L1 error", [ev({ kind: "L1_ERROR", errorKind: "throw" })], "l1_error"],
    ["an L2 shed for saturation, not budget", [decided({ lane: null, shedReason: "evaluator_saturation", dt: undefined, lvl: undefined, lseq: undefined })], "l2_shed_other_none_evaluator_saturation"],
    ["a credited-lane budget shed (this workload never farms credits)", [decided({ lane: "credited" })], "l2_shed_other_credited_lane_budget"],
    ["an open-class shed", [decided({ class: "open", lane: "open" })], "l2_shed_other_open_lane_budget"],
    ["an L2 error", [ev({ kind: "L2_DECIDED", class: "mutation", lane: null, outcome: "error", l2ErrorKind: "throw" })], "l2_error"],
    ["a simulated verdict", [decided({ basis: "simulated", shadow: "shed:unverified:lane_budget" })], "l2_simulated"],
    ["a shed that nonetheless reached egress", [decided({}), ev({ kind: "EGRESS_ATTEMPTED" })], "l2_shed_with_egress"],
    ["a 503 proxied from downstream", [ev({ kind: "L2_DECIDED", class: "mutation", lane: "unverified", outcome: "admitted" }), ev({ kind: "EGRESS_ATTEMPTED" })], "proxied_503"],
    ["a 503 with no record at all", [], "other"],
  ];
  for (const [label, events, cause] of cases) assert.deepEqual(attributeShed(events, ALLOWED), { expected: false, cause }, label);
  assert.equal(attributeShed([decided({})], []).expected, false, "with no allowed shed configured nothing is expected");
});

test("HTTP status is never what attributes a shed: the reducer reads only the plane's own events, so a 503 with no matching decision is unexplained", () => {
  const { reducer, factory } = rig();
  const lifecycle = factory.lifecycle("get_proxied");
  // forge: the plane answered 503 but its own record is an admitted open request that went downstream
  const forged = lifecycle.plane.map((event) => (event.kind === "INGRESS_RESPONDED" || event.kind === "EGRESS_RESPONDED" ? { ...event, status: 503 } : event));
  feed(reducer, { ...lifecycle, plane: forged });
  const c = reducer.counters();
  assert.equal(c.status503.total, 1);
  assert.equal(c.status503.unexplained, 1);
  assert.equal(c.status503.expectedShed, 0);
});

// ------------------------------------------------------------------------------------------------ fatal things stay fatal
test("an App admission whose proof tags do not match the plane's lineage is a bypass anomaly", () => {
  const { reducer, anomalies, factory } = rig();
  const lifecycle = factory.lifecycle("get_proxied");
  lifecycle.app = lifecycle.app.map((event) => (event.kind === "APP_ADMITTED" ? { ...event, pbTag: "x".repeat(16) } : event));
  feed(reducer, lifecycle);
  assert.ok(anomalies.some((anomaly) => anomaly.code === "app_admit_without_lineage"), anomalies.map((anomaly) => anomaly.code).join(","));
});

test("a request the plane never terminates is unresolved at finalization (an anomaly, never silent), and a late event for a closed request is flagged", () => {
  const { reducer, anomalies, factory } = rig();
  const lifecycle = factory.lifecycle("get_proxied");
  reducer.ingestPlane(lifecycle.plane[0]);
  reducer.ingestPlane(lifecycle.plane[1]);
  assert.equal(reducer.activeCount, 1);
  reducer.finalize();
  const codes = anomalies.map((anomaly) => anomaly.code);
  assert.ok(codes.includes("external_unresolved"));
  assert.ok(codes.includes("disappeared_after_ingress"));
  assert.equal(reducer.counters().terminal.unresolved, 1);
  assert.equal(reducer.ingestPlane(lifecycle.plane[2]), true);
  assert.ok(anomalies.some((anomaly) => anomaly.code === "external_late_event"), "the closed request is remembered, so a straggler is flagged, not re-opened");
  assert.equal(reducer.activeCount, 0);
});

test("the same plane-minted nonce opening twice is an anomaly", () => {
  const { reducer, anomalies, factory } = rig();
  const first = factory.lifecycle("get_proxied", "u".repeat(22));
  feed(reducer, first);
  feed(reducer, { plane: [{ ...first.plane[0], seq: 999 }], boundary: [], app: [] });
  assert.ok(anomalies.some((anomaly) => anomaly.code === "external_duplicate_nonce"));
});

test("an unreturned downstream hop does not leave a request open forever: after the grace the request is reduced as it stands, with the missing hops as anomalies", () => {
  const { reducer, anomalies, clock, factory } = rig({ downstreamGraceMs: 1_000 });
  const lifecycle = factory.lifecycle("get_proxied");
  for (const event of lifecycle.plane) reducer.ingestPlane(event);
  for (const event of lifecycle.boundary.slice(0, 2)) reducer.ingestBoundary(event);
  assert.equal(reducer.activeCount, 1, "waiting for the downstream hops");
  clock.now = 500;
  reducer.sweep();
  assert.equal(reducer.activeCount, 1);
  clock.now = 1_200;
  reducer.sweep();
  assert.equal(reducer.activeCount, 0);
  assert.ok(anomalies.length > 0);
  assert.equal(reducer.counters().reduced, 1);
});

test("downstream events no plane ingress claims: a refusal-only orphan is counted anonymously (as the unreduced collector does); anything else is an anomaly", () => {
  const { reducer, anomalies, clock } = rig({ orphanGraceMs: 1_000 });
  reducer.ingestBoundary({ seq: 1, t: 0, nonce: "R".repeat(22), kind: "BOUNDARY_ARRIVED" });
  reducer.ingestBoundary({ seq: 2, t: 0, nonce: "R".repeat(22), kind: "BOUNDARY_REJECTED", reason: "ob.proof_missing" });
  reducer.ingestApp({ seq: 1, t: 0, nonce: "A".repeat(22), kind: "APP_REFUSED", reason: "ob.proof_missing" });
  reducer.ingestApp({ seq: 2, t: 0, nonce: "B".repeat(22), kind: "APP_ADMITTED", hop: 1, pbTag: "p".repeat(16), baTag: "b".repeat(16), spoofed: 0 });
  assert.equal(reducer.orphanCount, 3);
  clock.now = 2_000;
  reducer.sweep();
  assert.equal(reducer.orphanCount, 0);
  assert.deepEqual(reducer.anonymousRefusals(), { refused: 2 });
  assert.deepEqual(anomalies.map((anomaly) => anomaly.code), ["external_unclaimed_downstream"], "only the admission with no plane behind it");
});

// ------------------------------------------------------------------------------------------------ bounded memory
test("BOUNDED: open requests are capped; beyond the cap each new ingress is an overflow anomaly, never more state", () => {
  const { reducer, anomalies, factory } = rig({ maxActive: 50 });
  for (let index = 0; index < 2_000; index++) reducer.ingestPlane(factory.lifecycle("get_proxied").plane[0]);
  assert.equal(reducer.activeCount, 50);
  assert.equal(anomalies.filter((anomaly) => anomaly.code === "external_state_overflow").length, 1_950);
  assert.equal(reducer.counters().overflow.active, 1_950);
});

test("BOUNDED: the orphan table is capped", () => {
  const { reducer, anomalies } = rig({ maxOrphans: 40 });
  for (let index = 0; index < 5_000; index++) reducer.ingestApp({ seq: index + 1, t: 0, nonce: `O${String(index).padStart(21, "0")}`, kind: "APP_ADMITTED", hop: 1, pbTag: "p".repeat(16), baTag: "b".repeat(16), spoofed: 0 });
  assert.equal(reducer.orphanCount, 40);
  assert.equal(anomalies.filter((anomaly) => anomaly.code === "external_state_overflow").length, 4_960);
});

test("BOUNDED: the recently-closed ring, the retained traces and the retained decisions have hard caps whatever the volume", () => {
  const { reducer, factory } = rig({ recentRing: 50, maxTraces: 20, headTraces: 5, perKindTraces: 2, maxDecisions: 100 });
  // One simulated second between mutations so the unverified bucket (1 token per second) admits each of them.
  for (let index = 0; index < 5_000; index++) { if (index % 3 === 0) factory.now += 1_000; feed(reducer, factory.lifecycle(index % 3 === 0 ? "post_mutated" : "get_proxied")); }
  assert.equal(reducer.recentCount, 50, "the ring holds the newest 50 and forgets the rest");
  assert.ok(reducer.traces().length <= 20, `traces ${reducer.traces().length}`);
  assert.equal(reducer.counters().traces.retained, reducer.traces().length);
  assert.ok(reducer.counters().traces.droppedByCap > 0, "the cap was reached and counted, not exceeded");
  assert.equal(reducer.decisions().length, 100);
  assert.ok(reducer.counters().decisions.droppedByCap > 0);
  assert.equal(reducer.counters().reduced, 5_000, "the COUNTERS stay exact however much trace is dropped");
  assert.equal(reducer.activeCount, 0);
});

test("retained traces are chosen by explanation, not by luck: every anomaly and mutation first, then the first of each kind, then a head sample", () => {
  const { reducer, factory } = rig({ maxTraces: 1_000, headTraces: 3, perKindTraces: 2 });
  for (let index = 0; index < 50; index++) feed(reducer, factory.lifecycle("get_proxied"));
  const reasons = (): string[] => reducer.traces().map((trace) => trace.reason);
  assert.deepEqual([...new Set(reasons())].sort(), ["first_of_kind", "head"]);
  assert.equal(reducer.traces().length, 5, "2 first-of-kind + 3 head");
  feed(reducer, factory.lifecycle("post_mutated"));
  assert.ok(reasons().includes("mutation"), "a mutation is always kept");
  const bad = factory.lifecycle("get_proxied");
  bad.app = bad.app.filter((event) => event.kind !== "APP_COMPLETED");
  feed(reducer, bad);
  reducer.finalize();
  assert.ok(reasons().includes("anomaly"), "an anomalous request is always kept");
});

test("the counters and the compact traces are evidence-safe: no nonce, no address, no token", () => {
  const { reducer, factory } = rig();
  for (const kind of ["get_proxied", "post_mutated", "post_shed", "l1_rejected", "get_egress_failed"] as const) feed(reducer, factory.lifecycle(kind));
  assert.doesNotThrow(() => assertEvidenceSafe({ counters: reducer.counters(), traces: reducer.traces().map(compactTrace) }, "$external"));
  const text = JSON.stringify(reducer.traces().map(compactTrace));
  assert.doesNotMatch(text, /u[X]{3,}/, "the plane-minted nonce never appears in a trace");
});
