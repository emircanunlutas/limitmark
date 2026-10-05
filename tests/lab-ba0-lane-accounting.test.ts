import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import type { PlaneEvent } from "../defense/core/ledger";
import { JourneyLanes, UNIT, type LaneDecision, type LanesConfig } from "../defense/core/lanes";
import type { L2Params } from "../defense/plane/l2-protocol";
import { auditBucket, bucketLaneOf, deriveLaneAccounting, penetrationTable, realDecision } from "../lab/defense/lane-accounting";
import type { LedgerRecord, RequestMeta } from "../lab/defense/collector";
import type { LayerRequest } from "../defense/core/types";

const L2: L2Params = { filterBits: 2 ** 14, filterHashes: 7, epochMs: 60_000, credited: { capacity: 4, refillPerSecond: 2 }, unverified: { capacity: 2, refillPerSecond: 1 }, maxUses: 3, ledgerCapacity: 1_000 };
const post = (token: string): LayerRequest => ({ method: "POST", target: "/api/public-inquiries", headers: [], bodyStatus: "complete", body: Buffer.from(`submissionToken=${token}`) });
const token = () => randomBytes(32).toString("base64url");

function rig() {
  let now = 1_000;
  const config: LanesConfig = { ...L2, mono: () => now, key: Buffer.alloc(32, 5) };
  return { lanes: new JourneyLanes(config), tick: (ms: number) => { now += ms; } };
}

let seq = 0;
const decisionEvent = (decision: LaneDecision, extra: Partial<PlaneEvent> = {}): PlaneEvent => ({
  seq: ++seq, t: 0, nonce: "n", kind: "L2_DECIDED", class: decision.class, lane: decision.lane, outcome: decision.outcome, shedReason: decision.shedReason, l2ErrorKind: decision.errorKind,
  creditTag: decision.creditTag, dt: decision.dt, lvl: decision.lvl, lseq: decision.lseq, spent: decision.spent, touched: decision.touched, ...extra,
});

/** A genuine pressure sequence through the real mechanism, expressed as the events the plane would emit. */
function pressure(): { events: PlaneEvent[]; lanes: JourneyLanes } {
  const { lanes, tick } = rig();
  const events: PlaneEvent[] = [];
  const genuine = Array.from({ length: 6 }, () => { const value = token(); lanes.enroll(value); return value; });
  for (let step = 0; step < 40; step++) {
    tick(120);
    const decision = step % 3 === 0 ? lanes.decide(post(genuine[step % genuine.length])) : lanes.decide(post(token()));
    lanes.record(decision);
    events.push(decisionEvent(decision));
  }
  return { events, lanes };
}
const entries = (events: PlaneEvent[]) => events.filter((event) => event.dt !== undefined).map((event) => ({ event, bucketLane: bucketLaneOf(event) }));

test("the bucket replay audit reproduces a genuine run exactly: every admit consumed one token, every shed had less than one, no decision is missing", () => {
  const { events } = pressure();
  assert.ok(events.some((event) => event.outcome === "shed") && events.some((event) => event.outcome === "admitted"));
  const credited = auditBucket(entries(events), "credited", L2.credited);
  const unverified = auditBucket(entries(events), "unverified", L2.unverified);
  assert.deepEqual([credited.mismatches, credited.gaps, unverified.mismatches, unverified.gaps], [0, 0, 0, 0], JSON.stringify([credited.firstMismatch, unverified.firstMismatch]));
  assert.equal(credited.decisions + unverified.decisions, events.length);
});

test("the audit catches a refund (a token that came back), a missing decision, a forged level and a time reversal", () => {
  const { events } = pressure();
  const unverified = entries(events).filter((entry) => entry.bucketLane === "unverified");
  const refunded = events.map((event) => (event.lseq === 3 && realDecision(event).lane === "unverified" ? { ...event, lvl: (event.lvl ?? 0) + UNIT } : event));
  assert.ok(auditBucket(entries(refunded), "unverified", L2.unverified).mismatches > 0, "a level that went UP by a token is a refund");
  const gap = entries(events).filter((entry) => !(entry.bucketLane === "unverified" && entry.event.lseq === 4));
  assert.ok(auditBucket(gap, "unverified", L2.unverified).gaps > 0, "a missing decision shows as a gap in the numbering");
  const forged = events.map((event) => (event.lseq === 2 && realDecision(event).lane === "unverified" ? { ...event, lvl: 0 } : event));
  assert.ok(auditBucket(entries(forged), "unverified", L2.unverified).mismatches > 0);
  const reversed = events.map((event) => (event.lseq === 5 && realDecision(event).lane === "unverified" ? { ...event, dt: 1 } : event));
  assert.ok(auditBucket(entries(reversed), "unverified", L2.unverified).mismatches > 0, "the bucket's clock never goes back");
  assert.ok(unverified.length > 5);
});

test("a discarded decision is part of the replay: what it consumed (spent) or merely took a decision from (touched) keeps the numbering and the levels exact", () => {
  const { lanes, tick } = rig();
  const events: PlaneEvent[] = [];
  const first = lanes.decide(post(token())); events.push(decisionEvent(first));
  tick(10);
  const consumed = lanes.decide(post(token()));
  events.push(decisionEvent({ class: "mutation", lane: null, outcome: "error", errorKind: "timeout", spent: "unverified", dt: consumed.dt, lvl: consumed.lvl, lseq: consumed.lseq }));
  tick(10);
  const shed = lanes.decide(post(token()));
  assert.equal(shed.outcome, "shed");
  events.push(decisionEvent({ class: "mutation", lane: null, outcome: "error", errorKind: "timeout", touched: "unverified", dt: shed.dt, lvl: shed.lvl, lseq: shed.lseq }));
  const audit = auditBucket(entries(events), "unverified", L2.unverified);
  assert.deepEqual([audit.mismatches, audit.gaps, audit.admitted, audit.shed], [0, 0, 2, 1], audit.firstMismatch ?? "");
});

test("a simulated verdict is replayed from its SHADOW: the bucket saw the real decision, not the delivered one", () => {
  const { lanes } = rig();
  for (let i = 0; i < 2; i++) lanes.decide(post(token()));
  const real = lanes.decide(post(token()));
  assert.equal(real.outcome, "shed");
  const delivered = decisionEvent({ ...real, outcome: "admitted", shedReason: undefined }, { basis: "simulated", shadow: "shed:unverified:lane_budget" });
  assert.deepEqual(realDecision(delivered), { outcome: "shed", lane: "unverified" });
});

// ---------------------------------------------------------------------------
// deriveLaneAccounting over synthetic records
// ---------------------------------------------------------------------------

let rid = 0;
const meta = (scenario: string, cls: RequestMeta["cls"] = "canary", phase = "baseline"): RequestMeta => ({ lane: "protected", phase, cls, scenario, journey: 1, step: 1, method: "GET" });
function record(scenario: string, plane: PlaneEvent[], cls: RequestMeta["cls"] = "canary", phase = "baseline"): LedgerRecord {
  rid++;
  return { rid: `r${rid}`, nonce: `n${rid}`, meta: meta(scenario, cls, phase), harness: [{ kind: "SENT" }, { kind: "CLIENT_COMPLETED", result: "response", status: 200 }], plane, origin: [], boundary: [], app: [], latencyMs: 1 };
}
const e = (kind: PlaneEvent["kind"], extra: Partial<PlaneEvent> = {}): PlaneEvent => ({ seq: ++seq, t: 0, nonce: "n", kind, ...extra });
const head = (): PlaneEvent[] => [e("INGRESS_ACCEPTED"), e("L1_ENTERED"), e("L1_PASSED"), e("L2_ENTERED")];
const respond = (): PlaneEvent[] => [e("EGRESS_ATTEMPTED"), e("EGRESS_RESPONDED", { status: 200 })];
const done = (): PlaneEvent => e("INGRESS_RESPONDED", { status: 200 });
const derive = (records: LedgerRecord[]) => deriveLaneAccounting({ records, fin: null, l2: L2, renderScenarios: new Set(["journey_form"]), maxUses: 3 });

test("lane accounting: every identity holds for a clean sequence of one render and its credited POST, and the G2 ordering is checked in the plane's own sequence", () => {
  const render = record("journey_form", [...head(), e("L2_DECIDED", { class: "open", lane: "open", outcome: "admitted" }), ...respond(), e("L2_ENROLLED", { creditTag: "tagTAG0000000001", fill: [7, 0] }), done()]);
  const credited = record("journey_valid_post", [...head(), e("L2_DECIDED", { class: "mutation", lane: "credited", outcome: "admitted", creditTag: "tagTAG0000000001", dt: 10, lvl: 3 * UNIT, lseq: 1 }), ...respond(), done()]);
  const report = derive([render, credited]);
  assert.equal(report.identitiesOk, true, JSON.stringify(report.identities.filter((identity) => !identity.ok)));
  assert.deepEqual([report.credit.creditedAdmitted, report.credit.withEnrollment, report.credit.falsePositive, report.ordering.violations], [1, 1, 0, 0]);
  assert.deepEqual(report.canaryPost, { total: 1, credited: 1, unverified: 0, shed: 0, other: 0 });
});

test("lane accounting detects: an enrollment AFTER the decision (G2), a credited admission with no enrollment (a false positive), more than K uses, and a missing disposition", () => {
  const credited = (tag: string, lseq: number) => record("journey_valid_post", [...head(), e("L2_DECIDED", { class: "mutation", lane: "credited", outcome: "admitted", creditTag: tag, dt: 10 + lseq, lvl: (4 - lseq) * UNIT, lseq }), ...respond(), done()]);
  const late = [credited("lateTAG000000001", 1), record("journey_form", [...head(), e("L2_DECIDED", { class: "open", lane: "open", outcome: "admitted" }), ...respond(), e("L2_ENROLLED", { creditTag: "lateTAG000000001", fill: [7, 0] }), done()])];
  assert.equal(derive(late).ordering.violations, 1, "the POST was decided before the render was enrolled");
  assert.equal(derive(late).identitiesOk, false);

  const falsePositive = derive([credited("noEnrollTAG00001", 1)]);
  assert.equal(falsePositive.credit.falsePositive, 1, "a credited admission nobody enrolled is a measured false positive, not silently fine");
  assert.deepEqual(falsePositive.credit.falsePositiveByPhase, { baseline: 1 });

  const overK = derive([1, 2, 3, 4].map((n) => credited("overKTAG00000001", n)));
  assert.equal(overK.credit.tagsOverK, 1);
  assert.equal(overK.identitiesOk, false);

  const missing = derive([record("journey_form", [...head(), e("L2_DECIDED", { class: "open", lane: "open", outcome: "admitted" }), ...respond(), done()])]);
  assert.equal(missing.enrollment.missing, 1);
  assert.equal(missing.identitiesOk, false);
});

test("lane accounting detects a request that disappeared between layers and a decision-less L2 entry", () => {
  const vanished = record("journey_valid_post", [e("INGRESS_ACCEPTED"), e("L1_ENTERED"), e("L1_PASSED"), done()]);
  const report = derive([vanished]);
  assert.equal(report.identitiesOk, false);
  assert.ok(report.identities.some((identity) => identity.id === "l2.entered_equals_l1_passed" && !identity.ok));
  const undecided = derive([record("journey_valid_post", [...head(), done()])]);
  assert.ok(undecided.identities.some((identity) => identity.id === "l2.decided_equals_entered" && !identity.ok));
});

test("the penetration table never merges natural and simulated rows, and keeps lane and terminal explanation per family", () => {
  const natural = record("f1_fabricated", [...head(), e("L2_DECIDED", { class: "mutation", lane: "unverified", outcome: "shed", shedReason: "lane_budget", dt: 1, lvl: 0, lseq: 1 }), done()], "hostile");
  const simulated = record("fx_unknown_field", [e("INGRESS_ACCEPTED"), e("L1_ENTERED"), e("L1_PASSED", { basis: "simulated", shadow: "reject:a7.form_field_not_allowed" }), e("L2_ENTERED"),
    e("L2_DECIDED", { class: "mutation", lane: "unverified", outcome: "shed", shedReason: "lane_budget", dt: 2, lvl: 0, lseq: 2 }), done()], "hostile");
  const table = penetrationTable([natural, simulated], (r) => (r.meta.scenario.startsWith("f1_") ? "f1_natural" : "forced"));
  assert.equal(table.rows.length, 2);
  assert.deepEqual(table.rows.map((row) => [row.family, row.basis, row.l1, row.terminal]).sort(), [
    ["f1_natural", "natural", "natural_pass", "l2_shed:unverified:lane_budget"], ["forced", "simulated", "simulated_pass", "l2_shed:unverified:lane_budget"],
  ].sort());
});
