import assert from "node:assert/strict";
import { test } from "node:test";
import type { AppEvent, BoundaryEvent, LifecycleView, PlaneEvent } from "../defense/core/ledger";
import { validateLifecycle } from "../defense/core/ledger";
import { validateL2Lifecycle } from "../defense/core/l2-lifecycle";
import { isNaturalL1Bypass, penetrationOf } from "../defense/core/penetration";

let seq = 0;
const p = (kind: PlaneEvent["kind"], extra: Partial<PlaneEvent> = {}): PlaneEvent => ({ seq: ++seq, t: 0, nonce: "n", kind, ...extra });
const b = (kind: BoundaryEvent["kind"], extra: Partial<BoundaryEvent> = {}): BoundaryEvent => ({ seq: ++seq, t: 0, nonce: "n", kind, ...extra });
const a = (kind: AppEvent["kind"], extra: Partial<AppEvent> = {}): AppEvent => ({ seq: ++seq, t: 0, nonce: "n", kind, ...extra });

const view = (plane: PlaneEvent[], rest: Partial<LifecycleView> = {}): LifecycleView => ({
  nonce: "n", expected: "protected", harness: [{ kind: "SENT" }, { kind: "CLIENT_COMPLETED", result: "response", status: 200 }], plane, origin: [], l2: true, ...rest,
});

const base = (basis?: "simulated", shadow?: string): PlaneEvent[] => [
  p("INGRESS_ACCEPTED"), p("L1_ENTERED"), p("L1_PASSED", basis ? { basis, shadow } : {}), p("L2_ENTERED"),
];
const unverifiedAdmitted = (extra: Partial<PlaneEvent> = {}): PlaneEvent => p("L2_DECIDED", { class: "mutation", lane: "unverified", outcome: "admitted", dt: 5, lvl: 1_000_000, lseq: 1, ...extra });
const chain = (): { plane: PlaneEvent[]; boundary: BoundaryEvent[]; app: AppEvent[] } => ({
  plane: [...base(), unverifiedAdmitted(), p("EGRESS_ATTEMPTED"), p("PROOF_ISSUED", { pbTag: "pb" }), p("EGRESS_RESPONDED", { status: 200 }), p("INGRESS_RESPONDED", { status: 200 })],
  boundary: [b("BOUNDARY_ARRIVED"), b("BOUNDARY_ADMITTED", { hop: 1 }), b("APP_PROOF_ISSUED"), b("BOUNDARY_FORWARDED")],
  app: [a("APP_ADMITTED"), a("APP_EXECUTED"), a("APP_MUTATED"), a("APP_COMPLETED", { status: 200 })],
});

test("a natural L1 pass that reaches APP_MUTATED is a natural bypass; the SAME path with one simulated verdict anywhere is never summarized as natural", () => {
  const natural = chain();
  const naturalRecord = penetrationOf(view(natural.plane, { boundary: natural.boundary, app: natural.app }));
  assert.deepEqual([naturalRecord.basis, naturalRecord.l1, naturalRecord.l2, naturalRecord.deepest, naturalRecord.terminal], ["natural", "natural_pass", "quarantined", "app_mutated", "app_mutated"]);
  assert.equal(isNaturalL1Bypass(naturalRecord), true);

  const forced = chain();
  forced.plane[2] = p("L1_PASSED", { basis: "simulated", shadow: "reject:a7.form_field_not_allowed" });
  const forcedRecord = penetrationOf(view(forced.plane, { boundary: forced.boundary, app: forced.app }));
  assert.deepEqual([forcedRecord.basis, forcedRecord.l1, forcedRecord.deepest], ["simulated", "simulated_pass", "app_mutated"]);
  assert.equal(isNaturalL1Bypass(forcedRecord), false, "a simulated pass is not a natural bypass, whatever depth it reached");

  const l2Only = chain();
  l2Only.plane[3 + 1] = unverifiedAdmitted({ basis: "simulated", shadow: "shed:unverified:lane_budget" });
  const l2Record = penetrationOf(view(l2Only.plane, { boundary: l2Only.boundary, app: l2Only.app }));
  assert.equal(l2Record.l1, "natural_pass");
  assert.equal(l2Record.basis, "simulated", "one simulated L2 verdict makes the whole request simulated");
  assert.equal(isNaturalL1Bypass(l2Record), false, "L1's own pass is natural, but the request is not a natural bypass once any verdict was simulated");
});

test("a SKIPPED layer is not a bypass: the stage never ran, and the lifecycle says so distinctly", () => {
  const skipped = [p("INGRESS_ACCEPTED"), p("EGRESS_ATTEMPTED"), p("EGRESS_RESPONDED", { status: 200 }), p("INGRESS_RESPONDED", { status: 200 })];
  const record = penetrationOf(view(skipped));
  assert.equal(record.l1, "skipped");
  assert.notEqual(record.l1, "natural_pass");
  assert.equal(validateL2Lifecycle(view(skipped), true).some((anomaly) => anomaly.code === "layer_skipped" && anomaly.detail === "l1"), true);

  const l2Skipped = [p("INGRESS_ACCEPTED"), p("L1_ENTERED"), p("L1_PASSED"), p("EGRESS_ATTEMPTED"), p("EGRESS_RESPONDED", { status: 200 }), p("INGRESS_RESPONDED", { status: 200 })];
  assert.equal(penetrationOf(view(l2Skipped)).l2, "skipped");
  assert.equal(validateL2Lifecycle(view(l2Skipped), true).some((anomaly) => anomaly.code === "layer_skipped" && anomaly.detail === "l2"), true);
  assert.ok(validateLifecycle(view(l2Skipped), true).some((anomaly) => anomaly.code === "missing_transition"), "and the automaton refuses the missing stage too");
});

test("every distinct outcome has its own terminal explanation and its own stage vocabulary", () => {
  const terminal = (plane: PlaneEvent[], rest: Partial<LifecycleView> = {}) => penetrationOf(view(plane, rest)).terminal;
  const abort = [p("INGRESS_RESPONDED", { status: 400 })];
  assert.equal(terminal([p("INGRESS_ACCEPTED"), p("L1_ENTERED"), p("L1_REJECTED", { reason: "a7.path_not_allowed" }), ...abort]), "l1_rejected:a7.path_not_allowed");
  assert.equal(terminal([p("INGRESS_ACCEPTED"), p("L1_ENTERED"), p("L1_ERROR", { errorKind: "throw" }), ...abort]), "l1_error:throw");
  assert.equal(terminal([...base(), p("L2_DECIDED", { class: "mutation", lane: "credited", outcome: "shed", shedReason: "lane_budget", dt: 1, lvl: 0, lseq: 1 }), ...abort]), "l2_shed:credited:lane_budget");
  assert.equal(terminal([...base(), p("L2_DECIDED", { class: "mutation", lane: null, outcome: "shed", shedReason: "evaluator_saturation" }), ...abort]), "l2_shed:none:evaluator_saturation");
  assert.equal(terminal([...base(), p("L2_DECIDED", { class: "mutation", lane: null, outcome: "error", l2ErrorKind: "timeout" }), ...abort]), "l2_error:timeout");
  const degraded = penetrationOf(view([...base(), p("L2_DECIDED", { class: "open", lane: "open", outcome: "degraded" }), p("EGRESS_ATTEMPTED"), p("EGRESS_RESPONDED", { status: 200 }), p("INGRESS_RESPONDED", { status: 200 })]));
  assert.equal(degraded.l2, "degraded", "a degraded read is its own state, never `admitted`");
  assert.equal(terminal([...base(), unverifiedAdmitted(), p("EGRESS_ATTEMPTED"), p("EGRESS_FAILED", { egressError: "error", failStage: "canon" }), ...abort]), "canon_refused");
  assert.equal(terminal([...base(), unverifiedAdmitted(), p("EGRESS_ATTEMPTED"), p("EGRESS_FAILED", { egressError: "error", failStage: "sign" }), ...abort]), "sign_refused");
  const issued = [...base(), unverifiedAdmitted(), p("EGRESS_ATTEMPTED"), p("PROOF_ISSUED", { pbTag: "pb" })];
  assert.equal(terminal([...issued, p("EGRESS_RESPONDED", { status: 403 }), ...abort], { boundary: [b("BOUNDARY_ARRIVED"), b("BOUNDARY_REJECTED", { reason: "ob.replayed" })] }), "boundary_rejected:ob.replayed");
  const admitted = [b("BOUNDARY_ARRIVED"), b("BOUNDARY_ADMITTED"), b("APP_PROOF_ISSUED")];
  assert.equal(terminal([...issued, p("EGRESS_RESPONDED", { status: 403 }), ...abort], { boundary: admitted, app: [a("APP_REFUSED", { reason: "ob.proof_missing" })] }), "app_refused:ob.proof_missing");
  assert.equal(terminal([...issued, p("EGRESS_RESPONDED", { status: 200 }), ...abort], { boundary: admitted, app: [a("APP_ADMITTED"), a("APP_EXECUTED"), a("APP_COMPLETED")] }), "app_executed_no_mutation");
  const deepest = (app: AppEvent[]) => penetrationOf(view([...issued, p("EGRESS_RESPONDED", { status: 200 }), ...abort], { boundary: admitted, app })).deepest;
  assert.equal(deepest([a("APP_ADMITTED")]), "app_admitted");
  assert.equal(deepest([a("APP_ADMITTED"), a("APP_EXECUTED")]), "app_executed");
  assert.equal(deepest([a("APP_ADMITTED"), a("APP_EXECUTED"), a("APP_MUTATED")]), "app_mutated");
});

test("a composition without L2 still yields a penetration record (the reference arm): L2 is `not_reached`, not skipped", () => {
  const legacy: LifecycleView = { ...view([p("INGRESS_ACCEPTED"), p("L1_ENTERED"), p("L1_PASSED"), p("EGRESS_ATTEMPTED"), p("PROOF_ISSUED", { pbTag: "pb" }), p("EGRESS_RESPONDED", { status: 200 }), p("INGRESS_RESPONDED", { status: 200 })], { boundary: chain().boundary, app: chain().app }), l2: undefined };
  const record = penetrationOf(legacy);
  assert.deepEqual([record.l1, record.l2, record.deepest], ["natural_pass", "not_reached", "app_mutated"]);
});

test("the L2 automaton: exactly one decision per entry, no decision-less egress, and an L2 event is a violation in a Slice-1/2 view", () => {
  const ok = [...base(), unverifiedAdmitted(), p("EGRESS_ATTEMPTED"), p("EGRESS_RESPONDED", { status: 200 }), p("INGRESS_RESPONDED", { status: 200 })];
  assert.deepEqual(validateLifecycle(view(ok), false).filter((anomaly) => anomaly.code !== "origin_without_l1_pass"), []);
  const doubled = [...base(), unverifiedAdmitted(), unverifiedAdmitted(), p("EGRESS_ATTEMPTED"), p("EGRESS_RESPONDED", { status: 200 }), p("INGRESS_RESPONDED", { status: 200 })];
  assert.ok(validateLifecycle(view(doubled), false).some((anomaly) => anomaly.code === "duplicate_event" || anomaly.code === "duplicate_terminal" || anomaly.code === "impossible_order"));
  const noDecision = [...base(), p("EGRESS_ATTEMPTED"), p("EGRESS_RESPONDED", { status: 200 }), p("INGRESS_RESPONDED", { status: 200 })];
  assert.ok(validateLifecycle(view(noDecision), false).length > 0);
  assert.ok(validateLifecycle({ ...view(ok), l2: undefined }, false).length > 0, "a Slice-1/2 view has no L2 stage");
  const undecided = [...base(), p("INGRESS_RESPONDED", { status: 503 })];
  assert.ok(validateLifecycle(view(undecided), true).some((anomaly) => anomaly.code === "missing_transition" || anomaly.code === "disappeared_after_ingress" || anomaly.code === "impossible_order"));
});

test("L2 decision rules: the matrix, refused-but-egressed, credit tags, bucket fields, spent/touched, basis/shadow, and enrollment", () => {
  const codes = (plane: PlaneEvent[]) => validateL2Lifecycle(view(plane), true).map((anomaly) => `${anomaly.code}:${anomaly.detail}`);
  const tail = [p("EGRESS_ATTEMPTED"), p("EGRESS_RESPONDED", { status: 200 }), p("INGRESS_RESPONDED", { status: 200 })];
  assert.deepEqual(codes([...base(), unverifiedAdmitted(), ...tail]), []);
  assert.ok(codes([...base(), p("L2_DECIDED", { class: "open", lane: "credited", outcome: "admitted" }), ...tail]).some((c) => c.startsWith("l2_decision_invalid")), "an open class cannot be credited");
  assert.ok(codes([...base(), p("L2_DECIDED", { class: "mutation", lane: "credited", outcome: "degraded", dt: 1, lvl: 1, lseq: 1 }), ...tail]).some((c) => c.startsWith("l2_decision_invalid")), "a mutation never degrades");
  assert.ok(codes([...base(), p("L2_DECIDED", { class: "mutation", lane: "credited", outcome: "admitted", dt: 1, lvl: 1, lseq: 1 }), ...tail]).some((c) => c.includes("credit tag")), "a credited admission carries its tag");
  assert.ok(codes([...base(), p("L2_DECIDED", { class: "mutation", lane: "unverified", outcome: "admitted" }), ...tail]).some((c) => c.includes("without clock")), "a bucket decision carries the bucket's clock, level and number");
  assert.ok(codes([...base(), p("L2_DECIDED", { class: "mutation", lane: "unverified", outcome: "shed", shedReason: "lane_budget", dt: 1, lvl: 0, lseq: 1 }), ...tail]).some((c) => c.startsWith("l2_refused_but_egressed")), "a shed request never goes to egress");
  assert.ok(codes([...base(), p("L2_DECIDED", { class: "mutation", lane: null, outcome: "error", l2ErrorKind: "throw" }), ...tail]).some((c) => c.startsWith("l2_refused_but_egressed")));
  assert.ok(codes([...base(), unverifiedAdmitted({ spent: "unverified" }), ...tail]).some((c) => c.includes("spent or touched")), "spent/touched only on a discarded decision");
  assert.ok(codes([...base(), unverifiedAdmitted({ basis: "simulated" }), ...tail]).some((c) => c.includes("basis and shadow")), "a simulated label always carries the shadow");

  const open = (extra: Partial<PlaneEvent> = {}) => p("L2_DECIDED", { class: "open", lane: "open", outcome: "admitted", ...extra });
  const afterResponse = (...events: PlaneEvent[]) => [...base(), open(), p("EGRESS_ATTEMPTED"), p("EGRESS_RESPONDED", { status: 200 }), ...events, p("INGRESS_RESPONDED", { status: 200 })];
  assert.deepEqual(codes(afterResponse(p("L2_ENROLLED", { creditTag: "tag0000000000000", fill: [7, 0] }))), []);
  assert.ok(codes(afterResponse(p("L2_ENROLLED", { creditTag: "t", fill: [1, 0] }), p("L2_ENROLL_SKIPPED", { skipReason: "already_enrolled" }))).some((c) => c.includes("more than one disposition")), "two dispositions");
  assert.ok(validateL2Lifecycle(view(afterResponse(p("L2_ENROLL_SKIPPED", { skipReason: "degraded" }))), true).some((anomaly) => anomaly.detail.includes("degraded skip")), "a degraded skip needs a degraded decision");
  assert.ok(validateL2Lifecycle(view(afterResponse(p("L2_ENROLL_SKIPPED", { skipReason: "simulated" }))), true).some((anomaly) => anomaly.detail.includes("simulated skip")));
  const degradedEnrolled = [...base(), p("L2_DECIDED", { class: "open", lane: "open", outcome: "degraded" }), p("EGRESS_ATTEMPTED"), p("EGRESS_RESPONDED", { status: 200 }), p("L2_ENROLLED", { creditTag: "tag0000000000000", fill: [7, 0] }), p("INGRESS_RESPONDED", { status: 200 })];
  assert.ok(codes(degradedEnrolled).some((c) => c.includes("degraded or simulated")), "a degraded render can never enroll");
  const forPost = [...base(), unverifiedAdmitted(), p("EGRESS_ATTEMPTED"), p("EGRESS_RESPONDED", { status: 200 }), p("L2_ENROLL_SKIPPED", { skipReason: "status_not_200" }), p("INGRESS_RESPONDED", { status: 200 })];
  assert.ok(codes(forPost).some((c) => c.includes("not an admitted open render")), "only a render has an enrollment disposition");
});
