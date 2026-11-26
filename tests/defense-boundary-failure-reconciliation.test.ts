/**
 * Reconciliation of a request whose protected application was never reached.
 *
 * GCP Rehearsal 02 found that the lifecycle validator demanded ORIGIN_RECEIVED for every plane EGRESS_RESPONDED, including the response the
 * Origin Boundary itself generates after a refused connection to a stopped application. The retained rows below are the verbatim ledger
 * records of that rehearsal (see tests/fixtures/field-rehearsal-02/provenance.json, which also keeps the ORIGINAL field verdict: the
 * correction does not rewrite it). The correction accepts a missing origin receipt only when the boundary's own recorded evidence proves the
 * application was never reached; every other combination stays anomalous. These tests pin both halves.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { validateL2Lifecycle } from "../defense/core/l2-lifecycle";
import { validateLifecycle, type AppEvent, type BoundaryEvent, type HarnessEvent, type LifecycleView, type OriginEvent, type PlaneEvent } from "../defense/core/ledger";
import { protectedLineageComplete, validateOriginLineage } from "../defense/core/lineage";

type Rec = {
  rid: string; nonce: string; meta: { lane: LifecycleView["expected"]; scenario: string };
  harness: HarnessEvent[]; plane: PlaneEvent[]; origin: OriginEvent[]; boundary: BoundaryEvent[]; app: AppEvent[];
};
type Row = { round: string; record: Rec };

const FIXTURES = path.join(__dirname, "fixtures", "field-rehearsal-02");
const rows: Row[] = readFileSync(path.join(FIXTURES, "ledger-rows.jsonl"), "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line) as Row);
const provenance = JSON.parse(readFileSync(path.join(FIXTURES, "provenance.json"), "utf8")) as {
  source: { fileSha256: string }; rounds: string[]; rowCount: number; originalFieldVerdict: Record<string, { anomalyTotal: number; anomalies: { code: string; detail: string }[] }>;
};

const pick = (round: string, scenario: string, index = 0): Rec => structuredClone(rows.filter((row) => row.round === round && row.record.meta.scenario === scenario)[index].record);

/** The collector's own pure mapping from application events to the legacy origin events (lab/defense/collector.ts, ingestAppFrame). */
function deriveOrigin(record: Rec): OriginEvent[] {
  const origin: OriginEvent[] = [];
  for (const event of record.app) {
    if (event.kind === "APP_ADMITTED") origin.push({ instance: "protected", nonce: record.nonce, kind: "ORIGIN_RECEIVED", hop: event.hop ?? null, spoofed: event.spoofed ?? 0 });
    else if (event.kind === "APP_COMPLETED") origin.push({ instance: "protected", nonce: record.nonce, kind: "ORIGIN_COMPLETED", hop: event.hop ?? null, status: event.status });
    else if (event.kind === "APP_ABORTED") origin.push({ instance: "protected", nonce: record.nonce, kind: "ORIGIN_ABORTED", hop: event.hop ?? null });
  }
  return origin;
}

/** The three validators the collector runs at finalization, over the record exactly as the collector builds its view. */
function viewOf(record: Rec, over: Partial<LifecycleView> = {}): LifecycleView {
  return { nonce: record.nonce, expected: record.meta.lane, harness: record.harness, plane: record.plane, origin: deriveOrigin(record), boundary: record.boundary, app: record.app, l2: true, ...over };
}
function verdict(record: Rec, over: Partial<LifecycleView> = {}): string[] {
  const view = viewOf(record, over);
  const found = [...validateLifecycle(view, true), ...validateOriginLineage(view, true), ...(view.l2 === true ? validateL2Lifecycle(view, true) : [])];
  return found.map((anomaly) => `${anomaly.code}:${anomaly.detail}`);
}
const MISSING_ORIGIN = "missing_transition:ORIGIN_RECEIVED";

const boundaryOf = (record: Rec, kind: BoundaryEvent["kind"]): BoundaryEvent => {
  const event = record.boundary.find((candidate) => candidate.kind === kind);
  assert(event, kind);
  return event;
};
const planeOf = (record: Rec, kind: PlaneEvent["kind"]): PlaneEvent => {
  const event = record.plane.find((candidate) => candidate.kind === kind);
  assert(event, kind);
  return event;
};
/** Rewrites every status the lifecycle compares, so only the intended difference remains. */
function restatus(record: Rec, status: number): void {
  for (const event of [...record.plane, ...record.boundary, ...record.app]) if (event.status !== undefined) event.status = status;
  for (const event of record.harness) if (event.status !== undefined) event.status = status;
}

test("the fixture is the verbatim retained evidence and keeps the original field verdict", () => {
  assert.equal(provenance.source.fileSha256, "3ef4e3f628a742a87b3a903f1f6e4d18e5cc5d06ce5d0c4cfe2076b215c733d1");
  assert.equal(rows.length, provenance.rowCount);
  assert.deepEqual([...new Set(rows.map((row) => row.round))], provenance.rounds);
  // The historical verdict is retained as observed: exactly the four application-down failures, two in each application-outage round.
  for (const [round, original] of Object.entries(provenance.originalFieldVerdict)) {
    const expected = round === "app-1" || round === "app-2" ? [{ code: "missing_transition", nonce: "r7", detail: "ORIGIN_RECEIVED" }, { code: "missing_transition", nonce: "r8", detail: "ORIGIN_RECEIVED" }] : [];
    assert.deepEqual(original.anomalies, expected, round);
    assert.equal(original.anomalyTotal, expected.length, round);
  }
});

test("replay of the retained rounds: the four application-down rows reconcile and nothing else changes", () => {
  const appDown = rows.filter((row) => row.record.meta.scenario === "app-down");
  assert.equal(appDown.length, 4);
  for (const { round, record } of rows) assert.deepEqual(verdict(structuredClone(record)), [], `${round}/${record.rid}/${record.meta.scenario}`);
  for (const { record } of appDown) {
    // The rows carry no application evidence at all: nothing is fabricated to make the reconciliation pass.
    assert.deepEqual(record.app, []);
    assert.deepEqual(record.origin, []);
    assert.deepEqual(deriveOrigin(record), []);
    assert.deepEqual(record.boundary.map((event) => event.kind), ["BOUNDARY_ARRIVED", "BOUNDARY_ADMITTED", "APP_PROOF_ISSUED", "BOUNDARY_FORWARDED", "BOUNDARY_FORWARD_FAILED", "BOUNDARY_RESPONDED"]);
    assert.equal(boundaryOf(record, "BOUNDARY_FORWARD_FAILED").forwardError, "refused");
  }
});

test("healthy protected requests, restoration and the synthetic-origin control keep complete lineage", () => {
  for (const { round, record } of rows) {
    if (!["page", "client-facts"].includes(record.meta.scenario)) continue;
    assert.deepEqual(record.app.map((event) => event.kind), ["APP_ADMITTED", "APP_EXECUTED", "APP_COMPLETED"], `${round}/${record.rid}`);
    assert(protectedLineageComplete(viewOf(record)), `${round}/${record.rid}`);
  }
  assert(rows.some((row) => row.round === "restored" && row.record.meta.scenario === "page"));
  assert(rows.some((row) => row.round === "control" && row.record.meta.scenario === "page"));
  // Removing the application's evidence from a healthy request is still detected: the correction did not loosen the normal path.
  const noApp = pick("app-1", "page");
  noApp.app = [];
  assert(verdict(noApp).includes(MISSING_ORIGIN));
  const noCompletion = pick("app-1", "page");
  noCompletion.app = noCompletion.app.filter((event) => event.kind !== "APP_COMPLETED");
  assert(verdict(noCompletion).includes("missing_transition:ORIGIN_COMPLETED"));
});

test("an unavailable boundary keeps its existing behaviour: plane EGRESS_FAILED, nothing downstream, no anomaly", () => {
  const down = rows.filter((row) => row.record.meta.scenario === "boundary-down");
  assert.equal(down.length, 2);
  for (const { record } of down) {
    assert.equal(planeOf(record, "EGRESS_FAILED").egressError, "refused");
    assert.deepEqual([record.boundary, record.app, record.origin], [[], [], []]);
    assert.deepEqual(verdict(structuredClone(record)), []);
  }
});

test("the exemption is decided from the boundary's evidence, never from the HTTP status", () => {
  const broken: [string, (record: Rec) => void][] = [
    ["a reset forward is not proof the application was never reached", (record) => { boundaryOf(record, "BOUNDARY_FORWARD_FAILED").forwardError = "reset"; }],
    ["a timed-out forward is not proof either", (record) => { boundaryOf(record, "BOUNDARY_FORWARD_FAILED").forwardError = "timeout"; restatus(record, 504); }],
    ["an unclassified forward error is not proof either", (record) => { boundaryOf(record, "BOUNDARY_FORWARD_FAILED").forwardError = "error"; }],
    ["a 502 the boundary RELAYED from an upstream response is not its own failure", (record) => {
      const failed = boundaryOf(record, "BOUNDARY_FORWARD_FAILED");
      failed.kind = "BOUNDARY_FORWARD_RESPONDED"; failed.status = 502; delete failed.forwardError;
    }],
    ["a boundary answer that differs from the plane's is contradictory", (record) => { boundaryOf(record, "BOUNDARY_RESPONDED").status = 503; }],
    ["a refused forward that the boundary did not answer with 502 is contradictory", (record) => { restatus(record, 503); }],
    ["a boundary that never admitted the plane's hop is not evidence", (record) => { record.boundary = record.boundary.filter((event) => event.kind !== "BOUNDARY_ADMITTED"); }],
    ["an admission for another hop does not count", (record) => { boundaryOf(record, "BOUNDARY_ADMITTED").hop = 99_999; }],
    ["an admission for another proof does not count", (record) => { boundaryOf(record, "BOUNDARY_ADMITTED").pbTag = "AAAAAAAAAAAAAAAA"; }],
    ["a missing boundary record leaves the missing receipt unexplained", (record) => { record.boundary = []; }],
    ["a boundary that never recorded its answer is incomplete", (record) => { record.boundary = record.boundary.filter((event) => event.kind !== "BOUNDARY_RESPONDED"); }],
    ["a boundary that aborted instead of answering is not a recorded answer", (record) => { boundaryOf(record, "BOUNDARY_RESPONDED").kind = "BOUNDARY_ABORTED"; }],
    ["a duplicated forward failure is contradictory", (record) => {
      const failed = boundaryOf(record, "BOUNDARY_FORWARD_FAILED");
      record.boundary.splice(record.boundary.indexOf(failed) + 1, 0, { ...failed, seq: failed.seq + 0.5 });
    }],
    ["any application event means the application was reached", (record) => {
      record.app = [{ seq: 1, t: 0, nonce: record.nonce, kind: "APP_REFUSED", reason: "ob.proof_missing" }];
    }],
  ];
  for (const [title, mutate] of broken) {
    const record = pick("app-1", "app-down");
    assert.deepEqual(verdict(structuredClone(record)), [], "control: the unmodified row reconciles");
    mutate(record);
    assert(verdict(record).includes(MISSING_ORIGIN), title);
  }
});

test("without the hop-gate streams (the Slice-1 shape) a missing origin receipt is never explained away", () => {
  const record = pick("app-1", "app-down");
  assert(validateLifecycle(viewOf(record, { boundary: undefined, app: undefined }), true).some((anomaly) => anomaly.code === "missing_transition" && anomaly.detail === "ORIGIN_RECEIVED"));
  assert(validateLifecycle(viewOf(record, { app: undefined }), true).some((anomaly) => anomaly.detail === "ORIGIN_RECEIVED"));
  assert(validateLifecycle(viewOf(record, { boundary: undefined }), true).some((anomaly) => anomaly.detail === "ORIGIN_RECEIVED"));
});

test("an application-generated error keeps its application evidence requirement, even when the status is 502", () => {
  // The application answered 404 for a path outside the page list: complete application evidence, no anomaly.
  assert.deepEqual(verdict(pick("app-1", "outside-page-list")), []);
  // The application itself answering 502 (relayed by the boundary) is clean with complete application evidence ...
  const appGenerated = pick("app-1", "page");
  restatus(appGenerated, 502);
  assert.deepEqual(verdict(appGenerated), []);
  // ... and anomalous without it: a 502 is never accepted on its status.
  const missingApp = structuredClone(appGenerated);
  missingApp.app = [];
  const codes = verdict(missingApp);
  assert(codes.includes(MISSING_ORIGIN));
  assert(codes.includes("missing_transition:APP_ADMITTED"));
  // Application evidence that stops before completion stays visible.
  const unfinished = structuredClone(appGenerated);
  unfinished.app = unfinished.app.filter((event) => event.kind !== "APP_COMPLETED");
  const unfinishedCodes = verdict(unfinished);
  assert(unfinishedCodes.includes("missing_transition:ORIGIN_COMPLETED"));
  assert(unfinishedCodes.includes("unresolved_at_finalization:app"));
});

test("contradictory or incomplete evidence stays anomalous", () => {
  // The boundary says the connection was refused, yet an application admitted and completed the request with another status.
  const contradictory = pick("app-1", "app-down");
  const attempted = planeOf(contradictory, "EGRESS_ATTEMPTED");
  const pbTag = planeOf(contradictory, "PROOF_ISSUED").pbTag;
  const baTag = boundaryOf(contradictory, "APP_PROOF_ISSUED").baTag;
  contradictory.app = [
    { seq: 1, t: 0, nonce: contradictory.nonce, kind: "APP_ADMITTED", hop: attempted.seq, pbTag, baTag, spoofed: 0 },
    { seq: 2, t: 0, nonce: contradictory.nonce, kind: "APP_COMPLETED", hop: attempted.seq, pbTag, baTag, status: 200 },
  ];
  assert(verdict(contradictory).some((code) => code.startsWith("origin_status_mismatch")));
  // The boundary's record stops after forwarding: no failure, no answer.
  const truncated = pick("app-1", "app-down");
  truncated.boundary = truncated.boundary.filter((event) => !["BOUNDARY_FORWARD_FAILED", "BOUNDARY_RESPONDED"].includes(event.kind));
  const codes = verdict(truncated);
  assert(codes.includes(MISSING_ORIGIN));
  assert(codes.includes("unresolved_at_finalization:boundary"));
  // The client saw something other than the boundary's failure response.
  const clientMismatch = pick("app-1", "app-down");
  clientMismatch.harness.find((event) => event.kind === "CLIENT_COMPLETED")!.status = 200;
  assert(verdict(clientMismatch).some((code) => code.startsWith("client_status_mismatch")));
  // The plane relays a different status than the one its own egress event recorded.
  const planeMismatch = pick("app-1", "app-down");
  planeOf(planeMismatch, "INGRESS_RESPONDED").status = 200;
  assert(verdict(planeMismatch).some((code) => code.startsWith("plane_status_mismatch")));
});

test("application termination after admission is never a clean completion", () => {
  const forwardReset = (terminal: "none" | "aborted"): Rec => {
    const record = pick("app-1", "app-down");
    boundaryOf(record, "BOUNDARY_FORWARD_FAILED").forwardError = "reset";
    const attempted = planeOf(record, "EGRESS_ATTEMPTED");
    const pbTag = planeOf(record, "PROOF_ISSUED").pbTag;
    const baTag = boundaryOf(record, "APP_PROOF_ISSUED").baTag;
    const base = { t: 0, nonce: record.nonce, hop: attempted.seq, pbTag, baTag };
    record.app = [{ ...base, seq: 1, kind: "APP_ADMITTED", spoofed: 0 }, { ...base, seq: 2, kind: "APP_EXECUTED" }];
    if (terminal === "aborted") record.app.push({ ...base, seq: 3, kind: "APP_ABORTED" });
    return record;
  };
  // Killed mid-request: the application never reports a terminal event.
  const killed = forwardReset("none");
  assert.deepEqual(deriveOrigin(killed).map((event) => event.kind), ["ORIGIN_RECEIVED"]);
  const killedCodes = verdict(killed);
  assert(killedCodes.includes("missing_transition:ORIGIN_COMPLETED"));
  assert(killedCodes.includes("unresolved_at_finalization:app"));
  // An application that reports its own abort is accounted as an abort, never as ORIGIN_COMPLETED.
  const aborted = forwardReset("aborted");
  assert.deepEqual(deriveOrigin(aborted).map((event) => event.kind), ["ORIGIN_RECEIVED", "ORIGIN_ABORTED"]);
  assert(!deriveOrigin(aborted).some((event) => event.kind === "ORIGIN_COMPLETED"));
});

test("a Slice-2 composition without L2 reconciles the same way", () => {
  const record = pick("app-1", "app-down");
  record.plane = record.plane.filter((event) => !event.kind.startsWith("L2_"));
  assert.deepEqual(verdict(record, { l2: false }), []);
  boundaryOf(record, "BOUNDARY_FORWARD_FAILED").forwardError = "reset";
  assert(verdict(record, { l2: false }).includes(MISSING_ORIGIN));
});

test("the external lane is judged by the same rule", () => {
  const record = pick("app-1", "app-down");
  planeOf(record, "INGRESS_ACCEPTED").ingress = "external";
  const external = (mutate?: (copy: Rec) => void): string[] => {
    const copy = structuredClone(record);
    mutate?.(copy);
    // As lab/defense/external-reducer.ts does: the lifecycle is judged as external, the lineage as the protected chain it is.
    const view = viewOf(copy, { expected: "external", harness: [] });
    return [...validateLifecycle(view, true), ...validateOriginLineage({ ...view, expected: "protected" }, true), ...validateL2Lifecycle(view, true)].map((anomaly) => `${anomaly.code}:${anomaly.detail}`);
  };
  assert.deepEqual(external(), []);
  assert(external((copy) => { boundaryOf(copy, "BOUNDARY_FORWARD_FAILED").forwardError = "timeout"; }).includes(MISSING_ORIGIN));
  assert(external((copy) => { copy.boundary = []; }).includes(MISSING_ORIGIN));
});

test("the legacy synthetic-origin shape (plane and origin events only) is unchanged", () => {
  const record = pick("app-1", "page");
  const legacy = (origin: OriginEvent[], status: number): string[] => {
    const copy = structuredClone(record);
    restatus(copy, status);
    return validateLifecycle(viewOf(copy, { boundary: undefined, app: undefined, origin, l2: true }), true).map((anomaly) => `${anomaly.code}:${anomaly.detail}`);
  };
  const hop = planeOf(record, "EGRESS_ATTEMPTED").seq;
  const received: OriginEvent = { instance: "protected", nonce: record.nonce, kind: "ORIGIN_RECEIVED", hop, spoofed: 0 };
  assert.deepEqual(legacy([received, { instance: "protected", nonce: record.nonce, kind: "ORIGIN_COMPLETED", hop, status: 502 }], 502), []);
  assert(legacy([], 502).includes(MISSING_ORIGIN));
  assert(legacy([], 200).includes(MISSING_ORIGIN));
});
