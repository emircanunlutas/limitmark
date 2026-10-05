import assert from "node:assert/strict";
import { test } from "node:test";
import {
  BoundedEventChannel, terminalOutcome, validateLifecycle, type EventFrame, type HarnessEvent, type LifecycleView, type OriginEvent, type PlaneEvent,
} from "../defense/core/ledger";

let seq = 0;
const plane = (kind: PlaneEvent["kind"], extra: Partial<PlaneEvent> = {}): PlaneEvent => ({ seq: ++seq, nonce: "n", kind, t: 0, ...extra });
const harness = (completed = true, status = 200, outcomeHeader?: string): HarnessEvent[] => [{ kind: "SENT" }, ...(completed ? [{ kind: "CLIENT_COMPLETED" as const, result: "response" as const, status, outcomeHeader }] : [])];
const originEvents = (hop: number | null, status = 200, instance: "protected" | "control" = "protected"): OriginEvent[] => [
  { instance, nonce: "n", kind: "ORIGIN_RECEIVED", hop, spoofed: 0 }, { instance, nonce: "n", kind: "ORIGIN_COMPLETED", hop, status },
];

function goodProxied(): { events: PlaneEvent[]; hop: number } {
  const events = [plane("INGRESS_ACCEPTED", { stripped: 0 }), plane("L1_ENTERED"), plane("L1_PASSED")];
  const attempted = plane("EGRESS_ATTEMPTED");
  events.push(attempted, plane("EGRESS_RESPONDED", { status: 200 }), plane("INGRESS_RESPONDED", { status: 200 }));
  return { events, hop: attempted.seq };
}
const view = (overrides: Partial<LifecycleView>): LifecycleView => ({ nonce: "n", expected: "protected", harness: harness(), plane: [], origin: [], ...overrides });
const codes = (v: LifecycleView, final = true) => validateLifecycle(v, final).map((anomaly) => anomaly.code);

test("a complete protected lifecycle (SENT .. CLIENT_COMPLETED, origin reconciled by hop) has no anomaly", () => {
  const { events, hop } = goodProxied();
  assert.deepEqual(codes(view({ plane: events, origin: originEvents(hop), harness: harness(true, 200, "proxied") })), []);
  assert.equal(terminalOutcome(events), "proxied");
});

test("a rejected lifecycle is complete without egress or origin events", () => {
  const events = [plane("INGRESS_ACCEPTED"), plane("L1_ENTERED"), plane("L1_REJECTED", { reason: "a7.path_not_allowed", stage: "pre_parse" }), plane("INGRESS_RESPONDED", { status: 404 })];
  assert.deepEqual(codes(view({ plane: events, harness: harness(true, 404, "rejected") })), []);
  assert.equal(terminalOutcome(events), "rejected");
});

test("L1 error and shed are terminal, fail-closed lifecycles (503) that never reach egress", () => {
  for (const make of [() => plane("L1_ERROR", { errorKind: "throw" }), () => plane("L1_SHED")]) {
    const events = [plane("INGRESS_ACCEPTED"), plane("L1_ENTERED"), make(), plane("INGRESS_RESPONDED", { status: 503 })];
    assert.deepEqual(codes(view({ plane: events, harness: harness(true, 503) })), []);
    const leaked = [plane("INGRESS_ACCEPTED"), plane("L1_ENTERED"), make(), plane("EGRESS_ATTEMPTED"), plane("EGRESS_RESPONDED", { status: 200 }), plane("INGRESS_RESPONDED", { status: 200 })];
    assert.ok(codes(view({ plane: leaked })).length > 0, "an error or shed followed by egress (error became a pass) is flagged");
  }
});

test("duplicate terminal processing is detected (two responses, two verdicts, two client completions)", () => {
  const { events, hop } = goodProxied();
  assert.ok(codes(view({ plane: [...events, plane("INGRESS_RESPONDED", { status: 200 })], origin: originEvents(hop) })).includes("duplicate_terminal"));
  const twoVerdicts = [plane("INGRESS_ACCEPTED"), plane("L1_ENTERED"), plane("L1_PASSED"), plane("L1_REJECTED", { reason: "a7.path_not_allowed" })];
  assert.ok(codes(view({ plane: twoVerdicts })).includes("duplicate_terminal"));
  assert.ok(codes(view({ plane: events, origin: originEvents(hop), harness: [...harness(), { kind: "CLIENT_COMPLETED", result: "response", status: 200 }] })).includes("duplicate_terminal"));
});

test("missing transitions are detected (a verdict without L1_ENTERED; a pass that skips egress)", () => {
  assert.ok(codes(view({ plane: [plane("INGRESS_ACCEPTED"), plane("L1_PASSED"), plane("EGRESS_ATTEMPTED"), plane("EGRESS_RESPONDED", { status: 200 }), plane("INGRESS_RESPONDED", { status: 200 })] })).includes("missing_transition"));
  assert.ok(codes(view({ plane: [plane("INGRESS_ACCEPTED"), plane("L1_ENTERED"), plane("L1_PASSED"), plane("INGRESS_RESPONDED", { status: 200 })] })).includes("missing_transition"));
});

test("impossible order is detected", () => {
  assert.ok(codes(view({ plane: [plane("L1_ENTERED"), plane("INGRESS_ACCEPTED")] })).includes("impossible_order"));
  const out: PlaneEvent[] = [plane("INGRESS_ACCEPTED"), plane("L1_ENTERED"), plane("L1_PASSED")];
  out.push({ ...plane("EGRESS_ATTEMPTED"), seq: out[0].seq });
  assert.ok(codes(view({ plane: out })).includes("impossible_order"), "a non-increasing sequence is an impossible order");
  assert.ok(codes(view({ plane: [], origin: [{ instance: "protected", nonce: "n", kind: "ORIGIN_COMPLETED", hop: 1, status: 200 }] }), false).includes("impossible_order"), "completion before receipt");
});

test("a request disappearing after ingress, and unresolved in-flight work at finalization, are detected", () => {
  const stuck = [plane("INGRESS_ACCEPTED"), plane("L1_ENTERED")];
  const found = codes(view({ plane: stuck }));
  assert.ok(found.includes("disappeared_after_ingress"));
  assert.ok(found.includes("unresolved_at_finalization"));
  assert.ok(!codes(view({ plane: stuck }), false).includes("disappeared_after_ingress"), "not final yet: still in flight");
  assert.ok(codes(view({ plane: [] })).includes("ingress_loss"));
  assert.ok(codes(view({ plane: [], harness: harness(false) })).includes("sent_without_completion"));
});

test("duplicate origin processing and an origin receipt with no L1 pass behind it (bypass) are detected", () => {
  const { events, hop } = goodProxied();
  assert.ok(codes(view({ plane: events, origin: [...originEvents(hop), { instance: "protected", nonce: "n", kind: "ORIGIN_RECEIVED", hop, spoofed: 0 }] })).includes("duplicate_origin_processing"));
  const rejected = [plane("INGRESS_ACCEPTED"), plane("L1_ENTERED"), plane("L1_REJECTED", { reason: "a7.path_not_allowed" }), plane("INGRESS_RESPONDED", { status: 404 })];
  assert.ok(codes(view({ plane: rejected, origin: originEvents(null, 200), harness: harness(true, 404) })).includes("origin_without_l1_pass"));
  const preIngress = codes(view({ expected: "pre_ingress", plane: [], origin: originEvents(null) }));
  assert.ok(preIngress.includes("origin_without_l1_pass"));
});

test("origin and plane must agree: hop, status, and what the client saw", () => {
  const { events, hop } = goodProxied();
  assert.ok(codes(view({ plane: events, origin: originEvents(hop + 99) })).includes("origin_hop_mismatch"));
  assert.ok(codes(view({ plane: events, origin: originEvents(hop, 500) })).includes("origin_status_mismatch"));
  assert.ok(codes(view({ plane: events, origin: originEvents(hop), harness: harness(true, 502) })).includes("client_status_mismatch"));
  assert.ok(codes(view({ plane: events, origin: originEvents(hop), harness: harness(true, 200, "rejected") })).includes("outcome_header_mismatch"));
  const wrongStatus = [plane("INGRESS_ACCEPTED"), plane("L1_ENTERED"), plane("L1_REJECTED", { reason: "a7.path_not_allowed" }), plane("INGRESS_RESPONDED", { status: 200 })];
  assert.ok(codes(view({ plane: wrongStatus, harness: harness(true, 200) })).includes("plane_status_mismatch"));
});

test("egress failures are attributed separately and need no origin receipt; an origin that DID receive is still reconciled", () => {
  for (const [egressError, status] of [["refused", 502], ["reset", 502], ["timeout", 504]] as const) {
    const events: PlaneEvent[] = [];
    for (const kind of ["INGRESS_ACCEPTED", "L1_ENTERED", "L1_PASSED", "EGRESS_ATTEMPTED"] as const) events.push(plane(kind));
    events.push(plane("EGRESS_FAILED", { egressError }), plane("INGRESS_RESPONDED", { status }));
    assert.deepEqual(codes(view({ plane: events, harness: harness(true, status, "egress_failed") })), [], egressError);
    assert.equal(terminalOutcome(events), "egress_failed");
  }
  const failedAfterReceipt: PlaneEvent[] = [plane("INGRESS_ACCEPTED"), plane("L1_ENTERED"), plane("L1_PASSED")];
  const attempted = plane("EGRESS_ATTEMPTED");
  failedAfterReceipt.push(attempted, plane("EGRESS_FAILED", { egressError: "timeout" }), plane("INGRESS_RESPONDED", { status: 504 }));
  assert.deepEqual(codes(view({ plane: failedAfterReceipt, origin: originEvents(attempted.seq), harness: harness(true, 504, "egress_failed") })), []);
});

test("control lane: origin only, and any plane event there is an anomaly", () => {
  assert.deepEqual(codes(view({ expected: "control", plane: [], origin: originEvents(null, 200, "control") })), []);
  assert.ok(codes(view({ expected: "control", plane: [plane("INGRESS_ACCEPTED")], origin: originEvents(null, 200, "control") })).includes("plane_event_on_unexpected_lane"));
  assert.ok(codes(view({ expected: "control", plane: [], origin: originEvents(null, 200, "protected") })).includes("origin_lane_mismatch"));
  assert.ok(codes(view({ expected: "control", plane: [], origin: [] })).includes("missing_transition"));
});

test("a spoofable header reaching the origin and an uncorrelated (minted) nonce are anomalies", () => {
  const { events, hop } = goodProxied();
  const spoofed = originEvents(hop); spoofed[0] = { ...spoofed[0], spoofed: 2 };
  assert.ok(codes(view({ plane: events, origin: spoofed })).includes("origin_spoofed_header_seen"));
  const minted = [{ ...events[0], uncorrelated: true }, ...events.slice(1)];
  assert.ok(codes(view({ plane: minted, origin: originEvents(hop) })).includes("uncorrelated_ingress"));
});

// ---- bounded event channel

function channel(options: ConstructorParameters<typeof BoundedEventChannel>[1]) {
  const frames: EventFrame[] = [];
  return { frames, channel: new BoundedEventChannel({ send: (frame) => frames.push(frame) }, options) };
}

test("the event channel never grows past its bounds: overflow drops and counts, and consumes the sequence number so the gap is visible", () => {
  const { frames, channel: bounded } = channel({ queueCap: 10, windowCap: 5, maxFrameEvents: 5, flushIntervalMs: 1_000 });
  for (let index = 0; index < 1_000; index++) bounded.emit({ nonce: "n", kind: "INGRESS_ACCEPTED" });
  const stats = bounded.stats();
  assert.equal(stats.emitted, 1_000);
  assert.ok(stats.queueHighWater <= 10, `queue high water ${stats.queueHighWater}`);
  assert.ok(stats.unacknowledged <= 5);
  assert.equal(stats.dropped, 1_000 - stats.sent - stats.queued, "every emitted event is sent, queued or counted as dropped");
  assert.ok(stats.dropped > 900);
  const sentSeqs = frames.flatMap((frame) => frame.events.map((event) => event.seq));
  assert.ok(sentSeqs.length <= 5, "nothing beyond the window is sent without acknowledgements");
  assert.equal(stats.lastSeq, 1_000, "dropped events still consume a sequence number");
  // The drop count travels on the next frame once the window reopens, and the final sequence number exposes the loss even though
  // the dropped events were the newest ones (the sent sequence is gapless but stops short of lastSeq).
  bounded.acknowledge(frames.flatMap((frame) => frame.events).length);
  const later = frames.at(-1)!;
  assert.equal(later.dropped, stats.dropped, "frames carry the cumulative drop count");
  assert.ok(Math.max(...frames.flatMap((frame) => frame.events.map((event) => event.seq))) < stats.lastSeq);
});

test("acknowledgements open the window and the queue drains completely", async () => {
  const { frames, channel: bounded } = channel({ queueCap: 100, windowCap: 4, maxFrameEvents: 2, flushIntervalMs: 1 });
  for (let index = 0; index < 20; index++) bounded.emit({ nonce: "n", kind: "L1_ENTERED" });
  let received = 0;
  const pump = setInterval(() => { received = frames.reduce((total, frame) => total + frame.events.length, 0); bounded.acknowledge(received); }, 2);
  assert.equal(await bounded.drain(2_000), true);
  clearInterval(pump);
  const all = frames.flatMap((frame) => frame.events.map((event) => event.seq));
  assert.deepEqual(all, Array.from({ length: 20 }, (_, index) => index + 1), "in order, gapless, exactly once");
  assert.equal(bounded.stats().dropped, 0);
  assert.equal(bounded.stats().unacknowledged, 0);
});

test("drain reports false (not success) when the collector never acknowledges", async () => {
  const { channel: bounded } = channel({ queueCap: 10, windowCap: 2, flushIntervalMs: 1 });
  for (let index = 0; index < 5; index++) bounded.emit({ nonce: "n", kind: "L1_ENTERED" });
  assert.equal(await bounded.drain(60), false);
});

test("emit never throws or blocks even when the transport is unusable", () => {
  const bounded = new BoundedEventChannel({ send: () => undefined }, { queueCap: 2, windowCap: 1, flushIntervalMs: 1_000 });
  for (let index = 0; index < 50; index++) assert.doesNotThrow(() => bounded.emit({ nonce: "n", kind: "INGRESS_ACCEPTED" }));
});
