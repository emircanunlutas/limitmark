import assert from "node:assert/strict";
import http from "node:http";
import { test } from "node:test";
import type { HarnessEvent, OriginEvent, PlaneEvent } from "../defense/core/ledger";
import { validateLifecycle } from "../defense/core/ledger";
import { JourneyLanes, type LanesConfig } from "../defense/core/lanes";
import type { VerdictOverridePort } from "../defense/core/override-port";
import type { Layer, LayerVerdict } from "../defense/core/types";
import { createSyntheticOrigin } from "../defense/origin/synthetic-origin";
import { createFront } from "../defense/plane/front";
import { L2Stage } from "../defense/plane/l2-stage";

let counter = 0;
const nonce = () => `${String(++counter).padStart(22, "L")}`;
const TOKEN = /name="submissionToken" value="([A-Za-z0-9_-]{43})"/;

type Rig = Awaited<ReturnType<typeof rig>>;
async function rig(options: {
  config?: Partial<LanesConfig>; wrapLayer?: (layer: Layer) => Layer; stageComposer?: { timeoutMs?: number; maxConcurrent?: number };
  verdictOverride?: VerdictOverridePort; upstream?: http.Server; layer?: Layer; maxResponseBytes?: number; egressTimeoutMs?: number;
} = {}) {
  const planeEvents: PlaneEvent[] = [];
  const originEvents: OriginEvent[] = [];
  const origin = createSyntheticOrigin({ instance: "protected", onObservation: (event) => originEvents.push(event) });
  let upstreamPort = await origin.listen();
  if (options.upstream) await new Promise<void>((resolve) => options.upstream!.listen(0, "127.0.0.1", () => resolve()));
  if (options.upstream) upstreamPort = (options.upstream.address() as { port: number }).port;
  const lanes = new JourneyLanes({
    filterBits: 2 ** 14, filterHashes: 7, epochMs: 60_000, credited: { capacity: 8, refillPerSecond: 4 }, unverified: { capacity: 3, refillPerSecond: 0.001 },
    maxUses: 3, ledgerCapacity: 9_000, mono: () => performance.now(), key: Buffer.alloc(32, 3), ...options.config,
  });
  const stage = new L2Stage(lanes, { wrapLayer: options.wrapLayer, composer: options.stageComposer, maxResponseBytes: options.maxResponseBytes ?? 1_048_576 });
  let seq = 0;
  const front = createFront({
    upstream: { host: "127.0.0.1", port: upstreamPort }, l2: stage, verdictOverride: options.verdictOverride, layer: options.layer,
    emit: (event) => { const next = ++seq; planeEvents.push({ ...event, seq: next, t: 0 }); return next; },
    maxResponseBytes: options.maxResponseBytes, egressTimeoutMs: options.egressTimeoutMs,
  });
  const port = await front.listen();
  const eventsFor = (id: string) => planeEvents.filter((event) => event.nonce === id);
  return {
    origin, front, port, lanes, stage, planeEvents, originEvents, eventsFor,
    close: async () => { await front.close(500); await origin.close(); if (options.upstream) await new Promise<void>((resolve) => options.upstream!.close(() => resolve())); },
  };
}

type Reply = { status: number; headers: http.IncomingHttpHeaders; body: string };
function send(port: number, method: string, path: string, headers: Record<string, string> = {}, body?: string): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: "127.0.0.1", port, method, path, headers: { ...headers, ...(body !== undefined ? { "content-length": String(Buffer.byteLength(body)) } : {}) }, agent: false }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    request.on("error", reject);
    request.end(body);
  });
}
const kinds = (events: PlaneEvent[]) => events.map((event) => event.kind);
/** The second argument is the plane's port, kept so call sites read like the request they send; the body does not depend on it. */
const form = (token: string, port: number): string => {
  void port;
  return new URLSearchParams({ name: "Canary", email: "c@example.test", service: "web", system: "s", objective: "o", environment: "staging", authority: "authorized", submissionToken: token }).toString();
};
const postHeaders = (port: number, id: string) => ({ "x-ba0-nonce": id, "content-type": "application/x-www-form-urlencoded", origin: `http://127.0.0.1:${port}` });
const view = (r: Rig, id: string, reply: Reply): Parameters<typeof validateLifecycle>[0] => ({
  nonce: id, expected: "protected", l2: true, plane: r.eventsFor(id), origin: r.originEvents.filter((event) => event.nonce === id),
  harness: [{ kind: "SENT" }, { kind: "CLIENT_COMPLETED", result: "response", status: reply.status, outcomeHeader: reply.headers["x-ba0-outcome"] as string } as HarnessEvent],
});
const cleanly = (r: Rig, id: string, reply: Reply) => assert.deepEqual(validateLifecycle(view(r, id, reply), true), []);

test("a render then a POST: the full L2 lifecycle, the POST credited, and the ledger validates with the L2 automaton", async () => {
  const r = await rig();
  try {
    const renderId = nonce();
    const render = await send(r.port, "GET", "/test-talep-et", { "x-ba0-nonce": renderId });
    assert.equal(render.status, 200);
    assert.deepEqual(kinds(r.eventsFor(renderId)), ["INGRESS_ACCEPTED", "L1_ENTERED", "L1_PASSED", "L2_ENTERED", "L2_DECIDED", "EGRESS_ATTEMPTED", "EGRESS_RESPONDED", "L2_ENROLLED", "INGRESS_RESPONDED"]);
    const decided = r.eventsFor(renderId).find((event) => event.kind === "L2_DECIDED")!;
    assert.deepEqual([decided.class, decided.lane, decided.outcome], ["open", "open", "admitted"]);
    cleanly(r, renderId, render);

    const token = TOKEN.exec(render.body)![1];
    const postId = nonce();
    const post = await send(r.port, "POST", "/api/public-inquiries", postHeaders(r.port, postId), form(token, r.port));
    assert.equal(post.status, 200);
    const decision = r.eventsFor(postId).find((event) => event.kind === "L2_DECIDED")!;
    assert.deepEqual([decision.class, decision.lane, decision.outcome], ["mutation", "credited", "admitted"]);
    assert.equal(decision.creditTag, r.eventsFor(renderId).find((event) => event.kind === "L2_ENROLLED")!.creditTag, "the credited decision names the enrollment it consumed");
    assert.ok(decision.dt !== undefined && decision.lvl !== undefined && decision.lseq === 1);
    cleanly(r, postId, post);
  } finally { await r.close(); }
});

test("G2: for every legitimate render→POST, L2_ENROLLED precedes the POST's L2_DECIDED and the POST is credited: a real client that POSTs immediately, under injected event-loop stress", async () => {
  const r = await rig({ config: { epochMs: 10_000, credited: { capacity: 200, refillPerSecond: 100 } } });
  let stress = true;
  const stressLoop = () => { if (!stress) return; const end = performance.now() + 3; while (performance.now() < end) { /* block the loop */ } setImmediate(stressLoop); };
  setImmediate(stressLoop);
  try {
    for (let journey = 0; journey < 60; journey++) {
      const renderId = nonce();
      const render = await send(r.port, "GET", journey % 2 === 0 ? "/test-talep-et" : "/test-talep-et?hizmet=web", { "x-ba0-nonce": renderId });
      const token = TOKEN.exec(render.body)![1];
      const postId = nonce(); // POSTs the instant the response body has been read
      const post = await send(r.port, "POST", "/api/public-inquiries", postHeaders(r.port, postId), form(token, r.port));
      assert.equal(post.status, 200);
      const enrolled = r.eventsFor(renderId).find((event) => event.kind === "L2_ENROLLED");
      const decided = r.eventsFor(postId).find((event) => event.kind === "L2_DECIDED")!;
      assert.ok(enrolled, `journey ${journey}: the render was enrolled`);
      assert.ok(enrolled.seq < decided.seq, `journey ${journey}: enrollment ${enrolled.seq} precedes decision ${decided.seq}`);
      assert.equal(decided.lane, "credited", `journey ${journey}: the POST was credited`);
    }
    // concurrent journeys too: the whole batch is interleaved
    await Promise.all(Array.from({ length: 20 }, async () => {
      const renderId = nonce();
      const render = await send(r.port, "GET", "/test-talep-et", { "x-ba0-nonce": renderId });
      const postId = nonce();
      await send(r.port, "POST", "/api/public-inquiries", postHeaders(r.port, postId), form(TOKEN.exec(render.body)![1], r.port));
      const enrolled = r.eventsFor(renderId).find((event) => event.kind === "L2_ENROLLED");
      const decided = r.eventsFor(postId).find((event) => event.kind === "L2_DECIDED")!;
      assert.ok(enrolled && enrolled.seq < decided.seq && decided.lane === "credited");
    }));
  } finally { stress = false; await r.close(); }
});

test("a fabricated-token flood is bounded by the unverified bucket; the shed is a 503 `l2_shed`, never reaches the origin, and validates", async () => {
  const r = await rig();
  try {
    const replies: { id: string; reply: Reply }[] = [];
    for (let i = 0; i < 8; i++) {
      const id = nonce();
      replies.push({ id, reply: await send(r.port, "POST", "/api/public-inquiries", postHeaders(r.port, id), form("F".repeat(43), r.port)) });
    }
    assert.equal(replies.filter((entry) => entry.reply.status === 200).length, 3);
    const shed = replies.filter((entry) => entry.reply.status === 503);
    assert.equal(shed.length, 5);
    for (const { id, reply } of shed) {
      assert.equal(reply.headers["x-ba0-outcome"], "l2_shed");
      assert.deepEqual(kinds(r.eventsFor(id)), ["INGRESS_ACCEPTED", "L1_ENTERED", "L1_PASSED", "L2_ENTERED", "L2_DECIDED", "INGRESS_RESPONDED"]);
      const decided = r.eventsFor(id).find((event) => event.kind === "L2_DECIDED")!;
      assert.deepEqual([decided.lane, decided.outcome, decided.shedReason], ["unverified", "shed", "lane_budget"]);
      assert.equal(r.originEvents.filter((event) => event.nonce === id).length, 0, "a shed request never reached the origin");
      cleanly(r, id, reply);
    }
    assert.equal(r.lanes.snapshot().credited.takes, 0, "no credited decision was ever made for a never-enrolled token");
  } finally { await r.close(); }
});

test("P1 at the front: a credited shed answers 503 and the unverified lane is untouched", async () => {
  const r = await rig({ config: { credited: { capacity: 1, refillPerSecond: 0.001 } } });
  try {
    const tokens: string[] = [];
    for (let i = 0; i < 2; i++) tokens.push(TOKEN.exec((await send(r.port, "GET", "/test-talep-et", { "x-ba0-nonce": nonce() })).body)![1]);
    const first = await send(r.port, "POST", "/api/public-inquiries", postHeaders(r.port, nonce()), form(tokens[0], r.port));
    const id = nonce();
    const second = await send(r.port, "POST", "/api/public-inquiries", postHeaders(r.port, id), form(tokens[1], r.port));
    assert.equal(first.status, 200);
    assert.equal(second.status, 503);
    const decided = r.eventsFor(id).find((event) => event.kind === "L2_DECIDED")!;
    assert.deepEqual([decided.lane, decided.outcome, decided.shedReason], ["credited", "shed", "lane_budget"]);
    assert.equal(r.lanes.snapshot().unverified.takes, 0);
  } finally { await r.close(); }
});

test("failure matrix at the front: mutation fails CLOSED on L2 error, timeout and saturation; an open GET degrades, is explicit, enrolls nothing, and is never `admitted`", async () => {
  const throwing: Layer = { id: "a7.journey-lanes", evaluate: () => { throw new Error("boom"); } };
  const r = await rig({ wrapLayer: () => throwing });
  try {
    const id = nonce();
    const post = await send(r.port, "POST", "/api/public-inquiries", postHeaders(r.port, id), form("A".repeat(43), r.port));
    assert.equal(post.status, 503);
    assert.equal(post.headers["x-ba0-outcome"], "l2_error");
    const decided = r.eventsFor(id).find((event) => event.kind === "L2_DECIDED")!;
    assert.deepEqual([decided.class, decided.lane, decided.outcome, decided.l2ErrorKind], ["mutation", null, "error", "throw"]);
    assert.equal(r.originEvents.filter((event) => event.nonce === id).length, 0);
    cleanly(r, id, post);

    const renderId = nonce();
    const render = await send(r.port, "GET", "/test-talep-et", { "x-ba0-nonce": renderId });
    assert.equal(render.status, 200, "browsing survives a failed L2");
    const degraded = r.eventsFor(renderId).find((event) => event.kind === "L2_DECIDED")!;
    assert.deepEqual([degraded.class, degraded.lane, degraded.outcome], ["open", "open", "degraded"]);
    assert.deepEqual(kinds(r.eventsFor(renderId)).slice(-3), ["EGRESS_RESPONDED", "L2_ENROLL_SKIPPED", "INGRESS_RESPONDED"]);
    assert.equal(r.eventsFor(renderId).find((event) => event.kind === "L2_ENROLL_SKIPPED")!.skipReason, "degraded");
    cleanly(r, renderId, render);
    // The token the degraded render delivered earns no credit: a POST with it is simply unverified.
    const healthy = new L2Stage(r.lanes, { maxResponseBytes: 1_048_576 });
    assert.equal((await healthy.decide({ method: "POST", target: "/api/public-inquiries", headers: [], bodyStatus: "complete", body: Buffer.from(`submissionToken=${TOKEN.exec(render.body)![1]}`) })).lane, "unverified");
  } finally { await r.close(); }

  const hung = await rig({ wrapLayer: () => ({ id: "a7.journey-lanes", evaluate: () => new Promise<LayerVerdict>(() => undefined) }), stageComposer: { timeoutMs: 30, maxConcurrent: 1 } });
  try {
    const first = nonce(); const second = nonce();
    const timedOut = await send(hung.port, "POST", "/api/public-inquiries", postHeaders(hung.port, first), form("B".repeat(43), hung.port));
    assert.equal(timedOut.status, 503);
    assert.equal(hung.eventsFor(first).find((event) => event.kind === "L2_DECIDED")!.l2ErrorKind, "timeout");
    const saturated = await send(hung.port, "POST", "/api/public-inquiries", postHeaders(hung.port, second), form("C".repeat(43), hung.port));
    assert.equal(saturated.status, 503);
    const decided = hung.eventsFor(second).find((event) => event.kind === "L2_DECIDED")!;
    assert.deepEqual([decided.lane, decided.outcome, decided.shedReason], [null, "shed", "evaluator_saturation"]);
    assert.equal(hung.originEvents.length, 0, "nothing reached the origin");
  } finally { await hung.close(); }
});

test("P3 at the front: a decision the composer discards (a late verdict) has already consumed its bucket token and stays consumed; it is accounted, never refunded", async () => {
  const delayed = (inner: Layer): Layer => ({ id: "a7.journey-lanes", evaluate: (request) => { const verdict = inner.evaluate(request) as LayerVerdict; return new Promise<LayerVerdict>((resolve) => setTimeout(() => resolve(verdict), 120)); } });
  const r = await rig({ wrapLayer: delayed, stageComposer: { timeoutMs: 30, maxConcurrent: 8 } });
  try {
    const id = nonce();
    const reply = await send(r.port, "POST", "/api/public-inquiries", postHeaders(r.port, id), form("D".repeat(43), r.port));
    assert.equal(reply.status, 503);
    const decided = r.eventsFor(id).find((event) => event.kind === "L2_DECIDED")!;
    assert.deepEqual([decided.outcome, decided.l2ErrorKind, decided.lane, decided.spent], ["error", "timeout", null, "unverified"]);
    assert.equal(decided.lseq, 1);
    assert.equal(r.lanes.snapshot().unverified.admitted, 1, "the token the discarded decision took was not returned");
    assert.ok(decided.lvl !== undefined && decided.lvl <= 2_000_000 + 10, "the recorded level shows the consumption");
    cleanly(r, id, reply);
  } finally { await r.close(); }
});

function stub(handler: (res: http.ServerResponse) => void): http.Server { return http.createServer((_req, res) => handler(res)); }
const page = (token: string, extra = "") => `<!doctype html><form class="request-form"><input type="hidden" name="submissionToken" value="${token}">${extra}</form>`;

test("every enrollment skip reason is reachable and exactly one disposition is emitted per observed render", async () => {
  const T = "E".repeat(43);
  const cases: [string, (res: http.ServerResponse) => void, string][] = [
    ["status_not_200", (res) => { res.writeHead(404, { "content-type": "text/html; charset=utf-8" }); res.end(page(T)); }, "status_not_200"],
    ["content_type", (res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end(page(T)); }, "content_type"],
    ["encoding", (res) => { res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-encoding": "identity" }); res.end(page(T)); }, "content_type"],
    ["zero", (res) => { res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); res.end("<p>no form</p>"); }, "token_count_zero"],
    ["multiple", (res) => { res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); res.end(page(T, `<input type="hidden" name="submissionToken" value="${"G".repeat(43)}">`)); }, "token_count_multiple"],
  ];
  for (const [label, handler, expected] of cases) {
    const r = await rig({ upstream: stub(handler) });
    try {
      const id = nonce();
      const reply = await send(r.port, "GET", "/test-talep-et", { "x-ba0-nonce": id });
      const dispositions = r.eventsFor(id).filter((event) => event.kind === "L2_ENROLLED" || event.kind === "L2_ENROLL_SKIPPED");
      assert.equal(dispositions.length, 1, label);
      assert.equal(dispositions[0].kind, "L2_ENROLL_SKIPPED", label);
      assert.equal(dispositions[0].skipReason, expected, label);
      assert.equal(r.lanes.snapshot().filter.inserts, 0, `${label}: nothing was enrolled`);
      assert.deepEqual(validateLifecycle({ ...view(r, id, reply), origin: [] }, true).filter((a) => a.code !== "origin_without_l1_pass" && a.code !== "missing_transition"), [], label);
    } finally { await r.close(); }
  }
  // an upstream that fails outright
  const failed = await rig({ upstream: stub((res) => { res.destroy(); }) });
  try {
    const id = nonce();
    await send(failed.port, "GET", "/test-talep-et", { "x-ba0-nonce": id });
    const skip = failed.eventsFor(id).filter((event) => event.kind === "L2_ENROLL_SKIPPED");
    assert.deepEqual(skip.map((event) => event.skipReason), ["upstream_failed"]);
  } finally { await failed.close(); }
});

test("a client that aborts before delivery earns no credit: exactly one skip, `delivery_incomplete`, and the request is aborted", async () => {
  const r = await rig();
  try {
    r.origin.armFault({ kind: "delay", remaining: 1, delayMs: 200 });
    const id = nonce();
    await new Promise<void>((resolve) => {
      const request = http.request({ host: "127.0.0.1", port: r.port, method: "GET", path: "/test-talep-et", headers: { "x-ba0-nonce": id }, agent: false });
      request.on("error", () => resolve());
      request.on("socket", (socket) => socket.once("connect", () => setTimeout(() => request.destroy(), 40)));
      request.end();
      setTimeout(resolve, 600);
    });
    await new Promise((resolve) => setTimeout(resolve, 400));
    const events = r.eventsFor(id);
    assert.deepEqual(events.filter((event) => event.kind === "L2_ENROLLED").length, 0);
    assert.deepEqual(events.filter((event) => event.kind === "L2_ENROLL_SKIPPED").map((event) => event.skipReason), ["delivery_incomplete"]);
    assert.equal(events[events.length - 1].kind, "INGRESS_ABORTED");
    assert.equal(r.lanes.snapshot().filter.inserts, 0);
  } finally { await r.close(); }
});

test("a token already enrolled is never re-enrolled: the second render of the same token is a skip `already_enrolled`", async () => {
  const T = "H".repeat(43);
  const r = await rig({ upstream: stub((res) => { res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); res.end(page(T)); }) });
  try {
    const a = nonce(); const b = nonce();
    await send(r.port, "GET", "/test-talep-et", { "x-ba0-nonce": a });
    await send(r.port, "GET", "/test-talep-et", { "x-ba0-nonce": b });
    assert.deepEqual(r.eventsFor(a).filter((event) => event.kind.startsWith("L2_ENROLL")).map((event) => event.kind), ["L2_ENROLLED"]);
    assert.deepEqual(r.eventsFor(b).filter((event) => event.kind.startsWith("L2_ENROLL")).map((event) => [event.kind, event.skipReason]), [["L2_ENROLL_SKIPPED", "already_enrolled"]]);
    assert.equal(r.lanes.snapshot().filter.inserts, 1);
  } finally { await r.close(); }
});

test("a simulated verdict is permanently labelled, the shadow is the layer's real verdict, enrollment never happens for it, and nothing is selected by the request alone", async () => {
  const seen: string[] = [];
  const port: VerdictOverridePort = {
    l1: ({ request, nonce: id, outcome }) => { seen.push(`l1:${id.length}`); return request.target === "/admin" && outcome.kind === "reject" ? { shadow: `reject:${outcome.reason}` } : null; },
    l2: ({ request, decision }) => (request.target === "/admin" && decision.outcome === "shed" ? { shadow: "shed" } : null),
  };
  const r = await rig({ verdictOverride: port });
  try {
    const id = nonce();
    const reply = await send(r.port, "GET", "/admin", { "x-ba0-nonce": id });
    assert.equal(reply.status, 404, "the origin answered: the request really traversed the rest of the path");
    const passed = r.eventsFor(id).find((event) => event.kind === "L1_PASSED")!;
    assert.deepEqual([passed.basis, passed.shadow], ["simulated", "reject:a7.path_not_allowed"]);
    const decided = r.eventsFor(id).find((event) => event.kind === "L2_DECIDED")!;
    assert.deepEqual([decided.class, decided.lane, decided.outcome, decided.basis], ["unknown", "unverified", "admitted", undefined], "an unlabelled L2 decision here is natural");
    // an uncorrelated request (no nonce header) is never offered to the port with a usable nonce
    await send(r.port, "GET", "/admin", {});
    assert.ok(seen.includes("l1:0"), "an uncorrelated request reaches the port with an empty nonce, so it can never match an arm");
  } finally { await r.close(); }

  const plain = await rig();
  try {
    const reply = await send(plain.port, "GET", "/admin", { "x-ba0-nonce": nonce() });
    assert.equal(reply.status, 404);
    assert.equal(plain.planeEvents.some((event) => event.kind === "L1_PASSED"), false, "without the port a refusal is simply a refusal");
    assert.equal(plain.planeEvents.some((event) => event.basis !== undefined), false);
  } finally { await plain.close(); }
});
