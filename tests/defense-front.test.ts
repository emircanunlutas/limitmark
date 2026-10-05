import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { test } from "node:test";
import type { OriginEvent, PlaneEvent } from "../defense/core/ledger";
import { terminalOutcome } from "../defense/core/ledger";
import type { Layer, LayerVerdict } from "../defense/core/types";
import { createSyntheticOrigin } from "../defense/origin/synthetic-origin";
import { createFront } from "../defense/plane/front";

let counter = 0;
const nonce = () => `${String(++counter).padStart(22, "N")}`;

async function rig(options: { layer?: Layer; composer?: { timeoutMs?: number; maxConcurrent?: number }; egressTimeoutMs?: number; bodyDeadlineMs?: number; upstreamPort?: number } = {}) {
  const planeEvents: PlaneEvent[] = [];
  const originEvents: OriginEvent[] = [];
  const origin = createSyntheticOrigin({ instance: "protected", onObservation: (event) => originEvents.push(event) });
  const originPort = await origin.listen();
  let seq = 0;
  const front = createFront({
    upstream: { host: "127.0.0.1", port: options.upstreamPort ?? originPort },
    emit: (event) => { const next = ++seq; planeEvents.push({ ...event, seq: next, t: 0 }); return next; },
    layer: options.layer, composer: options.composer, egressTimeoutMs: options.egressTimeoutMs, bodyDeadlineMs: options.bodyDeadlineMs,
  });
  const port = await front.listen();
  const eventsFor = (id: string) => planeEvents.filter((event) => event.nonce === id);
  return { origin, front, port, planeEvents, originEvents, eventsFor, close: async () => { await front.close(500); await origin.close(); } };
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

test("a legitimate request is proxied and its full lifecycle is emitted in order, with the origin reconciling by hop", async () => {
  const r = await rig();
  try {
    const id = nonce();
    const reply = await send(r.port, "GET", "/gizlilik", { "x-ba0-nonce": id });
    assert.equal(reply.status, 200);
    assert.equal(reply.headers["x-ba0-outcome"], "proxied");
    assert.match(reply.body, /Gizlilik/);
    assert.deepEqual(kinds(r.eventsFor(id)), ["INGRESS_ACCEPTED", "L1_ENTERED", "L1_PASSED", "EGRESS_ATTEMPTED", "EGRESS_RESPONDED", "INGRESS_RESPONDED"]);
    const attempted = r.eventsFor(id).find((event) => event.kind === "EGRESS_ATTEMPTED")!;
    const received = r.originEvents.find((event) => event.nonce === id && event.kind === "ORIGIN_RECEIVED")!;
    assert.equal(received.hop, attempted.seq, "the origin saw the hop of the plane's egress attempt");
    assert.equal(terminalOutcome(r.eventsFor(id)), "proxied");
  } finally { await r.close(); }
});

test("an L1 reject is answered by the plane and never reaches the origin", async () => {
  const r = await rig();
  try {
    const id = nonce();
    const reply = await send(r.port, "GET", "/admin", { "x-ba0-nonce": id });
    assert.equal(reply.status, 404);
    assert.equal(reply.headers["x-ba0-outcome"], "rejected");
    assert.deepEqual(kinds(r.eventsFor(id)), ["INGRESS_ACCEPTED", "L1_ENTERED", "L1_REJECTED", "INGRESS_RESPONDED"]);
    assert.equal(r.eventsFor(id).find((event) => event.kind === "L1_REJECTED")?.reason, "a7.path_not_allowed");
    assert.equal(r.originEvents.length, 0);
  } finally { await r.close(); }
});

test("spoofable internal and forwarding headers are stripped before the layer and never reach the origin", async () => {
  const seen: string[][] = [];
  const spy: Layer = { id: "a7.shape-gate", evaluate: (request): LayerVerdict => { seen.push(request.headers.map(([name]) => name)); return { kind: "pass" }; } };
  const r = await rig({ layer: spy });
  try {
    const id = nonce();
    const reply = await send(r.port, "GET", "/", {
      "x-ba0-nonce": id, "x-ba0-hop": "999", "X-BA0-Class": "legitimate", "x-forwarded-for": "10.9.9.9", "x-real-ip": "10.9.9.8", forwarded: "for=1.2.3.4",
      "cf-connecting-ip": "10.1.1.1", "x-limitmark-origin-secret": "not-a-secret", "x-vercel-protection-bypass": "x",
    });
    assert.equal(reply.status, 200);
    assert.equal(seen.length, 1);
    for (const name of seen[0]) assert.doesNotMatch(name, /^x-ba0-|^x-forwarded-|^forwarded$|^x-real-ip$|^cf-connecting-ip$|^x-limitmark-|^x-vercel-/);
    assert.equal(r.eventsFor(id).find((event) => event.kind === "INGRESS_ACCEPTED")?.stripped, 8);
    const received = r.originEvents.find((event) => event.nonce === id && event.kind === "ORIGIN_RECEIVED")!;
    assert.equal(received.spoofed, 0);
    assert.notEqual(received.hop, 999, "a client-supplied hop is never trusted; the origin saw the plane's own");
  } finally { await r.close(); }
});

test("a request without a usable nonce is flagged as uncorrelated (the front mints one; the collector will mark the run INVALID)", async () => {
  const r = await rig();
  try {
    await send(r.port, "GET", "/gizlilik", { "x-ba0-nonce": "short" });
    await send(r.port, "GET", "/gizlilik");
    const accepted = r.planeEvents.filter((event) => event.kind === "INGRESS_ACCEPTED");
    assert.equal(accepted.length, 2);
    for (const event of accepted) assert.equal(event.uncorrelated, true);
    for (const event of accepted) assert.notEqual(event.nonce, "short");
  } finally { await r.close(); }
});

test("the upstream is fixed and loopback only: construction refuses anything else and a request cannot redirect it", async () => {
  assert.throws(() => createFront({ upstream: { host: "10.0.0.1" as "127.0.0.1", port: 80 }, emit: () => 0 }), /fixed 127\.0\.0\.1/);
  assert.throws(() => createFront({ upstream: { host: "127.0.0.1", port: 0 }, emit: () => 0 }), /fixed 127\.0\.0\.1/);
  const r = await rig();
  try {
    for (const target of ["http://example.invalid/", "//example.invalid/", "/@example.invalid/"]) {
      const reply = await send(r.port, "GET", target, { "x-ba0-nonce": nonce(), host: "example.invalid" });
      assert.ok(reply.status >= 400 && reply.status < 500, `${target} -> ${reply.status}`);
    }
    assert.equal(r.originEvents.length, 0, "none of them reached any upstream");
  } finally { await r.close(); }
});

test("an injected layer throw is an explicit L1_ERROR, answered 503, and never proxied (fail closed)", async () => {
  const r = await rig({ layer: { id: "a7.shape-gate", evaluate: () => { throw new Error("injected"); } } });
  try {
    const id = nonce();
    const reply = await send(r.port, "GET", "/", { "x-ba0-nonce": id });
    assert.equal(reply.status, 503);
    assert.equal(reply.headers["x-ba0-outcome"], "error");
    assert.deepEqual(kinds(r.eventsFor(id)), ["INGRESS_ACCEPTED", "L1_ENTERED", "L1_ERROR", "INGRESS_RESPONDED"]);
    assert.equal(r.eventsFor(id).find((event) => event.kind === "L1_ERROR")?.errorKind, "throw");
    assert.equal(r.originEvents.length, 0);
  } finally { await r.close(); }
});

test("an injected layer hang is an explicit L1_ERROR(timeout) within the deadline", async () => {
  const r = await rig({ layer: { id: "a7.shape-gate", evaluate: () => new Promise<LayerVerdict>(() => undefined) }, composer: { timeoutMs: 50 } });
  try {
    const id = nonce();
    const started = performance.now();
    const reply = await send(r.port, "GET", "/", { "x-ba0-nonce": id });
    assert.ok(performance.now() - started < 1_000);
    assert.equal(reply.status, 503);
    assert.equal(r.eventsFor(id).find((event) => event.kind === "L1_ERROR")?.errorKind, "timeout");
    assert.equal(r.originEvents.length, 0);
  } finally { await r.close(); }
});

test("saturation is an explicit L1_SHED (503); nothing disappears", async () => {
  const r = await rig({ layer: { id: "a7.shape-gate", evaluate: () => new Promise<LayerVerdict>((resolve) => setTimeout(() => resolve({ kind: "pass" }), 150)) }, composer: { maxConcurrent: 2, timeoutMs: 1_000 } });
  try {
    const ids = Array.from({ length: 6 }, nonce);
    const replies = await Promise.all(ids.map((id) => send(r.port, "GET", "/gizlilik", { "x-ba0-nonce": id })));
    assert.equal(replies.filter((reply) => reply.status === 200).length, 2);
    assert.equal(replies.filter((reply) => reply.status === 503).length, 4);
    for (const id of ids) {
      const outcome = terminalOutcome(r.eventsFor(id));
      assert.ok(outcome === "proxied" || outcome === "shed", `${id} -> ${outcome}`);
    }
    assert.equal(r.planeEvents.filter((event) => event.kind === "L1_SHED").length, 4);
  } finally { await r.close(); }
});

test("egress failures are separately attributed: refused, reset and timeout, each answered 502/504, and distinct from an L1 pass", async () => {
  // refused: the upstream port has nothing listening
  const dead = net.createServer(); await new Promise<void>((resolve) => dead.listen(0, "127.0.0.1", resolve));
  const deadPort = (dead.address() as net.AddressInfo).port; await new Promise<void>((resolve) => dead.close(() => resolve()));
  const refused = await rig({ upstreamPort: deadPort });
  try {
    const id = nonce();
    const reply = await send(refused.port, "GET", "/gizlilik", { "x-ba0-nonce": id });
    assert.equal(reply.status, 502);
    assert.equal(reply.headers["x-ba0-outcome"], "egress_failed");
    assert.equal(refused.eventsFor(id).find((event) => event.kind === "EGRESS_FAILED")?.egressError, "refused");
    assert.deepEqual(kinds(refused.eventsFor(id)), ["INGRESS_ACCEPTED", "L1_ENTERED", "L1_PASSED", "EGRESS_ATTEMPTED", "EGRESS_FAILED", "INGRESS_RESPONDED"]);
  } finally { await refused.close(); }

  const r = await rig({ egressTimeoutMs: 300 });
  try {
    r.origin.armFault({ kind: "reset", remaining: 1 });
    const resetId = nonce();
    assert.equal((await send(r.port, "GET", "/gizlilik", { "x-ba0-nonce": resetId })).status, 502);
    assert.equal(r.eventsFor(resetId).find((event) => event.kind === "EGRESS_FAILED")?.egressError, "reset");
    r.origin.armFault({ kind: "hang", remaining: 1 });
    const hangId = nonce();
    assert.equal((await send(r.port, "GET", "/gizlilik", { "x-ba0-nonce": hangId })).status, 504);
    assert.equal(r.eventsFor(hangId).find((event) => event.kind === "EGRESS_FAILED")?.egressError, "timeout");
    // Both were L1 PASSES that the origin did not (successfully) deliver: the plane's pass is not delivery.
    assert.equal(r.planeEvents.filter((event) => event.kind === "L1_PASSED").length, 2);
    assert.equal(r.originEvents.filter((event) => event.kind === "ORIGIN_COMPLETED").length, 0);
  } finally { await r.close(); }
});

test("event-loop safety: an oversized body is rejected from its declared length and never read or parsed", async () => {
  const r = await rig();
  try {
    const id = nonce();
    const reply = await new Promise<string>((resolve) => {
      const socket = net.connect(r.port, "127.0.0.1");
      let data = "";
      socket.on("data", (chunk) => { data += chunk.toString("latin1"); if (data.includes("\r\n\r\n")) { socket.destroy(); resolve(data); } });
      socket.on("close", () => resolve(data));
      socket.on("connect", () => socket.write(`POST /api/public-inquiries HTTP/1.1\r\nHost: 127.0.0.1:${r.port}\r\nx-ba0-nonce: ${id}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 10485760\r\n\r\n`));
    });
    assert.match(reply, /^HTTP\/1\.1 413/);
    const rejected = r.eventsFor(id).find((event) => event.kind === "L1_REJECTED");
    assert.equal(rejected?.reason, "a7.body_too_large");
    assert.equal(rejected?.stage, "pre_parse");
    assert.equal(r.front.gate?.stats().grammarParses, 0, "the grammar parser never ran");
    assert.equal(r.originEvents.length, 0);
  } finally { await r.close(); }
});

test("a valid POST is proxied with its body intact and the grammar parser ran exactly once", async () => {
  const r = await rig();
  try {
    const token = "B".repeat(43);
    const body = new URLSearchParams({ name: "A", email: "a@example.test", service: "web", system: "s", objective: "o", environment: "staging", authority: "owner", submissionToken: token }).toString();
    const origin = `http://127.0.0.1:${r.port}`;
    const reply = await send(r.port, "POST", "/api/public-inquiries", { "x-ba0-nonce": nonce(), "content-type": "application/x-www-form-urlencoded", origin }, body);
    assert.equal(reply.status, 200);
    assert.deepEqual(JSON.parse(reply.body), { kind: "redirect", location: "/test-talep-et/tesekkurler" });
    assert.equal(r.front.gate?.stats().grammarParses, 1);
  } finally { await r.close(); }
});
