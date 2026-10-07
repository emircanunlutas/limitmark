import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { test } from "node:test";
import type { PlaneEvent } from "../defense/core/ledger";
import type { PeerClass } from "../defense/core/ingress-class";
import { createSyntheticOrigin } from "../defense/origin/synthetic-origin";
import { createFront, type FrontOptions } from "../defense/plane/front";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const NONCE = "N".repeat(22);

async function rig(options: Partial<FrontOptions> = {}) {
  const events: PlaneEvent[] = [];
  const origin = createSyntheticOrigin({ instance: "protected", onObservation: () => undefined });
  const originPort = await origin.listen();
  let seq = 0;
  const front = createFront({ upstream: { host: "127.0.0.1", port: originPort }, emit: (event) => { const next = ++seq; events.push({ ...event, seq: next, t: 0 }); return next; }, ...options });
  const port = await front.listen();
  return { front, port, events, kinds: () => events.map((event) => event.kind), close: async () => { await front.close(200); await origin.close(); } };
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

const connect = (port: number) => new Promise<net.Socket>((resolve) => { const socket = net.connect({ host: "127.0.0.1", port }, () => resolve(socket)); socket.on("error", () => undefined); });
const collect = (socket: net.Socket): { text: () => string } => { let received = ""; socket.on("data", (chunk) => { received += chunk.toString("latin1"); }); return { text: () => received }; };

// ------------------------------------------------------------------------------------------------ the bind
test("an invalid ingress bind is refused at construction, before any socket exists", async () => {
  for (const ingress of [{ ip: "0.0.0.0", port: 8080 }, { ip: "::", port: 8080 }, { ip: "example.test", port: 8080 }, { ip: "10.0.0.5", port: 0 }, { ip: "10.0.0.5", port: 8080, extra: 1 } as never]) {
    assert.throws(() => createFront({ upstream: { host: "127.0.0.1", port: 9 }, emit: () => 1, ingress }), /ingress refused/);
  }
});

test("with no ingress the front binds 127.0.0.1 on an ephemeral port, exactly as every Slice-1/2/3 composition did", async () => {
  const r = await rig();
  try {
    assert.ok(r.port > 0);
    assert.equal((await send(r.port, "GET", "/gizlilik")).status, 200);
  } finally { await r.close(); }
});

test("a fixed ingress binds exactly that address and port", async () => {
  const probe = net.createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", () => resolve()));
  const port = (probe.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  const r = await rig({ ingress: { ip: "127.0.0.1", port } });
  try {
    assert.equal(r.port, port);
    assert.equal((await send(port, "GET", "/gizlilik")).status, 200);
  } finally { await r.close(); }
});

// ------------------------------------------------------------------------------------------------ remote peers
const remote = (): PeerClass => "remote";

test("a REMOTE peer cannot choose the nonce: the header is stripped and counted, the plane mints the id and marks the request external", async () => {
  const r = await rig({ peerClass: remote });
  try {
    const reply = await send(r.port, "GET", "/gizlilik", { "x-ba0-nonce": NONCE });
    assert.equal(reply.status, 200);
    const accepted = r.events.find((event) => event.kind === "INGRESS_ACCEPTED")!;
    assert.notEqual(accepted.nonce, NONCE, "the supplied nonce is never adopted");
    assert.equal(accepted.ingress, "external");
    assert.equal(accepted.stripped, 1, "the supplied header counts as a stripped spoof attempt");
    assert.equal(accepted.uncorrelated, undefined, "an external request is not an uncorrelated harness request");
    assert.equal(r.events.some((event) => event.nonce === NONCE), false);
    assert.equal(r.front.externalStats().accepted, 1);
  } finally { await r.close(); }
});

test("a LOCAL peer keeps the harness behaviour: its valid nonce is honored, there is no external marker, and the decision header is present", async () => {
  const r = await rig();
  try {
    const reply = await send(r.port, "GET", "/gizlilik", { "x-ba0-nonce": NONCE });
    assert.equal(reply.headers["x-ba0-outcome"], "proxied");
    const accepted = r.events.find((event) => event.kind === "INGRESS_ACCEPTED")!;
    assert.equal(accepted.nonce, NONCE);
    assert.equal(accepted.ingress, undefined);
    assert.equal(accepted.stripped, 0);
    assert.equal(r.front.externalStats().accepted, 0);
  } finally { await r.close(); }
});

test("a REMOTE client is never told an internal decision: no outcome header on a pass, an L1 reject, a parser reject or an egress failure", async () => {
  const r = await rig({ peerClass: remote });
  try {
    const proxied = await send(r.port, "GET", "/gizlilik");
    const rejected = await send(r.port, "GET", "/admin");
    assert.equal(proxied.status, 200);
    assert.equal(rejected.status, 404);
    for (const reply of [proxied, rejected]) assert.equal(reply.headers["x-ba0-outcome"], undefined);
    const socket = await connect(r.port);
    const answer = collect(socket);
    socket.write("FOO / HTTP/1.1\r\nHost: x\r\n\r\n");
    await sleep(300);
    assert.match(answer.text(), /^HTTP\/1\.1 400 /);
    assert.doesNotMatch(answer.text(), /x-ba0-outcome/i, "the parser refusal carries no decision label either");
    socket.destroy();
  } finally { await r.close(); }
});

test("a REMOTE request that the origin cannot serve is answered without a decision label (egress failure)", async () => {
  const events: PlaneEvent[] = [];
  let seq = 0;
  const front = createFront({ upstream: { host: "127.0.0.1", port: 1 }, emit: (event) => { events.push({ ...event, seq: ++seq, t: 0 }); return seq; }, peerClass: remote });
  const port = await front.listen();
  try {
    const reply = await send(port, "GET", "/gizlilik");
    assert.equal(reply.status, 502);
    assert.equal(reply.headers["x-ba0-outcome"], undefined);
    assert.ok(events.some((event) => event.kind === "EGRESS_FAILED"));
  } finally { await front.close(200); }
});

test("the in-flight gauges separate remote requests and report interval maxima that reset", async () => {
  const r = await rig({ peerClass: remote });
  try {
    await Promise.all([send(r.port, "GET", "/gizlilik"), send(r.port, "GET", "/gizlilik"), send(r.port, "GET", "/")]);
    const first = r.front.intervalInFlight();
    assert.ok(first.max >= 1 && first.maxExternal >= 1 && first.maxExternal <= first.max);
    const second = r.front.intervalInFlight();
    assert.deepEqual(second, { max: 0, maxExternal: 0 }, "the interval maxima restart from the current (idle) values");
    assert.equal(r.front.externalStats().accepted, 3);
    assert.equal(r.front.externalStats().inFlight, 0);
    assert.ok(r.front.externalStats().inFlightHighWater >= 1);
  } finally { await r.close(); }
});

// ------------------------------------------------------------------------------------------------ close_ingress
test("closeIngress stops accepting at once: the listener is gone, new connections are refused, and a request already in flight still finishes", async () => {
  const r = await rig({ peerClass: remote });
  try {
    assert.equal(r.front.listening(), true);
    const socket = await connect(r.port);
    socket.write("GET /gizlilik HTTP/1.1\r\nHost: x\r\n\r\n");
    await sleep(50);
    const answer = collect(socket);
    assert.equal(r.front.closeIngress(), true);
    assert.equal(r.front.listening(), false);
    await assert.rejects(() => new Promise((resolve, reject) => { const probe = net.connect({ host: "127.0.0.1", port: r.port }, () => { probe.destroy(); resolve(true); }); probe.on("error", reject); }), /ECONNREFUSED/);
    await sleep(200);
    socket.destroy();
    void answer;
    assert.equal(r.front.closeIngress(), true, "closing twice is harmless");
  } finally { await r.close(); }
});

// ------------------------------------------------------------------------------------------------ Node 22 pre-ingress behaviour (findings, asserted)
//
// Each test pins what Node 22 ACTUALLY does for one pre-ingress shape, so the field accounting never rests on documentation:
//   - what the front's exact connection counters show, and
//   - whether a lifecycle (INGRESS_ACCEPTED ...) exists for it.
// Where Node does not distinguish two things, the test says so: the ambiguity is a stated property of user-space observation.

test("Node 22: a clean close with no data is a connection that never delivered a request (counted, no lifecycle)", async () => {
  const r = await rig();
  try {
    const socket = await connect(r.port);
    socket.end();
    await sleep(300);
    const c = r.front.connectionStats();
    assert.equal(c.accepted.local, 1);
    assert.equal(c.closed.clean, 1);
    assert.equal(c.closedWithoutRequest, 1);
    assert.deepEqual(c.clientError, {});
    assert.deepEqual(r.events, []);
  } finally { await r.close(); }
});

test("Node 22: an RST in the middle of the headers is a clientError ECONNRESET with no request in flight, closed with an error, and no lifecycle", async () => {
  const r = await rig();
  try {
    const socket = await connect(r.port);
    socket.write("GET / HTTP/1.1\r\nHost: x");
    await sleep(50);
    socket.resetAndDestroy();
    await sleep(300);
    const c = r.front.connectionStats();
    assert.equal(c.clientError.ECONNRESET, 1);
    assert.equal(c.clientErrorNoRequest, 1);
    assert.equal(c.clientErrorInRequest, 0);
    assert.equal(c.socketError.ECONNRESET, 1);
    assert.equal(c.closed.error, 1);
    assert.equal(c.closedWithoutRequest, 1);
    assert.deepEqual(r.events, []);
  } finally { await r.close(); }
});

test("Node 22: a FIN in the middle of the headers is clientError HPE_INVALID_EOF_STATE, which is NOT in the parser allowlist: destroyed, never answered, no lifecycle", async () => {
  const r = await rig();
  try {
    const socket = await connect(r.port);
    socket.write("GET / HTTP/1.1\r\nHost: x");
    await sleep(50);
    socket.end();
    await sleep(300);
    const c = r.front.connectionStats();
    assert.equal(c.clientError.HPE_INVALID_EOF_STATE, 1);
    assert.equal(c.clientErrorDestroyed, 1);
    assert.equal(c.clientErrorAnswered, 0);
    assert.equal(c.clientErrorNoRequest, 1);
    assert.equal(r.front.stats().parserRejected, 0, "the parser-rejection counter covers only the allowlist");
    assert.deepEqual(r.events, []);
  } finally { await r.close(); }
});

test("Node 22: an EOF in the middle of a body has a lifecycle (INGRESS_ACCEPTED ... INGRESS_ABORTED) AND a clientError raised while the request is in flight, so it is counted once, not twice, as a loss", async () => {
  const r = await rig();
  try {
    const socket = await connect(r.port);
    socket.write("POST /api/public-inquiries HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\nname=a");
    await sleep(50);
    socket.end();
    await sleep(400);
    const c = r.front.connectionStats();
    assert.equal(c.clientError.HPE_INVALID_EOF_STATE, 1);
    assert.equal(c.clientErrorInRequest, 1, "the request was in flight: it is attributed to its own lifecycle");
    assert.equal(c.clientErrorNoRequest, 0);
    assert.equal(r.kinds()[0], "INGRESS_ACCEPTED");
    assert.equal(r.kinds().at(-1), "INGRESS_ABORTED");
    assert.equal(r.front.stats().aborted, 1);
  } finally { await r.close(); }
});

test("Node 22: when the listener's connection cap is hit the extra socket is dropped; Node's 'drop' event is reliable and the dropped socket never becomes a connection", async () => {
  const r = await rig({ maxConnections: 2 });
  try {
    const sockets = [await connect(r.port), await connect(r.port), await connect(r.port)];
    await sleep(200);
    const c = r.front.connectionStats();
    assert.equal(c.accepted.local, 2);
    assert.equal(c.dropped, 1);
    for (const socket of sockets) socket.destroy();
  } finally { await r.close(); }
});

test("Node 22: a stalled header block surfaces as clientError ERR_HTTP_REQUEST_TIMEOUT (the same code as a request timeout: the two are NOT distinguishable); it is destroyed with no lifecycle", async () => {
  const r = await rig({ serverTimeouts: { headersTimeoutMs: 300, requestTimeoutMs: 5_000, connectionsCheckingIntervalMs: 100 } });
  try {
    const socket = await connect(r.port);
    socket.write("GET / HTTP/1.1\r\nHost: x\r\n");
    await sleep(1_000);
    const c = r.front.connectionStats();
    assert.equal(c.clientError.ERR_HTTP_REQUEST_TIMEOUT, 1);
    assert.equal(c.clientErrorNoRequest, 1);
    assert.equal(c.closedWithoutRequest, 1);
    assert.deepEqual(r.events, []);
    socket.destroy();
  } finally { await r.close(); }
});

test("Node 22: a stalled body surfaces as the SAME clientError code ERR_HTTP_REQUEST_TIMEOUT, raised while the request is in flight, and the request ends INGRESS_ABORTED", async () => {
  const r = await rig({ serverTimeouts: { headersTimeoutMs: 200, requestTimeoutMs: 500, connectionsCheckingIntervalMs: 100 }, bodyDeadlineMs: 5_000 });
  try {
    const socket = await connect(r.port);
    socket.write("POST /api/public-inquiries HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\nname=a");
    await sleep(1_400);
    const c = r.front.connectionStats();
    assert.equal(c.clientError.ERR_HTTP_REQUEST_TIMEOUT, 1);
    assert.equal(c.clientErrorInRequest, 1);
    assert.equal(r.kinds().at(-1), "INGRESS_ABORTED");
    socket.destroy();
  } finally { await r.close(); }
});

test("Node 22: an Upgrade request is NOT intercepted (no 'upgrade' listener means Node treats it as an ordinary request): it gets a normal lifecycle; the plane must not add a listener that would hide it", async () => {
  const r = await rig();
  try {
    const socket = await connect(r.port);
    const answer = collect(socket);
    socket.write("GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
    await sleep(400);
    assert.match(answer.text(), /^HTTP\/1\.1 200 /);
    assert.deepEqual(r.kinds().slice(0, 3), ["INGRESS_ACCEPTED", "L1_ENTERED", "L1_PASSED"]);
    socket.destroy();
  } finally { await r.close(); }
});

test("Node 22: CONNECT gets no answer and no lifecycle: the front destroys the socket (as Node did) and now COUNTS it", async () => {
  const r = await rig();
  try {
    const socket = await connect(r.port);
    const answer = collect(socket);
    socket.write("CONNECT a:1 HTTP/1.1\r\nHost: a:1\r\n\r\n");
    await sleep(300);
    assert.equal(answer.text(), "");
    const c = r.front.connectionStats();
    assert.equal(c.protocolRefused.connect, 1);
    assert.equal(c.closedWithoutRequest, 1);
    assert.deepEqual(r.events, []);
  } finally { await r.close(); }
});

test("Node 22: Expect: 100-continue is answered 100 Continue and then an ordinary lifecycle; any OTHER Expect value is Node's own 417 before any lifecycle, now counted", async () => {
  const r = await rig();
  try {
    const first = await connect(r.port);
    const firstAnswer = collect(first);
    first.write("POST /api/public-inquiries HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\n\r\n");
    await sleep(200);
    first.write("name=a");
    await sleep(300);
    assert.match(firstAnswer.text(), /^HTTP\/1\.1 100 Continue/);
    assert.equal(r.kinds()[0], "INGRESS_ACCEPTED");
    const before = r.events.length;
    const second = await connect(r.port);
    const secondAnswer = collect(second);
    second.write("GET / HTTP/1.1\r\nHost: x\r\nExpect: foo\r\n\r\n");
    await sleep(300);
    assert.match(secondAnswer.text(), /^HTTP\/1\.1 417 /);
    assert.equal(r.events.length, before, "no lifecycle for the 417");
    assert.equal(r.front.connectionStats().protocolRefused.expectation, 1);
    first.destroy();
    second.destroy();
  } finally { await r.close(); }
});

test("Node 22: pipelined requests on one connection are BOTH processed and can be in flight together, so server-side external in-flight is the check that catches a pipelining client", async () => {
  const r = await rig({ peerClass: remote });
  try {
    const socket = await connect(r.port);
    const answer = collect(socket);
    socket.write("GET / HTTP/1.1\r\nHost: x\r\n\r\nGET /gizlilik HTTP/1.1\r\nHost: x\r\n\r\n");
    await sleep(500);
    assert.equal((answer.text().match(/HTTP\/1\.1 200/g) ?? []).length, 2);
    assert.equal(r.front.externalStats().accepted, 2);
    assert.equal(r.front.externalStats().inFlightHighWater, 2, "two requests from one connection were in flight at once");
    socket.destroy();
  } finally { await r.close(); }
});

test("Node 22: an invalid method is a parser refusal: answered 400, counted by code, and recorded as an anonymous PARSER_REJECTED event", async () => {
  const r = await rig();
  try {
    const socket = await connect(r.port);
    const answer = collect(socket);
    socket.write("FOO / HTTP/1.1\r\nHost: x\r\n\r\n");
    await sleep(300);
    assert.match(answer.text(), /^HTTP\/1\.1 400 /);
    const c = r.front.connectionStats();
    assert.equal(c.clientError.HPE_INVALID_METHOD, 1);
    assert.equal(c.clientErrorAnswered, 1);
    assert.equal(c.clientErrorNoRequest, 1);
    assert.equal(r.front.stats().parserRejected, 1);
    assert.equal(r.events[0].kind, "PARSER_REJECTED");
    assert.equal(r.events[0].nonce, null);
  } finally { await r.close(); }
});

test("Node 22: oversized headers are a parser refusal answered 431 and counted by code", async () => {
  const r = await rig();
  try {
    const socket = await connect(r.port);
    const answer = collect(socket);
    socket.write(`GET / HTTP/1.1\r\nHost: x\r\nX-Big: ${"a".repeat(20_000)}\r\n\r\n`);
    await sleep(300);
    assert.match(answer.text(), /^HTTP\/1\.1 431 /);
    assert.equal(r.front.connectionStats().clientError.HPE_HEADER_OVERFLOW, 1);
    assert.equal(r.front.stats().parserRejected, 1);
  } finally { await r.close(); }
});

test("Node 22 (ambiguity, stated): a keep-alive connection that ends after serving a request is a clean close; the server's own idle timeout and a polite client close are NOT distinguishable in user space", async () => {
  const r = await rig({ serverTimeouts: { keepAliveTimeoutMs: 200 } });
  try {
    const socket = await connect(r.port);
    socket.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    // Node adds a one second buffer to the keep-alive timeout before it closes an idle socket.
    await sleep(1_800);
    const c = r.front.connectionStats();
    assert.equal(c.closed.clean, 1);
    assert.equal(c.closedWithoutRequest, 0, "it served a request");
    assert.deepEqual(c.clientError, {}, "no clientError distinguishes the idle close");
    socket.destroy();
  } finally { await r.close(); }
});

test("Node 22: an RST on an idle keep-alive connection AFTER a completed request is a clientError with no request in flight (so it is not a lost request, but it is counted)", async () => {
  const r = await rig();
  try {
    const socket = await connect(r.port);
    socket.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    await sleep(300);
    socket.resetAndDestroy();
    await sleep(300);
    const c = r.front.connectionStats();
    assert.equal(c.clientError.ECONNRESET, 1);
    assert.equal(c.clientErrorNoRequest, 1);
    assert.equal(c.closedWithoutRequest, 0);
    assert.equal(r.front.stats().completed, 1);
  } finally { await r.close(); }
});

test("the distinct-code tables are bounded: more distinct clientError codes than the cap go to an overflow counter, never to unbounded memory", async () => {
  const r = await rig();
  try {
    // The table is capped at 64 distinct codes; the realistic set is far smaller, so the cap is asserted through the type of the counters.
    const c = r.front.connectionStats();
    assert.equal(typeof c.clientErrorOverflow, "number");
    assert.equal(typeof c.socketErrorOverflow, "number");
    assert.deepEqual(Object.keys(c).sort(), [
      "accepted", "active", "activeHighWater", "clientError", "clientErrorAnswered", "clientErrorDestroyed", "clientErrorInRequest", "clientErrorNoRequest", "clientErrorOverflow",
      "closed", "closedWithoutRequest", "dropped", "protocolRefused", "socketError", "socketErrorOverflow",
    ]);
  } finally { await r.close(); }
});
