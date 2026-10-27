import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { test } from "node:test";
import { validateLifecycle, terminalOutcome, type PlaneEvent } from "../defense/core/ledger";
import { createSyntheticOrigin } from "../defense/origin/synthetic-origin";
import { createFront } from "../defense/plane/front";

// P0-01: a request the front refuses while its body is still unread (or never framed) must not leave the connection consuming request
// bytes. Loopback only; the flood is capped at FLOOD_BYTES per case and stops as soon as the server closes the connection.

const FLOOD_BYTES = 8 * 1024 * 1024;
const FLOOD_CHUNK = Buffer.alloc(64 * 1024, 0x61);
/** What the server may read after the response head was seen: the drain cap plus socket read granularity, far below FLOOD_BYTES. */
const MAX_READ_AFTER_REFUSAL = 256 * 1024;
const FLOOD_WALL_MS = 3_000;
/** A chunk header declaring 2 GiB: every flooded byte is valid chunk data, so only the server (not the parser) can end the exchange. */
const OPEN_CHUNK = "7fffffff\r\n";

let counter = 0;
const nonce = () => `${String(++counter).padStart(22, "R")}`;
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

async function rig() {
  const events: PlaneEvent[] = [];
  const serverSockets = new Set<net.Socket>();
  const origin = createSyntheticOrigin({ instance: "protected", onObservation: () => undefined });
  const originPort = await origin.listen();
  let seq = 0;
  const front = createFront({
    upstream: { host: "127.0.0.1", port: originPort },
    emit: (event) => { const next = ++seq; events.push({ ...event, seq: next, t: 0 }); return next; },
    // The classifier sees every accepted socket: the only way a test can read the server side's byte counter.
    peerClass: (socket) => { serverSockets.add(socket); return "local"; },
  });
  const port = await front.listen();
  return {
    front, port, events, serverSockets,
    eventsFor: (id: string) => events.filter((event) => event.nonce === id),
    serverSideOf: (client: net.Socket) => [...serverSockets].find((socket) => socket.remotePort === client.localPort),
    close: async () => { await front.close(200); await origin.close(); },
  };
}
type Rig = Awaited<ReturnType<typeof rig>>;

type Flood = { text: string; status: number; closeHeader: boolean; serverBytesRead: number; serverClosed: boolean; floodWritten: number; headBytes: number };

/** Writes `head`, waits for the response head, then keeps writing (capped) while the server keeps accepting. */
async function floodAfterHead(r: Rig, head: string, trailer = ""): Promise<Flood> {
  const client = net.connect({ host: "127.0.0.1", port: r.port });
  client.on("error", () => undefined);
  let text = "";
  client.on("data", (chunk) => { text += chunk.toString("latin1"); });
  await new Promise<void>((resolve) => client.once("connect", () => resolve()));
  const headBytes = Buffer.byteLength(head + trailer);
  client.write(head + trailer);
  const deadline = Date.now() + 2_000;
  while (!text.includes("\r\n\r\n") && Date.now() < deadline && !client.destroyed) await sleep(5);
  let floodWritten = 0;
  const wallEnd = Date.now() + FLOOD_WALL_MS;
  while (floodWritten < FLOOD_BYTES && Date.now() < wallEnd && !client.destroyed && client.writable) {
    const accepted = await new Promise<boolean>((resolve) => { client.write(FLOOD_CHUNK, (error) => resolve(!error)); });
    if (!accepted) break;
    floodWritten += FLOOD_CHUNK.length;
  }
  const server = r.serverSideOf(client);
  // A missing server socket would make every bound below vacuous, so it is an error rather than "closed".
  assert.ok(server, "the server-side socket of the client connection was observed");
  const closeBy = Date.now() + 1_500;
  while (!server.destroyed && Date.now() < closeBy) await sleep(10);
  const result: Flood = {
    text, status: Number(/^HTTP\/1\.1 (\d{3})/.exec(text)?.[1] ?? 0), closeHeader: /\r\nconnection: close\r\n/i.test(text),
    serverBytesRead: server.bytesRead, serverClosed: server.destroyed, floodWritten, headBytes,
  };
  client.destroy();
  return result;
}

function assertBounded(flood: Flood, label: string): void {
  assert.ok(flood.status >= 400 && flood.status < 500, `${label}: refused with a 4xx, got ${flood.status}`);
  assert.equal(flood.serverClosed, true, `${label}: the server must close the connection (it was still open after ${flood.floodWritten} flooded bytes)`);
  assert.ok(flood.serverBytesRead <= flood.headBytes + MAX_READ_AFTER_REFUSAL,
    `${label}: the server read ${flood.serverBytesRead} bytes after a refusal (head ${flood.headBytes}, allowed extra ${MAX_READ_AFTER_REFUSAL})`);
}

function assertLedgerSingleTerminal(r: Rig, id: string, outcome: "rejected" | "client_aborted"): void {
  const plane = r.eventsFor(id);
  const terminals = plane.filter((event) => event.kind === "INGRESS_RESPONDED" || event.kind === "INGRESS_ABORTED");
  assert.equal(terminals.length, 1, `exactly one terminal event, saw ${plane.map((event) => event.kind).join(">")}`);
  assert.equal(terminalOutcome(plane), outcome);
  assert.deepEqual(validateLifecycle({ nonce: id, expected: "external", harness: [], plane: plane.map((event, index) => (index === 0 ? { ...event, ingress: "external" as const } : event)), origin: [] }, true), []);
}

const formHeaders = (port: number, id: string) => `Host: 127.0.0.1:${port}\r\nx-ba0-nonce: ${id}\r\nContent-Type: application/x-www-form-urlencoded\r\n`;

// ------------------------------------------------------------------------------------------------ 1. chunked POST
test("a rejected Transfer-Encoding: chunked POST does not leave the connection consuming request bytes", async () => {
  const r = await rig();
  try {
    const id = nonce();
    const flood = await floodAfterHead(r, `POST /api/public-inquiries HTTP/1.1\r\n${formHeaders(r.port, id)}Transfer-Encoding: chunked\r\n\r\n`, OPEN_CHUNK);
    assertBounded(flood, "chunked POST");
    assert.equal(flood.closeHeader, true, "the refusal announces Connection: close");
    assert.equal(r.eventsFor(id).find((event) => event.kind === "L1_REJECTED")?.reason, "a7.framing_invalid");
    assertLedgerSingleTerminal(r, id, "rejected");
  } finally { await r.close(); }
});

// ------------------------------------------------------------------------------------------------ 2. GET carrying a body
test("a rejected GET carrying a chunked body is handled safely", async () => {
  const r = await rig();
  try {
    const id = nonce();
    const flood = await floodAfterHead(r, `GET /gizlilik HTTP/1.1\r\nHost: 127.0.0.1:${r.port}\r\nx-ba0-nonce: ${id}\r\nTransfer-Encoding: chunked\r\n\r\n`, OPEN_CHUNK);
    assertBounded(flood, "chunked GET");
    assertLedgerSingleTerminal(r, id, "rejected");
  } finally { await r.close(); }
});

test("a rejected GET declaring a large Content-Length body is handled safely", async () => {
  const r = await rig();
  try {
    const id = nonce();
    const flood = await floodAfterHead(r, `GET /gizlilik HTTP/1.1\r\nHost: 127.0.0.1:${r.port}\r\nx-ba0-nonce: ${id}\r\nContent-Length: 104857600\r\n\r\n`);
    assertBounded(flood, "GET with Content-Length");
    assert.equal(r.eventsFor(id).find((event) => event.kind === "L1_REJECTED")?.reason, "a7.framing_invalid");
    assertLedgerSingleTerminal(r, id, "rejected");
  } finally { await r.close(); }
});

test("a rejected GET whose small body arrived with the headers is refused without needing to close a clean connection", async () => {
  const r = await rig();
  try {
    const id = nonce();
    const flood = await floodAfterHead(r, `GET /gizlilik HTTP/1.1\r\nHost: 127.0.0.1:${r.port}\r\nx-ba0-nonce: ${id}\r\nContent-Length: 5\r\n\r\nhello`);
    assert.equal(flood.status, 400);
    assertLedgerSingleTerminal(r, id, "rejected");
  } finally { await r.close(); }
});

// ------------------------------------------------------------------------------------------------ 3. invalid / ambiguous framing
const FRAMING_CASES: ReadonlyArray<[string, (port: number, id: string) => string]> = [
  // Ten digits: past the front's own 9-digit grammar, so no declared length is derived and the oversize check is skipped.
  ["Content-Length with ten digits", (port, id) => `POST /api/public-inquiries HTTP/1.1\r\n${formHeaders(port, id)}Content-Length: 4000000000\r\n\r\n`],
  ["Content-Length with leading zeros", (port, id) => `POST /api/public-inquiries HTTP/1.1\r\n${formHeaders(port, id)}Content-Length: 0000104857600\r\n\r\n`],
  ["duplicate equal Content-Length", (port, id) => `POST /api/public-inquiries HTTP/1.1\r\n${formHeaders(port, id)}Content-Length: 104857600\r\nContent-Length: 104857600\r\n\r\n`],
  ["duplicate conflicting Content-Length", (port, id) => `POST /api/public-inquiries HTTP/1.1\r\n${formHeaders(port, id)}Content-Length: 5\r\nContent-Length: 104857600\r\n\r\n`],
  ["Content-Length together with Transfer-Encoding", (port, id) => `POST /api/public-inquiries HTTP/1.1\r\n${formHeaders(port, id)}Content-Length: 104857600\r\nTransfer-Encoding: chunked\r\n\r\n`],
  ["oversize declared Content-Length", (port, id) => `POST /api/public-inquiries HTTP/1.1\r\n${formHeaders(port, id)}Content-Length: 10485760\r\n\r\n`],
  ["wrong content type with a large body", (port, id) => `POST /api/public-inquiries HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nx-ba0-nonce: ${id}\r\nContent-Type: text/plain\r\nContent-Length: 104857600\r\n\r\n`],
];
for (const [label, build] of FRAMING_CASES) {
  test(`framing that cannot be trusted (${label}) cannot bypass the rejection lifecycle`, async () => {
    const r = await rig();
    try {
      const id = nonce();
      const flood = await floodAfterHead(r, build(r.port, id));
      assertBounded(flood, label);
      // A parser-level refusal (clientError) has no nonce and never enters the ledger; every other case is exactly one rejected lifecycle.
      if (r.eventsFor(id).length > 0) assertLedgerSingleTerminal(r, id, "rejected");
      else assert.ok(r.events.some((event) => event.kind === "PARSER_REJECTED"), "a parser refusal is its own ledger event");
    } finally { await r.close(); }
  });
}

// ------------------------------------------------------------------------------------------------ 4. legitimate bounded requests
function exchange(agent: http.Agent, port: number, method: string, path: string, headers: Record<string, string>, body?: string) {
  return new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string; socket: net.Socket }>((resolve, reject) => {
    const request = http.request({ host: "127.0.0.1", port, method, path, agent, headers: { ...headers, ...(body !== undefined ? { "content-length": String(Buffer.byteLength(body)) } : {}) } }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks).toString("utf8"), socket: response.socket }));
    });
    request.on("error", reject);
    request.end(body);
  });
}

test("a legitimate bounded POST is still proxied intact and its keep-alive connection is not closed", async () => {
  const r = await rig();
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  try {
    const token = "B".repeat(43);
    const body = new URLSearchParams({ name: "A", email: "a@example.test", service: "web", system: "s", objective: "o", environment: "staging", authority: "owner", submissionToken: token }).toString();
    const id = nonce();
    const first = await exchange(agent, r.port, "POST", "/api/public-inquiries", { "x-ba0-nonce": id, "content-type": "application/x-www-form-urlencoded", origin: `http://127.0.0.1:${r.port}` }, body);
    assert.equal(first.status, 200);
    assert.deepEqual(JSON.parse(first.body), { kind: "redirect", location: "/test-talep-et/tesekkurler" });
    assert.notEqual(first.headers.connection, "close");
    const second = await exchange(agent, r.port, "GET", "/gizlilik", { "x-ba0-nonce": nonce() });
    assert.equal(second.status, 200);
    assert.equal(second.socket, first.socket, "the same keep-alive connection served both requests");
    assert.equal(terminalOutcome(r.eventsFor(id)), "proxied");
  } finally { agent.destroy(); await r.close(); }
});

test("a refusal whose request was fully received keeps the connection (nothing is left unread to close for)", async () => {
  const r = await rig();
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  try {
    const wrongType = await exchange(agent, r.port, "POST", "/api/public-inquiries", { "x-ba0-nonce": nonce(), "content-type": "text/plain" }, "hello");
    assert.equal(wrongType.status, 415);
    assert.notEqual(wrongType.headers.connection, "close");
    const unknownPath = await exchange(agent, r.port, "GET", "/nope", { "x-ba0-nonce": nonce() });
    assert.equal(unknownPath.status, 404);
    assert.equal(unknownPath.socket, wrongType.socket, "the same keep-alive connection served both refusals");
    assert.equal((await exchange(agent, r.port, "GET", "/gizlilik", { "x-ba0-nonce": nonce() })).status, 200);
  } finally { agent.destroy(); await r.close(); }
});

// ------------------------------------------------------------------------------------------------ 5. ledger accounting under mixed traffic
test("ledger accounting stays one terminal event per request across rejected-with-unread-body, rejected-complete and proxied requests", async () => {
  const r = await rig();
  try {
    const ids = { chunked: nonce(), oversize: nonce(), getBody: nonce() };
    await floodAfterHead(r, `POST /api/public-inquiries HTTP/1.1\r\n${formHeaders(r.port, ids.chunked)}Transfer-Encoding: chunked\r\n\r\n`, OPEN_CHUNK);
    await floodAfterHead(r, `POST /api/public-inquiries HTTP/1.1\r\n${formHeaders(r.port, ids.oversize)}Content-Length: 10485760\r\n\r\n`);
    await floodAfterHead(r, `GET /gizlilik HTTP/1.1\r\nHost: 127.0.0.1:${r.port}\r\nx-ba0-nonce: ${ids.getBody}\r\nContent-Length: 104857600\r\n\r\n`);
    const agent = new http.Agent({ keepAlive: false });
    const okId = nonce();
    assert.equal((await exchange(agent, r.port, "GET", "/gizlilik", { "x-ba0-nonce": okId })).status, 200);
    await sleep(50);
    for (const id of Object.values(ids)) assertLedgerSingleTerminal(r, id, "rejected");
    assert.equal(terminalOutcome(r.eventsFor(okId)), "proxied");
    const stats = r.front.stats();
    assert.equal(stats.inFlight, 0, "no request is left in flight");
    assert.equal(stats.aborted, 0, "a plane-answered refusal is never recorded as an abort");
    assert.equal(stats.completed, 4);
    assert.equal(r.front.connectionStats().clientErrorInRequest, 0);
  } finally { await r.close(); }
});
