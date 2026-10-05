import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { test } from "node:test";
import { createBoundary, type Boundary } from "../defense/boundary/boundary";
import { validateLifecycle, type AppEvent, type BoundaryEvent, type LifecycleView, type OriginEvent, type PlaneEvent } from "../defense/core/ledger";
import { validateOriginLineage } from "../defense/core/lineage";
import { importPrivateKey, importPublicKey, issuePb } from "../defense/core/hop-proof";
import { ShapeGate } from "../defense/layers/a7-shape-gate";
import { createAppGuard } from "../defense/origin/app-guard";
import { createSyntheticOrigin, type SyntheticOrigin } from "../defense/origin/synthetic-origin";
import { createFront, type Front } from "../defense/plane/front";
import { SemanticGate } from "../defense/plane/semantic-gate";
import { HopTrustRoot } from "../lab/defense/hop-keys";

const FORM = "application/x-www-form-urlencoded";
let counter = 0;
const nonce = () => String(++counter).padStart(22, "N");
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

const validForm = new URLSearchParams({
  name: "Canary Journey", email: "canary@example.test", company: "Synthetic Co", service: "web", system: "synthetic canary system", objective: "synthetic canary objective",
  environment: "staging", authority: "authorized", protection: "unknown", provider: "", notes: "", submissionToken: "A".repeat(43),
}).toString();

/** A raw TCP relay between the plane and the boundary that can rewrite the request head in flight and records every request it forwards. */
function relay(targetPort: () => number, mutate: (head: string) => string, captured: Buffer[]): Promise<{ port: number; close(): Promise<void> }> {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((client) => {
    sockets.add(client);
    client.on("close", () => sockets.delete(client));
    const upstream = net.connect(targetPort(), "127.0.0.1");
    sockets.add(upstream);
    upstream.on("close", () => sockets.delete(upstream));
    let buffered = Buffer.alloc(0);
    let headSent = false;
    client.on("data", (chunk) => {
      if (headSent) { upstream.write(chunk); return; }
      buffered = Buffer.concat([buffered, chunk]);
      const end = buffered.indexOf("\r\n\r\n");
      if (end < 0) return;
      const out = Buffer.concat([Buffer.from(`${mutate(buffered.subarray(0, end).toString("latin1"))}\r\n\r\n`, "latin1"), buffered.subarray(end + 4)]);
      captured.push(out);
      upstream.write(out);
      headSent = true;
    });
    upstream.on("data", (chunk) => client.write(chunk));
    upstream.on("close", () => client.end());
    upstream.on("error", () => client.destroy());
    client.on("close", () => upstream.destroy());
    client.on("error", () => upstream.destroy());
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({
    port: (server.address() as net.AddressInfo).port,
    close: () => new Promise<void>((done) => { server.close(() => done()); for (const socket of sockets) socket.destroy(); }),
  })));
}

type Stack = {
  root: HopTrustRoot; front: Front; frontPort: number; boundary: Boundary; boundaryPort: number; origin: SyntheticOrigin; appPort: number;
  planeEvents: PlaneEvent[]; boundaryEvents: BoundaryEvent[]; appEvents: AppEvent[]; captured: Buffer[]; close(): Promise<void>;
};

async function stack(options: { mutate?: (head: string) => string; replayCapacity?: number; appFault?: boolean } = {}): Promise<Stack> {
  const root = new HopTrustRoot();
  const material = root.keyMaterial();
  const planeEvents: PlaneEvent[] = []; const boundaryEvents: BoundaryEvent[] = []; const appEvents: AppEvent[] = [];
  let pSeq = 0; let bSeq = 0; let aSeq = 0;
  const built = createAppGuard({
    keyB: importPublicKey(material.publicB), kidB: root.kidB, keyP: importPublicKey(material.publicP), kidP: root.kidP, appId: root.appId, boundaryId: root.boundaryId,
    replayCapacity: 4_096, bodyDeadlineMs: 2_000,
  });
  const origin = createSyntheticOrigin({ instance: "protected", onObservation: () => undefined, guard: built.guard, onApp: (event) => { appEvents.push({ ...event, seq: ++aSeq, t: 0 }); } });
  const appPort = await origin.listen();
  const boundary = createBoundary({
    appPort, keyP: importPublicKey(material.publicP), kidP: root.kidP, boundaryId: root.boundaryId, keyB: importPrivateKey(material.privateB), kidB: root.kidB, appId: root.appId,
    limits: { replayCapacity: options.replayCapacity ?? 4_096, bodyDeadlineMs: 2_000, forwardTimeoutMs: 2_000, baLifetimeMs: 1_500 },
    emit: (event) => { boundaryEvents.push({ ...event, seq: ++bSeq, t: 0 }); return bSeq; },
  });
  const boundaryPort = await boundary.listen();
  const captured: Buffer[] = [];
  const relayed = options.mutate ? await relay(() => boundaryPort, options.mutate, captured) : null;
  const issuer = { kid: root.kidP, privateKey: importPrivateKey(material.privateP), boundaryId: root.boundaryId, lifetimeMs: 4_000, now: () => Date.now() };
  const front = createFront({
    upstream: { host: "127.0.0.1", port: relayed?.port ?? boundaryPort },
    emit: (event) => { planeEvents.push({ ...event, seq: ++pSeq, t: 0 }); return pSeq; },
    layer: new SemanticGate(new ShapeGate()),
    hop: { issue: (approved, context) => issuePb(issuer, approved, context) },
    egressTimeoutMs: 3_000,
  });
  const frontPort = await front.listen();
  return {
    root, front, frontPort, boundary, boundaryPort, origin, appPort, planeEvents, boundaryEvents, appEvents, captured,
    close: async () => { await front.close(500); await boundary.close(); await origin.close(); await relayed?.close(); },
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
const raw = (port: number, bytes: Buffer | string): Promise<string> => new Promise((resolve) => {
  const socket = net.connect(port, "127.0.0.1", () => socket.write(bytes));
  let data = "";
  socket.on("data", (chunk) => { data += chunk.toString("latin1"); });
  socket.on("close", () => resolve(data));
  socket.on("error", () => resolve(data));
  setTimeout(() => socket.destroy(), 1_500).unref();
});

const originOf = (events: AppEvent[], id: string): OriginEvent[] => events.filter((event) => event.nonce === id).flatMap((event): OriginEvent[] =>
  event.kind === "APP_ADMITTED" ? [{ instance: "protected", nonce: id, kind: "ORIGIN_RECEIVED", hop: event.hop ?? null, spoofed: event.spoofed ?? 0 }]
    : event.kind === "APP_COMPLETED" ? [{ instance: "protected", nonce: id, kind: "ORIGIN_COMPLETED", hop: event.hop ?? null, status: event.status }]
      : event.kind === "APP_ABORTED" ? [{ instance: "protected", nonce: id, kind: "ORIGIN_ABORTED", hop: event.hop ?? null }] : []);
function viewOf(s: Stack, id: string, status: number, outcome = "proxied"): LifecycleView {
  return {
    nonce: id, expected: "protected", harness: [{ kind: "SENT" }, { kind: "CLIENT_COMPLETED", result: "response", status, outcomeHeader: outcome }],
    plane: s.planeEvents.filter((event) => event.nonce === id), origin: originOf(s.appEvents, id),
    boundary: s.boundaryEvents.filter((event) => event.nonce === id), app: s.appEvents.filter((event) => event.nonce === id),
  };
}
const kinds = (events: { kind: string }[]) => events.map((event) => event.kind);
const submissionHeaders = (port: number, id: string) => ({ "x-ba0-nonce": id, "content-type": FORM, origin: `http://127.0.0.1:${port}` });

test("a legitimate GET and a valid POST traverse Plane -> Boundary -> App with complete, matching lineage and exactly one mutation", async () => {
  const s = await stack();
  try {
    const getId = nonce();
    const page = await send(s.frontPort, "GET", "/gizlilik", { "x-ba0-nonce": getId });
    assert.equal(page.status, 200);
    assert.match(page.body, /Gizlilik/);
    const postId = nonce();
    const submitted = await send(s.frontPort, "POST", "/api/public-inquiries", submissionHeaders(s.frontPort, postId), validForm);
    assert.equal(submitted.status, 200);
    assert.deepEqual(JSON.parse(submitted.body), { kind: "redirect", location: "/test-talep-et/tesekkurler" });
    await sleep(50);

    assert.deepEqual(kinds(s.planeEvents.filter((event) => event.nonce === getId)), ["INGRESS_ACCEPTED", "L1_ENTERED", "L1_PASSED", "EGRESS_ATTEMPTED", "PROOF_ISSUED", "EGRESS_RESPONDED", "INGRESS_RESPONDED"]);
    assert.deepEqual(kinds(s.boundaryEvents.filter((event) => event.nonce === getId)), ["BOUNDARY_ARRIVED", "BOUNDARY_ADMITTED", "APP_PROOF_ISSUED", "BOUNDARY_FORWARDED", "BOUNDARY_FORWARD_RESPONDED", "BOUNDARY_RESPONDED"]);
    assert.deepEqual(kinds(s.appEvents.filter((event) => event.nonce === getId)), ["APP_ADMITTED", "APP_EXECUTED", "APP_COMPLETED"]);
    assert.deepEqual(kinds(s.appEvents.filter((event) => event.nonce === postId)), ["APP_ADMITTED", "APP_EXECUTED", "APP_MUTATED", "APP_COMPLETED"]);
    for (const [id, status] of [[getId, 200], [postId, 200]] as const) {
      const view = viewOf(s, id, status);
      assert.deepEqual(validateLifecycle(view, true), [], id);
      assert.deepEqual(validateOriginLineage(view, true), [], id);
    }
    assert.equal(s.origin.appStats().stateMutations, 1);
    assert.equal(s.origin.appStats().admitted, 2);
    assert.equal(s.origin.appStats().executed, 2);
    // the three identifiers are consistent end to end: hop, the plane's proof tag, the boundary's proof tag
    const hop = s.planeEvents.find((event) => event.nonce === getId && event.kind === "EGRESS_ATTEMPTED")!.seq;
    const pbTag = s.planeEvents.find((event) => event.nonce === getId && event.kind === "PROOF_ISSUED")!.pbTag;
    const issued = s.boundaryEvents.find((event) => event.nonce === getId && event.kind === "APP_PROOF_ISSUED")!;
    const admitted = s.appEvents.find((event) => event.nonce === getId && event.kind === "APP_ADMITTED")!;
    assert.deepEqual([issued.hop, issued.pbTag, admitted.hop, admitted.pbTag, admitted.baTag], [hop, pbTag, hop, pbTag, issued.baTag]);
    assert.notEqual(pbTag, issued.baTag, "the two hops carry different tags");
  } finally { await s.close(); }
});

test("the forwarded request is REBUILT from the approved request: dropped client headers never reach the boundary, and the plain nonce/hop headers are not sent", async () => {
  const seen: string[][] = [];
  const spy = http.createServer((request, response) => { seen.push([...request.rawHeaders]); response.writeHead(200, { "content-length": 0 }); response.end(); });
  await new Promise<void>((resolve) => spy.listen(0, "127.0.0.1", resolve));
  const root = new HopTrustRoot();
  const material = root.keyMaterial();
  const events: PlaneEvent[] = []; let seq = 0;
  const front = createFront({
    upstream: { host: "127.0.0.1", port: (spy.address() as net.AddressInfo).port }, emit: (event) => { events.push({ ...event, seq: ++seq, t: 0 }); return seq; },
    layer: new SemanticGate(new ShapeGate()),
    hop: { issue: (approved, context) => issuePb({ kid: root.kidP, privateKey: importPrivateKey(material.privateP), boundaryId: root.boundaryId, lifetimeMs: 4_000, now: () => Date.now() }, approved, context) },
  });
  const port = await front.listen();
  try {
    const reply = await send(port, "GET", "/gizlilik", { "x-ba0-nonce": nonce(), accept: "text/html", "user-agent": "t", cookie: "a=b", referer: "http://x/", "x-forwarded-for": "10.0.0.1", "x-ba0-hop": "999" });
    assert.equal(reply.status, 200);
    const names = seen[0].filter((_, index) => index % 2 === 0).map((name) => name.toLowerCase()).sort();
    assert.deepEqual(names, ["connection", "host", "x-ba0-hop-pb"], "exactly the bound header, the transport header and the PB proof");
    assert.equal(front.hopStats().droppedUnbound, 4);
    assert.equal(front.hopStats().issued, 1);
  } finally { await front.close(500); await new Promise<void>((resolve) => spy.close(() => resolve())); }
});

type Tamper = { label: string; method: "GET" | "POST"; mutate: (head: string) => string; reason: string };
const tampers: Tamper[] = [
  { label: "altered Content-Type", method: "POST", mutate: (h) => h.replace(`content-type: ${FORM}`, "content-type: text/plain"), reason: "ob.header_mismatch" },
  { label: "altered Host", method: "GET", mutate: (h) => h.replace(/\r\nhost: [^\r]+/, "\r\nhost: evil.test"), reason: "ob.header_mismatch" },
  { label: "altered Origin", method: "POST", mutate: (h) => h.replace(/\r\norigin: [^\r]+/, "\r\norigin: http://evil.test"), reason: "ob.header_mismatch" },
  { label: "injected X-Forwarded-For", method: "GET", mutate: (h) => `${h}\r\nx-forwarded-for: 10.0.0.1`, reason: "ob.header_unbound" },
  { label: "injected X-Limitmark-Origin-Secret", method: "GET", mutate: (h) => `${h}\r\nx-limitmark-origin-secret: not-a-secret`, reason: "ob.header_unbound" },
  { label: "injected Cookie", method: "GET", mutate: (h) => `${h}\r\ncookie: a=b`, reason: "ob.header_unbound" },
  { label: "duplicated Host", method: "GET", mutate: (h) => `${h}\r\nhost: evil.test`, reason: "ob.header_duplicate" },
  { label: "duplicated Origin (case variant)", method: "POST", mutate: (h) => `${h}\r\nORIGIN: http://evil.test`, reason: "ob.header_duplicate" },
  { label: "duplicated Content-Type", method: "POST", mutate: (h) => `${h}\r\ncontent-type: text/plain`, reason: "ob.header_duplicate" },
  { label: "Host with a trailing dot", method: "GET", mutate: (h) => h.replace(/\r\nhost: ([^\r]+)/, "\r\nhost: $1."), reason: "ob.header_mismatch" },
  { label: "Origin with a trailing slash", method: "POST", mutate: (h) => h.replace(/\r\norigin: ([^\r]+)/, "\r\norigin: $1/"), reason: "ob.header_mismatch" },
];

test("END TO END: every in-flight alteration of a plane-issued request is refused at the boundary and the application executes and mutates nothing", async () => {
  for (const tamper of tampers) {
    const s = await stack({ mutate: tamper.mutate });
    try {
      const id = nonce();
      const reply = tamper.method === "POST"
        ? await send(s.frontPort, "POST", "/api/public-inquiries", submissionHeaders(s.frontPort, id), validForm)
        : await send(s.frontPort, "GET", "/gizlilik", { "x-ba0-nonce": id });
      assert.equal(reply.status, 403, tamper.label);
      await sleep(30);
      const rejected = s.boundaryEvents.find((event) => event.kind === "BOUNDARY_REJECTED");
      assert.equal(rejected?.reason, tamper.reason, tamper.label);
      assert.equal(s.boundaryEvents.some((event) => event.kind === "BOUNDARY_ADMITTED"), false, `${tamper.label}: never admitted`);
      assert.equal(s.appEvents.length, 0, `${tamper.label}: the application saw nothing`);
      assert.deepEqual([s.origin.appStats().admitted, s.origin.appStats().executed, s.origin.appStats().stateMutations], [0, 0, 0], tamper.label);
    } finally { await s.close(); }
  }
});

test("name-case and whitespace variants of the same headers are the SAME request: admitted, and the application sees the canonical values", async () => {
  const s = await stack({ mutate: (h) => h.replace(/\r\nhost: ([^\r]+)/, "\r\nHOST:   $1   ").replace(/\r\norigin: ([^\r]+)/, "\r\nOrigin:\t$1 ") });
  try {
    const id = nonce();
    const reply = await send(s.frontPort, "POST", "/api/public-inquiries", submissionHeaders(s.frontPort, id), validForm);
    assert.equal(reply.status, 200);
    assert.equal(s.origin.appStats().stateMutations, 1);
    assert.deepEqual(validateOriginLineage(viewOf(s, id, 200), true), []);
  } finally { await s.close(); }
});

test("a captured plane request replayed straight at the boundary is refused, and the application is not reached a second time", async () => {
  const s = await stack({ mutate: (h) => h });
  try {
    const id = nonce();
    assert.equal((await send(s.frontPort, "POST", "/api/public-inquiries", submissionHeaders(s.frontPort, id), validForm)).status, 200);
    assert.equal(s.captured.length, 1);
    const before = s.origin.appStats();
    const replayed = await raw(s.boundaryPort, s.captured[0]);
    assert.match(replayed, /^HTTP\/1\.1 403/);
    await sleep(30);
    assert.equal(s.boundaryEvents.filter((event) => event.kind === "BOUNDARY_REJECTED").at(-1)?.reason, "ob.replayed");
    assert.deepEqual(s.origin.appStats().executed, before.executed);
    assert.deepEqual(s.origin.appStats().stateMutations, 1, "the replay did not mutate");
  } finally { await s.close(); }
});

test("a Defense Plane that is gone changes nothing at the boundary: direct traffic is still refused and the application is never reached", async () => {
  const s = await stack();
  try {
    assert.equal((await send(s.frontPort, "GET", "/gizlilik", { "x-ba0-nonce": nonce() })).status, 200);
    await s.front.close(100);
    const executedBefore = s.origin.appStats().executed;
    for (const [method, path, headers, body] of [
      ["GET", "/", {}, undefined], ["GET", "/gizlilik", { "x-ba0-hop": "1" }, undefined],
      ["POST", "/api/public-inquiries", { "content-type": FORM, origin: `http://127.0.0.1:${s.boundaryPort}` }, validForm],
    ] as const) {
      const reply = await send(s.boundaryPort, method, path, { "x-ba0-nonce": nonce(), ...headers }, body);
      assert.equal(reply.status, 403, `${method} ${path}`);
    }
    assert.equal(s.origin.appStats().executed, executedBefore, "no direct request executed");
    assert.equal(s.origin.appStats().stateMutations, 0);
    const stats = s.boundary.stats();
    assert.equal(stats.rejected, 3);
    assert.equal(stats.rejectedByReason["ob.proof_missing"], 3);
  } finally { await s.close(); }
});

test("the boundary's replay set is bounded: at capacity a verified request fails closed with 503 and nothing already admitted is evicted", async () => {
  const s = await stack({ replayCapacity: 2, mutate: (h) => h });
  try {
    for (let index = 0; index < 2; index++) assert.equal((await send(s.frontPort, "GET", "/gizlilik", { "x-ba0-nonce": nonce() })).status, 200);
    const third = await send(s.frontPort, "GET", "/gizlilik", { "x-ba0-nonce": nonce() });
    assert.equal(third.status, 503, "authenticated but refused for capacity: a status unauthenticated senders can never trigger");
    await sleep(30);
    assert.equal(s.boundary.stats().rejectedByReason["ob.replay_cache_full"], 1);
    assert.equal(s.boundary.stats().replay.capacityRejected, 1);
    assert.equal(s.origin.appStats().executed, 2, "the refused request never reached the application");
    assert.equal(s.captured.length, 3);
    for (const request of s.captured.slice(0, 2)) assert.match(await raw(s.boundaryPort, request), /^HTTP\/1\.1 403/, "an admitted request is still a replay, not a free slot");
    assert.match(await raw(s.boundaryPort, s.captured[2]), /^HTTP\/1\.1 503/, "the refused one was never reserved: still refused for capacity, still no entry created");
  } finally { await s.close(); }
});

test("no 100-continue invitation, no upgrade, no tunnel: the boundary refuses each before reading anything", async () => {
  const s = await stack();
  try {
    const expect = await raw(s.boundaryPort, `POST /api/public-inquiries HTTP/1.1\r\nHost: x.test\r\nExpect: 100-continue\r\nContent-Type: ${FORM}\r\nContent-Length: 6\r\nConnection: close\r\nX-Ba0-Nonce: ${nonce()}\r\n\r\nname=A`);
    assert.match(expect, /^HTTP\/1\.1 403/);
    assert.doesNotMatch(expect, /100 Continue/, "the boundary never invites a body from an unauthenticated sender");
    await raw(s.boundaryPort, "GET / HTTP/1.1\r\nHost: x.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
    await raw(s.boundaryPort, "CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n");
    await sleep(50);
    const stats = s.boundary.stats();
    assert.equal(stats.rejectedByReason["ob.expect_refused"], 1);
    assert.equal(stats.protocolRefused, 2);
    assert.equal(stats.contentReadsStarted, 0, "nothing was read from any of them");
    assert.equal(s.origin.appStats().executed, 0);
  } finally { await s.close(); }
});

test("an application failure behind the boundary is attributed to the forward, not to authentication", async () => {
  const s = await stack();
  try {
    s.origin.armFault({ kind: "reset", remaining: 1 });
    const reply = await send(s.frontPort, "GET", "/gizlilik", { "x-ba0-nonce": nonce() });
    assert.equal(reply.status, 502);
    await sleep(50);
    const stats = s.boundary.stats();
    assert.equal(stats.forwardFailedByKind.reset, 1);
    assert.equal(stats.admitted, 1, "the request WAS authenticated");
    assert.equal(stats.rejected, 0);
  } finally { await s.close(); }
});

test("the boundary has no fail-open construction: it needs a fixed loopback app port and key material, and exposes no mode, flag or route", async () => {
  const root = new HopTrustRoot();
  const material = root.keyMaterial();
  const base = {
    keyP: importPublicKey(material.publicP), kidP: root.kidP, boundaryId: root.boundaryId, keyB: importPrivateKey(material.privateB), kidB: root.kidB, appId: root.appId,
    limits: { replayCapacity: 8, bodyDeadlineMs: 100, forwardTimeoutMs: 100, baLifetimeMs: 1_000 }, emit: () => 0,
  };
  for (const appPort of [0, -1, 65_536, 1.5, Number.NaN]) assert.throws(() => createBoundary({ ...base, appPort }), /fixed 127\.0\.0\.1 port/);
  assert.throws(() => importPublicKey("not a key"));
  const boundary = createBoundary({ ...base, appPort: 9 });
  assert.deepEqual(Object.keys(boundary).sort(), ["close", "listen", "stats"], "no pass-through, health or admin surface");
});
