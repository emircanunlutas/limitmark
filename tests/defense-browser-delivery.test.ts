import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type net from "node:net";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { AUTHORIZATION_PAGE_TARGET } from "../defense/core/types";
import { createBoundary } from "../defense/boundary/boundary";
import { importPrivateKey, importPublicKey, issuePb } from "../defense/core/hop-proof";
import { JourneyLanes, operationClassOf } from "../defense/core/lanes";
import { RESPONSE_RELAY_HEADERS, type LayerRequest } from "../defense/core/types";
import { AuthorizationPageGate } from "../defense/layers/a7-authorization-page";
import { ShapeGate } from "../defense/layers/a7-shape-gate";
import { MAX_STATIC_ASSETS, StaticAssetGate, validateStaticAssets } from "../defense/layers/a7-static-assets";
import { createAppGuard } from "../defense/origin/app-guard";
import { createFront } from "../defense/plane/front";
import { MAX_RESPONSE_BYTES } from "../defense/plane/runtime";
import { SemanticGate } from "../defense/plane/semantic-gate";
import { BrowserRelay } from "../lab/defense/browser-relay";
import { MAX_RELAYED_ASSET_BYTES, READ_ONLY_PAGE_TARGETS, staticAssetTargets } from "../lab/defense/browser-scope";
import { Collector } from "../lab/defense/collector";
import { HopTrustRoot } from "../lab/defense/hop-keys";

const CSS = "/_next/static/chunks/3eb3zfb5qujm8.css";
const JS = "/_next/static/chunks/turbopack-2u1d16houkiyo.js";
const MANIFEST = "/_next/static/ai7KZ_SCQQ6cqIWYF288w/_buildManifest.js";
const get = (target: string, method = "GET"): LayerRequest => ({ method, target, headers: [["host", "127.0.0.1:3000"]], bodyStatus: "none", body: null });
const listen = async (server: http.Server) => { await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve)); return (server.address() as net.AddressInfo).port; };
const closeServer = (server: http.Server) => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); });

type Reply = { status: number; headers: http.IncomingHttpHeaders; body: Buffer };
function send(port: number, method: string, target: string, headers: Record<string, string> = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: "127.0.0.1", port, method, path: target, headers, agent: false }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks) }));
    });
    request.on("error", reject);
    request.end();
  });
}

test("L1 admits a configured static asset only as an exact, query-free GET; without a list nothing under /_next is admitted", () => {
  const gate = new StaticAssetGate(new ShapeGate(), [CSS, JS, MANIFEST]);
  assert.equal(gate.id, "a7.shape-gate");
  for (const target of [CSS, JS, MANIFEST, "/", "/gizlilik", "/test-talep-et?hizmet=web"]) assert.deepEqual(gate.evaluate(get(target)), { kind: "pass" }, target);
  const cases: [LayerRequest, string][] = [
    [get(`${CSS}?v=1`), "a7.path_not_allowed"],
    [get(CSS, "POST"), "a7.method_not_allowed"],
    [get(CSS, "HEAD"), "a7.method_not_allowed"],
    [{ ...get(CSS), headers: [] }, "a7.host_header_invalid"],
    [{ ...get(CSS), headers: [["host", "127.0.0.1"], ["content-length", "5"]] }, "a7.framing_invalid"],
    [{ ...get(CSS), headers: [["host", "127.0.0.1"], ["x-bad", "\u0001"]] }, "a7.header_value_invalid"],
    [get("/_next/static/chunks/other.js"), "a7.path_not_allowed"],
    [get("/_next/static/chunks/"), "a7.path_not_allowed"],
    [get("/_next/static/CHUNKS/3eb3zfb5qujm8.css"), "a7.path_not_allowed"],
    [get("/_next/image?url=x"), "a7.path_not_allowed"],
    [get("/_next/static/chunks/../chunks/3eb3zfb5qujm8.css"), "a7.target_malformed"],
    [get("/_next/static/chunks/%33eb3zfb5qujm8.css"), "a7.target_malformed"],
    [get("/test-yetkilendirmesi"), "a7.path_not_allowed"],
  ];
  for (const [request, reason] of cases) assert.deepEqual(gate.evaluate(request), { kind: "reject", reason }, request.target);
  const plain = new ShapeGate();
  for (const target of [CSS, JS]) assert.deepEqual(plain.evaluate(get(target)), { kind: "reject", reason: "a7.path_not_allowed" });
});

test("an asset list that is not an exact, bounded set of /_next/static paths is refused at construction", () => {
  for (const bad of [
    ["/_next/static/"], ["/_next/static/../package.json"], ["/_next/static/a/../b.js"], ["/_next/static/./a.js"], ["/_next/static/a.js?x"],
    ["/_next/data/a.json"], ["/public/a.js"], ["/_next/static/a b.js"], ["/_next/static/%2e.js"], ["/_next/static/*"], ["/_next/static/a/b/c/d/e.js"],
    ["/_next/static/.hidden"], [CSS, CSS], [`/_next/static/${"a".repeat(129)}`],
    [],
  ]) assert.throws(() => new StaticAssetGate(new ShapeGate(), bad), /static asset/, JSON.stringify(bad));
  assert.throws(() => validateStaticAssets(Array.from({ length: MAX_STATIC_ASSETS + 1 }, (_, index) => `/_next/static/chunks/c${index}.js`)), /at most/);
  assert.throws(() => validateStaticAssets("/_next/static/a.js" as unknown as string[]), /list/);
  assert.equal(validateStaticAssets([CSS, JS]).size, 2);
});

test("L2 classifies only a configured asset GET as an open read; the pure class map is unchanged", () => {
  const config = {
    filterBits: 1_024, filterHashes: 3, epochMs: 60_000, credited: { capacity: 2, refillPerSecond: 1 }, unverified: { capacity: 1, refillPerSecond: 0.001 },
    maxUses: 2, ledgerCapacity: 4_096, mono: () => 0,
  };
  const lanes = new JourneyLanes({ ...config, openAssets: validateStaticAssets([CSS]) });
  assert.equal(operationClassOf("GET", CSS), "unknown");
  assert.equal(lanes.classOf("GET", CSS), "open");
  assert.equal(lanes.classOf("POST", CSS), "unknown");
  assert.equal(lanes.classOf("GET", `${CSS}?v=1`), "unknown");
  assert.equal(lanes.classOf("GET", JS), "unknown");
  // Open reads never touch a bucket: many asset decisions leave the one-token unverified lane intact.
  for (let index = 0; index < 20; index++) assert.deepEqual(lanes.decide(get(CSS)), { class: "open", lane: "open", outcome: "admitted" });
  assert.equal(lanes.decide(get("/admin")).outcome, "admitted");
  assert.equal(lanes.decide(get("/admin")).outcome, "shed");
  assert.equal(new JourneyLanes(config).classOf("GET", CSS), "unknown");
});

test("browser scope admits only the exact authorization document as an extra open GET", () => {
  const shape = new ShapeGate();
  const gate = new AuthorizationPageGate(shape);
  const config = {
    filterBits: 1_024, filterHashes: 3, epochMs: 60_000, credited: { capacity: 2, refillPerSecond: 1 }, unverified: { capacity: 1, refillPerSecond: 0.001 },
    maxUses: 2, ledgerCapacity: 4_096, mono: () => 0,
  };
  const lanes = new JourneyLanes({ ...config, authorizationPage: true });
  for (const target of READ_ONLY_PAGE_TARGETS) {
    assert.deepEqual(gate.evaluate(get(target)), { kind: "pass" }, target);
    assert.equal(lanes.classOf("GET", target), "open", target);
  }
  assert(READ_ONLY_PAGE_TARGETS.includes(AUTHORIZATION_PAGE_TARGET));
  assert.deepEqual(shape.evaluate(get(AUTHORIZATION_PAGE_TARGET)), { kind: "reject", reason: "a7.path_not_allowed" });
  assert.equal(new JourneyLanes(config).classOf("GET", AUTHORIZATION_PAGE_TARGET), "unknown");
  for (const request of [
    get(AUTHORIZATION_PAGE_TARGET, "POST"), get(AUTHORIZATION_PAGE_TARGET, "HEAD"),
    get(`${AUTHORIZATION_PAGE_TARGET}?x=1`), get(`${AUTHORIZATION_PAGE_TARGET}/`), get("/admin"),
    { ...get(AUTHORIZATION_PAGE_TARGET), headers: [] },
  ]) assert.notDeepEqual(gate.evaluate(request), { kind: "pass" }, request.target);
  for (const request of [
    get(AUTHORIZATION_PAGE_TARGET, "POST"), get(AUTHORIZATION_PAGE_TARGET, "HEAD"),
    get(`${AUTHORIZATION_PAGE_TARGET}?x=1`), get(`${AUTHORIZATION_PAGE_TARGET}/`), get("/admin"),
  ]) assert.equal(lanes.classOf(request.method, request.target), "unknown", request.target);
  assert.equal(new Set(READ_ONLY_PAGE_TARGETS).size, READ_ONLY_PAGE_TARGETS.length);
  assert.equal(MAX_RELAYED_ASSET_BYTES, MAX_RESPONSE_BYTES);
});

test("the asset manifest is read exactly from the build's static output and fails closed on anything it cannot relay", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "lm-assets-"));
  try {
    const dir = path.join(root, ".next", "static");
    mkdirSync(path.join(dir, "chunks"), { recursive: true });
    mkdirSync(path.join(dir, "build1"), { recursive: true });
    writeFileSync(path.join(dir, "chunks", "b.js"), "b");
    writeFileSync(path.join(dir, "chunks", "a.css"), "a");
    writeFileSync(path.join(dir, "build1", "_buildManifest.js"), "m");
    assert.deepEqual(staticAssetTargets(root), ["/_next/static/build1/_buildManifest.js", "/_next/static/chunks/a.css", "/_next/static/chunks/b.js"]);
    writeFileSync(path.join(dir, "chunks", "big.js"), Buffer.alloc(MAX_RELAYED_ASSET_BYTES + 1));
    assert.throws(() => staticAssetTargets(root), /relayed response bound/);
    rmSync(path.join(dir, "chunks", "big.js"));
    writeFileSync(path.join(dir, "chunks", "bad name.js"), "x");
    assert.throws(() => staticAssetTargets(root), /static asset/);
    rmSync(dir, { recursive: true });
    mkdirSync(dir, { recursive: true });
    assert.throws(() => staticAssetTargets(root), /no static assets/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("the plane relays exactly its closed response set, the application's security policies included and unchanged", async () => {
  const upstream = http.createServer((_req, res) => {
    res.writeHead(200, [
      "content-type", "text/html; charset=utf-8", "cache-control", "private, no-store", "content-security-policy", "frame-ancestors 'none'",
      "x-frame-options", "DENY", "referrer-policy", "strict-origin-when-cross-origin", "permissions-policy", "camera=()", "x-content-type-options", "nosniff",
      "set-cookie", "a=b", "server", "x", "x-powered-by", "Next.js", "vary", "rsc", "strict-transport-security", "max-age=1", "x-nextjs-cache", "HIT",
    ]);
    res.end("<p>ok</p>");
  });
  const upstreamPort = await listen(upstream);
  const front = createFront({ upstream: { host: "127.0.0.1", port: upstreamPort }, emit: (() => { let seq = 0; return () => ++seq; })() });
  const port = await front.listen();
  try {
    const reply = await send(port, "GET", "/gizlilik", { "x-ba0-nonce": "C".repeat(22) });
    assert.equal(reply.status, 200);
    const names = Object.keys(reply.headers).filter((name) => !["date", "connection", "keep-alive"].includes(name)).sort();
    assert.deepEqual(names, ["cache-control", "content-length", "content-security-policy", "content-type", "permissions-policy", "referrer-policy", "x-ba0-outcome", "x-content-type-options", "x-frame-options"]);
    for (const name of names) if (!["content-length", "x-ba0-outcome"].includes(name)) assert(RESPONSE_RELAY_HEADERS.has(name), name);
    assert.deepEqual([reply.headers["content-security-policy"], reply.headers["x-frame-options"], reply.headers["referrer-policy"], reply.headers["permissions-policy"]],
      ["frame-ancestors 'none'", "DENY", "strict-origin-when-cross-origin", "camera=()"]);
  } finally { await front.close(500); await closeServer(upstream); }
});

test("an admitted asset crosses plane, boundary and the app's proof verifier with its cache policy; the accepted boundary still drops the four security policies", async () => {
  const root = new HopTrustRoot();
  const material = root.keyMaterial();
  const { guard } = createAppGuard({
    keyB: importPublicKey(material.publicB), kidB: root.kidB, keyP: importPublicKey(material.publicP), kidP: root.kidP, appId: root.appId, boundaryId: root.boundaryId,
    replayCapacity: 64, bodyDeadlineMs: 2_000,
  });
  const served: string[] = [];
  const refusals: string[] = [];
  const boundaryEvents: { kind: string; reason?: string }[] = [];
  const app = http.createServer((req, res) => {
    void guard(req).then((decision) => {
      if (!decision.ok) { refusals.push(decision.reason); res.writeHead(403, { "content-length": 0 }); res.end(); return; }
      served.push(decision.facts.url);
      res.writeHead(200, [
        "content-type", "text/css; charset=UTF-8", "cache-control", "public, max-age=31536000, immutable", "etag", 'W/"1-a"', "last-modified", "Thu, 26 Nov 2026 18:29:47 GMT",
        "content-security-policy", "frame-ancestors 'none'; object-src 'none'; base-uri 'self'", "content-security-policy", "script-src 'self'",
        "x-frame-options", "DENY", "referrer-policy", "strict-origin-when-cross-origin", "permissions-policy", "camera=(), microphone=(), geolocation=()",
        "x-content-type-options", "nosniff", "set-cookie", "session=secret", "server", "origin-identity", "x-powered-by", "Next.js", "vary", "rsc, Accept-Encoding",
        "x-nextjs-cache", "HIT", "access-control-allow-origin", "*", "strict-transport-security", "max-age=1", "accept-ranges", "bytes",
      ]);
      res.end("body{}");
    });
  });
  const appPort = await listen(app);
  const boundary = createBoundary({
    appPort, keyP: importPublicKey(material.publicP), kidP: root.kidP, boundaryId: root.boundaryId, keyB: importPrivateKey(material.privateB), kidB: root.kidB, appId: root.appId,
    limits: { replayCapacity: 64, bodyDeadlineMs: 2_000, forwardTimeoutMs: 2_000, baLifetimeMs: 1_500 }, emit: (event) => boundaryEvents.push(event),
  });
  const boundaryPort = await boundary.listen();
  const issuer = { kid: root.kidP, privateKey: importPrivateKey(material.privateP), boundaryId: root.boundaryId, lifetimeMs: 4_000, now: () => Date.now() };
  const front = createFront({
    upstream: { host: "127.0.0.1", port: boundaryPort }, emit: (() => { let seq = 0; return () => ++seq; })(), layer: new SemanticGate(new StaticAssetGate(new ShapeGate(), [CSS])),
    hop: { issue: (approved, context) => issuePb(issuer, approved, context) },
  });
  const port = await front.listen();
  try {
    const reply = await send(port, "GET", CSS, { "x-ba0-nonce": "A".repeat(22), "accept-encoding": "gzip, br", "if-none-match": 'W/"1-a"', cookie: "a=b" });
    assert.equal(reply.status, 200, JSON.stringify({ refusals, boundary: boundaryEvents.map((event) => `${event.kind}:${event.reason ?? ""}`) }));
    assert.equal(reply.body.toString(), "body{}");
    assert.deepEqual(served, [CSS]);
    const names = Object.keys(reply.headers).filter((name) => !["date", "connection", "keep-alive"].includes(name)).sort();
    // The architectural blocker, pinned here so its removal is a deliberate, visible change: the accepted boundary's relay set has no
    // CSP, X-Frame-Options, Referrer-Policy or Permissions-Policy, so they never reach the plane.
    assert.deepEqual(names, ["cache-control", "content-length", "content-type", "etag", "last-modified", "x-ba0-outcome", "x-content-type-options"]);
    assert.equal(reply.headers["cache-control"], "public, max-age=31536000, immutable");
    assert.equal(reply.headers["x-content-type-options"], "nosniff");
    // A target outside the list never reaches the boundary.
    const other = await send(port, "GET", JS, { "x-ba0-nonce": "B".repeat(22) });
    assert.equal(other.status, 404);
    assert.deepEqual(served, [CSS]);
  } finally {
    await front.close(500);
    await boundary.close();
    await closeServer(app);
  }
});

test("the browser adapter registers every request before sending it, passes the browser's headers unchanged with one measurement tag, and hides only the outcome label", async () => {
  const seen: string[][] = [];
  const plane = http.createServer((req, res) => {
    seen.push([...req.rawHeaders]);
    res.writeHead(200, { "content-type": "text/plain", "content-length": 2, "x-ba0-outcome": "proxied", "content-security-policy": "object-src 'none'" });
    res.end("ok");
  });
  const planePort = await listen(plane);
  const collector = new Collector(null);
  const relay = new BrowserRelay(collector, planePort, (method, target) => `${method} ${target}`);
  const port = await relay.listen();
  try {
    const reply = await send(port, "GET", "/gizlilik", { accept: "text/html", "sec-fetch-mode": "navigate", "x-forwarded-for": "10.0.0.1" });
    assert.equal(reply.status, 200);
    assert.equal(reply.body.toString(), "ok");
    assert.equal(reply.headers["x-ba0-outcome"], undefined);
    assert.equal(reply.headers["content-security-policy"], "object-src 'none'");
    const names = seen[0].filter((_, index) => index % 2 === 0).map((name) => name.toLowerCase());
    for (const name of ["accept", "sec-fetch-mode", "x-forwarded-for", "host"]) assert(names.includes(name), name);
    assert.equal(names.filter((name) => name === "x-ba0-nonce").length, 1);
    const records = [...collector.allRecords()];
    assert.equal(records.length, 1);
    assert.deepEqual(records[0].meta, { lane: "protected", phase: "browser", cls: "canary", scenario: "GET /gizlilik", journey: null, step: null, method: "GET" });
    assert.deepEqual(records[0].harness.map((event) => [event.kind, event.status ?? null, event.outcomeHeader ?? null]), [["SENT", null, null], ["CLIENT_COMPLETED", 200, "proxied"]]);
    const [exchange] = relay.exchanges();
    assert.deepEqual([exchange.rid, exchange.status, exchange.outcome, exchange.bytes], ["r1", 200, "proxied", 2]);
  } finally { await relay.close(); await closeServer(plane); }
});

test("the browser adapter has no fallback: an unreachable plane is an empty 502 recorded as a client-side reset", async () => {
  const plane = http.createServer();
  const planePort = await listen(plane);
  await closeServer(plane);
  const collector = new Collector(null);
  const relay = new BrowserRelay(collector, planePort, () => "page");
  const port = await relay.listen();
  try {
    const reply = await send(port, "GET", "/");
    assert.deepEqual([reply.status, reply.body.length, reply.headers["cache-control"]], [502, 0, "no-store"]);
    const [record] = [...collector.allRecords()];
    assert.deepEqual(record.harness.map((event) => [event.kind, event.result ?? null]), [["SENT", null], ["CLIENT_COMPLETED", "reset"]]);
    await relay.idle();
  } finally { await relay.close(); }
  assert.throws(() => new BrowserRelay(collector, 0, () => "page"), /fixed 127\.0\.0\.1 port/);
});
