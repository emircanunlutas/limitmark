import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { test } from "node:test";
import {
  EMPTY_BODY_SHA256, FORM_CONTENT_TYPE, REFUSED_HEADERS, buildApprovedRequest, canonicalValue, classifyHeader, isApprovedRequest, samePairs, scanHopHeaders, semanticWireHeaders,
  type HeaderClass,
} from "../defense/core/semantic-request";
import type { LayerRequest } from "../defense/core/types";
import { ALL_REJECT_REASONS, REJECT_REASONS, REJECT_STATUS, REJECT_STAGE, SEMANTIC_REJECT_REASONS } from "../defense/core/types";
import { SemanticGate } from "../defense/plane/semantic-gate";
import { ShapeGate } from "../defense/layers/a7-shape-gate";

type H = [string, string][];
const HOST: [string, string] = ["host", "limitmark.test"];
const get = (target: string, headers: H = [HOST]): LayerRequest => ({ method: "GET", target, headers, bodyStatus: "none", body: null });
const post = (body: string, headers: H = [HOST, ["content-type", FORM_CONTENT_TYPE], ["content-length", String(Buffer.byteLength(body))]]): LayerRequest =>
  ({ method: "POST", target: "/api/public-inquiries", headers, bodyStatus: "complete", body: new Uint8Array(Buffer.from(body)) });
const reasonOf = (request: LayerRequest) => { const built = buildApprovedRequest(request); return built.ok ? "ok" : built.reason; };

test("every header name has exactly one class, and the classes match the written policy", () => {
  const expected: Record<string, HeaderClass> = {
    host: "bound", origin: "bound", "content-type": "bound", "content-length": "derived", connection: "transport", "x-ba0-nonce": "measurement",
    "x-ba0-hop-pb": "proof", "x-ba0-hop-ba": "proof", "x-ba0-hop": "spoofable", "x-ba0-class": "spoofable", "x-forwarded-for": "spoofable", "x-forwarded-host": "spoofable",
    forwarded: "spoofable", "x-real-ip": "spoofable", "x-client-ip": "spoofable", "true-client-ip": "spoofable", "cf-connecting-ip": "spoofable", "cf-ipcountry": "spoofable",
    "x-limitmark-origin-secret": "spoofable", "x-vercel-forwarded-for": "spoofable", "x-original-url": "spoofable", "x-rewrite-url": "spoofable", "x-http-method-override": "spoofable",
    "cf-ray": "ingress_indicator", "cf-worker": "ingress_indicator", "cf-pseudo-ipv4": "ingress_indicator",
    accept: "dropped", "user-agent": "dropped", cookie: "dropped", referer: "dropped", "cache-control": "dropped", pragma: "dropped", "if-none-match": "dropped", "sec-fetch-site": "dropped", "keep-alive": "dropped", "proxy-connection": "dropped",
  };
  for (const name of REFUSED_HEADERS) expected[name] = "refused";
  for (const [name, klass] of Object.entries(expected)) assert.equal(classifyHeader(name), klass, name);
  assert.deepEqual([...REFUSED_HEADERS].sort(), ["authorization", "content-encoding", "expect", "if-range", "proxy-authorization", "range", "te", "trailer", "transfer-encoding", "upgrade"]);
});

test("an approved request is the canonical, closed, branded representation: sorted unique pairs, lowercase names, derived length", () => {
  const built = buildApprovedRequest(post("name=A", [["Content-Type", FORM_CONTENT_TYPE], ["HOST", "limitmark.test"], ["Origin", "http://limitmark.test"], ["Content-Length", "6"], ["Connection", "close"]]));
  assert.ok(built.ok);
  assert.deepEqual(built.approved.pairs, [["content-type", FORM_CONTENT_TYPE], ["host", "limitmark.test"], ["origin", "http://limitmark.test"]]);
  assert.equal(built.approved.bodyLen, 6);
  assert.equal(built.approved.method, "POST");
  assert.deepEqual(semanticWireHeaders(built.approved), { "content-type": FORM_CONTENT_TYPE, host: "limitmark.test", origin: "http://limitmark.test", "content-length": "6" });
  assert.equal(isApprovedRequest(built.approved), true);
  assert.equal(isApprovedRequest({ ...built.approved }), false, "a copy is not an approved request: only buildApprovedRequest mints one");
  assert.equal(Object.isFrozen(built.approved), true);
  const bare = buildApprovedRequest(get("/gizlilik"));
  assert.ok(bare.ok);
  assert.equal(bare.approved.bodySha256, EMPTY_BODY_SHA256);
  assert.deepEqual(semanticWireHeaders(bare.approved), { host: "limitmark.test" }, "a GET carries no content-length");
});

test("normalisation is exactly: lowercase names and trimmed ASCII whitespace. Nothing else is rewritten", () => {
  const built = buildApprovedRequest(get("/", [["HoSt", "  limitmark.test \t"], ["oRiGiN", "\t HTTP://LimitMark.TEST/ "]]));
  assert.ok(built.ok);
  assert.deepEqual(built.approved.pairs, [["host", "limitmark.test"], ["origin", "HTTP://LimitMark.TEST/"]], "value case, scheme case, trailing slash all preserved byte for byte");
  assert.equal(canonicalValue("  a b  "), "a b");
  assert.equal(canonicalValue("a\tb"), null, "an internal tab is not representable");
  assert.equal(canonicalValue(""), null);
  assert.equal(canonicalValue("   "), null);
  assert.equal(canonicalValue("café"), null);
  assert.equal(canonicalValue("x".repeat(255))?.length, 255);
  assert.equal(canonicalValue("x".repeat(256)), null);
});

test("a duplicated bound header is refused, in any case and with any values: never merged, never first- or last-wins", () => {
  for (const headers of [
    [HOST, ["origin", "http://a"], ["origin", "http://b"]], [HOST, ["origin", "http://a"], ["ORIGIN", "http://a"]], [HOST, HOST],
    [HOST, ["Host", "evil.test"]],
  ] as H[]) assert.equal(reasonOf(get("/", headers)), "a7.semantic_duplicate", JSON.stringify(headers));
  assert.equal(reasonOf(post("name=A", [HOST, ["content-type", FORM_CONTENT_TYPE], ["content-type", "text/plain"], ["content-length", "6"]])), "a7.semantic_duplicate");
  assert.equal(reasonOf(post("name=A", [HOST, ["content-type", FORM_CONTENT_TYPE], ["content-length", "6"], ["content-length", "6"]])), "a7.semantic_duplicate");
});

test("a value that cannot be represented is refused, never repaired", () => {
  const cases: [string, LayerRequest][] = [
    ["empty origin", get("/", [HOST, ["origin", ""]])], ["blank origin", get("/", [HOST, ["origin", "   "]])], ["over-long origin", get("/", [HOST, ["origin", `http://${"a".repeat(300)}`]])],
    ["control character", get("/", [HOST, ["origin", "http://a\u0001b"]])], ["non-ASCII host", get("/", [["host", "limitmarké.test"]])], ["internal tab", get("/", [HOST, ["origin", "http://a\tb"]])],
    ["content-type on a GET", get("/", [HOST, ["content-type", FORM_CONTENT_TYPE]])], ["no host", get("/", [])],
    ["target too long", get(`/${"a".repeat(300)}`)], ["target without a leading slash", get("gizlilik")],
    ["content-length on a GET other than 0", get("/", [HOST, ["content-length", "5"]])], ["non-numeric length", get("/", [HOST, ["content-length", "abc"]])],
  ];
  for (const [label, request] of cases) assert.equal(reasonOf(request), "a7.semantic_value_invalid", label);
  assert.equal(reasonOf(get("/", [HOST, ["content-length", "0"]])), "ok", "a zero length on a GET carries no meaning and is dropped, not forwarded");
  assert.equal(reasonOf(post("name=A", [HOST, ["content-type", "text/plain"], ["content-length", "6"]])), "a7.semantic_value_invalid");
  assert.equal(reasonOf(post("name=A", [HOST, ["content-length", "6"]])), "a7.semantic_value_invalid", "a POST must carry its content type");
  assert.equal(reasonOf(post("name=A", [HOST, ["content-type", FORM_CONTENT_TYPE], ["content-length", "7"]])), "a7.semantic_value_invalid", "the declared length must equal the body");
  assert.equal(reasonOf({ ...post("name=A"), bodyStatus: "timeout", body: null }), "a7.semantic_value_invalid");
  assert.equal(reasonOf({ ...get("/"), method: "PUT" }), "a7.semantic_value_invalid");
});

test("a header the application interprets but the plane will not forward is refused, never silently dropped", () => {
  for (const name of [...REFUSED_HEADERS, "Content-Encoding", "AUTHORIZATION"]) assert.equal(reasonOf(get("/", [HOST, [name, "x"]])), "a7.semantic_refused_header", name);
  for (const connection of ["origin", "keep-alive, close", "upgrade", "close, upgrade", ""]) assert.equal(reasonOf(get("/", [HOST, ["connection", connection]])), "a7.semantic_refused_header", `connection: ${connection}`);
  assert.equal(reasonOf(get("/", [HOST, ["connection", "close"], ["connection", "close"]])), "a7.semantic_refused_header");
  assert.equal(reasonOf(get("/", [HOST, ["connection", "Keep-Alive"]])), "ok");
  assert.equal(reasonOf(get("/", [HOST, ["x-forwarded-for", "10.0.0.1"]])), "a7.semantic_refused_header", "a spoofable header that somehow reached the gate is refused");
});

test("headers the application never interprets are dropped and counted, and never reach the semantic request", () => {
  const built = buildApprovedRequest(get("/", [HOST, ["accept", "text/html"], ["accept", "text/plain"], ["user-agent", "x"], ["cookie", "a=b"], ["cf-ray", "abc"], ["referer", "http://x/"]]));
  assert.ok(built.ok);
  assert.equal(built.dropped, 6);
  assert.deepEqual(built.approved.pairs, [HOST]);
});

test("the semantic gate refuses only what L1 passed: every Slice-1 reject keeps its reason, and the semantic reasons are a separate closed list", () => {
  const shape = new ShapeGate();
  const gate = new SemanticGate(new ShapeGate());
  for (const request of [get("/admin"), { ...get("/"), method: "DELETE" }, get("/", [["origin", "http://x"]])]) {
    assert.equal(shape.evaluate(request).kind, "reject");
    assert.deepEqual(gate.evaluate(request), shape.evaluate(request), "a request the shape gate rejects keeps the shape gate's exact verdict");
  }
  assert.deepEqual(gate.evaluate(get("/", [HOST, ["origin", "http://a"], ["origin", "http://b"]])), { kind: "reject", reason: "a7.semantic_duplicate" });
  assert.deepEqual(gate.evaluate(get("/", [HOST, ["range", "bytes=0-1"]])), { kind: "reject", reason: "a7.semantic_refused_header" });
  assert.deepEqual(gate.evaluate(get("/", [HOST, ["origin", ""]])), { kind: "reject", reason: "a7.semantic_value_invalid" });
  assert.deepEqual(gate.evaluate(get("/")), { kind: "pass" });
  assert.equal(gate.id, "a7.shape-gate");
  assert.deepEqual(SEMANTIC_REJECT_REASONS, ["a7.semantic_duplicate", "a7.semantic_refused_header", "a7.semantic_value_invalid"]);
  for (const reason of SEMANTIC_REJECT_REASONS) { assert.equal(REJECT_STATUS[reason], 400); assert.equal(REJECT_STAGE[reason], "pre_parse"); assert.ok(!(REJECT_REASONS as readonly string[]).includes(reason)); assert.ok((ALL_REJECT_REASONS as readonly string[]).includes(reason)); }
  assert.equal(REJECT_REASONS.length, 22, "the shape gate's own list is exactly Slice 1's");
});

// ---------------------------------------------------------------------------
// The verifier side, and the plane/verifier equivalence
// ---------------------------------------------------------------------------

const raw = (headers: H): string[] => headers.flatMap(([name, value]) => [name, value]);

test("the verifier's scan reports one violation by fixed precedence: duplicate > unbound > framing > value", () => {
  const scan = (headers: H, method = "GET") => scanHopHeaders(raw(headers), method);
  assert.equal(scan([HOST]).violation, null);
  assert.equal(scan([HOST, HOST]).violation, "ob.header_duplicate");
  assert.equal(scan([HOST, ["x-forwarded-for", "1"]]).violation, "ob.header_unbound");
  assert.equal(scan([HOST, ["cookie", "a=b"]]).violation, "ob.header_unbound");
  assert.equal(scan([HOST, ["authorization", "x"]]).violation, "ob.header_unbound");
  assert.equal(scan([HOST, ["x-ba0-hop", "1"]]).violation, "ob.header_unbound");
  assert.equal(scan([HOST, ["content-length", "0"]]).violation, "ob.framing_invalid", "a GET carries no content-length");
  assert.equal(scan([HOST, ["connection", "origin"]]).violation, "ob.framing_invalid");
  assert.equal(scan([HOST, ["connection", "close"], ["connection", "close"]]).violation, "ob.framing_invalid");
  assert.equal(scan([HOST, ["origin", ""]]).violation, "ob.header_value_invalid");
  assert.equal(scan([HOST, ["origin", "a\tb"]]).violation, "ob.header_value_invalid");
  assert.equal(scan([HOST, ["x-ba0-nonce", "short"]]).violation, "ob.header_value_invalid");
  assert.equal(scan([HOST, ["x-ba0-nonce", "n".repeat(22)], ["x-ba0-nonce", "n".repeat(22)]]).violation, "ob.header_duplicate");
  assert.equal(scan([HOST, HOST, ["x-forwarded-for", "1"], ["content-length", "0"], ["origin", ""]]).violation, "ob.header_duplicate", "precedence: duplicate first");
  assert.equal(scan([HOST, ["x-forwarded-for", "1"], ["content-length", "0"], ["origin", ""]]).violation, "ob.header_unbound", "then unbound");
  assert.equal(scan([HOST, ["content-length", "0"], ["origin", ""]]).violation, "ob.framing_invalid", "then framing");
  assert.equal(scan([HOST, ["content-type", FORM_CONTENT_TYPE], ["content-length", "6"]], "POST").violation, null);
  assert.equal(scan([HOST, ["content-type", FORM_CONTENT_TYPE]], "POST").violation, "ob.framing_invalid", "a POST must carry its content-length");
  assert.equal(scan([HOST, ["content-type", FORM_CONTENT_TYPE], ["content-length", "6"], ["content-length", "6"]], "POST").violation, "ob.framing_invalid");
  assert.equal(scan([HOST, ["content-type", FORM_CONTENT_TYPE], ["content-length", "06"]], "POST").violation, "ob.framing_invalid", "a non-canonical decimal length");
  const proof = scan([HOST, ["X-Ba0-Hop-Pb", "p"], ["x-ba0-hop-ba", "b"], ["X-BA0-NONCE", "n".repeat(22)]]);
  assert.deepEqual([proof.pb, proof.ba, proof.nonces, proof.violation], [["p"], ["b"], ["n".repeat(22)], null], "proof and measurement headers are collected, never flagged as unbound");
});

// A seeded, fixed-count differential test: what the plane approves, a verifier reconstructs identically; anything else executes nothing.
function prng(seed: number): () => number {
  let state = seed >>> 0;
  return () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state / 2 ** 32; };
}

const NAME_VARIANTS: Record<string, string[]> = { host: ["host", "Host", "HOST", "hOsT"], origin: ["origin", "Origin", "ORIGIN"], "content-type": ["content-type", "Content-Type", "CONTENT-TYPE"], connection: ["connection", "Connection"] };
const NOISE: [string, string][] = [["accept", "text/html"], ["user-agent", "ba0"], ["cookie", "a=b"], ["referer", "http://x/"], ["cf-ray", "abc"], ["accept-language", "tr"], ["cache-control", "no-cache"]];
const REFUSALS: [string, string][] = [["range", "bytes=0-1"], ["authorization", "Bearer x"], ["content-encoding", "gzip"], ["te", "trailers"], ["expect", "100-continue"]];
const WEIRD_VALUES = ["", "   ", "a\tb", "x".repeat(300), "café", "http://limitmark.test", "http://LimitMark.test/", "  http://limitmark.test  ", "null"];

test("DIFFERENTIAL (300 seeded cases): what the plane approves, a verifier reconstructs identically; every disagreement fails closed", () => {
  const next = prng(20_260_410);
  const pick = <T>(items: readonly T[]): T => items[Math.floor(next() * items.length)];
  let approved = 0; let refused = 0;
  for (let index = 0; index < 300; index++) {
    const isPost = next() < 0.4;
    const body = isPost ? `name=${"A".repeat(1 + Math.floor(next() * 20))}` : "";
    const headers: H = [];
    const host = pick(["limitmark.test", "127.0.0.1:8080", "LIMITMARK.test", "limitmark.test.", ...(next() < 0.1 ? WEIRD_VALUES : [])]);
    headers.push([pick(NAME_VARIANTS.host), `${next() < 0.3 ? "  " : ""}${host}${next() < 0.3 ? " \t" : ""}`]);
    if (next() < 0.5) headers.push([pick(NAME_VARIANTS.origin), pick(WEIRD_VALUES)]);
    if (isPost) { headers.push([pick(NAME_VARIANTS["content-type"]), next() < 0.9 ? FORM_CONTENT_TYPE : "text/plain"], ["content-length", String(Buffer.byteLength(body))]); }
    if (next() < 0.5) headers.push([pick(NAME_VARIANTS.connection), pick(["close", "keep-alive", "Close"])]);
    for (let n = Math.floor(next() * 4); n > 0; n--) headers.push(pick(NOISE));
    if (next() < 0.1) headers.push(pick(REFUSALS));
    if (next() < 0.1) headers.push(pick(headers.filter(([name]) => /^(host|origin|content-type)$/i.test(name)) ?? [HOST]));
    const request: LayerRequest = isPost
      ? { method: "POST", target: "/api/public-inquiries", headers, bodyStatus: "complete", body: new Uint8Array(Buffer.from(body)) }
      : { method: "GET", target: pick(["/", "/gizlilik", "/test-talep-et", "/test-talep-et?hizmet=web"]), headers, bodyStatus: "none", body: null };
    const built = buildApprovedRequest(request);
    if (!built.ok) { refused++; continue; }
    approved++;
    // The plane would emit exactly these headers. A verifier scanning them must find a clean set equal to the approved pairs.
    const wire = Object.entries(semanticWireHeaders(built.approved));
    const scan = scanHopHeaders(raw([...wire, ["connection", "close"]]), request.method);
    assert.equal(scan.violation, null, `case ${index}: the verifier rejected what the plane approved`);
    assert.ok(samePairs(scan.pairs, built.approved.pairs), `case ${index}: the verifier reconstructed different pairs`);
    // Every single-step tamper of the approved wire either violates the closed set or changes the pairs: it can never match the signed ones silently.
    const tampers: H[] = [
      [...wire, ["x-forwarded-for", "10.0.0.1"]], [...wire, ["cookie", "a=b"]], [...wire, ["host", "evil.test"]], wire.filter(([name]) => name !== "host"),
      [...wire, ["origin", "http://evil.test"]], wire.map(([name, value]) => (name === "host" ? [name, `${value}.`] : [name, value])), [...wire, ["authorization", "x"]],
    ];
    for (const tampered of tampers) {
      const result = scanHopHeaders(raw([...tampered, ["connection", "close"]]), request.method);
      assert.ok(result.violation !== null || !samePairs(result.pairs, built.approved.pairs) || JSON.stringify(tampered) === JSON.stringify(wire), `case ${index}: a tampered request matched the signed pairs`);
    }
  }
  assert.ok(approved > 60 && refused > 60, `the generator exercises both outcomes (approved ${approved}, refused ${refused})`);
});

test("EQUIVALENCE through a real HTTP parser: whitespace and name-case variants canonicalise to one representation; duplicates and extras never do", async () => {
  const seen: string[][] = [];
  const server = http.createServer((request, response) => { seen.push([...request.rawHeaders]); response.writeHead(204, { connection: "close" }); response.end(); });
  server.on("clientError", (_error, socket) => socket.destroy());
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as net.AddressInfo).port;
  const send = (lines: string[]) => new Promise<void>((resolve) => {
    const socket = net.connect(port, "127.0.0.1", () => socket.write(`GET /gizlilik HTTP/1.1\r\n${lines.join("\r\n")}\r\nConnection: close\r\n\r\n`, "latin1"));
    socket.on("close", () => resolve());
    socket.on("data", () => undefined);
  });
  try {
    for (const variant of [["Host: limitmark.test"], ["host:limitmark.test"], ["HOST:   limitmark.test   "], ["hOsT:\tlimitmark.test\t"]]) await send(variant);
    const canonical = seen.map((headers) => { const built = buildApprovedRequest(get("/gizlilik", pairsOf(headers))); assert.ok(built.ok); return JSON.stringify(built.approved.pairs); });
    assert.equal(new Set(canonical).size, 1, `all four spellings canonicalise to one representation: ${canonical.join(" | ")}`);
    for (const headers of seen) {
      const scan = scanHopHeaders(headers, "GET");
      assert.equal(scan.violation, null, "the verifier's view of the same bytes is clean");
      assert.deepEqual(scan.pairs, [["host", "limitmark.test"]], "and reconstructs the same representation as the plane");
    }
    seen.length = 0;
    await send(["Host: limitmark.test", "Origin: http://a", "ORIGIN: http://a"]);
    assert.equal(reasonOf(get("/gizlilik", pairsOf(seen[0]))), "a7.semantic_duplicate");
    assert.equal(scanHopHeaders(seen[0], "GET").violation, "ob.header_duplicate");
  } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
});

function pairsOf(rawHeaders: string[]): H {
  const out: H = [];
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) out.push([rawHeaders[index].toLowerCase(), rawHeaders[index + 1]]);
  return out.filter(([name]) => name !== "connection");
}
