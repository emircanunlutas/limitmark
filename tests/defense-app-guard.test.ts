import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { test } from "node:test";
import type { AppEvent } from "../defense/core/ledger";
import { importPublicKey } from "../defense/core/hop-proof";
import { OB_REASONS } from "../defense/core/types";
import { createAppGuard } from "../defense/origin/app-guard";
import { createSyntheticOrigin, type AppGuardDecision, type RequestFacts } from "../defense/origin/synthetic-origin";
import { HopTrustRoot, type OracleRequest } from "../lab/defense/hop-keys";

const FORM = "application/x-www-form-urlencoded";
const HOST = "limitmark.test";
const ORIGIN = `http://${HOST}`;
const GET: OracleRequest = { method: "GET", target: "/gizlilik", host: HOST, body: Buffer.alloc(0) };
const validForm = new URLSearchParams({
  name: "Canary Journey", email: "canary@example.test", company: "Synthetic Co", service: "web", system: "synthetic canary system", objective: "synthetic canary objective",
  environment: "staging", authority: "authorized", protection: "unknown", provider: "", notes: "", submissionToken: "A".repeat(43),
}).toString();
const VALID_POST: OracleRequest = { method: "POST", target: "/api/public-inquiries", host: HOST, origin: ORIGIN, contentType: FORM, body: Buffer.from(validForm) };
const INVALID_POST: OracleRequest = { ...VALID_POST, body: Buffer.from("name=A") };
let counter = 0;
const nonce = () => String(++counter).padStart(22, "A");

type Rig = { root: HopTrustRoot; port: number; origin: ReturnType<typeof createSyntheticOrigin>; events: AppEvent[]; facts: RequestFacts[]; close(): Promise<void> };
async function rig(options: { maxConcurrent?: number } = {}): Promise<Rig> {
  const root = new HopTrustRoot();
  const material = root.keyMaterial();
  const built = createAppGuard({
    keyB: importPublicKey(material.publicB), kidB: root.kidB, keyP: importPublicKey(material.publicP), kidP: root.kidP, appId: root.appId, boundaryId: root.boundaryId,
    replayCapacity: 64, bodyDeadlineMs: 500,
  });
  const events: AppEvent[] = []; const facts: RequestFacts[] = [];
  let seq = 0;
  const guard = async (req: http.IncomingMessage): Promise<AppGuardDecision> => { const decision = await built.guard(req); if (decision.ok) facts.push(decision.facts); return decision; };
  const origin = createSyntheticOrigin({ instance: "protected", maxConcurrent: options.maxConcurrent, onObservation: () => undefined, guard, onApp: (event) => { events.push({ ...event, seq: ++seq, t: 0 }); } });
  const port = await origin.listen();
  return { root, port, origin, events, facts, close: () => origin.close() };
}

function send(port: number, request: OracleRequest, headers: [string, string][], body: Buffer = request.body): Promise<{ status: number; body: string; raw: string }> {
  return new Promise((resolve) => {
    const socket = net.connect(port, "127.0.0.1", () => {
      const lines = [`${request.method} ${request.target} HTTP/1.1`, `Host: ${request.host}`, "Connection: close"];
      if (request.origin !== undefined) lines.push(`Origin: ${request.origin}`);
      if (request.method === "POST") lines.push(`Content-Type: ${request.contentType ?? FORM}`, `Content-Length: ${body.length}`);
      for (const [name, value] of headers) lines.push(`${name}: ${value}`);
      socket.write(Buffer.concat([Buffer.from(lines.join("\r\n") + "\r\n\r\n", "latin1"), body]));
    });
    let data = "";
    socket.on("data", (chunk) => { data += chunk.toString("latin1"); });
    const done = () => { const status = /^HTTP\/1\.1 (\d{3})/.exec(data); resolve({ status: status ? Number(status[1]) : 0, body: data.split("\r\n\r\n")[1] ?? "", raw: data }); };
    socket.on("close", done);
    socket.on("error", done);
    setTimeout(() => socket.destroy(), 2_000).unref();
  });
}
const chainHeaders = (root: HopTrustRoot, request: OracleRequest, id: string): [string, string][] => { const chain = root.mintChain(request, id); return [["X-Ba0-Hop-Ba", chain.ba.header], ["X-Ba0-Hop-Pb", chain.pb.header], ["X-Ba0-Nonce", id]]; };

test("a genuine BA+PB chain is admitted, executed and completed: the application counts each stage itself", async () => {
  const r = await rig();
  try {
    const id = nonce();
    const reply = await send(r.port, GET, chainHeaders(r.root, GET, id));
    assert.equal(reply.status, 200);
    assert.match(reply.body, /Gizlilik/);
    assert.deepEqual(r.events.map((event) => event.kind), ["APP_ADMITTED", "APP_EXECUTED", "APP_COMPLETED"]);
    assert.ok(r.events.every((event) => event.nonce === id), "events carry the SIGNED correlation id");
    const counters = r.origin.appStats();
    assert.deepEqual([counters.admitted, counters.executed, counters.stateMutations, counters.refused], [1, 1, 0, 0]);
  } finally { await r.close(); }
});

test("a valid submission with a genuine chain mutates state exactly once, and the application counts the mutation itself", async () => {
  const r = await rig();
  try {
    const id = nonce();
    const headers = chainHeaders(r.root, VALID_POST, id);
    const reply = await send(r.port, VALID_POST, headers);
    assert.equal(reply.status, 200);
    assert.deepEqual(JSON.parse(reply.body), { kind: "redirect", location: "/test-talep-et/tesekkurler" });
    assert.deepEqual(r.events.map((event) => event.kind), ["APP_ADMITTED", "APP_EXECUTED", "APP_MUTATED", "APP_COMPLETED"]);
    assert.equal(r.origin.appStats().stateMutations, 1);
    // the SAME chain again (same bytes, a different measurement tag) changes nothing
    const replay = await send(r.port, VALID_POST, [...headers.slice(0, 2), ["X-Ba0-Nonce", nonce()]]);
    assert.equal(replay.status, 403);
    assert.equal(r.origin.appStats().stateMutations, 1);
    assert.equal(r.origin.appStats().refusedByReason["ob.replayed"], 1);
  } finally { await r.close(); }
});

test("a semantically invalid submission is executed but never mutates; the app counts executed and mutated separately", async () => {
  const r = await rig();
  try {
    const reply = await send(r.port, INVALID_POST, chainHeaders(r.root, INVALID_POST, nonce()));
    assert.equal(reply.status, 200);
    assert.deepEqual(JSON.parse(reply.body), { kind: "state", state: { errors: { form: "invalid" } } });
    const counters = r.origin.appStats();
    assert.deepEqual([counters.executed, counters.stateMutations], [1, 0]);
  } finally { await r.close(); }
});

test("the exact bytes of a valid submission sent straight at the app's own port, with no proof or the wrong proofs, never execute or mutate", async () => {
  const r = await rig();
  try {
    const id = nonce();
    const chain = r.root.mintChain(VALID_POST, id);
    const attacks: [string, [string, string][]][] = [
      ["no proof", [["X-Ba0-Nonce", nonce()]]], ["plain hop and nonce headers", [["X-Ba0-Hop", "1"], ["X-Ba0-Nonce", nonce()]]],
      ["PB only", [["X-Ba0-Hop-Pb", chain.pb.header], ["X-Ba0-Nonce", nonce()]]], ["BA only", [["X-Ba0-Hop-Ba", chain.ba.header], ["X-Ba0-Nonce", nonce()]]],
      ["static-secret style", [["Authorization", "Bearer not-a-secret"], ["X-Limitmark-Origin-Secret", "not-a-secret"], ["X-Ba0-Nonce", nonce()]]],
    ];
    for (const [label, headers] of attacks) {
      const reply = await send(r.port, VALID_POST, headers);
      assert.equal(reply.status, 403, label);
      assert.equal(reply.body, "", `${label}: no body, so nothing about the reason is revealed`);
    }
    const counters = r.origin.appStats();
    assert.deepEqual([counters.admitted, counters.executed, counters.stateMutations, counters.refused], [0, 0, 0, attacks.length]);
    assert.equal(r.events.every((event) => event.kind === "APP_REFUSED"), true);
    assert.equal(counters.refusedByReason["ob.proof_missing"], 4);
    assert.equal(counters.refusedByReason["ob.lineage_missing"], 1);
  } finally { await r.close(); }
});

test("every refusal looks the same from outside: one status, no body, the connection closed", async () => {
  const r = await rig();
  try {
    const id = nonce();
    const chain = r.root.mintChain(GET, id);
    const variants: [string, [string, string][]][] = [
      ["missing", []], ["malformed", [["X-Ba0-Hop-Ba", "x"], ["X-Ba0-Hop-Pb", "y"]]], ["wrong hop", [["X-Ba0-Hop-Ba", chain.pb.header], ["X-Ba0-Hop-Pb", chain.pb.header]]],
      ["injected header", [["X-Ba0-Hop-Ba", chain.ba.header], ["X-Ba0-Hop-Pb", chain.pb.header], ["X-Forwarded-For", "1.2.3.4"]]],
    ];
    const shapes = new Set<string>();
    for (const [, headers] of variants) {
      const reply = await send(r.port, GET, headers);
      shapes.add(`${reply.status}|${reply.body.length}|${/connection: close/i.test(reply.raw)}|${/x-ba0-outcome: refused/i.test(reply.raw)}`);
    }
    assert.deepEqual([...shapes], ["403|0|true|true"]);
  } finally { await r.close(); }
});

test("the application interprets the VERIFIED CLAIMS, not a header view of its own", async () => {
  const r = await rig();
  try {
    const id = nonce();
    await send(r.port, VALID_POST, chainHeaders(r.root, VALID_POST, id));
    assert.equal(r.facts.length, 1);
    assert.deepEqual({ ...r.facts[0], body: r.facts[0].body?.toString() }, { method: "POST", url: "/api/public-inquiries", contentType: FORM, origin: ORIGIN, host: HOST, body: validForm });
    const getId = nonce();
    await send(r.port, GET, chainHeaders(r.root, GET, getId));
    assert.deepEqual(r.facts[1], { method: "GET", url: "/gizlilik", contentType: undefined, origin: undefined, host: HOST, body: null });
  } finally { await r.close(); }
});

test("admitted is not executed: an application at capacity admits (authentic) but does not execute, and the two counters differ", async () => {
  const r = await rig({ maxConcurrent: 0 });
  try {
    const reply = await send(r.port, GET, chainHeaders(r.root, GET, nonce()));
    assert.equal(reply.status, 503);
    const counters = r.origin.appStats();
    assert.deepEqual([counters.admitted, counters.executed], [1, 0]);
    assert.deepEqual(r.events.map((event) => event.kind), ["APP_ADMITTED", "APP_COMPLETED"]);
  } finally { await r.close(); }
});

test("an application failure after admission is an abort with the same lineage identifiers, never a silent loss", async () => {
  const r = await rig();
  try {
    r.origin.armFault({ kind: "reset", remaining: 1 });
    const id = nonce();
    await send(r.port, GET, chainHeaders(r.root, GET, id));
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.deepEqual(r.events.map((event) => event.kind), ["APP_ADMITTED", "APP_ABORTED"]);
    assert.equal(r.events[1].baTag, r.events[0].baTag);
  } finally { await r.close(); }
});

test("`Expect: 100-continue`, upgrade and CONNECT are refused by the app itself, with no invitation and no tunnel", async () => {
  const r = await rig();
  try {
    const id = nonce();
    const expect = await send(r.port, VALID_POST, [["Expect", "100-continue"], ["X-Ba0-Nonce", id]]);
    assert.equal(expect.status, 403);
    assert.doesNotMatch(expect.raw, /100 Continue/);
    await send(r.port, GET, [["Upgrade", "websocket"], ["Connection", "Upgrade"]]);
    await new Promise((resolve) => setTimeout(resolve, 50));
    const counters = r.origin.appStats();
    assert.equal(counters.refusedByReason["ob.expect_refused"], 1);
    assert.ok(counters.protocolRefused >= 0);
    assert.deepEqual([counters.admitted, counters.executed, counters.stateMutations], [0, 0, 0]);
  } finally { await r.close(); }
});

test("the app's counters start at zero for every closed reason and only ever count a reason from the closed list", async () => {
  const r = await rig();
  try {
    assert.deepEqual(Object.keys(r.origin.appStats().refusedByReason).sort(), [...OB_REASONS].sort());
    assert.ok(Object.values(r.origin.appStats().refusedByReason).every((count) => count === 0));
  } finally { await r.close(); }
});

// ---------------------------------------------------------------------------
// Key custody
// ---------------------------------------------------------------------------

test("KEY CUSTODY: each process is given exactly the key material its role needs, and the App is given no private key at all", () => {
  const root = new HopTrustRoot();
  const keys = root.keyMaterial();
  const limits = { replayCapacity: 8, bodyDeadlineMs: 100, forwardTimeoutMs: 100, baLifetimeMs: 1_000 };
  const plane = JSON.stringify(root.planeInit(5_000));
  const boundary = JSON.stringify(root.boundaryInit(1234, limits));
  const app = JSON.stringify(root.appInit({ replayCapacity: 8, bodyDeadlineMs: 100 }));
  assert.ok(plane.includes(keys.privateP) && !plane.includes(keys.privateB) && !plane.includes(keys.publicB) && !plane.includes(root.appId), "the plane: K_P private only, never the App's id or key");
  assert.ok(boundary.includes(keys.publicP) && boundary.includes(keys.privateB) && !boundary.includes(keys.privateP) && !boundary.includes(keys.publicB), "the boundary: K_P public and K_B private, never K_P private");
  assert.ok(app.includes(keys.publicB) && app.includes(keys.publicP) && !app.includes(keys.privateP) && !app.includes(keys.privateB), "the app: public keys only");
  assert.deepEqual(Object.keys(JSON.parse(app) as object).filter((key) => /private/i.test(key)), [], "the App init has no field that could carry a private key");
  assert.notEqual(keys.publicP, keys.publicB, "two distinct keypairs");
  assert.notEqual(keys.privateP, keys.privateB);
  assert.notEqual(root.boundaryId, root.appId, "two distinct audiences");
  assert.notEqual(root.kidP, root.kidB);
  assert.ok(root.kidP.startsWith("pb-") && root.kidB.startsWith("ba-"));
});

test("the App guard cannot be constructed with a private key: its options name public keys only", () => {
  const root = new HopTrustRoot();
  const material = root.keyMaterial();
  const publicOnly = importPublicKey(material.publicB);
  assert.equal(publicOnly.type, "public");
  const options = { keyB: publicOnly, kidB: root.kidB, keyP: importPublicKey(material.publicP), kidP: root.kidP, appId: root.appId, boundaryId: root.boundaryId, replayCapacity: 4, bodyDeadlineMs: 100 };
  assert.equal(options.keyP.type, "public");
  assert.doesNotThrow(() => createAppGuard(options));
});
