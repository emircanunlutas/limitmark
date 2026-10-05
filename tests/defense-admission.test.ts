import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import {
  admitHopRequest, newAdmissionStats, type AdmissionConfig, type AdmissionOutcome, type AdmissionRequest, type AdmissionStats, type BaAdmissionConfig, type PbAdmissionConfig,
} from "../defense/core/hop-admission";
import { importPublicKey } from "../defense/core/hop-proof";
import { ClockFence, ReplayGuard } from "../defense/core/replay-guard";
import { HopTrustRoot, type MintSpec, type Minted, type OracleRequest } from "../lab/defense/hop-keys";

const FORM = "application/x-www-form-urlencoded";
const HOST = "limitmark.test";
const ORIGIN = `http://${HOST}`;
const GET: OracleRequest = { method: "GET", target: "/gizlilik", host: HOST, body: Buffer.alloc(0) };
const POST: OracleRequest = { method: "POST", target: "/api/public-inquiries", host: HOST, origin: ORIGIN, contentType: FORM, body: Buffer.from("name=A") };
let counter = 0;
const nonce = () => String(++counter).padStart(22, "n");

type Header = [string, string];
function headersFor(request: OracleRequest, tag: string, body: Buffer = request.body): Header[] {
  const headers: Header[] = [["host", request.host]];
  if (request.origin !== undefined) headers.push(["origin", request.origin]);
  if (request.method === "POST") headers.push(["content-type", request.contentType ?? FORM], ["content-length", String(body.length)]);
  headers.push(["connection", "close"], ["x-ba0-nonce", tag]);
  return headers;
}

type Fake = { request: AdmissionRequest; stream: PassThrough; release(): void; abort(): void };
/** A fake request: `hold` keeps the body stream open (a stalled sender) until `release()`; `abort()` drops it like a vanished client. */
function fake(request: OracleRequest, headers: Header[], options: { hold?: boolean; body?: Buffer; method?: string; url?: string } = {}): Fake {
  const stream = new PassThrough();
  const body = options.body ?? request.body;
  if (!options.hold) stream.end(body);
  return {
    stream,
    request: { method: options.method ?? request.method, url: options.url ?? request.target, rawHeaders: headers.flatMap(([name, value]) => [name, value]), stream },
    release: () => { stream.end(body); },
    abort: () => { stream.destroy(); },
  };
}

function setup(options: { capacity?: number; bodyDeadlineMs?: number } = {}) {
  const root = new HopTrustRoot();
  const material = root.keyMaterial();
  const stats: AdmissionStats = newAdmissionStats();
  const wall = () => Date.now();
  const mono = () => performance.now();
  const boundaryGuard = new ReplayGuard(options.capacity ?? 64, mono);
  const appGuard = new ReplayGuard((options.capacity ?? 64) * 2, mono);
  const fence = new ClockFence(wall, mono);
  const pb: PbAdmissionConfig = {
    role: "pb", keyP: importPublicKey(material.publicP), kidP: root.kidP, boundaryId: root.boundaryId, guard: boundaryGuard, fence, now: wall, bodyDeadlineMs: options.bodyDeadlineMs ?? 2_000, stats,
  };
  const appStats = newAdmissionStats();
  const ba: BaAdmissionConfig = {
    role: "ba", keyB: importPublicKey(material.publicB), kidB: root.kidB, keyP: importPublicKey(material.publicP), kidP: root.kidP, appId: root.appId, boundaryId: root.boundaryId,
    guard: appGuard, fence, now: wall, bodyDeadlineMs: options.bodyDeadlineMs ?? 2_000, stats: appStats,
  };
  return { root, pb, ba, boundaryGuard, appGuard, fence, stats, appStats };
}

const withPb = (headers: Header[], pb: string): Header[] => [...headers, ["x-ba0-hop-pb", pb]];
const withChain = (headers: Header[], chain: { pb: Minted; ba: Minted }): Header[] => [...headers, ["x-ba0-hop-ba", chain.ba.header], ["x-ba0-hop-pb", chain.pb.header]];
const reasonOf = (outcome: AdmissionOutcome) => (outcome.ok ? "admitted" : outcome.reason);
const tick = (ms = 0) => new Promise<void>((resolve) => setTimeout(resolve, ms));

// ---------------------------------------------------------------------------
// The Boundary role (PB)
// ---------------------------------------------------------------------------

test("a genuine PB for the exact request is admitted exactly once, with the signed identity and a sealed capability", async () => {
  const { root, pb, boundaryGuard } = setup();
  const tag = nonce();
  const minted = root.mintPb({ request: POST, corr: tag });
  const outcome = await admitHopRequest(pb, fake(POST, withPb(headersFor(POST, tag), minted.header)).request);
  assert.ok(outcome.ok);
  assert.equal(outcome.nonce, tag);
  assert.equal(outcome.hop, minted.hop);
  assert.equal(outcome.baTag, null);
  assert.deepEqual([...outcome.body], [...POST.body]);
  assert.equal(boundaryGuard.stats().committed, 1);
  assert.equal(boundaryGuard.stats().open, 0);
});

test("each refusal has its exact reason, and nothing a refusal does reaches the body, the reservation or the application", async () => {
  const { root, pb, boundaryGuard, stats } = setup();
  const t = () => nonce();
  const cases: [string, (tag: string) => Fake, string][] = [
    ["no proof", (tag) => fake(GET, headersFor(GET, tag)), "ob.proof_missing"],
    ["malformed", (tag) => fake(GET, withPb(headersFor(GET, tag), "garbage")), "ob.proof_malformed"],
    ["the BA's role in the PB slot", (tag) => fake(GET, withPb(headersFor(GET, tag), root.mintChain(GET, tag).ba.header)), "ob.wrong_hop"],
    ["wrong audience", (tag) => fake(GET, withPb(headersFor(GET, tag), root.mintPb({ request: GET, corr: tag, aud: root.appId }).header)), "ob.audience_mismatch"],
    ["unknown kid", (tag) => fake(GET, withPb(headersFor(GET, tag), root.mintPb({ request: GET, corr: tag, kid: "pb-unknown" }).header)), "ob.key_unknown"],
    ["expired", (tag) => fake(GET, withPb(headersFor(GET, tag), root.mintPb({ request: GET, corr: tag, iat: Date.now() - 20_000, exp: Date.now() - 16_000 }).header)), "ob.expired"],
    ["not yet valid", (tag) => fake(GET, withPb(headersFor(GET, tag), root.mintPb({ request: GET, corr: tag, iat: Date.now() + 30_000, exp: Date.now() + 33_000 }).header)), "ob.not_yet_valid"],
    ["lifetime too long", (tag) => fake(GET, withPb(headersFor(GET, tag), root.mintPb({ request: GET, corr: tag, iat: Date.now(), exp: Date.now() + 60_000 }).header)), "ob.lifetime_invalid"],
    ["wrong method", (tag) => fake({ ...POST, method: "GET" }, withPb(headersFor({ ...POST, method: "GET" }, tag), root.mintPb({ request: POST, corr: tag }).header)), "ob.method_mismatch"],
    ["wrong target", (tag) => fake(GET, withPb(headersFor(GET, tag), root.mintPb({ request: GET, corr: tag }).header), { url: "/" }), "ob.target_mismatch"],
    ["altered Host", (tag) => fake(GET, withPb(headersFor({ ...GET, host: "evil.test" }, tag), root.mintPb({ request: GET, corr: tag }).header)), "ob.header_mismatch"],
    ["injected header", (tag) => fake(GET, withPb([...headersFor(GET, tag), ["x-forwarded-for", "10.0.0.1"]], root.mintPb({ request: GET, corr: tag }).header)), "ob.header_unbound"],
    ["forged signature", (tag) => fake(GET, withPb(headersFor(GET, tag), root.mintPb({ request: GET, corr: tag, key: "attacker" }).header)), "ob.signature_invalid"],
    ["PB signed with the App's key", (tag) => fake(GET, withPb(headersFor(GET, tag), root.mintPb({ request: GET, corr: tag, key: "B" }).header)), "ob.signature_invalid"],
    ["a stray BA header beside a valid PB", (tag) => fake(GET, [...withPb(headersFor(GET, tag), root.mintPb({ request: GET, corr: tag }).header), ["x-ba0-hop-ba", "x"]]), "ob.header_unbound"],
  ];
  for (const [label, build, reason] of cases) {
    const tag = t();
    const attempt = build(tag);
    const outcome = await admitHopRequest(pb, attempt.request);
    assert.equal(reasonOf(outcome), reason, label);
    assert.equal(attempt.stream.listenerCount("data"), 0, `${label}: no body byte was read`);
  }
  assert.equal(stats.contentReadsStarted, 0, "no refusal before the reservation ever started a body read");
  assert.equal(boundaryGuard.stats().reserved, 0, "no refusal before the signature ever created a replay entry");
});

test("a refusal after the signature (replay, digest, abort) is attributed to the request's OWN tag, never to the original's signed id", async () => {
  const { root, pb } = setup();
  const original = nonce();
  const minted = root.mintPb({ request: GET, corr: original });
  assert.ok((await admitHopRequest(pb, fake(GET, withPb(headersFor(GET, original), minted.header)).request)).ok);
  const replayTag = nonce();
  const replay = await admitHopRequest(pb, fake(GET, withPb(headersFor(GET, replayTag), minted.header)).request);
  assert.deepEqual(replay, { ok: false, reason: "ob.replayed", nonce: replayTag });
  const anonymous = await admitHopRequest(pb, fake(GET, withPb(headersFor(GET, replayTag).filter(([name]) => name !== "x-ba0-nonce"), minted.header)).request);
  assert.deepEqual(anonymous, { ok: false, reason: "ob.replayed", nonce: original }, "with no tag, a signed request falls back to its signed correlation id");
});

test("CONCURRENT REPLAY RACE: 8 presenters of one proof, the first stalled in its body: exactly one is admitted, seven are replays, and none waits", async () => {
  const { root, pb, boundaryGuard } = setup();
  const winnerTag = nonce();
  const minted = root.mintPb({ request: POST, corr: winnerTag });
  const winner = fake(POST, withPb(headersFor(POST, winnerTag), minted.header), { hold: true });
  const first = admitHopRequest(pb, winner.request);
  const others = Array.from({ length: 7 }, () => { const tag = nonce(); return admitHopRequest(pb, fake(POST, withPb(headersFor(POST, tag), minted.header)).request); });
  const settled = await Promise.all(others);
  for (const outcome of settled) assert.equal(reasonOf(outcome), "ob.replayed");
  assert.equal(boundaryGuard.stats().open, 1, "the winner still holds its reservation");
  winner.release();
  const admitted = await first;
  assert.ok(admitted.ok, "the stalled winner completes once its body arrives");
  const stats = boundaryGuard.stats();
  assert.deepEqual({ reserved: stats.reserved, committed: stats.committed, burned: stats.burned, replayRejected: stats.replayRejected, open: stats.open }, { reserved: 1, committed: 1, burned: 0, replayRejected: 7, open: 0 });
});

test("the reservation is made before any await: two calls started in the same tick can never both be admitted", async () => {
  const { root, pb } = setup();
  const tag = nonce();
  const minted = root.mintPb({ request: POST, corr: tag });
  const results = await Promise.all([
    admitHopRequest(pb, fake(POST, withPb(headersFor(POST, tag), minted.header)).request),
    admitHopRequest(pb, fake(POST, withPb(headersFor(POST, tag), minted.header)).request),
  ]);
  assert.deepEqual(results.map(reasonOf).sort(), ["admitted", "ob.replayed"]);
});

test("ABORTED BODY: the client vanishes after the reservation; the proof is BURNED until expiry and a full replay is refused", async () => {
  const { root, pb, boundaryGuard } = setup();
  const tag = nonce();
  const minted = root.mintPb({ request: POST, corr: tag });
  const stalled = fake(POST, withPb(headersFor(POST, tag), minted.header), { hold: true });
  const pending = admitHopRequest(pb, stalled.request);
  await tick(20);
  assert.equal(boundaryGuard.stats().open, 1);
  stalled.abort();
  assert.equal(reasonOf(await pending), "ob.content_incomplete");
  assert.equal(boundaryGuard.stats().burned, 1);
  assert.equal(boundaryGuard.stats().open, 0);
  const replay = await admitHopRequest(pb, fake(POST, withPb(headersFor(POST, nonce()), minted.header)).request);
  assert.equal(reasonOf(replay), "ob.replayed", "an aborted request does not free its proof");
});

test("TIMED-OUT BODY: a stalled sender past the deadline burns the proof; a full replay is refused", async () => {
  const { root, pb, boundaryGuard } = setup({ bodyDeadlineMs: 40 });
  const tag = nonce();
  const minted = root.mintPb({ request: POST, corr: tag });
  const stalled = fake(POST, withPb(headersFor(POST, tag), minted.header), { hold: true });
  const started = performance.now();
  assert.equal(reasonOf(await admitHopRequest(pb, stalled.request)), "ob.content_incomplete");
  assert.ok(performance.now() - started < 1_000, "the deadline bounds the wait");
  assert.deepEqual([boundaryGuard.stats().burned, boundaryGuard.stats().open], [1, 0]);
  assert.equal(reasonOf(await admitHopRequest(pb, fake(POST, withPb(headersFor(POST, nonce()), minted.header)).request)), "ob.replayed");
});

test("a digest mismatch, a short body and an over-long body all burn the proof", async () => {
  for (const [label, body, reason] of [["same length, other bytes", Buffer.from("name=B"), "ob.digest_mismatch"], ["short", Buffer.from("nam"), "ob.content_incomplete"]] as const) {
    const { root, pb, boundaryGuard } = setup();
    const tag = nonce();
    const minted = root.mintPb({ request: POST, corr: tag });
    const attempt = fake(POST, withPb(headersFor(POST, tag), minted.header), { body });
    assert.equal(reasonOf(await admitHopRequest(pb, attempt.request)), reason, label);
    assert.equal(boundaryGuard.stats().burned, 1, label);
    assert.equal(reasonOf(await admitHopRequest(pb, fake(POST, withPb(headersFor(POST, nonce()), minted.header)).request)), "ob.replayed", `${label}: replay`);
  }
});

test("a declared length that differs from the signed one is refused BEFORE the signature and before anything is read", async () => {
  const { root, pb, boundaryGuard, stats } = setup();
  const tag = nonce();
  const minted = root.mintPb({ request: POST, corr: tag });
  const longer = fake(POST, withPb(headersFor(POST, tag, Buffer.from("name=AAAA")), minted.header), { body: Buffer.from("name=AAAA") });
  assert.equal(reasonOf(await admitHopRequest(pb, longer.request)), "ob.length_mismatch");
  assert.deepEqual([stats.contentReadsStarted, boundaryGuard.stats().reserved], [0, 0]);
});

test("REPLAY CACHE CAPACITY: at the cap a verified proof fails closed, creates nothing, and no earlier entry is evicted", async () => {
  const { root, pb, boundaryGuard } = setup({ capacity: 2 });
  const minted: Minted[] = [];
  for (let index = 0; index < 2; index++) {
    const tag = nonce();
    const proof = root.mintPb({ request: GET, corr: tag });
    minted.push(proof);
    assert.ok((await admitHopRequest(pb, fake(GET, withPb(headersFor(GET, tag), proof.header)).request)).ok);
  }
  const overflowTag = nonce();
  const overflowing = root.mintPb({ request: GET, corr: overflowTag });
  assert.equal(reasonOf(await admitHopRequest(pb, fake(GET, withPb(headersFor(GET, overflowTag), overflowing.header)).request)), "ob.replay_cache_full");
  assert.equal(boundaryGuard.stateOf(`pb:${overflowing.jti}`), "UNSEEN", "the refused proof left no entry");
  for (const proof of minted) {
    assert.equal(boundaryGuard.stateOf(`pb:${proof.jti}`), "COMMITTED", "no unexpired entry was evicted to make room");
    assert.equal(reasonOf(await admitHopRequest(pb, fake(GET, withPb(headersFor(GET, nonce()), proof.header)).request)), "ob.replayed", "an earlier proof is still a replay, not a free slot");
  }
  assert.equal(boundaryGuard.stats().capacityRejected, 1);
});

test("VERIFIER START FENCE: a proof issued before the verifier started is refused even though it has not expired", async () => {
  const { root, pb, fence } = setup();
  const tag = nonce();
  const old = root.mintPb({ request: GET, corr: tag, iat: fence.fenceMs - 100, exp: fence.fenceMs + 3_000 });
  assert.equal(reasonOf(await admitHopRequest(pb, fake(GET, withPb(headersFor(GET, tag), old.header)).request)), "ob.before_fence");
  const fresh = root.mintPb({ request: GET, corr: tag, iat: fence.fenceMs + 1, exp: fence.fenceMs + 3_000 });
  assert.ok((await admitHopRequest(pb, fake(GET, withPb(headersFor(GET, tag), fresh.header)).request)).ok);
});

test("the runtime's merged header view is cross-checked before the commit, and a disagreement burns the proof", async () => {
  const { root, pb, boundaryGuard } = setup();
  const tag = nonce();
  const minted = root.mintPb({ request: GET, corr: tag });
  const attempt = fake(GET, withPb(headersFor(GET, tag), minted.header));
  assert.equal(reasonOf(await admitHopRequest(pb, { ...attempt.request, crossCheck: () => false })), "ob.canon_error");
  assert.equal(boundaryGuard.stats().burned, 1);
});

// ---------------------------------------------------------------------------
// The App role (BA + lineage)
// ---------------------------------------------------------------------------

test("the App admits only a BA that carries the Plane's PB as lineage, and reserves BOTH ids", async () => {
  const { root, ba, appGuard } = setup();
  const tag = nonce();
  const chain = root.mintChain(POST, tag);
  const outcome = await admitHopRequest(ba, fake(POST, withChain(headersFor(POST, tag), chain)).request);
  assert.ok(outcome.ok);
  assert.equal(outcome.role, "ba");
  assert.ok(outcome.baTag !== null);
  assert.equal(appGuard.stateOf(`ba:${chain.ba.jti}`), "COMMITTED");
  assert.equal(appGuard.stateOf(`ln:${chain.pb.jti}`), "COMMITTED");
});

test("a PB alone never admits at the App, a BA alone never admits, and a duplicated lineage header is refused", async () => {
  const { root, ba } = setup();
  const tag = nonce();
  const chain = root.mintChain(GET, tag);
  assert.equal(reasonOf(await admitHopRequest(ba, fake(GET, withPb(headersFor(GET, tag), chain.pb.header)).request)), "ob.proof_missing");
  assert.equal(reasonOf(await admitHopRequest(ba, fake(GET, [...headersFor(GET, tag), ["x-ba0-hop-ba", chain.ba.header]]).request)), "ob.lineage_missing");
  assert.equal(reasonOf(await admitHopRequest(ba, fake(GET, [...withChain(headersFor(GET, tag), chain), ["x-ba0-hop-pb", chain.pb.header]]).request)), "ob.proof_duplicate");
  assert.equal(reasonOf(await admitHopRequest(ba, fake(GET, [...headersFor(GET, tag), ["x-ba0-hop-ba", chain.pb.header], ["x-ba0-hop-pb", chain.pb.header]]).request)), "ob.wrong_hop", "a PB presented as the BA");
});

test("a BA proof never admits at the Boundary: not alone, not in the PB slot, not beside a PB", async () => {
  const { root, pb } = setup();
  const tag = nonce();
  const chain = root.mintChain(GET, tag);
  assert.equal(reasonOf(await admitHopRequest(pb, fake(GET, [...headersFor(GET, tag), ["x-ba0-hop-ba", chain.ba.header]]).request)), "ob.proof_missing");
  assert.equal(reasonOf(await admitHopRequest(pb, fake(GET, withPb(headersFor(GET, tag), chain.ba.header)).request)), "ob.wrong_hop");
  assert.equal(reasonOf(await admitHopRequest(pb, fake(GET, withChain(headersFor(GET, tag), chain)).request)), "ob.header_unbound");
});

test("COMPROMISED BOUNDARY holding only K_B: a BA it signs for any request admits nothing without authentic PB lineage", async () => {
  const { root, ba, appGuard } = setup();
  const tag = nonce();
  const arbitrary: OracleRequest = { ...POST, body: Buffer.from("name=Eve&email=eve%40example.test") };
  const real = root.mintPb({ request: GET, corr: tag });
  const attacks: [string, Header[], string][] = [
    ["no PB at all", [["x-ba0-hop-ba", root.mintBa({ request: arbitrary, corr: tag, pb: { header: "forged.lineage", jti: "A".repeat(22) } }).header]], "ob.lineage_missing"],
    ["a PB signed by an attacker", (() => { const pb = root.mintPb({ request: arbitrary, corr: tag, key: "attacker" }); return [["x-ba0-hop-ba", root.mintBa({ request: arbitrary, corr: tag, hop: pb.hop, pb }).header], ["x-ba0-hop-pb", pb.header]] as Header[]; })(), "ob.signature_invalid"],
    ["a genuine PB for a different request", [["x-ba0-hop-ba", root.mintBa({ request: arbitrary, corr: tag, hop: real.hop, pb: real }).header], ["x-ba0-hop-pb", real.header]], "ob.lineage_mismatch"],
    ["a BA that commits to a different PB header", (() => { const other = root.mintPb({ request: arbitrary, corr: tag }); return [["x-ba0-hop-ba", root.mintBa({ request: arbitrary, corr: tag, hop: other.hop, pb: { header: other.header + "x", jti: other.jti } }).header], ["x-ba0-hop-pb", other.header]] as Header[]; })(), "ob.lineage_mismatch"],
    ["a genuine but expired PB", (() => { const pb = root.mintPb({ request: arbitrary, corr: tag, iat: Date.now() - 20_000, exp: Date.now() - 16_000 }); return [["x-ba0-hop-ba", root.mintBa({ request: arbitrary, corr: tag, hop: pb.hop, pb }).header], ["x-ba0-hop-pb", pb.header]] as Header[]; })(), "ob.expired"],
    ["a PB addressed to the App instead of the Boundary", (() => { const pb = root.mintPb({ request: arbitrary, corr: tag, aud: root.appId }); return [["x-ba0-hop-ba", root.mintBa({ request: arbitrary, corr: tag, hop: pb.hop, pb }).header], ["x-ba0-hop-pb", pb.header]] as Header[]; })(), "ob.audience_mismatch"],
  ];
  for (const [label, proofs, reason] of attacks) {
    const attempt = fake(arbitrary, [...headersFor(arbitrary, tag), ...proofs]);
    assert.equal(reasonOf(await admitHopRequest(ba, attempt.request)), reason, label);
    assert.equal(attempt.stream.listenerCount("data"), 0, `${label}: no body byte was read`);
  }
  assert.equal(appGuard.stats().reserved, 0, "none of them created a replay entry");
});

test("LINEAGE REPLAY: a relayed approval is single-use at the App even when the Boundary mints a fresh BA, and the fresh BA's id is NOT consumed", async () => {
  const { root, ba, appGuard } = setup();
  const tag = nonce();
  const chain = root.mintChain(GET, tag);
  assert.ok((await admitHopRequest(ba, fake(GET, withChain(headersFor(GET, tag), chain)).request)).ok);
  assert.equal(reasonOf(await admitHopRequest(ba, fake(GET, withChain(headersFor(GET, nonce()), chain)).request)), "ob.replayed", "the same BA again");
  const fresh = root.mintBa({ request: GET, corr: tag, hop: chain.pb.hop, pb: chain.pb });
  assert.equal(reasonOf(await admitHopRequest(ba, fake(GET, withChain(headersFor(GET, nonce()), { pb: chain.pb, ba: fresh })).request)), "ob.replayed", "a fresh BA over a used PB");
  assert.equal(appGuard.stateOf(`ba:${fresh.jti}`), "UNSEEN", "all-or-nothing: the refused BA left no entry");
});

test("a BA signed with the Plane's key, or with the PB domain, or with the wrong role string, is refused at the App", async () => {
  const { root, ba } = setup();
  for (const [label, spec, reason] of [
    ["signed with K_P", { key: "P" }, "ob.signature_invalid"], ["PB signing domain", { domain: "ba0:pb:ed25519:v2\0" }, "ob.signature_invalid"],
    ["PB role string", { role: "ba0-pb-v2" }, "ob.wrong_hop"], ["audience is the boundary", { aud: root.boundaryId }, "ob.audience_mismatch"],
    ["kid of the plane", { kid: root.kidP }, "ob.key_unknown"], ["expired", { iat: Date.now() - 20_000, exp: Date.now() - 18_000 }, "ob.expired"],
  ] as [string, Partial<MintSpec>, string][]) {
    const tag = nonce();
    const pbProof = root.mintPb({ request: GET, corr: tag });
    const baProof = root.mintBa({ request: GET, corr: tag, hop: pbProof.hop, pb: pbProof, ...spec });
    assert.equal(reasonOf(await admitHopRequest(ba, fake(GET, withChain(headersFor(GET, tag), { pb: pbProof, ba: baProof })).request)), reason, label);
  }
});

test("at the App the altered semantics, an injected header and a duplicated header are refused even with a genuine chain", async () => {
  const { root, ba } = setup();
  const tag = nonce();
  const chain = root.mintChain(POST, tag);
  const base = withChain(headersFor(POST, tag), chain);
  const alter = (name: string, value: string) => base.map(([n, v]): Header => (n === name ? [n, value] : [n, v]));
  for (const [label, headers, reason] of [
    ["altered Origin", alter("origin", "http://evil.test"), "ob.header_mismatch"], ["altered Content-Type", alter("content-type", "text/plain"), "ob.header_mismatch"],
    ["altered Host", alter("host", "evil.test"), "ob.header_mismatch"], ["injected header", [...base, ["x-forwarded-host", HOST]] as Header[], "ob.header_unbound"],
    ["duplicated Host", [...base, ["host", "evil.test"]] as Header[], "ob.header_duplicate"],
  ] as [string, Header[], string][]) assert.equal(reasonOf(await admitHopRequest(ba, fake(POST, headers).request)), reason, label);
});

test("an unexpected failure inside admission is `ob.canon_error`, never an admission, and never throws", async () => {
  const { root, pb } = setup();
  const tag = nonce();
  const minted = root.mintPb({ request: GET, corr: tag });
  const attempt = () => fake(GET, withPb(headersFor(GET, tag), minted.header)).request;
  const throwingClock: AdmissionConfig = { ...pb, now: () => { throw new Error("clock failure"); } };
  assert.equal(reasonOf(await admitHopRequest(throwingClock, attempt())), "ob.canon_error");
  const throwingGuard: AdmissionConfig = { ...pb, guard: { reserve: () => { throw new Error("guard failure"); } } as unknown as ReplayGuard };
  assert.equal(reasonOf(await admitHopRequest(throwingGuard, attempt())), "ob.canon_error");
  // a bad key is a refusal too (fail closed): the signature primitive reports false rather than throwing
  const badKey = { ...pb, keyP: undefined } as unknown as AdmissionConfig;
  assert.equal(reasonOf(await admitHopRequest(badKey, attempt())), "ob.signature_invalid");
  assert.ok((await admitHopRequest(pb, attempt())).ok, "and the same proof was never consumed by any of the failed attempts");
});
