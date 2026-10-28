import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { createBoundary } from "../defense/boundary/boundary";
import { admitHopRequest, newAdmissionStats, type BaAdmissionConfig, type PbAdmissionConfig } from "../defense/core/hop-admission";
import { HOP_SKEW_MS, checkProofWindow, importPrivateKey, importPublicKey } from "../defense/core/hop-proof";
import { ClockFence, ReplayGuard, type ReserveRequest } from "../defense/core/replay-guard";
import { OB_REASONS } from "../defense/core/types";
import type { AppEvent, BoundaryEvent } from "../defense/core/ledger";
import { createAppGuard } from "../defense/origin/app-guard";
import { createSyntheticOrigin } from "../defense/origin/synthetic-origin";
import { HopTrustRoot, type OracleRequest } from "../lab/defense/hop-keys";

/**
 * P0-02 expiry horizon (EH). Replay retention is measured on the monotonic clock, but a proof's validity window is on the wall clock; a
 * wall step backward after an entry was purged used to reopen the window. EH makes the guard remember the highest `windowEnd` of any
 * purged entry (the horizon) and refuse a new reservation unless the SAME wall sample used for the window check is strictly greater.
 *
 * Every clock here is injected and nothing waits. What these tests establish is stated in each title; they are examples and a bounded
 * exhaustive search over small event sequences, not a proof. The proof is in the header comment of defense/core/replay-guard.ts.
 * NOT covered, deliberately: a verifier restart (the cache and the horizon live in the process), see the last test.
 */
const W0 = 1_800_000_000_000;
const GET: OracleRequest = { method: "GET", target: "/gizlilik", host: "limitmark.test", body: Buffer.alloc(0) };
const PB_LIFE = 5_000, BA_LIFE = 2_000;
let counter = 0;
const tag = (suffix: string) => `${String(++counter).padStart(21, "0")}${suffix}`;

// ---------------------------------------------------------------------------
// Admission-level rig: real signed proofs, real admitHopRequest, two independent verifiers sharing injected clocks
// ---------------------------------------------------------------------------

type Clock = { wall: number; mono: number };
function rig(options: { pbCapacity?: number; appCapacity?: number; wallOf?: (clock: Clock) => number } = {}) {
  const clock: Clock = { wall: W0, mono: 10_000 };
  const root = new HopTrustRoot();
  const material = root.keyMaterial();
  const wall = options.wallOf ? () => options.wallOf!(clock) : () => clock.wall;
  const mono = () => clock.mono;
  const pbGuard = new ReplayGuard(options.pbCapacity ?? 4_096, mono);
  const baGuard = new ReplayGuard(options.appCapacity ?? 8_192, mono);
  const pb: PbAdmissionConfig = {
    role: "pb", keyP: importPublicKey(material.publicP), kidP: root.kidP, boundaryId: root.boundaryId, guard: pbGuard, fence: new ClockFence(wall, mono), now: wall,
    bodyDeadlineMs: 2_000, stats: newAdmissionStats(),
  };
  const ba: BaAdmissionConfig = {
    role: "ba", keyB: importPublicKey(material.publicB), kidB: root.kidB, keyP: importPublicKey(material.publicP), kidP: root.kidP, appId: root.appId, boundaryId: root.boundaryId,
    guard: baGuard, fence: new ClockFence(wall, mono), now: wall, bodyDeadlineMs: 2_000, stats: newAdmissionStats(),
  };
  const headers = (id: string, extra: [string, string][]) => ["host", GET.host, "connection", "close", "x-ba0-nonce", id, ...extra.flat()];
  const request = (rawHeaders: string[]) => { const stream = new PassThrough(); stream.end(); return { method: "GET", url: GET.target, rawHeaders, stream }; };
  const mintPb = (iat = clock.wall) => root.mintPb({ request: GET, corr: tag("p"), iat, exp: iat + PB_LIFE });
  const mintChain = (iat = clock.wall) => {
    const corr = tag("c");
    const pbProof = root.mintPb({ request: GET, corr, iat, exp: iat + PB_LIFE });
    return { corr, pb: pbProof, ba: root.mintBa({ request: GET, corr, hop: pbProof.hop, pb: pbProof, iat, exp: iat + BA_LIFE }) };
  };
  /** A FRESH Boundary-to-App proof (new id, current time) over an already consumed Plane proof: only the lineage key can recognise the reuse. */
  const freshBaOver = (chain: { corr: string; pb: ReturnType<typeof root.mintPb> }) => ({
    corr: chain.corr, pb: chain.pb, ba: root.mintBa({ request: GET, corr: chain.corr, hop: chain.pb.hop, pb: chain.pb, iat: clock.wall, exp: clock.wall + BA_LIFE }),
  });
  type Chain = ReturnType<typeof mintChain>;
  return {
    clock, root, pb, ba, pbGuard, baGuard, mintPb, mintChain, freshBaOver,
    advance: (ms: number) => { clock.wall += ms; clock.mono += ms; },
    stepWall: (ms: number) => { clock.wall += ms; },
    presentPb: async (proof: { header: string }): Promise<string> => { const out = await admitHopRequest(pb, request(headers(tag("n"), [["x-ba0-hop-pb", proof.header]]))); return out.ok ? "ADMITTED" : out.reason; },
    presentChain: async (chain: Chain): Promise<string> => { const out = await admitHopRequest(ba, request(headers(tag("n"), [["x-ba0-hop-ba", chain.ba.header], ["x-ba0-hop-pb", chain.pb.header]]))); return out.ok ? "ADMITTED" : out.reason; },
  };
}
type Rig = ReturnType<typeof rig>;

// ---------------------------------------------------------------------------
// Guard-level helpers (real checkProofWindow + real ReplayGuard, no signatures: fast enough for an exhaustive search)
// ---------------------------------------------------------------------------

type Comp = { key: string; iat: number; exp: number; role: "pb" | "ba"; retain: number };
let ids = 0;
const compsPb = (iat: number): Comp[] => [{ key: `pb:${++ids}`, iat, exp: iat + PB_LIFE, role: "pb", retain: 8_000 }];
const compsChain = (iat: number): Comp[] => [{ key: `ba:${++ids}`, iat, exp: iat + BA_LIFE, role: "ba", retain: 5_000 }, { key: `ln:${++ids}`, iat, exp: iat + PB_LIFE, role: "pb", retain: 8_000 }];
const KEYS = new Map([["k", null as never]]);
/** The same two steps hop-admission runs: window checks and reservation, on ONE wall sample. `gateWall` lets the control run neutralise the gate. */
function admitComps(guard: ReplayGuard, clock: Clock, comps: Comp[], fenceMs = W0, gateWall = clock.wall): string {
  for (const c of comps) {
    const w = checkProofWindow({ kid: "k", aud: "a", iat: c.iat, exp: c.exp, role: c.role } as never, { keys: KEYS, aud: "a", nowMs: clock.wall, fenceMs });
    if (w !== null) return w;
  }
  const result = guard.reserve(comps.map((c): ReserveRequest => ({ key: c.key, retainMs: c.retain, windowEndMs: c.exp + HOP_SKEW_MS })), gateWall);
  if (!result.ok) return result.reason;
  result.ticket.commit();
  return "ADMITTED";
}

// ---------------------------------------------------------------------------
// 1-2. replay after retention expiry and a wall rollback; recovery
// ---------------------------------------------------------------------------

test("[1] a consumed PB is refused after its monotonic retention expired and the wall clock stepped back (it was admitted before EH)", async () => {
  const r = rig();
  const proof = r.mintPb();
  assert.equal(await r.presentPb(proof), "ADMITTED");
  r.advance(8_300);   // past the 8 s retention: the entry is purged on the next reservation
  r.stepWall(-4_000); // the wall is now inside the proof's validity window again (iat..exp+skew)
  assert.ok(r.clock.wall <= W0 + PB_LIFE + HOP_SKEW_MS, "the replay is inside the proof's wall window, so only the horizon can stop it");
  assert.equal(await r.presentPb(proof), "ob.expiry_horizon");
  assert.equal(r.pbGuard.stats().horizonRejected, 1);
  assert.equal(r.pbGuard.stats().replayRejected, 0, "the entry was already purged: this is not a cache hit");
});

test("[2] the hold ends exactly when the wall passes the horizon: equal is still held, one millisecond later a fresh proof is admitted", async () => {
  const r = rig();
  const proof = r.mintPb(); // windowEnd = W0 + 5000 + 1000
  await r.presentPb(proof);
  r.advance(8_300); r.stepWall(-4_000);                       // wall = W0 + 4300
  assert.equal(await r.presentPb(r.mintPb()), "ob.expiry_horizon", "a fresh, validly signed proof is held too: it cannot be told from a replay by time alone");
  r.stepWall(W0 + 6_000 - r.clock.wall);                      // wall == horizon
  assert.equal(await r.presentPb(r.mintPb()), "ob.expiry_horizon", "strictly greater is required");
  r.advance(1);
  assert.equal(await r.presentPb(r.mintPb()), "ADMITTED");
  assert.equal(await r.presentPb(proof), "ob.expired", "and the old proof is now outside its window, so the window check refuses it before EH is consulted");
});

// ---------------------------------------------------------------------------
// 3-5. distinct boundaries, partial purge, burned and committed entries
// ---------------------------------------------------------------------------

test("[3][4] BA and lineage keep their own window ends; a partial purge leaves the unpurged key to refuse as replayed; the later boundary sets the horizon", async () => {
  const r = rig();
  const chain = r.mintChain(); // ba windowEnd W0+3000 (retained 5 s), ln windowEnd W0+6000 (retained 8 s)
  assert.equal(await r.presentChain(chain), "ADMITTED");
  r.advance(5_300); r.stepWall(-4_000);                       // wall = W0 + 1300: the ba: entry is purged, the ln: entry is not
  assert.equal(await r.presentChain(chain), "ob.replayed", "ln: is still cached: all-or-nothing, and this is a cache hit, not a horizon hold");
  assert.equal(await r.presentChain(r.freshBaOver(chain)), "ob.replayed", "a fresh BA over the consumed Plane proof is caught by the lineage key alone");
  assert.equal(r.baGuard.stats().size, 1, "only the ln: entry is left; the refused replays created nothing");
  r.advance(3_000);                                           // mono +8300: ln: purged too; wall = W0 + 4300
  assert.ok(r.clock.wall > W0 + BA_LIFE + HOP_SKEW_MS, "the BA boundary alone (W0+3000) would let a fresh BA over the old lineage through");
  assert.equal(await r.presentChain(chain), "ob.expired", "the original BA is outside its own (shorter) window: the window check refuses first");
  assert.equal(await r.presentChain(r.freshBaOver(chain)), "ob.expiry_horizon", "the lineage boundary (W0+6000) holds it");
  r.stepWall(W0 + PB_LIFE + HOP_SKEW_MS + 1 - r.clock.wall);
  assert.equal(await r.presentChain(r.freshBaOver(chain)), "ob.expired", "past the lineage window the PB window check refuses it");
  assert.equal(await r.presentChain(r.mintChain()), "ADMITTED");
});

test("[5] burned and committed entries both raise the horizon when purged; a RESERVED entry never does", () => {
  const clock: Clock = { wall: W0, mono: 1_000 };
  const guard = new ReplayGuard(8, () => clock.mono);
  const committed = guard.reserve([{ key: "pb:committed", retainMs: 8_000, windowEndMs: W0 + 6_000 }], clock.wall);
  assert.ok(committed.ok); committed.ticket.commit();
  const burned = guard.reserve([{ key: "pb:burned", retainMs: 8_000, windowEndMs: W0 + 7_000 }], clock.wall);
  assert.ok(burned.ok); burned.ticket.burn();
  const inFlight = guard.reserve([{ key: "pb:inflight", retainMs: 100, windowEndMs: W0 + 90_000 }], clock.wall);
  assert.ok(inFlight.ok); // never settled
  clock.mono += 100_000;
  const probe = (windowEndMs: number, wall: number) => guard.reserve([{ key: `pb:probe${windowEndMs}`, retainMs: 8_000, windowEndMs }], wall);
  assert.deepEqual(probe(1, W0 + 7_000), { ok: false, reason: "horizon" }, "the burned entry's windowEnd (W0+7000) is the horizon; the committed one (W0+6000) is lower");
  assert.equal(guard.stateOf("pb:inflight"), "RESERVED", "an in-flight reservation survives any purge");
  assert.ok(probe(2, W0 + 7_001).ok, "the in-flight entry (windowEnd W0+90000) did not raise the horizon");
  assert.equal(guard.stateOf("pb:committed"), "UNSEEN");
});

// ---------------------------------------------------------------------------
// 6-8. rollback with nothing consumed, forward spike with and without admissions
// ---------------------------------------------------------------------------

test("[6] a wall rollback before ANY proof was consumed holds nothing (the horizon starts below every clock)", async () => {
  const r = rig();
  r.advance(60_000); r.stepWall(-30_000); // wall = W0 + 30 s, still after the verifier's start fence
  for (let i = 0; i < 20; i++) { r.advance(1_000); assert.equal(await r.presentPb(r.mintPb()), "ADMITTED"); }
  assert.equal(r.pbGuard.stats().horizonRejected, 0);
});

test("[7] a forward spike during which nothing was admitted leaves no hold after the correction", async () => {
  const r = rig();
  r.advance(10_000);
  r.stepWall(3_600_000);
  r.advance(30_000);
  const forged = r.root.mintPb({ request: GET, corr: tag("f"), key: "attacker", iat: r.clock.wall, exp: r.clock.wall + PB_LIFE });
  assert.equal(await r.presentPb(forged), "ob.signature_invalid", "observed by an unauthenticated request only: refused before any reservation");
  assert.equal(await r.presentPb({ header: "garbage" }), "ob.proof_malformed");
  r.stepWall(-3_600_000);
  for (let i = 0; i < 10; i++) { r.advance(1_000); assert.equal(await r.presentPb(r.mintPb()), "ADMITTED"); }
  assert.equal(r.pbGuard.stats().horizonRejected, 0);
});

test("[8] a forward spike WITH admitted proofs, then a correction: every refusal is an expiry-horizon hold, the hold ends at the last spike window end, no id is admitted twice", async () => {
  const r = rig();
  const consumed: { header: string }[] = [];
  const tick = async () => { r.advance(1_000); const proof = r.mintPb(); const result = await r.presentPb(proof); if (result === "ADMITTED") consumed.push(proof); return { result, wall: r.clock.wall }; };
  for (let i = 0; i < 10; i++) await tick();
  r.stepWall(3_600_000);
  let lastSpikeWindowEnd = 0;
  for (let i = 0; i < 30; i++) { const t = await tick(); assert.equal(t.result, "ADMITTED"); lastSpikeWindowEnd = t.wall + PB_LIFE + HOP_SKEW_MS; }
  r.stepWall(-3_600_000);
  let firstAdmitted = -1; const refusals = new Set<string>();
  for (let i = 0; i < 3_700 && firstAdmitted < 0; i++) {
    const t = await tick();
    if (t.result === "ADMITTED") firstAdmitted = t.wall; else refusals.add(t.result);
    for (const old of consumed.slice(-10)) assert.notEqual(await r.presentPb(old), "ADMITTED", "no consumed proof is ever re-admitted");
  }
  assert.deepEqual([...refusals], ["ob.expiry_horizon"]);
  assert.ok(firstAdmitted > lastSpikeWindowEnd && firstAdmitted <= lastSpikeWindowEnd + 1_000, `admitted again at ${firstAdmitted - W0} after the last spike window end ${lastSpikeWindowEnd - W0}`);
  for (let i = 0; i < 20; i++) assert.equal((await tick()).result, "ADMITTED", "and it stays recovered");
});

// ---------------------------------------------------------------------------
// 9. repeated alternating adjustments
// ---------------------------------------------------------------------------

function prng(seed: number) { let s = seed >>> 0 || 1; return () => { s ^= s << 13; s >>>= 0; s ^= s >> 17; s ^= s << 5; s >>>= 0; return s / 0x1_0000_0000; }; }

test("[9] seeded random walks of advances, backward and forward steps and corrections never re-admit a consumed PB or BA+lineage chain", async () => {
  for (const seed of [1, 2, 3]) {
    const r = rig(); const rnd = prng(seed);
    const pbs: { header: string }[] = []; const chains: ReturnType<Rig["mintChain"]>[] = [];
    let admitted = 0;
    for (let step = 0; step < 150; step++) {
      const k = rnd();
      if (k < 0.45) r.advance(Math.floor(rnd() * 3_000)); else if (k < 0.6) r.stepWall(-Math.floor(1 + rnd() * 20_000)); else if (k < 0.75) r.stepWall(Math.floor(1 + rnd() * 20_000)); else r.advance(Math.floor(rnd() * 12_000));
      const p = r.mintPb(); if (await r.presentPb(p) === "ADMITTED") { pbs.push(p); admitted++; }
      const c = r.mintChain(); if (await r.presentChain(c) === "ADMITTED") { chains.push(c); admitted++; }
      for (const old of pbs) assert.notEqual(await r.presentPb(old), "ADMITTED", `seed ${seed} step ${step}`);
      for (const old of chains) assert.notEqual(await r.presentChain(old), "ADMITTED", `seed ${seed} step ${step}`);
    }
    assert.ok(admitted > 20, "the walk admitted a meaningful number of proofs, so the replays were tested against real state");
  }
});

test("[9] bounded exhaustive search: every sequence of 5 events from {+1 s, +9 s, wall -4 s, -12 s, +4 s, +12 s, fresh proof}, every consumed proof replayed after every event, PB and chain", () => {
  const ALPHABET = 7, LENGTH = 5;
  const search = (kind: "pb" | "chain", neutralised: boolean): number => {
    const total = ALPHABET ** LENGTH; let violating = 0;
    for (let n = 0; n < total; n++) {
      const clock: Clock = { wall: W0, mono: 5_000 };
      const guard = new ReplayGuard(1 << 16, () => clock.mono);
      const mint = (iat: number) => (kind === "pb" ? compsPb(iat) : compsChain(iat));
      const gate = () => (neutralised ? Number.MAX_VALUE : clock.wall);
      const consumed: Comp[][] = [];
      const first = mint(clock.wall); assert.equal(admitComps(guard, clock, first, W0, gate()), "ADMITTED"); consumed.push(first);
      let x = n, bad = false;
      for (let i = 0; i < LENGTH && !bad; i++) {
        const event = x % ALPHABET; x = Math.floor(x / ALPHABET);
        if (event === 0) { clock.wall += 1_000; clock.mono += 1_000; } else if (event === 1) { clock.wall += 9_000; clock.mono += 9_000; }
        else if (event === 2) clock.wall -= 4_000; else if (event === 3) clock.wall -= 12_000; else if (event === 4) clock.wall += 4_000; else if (event === 5) clock.wall += 12_000;
        else { const fresh = mint(clock.wall); if (admitComps(guard, clock, fresh, W0, gate()) === "ADMITTED") consumed.push(fresh); }
        for (const old of consumed) if (admitComps(guard, clock, old, W0, gate()) === "ADMITTED") bad = true;
      }
      if (bad) violating++;
    }
    return violating;
  };
  for (const kind of ["pb", "chain"] as const) {
    assert.equal(search(kind, false), 0, `${kind}: no replay is ever admitted`);
    assert.ok(search(kind, true) > 1_000, `${kind}: control run with the gate neutralised finds the pre-EH defect, so the search can see it`);
  }
});

// ---------------------------------------------------------------------------
// 10-11. non-finite clocks and numerical boundaries
// ---------------------------------------------------------------------------

test("[10] non-finite wall samples are refused at the guard (nothing created) and at admission (ob.canon_error, nothing reserved); service resumes when the clock is healthy", async () => {
  const clock: Clock = { wall: W0, mono: 1_000 };
  const guard = new ReplayGuard(8, () => clock.mono);
  for (const bad of [Number.NaN, Infinity, -Infinity, undefined as unknown as number]) {
    assert.deepEqual(guard.reserve([{ key: "pb:x", retainMs: 8_000, windowEndMs: W0 + 6_000 }], bad), { ok: false, reason: "horizon" });
  }
  assert.equal(guard.stats().size, 0);
  assert.equal(guard.stats().horizonRejected, 4);

  let broken = false;
  const r = rig({ wallOf: (c) => (broken ? Number.NaN : c.wall) });
  assert.equal(await r.presentPb(r.mintPb()), "ADMITTED");
  broken = true;
  assert.equal(await r.presentPb(r.mintPb()), "ob.canon_error", "a NaN wall would pass every ordered comparison in the window check: it is refused first");
  assert.equal(await r.presentChain(r.mintChain()), "ob.canon_error");
  assert.equal(r.pbGuard.stats().reserved, 1, "the refused request reserved nothing");
  broken = false; r.advance(1_000);
  assert.equal(await r.presentPb(r.mintPb()), "ADMITTED");

  const monoClock = { wall: W0, mono: 1_000 }; let monoBroken = false;
  const monoGuard = new ReplayGuard(8, () => (monoBroken ? Number.NaN : monoClock.mono));
  assert.ok(monoGuard.reserve([{ key: "pb:a", retainMs: 8_000, windowEndMs: W0 + 6_000 }], W0).ok);
  monoBroken = true;
  assert.deepEqual(monoGuard.reserve([{ key: "pb:b", retainMs: 8_000, windowEndMs: W0 + 6_000 }], W0), { ok: false, reason: "horizon" }, "a non-finite monotonic reading cannot date an entry or a purge");
  assert.equal(monoGuard.stats().size, 1);
});

test("[11] numerical boundaries: window ends must be safe integers; MAX_SAFE_INTEGER is accepted but can never be exceeded; exp + skew past 2^53 is refused", async () => {
  const guard = new ReplayGuard(8, () => 1_000);
  for (const windowEndMs of [Number.MAX_SAFE_INTEGER + 1, 2 ** 53 + 2, 1.5, Number.NaN, Infinity, -Infinity, undefined as unknown as number]) {
    assert.deepEqual(guard.reserve([{ key: "pb:x", retainMs: 8_000, windowEndMs }], W0), { ok: false, reason: "horizon" }, String(windowEndMs));
  }
  assert.equal(guard.stats().size, 0);
  assert.ok(guard.reserve([{ key: "pb:max", retainMs: 8_000, windowEndMs: Number.MAX_SAFE_INTEGER }], W0).ok, "the largest safe window end is representable");

  const clock = { mono: 1_000 };
  const edge = new ReplayGuard(8, () => clock.mono);
  const ok = edge.reserve([{ key: "pb:edge", retainMs: 100, windowEndMs: Number.MAX_SAFE_INTEGER }], W0);
  assert.ok(ok.ok); ok.ticket.commit();
  clock.mono += 1_000;
  assert.deepEqual(edge.reserve([{ key: "pb:next", retainMs: 100, windowEndMs: 1 }], Number.MAX_SAFE_INTEGER), { ok: false, reason: "horizon" }, "strictly greater than the horizon: the largest safe wall is not");

  // Through admission: iat so large that exp + skew = 2^53 is not a safe integer. The window check passes, EH refuses, nothing is reserved.
  const iat = Number.MAX_SAFE_INTEGER - HOP_SKEW_MS - PB_LIFE + 1;
  const big = rig({ wallOf: () => iat });
  const proof = big.root.mintPb({ request: GET, corr: tag("b"), iat, exp: iat + PB_LIFE });
  assert.equal(Number.isSafeInteger(iat + PB_LIFE), true);
  assert.equal(Number.isSafeInteger(iat + PB_LIFE + HOP_SKEW_MS), false);
  assert.equal(await big.presentPb(proof), "ob.expiry_horizon");
  assert.equal(big.pbGuard.stats().reserved, 0);
});

// ---------------------------------------------------------------------------
// 12. capacity and atomicity
// ---------------------------------------------------------------------------

test("[12] precedence is replayed > full > horizon, and every refusal creates nothing (all-or-nothing)", () => {
  const clock: Clock = { wall: W0, mono: 1_000 };
  const guard = new ReplayGuard(3, () => clock.mono);
  const want = (key: string, windowEndMs = W0 + 6_000): ReserveRequest => ({ key, retainMs: 8_000, windowEndMs });
  const first = guard.reserve([want("pb:a"), want("pb:b")], clock.wall);
  assert.ok(first.ok); first.ticket.commit();
  assert.deepEqual(guard.reserve([want("pb:c"), want("pb:a")], clock.wall), { ok: false, reason: "replayed" });
  assert.equal(guard.stats().size, 2, "a replayed member created nothing for the others");
  assert.deepEqual(guard.reserve([want("pb:c"), want("pb:d")], clock.wall), { ok: false, reason: "full" });
  assert.equal(guard.stats().size, 2);
  clock.mono += 8_300; // both entries are purgeable: horizon becomes W0 + 6000
  assert.deepEqual(guard.reserve([want("pb:e"), want("pb:f")], W0 + 6_000), { ok: false, reason: "horizon" });
  assert.equal(guard.stats().size, 0, "purged, and the held request created no entry");
  const s = guard.stats();
  assert.deepEqual([s.capacityRejected, s.horizonRejected, s.replayRejected, s.open], [1, 1, 1, 0]);
  const ok = guard.reserve([want("pb:e"), want("pb:f")], W0 + 6_001);
  assert.ok(ok.ok, "all keys are reserved together once the wall passed the horizon");
  ok.ticket.commit();
  assert.equal(guard.stats().reserved, guard.stats().committed + guard.stats().burned + guard.stats().open);
  clock.mono += 8_300;
  assert.deepEqual(guard.reserve([want("pb:x")], W0 + 6_000), { ok: false, reason: "horizon" }, "the horizon never decreases, whatever windowEnd later entries had");
});

// ---------------------------------------------------------------------------
// 13-14. legitimate traffic and no permanent degradation
// ---------------------------------------------------------------------------

test("[13] legitimate traffic under healthy clocks is never held: 10 req/s, 1 ms wall jitter, an issuer a full skew ahead, and a wall 5% slower than the monotonic clock", async () => {
  for (const [label, wallOf, issuerAhead] of [
    ["lockstep", (c: Clock) => c.wall, 0], ["jitter", (c: Clock) => c.wall + ((c.mono / 100) % 3) - 1, 0], ["issuer +skew", (c: Clock) => c.wall, HOP_SKEW_MS], ["wall 5% slow", (c: Clock) => W0 + Math.round((c.wall - W0) * 0.95), 0],
  ] as const) {
    const r = rig({ wallOf });
    for (let i = 0; i < 600; i++) {
      r.advance(100);
      const iat = wallOf(r.clock) + issuerAhead;
      assert.equal(await r.presentPb(r.mintPb(iat)), "ADMITTED", `${label} pb ${i}`);
      assert.equal(await r.presentChain(r.mintChain(iat)), "ADMITTED", `${label} chain ${i}`);
    }
    assert.equal(r.pbGuard.stats().horizonRejected + r.baGuard.stats().horizonRejected, 0, label);
    assert.ok(r.pbGuard.stats().purged > 0, `${label}: retention really expired entries during the run, so the gate was exercised`);
  }
});

test("[14] after a survived wall step the freshness window is exactly what it was before (PB 6 s, BA 3 s): no residual lead of the verifier over the wall", async () => {
  const oldestAdmittedAge = async (r: Rig, kind: "pb" | "chain") => {
    let best = -1;
    for (let age = 0; age <= 7_000; age += 10) {
      const iat = r.clock.wall - age;
      if ((kind === "pb" ? await r.presentPb(r.mintPb(iat)) : await r.presentChain(r.mintChain(iat))) === "ADMITTED") best = age;
    }
    return best;
  };
  for (const kind of ["pb", "chain"] as const) {
    for (const step of [-2_000, -10_000, -60_000]) {
      const r = rig();
      const pump = async () => { r.advance(100); return kind === "pb" ? r.presentPb(r.mintPb()) : r.presentChain(r.mintChain()); };
      for (let i = 0; i < 300; i++) await pump();
      const before = await oldestAdmittedAge(r, kind);
      r.stepWall(step);
      // The hold can be intermittent at first: pumps are admitted while older pre-step entries are still cached (safe: distinct ids), and
      // refused again as those entries are purged and raise the horizon. What must hold is that the LAST refusal is within the step plus one retention.
      let lastRefusal = -1; const windowPumps = (Math.abs(step) + 10_000) / 100;
      for (let i = 0; i < windowPumps; i++) if (await pump() !== "ADMITTED") lastRefusal = i;
      assert.ok((lastRefusal + 1) * 100 <= Math.abs(step) + 8_000, `${kind} ${step}: the last refusal is within the step plus one retention (at ${(lastRefusal + 1) * 100} ms)`);
      if (step <= -10_000) assert.ok(lastRefusal >= 0, `${kind} ${step}: a step this large really was held`);
      for (let i = 0; i < 6_000; i++) assert.equal(await pump(), "ADMITTED", `${kind} ${step}: pump ${i} after recovery`);
      assert.equal(await oldestAdmittedAge(r, kind), before, `${kind} ${step}: same freshness window as before the step`);
      assert.equal(before, kind === "pb" ? PB_LIFE + HOP_SKEW_MS : BA_LIFE + HOP_SKEW_MS);
    }
  }
});

// ---------------------------------------------------------------------------
// 15. reason vocabulary, HTTP mapping, counters and ledger reconciliation (Boundary and App, real servers)
// ---------------------------------------------------------------------------

function httpGet(port: number, headers: Record<string, string>): Promise<number> {
  return new Promise((resolve) => {
    const request = http.request({ host: "127.0.0.1", port, method: "GET", path: GET.target, headers: { host: GET.host, ...headers }, agent: false }, (response) => { response.resume(); response.on("end", () => resolve(response.statusCode ?? 0)); });
    request.on("error", () => resolve(0));
    request.end();
  });
}

test("[15] vocabulary: ob.expiry_horizon is a member of the one closed OB_REASONS list, exactly once, distinct from ob.replay_cache_full", () => {
  assert.equal(OB_REASONS.filter((reason) => reason === "ob.expiry_horizon").length, 1);
  assert.notEqual("ob.expiry_horizon", "ob.replay_cache_full");
  assert.equal(new Set(OB_REASONS).size, OB_REASONS.length);
});

test("[15] the Boundary answers an expiry-horizon hold with 503 (authenticated senders only), counts it under its own reason and its own replay counter, and its ledger reconciles", async () => {
  const clock: Clock = { wall: W0, mono: 10_000 };
  const root = new HopTrustRoot(); const material = root.keyMaterial();
  const upstream = http.createServer((_req, res) => { res.statusCode = 200; res.end("ok"); });
  await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const events: BoundaryEvent[] = []; let seq = 0;
  const boundary = createBoundary({
    appPort: (upstream.address() as net.AddressInfo).port, keyP: importPublicKey(material.publicP), kidP: root.kidP, boundaryId: root.boundaryId,
    keyB: importPrivateKey(material.privateB), kidB: root.kidB, appId: root.appId,
    limits: { replayCapacity: 64, bodyDeadlineMs: 1_000, forwardTimeoutMs: 1_000, baLifetimeMs: 1_500 },
    emit: (event) => { events.push({ ...event, seq: ++seq, t: 0 }); return seq; }, now: () => clock.wall, mono: () => clock.mono,
  });
  const port = await boundary.listen();
  try {
    const headersFor = (proof: { header: string }) => ({ "x-ba0-nonce": tag("h"), "x-ba0-hop-pb": proof.header });
    const proof = root.mintPb({ request: GET, corr: tag("h"), iat: clock.wall, exp: clock.wall + PB_LIFE });
    assert.equal(await httpGet(port, headersFor(proof)), 200);
    clock.wall += 8_300 - 4_000; clock.mono += 8_300;
    assert.equal(await httpGet(port, headersFor(proof)), 503, "replay after retention and a rollback: held, with the authenticated-only status");
    assert.equal(await httpGet(port, { "x-ba0-nonce": tag("h") }), 403, "an unauthenticated request still gets the uniform 403");
    const stats = boundary.stats();
    assert.equal(stats.rejectedByReason["ob.expiry_horizon"], 1);
    assert.equal(stats.rejectedByReason["ob.replay_cache_full"], 0);
    assert.equal(stats.rejectedByReason["ob.replayed"], 0);
    assert.equal(stats.replay.horizonRejected, 1);
    assert.equal(stats.replay.capacityRejected, 0);
    assert.equal(events.filter((e) => e.kind === "BOUNDARY_REJECTED" && e.reason === "ob.expiry_horizon").length, 1, "the ledger carries the reason the counter counted");
    assert.deepEqual([stats.arrived, stats.admitted, stats.rejected], [3, 1, 2]);
    assert.equal(stats.replay.reserved, stats.replay.committed + stats.replay.burned, "reservation accounting is closed: the hold reserved nothing");
    assert.equal(stats.replay.open, 0);
    assert.equal(stats.clockStep, true, "the step detector (unchanged, observation-only) still sees the rollback: a lab run in which this happened is INVALID by o2.clock_step_absent, EH or not");
  } finally { await boundary.close(); await new Promise<void>((resolve) => upstream.close(() => resolve())); }
});

test("[15] the App answers an expiry-horizon hold with 503, refuses under the same reason in its own counters and ledger, and executes nothing", async () => {
  const clock: Clock = { wall: W0, mono: 10_000 };
  const root = new HopTrustRoot(); const material = root.keyMaterial();
  const built = createAppGuard({
    keyB: importPublicKey(material.publicB), kidB: root.kidB, keyP: importPublicKey(material.publicP), kidP: root.kidP, appId: root.appId, boundaryId: root.boundaryId,
    replayCapacity: 64, bodyDeadlineMs: 1_000, now: () => clock.wall, mono: () => clock.mono,
  });
  const events: AppEvent[] = []; let seq = 0;
  const origin = createSyntheticOrigin({ instance: "protected", onObservation: () => undefined, guard: built.guard, onApp: (event) => { events.push({ ...event, seq: ++seq, t: 0 }); } });
  const port = await origin.listen();
  try {
    const corr = tag("a");
    const pb = root.mintPb({ request: GET, corr, iat: clock.wall, exp: clock.wall + PB_LIFE });
    const ba = root.mintBa({ request: GET, corr, hop: pb.hop, pb, iat: clock.wall, exp: clock.wall + BA_LIFE });
    const headers = { "x-ba0-nonce": corr, "x-ba0-hop-ba": ba.header, "x-ba0-hop-pb": pb.header };
    assert.equal(await httpGet(port, headers), 200);
    clock.wall += 8_300 - 4_000; clock.mono += 8_300;
    const freshBa = root.mintBa({ request: GET, corr, hop: pb.hop, pb, iat: clock.wall, exp: clock.wall + BA_LIFE }); // the exact BA is already outside its own 3 s window; a fresh BA over the consumed Plane proof is what the lineage boundary holds
    assert.equal(await httpGet(port, { ...headers, "x-ba0-hop-ba": freshBa.header }), 503);
    const counters = origin.appStats();
    assert.equal(counters.refusedByReason["ob.expiry_horizon"], 1);
    assert.deepEqual([counters.admitted, counters.executed, counters.refused], [1, 1, 1], "the held replay was not admitted or executed");
    assert.equal(events.filter((e) => e.kind === "APP_REFUSED" && e.reason === "ob.expiry_horizon").length, 1);
    const replay = built.stats().replay;
    assert.equal(replay.horizonRejected, 1);
    assert.equal(replay.committed, 2, "one chain admitted = BA + lineage entries");
    assert.equal(replay.reserved, replay.committed + replay.burned);
  } finally { await origin.close(); }
});

// ---------------------------------------------------------------------------
// Non-claims, written down as assertions so they cannot be forgotten
// ---------------------------------------------------------------------------

test("NON-CLAIM: a verifier RESTART loses the cache and the horizon; only the start fence remains (it protects only if the wall did not go backward across the restart)", async () => {
  const clock: Clock = { wall: W0, mono: 10_000 };
  const root = new HopTrustRoot(); const material = root.keyMaterial();
  const build = () => {
    const wall = () => clock.wall, mono = () => clock.mono;
    return { role: "pb", keyP: importPublicKey(material.publicP), kidP: root.kidP, boundaryId: root.boundaryId, guard: new ReplayGuard(64, mono), fence: new ClockFence(wall, mono), now: wall, bodyDeadlineMs: 1_000 } as PbAdmissionConfig;
  };
  const present = async (config: PbAdmissionConfig, header: string) => {
    const stream = new PassThrough(); stream.end();
    const out = await admitHopRequest(config, { method: "GET", url: GET.target, rawHeaders: ["host", GET.host, "x-ba0-nonce", tag("r"), "x-ba0-hop-pb", header], stream });
    return out.ok ? "ADMITTED" : out.reason;
  };
  const first = build();
  const proof = root.mintPb({ request: GET, corr: tag("r"), iat: clock.wall, exp: clock.wall + PB_LIFE });
  assert.equal(await present(first, proof.header), "ADMITTED");
  clock.wall += 2_000; clock.mono += 2_000;
  assert.equal(await present(build(), proof.header), "ob.before_fence", "restart without a clock step: the fence refuses the old proof");
  clock.wall -= 30_000; // rollback, then restart
  const restarted = build();
  clock.wall += 28_000; clock.mono += 28_000; // the wall re-enters the old proof's window (iat..exp+skew)
  assert.equal(await present(restarted, proof.header), "ADMITTED", "documented residual risk: replay across a restart that follows a wall rollback is NOT prevented by EH");
});
