import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  ALT_VERSION, AltModel, AttestationAuthority, FAIR_BASE, FairShare, SpentSet, waterLevel, type Ctx,
} from "./support/l2-alt-model";
import { CORE_VARIANTS, CREDITED_BOUND, DEV_SEEDS, EVAL_SEEDS, generate, runScenario, runVariant, VARIANTS } from "./support/l2-alt-matrix";
import { ALT_CRITERIA, buildAltScenarios, evaluateAlt } from "./support/l2-alt-scenarios";
import { laneConfig } from "./support/l2-v2-shadow";

/**
 * EXPERIMENTAL, RESEARCH-ONLY comparison of L2 alternatives (max-min fair-share, attested reserved pool) against V1 and the previously evaluated
 * Approach A, versioned `l2-alt-research-experimental-1`. Nothing here is production behaviour: models live in tests/support, V1 is imported
 * read-only, clocks and seeds are injected. The literals pinned below are MEASUREMENTS of a deterministic simulation (3 evaluation seeds x 120 s virtual
 * time); a change that moves them is a reviewed change to this file. Interpretation: docs/BA0_L2_V2_ALTERNATIVES_EVALUATION.md.
 */

const tok = (n: string) => createHash("sha256").update(`alt-test:${n}`).digest("base64url");
const post = (token: string) => ({ method: "POST", target: "/api/public-inquiries", headers: [] as [string, string][], bodyStatus: "complete" as const, body: Buffer.from(`name=A&submissionToken=${token}`, "latin1") });

test("versioning and pre-registration: models are labelled experimental, the criteria and seed sets are the recorded ones", () => {
  assert.equal(ALT_VERSION, "l2-alt-research-experimental-1");
  assert.deepEqual({ ...ALT_CRITERIA }, { k1V1Ceiling: 0.8, k1Improve: 0.2, k1Restore: 0.05, worseTolerance: 0.02, attackerSlack: 5, k4Improve: 0.2 });
  assert.deepEqual([...EVAL_SEEDS], [211, 223, 227]);
  assert.deepEqual([...DEV_SEEDS], [1, 2, 3]);
  assert.equal(CREDITED_BOUND, 250);
  assert.ok(Object.isFrozen(VARIANTS));
});

test("water-filling: work-conserving when demand fits, equal split among the capped, small demands untouched", () => {
  assert.equal(waterLevel([1, 0.5], 2), Infinity);
  assert.equal(waterLevel([4, 0.5], 2), 1.5);
  assert.ok(Math.abs(waterLevel([3, 3, 3], 2) - 2 / 3) < 1e-12);
  assert.equal(waterLevel([4, 0.25, 0.25], 2), 1.5, "the heavy entity gets what the small ones leave");
});

test("fair share is a no-op while total demand fits the refill (V1 behaviour), and restricts only the heavy entity once it does not", () => {
  const fs = new FairShare({ ...FAIR_BASE, key: "class" }, 2, Buffer.alloc(32, 1));
  const ctx = (klass: string): Ctx => ({ klass, session: "s", token: "t", att: null, instance: null });
  let now = 0, refused = 0;
  for (let i = 0; i < 40; i++) { now += 1000; const h = fs.attempt(ctx("light"), now); if (!fs.allow(h, now)) refused++; else fs.charge(h); }
  assert.equal(refused, 0, "a lone 1/s class under a 2/s refill is never restricted");
  let heavyAdmitted = 0, lightRefused = 0;
  for (let i = 0; i < 4000; i++) { // 10/s heavy, 0.5/s light, for 400 s
    now += 100;
    const hv = fs.attempt(ctx("heavy"), now); if (fs.allow(hv, now)) { fs.charge(hv); heavyAdmitted++; }
    if (i % 20 === 0) { const l = fs.attempt(ctx("light"), now); if (fs.allow(l, now)) fs.charge(l); else lightRefused++; }
  }
  assert.equal(lightRefused, 0, "the light class keeps its demand once the heavy one is capped");
  assert.ok(heavyAdmitted / 400 < 1.8 && heavyAdmitted / 400 > 1.2, `heavy class is held near the residual share (${(heavyAdmitted / 400).toFixed(2)}/s)`);
});

test("attestations are single-use, signed and expiring: forged, tampered, expired and replayed ones never reach the reserved pool", () => {
  const authority = new AttestationAuthority(Buffer.alloc(32, 9));
  const a = authority.issue("id-1", 1000);
  assert.equal(authority.verify(a, 1001), true);
  assert.equal(authority.verify({ ...a, mac: "0".repeat(32) }, 1001), false, "forged mac");
  assert.equal(authority.verify({ ...a, id: "id-2" }, 1001), false, "id swapped under the same mac");
  assert.equal(authority.verify({ ...a, exp: a.exp + 1 }, 1001), false, "expiry extended");
  assert.equal(authority.verify(a, a.exp), false, "expired");
  assert.equal(authority.verify(new AttestationAuthority(Buffer.alloc(32, 8)).issue("id-1", 1000), 1001), false, "another issuer's key");

  let now = 5_000_000;
  const model = new AltModel(laneConfig(() => now), { kind: "pool", pool: { reserve: 0.2, overflow: false, issuer: "ext", instances: 1, sharedSpent: false } }, 1);
  const ctx = (token: string, att: Ctx["att"]): Ctx => ({ klass: "c", session: "s", token, att, instance: null });
  const [t1, t2, t3, t4] = ["t1", "t2", "t3", "t4"].map(tok);
  for (const t of [t1, t2, t3, t4]) model.enroll(t);
  const att = model.mint("x", now);
  assert.equal(model.decide(post(t1), ctx(t1, att)).via, "reserved", "first use spends from the reserved pool");
  assert.equal(model.decide(post(t2), ctx(t2, att)).via, "general", "replay is treated as an ordinary request");
  assert.equal(model.decide(post(t3), ctx(t3, { ...att, mac: "f".repeat(32) })).via, "general", "forgery is treated as an ordinary request");
  now += 61_000;
  assert.equal(model.decide(post(t4), ctx(t4, att)).via, "general", "expired attestation is treated as an ordinary request");
  const c = model.counters();
  assert.deepEqual([c.reservedAdmitted, c.attestationReplayRefused, c.attestationInvalid, c.doubleSpends], [1, 1, 2, 0]);
});

test("the spent set is bounded and fails CLOSED to the ordinary path when full; expired entries are reclaimed", () => {
  const set = new SpentSet(2);
  assert.ok(set.canAdd(0)); set.add("a", 100, 0); set.add("b", 100, 0);
  assert.equal(set.canAdd(50), false, "full: no attestation may take a reserved token");
  assert.equal(set.canAdd(101), true, "expired entries are purged");
});

test("the pool only PARTITIONS V1's credited capacity: general + reserved = 10, never more", () => {
  for (const [reserve, general, reserved] of [[0.1, 9, 1], [0.2, 8, 2], [0.4, 6, 4]] as const) {
    const m = new AltModel(laneConfig(() => 0), { kind: "pool", pool: { reserve, overflow: false, issuer: "ext", instances: 1, sharedSpent: false } }, 1);
    assert.deepEqual(m.creditedBound(), { general, reserved });
  }
  assert.throws(() => new AltModel(laneConfig(() => 0), { kind: "pool", pool: { reserve: 0.1, overflow: false, issuer: "ext", instances: 2, sharedSpent: false } }, 1), /whole tokens/);
});

test("the harness is deterministic (same seed, same numbers) and V1 is the real JourneyLanes", () => {
  const sc = buildAltScenarios().find((s) => s.id === "D1-rate/rate-4");
  assert.ok(sc);
  const gen = generate(sc, 211);
  assert.deepEqual(runVariant(sc, gen, "pool20_ext", 211), runVariant(sc, gen, "pool20_ext", 211));
  assert.deepEqual(runVariant(sc, gen, "fs_class", 211), runVariant(sc, gen, "fs_class", 211));
  const src = readFileSync(new URL("./support/l2-alt-model.ts", import.meta.url), "utf8");
  assert.deepEqual([...src.matchAll(/from "([^"]+)"/g)].map((m) => m[1]).sort(),
    ["../../defense/core/credit-filter", "../../defense/core/lanes", "../../defense/core/types", "./l2-v2-shadow", "node:crypto"].sort(), "only V1 code, the earlier study's model and node:crypto are imported");
});

const cells = buildAltScenarios().map((s) => runScenario(s, EVAL_SEEDS));
const byId = new Map(cells.map((c) => [c.id, c]));
const ok = (id: string, v: string): number => { const c = byId.get(id); assert.ok(c, id); const r = c.results[v]; assert.ok(r, `${id} ${v}`); return r.successRate; };

test("accounting: no variant ever admits more than V1's credited bound, and every decision is accounted exactly once", () => {
  assert.equal(cells.length, 47);
  for (const c of cells) for (const [v, r] of Object.entries(c.results)) assert.equal(r.idFailures, 0, `${c.id} ${v}`);
});

test("pre-registered criteria, per variant (K1 continuity, K2 shared networks, K3 exposure, K4 free identities, K6 optional issuer)", () => {
  const verdict = (v: string) => { const r = evaluateAlt(cells, v); return [r.k1.pass, r.k2.pass, r.k3.pass, r.k4.pass, r.k6.pass]; };
  const expected: Record<string, boolean[]> = {
    v1: [false, true, true, false, true],
    A_always: [true, false, true, true, true],
    A_gated: [true, false, true, true, true],
    A_gated_low: [true, true, true, true, true],
    fs_token: [false, true, true, false, true],
    fs_session: [false, false, true, false, true],
    fs_class: [false, false, true, true, true],
    fs_hier: [false, false, true, true, true],
    thin: [false, false, true, false, false],
    pool10_ext: [false, true, true, true, false],
    pool20_ext: [false, true, true, true, false],
    pool40_ext: [false, true, true, true, false],
    pool20_overflow_ext: [false, true, true, true, false],
    pool20_ldi: [false, false, true, true, true],
  };
  assert.deepEqual([...CORE_VARIANTS].sort(), Object.keys(expected).sort());
  for (const v of CORE_VARIANTS) assert.deepEqual(verdict(v), expected[v], v);
});

test("fair share: keyed by a free identity it is no fairness at all; keyed by class it degrades with the number of classes and fails shared networks", () => {
  for (const id of ["D1-rate/rate-4", "D1-rate/rate-100"]) assert.ok(Math.abs(ok(`${id}`, "fs_token") - ok(id, "v1")) < 0.02, `per-token fairness equals V1 (${id})`);
  assert.ok(ok("D2-identities/sessions-64-rate-100", "fs_session") < 0.1, "64 free sessions dominate per-session fairness");
  assert.ok(ok("D2-identities/sessions-64-rate-4", "fs_session") < ok("D2-identities/sessions-8-rate-4", "fs_session"));
  for (const v of ["fs_class", "fs_hier"]) assert.ok(ok("D2-identities/sessions-64-rate-100", v) > 0.65, `${v} is immune to session multiplication`);
  const classes = (n: number) => ok(`D2-identities/classes-${n}-rate-4`, "fs_class");
  assert.ok(classes(4) > classes(16) && classes(16) > classes(64) && classes(64) > ok("D2-identities/classes-64-rate-4", "v1"), "graceful, monotone loss, still above V1");
  assert.ok(ok("D2-identities/classes-64-rate-4", "fs_class") < 0.5, "64 classes: the attacker takes most of the allocation");
  assert.ok(ok("D3-shared/nat8-demand-0.5-in-attacker-class-sessions-1", "fs_class") < 0.1, "legitimate users inside the attacker's class are indistinguishable from it");
  assert.ok(ok("D3-shared/nat8-demand-1.9-no-attacker", "fs_class") < ok("D3-shared/nat8-demand-1.9-no-attacker", "v1") - 0.02, "burst cap hurts a shared network near saturation");
  assert.ok(ok("D1-rate/rate-4", "fs_class") < 0.95, "work-conserving max-min leaves legitimate bursts no slack (no full restoration)");
});

test("Approach A baselines: static ceilings collapse to V1 at 16 classes; the post-hoc gated-low variant is still only a class-keyed ceiling", () => {
  for (const v of ["A_always", "A_gated", "A_gated_low"]) assert.ok(Math.abs(ok("D2-identities/classes-16-rate-4", v) - ok("D2-identities/classes-16-rate-4", "v1")) < 0.01, v);
  assert.ok(ok("D4-adaptive/spread-rate-4", "A_gated_low") < 0.2, "an adaptive attacker that buys classes at 0.5/s defeats it");
  assert.ok(ok("D3-shared/nat8-demand-1-no-attacker", "A_always") < 0.4, "ungated ceilings still sink a shared network");
});

test("attested pool: independent of identities and classes; protection ends when attacker attestations reach the reserved refill", () => {
  assert.ok(ok("D2-identities/classes-64-rate-4", "pool40_ext") > 0.8 && ok("D2-identities/sessions-64-rate-100", "pool40_ext") > 0.8, "class and session multiplication do not matter");
  assert.ok(ok("D3-shared/nat8-demand-0.5-in-attacker-class-sessions-64", "pool40_ext") > 0.85, "legitimate users inside the attacker's class and session flood are still served");
  const a = (rate: number, v: string) => ok(`D5-attest/attacker-acquires-${rate}-per-s-rate-4`, v);
  assert.ok(a(0.1, "pool20_ext") > 0.7 && a(0.5, "pool20_ext") < 0.3, "a 20% pool (0.4/s) is exhausted by 0.5 attestations/s");
  assert.ok(a(0.5, "pool40_ext") > 0.85 && a(2, "pool40_ext") < 0.4, "a 40% pool (0.8/s) is exhausted by 2 attestations/s");
  for (const v of ["pool10_ext", "pool20_ext", "pool40_ext", "pool20_overflow_ext"]) assert.ok(a(100, v) < 0.3, `${v}: with abundant attestations the attacker is back near V1`);
  const atk = (id: string, v: string) => { const r = byId.get(id)!.results[v]; return r.farmCredited + r.farmUnverified; };
  assert.ok(atk("D5-attest/attacker-acquires-100-per-s-rate-4", "pool20_ext") <= atk("D5-attest/attacker-acquires-100-per-s-rate-4", "v1") + ALT_CRITERIA.attackerSlack, "exposure never exceeds V1's");
});

test("attested pool costs: accessibility caps the benefit, a missing issuer wastes the reserve, a local deterministic issuer is a class-keyed rate limit", () => {
  assert.ok(ok("D5-attest/accessible-0.5-rate-4", "pool20_ext") < 0.6 && ok("D5-attest/accessible-0.0-rate-4", "pool20_ext") < 0.1, "unattested users get V1 service");
  assert.ok(ok("D5-attest/issuer-down-all-no-attacker-demand-1.9", "pool40_ext") < ok("D5-attest/issuer-down-all-no-attacker-demand-1.9", "v1") - 0.2, "with the issuer down a 40% reserve costs 30+ points at demand 1.9");
  assert.ok(ok("D5-attest/issuer-down-all-no-attacker-demand-1.9", "pool20_overflow_ext") > ok("D5-attest/issuer-down-all-no-attacker-demand-1.9", "pool20_ext"), "overflow recovers part of it");
  assert.ok(ok("D2-identities/classes-16-rate-4", "pool20_ldi") < 0.4, "a local deterministic issuer is defeated by class rotation");
  assert.ok(ok("D5-attest/latency-5000-rate-4", "pool20_ext") > 0.75, "latency alone is cheap for a 20% pool");
  assert.ok(byId.get("D5-attest/latency-5000-rate-4")!.results.pool20_ext.legitAddedLatencyMean > 3500, "but it is paid by every attested journey");
});

test("multiple verifier instances: per-instance spent sets allow double spends; a shared spent set does not; reserved capacity (the exposure bound) is unchanged", () => {
  const replay = byId.get("D5b-verifiers/replay-4-acquires-2-per-s-rate-4")!;
  assert.ok(replay.results.pool40_ext_n2_local.doubleSpends > 20);
  assert.equal(replay.results.pool40_ext_n2_shared.doubleSpends, 0);
  assert.equal(replay.results.pool40_ext.doubleSpends, 0);
  assert.equal(replay.results.pool40_ext_n2_local.farmReserved, replay.results.pool40_ext_n2_shared.farmReserved, "double spending buys attestations' worth, not extra capacity");
  assert.ok(replay.results.pool40_ext_n2_local.creditedAdmitted <= CREDITED_BOUND);
});

test("allocation fairness among independent legitimate clients: V1 is highly unequal under farming, every alternative improves it", () => {
  const jain = (v: string) => byId.get("D3-shared/own8-demand-1-attacker")!.results[v].jain;
  assert.ok(jain("v1") < 0.5);
  for (const v of ["A_gated", "fs_class", "fs_hier", "pool40_ext"]) assert.ok(jain(v) > 0.9, v);
});
