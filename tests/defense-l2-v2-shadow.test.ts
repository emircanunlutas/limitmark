import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { JourneyLanes } from "../defense/core/lanes";
import { generate, runScenario, worldA } from "./support/l2-v2-matrix";
import type { Cell } from "./support/l2-v2-matrix";
import { CRITERIA, HELD_OUT_SEEDS, buildHeldOutScenarios, buildScenarios, evaluateHeldOut, evaluateHypotheses } from "./support/l2-v2-scenarios";
import { V2Model, V2_VARIANTS, V2_VERSION, EXPLORATORY, laneConfig, variantParams } from "./support/l2-v2-shadow";

/**
 * EXPERIMENTAL, SHADOW-ONLY evaluation of "Approach A" (per-class credited-lane ceilings) for L2, versioned `l2-v2-shadow-experimental-1`.
 * Nothing here is production behaviour: the V2 model lives in tests/support, V1 (`defense/core/lanes.ts`) is imported and never modified,
 * V2 is never enforced against a live request, and the clocks and seeds are injected so every number is exact.
 *
 * The literals pinned below are MEASUREMENTS of a deterministic simulation (Poisson or periodic arrivals, 3 seeds x 120 s virtual time for the
 * pre-registered matrix, 5 unseen seeds for the held-out one). They are not claims about a live deployment. A change that moves them is a
 * reviewed change to this file. Interpretation, assumptions and counterexamples: docs/BA0_L2_V2_SHADOW_EVALUATION.md.
 */

const LABEL = "gated_low";
EXPLORATORY.set(LABEL, { ...V2_VARIANTS.gated, gate: 0.25 }); // the post-hoc candidate; see the document: chosen AFTER the pre-registered run
const cells: Cell[] = buildScenarios([LABEL]).map((s) => runScenario(s));
const byId = new Map(cells.map((c) => [c.id, c]));
const cell = (id: string): Cell => { const c = byId.get(id); assert.ok(c, `cell ${id}`); return c; };

test("versioning: every experimental behaviour is labelled V2 and the pre-registered criteria are the ones recorded before the first full run", () => {
  assert.equal(V2_VERSION, "l2-v2-shadow-experimental-1");
  assert.deepEqual({ ...CRITERIA }, { h1ImproveOverV1: 0.2, h1V1Ceiling: 0.8, h1RestoreWithin: 0.02, h2Tolerance: 0.02, h3AttackerSlack: 5, h4DegenerateShare: 0.9, h4ExemptTolerance: 0.02 });
  assert.equal(variantParams("off").enforce, false);
  assert.equal(variantParams(LABEL).gate, 0.25);
});

test("H5 (differential): with enforcement off, the V2 model decides exactly like the real V1 JourneyLanes over 150k mixed decisions (sheds, K exhaustion, epoch rotations included)", () => {
  let now = 5_000_000;
  const cfg = laneConfig(() => now);
  const v1 = new JourneyLanes(cfg), v2 = new V2Model(cfg, V2_VARIANTS.off);
  let seed = 99;
  const rnd = () => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed / 4294967296; };
  const tok = (n: number) => createHash("sha256").update(`t${n}`).digest("base64url");
  const post = (t: string) => ({ method: "POST", target: "/api/public-inquiries", headers: [], bodyStatus: "complete" as const, body: Buffer.from(`name=A&submissionToken=${t}`, "latin1") });
  const get = (t: string) => ({ method: "GET", target: t, headers: [], bodyStatus: "none" as const, body: null });
  const norm = (d: Record<string, unknown>) => JSON.stringify([d.class, d.lane, d.outcome, d.shedReason ?? (d.reason === "lane_budget" ? "lane_budget" : null), d.errorKind ?? (d.reason === "ledger_full" ? "ledger_full" : null), d.creditTag ?? null, d.dt ?? null, d.lvl ?? null, d.lseq ?? null]);
  const enrolled: string[] = [];
  let compared = 0, sheds = 0;
  for (let i = 0; i < 150_000; i++) {
    now += Math.floor(rnd() * 60);
    const r = rnd();
    let req;
    if (r < 0.15) { const t = tok(i); v1.enroll(t); v2.enroll(t); enrolled.push(t); continue; }
    if (r < 0.2) req = get(rnd() < 0.5 ? "/" : "/unknown");
    else if (r < 0.9 && enrolled.length) req = post(enrolled[Math.floor(rnd() * enrolled.length)]);
    else req = post(tok(1_000_000 + i));
    const a = v1.decide(req), b = v2.decide(req, { source: "peer", id: "x" });
    assert.equal(norm(a as unknown as Record<string, unknown>), norm(b as unknown as Record<string, unknown>), `decision ${i}`);
    compared++;
    if (a.outcome === "shed") sheds++;
  }
  assert.ok(compared > 100_000 && sheds > 1_000, `the stream exercised sheds (${compared} decisions, ${sheds} sheds)`);
  const s1 = v1.snapshot().credited, m = v2.creditedSnapshot();
  assert.equal(m.admitted, s1.admitted);
  assert.equal(m.shed, s1.shed);
});

test("H5 (no side effects): running the shadow models beside V1 leaves V1's decisions, counters and token accounting byte-identical", () => {
  const ids = ["B1-farm-rate/rate-4", "B1-farm-rate/rate-100", "B2-spread/rate-4-classes-4", "B4-nat/no-attacker-demand-1", "B5-proxy/undeclared-farmer-4", "B6-hints/spoof-victim-class-farmer-4", "B8-retry/farmer-4-retry-1s-x5", "B9-jitter-order/jitter-50-legit-first-true"];
  const scenarios = buildScenarios([LABEL]);
  let checked = 0;
  for (const id of ids) {
    const sc = scenarios.find((s) => s.id === id) ?? scenarios.find((s) => s.id.startsWith(id));
    assert.ok(sc, `scenario ${id}`);
    for (const seed of [11, 37]) {
      const gen = generate(sc, seed);
      const alone = worldA(sc, gen, []);
      const shadowed = worldA(sc, gen, sc.variants);
      assert.equal(shadowed.v1Fingerprint, alone.v1Fingerprint, `${sc.id}/${seed}: V1 decision stream`);
      assert.equal(shadowed.snapshotJson, alone.snapshotJson, `${sc.id}/${seed}: V1 snapshot (buckets, ledger, filter)`);
      assert.deepEqual(shadowed.v1, alone.v1, `${sc.id}/${seed}: V1 outcome accounting`);
      checked++;
    }
  }
  assert.equal(checked, ids.length * 2);
});

test("H5 (structure): the shadow wrapper reaches V1 only through decide() and enroll(), and nothing outside tests/support or docs was touched", () => {
  const src = readFileSync(new URL("./support/l2-v2-shadow.ts", import.meta.url), "utf8");
  const used = new Set([...src.matchAll(/\bthis\.v1\.(\w+)/g)].map((m) => m[1]));
  assert.deepEqual([...used].sort(), ["decide", "enroll"]);
  const imports = [...src.matchAll(/from "([^"]+)"/g)].map((m) => m[1]).sort();
  assert.deepEqual(imports, ["../../defense/core/credit-filter", "../../defense/core/lanes", "../../defense/core/types", "../../lab/defense/field-thresholds", "node:crypto"].sort(), "only V1 code and the pinned V1 constants are imported, read-only");
});

test("accounting: V2 never raises V1's capacity (credited admissions <= capacity + refill x time) and every V2 credited decision is exactly admitted + global shed + class shed", () => {
  assert.equal(cells.length, 55);
  for (const c of cells) assert.deepEqual(c.identityFailures, [], c.id);
});

test("validation: with no retries the shadow verdict equals an independent V2-as-sole-decider run in every cell; retry cells differ only by the documented open-loop bias", () => {
  const noRetry = cells.filter((c) => c.noRetry);
  assert.equal(noRetry.length, 47);
  for (const c of noRetry) for (const [variant, equal] of Object.entries(c.shadowEqualsEnforced)) assert.ok(equal, `${c.id} ${variant}`);
  const retry = cells.filter((c) => !c.noRetry);
  assert.ok(retry.length >= 8);
  const biased = cell("B8-retry/farmer-4-retry-1s-x5");
  assert.ok(biased.shadow.gated.legitAttempts > biased.enforced.gated.legitAttempts, "the shadow stream is generated by V1 outcomes, so it carries more retries than a V2-only world");
});

test("H1 (pre-registered always, gated): a single-class farmer is constrained enough to restore independent legitimate continuity", () => {
  for (const v of ["always", "gated"]) {
    const r = evaluateHypotheses(cells, v);
    assert.equal(r.h1.improve, true, `${v}: improve tier`);
    assert.equal(r.h1.restore, true, `${v}: restore tier`);
  }
  const v1 = cell("B1-farm-rate/rate-4"), hundred = cell("B1-farm-rate/rate-100");
  assert.ok(v1.v1.successRate < 0.1 && v1.enforced.gated.successRate > 0.95, "4/s: V1 starved, gated V2 restores");
  assert.ok(hundred.v1.successRate < 0.05 && hundred.enforced.gated.successRate > 0.95, "100/s: V1 starved, gated V2 restores");
  assert.ok(v1.enforced.gated.farmCredited < v1.v1.farmCredited, "the farmer is admitted less often, never more");
});

test("H2 (pre-registered): shared-network legitimate users are WORSE off than under V1, so Approach A as specified is not a safe general default", () => {
  const always = evaluateHypotheses(cells, "always"), gated = evaluateHypotheses(cells, "gated");
  assert.equal(always.h2.pass, false);
  assert.equal(gated.h2.pass, false);
  assert.deepEqual(always.h2.failing.map((s) => s.split(":")[0]), ["B3-attacker-class/rho-1", "B4-nat/no-attacker-demand-0.25", "B4-nat/no-attacker-demand-0.5", "B4-nat/no-attacker-demand-1", "B4-nat/no-attacker-demand-1.9", "B4-nat/no-attacker-demand-3", "B5-proxy/undeclared-farmer-4", "B5-proxy/undeclared-no-attacker-demand-1"]);
  assert.deepEqual(gated.h2.failing.map((s) => s.split(":")[0]), ["B3-attacker-class/rho-1", "B4-nat/no-attacker-demand-1.9", "B5-proxy/undeclared-farmer-4"]);
  const nat = cell("B4-nat/no-attacker-demand-1");
  assert.ok(nat.v1.successRate > 0.99 && nat.enforced.always.successRate < 0.3, "ungated ceilings turn a harmless NAT into a self-inflicted outage");
  assert.ok(nat.enforced.gated.successRate > 0.99, "gating removes that harm when the lane is not contended");
  const nearSaturation = cell("B4-nat/no-attacker-demand-1.9");
  assert.ok(nearSaturation.v2OnlyRefusals.gated > nearSaturation.v1OnlyRefusals.gated, "near saturation the gated ceiling still causes real false rejects");
});

test("H3: rotating across classes never raises total credited exposure above V1, and the farmer needs about 1/phi = 8 classes to get back to V1 behaviour", () => {
  for (const v of ["always", "gated", LABEL]) assert.equal(evaluateHypotheses(cells, v).h3.pass, true, v);
  const rotate = (n: number) => cell(`B2-spread/rate-4-classes-${n}`);
  assert.ok(rotate(1).enforced.gated.successRate > 0.95 && rotate(4).enforced.gated.successRate > 0.95);
  assert.ok(rotate(8).enforced.gated.successRate < 0.3, "8 classes: mostly back to starvation");
  assert.ok(Math.abs(rotate(16).enforced.gated.successRate - rotate(16).v1.successRate) < 0.005, "16 classes: identical to V1");
  assert.ok(rotate(16).enforced.gated.farmCredited <= rotate(16).v1.farmCredited + CRITERIA.h3AttackerSlack);
});

test("H4: only peer-derived hints are ever enforced; missing, declared-shared and forwarded hints cannot cause a class shed; an undeclared single proxy is flagged", () => {
  assert.equal(evaluateHypotheses(cells, "gated").h4.pass, true);
  assert.equal(evaluateHypotheses(cells, LABEL).h4.pass, true);
  for (const v of ["always", "gated", LABEL]) {
    const r = evaluateHypotheses(cells, v);
    assert.equal(r.h4.safeEnforcementOnlyOnPeer, true, v);
    assert.equal(r.h4.degenerateFlagRaised, true, v);
  }
  // `always` fails ONLY the pre-registered spoof criterion, which is confounded: the same clipping happens with no attacker at all (see the document)
  assert.deepEqual(evaluateHypotheses(cells, "always").h4.failing, ["B6-hints/spoof-victim-class-farmer-1.5: spoofed hint harmed the victim"]);
});

test("H4 counterexample: if forwarded hints are TRUSTED (unsafe switch) an attacker can target a victim class and deny it service; untrusted, the same spoof is inert", () => {
  const spoof = cells.find((c) => c.id === "B6-hints/spoof-victim-class-farmer-1.5");
  assert.ok(spoof);
  assert.ok(spoof.v1.successRate > 0.99, "V1: a 1.5/s farmer does not starve anyone");
  assert.ok(spoof.enforced.gated.successRate > 0.99, "untrusted forwarded hint: no effect");
  assert.equal(spoof.classShedBySource.gated.forwarded ?? 0, 0);
  const unsafe = buildScenarios(["always_trustfwd"]).find((s) => s.id === spoof.id);
  assert.ok(unsafe);
  const hit = runScenario(unsafe, [11, 23, 37]);
  assert.ok(hit.enforced.always_trustfwd.successRate < 0.05, `trusting the header lets 1.5 req/s of spoofed traffic starve the victim (${hit.enforced.always_trustfwd.successRate.toFixed(3)})`);
  assert.ok(hit.v2OnlyRefusals.always_trustfwd > 50);
});

test("post-hoc candidate gated_low (gate 0.25), original seeds: passes H1-improve, H2, H3, H4 but MISSES the pre-registered restore tier by 0.3 points", () => {
  const r = evaluateHypotheses(cells, LABEL);
  assert.deepEqual([r.h1.improve, r.h1.restore, r.h2.pass, r.h3.pass, r.h4.pass], [true, false, true, true, true]);
  assert.equal(r.h1.failingRestore.length, 8);
  assert.ok(cell("B1-farm-rate/rate-4").enforced[LABEL].successRate > 0.97);
});

test("held-out validation (5 unseen seeds, new scenarios, criteria unchanged): always fails H2; gated passes H2/H3 but misses restore; gated_low passes H1-improve/H2/H3 and misses restore", () => {
  const variants = ["always", "gated", LABEL];
  const held = buildHeldOutScenarios(variants).map((s) => runScenario(s, HELD_OUT_SEEDS));
  assert.equal(held.length, 24);
  for (const c of held) assert.deepEqual(c.identityFailures, [], c.id);
  const always = evaluateHeldOut(held, "always"), gated = evaluateHeldOut(held, "gated"), low = evaluateHeldOut(held, LABEL);
  assert.deepEqual([always.h1Improve, always.h1Restore, always.h2, always.h3], [true, true, false, true]);
  assert.deepEqual([gated.h1Improve, gated.h1Restore, gated.h2, gated.h3], [true, false, true, true]);
  assert.deepEqual([low.h1Improve, low.h1Restore, low.h2, low.h3], [true, false, true, true]);
  assert.equal(always.h2Fail.length, 5);
  assert.equal(low.restoreFail.length, 4);
  assert.equal(gated.restoreFail.length, 1);
  const lowestLow = Math.min(...held.filter((c) => c.block === "HO1-single-class" && c.id !== "HO1-single-class/control").map((c) => c.enforced[LABEL].successRate));
  assert.ok(lowestLow > 0.7, `gated_low never falls below 0.7 on the single-class cells (min ${lowestLow.toFixed(3)})`);
});
