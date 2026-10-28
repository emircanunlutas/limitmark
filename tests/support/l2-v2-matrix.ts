import { createHash } from "node:crypto";
import type { LayerRequest } from "../../defense/core/types";
import {
  FIELD_L2, ShadowedLanes, V2Model, laneConfig, variantParams, type ClassHint,
} from "./l2-v2-shadow";

/**
 * Deterministic adversarial matrix for the V2 shadow study. Virtual time only: every clock is injected, every random draw comes from a seeded
 * generator, nothing waits and nothing touches a network. Two worlds are run from the SAME generated stream:
 *
 *   world A  "shadow":   the real V1 `JourneyLanes` decides; V2 models only observe. Clients react to V1's answers (retries).
 *   world B  "enforced": a V2 model decides alone and clients react to ITS answers. This is what enforcement would do (a MODEL, not a plane).
 *
 * Without retries the request streams are identical, so shadow and enforced must agree exactly (a validation of the shadow evaluator);
 * with retries they differ, and the difference is the open-loop bias of shadow mode, reported rather than hidden.
 */
export const DURATION_MS = 120_000; // two 60 s filter generations
export const SEEDS: readonly number[] = [11, 23, 37];
const CREDITED_BOUND = FIELD_L2.credited.capacity + Math.floor((FIELD_L2.credited.refillPerSecond * DURATION_MS) / 1000);

export type Retry = { intervalMs: number; max: number }; // max total attempts; 1 = never retries
export const NO_RETRY: Retry = { intervalMs: 0, max: 1 };
export type FarmerSpec = { totalRate: number; classes: readonly string[]; hint: ClassHint["source"]; claimedClass?: string; jitterMs: number };
export type LegitSpec = { rate: number; arrivals: "poisson" | "periodic"; place: (journey: number, rnd: () => number) => ClassHint; retry: Retry };
export type Scenario = {
  id: string; block: string; farmer: FarmerSpec | null; legit: LegitSpec; legitFirstOnTie: boolean; variants: readonly string[]; note?: string;
};

// ---------------------------------------------------------------------------
// Deterministic generation
// ---------------------------------------------------------------------------

const mulberry32 = (seed: number) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const tokenFor = (label: string, n: number): string => createHash("sha256").update(`l2v2:${label}:${n}`).digest("base64url");
const post = (token: string): LayerRequest => ({
  method: "POST", target: "/api/public-inquiries", headers: [], bodyStatus: "complete", body: Buffer.from(`name=A&email=a%40b.co&service=web&submissionToken=${token}`, "latin1"),
});

type FarmEvent = { t: number; idx: number; hint: ClassHint; token: string };
type Journey = { idx: number; startMs: number; hint: ClassHint; token: string };
export type Generated = { farm: FarmEvent[]; journeys: Journey[] };

export function generate(sc: Scenario, seed: number): Generated {
  const farm: FarmEvent[] = [];
  if (sc.farmer && sc.farmer.totalRate > 0) {
    const period = 1000 / sc.farmer.totalRate; const rnd = mulberry32(seed ^ 0x9e3779b9); const jitter = sc.farmer.jitterMs;
    for (let i = 0; Math.round(i * period) < DURATION_MS; i++) {
      const offset = jitter > 0 ? Math.floor(rnd() * (2 * jitter + 1)) - jitter : 0;
      const id = sc.farmer.classes[i % sc.farmer.classes.length];
      const source = sc.farmer.hint;
      const hint: ClassHint = source === "missing" ? { source: "missing" } : { source, id: source === "forwarded" ? (sc.farmer.claimedClass ?? id) : id } as ClassHint;
      farm.push({ t: Math.max(0, Math.round(i * period) + offset), idx: i, hint, token: tokenFor("farm", i) });
    }
  }
  const journeys: Journey[] = []; const rnd = mulberry32(seed);
  let t = sc.legit.arrivals === "periodic" ? 125 : 0;
  for (let j = 0; ; j++) {
    t += sc.legit.arrivals === "periodic" ? (j === 0 ? 0 : 1000 / sc.legit.rate) : (-Math.log(1 - rnd()) * 1000) / sc.legit.rate;
    const startMs = Math.round(t);
    if (startMs >= DURATION_MS) break;
    journeys.push({ idx: j, startMs, hint: sc.legit.place(j, rnd), token: tokenFor(`legit${seed}`, j) });
  }
  return { farm, journeys };
}

// ---------------------------------------------------------------------------
// The shared closed-loop driver
// ---------------------------------------------------------------------------

type Req = { actor: "farm" | "legit"; token: string; hint: ClassHint; journey: number; attempt: number; t: number };
type Ev = { t: number; order: number; kind: "farm" | "legit"; idx: number; attempt: number };
const before = (a: Ev, b: Ev) => a.t - b.t || a.order - b.order || a.idx - b.idx || a.attempt - b.attempt;

function drive(sc: Scenario, gen: Generated, setNow: (ms: number) => void, enroll: (token: string) => void, handle: (r: Req) => boolean): { doneAt: (number | null)[] } {
  const farmOrder = sc.legitFirstOnTie ? 1 : 0, legitOrder = sc.legitFirstOnTie ? 0 : 1;
  const queue: Ev[] = [
    ...gen.farm.map((e): Ev => ({ t: e.t, order: farmOrder, kind: "farm", idx: e.idx, attempt: 0 })),
    ...gen.journeys.map((j): Ev => ({ t: j.startMs, order: legitOrder, kind: "legit", idx: j.idx, attempt: 0 })),
  ].sort(before);
  const doneAt: (number | null)[] = gen.journeys.map(() => null);
  for (let at = 0; at < queue.length; at++) {
    const e = queue[at];
    setNow(e.t);
    if (e.kind === "farm") {
      const f = gen.farm[e.idx];
      enroll(f.token); // a free render, enrolled after delivery
      handle({ actor: "farm", token: f.token, hint: f.hint, journey: -1, attempt: 0, t: e.t });
      continue;
    }
    const j = gen.journeys[e.idx];
    if (doneAt[j.idx] !== null) continue;
    if (e.attempt === 0) enroll(j.token);
    const ok = handle({ actor: "legit", token: j.token, hint: j.hint, journey: j.idx, attempt: e.attempt, t: e.t });
    if (ok) { doneAt[j.idx] = e.t; continue; }
    if (e.attempt + 1 < sc.legit.retry.max && e.t + sc.legit.retry.intervalMs < DURATION_MS) {
      const next: Ev = { t: e.t + sc.legit.retry.intervalMs, order: legitOrder, kind: "legit", idx: j.idx, attempt: e.attempt + 1 };
      let lo = at + 1, hi = queue.length;
      while (lo < hi) { const mid = (lo + hi) >> 1; if (before(queue[mid], next) <= 0) lo = mid + 1; else hi = mid; }
      queue.splice(lo, 0, next);
    }
  }
  return { doneAt };
}

// ---------------------------------------------------------------------------
// Per-side accounting
// ---------------------------------------------------------------------------

export type Side = {
  journeys: number; journeysOk: number; successRate: number;
  legitAttempts: number; legitAdmitted: number; legitRefused: number;
  farmAttempts: number; farmCredited: number; farmUnverified: number;
  creditedAdmitted: number; creditedShedGlobal: number; classShed: number; unverifiedShed: number;
  starvedMsMax: number;
};
const emptySide = (): Side => ({ journeys: 0, journeysOk: 0, successRate: 0, legitAttempts: 0, legitAdmitted: 0, legitRefused: 0, farmAttempts: 0, farmCredited: 0, farmUnverified: 0, creditedAdmitted: 0, creditedShedGlobal: 0, classShed: 0, unverifiedShed: 0, starvedMsMax: 0 });

type Verdict = { admitted: boolean; lane: string | null; reason?: string };
function note(side: Side, req: Req, v: Verdict): void {
  if (req.actor === "legit") { side.legitAttempts++; if (v.admitted) side.legitAdmitted++; else side.legitRefused++; }
  else { side.farmAttempts++; if (v.admitted) { if (v.lane === "credited") side.farmCredited++; else side.farmUnverified++; } }
  if (v.lane === "credited") {
    if (v.admitted) side.creditedAdmitted++; else if (v.reason === "class_ceiling") side.classShed++; else side.creditedShedGlobal++;
  } else if (v.lane === "unverified" && !v.admitted) side.unverifiedShed++;
}
function finish(side: Side, gen: Generated, ok: boolean[]): Side {
  side.journeys = gen.journeys.length; side.journeysOk = ok.filter(Boolean).length; side.successRate = side.journeys === 0 ? 1 : side.journeysOk / side.journeys;
  let streakStart: number | null = null;
  for (const j of gen.journeys) {
    if (!ok[j.idx]) { if (streakStart === null) streakStart = j.startMs; }
    else if (streakStart !== null) { side.starvedMsMax = Math.max(side.starvedMsMax, j.startMs - streakStart); streakStart = null; }
  }
  if (streakStart !== null) side.starvedMsMax = Math.max(side.starvedMsMax, DURATION_MS - streakStart);
  return side;
}

// ---------------------------------------------------------------------------
// The two worlds
// ---------------------------------------------------------------------------

export type WorldA = { v1: Side; v1Ok: boolean[]; shadow: Record<string, Side>; shadowOk: Record<string, boolean[]>; v1Fingerprint: string; snapshotJson: string; topClassShare: Record<string, { total: number; share: number }>; classShedBySource: Record<string, Record<string, number>>; exempt: Record<string, Record<string, number>> };

export function worldA(sc: Scenario, gen: Generated, variantNames: readonly string[]): WorldA {
  let now = 1_000_000;
  const shadowed = new ShadowedLanes(laneConfig(() => now), Object.fromEntries(variantNames.map((n) => [n, variantParams(n)])));
  const v1 = emptySide(); const shadow: Record<string, Side> = Object.fromEntries(variantNames.map((n) => [n, emptySide()]));
  const anyShadow: Record<string, boolean[]> = Object.fromEntries(variantNames.map((n) => [n, gen.journeys.map(() => false)]));
  const fingerprint = createHash("sha256");
  const { doneAt } = drive(sc, gen, (ms) => { now = 1_000_000 + ms; }, (token) => shadowed.enroll(token), (req) => {
    const verdict = shadowed.decide(post(req.token), req.hint);
    const d = verdict.v1;
    const v1Verdict: Verdict = { admitted: d.outcome === "admitted", lane: d.lane, reason: d.shedReason };
    note(v1, req, v1Verdict);
    fingerprint.update(`${req.t}|${req.actor}|${d.lane}|${d.outcome}|${d.shedReason ?? ""}|${d.errorKind ?? ""}|${d.dt ?? ""}|${d.lvl ?? ""}|${d.lseq ?? ""};`);
    for (const name of variantNames) {
      const s = verdict.shadow[name]; const sv: Verdict = { admitted: s.outcome === "admitted", lane: s.lane, reason: s.reason };
      note(shadow[name], req, sv);
      if (req.actor === "legit" && sv.admitted) anyShadow[name][req.journey] = true;
    }
    return v1Verdict.admitted;
  });
  const v1Ok = doneAt.map((t) => t !== null);
  finish(v1, gen, v1Ok);
  for (const name of variantNames) finish(shadow[name], gen, anyShadow[name]);
  const topClassShare: WorldA["topClassShare"] = {}; const classShedBySource: WorldA["classShedBySource"] = {}; const exempt: WorldA["exempt"] = {};
  for (const name of variantNames) {
    const st = shadowed.model(name).stats();
    let total = 0, top = 0; for (const n of st.peerRequestsByClass.values()) { total += n; top = Math.max(top, n); }
    topClassShare[name] = { total, share: total === 0 ? 0 : top / total }; classShedBySource[name] = st.classShedBySource; exempt[name] = st.exemptBySource;
  }
  return { v1, v1Ok, shadow, shadowOk: anyShadow, v1Fingerprint: fingerprint.digest("hex"), snapshotJson: JSON.stringify(shadowed.v1.snapshot()), topClassShare, classShedBySource, exempt };
}

export type WorldB = { side: Side; classShedBySource: Record<string, number>; classesShed: number; creditedDecisions: number };

export function worldB(sc: Scenario, gen: Generated, variant: string): WorldB {
  let now = 1_000_000;
  const model = new V2Model(laneConfig(() => now), variantParams(variant));
  const side = emptySide(); let creditedDecisions = 0;
  const { doneAt } = drive(sc, gen, (ms) => { now = 1_000_000 + ms; }, (token) => model.enroll(token), (req) => {
    const d = model.decide(post(req.token), req.hint);
    const v: Verdict = { admitted: d.outcome === "admitted", lane: d.lane, reason: d.reason };
    if (d.lane === "credited") creditedDecisions++;
    note(side, req, v);
    return v.admitted;
  });
  finish(side, gen, doneAt.map((t) => t !== null));
  const st = model.stats();
  return { side, classShedBySource: st.classShedBySource, classesShed: st.classesShed, creditedDecisions };
}

// ---------------------------------------------------------------------------
// One scenario over all seeds, with its accounting identities
// ---------------------------------------------------------------------------

export type Agg = { successRate: number; successMin: number; successMax: number } & Record<Exclude<keyof Side, "successRate" | "journeys" | "journeysOk">, number> & { journeys: number };
function aggregate(sides: readonly Side[]): Agg {
  const mean = (pick: (s: Side) => number) => sides.reduce((a, s) => a + pick(s), 0) / sides.length;
  const rates = sides.map((s) => s.successRate);
  return {
    successRate: mean((s) => s.successRate), successMin: Math.min(...rates), successMax: Math.max(...rates), journeys: mean((s) => s.journeys),
    legitAttempts: mean((s) => s.legitAttempts), legitAdmitted: mean((s) => s.legitAdmitted), legitRefused: mean((s) => s.legitRefused),
    farmAttempts: mean((s) => s.farmAttempts), farmCredited: mean((s) => s.farmCredited), farmUnverified: mean((s) => s.farmUnverified),
    creditedAdmitted: mean((s) => s.creditedAdmitted), creditedShedGlobal: mean((s) => s.creditedShedGlobal), classShed: mean((s) => s.classShed), unverifiedShed: mean((s) => s.unverifiedShed),
    starvedMsMax: Math.max(...sides.map((s) => s.starvedMsMax)),
  };
}

export type Cell = {
  id: string; block: string; noRetry: boolean;
  v1: Agg; shadow: Record<string, Agg>; enforced: Record<string, Agg>;
  /** per variant: journeys V1 completed that the shadow V2 would have refused (false rejects) and the reverse, summed over seeds */
  v2OnlyRefusals: Record<string, number>; v1OnlyRefusals: Record<string, number>;
  /** the pure open-loop agreement: shadow == enforced exactly (only meaningful without retries) */
  shadowEqualsEnforced: Record<string, boolean>;
  identityFailures: string[];
  topClassShare: Record<string, number>; classShedBySource: Record<string, Record<string, number>>; exempt: Record<string, Record<string, number>>;
};

export function runScenario(sc: Scenario, seeds: readonly number[] = SEEDS): Cell {
  const noRetry = sc.legit.retry.max === 1;
  const v1s: Side[] = []; const shadowSides: Record<string, Side[]> = {}; const enforcedSides: Record<string, Side[]> = {};
  const v2Only: Record<string, number> = {}, v1Only: Record<string, number> = {}; const eq: Record<string, boolean> = {};
  const failures: string[] = []; const top: Record<string, number> = {}; const bySource: Record<string, Record<string, number>> = {}; const exempt: Record<string, Record<string, number>> = {};
  for (const n of sc.variants) { shadowSides[n] = []; enforcedSides[n] = []; v2Only[n] = 0; v1Only[n] = 0; eq[n] = true; top[n] = 0; bySource[n] = {}; exempt[n] = {}; }
  for (const seed of seeds) {
    const gen = generate(sc, seed);
    const a = worldA(sc, gen, sc.variants);
    v1s.push(a.v1);
    if (a.v1.creditedAdmitted > CREDITED_BOUND) failures.push(`seed ${seed}: V1 credited admissions ${a.v1.creditedAdmitted} exceed the bound ${CREDITED_BOUND}`);
    for (const n of sc.variants) {
      shadowSides[n].push(a.shadow[n]);
      const b = worldB(sc, gen, n); enforcedSides[n].push(b.side);
      for (const [label, side] of [["shadow", a.shadow[n]], ["enforced", b.side]] as const) {
        if (side.creditedAdmitted > CREDITED_BOUND) failures.push(`seed ${seed} ${n}: ${label} V2 credited admissions ${side.creditedAdmitted} exceed the bound ${CREDITED_BOUND}`);
      }
      if (b.creditedDecisions !== b.side.creditedAdmitted + b.side.creditedShedGlobal + b.side.classShed) failures.push(`seed ${seed} ${n}: enforced credited decisions do not add up`);
      // journey-level differences against V1, from the per-journey outcomes of this seed
      for (const j of gen.journeys) {
        const okV1 = a.v1Ok[j.idx], okV2 = a.shadowOk[n][j.idx];
        if (okV1 && !okV2) v2Only[n]++;
        if (!okV1 && okV2) v1Only[n]++;
      }
      if (noRetry) {
        const s = a.shadow[n], e = b.side;
        if (s.legitAdmitted !== e.legitAdmitted || s.farmCredited !== e.farmCredited || s.classShed !== e.classShed || s.creditedShedGlobal !== e.creditedShedGlobal || s.journeysOk !== e.journeysOk) eq[n] = false;
      }
      top[n] = Math.max(top[n], a.topClassShare[n].total >= 50 ? a.topClassShare[n].share : 0);
      for (const [k, v] of Object.entries(a.classShedBySource[n])) bySource[n][k] = (bySource[n][k] ?? 0) + v;
      for (const [k, v] of Object.entries(a.exempt[n])) exempt[n][k] = (exempt[n][k] ?? 0) + v;
    }
  }
  return {
    id: sc.id, block: sc.block, noRetry, v1: aggregate(v1s),
    shadow: Object.fromEntries(sc.variants.map((n) => [n, aggregate(shadowSides[n])])), enforced: Object.fromEntries(sc.variants.map((n) => [n, aggregate(enforcedSides[n])])),
    v2OnlyRefusals: v2Only, v1OnlyRefusals: v1Only, shadowEqualsEnforced: eq, identityFailures: failures, topClassShare: top, classShedBySource: bySource, exempt,
  };
}
