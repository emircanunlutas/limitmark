import { createHash } from "node:crypto";
import type { LayerRequest } from "../../defense/core/types";
import {
  AltModel, ApproachADecider, FAIR_BASE, V1Decider, waterLevel, type Ctx, type Decider, type Out, type Policy,
} from "./l2-alt-model";
import { FIELD_L2, laneConfig } from "./l2-v2-shadow";

/**
 * Deterministic comparison harness for the L2 alternatives study. Virtual time only: clocks are injected, every random draw comes from a seeded
 * generator, nothing waits and nothing touches a network. Every variant is the SOLE decider of one closed-loop run over the SAME generated
 * stream (clients react to that variant's answers: retries, attestation latency). There is no shadow world here: this study compares
 * allocation policies, and an open-loop shadow would only reintroduce the bias the previous study had to disclose.
 *
 * Seed discipline (pre-registration): DEV_SEEDS were used only to check the harness runs and its identities hold; EVAL_SEEDS were run once for the reported
 * results. No parameter below was chosen by looking at EVAL_SEEDS results; the variant grid is fixed and every grid point is reported.
 */
export const ALT_DURATION_MS = 120_000;
export const DEV_SEEDS: readonly number[] = [1, 2, 3];
export const EVAL_SEEDS: readonly number[] = [211, 223, 227];
export const CREDITED_BOUND = FIELD_L2.credited.capacity + Math.floor((FIELD_L2.credited.refillPerSecond * ALT_DURATION_MS) / 1000);

export type Retry = { intervalMs: number; max: number };
export const NO_RETRY: Retry = { intervalMs: 0, max: 1 };
export type FarmSpec = {
  rate: number; jitterMs: number;
  /** Identities the farmer controls for free (sessions) or at a cost (classes). Events cycle classes first, then sessions. */
  classes: number; sessions: number;
  /** Adaptive: +1 session per shed (free, up to maxSessions); +1 class per shed but never faster than classesPerS (an assumed acquisition rate). */
  spread?: { classesPerS: number; maxSessions: number };
  onOff?: { onMs: number; offMs: number };
  /** External attestations the attacker acquires per second (0 = none). Each is single-use and valid 60 s. */
  attPerS: number;
  /** After an attested admission the attacker re-sends the same attestation this many times in total (1 = no replay) to the next verifier instances. */
  replay: number;
};
export type LegitSpec = { rate: number; clients: number; placement: "own" | "one" | "attacker"; arrivals: "poisson" | "periodic"; retry: Retry };
/** External issuer behaviour seen by legitimate clients. `pOk` is the share of clients that can obtain an attestation at all (accessibility). */
export type IssuerSpec = { pOk: number; latencyMs: number; failMs: number; down: readonly [number, number] | null };
export type Scenario = { id: string; block: string; farm: FarmSpec | null; legit: LegitSpec; issuer: IssuerSpec; variants: readonly string[] };

// ---------------------------------------------------------------------------
// Variants (fixed grid, pre-registered; every point is reported)
// ---------------------------------------------------------------------------

export type VariantSpec =
  | { family: "v1" }
  | { family: "A"; model: string; note?: string }
  | { family: "alt"; policy: Policy; attest: "ext" | "ldi" | null };
const fair = (key: "token" | "session" | "class" | "hier"): Policy => ({ kind: "fair", fair: { ...FAIR_BASE, key } });
const pool = (reserve: number, overflow: boolean, issuer: "ext" | "ldi", instances = 1, sharedSpent = false): VariantSpec => ({ family: "alt", policy: { kind: "pool", pool: { reserve, overflow, issuer, instances, sharedSpent } }, attest: issuer });
export const VARIANTS: Readonly<Record<string, VariantSpec>> = Object.freeze({
  v1: { family: "v1" },
  A_always: { family: "A", model: "always" },
  A_gated: { family: "A", model: "gated" },
  A_gated_low: { family: "A", model: "gated_low", note: "post hoc, not approved; reference only" },
  fs_token: { family: "alt", policy: fair("token"), attest: null },
  fs_session: { family: "alt", policy: fair("session"), attest: null },
  fs_class: { family: "alt", policy: fair("class"), attest: null },
  fs_hier: { family: "alt", policy: fair("hier"), attest: null },
  thin: { family: "alt", policy: { kind: "thin", tauMs: FAIR_BASE.tauMs }, attest: null },
  pool10_ext: pool(0.1, false, "ext"),
  pool20_ext: pool(0.2, false, "ext"),
  pool40_ext: pool(0.4, false, "ext"),
  pool20_overflow_ext: pool(0.2, true, "ext"),
  pool20_ldi: pool(0.2, false, "ldi"),
  pool40_ext_n2_local: pool(0.4, false, "ext", 2, false),
  pool40_ext_n2_shared: pool(0.4, false, "ext", 2, true),
});
/** Post-hoc diagnostic variants registered by a study script (never part of the pre-registered grid or the decision). */
export const EXPLORATORY = new Map<string, VariantSpec>();
export const CORE_VARIANTS: readonly string[] = ["v1", "A_always", "A_gated", "A_gated_low", "fs_token", "fs_session", "fs_class", "fs_hier", "thin", "pool10_ext", "pool20_ext", "pool40_ext", "pool20_overflow_ext", "pool20_ldi"];

// ---------------------------------------------------------------------------
// Deterministic generation
// ---------------------------------------------------------------------------

const mulberry32 = (seed: number) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const tokenFor = (label: string, n: number): string => createHash("sha256").update(`l2alt:${label}:${n}`).digest("base64url");
const post = (token: string): LayerRequest => ({
  method: "POST", target: "/api/public-inquiries", headers: [], bodyStatus: "complete", body: Buffer.from(`name=A&email=a%40b.co&service=web&submissionToken=${token}`, "latin1"),
});

type FarmEvent = { t: number; i: number };
type Journey = { idx: number; startMs: number; client: number; capable: boolean };
export type Generated = { farm: FarmEvent[]; journeys: Journey[] };

export function generate(sc: Scenario, seed: number): Generated {
  const farm: FarmEvent[] = [];
  if (sc.farm && sc.farm.rate > 0) {
    const f = sc.farm, period = 1000 / f.rate, rnd = mulberry32(seed ^ 0x9e3779b9);
    for (let i = 0; Math.round(i * period) < ALT_DURATION_MS; i++) {
      const offset = f.jitterMs > 0 ? Math.floor(rnd() * (2 * f.jitterMs + 1)) - f.jitterMs : 0;
      const t = Math.max(0, Math.round(i * period) + offset);
      if (f.onOff && t % (f.onOff.onMs + f.onOff.offMs) >= f.onOff.onMs) continue;
      farm.push({ t, i });
    }
  }
  const journeys: Journey[] = []; const rnd = mulberry32(seed), cap = mulberry32(seed ^ 0xabcdef), who = mulberry32(seed ^ 0x13579b);
  const L = sc.legit;
  let t = L.arrivals === "periodic" ? 125 : 0;
  for (let j = 0; ; j++) {
    t += L.arrivals === "periodic" ? (j === 0 ? 0 : 1000 / L.rate) : (-Math.log(1 - rnd()) * 1000) / L.rate;
    const startMs = Math.round(t);
    if (startMs >= ALT_DURATION_MS) break;
    journeys.push({ idx: j, startMs, client: Math.floor(who() * L.clients), capable: cap() < sc.issuer.pOk });
  }
  return { farm, journeys };
}

// ---------------------------------------------------------------------------
// Accounting
// ---------------------------------------------------------------------------

export type Acct = {
  journeys: number; journeysOk: number; successRate: number;
  legitAttempts: number; legitAdmitted: number; legitRefused: number;
  farmAttempts: number; farmCredited: number; farmUnverified: number; farmReserved: number;
  creditedAdmitted: number; creditedShedGlobal: number; entityShed: number; unverifiedShed: number;
  starvedMsMax: number; legitAddedLatencyMean: number; legitAttested: number;
  attestationsAcquired: number; doubleSpends: number; distinctSpent: number;
  jain: number; minClient: number; dominance: number; farmEntitiesMax: number;
  idFailures: number;
};
const emptyAcct = (): Acct => ({
  journeys: 0, journeysOk: 0, successRate: 0, legitAttempts: 0, legitAdmitted: 0, legitRefused: 0, farmAttempts: 0, farmCredited: 0, farmUnverified: 0, farmReserved: 0,
  creditedAdmitted: 0, creditedShedGlobal: 0, entityShed: 0, unverifiedShed: 0, starvedMsMax: 0, legitAddedLatencyMean: 0, legitAttested: 0,
  attestationsAcquired: 0, doubleSpends: 0, distinctSpent: 0, jain: 1, minClient: 1, dominance: 0, farmEntitiesMax: 0, idFailures: 0,
});

const ENTITY_REASONS = new Set(["entity_ceiling", "thinned", "class_ceiling"]);
function note(a: Acct, actor: "legit" | "farm", out: Out): void {
  if (actor === "legit") { a.legitAttempts++; if (out.admitted) a.legitAdmitted++; else a.legitRefused++; }
  else { a.farmAttempts++; if (out.admitted) { if (out.lane === "credited") a.farmCredited++; else a.farmUnverified++; if (out.via === "reserved") a.farmReserved++; } }
  if (out.lane === "credited") { if (out.admitted) a.creditedAdmitted++; else if (out.reason !== undefined && ENTITY_REASONS.has(out.reason)) a.entityShed++; else a.creditedShedGlobal++; }
  else if (out.lane === "unverified" && !out.admitted) a.unverifiedShed++;
}

/** Ideal attacker allocation if the attacker counted as ONE actor and capacity were divided max-min among actors (rate x time + the burst). */
function idealAttackerAdmissions(sc: Scenario): number {
  if (!sc.farm || sc.farm.rate <= 0) return 0;
  const R = FIELD_L2.credited.refillPerSecond, per = sc.legit.rate / sc.legit.clients;
  const demands = Array.from({ length: sc.legit.clients }, () => per);
  const L = waterLevel([...demands, 1e9], R);
  const legitTake = demands.reduce((s, d) => s + Math.min(d, L), 0);
  return Math.max(0, R - legitTake) * (ALT_DURATION_MS / 1000) + FIELD_L2.credited.capacity;
}

// ---------------------------------------------------------------------------
// One variant, one seed
// ---------------------------------------------------------------------------

type Ev = { t: number; rank: number; kind: "render" | "farm" | "post"; idx: number; attempt: number };
const before = (a: Ev, b: Ev) => a.t - b.t || a.rank - b.rank || a.idx - b.idx || a.attempt - b.attempt;

export function runVariant(sc: Scenario, gen: Generated, name: string, seed: number): Acct {
  const spec = VARIANTS[name] ?? EXPLORATORY.get(name);
  if (!spec) throw new Error(`unknown variant ${name}`);
  let now = 1_000_000;
  const cfg = laneConfig(() => now);
  const decider: Decider = spec.family === "v1" ? new V1Decider(cfg) : spec.family === "A" ? new ApproachADecider(cfg, spec.model) : new AltModel(cfg, spec.policy, seed);
  const alt = decider instanceof AltModel ? decider : null;
  const attest = spec.family === "alt" ? spec.attest : null;
  const a = emptyAcct();
  const L = sc.legit, F = sc.farm;
  const instances = alt && alt.policy.kind === "pool" ? alt.policy.pool.instances : 1;

  // legitimate clients: class / session by placement
  const klassOf = (client: number): string => (L.placement === "one" ? "NAT" : L.placement === "attacker" ? "F0" : `LC${client}`);
  const sessionOf = (client: number): string => `LS${client}`;
  const issuerUp = (t: number): boolean => !(sc.issuer.down && t >= sc.issuer.down[0] && t < sc.issuer.down[1]);

  // legitimate journeys: attestation (external) obtained between render and POST, at the issuer's latency and success rate
  const postAt = gen.journeys.map((j) => {
    if (attest !== "ext") return j.startMs;
    if (!j.capable) return j.startMs;
    return j.startMs + (issuerUp(j.startMs) ? sc.issuer.latencyMs : sc.issuer.failMs);
  });
  const legitAtt = new Map<number, ReturnType<AltModel["mint"]>>();
  const queue: Ev[] = [
    ...gen.farm.map((e): Ev => ({ t: e.t, rank: 1, kind: "farm", idx: e.i, attempt: 0 })),
    ...gen.journeys.flatMap((j): Ev[] => [{ t: j.startMs, rank: 0, kind: "render", idx: j.idx, attempt: 0 }, { t: postAt[j.idx], rank: 2, kind: "post", idx: j.idx, attempt: 0 }]),
  ].sort(before);
  const doneAt: (number | null)[] = gen.journeys.map(() => null);
  const clientTotal = Array.from({ length: L.clients }, () => 0), clientOk = Array.from({ length: L.clients }, () => 0);
  let addedLatency = 0;
  for (const j of gen.journeys) { clientTotal[j.client]++; addedLatency += postAt[j.idx] - j.startMs; }

  // attacker state
  const stock: ReturnType<AltModel["mint"]>[] = [];
  let nextAcq = 1, shedPressure = 0;
  const entities = new Set<string>();
  const acquire = (t: number): void => {
    if (!F || F.attPerS <= 0 || attest !== "ext" || !alt) return;
    while ((nextAcq * 1000) / F.attPerS <= t) { stock.push(alt.mint(`A${nextAcq}`, 1_000_000 + Math.floor((nextAcq * 1000) / F.attPerS))); a.attestationsAcquired++; nextAcq++; }
  };

  for (let at = 0; at < queue.length; at++) {
    const e = queue[at];
    now = 1_000_000 + e.t;
    if (e.kind === "render") { decider.enroll(tokenFor(`legit${seed}`, e.idx)); continue; }
    if (e.kind === "farm" && F) {
      const token = tokenFor("farm", e.idx);
      decider.enroll(token); // a free render
      const sessionsN = F.spread ? Math.min(F.spread.maxSessions, 1 + shedPressure) : F.sessions;
      const classesN = F.spread ? Math.min(1 + Math.floor((F.spread.classesPerS * e.t) / 1000), 1 + shedPressure) : F.classes;
      const klass = `F${e.idx % classesN}`, session = `FS${e.idx % classesN}-${Math.floor(e.idx / classesN) % sessionsN}`; // sessions are free: a class-rotating attacker also has its own sessions
      entities.add(`${klass}|${session}`);
      acquire(e.t);
      while (stock.length > 0 && stock[0].exp <= now) stock.shift();
      if (attest === "ldi" && alt && stock.length === 0) { const issued = alt.issue(klass); if (issued) { stock.push(issued); a.attestationsAcquired++; } }
      const att = attest !== null && stock.length > 0 ? stock[0] : null;
      const inst = instances > 1 ? e.idx % instances : null;
      const ctx: Ctx = { klass, session, token, att, instance: inst };
      const out = decider.decide(post(token), ctx);
      note(a, "farm", out);
      if (!out.admitted && out.lane === "credited") shedPressure++;
      if (out.admitted && out.via === "reserved" && att !== null) {
        stock.shift();
        for (let r = 1; r < F.replay; r++) { // double-spend attempts: the same attestation, a fresh free credit, the next verifier instance
          const rt = tokenFor("replay", e.idx * 16 + r); decider.enroll(rt);
          note(a, "farm", decider.decide(post(rt), { klass, session, token: rt, att, instance: instances > 1 ? (e.idx + r) % instances : null }));
        }
      }
      continue;
    }
    if (e.kind !== "post") continue;
    const j = gen.journeys[e.idx];
    if (doneAt[j.idx] !== null) continue;
    const token = tokenFor(`legit${seed}`, j.idx);
    let att = null as ReturnType<AltModel["mint"]> | null;
    if (attest === "ext" && alt && j.capable && issuerUp(j.startMs)) att = legitAtt.get(j.idx) ?? alt.mint(`L${seed}-${j.idx}`, now);
    else if (attest === "ldi" && alt) att = legitAtt.get(j.idx) ?? alt.issue(klassOf(j.client));
    if (att) legitAtt.set(j.idx, att);
    const out = decider.decide(post(token), { klass: klassOf(j.client), session: sessionOf(j.client), token, att: att ?? null, instance: null });
    note(a, "legit", out);
    if (out.admitted) { doneAt[j.idx] = e.t; clientOk[j.client]++; if (out.via === "reserved") a.legitAttested++; continue; }
    if (e.attempt + 1 < L.retry.max && e.t + L.retry.intervalMs < ALT_DURATION_MS) {
      const next: Ev = { t: e.t + L.retry.intervalMs, rank: 2, kind: "post", idx: j.idx, attempt: e.attempt + 1 };
      let lo = at + 1, hi = queue.length;
      while (lo < hi) { const mid = (lo + hi) >> 1; if (before(queue[mid], next) <= 0) lo = mid + 1; else hi = mid; }
      queue.splice(lo, 0, next);
    }
  }

  a.journeys = gen.journeys.length; a.journeysOk = doneAt.filter((t) => t !== null).length; a.successRate = a.journeys === 0 ? 1 : a.journeysOk / a.journeys;
  let streak: number | null = null;
  for (const j of gen.journeys) {
    if (doneAt[j.idx] === null) { if (streak === null) streak = j.startMs; }
    else if (streak !== null) { a.starvedMsMax = Math.max(a.starvedMsMax, j.startMs - streak); streak = null; }
  }
  if (streak !== null) a.starvedMsMax = Math.max(a.starvedMsMax, ALT_DURATION_MS - streak);
  a.legitAddedLatencyMean = gen.journeys.length === 0 ? 0 : addedLatency / gen.journeys.length;
  const rates = clientTotal.map((n, k) => (n === 0 ? null : clientOk[k] / n)).filter((x): x is number => x !== null);
  const sum = rates.reduce((s, x) => s + x, 0), sq = rates.reduce((s, x) => s + x * x, 0);
  a.jain = rates.length === 0 || sq === 0 ? 1 : (sum * sum) / (rates.length * sq);
  a.minClient = rates.length === 0 ? 1 : Math.min(...rates);
  const ideal = idealAttackerAdmissions(sc);
  a.dominance = ideal === 0 ? 0 : (a.farmCredited + a.farmUnverified) / ideal;
  a.farmEntitiesMax = entities.size;
  const c = decider.counters();
  if (alt) { a.doubleSpends = c.doubleSpends; a.distinctSpent = c.distinctAttestationsSpent; }
  // accounting identities against the decider's own counters; V1's capacity bound
  if (c.creditedAdmitted !== a.creditedAdmitted || c.creditedShedGlobal !== a.creditedShedGlobal || c.entityShed !== a.entityShed || c.unverifiedShed !== a.unverifiedShed) a.idFailures++;
  if (a.creditedAdmitted > CREDITED_BOUND) a.idFailures++;
  return a;
}

// ---------------------------------------------------------------------------
// One scenario over all variants and seeds
// ---------------------------------------------------------------------------

export type Agg = Acct & { successMin: number; successMax: number };
function aggregate(list: readonly Acct[]): Agg {
  const keys = Object.keys(list[0]) as (keyof Acct)[];
  const out: Record<string, number> = {};
  for (const k of keys) out[k] = k === "starvedMsMax" || k === "idFailures" ? Math.max(...list.map((x) => x[k])) : list.reduce((s, x) => s + x[k], 0) / list.length;
  const rates = list.map((x) => x.successRate);
  return { ...(out as unknown as Acct), successMin: Math.min(...rates), successMax: Math.max(...rates) };
}
export type Cell = { id: string; block: string; results: Record<string, Agg> };
export function runScenario(sc: Scenario, seeds: readonly number[]): Cell {
  const per: Record<string, Acct[]> = Object.fromEntries(sc.variants.map((v) => [v, [] as Acct[]]));
  for (const seed of seeds) {
    const gen = generate(sc, seed);
    for (const v of sc.variants) per[v].push(runVariant(sc, gen, v, seed));
  }
  return { id: sc.id, block: sc.block, results: Object.fromEntries(sc.variants.map((v) => [v, aggregate(per[v])])) };
}
