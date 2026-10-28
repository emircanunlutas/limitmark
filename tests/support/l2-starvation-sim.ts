import { createHash } from "node:crypto";
import { JourneyLanes, type LaneDecision, type LanesConfig } from "../../defense/core/lanes";
import type { LayerRequest } from "../../defense/core/types";
import { BA0_FIELD_V1 } from "../../lab/defense/field-thresholds";

/**
 * Deterministic characterization harness for the L2 credited lane (`JourneyLanes`) under one credit-farming actor and one independent
 * legitimate client. Nothing here is a defense and nothing under defense/ is touched: it drives the REAL `JourneyLanes` through the same
 * two calls the plane makes (`enroll` after a delivered form render, `decide` for a request), on an injected monotonic clock.
 *
 * Scope: L2 only. L1 (stateless shape gate) is not modeled. The sender is never an input to L2, so "actor" below is a label of the harness
 * (which tokens an actor holds); the lanes cannot see it.
 */
export const FIELD_L2 = BA0_FIELD_V1.l2;

export type FarmerMint =
  | "per_post"        // a fresh render (free credit) before every POST: the strongest credit farmer
  | "per_k"           // one render per K POSTs (collapse-run fixture f3: postsPerCredit = K)
  | "none"            // never renders: a fresh fabricated token each POST (never enrolled)
  | "single_reuse";   // one render in total, the same token reused for every POST
/** `jitterMs`: each tick moves by a deterministic pseudo-random offset in [-jitterMs, +jitterMs] (a seeded LCG: no Math.random, nothing varies between runs). */
export type FarmerSpec = { ratePerSecond: number; mint: FarmerMint; jitterMs?: number };
export type LegitSpec = { journeys: number; gapMs: number; offsetMs: number; retryIntervalMs: number; maxAttempts: number };
export type SimSpec = { durationMs: number; farmer: FarmerSpec | null; legit: LegitSpec; legitFirstOnTie?: boolean; creditedOverride?: { capacity: number; refillPerSecond: number } };

const FORM = "/test-talep-et";
const TOKEN_ALPHABET_LENGTH = 43;
const tokenFor = (label: string, n: number): string => {
  const value = createHash("sha256").update(`l2-starvation:${label}:${n}`).digest("base64url");
  if (value.length !== TOKEN_ALPHABET_LENGTH) throw new Error("token shape");
  return value;
};
const get = (target: string): LayerRequest => ({ method: "GET", target, headers: [], bodyStatus: "none", body: null });
const post = (token: string): LayerRequest => ({
  method: "POST", target: "/api/public-inquiries", headers: [], bodyStatus: "complete", body: Buffer.from(`name=A&email=a%40b.co&service=web&submissionToken=${token}`, "latin1"),
});

export type Tally = { attempts: number; admittedCredited: number; admittedUnverified: number; shedCredited: number; shedUnverified: number; errors: number; shedReasons: Record<string, number> };
const emptyTally = (): Tally => ({ attempts: 0, admittedCredited: 0, admittedUnverified: 0, shedCredited: 0, shedUnverified: 0, errors: 0, shedReasons: {} });
function count(tally: Tally, decision: LaneDecision): void {
  tally.attempts++;
  if (decision.outcome === "admitted") { if (decision.lane === "credited") tally.admittedCredited++; else tally.admittedUnverified++; return; }
  if (decision.outcome === "shed") {
    if (decision.lane === "credited") tally.shedCredited++; else if (decision.lane === "unverified") tally.shedUnverified++;
    const reason = decision.shedReason ?? "none"; tally.shedReasons[reason] = (tally.shedReasons[reason] ?? 0) + 1; return;
  }
  tally.errors++;
}

export type JourneyResult = { index: number; startMs: number; completedAtMs: number | null; attempts: number; firstLane: string; firstOutcome: string };
export type SimResult = {
  farmer: Tally; farmerRenders: number; legit: Tally; journeys: JourneyResult[];
  legitCompleted: number; legitCompletedFirstAttempt: number; legitAdmittedByWindow: number[];
  firstCreditedShedMs: number | null; lastCreditedLegitAdmitMs: number | null;
  credited: { takes: number; admitted: number; shed: number; levelUnits: number; capacityBound: number };
  unverified: { takes: number; admitted: number; shed: number };
  ledger: { allocated: number; committedLive: number; fullRefusals: number; stateViolations: number }; openRendersAdmitted: number;
  filterPopcount: readonly [number, number]; poisoned: boolean;
};

type Ev = { t: number; actor: 0 | 1; seq: number; attempt: number; kind: "farm" | "legit" };

export function simulate(spec: SimSpec, windowMs = 30_000): SimResult {
  const start = 1_000_000; let now = start;
  const config: LanesConfig = {
    filterBits: FIELD_L2.filterBits, filterHashes: FIELD_L2.filterHashes, epochMs: FIELD_L2.epochMs, credited: spec.creditedOverride ?? FIELD_L2.credited, unverified: FIELD_L2.unverified,
    maxUses: FIELD_L2.maxUses, ledgerCapacity: FIELD_L2.ledgerCapacity, mono: () => now, key: Buffer.alloc(32, 7),
  };
  const lanes = new JourneyLanes(config);
  const events: Ev[] = [];
  const farmActor: 0 | 1 = spec.legitFirstOnTie ? 1 : 0, legitActor: 0 | 1 = spec.legitFirstOnTie ? 0 : 1;
  if (spec.farmer && spec.farmer.ratePerSecond > 0) {
    const period = 1000 / spec.farmer.ratePerSecond; const jitter = spec.farmer.jitterMs ?? 0; let lcg = 12345;
    for (let i = 0; Math.round(i * period) < spec.durationMs; i++) {
      lcg = (Math.imul(lcg, 1664525) + 1013904223) >>> 0;
      const offset = jitter > 0 ? (lcg >>> 8) % (2 * jitter + 1) - jitter : 0;
      events.push({ t: Math.max(0, Math.round(i * period) + offset), actor: farmActor, seq: i, attempt: 0, kind: "farm" });
    }
  }
  for (let j = 0; j < spec.legit.journeys; j++) for (let a = 0; a < spec.legit.maxAttempts; a++) events.push({ t: spec.legit.offsetMs + j * spec.legit.gapMs + a * spec.legit.retryIntervalMs, actor: legitActor, seq: j, attempt: a, kind: "legit" });
  events.sort((a, b) => a.t - b.t || a.actor - b.actor || a.seq - b.seq || a.attempt - b.attempt);

  const farmer = emptyTally(), legit = emptyTally();
  let farmerRenders = 0, farmerToken: string | null = null, openRenders = 0, firstCreditedShedMs: number | null = null, lastCreditedLegitAdmitMs: number | null = null;
  const journeys: JourneyResult[] = [];
  const windows = Array.from({ length: Math.ceil(spec.durationMs / windowMs) }, () => 0);
  const render = (): void => { const d = lanes.decide(get(FORM)); if (d.lane === "open" && d.outcome === "admitted") openRenders++; };
  const noteShed = (d: LaneDecision, at: number): void => { if (d.lane === "credited" && d.outcome === "shed" && firstCreditedShedMs === null) firstCreditedShedMs = at; };

  for (const event of events) {
    if (event.t >= spec.durationMs) continue;
    now = start + event.t;
    if (event.kind === "farm") {
      const mint = spec.farmer!.mint; let token: string;
      if (mint === "per_post" || (mint === "per_k" && farmerRenders * FIELD_L2.maxUses <= event.seq) || (mint === "single_reuse" && farmerToken === null)) {
        render(); farmerRenders++; token = tokenFor("farm", farmerRenders); lanes.enroll(token); farmerToken = token;
      } else if (mint === "none") token = tokenFor("fab", event.seq);
      else token = farmerToken as string;
      const d = lanes.decide(post(token)); count(farmer, d); noteShed(d, event.t);
      continue;
    }
    // legitimate journey: render the form (free) and the plane enrolls its token after delivery, then POST; a shed consumes nothing, so the SAME token is retried
    const tokenOf = tokenFor("legit", event.seq);
    let journey = journeys[event.seq];
    if (event.attempt === 0) { render(); lanes.enroll(tokenOf); }
    else if (journey === undefined || journey.completedAtMs !== null) continue;
    const d = lanes.decide(post(tokenOf)); count(legit, d); noteShed(d, event.t);
    if (event.attempt === 0) { journey = { index: event.seq, startMs: event.t, completedAtMs: null, attempts: 0, firstLane: String(d.lane), firstOutcome: d.outcome }; journeys[event.seq] = journey; }
    journey.attempts = event.attempt + 1;
    if (d.outcome === "admitted") {
      journey.completedAtMs = event.t; windows[Math.min(windows.length - 1, Math.floor(event.t / windowMs))]++;
      if (d.lane === "credited") lastCreditedLegitAdmitMs = event.t;
    }
  }
  now = start + spec.durationMs;
  const snap = lanes.snapshot();
  return {
    farmer, farmerRenders, legit, journeys,
    legitCompleted: journeys.filter((j) => j.completedAtMs !== null).length,
    legitCompletedFirstAttempt: journeys.filter((j) => j.completedAtMs !== null && j.attempts === 1).length,
    legitAdmittedByWindow: windows, firstCreditedShedMs, lastCreditedLegitAdmitMs,
    credited: { takes: snap.credited.takes, admitted: snap.credited.admitted, shed: snap.credited.shed, levelUnits: snap.credited.levelUnits,
      capacityBound: config.credited.capacity + Math.floor((config.credited.refillPerSecond * spec.durationMs) / 1000) },
    unverified: { takes: snap.unverified.takes, admitted: snap.unverified.admitted, shed: snap.unverified.shed },
    ledger: { allocated: snap.ledger.allocated, committedLive: snap.ledger.committedLive, fullRefusals: snap.ledger.fullRefusals, stateViolations: snap.ledger.stateViolations },
    openRendersAdmitted: openRenders, filterPopcount: snap.filter.popcount, poisoned: snap.poisoned,
  };
}

// ---------------------------------------------------------------------------
// The characterization matrix. One definition, used by the test (which pins what it measured) and by any exploratory printing script.
// ---------------------------------------------------------------------------

const LEGIT_30: LegitSpec = { journeys: 30, gapMs: 4_000, offsetMs: 125, retryIntervalMs: 1_000, maxAttempts: 1 };
const RUN_MS = 120_000; // two full 60 s filter generations
const farmerLine = (r: SimResult) => ({ attempts: r.farmer.attempts, admittedCredited: r.farmer.admittedCredited, admittedUnverified: r.farmer.admittedUnverified, shedCredited: r.farmer.shedCredited, shedUnverified: r.farmer.shedUnverified, renders: r.farmerRenders });
const legitLine = (r: SimResult) => ({ attempts: r.legit.attempts, completed: r.legitCompleted, firstAttempt: r.legitCompletedFirstAttempt, shedCredited: r.legit.shedCredited, shedUnverified: r.legit.shedUnverified, shedReasons: r.legit.shedReasons, byWindow30s: r.legitAdmittedByWindow });
const bucketLine = (r: SimResult) => ({ creditedTakes: r.credited.takes, creditedAdmitted: r.credited.admitted, creditedShed: r.credited.shed, creditedBound: r.credited.capacityBound, unverifiedTakes: r.unverified.takes, unverifiedAdmitted: r.unverified.admitted, unverifiedShed: r.unverified.shed });

/** Legitimate success of ONE attempt at many steady-state arrival instants (13..37 ms apart: every phase of the 250/500 ms grids is visited). */
export function probeSingleAttempt(farmer: FarmerSpec | null, probes: number, stepMs: number): number {
  let ok = 0;
  for (let k = 0; k < probes; k++) {
    const at = 20_000 + k * stepMs;
    ok += simulate({ durationMs: at + 1_000, farmer, legit: { journeys: 1, gapMs: 1, offsetMs: at, retryIntervalMs: 1, maxAttempts: 1 } }).legitCompleted;
  }
  return ok;
}

export function characterize() {
  const run = (farmer: FarmerSpec | null, legit: LegitSpec = LEGIT_30, extra: Partial<SimSpec> = {}) => simulate({ durationMs: RUN_MS, farmer, legit, ...extra });
  const periodic = (mint: FarmerMint, ratePerSecond = 4): FarmerSpec => ({ ratePerSecond, mint });
  const results = new Map<string, SimResult>();
  const keep = (label: string, r: SimResult) => { results.set(label, r); return r; };

  const control = keep("control", run(null));
  const mints = Object.fromEntries((["per_post", "per_k", "none", "single_reuse"] as const).map((mint) => {
    const r = keep(`mint:${mint}`, run(periodic(mint)));
    return [mint, { farmer: farmerLine(r), legit: legitLine(r), buckets: bucketLine(r), firstCreditedShedMs: r.firstCreditedShedMs, lastCreditedLegitAdmitMs: r.lastCreditedLegitAdmitMs, openRendersAdmitted: r.openRendersAdmitted }];
  }));
  const rates = Object.fromEntries([0, 1, 1.9, 2, 2.1, 3, 4, 8, 20].map((rate) => {
    const r = keep(`rate:${rate}`, run(rate === 0 ? null : periodic("per_post", rate)));
    return [String(rate), { legitCompleted: r.legitCompleted, farmerCredited: r.farmer.admittedCredited, creditedShed: r.credited.shed, firstCreditedShedMs: r.firstCreditedShedMs }];
  }));
  const phase = {
    noFarmer: probeSingleAttempt(null, 120, 37),
    periodic4: probeSingleAttempt(periodic("per_post"), 120, 37),
    jitter4: probeSingleAttempt({ ratePerSecond: 4, mint: "per_post", jitterMs: 50 }, 120, 37),
    jitter100: probeSingleAttempt({ ratePerSecond: 100, mint: "per_post", jitterMs: 3 }, 120, 37),
  };
  const retry = (farmer: FarmerSpec, retryIntervalMs: number, maxAttempts: number) => {
    const r = keep(`retry:${farmer.ratePerSecond}:${farmer.jitterMs ?? 0}:${retryIntervalMs}x${maxAttempts}`, run(farmer, { ...LEGIT_30, retryIntervalMs, maxAttempts }));
    return { completed: r.legitCompleted, firstAttempt: r.legitCompletedFirstAttempt, meanAttemptsPerJourneyX10: Math.round((10 * r.journeys.reduce((a, j) => a + j.attempts, 0)) / r.journeys.length), farmerCredited: r.farmer.admittedCredited };
  };
  const retries = {
    periodic4_10msX500: retry(periodic("per_post"), 10, 500),
    jitter4_1sX5: retry({ ratePerSecond: 4, mint: "per_post", jitterMs: 50 }, 1_000, 5),
    jitter4_20msX250: retry({ ratePerSecond: 4, mint: "per_post", jitterMs: 50 }, 20, 250),
    jitter100_1sX5: retry({ ratePerSecond: 100, mint: "per_post", jitterMs: 3 }, 1_000, 5),
    jitter100_20msX250: retry({ ratePerSecond: 100, mint: "per_post", jitterMs: 3 }, 20, 250),
  };
  const canaryShape = run(periodic("per_post"), { ...LEGIT_30, journeys: 12 }, { durationMs: 60_000 });
  keep("canary12", canaryShape);
  return { control: { legit: legitLine(control), buckets: bucketLine(control), firstCreditedShedMs: control.firstCreditedShedMs }, mints, rates, phase, retries,
    canary12In60s: { farmer: farmerLine(canaryShape), legit: legitLine(canaryShape) }, results };
}
