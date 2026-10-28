import { NO_RETRY, type Cell, type LegitSpec, type Retry, type Scenario } from "./l2-v2-matrix";
import type { ClassHint, V2VariantName } from "./l2-v2-shadow";

/**
 * The adversarial matrix and the PRE-REGISTERED decision criteria of the V2 shadow study. The criteria below were written before the first
 * full matrix run and are not tuned afterwards; a failing hypothesis is reported as failing.
 *
 * Reading the variants: `always` enforces a per-class ceiling at every moment; `gated` enforces it only while the V2 global credited level is
 * below half its capacity ("under contention"); the `_trustfwd` variants are UNSAFE counterexamples that also enforce on forwarded-header
 * hints. The ceiling is phi = 1/8 of the credited refill (0.25/s, capacity 2) per class; the global bucket is V1's, unchanged.
 */
export const CRITERIA = Object.freeze({
  /** H1: a single-class farmer is constrained enough to improve independent legitimate continuity. */
  h1ImproveOverV1: 0.20,        // enforced-V2 journey success must beat V1 by at least this in every single-class farmer cell where V1 success is at most h1V1Ceiling
  h1V1Ceiling: 0.80,
  h1RestoreWithin: 0.02,        // second tier, reported separately: within this of the no-attacker control
  /** H2: shared-network legitimate users are not materially worse off than under V1. */
  h2Tolerance: 0.02,            // enforced-V2 success may be at most this below V1 in every shared-network cell
  /** H3: spreading across classes does not raise attacker exposure above V1. */
  h3AttackerSlack: 5,           // attacker credited admissions under V2 at most V1 plus this (mean over seeds, of 240 maximum) in every cell
  /** H4: missing or proxy-derived hints cannot silently produce unsafe enforcement. */
  h4DegenerateShare: 0.90,      // the flag the shadow evaluator must raise when one peer class carries at least this share of credited-eligible requests
  h4ExemptTolerance: 0.02,
});

export const SAFE_VARIANTS: readonly V2VariantName[] = ["always", "gated"];
const ALL_VARIANTS: readonly V2VariantName[] = ["always", "gated", "always_trustfwd", "gated_trustfwd"];

const peer = (id: string): ClassHint => ({ source: "peer", id });
const independent = (_j: number, rnd: () => number): ClassHint => peer(`u${Math.floor(rnd() * 4096)}`);
const legit = (rate: number, place: LegitSpec["place"] = independent, retry: Retry = NO_RETRY, arrivals: LegitSpec["arrivals"] = "poisson"): LegitSpec => ({ rate, arrivals, place, retry });
const classIds = (n: number) => Array.from({ length: n }, (_, i) => `A${i}`);
const farmer = (totalRate: number, classes: readonly string[] = ["A0"], hint: ClassHint["source"] = "peer", jitterMs = 0, claimedClass?: string) => ({ totalRate, classes, hint, jitterMs, claimedClass });
let activeVariants: readonly string[] = SAFE_VARIANTS;
const sc = (block: string, id: string, f: Scenario["farmer"], l: LegitSpec, over: Partial<Scenario> = {}): Scenario => ({ id: `${block}/${id}`, block, farmer: f, legit: l, legitFirstOnTie: false, variants: activeVariants, ...over });

export function buildScenarios(extraVariants: readonly string[] = []): Scenario[] {
  activeVariants = [...SAFE_VARIANTS, ...extraVariants];
  const out: Scenario[] = [];
  // B1: one single-class farmer at 0 (control), 1, 2, 3, 4, 100 POST/s; independent legitimate clients at 0.25/s, no retry
  for (const rate of [0, 1, 2, 3, 4, 100]) out.push(sc("B1-farm-rate", `rate-${rate}`, rate === 0 ? null : farmer(rate), legit(0.25)));
  // B2: the same total farm rate spread across 1, 2, 4, 8, 16 classes
  for (const total of [4, 100]) for (const n of [1, 2, 4, 8, 16]) out.push(sc("B2-spread", `rate-${total}-classes-${n}`, farmer(total, classIds(n)), legit(0.25)));
  // B3: legitimate clients sharing the attacker's class (fraction rho of journeys come from class A0)
  for (const rho of [0.1, 0.5, 1]) out.push(sc("B3-attacker-class", `rho-${rho}`, farmer(4), legit(0.25, (j, rnd) => (rnd() < rho ? peer("A0") : independent(j, rnd)))));
  // B4: many legitimate clients behind one NAT (class "NAT"), with and without a farmer elsewhere
  for (const demand of [0.25, 0.5, 1, 1.9, 3]) out.push(sc("B4-nat", `no-attacker-demand-${demand}`, null, legit(demand, () => peer("NAT"))));
  for (const demand of [0.25, 1]) out.push(sc("B4-nat", `attacker-elsewhere-demand-${demand}`, farmer(4), legit(demand, () => peer("NAT"))));
  // B5: everyone appears behind one proxy: undeclared (peer = proxy, one class) and declared shared infrastructure
  out.push(sc("B5-proxy", "undeclared-farmer-4", farmer(4, ["PROXY"]), legit(0.25, () => peer("PROXY"))));
  out.push(sc("B5-proxy", "undeclared-no-attacker-demand-1", null, legit(1, () => peer("PROXY"))));
  out.push(sc("B5-proxy", "declared-farmer-4", farmer(4, ["PROXY"], "declared_shared"), legit(0.25, () => ({ source: "declared_shared", id: "PROXY" }))));
  // B6: missing and spoofed hints
  out.push(sc("B6-hints", "all-missing-farmer-4", farmer(4, ["A0"], "missing"), legit(0.25, () => ({ source: "missing" }))));
  out.push(sc("B6-hints", "farmer-missing-only", farmer(4, ["A0"], "missing"), legit(0.25)));
  for (const rate of [1.5, 4]) out.push(sc("B6-hints", `spoof-victim-class-farmer-${rate}`, farmer(rate, ["A0"], "forwarded", 0, "VICTIM"), legit(0.25, () => peer("VICTIM")), { variants: [...ALL_VARIANTS, ...extraVariants] }));
  // B7: legitimate demand below, near and above the global refill (2/s), with a single-class farmer; and without one
  for (const demand of [0.25, 1, 1.9, 3]) out.push(sc("B7-demand", `farmer-4-demand-${demand}`, farmer(4), legit(demand)));
  for (const demand of [1.9, 3]) out.push(sc("B7-demand", `no-attacker-demand-${demand}`, null, legit(demand)));
  // B8: retry and no-retry clients against slow and fast single-class farmers
  const retries: [string, Retry][] = [["none", NO_RETRY], ["1s-x5", { intervalMs: 1000, max: 5 }], ["20ms-x250", { intervalMs: 20, max: 250 }]];
  for (const total of [4, 100]) for (const [name, retry] of retries) out.push(sc("B8-retry", `farmer-${total}-retry-${name}`, farmer(total), legit(0.25, independent, retry)));
  for (const [total, jitter] of [[4, 50], [100, 3]] as const) for (const [name, retry] of retries) out.push(sc("B8-retry", `jittered-farmer-${total}-retry-${name}`, farmer(total, ["A0"], "peer", jitter), legit(0.25, independent, retry)));
  // B9: clock jitter on the farmer and deterministic arrival-order variation at ties
  for (const jitter of [0, 50]) for (const legitFirst of [false, true]) out.push(sc("B9-jitter-order", `jitter-${jitter}-legit-first-${legitFirst}`, farmer(4, ["A0"], "peer", jitter), legit(0.25), { legitFirstOnTie: legitFirst }));
  return out;
}

// ---------------------------------------------------------------------------
// Hypothesis evaluation (pure function of the measured cells)
// ---------------------------------------------------------------------------

export type HypothesisReport = {
  variant: string;
  h1: { improve: boolean; restore: boolean; failingImprove: string[]; failingRestore: string[] };
  h2: { pass: boolean; failing: string[] };
  h3: { pass: boolean; failing: string[] };
  h4: { pass: boolean; safeEnforcementOnlyOnPeer: boolean; degenerateFlagRaised: boolean; failing: string[] };
};

export function evaluateHypotheses(cells: readonly Cell[], variant: string): HypothesisReport {
  const byId = new Map(cells.map((c) => [c.id, c]));
  const cell = (id: string): Cell => { const c = byId.get(id); if (!c) throw new Error(`missing cell ${id}`); return c; };
  const control = cell("B1-farm-rate/rate-0").v1.successRate;

  const h1Cells = cells.filter((c) => /^B1-farm-rate\/rate-(2|3|4|100)$/.test(c.id) || (c.block === "B9-jitter-order") || /^B8-retry\/farmer-(4|100)-retry-none$/.test(c.id) || /^B2-spread\/rate-(4|100)-classes-1$/.test(c.id));
  const failingImprove: string[] = [], failingRestore: string[] = [];
  for (const c of h1Cells) {
    const v1 = c.v1.successRate, v2 = c.enforced[variant].successRate;
    if (v1 <= CRITERIA.h1V1Ceiling && v2 - v1 < CRITERIA.h1ImproveOverV1) failingImprove.push(`${c.id}: V1 ${v1.toFixed(3)} -> V2 ${v2.toFixed(3)}`);
    if (v1 <= CRITERIA.h1V1Ceiling && v2 < control - CRITERIA.h1RestoreWithin) failingRestore.push(`${c.id}: V2 ${v2.toFixed(3)} vs control ${control.toFixed(3)}`);
  }

  const h2Cells = cells.filter((c) => c.block === "B3-attacker-class" || c.block === "B4-nat" || /^B5-proxy\/undeclared/.test(c.id));
  const h2Failing = h2Cells.filter((c) => c.enforced[variant].successRate < c.v1.successRate - CRITERIA.h2Tolerance)
    .map((c) => `${c.id}: V1 ${c.v1.successRate.toFixed(3)} -> V2 ${c.enforced[variant].successRate.toFixed(3)}`);

  const h3Failing: string[] = [];
  for (const c of cells) {
    if (c.identityFailures.length) h3Failing.push(`${c.id}: ${c.identityFailures[0]}`);
    const v1 = c.v1.farmCredited + c.v1.farmUnverified, v2 = c.enforced[variant].farmCredited + c.enforced[variant].farmUnverified;
    if (v2 > v1 + CRITERIA.h3AttackerSlack) h3Failing.push(`${c.id}: attacker admissions V1 ${v1.toFixed(1)} -> V2 ${v2.toFixed(1)}`);
  }

  const exemptCells = cells.filter((c) => c.block === "B6-hints" || /^B5-proxy\/declared/.test(c.id));
  const h4Failing: string[] = [];
  let onlyPeer = true;
  for (const c of cells) for (const source of Object.keys(c.classShedBySource[variant] ?? {})) if (source !== "peer") { onlyPeer = false; h4Failing.push(`${c.id}: class shed on a ${source} hint`); }
  for (const c of exemptCells.filter((x) => !/spoof/.test(x.id))) {
    if (c.enforced[variant].classShed !== 0) h4Failing.push(`${c.id}: class sheds on exempt traffic`);
    if (c.enforced[variant].successRate < c.v1.successRate - CRITERIA.h4ExemptTolerance) h4Failing.push(`${c.id}: exempt traffic worse than V1`);
  }
  for (const c of exemptCells.filter((x) => /spoof/.test(x.id))) if (c.enforced[variant].successRate < c.v1.successRate - CRITERIA.h4ExemptTolerance) h4Failing.push(`${c.id}: spoofed hint harmed the victim`);
  const flagged = cells.filter((c) => /^B5-proxy\/undeclared/.test(c.id)).every((c) => c.topClassShare[variant] >= CRITERIA.h4DegenerateShare);
  if (!flagged) h4Failing.push("the degenerate-topology flag was not raised in an undeclared single-proxy cell");

  return {
    variant,
    h1: { improve: failingImprove.length === 0, restore: failingRestore.length === 0, failingImprove, failingRestore },
    h2: { pass: h2Failing.length === 0, failing: h2Failing },
    h3: { pass: h3Failing.length === 0, failing: h3Failing },
    h4: { pass: h4Failing.length === 0, safeEnforcementOnlyOnPeer: onlyPeer, degenerateFlagRaised: flagged, failing: h4Failing },
  };
}

// ---------------------------------------------------------------------------
// HELD-OUT validation of the post-hoc candidate (parameters never used while choosing it; five unseen seeds)
// ---------------------------------------------------------------------------

export const HELD_OUT_SEEDS: readonly number[] = [101, 103, 107, 109, 113];

export function buildHeldOutScenarios(variants: readonly string[]): Scenario[] {
  activeVariants = variants;
  const out: Scenario[] = [];
  out.push(sc("HO1-single-class", "control", null, legit(0.25)));
  for (const rate of [2.5, 6, 25]) out.push(sc("HO1-single-class", `rate-${rate}`, farmer(rate), legit(0.25)));
  for (const demand of [0.5, 1.5]) out.push(sc("HO1-single-class", `rate-4-demand-${demand}`, farmer(4), legit(demand)));
  out.push(sc("HO1-single-class", "rate-4-periodic-legit", farmer(4), legit(0.25, independent, NO_RETRY, "periodic")));
  out.push(sc("HO1-single-class", "jittered-5ms-rate-4-retry-1s-x5", farmer(4, ["A0"], "peer", 5), legit(0.25, independent, { intervalMs: 1000, max: 5 })));
  for (const n of [3, 5, 6, 7]) out.push(sc("HO3-spread", `rate-4-classes-${n}`, farmer(4, classIds(n)), legit(0.25)));
  out.push(sc("HO3-spread", "rate-100-classes-12", farmer(100, classIds(12)), legit(0.25)));
  for (const rho of [0.25, 0.75]) out.push(sc("HO2-shared", `attacker-class-rho-${rho}`, farmer(4), legit(0.25, (j, rnd) => (rnd() < rho ? peer("A0") : independent(j, rnd)))));
  for (const demand of [0.75, 1.5, 2.5]) out.push(sc("HO2-shared", `nat-no-attacker-demand-${demand}`, null, legit(demand, () => peer("NAT"))));
  for (const demand of [0.5, 1.9]) out.push(sc("HO2-shared", `nat-attacker-elsewhere-demand-${demand}`, farmer(4), legit(demand, () => peer("NAT"))));
  out.push(sc("HO2-shared", "three-nats-no-attacker-demand-1.5", null, legit(1.5, (_j, rnd) => peer(`NAT${Math.floor(rnd() * 3)}`))));
  out.push(sc("HO2-shared", "three-nats-attacker-demand-1", farmer(4), legit(1, (_j, rnd) => peer(`NAT${Math.floor(rnd() * 3)}`))));
  out.push(sc("HO2-shared", "undeclared-proxy-no-attacker-demand-1.5", null, legit(1.5, () => peer("PROXY"))));
  out.push(sc("HO4-hints", "half-legit-missing-farmer-4", farmer(4), legit(0.25, (j, rnd) => (rnd() < 0.5 ? { source: "missing" } : independent(j, rnd)))));
  return out;
}

export function evaluateHeldOut(cells: readonly Cell[], variant: string) {
  const control = cells.find((c) => c.id === "HO1-single-class/control")!.v1.successRate;
  const improveFail: string[] = [], restoreFail: string[] = [], h2Fail: string[] = [], h3Fail: string[] = [];
  for (const c of cells) {
    const v1 = c.v1.successRate, v2 = c.enforced[variant].successRate;
    if (c.block === "HO1-single-class" && c.id !== "HO1-single-class/control" && v1 <= CRITERIA.h1V1Ceiling) {
      if (v2 - v1 < CRITERIA.h1ImproveOverV1) improveFail.push(`${c.id}: V1 ${v1.toFixed(3)} -> V2 ${v2.toFixed(3)}`);
      if (v2 < control - CRITERIA.h1RestoreWithin) restoreFail.push(`${c.id}: V2 ${v2.toFixed(3)} vs control ${control.toFixed(3)}`);
    }
    if (c.block === "HO2-shared" && v2 < v1 - CRITERIA.h2Tolerance) h2Fail.push(`${c.id}: V1 ${v1.toFixed(3)} -> V2 ${v2.toFixed(3)}`);
    if (c.identityFailures.length) h3Fail.push(`${c.id}: ${c.identityFailures[0]}`);
    const a1 = c.v1.farmCredited + c.v1.farmUnverified, a2 = c.enforced[variant].farmCredited + c.enforced[variant].farmUnverified;
    if (a2 > a1 + CRITERIA.h3AttackerSlack) h3Fail.push(`${c.id}: attacker admissions V1 ${a1.toFixed(1)} -> V2 ${a2.toFixed(1)}`);
  }
  return { variant, h1Improve: improveFail.length === 0, h1Restore: restoreFail.length === 0, h2: h2Fail.length === 0, h3: h3Fail.length === 0, improveFail, restoreFail, h2Fail, h3Fail };
}
