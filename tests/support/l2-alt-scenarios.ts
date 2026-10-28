import {
  CORE_VARIANTS, NO_RETRY, type Cell, type FarmSpec, type IssuerSpec, type LegitSpec, type Scenario,
} from "./l2-alt-matrix";

/**
 * PRE-REGISTERED scenarios and criteria for the L2 alternatives study. Written before the first evaluation run; the evaluation seeds are
 * EVAL_SEEDS in l2-alt-matrix.ts. Changes after the first full run are listed in the document, not hidden here.
 */
export const ALT_CRITERIA = Object.freeze({
  /** K1: where V1 completes <= ceiling, a variant must add at least `improve` and come within `restore` of the no-attacker control. */
  k1V1Ceiling: 0.8, k1Improve: 0.2, k1Restore: 0.05,
  /** K2 and K6: legitimate users without an attacker (shared network, issuer down) may be at most this much worse than V1. */
  worseTolerance: 0.02,
  /** K3: attacker admissions may exceed V1's by at most this many (credited + unverified, mean per seed); capacity identities must hold exactly. */
  attackerSlack: 5,
  /** K4: with attacker identities that cost nothing (sessions), the variant must still beat V1 by `improve`. */
  k4Improve: 0.2,
});

const farm = (rate: number, over: Partial<FarmSpec> = {}): FarmSpec => ({ rate, jitterMs: 0, classes: 1, sessions: 1, attPerS: 0, replay: 1, ...over });
const legit = (rate: number, over: Partial<LegitSpec> = {}): LegitSpec => ({ rate, clients: 64, placement: "own", arrivals: "poisson", retry: NO_RETRY, ...over });
const ISSUER: IssuerSpec = { pOk: 0.9, latencyMs: 800, failMs: 2000, down: null };
const DEFAULT_LEGIT = 0.25;

export function buildAltScenarios(): Scenario[] {
  const out: Scenario[] = [];
  const add = (block: string, id: string, f: FarmSpec | null, l: LegitSpec, issuer: IssuerSpec = ISSUER, variants: readonly string[] = CORE_VARIANTS): void => {
    out.push({ id: `${block}/${id}`, block, farm: f, legit: l, issuer, variants });
  };
  // D1: one identity, rising rate
  for (const rate of [0, 1, 2, 4, 100]) add("D1-rate", `rate-${rate}`, rate === 0 ? null : farm(rate), legit(DEFAULT_LEGIT));
  // D2: attacker multiplies identities (sessions are free; classes cost an unknown amount)
  add("D2-identities", "sessions-8-rate-4", farm(4, { sessions: 8 }), legit(DEFAULT_LEGIT));
  add("D2-identities", "sessions-64-rate-4", farm(4, { sessions: 64 }), legit(DEFAULT_LEGIT));
  add("D2-identities", "sessions-64-rate-100", farm(100, { sessions: 64 }), legit(DEFAULT_LEGIT));
  for (const c of [4, 16, 64]) add("D2-identities", `classes-${c}-rate-4`, farm(4, { classes: c }), legit(DEFAULT_LEGIT));
  add("D2-identities", "classes-16-rate-100", farm(100, { classes: 16 }), legit(DEFAULT_LEGIT));
  add("D2-identities", "classes-4-sessions-16-rate-100", farm(100, { classes: 4, sessions: 16 }), legit(DEFAULT_LEGIT));
  // D3: shared networks (8 legitimate clients behind one class), and independent clients for the fairness index
  add("D3-shared", "nat8-demand-1-no-attacker", null, legit(1, { clients: 8, placement: "one" }));
  add("D3-shared", "nat8-demand-1.9-no-attacker", null, legit(1.9, { clients: 8, placement: "one" }));
  add("D3-shared", "nat8-demand-1-attacker-elsewhere", farm(4), legit(1, { clients: 8, placement: "one" }));
  add("D3-shared", "nat8-demand-0.5-in-attacker-class-sessions-1", farm(4), legit(0.5, { clients: 8, placement: "attacker" }));
  add("D3-shared", "nat8-demand-0.5-in-attacker-class-sessions-64", farm(4, { sessions: 64 }), legit(0.5, { clients: 8, placement: "attacker" }));
  add("D3-shared", "own8-demand-1-attacker", farm(4), legit(1, { clients: 8, placement: "own" }));
  // D4: attacker adapts its timing or its identities to the policy
  add("D4-adaptive", "spread-rate-4", farm(4, { spread: { classesPerS: 0.5, maxSessions: 256 } }), legit(DEFAULT_LEGIT));
  add("D4-adaptive", "spread-rate-100", farm(100, { spread: { classesPerS: 0.5, maxSessions: 256 } }), legit(DEFAULT_LEGIT));
  add("D4-adaptive", "on-off-20-per-s", farm(20, { onOff: { onMs: 10_000, offMs: 10_000 } }), legit(DEFAULT_LEGIT));
  add("D4-adaptive", "slow-2.1", farm(2.1), legit(DEFAULT_LEGIT));
  add("D4-adaptive", "jitter-50-rate-4", farm(4, { jitterMs: 50 }), legit(DEFAULT_LEGIT));
  // D5: attestation economics, accessibility, latency, issuer availability (only the pool variants react to the issuer)
  for (const a of [0.1, 0.5, 2, 10, 100]) add("D5-attest", `attacker-acquires-${a}-per-s-rate-4`, farm(4, { attPerS: a }), legit(DEFAULT_LEGIT));
  add("D5-attest", "attacker-acquires-0.5-per-s-rate-100", farm(100, { attPerS: 0.5 }), legit(DEFAULT_LEGIT));
  add("D5-attest", "accessible-0.5-rate-4", farm(4), legit(DEFAULT_LEGIT), { ...ISSUER, pOk: 0.5 });
  add("D5-attest", "accessible-0.0-rate-4", farm(4), legit(DEFAULT_LEGIT), { ...ISSUER, pOk: 0 });
  add("D5-attest", "latency-5000-rate-4", farm(4), legit(DEFAULT_LEGIT), { ...ISSUER, latencyMs: 5000 });
  add("D5-attest", "issuer-down-all-rate-4", farm(4), legit(DEFAULT_LEGIT), { ...ISSUER, down: [0, 120_000] });
  add("D5-attest", "issuer-down-second-half-rate-4", farm(4), legit(DEFAULT_LEGIT), { ...ISSUER, down: [60_000, 120_000] });
  add("D5-attest", "issuer-down-all-no-attacker-demand-1.9", null, legit(1.9), { ...ISSUER, down: [0, 120_000] });
  add("D5-attest", "issuer-down-all-no-attacker-demand-3", null, legit(3), { ...ISSUER, down: [0, 120_000] });
  add("D5-attest", "attacker-classes-16-rate-4-ldi-acquisition", farm(4, { classes: 16 }), legit(DEFAULT_LEGIT));
  const n2 = ["v1", "pool40_ext_n2_local", "pool40_ext_n2_shared", "pool40_ext"];
  add("D5b-verifiers", "replay-4-acquires-2-per-s-rate-4", farm(4, { attPerS: 2, replay: 4 }), legit(DEFAULT_LEGIT), ISSUER, n2);
  add("D5b-verifiers", "no-replay-acquires-2-per-s-rate-4", farm(4, { attPerS: 2, replay: 1 }), legit(DEFAULT_LEGIT), ISSUER, n2);
  // D6: legitimate demand below, near and above the credited refill, with and without an attacker
  for (const d of [1, 1.9, 3]) add("D6-demand", `attacker-4-demand-${d}`, farm(4), legit(d));
  for (const d of [1.9, 3]) add("D6-demand", `no-attacker-demand-${d}`, null, legit(d));
  // D7: retry behaviour
  add("D7-retry", "rate-4-retry-1s-x5", farm(4), legit(DEFAULT_LEGIT, { retry: { intervalMs: 1000, max: 5 } }));
  add("D7-retry", "rate-100-retry-20ms-x250", farm(100), legit(DEFAULT_LEGIT, { retry: { intervalMs: 20, max: 250 } }));
  return out;
}

// ---------------------------------------------------------------------------
// Evaluation (a pure function of the measured cells)
// ---------------------------------------------------------------------------

export type CriterionResult = { pass: boolean | null; failing: string[] };
export type AltReport = { variant: string; k1: CriterionResult; k2: CriterionResult; k3: CriterionResult; k4: CriterionResult; k6: CriterionResult };

export function evaluateAlt(cells: readonly Cell[], variant: string): AltReport {
  const byId = new Map(cells.map((c) => [c.id, c]));
  const cell = (id: string): Cell => { const c = byId.get(id); if (!c) throw new Error(`missing cell ${id}`); return c; };
  const r = (c: Cell, v: string) => { const x = c.results[v]; if (!x) throw new Error(`cell ${c.id} has no ${v}`); return x; };
  const control = r(cell("D1-rate/rate-0"), "v1").successRate;
  const K = ALT_CRITERIA;
  const k1: string[] = [], k2: string[] = [], k3: string[] = [], k4: string[] = [], k6: string[] = [];

  for (const id of ["D1-rate/rate-2", "D1-rate/rate-4", "D1-rate/rate-100", "D4-adaptive/slow-2.1", "D4-adaptive/jitter-50-rate-4"]) {
    const c = cell(id), v1 = r(c, "v1").successRate, v2 = r(c, variant).successRate;
    if (v1 <= K.k1V1Ceiling && v2 - v1 < K.k1Improve) k1.push(`${id}: V1 ${v1.toFixed(3)} -> ${v2.toFixed(3)} (improve < ${K.k1Improve})`);
    if (v1 <= K.k1V1Ceiling && v2 < control - K.k1Restore) k1.push(`${id}: ${v2.toFixed(3)} below control ${control.toFixed(3)} - ${K.k1Restore}`);
  }
  for (const id of ["D3-shared/nat8-demand-1-no-attacker", "D3-shared/nat8-demand-1.9-no-attacker", "D3-shared/nat8-demand-1-attacker-elsewhere", "D6-demand/no-attacker-demand-1.9", "D6-demand/no-attacker-demand-3"]) {
    const c = cell(id), v1 = r(c, "v1").successRate, v2 = r(c, variant).successRate;
    if (v2 < v1 - K.worseTolerance) k2.push(`${id}: V1 ${v1.toFixed(3)} -> ${v2.toFixed(3)}`);
  }
  for (const c of cells) {
    if (c.results[variant] === undefined) continue; // the verifier-instance cells carry only their own variants
    const x = r(c, variant), v1 = r(c, "v1");
    if (x.idFailures > 0) k3.push(`${c.id}: capacity/accounting identity failed`);
    const atk = x.farmCredited + x.farmUnverified, atk1 = v1.farmCredited + v1.farmUnverified;
    if (atk > atk1 + K.attackerSlack) k3.push(`${c.id}: attacker admissions V1 ${atk1.toFixed(1)} -> ${atk.toFixed(1)}`);
  }
  for (const id of ["D2-identities/sessions-8-rate-4", "D2-identities/sessions-64-rate-4", "D2-identities/sessions-64-rate-100"]) {
    const c = cell(id), v1 = r(c, "v1").successRate, v2 = r(c, variant).successRate;
    if (v2 - v1 < K.k4Improve) k4.push(`${id}: V1 ${v1.toFixed(3)} -> ${v2.toFixed(3)}`);
  }
  for (const id of ["D5-attest/issuer-down-all-no-attacker-demand-1.9", "D5-attest/issuer-down-all-no-attacker-demand-3", "D5-attest/issuer-down-all-rate-4"]) {
    const c = cell(id), v1 = r(c, "v1").successRate, v2 = r(c, variant).successRate;
    if (v2 < v1 - K.worseTolerance) k6.push(`${id}: V1 ${v1.toFixed(3)} -> ${v2.toFixed(3)}`);
  }
  const res = (failing: string[]): CriterionResult => ({ pass: failing.length === 0, failing });
  return { variant, k1: res(k1), k2: res(k2), k3: res(k3), k4: res(k4), k6: res(k6) };
}
