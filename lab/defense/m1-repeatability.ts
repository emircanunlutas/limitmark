/**
 * M1 criterion 7 (owner decision, 2026-11-08): three independent runs, fresh state, the same commit, parameters and fixture cycle, all with a base verdict
 * of VALID, identical shed-reason sets and per-run shed shares within +/-5 percentage points of the median.
 *
 * A pure, read-only evaluator over per-run facts that the CLI (ba0-m1-repeatability.ts) extracts from finalized evidence. It adds no verdict category,
 * changes no historical verdict and never accepts evidence it cannot read: anything missing, malformed or ambiguous is ERROR (evaluated = false).
 *
 * What "independent runs on fresh state" means HERE (the only parts evidence can prove; the rest is an operator attestation and is reported as such):
 *   - three DIFFERENT level executions: distinct server evidence run ids, distinct campaign ids, distinct generator run ids;
 *   - strictly sequential, non-overlapping windows (each run closed before the next opened), so no run shared a window with, or ran inside, another;
 *   - each execution started its own processes (a level runner always spawns a fresh Defense Plane, Boundary and App; nothing persists between levels).
 * NOT provable from evidence, and therefore never claimed: a freshly provisioned machine, an empty page cache, or the absence of state outside the processes.
 *
 * Shed share = 100 x (client-visible 503 sheds the server attributed) / (requests the server accepted from the remote generator), per run.
 */
import { BASE_VERDICT_VALID } from "./m1-status-contract";

export const M1_REPEATABILITY_RUNS = 3;
export const M1_SHED_SHARE_TOLERANCE_POINTS = 5;

export type RepeatabilityRun = {
  serverRunId: string;
  generatorRunId: string;
  campaignId: string;
  levelId: string;
  gitSha: string;
  paramsFingerprintSha256: string;
  workloadFingerprintSha256: string;
  workers: number;
  windowOpenedAt: string;
  windowClosedAt: string;
  baseVerdict: string;
  /** Shed reasons with a non-zero count in this run, keyed `class.lane.reason`. */
  shedReasonCounts: Record<string, number>;
  externalAccepted: number;
  status503Total: number;
};

export type RepeatabilityResult = {
  evaluated: boolean;
  outcome: "PASS" | "REJECT" | "ERROR";
  reasons: string[];
  details: { medianShedSharePct: number | null; runs: { runId: string; shedSharePct: number | null; deviationPoints: number | null }[]; shedReasonSets: string[][] } | null;
};

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const str = (value: unknown, pattern: RegExp): value is string => typeof value === "string" && pattern.test(value);
const ID = /^[A-Za-z0-9._-]{1,120}$/u;
const SHA40 = /^[0-9a-f]{40}$/u;
const SHA64 = /^[0-9a-f]{64}$/u;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u;
const REASON_KEY = /^[a-z0-9_]{1,24}\.[a-z0-9_]{1,24}\.[a-z0-9_]{1,40}$/u;

function readRun(value: unknown): RepeatabilityRun | null {
  if (!isRecord(value)) return null;
  const v = value;
  if (!str(v.serverRunId, ID) || !str(v.generatorRunId, ID) || !str(v.campaignId, ID) || !str(v.levelId, ID) || !str(v.gitSha, SHA40) || !str(v.paramsFingerprintSha256, SHA64) ||
      !str(v.workloadFingerprintSha256, SHA64) || !isCount(v.workers) || v.workers < 1 || !str(v.windowOpenedAt, ISO) || !str(v.windowClosedAt, ISO) || typeof v.baseVerdict !== "string" ||
      !isCount(v.externalAccepted) || !isCount(v.status503Total) || !isRecord(v.shedReasonCounts)) return null;
  const counts: Record<string, number> = Object.create(null);
  for (const [key, count] of Object.entries(v.shedReasonCounts)) { if (!REASON_KEY.test(key) || !isCount(count)) return null; if (count > 0) counts[key] = count; }
  const opened = Date.parse(v.windowOpenedAt); const closed = Date.parse(v.windowClosedAt);
  if (!Number.isFinite(opened) || !Number.isFinite(closed) || closed < opened) return null;
  return { serverRunId: v.serverRunId, generatorRunId: v.generatorRunId, campaignId: v.campaignId, levelId: v.levelId, gitSha: v.gitSha, paramsFingerprintSha256: v.paramsFingerprintSha256,
    workloadFingerprintSha256: v.workloadFingerprintSha256, workers: v.workers, windowOpenedAt: v.windowOpenedAt, windowClosedAt: v.windowClosedAt, baseVerdict: v.baseVerdict,
    shedReasonCounts: counts, externalAccepted: v.externalAccepted, status503Total: v.status503Total };
}

const distinct = (values: readonly string[]): boolean => new Set(values).size === values.length;
const same = (values: readonly (string | number)[]): boolean => new Set(values).size === 1;
const median = (values: readonly number[]): number => { const sorted = [...values].sort((a, b) => a - b); return sorted[Math.floor(sorted.length / 2)]; };

/** Never throws. Not exactly three well-formed runs => ERROR. */
export function evaluateRepeatability(input: unknown): RepeatabilityResult {
  try {
    if (!Array.isArray(input) || input.length !== M1_REPEATABILITY_RUNS) return { evaluated: false, outcome: "ERROR", reasons: ["m1.repeat.evidence_not_three_runs"], details: null };
    const runs = input.map(readRun);
    if (runs.some((run) => run === null)) return { evaluated: false, outcome: "ERROR", reasons: ["m1.repeat.evidence_malformed_run"], details: null };
    const list = runs as RepeatabilityRun[];
    const reasons: string[] = [];

    if (!distinct(list.map((run) => run.serverRunId))) reasons.push("m1.repeat.server_run_ids_not_distinct");
    if (!distinct(list.map((run) => run.campaignId))) reasons.push("m1.repeat.campaign_ids_not_distinct");
    if (!distinct(list.map((run) => run.generatorRunId))) reasons.push("m1.repeat.generator_run_ids_not_distinct");
    const ordered = [...list].sort((a, b) => Date.parse(a.windowOpenedAt) - Date.parse(b.windowOpenedAt));
    for (let index = 1; index < ordered.length; index++) if (!(Date.parse(ordered[index - 1].windowClosedAt) < Date.parse(ordered[index].windowOpenedAt))) { reasons.push("m1.repeat.windows_overlap"); break; }

    if (!same(list.map((run) => run.gitSha))) reasons.push("m1.repeat.commit_differs");
    if (!same(list.map((run) => run.paramsFingerprintSha256))) reasons.push("m1.repeat.parameters_differ");
    if (!same(list.map((run) => run.workloadFingerprintSha256))) reasons.push("m1.repeat.fixture_cycle_differs");
    if (!same(list.map((run) => run.levelId))) reasons.push("m1.repeat.level_differs");
    if (!same(list.map((run) => run.workers))) reasons.push("m1.repeat.workers_differ");
    if (list.some((run) => run.baseVerdict !== BASE_VERDICT_VALID)) reasons.push("m1.repeat.base_verdict_not_valid");

    const sets = list.map((run) => Object.keys(run.shedReasonCounts).sort());
    if (new Set(sets.map((set) => set.join("|"))).size !== 1) reasons.push("m1.repeat.shed_reason_sets_differ");

    if (list.some((run) => run.externalAccepted === 0)) return { evaluated: false, outcome: "ERROR", reasons: ["m1.repeat.evidence_no_accepted_requests"], details: null };
    const shares = list.map((run) => 100 * run.status503Total / run.externalAccepted);
    const mid = median(shares);
    const deviations = shares.map((share) => Math.abs(share - mid));
    if (deviations.some((deviation) => deviation > M1_SHED_SHARE_TOLERANCE_POINTS)) reasons.push("m1.repeat.shed_share_outside_tolerance");

    const details = { medianShedSharePct: mid, runs: list.map((run, index) => ({ runId: run.serverRunId, shedSharePct: shares[index], deviationPoints: deviations[index] })), shedReasonSets: sets };
    return reasons.length === 0 ? { evaluated: true, outcome: "PASS", reasons: [], details } : { evaluated: true, outcome: "REJECT", reasons, details };
  } catch {
    return { evaluated: false, outcome: "ERROR", reasons: ["m1.repeat.evaluation_failed"], details: null };
  }
}

/** The invariants of the result: PASS => evaluated and empty reasons; REJECT => evaluated and reasons; ERROR => not evaluated and reasons. */
export function repeatabilityWellFormed(result: RepeatabilityResult): boolean {
  if (result.outcome === "PASS") return result.evaluated && result.reasons.length === 0 && result.details !== null;
  if (result.outcome === "REJECT") return result.evaluated && result.reasons.length > 0 && result.details !== null;
  if (result.outcome === "ERROR") return !result.evaluated && result.reasons.length > 0;
  return false;
}
