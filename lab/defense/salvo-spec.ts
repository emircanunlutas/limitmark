/** Reviewed arrival waveform and observation rules. These never enter defense enforcement. */
import { summarizeLatencies } from "../policy/thresholds";
export const SALVO_SPEC = Object.freeze({
  pairs: 750, requestsPerPair: 2, periodMs: 80, durationMs: 60_000, binMs: 1_000, bins: 60,
  dispatchLatenessExclusiveMs: 40, materialSeparationMs: 0.5, materialRatio: 0.75,
  jointMaterialPairs: 743, missingPerPlannedBin: 1, materialStartsPerActualBin: 11,
  maxElapsedMs: 64_000,
  rateInterpretation: "25 per second campaign average; burst two; nominal one-second bins alternate 26 and 24",
});

export type SalvoPair = { index: number; startsMs: [number | null, number | null]; settledMs: [number | null, number | null] };
export const plannedPairBin = (index: number): number => Math.floor(index * SALVO_SPEC.periodMs / SALVO_SPEC.binMs);
export const plannedPairCounts = (): number[] => {
  const counts = Array<number>(SALVO_SPEC.bins).fill(0);
  for (let index = 0; index < SALVO_SPEC.pairs; index++) counts[plannedPairBin(index)]++;
  return counts;
};

export type PairDerivation = {
  valid: boolean; scheduleValid: boolean; materialIndices: number[]; plannedMaterial: number[];
  actualMaterial: number[]; opportunityMs: number[]; overlapMs: number[];
  firstMs: number | null; lastMs: number | null; settlementMs: number | null; maxInFlight: number;
};

/** Strict bounded records are the sole source of all exposure summaries. No aggregate claim is consulted. */
export function derivePairs(value: unknown, generator: boolean): PairDerivation {
  const result: PairDerivation = { valid: false, scheduleValid: false, materialIndices: [],
    plannedMaterial: Array<number>(60).fill(0), actualMaterial: Array<number>(60).fill(0),
    opportunityMs: Array<number>(60).fill(0), overlapMs: Array<number>(60).fill(0),
    firstMs: null, lastMs: null, settlementMs: null, maxInFlight: 0 };
  if (!Array.isArray(value) || value.length !== SALVO_SPEC.pairs) return result;
  let previousEnd = 0;
  let scheduleValid = true;
  for (let i = 0; i < value.length; i++) {
    const row = value[i] as Partial<SalvoPair> | null;
    if (!row || typeof row !== "object" || Object.keys(row).length !== 3 || row.index !== i
      || !Array.isArray(row.startsMs) || !Array.isArray(row.settledMs) || row.startsMs.length !== 2 || row.settledMs.length !== 2) return result;
    const [a, b] = row.startsMs; const [ea, eb] = row.settledMs;
    const finiteTime = (n: unknown): n is number => typeof n === "number" && Number.isFinite(n) && n >= 0 && n <= SALVO_SPEC.maxElapsedMs;
    if (!finiteTime(a) || !finiteTime(b) || !finiteTime(ea) || !finiteTime(eb) || ea <= a || eb <= b) return result;
    const first = Math.min(a, b); const last = Math.max(a, b); const end = Math.max(ea, eb);
    if (first < previousEnd || (i === 0 && !generator && first !== 0)) return result;
    previousEnd = end;
    if (i === 0) result.firstMs = first;
    result.lastMs = last; result.settlementMs = end;
    const slot = i * SALVO_SPEC.periodMs;
    if (generator && (first < slot || last >= slot + SALVO_SPEC.dispatchLatenessExclusiveMs || last >= SALVO_SPEC.durationMs
      || (i + 1 < SALVO_SPEC.pairs && end > (i + 1) * SALVO_SPEC.periodMs))) scheduleValid = false;
    const p = Math.min(ea - a, eb - b);
    const o = Math.max(0, Math.min(ea, eb) - last);
    result.maxInFlight = Math.max(result.maxInFlight, o > 0 ? 2 : 1);
    const bin = plannedPairBin(i);
    result.opportunityMs[bin] += p; result.overlapMs[bin] += o;
    // Cross multiplication avoids division at the qualification boundary. No upward rounding.
    if (p > 0 && o > 0 && o >= SALVO_SPEC.materialRatio * p
      && (!generator || Math.abs(a - b) <= SALVO_SPEC.materialSeparationMs)) {
      result.materialIndices.push(i); result.plannedMaterial[bin]++;
      const actualBin = Math.floor(last / SALVO_SPEC.binMs);
      if (actualBin >= 0 && actualBin < SALVO_SPEC.bins) result.actualMaterial[actualBin]++;
    }
  }
  result.valid = true; result.scheduleValid = scheduleValid;
  return result;
}

export function sourceExercised(d: PairDerivation): boolean {
  const expected = plannedPairCounts();
  return d.valid && d.materialIndices.length >= SALVO_SPEC.jointMaterialPairs
    && d.plannedMaterial.every((n, i) => n >= expected[i] - SALVO_SPEC.missingPerPlannedBin)
    && d.actualMaterial.every((n) => n >= SALVO_SPEC.materialStartsPerActualBin)
    && d.opportunityMs.every((p, i) => p > 0 && d.overlapMs[i] >= SALVO_SPEC.materialRatio * p);
}

export function pairFixtureLatencies(pairs: readonly SalvoPair[]) {
  const ids = ["get_home", "get_privacy", "get_form", "post_inquiry"];
  const samples = ids.map(() => [] as number[]);
  for (const pair of pairs) for (const slot of [0, 1] as const) {
    const start = pair.startsMs[slot]; const end = pair.settledMs[slot];
    if (start !== null && end !== null) samples[(pair.index % 2) * 2 + slot].push(end - start);
  }
  return Object.fromEntries(ids.map((id, i) => [id, summarizeLatencies(samples[i])]));
}

export function pairSummaries(pairs: readonly SalvoPair[]) {
  const lifetimes: number[] = []; const lags: number[] = [];
  for (const pair of pairs) for (const slot of [0, 1] as const) {
    const start = pair.startsMs[slot]; const end = pair.settledMs[slot];
    if (start !== null) lags.push(start - pair.index * SALVO_SPEC.periodMs);
    if (start !== null && end !== null) lifetimes.push(end - start);
  }
  return { latencyMs: summarizeLatencies(lifetimes), lagMs: summarizeLatencies(lags) };
}
