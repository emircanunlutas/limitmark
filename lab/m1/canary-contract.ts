/**
 * Legitimate-user (canary) acceptance contract for the first authorized remote M1 campaign. Pure; never throws. Local and additive: it changes no verdict, parameter or
 * pinned file, and it never makes a run QUALIFIED.
 *
 * Contract: EVERY journey of EVERY phase (baseline, window, recovery) completes EVERY required step successfully (initial target: 100 percent). Any unexpected 429, challenge,
 * timeout, transport failure, HTTP error status or false rejection is a failure. Latency is MEASURED and reported per phase (baseline and attack window separately) but no
 * numerical latency threshold is set here: setting one is an owner decision that needs the measurements listed in LATENCY_MEASUREMENTS_REQUIRED. The pinned BA0_FIELD_V1
 * window latency rule is evaluated elsewhere (lab/m1/observation-check.ts) and is not changed by this contract.
 *
 * "Operational actions" are the supported actions beyond the browse-and-submit path. None is implemented by the local fixture, so the owner must name them; until then the
 * contract reports them as an open item and the outcome can be at most INCOMPLETE.
 */
export const CANARY_CONTRACT = "m1-canary-contract-v1";
export const BROWSE_AND_SUBMIT_STEPS = ["home", "asset", "faq", "form", "submit", "thanks"] as const;
export const PHASES = ["baseline", "window", "recovery"] as const;
export const LATENCY_MEASUREMENTS_REQUIRED = [
  "baseline p50, p95 and p99 per journey step on the target with no load, from at least the number of journeys the owner fixes, on three separate fresh instances",
  "run-to-run spread of the baseline percentiles (to size the allowed degradation above the noise)",
  "attack-window p50, p95 and p99 of the same steps from a rehearsal that is not qualification evidence",
  "canary-to-target network round trip with no application work (to remove the path from the budget)",
  "recovery-phase percentiles after the load stops, and the time until they return to the baseline spread",
  "canary scheduling lag and clock source error (the measurement floor)",
] as const;

export type CanaryStep = { phase: string; journey: number; step: string; status: number | null; ok: boolean; timedOut: boolean; failed: boolean; challenged: boolean; latencyMs: number };
export type CanaryContractInput = { steps: unknown; requiredSteps?: readonly string[]; operationalActions: readonly string[] };
export type PhaseLatency = { observations: number; p50: number | null; p95: number | null; p99: number | null };
export type CanaryContractResult = {
  contract: typeof CANARY_CONTRACT; outcome: "PASS" | "REJECT" | "INCOMPLETE" | "ERROR"; reasons: string[];
  journeys: Record<string, { total: number; succeeded: number }>;
  failures: { unexpected429: number; challenges: number; timeouts: number; transportFailures: number; httpErrors: number; falseRejects: number; missingSteps: number };
  latency: Record<string, PhaseLatency>; latencyThresholds: "UNSET_OWNER_DECISION"; openItems: string[]; qualification: "UNREACHABLE";
};

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const percentile = (values: number[], p: number): number | null => { if (values.length === 0) return null; const sorted = [...values].sort((a, b) => a - b); return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]!; };
const readStep = (value: unknown): CanaryStep | null => {
  if (!isRecord(value)) return null;
  const v = value;
  if (typeof v.phase !== "string" || !Number.isSafeInteger(v.journey) || typeof v.step !== "string" || !(v.status === null || Number.isSafeInteger(v.status)) || typeof v.ok !== "boolean" ||
      typeof v.timedOut !== "boolean" || typeof v.failed !== "boolean" || typeof v.challenged !== "boolean" || typeof v.latencyMs !== "number" || !Number.isFinite(v.latencyMs) || v.latencyMs < 0) return null;
  return v as unknown as CanaryStep;
};

export function evaluateCanaryContract(input: CanaryContractInput): CanaryContractResult {
  const empty = (outcome: CanaryContractResult["outcome"], reasons: string[], openItems: string[] = []): CanaryContractResult => ({ contract: CANARY_CONTRACT, outcome, reasons: [...new Set(reasons)],
    journeys: {}, failures: { unexpected429: 0, challenges: 0, timeouts: 0, transportFailures: 0, httpErrors: 0, falseRejects: 0, missingSteps: 0 }, latency: {}, latencyThresholds: "UNSET_OWNER_DECISION", openItems, qualification: "UNREACHABLE" });
  try {
    if (!Array.isArray(input.steps)) return empty("ERROR", ["m1.canary.steps_missing"]);
    const parsed = input.steps.map(readStep);
    if (parsed.some((step) => step === null)) return empty("ERROR", ["m1.canary.steps_malformed"]);
    const steps = parsed as CanaryStep[];
    const required = input.requiredSteps ?? BROWSE_AND_SUBMIT_STEPS;
    const reasons: string[] = []; const openItems: string[] = [];
    if (steps.some((step) => !(PHASES as readonly string[]).includes(step.phase))) reasons.push("m1.canary.unknown_phase");
    if (input.operationalActions.length === 0) openItems.push("m1.canary.operational_actions_unspecified");
    const requiredAll = [...required, ...input.operationalActions];

    const journeys: CanaryContractResult["journeys"] = {};
    const failures = { unexpected429: 0, challenges: 0, timeouts: 0, transportFailures: 0, httpErrors: 0, falseRejects: 0, missingSteps: 0 };
    for (const phase of PHASES) {
      const inPhase = steps.filter((step) => step.phase === phase);
      const ids = [...new Set(inPhase.map((step) => step.journey))];
      journeys[phase] = { total: ids.length, succeeded: 0 };
      if (ids.length === 0) { reasons.push(`m1.canary.${phase}_not_observed`); continue; }
      for (const id of ids) {
        const own = inPhase.filter((step) => step.journey === id);
        const names = own.map((step) => step.step);
        const missing = requiredAll.filter((name) => !names.includes(name));
        if (missing.length > 0 || new Set(names).size !== names.length) failures.missingSteps += missing.length || 1;
        if (own.every((step) => step.ok) && missing.length === 0 && new Set(names).size === names.length) journeys[phase]!.succeeded++;
      }
    }
    for (const step of steps) {
      if (step.status === 429) failures.unexpected429++;
      if (step.challenged) failures.challenges++;
      if (step.timedOut) failures.timeouts++;
      if (step.failed) failures.transportFailures++;
      if (step.status !== null && step.status >= 400) failures.httpErrors++;
      if (step.status === 403 || step.status === 429 || step.status === 503) failures.falseRejects++;
    }
    if (failures.unexpected429 > 0) reasons.push("m1.canary.unexpected_429");
    if (failures.challenges > 0) reasons.push("m1.canary.challenge_observed");
    if (failures.timeouts > 0) reasons.push("m1.canary.timeout_observed");
    if (failures.transportFailures > 0) reasons.push("m1.canary.transport_failure");
    if (failures.httpErrors > 0) reasons.push("m1.canary.http_error");
    if (failures.falseRejects > 0) reasons.push("m1.canary.false_rejection");
    if (failures.missingSteps > 0) reasons.push("m1.canary.required_step_missing");
    for (const phase of PHASES) if (journeys[phase]!.total > 0 && journeys[phase]!.succeeded < journeys[phase]!.total) reasons.push(`m1.canary.${phase}_journey_failed`);

    const latency: Record<string, PhaseLatency> = {};
    for (const phase of PHASES) {
      const values = steps.filter((step) => step.phase === phase && step.status !== null).map((step) => step.latencyMs);
      latency[phase] = { observations: values.length, p50: percentile(values, 50), p95: percentile(values, 95), p99: percentile(values, 99) };
    }
    const missingPhase = reasons.some((reason) => reason.endsWith("_not_observed"));
    const hard = reasons.filter((reason) => !reason.endsWith("_not_observed"));
    const outcome = hard.length > 0 ? "REJECT" : missingPhase || openItems.length > 0 ? "INCOMPLETE" : "PASS";
    return { contract: CANARY_CONTRACT, outcome, reasons: [...new Set(reasons)], journeys, failures, latency, latencyThresholds: "UNSET_OWNER_DECISION", openItems, qualification: "UNREACHABLE" };
  } catch { return empty("ERROR", ["m1.canary.evaluation_failed"]); }
}
