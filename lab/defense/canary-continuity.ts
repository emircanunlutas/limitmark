/**
 * BA0 canary continuity DIAGNOSTICS (schema ba0-canary-continuity-v1). Informational only; observation only.
 *
 * Derived EXCLUSIVELY from the legitimate-user journey results the field runner already holds (`JourneyResult[]`, byte-pinned `canary.ts` shape).
 * It generates no request, reads no clock, touches no socket and no defense event, and runs only after the server-side decision is made. Its result is
 * written as a sibling artifact (`canary-continuity.json`) and is never read by any gate, identity, verdict, threshold or the Defense Plane:
 * `influencesVerdict` is the literal `false`. If it should ever disqualify a run, that is a separate, preregistered qualification-policy revision.
 *
 * Integrity rules (each pinned by tests/lab-ba0-canary-continuity.test.ts):
 *   - A journey stops at its first failing step, so later steps are `notAttempted` — never `failed`, never `ok`.
 *   - Success is recomputed from the step records (five steps, all ok); a journey flagged `completed` that the steps do not support is counted in
 *     `completionMismatch` and is NOT counted as completed.
 *   - A latency that is not a finite non-negative number is a MISSING sample (`missingLatency`); percentiles over zero samples are `null`, never 0.
 *   - A record that does not have exactly the expected shape is REJECTED whole (counted by a closed reason), never partially trusted.
 *   - Journeys a STOP interrupted (protected lane) are counted separately and excluded from the step statistics, exactly as the existing rates exclude them.
 *   - Failure categories are a closed vocabulary; request identity is never inferred (no nonce, ordinal join, token, body, header or address is read or kept).
 */
import { percentile } from "../policy/thresholds";
import type { JourneyResult, StepRecord } from "./canary";

export const CANARY_CONTINUITY_SCHEMA = "ba0-canary-continuity-v1" as const;

export const CONTINUITY_PHASES = ["baseline", "window", "residual", "recovery"] as const;
export const CONTINUITY_LANES = ["protected", "control"] as const;
export const CONTINUITY_STEPS = ["homepage", "privacy", "form", "valid_post", "thank_you"] as const;
/**
 * Closed failure vocabulary. `anti_forgery_missing` is the form's submission-token field absent from the form page (`form_token_missing`); the artifact avoids the
 * word token in keys because the evidence scanner reserves it.
 */
export const FAILURE_CATEGORIES = [
  "status_429", "status_4xx_other", "status_5xx", "status_other", "timeout", "reset", "client_error", "content_mismatch", "anti_forgery_missing", "unrecognized",
] as const;
export const REJECT_REASONS = ["shape", "identity", "step_sequence", "outcome", "status", "duplicate"] as const;

export type FailureCategory = (typeof FAILURE_CATEGORIES)[number];
export type RejectReason = (typeof REJECT_REASONS)[number];
type Phase = (typeof CONTINUITY_PHASES)[number];
type Lane = (typeof CONTINUITY_LANES)[number];

export const CANARY_CONTINUITY_LIMITS = Object.freeze({
  /** 4 phases x 2 lanes. */
  rows: CONTINUITY_PHASES.length * CONTINUITY_LANES.length,
  /** Rows x 5 steps. The artifact has a FIXED shape: its size does not grow with the number of journeys, only with the digits of its counters. */
  stepRows: CONTINUITY_PHASES.length * CONTINUITY_LANES.length * CONTINUITY_STEPS.length,
  /** Hard ceiling of the serialized artifact (pretty-printed JSON, as written). A larger result is replaced by a `failed` artifact. */
  maxSerializedBytes: 64 * 1024,
  /** Journeys the aggregation will read; more are counted in `rejected` as `shape` and not read. Far above any reviewed level (about 64 journeys). */
  maxJourneys: 4096,
});

export type LatencyDigest = { samples: number; p50: number | null; p95: number | null; p99: number | null; max: number | null };
export type StepDigest = {
  step: number; name: (typeof CONTINUITY_STEPS)[number];
  attempted: number; ok: number; failed: number; notAttempted: number; missingLatency: number;
  /** Every attempted step with a usable latency (failed steps included: a timeout is a latency the user felt). */
  latencyMs: LatencyDigest;
  /** Only steps that succeeded. */
  okLatencyMs: LatencyDigest;
  failures: Record<FailureCategory, number>;
};
export type ContinuityRow = {
  phase: Phase; lane: Lane;
  /** Valid, uninterrupted journeys aggregated into this row. 0 means the phase did not run for this lane: unknown, not success. */
  journeys: number; interrupted: number; completed: number; incomplete: number;
  /** For each step 1..5, how many journeys had it as their FIRST failing step. */
  firstFailureByStep: [number, number, number, number, number];
  /** Journeys that ended without a completed flag and without any failing step on record (cause unobservable). */
  unexplainedIncomplete: number;
  /** Journeys whose `completed` flag disagrees with their own step records. */
  completionMismatch: number;
  steps: StepDigest[];
};
export type ContinuityOk = {
  schema: typeof CANARY_CONTINUITY_SCHEMA; status: "ok"; influencesVerdict: false;
  provenance: typeof PROVENANCE;
  steps: typeof CONTINUITY_STEPS;
  limits: { rows: number; stepRows: number; maxSerializedBytes: number };
  input: { journeysSupplied: number; accepted: number; rejected: number; rejectedByReason: Record<RejectReason, number> };
  rows: ContinuityRow[];
  totals: Record<Lane, Record<FailureCategory, number>>;
  recovery: { timeToRecovery: "UNAVAILABLE"; reason: string };
  challenge: { observed: "UNAVAILABLE"; reason: string };
};
export type ContinuityFailed = { schema: typeof CANARY_CONTINUITY_SCHEMA; status: "failed"; influencesVerdict: false; failure: "aggregation_error" | "size_limit"; provenance: typeof PROVENANCE };
export type CanaryContinuity = ContinuityOk | ContinuityFailed;

const PROVENANCE = Object.freeze({
  source: "the legitimate-user journey results the field runner already collected; no request was generated for this artifact",
  clock: "client monotonic latency per step, as recorded by the existing canary",
  percentile: "nearest rank, ceil(p/100 x n), over the sorted samples; values rounded to two decimals; null when there are no samples",
  missing: "a step that was not attempted is notAttempted; a missing or invalid latency is missingLatency; neither is counted as ok or as failed",
  verdict: "informational only: no gate, identity or verdict reads this artifact",
});

const RECOVERY_REASON = "journey results carry no timestamps, so a time to recovery cannot be derived; read the recovery phase rows instead";
const CHALLENGE_REASON = "neither the canary nor the lab origin defines a challenge response; a challenge would only appear as an unexpected status or a content mismatch";

const zeroFailures = (): Record<FailureCategory, number> => Object.fromEntries(FAILURE_CATEGORIES.map((category) => [category, 0])) as Record<FailureCategory, number>;
/**
 * Largest latency (ms) the artifact carries: about 11.6 days, far above any client timeout. A finite sample above it is a MISSING sample, so rounding
 * can never overflow to Infinity (which JSON writes as null) and no percentile is ever invented from an absurd value.
 */
export const MAX_LATENCY_MS = 1e9;
const round2 = (value: number): number => Math.round(value * 100) / 100;

function digest(values: readonly number[]): LatencyDigest {
  if (values.length === 0) return { samples: 0, p50: null, p95: null, p99: null, max: null };
  const sorted = [...values].sort((a, b) => a - b);
  return { samples: sorted.length, p50: round2(percentile(sorted, 50)), p95: round2(percentile(sorted, 95)), p99: round2(percentile(sorted, 99)), max: round2(sorted[sorted.length - 1]) };
}

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const hasExactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean => { const own = Object.keys(value); return own.length === keys.length && keys.every((key) => own.includes(key)); };
const isUsableLatency = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= MAX_LATENCY_MS;

/** Maps a recorded failure string to a closed category, or null when the string is not one the canary can produce. */
export function classifyFailure(failure: string): { category: FailureCategory; status: number | null } {
  const statusMatch = /^status_(\d{3})$/.exec(failure);
  if (statusMatch) {
    const status = Number(statusMatch[1]);
    if (status === 429) return { category: "status_429", status };
    if (status >= 400 && status < 500) return { category: "status_4xx_other", status };
    if (status >= 500 && status < 600) return { category: "status_5xx", status };
    return { category: "status_other", status };
  }
  if (failure === "client_timeout") return { category: "timeout", status: null };
  if (failure === "client_reset") return { category: "reset", status: null };
  if (failure === "client_error") return { category: "client_error", status: null };
  if (failure === "form_token_missing") return { category: "anti_forgery_missing", status: null };
  if (["homepage_content", "privacy_content", "post_not_redirect", "post_not_json", "thank_you_content"].includes(failure)) return { category: "content_mismatch", status: null };
  return { category: "unrecognized", status: null };
}

/** The only step on which `runJourney` emits each content / anti-forgery failure (and only after an HTTP 200, because the content check runs only then). */
const CONTENT_FAILURE_STEP: Readonly<Record<string, number>> = Object.freeze({
  homepage_content: 1, privacy_content: 2, form_token_missing: 3, post_not_redirect: 4, post_not_json: 4, thank_you_content: 5,
});

/**
 * True when (failure, status, step) is a combination the real `runJourney` + `trackedHttp` can produce:
 *   - `client_*`: no completed response, so the status is null;
 *   - `status_NNN`: the status check runs first and only for NNN != 200, and the step records that same status;
 *   - content / anti-forgery failures: only after an HTTP 200, and only on their own step;
 *   - an unrecognized code is not special-cased: it keeps any in-range status or null (already validated), and is counted as `unrecognized`.
 */
function failureAgrees(failure: string, status: unknown, stepNumber: number): boolean {
  const classified = classifyFailure(failure);
  switch (classified.category) {
    case "status_429": case "status_4xx_other": case "status_5xx": case "status_other": return classified.status !== 200 && status === classified.status;
    case "timeout": case "reset": case "client_error": return status === null;
    case "content_mismatch": case "anti_forgery_missing": return status === 200 && CONTENT_FAILURE_STEP[failure] === stepNumber;
    default: return true;
  }
}

type Checked = { journey: { lane: Lane; phase: Phase; id: number; completed: boolean; steps: StepRecord[] }; error: null } | { journey: null; error: RejectReason };

function check(value: unknown): Checked {
  const bad = (error: RejectReason): Checked => ({ journey: null, error });
  if (!isObject(value) || !hasExactKeys(value, ["lane", "phase", "journey", "completed", "steps"])) return bad("shape");
  const { lane, phase, journey, completed, steps } = value;
  if (!(CONTINUITY_LANES as readonly unknown[]).includes(lane) || !(CONTINUITY_PHASES as readonly unknown[]).includes(phase) || !Number.isSafeInteger(journey) || (journey as number) < 1) return bad("identity");
  if (typeof completed !== "boolean" || !Array.isArray(steps)) return bad("shape");
  if (steps.length > CONTINUITY_STEPS.length) return bad("step_sequence");
  for (let index = 0; index < steps.length; index++) {
    const step = steps[index] as unknown;
    if (!isObject(step)) return bad("shape");
    if (step.step !== index + 1 || step.name !== CONTINUITY_STEPS[index]) return bad("step_sequence");
    if (typeof step.ok !== "boolean" || (step.failure !== null && typeof step.failure !== "string")) return bad("shape");
    if ((step.ok && step.failure !== null) || (!step.ok && step.failure === null)) return bad("outcome");
    if (step.status !== null && !(typeof step.status === "number" && Number.isInteger(step.status) && step.status >= 100 && step.status <= 599)) return bad("status");
    if (step.ok && step.status !== 200) return bad("status");
    if (!step.ok && typeof step.failure === "string") {
      // The failure must agree with the status the step itself recorded; the status is never taken from anything else.
      if (!failureAgrees(step.failure, step.status, index + 1)) return bad("status");
    }
    // Only a step that ran can be followed by another: a failed step ends the journey.
    if (!step.ok && index !== steps.length - 1) return bad("step_sequence");
  }
  return { journey: { lane: lane as Lane, phase: phase as Phase, id: journey as number, completed, steps: steps as StepRecord[] }, error: null };
}

/**
 * Builds the artifact. `interrupted` holds `${phase}/${journey}` keys of PROTECTED journeys a STOP cut short (the runner's own set). Pure; throws only
 * on an internal error, which `buildCanaryContinuity` converts into a recorded failure.
 */
export function aggregateCanaryContinuity(journeys: readonly unknown[], interrupted: ReadonlySet<string>): ContinuityOk {
  type Accumulator = {
    row: ContinuityRow; latencies: number[][]; okLatencies: number[][];
  };
  const accumulators = new Map<string, Accumulator>();
  for (const phase of CONTINUITY_PHASES) {
    for (const lane of CONTINUITY_LANES) {
      accumulators.set(`${phase}/${lane}`, {
        row: {
          phase, lane, journeys: 0, interrupted: 0, completed: 0, incomplete: 0, firstFailureByStep: [0, 0, 0, 0, 0], unexplainedIncomplete: 0, completionMismatch: 0,
          steps: CONTINUITY_STEPS.map((name, index) => ({
            step: index + 1, name, attempted: 0, ok: 0, failed: 0, notAttempted: 0, missingLatency: 0,
            latencyMs: digest([]), okLatencyMs: digest([]), failures: zeroFailures(),
          })),
        },
        latencies: CONTINUITY_STEPS.map(() => []), okLatencies: CONTINUITY_STEPS.map(() => []),
      });
    }
  }
  const rejectedByReason = Object.fromEntries(REJECT_REASONS.map((reason) => [reason, 0])) as Record<RejectReason, number>;
  const totals: Record<Lane, Record<FailureCategory, number>> = { protected: zeroFailures(), control: zeroFailures() };
  let accepted = 0; let rejected = 0;
  /** Bounded by maxJourneys short keys. */
  const seen = new Set<string>();

  const read = Math.min(journeys.length, CANARY_CONTINUITY_LIMITS.maxJourneys);
  for (let index = read; index < journeys.length; index++) { rejected++; rejectedByReason.shape++; }
  for (let index = 0; index < read; index++) {
    const checked = check(journeys[index]);
    if (checked.journey === null) { rejected++; rejectedByReason[checked.error]++; continue; }
    const { lane, phase, steps, completed, id } = checked.journey;
    // One observation per (phase, lane, journey): a repeat is rejected whole and never counted twice.
    const identity = `${phase}/${lane}/${id}`;
    if (seen.has(identity)) { rejected++; rejectedByReason.duplicate++; continue; }
    seen.add(identity);
    const accumulator = accumulators.get(`${phase}/${lane}`)!;
    accepted++;
    if (lane === "protected" && interrupted.has(`${phase}/${id}`)) { accumulator.row.interrupted++; continue; }
    const row = accumulator.row;
    row.journeys++;
    const supported = steps.length === CONTINUITY_STEPS.length && steps.every((step) => step.ok);
    if (supported) row.completed++; else row.incomplete++;
    if (completed !== supported) row.completionMismatch++;
    const firstFailure = steps.findIndex((step) => !step.ok);
    if (firstFailure >= 0) row.firstFailureByStep[firstFailure]++;
    else if (!supported) row.unexplainedIncomplete++;
    for (let position = 0; position < CONTINUITY_STEPS.length; position++) {
      const digestRow = row.steps[position];
      const step = steps[position];
      if (step === undefined) { digestRow.notAttempted++; continue; }
      digestRow.attempted++;
      if (step.ok) digestRow.ok++; else {
        digestRow.failed++;
        const { category } = classifyFailure(step.failure as string);
        digestRow.failures[category]++; totals[lane][category]++;
      }
      if (isUsableLatency(step.latencyMs)) { accumulator.latencies[position].push(step.latencyMs); if (step.ok) accumulator.okLatencies[position].push(step.latencyMs); } else digestRow.missingLatency++;
    }
  }
  const rows: ContinuityRow[] = [];
  for (const accumulator of accumulators.values()) {
    accumulator.row.steps.forEach((step, position) => { step.latencyMs = digest(accumulator.latencies[position]); step.okLatencyMs = digest(accumulator.okLatencies[position]); });
    rows.push(accumulator.row);
  }
  return {
    schema: CANARY_CONTINUITY_SCHEMA, status: "ok", influencesVerdict: false, provenance: PROVENANCE, steps: CONTINUITY_STEPS,
    limits: { rows: CANARY_CONTINUITY_LIMITS.rows, stepRows: CANARY_CONTINUITY_LIMITS.stepRows, maxSerializedBytes: CANARY_CONTINUITY_LIMITS.maxSerializedBytes },
    input: { journeysSupplied: journeys.length, accepted, rejected, rejectedByReason }, rows, totals,
    recovery: { timeToRecovery: "UNAVAILABLE", reason: RECOVERY_REASON }, challenge: { observed: "UNAVAILABLE", reason: CHALLENGE_REASON },
  };
}

/** The serialized size as the evidence writer will produce it (pretty-printed, trailing newline). */
export const serializedBytes = (value: unknown): number => Buffer.byteLength(`${JSON.stringify(value, null, 2)}\n`);

/**
 * Never throws. An internal error or an oversized result becomes a small `failed` artifact; the caller's verdict is unaffected either way.
 * `aggregate` is injectable only so a test can prove the failure path.
 */
export function buildCanaryContinuity(journeys: readonly JourneyResult[] | readonly unknown[], interrupted: ReadonlySet<string>, aggregate: typeof aggregateCanaryContinuity = aggregateCanaryContinuity): CanaryContinuity {
  const failed = (failure: ContinuityFailed["failure"]): ContinuityFailed => ({ schema: CANARY_CONTINUITY_SCHEMA, status: "failed", influencesVerdict: false, failure, provenance: PROVENANCE });
  try {
    const built = aggregate(journeys, interrupted);
    return serializedBytes(built) > CANARY_CONTINUITY_LIMITS.maxSerializedBytes ? failed("size_limit") : built;
  } catch { return failed("aggregation_error"); }
}
