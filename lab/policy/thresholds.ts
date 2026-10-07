/**
 * Named PASS / STOP threshold sets. The runner picks exactly one, records its id,
 * version and content hash in the evidence manifest, and evaluates:
 *
 *  - STOP: checked continuously while running; the first breach aborts the run
 *    immediately (result STOP). It protects the system under test.
 *  - PASS: checked once after the run; failing any criterion is result FAIL.
 *
 * These are INITIAL values, to be calibrated after the first local baseline and the
 * first remote baseline; changing a number changes the recorded hash.
 */
import { createHash } from "node:crypto";
import type { WorkloadId } from "./workloads";

export type PhaseRuleKind =
  /** Normal phase: counts toward error-rate, latency and STOP rules. */
  | "measured"
  /** Failures are the point of the phase (client timeouts, service down). Excluded from STOP/error-rate. */
  | "expect-failures"
  /** Every request must succeed. */
  | "health";

export type HttpThresholds = {
  pass: {
    maxErrorRate: number;
    maxP95Ms: number;
    maxP99Ms: number;
    minSamples: number;
  };
  stop: {
    /** Abort when the measured error rate reaches this after `afterSamples` measured samples. */
    errorRate: number;
    afterSamples: number;
    consecutiveFailures: number;
    /** Abort when measured p99 exceeds this after `afterSamples` measured samples. */
    p99Ms: number;
  };
  /** Phase name prefix -> rule. Unlisted phases are "measured". */
  phaseRules?: Readonly<Record<string, PhaseRuleKind>>;
};

export type RecoveryThresholds = {
  /** The "down"/"outage" phase must really have been down: minimum failure rate observed. */
  minFailureRateWhileDown: number;
  /** PASS if time-to-first-healthy-after-restart is at most this. */
  maxRecoverySeconds: number;
  /** STOP (abort) if not recovered by this point. */
  stopRecoverySeconds: number;
  /** Failure must be fast and bounded: every probe during the outage finishes within this. */
  maxProbeDurationMs: number;
};

export type ThresholdSet = {
  id: string;
  version: number;
  description: string;
  /** The closed-loop BA0 level has no open-loop threshold set: the server-side evidence decides, never the generator's status counts. */
  http: Readonly<Record<Exclude<WorkloadId, "app-restart" | "postgres-outage" | "ba0-l7-pressure-c1" | "ba0-l7-pressure-c2">, HttpThresholds>>;
  recovery: Readonly<Record<"app-restart" | "postgres-outage", RecoveryThresholds>>;
};

const timeoutRules = {
  "timeout-": "expect-failures",
  "health-probe": "health",
} as const;

function httpSet(scale: {
  p95: number; p99: number; err: number; stopErr: number; stopP99: number; stopConsecutive: number; burstP95: number; burstP99: number;
}): ThresholdSet["http"] {
  const standard: HttpThresholds = {
    pass: { maxErrorRate: scale.err, maxP95Ms: scale.p95, maxP99Ms: scale.p99, minSamples: 20 },
    stop: { errorRate: scale.stopErr, afterSamples: 40, consecutiveFailures: scale.stopConsecutive, p99Ms: scale.stopP99 },
  };
  return {
    "connectivity-baseline": { ...standard, pass: { ...standard.pass, minSamples: 20 } },
    "latency-measurement": standard,
    "controlled-concurrency": { ...standard, pass: { ...standard.pass, maxP95Ms: scale.p95 * 2, maxP99Ms: scale.p99 * 2 } },
    burst: { ...standard, pass: { ...standard.pass, maxP95Ms: scale.burstP95, maxP99Ms: scale.burstP99 } },
    "sustained-soak": standard,
    "timeout-behaviour": {
      pass: { ...standard.pass, maxErrorRate: 1, minSamples: 5 },
      stop: { ...standard.stop, errorRate: 1.01, consecutiveFailures: 1_000 },
      phaseRules: timeoutRules,
    },
    "demo-submission-post": standard,
  };
}

export const THRESHOLD_SETS: Readonly<Record<string, ThresholdSet>> = Object.freeze({
  "local-loopback-v1": {
    id: "local-loopback-v1",
    version: 1,
    description: "Loopback or same-host container target: tight latency, small tolerance for errors.",
    http: httpSet({ p95: 250, p99: 600, err: 0.005, stopErr: 0.05, stopP99: 3_000, stopConsecutive: 10, burstP95: 1_000, burstP99: 2_500 }),
    recovery: {
      "app-restart": { minFailureRateWhileDown: 0.9, maxRecoverySeconds: 30, stopRecoverySeconds: 60, maxProbeDurationMs: 2_500 },
      "postgres-outage": { minFailureRateWhileDown: 0.9, maxRecoverySeconds: 30, stopRecoverySeconds: 60, maxProbeDurationMs: 7_000 },
    },
  },
  "field-remote-v1": {
    id: "field-remote-v1",
    version: 1,
    description: "Remote disposable system under test over the internet: allows for RTT and shared-host jitter.",
    http: httpSet({ p95: 1_500, p99: 3_000, err: 0.01, stopErr: 0.1, stopP99: 8_000, stopConsecutive: 15, burstP95: 3_000, burstP99: 6_000 }),
    recovery: {
      "app-restart": { minFailureRateWhileDown: 0.9, maxRecoverySeconds: 45, stopRecoverySeconds: 60, maxProbeDurationMs: 2_500 },
      "postgres-outage": { minFailureRateWhileDown: 0.9, maxRecoverySeconds: 45, stopRecoverySeconds: 60, maxProbeDurationMs: 7_000 },
    },
  },
});

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function thresholdSetFingerprint(set: ThresholdSet): { id: string; version: number; sha256: string } {
  return { id: set.id, version: set.version, sha256: createHash("sha256").update(canonicalJson(set)).digest("hex") };
}

export function selectThresholdSet(id: string | undefined, targetClass: "lab-local" | "lab-remote"): ThresholdSet {
  // Remote targets must name the set explicitly: no silent default to the tight local set.
  if (targetClass === "lab-remote" && id === undefined) throw new Error("a remote target requires an explicit --thresholds set");
  const chosen = id ?? "local-loopback-v1";
  if (!Object.prototype.hasOwnProperty.call(THRESHOLD_SETS, chosen)) throw new Error(`unknown threshold set ${chosen}`);
  return THRESHOLD_SETS[chosen];
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export type LatencySummary = { count: number; min: number; mean: number; p50: number; p90: number; p95: number; p99: number; max: number };

export type PhaseStats = {
  name: string;
  startedAt: string;
  endedAt: string;
  planned: { durationSeconds: number; ratePerSecond: number; concurrency: number; timeoutMs: number };
  attempted: number;
  succeeded: number;
  failed: number;
  outcomes: Record<string, number>;
  statuses: Record<string, number>;
  droppedByConcurrencyCap: number;
  bytesReceived: number;
  latencyMs: LatencySummary;
};

export function percentile(sortedAscending: readonly number[], p: number): number {
  if (sortedAscending.length === 0) return 0;
  const rank = Math.min(sortedAscending.length - 1, Math.max(0, Math.ceil((p / 100) * sortedAscending.length) - 1));
  return sortedAscending[rank];
}

export function summarizeLatencies(values: readonly number[]): LatencySummary {
  const sorted = [...values].sort((a, b) => a - b);
  const sum = sorted.reduce((total, value) => total + value, 0);
  const round = (value: number) => Math.round(value * 100) / 100;
  return {
    count: sorted.length,
    min: round(sorted[0] ?? 0),
    mean: round(sorted.length ? sum / sorted.length : 0),
    p50: round(percentile(sorted, 50)),
    p90: round(percentile(sorted, 90)),
    p95: round(percentile(sorted, 95)),
    p99: round(percentile(sorted, 99)),
    max: round(sorted[sorted.length - 1] ?? 0),
  };
}

export function ruleFor(thresholds: HttpThresholds, phaseName: string): PhaseRuleKind {
  const rules = thresholds.phaseRules ?? {};
  for (const [prefix, kind] of Object.entries(rules)) if (phaseName.startsWith(prefix)) return kind;
  return "measured";
}

export type Verdict = { result: "PASS" | "FAIL"; failures: string[] };

export function evaluateHttpPass(thresholds: HttpThresholds, phases: readonly PhaseStats[]): Verdict {
  const failures: string[] = [];
  let attempted = 0;
  let failed = 0;
  for (const phase of phases) {
    const rule = ruleFor(thresholds, phase.name);
    if (rule === "health") {
      if (phase.attempted === 0 || phase.failed > 0) failures.push(`${phase.name}: health phase must have no failures and at least one request`);
      continue;
    }
    if (rule === "expect-failures") continue;
    attempted += phase.attempted;
    failed += phase.failed;
  }
  if (attempted < thresholds.pass.minSamples && phases.some((phase) => ruleFor(thresholds, phase.name) === "measured")) {
    failures.push(`only ${attempted} measured samples, need ${thresholds.pass.minSamples}`);
  }
  if (attempted > 0 && failed / attempted > thresholds.pass.maxErrorRate) failures.push(`error rate ${(failed / attempted).toFixed(4)} > ${thresholds.pass.maxErrorRate}`);
  for (const phase of phases) {
    if (ruleFor(thresholds, phase.name) !== "measured" || phase.latencyMs.count === 0) continue;
    if (phase.latencyMs.p95 > thresholds.pass.maxP95Ms) failures.push(`${phase.name}: p95 ${phase.latencyMs.p95}ms > ${thresholds.pass.maxP95Ms}ms`);
    if (phase.latencyMs.p99 > thresholds.pass.maxP99Ms) failures.push(`${phase.name}: p99 ${phase.latencyMs.p99}ms > ${thresholds.pass.maxP99Ms}ms`);
  }
  return { result: failures.length === 0 ? "PASS" : "FAIL", failures };
}

export type StopState = { measured: number; failed: number; consecutiveFailures: number; latenciesMs: number[] };

/** Returns a reason string when the run must stop immediately. */
export function evaluateStop(thresholds: HttpThresholds, state: StopState): string | null {
  const { stop } = thresholds;
  if (state.consecutiveFailures >= stop.consecutiveFailures) return `${state.consecutiveFailures} consecutive failures`;
  if (state.measured >= stop.afterSamples) {
    if (state.failed / state.measured >= stop.errorRate) return `error rate ${(state.failed / state.measured).toFixed(3)} >= ${stop.errorRate}`;
    const sorted = [...state.latenciesMs].sort((a, b) => a - b);
    const p99 = percentile(sorted, 99);
    if (p99 > stop.p99Ms) return `p99 ${Math.round(p99)}ms > ${stop.p99Ms}ms`;
  }
  return null;
}
