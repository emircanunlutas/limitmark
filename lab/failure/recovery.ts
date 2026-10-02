import type { PhaseStats, RecoveryThresholds } from "../policy/thresholds";

export type RecoveryObservation = {
  phases: readonly PhaseStats[];
  /** Seconds from the restart/start command to the first healthy response; null if it never recovered. */
  recoverySeconds: number | null;
  /** Longest single probe during the down/outage phase. */
  maxProbeDurationDownMs: number;
  downPhase: string;
  recoveryPhase: string;
  steadyPhases: readonly string[];
};

export type RecoveryVerdict = { result: "PASS" | "FAIL" | "STOP"; reasons: string[] };

/** STOP = never recovered inside the stop window; FAIL = recovered or behaved outside the PASS criteria. */
export function evaluateRecovery(thresholds: RecoveryThresholds, observation: RecoveryObservation): RecoveryVerdict {
  const reasons: string[] = [];
  const phase = (name: string) => observation.phases.find((entry) => entry.name === name);
  const down = phase(observation.downPhase);
  if (!down || down.attempted === 0) reasons.push("down phase produced no probes");
  else if (down.failed / down.attempted < thresholds.minFailureRateWhileDown) {
    reasons.push(`failure rate while down ${(down.failed / down.attempted).toFixed(2)} < ${thresholds.minFailureRateWhileDown} (the fault may not have been injected)`);
  }
  if (observation.maxProbeDurationDownMs > thresholds.maxProbeDurationMs) {
    reasons.push(`probe during outage took ${Math.round(observation.maxProbeDurationDownMs)}ms > ${thresholds.maxProbeDurationMs}ms (failure is not bounded)`);
  }
  for (const name of observation.steadyPhases) {
    const steady = phase(name);
    if (!steady || steady.attempted === 0 || steady.failed > 0) reasons.push(`${name}: expected a fully healthy phase`);
  }
  if (observation.recoverySeconds === null) {
    return { result: "STOP", reasons: [...reasons, `no recovery within ${thresholds.stopRecoverySeconds}s`] };
  }
  if (observation.recoverySeconds > thresholds.maxRecoverySeconds) reasons.push(`recovery ${observation.recoverySeconds.toFixed(1)}s > ${thresholds.maxRecoverySeconds}s`);
  return { result: reasons.length === 0 ? "PASS" : "FAIL", reasons };
}
