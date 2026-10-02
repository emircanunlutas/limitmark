/**
 * Application restart / connection-failure workload against the lab-managed local app.
 * The lab kills ONLY the process tree it started, then restarts it and measures how long
 * the first healthy response takes.
 */
import { performance } from "node:perf_hooks";
import { LocalApp } from "../host/local-app";
import { executeHttpWorkload, type EngineResult } from "../load/engine";
import type { AuthorizedRun } from "../policy/target-policy";
import type { HttpThresholds, ThresholdSet } from "../policy/thresholds";
import { evaluateRecovery, type RecoveryVerdict } from "./recovery";

export type AppRestartOutcome = { engine: EngineResult; verdict: RecoveryVerdict; recoverySeconds: number | null; maxProbeDurationDownMs: number; firstFailureAfterKillSeconds: number | null };

export async function runAppRestart(run: AuthorizedRun, set: ThresholdSet): Promise<AppRestartOutcome> {
  const base = set.http["latency-measurement"];
  const thresholds: HttpThresholds = { ...base, phaseRules: { down: "expect-failures", recovery: "expect-failures" } };
  const app = new LocalApp(run.target.port);
  await app.start();
  await app.waitUntilListening();
  let killedAt = 0, startedAt = 0, firstFailureAt: number | null = null, firstOkAt: number | null = null, consecutiveOk = 0, maxDown = 0;
  try {
    const engine = await executeHttpWorkload({
      run, thresholds,
      onPhaseStart: async (phase) => {
        if (phase.name === "down") { await app.kill(); killedAt = performance.now(); }
        if (phase.name === "recovery") { startedAt = performance.now(); await app.start(); }
      },
      onResult: (phase, result) => {
        const now = performance.now();
        if (phase === "down") {
          maxDown = Math.max(maxDown, result.latencyMs);
          if (result.outcome !== "ok" && firstFailureAt === null) firstFailureAt = now;
        }
        if (phase === "recovery") {
          if (result.outcome === "ok") { consecutiveOk++; firstOkAt ??= now; } else consecutiveOk = 0;
        }
      },
      shouldEndPhase: (phase) => phase === "recovery" && consecutiveOk >= 5,
    });
    const recoverySeconds = firstOkAt === null ? null : Math.round(((firstOkAt as number) - startedAt) / 10) / 100;
    const verdict = evaluateRecovery(set.recovery["app-restart"], {
      phases: engine.phases, recoverySeconds, maxProbeDurationDownMs: maxDown,
      downPhase: "down", recoveryPhase: "recovery", steadyPhases: ["steady-before", "steady-after"],
    });
    return {
      engine, verdict, recoverySeconds, maxProbeDurationDownMs: Math.round(maxDown),
      firstFailureAfterKillSeconds: firstFailureAt === null ? null : Math.round(((firstFailureAt as number) - killedAt) / 10) / 100,
    };
  } finally {
    await app.kill();
  }
}
