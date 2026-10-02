/**
 * Lab runner CLI. Every load/failure workload goes through here and through target-policy.ts.
 *
 *   tsx --conditions=react-server lab/run.ts --target local-app --workload latency-measurement --manage-app
 *   tsx --conditions=react-server lab/run.ts --workload postgres-outage --pg 16 [--outage-mode stop|pause]
 *
 * The CLI accepts NO URL, host, port, path, method or header. It names a target ID, a workload ID,
 * and optionally LOWER limits. Anything else is refused before any network activity.
 *
 * Exit codes: 0 PASS, 1 FAIL, 2 REFUSED, 3 STOP, 4 ERROR.
 */
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { LocalApp } from "./host/local-app";
import { executeHttpWorkload, warmUp, type EngineResult } from "./load/engine";
import { runK6 } from "./load/k6";
import { runAppRestart } from "./failure/app-restart";
import { runPostgresOutage, type OutageMode } from "./failure/postgres-outage";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState, type EvidenceResult } from "./evidence/manifest";
import {
  PolicyRefusal, authorizeManagedPostgresRun, authorizeRun, buildRegistry, parseStrictPositiveInteger,
  type AuthorizedRun, type CliLimits,
} from "./policy/target-policy";
import { HARD_CEILINGS, WORKLOADS, isWorkloadId } from "./policy/workloads";
import {
  evaluateHttpPass, selectThresholdSet, thresholdSetFingerprint, type PhaseStats,
} from "./policy/thresholds";
import { assertVersion, labDbDown, labDbUp, teardownOnCrash, type PgVersion } from "./postgres/lab-db";
import { libraryFaults } from "./postgres/known-faults";

const VALUE_FLAGS = new Set(["--target", "--workload", "--thresholds", "--max-rate", "--max-concurrency", "--max-duration", "--pg", "--outage-mode", "--engine", "--k6-netns-container"]);
const BOOLEAN_FLAGS = new Set(["--manage-app", "--dry-run"]);
export const OPERATOR_TARGETS_FILE = path.join(REPOSITORY_ROOT, "artifacts", "lab", "targets.json");

export type ParsedArguments = {
  target?: string; workload?: string; thresholds?: string; pg?: string; outageMode?: string; engine?: string; k6Netns?: string;
  limits: CliLimits; manageApp: boolean; dryRun: boolean;
};

/** Strict parser: unknown flags, duplicates, positionals, `--flag=value` and URL-ish values are all refused. */
export function parseArguments(argv: readonly string[]): ParsedArguments {
  const seen = new Set<string>();
  const values: Record<string, string> = {};
  const flags = new Set<string>();
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (!arg.startsWith("--") || arg.includes("=")) throw new PolicyRefusal("limit-invalid", `unexpected argument "${arg.slice(0, 20)}"`);
    if (seen.has(arg)) throw new PolicyRefusal("limit-invalid", `${arg} given twice`);
    seen.add(arg);
    if (BOOLEAN_FLAGS.has(arg)) { flags.add(arg); continue; }
    if (!VALUE_FLAGS.has(arg)) throw new PolicyRefusal("target-unknown", `unknown option ${arg.slice(0, 24)}; targets are chosen by ID only`);
    const value = argv[++index];
    if (value === undefined || value.startsWith("--")) throw new PolicyRefusal("limit-invalid", `${arg} needs a value`);
    values[arg] = value;
  }
  const limits: CliLimits = {};
  if (values["--max-rate"] !== undefined) limits.maxRate = parseStrictPositiveInteger(values["--max-rate"], "--max-rate");
  if (values["--max-concurrency"] !== undefined) limits.maxConcurrency = parseStrictPositiveInteger(values["--max-concurrency"], "--max-concurrency");
  if (values["--max-duration"] !== undefined) limits.maxDurationSeconds = parseStrictPositiveInteger(values["--max-duration"], "--max-duration");
  return {
    target: values["--target"], workload: values["--workload"], thresholds: values["--thresholds"], pg: values["--pg"],
    outageMode: values["--outage-mode"], engine: values["--engine"], k6Netns: values["--k6-netns-container"], limits, manageApp: flags.has("--manage-app"), dryRun: flags.has("--dry-run"),
  };
}

export function loadOperatorTargets(file = OPERATOR_TARGETS_FILE): unknown[] {
  if (!existsSync(file)) return [];
  const parsed: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (!Array.isArray(parsed)) throw new PolicyRefusal("target-definition-invalid", "targets file must be a JSON array");
  // Loopback targets are the built-in fixtures only. A file-defined loopback port could be an SSH/port forward to
  // a host the policy never saw, so the operator file may define lab-remote (expiring, IP-literal) targets only.
  for (const entry of parsed) {
    if (typeof entry !== "object" || entry === null || (entry as { class?: unknown }).class !== "lab-remote") {
      throw new PolicyRefusal("target-definition-invalid", "the operator targets file may only define lab-remote targets");
    }
  }
  return parsed;
}

function summarize(phases: readonly PhaseStats[]) {
  const attempted = phases.reduce((sum, phase) => sum + phase.attempted, 0);
  const failed = phases.reduce((sum, phase) => sum + phase.failed, 0);
  return { attempted, failed, errorRate: attempted ? Math.round((failed / attempted) * 10_000) / 10_000 : 0 };
}

const EXIT: Record<EvidenceResult, number> = { PASS: 0, FAIL: 1, REFUSED: 2, STOP: 3, ERROR: 4 };

async function main(): Promise<number> {
  const startedAt = new Date();
  const git = collectGitState();
  let args: ParsedArguments;
  const refuse = (error: PolicyRefusal, label: string): number => {
    const evidence = new EvidenceRun("load-refusal", label, startedAt);
    evidence.finalize({
      git, environment: collectEnvironment(), target: null, workload: null, ceilings: { hard: { ...HARD_CEILINGS } }, thresholds: null,
      engine: "none", result: "REFUSED", resultReasons: [error.code], metrics: { networkActivity: false },
    });
    console.error(`REFUSED before any network activity: ${error.message}\nevidence=${evidence.id}`);
    return EXIT.REFUSED;
  };
  try {
    args = parseArguments(process.argv.slice(2));
  } catch (error) {
    if (error instanceof PolicyRefusal) return refuse(error, "bad-arguments");
    throw error;
  }
  if (args.engine !== undefined && args.engine !== "node" && args.engine !== "k6") return refuse(new PolicyRefusal("limit-invalid", "--engine must be node or k6"), "bad-engine");
  if (args.engine === "k6" && args.manageApp) return refuse(new PolicyRefusal("limit-invalid", "--manage-app is for the node engine; k6 runs in Docker and cannot reach the host loopback"), "bad-engine");
  if (args.k6Netns !== undefined && args.engine !== "k6") return refuse(new PolicyRefusal("limit-invalid", "--k6-netns-container needs --engine k6"), "bad-engine");

  const workloadId = args.workload ?? "";
  if (isWorkloadId(workloadId) && WORKLOADS[workloadId].engine === "managed-postgres") {
    return runPostgres(args, git, startedAt, refuse);
  }

  let run: AuthorizedRun;
  try {
    run = authorizeRun({
      targetId: args.target ?? "", workloadId, limits: args.limits,
      registry: buildRegistry(loadOperatorTargets(), startedAt), now: startedAt, treeIsClean: !git.dirty,
    });
  } catch (error) {
    if (error instanceof PolicyRefusal) return refuse(error, "refused");
    throw error;
  }
  const set = selectThresholdSet(args.thresholds, run.target.class);
  const fingerprint = thresholdSetFingerprint(set);
  if (args.dryRun) {
    console.log(JSON.stringify({ dryRun: true, target: run.target.id, workload: run.workload.id, thresholds: fingerprint, limits: run.limits }, null, 2));
    return 0;
  }

  const evidence = new EvidenceRun("load", run.workload.id, startedAt);
  let result: EvidenceResult = "ERROR";
  const reasons: string[] = [];
  let phases: readonly PhaseStats[] = [];
  let extra: Record<string, unknown> = {};
  let app: LocalApp | null = null;
  let engineName = "node-http";
  try {
    if (run.workload.engine === "managed-app") {
      const outcome = await runAppRestart(run, set);
      phases = outcome.engine.phases;
      result = outcome.verdict.result;
      reasons.push(...outcome.verdict.reasons, ...(outcome.engine.stopReason ? [outcome.engine.stopReason] : []));
      extra = { recoverySeconds: outcome.recoverySeconds, maxProbeDurationWhileDownMs: outcome.maxProbeDurationDownMs, firstFailureAfterKillSeconds: outcome.firstFailureAfterKillSeconds };
    } else {
      if (args.manageApp) {
        if (run.target.class !== "lab-local") throw new PolicyRefusal("workload-local-only", "--manage-app only applies to lab-local targets");
        app = new LocalApp(run.target.port);
        await app.start();
        await app.waitUntilListening();
        extra = { warmup: await warmUp(run) };
      }
      const thresholds = set.http[run.workload.id as keyof typeof set.http];
      if (args.engine === "k6") {
        if (run.workload.engine !== "http") throw new PolicyRefusal("workload-local-only", "k6 drives HTTP workloads only");
        const k6 = await runK6(run, thresholds, { netnsContainer: args.k6Netns, runId: evidence.id });
        engineName = "k6";
        result = k6.result; reasons.push(...k6.reasons);
        extra = { ...extra, k6Version: k6.k6Version, planSha256: k6.planSha256, ...k6.metrics };
      } else {
        const engine: EngineResult = await executeHttpWorkload({ run, thresholds });
        phases = engine.phases;
        extra = { ...extra, wallClockSeconds: engine.wallClockSeconds, totalAttempted: engine.totalAttempted };
        if (engine.stopReason) { result = "STOP"; reasons.push(engine.stopReason); }
        else {
          const verdict = evaluateHttpPass(thresholds, engine.phases);
          result = verdict.result; reasons.push(...verdict.failures);
        }
      }
    }
  } catch (error) {
    reasons.push(error instanceof Error ? error.message.slice(0, 300) : "unknown error");
    result = error instanceof PolicyRefusal ? "REFUSED" : "ERROR";
  } finally {
    await app?.kill();
  }
  evidence.addJsonArtifact("phases.json", { phases });
  evidence.finalize({
    git, environment: collectEnvironment(),
    target: { id: run.target.id, class: run.target.class, scheme: run.target.scheme, port: run.target.port },
    workload: { id: run.workload.id, phases: run.limits.phases },
    ceilings: {
      hard: { ...HARD_CEILINGS }, reviewed: { ...run.workload.ceilings },
      effective: { maxRequestsPerSecond: run.limits.maxRequestsPerSecond, maxConcurrency: run.limits.maxConcurrency, maxDurationSeconds: run.limits.maxDurationSeconds, maxTotalRequests: run.limits.maxTotalRequests },
    },
    thresholds: fingerprint, engine: engineName, result, resultReasons: reasons, metrics: { ...summarize(phases), ...extra },
  });
  console.log(`${result}  ${run.workload.id} -> ${run.target.id}  thresholds=${fingerprint.id}@${fingerprint.version}\n${reasons.map((reason) => `  - ${reason}`).join("\n")}\nevidence=${evidence.id}`);
  return EXIT[result];
}

async function runPostgres(args: ParsedArguments, git: ReturnType<typeof collectGitState>, startedAt: Date, refuse: (e: PolicyRefusal, label: string) => number): Promise<number> {
  let version: PgVersion;
  let limits;
  let mode: OutageMode;
  try {
    if (args.target !== undefined) throw new PolicyRefusal("target-unknown", "postgres-outage acts on the lab container only; --target is not accepted");
    version = assertVersion(args.pg);
    if (args.outageMode !== undefined && args.outageMode !== "stop" && args.outageMode !== "pause") throw new PolicyRefusal("limit-invalid", "--outage-mode must be stop or pause");
    mode = (args.outageMode ?? "stop") as OutageMode;
    limits = authorizeManagedPostgresRun(args.workload ?? "", args.limits);
  } catch (error) {
    if (error instanceof PolicyRefusal) return refuse(error, "refused");
    if (error instanceof Error) return refuse(new PolicyRefusal("limit-invalid", error.message), "refused");
    throw error;
  }
  const set = selectThresholdSet(args.thresholds, "lab-local");
  const fingerprint = thresholdSetFingerprint(set);
  if (args.dryRun) { console.log(JSON.stringify({ dryRun: true, workload: "postgres-outage", pg: version, mode, thresholds: fingerprint, limits: limits.limits }, null, 2)); return 0; }
  teardownOnCrash([version], { tolerateKnownPostgresJsFault: true });
  const evidence = new EvidenceRun("failure", `postgres-outage-${mode}`, startedAt);
  const state = await labDbUp(version);
  let result: EvidenceResult = "ERROR";
  const reasons: string[] = [];
  let phases: readonly PhaseStats[] = [];
  let extra: Record<string, unknown> = {};
  try {
    const outcome = await runPostgresOutage(state, limits.limits, set, mode);
    phases = outcome.phases; result = outcome.verdict.result; reasons.push(...outcome.verdict.reasons);
    extra = { mode, recoverySeconds: outcome.recoverySeconds, maxProbeDurationWhileDownMs: outcome.maxProbeDurationDownMs, integrity: outcome.integrity };
  } catch (error) {
    reasons.push(error instanceof Error ? error.message.slice(0, 300) : "unknown error");
  } finally {
    await labDbDown(version).catch((error) => reasons.push(`teardown: ${(error as Error).message}`));
  }
  evidence.addJsonArtifact("phases.json", { phases });
  evidence.finalize({
    git, environment: collectEnvironment(state.serverVersion), target: { id: `postgres-lab-${version}`, class: "lab-local" },
    workload: { id: "postgres-outage", phases: limits.limits.phases },
    ceilings: { hard: { ...HARD_CEILINGS }, reviewed: { ...limits.workload.ceilings }, effective: { maxRequestsPerSecond: limits.limits.maxRequestsPerSecond, maxConcurrency: limits.limits.maxConcurrency, maxDurationSeconds: limits.limits.maxDurationSeconds, maxTotalRequests: limits.limits.maxTotalRequests } },
    thresholds: fingerprint, engine: "node-postgres", result, resultReasons: reasons,
    metrics: { ...summarize(phases), ...extra, postgresJsUncaughtNullSocketWrite: libraryFaults.postgresJsNullSocketWrite },
  });
  if (libraryFaults.postgresJsNullSocketWrite > 0) console.log(`FINDING: postgres.js threw ${libraryFaults.postgresJsNullSocketWrite} uncaught null-socket write TypeError(s)`);
  console.log(`${result}  postgres-outage (${mode}) PG${version}\n${reasons.map((reason) => `  - ${reason}`).join("\n")}\nevidence=${evidence.id}`);
  return EXIT[result];
}

if (require.main === module) {
  main().then((code) => process.exit(code), (error) => { console.error(error instanceof Error ? error.message : error); process.exit(EXIT.ERROR); });
}
