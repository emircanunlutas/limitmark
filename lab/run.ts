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
import { executeClosedLoop } from "./load/closed-loop";
import { fieldLevelForWorkload, ba0FieldFingerprint } from "./defense/field-thresholds";
import { buildGeneratorReport, campaignIdPattern, workloadFingerprint } from "./defense/generator-report";
import { assertSameLabAppContainer, inspectLabContainer } from "./host/docker";
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
import { applyKnownFaultVerdict, libraryFaults } from "./postgres/known-faults";
import { evidenceSafeError } from "./evidence/redact";

const VALUE_FLAGS = new Set(["--target", "--workload", "--thresholds", "--max-rate", "--max-concurrency", "--max-duration", "--pg", "--outage-mode", "--engine", "--k6-netns-container", "--app-container", "--campaign"]);
const BOOLEAN_FLAGS = new Set(["--manage-app", "--dry-run"]);
export const OPERATOR_TARGETS_FILE = path.join(REPOSITORY_ROOT, "artifacts", "lab", "targets.json");

export type ParsedArguments = {
  target?: string; workload?: string; thresholds?: string; pg?: string; outageMode?: string; engine?: string; k6Netns?: string; appContainer?: string;
  /** The campaign id of a BA0 field level (a plain label chosen by the operator; recorded in the evidence, never an input to any decision). */
  campaign?: string;
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
    outageMode: values["--outage-mode"], engine: values["--engine"], k6Netns: values["--k6-netns-container"], appContainer: values["--app-container"], campaign: values["--campaign"],
    limits, manageApp: flags.has("--manage-app"), dryRun: flags.has("--dry-run"),
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

/**
 * A loopback port is not proof of WHAT listens there: a forwarder (ssh -L, socat, a stray process) on 3000/3100 would silently
 * turn an authorized target into another destination. A local HTTP run therefore needs a destination the lab itself
 * established: a process it started (--manage-app), a lab-labelled container that publishes exactly that loopback port
 * (--app-container), or k6 inside such a container's own network namespace (--k6-netns-container). Pure.
 */
export function checkDestinationProof(targetClass: string, workloadEngine: string, args: Pick<ParsedArguments, "engine" | "manageApp" | "appContainer" | "k6Netns">): PolicyRefusal | null {
  if (targetClass !== "lab-local" || workloadEngine !== "http") return null;
  const proven = args.engine === "k6" ? args.k6Netns !== undefined : args.manageApp || args.appContainer !== undefined;
  if (proven) return null;
  return new PolicyRefusal("target-listener-unproven", args.engine === "k6"
    ? "a local k6 run needs --k6-netns-container (its own loopback is the only destination it can prove)"
    : "an existing listener on a local port is not an authorized destination; use --manage-app or --app-container <lab container>");
}

function summarize(phases: readonly PhaseStats[]) {
  const attempted = phases.reduce((sum, phase) => sum + phase.attempted, 0);
  const failed = phases.reduce((sum, phase) => sum + phase.failed, 0);
  return { attempted, failed, errorRate: attempted ? Math.round((failed / attempted) * 10_000) / 10_000 : 0 };
}

const EXIT: Record<EvidenceResult, number> = {
  PASS: 0, FAIL: 1, REFUSED: 2, STOP: 3, ERROR: 4, "BASELINE-VALID": 0, "APP-NON-BYPASS-VALID": 0, "LAYER-DIVERSITY-VALID": 0, INVALID: 1,
  "GENERATOR-COMPLETE": 0, "SERVER-COMPLETE": 0, ABORTED: 3, "EXTERNAL-L7-QUALIFICATION-VALID": 0,
};

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
  if (args.appContainer !== undefined && (args.engine === "k6" || args.manageApp)) return refuse(new PolicyRefusal("limit-invalid", "--app-container is for the node engine without --manage-app"), "bad-engine");
  for (const name of [args.k6Netns, args.appContainer]) {
    if (name !== undefined && !/^limitmark-lab-[a-z0-9-]{1,60}$/.test(name)) return refuse(new PolicyRefusal("limit-invalid", "container options take a lab container name"), "bad-container");
  }

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
  const unproven = checkDestinationProof(run.target.class, run.workload.engine, args);
  if (unproven) return refuse(unproven, "listener-unproven");
  // A closed-loop BA0 level has its own engine, its own parameter set and its own report; the open-loop engine below never runs it.
  if (run.workload.engine === "http-closed-loop") return runClosedLoopLevel(run, args, git, startedAt, refuse);
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
  // What the lab actually established about the destination, recorded verbatim (never "proven" for a remote target).
  let ownership = run.target.class === "lab-remote" ? "operator-asserted" : "unproven";
  try {
    if (run.workload.engine === "managed-app") {
      ownership = "lab-process";
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
        ownership = "lab-process";
        extra = { warmup: await warmUp(run) };
      }
      const containerGate = args.appContainer;
      let appContainerId: string | undefined;
      if (containerGate !== undefined) {
        // The identity (immutable id) is captured once; every later check must find THE SAME running container.
        appContainerId = await verifyAppContainer(containerGate, run.target.port);
        ownership = "lab-container-port";
      }
      const thresholds = set.http[run.workload.id as keyof typeof set.http];
      if (args.engine === "k6") {
        if (run.workload.engine !== "http") throw new PolicyRefusal("workload-local-only", "k6 drives HTTP workloads only");
        const k6 = await runK6(run, thresholds, { netnsContainer: args.k6Netns, runId: evidence.id });
        engineName = "k6";
        if (args.k6Netns !== undefined) ownership = "lab-container-netns";
        result = k6.result; reasons.push(...k6.reasons);
        extra = { ...extra, k6Version: k6.k6Version, k6ImageId: k6.imageId, planSha256: k6.planSha256, k6ContainerRemoved: k6.containerRemoved, k6Envelope: k6.envelope, ...k6.metrics };
      } else {
        const engine: EngineResult = await executeHttpWorkload({
          run, thresholds,
          // The destination is re-proved before the first request and then throughout every phase (a container that stops mid-phase and a
          // listener that takes its port must not keep receiving authorized traffic).
          destination: containerGate === undefined ? undefined : { verify: async () => { await verifyAppContainer(containerGate, run.target.port, appContainerId); } },
        });
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
    reasons.push(evidenceSafeError(error));
    result = error instanceof PolicyRefusal ? "REFUSED" : "ERROR";
  } finally {
    await app?.kill();
  }
  evidence.addJsonArtifact("phases.json", { phases });
  evidence.finalize({
    git, environment: collectEnvironment(),
    target: { id: run.target.id, class: run.target.class, scheme: run.target.scheme, port: run.target.port, ownership },
    workload: { id: run.workload.id, phases: run.limits.phases },
    ceilings: {
      // These bound ONE process. Two valid processes together may reach twice the rate and connection count; a campaign or fleet
      // budget has to be planned and enforced by the operator (see lab/README.md "What the ceilings bound").
      scope: "per-process; not campaign- or fleet-wide",
      hard: { ...HARD_CEILINGS }, reviewed: { ...run.workload.ceilings },
      effective: { maxRequestsPerSecond: run.limits.maxRequestsPerSecond, maxConcurrency: run.limits.maxConcurrency, maxDurationSeconds: run.limits.maxDurationSeconds, maxTotalRequests: run.limits.maxTotalRequests },
    },
    thresholds: fingerprint, engine: engineName, result, resultReasons: reasons, metrics: { ...summarize(phases), ...extra },
  });
  console.log(`${result}  ${run.workload.id} -> ${run.target.id}  thresholds=${fingerprint.id}@${fingerprint.version}\n${reasons.map((reason) => `  - ${reason}`).join("\n")}\nevidence=${evidence.id}`);
  return EXIT[result];
}

/**
 * A BA0 field level's GENERATOR. It sends the reviewed closed-loop workload to the reviewed remote target and writes a generator report. It never
 * concludes a verdict: the server-side evidence and the offline reconcile do. It accepts no limit override and no engine choice, so the level it
 * runs is exactly the one whose fingerprint the VALID verdict is scoped to.
 */
async function runClosedLoopLevel(run: AuthorizedRun, args: ParsedArguments, git: ReturnType<typeof collectGitState>, startedAt: Date, refuse: (e: PolicyRefusal, label: string) => number): Promise<number> {
  const field = fieldLevelForWorkload(run.workload.id)?.thresholds;
  if (field === undefined) return refuse(new PolicyRefusal("limit-invalid", "closed-loop workload is not a reviewed field level"), "level-not-reviewed");
  if (args.campaign === undefined || !campaignIdPattern.test(args.campaign)) return refuse(new PolicyRefusal("limit-invalid", "--campaign must be a plain label (lowercase letters, digits, hyphens; 6 to 41 characters)"), "bad-campaign");
  if (args.engine !== undefined || args.manageApp || args.appContainer !== undefined || args.k6Netns !== undefined || args.thresholds !== undefined) {
    return refuse(new PolicyRefusal("limit-invalid", "a closed-loop level takes only --target, --workload and --campaign"), "bad-options");
  }
  if (args.limits.maxRate !== undefined || args.limits.maxConcurrency !== undefined || args.limits.maxDurationSeconds !== undefined) {
    return refuse(new PolicyRefusal("limit-invalid", "a qualification level takes no limit override: its verdict is scoped to the exact reviewed level"), "bad-limits");
  }
  const phase = run.limits.phases[0];
  if (phase.concurrency !== field.level.workers || phase.ratePerSecond !== field.level.maxRequestsPerSecond || phase.durationSeconds !== field.level.durationSeconds
    || run.limits.maxTotalRequests !== field.level.maxTotalRequests || phase.timeoutMs !== field.level.requestTimeoutMs) {
    return refuse(new PolicyRefusal("limit-above-reviewed-ceiling", `the workload catalogue and ${field.id} disagree about the level`), "level-mismatch");
  }
  const fingerprint = ba0FieldFingerprint(field);
  const workloadHash = workloadFingerprint(run.workload);
  if (args.dryRun) {
    console.log(JSON.stringify({ dryRun: true, target: run.target.id, workload: run.workload.id, level: field.level.id, campaign: args.campaign, parameters: fingerprint, workloadSha256: workloadHash, limits: run.limits }, null, 2));
    return 0;
  }
  const evidence = new EvidenceRun("load", run.workload.id, startedAt);
  const abort = new AbortController();
  const onSignal = () => abort.abort();
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  let result: EvidenceResult = "ERROR";
  const reasons: string[] = [];
  let summary: Record<string, unknown> = {};
  try {
    const outcome = await executeClosedLoop({ run, signal: abort.signal, stopOnTransportFailure: true });
    const report = buildGeneratorReport({
      result: outcome, runId: evidence.id, campaignId: args.campaign, levelId: field.level.id, gitSha: git.gitSha, paramsFingerprintSha256: fingerprint.sha256,
      workload: run.workload, targetId: run.target.id, ceilingRatePerSecond: phase.ratePerSecond,
    });
    evidence.addJsonArtifact("generator-report.json", report);
    const ended = outcome.stop.kind;
    if (ended === "completed" || (field.level.id !== "ba0-l7-c2-salvo" && ended === "total_ceiling")) result = "GENERATOR-COMPLETE";
    else if (ended === "operator_abort") result = "ABORTED";
    else result = "STOP";
    if (ended !== "completed") reasons.push(`generator stop: ${ended}${outcome.stop.detail ? ` ${outcome.stop.detail}` : ""}`);
    summary = { attempted: outcome.attempted, responses: outcome.responses, transportFailures: outcome.transportFailures, maxInFlightObserved: outcome.concurrency.maxInFlightObserved, stopKind: ended };
  } catch (error) {
    reasons.push(evidenceSafeError(error));
    result = error instanceof PolicyRefusal ? "REFUSED" : "ERROR";
  } finally {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  }
  evidence.finalize({
    git, environment: collectEnvironment(), target: { id: run.target.id, class: run.target.class, scheme: run.target.scheme, port: run.target.port, ownership: "operator-asserted" },
    workload: { id: run.workload.id, phases: run.limits.phases },
    ceilings: { scope: "per-process; not campaign- or fleet-wide", hard: { ...HARD_CEILINGS }, reviewed: { ...run.workload.ceilings }, level: field.level.id },
    thresholds: fingerprint, engine: "node-http-closed-loop", result, resultReasons: reasons,
    metrics: { ...summary, campaign: args.campaign, workloadSha256: workloadHash, verdict: "not_decided_here", note: "the generator concludes no verdict: the server-side evidence and the offline reconcile do" },
  });
  console.log(`${result}  ${run.workload.id} -> ${run.target.id}  parameters=${fingerprint.id}@${fingerprint.version}  (no verdict here: the server-side evidence and the offline reconcile decide)\n${reasons.map((reason) => `  - ${reason}`).join("\n")}\nevidence=${evidence.id}`);
  return EXIT[result];
}

/** The destination container must still be a running lab app container publishing exactly 127.0.0.1:<port>. */
async function verifyAppContainer(name: string, port: number, expectedId?: string): Promise<string> {
  const facts = await inspectLabContainer(name, "app");
  assertSameLabAppContainer(facts, port, 3000, expectedId);
  return facts.id;
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
    extra = { mode, recoverySeconds: outcome.recoverySeconds, maxProbeDurationWhileDownMs: outcome.maxProbeDurationDownMs, integrity: outcome.integrity, abandonedProbes: outcome.abandonedProbes, maxUnsettledProbes: outcome.maxUnsettledProbes, orphanedBackends: outcome.orphanedBackends };
  } catch (error) {
    reasons.push(evidenceSafeError(error));
  } finally {
    await labDbDown(version).catch((error) => reasons.push(`teardown: ${evidenceSafeError(error)}`));
  }
  // The known postgres.js defect is a FINDING, never compatible with PASS.
  ({ result } = applyKnownFaultVerdict(result, reasons, libraryFaults));
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
