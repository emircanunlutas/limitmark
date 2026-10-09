/**
 * BA0 FIELD LEVEL runner: the server side of ONE reviewed external L7 qualification level. Linux only; it runs ON the disposable system under
 * test and never drives a remote host.
 *
 *   npm run lab:ba0:field -- --target <target id> --level ba0-l7-c1 --campaign <campaign id>
 *
 * One invocation is one reviewed level; there is no escalation, no ramp and no second level in the same process. The target comes from the
 * reviewed operator registry (artifacts/lab/targets.json: an IPv4 literal, a port, `disposable`, an expiry), authorized by the same
 * `authorizeRun` the generator uses; the Defense Plane binds exactly that address and port and nothing else. No URL, host, port or path is
 * accepted on the command line.
 *
 *   PREFLIGHT -> TOPOLOGY_UP -> BASELINE -> ARMED -> WINDOW -> RESIDUAL -> QUIET -> RECOVERY -> FINALIZING -> DONE
 *
 * While the level runs: a 1-second tick (exposure proof, /proc and host sampler, harness event loop, the three child processes' own ticks,
 * live STOP rules) and an independent canary (the harness's own scheduler, on the VM, reaching the Plane at its bound address). A STOP latches
 * the first reason, closes the public ingress at once, and runs the ordered, bounded finalization (field-state.ts) so the evidence that
 * explains it is preserved before anything is terminated.
 *
 * The runner concludes only `complete | invalid | aborted | refused`. It NEVER concludes EXTERNAL-L7-QUALIFICATION-VALID: that exists only after
 * the offline reconcile of this evidence with the generator report (`ba0-field-reconcile.ts`).
 *
 * Exit codes: 0 complete, 1 invalid, 2 refused at preflight, 3 aborted, 4 error.
 */
import { mkdirSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { validateIngressBind, type IngressBind } from "../../defense/core/ingress-class";
import { UNIT } from "../../defense/core/lanes";
import { ProcessSampler, type Tick } from "../../defense/core/telemetry";
import type { Anomaly } from "../../defense/core/ledger";
import { createSyntheticOrigin } from "../../defense/origin/synthetic-origin";
import type { AppTick } from "../../defense/origin/app-field-protocol";
import type { BoundaryTick } from "../../defense/boundary/field-protocol";
import type { PlaneTick } from "../../defense/plane/l2-protocol";
import { EVIDENCE_ROOT, EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState, type GitState } from "../evidence/manifest";
import { evidenceSafeError } from "../evidence/redact";
import { PolicyRefusal, authorizeRun, buildRegistry, type AuthorizedRun, type TargetRegistry } from "../policy/target-policy";
import { WORKLOADS } from "../policy/workloads";
import { summarizeLatencies } from "../policy/thresholds";
import { buildCanaryContinuity } from "./canary-continuity";
import { loadOperatorTargets } from "../run";
import { compareParity, journeyCompletionRates, type JourneyResult } from "./canary";
import { Collector, type AppFin, type BoundaryFin, type PlaneFin } from "./collector";
import { ExternalReducer } from "./external-reducer";
import { canaryCounts, deriveExternalAccounting, unverifiedMutationBound, type ExternalAccountingReport } from "./external-accounting";
import { proveExposure, type ExposureResult, type TopologyPids } from "./exposure-proof";
import { writeFieldEvidence, type CanarySummary, type FieldEvidenceBundle, type WriteResult } from "./field-evidence";
import { runFieldJourney } from "./field-canary";
import { FieldAppProcess, FieldBoundaryProcess } from "./field-processes";
import { TickMonitor } from "./field-monitor";
import { realFieldEnvironment, runFieldPreflight, type FieldEnvironment, type PreflightResult } from "./field-preflight";
import { FieldMachine, runSequence, type SequenceStep, type StepResult } from "./field-state";
import { BA0_FIELD_V1, fieldLevel, ba0FieldFingerprint, evaluateBudgetGates, type Ba0FieldThresholds } from "./field-thresholds";
import { FIELD_EXIT, decideServerSide, type Reason, type ServerSideDecision } from "./field-verdict";
import { workloadFingerprint } from "./generator-report";
import { HopTrustRoot } from "./hop-keys";
import { PLANE_L2_ENTRY, PlaneProcess } from "./plane-process";
import { ProcSampler } from "./proc-sampler";
import type { ServerLevelEvidence } from "./reconcile";
import { N2ServerObserver, n2ExerciseSpec } from "./n2-measurement";
import { SalvoServerObserver } from "./salvo-measurement";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** The reviewed levels. A new level is a code addition with its own parameter set, never an option. */
export { FIELD_LEVELS } from "./field-thresholds";

export type FieldLevelArgs = { targetId: string; levelId: string; campaignId: string };

export type AuthorizationLike = Pick<AuthorizedRun, "target" | "authorizedUntilMs" | "assertStillAuthorized">;

/**
 * Programmatic seams for tests. NONE is reachable from the command line or the environment. A real field run passes nothing.
 */
export type FieldRunSeams = {
  env?: FieldEnvironment;
  thresholds?: Ba0FieldThresholds;
  registry?: TargetRegistry;
  /** Replaces the reviewed-target authorization (a loopback target cannot pass `authorizeRun`, which is the point of that policy). */
  authorization?: AuthorizationLike;
  git?: GitState;
  treeIsClean?: boolean;
  allowLoopbackIngress?: boolean;
  skipPlatformCheck?: boolean;
  evidenceRoot?: string;
  lockFile?: string;
  now?: () => Date;
  log?: (line: string) => void;
  abort?: AbortSignal;
  /** Called right after the three processes are up (a test fills its fake /proc here). */
  onTopology?: (info: { pids: TopologyPids; ports: { plane: number; boundary: number; app: number; control: number }; ingress: IngressBind }) => void;
  /** Called when the plane acknowledges that its public ingress is closed (a test updates its fake /proc here). */
  onIngressClosed?: () => void;
  /** Called when the level is ARMED (a test may inject stray traffic here). */
  onArmed?: (info: { ingress: IngressBind }) => void;
  /** Replaces waiting for a remote generator: opens and closes the window on a timer, so a loopback run can drive the whole machine. */
  manualWindow?: { openAfterMs: number; closeAfterMs: number };
};

export type FieldRunOutcome = {
  exit: number;
  status: "complete" | "invalid" | "aborted" | "refused" | "error";
  serverSide: ServerSideDecision | null;
  refusals: string[];
  evidenceId: string | null;
  evidenceDirectory: string | null;
  bundle: FieldEvidenceBundle | null;
  write: WriteResult | null;
};

/**
 * The anomaly codes a canary request shows when the STOP's own ingress close refused or cut it: the request never reached the plane, or never got
 * an answer. Only these, and only for a journey the STOP interrupted, are treated as explained by the STOP (and counted).
 */
const INTERRUPTION_CODES: ReadonlySet<string> = new Set(["ingress_loss", "sent_without_completion", "disappeared_after_ingress", "unresolved_at_finalization"]);

/** Maps what the collector's finalization found to reasons, by class. */
function anomalyReasons(anomalies: readonly Anomaly[], total: number): Reason[] {
  const reasons: Reason[] = [];
  const seen = new Set<string>();
  const add = (reason: Reason) => { const key = `${reason.code}:${reason.detail ?? ""}`; if (!seen.has(key)) { seen.add(key); reasons.push(reason); } };
  for (const anomaly of anomalies) {
    const code = anomaly.code;
    if (/^(app_admit_without_lineage|app_execution_without_lineage|app_mutation_without_lineage|direct_app_|unattributed_app_|origin_without_l1_pass|plane_egress_not_admitted|boundary_rejected_plane_egress)/.test(code)) add({ code: "app_bypass", detail: code });
    else if (/^(plane_crashed|boundary_crashed|app_crashed)$/.test(code)) add({ code: "process_crash", detail: code });
    else if (/channel_loss|duplicate_sequence|plane_not_finalized|boundary_not_finalized|app_not_finalized|late_event_after_finalization/.test(code)) add({ code: "evidence_gap", detail: code });
    else if (code === "journal_overflow" || code === "ledger_capacity_exceeded") add({ code: "journal_overflow", detail: code });
    else if (code === "external_state_overflow") add({ code: "external_state_overflow" });
    else add({ code: "ledger_anomaly", detail: code });
  }
  if (total > anomalies.length) add({ code: "ledger_anomaly", detail: `${total} anomalies in total` });
  return reasons;
}

/** Maps a failing identity id to the reason it raises. */
function identityReason(id: string): Reason {
  if (id.startsWith("e8.")) return { code: "unattributed_503", detail: id };
  if (id === "e7.external_mutations_within_unverified_budget" || id === "e7.external_credited_mutations_zero" || id === "e7.external_open_or_unlaned_mutations_zero") return { code: "mutation_over_budget", detail: id };
  if (id.startsWith("e11.")) return { code: "generator_in_flight_exceeded", detail: id };
  if (id.startsWith("e9.") || id.startsWith("e1.") || id === "e3.egress_failed_is_zero") return { code: "unexplained_traffic", detail: id };
  if (id.startsWith("e10.")) return { code: "evidence_gap", detail: id };
  return { code: "identity_failed", detail: id };
}

export async function runFieldLevel(args: FieldLevelArgs, seams: FieldRunSeams = {}): Promise<FieldRunOutcome> {
  const level = fieldLevel(args.levelId);
  const t = seams.thresholds ?? level?.thresholds ?? BA0_FIELD_V1;
  const log = seams.log ?? (() => undefined);
  const clock = () => performance.now();
  const wallNow = seams.now ?? (() => new Date());
  const startedAt = wallNow();
  const env = seams.env ?? realFieldEnvironment();
  const git = seams.git ?? collectGitState();
  const machine = new FieldMachine(clock);
  const evidence = new EvidenceRun("field-level", args.levelId.slice(0, 30) || "level", startedAt, seams.evidenceRoot ?? EVIDENCE_ROOT);
  const fingerprint = ba0FieldFingerprint(t);
  const workload = WORKLOADS[level?.workload ?? "ba0-l7-pressure-c1"];
  const workloadHash = workloadFingerprint(workload);
  const lockFile = seams.lockFile ?? path.join(REPOSITORY_ROOT, "artifacts", "lab", "field-run.lock");
  let lockHeld = false;

  const refusedOutcome = (refusals: string[], preflight: PreflightResult | null): FieldRunOutcome => {
    machine.refuse({ code: "preflight_refused", detail: refusals.slice(0, 3).join(",").slice(0, 120) });
    try {
      evidence.addJsonArtifact("core.json", { level: { id: args.levelId, campaignId: args.campaignId }, serverSide: { status: "aborted", failureClass: "operational", reasons: [{ code: "preflight_refused" }] }, refused: refusals.slice(0, 40), networkActivity: false, finalVerdict: "not_decided_here" });
      if (preflight) evidence.addJsonArtifact("preflight.json", { ok: preflight.ok, checks: preflight.checks, ambientNonLoopbackPorts: preflight.ambientNonLoopbackPorts });
    } catch { /* the refusal itself is what matters */ }
    evidence.finalize({
      git, environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: fingerprint, engine: "node-http-field-level", result: "REFUSED",
      resultReasons: refusals.slice(0, 20).map((reason) => `field.${reason}`.slice(0, 200)), metrics: { serverSide: "aborted", networkActivity: false, defenseQualification: "not_claimed" },
    });
    return { exit: FIELD_EXIT.refused, status: "refused", serverSide: null, refusals, evidenceId: evidence.id, evidenceDirectory: evidence.directory, bundle: null, write: null };
  };

  // =========================================================================================== PREFLIGHT
  machine.advance("PREFLIGHT");
  if (level === undefined || args.levelId !== t.level.id) return refusedOutcome(["level_not_reviewed"], null);
  let authorization: AuthorizationLike;
  try {
    authorization = seams.authorization ?? authorizeRun({
      targetId: args.targetId, workloadId: level.workload, registry: seams.registry ?? buildRegistry(loadOperatorTargets(), startedAt), now: startedAt,
      treeIsClean: seams.treeIsClean ?? !git.dirty,
    });
  } catch (error) {
    return refusedOutcome([error instanceof PolicyRefusal ? `policy_${error.code}` : "authorization_failed"], null);
  }
  let ingress: IngressBind;
  try { ingress = validateIngressBind({ ip: authorization.target.host, port: authorization.target.port }); } catch { return refusedOutcome(["bind_invalid"], null); }
  const remaining = authorization.authorizedUntilMs === null ? null : authorization.authorizedUntilMs - wallNow().getTime();
  const gates = evaluateBudgetGates(t, remaining);
  const preflight = await runFieldPreflight({
    env, thresholds: t, plane: ingress, treeIsClean: seams.treeIsClean ?? !git.dirty, budgetGates: gates,
    allowLoopbackIngress: seams.allowLoopbackIngress, skipPlatformCheck: seams.skipPlatformCheck,
  });
  if (!preflight.ok) return refusedOutcome(preflight.checks.filter((entry) => !entry.ok).map((entry) => entry.id), preflight);
  // A single-instance lock: a stale lock refuses (the operator removes it after looking), it is never taken over.
  try {
    mkdirSync(path.dirname(lockFile), { recursive: true });
    writeFileSync(lockFile, `${process.pid}\n`, { flag: "wx" });
    lockHeld = true;
  } catch { return refusedOutcome(["lock_held_or_stale"], preflight); }

  // ====================================================================================== runtime state
  const baselineAmbient = preflight.ambientNonLoopbackPorts;
  const collector = new Collector(path.join(evidence.directory, "ledger-journal-field.ndjson"), { ...t.collector });
  const salvo = args.levelId === "ba0-l7-c2-salvo" ? new SalvoServerObserver(n2ExerciseSpec(t)) : undefined;
  const n2 = args.levelId === "ba0-l7-c2" ? new N2ServerObserver(n2ExerciseSpec(t)) : salvo;
  collector.enableOriginStreams();
  collector.enableLaneStreams();
  const reducer = new ExternalReducer({ limits: t.external, allowedShed: t.allowedShed, now: clock, report: (code, rid, detail) => collector.externalAnomaly(code, rid, detail) });
  collector.enableExternalLane(reducer);
  const monitor = new TickMonitor(t, clock);
  const root = new HopTrustRoot();
  const control = createSyntheticOrigin({ instance: "control", onObservation: (event) => collector.ingestOrigin(event) });
  let plane: PlaneProcess | null = null;
  let boundary: FieldBoundaryProcess | null = null;
  let app: FieldAppProcess | null = null;
  let controlPort = 0;
  let pids: TopologyPids = { runner: process.pid };
  let procSampler: ProcSampler | null = null;
  const harnessSampler = new ProcessSampler();
  let latestPlane = null as PlaneTick | null;
  let externalInFlightMax = 0;
  let ingressCloseRequested = false;
  let ingressCloseAcked = false;
  let exposureChecks = 0;
  const exposureViolations = new Set<string>();
  let lastAnomalyCount = 0;
  const peaks: Record<string, number> = { hostCpuBusyPct: 0, planeEldP99Ms: 0, harnessEldP99Ms: 0, planeRssMb: 0, boundaryRssMb: 0, appRssMb: 0, runnerRssMb: 0, planeFds: 0, tcpInUse: 0 };
  const journeys: JourneyResult[] = [];
  const scheduleLags: number[] = [];
  let armedAtMs = 0;
  let windowOpenedAtMs: number | null = null;
  let windowOpenedWall: Date | null = null;
  let windowClosedWall: Date | null = null;
  let windowClosedAtMs: number | null = null;
  let acceptedAtWindowClose: number | null = null;
  let windowClosing = false;
  const stepFailures: Record<string, number> = {};
  /**
   * Canary journeys that were still running when a STOP began (or began after it). The STOP closes the public ingress at once, so such a journey's
   * later requests are refused BY THE STOP ITSELF: that is explained by the reason already latched, not a new failure of the defense or of the
   * measurement. They are excluded from the journey completion rate and from the interruption-shaped anomalies, and COUNTED in the evidence.
   */
  const interruptedKeys = new Set<string>();
  let recovery = { quietMs: t.recovery.quietMs, checked: false, ok: false, detail: "not reached" };
  let finalExposure: ExposureResult | null = null;
  let tickTimer: NodeJS.Timeout | null = null;
  let tickBusy = false;
  let signalReceived = false;
  let phasesCompleted = false;
  const sequenceResults: StepResult[] = [];
  let boundaryFinal: BoundaryFin | null = null;
  let appFinal: AppFin | null = null;
  let planeFinal: PlaneFin | null = null;
  let finalOutcome: FieldRunOutcome | null = null;

  const latch = (reason: Reason, stops = true): void => {
    machine.latch(reason, stops);
    if (machine.stopped && !ingressCloseRequested) { ingressCloseRequested = true; plane?.sendControl({ type: "close_ingress" }); }
  };
  const latchAll = (reasons: readonly Reason[], stops = true): void => { for (const reason of reasons) latch(reason, stops); };
  if (n2) collector.observePlaneEvents((event) => {
    n2.observe(event);
    if (n2.earlyIngress > 0) latch({ code: "identity_failed", detail: "n2_pre_armed_ingress" });
  });

  const checkExposure = (mode: "running" | "final"): ExposureResult => proveExposure({
    reader: env.reader, mode, pids, plane: ingress,
    // The plane must be listening until its ingress is closed; once the close was ACKNOWLEDGED it must be gone; between the request and the ack neither is required.
    expectPlaneListening: mode === "running" && !ingressCloseAcked, planeMayBeClosing: mode === "running" && ingressCloseRequested && !ingressCloseAcked,
    ambientAllowedPorts: t.exposure.ambientAllowedPorts, forbiddenAmbientPorts: t.exposure.forbiddenAmbientPorts, baselineAmbientPorts: baselineAmbient, fullScan: mode === "final",
  });

  const windowElapsedMs = (): number => (windowOpenedAtMs === null ? 0 : (windowClosedAtMs ?? clock()) - windowOpenedAtMs);

  /** One second of observation. Never throws; a failure to observe is a measurement reason, not a crash. */
  const tickOnce = async (): Promise<void> => {
    if (tickBusy) return;
    tickBusy = true;
    try {
      const harness = harnessSampler.sample();
      const proc = procSampler === null ? { perRole: {}, host: null } : procSampler.sample({ runner: process.pid, ...(pids.plane ? { plane: pids.plane } : {}), ...(pids.boundary ? { boundary: pids.boundary } : {}), ...(pids.app ? { app: pids.app } : {}) });
      peaks.harnessEldP99Ms = Math.max(peaks.harnessEldP99Ms, harness.eldP99Ms);
      if (proc.host) { peaks.hostCpuBusyPct = Math.max(peaks.hostCpuBusyPct, proc.host.cpuBusyPct); peaks.tcpInUse = Math.max(peaks.tcpInUse, proc.host.tcpInUse); }
      for (const [role, key] of [["runner", "runnerRssMb"], ["plane", "planeRssMb"], ["boundary", "boundaryRssMb"], ["app", "appRssMb"]] as const) peaks[key] = Math.max(peaks[key], proc.perRole[role]?.rssMb ?? 0);
      peaks.planeFds = Math.max(peaks.planeFds, proc.perRole.plane?.fds ?? 0);
      latchAll(monitor.observeHarness({ eldP99Ms: harness.eldP99Ms, eldMaxMs: harness.eldMaxMs, proc }));
      latchAll(monitor.checkSilence());

      // D1: the exposure proof, every tick
      if (pids.plane !== undefined && machine.state !== "DONE") {
        const exposure = checkExposure("running");
        exposureChecks++;
        if (!exposure.ok) {
          for (const violation of exposure.violations) exposureViolations.add(violation);
          latch({ code: exposure.violations.includes("proc_unreadable") || exposure.violations.includes("netns_unproven") ? "exposure_unproven" : "exposure_violation", detail: exposure.violations.slice(0, 4).join(",") });
        }
      }
      // Crashes
      const crashed = [collector.channel.crashed, collector.boundaryInfo.crashed, collector.appInfo.crashed].some((entry) => entry !== null);
      if (crashed) latch({ code: "process_crash" });
      // The target authorization lapsing is an operational end
      try { authorization.assertStillAuthorized(); } catch { latch({ code: "target_expired" }); }
      // Live rules over the external lane
      const counters = reducer.counters();
      if (counters.status503.unexplained > 0) latch({ code: "unattributed_503", detail: `${counters.status503.unexplained} unexplained` });
      if (counters.status5xxOther > 0) latch({ code: "unexplained_traffic", detail: `${counters.status5xxOther} 5xx` });
      if (windowOpenedAtMs !== null && counters.app.mutated > unverifiedMutationBound(t.l2, windowElapsedMs() + 2_000)) latch({ code: "mutation_over_budget", detail: `${counters.app.mutated} external mutations` });
      if (externalInFlightMax > t.level.workers) latch({ code: "generator_in_flight_exceeded", detail: `server saw ${externalInFlightMax}` });
      if (collector.anomalyTotalSoFar > lastAnomalyCount) { lastAnomalyCount = collector.anomalyTotalSoFar; latch({ code: "ledger_anomaly", detail: `${lastAnomalyCount} anomalies so far` }); }
      if (acceptedAtWindowClose !== null && counters.accepted > acceptedAtWindowClose) latch({ code: "traffic_in_quiet", detail: `${counters.accepted - acceptedAtWindowClose} external requests after the window` });
      reducer.sweep();
    } catch (error) {
      latch({ code: "runner_internal_error", detail: evidenceSafeError(error).slice(0, 120) });
    } finally { tickBusy = false; }
  };

  const onTick = (tick: Tick<unknown>): void => {
    latchAll(monitor.observe(tick));
    if (tick.role === "plane") {
      latestPlane = tick as PlaneTick;
      externalInFlightMax = Math.max(externalInFlightMax, latestPlane.data.inFlightExternalMax, latestPlane.data.external.inFlightHighWater);
      peaks.planeEldP99Ms = Math.max(peaks.planeEldP99Ms, tick.sample.eldP99Ms);
    }
  };

  // Operator signals end the level orderly, never abruptly.
  const onSignal = (): void => { signalReceived = true; latch({ code: "operator_abort" }); };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  process.on("SIGHUP", onSignal);
  seams.abort?.addEventListener("abort", onSignal, { once: true });

  // ==================================================================================== canary scheduling
  const canaryPhase = async (phase: string, options: { count?: number; until?: () => boolean; gapMs: number; withControl: boolean }): Promise<void> => {
    let index = 0;
    let next = clock();
    while (machine.canStartWork() && (options.count === undefined || index < options.count) && !(options.until?.() ?? false)) {
      const wait = next - clock();
      if (wait > 0) await sleep(wait);
      if (!machine.canStartWork() || (options.until?.() ?? false)) break;
      scheduleLags.push(Math.max(0, clock() - next));
      index++;
      if (options.withControl) journeys.push(await runFieldJourney(collector, { lane: "control", host: "127.0.0.1", port: controlPort, phase, journey: index, timeoutMs: t.canary.timeoutMs }));
      const journey = await runFieldJourney(collector, { lane: "protected", host: ingress.ip, port: ingress.port, phase, journey: index, timeoutMs: t.canary.timeoutMs });
      journeys.push(journey);
      const interrupted = machine.stopped;
      if (interrupted) interruptedKeys.add(`${phase}/${index}`);
      if (!journey.completed && !interrupted) {
        for (const step of journey.steps) if (!step.ok && step.failure !== null) stepFailures[`${phase}.${step.failure}`.slice(0, 60)] = (stepFailures[`${phase}.${step.failure}`.slice(0, 60)] ?? 0) + 1;
        if (journey.steps.some((step) => step.failure?.startsWith("status_"))) latch({ code: "legitimate_refusal", detail: `${phase} journey ${index}` });
        latch({ code: "jcr_below_minimum", detail: `${phase} journey ${index}` });
      }
      next += options.gapMs;
    }
  };

  /** Waits while the level can continue. Returns false when a STOP began. */
  const waitFor = async (ms: number, done?: () => boolean): Promise<boolean> => {
    const until = clock() + ms;
    while (clock() < until && machine.canStartWork()) { if (done?.() ?? false) return true; await sleep(Math.min(100, Math.max(1, until - clock()))); }
    return machine.canStartWork();
  };

  // ======================================================================== finalization (shared by both paths)
  const finalize = async (): Promise<FieldRunOutcome> => {
    const steps: SequenceStep[] = [
      { name: "close_ingress", budgetMs: t.stop.closeIngressMs, essential: false, before: () => { if (machine.stopped && machine.state === "STOPPING") machine.advance("DRAINING"); else if (!machine.stopped && machine.state === "RECOVERY") machine.advance("FINALIZING"); },
        run: async () => {
          if (!ingressCloseRequested) { ingressCloseRequested = true; plane?.sendControl({ type: "close_ingress" }); }
          const until = clock() + t.stop.closeIngressMs;
          while (!ingressCloseAcked && clock() < until && plane !== null && !plane.hasExited) await sleep(20);
        } },
      { name: "drain", budgetMs: t.stop.drainMs, essential: false,
        run: async () => {
          // accepted work first (the reducer's open requests), then the processes' own queues
          const until = clock() + t.stop.drainMs / 2;
          while ((reducer.activeCount > 0) && clock() < until) await sleep(50);
          const [p, b, a] = await Promise.all([plane?.finish(t.stop.drainMs / 2) ?? null, boundary?.finish(t.stop.drainMs / 2) ?? null, app?.finish(t.stop.drainMs / 2) ?? null]);
          planeFinal = p; boundaryFinal = b; appFinal = a;
        } },
      { name: "final_telemetry", budgetMs: t.stop.finalTelemetryMs, essential: false,
        before: () => { if (machine.stopped && machine.state === "DRAINING") machine.advance("SNAPSHOT"); },
        run: async () => { await sleep(200); /* the final ticks travel with the fin results; let them arrive */ } },
      { name: "snapshot", budgetMs: t.stop.snapshotMs, essential: false,
        run: async () => {
          if (pids.plane !== undefined) { finalExposure = checkExposure("final"); if (!finalExposure.ok) for (const violation of finalExposure.violations) exposureViolations.add(violation); }
        },
        before: () => { if (machine.stopped && machine.state === "SNAPSHOT") machine.advance("FINALIZING"); } },
      { name: "finalize_evidence", budgetMs: t.stop.finalizeMs, essential: true,
        run: async () => { finalOutcome = await writeEvidence(); } },
      { name: "terminate", budgetMs: t.stop.terminateMs, essential: true,
        run: async () => {
          await Promise.allSettled([plane?.stop(t.stop.terminateMs - 1_000), boundary?.stop(t.stop.terminateMs - 1_000), app?.stop(t.stop.terminateMs - 1_000)]);
          await control.close().catch(() => undefined);
        } },
    ];
    await runSequence(steps, t.stop.hardCapMs, clock, sequenceResults);
    if (tickTimer) clearInterval(tickTimer);
    if (machine.state !== "DONE") { try { machine.advance("DONE"); } catch { /* already terminal */ } }
    return finalOutcome ?? { exit: FIELD_EXIT.error, status: "error", serverSide: null, refusals: [], evidenceId: evidence.id, evidenceDirectory: evidence.directory, bundle: null, write: null };
  };

  // ============================================================= assessment, verdict, evidence
  const writeEvidence = async (): Promise<FieldRunOutcome> => {
    collector.freeze();
    await sleep(100);
    const { anomalies, anomalyTotal } = collector.finalize();
    const journal = await collector.closeJournal().catch(() => null);
    const records = [...collector.allRecords()];
    const counters = reducer.counters();
    const reasons: Reason[] = [];

    // ---- canary
    const uninterrupted = journeys.filter((journey) => !(journey.lane === "protected" && interruptedKeys.has(`${journey.phase}/${journey.journey}`)));
    const rates = journeyCompletionRates(uninterrupted);
    for (const entry of rates) if (entry.rate < t.canary.jcrMinimum) reasons.push({ code: entry.phase === "recovery" ? "recovery_failed" : entry.phase === "residual" ? "residual_denial" : "jcr_below_minimum", detail: `${entry.lane}.${entry.phase}` });
    const protectedRecords = records.filter((record) => record.meta.lane === "protected" && record.meta.cls === "canary" && !interruptedKeys.has(`${record.meta.phase}/${record.meta.journey}`));
    let l1FalseRejects = 0; let l2NonAdmits = 0;
    for (const record of protectedRecords) {
      if (record.plane.some((event) => event.kind === "L1_REJECTED")) l1FalseRejects++;
      const decided = record.plane.find((event) => event.kind === "L2_DECIDED");
      if (decided && decided.outcome !== "admitted") l2NonAdmits++;
    }
    if (l1FalseRejects > 0) reasons.push({ code: "l1_false_reject", detail: `${l1FalseRejects}` });
    if (l2NonAdmits > 0) reasons.push({ code: "l2_legitimate_non_admit", detail: `${l2NonAdmits}` });
    const parityJourneys = uninterrupted.filter((journey) => journey.phase === "baseline" || journey.phase === "recovery");
    const parity = compareParity(parityJourneys);
    if (parity.mismatches.length > 0) reasons.push({ code: "parity_mismatch", detail: `${parity.mismatches.length}` });
    const protectedSteps = (phase: string) => journeys.filter((journey) => journey.lane === "protected" && journey.phase === phase).flatMap((journey) => journey.steps.map((step) => step.latencyMs));
    const latency = Object.fromEntries(["baseline", "window", "residual", "recovery"].map((phase) => { const s = summarizeLatencies(protectedSteps(phase)); return [phase, { count: s.count, p50: s.p50, p95: s.p95, p99: s.p99, max: s.max }]; }));
    let windowLatencyOk: boolean | null = null;
    if (latency.baseline.count > 0 && latency.window.count > 0) {
      windowLatencyOk = latency.window.p95 <= Math.max(t.canary.windowLatency.p95Factor * latency.baseline.p95, latency.baseline.p95 + t.canary.windowLatency.p95AddedMs);
      if (!windowLatencyOk) reasons.push({ code: "latency_envelope_exceeded", detail: `window p95 ${latency.window.p95} ms vs baseline p95 ${latency.baseline.p95} ms` });
    }
    const lagSummary = summarizeLatencies(scheduleLags);
    const harnessEld = monitor.harnessEld();
    if (lagSummary.p99 > t.canary.scheduleLagP99Ms || harnessEld.highTicks > 0) reasons.push({ code: "canary_starved", detail: `schedule lag p99 ${lagSummary.p99} ms, harness event-loop ticks over the limit ${harnessEld.highTicks}` });
    const clientObservedMutations = journeys.filter((journey) => journey.lane === "protected" && journey.steps[3]?.ok === true).length;
    const canary: CanarySummary = {
      jcr: rates, journeys: journeys.length, legitimateRefusals: Object.entries(stepFailures).filter(([key]) => /status_/.test(key)).reduce((total, [, value]) => total + value, 0), l1FalseRejects, l2NonAdmits,
      parityMismatches: parity.mismatches.length, parityCompared: parity.compared,
      scheduleLagMs: { count: lagSummary.count, p50: lagSummary.p50, p95: lagSummary.p95, p99: lagSummary.p99, max: lagSummary.max },
      latencyMs: latency, windowLatencyOk, stepFailures, clientObservedMutations, interruptedJourneys: interruptedKeys.size,
    };

    // ---- the external accounting
    const lastPlane = latestPlane as PlaneTick | null;
    const connections = lastPlane === null ? null : {
      acceptedLocal: lastPlane.data.connections.accepted.local, acceptedRemote: lastPlane.data.connections.accepted.remote,
      closedClean: lastPlane.data.connections.closed.clean, closedError: lastPlane.data.connections.closed.error, active: lastPlane.data.connections.active,
      dropped: lastPlane.data.connections.dropped, clientErrorTotal: Object.values(lastPlane.data.connections.clientError).reduce((total, value) => total + value, 0) + lastPlane.data.connections.clientErrorOverflow,
      clientErrorNoRequest: lastPlane.data.connections.clientErrorNoRequest,
      protocolRefused: lastPlane.data.connections.protocolRefused.connect + lastPlane.data.connections.protocolRefused.expectation, parserRejected: lastPlane.data.front.parserRejected,
    };
    let accounting: ExternalAccountingReport | null = null;
    try {
      accounting = deriveExternalAccounting({
        external: counters, externalDecisions: reducer.decisions(), canary: canaryCounts(records, clientObservedMutations), planeFin: planeFinal, boundaryFin: boundaryFinal, appFin: appFinal,
        connections, l2: t.l2, windowElapsedMs: windowElapsedMs() + 2_000, workers: t.level.workers, externalInFlightMax,
        streams: {
          planeDropped: planeFinal?.channel.dropped ?? 0, boundaryDropped: boundaryFinal?.channel.dropped ?? 0, appDropped: appFinal?.channel.dropped ?? 0,
          drained: planeFinal?.drained === true && boundaryFinal?.drained === true && appFinal?.drained === true, finalTicks: monitor.finalTicks(), tickGaps: monitor.tickGaps,
        },
      });
      for (const entry of accounting.identities) if (!entry.ok) reasons.push(identityReason(entry.id));
    } catch (error) { reasons.push({ code: "runner_internal_error", detail: `accounting ${evidenceSafeError(error)}`.slice(0, 120) }); }

    // ---- collector, telemetry, exposure, crashes
    const interruptedRids = new Set(records.filter((record) => record.meta.lane === "protected" && interruptedKeys.has(`${record.meta.phase}/${record.meta.journey}`)).map((record) => record.rid));
    const explainedByStop = anomalies.filter((anomaly) => anomaly.nonce !== null && interruptedRids.has(anomaly.nonce) && INTERRUPTION_CODES.has(anomaly.code));
    const remaining = anomalies.filter((anomaly) => !explainedByStop.includes(anomaly));
    reasons.push(...anomalyReasons(remaining, anomalyTotal - explainedByStop.length));
    reasons.push(...monitor.finalReasons());
    if (finalExposure !== null && !(finalExposure as ExposureResult).ok) reasons.push({ code: "exposure_violation", detail: (finalExposure as ExposureResult).violations.slice(0, 4).join(",") });
    if (exposureViolations.size > 0) reasons.push({ code: "exposure_violation", detail: [...exposureViolations].slice(0, 4).join(",") });
    if (collector.channel.crashed !== null || collector.boundaryInfo.crashed !== null || collector.appInfo.crashed !== null) reasons.push({ code: "process_crash" });
    if (journal?.overflow === true) reasons.push({ code: "journal_overflow" });
    if (!recovery.ok && recovery.checked) reasons.push({ code: "recovery_failed", detail: recovery.detail.slice(0, 100) });
    const latched = machine.allReasons().map((entry): Reason => ({ code: entry.code, ...(entry.detail !== undefined ? { detail: entry.detail } : {}) }));
    const all: Reason[] = [...latched];
    for (const reason of reasons) if (!all.some((entry) => entry.code === reason.code && entry.detail === reason.detail)) all.push(reason);
    const serverSide = decideServerSide(all, phasesCompleted);

    const reconcileInput: ServerLevelEvidence["reconcileInput"] = {
      externalAccepted: counters.accepted, statusHistogram: counters.statusHistogram,
      status503: { total: counters.status503.total, expectedShed: counters.status503.expectedShed, unexplained: counters.status503.unexplained },
      classes: counters.l2.classes, l1Rejected: counters.l1.rejected, egressFailed: counters.egress.failed,
      connections: { acceptedRemote: connections?.acceptedRemote ?? 0, dropped: connections?.dropped ?? 0, clientErrorTotal: connections?.clientErrorTotal ?? 0, clientErrorNoRequest: connections?.clientErrorNoRequest ?? 0, parserRejected: connections?.parserRejected ?? 0, protocolRefused: connections?.protocolRefused ?? 0 },
      externalInFlightMax,
    };
    // Informational sibling artifact, computed AFTER the server-side decision from journeys already collected. Nothing below reads it back.
    const canaryContinuity = salvo ? buildCanaryContinuity(journeys, interruptedKeys) : undefined;
    const bundle: FieldEvidenceBundle = {
      level: { id: args.levelId, campaignId: args.campaignId, workers: t.level.workers }, parameters: fingerprint, workloadSha256: workloadHash, thresholds: t, git,
      serverSide, firstReason: machine.firstReason, reasons: machine.allReasons(), machine: { transitions: machine.transitions(), phasesCompleted }, sequence: sequenceResults,
      preflight, exposure: { running: { checks: exposureChecks, violations: [...exposureViolations] }, final: finalExposure },
      window: windowOpenedWall && windowClosedWall ? { openedAt: windowOpenedWall.toISOString(), closedAt: windowClosedWall.toISOString(), elapsedMs: Math.round(windowElapsedMs()) } : null,
      external: counters, accounting, traces: reducer.traces(), canary,
      telemetry: { gaps: monitor.tickGaps, gapDetails: monitor.gapDetails(), finalTicks: monitor.finalTicks(), ring: monitor.ring(), harnessEld, peaks },
      connections, externalInFlightMax, processes: { plane: planeFinal, boundary: boundaryFinal, app: appFinal },
      collector: { anomalyTotal, anomalies, records: records.length, journal }, recovery, reconcileInput, anonymousRefusals: reducer.anonymousRefusals(),
      ...(args.levelId === "ba0-l7-c2" && n2 ? { n2: n2.snapshot() } : {}),
      ...(salvo ? { salvo: salvo.snapshotSalvo() } : {}),
      ...(salvo ? { salvoDiagnostics: salvo.snapshotDiagnostics() } : {}),
      ...(canaryContinuity ? { canaryContinuity } : {}),
    };
    const write = writeFieldEvidence(evidence, bundle);
    const status = serverSide.status;
    evidence.finalize({
      git, environment: collectEnvironment(),
      target: { id: authorization.target.id, class: authorization.target.class, scheme: authorization.target.scheme, port: authorization.target.port, ownership: "operator-asserted" },
      workload: { id: workload.id, phases: workload.phases }, ceilings: { level: t.level.id, workers: t.level.workers, maxTotalRequests: t.level.maxTotalRequests, maxRequestsPerSecond: t.level.maxRequestsPerSecond, durationSeconds: t.level.durationSeconds },
      thresholds: fingerprint, engine: "node-http-field-level", result: status === "complete" ? "SERVER-COMPLETE" : status === "invalid" ? "INVALID" : "ABORTED",
      resultReasons: serverSide.reasons.map((reason) => `field.${reason.code}${reason.detail ? `.${reason.detail.replace(/[^A-Za-z0-9_.-]/g, "_")}` : ""}`.slice(0, 200)),
      metrics: {
        scope: "see core.json", serverSide: status, failureClass: serverSide.failureClass, finalVerdict: "not_decided_here", defenseQualification: "not_claimed",
        networkNonBypass: "not_measured", originNetworkIsolation: "not_measured", artifactsWritten: write.written.length, artifactsRefused: write.failed.length,
        externalAccepted: counters.accepted, anomalyTotal,
      },
    });
    return { exit: status === "complete" ? FIELD_EXIT.complete : status === "invalid" ? FIELD_EXIT.invalid : FIELD_EXIT.aborted, status, serverSide, refusals: [], evidenceId: evidence.id, evidenceDirectory: evidence.directory, bundle, write };
  };

  // ============================================================================================ run
  try {
    // ---- TOPOLOGY_UP
    machine.advance("TOPOLOGY_UP");
    controlPort = await control.listen();
    const telemetry = { tickMs: t.telemetry.tickMs };
    app = await FieldAppProcess.start(collector, { ...root.appInit({ replayCapacity: t.hop.replayCapacity, bodyDeadlineMs: t.hop.bodyDeadlineMs }, t.channel), telemetry }, (tick: AppTick) => onTick(tick));
    boundary = await FieldBoundaryProcess.start(collector, {
      ...root.boundaryInit(app.port, { replayCapacity: t.hop.replayCapacity, bodyDeadlineMs: t.hop.bodyDeadlineMs, forwardTimeoutMs: t.hop.forwardTimeoutMs, baLifetimeMs: t.hop.baLifetimeMs }, t.channel), telemetry,
    }, (tick: BoundaryTick) => onTick(tick));
    plane = await PlaneProcess.start(collector, {
      upstreamPort: boundary.port, bodyDeadlineMs: t.plane.bodyDeadlineMs, egressTimeoutMs: t.plane.egressTimeoutMs,
      composer: { timeoutMs: t.composer.timeoutMs, maxConcurrent: t.composer.maxConcurrent, failurePolicy: "fail_closed" }, channel: t.channel,
      hop: root.planeInit(t.hop.pbLifetimeMs), l2: t.l2, ingress, telemetry,
    }, 20_000, PLANE_L2_ENTRY);
    plane.onExtra((message) => {
      if (message.type === "tick") onTick(message as unknown as Tick<unknown>);
      else if (message.type === "ingress_closed") { ingressCloseAcked = (message as unknown as { closed?: boolean }).closed === true; if (ingressCloseAcked) seams.onIngressClosed?.(); }
    });
    pids = { runner: process.pid, plane: plane.pid, boundary: boundary.pid, app: app.pid };
    procSampler = new ProcSampler(env.reader);
    seams.onTopology?.({ pids, ports: { plane: plane.port, boundary: boundary.port, app: app.port, control: controlPort }, ingress });
    tickTimer = setInterval(() => { void tickOnce(); }, t.telemetry.tickMs);
    await tickOnce();
    log(`topology up; exposure checks ${exposureChecks}`);

    // ---- BASELINE
    if (machine.canStartWork()) {
      machine.advance("BASELINE");
      await canaryPhase("baseline", { count: t.canary.baselineJourneys, gapMs: t.canary.gapMs, withControl: true });
    }
    // ---- ARMED
    if (machine.canStartWork() && n2) {
      const mark = await plane.measurementBarrier("armed", t.window.setupAllowanceMs);
      if (mark === null) latch({ code: "evidence_gap", detail: "n2_armed_barrier" });
      else {
        n2.arm(mark);
        if (mark.acceptedExternal !== 0 || mark.inFlightExternal !== 0) latch({ code: "identity_failed", detail: "n2_pre_armed_ingress" });
      }
    }
    if (machine.canStartWork()) {
      machine.advance("ARMED");
      armedAtMs = clock();
      log(`ARMED level ${args.levelId} campaign ${args.campaignId}: start the authorized generator now (${Math.round(t.window.startSlackMs / 1000)} s allowed)`);
      seams.onArmed?.({ ingress });
      const manual = seams.manualWindow;
      const opened = await waitFor(t.window.startSlackMs, () => (manual ? clock() - armedAtMs >= manual.openAfterMs : reducer.counters().accepted > 0));
      if (opened && !machine.stopped && !(manual ? clock() - armedAtMs >= manual.openAfterMs : reducer.counters().accepted > 0)) latch({ code: "generator_not_started" });
      else if (!opened && machine.canStartWork()) latch({ code: "generator_not_started" });
    }
    // ---- WINDOW
    if (machine.canStartWork()) {
      machine.advance("WINDOW");
      windowOpenedAtMs = clock();
      windowOpenedWall = wallNow();
      monitor.setWindowActive(true);
      let lastChangeAt = clock();
      let lastAccepted = reducer.counters().accepted;
      const canaryRun = canaryPhase("window", { until: () => windowClosing, gapMs: t.canary.gapMs, withControl: false });
      while (machine.canStartWork() && !windowClosing) {
        await sleep(100);
        const accepted = reducer.counters().accepted;
        if (accepted !== lastAccepted) { lastAccepted = accepted; lastChangeAt = clock(); }
        const quiet = !seams.manualWindow && accepted > 0 && clock() - lastChangeAt >= t.window.quiescenceMs && reducer.activeCount === 0 && (latestPlane?.data.external.inFlight ?? 0) === 0;
        const manualDone = seams.manualWindow !== undefined && clock() - windowOpenedAtMs >= seams.manualWindow.closeAfterMs - seams.manualWindow.openAfterMs;
        if (quiet || manualDone || clock() >= armedAtMs + t.window.hardDeadlineMs) windowClosing = true;
      }
      windowClosing = true;
      await canaryRun;
      if (n2) {
        const mark = await plane.measurementBarrier("closed", t.window.drainAllowanceMs);
        if (mark === null) latch({ code: "evidence_gap", detail: "n2_closed_barrier" });
        else {
          n2.close(mark);
          if (mark.inFlightExternal !== 0) latch({ code: "identity_failed", detail: "n2_undrained_window" });
        }
      }
      windowClosedWall = wallNow();
      windowClosedAtMs = clock();
      acceptedAtWindowClose = reducer.counters().accepted;
      monitor.setWindowActive(false);
    }
    // ---- RESIDUAL
    if (machine.canStartWork()) {
      machine.advance("RESIDUAL");
      await canaryPhase("residual", { count: t.canary.residualJourneys, gapMs: t.canary.residualGapMs, withControl: false });
    }
    // ---- QUIET (D4: derived from the parameter set; the canary is silent)
    if (machine.canStartWork()) {
      machine.advance("QUIET");
      await waitFor(t.recovery.quietMs);
    }
    // ---- RECOVERY
    if (machine.canStartWork()) {
      machine.advance("RECOVERY");
      const seenSeq = (latestPlane as PlaneTick | null)?.tickSeq ?? 0;
      await waitFor(5_000, () => ((latestPlane as PlaneTick | null)?.tickSeq ?? 0) >= seenSeq + 2);
      const state = (latestPlane as PlaneTick | null)?.data.l2.lanes;
      if (state) {
        const credited = state.credited.levelUnits >= state.credited.capacity * UNIT;
        const unverified = state.unverified.levelUnits >= state.unverified.capacity * UNIT;
        const credits = state.filter.popcount[0] === 0 && state.filter.popcount[1] === 0 && state.ledger.size === 0;
        recovery = { quietMs: t.recovery.quietMs, checked: true, ok: credited && unverified && credits, detail: `credited bucket full ${credited}, unverified bucket full ${unverified}, live credits zero ${credits}` };
        if (!recovery.ok) latch({ code: "recovery_failed", detail: recovery.detail });
      } else { recovery = { quietMs: t.recovery.quietMs, checked: false, ok: false, detail: "no plane tick after the quiet interval" }; latch({ code: "recovery_failed", detail: recovery.detail }); }
      await canaryPhase("recovery", { count: t.canary.recoveryJourneys, gapMs: t.canary.gapMs, withControl: true });
      phasesCompleted = !machine.stopped;
    }
  } catch (error) {
    latch({ code: "runner_internal_error", detail: evidenceSafeError(error).slice(0, 120) });
  }

  // ------------------------------------------------------------------------------- finalize + cleanup
  let outcome: FieldRunOutcome;
  try { outcome = await finalize(); }
  catch (error) { outcome = { exit: FIELD_EXIT.error, status: "error", serverSide: null, refusals: [evidenceSafeError(error)], evidenceId: evidence.id, evidenceDirectory: evidence.directory, bundle: null, write: null }; }
  finally {
    if (tickTimer) clearInterval(tickTimer);
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
    process.off("SIGHUP", onSignal);
    harnessSampler.stop();
    if (lockHeld) { try { unlinkSync(lockFile); } catch { /* the operator removes a stale lock */ } }
  }
  void signalReceived;
  return outcome;
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

export type FieldCli = { targetId: string; levelId: string; campaignId: string; dryRun: boolean; selftest: boolean };

/** Strict: exactly --target, --level, --campaign (and the two boolean flags); no URL, host, port, path or `=` form is accepted. */
export function parseFieldArguments(argv: readonly string[]): FieldCli {
  const values: Record<string, string> = {};
  const flags = new Set<string>();
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === "--dry-run" || arg === "--selftest") { if (flags.has(arg)) throw new Error(`${arg} given twice`); flags.add(arg); continue; }
    if (!["--target", "--level", "--campaign"].includes(arg)) throw new Error(`unexpected argument "${arg.slice(0, 24)}": a field level takes only --target, --level and --campaign`);
    if (arg in values) throw new Error(`${arg} given twice`);
    const value = argv[++index];
    if (value === undefined || value.startsWith("--")) throw new Error(`${arg} needs a value`);
    values[arg] = value;
  }
  if (flags.has("--selftest")) return { targetId: "", levelId: "", campaignId: "", dryRun: false, selftest: true };
  for (const name of ["--target", "--level", "--campaign"]) if (values[name] === undefined) throw new Error(`${name} is required`);
  if (!/^[a-z][a-z0-9-]{2,40}$/.test(values["--target"])) throw new Error("--target must be a reviewed target id");
  if (!/^[a-z0-9][a-z0-9-]{5,40}$/.test(values["--campaign"])) throw new Error("--campaign must be a plain label");
  if (!/^[a-z0-9][a-z0-9-]{2,30}$/.test(values["--level"])) throw new Error("--level must be a reviewed level id");
  return { targetId: values["--target"], levelId: values["--level"], campaignId: values["--campaign"], dryRun: flags.has("--dry-run"), selftest: false };
}

async function main(argv: readonly string[]): Promise<number> {
  let cli: FieldCli;
  try { cli = parseFieldArguments(argv); } catch (error) { console.error(`REFUSED  ${error instanceof Error ? error.message : "bad arguments"}`); return FIELD_EXIT.refused; }
  if (cli.selftest) {
    const { runFieldSelftest } = await import("./field-selftest");
    const result = await runFieldSelftest();
    console.log(`${result.ok ? "SELFTEST-OK" : "SELFTEST-FAILED"}  artifacts written ${result.written.length}, refused ${result.failed.length}`);
    for (const failure of result.failed) console.log(`  - ${failure.artifact}: ${failure.rule}`);
    return result.ok ? 0 : FIELD_EXIT.error;
  }
  if (cli.dryRun) {
    const level = fieldLevel(cli.levelId);
    if (!level) { console.error("REFUSED  level_not_reviewed"); return FIELD_EXIT.refused; }
    const gates = evaluateBudgetGates(level.thresholds, null);
    console.log(JSON.stringify({ dryRun: true, level: cli.levelId, campaign: cli.campaignId, parameters: ba0FieldFingerprint(level.thresholds), gates: gates.map((gate) => ({ id: gate.id, ok: gate.ok })), networkActivity: false }, null, 2));
    return gates.every((gate) => gate.ok) ? 0 : FIELD_EXIT.refused;
  }
  const outcome = await runFieldLevel({ targetId: cli.targetId, levelId: cli.levelId, campaignId: cli.campaignId }, { log: (line) => console.log(line) });
  console.log(`${outcome.status.toUpperCase()}  ba0 field level ${cli.levelId} (server side only: the final verdict comes from the offline reconcile with the generator report; DDoS resistance, network isolation and production readiness are NOT claimed)`);
  for (const reason of outcome.serverSide?.reasons ?? []) console.log(`  - ${reason.code}${reason.detail ? ` ${reason.detail}` : ""}`);
  for (const refusal of outcome.refusals) console.log(`  - refused: ${refusal}`);
  console.log(`evidence=${outcome.evidenceId ?? "none"}`);
  return outcome.exit;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === __filename) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (error) => { console.error(error instanceof Error ? evidenceSafeError(error) : "ERROR"); process.exit(FIELD_EXIT.error); });
}
