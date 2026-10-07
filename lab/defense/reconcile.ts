/**
 * Field qualification: the OFFLINE RECONCILE of the server-side level evidence and the generator report. Pure. It is the only place a final
 * verdict (EXTERNAL-L7-QUALIFICATION-VALID | INVALID | ABORTED) is produced, and it produces one only from BOTH inputs.
 *
 * The generator's numbers are evidence about the generator, never about the server: they are compared against the server-side ledger and
 * can only ADD reasons (a disagreement is a measurement failure). Nothing here changes what the server enforced.
 *
 *   G1  generator attempted = server external ingress accepted + pre-ingress losses, within the generator's own ambiguity (N_amb = its
 *       timeouts, resets and refusals, whose server-side fate it cannot know). VALID at N = 1 additionally requires N_amb = 0.
 *   G2  the generator's status histogram = the server's INGRESS_RESPONDED status histogram, status by status
 *   G3  the generator's GETs = the server's open-class requests, its POSTs = the mutation class; the unknown class and L1 rejects are zero
 *   G4  the generator's new connections = the server's remote connections accepted plus dropped
 *   G5  the generator's logical in-flight never exceeded N (nor did the server's external in-flight); no retries, no pipelining; the
 *       generator itself was not saturated (schedule lag and event-loop delay under their pinned ceilings)
 *   G6  campaign id, level id, commit, parameter and workload fingerprints and N match; historical N=1 timing is informational.
 *       N=2 additionally requires duration completion, repeated dual-request exposure and source-bound campaign/drain phases.
 */
import type { Identity } from "./accounting";
import { decideFinal, type FinalDecision, type Reason, type ServerSideDecision } from "./field-verdict";
import type { GeneratorReport } from "./generator-report";
import { workloadFingerprint } from "./generator-report";
import { BA0_FIELD_C2_V1, FIELD_LEVELS, ba0FieldFingerprint } from "./field-thresholds";
import { WORKLOADS } from "../policy/workloads";
import { exercised, n2ExerciseSpec, type ServerN2Measurement } from "./n2-measurement";

export const SERVER_LEVEL_SCHEMA = "ba0-server-level-v1" as const;

export type ServerLevelEvidence = {
  n2?: ServerN2Measurement;
  schema: typeof SERVER_LEVEL_SCHEMA;
  campaignId: string;
  levelId: string;
  gitSha: string;
  paramsFingerprintSha256: string;
  workloadFingerprintSha256: string;
  workers: number;
  serverSide: { status: "complete" | "invalid" | "aborted"; failureClass: string | null; reasons: { code: string }[] };
  window: { openedAt: string; closedAt: string; elapsedMs: number } | null;
  reconcileInput: {
    externalAccepted: number;
    statusHistogram: Record<string, number>;
    status503: { total: number; expectedShed: number; unexplained: number };
    classes: Record<string, number>;
    l1Rejected: number;
    egressFailed: number;
    connections: { acceptedRemote: number; dropped: number; clientErrorTotal: number; clientErrorNoRequest: number; parserRejected: number; protocolRefused: number };
    externalInFlightMax: number;
  };
};

export type ReconcileLimits = { scheduleLagP99Ms: number; eldP99Ms: number };

export type ReconcileResult = {
  identities: Identity[];
  reasons: Reason[];
  /** Historical observation retained for N=1. N=2 also enforces source-bound timing identities; clock skew is assumed, not measured. */
  informational: { windowConsistent: boolean | null; clockSkewAssumption: string };
};

const identity = (id: string, description: string, left: number, right: number, ok = left === right): Identity => ({ id, description, left, right, ok });

/** Compares two {status -> count} tables. Returns the number of statuses on which they differ. */
function histogramDifferences(a: Record<string, number>, b: Record<string, number>): number {
  let differing = 0;
  for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) if ((a[key] ?? 0) !== (b[key] ?? 0)) differing++;
  return differing;
}

export function reconcile(server: ServerLevelEvidence, report: GeneratorReport | null, limits: ReconcileLimits): ReconcileResult {
  const reasons: Reason[] = [];
  const identities: Identity[] = [];
  const informational: ReconcileResult["informational"] = { windowConsistent: null, clockSkewAssumption: "the two hosts' clocks are assumed within 2000 ms; skew is not measured" };
  if (report === null) {
    reasons.push({ code: "generator_report_missing" });
    return { identities, reasons, informational };
  }
  const input = server.reconcileInput;

  // ---- G6: binding
  const binding = [
    server.campaignId === report.campaignId, server.levelId === report.levelId, server.gitSha === report.gitSha,
    server.paramsFingerprintSha256 === report.paramsFingerprintSha256, server.workloadFingerprintSha256 === report.workloadFingerprintSha256, server.workers === report.workers,
  ];
  identities.push(identity("g6.binding_matches", "campaign, level, commit, parameter and workload fingerprints and N are identical in both inputs", binding.filter(Boolean).length, binding.length));
  if (binding.some((ok) => !ok)) reasons.push({ code: "identity_binding_mismatch" });

  // The new level also verifies its reviewed binding locally. Historical N=1 evidence keeps G1..G6 unchanged.
  if (server.levelId === "ba0-l7-c2" || report.levelId === "ba0-l7-c2") {
    const t = BA0_FIELD_C2_V1;
    const params = ba0FieldFingerprint(t).sha256;
    const workload = workloadFingerprint(WORKLOADS[FIELD_LEVELS["ba0-l7-c2"].workload]);
    const reviewed = [server, report].every((side) => side.levelId === t.level.id && side.workers === t.level.workers
      && side.paramsFingerprintSha256 === params && side.workloadFingerprintSha256 === workload)
      && report.concurrency.planned === t.level.workers && report.concurrency.inFlightNow === 0
      && report.rate.ceilingPerSecond === t.level.maxRequestsPerSecond && report.attempted <= t.level.maxTotalRequests;
    identities.push(identity("g6.n2_reviewed_binding", "both inputs bind the exact reviewed N equals 2 parameters, workload, worker count and ceilings", reviewed ? 0 : 1, 0));
    if (!reviewed) reasons.push({ code: "identity_binding_mismatch", detail: "n2_reviewed_binding" });
    const sum = (table: Record<string, number>) => Object.values(table).reduce((total, value) => total + value, 0);
    const fixtures = Object.values(report.perFixture);
    // VALID has zero transport ambiguity. Every attempted request must therefore have exactly one reported response and outcome.
    const fates = report.responses === report.attempted && sum(report.statuses) === report.responses && sum(report.outcomes) === report.attempted
      && fixtures.reduce((total, item) => total + item.attempted, 0) === report.attempted
      && fixtures.reduce((total, item) => total + item.responses, 0) === report.responses
      && fixtures.reduce((total, item) => total + item.transportFailures, 0) === report.transportFailures;
    identities.push(identity("g1.n2_generator_fates_complete", "all generator attempts, responses, outcomes and fixture fates conserve exactly for a zero-ambiguity VALID level", fates ? 0 : 1, 0));
    if (!fates) reasons.push({ code: "generator_report_mismatch", detail: "n2_generator_fates" });
    const unexpectedStatuses = (table: Record<string, number>) => Object.entries(table)
      .reduce((total, [status, count]) => total + (status === "429" || (Number(status) >= 500 && Number(status) <= 599 && status !== "503") ? count : 0), 0);
    const unexplained = unexpectedStatuses(report.statuses) + unexpectedStatuses(input.statusHistogram) + input.status503.unexplained;
    identities.push(identity("g2.n2_no_unexplained_status", "no unreviewed 429 or 5xx response or unattributed 503 exists in either view", unexplained, 0));
    if (unexplained !== 0) reasons.push({ code: "unexplained_traffic", detail: "n2_response_status" });

    const spec = n2ExerciseSpec(t);
    const g = report.n2;
    const s = server.n2;
    const finite = (n: unknown): n is number => typeof n === "number" && Number.isFinite(n);
    const completion = report.stop.kind === "completed" && report.stop.detail === null && g != null
      && finite(g.elapsedMs) && g.elapsedMs >= spec.durationMs
      && g.elapsedMs <= spec.durationMs + t.window.setupAllowanceMs + t.window.drainAllowanceMs
      && Math.abs(report.wallClockSeconds * 1000 - g.elapsedMs) <= 10
      && finite(g.firstDispatchMs) && finite(g.lastDispatchMs) && finite(g.lastSettlementMs)
      && g.firstDispatchMs >= 0 && g.firstDispatchMs <= t.window.setupAllowanceMs
      && g.lastDispatchMs >= g.firstDispatchMs && g.lastDispatchMs < spec.durationMs
      && g.lastSettlementMs >= g.lastDispatchMs && g.lastSettlementMs <= g.elapsedMs;
    identities.push(identity("g6.n2_completion", "duration-completed only: full monotonic campaign and bounded drain; no abort, expiry or ceiling stop", completion ? 0 : 1, 0));
    if (!completion) reasons.push({ code: "generator_report_mismatch", detail: "n2_completion" });

    const exercise = report.concurrency.maxInFlightObserved === 2 && input.externalInFlightMax === 2
      && exercised(g?.exposure, spec, report.attempted) && exercised(s?.exposure, spec, input.externalAccepted);
    identities.push(identity("g5.n2_exercised", "both source clocks prove one fixture cycle of overlap starts and pacing-slot residency in every telemetry interval", exercise ? 0 : 1, 0));
    if (!exercise) reasons.push({ code: "identity_failed", detail: "n2_exercise" });

    // Source barriers include cumulative counters and sequence watermarks: delayed IPC cannot hide pre-arm or post-close ingress.
    const a = s?.armed; const c = s?.closed;
    const skew = t.qualification!.clockAgreementMs;
    const start = Date.parse(report.startedAt); const end = Date.parse(report.endedAt);
    const near = (x: number, y: number) => Number.isFinite(x) && Number.isFinite(y) && Math.abs(x - y) <= skew;
    const validMark = (mark: typeof a) => mark != null && Number.isSafeInteger(mark.seq) && mark.seq >= 0
      && finite(mark.atMs) && mark.atMs >= 0 && Number.isFinite(Date.parse(mark.wallAt))
      && Number.isSafeInteger(mark.acceptedExternal) && mark.acceptedExternal >= 0
      && Number.isSafeInteger(mark.inFlightExternal) && mark.inFlightExternal >= 0;
    const w = server.window;
    const phase = completion && s != null && validMark(a) && validMark(c) && a != null && c != null
      && a.phase === "armed" && c.phase === "closed" && c.seq >= a.seq && c.atMs >= a.atMs
      && c.atMs - a.atMs <= t.window.hardDeadlineMs
      && a.acceptedExternal === 0 && a.inFlightExternal === 0 && c.inFlightExternal === 0
      && s.beforeArmed === 0 && s.afterClosed === 0 && s.faults === 0 && s.inFlightAtClose === 0
      && s.inWindow === report.attempted && s.inWindow === input.externalAccepted && c.acceptedExternal === s.inWindow
      && s.settledInWindow === report.responses
      && finite(s.firstIngressMs) && finite(s.lastIngressMs) && finite(s.lastSettlementMs)
      && s.firstIngressMs >= a.atMs && s.firstIngressMs - a.atMs <= t.window.startSlackMs
      && s.lastIngressMs >= s.firstIngressMs && s.lastSettlementMs >= s.lastIngressMs && s.lastSettlementMs <= c.atMs
      && s.lastSettlementMs - s.firstIngressMs <= spec.durationMs + t.window.setupAllowanceMs + t.window.drainAllowanceMs
      && c.atMs - s.firstIngressMs >= spec.durationMs
      && near(Date.parse(c.wallAt) - Date.parse(a.wallAt), c.atMs - a.atMs)
      && near(end - start, g!.elapsedMs)
      && near(start + g!.firstDispatchMs!, Date.parse(a.wallAt) + s.firstIngressMs - a.atMs)
      && near(start + g!.lastDispatchMs!, Date.parse(a.wallAt) + s.lastIngressMs - a.atMs)
      && near(start + g!.lastSettlementMs!, Date.parse(a.wallAt) + s.lastSettlementMs - a.atMs)
      && w != null && finite(w.elapsedMs) && w.elapsedMs >= spec.durationMs
      && near(Date.parse(w.closedAt) - Date.parse(w.openedAt), w.elapsedMs)
      && near(Date.parse(w.openedAt), Date.parse(a.wallAt) + s.firstIngressMs - a.atMs)
      && start >= Date.parse(w.openedAt) - skew && end <= Date.parse(w.closedAt) + skew
      && near(Date.parse(w.closedAt), Date.parse(c.wallAt));
    identities.push(identity("g6.n2_measurement_phase", "zero pre-arm/post-close ingress; all campaign fates settle before source close; clocks and window agree within reviewed tolerance", phase ? 0 : 1, 0));
    if (!phase) reasons.push({ code: "identity_failed", detail: "n2_measurement_phase" });
  }

  // ---- generator ambiguity: requests whose server-side fate the generator cannot know
  const ambiguity = report.transportFailures;
  if (ambiguity > 0) reasons.push({ code: "generator_ambiguity", detail: `${ambiguity} transport failure(s)` });

  // ---- G1
  // A clientError raised while a request was in flight belongs to that request (it is INGRESS_ABORTED); only the ones with no request in flight are losses before ingress.
  const preIngress = input.connections.clientErrorNoRequest + input.connections.parserRejected + input.connections.protocolRefused;
  const delta = report.attempted - (input.externalAccepted + preIngress);
  identities.push(identity("g1.attempted_equals_ingress_plus_preingress", "generator attempted equals server external ingress plus pre-ingress losses (within the generator's own ambiguity)", report.attempted, input.externalAccepted + preIngress, delta >= 0 && delta <= ambiguity));
  if (!(delta >= 0 && delta <= ambiguity)) reasons.push({ code: "unexplained_traffic", detail: "g1" });
  identities.push(identity("g1.preingress_is_zero", "this workload sends only well-formed requests: no clientError, parser or protocol refusal reached the plane", preIngress + (input.connections.clientErrorTotal - input.connections.clientErrorNoRequest), 0));
  if (preIngress + (input.connections.clientErrorTotal - input.connections.clientErrorNoRequest) > 0) reasons.push({ code: "unexplained_traffic", detail: "preingress" });

  // ---- G2
  const differing = histogramDifferences(report.statuses, input.statusHistogram);
  identities.push(identity("g2.status_histogram_equal", "generator and server status histograms agree on every status", differing, 0));
  if (differing > 0) reasons.push({ code: "generator_report_mismatch", detail: "g2" });
  identities.push(identity("g2.generator_503_equals_expected_shed", "every 503 the generator saw is a server-attributed expected defense shed", report.statuses["503"] ?? 0, input.status503.expectedShed));
  if ((report.statuses["503"] ?? 0) !== input.status503.expectedShed) reasons.push({ code: "unattributed_503", detail: "g2" });

  // ---- G3
  const get = (report.perFixture.get_home?.attempted ?? 0) + (report.perFixture.get_privacy?.attempted ?? 0) + (report.perFixture.get_form?.attempted ?? 0);
  const post = report.perFixture.post_inquiry?.attempted ?? 0;
  const openClass = input.classes.open ?? 0;
  const mutationClass = input.classes.mutation ?? 0;
  const within = (generatorSide: number, serverSide: number): boolean => generatorSide - serverSide >= 0 && generatorSide - serverSide <= ambiguity;
  identities.push(identity("g3.gets_equal_open_class", "generator GETs equal the server's open-class requests", get, openClass, within(get, openClass)));
  identities.push(identity("g3.posts_equal_mutation_class", "generator POSTs equal the server's mutation-class requests", post, mutationClass, within(post, mutationClass)));
  identities.push(identity("g3.unknown_class_is_zero", "no request fell in the unknown class", input.classes.unknown ?? 0, 0));
  identities.push(identity("g3.l1_rejects_is_zero", "L1 refused none of the generator's requests", input.l1Rejected, 0));
  if (!within(get, openClass) || !within(post, mutationClass) || (input.classes.unknown ?? 0) > 0 || input.l1Rejected > 0) reasons.push({ code: "unexplained_traffic", detail: "g3" });

  // ---- G4
  const connections = input.connections.acceptedRemote + input.connections.dropped;
  const connectionDelta = report.connections.new - connections;
  identities.push(identity("g4.new_connections_equal_accepted", "generator new connections equal the server's remote connections accepted plus dropped", report.connections.new, connections, connectionDelta >= 0 && connectionDelta <= ambiguity));
  if (!(connectionDelta >= 0 && connectionDelta <= ambiguity)) reasons.push({ code: "unexplained_traffic", detail: "g4" });
  identities.push(identity("g4.server_dropped_is_zero", "the server dropped no connection", input.connections.dropped, 0));
  if (input.connections.dropped > 0) reasons.push({ code: "unexplained_traffic", detail: "dropped" });

  // ---- G5
  identities.push(identity("g5.generator_in_flight_within_n", "the generator's logical in-flight never exceeded N", report.concurrency.maxInFlightObserved, Math.min(report.concurrency.maxInFlightObserved, server.workers), report.concurrency.maxInFlightObserved <= server.workers));
  identities.push(identity("g5.server_external_in_flight_within_n", "the server's external in-flight never exceeded N", input.externalInFlightMax, Math.min(input.externalInFlightMax, server.workers), input.externalInFlightMax <= server.workers));
  if (report.concurrency.maxInFlightObserved > server.workers || input.externalInFlightMax > server.workers) reasons.push({ code: "generator_in_flight_exceeded" });
  identities.push(identity("g5.no_retries_no_pipelining", "the generator used no retries and no pipelining", report.retries === 0 && !report.pipelining ? 0 : 1, 0));
  if (server.levelId === "ba0-l7-c2" && (report.retries !== 0 || report.pipelining)) reasons.push({ code: "identity_failed", detail: "g5.no_retries_no_pipelining" });
  const saturated = report.schedule.lagMs.p99 > limits.scheduleLagP99Ms || report.generatorHealth.eldP99Ms > limits.eldP99Ms;
  identities.push(identity("g5.generator_not_saturated", "the generator's schedule lag and event-loop delay stayed under their ceilings", saturated ? 1 : 0, 0));
  if (saturated) reasons.push({ code: "generator_saturation" });

  // ---- G6 (informational): the generator ran inside the server's window, within an assumed clock skew
  if (server.window !== null) {
    const skew = 2_000;
    const opened = Date.parse(server.window.openedAt);
    const closed = Date.parse(server.window.closedAt);
    informational.windowConsistent = Date.parse(report.startedAt) >= opened - skew && Date.parse(report.endedAt) <= closed + skew;
  }
  return { identities, reasons, informational };
}

/** The final verdict: the server-side decision and the reconcile's reasons, and nothing else. */
export function finalFrom(server: ServerLevelEvidence, report: GeneratorReport | null, limits: ReconcileLimits): { decision: FinalDecision; result: ReconcileResult } {
  const result = reconcile(server, report, limits);
  const serverSide: ServerSideDecision = {
    status: server.serverSide.status, failureClass: server.serverSide.failureClass as ServerSideDecision["failureClass"],
    reasons: server.serverSide.reasons.map((reason) => ({ code: reason.code as Reason["code"] })),
  };
  return { decision: decideFinal(serverSide, result.reasons), result };
}
