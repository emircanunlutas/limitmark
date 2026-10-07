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
 *   G6  campaign id, level id, commit, parameter and workload fingerprints and N match; window time consistency is informational only
 */
import type { Identity } from "./accounting";
import { decideFinal, type FinalDecision, type Reason, type ServerSideDecision } from "./field-verdict";
import type { GeneratorReport } from "./generator-report";

export const SERVER_LEVEL_SCHEMA = "ba0-server-level-v1" as const;

export type ServerLevelEvidence = {
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
  /** Observations that are reported and never decide: clock skew between the two hosts is not measured. */
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
