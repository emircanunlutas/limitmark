/**
 * Field qualification: the server-side accounting identities E1..E11 of one level. Counters come from the correlated event streams (the
 * external reducer for requests from remote peers, the registered ledger records for the canary); the processes' own counters are SECONDARY
 * cross-checks, never the source of truth. A failing identity is a reason; it is never silently tolerated.
 *
 *   E1  external ingress = the sum of terminal outcomes + unresolved (zero)
 *   E2  L1 in = its outcomes; L2 in = L1 passes; L2 decisions = L2 entries; the decision outcomes partition the decisions
 *   E3  egress attempts = L2 admitted + degraded; every attempt is attributed; no external egress failed
 *   E4  proofs issued = egress attempts minus failures before the Boundary
 *   E5  the Boundary's and the App's own counters = what the ledger shows across external and canary requests
 *   E6  application mutations: the App's own counter = the ledger (external + canary) = the canary's client-observed successes + external
 *   E7  external mutations are within the L2 unverified budget over the window and none was credited; both buckets replay exactly
 *   E8  every 503 is a server-attributed expected defense shed; nothing else answered 5xx
 *   E9  connection accounting balances, and nothing reached the plane through a parser error, a protocol refusal or a drop
 *   E10 no stream dropped, gapped or failed to drain
 *   E11 the server's external in-flight never exceeded N
 *
 * Lifecycle validity per request (including App lineage / bypass) and stream sequence gaps are checked by the collector itself and arrive here as
 * the anomaly total.
 */
import type { PlaneEvent } from "../../defense/core/ledger";
import type { L2Params } from "../../defense/plane/l2-protocol";
import type { Identity } from "./accounting";
import type { AppFin, BoundaryFin, LedgerRecord, PlaneFin } from "./collector";
import type { ExternalCounters } from "./external-reducer";
import { auditBucket, bucketLaneOf, type BucketAudit } from "./lane-accounting";

export type CanaryCounts = {
  planeAccepted: number;
  l2ByKey: Record<string, number>;
  boundary: { arrived: number; admitted: number; rejected: number; appProofsIssued: number; responded: number; aborted: number };
  app: { admitted: number; refused: number; executed: number; mutated: number; completed: number };
  /** Journeys whose valid POST succeeded, as the canary CLIENT observed them. */
  clientObservedMutations: number;
  decisions: PlaneEvent[];
};

/** Counts the registered (canary) records' own events, by the same event kinds the external reducer counts. */
export function canaryCounts(records: readonly LedgerRecord[], clientObservedMutations: number): CanaryCounts {
  const out: CanaryCounts = {
    planeAccepted: 0, l2ByKey: {}, boundary: { arrived: 0, admitted: 0, rejected: 0, appProofsIssued: 0, responded: 0, aborted: 0 },
    app: { admitted: 0, refused: 0, executed: 0, mutated: 0, completed: 0 }, clientObservedMutations, decisions: [],
  };
  for (const record of records) {
    if (record.meta.lane !== "protected") continue;
    if (record.plane.some((event) => event.kind === "INGRESS_ACCEPTED")) out.planeAccepted++;
    const decided = record.plane.find((event) => event.kind === "L2_DECIDED");
    if (decided) {
      out.decisions.push(decided);
      const real = decided.basis === "simulated" && decided.shadow ? decided.shadow.split(":") : [decided.outcome ?? "none", decided.lane ?? "none"];
      const outcome = decided.basis === "simulated" ? real[0] : decided.outcome ?? "none";
      const lane = decided.basis === "simulated" ? real[1] ?? "none" : decided.lane ?? "none";
      const key = `${decided.class}.${lane}.${outcome}`;
      out.l2ByKey[key] = (out.l2ByKey[key] ?? 0) + 1;
    }
    for (const event of record.boundary) {
      if (event.kind === "BOUNDARY_ARRIVED") out.boundary.arrived++;
      else if (event.kind === "BOUNDARY_ADMITTED") out.boundary.admitted++;
      else if (event.kind === "BOUNDARY_REJECTED") out.boundary.rejected++;
      else if (event.kind === "APP_PROOF_ISSUED") out.boundary.appProofsIssued++;
      else if (event.kind === "BOUNDARY_RESPONDED") out.boundary.responded++;
      else if (event.kind === "BOUNDARY_ABORTED") out.boundary.aborted++;
    }
    for (const event of record.app) {
      if (event.kind === "APP_ADMITTED") out.app.admitted++;
      else if (event.kind === "APP_REFUSED") out.app.refused++;
      else if (event.kind === "APP_EXECUTED") out.app.executed++;
      else if (event.kind === "APP_MUTATED") out.app.mutated++;
      else if (event.kind === "APP_COMPLETED") out.app.completed++;
    }
  }
  return out;
}

export type ExternalAccountingInput = {
  external: ExternalCounters;
  externalDecisions: readonly PlaneEvent[];
  canary: CanaryCounts;
  planeFin: PlaneFin | null;
  boundaryFin: BoundaryFin | null;
  appFin: AppFin | null;
  /** The plane's last tick connection state after the ingress was closed and drained. */
  connections: {
    acceptedLocal: number; acceptedRemote: number; closedClean: number; closedError: number; active: number; dropped: number;
    clientErrorTotal: number; clientErrorNoRequest: number; protocolRefused: number; parserRejected: number;
  } | null;
  l2: L2Params;
  /** Elapsed time of the pressure window, used for the unverified budget bound. */
  windowElapsedMs: number;
  workers: number;
  externalInFlightMax: number;
  /** Streams: dropped event counts, the last tick of each role present, and the number of tick gaps the monitor saw. */
  streams: { planeDropped: number; boundaryDropped: number; appDropped: number; drained: boolean; finalTicks: { plane: boolean; boundary: boolean; app: boolean }; tickGaps: number };
};

export type BucketAudits = { credited: BucketAudit; unverified: BucketAudit };

export type ExternalAccountingReport = {
  identities: Identity[];
  identitiesOk: boolean;
  buckets: BucketAudits;
  /** The maximum external mutations the L2 unverified budget allows over the window. */
  mutationBound: number;
  summary: Record<string, number>;
};

const identity = (id: string, description: string, left: number, right: number, ok = left === right): Identity => ({ id, description, left, right, ok });
const sum = (table: Record<string, number>): number => Object.values(table).reduce((total, value) => total + value, 0);
const countWhere = (table: Record<string, number>, outcome: string): number => Object.entries(table).filter(([key]) => key.endsWith(`.${outcome}`)).reduce((total, [, value]) => total + value, 0);

/** The most mutations the unverified bucket can admit over `elapsedMs`: its capacity plus its refill, plus one decision of slack at the edges. */
export function unverifiedMutationBound(l2: L2Params, elapsedMs: number): number {
  return l2.unverified.capacity + Math.floor((l2.unverified.refillPerSecond * elapsedMs) / 1000) + 1;
}

export function deriveExternalAccounting(input: ExternalAccountingInput): ExternalAccountingReport {
  const { external: e, canary: c } = input;
  const identities: Identity[] = [];
  const add = (...args: Parameters<typeof identity>) => identities.push(identity(...args));

  // ---- E1
  const terminalTotal = sum(e.terminal) - (e.terminal.unresolved ?? 0);
  add("e1.external_accepted_equals_terminal", "external ingress equals the derived terminal outcomes", e.accepted, terminalTotal + (e.terminal.unresolved ?? 0));
  add("e1.unresolved_is_zero", "no external request is unresolved at finalization", e.terminal.unresolved ?? 0, 0);
  add("e1.reduced_equals_accepted", "every external request was reduced exactly once", e.reduced, e.accepted);

  // ---- E2
  add("e2.l1_in_equals_ingress", "every external request entered L1", e.l1.entered, e.accepted);
  add("e2.l1_in_equals_outcomes", "L1 input equals its outcomes", e.l1.entered, e.l1.passed + e.l1.rejected + e.l1.shed + e.l1.error);
  add("e2.l2_in_equals_l1_pass", "every L1 pass entered L2", e.l2.entered, e.l1.passed);
  add("e2.l2_decided_equals_entered", "exactly one L2 decision follows every L2 entry", e.l2.decided, e.l2.entered);
  add("e2.l2_decisions_partition", "the decision outcomes partition the decisions", e.l2.decided, countWhere(e.l2.byKey, "admitted") + countWhere(e.l2.byKey, "shed") + countWhere(e.l2.byKey, "error") + countWhere(e.l2.byKey, "degraded"));

  // ---- E3
  const proceeds = countWhere(e.l2.byKey, "admitted") + countWhere(e.l2.byKey, "degraded");
  add("e3.egress_equals_l2_proceeds", "only an admitted or degraded decision proceeds to egress", e.egress.attempted, proceeds);
  add("e3.egress_attributed", "every egress attempt is attributed", e.egress.attempted, e.egress.responded + e.egress.failed);
  add("e3.egress_failed_is_zero", "no external egress failed", e.egress.failed, 0);

  // ---- E4
  add("e4.proofs_equal_egress_minus_precontact_failures", "proofs issued equal egress attempts minus failures before the Boundary", e.proofsIssued, e.egress.attempted - e.egress.failedAtProof);

  // ---- E5: the processes' own counters against the ledger (external + canary)
  const boundary = input.boundaryFin?.stats;
  if (boundary) {
    add("e5.boundary_arrived_equals_ledger", "the Boundary's own arrival counter equals the ledger", boundary.arrived, e.boundary.arrived + c.boundary.arrived);
    add("e5.boundary_admitted_equals_ledger", "the Boundary's own admission counter equals the ledger", boundary.admitted, e.boundary.admitted + c.boundary.admitted);
    add("e5.boundary_rejected_is_zero", "the Boundary rejected nothing", boundary.rejected + e.boundary.rejected + c.boundary.rejected, 0);
    add("e5.boundary_refusals_zero", "the Boundary refused no parser or protocol input", boundary.parserRejected + boundary.protocolRefused, 0);
  }
  add("e5.external_admitted_equals_app_proofs", "every external admission issued exactly one App proof", e.boundary.admitted, e.boundary.appProofsIssued);
  const app = input.appFin?.stats.counters;
  if (app) {
    add("e5.app_admitted_equals_ledger", "the App's own admission counter equals the ledger", app.admitted, e.app.admitted + c.app.admitted);
    add("e5.app_executed_equals_ledger", "the App's own execution counter equals the ledger", app.executed, e.app.executed + c.app.executed);
    add("e5.app_refused_is_zero", "the App refused nothing", app.refused + e.app.refused + c.app.refused, 0);
  }
  add("e5.external_app_admitted_equals_forwarded", "every external request the Boundary forwarded and answered was admitted by the App", e.app.admitted, e.boundary.forwardResponded);

  // ---- E6
  const ledgerMutations = e.app.mutated + c.app.mutated;
  if (app) add("e6.app_counter_equals_ledger_mutations", "the App's own mutation counter equals the ledger (external plus canary)", app.stateMutations, ledgerMutations);
  add("e6.canary_ledger_equals_client", "the canary's ledger mutations equal the mutations its client observed", c.app.mutated, c.clientObservedMutations);

  // ---- E7
  const bound = unverifiedMutationBound(input.l2, input.windowElapsedMs);
  add("e7.external_mutations_within_unverified_budget", `external mutations stay within the unverified budget over the window (at most ${bound})`, e.app.mutated, Math.min(e.app.mutated, bound), e.app.mutated <= bound);
  add("e7.external_credited_mutations_zero", "no external request mutated through the credited lane", e.mutatedByLane.credited ?? 0, 0);
  add("e7.external_open_or_unlaned_mutations_zero", "no external mutation outside a bucket lane", (e.mutatedByLane.open ?? 0) + (e.mutatedByLane.none ?? 0), 0);
  const decisions = [...input.externalDecisions, ...c.decisions];
  const bucketed = decisions.filter((event) => event.dt !== undefined).map((event) => ({ event, bucketLane: bucketLaneOf(event) })).filter((entry) => entry.bucketLane === "credited" || entry.bucketLane === "unverified");
  const buckets: BucketAudits = { credited: auditBucket(bucketed, "credited", input.l2.credited), unverified: auditBucket(bucketed, "unverified", input.l2.unverified) };
  add("e7.credited_bucket_replays_exactly", "the credited bucket replays exactly from the ledger", buckets.credited.mismatches, 0);
  add("e7.unverified_bucket_replays_exactly", "the unverified bucket replays exactly from the ledger", buckets.unverified.mismatches, 0);
  add("e7.credited_decisions_gapless", "no credited bucket decision is missing", buckets.credited.gaps, 0);
  add("e7.unverified_decisions_gapless", "no unverified bucket decision is missing", buckets.unverified.gaps, 0);
  if (input.planeFin && "l2" in input.planeFin.advisory) {
    const plane = (input.planeFin.advisory as { l2: { lanes: { decisions: Record<string, number> } } }).l2.lanes.decisions;
    const keys = new Set([...Object.keys(plane), ...Object.keys(e.l2.byKey), ...Object.keys(c.l2ByKey)]);
    let mismatches = 0;
    for (const key of keys) if ((plane[key] ?? 0) !== (e.l2.byKey[key] ?? 0) + (c.l2ByKey[key] ?? 0)) mismatches++;
    add("e7.plane_l2_counters_equal_ledger", "the plane's own L2 decision counters equal the ledger (secondary cross-check)", mismatches, 0);
  }

  // ---- E8 (D6)
  add("e8.status_503_all_attributed", "no 503 is unexplained: each is a server-attributed expected defense shed", e.status503.unexplained, 0);
  add("e8.status_503_equals_expected_shed", "the 503 responses equal the server-attributed expected sheds", e.status503.total, e.status503.expectedShed);
  add("e8.no_other_5xx", "nothing else answered 5xx", e.status5xxOther, 0);
  add("e8.expected_shed_equals_l2_budget_sheds", "expected sheds equal the L2 budget sheds of the allowed lane", e.status503.expectedShed, e.l2.shedByReason["mutation.unverified.lane_budget"] ?? 0);

  // ---- E9
  const connection = input.connections;
  if (connection) {
    add("e9.connections_balance", "connections accepted equal closed plus active", connection.acceptedLocal + connection.acceptedRemote, connection.closedClean + connection.closedError + connection.active);
    add("e9.active_connections_zero_after_drain", "no connection stayed open after the ingress was closed and drained", connection.active, 0);
    add("e9.dropped_is_zero", "the listener dropped no connection", connection.dropped, 0);
    add("e9.client_errors_zero", "no clientError of any code reached the plane", connection.clientErrorTotal, 0);
    add("e9.protocol_refusals_zero", "no CONNECT or Expect refusal", connection.protocolRefused, 0);
    add("e9.parser_rejections_zero", "no parser rejection", connection.parserRejected, 0);
  }

  // ---- E10
  add("e10.no_dropped_events", "no stream dropped an event", input.streams.planeDropped + input.streams.boundaryDropped + input.streams.appDropped, 0);
  add("e10.streams_drained", "every stream drained its queue", input.streams.drained ? 0 : 1, 0);
  add("e10.final_ticks_present", "every process delivered a final tick", Object.values(input.streams.finalTicks).filter(Boolean).length, 3);
  add("e10.no_tick_gaps", "no tick gap was seen", input.streams.tickGaps, 0);

  // ---- E11
  add("e11.external_in_flight_within_n", "the server's external in-flight never exceeded N", input.externalInFlightMax, Math.min(input.externalInFlightMax, input.workers), input.externalInFlightMax <= input.workers);

  return {
    identities, identitiesOk: identities.every((entry) => entry.ok), buckets, mutationBound: bound,
    summary: { externalAccepted: e.accepted, externalMutated: e.app.mutated, status503Total: e.status503.total, status503Expected: e.status503.expectedShed, canaryRequests: c.planeAccepted },
  };
}
