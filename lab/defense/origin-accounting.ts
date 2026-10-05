/**
 * BA0 Slice 2 accounting, DERIVED from the correlated lifecycle records and cross-checked against the Boundary's and the App's own
 * independent counters. Counters here are computed; they are never the source of truth. The Slice-1 plane-side identities still come from
 * `deriveAccounting` (called only on the Slice-1 lanes); everything about the two authenticated hops, the direct lanes, the positive
 * controls and mutation reconciliation is below. A failing identity makes the run INVALID.
 *
 * Protected-lane identities are computed over lane `protected` ONLY: a positive control (lab-minted, no plane lineage) is accounted in
 * its own block and can never satisfy or mask a protected identity.
 */
import { protectedLineageComplete } from "../../defense/core/lineage";
import type { LifecycleView } from "../../defense/core/ledger";
import type { AppCounters } from "../../defense/origin/synthetic-origin";
import type { HopStats } from "../../defense/plane/front";
import { OB_REASONS } from "../../defense/core/types";
import type { Identity } from "./accounting";
import type { JourneyResult } from "./canary";
import type { AppFin, BoundaryFin, LedgerRecord } from "./collector";

export type OriginAccountingInput = {
  records: readonly LedgerRecord[];
  journeys: readonly JourneyResult[];
  boundary: BoundaryFin | null;
  app: AppFin | null;
  controlCounters: AppCounters;
  boundaryAnonymous: Record<string, number>;
  appAnonymous: Record<string, number>;
  hop: HopStats | undefined;
  expected: { positiveControls: number; parserCases: number; droppedUnbound: number };
};

export type OriginAccountingReport = {
  plane: { attempted: number; proofIssued: number; signFailures: number };
  boundary: { admitted: number; rejectedOfPlane: number; appProofIssued: number; relayed: number; forwardResponded: number; forwardFailed: number; responded: number };
  app: { admitted: number; executed: number; completed: number; aborted: number; mutated: number };
  lineage: { protectedWithAppAdmission: number; complete: number; appAdmitsWithoutLineage: number };
  mutation: { clientObserved: number; ledgerCorrelated: number; appAuthoritative: number; perRecordViolations: number; controlClient: number; controlApp: number };
  direct: {
    boundarySent: number; boundaryRefused: number; boundaryParser: number; appSent: number; appRefused: number;
    appAdmissionsOnRejectedLanes: number; appExecutionsOnRejectedLanes: number; appMutationsOnRejectedLanes: number;
  };
  positiveControls: { sent: number; admitted: number; executed: number; mutated: number };
  refusedByReason: Record<string, number>;
  identities: Identity[];
  identitiesOk: boolean;
};

const identity = (id: string, description: string, left: number, right: number): Identity => ({ id, description, left, right, ok: left === right });
const count = <T>(items: readonly T[], predicate: (item: T) => boolean): number => items.reduce((total, item) => total + (predicate(item) ? 1 : 0), 0);
const events = <K extends "boundary" | "app" | "plane">(records: readonly LedgerRecord[], stream: K, kind: string): number =>
  records.reduce((total, record) => total + (record[stream] as readonly { kind: string }[]).filter((event) => event.kind === kind).length, 0);

export function deriveOriginAccounting(input: OriginAccountingInput): OriginAccountingReport {
  const { records } = input;
  const protectedRecords = records.filter((record) => record.meta.lane === "protected");
  const directBoundary = records.filter((record) => record.meta.lane === "direct_boundary_rejected");
  const directApp = records.filter((record) => record.meta.lane === "direct_app_rejected");
  const controls = records.filter((record) => record.meta.lane === "positive_control_boundary" || record.meta.lane === "positive_control_app");
  const view = (record: LedgerRecord): LifecycleView => ({ nonce: record.nonce, expected: record.meta.lane, harness: record.harness, plane: record.plane, origin: record.origin, boundary: record.boundary, app: record.app });
  const has = (record: LedgerRecord, stream: "plane" | "boundary" | "app", kind: string) => (record[stream] as readonly { kind: string }[]).some((event) => event.kind === kind);

  // ---- protected lane, hop by hop
  const attempted = count(protectedRecords, (r) => has(r, "plane", "EGRESS_ATTEMPTED"));
  const proofIssued = count(protectedRecords, (r) => has(r, "plane", "PROOF_ISSUED"));
  const signFailures = count(protectedRecords, (r) => has(r, "plane", "EGRESS_ATTEMPTED") && !has(r, "plane", "PROOF_ISSUED") && has(r, "plane", "EGRESS_FAILED"));
  const boundary = {
    admitted: count(protectedRecords, (r) => has(r, "boundary", "BOUNDARY_ADMITTED")),
    rejectedOfPlane: count(protectedRecords, (r) => has(r, "boundary", "BOUNDARY_REJECTED")),
    appProofIssued: count(protectedRecords, (r) => has(r, "boundary", "APP_PROOF_ISSUED")),
    relayed: count(protectedRecords, (r) => has(r, "boundary", "BOUNDARY_FORWARDED")),
    forwardResponded: count(protectedRecords, (r) => has(r, "boundary", "BOUNDARY_FORWARD_RESPONDED")),
    forwardFailed: count(protectedRecords, (r) => has(r, "boundary", "BOUNDARY_FORWARD_FAILED")),
    responded: count(protectedRecords, (r) => has(r, "boundary", "BOUNDARY_RESPONDED")),
  };
  const app = {
    admitted: count(protectedRecords, (r) => has(r, "app", "APP_ADMITTED")),
    executed: count(protectedRecords, (r) => has(r, "app", "APP_EXECUTED")),
    completed: count(protectedRecords, (r) => has(r, "app", "APP_COMPLETED")),
    aborted: count(protectedRecords, (r) => has(r, "app", "APP_ABORTED")),
    mutated: protectedRecords.reduce((total, r) => total + r.app.filter((event) => event.kind === "APP_MUTATED").length, 0),
  };
  const complete = count(protectedRecords, (r) => protectedLineageComplete(view(r)));
  const lineage = { protectedWithAppAdmission: app.admitted, complete, appAdmitsWithoutLineage: app.admitted - count(protectedRecords, (r) => has(r, "app", "APP_ADMITTED") && protectedLineageComplete(view(r))) };

  // ---- mutation, three ways
  const isValidPost = (journey: JourneyResult) => journey.steps[3]?.ok === true;
  const clientObserved = count(input.journeys.filter((journey) => journey.lane === "protected"), isValidPost);
  const ledgerCorrelated = count(protectedRecords, (r) => r.app.some((event) => event.kind === "APP_MUTATED") && protectedLineageComplete(view(r)));
  const validPostRecords = protectedRecords.filter((r) => r.meta.scenario === "journey_valid_post");
  const perRecordViolations = count(validPostRecords, (r) => {
    const client = r.harness.find((event) => event.kind === "CLIENT_COMPLETED");
    const success = client?.result === "response" && client.status === 200;
    return success !== (r.app.filter((event) => event.kind === "APP_MUTATED").length === 1);
  });
  const appAuthoritative = input.app?.stats.counters.stateMutations ?? -1;
  const mutation = {
    clientObserved, ledgerCorrelated, appAuthoritative, perRecordViolations,
    controlClient: count(input.journeys.filter((journey) => journey.lane === "control"), isValidPost), controlApp: input.controlCounters.stateMutations,
  };

  // ---- direct lanes and positive controls
  const onRejected = [...directBoundary, ...directApp];
  const direct = {
    boundarySent: directBoundary.length,
    boundaryRefused: count(directBoundary, (r) => has(r, "boundary", "BOUNDARY_REJECTED")),
    boundaryParser: input.expected.parserCases,
    appSent: directApp.length,
    appRefused: count(directApp, (r) => has(r, "app", "APP_REFUSED")),
    appAdmissionsOnRejectedLanes: count(onRejected, (r) => has(r, "app", "APP_ADMITTED")),
    appExecutionsOnRejectedLanes: count(onRejected, (r) => has(r, "app", "APP_EXECUTED")),
    appMutationsOnRejectedLanes: onRejected.reduce((total, r) => total + r.app.filter((event) => event.kind === "APP_MUTATED").length, 0),
  };
  const positiveControls = {
    sent: controls.length,
    admitted: count(controls, (r) => has(r, "app", "APP_ADMITTED")),
    executed: count(controls, (r) => has(r, "app", "APP_EXECUTED")),
    mutated: controls.reduce((total, r) => total + r.app.filter((event) => event.kind === "APP_MUTATED").length, 0),
  };

  // ---- the independent counters, against the events derived for ALL records
  const bStats = input.boundary?.stats;
  const aStats = input.app?.stats;
  const refusedByReason: Record<string, number> = Object.fromEntries(OB_REASONS.map((reason) => [reason, 0]));
  for (const record of records) {
    for (const event of record.boundary) if (event.kind === "BOUNDARY_REJECTED" && event.reason) refusedByReason[event.reason]++;
  }
  const appRefusedByReason: Record<string, number> = Object.fromEntries(OB_REASONS.map((reason) => [reason, 0]));
  for (const record of records) for (const event of record.app) if (event.kind === "APP_REFUSED" && event.reason) appRefusedByReason[event.reason]++;
  const appAnonymousRefusals = input.appAnonymous.APP_REFUSED ?? 0;
  const boundaryEvents = (kind: string) => events(records, "boundary", kind);
  const appEvents = (kind: string) => events(records, "app", kind);
  const mismatch = (pairs: [number, number][]) => pairs.reduce((total, [a, b]) => total + (a === b ? 0 : 1), 0);

  const bCounterMismatch = bStats === undefined ? -1 : mismatch([
    [bStats.arrived, boundaryEvents("BOUNDARY_ARRIVED")], [bStats.admitted, boundaryEvents("BOUNDARY_ADMITTED")], [bStats.rejected, boundaryEvents("BOUNDARY_REJECTED")],
    [bStats.appProofsIssued, boundaryEvents("APP_PROOF_ISSUED")], [bStats.relayed, boundaryEvents("BOUNDARY_FORWARDED")], [bStats.forwardResponded, boundaryEvents("BOUNDARY_FORWARD_RESPONDED")],
    [bStats.forwardFailed, boundaryEvents("BOUNDARY_FORWARD_FAILED")], [bStats.responded, boundaryEvents("BOUNDARY_RESPONDED")], [bStats.aborted, boundaryEvents("BOUNDARY_ABORTED")],
    [bStats.parserRejected, input.boundaryAnonymous.BOUNDARY_PARSER_REJECTED ?? 0], [bStats.protocolRefused, input.boundaryAnonymous.BOUNDARY_PROTOCOL_REFUSED ?? 0],
    ...OB_REASONS.map((reason): [number, number] => [bStats.rejectedByReason[reason] ?? 0, refusedByReason[reason]]),
  ]);
  const aCounterMismatch = aStats === undefined ? -1 : mismatch([
    [aStats.counters.admitted, appEvents("APP_ADMITTED")], [aStats.counters.refused, appEvents("APP_REFUSED") + appAnonymousRefusals],
    [aStats.counters.executed, appEvents("APP_EXECUTED")], [aStats.counters.stateMutations, appEvents("APP_MUTATED")],
    [aStats.served.completed, appEvents("APP_COMPLETED")], [aStats.served.aborted, appEvents("APP_ABORTED")],
    ...OB_REASONS.map((reason): [number, number] => [aStats.counters.refusedByReason[reason] ?? 0, appRefusedByReason[reason]]),
  ]);
  const spoofed = records.reduce((total, r) => total + r.app.reduce((sum, event) => sum + (event.spoofed ?? 0), 0), 0);
  const replayBoundary = bStats?.replay;
  const replayApp = aStats?.guard.replay;

  const identities: Identity[] = [
    identity("o2.plane_attempted_equals_proof_issued_plus_sign_failures", "every plane egress attempt is signed, or fails closed before anything is sent", attempted, proofIssued + signFailures),
    identity("o2.plane_proof_counter_equals_ledger", "the plane's own issuance counter equals the ledger's PROOF_ISSUED count", input.hop?.issued ?? -1, proofIssued),
    identity("o2.plane_sign_failures_equal_ledger", "the plane's own signing-failure counter equals the ledger", input.hop?.signFailures ?? -1, signFailures),
    identity("o2.dropped_unbound_matches_corpus", "headers the plane dropped as unbound equal what the corpora declare", input.hop?.droppedUnbound ?? -1, input.expected.droppedUnbound),
    identity("o2.proof_issued_equals_boundary_admitted", "every Plane-to-Boundary proof is admitted by the boundary exactly once", proofIssued, boundary.admitted),
    identity("o2.boundary_rejections_of_plane_egress_is_zero", "the boundary never refuses a request the plane approved and signed", boundary.rejectedOfPlane, 0),
    identity("o2.boundary_admitted_equals_app_proof_issued", "every boundary admission issues exactly one Boundary-to-App proof", boundary.admitted, boundary.appProofIssued),
    identity("o2.app_proof_issued_equals_app_admitted", "every Boundary-to-App proof is admitted by the app exactly once", boundary.appProofIssued, app.admitted),
    identity("o2.boundary_relayed_equals_app_proof_issued", "every issued app proof is forwarded", boundary.relayed, boundary.appProofIssued),
    identity("o2.app_admitted_equals_executed", "every admitted request is executed (clean run: none shed)", app.admitted, app.executed),
    identity("o2.app_admitted_equals_completed_plus_aborted", "every admitted request resolves", app.admitted, app.completed + app.aborted),
    identity("o2.boundary_relayed_equals_responded_plus_failed", "every forward is attributed", boundary.relayed, boundary.forwardResponded + boundary.forwardFailed),
    identity("o2.lineage_complete_equals_app_admitted", "every app admission has the complete cryptographic lineage behind it", lineage.complete, app.admitted),
    identity("o2.app_admits_without_lineage_is_zero", "no application admission lacks lineage", lineage.appAdmitsWithoutLineage, 0),
    identity("o2.mutation_client_equals_ledger", "client-observed successful submissions equal ledger-correlated mutations", mutation.clientObserved, mutation.ledgerCorrelated),
    identity("o2.mutation_ledger_equals_app", "ledger-correlated mutations equal the application's own authoritative counter", mutation.ledgerCorrelated, mutation.appAuthoritative),
    identity("o2.mutation_per_record_agreement", "per request, client success holds exactly when the app mutated once", mutation.perRecordViolations, 0),
    identity("o2.control_mutation_client_equals_origin", "the unguarded baseline's mutations equal its client-observed successes", mutation.controlClient, mutation.controlApp),
    identity("o2.direct_boundary_sent_equals_refused_plus_parser", "every direct boundary attempt is refused by the boundary (or by the HTTP parser, counted)", direct.boundarySent, direct.boundaryRefused + direct.boundaryParser),
    identity("o2.direct_app_sent_equals_refused", "every direct app-port attempt is refused by the app's own guard", direct.appSent, direct.appRefused),
    identity("o2.direct_app_admissions_is_zero", "no refused direct lane was admitted by the application", direct.appAdmissionsOnRejectedLanes, 0),
    identity("o2.direct_app_executions_is_zero", "no refused direct lane produced an application execution", direct.appExecutionsOnRejectedLanes, 0),
    identity("o2.direct_app_mutations_is_zero", "no refused direct lane produced a state mutation", direct.appMutationsOnRejectedLanes, 0),
    identity("o2.positive_controls_admitted_equals_expected", "each labelled positive control was admitted exactly once", positiveControls.admitted, input.expected.positiveControls),
    identity("o2.positive_controls_executed_equals_admitted", "each admitted positive control executed", positiveControls.executed, positiveControls.admitted),
    identity("o2.positive_controls_mutations_is_zero", "positive controls never mutate", positiveControls.mutated, 0),
    identity("o2.app_executions_equal_attributed", "the app's own execution counter equals protected plus positive-control executions (nothing unattributed)", aStats?.counters.executed ?? -1, app.executed + positiveControls.executed),
    identity("o2.app_mutations_equal_attributed", "the app's own mutation counter equals protected plus positive-control mutations (nothing unattributed)", aStats?.counters.stateMutations ?? -1, app.mutated + positiveControls.mutated),
    identity("o2.boundary_counters_equal_ledger", "the boundary's independent counters (arrival, decision, forward, per-reason) equal the ledger-derived counts", bCounterMismatch, 0),
    identity("o2.no_anonymous_decisions", "every boundary decision and app refusal is attributable to a request (only parser and protocol refusals are anonymous)",
      Object.entries(input.boundaryAnonymous).filter(([kind]) => kind !== "BOUNDARY_PARSER_REJECTED" && kind !== "BOUNDARY_PROTOCOL_REFUSED").reduce((total, [, n]) => total + n, 0) + (input.appAnonymous.APP_REFUSED ?? 0), 0),
    identity("o2.app_counters_equal_ledger", "the app's independent counters (admitted, refused, executed, mutated, per-reason) equal the ledger-derived counts", aCounterMismatch, 0),
    identity("o2.boundary_replay_state_closed", "no reservation is left in flight; reserved equals committed plus burned; committed equals admitted", replayBoundary ? replayBoundary.open + Math.abs(replayBoundary.reserved - replayBoundary.committed - replayBoundary.burned) + Math.abs(replayBoundary.committed - (bStats?.admitted ?? 0)) : -1, 0),
    identity("o2.app_replay_state_closed", "no reservation is left in flight; reserved equals committed plus burned; committed equals twice the admissions", replayApp ? replayApp.open + Math.abs(replayApp.reserved - replayApp.committed - replayApp.burned) + Math.abs(replayApp.committed - 2 * (aStats?.counters.admitted ?? 0)) : -1, 0),
    identity("o2.replay_state_violations_is_zero", "no replay ticket was settled twice", (replayBoundary?.stateViolations ?? 1) + (replayApp?.stateViolations ?? 1), 0),
    identity("o2.body_reads_only_after_reservation", "a body read starts only for a request that holds a reservation", Math.max(0, (bStats?.contentReadsStarted ?? 1) - (replayBoundary?.reserved ?? 0)) + Math.max(0, (aStats?.guard.contentReadsStarted ?? 1) - (replayApp?.reserved ?? 0)), 0),
    identity("o2.clock_step_absent", "neither verifier observed a wall-clock step against its monotonic clock", (bStats?.clockStep ? 1 : 0) + (aStats?.guard.clockStep ? 1 : 0), 0),
    identity("o2.app_spoofed_headers_is_zero", "no spoofable header reached the application", spoofed, 0),
  ];

  return {
    plane: { attempted, proofIssued, signFailures }, boundary, app, lineage, mutation, direct, positiveControls, refusedByReason: Object.fromEntries(Object.entries(refusedByReason).filter(([, n]) => n > 0)),
    identities, identitiesOk: identities.every((entry) => entry.ok),
  };
}
