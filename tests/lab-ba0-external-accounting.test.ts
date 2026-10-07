import assert from "node:assert/strict";
import { test } from "node:test";
import { canaryCounts, deriveExternalAccounting, unverifiedMutationBound, type ExternalAccountingInput } from "../lab/defense/external-accounting";
import { ExternalReducer, type ExternalCounters } from "../lab/defense/external-reducer";
import { ExternalEventFactory, feed } from "../lab/defense/field-selftest";
import { BA0_FIELD_V1 } from "../lab/defense/field-thresholds";

const L2 = BA0_FIELD_V1.l2;

/** A clean level: reads, mutations and L2 budget sheds, with every process's own counters agreeing with the ledger. */
function clean(): ExternalAccountingInput {
  const factory = new ExternalEventFactory(L2);
  const reducer = new ExternalReducer({ allowedShed: BA0_FIELD_V1.allowedShed, report: () => undefined });
  for (let index = 0; index < 4; index++) feed(reducer, factory.lifecycle("get_proxied"));
  for (let index = 0; index < 3; index++) feed(reducer, factory.lifecycle("post_mutated"));
  for (let index = 0; index < 2; index++) feed(reducer, factory.lifecycle("post_shed"));
  reducer.finalize();
  const c = reducer.counters();
  return {
    external: c, externalDecisions: reducer.decisions(), canary: canaryCounts([], 0), planeFin: null,
    boundaryFin: { drained: true, channel: {} as never, stats: { arrived: c.boundary.arrived, admitted: c.boundary.admitted, rejected: 0, parserRejected: 0, protocolRefused: 0 } as never },
    appFin: { drained: true, channel: {} as never, stats: { counters: { admitted: c.app.admitted, executed: c.app.executed, refused: 0, stateMutations: c.app.mutated } as never, served: {} as never, guard: {} as never } },
    connections: { acceptedLocal: 0, acceptedRemote: 1, closedClean: 1, closedError: 0, active: 0, dropped: 0, clientErrorTotal: 0, clientErrorNoRequest: 0, protocolRefused: 0, parserRejected: 0 },
    l2: L2, windowElapsedMs: 30_000, workers: 1, externalInFlightMax: 1,
    streams: { planeDropped: 0, boundaryDropped: 0, appDropped: 0, drained: true, finalTicks: { plane: true, boundary: true, app: true }, tickGaps: 0 },
  };
}

const run = (change: (input: ExternalAccountingInput) => void) => { const input = clean(); change(input); return deriveExternalAccounting(input); };
const failedIds = (report: ReturnType<typeof deriveExternalAccounting>): string[] => report.identities.filter((entry) => !entry.ok).map((entry) => entry.id);
const mutateCounters = (input: ExternalAccountingInput, change: (counters: ExternalCounters) => void): void => { const copy = structuredClone(input.external); change(copy); input.external = copy; };

test("a clean level satisfies every identity E1..E11, and the bucket replay is exact", () => {
  const report = deriveExternalAccounting(clean());
  assert.deepEqual(failedIds(report), []);
  assert.equal(report.identitiesOk, true);
  assert.equal(report.buckets.unverified.mismatches, 0);
  assert.equal(report.buckets.unverified.gaps, 0);
  assert.equal(report.buckets.unverified.decisions, 5, "3 admitted + 2 shed on the unverified bucket");
  const ids = report.identities.map((entry) => entry.id);
  for (const group of ["e1.", "e2.", "e3.", "e4.", "e5.", "e6.", "e7.", "e8.", "e9.", "e10.", "e11."]) assert.ok(ids.some((id) => id.startsWith(group)), group);
});

test("N=2 server accounting accepts exactly two in flight and catches three without changing budgets", () => {
  const input = clean();
  input.workers = 2;
  input.externalInFlightMax = 2;
  assert.deepEqual(failedIds(deriveExternalAccounting(input)), []);
  input.externalInFlightMax = 3;
  assert.ok(failedIds(deriveExternalAccounting(input)).includes("e11.external_in_flight_within_n"));
});

test("E1: an unresolved or double-reduced request breaks the ingress identities", () => {
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.terminal.unresolved = 1; }))).includes("e1.unresolved_is_zero"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.reduced++; }))).includes("e1.reduced_equals_accepted"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.accepted++; }))).includes("e1.external_accepted_equals_terminal"));
});

test("E2: a request that vanishes between L1 and L2, or an L2 entry with no decision, breaks the layer identities", () => {
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.l1.entered--; }))).includes("e2.l1_in_equals_ingress"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.l2.entered--; }))).includes("e2.l2_in_equals_l1_pass"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.l2.decided--; }))).includes("e2.l2_decided_equals_entered"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.l1.rejected++; }))).includes("e2.l1_in_equals_outcomes"));
});

test("E3 and E4: an egress without an L2 admission, an unattributed attempt, any external egress failure, or a proof that does not match breaks them", () => {
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.egress.attempted++; }))).includes("e3.egress_equals_l2_proceeds"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.egress.responded--; }))).includes("e3.egress_attributed"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.egress.failed = 1; c.egress.responded--; }))).includes("e3.egress_failed_is_zero"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.proofsIssued--; }))).includes("e4.proofs_equal_egress_minus_precontact_failures"));
});

test("E5: the Boundary's and the App's own counters must equal the ledger (a hidden admission or execution is caught from the process side)", () => {
  assert.ok(failedIds(run((input) => { input.boundaryFin!.stats.arrived++; })).includes("e5.boundary_arrived_equals_ledger"));
  assert.ok(failedIds(run((input) => { input.boundaryFin!.stats.admitted--; })).includes("e5.boundary_admitted_equals_ledger"));
  assert.ok(failedIds(run((input) => { input.boundaryFin!.stats.rejected = 1; })).includes("e5.boundary_rejected_is_zero"));
  assert.ok(failedIds(run((input) => { input.boundaryFin!.stats.parserRejected = 1; })).includes("e5.boundary_refusals_zero"));
  assert.ok(failedIds(run((input) => { input.appFin!.stats.counters.admitted++; })).includes("e5.app_admitted_equals_ledger"));
  assert.ok(failedIds(run((input) => { input.appFin!.stats.counters.executed++; })).includes("e5.app_executed_equals_ledger"));
  assert.ok(failedIds(run((input) => { input.appFin!.stats.counters.refused = 2; })).includes("e5.app_refused_is_zero"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.boundary.appProofsIssued--; }))).includes("e5.external_admitted_equals_app_proofs"));
});

test("E6: an application mutation the ledger does not show (or one it shows that the App did not count) breaks the mutation identities", () => {
  assert.ok(failedIds(run((input) => { input.appFin!.stats.counters.stateMutations++; })).includes("e6.app_counter_equals_ledger_mutations"), "a hidden mutation");
  assert.ok(failedIds(run((input) => { input.appFin!.stats.counters.stateMutations--; })).includes("e6.app_counter_equals_ledger_mutations"));
  assert.ok(failedIds(run((input) => { input.canary.app.mutated = 1; })).includes("e6.canary_ledger_equals_client"), "a canary mutation its client never saw");
});

test("E7: external mutations are bounded by the unverified budget over the window, none may use the credited lane, and the bucket replay catches a missing or altered decision", () => {
  assert.equal(unverifiedMutationBound(L2, 30_000), 3 + 30 + 1);
  assert.equal(unverifiedMutationBound(L2, 0), 4);
  assert.ok(failedIds(run((input) => { input.windowElapsedMs = 0; mutateCounters(input, (c) => { c.app.mutated = 9; }); })).includes("e7.external_mutations_within_unverified_budget"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.mutatedByLane.credited = 1; }))).includes("e7.external_credited_mutations_zero"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.mutatedByLane.open = 1; }))).includes("e7.external_open_or_unlaned_mutations_zero"));
  const altered = run((input) => { input.externalDecisions = input.externalDecisions.map((event, index) => (index === 4 && event.lvl !== undefined ? { ...event, lvl: event.lvl + 1 } : event)); });
  assert.ok(failedIds(altered).includes("e7.unverified_bucket_replays_exactly"), "a token that came back (P3) or never left");
  const missing = run((input) => { input.externalDecisions = input.externalDecisions.filter((event, index) => !(event.lane === "unverified" && index === 5)); });
  assert.ok(failedIds(missing).includes("e7.unverified_decisions_gapless"), "a decision that disappeared from the ledger");
  const credited = run((input) => { const factory = new ExternalEventFactory(L2); input.canary.decisions = factory.lifecycle("post_credited_mutated").plane.filter((event) => event.kind === "L2_DECIDED"); });
  assert.equal(credited.buckets.credited.decisions, 1, "the canary's credited admissions are in the same replay");
});

test("E7: the plane's own aggregate L2 counters are cross-checked against the ledger", () => {
  const input = clean();
  const byKey: Record<string, number> = { ...input.external.l2.byKey };
  input.planeFin = { drained: true, channel: {} as never, advisory: { l2: { lanes: { decisions: byKey } } } as never };
  assert.deepEqual(failedIds(deriveExternalAccounting(input)), []);
  byKey["mutation.unverified.admitted"] = (byKey["mutation.unverified.admitted"] ?? 0) + 1;
  assert.ok(failedIds(deriveExternalAccounting(input)).includes("e7.plane_l2_counters_equal_ledger"));
});

test("E8 (D6): every 503 must be a server-attributed expected shed; any other 503 or 5xx fails, and expected sheds must equal the L2 budget sheds", () => {
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.status503.unexplained = 1; c.status503.expectedShed--; }))).includes("e8.status_503_all_attributed"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.status503.total++; }))).includes("e8.status_503_equals_expected_shed"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.status5xxOther = 1; }))).includes("e8.no_other_5xx"));
  assert.ok(failedIds(run((input) => mutateCounters(input, (c) => { c.status503.expectedShed++; c.status503.total++; }))).includes("e8.expected_shed_equals_l2_budget_sheds"));
});

test("E9: connection accounting balances, and a drop, a clientError of any kind, a protocol refusal or a parser rejection fails", () => {
  assert.ok(failedIds(run((input) => { input.connections!.closedClean = 0; })).includes("e9.connections_balance"));
  assert.ok(failedIds(run((input) => { input.connections!.active = 1; input.connections!.closedClean = 0; })).includes("e9.active_connections_zero_after_drain"));
  assert.ok(failedIds(run((input) => { input.connections!.dropped = 1; })).includes("e9.dropped_is_zero"));
  assert.ok(failedIds(run((input) => { input.connections!.clientErrorTotal = 1; })).includes("e9.client_errors_zero"));
  assert.ok(failedIds(run((input) => { input.connections!.protocolRefused = 1; })).includes("e9.protocol_refusals_zero"));
  assert.ok(failedIds(run((input) => { input.connections!.parserRejected = 1; })).includes("e9.parser_rejections_zero"));
});

test("E10 and E11: a dropped event, an undrained stream, a missing final tick, a tick gap, or an in-flight above N fails", () => {
  assert.ok(failedIds(run((input) => { input.streams.planeDropped = 1; })).includes("e10.no_dropped_events"));
  assert.ok(failedIds(run((input) => { input.streams.drained = false; })).includes("e10.streams_drained"));
  assert.ok(failedIds(run((input) => { input.streams.finalTicks.app = false; })).includes("e10.final_ticks_present"));
  assert.ok(failedIds(run((input) => { input.streams.tickGaps = 2; })).includes("e10.no_tick_gaps"));
  assert.ok(failedIds(run((input) => { input.externalInFlightMax = 2; })).includes("e11.external_in_flight_within_n"));
});

test("the canary's counts are taken from its registered records only, by the same event kinds", () => {
  const empty = canaryCounts([], 3);
  assert.deepEqual({ planeAccepted: empty.planeAccepted, mutated: empty.app.mutated, client: empty.clientObservedMutations, decisions: empty.decisions.length }, { planeAccepted: 0, mutated: 0, client: 3, decisions: 0 });
});
