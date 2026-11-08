import { EventKindLedger } from "../../lab/defense/event-kind-ledger";
import type { TallyCheckInput } from "../../lab/defense/m1-tally-check";
import { OutcomeCounters, type CountedEvent } from "../../lab/defense/outcome-counters";

// Shared, deterministic fixtures for the criterion 9 tests. The tally side is the REAL OutcomeCounters, the ledger side is the REAL EventKindLedger fed numbered
// events, so the "valid" evidence is valid by construction and every mutation in the tests is a deliberate disagreement. A valid level has two kinds of traffic:
// the collector's own canary requests (they appear in the journal) and remote-lane requests (they appear in the external reducer's counters, not the journal).

export type E = CountedEvent & { kind: string };
export const pass = (status: number): E[] => [
  { kind: "INGRESS_ACCEPTED" }, { kind: "L1_ENTERED" }, { kind: "L1_PASSED" }, { kind: "L2_ENTERED" }, { kind: "L2_DECIDED", class: "open", lane: "open", outcome: "admitted" },
  { kind: "EGRESS_ATTEMPTED" }, { kind: "PROOF_ISSUED" }, { kind: "EGRESS_RESPONDED", status }, { kind: "INGRESS_RESPONDED", status },
];
export const shed: E[] = [
  { kind: "INGRESS_ACCEPTED" }, { kind: "L1_ENTERED" }, { kind: "L1_PASSED" }, { kind: "L2_ENTERED" },
  { kind: "L2_DECIDED", class: "mutation", lane: "unverified", outcome: "shed", shedReason: "lane_budget" }, { kind: "INGRESS_RESPONDED", status: 503 },
];
export const enroll: E[] = [...pass(200), { kind: "L2_ENROLLED" }];
/** The collector's own canary traffic. */
export const workload = (): E[] => [...pass(200), ...pass(200), ...enroll, ...shed, ...shed];
/** Remote-lane traffic: 2 admitted GETs and 3 attributed sheds. */
export const remoteWorkload = (): E[] => [...pass(200), ...pass(200), ...shed, ...shed, ...shed];

export function tallyOf(events: E[], options: { injectedFault?: () => void } = {}) {
  const counters = new OutcomeCounters(options);
  for (const event of events) counters.observe(event);
  return counters.snapshot();
}
export const journalOf = (events: E[]): Record<string, number> => { const out: Record<string, number> = {}; for (const event of events) out[event.kind] = (out[event.kind] ?? 0) + 1; return out; };

/** `external.json` counters of a reducer that took exactly these remote-lane events. */
export function externalOf(remote: E[]) {
  const k = journalOf(remote);
  const statusHistogram: Record<string, number> = {};
  for (const event of remote) if (event.kind === "INGRESS_RESPONDED") statusHistogram[String(event.status)] = (statusHistogram[String(event.status)] ?? 0) + 1;
  const accepted = k.INGRESS_ACCEPTED ?? 0;
  const shedCount = k.L1_ENTERED === undefined ? 0 : remote.filter((event) => event.kind === "L2_DECIDED" && event.outcome === "shed").length;
  const attempted = k.EGRESS_ATTEMPTED ?? 0;
  return {
    accepted, strippedHeaders: 0, reduced: accepted, terminal: accepted === 0 ? {} : { status_200: accepted - shedCount, status_503: shedCount },
    l1: { entered: k.L1_ENTERED ?? 0, passed: k.L1_PASSED ?? 0, rejected: 0, shed: 0, error: 0 }, l2: { entered: k.L2_ENTERED ?? 0, decided: k.L2_DECIDED ?? 0, classes: accepted === 0 ? {} : { open: accepted - shedCount, mutation: shedCount } },
    egress: { attempted, responded: k.EGRESS_RESPONDED ?? 0, failed: 0 }, proofsIssued: k.PROOF_ISSUED ?? 0,
    boundary: { arrived: attempted, admitted: attempted, rejected: 0, relayed: attempted, responded: attempted }, app: { admitted: attempted, refused: 0, executed: attempted },
    statusHistogram, status503: { total: shedCount, expectedShed: shedCount, unexplained: 0 }, clientAborted: 0,
  };
}
/** A zero external lane (no remote traffic at all). */
export const noExternal = externalOf([]);

/** What the runner writes as kind-ledger.json for a clean run of these events (every event received, in order, once). */
export function ledgerArtifact(events: E[]) {
  const ledger = new EventKindLedger();
  events.forEach((event, index) => ledger.observe({ ...event, seq: index + 1, nonce: "n" }));
  return ledger.artifact({ received: events.length, lastSeq: events.length, droppedReported: 0 });
}
/** The plane's final stats (`processes.json` plane) for a clean, drained channel that carried `n` events. */
export const planeFinOf = (n: number) => ({ drained: true, channel: { emitted: n, dropped: 0, sent: n, received: n, queued: 0, unacknowledged: 0, queueHighWater: 3, lastSeq: n } });
/** boundary and app `processes.json` entries: independent counters at least as large as the reducer's external share (canary requests add to them). */
export function receiptFins(remote: E[], canaryRequests = 5) {
  const ext = externalOf(remote);
  const n = ext.egress.attempted + canaryRequests;
  const channel = { emitted: 100, dropped: 0, sent: 100, received: 100, queued: 0, unacknowledged: 0, queueHighWater: 3, lastSeq: 100 };
  return {
    boundaryFin: { drained: true, channel, stats: { arrived: n, admitted: n, rejected: 0, relayed: n, responded: n } },
    appFin: { drained: true, channel, stats: { counters: { admitted: n, refused: 0, executed: n, stateMutations: 0, parserRejected: 0, protocolRefused: 0 } } },
  };
}
/** connections.json of a plane that accepted remote connections. */
export const connectionsOf = (acceptedRemote: number) => ({ scope: "exact monotonic counters from the plane's listener", final: { acceptedLocal: 40, acceptedRemote, closedClean: 40 + acceptedRemote, closedError: 0, active: 0, dropped: 0, clientErrorTotal: 0, clientErrorNoRequest: 0 }, externalInFlightMax: 1 });

/** server-level.json / core.json / manifest.json of one completed level that carried `remote` traffic. */
export function levelEvidence(remote: E[] = remoteWorkload(), acceptedRemote = 3, gitSha = "a".repeat(40)) {
  const ext = externalOf(remote);
  const sha = { git: gitSha, params: "b".repeat(64), workload: "c".repeat(64) };
  const sequence = ["close_ingress", "drain", "final_telemetry", "snapshot"].map((name) => ({ name, ok: true, timedOut: false, skippedByCap: false, ms: 5, error: null }));
  return {
    serverLevel: {
      schema: "ba0-server-level-v1", campaignId: "campaign-a", levelId: "ba0-l7-c1", gitSha: sha.git, paramsFingerprintSha256: sha.params, workloadFingerprintSha256: sha.workload, workers: 1,
      serverSide: { status: "complete", failureClass: null, reasons: [] }, window: { openedAt: "2026-11-08T10:00:00.000Z", closedAt: "2026-11-08T10:01:00.000Z", elapsedMs: 60_000 },
      reconcileInput: { externalAccepted: ext.accepted, statusHistogram: ext.statusHistogram, status503: ext.status503, classes: ext.l2.classes, l1Rejected: 0, egressFailed: 0, connections: { acceptedRemote, dropped: 0, clientErrorTotal: 0, clientErrorNoRequest: 0 }, externalInFlightMax: 1 },
    },
    core: { level: { id: "ba0-l7-c1", campaignId: "campaign-a", workers: 1 }, parameters: { id: "ba0-field-v1", version: 1, sha256: sha.params }, workloadSha256: sha.workload,
      serverSide: { status: "complete", failureClass: null, reasons: [] }, firstReason: null, machine: { phasesCompleted: true }, sequence },
    manifest: { result: "SERVER-COMPLETE", git: { gitSha: sha.git, dirty: false } },
  };
}

/** Complete, valid criterion 9 evidence: `canary` traffic (journal) plus `remote` traffic (reducer). */
export function validInput(canary: E[] = workload(), remote: E[] = remoteWorkload()): TallyCheckInput {
  const all = [...canary, ...remote];
  return {
    tally: tallyOf(all), tallyFromFinalTick: true, journalByKind: journalOf(canary), journalIncomplete: false, external: externalOf(remote),
    kindLedger: ledgerArtifact(all), planeFin: planeFinOf(all.length), duplicateKeys: [], level: levelEvidence(remote),
    connections: connectionsOf(3), ...receiptFins(remote),
  };
}
