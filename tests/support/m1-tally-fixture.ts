import { EventKindLedger } from "../../lab/defense/event-kind-ledger";
import type { TallyCheckInput } from "../../lab/defense/m1-tally-check";
import { OutcomeCounters, type CountedEvent } from "../../lab/defense/outcome-counters";

// Shared, deterministic fixtures for the criterion 9 tests. The tally side is the REAL OutcomeCounters, the ledger side is the REAL EventKindLedger fed numbered
// events, so the "valid" evidence is valid by construction and every mutation in the tests is a deliberate disagreement.

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
export const workload = (): E[] => [...pass(200), ...pass(200), ...enroll, ...shed, ...shed];

export function tallyOf(events: E[], options: { injectedFault?: () => void } = {}) {
  const counters = new OutcomeCounters(options);
  for (const event of events) counters.observe(event);
  return counters.snapshot();
}
export const journalOf = (events: E[]): Record<string, number> => { const out: Record<string, number> = {}; for (const event of events) out[event.kind] = (out[event.kind] ?? 0) + 1; return out; };
export const noExternal = { accepted: 0, strippedHeaders: 0, reduced: 0, l1: { entered: 0, passed: 0, rejected: 0, shed: 0, error: 0 }, l2: { entered: 0, decided: 0 }, egress: { attempted: 0, responded: 0, failed: 0 }, proofsIssued: 0, statusHistogram: {}, clientAborted: 0 };

/** What the runner writes as kind-ledger.json for a clean run of these events (every event received, in order, once). */
export function ledgerArtifact(events: E[]) {
  const ledger = new EventKindLedger();
  events.forEach((event, index) => ledger.observe({ ...event, seq: index + 1, nonce: "n" }));
  return ledger.artifact({ received: events.length, lastSeq: events.length, droppedReported: 0 });
}
/** The plane's final stats (`processes.json` plane) for a clean, drained channel that carried `n` events. */
export const planeFinOf = (n: number) => ({ drained: true, channel: { emitted: n, dropped: 0, sent: n, received: n, queued: 0, unacknowledged: 0, queueHighWater: 3, lastSeq: n } });
/** server-level.json / core.json / manifest result of one completed level. */
export const levelEvidence = () => ({
  serverLevel: { schema: "ba0-server-level-v1", campaignId: "campaign-a", levelId: "ba0-l7-c1", gitSha: "a".repeat(40), paramsFingerprintSha256: "b".repeat(64), serverSide: { status: "complete", failureClass: null, reasons: [] } },
  core: { level: { id: "ba0-l7-c1" }, machine: { phasesCompleted: true }, serverSide: { status: "complete", failureClass: null, reasons: [] } },
  manifestResult: "SERVER-COMPLETE",
});

/** Complete, valid criterion 9 evidence for `events`. */
export function validInput(events: E[] = workload()): TallyCheckInput {
  return {
    tally: tallyOf(events), tallyFromFinalTick: true, journalByKind: journalOf(events), journalIncomplete: false, external: noExternal,
    kindLedger: ledgerArtifact(events), planeFin: planeFinOf(events.length), duplicateKeys: [], level: levelEvidence(),
  };
}
