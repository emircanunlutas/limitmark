/**
 * Observation-only cross-checks over the plane's own OUTCOME TALLY (lab/defense/outcome-counters.ts; the in-tree copy lives in PROPOSED-INSTRUMENTATION-WIRING.patch). Pure functions: no I/O, no clock.
 *
 * `checkOutcomeIdentities` verifies the tally against itself (quiescent snapshot: nothing in flight). `compareToLedger` reports every kind
 * whose plane-side count differs from the collector's ledger count: that difference is an UNEXPLAINED difference (typically events dropped
 * on the bounded channel). Neither function decides an admission, changes a verdict or is read by the verdict path; a caller may attach the
 * result to evidence as an advisory finding.
 */
import type { OutcomeSnapshot } from "./outcome-counters";

const sum = (table: Record<string, number>): number => Object.values(table).reduce((a, b) => a + b, 0);

export type IdentityFinding = { id: string; expected: number; actual: number };

export function checkOutcomeIdentities(snapshot: OutcomeSnapshot, options: { l2: boolean }): IdentityFinding[] {
  const e = snapshot.events;
  const findings: IdentityFinding[] = [];
  const same = (id: string, expected: number, actual: number): void => { if (expected !== actual) findings.push({ id, expected, actual }); };
  same("I1 L1 entered = passed+rejected+shed+error", e.L1_ENTERED, e.L1_PASSED + e.L1_REJECTED + e.L1_SHED + e.L1_ERROR);
  same("I2 reject reasons sum = L1 rejected", e.L1_REJECTED, sum(snapshot.rejectReasons));
  same("I3 egress attempted = responded+failed", e.EGRESS_ATTEMPTED, e.EGRESS_RESPONDED + e.EGRESS_FAILED);
  same("I4 ingress accepted = responded+aborted", e.INGRESS_ACCEPTED, e.INGRESS_RESPONDED + e.INGRESS_ABORTED);
  same("I5 client status buckets sum = responded", e.INGRESS_RESPONDED, sum(snapshot.clientResponseStatus));
  same("I6 egress status buckets sum = egress responded", e.EGRESS_RESPONDED, sum(snapshot.egressResponseStatus));
  same("I7 egress failure kinds sum = egress failed", e.EGRESS_FAILED, sum(snapshot.egressFailures));
  if (options.l2) {
    same("I8 L2 entered = L1 passed", e.L2_ENTERED, e.L1_PASSED);
    same("I9 L2 decided = L2 entered", e.L2_ENTERED, e.L2_DECIDED);
    same("I10 L2 decision buckets sum = L2 decided", e.L2_DECIDED, sum(snapshot.l2Decisions));
  }
  same("I11 no value outside a closed list", 0, snapshot.unknown);
  same("I12 no observer fault", 0, snapshot.faults);
  return findings;
}

export type LedgerDifference = { kind: string; plane: number; ledger: number };

/** Every event kind for which the plane's own count and the collector's ledger count disagree. Empty = no unexplained difference. */
export function compareToLedger(snapshot: OutcomeSnapshot, ledgerCounts: Readonly<Record<string, number>>): LedgerDifference[] {
  const out: LedgerDifference[] = [];
  for (const kind of Object.keys(snapshot.events)) {
    const ledger = ledgerCounts[kind] ?? 0;
    if (snapshot.events[kind] !== ledger) out.push({ kind, plane: snapshot.events[kind], ledger });
  }
  return out;
}
