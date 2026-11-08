/**
 * M1 criterion 9 (owner decision, 2026-11-08): the plane's own outcome tally and the collector ledger must agree per event kind, every tally identity must
 * hold, and an absent tally, a non-zero `faults` count or a non-zero `unknown` count fails M1 acceptance.
 *
 * A pure, read-only evaluator. The CLI (ba0-m1-tally-check.ts) reads the finalized evidence; nothing here touches I/O, a clock or the verdict path.
 *
 * Outcomes follow the approved overlay vocabulary: PASS (evaluated, no reasons) | REJECT (evaluated, reasons) | ERROR (not evaluable, reasons). The tally
 * being ABSENT is REJECT (the evidence was read and the tally is not in it); evidence that cannot be read or is incomplete is ERROR. Neither is acceptance.
 *
 * WHAT THE LEDGER SIDE IS. Stored evidence holds the ledger in two places: the journal (every plane event of a request the collector owns: the canary and
 * anonymous events) and the external reducer's counters (every request of the remote generator). The per-kind ledger count is journal + external. The
 * reducer does not count `L2_ENROLLED` / `L2_ENROLL_SKIPPED`, so when the remote generator was accepted at all (external.accepted > 0) the ledger count of those
 * two kinds is NOT observable and the kind is reported `ledger_unobservable` -- a failure, never an assumed agreement. This is a limit of today's evidence
 * artifacts, reported as such.
 */
import type { OutcomeSnapshot } from "./outcome-counters";
import { checkOutcomeIdentities, compareToLedger, type LedgerDifference } from "./plane-outcome-check";

export type TallyCheckResult = {
  evaluated: boolean;
  outcome: "PASS" | "REJECT" | "ERROR";
  reasons: string[];
  /** Per kind where the plane's count and the observable ledger count disagree (explicit, never absorbed). */
  differences: LedgerDifference[];
  /** Kinds whose ledger count cannot be observed from stored evidence while remote traffic was accepted. */
  unobservable: string[];
};

export type TallyCheckInput = {
  /** `data.outcomes` of the plane's FINAL telemetry tick; undefined/null when the tick carried none. */
  tally: unknown;
  /** True when that tick is the plane's final tick (a quiescent snapshot). */
  tallyFromFinalTick: boolean;
  /** Plane events per kind from the ledger journal (all kinds, including those absent from the plane's list), or null when the journal is unavailable. */
  journalByKind: Record<string, number> | null;
  /** The journal reached its size limit or failed its recorded digest: its counts are not a complete ledger. */
  journalIncomplete: boolean;
  /** `external.json.counters`, or null when unavailable. */
  external: unknown;
};

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const countTable = (value: unknown): Record<string, number> | null => {
  if (!isRecord(value)) return null;
  const out: Record<string, number> = Object.create(null);
  for (const [key, count] of Object.entries(value)) { if (!isCount(count)) return null; out[key] = count; }
  return out;
};

/** Kinds the reducer's counters cannot supply for remote traffic. */
export const EXTERNAL_UNOBSERVABLE_KINDS: readonly string[] = Object.freeze(["L2_ENROLLED", "L2_ENROLL_SKIPPED"]);

/** Per-kind counts the external reducer's aggregate counters imply for remote-lane requests, or null when the counters are malformed. */
export function externalKindCounts(external: unknown): { observable: Record<string, number>; accepted: number } | null {
  if (!isRecord(external)) return null;
  const { accepted, l1, l2, egress, proofsIssued, statusHistogram, clientAborted } = external;
  const l1t = isRecord(l1) ? l1 : null; const l2t = isRecord(l2) ? l2 : null; const egr = isRecord(egress) ? egress : null; const histogram = countTable(statusHistogram);
  if (!isCount(accepted) || l1t === null || l2t === null || egr === null || histogram === null || !isCount(proofsIssued) || !isCount(clientAborted)) return null;
  const need = [l1t.entered, l1t.passed, l1t.rejected, l1t.shed, l1t.error, l2t.entered, l2t.decided, egr.attempted, egr.responded, egr.failed];
  if (!need.every(isCount)) return null;
  return {
    accepted,
    observable: {
      INGRESS_ACCEPTED: accepted, L1_ENTERED: l1t.entered as number, L1_PASSED: l1t.passed as number, L1_REJECTED: l1t.rejected as number, L1_SHED: l1t.shed as number, L1_ERROR: l1t.error as number,
      EGRESS_ATTEMPTED: egr.attempted as number, PROOF_ISSUED: proofsIssued, EGRESS_RESPONDED: egr.responded as number, EGRESS_FAILED: egr.failed as number,
      INGRESS_RESPONDED: Object.values(histogram).reduce((a, b) => a + b, 0), INGRESS_ABORTED: clientAborted, L2_ENTERED: l2t.entered as number, L2_DECIDED: l2t.decided as number,
      PARSER_REJECTED: 0,
    },
  };
}

function readSnapshot(value: unknown): OutcomeSnapshot | null {
  if (!isRecord(value) || value.version !== 1 || !isCount(value.unknown) || !isCount(value.faults)) return null;
  const tables = ["events", "rejectReasons", "l2Decisions", "l2ShedReasons", "l2ErrorKinds", "egressFailures", "egressResponseStatus", "clientResponseStatus"] as const;
  const out: Record<string, unknown> = { version: 1, unknown: value.unknown, faults: value.faults };
  for (const name of tables) { const table = countTable(value[name]); if (table === null) return null; out[name] = table; }
  return out as unknown as OutcomeSnapshot;
}

const IDENTITY_REASON: Record<string, string> = { I11: "m1.tally.unknown_nonzero", I12: "m1.tally.faults_nonzero" };

/** Never throws. */
export function evaluateTallyAgainstLedger(input: TallyCheckInput): TallyCheckResult {
  const error = (reason: string): TallyCheckResult => ({ evaluated: false, outcome: "ERROR", reasons: [reason], differences: [], unobservable: [] });
  try {
    if (input.tally === null || input.tally === undefined) return { evaluated: true, outcome: "REJECT", reasons: ["m1.tally.tally_missing"], differences: [], unobservable: [] };
    const snapshot = readSnapshot(input.tally);
    if (snapshot === null) return error("m1.tally.evidence_malformed_tally");
    if (input.journalByKind === null) return error("m1.tally.evidence_journal_unavailable");
    const journal = countTable(input.journalByKind);
    if (journal === null) return error("m1.tally.evidence_malformed_journal");
    if (input.journalIncomplete) return error("m1.tally.evidence_journal_incomplete");
    const external = externalKindCounts(input.external);
    if (external === null) return error("m1.tally.evidence_malformed_external");

    const reasons: string[] = [];
    if (!input.tallyFromFinalTick) reasons.push("m1.tally.not_final_tick");
    if (snapshot.unknown !== 0) reasons.push("m1.tally.unknown_nonzero");
    if (snapshot.faults !== 0) reasons.push("m1.tally.faults_nonzero");
    for (const finding of checkOutcomeIdentities(snapshot, { l2: true })) {
      const key = finding.id.split(" ")[0];
      reasons.push(IDENTITY_REASON[key] ?? `m1.tally.identity_${key.toLowerCase()}_fails`);
    }

    const unobservable = external.accepted > 0 ? EXTERNAL_UNOBSERVABLE_KINDS.filter((kind) => Object.hasOwn(snapshot.events, kind)) : [];
    const ledger: Record<string, number> = Object.create(null);
    for (const kind of Object.keys(snapshot.events)) ledger[kind] = (journal[kind] ?? 0) + (external.observable[kind] ?? 0);
    // Unobservable kinds are excluded from the equality comparison and reported separately: their ledger count is not knowable, so agreement can neither be shown nor denied.
    const comparable: OutcomeSnapshot = { ...snapshot, events: Object.fromEntries(Object.entries(snapshot.events).filter(([kind]) => !unobservable.includes(kind))) };
    const differences = compareToLedger(comparable, ledger);
    for (const difference of differences) reasons.push(`m1.tally.difference_${difference.kind.toLowerCase()}`);
    for (const kind of unobservable) reasons.push(`m1.tally.ledger_unobservable_${kind.toLowerCase()}`);
    // The journal must not hold plane event kinds the tally does not know: that would be ledger activity the plane never tallied.
    for (const kind of Object.keys(journal)) if (!Object.hasOwn(snapshot.events, kind) && journal[kind] > 0) reasons.push(`m1.tally.ledger_kind_not_tallied_${kind.toLowerCase().replace(/[^a-z0-9_]/gu, "_").slice(0, 32)}`);

    const unique = [...new Set(reasons)];
    return unique.length === 0 ? { evaluated: true, outcome: "PASS", reasons: [], differences: [], unobservable: [] } : { evaluated: true, outcome: "REJECT", reasons: unique, differences, unobservable: [...unobservable] };
  } catch {
    return error("m1.tally.evaluation_failed");
  }
}

export function tallyCheckWellFormed(result: TallyCheckResult): boolean {
  if (result.outcome === "PASS") return result.evaluated && result.reasons.length === 0 && result.differences.length === 0 && result.unobservable.length === 0;
  if (result.outcome === "REJECT") return result.evaluated && result.reasons.length > 0;
  if (result.outcome === "ERROR") return !result.evaluated && result.reasons.length > 0;
  return false;
}
