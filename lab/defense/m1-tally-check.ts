/**
 * M1 criterion 9 (owner decision, 2026-11-08): the plane's own outcome tally and the collector ledger must agree per event kind, every tally identity must
 * hold, and an absent tally, a non-zero `faults` count or a non-zero `unknown` count fails M1 acceptance.
 *
 * A pure, read-only evaluator. The CLI (ba0-m1-tally-check.ts) reads the finalized evidence; nothing here touches I/O, a clock or the verdict path.
 *
 * Outcomes follow the approved overlay vocabulary: PASS (evaluated, no reasons) | REJECT (evaluated, reasons) | ERROR (not evaluable, reasons). The tally
 * being ABSENT is REJECT (the evidence was read and the tally is not in it); evidence that cannot be read or is incomplete is ERROR. Neither is acceptance.
 *
 * LEDGER SOURCES, strongest first.
 *   1. `kind-ledger.json` (event-kind-ledger.ts): a per-kind count of EVERY plane event the collector ingested, with a gapless-sequence integrity record.
 *      When present it is the ledger. It is checked for internal consistency, against the plane's own final channel stats (lastSeq / dropped), against
 *      the plane tally, and against the two older independent records (journal + external reducer counters) kind by kind.
 *   2. Without it (evidence written before the ledger existed): journal + external reducer counters. The reducer does not count `L2_ENROLLED` /
 *      `L2_ENROLL_SKIPPED`, so when remote traffic was accepted those two kinds are `ledger_unobservable` -- a failure, never an assumed agreement.
 * What is NOT claimed: events the plane never emitted (pre-parser traffic, kernel drops) and events lost on the plane's own bounded channel before
 * numbering are outside any of these records; the ledger can only show the numbered events and flag the gaps it sees.
 */
import { KIND_LEDGER_KINDS, KIND_LEDGER_SCHEMA } from "./event-kind-ledger";
import type { OutcomeSnapshot } from "./outcome-counters";
import { checkOutcomeIdentities, compareToLedger, type LedgerDifference } from "./plane-outcome-check";

export type TallyCheckResult = {
  evaluated: boolean;
  outcome: "PASS" | "REJECT" | "ERROR";
  reasons: string[];
  /** Per kind where the plane's count and the ledger count disagree (explicit, never absorbed). */
  differences: LedgerDifference[];
  /** Kinds whose ledger count cannot be observed from stored evidence while remote traffic was accepted (only without a kind ledger). */
  unobservable: string[];
  /** Which record was used as the ledger. */
  ledgerSource: "kind-ledger" | "journal-and-reducer" | "none";
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
  /** `kind-ledger.json`; undefined/null when the evidence has none (an older run). */
  kindLedger?: unknown;
  /** The plane's final channel stats (`processes.json` plane.channel: emitted / dropped / lastSeq), the authoritative sequence anchor; undefined/null when absent. */
  planeChannel?: unknown;
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

type KindLedger = { counts: Record<string, number>; total: number; firstSeq: number | null; lastSeq: number; missingSeqs: number; duplicatesOrReordered: number; unsupported: number; malformed: number };

/** Strict shape check of kind-ledger.json: the exact closed key set, integer counts, nothing extra required to be trusted. */
function readKindLedger(value: unknown): KindLedger | null {
  if (!isRecord(value) || value.schema !== KIND_LEDGER_SCHEMA) return null;
  const counts = countTable(value.counts);
  if (counts === null || Object.keys(counts).length !== KIND_LEDGER_KINDS.length || !KIND_LEDGER_KINDS.every((kind) => Object.hasOwn(counts, kind))) return null;
  const { total, firstSeq, lastSeq, missingSeqs, duplicatesOrReordered, unsupported, malformed } = value;
  if (!isCount(total) || !isCount(lastSeq) || !isCount(missingSeqs) || !isCount(duplicatesOrReordered) || !isCount(unsupported) || !isCount(malformed)) return null;
  if (!(firstSeq === null || (isCount(firstSeq) && firstSeq >= 1))) return null;
  return { counts, total, firstSeq, lastSeq, missingSeqs, duplicatesOrReordered, unsupported, malformed };
}

function readPlaneChannel(value: unknown): { lastSeq: number; dropped: number } | null {
  if (!isRecord(value) || !isCount(value.lastSeq) || !isCount(value.dropped)) return null;
  return { lastSeq: value.lastSeq, dropped: value.dropped };
}

const IDENTITY_REASON: Record<string, string> = { I11: "m1.tally.unknown_nonzero", I12: "m1.tally.faults_nonzero" };
const slug = (kind: string): string => kind.toLowerCase().replace(/[^a-z0-9_]/gu, "_").slice(0, 32);

/** Never throws. */
export function evaluateTallyAgainstLedger(input: TallyCheckInput): TallyCheckResult {
  const error = (reason: string): TallyCheckResult => ({ evaluated: false, outcome: "ERROR", reasons: [reason], differences: [], unobservable: [], ledgerSource: "none" });
  try {
    if (input.tally === null || input.tally === undefined) return { evaluated: true, outcome: "REJECT", reasons: ["m1.tally.tally_missing"], differences: [], unobservable: [], ledgerSource: "none" };
    const snapshot = readSnapshot(input.tally);
    if (snapshot === null) return error("m1.tally.evidence_malformed_tally");
    if (input.journalByKind === null) return error("m1.tally.evidence_journal_unavailable");
    const journal = countTable(input.journalByKind);
    if (journal === null) return error("m1.tally.evidence_malformed_journal");
    if (input.journalIncomplete) return error("m1.tally.evidence_journal_incomplete");
    const external = externalKindCounts(input.external);
    if (external === null) return error("m1.tally.evidence_malformed_external");
    const haveLedger = input.kindLedger !== undefined && input.kindLedger !== null;
    const kindLedger = haveLedger ? readKindLedger(input.kindLedger) : null;
    if (haveLedger && kindLedger === null) return error("m1.tally.evidence_malformed_kind_ledger");

    const reasons: string[] = [];
    if (!input.tallyFromFinalTick) reasons.push("m1.tally.not_final_tick");
    if (snapshot.unknown !== 0) reasons.push("m1.tally.unknown_nonzero");
    if (snapshot.faults !== 0) reasons.push("m1.tally.faults_nonzero");
    for (const finding of checkOutcomeIdentities(snapshot, { l2: true })) {
      const key = finding.id.split(" ")[0];
      reasons.push(IDENTITY_REASON[key] ?? `m1.tally.identity_${key.toLowerCase()}_fails`);
    }

    let differences: LedgerDifference[];
    let unobservable: string[] = [];
    let ledgerSource: TallyCheckResult["ledgerSource"];

    if (kindLedger !== null) {
      ledgerSource = "kind-ledger";
      // 1. the ledger's own integrity
      const sum = Object.values(kindLedger.counts).reduce((a, b) => a + b, 0);
      const accepted = kindLedger.total + kindLedger.unsupported;
      const consistent = sum === kindLedger.total && kindLedger.lastSeq === accepted + kindLedger.missingSeqs && (accepted === 0 ? kindLedger.firstSeq === null && kindLedger.lastSeq === 0 : kindLedger.firstSeq === 1);
      if (!consistent) reasons.push("m1.tally.ledger_internally_inconsistent");
      if (kindLedger.missingSeqs > 0) reasons.push("m1.tally.ledger_sequence_gap");
      if (kindLedger.duplicatesOrReordered > 0) reasons.push("m1.tally.ledger_duplicates_or_reordered");
      if (kindLedger.malformed > 0) reasons.push("m1.tally.ledger_malformed_events");
      if (kindLedger.unsupported > 0) reasons.push("m1.tally.ledger_unsupported_kinds");
      // 2. the authoritative anchor: the plane's own final channel stats. Without it completeness is NOT established (stated, not assumed).
      const channel = input.planeChannel === undefined || input.planeChannel === null ? null : readPlaneChannel(input.planeChannel);
      if (input.planeChannel !== undefined && input.planeChannel !== null && channel === null) return error("m1.tally.evidence_malformed_plane_channel");
      if (channel === null) reasons.push("m1.tally.ledger_completeness_unanchored");
      else if (kindLedger.lastSeq !== channel.lastSeq || kindLedger.missingSeqs !== channel.dropped) reasons.push("m1.tally.ledger_anchor_mismatch");
      // 3. the plane tally against the ledger, kind by kind (the two L2 enrollment kinds included)
      differences = compareToLedger(snapshot, kindLedger.counts);
      for (const difference of differences) reasons.push(`m1.tally.difference_${slug(difference.kind)}`);
      // 4. the older, independent records: ledger = journal (canary and anonymous events) + the reducer's remote-lane counts
      for (const kind of KIND_LEDGER_KINDS) {
        const own = journal[kind] ?? 0;
        const remote = external.observable[kind];
        const ok = remote !== undefined ? kindLedger.counts[kind] === own + remote
          : external.accepted === 0 ? kindLedger.counts[kind] === own : kindLedger.counts[kind] >= own; // the reducer's remote contribution to this kind is unknown unless no remote traffic was accepted
        if (!ok) reasons.push(`m1.tally.ledger_vs_reducer_${slug(kind)}`);
      }
      for (const kind of Object.keys(journal)) if (journal[kind] > 0 && !Object.hasOwn(kindLedger.counts, kind)) reasons.push(`m1.tally.ledger_kind_not_tallied_${slug(kind)}`);
    } else {
      ledgerSource = "journal-and-reducer";
      unobservable = external.accepted > 0 ? EXTERNAL_UNOBSERVABLE_KINDS.filter((kind) => Object.hasOwn(snapshot.events, kind)) : [];
      const ledger: Record<string, number> = Object.create(null);
      for (const kind of Object.keys(snapshot.events)) ledger[kind] = (journal[kind] ?? 0) + (external.observable[kind] ?? 0);
      // Unobservable kinds are excluded from the equality comparison and reported separately: their ledger count is not knowable, so agreement can neither be shown nor denied.
      const comparable: OutcomeSnapshot = { ...snapshot, events: Object.fromEntries(Object.entries(snapshot.events).filter(([kind]) => !unobservable.includes(kind))) };
      differences = compareToLedger(comparable, ledger);
      for (const difference of differences) reasons.push(`m1.tally.difference_${slug(difference.kind)}`);
      for (const kind of unobservable) reasons.push(`m1.tally.ledger_unobservable_${slug(kind)}`);
      // The journal must not hold plane event kinds the tally does not know: that would be ledger activity the plane never tallied.
      for (const kind of Object.keys(journal)) if (!Object.hasOwn(snapshot.events, kind) && journal[kind] > 0) reasons.push(`m1.tally.ledger_kind_not_tallied_${slug(kind)}`);
    }

    const unique = [...new Set(reasons)];
    return unique.length === 0
      ? { evaluated: true, outcome: "PASS", reasons: [], differences: [], unobservable: [], ledgerSource }
      : { evaluated: true, outcome: "REJECT", reasons: unique, differences, unobservable: [...unobservable], ledgerSource };
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
