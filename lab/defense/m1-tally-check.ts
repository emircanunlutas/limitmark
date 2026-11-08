/**
 * M1 criterion 9 (owner decision, 2026-11-08): the plane's own outcome tally and the collector ledger must agree per event kind, every tally identity must
 * hold, and an absent tally, a non-zero `faults` count or a non-zero `unknown` count fails M1 acceptance.
 *
 * A pure, read-only evaluator. The CLI (ba0-m1-tally-check.ts) reads the finalized evidence; nothing here touches I/O, a clock or the verdict path.
 *
 * Outcomes follow the approved overlay vocabulary: PASS (evaluated, no reasons) | REJECT (evaluated, reasons) | ERROR (not evaluable, reasons). The tally
 * being ABSENT is REJECT (the evidence was read and the tally is not in it); evidence that cannot be read or is malformed is ERROR. Neither is acceptance.
 *
 * WHAT THIS PROVES. Internal accounting consistency of the plane-to-collector event path for ONE completed, non-empty level: the plane counted what it
 * emitted (tally), the collector counted what it received (kind ledger), and the plane's final channel accounting, the collector's own counters, the journal
 * and the external reducer all agree with both. It does NOT prove end-to-end delivery (criterion 2 does), and an event the plane never emitted is invisible
 * to every record here. Events lost before numbering cannot be detected; events lost after numbering are (gaps, channel anchors).
 *
 * ENFORCED IDENTITIES (each with its authoritative source; nothing is inferred across counters of different meaning):
 *   plane sender, `processes.json` plane.channel = `ChannelStats` of the plane's event channel (defense/core/ledger.ts):
 *     S1 emitted === lastSeq                           both advance once per emitted event (`nextSeq - 1`, `emittedCount`)
 *     S2 emitted === dropped + sent + queued           an emitted event is either dropped at the full queue, sent, or still queued
 *     S3 unacknowledged === sent - received            by definition in `stats()`
 *     S4 drained && queued === 0 && unacknowledged === 0 && dropped === 0   quiescent, nothing lost (the collector's own finalization check says the same)
 *   collector, `kind-ledger.json` collector = the collector's own receive counters, taken independently of the ledger's per-kind counting:
 *     C1 collector.received === ledger.total + unsupported + duplicatesOrReordered + malformed   every received event reached the ledger observer exactly once
 *     C2 plane.emitted === collector.received + plane.dropped                                    (the collector's finalization identity)
 *     C3 plane.received === collector.received                                                   the plane's acknowledged count is the collector's count
 *     C4 plane.lastSeq === collector.lastSeq === ledger.lastSeq; ledger.missingSeqs === plane.dropped; collector.droppedReported <= plane.dropped
 *   tally and ledger: the tally key set equals the closed vocabulary exactly (no key is ever treated as zero), counts equal per kind, identities I1..I12 hold,
 *   unknown === 0 and faults === 0.
 *   level: `server-level.json`, `core.json` and the manifest describe ONE complete level (same level id), and the level was not empty.
 *   cross-records: ledger[k] === journal[k] + reducer[k] for each kind the reducer counts; ledger[k] >= journal[k] for the two enrollment kinds, whose remote
 *   share the reducer does not count (a lower bound only; equality with the tally still applies to them).
 * `kind-ledger.json` is MANDATORY. A run without it is REJECTED, never accepted by a weaker rule.
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
  /** Which record was used as the ledger. */
  ledgerSource: "kind-ledger" | "none";
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
  /** `kind-ledger.json`; undefined/null when the evidence has none (mandatory: absent is REJECT). */
  kindLedger?: unknown;
  /** The plane's final stats (`processes.json` plane: `{ drained, channel }`); undefined/null when absent (completeness then cannot be anchored: REJECT). */
  planeFin?: unknown;
  /** Object keys that occurred more than once in any evidence file read (JSON.parse silently keeps the last). */
  duplicateKeys?: readonly string[];
  /** `{ serverLevel, core, manifestResult }` read from the same evidence directory; undefined/null when absent (REJECT). */
  level?: unknown;
};

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const countTable = (value: unknown): Record<string, number> | null => {
  if (!isRecord(value)) return null;
  const out: Record<string, number> = Object.create(null);
  for (const [key, count] of Object.entries(value)) { if (!isCount(count)) return null; out[key] = count; }
  return out;
};

/** Object keys that appear twice in one JSON object of `text` (JSON.parse keeps the last silently). Returns `path:key` entries; a text that does not parse returns []. */
export function findDuplicateObjectKeys(text: string): string[] {
  const found: string[] = [];
  let index = 0;
  const skip = (): void => { while (index < text.length && " \t\r\n".includes(text[index])) index++; };
  const string = (): string => {
    const start = index; index++;
    while (index < text.length && text[index] !== '"') index += text[index] === "\\" ? 2 : 1;
    index++;
    return JSON.parse(text.slice(start, index)) as string;
  };
  const value = (path: string): void => {
    skip();
    const c = text[index];
    if (c === "{") {
      index++; const seen = new Set<string>(); skip();
      if (text[index] === "}") { index++; return; }
      for (;;) {
        skip(); const key = string(); if (seen.has(key)) found.push(`${path}:${key.slice(0, 40)}`); seen.add(key);
        skip(); index++; value(`${path}.${key.slice(0, 24)}`); skip();
        if (text[index] === ",") { index++; continue; }
        index++; return;
      }
    } else if (c === "[") {
      index++; skip();
      if (text[index] === "]") { index++; return; }
      for (;;) { value(`${path}[]`); skip(); if (text[index] === ",") { index++; continue; } index++; return; }
    } else if (c === '"') string();
    else while (index < text.length && !",}] \t\r\n".includes(text[index])) index++;
  };
  try { JSON.parse(text); value("$"); } catch { return []; }
  return found.slice(0, 20);
}

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

type KindLedger = {
  counts: Record<string, number>; total: number; firstSeq: number | null; lastSeq: number; missingSeqs: number; duplicatesOrReordered: number; unsupported: number; malformed: number;
  collector: { received: number; lastSeq: number; droppedReported: number };
};

/** Strict shape check of kind-ledger.json: the exact closed key set, integer counts, the collector's own counters. */
function readKindLedger(value: unknown): KindLedger | null {
  if (!isRecord(value) || value.schema !== KIND_LEDGER_SCHEMA) return null;
  const counts = countTable(value.counts);
  if (counts === null || Object.keys(counts).length !== KIND_LEDGER_KINDS.length || !KIND_LEDGER_KINDS.every((kind) => Object.hasOwn(counts, kind))) return null;
  const { total, firstSeq, lastSeq, missingSeqs, duplicatesOrReordered, unsupported, malformed, collector } = value;
  if (!isCount(total) || !isCount(lastSeq) || !isCount(missingSeqs) || !isCount(duplicatesOrReordered) || !isCount(unsupported) || !isCount(malformed)) return null;
  if (!(firstSeq === null || (isCount(firstSeq) && firstSeq >= 1))) return null;
  if (!isRecord(collector) || !isCount(collector.received) || !isCount(collector.lastSeq) || !isCount(collector.droppedReported)) return null;
  return { counts, total, firstSeq, lastSeq, missingSeqs, duplicatesOrReordered, unsupported, malformed, collector: { received: collector.received, lastSeq: collector.lastSeq, droppedReported: collector.droppedReported } };
}

type PlaneFin = { drained: boolean; emitted: number; dropped: number; sent: number; received: number; queued: number; unacknowledged: number; lastSeq: number };
function readPlaneFin(value: unknown): PlaneFin | null {
  if (!isRecord(value) || typeof value.drained !== "boolean" || !isRecord(value.channel)) return null;
  const c = value.channel;
  if (![c.emitted, c.dropped, c.sent, c.received, c.queued, c.unacknowledged, c.lastSeq].every(isCount)) return null;
  return { drained: value.drained, emitted: c.emitted as number, dropped: c.dropped as number, sent: c.sent as number, received: c.received as number, queued: c.queued as number, unacknowledged: c.unacknowledged as number, lastSeq: c.lastSeq as number };
}

type LevelEvidence = { levelId: string; complete: boolean; coreLevelId: string; manifestComplete: boolean };
/** Reads the level identity/completion evidence; null when its shape is not recognizable (ERROR). */
function readLevel(value: unknown): LevelEvidence | null {
  if (!isRecord(value) || !isRecord(value.serverLevel) || !isRecord(value.core) || typeof value.manifestResult !== "string") return null;
  const { serverLevel, core } = value;
  const status = isRecord(serverLevel.serverSide) ? serverLevel.serverSide : null;
  const coreLevel = isRecord(core.level) ? core.level : null;
  const machine = isRecord(core.machine) ? core.machine : null;
  const coreServer = isRecord(core.serverSide) ? core.serverSide : null;
  if (status === null || coreLevel === null || machine === null || coreServer === null) return null;
  if (typeof serverLevel.levelId !== "string" || typeof coreLevel.id !== "string" || serverLevel.schema !== "ba0-server-level-v1") return null;
  if (typeof serverLevel.campaignId !== "string" || typeof serverLevel.gitSha !== "string" || typeof serverLevel.paramsFingerprintSha256 !== "string") return null;
  const reasons = Array.isArray(status.reasons) ? status.reasons : null;
  if (reasons === null) return null;
  const complete = status.status === "complete" && status.failureClass === null && reasons.length === 0 && coreServer.status === "complete" && machine.phasesCompleted === true;
  return { levelId: serverLevel.levelId, complete, coreLevelId: coreLevel.id, manifestComplete: value.manifestResult === "SERVER-COMPLETE" };
}

const IDENTITY_REASON: Record<string, string> = { I11: "m1.tally.unknown_nonzero", I12: "m1.tally.faults_nonzero" };
const slug = (kind: string): string => kind.toLowerCase().replace(/[^a-z0-9_]/gu, "_").slice(0, 32);
const empty = (outcome: TallyCheckResult["outcome"], reasons: string[]): TallyCheckResult => ({ evaluated: outcome !== "ERROR", outcome, reasons, differences: [], ledgerSource: "none" });

/** Never throws. */
export function evaluateTallyAgainstLedger(input: TallyCheckInput): TallyCheckResult {
  try {
    if (input.tally === null || input.tally === undefined) return empty("REJECT", ["m1.tally.tally_missing"]);
    const snapshot = readSnapshot(input.tally);
    if (snapshot === null) return empty("ERROR", ["m1.tally.evidence_malformed_tally"]);
    if (input.journalByKind === null) return empty("ERROR", ["m1.tally.evidence_journal_unavailable"]);
    const journal = countTable(input.journalByKind);
    if (journal === null) return empty("ERROR", ["m1.tally.evidence_malformed_journal"]);
    if (input.journalIncomplete) return empty("ERROR", ["m1.tally.evidence_journal_incomplete"]);
    const external = externalKindCounts(input.external);
    if (external === null) return empty("ERROR", ["m1.tally.evidence_malformed_external"]);
    // F-2: the kind ledger is mandatory; there is no weaker fallback.
    if (input.kindLedger === undefined || input.kindLedger === null) return empty("REJECT", ["m1.tally.kind_ledger_absent"]);
    const kindLedger = readKindLedger(input.kindLedger);
    if (kindLedger === null) return empty("ERROR", ["m1.tally.evidence_malformed_kind_ledger"]);
    const haveFin = input.planeFin !== undefined && input.planeFin !== null;
    const fin = haveFin ? readPlaneFin(input.planeFin) : null;
    if (haveFin && fin === null) return empty("ERROR", ["m1.tally.evidence_malformed_plane_channel"]);
    const haveLevel = input.level !== undefined && input.level !== null;
    const level = haveLevel ? readLevel(input.level) : null;
    if (haveLevel && level === null) return empty("ERROR", ["m1.tally.evidence_malformed_level"]);

    const reasons: string[] = [];
    if ((input.duplicateKeys?.length ?? 0) > 0) reasons.push("m1.tally.duplicate_json_keys");
    if (!input.tallyFromFinalTick) reasons.push("m1.tally.not_final_tick");

    // F-1: the tally key set is the closed vocabulary, exactly. An absent key is never read as zero.
    const tallyKeys = Object.keys(snapshot.events);
    for (const kind of KIND_LEDGER_KINDS) if (!Object.hasOwn(snapshot.events, kind)) reasons.push(`m1.tally.tally_key_missing_${slug(kind)}`);
    if (tallyKeys.some((key) => !KIND_LEDGER_KINDS.includes(key))) reasons.push("m1.tally.tally_key_unexpected");

    if (snapshot.unknown !== 0) reasons.push("m1.tally.unknown_nonzero");
    if (snapshot.faults !== 0) reasons.push("m1.tally.faults_nonzero");
    for (const finding of checkOutcomeIdentities(snapshot, { l2: true })) {
      const key = finding.id.split(" ")[0];
      reasons.push(IDENTITY_REASON[key] ?? `m1.tally.identity_${key.toLowerCase()}_fails`);
    }

    // the ledger's own integrity
    const sum = Object.values(kindLedger.counts).reduce((a, b) => a + b, 0);
    const accepted = kindLedger.total + kindLedger.unsupported;
    const consistent = sum === kindLedger.total && kindLedger.lastSeq === accepted + kindLedger.missingSeqs && (accepted === 0 ? kindLedger.firstSeq === null && kindLedger.lastSeq === 0 : kindLedger.firstSeq === 1);
    if (!consistent) reasons.push("m1.tally.ledger_internally_inconsistent");
    if (kindLedger.missingSeqs > 0) reasons.push("m1.tally.ledger_sequence_gap");
    if (kindLedger.duplicatesOrReordered > 0) reasons.push("m1.tally.ledger_duplicates_or_reordered");
    if (kindLedger.malformed > 0) reasons.push("m1.tally.ledger_malformed_events");
    if (kindLedger.unsupported > 0) reasons.push("m1.tally.ledger_unsupported_kinds");

    // F-3: the plane's final channel accounting (S1..S4), the collector's own counters (C1..C4)
    const col = kindLedger.collector;
    if (col.received !== kindLedger.total + kindLedger.unsupported + kindLedger.duplicatesOrReordered + kindLedger.malformed) reasons.push("m1.tally.collector_received_vs_ledger");
    if (fin === null) reasons.push("m1.tally.ledger_completeness_unanchored");
    else {
      if (fin.emitted !== fin.lastSeq) reasons.push("m1.tally.channel_emitted_vs_lastseq");
      if (fin.emitted !== fin.dropped + fin.sent + fin.queued) reasons.push("m1.tally.channel_emitted_identity");
      if (fin.unacknowledged !== fin.sent - fin.received) reasons.push("m1.tally.channel_unacknowledged_identity");
      if (!fin.drained || fin.queued !== 0 || fin.unacknowledged !== 0) reasons.push("m1.tally.channel_not_quiescent");
      if (fin.dropped !== 0) reasons.push("m1.tally.channel_dropped_nonzero");
      if (kindLedger.lastSeq !== fin.lastSeq || kindLedger.missingSeqs !== fin.dropped) reasons.push("m1.tally.ledger_anchor_mismatch");
      if (col.lastSeq !== fin.lastSeq) reasons.push("m1.tally.collector_lastseq_mismatch");
      if (fin.emitted !== col.received + fin.dropped) reasons.push("m1.tally.collector_received_vs_emitted");
      if (fin.received !== col.received) reasons.push("m1.tally.channel_received_vs_collector");
      if (col.droppedReported > fin.dropped) reasons.push("m1.tally.collector_dropped_reported");
    }

    // the plane tally against the ledger, kind by kind (present keys only: a missing key is already a rejection, never a zero)
    const differences = compareToLedger(snapshot, kindLedger.counts);
    for (const difference of differences) reasons.push(`m1.tally.difference_${slug(difference.kind)}`);

    // the older, independent records
    for (const kind of KIND_LEDGER_KINDS) {
      const own = journal[kind] ?? 0;
      const remote = external.observable[kind];
      const ok = remote !== undefined ? kindLedger.counts[kind] === own + remote
        : external.accepted === 0 ? kindLedger.counts[kind] === own : kindLedger.counts[kind] >= own; // enrollment kinds: the reducer's remote share is unknown unless no remote traffic was accepted
      if (!ok) reasons.push(`m1.tally.ledger_vs_reducer_${slug(kind)}`);
    }
    for (const kind of Object.keys(journal)) if (journal[kind] > 0 && !Object.hasOwn(kindLedger.counts, kind)) reasons.push(`m1.tally.ledger_kind_not_tallied_${slug(kind)}`);

    // F-4: one completed, non-empty level, identified by the existing level evidence
    if (level === null) reasons.push("m1.tally.level_evidence_missing");
    else {
      if (level.levelId !== level.coreLevelId) reasons.push("m1.tally.level_identity_mismatch");
      if (!level.complete || !level.manifestComplete) reasons.push("m1.tally.level_not_complete");
    }
    if (kindLedger.total === 0 || kindLedger.counts.INGRESS_ACCEPTED === 0 || (snapshot.events.INGRESS_ACCEPTED ?? 0) === 0) reasons.push("m1.tally.level_empty");

    const unique = [...new Set(reasons)];
    return unique.length === 0
      ? { evaluated: true, outcome: "PASS", reasons: [], differences: [], ledgerSource: "kind-ledger" }
      : { evaluated: true, outcome: "REJECT", reasons: unique, differences, ledgerSource: "kind-ledger" };
  } catch {
    return empty("ERROR", ["m1.tally.evaluation_failed"]);
  }
}

export function tallyCheckWellFormed(result: TallyCheckResult): boolean {
  if (result.outcome === "PASS") return result.evaluated && result.reasons.length === 0 && result.differences.length === 0;
  if (result.outcome === "REJECT") return result.evaluated && result.reasons.length > 0;
  if (result.outcome === "ERROR") return !result.evaluated && result.reasons.length > 0;
  return false;
}
