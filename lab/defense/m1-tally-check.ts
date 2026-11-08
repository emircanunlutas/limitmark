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
 *   level (R-4): `server-level.json`, `core.json` and `manifest.json` describe ONE complete level: level id, campaign id, parameter fingerprint, workload fingerprint,
 *     worker count and server-side status/failure class/reasons are equal across the artifacts that carry them; the git SHA of server-level equals the manifest's; the time
 *     window is present and well formed; status complete, no failure class, no reasons, phasesCompleted, no firstReason, and the recorded finalization steps
 *     (close_ingress, drain, final_telemetry, snapshot) all ok. A missing identity field is ERROR, never assumed.
 *   external lane (R-1/R-2), each counter compared only with a counter of the SAME meaning:
 *     X1 external.accepted > 0. `accepted` is the external reducer's count of remote-lane requests (plane INGRESS_ACCEPTED for requests the collector does not own); the
 *        collector's canary requests are owned by the collector and never reach the reducer, so canary traffic cannot satisfy this. No minimum above zero is imposed.
 *     X2 external.accepted === server-level.reconcileInput.externalAccepted, and the other copies in reconcileInput (statusHistogram, status503, classes, l1Rejected,
 *        egressFailed, connections.acceptedRemote) equal their source counters. These are copies of one source: they detect substitution and truncation of one artifact.
 *     X3 independent ingress evidence: connections.json final.acceptedRemote >= 1 (a remote request needs a remote connection; one connection may carry many requests
 *        or none, so no equality) and equals reconcileInput.connections.acceptedRemote; sum(terminal) === accepted with terminal.unresolved === 0 (reducer E1).
 *     X4 independent receipt evidence: the reducer's per-external-request boundary counters (arrived, admitted, rejected, relayed, responded) do not exceed the boundary
 *        process's own counters of the same name, and its app counters (admitted, refused, executed) do not exceed the origin app's own; boundary.arrived <= egress.attempted.
 *   cross-records: ledger[k] === journal[k] + reducer[k] for each kind the reducer counts; ledger[k] >= journal[k] for the two enrollment kinds, whose remote
 *   share the reducer does not count (a lower bound only; equality with the tally still applies to them).
 * `kind-ledger.json` is MANDATORY. A run without it is REJECTED, never accepted by a weaker rule.
 */
import { KIND_LEDGER_KINDS, KIND_LEDGER_SCHEMA } from "./event-kind-ledger";
import { FIELD_LEVELS, ba0FieldFingerprint, type Ba0FieldThresholds } from "./field-thresholds";
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
  /** R-5: problems found while verifying the SHA256SUMS inventory of the artifacts criterion 9 consumes (unlisted, mismatching, duplicate, aliased, conflicting). Any entry is an ERROR: the bytes cannot be trusted. */
  inventoryProblems?: readonly string[];
  /** `accounting.json.anomalyTotal` (the collector's anomaly count). Mandatory: absent or non-count is ERROR, nonzero is REJECT. */
  anomalyTotal?: unknown;
  /** `{ serverLevel, core, manifest }` (the parsed server-level.json, core.json, manifest.json) from the same evidence directory; undefined/null when absent (REJECT). */
  level?: unknown;
  /** `connections.json` (the plane listener's exact counters); undefined/null when absent (REJECT). */
  connections?: unknown;
  /** `processes.json` boundary and app entries (`{ drained, channel, stats }`, or the string "no_fin"); absent or "no_fin" is REJECT (no receipt evidence). */
  boundaryFin?: unknown;
  appFin?: unknown;
};

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const countTable = (value: unknown): Record<string, number> | null => {
  if (!isRecord(value)) return null;
  const out: Record<string, number> = Object.create(null);
  for (const [key, count] of Object.entries(value)) { if (!isCount(count)) return null; out[key] = count; }
  return out;
};

/** Object keys that appear twice in one JSON object of `text` (JSON.parse keeps the last silently). Returns `path:key` entries; a text that does not parse returns []; a text that parses but cannot be scanned returns a `scanner-failed` entry. */
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
    path = path.length > 120 ? path.slice(0, 120) : path;
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
  try { JSON.parse(text); } catch { return []; } // invalid JSON is reported by the parser every consumer runs
  try { value("$"); } catch { return ["$:scanner-failed"]; } // text that parses but defeats the scanner (for example extreme nesting) is a finding, never silently clean
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

type Lane = {
  accepted: number; terminalSum: number; unresolved: number; egressAttempted: number; egressFailed: number; l1Rejected: number;
  boundary: Record<"arrived" | "admitted" | "rejected" | "relayed" | "responded", number>; app: Record<"admitted" | "refused" | "executed", number>;
  statusHistogram: Record<string, number>; status503: { total: number; expectedShed: number; unexplained: number }; classes: Record<string, number>;
};
/** The external reducer's counters this check relies on, or null when any is missing or not an exact count. */
function readLane(external: unknown): Lane | null {
  if (!isRecord(external)) return null;
  const { accepted, terminal, egress, l1, boundary, app, statusHistogram, status503, l2 } = external;
  const term = countTable(terminal); const hist = countTable(statusHistogram);
  if (!isCount(accepted) || term === null || hist === null || !isRecord(egress) || !isRecord(l1) || !isRecord(boundary) || !isRecord(app) || !isRecord(status503) || !isRecord(l2)) return null;
  const classes = countTable(l2.classes);
  const b = ["arrived", "admitted", "rejected", "relayed", "responded"].map((k) => boundary[k]); const a = ["admitted", "refused", "executed"].map((k) => app[k]);
  if (classes === null || !isCount(egress.attempted) || !isCount(egress.failed) || !isCount(l1.rejected) || !b.every(isCount) || !a.every(isCount)) return null;
  if (!isCount(status503.total) || !isCount(status503.expectedShed) || !isCount(status503.unexplained)) return null;
  return {
    accepted, terminalSum: Object.values(term).reduce((x, y) => x + y, 0), unresolved: term.unresolved ?? 0, egressAttempted: egress.attempted, egressFailed: egress.failed, l1Rejected: l1.rejected,
    boundary: { arrived: b[0] as number, admitted: b[1] as number, rejected: b[2] as number, relayed: b[3] as number, responded: b[4] as number },
    app: { admitted: a[0] as number, refused: a[1] as number, executed: a[2] as number },
    statusHistogram: hist, status503: { total: status503.total, expectedShed: status503.expectedShed, unexplained: status503.unexplained }, classes,
  };
}
const sameTable = (x: Record<string, number>, y: Record<string, number>): boolean => {
  const keys = new Set([...Object.keys(x), ...Object.keys(y)]);
  for (const key of keys) if ((x[key] ?? 0) !== (y[key] ?? 0)) return false;
  return true;
};

/** Receipt counters of a downstream process (processes.json boundary / app entry); null when it is the string "no_fin" or absent; undefined when malformed. */
function readBoundaryStats(value: unknown): Record<"arrived" | "admitted" | "rejected" | "relayed" | "responded", number> | null | undefined {
  if (value === undefined || value === null || typeof value === "string") return null;
  if (!isRecord(value) || !isRecord(value.stats)) return undefined;
  const s = value.stats; const keys = ["arrived", "admitted", "rejected", "relayed", "responded"] as const;
  if (!keys.every((k) => isCount(s[k]))) return undefined;
  return { arrived: s.arrived as number, admitted: s.admitted as number, rejected: s.rejected as number, relayed: s.relayed as number, responded: s.responded as number };
}
function readAppStats(value: unknown): Record<"admitted" | "refused" | "executed", number> | null | undefined {
  if (value === undefined || value === null || typeof value === "string") return null;
  if (!isRecord(value) || !isRecord(value.stats) || !isRecord(value.stats.counters)) return undefined;
  const c = value.stats.counters;
  if (!isCount(c.admitted) || !isCount(c.refused) || !isCount(c.executed)) return undefined;
  return { admitted: c.admitted, refused: c.refused, executed: c.executed };
}

type LevelEvidence = {
  levelId: string; coreLevelId: string; campaignId: string; coreCampaignId: string; paramsSha: string; coreParamsSha: string; workloadSha: string; coreWorkloadSha: string;
  workers: number; coreWorkers: number; gitSha: string; manifestGitSha: string; statusSame: boolean; complete: boolean; manifestComplete: boolean; windowValid: boolean;
  firstReasonSet: boolean; finalizationOk: boolean;
  coreParamsId: string; coreParamsVersion: unknown; dirty: boolean; windowConsistent: boolean;
  reconcile: { externalAccepted: number; statusHistogram: Record<string, number>; status503: { total: number; expectedShed: number; unexplained: number }; classes: Record<string, number>; l1Rejected: number; egressFailed: number; acceptedRemote: number } | null;
};
/** The wall-clock window (two Date reads) and `elapsedMs` (one monotonic span, rounded) are captured in adjacent statements by the field run; they are different clocks, so exact equality is not a valid test. 1 s bounds rounding and scheduling jitter and nothing else. */
const WINDOW_SKEW_MS = 1_000;
const HEX40 = /^[0-9a-f]{40}$/u; const HEX64 = /^[0-9a-f]{64}$/u;
const REQUIRED_STEPS = ["close_ingress", "drain", "final_telemetry", "snapshot"];
/** Reads the level identity/completion evidence; null when its shape is not recognizable (ERROR). Every identity field is required: nothing is defaulted. */
function readLevel(value: unknown): LevelEvidence | null {
  if (!isRecord(value) || !isRecord(value.serverLevel) || !isRecord(value.core) || !isRecord(value.manifest)) return null;
  const { serverLevel, core, manifest } = value;
  const status = isRecord(serverLevel.serverSide) ? serverLevel.serverSide : null;
  const coreLevel = isRecord(core.level) ? core.level : null;
  const params = isRecord(core.parameters) ? core.parameters : null;
  const machine = isRecord(core.machine) ? core.machine : null;
  const coreServer = isRecord(core.serverSide) ? core.serverSide : null;
  const git = isRecord(manifest.git) ? manifest.git : null;
  if (status === null || coreLevel === null || params === null || machine === null || coreServer === null || git === null) return null;
  if (serverLevel.schema !== "ba0-server-level-v1" || typeof manifest.result !== "string") return null;
  if (typeof serverLevel.levelId !== "string" || typeof coreLevel.id !== "string" || typeof serverLevel.campaignId !== "string" || typeof coreLevel.campaignId !== "string") return null;
  if (typeof serverLevel.gitSha !== "string" || !HEX40.test(serverLevel.gitSha) || typeof git.gitSha !== "string" || !HEX40.test(git.gitSha)) return null;
  if (typeof serverLevel.paramsFingerprintSha256 !== "string" || !HEX64.test(serverLevel.paramsFingerprintSha256) || typeof params.sha256 !== "string" || !HEX64.test(params.sha256)) return null;
  if (typeof serverLevel.workloadFingerprintSha256 !== "string" || !HEX64.test(serverLevel.workloadFingerprintSha256) || typeof core.workloadSha256 !== "string" || !HEX64.test(core.workloadSha256)) return null;
  if (!isCount(serverLevel.workers) || !isCount(coreLevel.workers)) return null;
  const reasons = Array.isArray(status.reasons) ? status.reasons : null; const coreReasons = Array.isArray(coreServer.reasons) ? coreServer.reasons : null;
  if (reasons === null || coreReasons === null || typeof status.status !== "string" || typeof coreServer.status !== "string") return null;
  if (!("failureClass" in status) || !("failureClass" in coreServer) || !("firstReason" in core) || !Array.isArray(core.sequence) || typeof machine.phasesCompleted !== "boolean") return null;
  const codes = (list: unknown[]): string => JSON.stringify(list.map((entry) => (isRecord(entry) ? entry.code : entry)));
  const w = serverLevel.window;
  const windowValid = isRecord(w) && typeof w.openedAt === "string" && typeof w.closedAt === "string" && Number.isFinite(Date.parse(w.openedAt)) && Number.isFinite(Date.parse(w.closedAt)) &&
    Date.parse(w.closedAt) >= Date.parse(w.openedAt) && typeof w.elapsedMs === "number" && Number.isFinite(w.elapsedMs) && w.elapsedMs >= 0;
  if (typeof git.dirty !== "boolean" || typeof params.id !== "string") return null;
  const windowConsistent = windowValid && Math.abs((Date.parse((w as { closedAt: string }).closedAt) - Date.parse((w as { openedAt: string }).openedAt)) - (w as { elapsedMs: number }).elapsedMs) <= WINDOW_SKEW_MS;
  const steps = core.sequence as unknown[];
  const finalizationOk = steps.every((step) => isRecord(step) && step.ok === true && step.timedOut !== true && step.skippedByCap !== true) &&
    REQUIRED_STEPS.every((name) => steps.some((step) => isRecord(step) && step.name === name));
  let reconcile: LevelEvidence["reconcile"] = null;
  const ri = serverLevel.reconcileInput;
  if (isRecord(ri)) {
    const hist = countTable(ri.statusHistogram); const classes = countTable(ri.classes); const s5 = ri.status503; const conn = ri.connections;
    if (isCount(ri.externalAccepted) && hist !== null && classes !== null && isRecord(s5) && isCount(s5.total) && isCount(s5.expectedShed) && isCount(s5.unexplained) &&
        isCount(ri.l1Rejected) && isCount(ri.egressFailed) && isRecord(conn) && isCount(conn.acceptedRemote)) {
      reconcile = { externalAccepted: ri.externalAccepted, statusHistogram: hist, status503: { total: s5.total, expectedShed: s5.expectedShed, unexplained: s5.unexplained }, classes, l1Rejected: ri.l1Rejected, egressFailed: ri.egressFailed, acceptedRemote: conn.acceptedRemote };
    } else return null;
  } else if (ri !== null && ri !== undefined) return null;
  return {
    levelId: serverLevel.levelId, coreLevelId: coreLevel.id, campaignId: serverLevel.campaignId, coreCampaignId: coreLevel.campaignId, paramsSha: serverLevel.paramsFingerprintSha256, coreParamsSha: params.sha256,
    workloadSha: serverLevel.workloadFingerprintSha256, coreWorkloadSha: core.workloadSha256, workers: serverLevel.workers, coreWorkers: coreLevel.workers, gitSha: serverLevel.gitSha, manifestGitSha: git.gitSha,
    statusSame: status.status === coreServer.status && JSON.stringify(status.failureClass) === JSON.stringify(coreServer.failureClass) && codes(reasons) === codes(coreReasons),
    complete: status.status === "complete" && status.failureClass === null && reasons.length === 0 && coreServer.status === "complete" && coreServer.failureClass === null && coreReasons.length === 0 && machine.phasesCompleted === true,
    manifestComplete: manifest.result === "SERVER-COMPLETE", windowValid, coreParamsId: params.id, coreParamsVersion: params.version, dirty: git.dirty, windowConsistent, firstReasonSet: core.firstReason !== null, finalizationOk, reconcile,
  };
}

const IDENTITY_REASON: Record<string, string> = { I11: "m1.tally.unknown_nonzero", I12: "m1.tally.faults_nonzero" };
const slug = (kind: string): string => kind.toLowerCase().replace(/[^a-z0-9_]/gu, "_").slice(0, 32);
const empty = (outcome: TallyCheckResult["outcome"], reasons: string[]): TallyCheckResult => ({ evaluated: outcome !== "ERROR", outcome, reasons, differences: [], ledgerSource: "none" });

/** Never throws. */
export function evaluateTallyAgainstLedger(input: TallyCheckInput): TallyCheckResult {
  try {
    if ((input.inventoryProblems?.length ?? 0) > 0) return empty("ERROR", ["m1.tally.evidence_inventory_invalid"]);
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
    const lane = readLane(input.external);
    if (lane === null) return empty("ERROR", ["m1.tally.evidence_malformed_external"]);
    const boundaryStats = readBoundaryStats(input.boundaryFin); const appStats = readAppStats(input.appFin);
    if (boundaryStats === undefined || appStats === undefined) return empty("ERROR", ["m1.tally.evidence_malformed_receipts"]);
    const haveConnections = input.connections !== undefined && input.connections !== null;
    let acceptedRemote: number | null = null;
    if (haveConnections) {
      const c = input.connections;
      if (!isRecord(c) || (c.final !== "not_available" && !(isRecord(c.final) && isCount(c.final.acceptedRemote)))) return empty("ERROR", ["m1.tally.evidence_malformed_connections"]);
      if (isRecord(c.final)) acceptedRemote = c.final.acceptedRemote as number;
    }

    const reasons: string[] = [];
    if ((input.duplicateKeys?.length ?? 0) > 0) reasons.push("m1.tally.duplicate_json_keys");
    if (!input.tallyFromFinalTick) reasons.push("m1.tally.not_final_tick");
    if (!isCount(input.anomalyTotal)) return empty("ERROR", ["m1.tally.evidence_malformed_accounting"]);
    if (input.anomalyTotal !== 0) reasons.push("m1.tally.anomalies_nonzero");

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

    // R-4: one completed level, identified consistently across the artifacts that carry its identity
    if (level === null) reasons.push("m1.tally.level_evidence_missing");
    else {
      if (level.levelId !== level.coreLevelId) reasons.push("m1.tally.level_identity_mismatch");
      if (level.campaignId !== level.coreCampaignId) reasons.push("m1.tally.level_campaign_mismatch");
      if (level.paramsSha !== level.coreParamsSha) reasons.push("m1.tally.level_params_mismatch");
      if (level.workloadSha !== level.coreWorkloadSha) reasons.push("m1.tally.level_workload_mismatch");
      if (level.workers !== level.coreWorkers) reasons.push("m1.tally.level_workers_mismatch");
      if (level.gitSha !== level.manifestGitSha) reasons.push("m1.tally.level_git_mismatch");
      if (!level.statusSame) reasons.push("m1.tally.level_status_mismatch");
      if (!level.complete || !level.manifestComplete) reasons.push("m1.tally.level_not_complete");
      if (!level.windowValid) reasons.push("m1.tally.level_window_invalid");
      else if (!level.windowConsistent) reasons.push("m1.tally.level_window_elapsed_inconsistent");
      if (level.dirty) reasons.push("m1.tally.source_tree_dirty");
      const pinned = Object.hasOwn(FIELD_LEVELS, level.levelId) ? ba0FieldFingerprint((FIELD_LEVELS as Record<string, { thresholds: Ba0FieldThresholds }>)[level.levelId].thresholds) : null;
      if (pinned === null || level.paramsSha !== pinned.sha256 || level.coreParamsSha !== pinned.sha256 || level.coreParamsId !== pinned.id || level.coreParamsVersion !== pinned.version) reasons.push("m1.tally.params_not_code_pinned");
      if (level.firstReasonSet) reasons.push("m1.tally.level_first_reason_set");
      if (!level.finalizationOk) reasons.push("m1.tally.level_finalization_incomplete");
    }
    // F-4: a non-empty level (plane-side)
    if (kindLedger.total === 0 || kindLedger.counts.INGRESS_ACCEPTED === 0 || (snapshot.events.INGRESS_ACCEPTED ?? 0) === 0) reasons.push("m1.tally.level_empty");

    // R-1 / R-2: authoritative external-lane activity. Each comparison is between counters of the same meaning (see the header).
    if (lane.accepted === 0) reasons.push("m1.tally.external_lane_inactive");
    if ((snapshot.events.INGRESS_ACCEPTED ?? 0) < lane.accepted) reasons.push("m1.tally.external_exceeds_plane_ingress");
    if (lane.terminalSum !== lane.accepted) reasons.push("m1.tally.external_terminal_vs_accepted");
    if (lane.unresolved !== 0) reasons.push("m1.tally.external_unresolved");
    if (level !== null) {
      if (level.reconcile === null) reasons.push("m1.tally.reconcile_input_missing");
      else {
        const r = level.reconcile;
        if (r.externalAccepted !== lane.accepted) reasons.push("m1.tally.external_accepted_vs_reconcile_input");
        if (!sameTable(r.statusHistogram, lane.statusHistogram) || r.status503.total !== lane.status503.total || r.status503.expectedShed !== lane.status503.expectedShed ||
            r.status503.unexplained !== lane.status503.unexplained || !sameTable(r.classes, lane.classes) || r.l1Rejected !== lane.l1Rejected || r.egressFailed !== lane.egressFailed) reasons.push("m1.tally.reconcile_input_vs_external");
        if (acceptedRemote !== null && r.acceptedRemote !== acceptedRemote) reasons.push("m1.tally.connections_vs_reconcile_input");
      }
    }
    if (acceptedRemote === null) reasons.push("m1.tally.connections_missing");
    else if (lane.accepted > 0 && acceptedRemote < 1) reasons.push("m1.tally.external_without_remote_connection");
    if (lane.boundary.arrived > lane.egressAttempted) reasons.push("m1.tally.receipt_exceeds_attempts");
    if (boundaryStats === null || appStats === null) reasons.push("m1.tally.receipt_evidence_missing");
    else {
      if (!(["arrived", "admitted", "rejected", "relayed", "responded"] as const).every((k) => lane.boundary[k] <= boundaryStats[k])) reasons.push("m1.tally.boundary_receipts_contradict");
      if (!(["admitted", "refused", "executed"] as const).every((k) => lane.app[k] <= appStats[k])) reasons.push("m1.tally.app_receipts_contradict");
    }

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
