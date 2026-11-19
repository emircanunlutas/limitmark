/**
 * M1 receipt reconciliation (additive, offline, pure). It is NOT criterion 9: criterion 9 accounts for the plane-to-collector event path; this evaluator reconciles what the
 * downstream observers say they received against what the ledger attributes to them. It never replaces or relaxes a field verdict.
 *
 * COUNTER SEMANTICS (every comparison below is justified by these definitions; connections are never compared with requests)
 *   - "request": one INGRESS_ACCEPTED at the plane, identified by a plane-minted nonce. "connection": a TCP connection (keep-alive makes connections <= requests; never compared).
 *   - "attempt": plane EGRESS_ATTEMPTED (one forward toward the Boundary). Failure before the Boundary is EGRESS_FAILED; E3 requires none in a valid level, so every attempt arrives.
 *   - Boundary counters (`processes.json` boundary.stats) count Boundary events at their emit point: arrived, admitted, rejected, appProofsIssued, relayed (BOUNDARY_FORWARDED),
 *     forwardResponded, forwardFailed, responded, aborted. Each increments with exactly one event of the same name.
 *   - App counters (appFin.stats.counters): admitted, refused, executed, stateMutations (APP_MUTATED); the origin-side `served` counters: received, completed, aborted.
 *     `served` is the only origin-side observation in the field level (the harness' "control" origin is a bypass probe, not a delivery observation).
 *   - The LEDGER attributes every event to exactly one of: the external reducer (remote-lane requests), a collector-registered record (the collector's own canary traffic,
 *     journaled with a request id), or the anonymous set (events whose nonce no record claimed, journaled without a request id). The Boundary/App stats must equal the sum
 *     of the three, per kind, EXACTLY: there is no permitted alternative path in this workload (rejections, refusals, parser/protocol refusals and forward failures are all
 *     required to be zero or explicitly counted by their own counters), so any difference is unexplained inflation or loss.
 *   - Channel `emitted` of each process equals the number of events of that process the ledger attributes (sum over all kinds): a dropped or unattributed event is a loss.
 *
 * LIMITATIONS (always reported, never silently dropped): receipts carry a nonce only. No event, counter or `processes.json` field names a run, campaign, level or origin
 * instance; the only run binding is the evidence directory and its manifest, and the generator report's own identity fields. A claim that a receipt belongs to THIS campaign
 * therefore cannot be established here (`campaignAttribution: "not_established"`); provenance verification has to supply it.
 *
 * Outcomes: PASS only when every identity holds on complete, inventoried evidence; REJECT for a violated identity; ERROR when evidence is missing or malformed.
 */
export const RECEIPT_CHECK_CONTRACT = "m1-receipt-check-v1";

export const BOUNDARY_KINDS = ["BOUNDARY_ARRIVED", "BOUNDARY_ADMITTED", "BOUNDARY_REJECTED", "APP_PROOF_ISSUED", "BOUNDARY_FORWARDED", "BOUNDARY_FORWARD_RESPONDED", "BOUNDARY_FORWARD_FAILED", "BOUNDARY_RESPONDED", "BOUNDARY_ABORTED"] as const;
export const APP_KINDS = ["APP_ADMITTED", "APP_REFUSED", "APP_EXECUTED", "APP_MUTATED", "APP_COMPLETED", "APP_ABORTED"] as const;
/** event kind -> [process stat name, external reducer counter name] */
const BOUNDARY_MAP: Record<(typeof BOUNDARY_KINDS)[number], [string, string]> = {
  BOUNDARY_ARRIVED: ["arrived", "arrived"], BOUNDARY_ADMITTED: ["admitted", "admitted"], BOUNDARY_REJECTED: ["rejected", "rejected"], APP_PROOF_ISSUED: ["appProofsIssued", "appProofsIssued"],
  BOUNDARY_FORWARDED: ["relayed", "relayed"], BOUNDARY_FORWARD_RESPONDED: ["forwardResponded", "forwardResponded"], BOUNDARY_FORWARD_FAILED: ["forwardFailed", "forwardFailed"],
  BOUNDARY_RESPONDED: ["responded", "responded"], BOUNDARY_ABORTED: ["aborted", "aborted"],
};
const APP_MAP: Record<(typeof APP_KINDS)[number], [string, string]> = {
  APP_ADMITTED: ["admitted", "admitted"], APP_REFUSED: ["refused", "refused"], APP_EXECUTED: ["executed", "executed"], APP_MUTATED: ["stateMutations", "mutated"],
  APP_COMPLETED: ["completed", "completed"], APP_ABORTED: ["aborted", "aborted"],
};

export type JournalReceipts = { boundary: Record<string, number>; app: Record<string, number>; anonymousBoundary: Record<string, number>; anonymousApp: Record<string, number> };

export type ReceiptCheckInput = {
  /** `external.json.counters` (the reducer's exact counters for remote-lane requests). */
  external: unknown;
  /** `processes.json` boundary / app entries. */
  boundaryFin: unknown;
  appFin: unknown;
  /** Per-kind Boundary/App events of collector-registered records (with request id) and anonymous ones (without), from the verified journal; null when unavailable. */
  journal: JournalReceipts | null;
  journalIncomplete: boolean;
  /** `accounting.json.anomalyTotal`. */
  anomalyTotal: unknown;
  /** `kind-ledger.json.counts` (plane events the collector received, per kind). */
  planeKindCounts: unknown;
  /** `canary.json.clientObservedMutations`: mutations the canary CLIENT saw succeed. */
  canaryClientMutations: unknown;
  /** The generator report's identity and counters, or undefined when none was supplied. */
  generator?: unknown;
  /** Identity of the server level the receipts are read from. */
  level?: { campaignId: unknown; levelId: unknown; gitSha: unknown };
  inventoryProblems?: readonly string[];
  /** Object keys that occurred more than once in any evidence file read. */
  duplicateKeys?: readonly string[];
};

export type ReceiptIdentity = { id: string; ok: boolean; left: number; right: number };
export type ReceiptCheckResult = {
  contract: typeof RECEIPT_CHECK_CONTRACT;
  outcome: "PASS" | "REJECT" | "ERROR";
  reasons: string[];
  identities: ReceiptIdentity[];
  limitations: string[];
  campaignAttribution: "not_established";
};

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const LIMITATIONS = ["receipts_nonce_only", "no_run_campaign_binding", "origin_is_app_served_only"];
const done = (outcome: ReceiptCheckResult["outcome"], reasons: string[], identities: ReceiptIdentity[] = []): ReceiptCheckResult =>
  ({ contract: RECEIPT_CHECK_CONTRACT, outcome, reasons: [...new Set(reasons)], identities, limitations: LIMITATIONS, campaignAttribution: "not_established" });

function table(value: unknown, allowed: readonly string[]): Record<string, number> | null {
  if (!isRecord(value)) return null;
  const out: Record<string, number> = {};
  for (const [key, count] of Object.entries(value)) { if (!isCount(count)) return null; out[key] = count; }
  void allowed;
  return out;
}
function counters(value: unknown, keys: readonly string[]): Record<string, number> | null {
  if (!isRecord(value)) return null;
  const out: Record<string, number> = {};
  for (const key of keys) { const entry = value[key]; if (!isCount(entry)) return null; out[key] = entry; }
  return out;
}
const channelOk = (value: unknown): { emitted: number; clean: boolean } | null => {
  if (!isRecord(value)) return null;
  const c = value;
  if (![c.emitted, c.dropped, c.sent, c.received, c.queued, c.unacknowledged, c.lastSeq].every(isCount)) return null;
  return { emitted: c.emitted as number, clean: c.dropped === 0 && c.queued === 0 && c.unacknowledged === 0 && c.sent === c.emitted && c.received === c.sent && c.lastSeq === c.emitted };
};

/** Never throws. */
export function evaluateReceipts(input: ReceiptCheckInput): ReceiptCheckResult {
  try {
    if ((input.inventoryProblems?.length ?? 0) > 0) return done("ERROR", ["m1.receipt.evidence_inventory_invalid"]);
    if ((input.duplicateKeys?.length ?? 0) > 0) return done("ERROR", ["m1.receipt.duplicate_json_keys"]);
    if (input.journal === null) return done("ERROR", ["m1.receipt.evidence_journal_unavailable"]);
    if (input.journalIncomplete) return done("ERROR", ["m1.receipt.evidence_journal_incomplete"]);
    if (!isCount(input.anomalyTotal)) return done("ERROR", ["m1.receipt.evidence_malformed_accounting"]);
    if (input.boundaryFin === undefined || input.boundaryFin === null || input.boundaryFin === "no_fin" || input.appFin === undefined || input.appFin === null || input.appFin === "no_fin")
      return done("REJECT", ["m1.receipt.receipt_evidence_missing"]);
    if (!isRecord(input.external) || !isRecord(input.external.boundary) || !isRecord(input.external.app) || !isRecord(input.external.egress)) return done("ERROR", ["m1.receipt.evidence_malformed_external"]);
    const bFin = input.boundaryFin as Record<string, unknown>; const aFin = input.appFin as Record<string, unknown>;
    if (!isRecord(bFin.stats) || !isRecord(aFin.stats) || !isRecord(aFin.stats.counters) || !isRecord(aFin.stats.served)) return done("ERROR", ["m1.receipt.evidence_malformed_receipts"]);
    const bStats = counters(bFin.stats, [...Object.values(BOUNDARY_MAP).map((entry) => entry[0]), "parserRejected", "protocolRefused"]);
    const aCounters = counters(aFin.stats.counters, ["admitted", "refused", "executed", "stateMutations", "parserRejected", "protocolRefused"]);
    const served = counters(aFin.stats.served, ["received", "completed", "aborted", "overloaded"]);
    const extB = counters(input.external.boundary, Object.values(BOUNDARY_MAP).map((entry) => entry[1]));
    const extA = counters(input.external.app, Object.values(APP_MAP).map((entry) => entry[1]));
    const extE = counters(input.external.egress, ["attempted", "responded", "failed"]);
    const bChannel = channelOk(bFin.channel); const aChannel = channelOk(aFin.channel);
    const j = input.journal;
    const jb = table(j.boundary, BOUNDARY_KINDS); const ja = table(j.app, APP_KINDS); const xb = table(j.anonymousBoundary, BOUNDARY_KINDS); const xa = table(j.anonymousApp, APP_KINDS);
    if (bStats === null || aCounters === null || served === null || extB === null || extA === null || extE === null || bChannel === null || aChannel === null || jb === null || ja === null || xb === null || xa === null)
      return done("ERROR", ["m1.receipt.evidence_malformed_receipts"]);
    const ledger = input.planeKindCounts;
    if (!isRecord(ledger) || !isCount(ledger.EGRESS_ATTEMPTED) || !isCount(ledger.EGRESS_FAILED)) return done("ERROR", ["m1.receipt.evidence_malformed_kind_ledger"]);
    if (!isCount(input.canaryClientMutations)) return done("ERROR", ["m1.receipt.evidence_malformed_canary"]);
    const accepted = isCount(input.external.accepted) ? input.external.accepted : null;
    if (accepted === null) return done("ERROR", ["m1.receipt.evidence_malformed_external"]);

    const reasons: string[] = [];
    const identities: ReceiptIdentity[] = [];
    const eq = (id: string, left: number, right: number): void => { const ok = left === right; identities.push({ id, ok, left, right }); if (!ok) reasons.push(`m1.receipt.${id}`); };

    // events of kinds the contract does not know are unattributable
    for (const key of [...Object.keys(jb), ...Object.keys(xb)]) if (!(BOUNDARY_KINDS as readonly string[]).includes(key)) reasons.push("m1.receipt.journal_unknown_kind");
    for (const key of [...Object.keys(ja), ...Object.keys(xa)]) if (!(APP_KINDS as readonly string[]).includes(key)) reasons.push("m1.receipt.journal_unknown_kind");

    // 1. the processes' own counters equal the ledger (reducer + registered canary + anonymous), per kind: unexplained inflation or loss is a violated identity
    let boundaryEvents = 0; let appEvents = 0;
    for (const kind of BOUNDARY_KINDS) {
      const [stat, ext] = BOUNDARY_MAP[kind]; const attributed = extB[ext] + (jb[kind] ?? 0) + (xb[kind] ?? 0);
      boundaryEvents += attributed; eq(`boundary_${stat}_equals_ledger`, bStats[stat], attributed);
    }
    for (const kind of APP_KINDS) {
      const [stat, ext] = APP_MAP[kind]; const attributed = extA[ext] + (ja[kind] ?? 0) + (xa[kind] ?? 0); appEvents += attributed;
      const own = stat === "completed" ? served.completed : stat === "aborted" ? served.aborted : aCounters[stat];
      eq(`app_${stat}_equals_ledger`, own, attributed);
    }
    // 2. channels: nothing was lost between the process and the collector, and the event totals equal what the ledger attributes
    if (!bChannel.clean || !aChannel.clean || bFin.drained !== true || aFin.drained !== true) reasons.push("m1.receipt.channel_incomplete");
    eq("boundary_channel_emitted_equals_attributed_events", bChannel.emitted, boundaryEvents);
    eq("app_channel_emitted_equals_attributed_events", aChannel.emitted, appEvents);
    if (input.anomalyTotal !== 0) reasons.push("m1.receipt.anomalies_nonzero");

    // 3. the pipeline chain inside the Boundary and App (documented E5 relations; verified identical for the collector's own traffic on real evidence)
    eq("boundary_arrived_equals_admitted_plus_rejected", bStats.arrived, bStats.admitted + bStats.rejected);
    eq("boundary_admitted_equals_app_proofs", bStats.admitted, bStats.appProofsIssued);
    eq("boundary_relayed_equals_admitted", bStats.relayed, bStats.admitted);
    eq("boundary_relayed_equals_forward_outcomes", bStats.relayed, bStats.forwardResponded + bStats.forwardFailed);
    eq("app_admitted_equals_boundary_forward_responded", aCounters.admitted, bStats.forwardResponded);
    eq("app_executed_equals_admitted", aCounters.executed, aCounters.admitted);
    eq("origin_received_equals_app_admitted", served.received, aCounters.admitted);
    eq("origin_completed_plus_aborted_equals_received", served.completed + served.aborted, served.received);
    // no alternative path exists in this workload: refusals, rejections and forward failures must be zero (E5)
    eq("no_boundary_rejections_or_refusals", bStats.rejected + bStats.parserRejected + bStats.protocolRefused + bStats.forwardFailed, 0);
    eq("no_app_refusals", aCounters.refused + aCounters.parserRejected + aCounters.protocolRefused, 0);
    eq("origin_overloaded_is_zero", served.overloaded, 0);

    // 4. plane to Boundary: every egress attempt arrived, and none failed (E3)
    eq("plane_egress_failed_is_zero", ledger.EGRESS_FAILED, 0);
    eq("plane_egress_attempts_equal_boundary_arrivals", ledger.EGRESS_ATTEMPTED, bStats.arrived);
    // 5. the external lane alone (reducer): each attempt reached the Boundary and was answered by the App (E3, E5)
    eq("external_egress_failed_is_zero", extE.failed, 0);
    eq("external_egress_attempts_equal_boundary_arrivals", extE.attempted, extB.arrived);
    eq("external_boundary_admitted_equals_app_proofs", extB.admitted, extB.appProofsIssued);
    eq("external_app_admitted_equals_forward_responded", extA.admitted, extB.forwardResponded);
    // 6. the independent canary client: mutations it saw succeed equal the App's mutations attributed to registered canary records
    eq("canary_client_mutations_equal_ledger", input.canaryClientMutations, ja.APP_MUTATED ?? 0);

    // 7. the generator (a separate process with its own identity) when the level carried remote traffic
    if (accepted > 0 || input.generator !== undefined) {
      const g = input.generator;
      if (!isRecord(g)) reasons.push("m1.receipt.generator_report_absent");
      else if (!isCount(g.attempted) || !isCount(g.responses) || !isCount(g.transportFailures) || !isRecord(g.statuses) || typeof g.campaignId !== "string" || typeof g.levelId !== "string" || typeof g.gitSha !== "string") return done("ERROR", ["m1.receipt.evidence_malformed_generator"]);
      else {
        const lv = input.level;
        if (!lv || g.campaignId !== lv.campaignId) reasons.push("m1.receipt.generator_campaign_mismatch");
        if (!lv || g.levelId !== lv.levelId) reasons.push("m1.receipt.generator_level_mismatch");
        if (!lv || g.gitSha !== lv.gitSha) reasons.push("m1.receipt.generator_git_mismatch");
        eq("generator_transport_failures_are_zero", g.transportFailures, 0); // a failure the server never saw would need explicit attribution; none exists
        eq("generator_responses_equal_external_accepted", g.responses, accepted);
        const serverStatuses = isRecord(input.external.statusHistogram) ? input.external.statusHistogram : null;
        const generatorStatuses = table(g.statuses, []);
        if (serverStatuses === null || generatorStatuses === null) return done("ERROR", ["m1.receipt.evidence_malformed_generator"]);
        const keys = new Set([...Object.keys(serverStatuses), ...Object.keys(generatorStatuses)]);
        let differing = 0; for (const key of keys) if ((generatorStatuses[key] ?? 0) !== (serverStatuses[key] ?? 0)) differing++;
        eq("generator_statuses_equal_server_statuses", differing, 0);
      }
    }
    return done(reasons.length === 0 ? "PASS" : "REJECT", reasons, identities);
  } catch { return done("ERROR", ["m1.receipt.evaluation_failed"]); }
}
