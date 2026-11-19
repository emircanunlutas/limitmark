/**
 * Explicit observation-completeness check for the independent observers. Pure; never throws. It is SEPARATE from the telemetry gap tolerance of the defense event-kind ledger
 * (MAX_GAP_RANGES in lab/defense/event-kind-ledger.ts), which concerns the defense plane's own event stream and is neither read nor widened here.
 *
 * Nothing is silently tolerated. Observer completeness is proven by evidence the observer itself declares and the verifier recounts:
 *   - the origin receipt collector's receipts carry a gapless sequence 1..n and the collector's closing declaration states the same count and last sequence;
 *   - the collector's declared coverage window contains the whole run window;
 *   - the collector's heartbeats (one per interval) leave no gap longer than the limit the OWNER sets before the run; with no limit set the check is INCOMPLETE, never PASS;
 *   - the canary declares the number of steps it planned and returned exactly that many;
 *   - every canary step that succeeded has an origin receipt for its request id (an unreceipted success is an observation failure, never ignored).
 * A request shed before the origin legitimately has no receipt, so a missing receipt for a NON-successful step is not a failure by itself.
 */
export const COMPLETENESS_CONTRACT = "m1-observation-completeness-v1";

export type ReceiptLike = { seq: number; requestId: string | null };
export type CollectorDeclaration = { receiptCount: number; lastSeq: number; coverageStartMs: number; coverageEndMs: number; heartbeatsMs: number[] };
export type CanaryLike = { requestId: string; ok: boolean };
export type CompletenessInput = {
  receipts: unknown; declaration: unknown; canarySteps: unknown; canaryPlannedSteps: number | null;
  runWindow: { startMs: number; endMs: number }; maxHeartbeatGapMs: number | null;
};
export type CompletenessResult = { contract: typeof COMPLETENESS_CONTRACT; outcome: "PASS" | "REJECT" | "INCOMPLETE" | "ERROR"; reasons: string[]; qualification: "UNREACHABLE" };

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

export function evaluateObservationCompleteness(input: CompletenessInput): CompletenessResult {
  const done = (outcome: CompletenessResult["outcome"], reasons: string[]): CompletenessResult => ({ contract: COMPLETENESS_CONTRACT, outcome, reasons: [...new Set(reasons)], qualification: "UNREACHABLE" });
  try {
    if (!Array.isArray(input.receipts)) return done("ERROR", ["m1.complete.receipts_unavailable"]);
    if (!Array.isArray(input.canarySteps)) return done("ERROR", ["m1.complete.canary_steps_unavailable"]);
    if (!isRecord(input.declaration)) return done("ERROR", ["m1.complete.collector_declaration_missing"]);
    const d = input.declaration;
    if (!isCount(d.receiptCount) || !isCount(d.lastSeq) || !isCount(d.coverageStartMs) || !isCount(d.coverageEndMs) || !Array.isArray(d.heartbeatsMs) || !d.heartbeatsMs.every(isCount)) return done("ERROR", ["m1.complete.collector_declaration_malformed"]);
    const receipts = input.receipts;
    if (!receipts.every((r) => isRecord(r) && isCount(r.seq) && (r.requestId === null || typeof r.requestId === "string"))) return done("ERROR", ["m1.complete.receipts_malformed"]);
    const got = receipts as ReceiptLike[];
    const steps = input.canarySteps;
    if (!steps.every((s) => isRecord(s) && typeof s.requestId === "string" && typeof s.ok === "boolean")) return done("ERROR", ["m1.complete.canary_steps_malformed"]);
    const canary = steps as CanaryLike[];

    const reasons: string[] = []; const incomplete: string[] = [];
    // collector receipts: gapless 1..n, in order, matching its own closing declaration
    got.forEach((receipt, index) => { if (receipt.seq !== index + 1) reasons.push("m1.complete.receipt_sequence_gap"); });
    if (d.receiptCount !== got.length) reasons.push("m1.complete.declared_receipt_count_mismatch");
    if (d.lastSeq !== (got.length === 0 ? 0 : got[got.length - 1]!.seq)) reasons.push("m1.complete.declared_last_sequence_mismatch");
    // coverage of the whole run window
    if (!(isCount(input.runWindow.startMs) && isCount(input.runWindow.endMs) && input.runWindow.endMs > input.runWindow.startMs)) return done("ERROR", ["m1.complete.run_window_invalid"]);
    if (d.coverageStartMs > input.runWindow.startMs || d.coverageEndMs < input.runWindow.endMs) reasons.push("m1.complete.collector_window_not_covering_run");
    // heartbeats: the limit is the owner's decision; without it nothing can be proven
    if (input.maxHeartbeatGapMs === null) incomplete.push("m1.complete.heartbeat_gap_limit_unset");
    else {
      const beats = [...d.heartbeatsMs].sort((a, b) => a - b);
      const marks = [input.runWindow.startMs, ...beats.filter((b) => b >= input.runWindow.startMs && b <= input.runWindow.endMs), input.runWindow.endMs];
      for (let i = 1; i < marks.length; i++) if (marks[i]! - marks[i - 1]! > input.maxHeartbeatGapMs) { reasons.push("m1.complete.heartbeat_gap_exceeded"); break; }
      if (beats.length === 0) reasons.push("m1.complete.no_heartbeats");
    }
    // canary completeness
    if (input.canaryPlannedSteps === null || !isCount(input.canaryPlannedSteps)) incomplete.push("m1.complete.canary_plan_unavailable");
    else if (canary.length !== input.canaryPlannedSteps) reasons.push("m1.complete.canary_steps_missing");
    // every successful canary step was seen at the origin
    const seen = new Set(got.map((r) => r.requestId).filter((id): id is string => id !== null));
    if (canary.some((step) => step.ok && !seen.has(step.requestId))) reasons.push("m1.complete.canary_success_without_origin_receipt");

    return done(reasons.length > 0 ? "REJECT" : incomplete.length > 0 ? "INCOMPLETE" : "PASS", [...reasons, ...incomplete]);
  } catch { return done("ERROR", ["m1.complete.evaluation_failed"]); }
}
