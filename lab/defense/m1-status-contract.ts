/**
 * M1 client-visible status contract (criterion 8): a pure, additive overlay over the evidence the reviewed `ba0-l7-c1` level already writes.
 *
 * It adds no verdict category and changes no historical verdict. It produces `statusOverlay: { evaluated, outcome, reasons }`:
 *
 *   PASS    evaluated = true,  reasons empty
 *   REJECT  evaluated = true,  reasons non-empty (the contract was evaluated and is not met)
 *   ERROR   evaluated = false, reasons non-empty (the evidence could not be evaluated; this is NEVER acceptance)
 *
 * M1 acceptance requires the unchanged base verdict to be EXTERNAL-L7-QUALIFICATION-VALID AND the overlay to PASS (`m1Accepted`).
 * A base INVALID or ABORTED can therefore never become an accepted M1 result, and an overlay can only ADD reasons: nothing here upgrades,
 * hides or rewrites a base reason.
 *
 * Contract (owner decision, 2026-11-08, for the existing synthetic-origin fixture only):
 *   - every status with a non-zero count, in the generator view AND in the server view, is 200 or 503;
 *   - every 503 is a server-attributed expected shed: the server's `status503.unexplained` is 0 and `total` equals `expectedShed`, the generator's
 *     503 count equals `expectedShed`, and the server histogram's 503 count equals `total`. (Which cause an expected shed has is closed elsewhere:
 *     the reviewed E8 identities tie `expectedShed` to the L2 `mutation.unverified.lane_budget` count and `allowedShed` is a single reviewed entry.)
 * Not claimed: any coverage of 302/303 or 403/404 (the fixture never produces them), network or transport behaviour, or anything outside the
 * application plane.
 */
import type { FinalVerdict } from "./field-verdict";

export const M1_STATUS_CONTRACT_ID = "m1-status-contract-v1";
/** Pinned. Confirmed empirically on the real plane -> Boundary -> App chain with the reviewed fixture cycle (200 and 503 only). */
export const M1_ALLOWED_STATUSES: readonly string[] = Object.freeze(["200", "503"]);
export const M1_ALLOWED_STATUS_LABEL = M1_ALLOWED_STATUSES.join(",");

export type OverlayOutcome = "PASS" | "REJECT" | "ERROR";
export type StatusOverlay = { evaluated: boolean; outcome: OverlayOutcome; reasons: string[] };

export type OverlayInput = {
  /** The decision of the unchanged final-verdict path for the same two inputs; anything else is malformed. */
  baseVerdict: unknown;
  /** `statuses` of the generator report, or null/undefined when no report was supplied. */
  generatorStatuses: unknown;
  /** `reconcileInput.statusHistogram` of server-level.json. */
  serverStatusHistogram: unknown;
  /** `reconcileInput.status503` of server-level.json. */
  serverStatus503: unknown;
};

const VERDICTS: ReadonlySet<string> = new Set<FinalVerdict>(["EXTERNAL-L7-QUALIFICATION-VALID", "INVALID", "ABORTED"]);
const isPlainRecord = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/** A status histogram: status-code keys (1 to 3 digits) mapped to non-negative integer counts. Null when malformed. */
function readHistogram(value: unknown): Record<string, number> | null {
  if (!isPlainRecord(value)) return null;
  const out: Record<string, number> = Object.create(null);
  for (const [key, count] of Object.entries(value)) {
    if (!/^[0-9]{1,3}$/u.test(key) || !isCount(count)) return null;
    out[key] = count;
  }
  return out;
}

function readShed(value: unknown): { total: number; expectedShed: number; unexplained: number } | null {
  if (!isPlainRecord(value)) return null;
  const { total, expectedShed, unexplained } = value;
  return isCount(total) && isCount(expectedShed) && isCount(unexplained) ? { total, expectedShed, unexplained } : null;
}

const outsideAllowList = (histogram: Record<string, number>): boolean => Object.entries(histogram).some(([status, count]) => count > 0 && !M1_ALLOWED_STATUSES.includes(status));

/** Never throws. Anything that cannot be read is ERROR (evaluated = false), never PASS. */
export function evaluateStatusOverlay(input: OverlayInput): StatusOverlay {
  try {
    const malformed: string[] = [];
    const base = typeof input.baseVerdict === "string" && VERDICTS.has(input.baseVerdict) ? (input.baseVerdict as FinalVerdict) : null;
    if (base === null) malformed.push("m1.evidence_malformed.base_verdict");
    if (input.generatorStatuses === null || input.generatorStatuses === undefined) malformed.push("m1.evidence_missing.generator_statuses");
    const generator = input.generatorStatuses === null || input.generatorStatuses === undefined ? null : readHistogram(input.generatorStatuses);
    if (generator === null && !malformed.includes("m1.evidence_missing.generator_statuses")) malformed.push("m1.evidence_malformed.generator_statuses");
    const server = readHistogram(input.serverStatusHistogram);
    if (server === null) malformed.push("m1.evidence_malformed.server_status_histogram");
    const shed = readShed(input.serverStatus503);
    if (shed === null) malformed.push("m1.evidence_malformed.server_status503");
    if (malformed.length > 0 || base === null || generator === null || server === null || shed === null) return { evaluated: false, outcome: "ERROR", reasons: malformed.length > 0 ? malformed : ["m1.evaluation_failed"] };

    const reasons: string[] = [];
    if (outsideAllowList(generator)) reasons.push("m1.status_allowlist_generator");
    if (outsideAllowList(server)) reasons.push("m1.status_allowlist_server");
    if (shed.unexplained !== 0) reasons.push("m1.shed_unattributed");
    if (shed.total !== shed.expectedShed) reasons.push("m1.shed_total_not_expected");
    if ((generator["503"] ?? 0) !== shed.expectedShed) reasons.push("m1.generator_503_not_attributed");
    if ((server["503"] ?? 0) !== shed.total) reasons.push("m1.server_503_histogram_inconsistent");
    if (base !== "EXTERNAL-L7-QUALIFICATION-VALID") reasons.push("m1.base_verdict_not_valid");
    return reasons.length === 0 ? { evaluated: true, outcome: "PASS", reasons: [] } : { evaluated: true, outcome: "REJECT", reasons };
  } catch {
    return { evaluated: false, outcome: "ERROR", reasons: ["m1.evaluation_failed"] };
  }
}

/** The invariants of the approved schema. Used by the writer and by tests; a violating object must never be written or accepted. */
export function overlayIsWellFormed(overlay: unknown): overlay is StatusOverlay {
  if (!isPlainRecord(overlay)) return false;
  const { evaluated, outcome, reasons } = overlay;
  if (Object.keys(overlay).sort().join(",") !== "evaluated,outcome,reasons" || typeof evaluated !== "boolean" || !Array.isArray(reasons)) return false;
  if (!reasons.every((reason) => typeof reason === "string" && /^m1\.[a-z0-9_.]{1,60}$/u.test(reason))) return false;
  if (outcome === "PASS") return evaluated === true && reasons.length === 0;
  if (outcome === "REJECT") return evaluated === true && reasons.length > 0;
  if (outcome === "ERROR") return evaluated === false && reasons.length > 0;
  return false;
}

/** M1 acceptance of the status contract: base VALID and a well-formed, evaluated PASS. Everything else is not accepted. */
export function m1Accepted(baseVerdict: unknown, overlay: unknown): boolean {
  return baseVerdict === "EXTERNAL-L7-QUALIFICATION-VALID" && overlayIsWellFormed(overlay) && overlay.outcome === "PASS" && overlay.evaluated === true;
}
