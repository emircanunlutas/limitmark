import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH } from "../../workers/admission-service/authority";
import { readProductionAuthorityResult, type ProductionReadInput } from "../../operator/authority-result-reader";
import { RECOVERY_TIMING } from "../../operator/recovery-decision-record";

// Verification goes ONLY through the reviewed single reader (operator/authority-result-reader.ts). `initialized` and `coverage` come from that reader's outcome, which
// copies them from the AUTHENTICATED Authority-signed reconciliation statement (never from a guard ledger, an unsigned diagnostic or any relay object).
type AuthorityResultTrustManifest = ProductionReadInput["trustManifest"];

/**
 * Recovery EVIDENCE evaluation for a stranded initialization (Gate 11A design parameters; DESIGN APPROVED, EXECUTION NOT AUTHORIZED).
 * REFERENCE MODEL in test support, on purpose: the reviewed boundary tests allow only the two CLI scripts to import the single reviewed reader, so a runtime/operator
 * module cannot verify reconciliations without an approved allowlist change. This model fixes the rules and is exercised against the real Authority; a runtime port
 * (and the allowlist change it needs) is a separate decision.
 *
 * This module decides nothing about executing a recovery and mutates nothing: it is a pure, offline judge of two Authority-signed reconciliations
 * against the approved timing rules. It never builds, signs or submits a command, replaces a guard or touches a ledger. A result of
 * `eligible: true` means "the evidence requirements are met" -- it is a necessary input to the two-person decision, never a sufficient one.
 *
 * Approved parameters (conservative proposal, GUARD-GENERATION-MARGIN-REVIEW.md):
 *   - command lifetime: the Authority accepts a command while |authorityClock - issuedAtMs| <= 300 000 ms, so its last acceptable instant is
 *     EXPIRY = issuedAtMs + 300 000 and every Authority clock reading after EXPIRY refuses it (workers/admission-service/operator-command.ts, final reading,
 *     no await before the synchronous transaction);
 *   - reconciliation #1: Authority-signed observedAtMs >= EXPIRY + 300 000 (the Authority's own clock: the statement time, not the relay time);
 *   - reconciliation #2: observedAtMs >= #1.observedAtMs + 60 000, with a different (fresh) nonce;
 *   - decision: no earlier than #2 and within 300 000 ms after it.
 * Both reconciliations must be genuine Authority signatures (trust manifest), for the exact stranded digest and the exact production Authority, and
 * both must state initialized:false / COMPLETE / NOT_FOUND with no receipt and no release rows. Anything else -- including a single blocker -- is
 * "blocked"; there is no partial credit, no retry heuristic and no inference from missing evidence.
 */
export { RECOVERY_TIMING };

export type RecoveryBlocker =
  | "input" | "digest" | "nonce-reused" | "signature-or-expectation" | "not-reconciliation" | "initialized-or-incomplete" | "receipt-or-release-present"
  | "first-too-early" | "second-too-early" | "order" | "collection-order" | "decision-too-early" | "decision-too-late";
export type RecoveryEvidenceVerdict =
  | { eligible: true; expiryMs: number; firstObservedAtMs: number; secondObservedAtMs: number; decisionAtMs: number; slackMs: { first: number; second: number; decision: number } }
  | { eligible: false; blockers: RecoveryBlocker[] };

export type RecoveryEvidenceInput = {
  /** The stranded command's digest (caller-known, never taken from stored objects). */
  strandedDigest: string;
  /** `issuedAtMs` of the stranded SIGNED command (the Authority-verified value, not the time the file was written). */
  issuedAtMs: number;
  /** The two stored reconciliation objects with the nonces the CALLER generated for them. */
  /** `collectedAtMs`: the local time at which the operator fetched the stored object. The existing 300 000 ms attestation freshness is enforced at THAT time,
   * because reconciliation #1 is necessarily older than 300 s by the time the decision is taken. #2 is additionally re-verified at the decision time. */
  first: { nonce: string; bytes: Uint8Array; collectedAtMs: number };
  second: { nonce: string; bytes: Uint8Array; collectedAtMs: number };
  trustManifest: AuthorityResultTrustManifest;
  /** The time at which the recovery decision is being taken (local clock, validated only as an ordering input). */
  decisionAtMs: number;
};

const digestPattern = /^[a-f0-9]{64}$/u;
const noncePattern = /^[a-f0-9]{32}$/u;

type Observed = { observedAtMs: number };
async function verify(side: RecoveryEvidenceInput["first"], input: RecoveryEvidenceInput, blockers: Set<RecoveryBlocker>, verifiedAtMs: number): Promise<Observed | null> {
  const outcome = await readProductionAuthorityResult({ kind: "reconciliation", digest: input.strandedDigest, nonce: side.nonce, bytes: side.bytes, trustManifest: input.trustManifest, nowMs: verifiedAtMs })
    .catch(() => null);
  // No authenticated command is supplied on purpose: a signed negative is VERIFIED_NON_POSITIVE; a positive can never be produced here.
  if (!outcome || outcome.status === "UNCONFIRMED") { blockers.add("signature-or-expectation"); return null; }
  if (outcome.environment !== "production" || outcome.kind !== "reconciliation" || outcome.digest !== input.strandedDigest) { blockers.add("signature-or-expectation"); return null; }
  if (outcome.status !== "VERIFIED_NON_POSITIVE") { blockers.add("receipt-or-release-present"); return null; }
  // Missing or contradictory signed fields cannot occur here (the reader reports UNCONFIRMED instead); a stale statement was already refused by the reader's freshness check.
  if (outcome.initialized !== false || outcome.coverage !== "COMPLETE" || outcome.observation !== "NOT_FOUND") blockers.add("initialized-or-incomplete");
  if (outcome.observation === "COMMAND_CONTEXT_REQUIRED") blockers.add("receipt-or-release-present");
  if (!Number.isSafeInteger(outcome.observedAtMs) || outcome.observedAtMs < 0) { blockers.add("input"); return null; }
  return { observedAtMs: outcome.observedAtMs };
}

export async function assessRecoveryEvidence(input: RecoveryEvidenceInput): Promise<RecoveryEvidenceVerdict> {
  const blockers = new Set<RecoveryBlocker>();
  if (!digestPattern.test(input.strandedDigest)) blockers.add("digest");
  if (!Number.isSafeInteger(input.issuedAtMs) || input.issuedAtMs < 0 || !Number.isSafeInteger(input.decisionAtMs) || input.decisionAtMs < 0) blockers.add("input");
  for (const side of [input.first, input.second]) {
    if (!side || typeof side.nonce !== "string" || !noncePattern.test(side.nonce) || !(side.bytes instanceof Uint8Array) || side.bytes.length === 0 || !Number.isSafeInteger(side.collectedAtMs) || side.collectedAtMs < 0) blockers.add("input");
  }
  if (blockers.size > 0) return { eligible: false, blockers: [...blockers] };
  if (input.first.nonce === input.second.nonce) blockers.add("nonce-reused");
  if (input.first.bytes.length === input.second.bytes.length && input.first.bytes.every((byte, index) => byte === input.second.bytes[index])) blockers.add("nonce-reused");
  const first = await verify(input.first, input, blockers, input.first.collectedAtMs);
  const second = await verify(input.second, input, blockers, input.second.collectedAtMs);
  // The decision-time check: the second reconciliation must still be attestation-fresh when the decision is taken.
  const decisionCheck = await verify(input.second, input, blockers, input.decisionAtMs);
  if (!first || !second || !decisionCheck || blockers.size > 0) return { eligible: false, blockers: [...blockers] };
  if (input.first.collectedAtMs > input.second.collectedAtMs || input.second.collectedAtMs > input.decisionAtMs) blockers.add("collection-order");

  const expiryMs = input.issuedAtMs + RECOVERY_TIMING.commandLifetimeMs;
  if (first.observedAtMs < expiryMs + RECOVERY_TIMING.firstReconciliationAfterExpiryMs) blockers.add("first-too-early");
  if (second.observedAtMs <= first.observedAtMs) blockers.add("order");
  else if (second.observedAtMs < first.observedAtMs + RECOVERY_TIMING.secondReconciliationAfterFirstMs) blockers.add("second-too-early");
  if (input.decisionAtMs < second.observedAtMs) blockers.add("decision-too-early");
  if (input.decisionAtMs - second.observedAtMs > RECOVERY_TIMING.decisionWithinAfterSecondMs) blockers.add("decision-too-late");
  if (blockers.size > 0) return { eligible: false, blockers: [...blockers] };
  return { eligible: true, expiryMs, firstObservedAtMs: first.observedAtMs, secondObservedAtMs: second.observedAtMs, decisionAtMs: input.decisionAtMs,
    slackMs: { first: first.observedAtMs - (expiryMs + RECOVERY_TIMING.firstReconciliationAfterExpiryMs),
      second: second.observedAtMs - (first.observedAtMs + RECOVERY_TIMING.secondReconciliationAfterFirstMs),
      decision: RECOVERY_TIMING.decisionWithinAfterSecondMs - (input.decisionAtMs - second.observedAtMs) } };
}
