import type { AttestationReceipt } from "../src/lib/authority-result-attestation";
import {
  verifyAuthoritySignedStatement,
  type AuthorityResultTrustManifest,
  type ResultAttestationExpectations,
} from "../src/lib/authority-result-trust";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../workers/admission-service/authority";
import {
  composeProductionAuthorityResult,
  composeStagingAuthorityResult,
  type ProductionAuthorityResult,
  type StagingAuthorityResult,
  type VerifiedNonPositiveObservation,
} from "./authority-result-verifier";
import { classifyUnsignedDiagnostic } from "./lifecycle-result";
import { isAuthenticatedLifecycleCommand, type AuthenticatedLifecycleCommand } from "./lifecycle-submitter";

/**
 * R06 Slice 2C: the ONLY active reader of lifecycle and reconciliation result objects (Production and staging operator CLIs).
 *
 * The stored object is hostile until proven otherwise. Nothing is read from its key, an outer wrapper, a metadata field, an outer
 * digest/environment/status/receipt/release/timestamp: the object is either (a) the Authority's exact signed envelope bytes,
 * judged ONLY by the frozen R06 verifier against caller-known expectations, a pinned trust manifest and the local clock, then
 * composed with the independent evidence the 2B composers require; or (b) not signed evidence, which is never positive.
 *
 *   Production POSITIVE = signed R06 evidence AND an authenticated R07 command AND 12-field command/receipt equality.
 *   Staging    POSITIVE = signed staging R06 evidence AND the Gate 7 canonical pins.
 *
 * There is no fallback: no code path parses an unsigned lifecycle or reconciliation result as anything but a non-positive
 * diagnostic, and a signature failure never falls back to a legacy verifier.
 *
 * Outcome taxonomy (what a caller may print or act on):
 *   POSITIVE              Authority-signed positive evidence that also satisfied the independent composition.
 *   VERIFIED_NON_POSITIVE Authority-signed, trusted, fresh observation that is not a success: NOT_FOUND, HISTORY_INCOMPLETE, or a
 *                         signed positive candidate that lacks (or has an inconsistent) command context (COMMAND_CONTEXT_REQUIRED).
 *   UNCONFIRMED           no trustworthy signed evidence: missing/stale/forged/wrong-target/replayed/malformed bytes, an unsigned
 *                         relay diagnostic, or genuine evidence that contradicts the command or the Gate 7 pins.
 * REFUSED / UNAVAILABLE are properties of mutation relays and local input handling, not of reading a stored result.
 */

const errorCode = /^(?:attestation|result)-[a-z]+(?:-[a-z]+)*$/u;
function reasonOf(error: unknown): string {
  return error instanceof Error && errorCode.test(error.message) ? error.message : "result-unreadable";
}

export type ReadKind = "lifecycle" | "reconciliation";
type ReadEnvironment = "production" | "staging";

export interface AuthorityReadPositive {
  readonly status: "POSITIVE";
  readonly environment: ReadEnvironment;
  readonly kind: ReadKind;
  readonly digest: string;
  readonly observedAtMs: number;
  readonly signingKeyFingerprint: string;
  readonly receipt: AttestationReceipt;
}
export interface AuthorityReadNonPositive {
  readonly status: "VERIFIED_NON_POSITIVE";
  readonly environment: ReadEnvironment;
  readonly kind: ReadKind;
  readonly digest: string;
  readonly observation: VerifiedNonPositiveObservation;
  readonly observedAtMs: number;
  readonly signingKeyFingerprint: string;
  /** Present only when the caller supplied a command that names a different digest; it was NOT used. */
  readonly commandContext?: "MISMATCHED";
}
export interface AuthorityReadUnconfirmed {
  readonly status: "UNCONFIRMED";
  readonly environment: ReadEnvironment;
  readonly kind: ReadKind;
  readonly digest: string;
  readonly reason: string;
  /** Present when the bytes were an explicit unsigned relay diagnostic; informational only. */
  readonly relayStatus?: "REFUSED" | "UNAVAILABLE" | "UNCONFIRMED";
}
export type AuthorityReadOutcome = AuthorityReadPositive | AuthorityReadNonPositive | AuthorityReadUnconfirmed;

function expectations(environment: ReadEnvironment, kind: ReadKind, digest: string, nonce: string | undefined): ResultAttestationExpectations {
  const authorityId = environment === "production" ? ADMISSION_AUTHORITY_ID : STAGING_ADMISSION_AUTHORITY_ID;
  return kind === "lifecycle"
    ? { kind, environment, authorityId, policyEpoch: ADMISSION_POLICY_EPOCH, digest }
    : { kind, environment, authorityId, policyEpoch: ADMISSION_POLICY_EPOCH, digest, nonce: nonce as string };
}

/** Evidence the verifier refused is still reported honestly: an explicit unsigned relay diagnostic says why there is no evidence;
 * anything else is unreadable. Neither is ever positive. */
function unconfirmed(environment: ReadEnvironment, kind: ReadKind, digest: string, nonce: string | undefined, bytes: Uint8Array, reason: string): AuthorityReadUnconfirmed {
  const diagnostic = classifyUnsignedDiagnostic(bytes, nonce === undefined ? { digest } : { digest, nonce });
  return diagnostic
    ? { status: "UNCONFIRMED", environment, kind, digest, reason: "no-signed-evidence", relayStatus: diagnostic.relayStatus }
    : { status: "UNCONFIRMED", environment, kind, digest, reason };
}

/** Keeps the branded composer result reachable for tests and provenance checks without ever serializing it. */
function withComposed<T extends object>(outcome: T, composed: ProductionAuthorityResult | StagingAuthorityResult): T {
  Object.defineProperty(outcome, "composed", { value: composed, enumerable: false });
  return Object.freeze(outcome);
}

export interface ProductionReadInput {
  readonly kind: ReadKind;
  /** Caller-known: the digest of the command the caller asked about (never taken from the stored object). */
  readonly digest: string;
  /** Caller-known reconciliation nonce (the one the caller generated); required for `reconciliation`. */
  readonly nonce?: string;
  /** The raw stored object. */
  readonly bytes: Uint8Array;
  readonly trustManifest: AuthorityResultTrustManifest;
  readonly nowMs: number;
  /** The unmodified result of `authenticateSealedLifecycleArtifact`. Required for any positive. If it names a different digest it
   * is reported as MISMATCHED and NOT used, so a valid signed negative is never erased by inconsistent optional context. */
  readonly authenticatedCommand?: AuthenticatedLifecycleCommand;
}

export async function readProductionAuthorityResult(input: ProductionReadInput): Promise<AuthorityReadOutcome> {
  const { kind, digest, nonce, bytes, trustManifest, nowMs, authenticatedCommand } = input;
  if (authenticatedCommand !== undefined && !isAuthenticatedLifecycleCommand(authenticatedCommand)) throw new Error("result-command-provenance");
  let verified;
  try { verified = await verifyAuthoritySignedStatement(bytes, expectations("production", kind, digest, nonce), trustManifest, nowMs); }
  catch (error) { return unconfirmed("production", kind, digest, nonce, bytes, reasonOf(error)); }
  const matching = authenticatedCommand !== undefined && authenticatedCommand.digest === digest ? authenticatedCommand : undefined;
  const mismatched = authenticatedCommand !== undefined && matching === undefined;
  let composed: ProductionAuthorityResult;
  try { composed = composeProductionAuthorityResult(verified, matching); }
  catch (error) {
    // Genuine signed evidence that contradicts the authenticated command is a contract failure, not a success and not a refusal.
    return { status: "UNCONFIRMED", environment: "production", kind, digest, reason: matching !== undefined ? "command-mismatch" : reasonOf(error) };
  }
  const common = { environment: "production", kind, digest, observedAtMs: verified.statement.observedAtMs, signingKeyFingerprint: verified.signingKeyFingerprint } as const;
  if (composed.status === "POSITIVE") {
    const receipt = verified.statement.kind === "lifecycle" ? verified.statement.receipt
      : verified.statement.status === "EXACT_RECEIPT" ? verified.statement.receipt : null;
    if (receipt === null) return { status: "UNCONFIRMED", environment: "production", kind, digest, reason: "result-contract" };
    return withComposed({ status: "POSITIVE", ...common, receipt } satisfies AuthorityReadPositive, composed);
  }
  return withComposed({ status: "VERIFIED_NON_POSITIVE", ...common, observation: composed.observation,
    ...(mismatched ? { commandContext: "MISMATCHED" as const } : {}) } satisfies AuthorityReadNonPositive, composed);
}

export interface StagingReadInput {
  readonly kind: ReadKind;
  readonly digest: string;
  readonly nonce?: string;
  readonly bytes: Uint8Array;
  readonly trustManifest: AuthorityResultTrustManifest;
  readonly nowMs: number;
}

export async function readStagingAuthorityResult(input: StagingReadInput): Promise<AuthorityReadOutcome> {
  const { kind, digest, nonce, bytes, trustManifest, nowMs } = input;
  let verified;
  try { verified = await verifyAuthoritySignedStatement(bytes, expectations("staging", kind, digest, nonce), trustManifest, nowMs); }
  catch (error) { return unconfirmed("staging", kind, digest, nonce, bytes, reasonOf(error)); }
  let composed: StagingAuthorityResult;
  // The Gate 7 canonical pins (receipt, operator fingerprint, release row) are enforced inside the composer; the signature never replaces them.
  try { composed = composeStagingAuthorityResult(verified); }
  catch (error) { return { status: "UNCONFIRMED", environment: "staging", kind, digest, reason: reasonOf(error) }; }
  const common = { environment: "staging", kind, digest, observedAtMs: verified.statement.observedAtMs, signingKeyFingerprint: verified.signingKeyFingerprint } as const;
  if (composed.status === "POSITIVE") {
    const receipt = verified.statement.kind === "lifecycle" ? verified.statement.receipt
      : verified.statement.status === "EXACT_RECEIPT" ? verified.statement.receipt : null;
    if (receipt === null) return { status: "UNCONFIRMED", environment: "staging", kind, digest, reason: "result-contract" };
    return withComposed({ status: "POSITIVE", ...common, receipt } satisfies AuthorityReadPositive, composed);
  }
  return withComposed({ status: "VERIFIED_NON_POSITIVE", ...common, observation: composed.observation } satisfies AuthorityReadNonPositive, composed);
}
