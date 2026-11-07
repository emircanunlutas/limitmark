import type { AttestationReceipt, ResultStatement } from "../src/lib/authority-result-attestation";
import {
  isVerifiedAuthorityStatement,
  verifyAuthoritySignedStatement,
  type AuthorityResultTrustManifest,
  type ResultAttestationExpectations,
  type VerifiedAuthorityStatement,
} from "../src/lib/authority-result-trust";
import { ADMISSION_POLICY_EPOCH, LAB_ADMISSION_AUTHORITY_ID } from "../workers/admission-service/authority";
import { classifyUnsignedDiagnostic } from "./lifecycle-result";
import { commandReceiptMismatches, type AuthorityResultKind, type VerifiedNonPositiveObservation } from "./authority-result-verifier";
import { isAuthenticatedLifecycleCommand, type AuthenticatedLifecycleCommand } from "./lifecycle-submitter";

/**
 * Laboratory result acceptance. Structurally independent of the production and staging composers (the repository's convention for
 * every environment): it accepts ONLY statements whose environment is `lab` and whose authority is `lab-public-inquiries-v1`, verified
 * against a lab trust manifest, and requires an authenticated operator command for any positive (like Production). It shares no
 * acceptance path with, and cannot produce, a Production or staging positive.
 */
export interface LabAuthorityPositive {
  readonly status: "POSITIVE";
  readonly environment: "lab";
  readonly kind: AuthorityResultKind;
  readonly authority: VerifiedAuthorityStatement;
  readonly command: AuthenticatedLifecycleCommand;
}
export interface LabVerifiedNonPositive {
  readonly status: "VERIFIED_NON_POSITIVE";
  readonly environment: "lab";
  readonly kind: AuthorityResultKind;
  readonly observation: VerifiedNonPositiveObservation;
  readonly authority: VerifiedAuthorityStatement;
}
export type LabAuthorityResult = LabAuthorityPositive | LabVerifiedNonPositive;

const labPositives = new WeakSet<object>();
export function isLabAuthorityPositive(value: unknown): value is LabAuthorityPositive {
  return typeof value === "object" && value !== null && labPositives.has(value);
}
function fail(code: string): never { throw new Error(code); }

type Classified =
  | { readonly positive: true; readonly kind: AuthorityResultKind; readonly receipt: AttestationReceipt }
  | { readonly positive: false; readonly kind: "reconciliation"; readonly observation: "NOT_FOUND" | "HISTORY_INCOMPLETE" };
function classify(statement: ResultStatement): Classified {
  if (statement.kind === "lifecycle") return { positive: true, kind: "lifecycle", receipt: statement.receipt };
  if (statement.status === "EXACT_RECEIPT" && statement.receipt !== null) return { positive: true, kind: "reconciliation", receipt: statement.receipt };
  if (statement.status === "NOT_FOUND" || statement.status === "HISTORY_INCOMPLETE") return { positive: false, kind: "reconciliation", observation: statement.status };
  return fail("result-contract");
}

export function composeLabAuthorityResult(verified: unknown, authenticatedCommand?: unknown): LabAuthorityResult {
  if (!isVerifiedAuthorityStatement(verified)) fail("result-authority-provenance");
  const statement = verified.statement;
  if (statement.environment !== "lab" || statement.authorityId !== LAB_ADMISSION_AUTHORITY_ID || verified.expectations.environment !== "lab" ||
      verified.expectations.digest !== statement.digest) fail("result-contract");
  let command: AuthenticatedLifecycleCommand | undefined;
  if (authenticatedCommand !== undefined) {
    if (!isAuthenticatedLifecycleCommand(authenticatedCommand)) fail("result-command-provenance");
    command = authenticatedCommand;
    if (command.expected.environment !== "lab" || command.expected.authorityId !== LAB_ADMISSION_AUTHORITY_ID ||
        command.digest !== statement.digest || command.expected.digest !== statement.digest) fail("result-contract");
  }
  const classified = classify(statement);
  if (!classified.positive) return Object.freeze({ status: "VERIFIED_NON_POSITIVE", environment: "lab", kind: classified.kind, observation: classified.observation, authority: verified });
  if (command === undefined) return Object.freeze({ status: "VERIFIED_NON_POSITIVE", environment: "lab", kind: classified.kind, observation: "COMMAND_CONTEXT_REQUIRED", authority: verified });
  if (commandReceiptMismatches(classified.receipt, command.expected).length !== 0) fail("result-contract");
  const positive: LabAuthorityPositive = Object.freeze({ status: "POSITIVE", environment: "lab", kind: classified.kind, authority: verified, command });
  labPositives.add(positive);
  return positive;
}

// ---- operator-facing reader --------------------------------------------------------------------------------------------
const errorCode = /^(?:attestation|result)-[a-z]+(?:-[a-z]+)*$/u;
const reasonOf = (error: unknown): string => (error instanceof Error && errorCode.test(error.message) ? error.message : "result-unreadable");

export interface LabReadPositive {
  readonly status: "POSITIVE"; readonly environment: "lab"; readonly kind: AuthorityResultKind; readonly digest: string;
  readonly observedAtMs: number; readonly signingKeyFingerprint: string; readonly receipt: AttestationReceipt;
}
export interface LabReadNonPositive {
  readonly status: "VERIFIED_NON_POSITIVE"; readonly environment: "lab"; readonly kind: AuthorityResultKind; readonly digest: string;
  readonly observation: VerifiedNonPositiveObservation; readonly observedAtMs: number; readonly signingKeyFingerprint: string;
  readonly commandContext?: "MISMATCHED";
}
export interface LabReadUnconfirmed {
  readonly status: "UNCONFIRMED"; readonly environment: "lab"; readonly kind: AuthorityResultKind; readonly digest: string; readonly reason: string;
  readonly relayStatus?: "REFUSED" | "UNAVAILABLE" | "UNCONFIRMED";
}
export type LabReadOutcome = LabReadPositive | LabReadNonPositive | LabReadUnconfirmed;

export interface LabReadInput {
  readonly kind: AuthorityResultKind;
  readonly digest: string;
  readonly nonce?: string;
  readonly bytes: Uint8Array;
  readonly trustManifest: AuthorityResultTrustManifest;
  readonly nowMs: number;
  readonly authenticatedCommand?: AuthenticatedLifecycleCommand;
}

function labExpectations(kind: AuthorityResultKind, digest: string, nonce: string | undefined): ResultAttestationExpectations {
  const base = { environment: "lab", authorityId: LAB_ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH, digest } as const;
  return kind === "lifecycle" ? { kind, ...base } : { kind, ...base, nonce: nonce as string };
}

export async function readLabAuthorityResult(input: LabReadInput): Promise<LabReadOutcome> {
  const { kind, digest, nonce, bytes, trustManifest, nowMs, authenticatedCommand } = input;
  if (authenticatedCommand !== undefined && !isAuthenticatedLifecycleCommand(authenticatedCommand)) throw new Error("result-command-provenance");
  let verified;
  try { verified = await verifyAuthoritySignedStatement(bytes, labExpectations(kind, digest, nonce), trustManifest, nowMs); }
  catch (error) {
    const diagnostic = classifyUnsignedDiagnostic(bytes, nonce === undefined ? { digest } : { digest, nonce });
    return diagnostic ? { status: "UNCONFIRMED", environment: "lab", kind, digest, reason: "no-signed-evidence", relayStatus: diagnostic.relayStatus }
      : { status: "UNCONFIRMED", environment: "lab", kind, digest, reason: reasonOf(error) };
  }
  const matching = authenticatedCommand !== undefined && authenticatedCommand.digest === digest ? authenticatedCommand : undefined;
  const mismatched = authenticatedCommand !== undefined && matching === undefined;
  let composed: LabAuthorityResult;
  try { composed = composeLabAuthorityResult(verified, matching); }
  catch (error) { return { status: "UNCONFIRMED", environment: "lab", kind, digest, reason: matching !== undefined ? "command-mismatch" : reasonOf(error) }; }
  const common = { environment: "lab", kind, digest, observedAtMs: verified.statement.observedAtMs, signingKeyFingerprint: verified.signingKeyFingerprint } as const;
  if (composed.status === "POSITIVE") {
    const receipt = verified.statement.kind === "lifecycle" ? verified.statement.receipt
      : verified.statement.status === "EXACT_RECEIPT" ? verified.statement.receipt : null;
    if (receipt === null) return { status: "UNCONFIRMED", environment: "lab", kind, digest, reason: "result-contract" };
    return Object.freeze({ status: "POSITIVE", ...common, receipt } satisfies LabReadPositive);
  }
  return Object.freeze({ status: "VERIFIED_NON_POSITIVE", ...common, observation: composed.observation,
    ...(mismatched ? { commandContext: "MISMATCHED" as const } : {}) } satisfies LabReadNonPositive);
}
