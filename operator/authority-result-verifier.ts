import {
  RECEIPT_FIELDS,
  type AttestationReceipt,
  type ResultStatement,
} from "../src/lib/authority-result-attestation";
import {
  isVerifiedAuthorityStatement,
  verifyAuthoritySignedStatement,
  type AuthorityResultTrustManifest,
  type ResultAttestationExpectations,
  type VerifiedAuthorityStatement,
} from "../src/lib/authority-result-trust";
import type { CommandDerivedReceipt } from "../workers/admission-service/operator-command";
import { commandDerivedReceiptFields } from "./lifecycle-result";
import { isAuthenticatedLifecycleCommand, type AuthenticatedLifecycleCommand } from "./lifecycle-submitter";
import { STAGING_GATE7_CONTINUITY } from "./staging-gate7-continuity";

/**
 * R06 Slice 2B: INERT composition of a verified Authority statement with the independent evidence that Production and
 * staging positive acceptance additionally require. Nothing in the CLI, mailbox, observer, guards or R2 result flow imports this
 * module (a source-level test pins that); Slice 2C switches producer, relay and verifier atomically.
 *
 * Production POSITIVE = genuine branded R06 statement (frozen verifier) AND a genuine authenticated R07 command context whose
 * twelve command-derived fields equal the attested receipt. R06 alone is never positive.
 * Staging POSITIVE = genuine branded staging R06 statement AND the committed Gate 7 canonical pins. The signature never replaces them.
 *
 * Both APIs are downgrade-closed: they accept only a signed v2 envelope. There is no unsigned/legacy parse and no fallback.
 * Settlement is guard state, not an Authority statement, and is outside this module.
 *
 * Failure taxonomy (thrown `Error.message`):
 *   attestation-*             the frozen R06 verifier refused the envelope/expectations/key/freshness/signature.
 *   result-authority-provenance  a value that is not a genuine `VerifiedAuthorityStatement` was presented to a composer.
 *   result-command-provenance    a value that is not a genuine `authenticateSealedLifecycleArtifact` result was presented.
 *   result-contract              the evidence is genuine but contradicts the binding (environment, digest, command or Gate 7 pin).
 * A signed positive with NO command is not an error: it is reported as VERIFIED_NON_POSITIVE / COMMAND_CONTEXT_REQUIRED.
 *
 * Signed negatives (NOT_FOUND, HISTORY_INCOMPLETE) are useful on their own and need no command. A caller that nevertheless supplies
 * a genuine command for a DIFFERENT digest has presented inconsistent optional context: that is a caller contract mismatch and throws
 * `result-contract`. The throw says nothing about the Authority evidence; Slice 2C must not hide or discard the underlying signed
 * negative merely because inconsistent optional context was supplied (it remains reportable when composed without that context).
 */

export type AuthorityResultKind = "lifecycle" | "reconciliation";
export type VerifiedNonPositiveObservation = "NOT_FOUND" | "HISTORY_INCOMPLETE" | "COMMAND_CONTEXT_REQUIRED";

/** Production positive. Retains the ORIGINAL branded R06 statement and the ORIGINAL authenticated command, never copies. */
export interface ProductionAuthorityPositive {
  readonly status: "POSITIVE";
  readonly environment: "production";
  readonly kind: AuthorityResultKind;
  readonly authority: VerifiedAuthorityStatement;
  readonly command: AuthenticatedLifecycleCommand;
}

/** Staging positive. The Gate 7 pins it was compared with are the module constants, not caller data. */
export interface StagingAuthorityPositive {
  readonly status: "POSITIVE";
  readonly environment: "staging";
  readonly kind: AuthorityResultKind;
  readonly authority: VerifiedAuthorityStatement;
}

/** An authenticated Authority observation that is not positive acceptance. Never a success. */
export interface VerifiedAuthorityNonPositive<Environment extends "production" | "staging"> {
  readonly status: "VERIFIED_NON_POSITIVE";
  readonly environment: Environment;
  readonly kind: AuthorityResultKind;
  readonly observation: VerifiedNonPositiveObservation;
  readonly authority: VerifiedAuthorityStatement;
}

export type ProductionAuthorityResult = ProductionAuthorityPositive | VerifiedAuthorityNonPositive<"production">;
export type StagingAuthorityResult = StagingAuthorityPositive | VerifiedAuthorityNonPositive<"staging">;

const productionPositives = new WeakSet<object>();
const stagingPositives = new WeakSet<object>();

/** Runtime proof that `value` was produced by `composeProductionAuthorityResult`. */
export function isProductionAuthorityPositive(value: unknown): value is ProductionAuthorityPositive {
  return typeof value === "object" && value !== null && productionPositives.has(value);
}
/** Runtime proof that `value` was produced by `composeStagingAuthorityResult`. */
export function isStagingAuthorityPositive(value: unknown): value is StagingAuthorityPositive {
  return typeof value === "object" && value !== null && stagingPositives.has(value);
}

function fail(code: string): never { throw new Error(code); }

type Classified =
  | { readonly positive: true; readonly kind: AuthorityResultKind; readonly receipt: AttestationReceipt }
  | { readonly positive: false; readonly kind: "reconciliation"; readonly observation: "NOT_FOUND" | "HISTORY_INCOMPLETE" };

/** Classifies a validated statement. Lifecycle APPLIED and reconciliation EXACT_RECEIPT are the only positive candidates; the
 * frozen validator guarantees a receipt exists exactly in those states. */
function classify(statement: ResultStatement): Classified {
  if (statement.kind === "lifecycle") return { positive: true, kind: "lifecycle", receipt: statement.receipt };
  if (statement.status === "EXACT_RECEIPT" && statement.receipt !== null) return { positive: true, kind: "reconciliation", receipt: statement.receipt };
  if (statement.status === "NOT_FOUND" || statement.status === "HISTORY_INCOMPLETE") return { positive: false, kind: "reconciliation", observation: statement.status };
  return fail("result-contract");
}

/** True only when `fields` are pairwise distinct and, after `rename`, are exactly the own enumerable keys of `record`. A field list
 * used for a security comparison must pass this first: a duplicate or a substituted name would otherwise silently drop a field. */
function isExactFieldSet(fields: readonly string[], record: object, rename: (field: string) => string = (field) => field): boolean {
  const names = new Set(fields.map(rename));
  const keys = Object.keys(record);
  return names.size === fields.length && keys.length === names.size && keys.every((key) => names.has(key));
}

/** Attested receipt names the operator key `operatorKeyFingerprint`; the authority/command side calls it `keyFingerprint`. */
type CommandField = (typeof commandDerivedReceiptFields)[number];
const attestedName = (field: CommandField): keyof AttestationReceipt => (field === "keyFingerprint" ? "operatorKeyFingerprint" : field);

/** Pure field comparison: the command-derived fields (the one list R07 already uses) on which the attested receipt differs from
 * the command-derived expectation. It confers no trust and checks no provenance; `sequence` and `appliedMs` are Authority-assigned
 * and deliberately absent from that list. Exported for the field-by-field tests; `composeProductionAuthorityResult` is the API.
 * Before comparing, the shared list itself must be the frozen, duplicate-free set of exactly the twelve keys of the command-derived
 * expectation (`expectedCommandReceipt`, the single R07 mapping), and its attested names plus the two Authority-assigned fields
 * must be exactly the fourteen keys of the attested receipt (the only rename is `keyFingerprint` -> `operatorKeyFingerprint`). */
export function commandReceiptMismatches(receipt: AttestationReceipt, expected: Readonly<CommandDerivedReceipt>): readonly CommandField[] {
  const fields = commandDerivedReceiptFields;
  const record: Readonly<Record<string, unknown>> = expected;
  if (!Object.isFrozen(fields) || fields.length !== 12 || !isExactFieldSet(fields, record) ||
      !isExactFieldSet([...fields.map(attestedName), "sequence", "appliedMs"], receipt)) fail("result-contract");
  return fields.filter((field) => receipt[attestedName(field)] !== record[field]);
}

/**
 * Composes an already verified R06 statement with an authenticated R07 command. Both inputs are checked for RUNTIME provenance
 * (`unknown` parameters: a TypeScript type is never accepted as evidence). Every value read here is frozen, module-owned data.
 * A supplied command is always provenance-checked and bound to the statement's digest/environment, even for negative statements.
 */
export function composeProductionAuthorityResult(verified: unknown, authenticatedCommand?: unknown): ProductionAuthorityResult {
  if (!isVerifiedAuthorityStatement(verified)) fail("result-authority-provenance");
  const statement = verified.statement;
  if (statement.environment !== "production" || verified.expectations.environment !== "production" ||
      verified.expectations.digest !== statement.digest) fail("result-contract");
  let command: AuthenticatedLifecycleCommand | undefined;
  // Checked before classification on purpose: inconsistent optional context is a caller contract mismatch even for a signed
  // negative (see the module comment); it never turns a negative positive, and the negative stays reportable without it.
  if (authenticatedCommand !== undefined) {
    if (!isAuthenticatedLifecycleCommand(authenticatedCommand)) fail("result-command-provenance");
    command = authenticatedCommand;
    if (command.expected.environment !== "production" || command.digest !== statement.digest || command.expected.digest !== statement.digest) fail("result-contract");
  }
  const classified = classify(statement);
  if (!classified.positive) {
    return Object.freeze({ status: "VERIFIED_NON_POSITIVE", environment: "production", kind: classified.kind, observation: classified.observation, authority: verified });
  }
  if (command === undefined) {
    return Object.freeze({ status: "VERIFIED_NON_POSITIVE", environment: "production", kind: classified.kind, observation: "COMMAND_CONTEXT_REQUIRED", authority: verified });
  }
  if (commandReceiptMismatches(classified.receipt, command.expected).length !== 0) fail("result-contract");
  const positive: ProductionAuthorityPositive = Object.freeze({ status: "POSITIVE", environment: "production", kind: classified.kind, authority: verified, command });
  productionPositives.add(positive);
  return positive;
}

export interface ProductionAuthorityVerificationInput {
  readonly bytes: Uint8Array;
  readonly expectations: ResultAttestationExpectations;
  readonly trustManifest: AuthorityResultTrustManifest;
  readonly nowMs: number;
  /** Must be the unmodified result of `authenticateSealedLifecycleArtifact`. Required for any positive. */
  readonly authenticatedCommand?: AuthenticatedLifecycleCommand;
}

/** Strict R06 verification of signed envelope bytes, then `composeProductionAuthorityResult`. No unsigned path, no fallback.
 * Caller-owned inputs are read once, synchronously, before the first `await`; the frozen verifier snapshots the expectations and
 * parses the bytes in that same synchronous prefix, and the command is a frozen registered object. */
export async function verifyProductionAuthorityResult(input: ProductionAuthorityVerificationInput): Promise<ProductionAuthorityResult> {
  if (typeof input !== "object" || input === null) fail("result-contract");
  const { bytes, expectations, trustManifest, nowMs, authenticatedCommand } = input;
  if (authenticatedCommand !== undefined && !isAuthenticatedLifecycleCommand(authenticatedCommand)) fail("result-command-provenance");
  const verified = await verifyAuthoritySignedStatement(bytes, expectations, trustManifest, nowMs);
  return composeProductionAuthorityResult(verified, authenticatedCommand);
}

// ---------------------------------------------------------------------------------------------------------------------
// Staging: Gate 7 canonical pins (operator/staging-gate7-continuity.ts) stay independent of the R06 signature.
// ---------------------------------------------------------------------------------------------------------------------
const gate7 = STAGING_GATE7_CONTINUITY;
const gate7Receipt: Readonly<Record<string, unknown>> = gate7.receipt;
const gate7Name = (field: string): string => (field === "operatorKeyFingerprint" ? "keyFingerprint" : field);
const gate7ReceiptValue = (field: keyof AttestationReceipt): unknown => gate7Receipt[gate7Name(field)];
// The frozen protocol's RECEIPT_FIELDS is a shared, unfrozen runtime array. The staging pins therefore iterate a module-owned
// frozen copy taken once at module initialization (the import itself is never mutated or frozen here), and only when that copy
// is exactly the fourteen distinct Gate 7 receipt keys (the only rename is `operatorKeyFingerprint` -> `keyFingerprint`). A later
// mutation of the imported array cannot reach this copy; a copy that was already wrong fails every staging positive closed.
const stagingReceiptFields: readonly (keyof AttestationReceipt)[] = Object.freeze(RECEIPT_FIELDS.slice());
const stagingReceiptFieldsExact = stagingReceiptFields.length === 14 && isExactFieldSet(stagingReceiptFields, gate7Receipt, gate7Name);

/** All fourteen receipt fields (including sequence 1 and appliedMs, as the existing staging verifier compares them). */
function assertReceiptMatchesGate7(receipt: AttestationReceipt): void {
  if (!stagingReceiptFieldsExact || !isExactFieldSet(stagingReceiptFields, receipt)) fail("result-contract");
  for (const field of stagingReceiptFields) if (receipt[field] !== gate7ReceiptValue(field)) fail("result-contract");
}

function assertSnapshotMatchesGate7(statement: Extract<ResultStatement, { kind: "reconciliation" }>): void {
  const [row, ...rest] = statement.releases;
  const pinned = gate7.releases[0];
  if (statement.initialized !== gate7.initialized || statement.coverage !== gate7.coverage || statement.status !== gate7.status ||
      gate7.releases.length !== 1 || rest.length !== 0 || row === undefined || row.releaseId !== pinned.release_id ||
      row.keyId !== pinned.key_id || row.activatedMs !== pinned.activated_ms || row.retiredMs !== pinned.retired_ms) fail("result-contract");
}

/** Composes a verified staging R06 statement with the Gate 7 pins. A signed negative observation carries no receipt and needs no
 * canonical-receipt equality; its environment/authority/trust were already enforced by the frozen verifier. */
export function composeStagingAuthorityResult(verified: unknown): StagingAuthorityResult {
  if (!isVerifiedAuthorityStatement(verified)) fail("result-authority-provenance");
  const statement = verified.statement;
  if (statement.environment !== "staging" || statement.authorityId !== gate7.authorityId || verified.expectations.environment !== "staging" ||
      verified.expectations.digest !== statement.digest) fail("result-contract");
  const classified = classify(statement);
  if (!classified.positive) {
    return Object.freeze({ status: "VERIFIED_NON_POSITIVE", environment: "staging", kind: classified.kind, observation: classified.observation, authority: verified });
  }
  assertReceiptMatchesGate7(classified.receipt);
  if (statement.kind === "reconciliation") assertSnapshotMatchesGate7(statement);
  const positive: StagingAuthorityPositive = Object.freeze({ status: "POSITIVE", environment: "staging", kind: classified.kind, authority: verified });
  stagingPositives.add(positive);
  return positive;
}

export interface StagingAuthorityVerificationInput {
  readonly bytes: Uint8Array;
  readonly expectations: ResultAttestationExpectations;
  readonly trustManifest: AuthorityResultTrustManifest;
  readonly nowMs: number;
}

/** Strict R06 verification of signed staging envelope bytes, then `composeStagingAuthorityResult`. No unsigned path. */
export async function verifyStagingAuthorityResult(input: StagingAuthorityVerificationInput): Promise<StagingAuthorityResult> {
  if (typeof input !== "object" || input === null) fail("result-contract");
  const { bytes, expectations, trustManifest, nowMs } = input;
  return composeStagingAuthorityResult(await verifyAuthoritySignedStatement(bytes, expectations, trustManifest, nowMs));
}
