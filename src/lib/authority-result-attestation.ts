import { decodeCanonicalBase64url, encodeBase64url, toArrayBuffer } from "./ingress-protocol";
import type { LifecycleReceipt } from "../../workers/admission-service/authority";

/**
 * Authority result attestation protocol, version 2 (provider-independent).
 *
 * A statement is a strict positional tuple. Signer and verifier share one set of types, constructors, validators,
 * field orders, receipt/release-row conversions and one canonical encoder (`JSON.stringify` of the validated tuple,
 * prefixed by the signing domain). There is no object canonicalizer: signed structures are arrays only.
 *
 * This module authenticates nothing on its own. Trust-key selection, caller expectations and freshness live in
 * `authority-result-trust.ts`. Nothing here is wired into the authority, mailbox, observer or CLI.
 *
 * Authority-producible states only. The validator rejects statements that current authority source cannot produce:
 *  - `initialize` receipts have sequence exactly 1; `rotate-release` receipts have sequence >= 2 (a rotation needs the
 *    command-receipt coverage row that only a command-backed initialization creates);
 *  - |appliedMs - activatesMs| <= 300000 for both operations (inclusive);
 *  - staging has no rotation path: a staging `rotate-release` attestation is rejected by protocol decision, so a future
 *    staging-rotation feature must revise this validator on purpose rather than inherit acceptance;
 *  - a one-row EXACT_RECEIPT snapshot means no rotation ever happened (every rotation leaves exactly two rows), so its
 *    receipt is the sequence-1 `initialize` receipt and its only row is [nextReleaseId, nextKeyId, activatesMs, null].
 *    Two-row snapshots are NOT tied to the historical receipt: a receipt describes its own command, the snapshot the
 *    current state;
 *  - a staging initialized snapshot has exactly one row (only `rotateAuthorityRelease` creates a second row, and it is
 *    Production-only), in every state that carries rows: EXACT_RECEIPT, initialized NOT_FOUND and HISTORY_INCOMPLETE;
 *  - a two-row snapshot satisfies 0 < retired.retiredMs - unretired.activatedMs <= 300000: the two rows are always the pair
 *    one rotation wrote (`previousRetiresAtMs`, `activatesAtMs`), and the rotation policy bounds exactly that difference.
 * Deliberately NOT enforced: `observedAtMs >= receipt.appliedMs`. The signer is the Authority DO and both times come from
 * its own clock, but they are separate `Date.now()` reads in separate invocations (the receipt when the command was applied,
 * `observedAtMs` when the result is attested), and the authority's own code treats that clock as possibly regressing (it
 * refuses to proceed when `now < last_now_ms`). Source does not prove the ordering, so it is not part of the protocol.
 *
 * Canonicalization: every entry point reads caller-owned data exactly once, through own data descriptors, into fresh plain
 * arrays; validates that snapshot; and encodes only that snapshot with a hook-free encoder whose output is byte-identical to
 * `JSON.stringify` for the tuple model. Array subclasses, `Symbol.species`, own or inherited `toJSON`, accessors, holes and
 * extra own properties therefore cannot make the encoder emit bytes the validator did not see; non-plain arrays are rejected.
 *
 * Transport: a signed envelope is an opaque byte string. Relay the canonical envelope bytes unchanged; any re-serialization
 * (whitespace, member order, re-encoding) is rejected by the strict parser even when semantically identical.
 */

export const ATTESTATION_VERSION = 2 as const;
export const ATTESTATION_TRUST_EPOCH = 1 as const;
export const ATTESTATION_POLICY_EPOCH = "phase5c-i1-epoch-1" as const;
/** Exact UTF-8 bytes signed before the statement: the text below followed by a single NUL byte. */
export const ATTESTATION_SIGNING_DOMAIN = "limitmark:authority-result-attestation:ed25519:v2\0" as const;
export const ATTESTATION_MAX_AGE_MS = 300_000;
export const ATTESTATION_MAX_FUTURE_SKEW_MS = 60_000;
export const ATTESTATION_MAX_ENVELOPE_BYTES = 8_192;
export const ATTESTATION_MAX_ROTATION_OVERLAP_MS = 5 * 60_000;
/** Source-proven: the authority applies a command only when |appliedMs - activatesMs| <= 300000 (inclusive), for both
 * `initialize` (`executeSignedAuthorityInitialization`) and `rotate-release` (`executeSignedAuthorityReleaseRotation`). The
 * relation is symmetric: activation may legitimately lie in the future of the apply time. */
export const ATTESTATION_MAX_APPLIED_ACTIVATION_SKEW_MS = 5 * 60_000;
export const ATTESTATION_MAX_SEQUENCE = 4_096;
/** Pinned in source so a Production statement can never name the staging authority (and vice versa). Tests pin these
 * to the authority module constants. */
export const ATTESTATION_AUTHORITY_IDS = {
  production: "production-public-inquiries-v1",
  staging: "staging-public-inquiries-v1",
} as const;

export type AttestationEnvironment = keyof typeof ATTESTATION_AUTHORITY_IDS;
export type AttestationOperation = "initialize" | "rotate-release";

/** The authority receipt as attested. `operatorKeyFingerprint` is the OPERATOR key that signed the lifecycle command
 * (the authority's `keyFingerprint`); it is unrelated to the result WRITER key fingerprint in the statement. */
export interface AttestationReceipt {
  readonly digest: string;
  readonly version: 1;
  readonly operation: AttestationOperation;
  readonly environment: AttestationEnvironment;
  readonly authorityId: string;
  readonly policyEpoch: typeof ATTESTATION_POLICY_EPOCH;
  readonly operatorKeyFingerprint: string;
  readonly sequence: number;
  readonly appliedMs: number;
  readonly currentReleaseId: string;
  readonly nextReleaseId: string;
  readonly nextKeyId: string;
  readonly activatesMs: number;
  readonly retiresMs: number | null;
}

export interface AttestationReleaseRow {
  readonly releaseId: string;
  readonly keyId: string;
  readonly activatedMs: number;
  readonly retiredMs: number | null;
}

export type ReceiptTuple = readonly [
  digest: string, version: 1, operation: AttestationOperation, environment: AttestationEnvironment, authorityId: string,
  policyEpoch: string, operatorKeyFingerprint: string, sequence: number, appliedMs: number, currentReleaseId: string,
  nextReleaseId: string, nextKeyId: string, activatesMs: number, retiresMs: number | null,
];
export type ReleaseRowTuple = readonly [releaseId: string, keyId: string, activatedMs: number, retiredMs: number | null];

export interface LifecycleStatement {
  readonly version: typeof ATTESTATION_VERSION;
  readonly trustEpoch: typeof ATTESTATION_TRUST_EPOCH;
  readonly environment: AttestationEnvironment;
  readonly authorityId: string;
  readonly policyEpoch: typeof ATTESTATION_POLICY_EPOCH;
  readonly kind: "lifecycle";
  readonly digest: string;
  /** Means only: the authority has committed or observed the immutable receipt. Never a relay-level outcome. */
  readonly outcome: "APPLIED";
  readonly receipt: AttestationReceipt;
  readonly observedAtMs: number;
  readonly writerKeyFingerprint: string;
}

export type ReconciliationCoverage = "COMPLETE" | "INCOMPLETE";
export type ReconciliationStatus = "EXACT_RECEIPT" | "NOT_FOUND" | "HISTORY_INCOMPLETE";

/** UNAVAILABLE is not an authority statement and intentionally has no variant. */
export interface ReconciliationStatement {
  readonly version: typeof ATTESTATION_VERSION;
  readonly trustEpoch: typeof ATTESTATION_TRUST_EPOCH;
  readonly environment: AttestationEnvironment;
  readonly authorityId: string;
  readonly policyEpoch: typeof ATTESTATION_POLICY_EPOCH;
  readonly kind: "reconciliation";
  readonly digest: string;
  readonly nonce: string;
  readonly initialized: boolean;
  readonly coverage: ReconciliationCoverage;
  readonly status: ReconciliationStatus;
  readonly receipt: AttestationReceipt | null;
  readonly releases: readonly AttestationReleaseRow[];
  readonly observedAtMs: number;
  readonly writerKeyFingerprint: string;
}

export type ResultStatement = LifecycleStatement | ReconciliationStatement;

export type LifecycleStatementInput = Omit<LifecycleStatement, "version" | "kind" | "outcome">;
export type ReconciliationStatementInput = Omit<ReconciliationStatement, "version" | "kind">;

export interface ResultAttestationEnvelope {
  readonly statement: ResultStatement;
  /** Canonical unpadded base64url of exactly 64 bytes. */
  readonly signature: string;
}

// ---------------------------------------------------------------------------------------------------------------------
// Field orders: the single positional contract. Each list is checked against its type at compile time in both
// directions (`satisfies` rejects an unknown key; `Exhaustive` resolves to `never` if a key is not listed), so adding a
// semantic field without updating protocol construction fails typecheck.
// ---------------------------------------------------------------------------------------------------------------------
type Exhaustive<T, List extends readonly (keyof T)[]> = [Exclude<keyof T, List[number]>] extends [never] ? List : never;

const listedReceiptFields = ["digest", "version", "operation", "environment", "authorityId", "policyEpoch", "operatorKeyFingerprint",
  "sequence", "appliedMs", "currentReleaseId", "nextReleaseId", "nextKeyId", "activatesMs", "retiresMs"] as const satisfies readonly (keyof AttestationReceipt)[];
export const RECEIPT_FIELDS: Exhaustive<AttestationReceipt, typeof listedReceiptFields> = listedReceiptFields;

const listedReleaseRowFields = ["releaseId", "keyId", "activatedMs", "retiredMs"] as const satisfies readonly (keyof AttestationReleaseRow)[];
export const RELEASE_ROW_FIELDS: Exhaustive<AttestationReleaseRow, typeof listedReleaseRowFields> = listedReleaseRowFields;

const listedLifecycleFields = ["version", "trustEpoch", "environment", "authorityId", "policyEpoch", "kind", "digest", "outcome", "receipt",
  "observedAtMs", "writerKeyFingerprint"] as const satisfies readonly (keyof LifecycleStatement)[];
export const LIFECYCLE_STATEMENT_FIELDS: Exhaustive<LifecycleStatement, typeof listedLifecycleFields> = listedLifecycleFields;

const listedReconciliationFields = ["version", "trustEpoch", "environment", "authorityId", "policyEpoch", "kind", "digest", "nonce", "initialized",
  "coverage", "status", "receipt", "releases", "observedAtMs", "writerKeyFingerprint"] as const satisfies readonly (keyof ReconciliationStatement)[];
export const RECONCILIATION_STATEMENT_FIELDS: Exhaustive<ReconciliationStatement, typeof listedReconciliationFields> = listedReconciliationFields;

// The authority's receipt and the attested receipt must carry the same semantic keys (only `keyFingerprint` is renamed).
type ReceiptKeysMatch = [Exclude<keyof LifecycleReceipt, "keyFingerprint"> | "operatorKeyFingerprint"] extends [keyof AttestationReceipt]
  ? [keyof AttestationReceipt] extends [Exclude<keyof LifecycleReceipt, "keyFingerprint"> | "operatorKeyFingerprint"] ? true : never : never;
const receiptKeysMatch: ReceiptKeysMatch = true;
void receiptKeysMatch;

// ---------------------------------------------------------------------------------------------------------------------
// Shared primitives
// ---------------------------------------------------------------------------------------------------------------------
const hex64Pattern = /^[a-f0-9]{64}$/u;
const nonceHexPattern = /^[a-f0-9]{32}$/u;
const releaseIdPattern = /^[A-Za-z0-9_.:-]{1,128}$/u;
const keyIdPattern = /^[A-Za-z0-9_-]{1,64}$/u;
const operations: readonly string[] = ["initialize", "rotate-release"];
const encoder = new TextEncoder();

function fail(code: string): never { throw new Error(code); }

export const isLowerHex64 = (value: unknown): value is string => typeof value === "string" && hex64Pattern.test(value);
/** Non-negative safe integer; `-0` is rejected so that JSON text and value stay one-to-one. */
export const isSafeTime = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** A plain array of the canonical tuple model: exactly `Array.prototype` (no subclass, so no species or inherited override),
 * no symbol keys, own keys exactly the indices and `length` (no own `toJSON`/`constructor`, no holes), every index a data
 * property (no accessors). `Array.isArray` alone is not enough. */
function isPlainArray(value: unknown): value is readonly unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length !== 0) return false;
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  const length: unknown = lengthDescriptor && "value" in lengthDescriptor ? lengthDescriptor.value : undefined;
  if (typeof length !== "number" || Object.getOwnPropertyNames(value).length !== length + 1) return false;
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor)) return false;
  }
  return true;
}

/** Reads one own data property exactly once (never through a getter or the prototype chain). */
function readOwnData(value: object, key: string, code: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !("value" in descriptor)) fail(code);
  return descriptor.value;
}

/** Fresh plain copy of a caller-owned plain array; each element read once. */
function snapshotPlainArray(value: unknown, code: string): unknown[] {
  if (!isPlainArray(value)) fail(code);
  const length = readOwnData(value, "length", code) as number;
  const copy: unknown[] = [];
  for (let index = 0; index < length; index += 1) copy[index] = readOwnData(value, String(index), code);
  return copy;
}

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

/** Exactly the listed own data keys, none undefined, no accessors. */
function hasExactFields(value: Record<string, unknown>, fields: readonly string[], code: string): void {
  const keys = Object.keys(value);
  if (keys.length !== fields.length || Object.getOwnPropertySymbols(value).length > 0) fail(code);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !("value" in descriptor) || descriptor.value === undefined) fail(code);
  }
}

// ---------------------------------------------------------------------------------------------------------------------
// Receipt and release-row validation / conversion
// ---------------------------------------------------------------------------------------------------------------------
interface OuterBinding { readonly digest: string; readonly environment: AttestationEnvironment; readonly authorityId: string }

function validateReceipt(value: unknown, outer: OuterBinding): asserts value is AttestationReceipt {
  if (!isPlainRecord(value)) fail("attestation-receipt");
  hasExactFields(value, RECEIPT_FIELDS, "attestation-receipt");
  if (!isLowerHex64(value.digest) || value.digest !== outer.digest || value.version !== 1 ||
      typeof value.operation !== "string" || !operations.includes(value.operation) ||
      value.environment !== outer.environment || value.authorityId !== outer.authorityId ||
      value.policyEpoch !== ATTESTATION_POLICY_EPOCH || !isLowerHex64(value.operatorKeyFingerprint) ||
      !isSafeTime(value.sequence) || value.sequence < 1 || value.sequence > ATTESTATION_MAX_SEQUENCE ||
      !isSafeTime(value.appliedMs) || !isSafeTime(value.activatesMs) || (value.retiresMs !== null && !isSafeTime(value.retiresMs)) ||
      typeof value.currentReleaseId !== "string" || !releaseIdPattern.test(value.currentReleaseId) ||
      typeof value.nextReleaseId !== "string" || !releaseIdPattern.test(value.nextReleaseId) ||
      typeof value.nextKeyId !== "string" || !keyIdPattern.test(value.nextKeyId)) fail("attestation-receipt");
  if (Math.abs((value.appliedMs as number) - (value.activatesMs as number)) > ATTESTATION_MAX_APPLIED_ACTIVATION_SKEW_MS) fail("attestation-receipt");
  if (value.operation === "initialize") {
    if (value.currentReleaseId !== value.nextReleaseId || value.retiresMs !== null || value.sequence !== 1) fail("attestation-receipt");
  } else if (value.environment !== "production" || (value.sequence as number) < 2 || value.currentReleaseId === value.nextReleaseId ||
      typeof value.retiresMs !== "number" || value.retiresMs <= (value.activatesMs as number) ||
      value.retiresMs - (value.activatesMs as number) > ATTESTATION_MAX_ROTATION_OVERLAP_MS) {
    fail("attestation-receipt");
  }
}

/** One row means no rotation ever happened: `initializeAuthority` inserts exactly one unretired row and every
 * `rotateAuthorityRelease` leaves exactly two (it deletes at most the old retired row, retires the current row and inserts
 * the next). The only receipt that can exist is then the sequence-1 initialization, and the row is its release. */
function assertOneRowReceiptCoherence(receipt: AttestationReceipt, releases: readonly AttestationReleaseRow[]): void {
  if (releases.length !== 1) return;
  const [row] = releases;
  if (receipt.operation !== "initialize" || receipt.sequence !== 1 || row.releaseId !== receipt.nextReleaseId ||
      row.keyId !== receipt.nextKeyId || row.activatedMs !== receipt.activatesMs || row.retiredMs !== null) fail("attestation-statement");
}

function validateReleaseRow(value: unknown): asserts value is AttestationReleaseRow {
  if (!isPlainRecord(value)) fail("attestation-releases");
  hasExactFields(value, RELEASE_ROW_FIELDS, "attestation-releases");
  if (typeof value.releaseId !== "string" || !releaseIdPattern.test(value.releaseId) ||
      typeof value.keyId !== "string" || !keyIdPattern.test(value.keyId) ||
      !isSafeTime(value.activatedMs) || (value.retiredMs !== null && !isSafeTime(value.retiredMs))) fail("attestation-releases");
}

/** Canonical order: activatedMs ascending, then releaseId, then keyId, by JS/Unicode code-unit ordering. */
function compareReleaseRows(a: AttestationReleaseRow, b: AttestationReleaseRow): number {
  if (a.activatedMs !== b.activatedMs) return a.activatedMs < b.activatedMs ? -1 : 1;
  if (a.releaseId !== b.releaseId) return a.releaseId < b.releaseId ? -1 : 1;
  if (a.keyId !== b.keyId) return a.keyId < b.keyId ? -1 : 1;
  return 0;
}

/** Validates rows and REQUIRES canonical order. Mirrors the source-proven authority snapshot invariants: one or two
 * rows when initialized (exactly one in staging, which cannot rotate), exactly one unretired, unique release/key ids,
 * retired > activated, and for two rows retired.activatedMs <= unretired.activatedMs and
 * 0 < retired.retiredMs - unretired.activatedMs <= 300000 (the rotation overlap bound). */
function validateReleaseRows(value: unknown, initialized: boolean, environment: AttestationEnvironment): asserts value is readonly AttestationReleaseRow[] {
  if (!isPlainArray(value)) fail("attestation-releases");
  const rows = value;
  if (initialized ? rows.length < 1 || rows.length > (environment === "staging" ? 1 : 2) : rows.length !== 0) fail("attestation-releases");
  for (const row of rows) validateReleaseRow(row);
  const typed = rows as readonly AttestationReleaseRow[];
  for (let index = 1; index < typed.length; index += 1) if (compareReleaseRows(typed[index - 1], typed[index]) >= 0) fail("attestation-releases");
  if (new Set(typed.map((row) => row.releaseId)).size !== typed.length || new Set(typed.map((row) => row.keyId)).size !== typed.length) fail("attestation-releases");
  if (!initialized) return;
  const unretired = typed.filter((row) => row.retiredMs === null);
  const retired = typed.filter((row) => row.retiredMs !== null);
  if (unretired.length !== 1 || retired.some((row) => row.retiredMs! <= row.activatedMs)) fail("attestation-releases");
  if (retired.length === 1) {
    const overlap = retired[0].retiredMs! - unretired[0].activatedMs;
    if (overlap <= 0 || overlap > ATTESTATION_MAX_ROTATION_OVERLAP_MS || unretired[0].activatedMs < retired[0].activatedMs) fail("attestation-releases");
  }
}

/** Constructor inputs are checked for exactly the contract keys (no extras, none undefined) before being copied. */
function assertExactInput(value: unknown, fields: readonly string[], code: string): void {
  if (!isPlainRecord(value)) fail(code);
  hasExactFields(value, fields, code);
}

const cloneReceipt = (receipt: AttestationReceipt): AttestationReceipt => (assertExactInput(receipt, RECEIPT_FIELDS, "attestation-receipt"), Object.freeze({
  digest: receipt.digest, version: receipt.version, operation: receipt.operation, environment: receipt.environment,
  authorityId: receipt.authorityId, policyEpoch: receipt.policyEpoch, operatorKeyFingerprint: receipt.operatorKeyFingerprint,
  sequence: receipt.sequence, appliedMs: receipt.appliedMs, currentReleaseId: receipt.currentReleaseId, nextReleaseId: receipt.nextReleaseId,
  nextKeyId: receipt.nextKeyId, activatesMs: receipt.activatesMs, retiresMs: receipt.retiresMs }));

const cloneRow = (row: AttestationReleaseRow): AttestationReleaseRow => (assertExactInput(row, RELEASE_ROW_FIELDS, "attestation-releases"), Object.freeze({
  releaseId: row.releaseId, keyId: row.keyId, activatedMs: row.activatedMs, retiredMs: row.retiredMs }));

/** The single authority-receipt → attested-receipt mapping. Shared by every signer. */
export function attestationReceiptFromLifecycleReceipt(receipt: LifecycleReceipt): AttestationReceipt {
  return cloneReceipt({
    digest: receipt.digest, version: receipt.version, operation: receipt.operation, environment: receipt.environment,
    authorityId: receipt.authorityId, policyEpoch: receipt.policyEpoch as typeof ATTESTATION_POLICY_EPOCH,
    operatorKeyFingerprint: receipt.keyFingerprint, sequence: receipt.sequence, appliedMs: receipt.appliedMs,
    currentReleaseId: receipt.currentReleaseId, nextReleaseId: receipt.nextReleaseId, nextKeyId: receipt.nextKeyId,
    activatesMs: receipt.activatesMs, retiresMs: receipt.retiresMs });
}

/** The single authority release-row → attested-row mapping (the authority query returns snake_case columns). */
export function attestationReleaseRowFromAuthority(row: { release_id: string; key_id: string; activated_ms: number; retired_ms: number | null }): AttestationReleaseRow {
  return cloneRow({ releaseId: row.release_id, keyId: row.key_id, activatedMs: row.activated_ms, retiredMs: row.retired_ms });
}

// ---------------------------------------------------------------------------------------------------------------------
// Statement validation, construction, tuple conversion
// ---------------------------------------------------------------------------------------------------------------------
type StatementBase = { environment: AttestationEnvironment; authorityId: string; digest: string };

function validateCommon(value: Record<string, unknown>): StatementBase {
  if (value.version !== ATTESTATION_VERSION || value.trustEpoch !== ATTESTATION_TRUST_EPOCH ||
      (value.environment !== "production" && value.environment !== "staging") ||
      value.authorityId !== ATTESTATION_AUTHORITY_IDS[value.environment] || value.policyEpoch !== ATTESTATION_POLICY_EPOCH ||
      !isLowerHex64(value.digest) || !isSafeTime(value.observedAtMs) || !isLowerHex64(value.writerKeyFingerprint)) fail("attestation-statement");
  return { environment: value.environment, authorityId: ATTESTATION_AUTHORITY_IDS[value.environment], digest: value.digest };
}

/** The one statement validator. Constructors, the canonical encoder, signer, parser and verifier all pass through it. */
export function validateResultStatement(value: unknown): asserts value is ResultStatement {
  if (!isPlainRecord(value)) fail("attestation-statement");
  if (value.kind === "lifecycle") {
    hasExactFields(value, LIFECYCLE_STATEMENT_FIELDS, "attestation-statement");
    const outer = validateCommon(value);
    if (value.outcome !== "APPLIED") fail("attestation-statement");
    validateReceipt(value.receipt, outer);
    return;
  }
  if (value.kind !== "reconciliation") fail("attestation-statement");
  hasExactFields(value, RECONCILIATION_STATEMENT_FIELDS, "attestation-statement");
  const outer = validateCommon(value);
  if (typeof value.nonce !== "string" || !nonceHexPattern.test(value.nonce) || typeof value.initialized !== "boolean") fail("attestation-statement");
  const state = `${value.initialized}/${String(value.coverage)}/${String(value.status)}`;
  const receiptRequired = state === "true/COMPLETE/EXACT_RECEIPT";
  if (!["false/COMPLETE/NOT_FOUND", "true/COMPLETE/EXACT_RECEIPT", "true/COMPLETE/NOT_FOUND", "true/INCOMPLETE/HISTORY_INCOMPLETE"].includes(state)) fail("attestation-statement");
  if (receiptRequired) validateReceipt(value.receipt, outer);
  else if (value.receipt !== null) fail("attestation-statement");
  validateReleaseRows(value.releases, value.initialized, outer.environment);
  if (receiptRequired) assertOneRowReceiptCoherence(value.receipt as AttestationReceipt, value.releases as readonly AttestationReleaseRow[]);
}

const lifecycleInputFields = LIFECYCLE_STATEMENT_FIELDS.filter((field) => field !== "version" && field !== "kind" && field !== "outcome");
const reconciliationInputFields = RECONCILIATION_STATEMENT_FIELDS.filter((field) => field !== "version" && field !== "kind");

export function makeLifecycleStatement(input: LifecycleStatementInput): LifecycleStatement {
  assertExactInput(input, lifecycleInputFields, "attestation-statement");
  const candidate: LifecycleStatement = {
    version: ATTESTATION_VERSION, trustEpoch: input.trustEpoch, environment: input.environment, authorityId: input.authorityId,
    policyEpoch: input.policyEpoch, kind: "lifecycle", digest: input.digest, outcome: "APPLIED",
    receipt: cloneReceipt(input.receipt), observedAtMs: input.observedAtMs, writerKeyFingerprint: input.writerKeyFingerprint };
  return snapshotResultStatement(candidate) as LifecycleStatement;
}

/** Accepts release rows in any order and emits them in canonical order; the validator requires that order. `releases` must
 * be a plain array (an Array subclass, proxy-like accessor or own `toJSON` is refused, never adopted). */
export function makeReconciliationStatement(input: ReconciliationStatementInput): ReconciliationStatement {
  assertExactInput(input, reconciliationInputFields, "attestation-statement");
  const rows = snapshotPlainArray(input.releases, "attestation-releases");
  const releases: AttestationReleaseRow[] = [];
  for (let index = 0; index < rows.length; index += 1) releases[index] = cloneRow(rows[index] as AttestationReleaseRow);
  releases.sort(compareReleaseRows);
  const candidate: ReconciliationStatement = {
    version: ATTESTATION_VERSION, trustEpoch: input.trustEpoch, environment: input.environment, authorityId: input.authorityId,
    policyEpoch: input.policyEpoch, kind: "reconciliation", digest: input.digest, nonce: input.nonce, initialized: input.initialized,
    coverage: input.coverage, status: input.status, receipt: input.receipt === null ? null : cloneReceipt(input.receipt),
    releases, observedAtMs: input.observedAtMs, writerKeyFingerprint: input.writerKeyFingerprint };
  return snapshotResultStatement(candidate) as ReconciliationStatement;
}

/** Positional copy of a plain record: exactly `fields`, each read once through its own data descriptor. */
function snapshotRecord(value: unknown, fields: readonly string[], code: string): unknown[] {
  if (!isPlainRecord(value)) fail(code);
  hasExactFields(value, fields, code);
  const tuple: unknown[] = [];
  for (let index = 0; index < fields.length; index += 1) tuple[index] = readOwnData(value, fields[index], code);
  return Object.freeze(tuple) as unknown[];
}

/** Reads a caller-owned statement exactly once into a fresh tuple of fresh plain arrays, each frozen by this module (leaf
 * values are never frozen: an invalid caller object leaf is rejected later, not mutated). Nothing is validated here; the
 * caller validates and encodes only THIS frozen tuple. */
function snapshotStatementTuple(statement: unknown): unknown[] {
  if (!isPlainRecord(statement)) fail("attestation-statement");
  const kind = readOwnData(statement, "kind", "attestation-statement");
  const fields = kind === "lifecycle" ? LIFECYCLE_STATEMENT_FIELDS : kind === "reconciliation" ? RECONCILIATION_STATEMENT_FIELDS : fail("attestation-statement");
  const tuple = [...snapshotRecord(statement, fields, "attestation-statement")];
  const receiptAt = kind === "lifecycle" ? 8 : 11;
  if (kind === "lifecycle" || tuple[receiptAt] !== null) tuple[receiptAt] = snapshotRecord(tuple[receiptAt], RECEIPT_FIELDS, "attestation-receipt");
  if (kind === "reconciliation") {
    const rows = snapshotPlainArray(tuple[12], "attestation-releases");
    for (let index = 0; index < rows.length; index += 1) rows[index] = snapshotRecord(rows[index], RELEASE_ROW_FIELDS, "attestation-releases");
    tuple[12] = Object.freeze(rows);
  }
  return Object.freeze(tuple) as unknown[];
}

/** The validated canonical tuple: a deep-frozen structure of plain arrays and primitives, owned by this module. */
function canonicalTuple(statement: unknown): readonly unknown[] {
  // Frozen BEFORE validation: the structure validated (a copy read from it) and the structure encoded are value-identical.
  const tuple = snapshotStatementTuple(statement);
  parseResultStatementTuple(tuple);
  return tuple;
}

/** A validated, deep-frozen, plain copy of `statement` that shares no object with the caller. */
export function snapshotResultStatement(statement: ResultStatement): ResultStatement {
  return parseResultStatementTuple(snapshotStatementTuple(statement));
}

/** The exact signed tuple (11 or 15 entries) for a validated statement: deep-frozen plain arrays and primitives only. */
export function resultStatementTuple(statement: ResultStatement): readonly unknown[] {
  return canonicalTuple(statement);
}

function recordFromTuple(tuple: readonly unknown[], fields: readonly string[], code: string): Record<string, unknown> {
  if (tuple.length !== fields.length) fail(code);
  const record: Record<string, unknown> = {};
  for (let index = 0; index < fields.length; index += 1) record[fields[index]] = tuple[index];
  return record;
}

/** Strict inverse of `resultStatementTuple`: plain arrays only (copied once), positional, exact lengths, then the shared
 * validator. The result is a fresh deep-frozen statement. */
export function parseResultStatementTuple(tuple: unknown): ResultStatement {
  const top = snapshotPlainArray(tuple, "attestation-statement");
  const kind = top[5];
  const fields = kind === "lifecycle" ? LIFECYCLE_STATEMENT_FIELDS : kind === "reconciliation" ? RECONCILIATION_STATEMENT_FIELDS : fail("attestation-statement");
  const statement = recordFromTuple(top, fields, "attestation-statement");
  if (kind === "lifecycle" || statement.receipt !== null) {
    statement.receipt = recordFromTuple(snapshotPlainArray(statement.receipt, "attestation-receipt"), RECEIPT_FIELDS, "attestation-receipt");
  }
  if (kind === "reconciliation") {
    const rows = snapshotPlainArray(statement.releases, "attestation-releases");
    for (let index = 0; index < rows.length; index += 1) {
      rows[index] = recordFromTuple(snapshotPlainArray(rows[index], "attestation-releases"), RELEASE_ROW_FIELDS, "attestation-releases");
    }
    statement.releases = rows;
  }
  validateResultStatement(statement);
  return deepFreeze(statement as unknown as ResultStatement);
}

// ---------------------------------------------------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------------------------------------------------
/** Byte-identical to `JSON.stringify` for the tuple model (null, booleans, non-negative safe integers, strings, plain
 * arrays), but never consults `toJSON`: `JSON.stringify` is applied to primitives only, for which the specification does
 * not look up `toJSON`, so even a polluted `Array.prototype.toJSON` / `Object.prototype.toJSON` cannot change the bytes. */
function encodeTupleJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return isSafeTime(value) ? JSON.stringify(value) : fail("attestation-statement");
  if (!isPlainArray(value)) return fail("attestation-statement");
  let text = "[";
  for (let index = 0; index < value.length; index += 1) text += (index === 0 ? "" : ",") + encodeTupleJson(value[index]);
  return text + "]";
}

const canonicalStatementText = (statement: unknown): string => encodeTupleJson(canonicalTuple(statement));
const signingBytesFromText = (statementText: string): Uint8Array => encoder.encode(ATTESTATION_SIGNING_DOMAIN + statementText);

/** UTF8(JSON.stringify(validatedStatementTuple)). */
export function canonicalStatementBytes(statement: ResultStatement): Uint8Array {
  return encoder.encode(canonicalStatementText(statement));
}

/** UTF8(domain, including the trailing NUL) || UTF8(JSON.stringify(validatedStatementTuple)). This is what is signed. */
export function attestationSigningBytes(statement: ResultStatement): Uint8Array {
  return signingBytesFromText(canonicalStatementText(statement));
}

function checkSignatureText(signature: unknown): asserts signature is string {
  if (typeof signature !== "string") fail("attestation-envelope");
  try { decodeCanonicalBase64url(signature, 64); } catch { fail("attestation-envelope"); }
}

/** `JSON.stringify({ statement, signature })` for an already-canonical statement text and a canonical signature string. */
const envelopeText = (statementText: string, signature: string): string => `{"statement":${statementText},"signature":${JSON.stringify(signature)}}`;

/** Reads a caller-owned envelope once: exactly `statement` and `signature`, as own data properties. */
function readEnvelope(envelope: unknown): { statement: unknown; signature: string } {
  if (!isPlainRecord(envelope)) fail("attestation-envelope");
  hasExactFields(envelope, ["statement", "signature"], "attestation-envelope");
  const statement = readOwnData(envelope, "statement", "attestation-envelope");
  const signature = readOwnData(envelope, "signature", "attestation-envelope");
  checkSignatureText(signature);
  return { statement, signature };
}

/** Canonical envelope bytes: `{"statement":<tuple>,"signature":"<base64url>"}`, at most 8192 bytes. */
export function encodeResultAttestationEnvelope(envelope: ResultAttestationEnvelope): Uint8Array {
  const { statement, signature } = readEnvelope(envelope);
  const bytes = encoder.encode(envelopeText(canonicalStatementText(statement), signature));
  if (bytes.length > ATTESTATION_MAX_ENVELOPE_BYTES) fail("attestation-envelope");
  return bytes;
}

// ---------------------------------------------------------------------------------------------------------------------
// Strict JSON (duplicate members, trailing content, integer-only numbers). Also used for the trust manifest.
// ---------------------------------------------------------------------------------------------------------------------
export function parseStrictJsonText(source: string, code: string, maxDepth = 16): unknown {
  let index = 0;
  const bad = (): never => fail(code);
  const space = () => { while (index < source.length && (source[index] === " " || source[index] === "\t" || source[index] === "\r" || source[index] === "\n")) index += 1; };
  const string = (): string => {
    if (source[index] !== '"') bad();
    const start = index++;
    while (index < source.length) {
      const character = source[index++];
      if (character === '"') {
        try { return JSON.parse(source.slice(start, index)) as string; } catch { return bad(); }
      }
      if (character === "\\") index += 1;
      else if (character.charCodeAt(0) < 0x20) bad();
    }
    return bad();
  };
  const value = (depth: number): unknown => {
    if (depth > maxDepth) bad();
    space();
    const character = source[index];
    if (character === '"') return string();
    if (character === "[") {
      index += 1; space();
      const array: unknown[] = [];
      if (source[index] === "]") { index += 1; return array; }
      for (;;) {
        array.push(value(depth + 1)); space();
        if (source[index] === "]") { index += 1; return array; }
        if (source[index++] !== ",") bad();
      }
    }
    if (character === "{") {
      index += 1; space();
      const object: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      if (source[index] === "}") { index += 1; return object; }
      for (;;) {
        space(); const key = string(); space();
        if (source[index++] !== ":" || Object.hasOwn(object, key)) bad();
        object[key] = value(depth + 1); space();
        if (source[index] === "}") { index += 1; return object; }
        if (source[index++] !== ",") bad();
      }
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*))/u.exec(source.slice(index, index + 32));
    if (!match || match[0] === "-0") return bad();
    index += match[0].length;
    if (match[0] === "true") return true;
    if (match[0] === "false") return false;
    if (match[0] === "null") return null;
    return Number(match[0]);
  };
  const parsed = value(0);
  space();
  if (index !== source.length) bad();
  return parsed;
}

/**
 * Strict envelope parser. Rejects: size 0 or > 8192, malformed UTF-8, BOM, duplicate JSON members, trailing content,
 * missing/extra/reordered fields, unsupported statement kind/version/length, non-canonical base64url or signature
 * length, and any input that is not byte-for-byte the canonical encoding of what it parses to.
 */
export function parseResultAttestationEnvelope(bytes: Uint8Array): ResultAttestationEnvelope {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > ATTESTATION_MAX_ENVELOPE_BYTES) fail("attestation-envelope");
  let source: string;
  try { source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); } catch { return fail("attestation-envelope"); }
  if (source.charCodeAt(0) === 0xfeff) fail("attestation-envelope");
  const value = parseStrictJsonText(source, "attestation-envelope");
  if (!isPlainRecord(value)) fail("attestation-envelope");
  hasExactFields(value, ["statement", "signature"], "attestation-envelope");
  checkSignatureText(value.signature);
  const envelope: ResultAttestationEnvelope = { statement: parseResultStatementTuple(value.statement), signature: value.signature };
  const canonical = encodeResultAttestationEnvelope(envelope);
  if (canonical.length !== bytes.length || canonical.some((byte, position) => byte !== bytes[position])) fail("attestation-envelope");
  return Object.freeze(envelope);
}

// ---------------------------------------------------------------------------------------------------------------------
// Freshness
// ---------------------------------------------------------------------------------------------------------------------
/** Age at most 300000 ms; at most 60000 ms ahead of the local clock. */
export function assertAttestationFresh(observedAtMs: number, nowMs: number): void {
  if (!isSafeTime(observedAtMs) || !isSafeTime(nowMs)) fail("attestation-stale");
  if (nowMs - observedAtMs > ATTESTATION_MAX_AGE_MS || observedAtMs - nowMs > ATTESTATION_MAX_FUTURE_SKEW_MS) fail("attestation-stale");
}

// ---------------------------------------------------------------------------------------------------------------------
// Keys: raw 32-byte public keys, RFC 8410 PKCS#8 test private keys, SHA-256 fingerprints, sign/verify
// ---------------------------------------------------------------------------------------------------------------------
const PKCS8_ED25519_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes))), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function decodeKey(value: unknown, length: number, code: string): Uint8Array {
  if (typeof value !== "string") return fail(code);
  try { return decodeCanonicalBase64url(value, length); } catch { return fail(code); }
}

/** lowercaseHex(SHA-256(raw 32-byte Ed25519 public key)) of a canonical unpadded base64url public key. */
export async function attestationKeyFingerprint(publicKey: string): Promise<string> {
  return sha256Hex(decodeKey(publicKey, 32, "attestation-key-material"));
}

// --- Ed25519 public-key safety -------------------------------------------------------------------------------------
// The runtime verifier (WebCrypto/OpenSSL) accepts every small-order public key and, for them, signatures that need no
// private scalar (identity key + R=identity, S=0 verifies ANY message; the same holds for non-canonical identity encodings
// and some order-8 points). A trust-manifest key must therefore be a canonical encoding of a point in the prime-order
// subgroup: on the curve, y < p, not the identity, and [L]A = identity. [L]A = identity excludes every other small-order point
// (gcd(L, 8) = 1, so [L] fixes a torsion point's order) and every mixed-order point (any torsion component), so no manifest
// key can validate a signature without its discrete log. Exact BigInt arithmetic, no ad-hoc blacklist.
const FIELD_P = (1n << 255n) - 19n;
const GROUP_ORDER_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const mod = (value: bigint): bigint => ((value % FIELD_P) + FIELD_P) % FIELD_P;
function power(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let square = mod(base);
  for (let remaining = exponent; remaining > 0n; remaining >>= 1n) {
    if (remaining & 1n) result = mod(result * square);
    square = mod(square * square);
  }
  return result;
}
const invert = (value: bigint): bigint => power(value, FIELD_P - 2n);
const CURVE_D = mod(-121665n * invert(121666n));
const SQRT_MINUS_ONE = power(2n, (FIELD_P - 1n) / 4n);

type ExtendedPoint = readonly [x: bigint, y: bigint, z: bigint, t: bigint];
const IDENTITY: ExtendedPoint = [0n, 1n, 1n, 0n];

function addPoints(a: ExtendedPoint, b: ExtendedPoint): ExtendedPoint {
  const left = mod((a[1] - a[0]) * (b[1] - b[0]));
  const right = mod((a[1] + a[0]) * (b[1] + b[0]));
  const c = mod(a[3] * 2n * CURVE_D * b[3]);
  const d = mod(a[2] * 2n * b[2]);
  const e = right - left;
  const f = d - c;
  const g = d + c;
  const h = right + left;
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
}

function multiplyPoint(point: ExtendedPoint, scalar: bigint): ExtendedPoint {
  let result: ExtendedPoint = IDENTITY;
  let addend = point;
  for (let remaining = scalar; remaining > 0n; remaining >>= 1n) {
    if (remaining & 1n) result = addPoints(result, addend);
    addend = addPoints(addend, addend);
  }
  return result;
}

const isIdentityPoint = (point: ExtendedPoint): boolean => point[0] === 0n && point[1] === point[2];

/** RFC 8032 section 5.1.3 decoding (rejecting y >= p and the x=0/sign=1 form), or `null` when not a curve point. */
function decodeCurvePoint(raw: Uint8Array): ExtendedPoint | null {
  let value = 0n;
  for (let index = raw.length - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(raw[index]);
  const sign = value >> 255n;
  const y = value & ((1n << 255n) - 1n);
  if (y >= FIELD_P) return null;
  const y2 = mod(y * y);
  const x2 = mod((y2 - 1n) * invert(mod(CURVE_D * y2 + 1n)));
  let x = power(x2, (FIELD_P + 3n) / 8n);
  if (mod(x * x) !== x2) x = mod(x * SQRT_MINUS_ONE);
  if (mod(x * x) !== x2) return null;
  if (x === 0n && sign === 1n) return null;
  if ((x & 1n) !== sign) x = mod(-x);
  return [x, y, 1n, mod(x * y)];
}

/** Throws `attestation-key-material` unless `raw` is a canonical prime-order-subgroup Ed25519 public key. */
export function assertSafeEd25519PublicKey(raw: Uint8Array): void {
  const point = raw.length === 32 ? decodeCurvePoint(raw) : null;
  if (!point || isIdentityPoint(point) || !isIdentityPoint(multiplyPoint(point, GROUP_ORDER_L))) fail("attestation-key-material");
}

export async function importAttestationPublicKey(publicKey: string): Promise<CryptoKey> {
  const raw = decodeKey(publicKey, 32, "attestation-key-material");
  assertSafeEd25519PublicKey(raw);
  try { return await crypto.subtle.importKey("raw", toArrayBuffer(raw), { name: "Ed25519" }, false, ["verify"]); } catch { return fail("attestation-key-material"); }
}

/** TEST KEYS ONLY in this slice. Canonical base64url of the exact 48-byte RFC 8410 PKCS#8 DER; imported non-extractable. */
export async function importAttestationTestPrivateKey(privateKey: string): Promise<CryptoKey> {
  const der = decodeKey(privateKey, 48, "attestation-key-material");
  if (!PKCS8_ED25519_PREFIX.every((byte, position) => der[position] === byte)) fail("attestation-key-material");
  try { return await crypto.subtle.importKey("pkcs8", toArrayBuffer(der), { name: "Ed25519" }, false, ["sign"]); } catch { return fail("attestation-key-material"); }
}

/** A canonical, well-formed signature slot (64 zero bytes) used only to probe the strict wire parser before signing. */
const PROBE_SIGNATURE = "A".repeat(86);

/** Fingerprint `SHA-256(raw public key)` must be the statement's writerKeyFingerprint, and the produced signature is
 * verified against that public key before it is returned (so a mismatched private/public pair cannot sign).
 *
 * Order, all synchronous before the first `await`, so nothing caller-owned is read after the snapshot exists:
 *  1. read the statement (and keys) once into a fresh validated canonical tuple; encode it once to `statementText`;
 *  2. strict-parse the exact wire representation `{"statement":statementText,"signature":<probe>}` with the same parser
 *     verifiers use (size, BOM/UTF-8, duplicates, canonical byte equality, validator) - so nothing the wire parser would
 *     reject is ever signed - and take the returned statement from that parse;
 *  3. sign exactly `domain || statementText`, the bytes from step 1.
 * The returned envelope re-encodes to exactly those statement bytes; the signer depends on the parser, never on a verifier.
 * A proxy (or any exotic object) as statement input is accepted only insofar as its single own-data-descriptor snapshot is
 * valid: that snapshot alone is validated, signed and returned; the proxy's [[Get]] results are never consulted. */
export async function signResultAttestation(statement: ResultStatement, keys: { privateKey: string; publicKey: string }): Promise<ResultAttestationEnvelope> {
  const privateKey: unknown = keys.privateKey;
  const publicKey: unknown = keys.publicKey;
  const statementText = canonicalStatementText(statement);
  const snapshot = parseResultAttestationEnvelope(encoder.encode(envelopeText(statementText, PROBE_SIGNATURE))).statement;
  const message = signingBytesFromText(statementText);
  if (typeof privateKey !== "string" || typeof publicKey !== "string") fail("attestation-key-material");
  if (snapshot.writerKeyFingerprint !== await attestationKeyFingerprint(publicKey)) fail("attestation-key-material");
  const signingKey = await importAttestationTestPrivateKey(privateKey);
  const signature = encodeBase64url(new Uint8Array(await crypto.subtle.sign("Ed25519", signingKey, toArrayBuffer(message))));
  const verifyKey = await importAttestationPublicKey(publicKey);
  if (!await crypto.subtle.verify("Ed25519", verifyKey, toArrayBuffer(decodeKey(signature, 64, "attestation-key-material")), toArrayBuffer(message))) {
    fail("attestation-key-material");
  }
  const envelope: ResultAttestationEnvelope = Object.freeze({ statement: snapshot, signature });
  if (envelopeText(statementText, signature) !== new TextDecoder().decode(encodeResultAttestationEnvelope(envelope))) fail("attestation-statement");
  return envelope;
}

/** Signature check only (no trust, expectation or freshness decision). Any failure is `false`. */
export async function verifyAttestationSignature(envelope: ResultAttestationEnvelope, publicKey: string): Promise<boolean> {
  try {
    const read = readEnvelope(envelope);
    const message = signingBytesFromText(canonicalStatementText(read.statement));
    const signature = decodeKey(read.signature, 64, "attestation-envelope");
    const key = await importAttestationPublicKey(publicKey);
    return await crypto.subtle.verify("Ed25519", key, toArrayBuffer(signature), toArrayBuffer(message));
  } catch {
    return false;
  }
}
