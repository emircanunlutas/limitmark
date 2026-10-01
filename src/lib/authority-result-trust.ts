import {
  ATTESTATION_AUTHORITY_IDS,
  ATTESTATION_MAX_FUTURE_SKEW_MS,
  ATTESTATION_POLICY_EPOCH,
  ATTESTATION_TRUST_EPOCH,
  ATTESTATION_VERSION,
  assertAttestationFresh,
  attestationKeyFingerprint,
  importAttestationPublicKey,
  isLowerHex64,
  isSafeTime,
  parseResultAttestationEnvelope,
  parseStrictJsonText,
  snapshotResultStatement,
  verifyAttestationSignature,
  type AttestationEnvironment,
  type ResultStatement,
} from "./authority-result-attestation";

/**
 * Authority result trust manifest (version 1) and verification-key selection. Malformed input invalidates the whole
 * manifest: there is no partial acceptance. A manifest object is usable by `selectAttestationTrustKey` only when it
 * was produced by `parseAuthorityResultTrustManifest`.
 */

export const TRUST_MANIFEST_VERSION = 1 as const;
export const TRUST_MANIFEST_MAX_BYTES = 16_384;
const ENVIRONMENT_ORDER: readonly AttestationEnvironment[] = ["production", "staging"];

export interface AttestationTrustKey {
  readonly keyFingerprint: string;
  /** Canonical unpadded base64url of the raw 32-byte Ed25519 public key. Must be a prime-order-subgroup point: identity,
   * small-order, mixed-order and non-canonical encodings invalidate the whole manifest (`importAttestationPublicKey`). */
  readonly publicKey: string;
  /** `retired` means IMMEDIATELY non-verifiable, regardless of `notAfterMs` (which is then only a record of the end of its
   * life). Only `active` keys are ever selected. */
  readonly status: "active" | "retired";
  readonly notBeforeMs: number;
  /** `null` means no finite end. A retired key always has a finite end. */
  readonly notAfterMs: number | null;
}

export interface AttestationTrustEnvironment {
  readonly environment: AttestationEnvironment;
  readonly authorityId: string;
  readonly policyEpoch: typeof ATTESTATION_POLICY_EPOCH;
  /** Identifies the signer-selection / current rollout key only (the key a signer should use now). Verification does NOT
   * require a statement to be signed by it: any ACTIVE key in this environment's list that is valid at the statement's
   * `observedAtMs` and the local clock, and that the statement names in `writerKeyFingerprint`, verifies. */
  readonly currentKeyFingerprint: string;
  readonly keys: readonly AttestationTrustKey[];
}

export interface AuthorityResultTrustManifest {
  readonly manifestVersion: typeof TRUST_MANIFEST_VERSION;
  readonly attestationVersion: typeof ATTESTATION_VERSION;
  readonly trustEpoch: typeof ATTESTATION_TRUST_EPOCH;
  readonly environments: readonly [AttestationTrustEnvironment, AttestationTrustEnvironment];
}

const parsedManifests = new WeakSet<object>();
const bad = (): never => { throw new Error("attestation-manifest"); };

function exactRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return bad();
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== fields.length || !fields.every((field) => Object.hasOwn(record, field) && record[field] !== undefined)) return bad();
  return record;
}

async function parseKeyEntry(value: unknown): Promise<AttestationTrustKey> {
  const entry = exactRecord(value, ["keyFingerprint", "publicKey", "status", "notBeforeMs", "notAfterMs"]);
  if (!isLowerHex64(entry.keyFingerprint) || typeof entry.publicKey !== "string" || (entry.status !== "active" && entry.status !== "retired") ||
      !isSafeTime(entry.notBeforeMs) || (entry.notAfterMs !== null && !isSafeTime(entry.notAfterMs))) return bad();
  if (entry.notAfterMs !== null && entry.notAfterMs <= entry.notBeforeMs) bad();
  if (entry.status === "retired" && entry.notAfterMs === null) bad();
  let fingerprint: string;
  try {
    await importAttestationPublicKey(entry.publicKey);
    fingerprint = await attestationKeyFingerprint(entry.publicKey);
  } catch { return bad(); }
  if (fingerprint !== entry.keyFingerprint) bad();
  return Object.freeze({ keyFingerprint: entry.keyFingerprint, publicKey: entry.publicKey, status: entry.status, notBeforeMs: entry.notBeforeMs, notAfterMs: entry.notAfterMs });
}

async function parseEnvironment(value: unknown, environment: AttestationEnvironment): Promise<AttestationTrustEnvironment> {
  const section = exactRecord(value, ["environment", "authorityId", "policyEpoch", "currentKeyFingerprint", "keys"]);
  if (section.environment !== environment || section.authorityId !== ATTESTATION_AUTHORITY_IDS[environment] ||
      section.policyEpoch !== ATTESTATION_POLICY_EPOCH || !isLowerHex64(section.currentKeyFingerprint) ||
      !Array.isArray(section.keys) || section.keys.length < 1 || section.keys.length > 3) return bad();
  const keys: AttestationTrustKey[] = [];
  for (const entry of section.keys as unknown[]) keys.push(await parseKeyEntry(entry));
  const current = keys.find((key) => key.keyFingerprint === section.currentKeyFingerprint);
  if (!current || current.status !== "active") bad();
  return Object.freeze({ environment, authorityId: ATTESTATION_AUTHORITY_IDS[environment], policyEpoch: ATTESTATION_POLICY_EPOCH,
    currentKeyFingerprint: section.currentKeyFingerprint, keys: Object.freeze(keys) });
}

export async function parseAuthorityResultTrustManifest(source: string | Uint8Array): Promise<AuthorityResultTrustManifest> {
  let text: string;
  try {
    if (typeof source === "string") text = source;
    else {
      if (source.length === 0 || source.length > TRUST_MANIFEST_MAX_BYTES) return bad();
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(source);
    }
  } catch { return bad(); }
  // Size is measured in UTF-8 bytes (a string source must not be allowed more bytes than a byte source).
  if (text.length === 0 || new TextEncoder().encode(text).length > TRUST_MANIFEST_MAX_BYTES || text.charCodeAt(0) === 0xfeff) bad();
  let value: unknown;
  try { value = parseStrictJsonText(text, "attestation-manifest"); } catch { return bad(); }
  const top = exactRecord(value, ["manifestVersion", "attestationVersion", "trustEpoch", "environments"]);
  if (top.manifestVersion !== TRUST_MANIFEST_VERSION || top.attestationVersion !== ATTESTATION_VERSION ||
      top.trustEpoch !== ATTESTATION_TRUST_EPOCH || !Array.isArray(top.environments) || top.environments.length !== ENVIRONMENT_ORDER.length) return bad();
  const environments = await Promise.all(ENVIRONMENT_ORDER.map((environment, index) => parseEnvironment((top.environments as unknown[])[index], environment)));
  const all = environments.flatMap((section) => section.keys);
  if (new Set(all.map((key) => key.keyFingerprint)).size !== all.length || new Set(all.map((key) => key.publicKey)).size !== all.length) bad();
  const manifest: AuthorityResultTrustManifest = Object.freeze({
    manifestVersion: TRUST_MANIFEST_VERSION, attestationVersion: ATTESTATION_VERSION, trustEpoch: ATTESTATION_TRUST_EPOCH,
    environments: Object.freeze([environments[0], environments[1]]) as unknown as AuthorityResultTrustManifest["environments"] });
  parsedManifests.add(manifest);
  return manifest;
}

/**
 * Returns the manifest key allowed to have signed `statement` at local time `nowMs`, or throws. The key must be listed in
 * the statement's own environment section (so a key from the other environment is unknown), be active, and be valid at
 * both the statement's `observedAtMs` and the local clock; the statement must also be fresh.
 */
export function selectAttestationTrustKey(manifest: AuthorityResultTrustManifest, statement: ResultStatement, nowMs: number): AttestationTrustKey {
  if (typeof manifest !== "object" || manifest === null || !parsedManifests.has(manifest)) throw new Error("attestation-manifest");
  // Decide on a validated module-owned copy, never on repeated reads of a caller-owned object.
  statement = snapshotResultStatement(statement);
  if (!isSafeTime(nowMs)) throw new Error("attestation-key");
  const section = manifest.environments.find((candidate) => candidate.environment === statement.environment);
  if (!section || section.authorityId !== statement.authorityId || section.policyEpoch !== statement.policyEpoch ||
      manifest.trustEpoch !== statement.trustEpoch) throw new Error("attestation-key");
  const key = section.keys.find((candidate) => candidate.keyFingerprint === statement.writerKeyFingerprint);
  if (!key || key.status !== "active" || key.notBeforeMs > statement.observedAtMs ||
      (key.notAfterMs !== null && statement.observedAtMs >= key.notAfterMs) ||
      nowMs < key.notBeforeMs - ATTESTATION_MAX_FUTURE_SKEW_MS || (key.notAfterMs !== null && nowMs >= key.notAfterMs)) throw new Error("attestation-key");
  assertAttestationFresh(statement.observedAtMs, nowMs);
  return key;
}

/** Caller-known facts. These are never derived from the untrusted envelope. */
export type ResultAttestationExpectations =
  | { readonly kind: "lifecycle"; readonly environment: AttestationEnvironment; readonly authorityId: string; readonly policyEpoch: string; readonly digest: string }
  | { readonly kind: "reconciliation"; readonly environment: AttestationEnvironment; readonly authorityId: string; readonly policyEpoch: string; readonly digest: string; readonly nonce: string };

const LIFECYCLE_EXPECTATION_FIELDS = ["kind", "environment", "authorityId", "policyEpoch", "digest"] as const;
const RECONCILIATION_EXPECTATION_FIELDS = [...LIFECYCLE_EXPECTATION_FIELDS, "nonce"] as const;

/**
 * Reads caller expectations exactly once and returns a validated, frozen, module-owned copy. All own property descriptors
 * are taken in a single `Object.getOwnPropertyDescriptors` pass; nothing is read through [[Get]] or the prototype chain.
 * Requires a plain object whose own keys are exactly the kind's fields (no symbols, no extras), each an enumerable data
 * property holding a string: accessors are rejected, never invoked. The caller object is never read again.
 */
function snapshotExpectations(value: unknown): ResultAttestationExpectations {
  let descriptors: Record<string | symbol, PropertyDescriptor>;
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error();
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new Error();
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch { throw new Error("attestation-expectation"); }
  const data = (field: string): string => {
    const descriptor = Object.hasOwn(descriptors, field) ? descriptors[field] : undefined;
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true || typeof descriptor.value !== "string") throw new Error("attestation-expectation");
    return descriptor.value;
  };
  const kind = data("kind");
  const fields: readonly string[] = kind === "lifecycle" ? LIFECYCLE_EXPECTATION_FIELDS : kind === "reconciliation" ? RECONCILIATION_EXPECTATION_FIELDS : [];
  const keys = Reflect.ownKeys(descriptors);
  if (fields.length === 0 || keys.length !== fields.length || !keys.every((key) => typeof key === "string" && fields.includes(key))) throw new Error("attestation-expectation");
  const environment = data("environment");
  const authorityId = data("authorityId");
  const policyEpoch = data("policyEpoch");
  const digest = data("digest");
  if ((environment !== "production" && environment !== "staging") || authorityId !== ATTESTATION_AUTHORITY_IDS[environment] ||
      policyEpoch !== ATTESTATION_POLICY_EPOCH || !isLowerHex64(digest)) throw new Error("attestation-expectation");
  if (kind === "lifecycle") return Object.freeze({ kind, environment, authorityId, policyEpoch, digest });
  const nonce = data("nonce");
  if (!/^[a-f0-9]{32}$/u.test(nonce)) throw new Error("attestation-expectation");
  return Object.freeze({ kind: "reconciliation", environment, authorityId, policyEpoch, digest, nonce });
}

// ---------------------------------------------------------------------------------------------------------------------
// R06 verification result: an opaque, branded, registry-backed type
// ---------------------------------------------------------------------------------------------------------------------
const verifiedRegistry = new WeakSet<object>();

/**
 * What the later Production integration must compose, stated here so it cannot be forgotten. Production POSITIVE
 * acceptance of a lifecycle result requires ALL of:
 *  1. a `VerifiedAuthorityStatement` (this module: R06 signature, trust key, freshness, caller expectations);
 *  2. an authenticated R07 command-derived expectation (the signed operator command and operator key, never the envelope);
 *  3. field-by-field equality between that command-derived receipt and the verified statement's receipt.
 * This module implements only (1) and duplicates none of (2)/(3).
 */
export const PRODUCTION_POSITIVE_ACCEPTANCE_REQUIRES = Object.freeze([
  "verified-r06-authority-statement",
  "authenticated-r07-command-derived-expectation",
  "field-by-field-command-receipt-equality",
] as const);

/**
 * The only output of successful R06 verification. It proves the authority-writer key signed exactly this statement, that the
 * statement matched the caller-supplied expectations, and that it was fresh under a trusted key. It is NOT Production
 * positive acceptance: nothing here ties the statement's receipt to an operator command.
 *
 * Provenance is RUNTIME, and consumers MUST call `isVerifiedAuthorityStatement` before treating any value as verified. Every
 * instance is registered in a module-private WeakSet; a copy (spread, `structuredClone`, `Object.assign`, JSON round trip)
 * or a hand-built object is never registered. The type is nominal through an ES-private brand, which object spread does not
 * copy, so a spread copy or a structurally identical literal does not even typecheck as this type; that is a convenience,
 * not the security boundary (a cast still compiles, and the registry still rejects it). The instance, its statement and
 * its expectations are deeply frozen.
 */
class VerifiedAuthorityStatementRecord {
  readonly #brand = true;
  readonly layer = "R06-authority-signature" as const;
  readonly acceptance = "NOT-PRODUCTION-POSITIVE-ACCEPTANCE" as const;
  constructor(
    readonly statement: ResultStatement,
    readonly signingKeyFingerprint: string,
    /** The verifier caller's supplied local verification time (`nowMs`), NOT an authority-authenticated timestamp. */
    readonly verifiedAtMs: number,
    /** The frozen snapshot of the caller's expectations taken at verification entry: exactly what was compared. */
    readonly expectations: ResultAttestationExpectations,
  ) {
    Object.freeze(this);
  }
  static isBranded(value: object): boolean { return #brand in value; }
}
export type VerifiedAuthorityStatement = VerifiedAuthorityStatementRecord;

/** Runtime proof that `value` was produced by `verifyAuthoritySignedStatement`. The ONLY way to establish verification. */
export function isVerifiedAuthorityStatement(value: unknown): value is VerifiedAuthorityStatement {
  return typeof value === "object" && value !== null && verifiedRegistry.has(value) && VerifiedAuthorityStatementRecord.isBranded(value);
}

/**
 * R06 verification ONLY: strict parse, caller expectations, trust-key selection (incl. freshness), then the Ed25519
 * signature. Returns the branded verified statement; throws on any failure. A legacy unsigned result object is not an
 * envelope and fails parsing. The result is not Production positive acceptance; see PRODUCTION_POSITIVE_ACCEPTANCE_REQUIRES.
 */
export async function verifyAuthoritySignedStatement(bytes: Uint8Array, expectations: ResultAttestationExpectations,
  manifest: AuthorityResultTrustManifest, nowMs: number): Promise<VerifiedAuthorityStatement> {
  // The single read of the caller's expectations. Comparison and the returned result use only this frozen snapshot.
  const expected = snapshotExpectations(expectations);
  const envelope = parseResultAttestationEnvelope(bytes);
  const { statement } = envelope;
  if (statement.kind !== expected.kind || statement.environment !== expected.environment ||
      statement.authorityId !== expected.authorityId || statement.policyEpoch !== expected.policyEpoch ||
      statement.digest !== expected.digest ||
      (statement.kind === "reconciliation" && expected.kind === "reconciliation" && statement.nonce !== expected.nonce)) {
    throw new Error("attestation-expectation");
  }
  const key = selectAttestationTrustKey(manifest, statement, nowMs);
  if (!await verifyAttestationSignature(envelope, key.publicKey)) throw new Error("attestation-signature");
  const verified = new VerifiedAuthorityStatementRecord(statement, key.keyFingerprint, nowMs, expected);
  verifiedRegistry.add(verified);
  return verified;
}
