import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";
import {
  ATTESTATION_AUTHORITY_IDS,
  ATTESTATION_MAX_AGE_MS,
  ATTESTATION_MAX_APPLIED_ACTIVATION_SKEW_MS,
  ATTESTATION_MAX_ENVELOPE_BYTES,
  ATTESTATION_MAX_FUTURE_SKEW_MS,
  ATTESTATION_POLICY_EPOCH,
  ATTESTATION_SIGNING_DOMAIN,
  ATTESTATION_TRUST_EPOCH,
  ATTESTATION_VERSION,
  LIFECYCLE_STATEMENT_FIELDS,
  RECEIPT_FIELDS,
  RECONCILIATION_STATEMENT_FIELDS,
  RELEASE_ROW_FIELDS,
  assertSafeEd25519PublicKey,
  attestationKeyFingerprint,
  attestationReceiptFromLifecycleReceipt,
  attestationReleaseRowFromAuthority,
  attestationSigningBytes,
  canonicalStatementBytes,
  encodeResultAttestationEnvelope,
  importAttestationPublicKey,
  importAttestationTestPrivateKey,
  makeLifecycleStatement,
  makeReconciliationStatement,
  parseResultAttestationEnvelope,
  parseResultStatementTuple,
  resultStatementTuple,
  signResultAttestation,
  snapshotResultStatement,
  verifyAttestationSignature,
  type LifecycleStatementInput,
  type ReconciliationStatementInput,
  type ResultStatement,
} from "../src/lib/authority-result-attestation";
import {
  PRODUCTION_POSITIVE_ACCEPTANCE_REQUIRES,
  isVerifiedAuthorityStatement,
  parseAuthorityResultTrustManifest,
  selectAttestationTrustKey,
  verifyAuthoritySignedStatement,
  type AuthorityResultTrustManifest,
  type ResultAttestationExpectations,
  type VerifiedAuthorityStatement,
} from "../src/lib/authority-result-trust";
import { encodeBase64url, toArrayBuffer } from "../src/lib/ingress-protocol";
import {
  ADMISSION_AUTHORITY_ID,
  ADMISSION_POLICY_EPOCH,
  STAGING_ADMISSION_AUTHORITY_ID,
  type LifecycleReceipt,
} from "../workers/admission-service/authority";

// ---------------------------------------------------------------------------------------------------------------------
// Frozen contract, restated independently of the implementation.
// ---------------------------------------------------------------------------------------------------------------------
const LIFECYCLE_ORDER = ["version", "trustEpoch", "environment", "authorityId", "policyEpoch", "kind", "digest", "outcome", "receipt", "observedAtMs", "writerKeyFingerprint"];
const RECONCILIATION_ORDER = ["version", "trustEpoch", "environment", "authorityId", "policyEpoch", "kind", "digest", "nonce", "initialized", "coverage", "status",
  "receipt", "releases", "observedAtMs", "writerKeyFingerprint"];
const RECEIPT_ORDER = ["digest", "version", "operation", "environment", "authorityId", "policyEpoch", "operatorKeyFingerprint", "sequence", "appliedMs",
  "currentReleaseId", "nextReleaseId", "nextKeyId", "activatesMs", "retiresMs"];
const ROW_ORDER = ["releaseId", "keyId", "activatedMs", "retiredMs"];
const DOMAIN = "limitmark:authority-result-attestation:ed25519:v2\0";
const PKCS8_PREFIX = "302e020100300506032b657004220420";
// RFC 8032 section 7.1 test vectors. TEST KEY — NEVER PROVISION. The third key exists only to exercise multi-key manifests.
const RFC = {
  production: { seedHex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", publicHex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" },
  staging: { seedHex: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", publicHex: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c" },
  third: { seedHex: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", publicHex: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025" },
  fourth: { seedHex: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42", publicHex: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf" },
} as const;
// Reviewed and frozen. A fixture edit must be an intentional, reviewed change to these pins.
const GOLDEN_SHA256 = "2608a25a33945088310ed959861e610bacde68beec58e676512465fddbb64a40";
const MANIFEST_FIXTURE_SHA256 = "465e888e39617752da240eee09a78bbe99d948691bd1be7e8f0b851942750e14";

type Role = "production" | "staging";
interface GoldenKey { warning: string; source: string; seedHex: string; privateKeyPkcs8: string; publicKeyHex: string; publicKey: string; fingerprint: string }
interface GoldenVector {
  name: string; keyRole: Role; kind: "lifecycle" | "reconciliation"; input: Record<string, unknown>; expectations: ResultAttestationExpectations;
  verifyAtMs: number; tuple: unknown[]; tupleJson: string; signingBytesHex: string; signingBytesSha256: string; signature: string; envelope: string;
}
interface Golden {
  fixtureVersion: number; protocol: string; attestationVersion: number; trustEpoch: number; warning: string; signingDomain: { hex: string };
  baseTimeMs: number; keys: Record<Role, GoldenKey>; vectors: GoldenVector[];
}
interface KeyJson { keyFingerprint: unknown; publicKey: unknown; status: unknown; notBeforeMs: unknown; notAfterMs: unknown; [extra: string]: unknown }
interface EnvJson { environment: unknown; authorityId: unknown; policyEpoch: unknown; currentKeyFingerprint: unknown; keys: KeyJson[]; [extra: string]: unknown }
interface ManifestJson { manifestVersion: unknown; attestationVersion: unknown; trustEpoch: unknown; environments: EnvJson[]; [extra: string]: unknown }

const enc = new TextEncoder();
const sha256Hex = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const fromHex = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));
const flipHex = (value: string) => (value[0] === "a" ? "b" : "a") + value.slice(1);
const concat = (...parts: Uint8Array[]) => { const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0)); let at = 0; for (const part of parts) { out.set(part, at); at += part.length; } return out; };
const privateKeyText = (seedHex: string) => encodeBase64url(fromHex(PKCS8_PREFIX + seedHex));
const publicKeyText = (publicHex: string) => encodeBase64url(fromHex(publicHex));

let loaded: Promise<{ golden: Golden; goldenBytes: Uint8Array; manifestText: string; manifestBytes: Uint8Array; manifest: AuthorityResultTrustManifest }> | undefined;
function load() {
  loaded ??= (async () => {
    const goldenBytes = new Uint8Array(await readFile(new URL("./fixtures/authority-result-attestation-v2.golden.json", import.meta.url)));
    const manifestBytes = new Uint8Array(await readFile(new URL("./fixtures/authority-result-trust-v1.test.json", import.meta.url)));
    const manifestText = new TextDecoder().decode(manifestBytes);
    return { golden: JSON.parse(new TextDecoder().decode(goldenBytes)) as Golden, goldenBytes, manifestText, manifestBytes,
      manifest: await parseAuthorityResultTrustManifest(manifestText) };
  })();
  return loaded;
}

const privateCache = new Map<string, CryptoKey>();
/** Signs with raw WebCrypto, deliberately NOT through the module under test. */
async function rawSign(privateKey: string, message: Uint8Array): Promise<string> {
  let key = privateCache.get(privateKey);
  if (!key) {
    key = await crypto.subtle.importKey("pkcs8", toArrayBuffer(Buffer.from(privateKey, "base64url")), { name: "Ed25519" }, false, ["sign"]);
    privateCache.set(privateKey, key);
  }
  return encodeBase64url(new Uint8Array(await crypto.subtle.sign("Ed25519", key, toArrayBuffer(message))));
}
const tupleMessage = (tuple: unknown, domain = DOMAIN) => concat(enc.encode(domain), enc.encode(JSON.stringify(tuple)));
const envelopeBytes = (tuple: unknown, signature: string) => enc.encode(JSON.stringify({ statement: tuple, signature }));
async function resigned(golden: Golden, role: Role, tuple: unknown, domain = DOMAIN): Promise<Uint8Array> {
  return envelopeBytes(tuple, await rawSign(golden.keys[role].privateKeyPkcs8, tupleMessage(tuple, domain)));
}

/** Runs `run`, requires rejection, and requires a protocol error code (never a leaked TypeError/SyntaxError). */
async function mustReject(label: string, run: () => Promise<unknown>, message?: string): Promise<void> {
  let failure: unknown;
  let accepted = false;
  try { await run(); accepted = true; } catch (error) { failure = error; }
  assert.equal(accepted, false, `ACCEPTED (must fail closed): ${label}`);
  assert.ok(failure instanceof Error && /^attestation-[a-z-]+$/u.test(failure.message), `${label}: unexpected failure ${String(failure)}`);
  if (message !== undefined) assert.equal((failure as Error).message, message, label);
}
const verifyVector = (manifest: AuthorityResultTrustManifest, v: GoldenVector, bytes: Uint8Array, options: { nowMs?: number; expectations?: ResultAttestationExpectations } = {}) =>
  verifyAuthoritySignedStatement(bytes, options.expectations ?? v.expectations, manifest, options.nowMs ?? v.verifyAtMs);
const statementOf = (v: GoldenVector): ResultStatement =>
  v.kind === "lifecycle" ? makeLifecycleStatement(v.input as unknown as LifecycleStatementInput) : makeReconciliationStatement(v.input as unknown as ReconciliationStatementInput);
const clone = <T>(value: T): T => structuredClone(value);

// ---------------------------------------------------------------------------------------------------------------------
test("protocol constants and field orders match the frozen contract", () => {
  assert.equal(ATTESTATION_VERSION, 2);
  assert.equal(ATTESTATION_TRUST_EPOCH, 1);
  assert.equal(ATTESTATION_POLICY_EPOCH, "phase5c-i1-epoch-1");
  assert.equal(ATTESTATION_MAX_AGE_MS, 300_000);
  assert.equal(ATTESTATION_MAX_FUTURE_SKEW_MS, 60_000);
  assert.equal(ATTESTATION_MAX_ENVELOPE_BYTES, 8_192);
  assert.equal(ATTESTATION_SIGNING_DOMAIN, DOMAIN);
  const domainBytes = enc.encode(ATTESTATION_SIGNING_DOMAIN);
  assert.equal(domainBytes.length, 50);
  assert.equal(domainBytes[49], 0);
  assert.equal(Buffer.from(domainBytes.subarray(0, 49)).toString("utf8"), "limitmark:authority-result-attestation:ed25519:v2");
  assert.deepEqual([...LIFECYCLE_STATEMENT_FIELDS], LIFECYCLE_ORDER);
  assert.deepEqual([...RECONCILIATION_STATEMENT_FIELDS], RECONCILIATION_ORDER);
  assert.deepEqual([...RECEIPT_FIELDS], RECEIPT_ORDER);
  assert.deepEqual([...RELEASE_ROW_FIELDS], ROW_ORDER);
  for (const order of [LIFECYCLE_ORDER, RECONCILIATION_ORDER, RECEIPT_ORDER, ROW_ORDER]) assert.equal(new Set(order).size, order.length);
  assert.deepEqual([LIFECYCLE_ORDER.length, RECONCILIATION_ORDER.length, RECEIPT_ORDER.length, ROW_ORDER.length], [11, 15, 14, 4]);
  // Environment/authority identity is pinned to the authority module, not re-invented here.
  assert.equal(ATTESTATION_AUTHORITY_IDS.production, ADMISSION_AUTHORITY_ID);
  assert.equal(ATTESTATION_AUTHORITY_IDS.staging, STAGING_ADMISSION_AUTHORITY_ID);
  assert.equal(ATTESTATION_POLICY_EPOCH, ADMISSION_POLICY_EPOCH);
});

test("golden fixtures are frozen, test-only, and never rewritten by tests", async () => {
  const { golden, goldenBytes, manifestBytes } = await load();
  assert.equal(sha256Hex(goldenBytes), GOLDEN_SHA256);
  assert.equal(sha256Hex(manifestBytes), MANIFEST_FIXTURE_SHA256);
  assert.match(golden.warning, /^TEST KEY — NEVER PROVISION/u);
  assert.equal(golden.signingDomain.hex, Buffer.from(DOMAIN, "utf8").toString("hex"));
  assert.deepEqual(Object.keys(golden.keys).sort(), ["production", "staging"]);
  for (const role of ["production", "staging"] as const) {
    const key = golden.keys[role];
    assert.equal(key.warning, "TEST KEY — NEVER PROVISION");
    assert.equal(key.seedHex, RFC[role].seedHex);
    assert.equal(key.publicKeyHex, RFC[role].publicHex);
    assert.equal(key.privateKeyPkcs8, privateKeyText(RFC[role].seedHex));
    assert.equal(key.publicKey, publicKeyText(RFC[role].publicHex));
    assert.equal(key.fingerprint, sha256Hex(fromHex(RFC[role].publicHex)));
    assert.equal(key.fingerprint, await attestationKeyFingerprint(key.publicKey));
  }
  assert.notEqual(golden.keys.production.publicKey, golden.keys.staging.publicKey);
});

test("golden inventory covers every required vector", async () => {
  const { golden } = await load();
  assert.deepEqual(golden.vectors.map((v) => v.name), [
    "production-lifecycle-initialize", "production-lifecycle-rotate", "staging-lifecycle-initialize", "production-reconciliation-exact-receipt",
    "production-reconciliation-initialized-not-found", "production-reconciliation-uninitialized-not-found", "staging-reconciliation-history-incomplete",
    "staging-reconciliation-exact-receipt-one-row", "production-reconciliation-two-rows-tie-order"]);
  const statements = golden.vectors.map((v) => v.tuple);
  assert.deepEqual(statements.map((tuple) => tuple.length), [11, 11, 11, 15, 15, 15, 15, 15, 15]);
  assert.deepEqual(golden.vectors.map((v) => v.keyRole), ["production", "production", "staging", "production", "production", "production", "staging", "staging", "production"]);
  const receipt = (v: GoldenVector) => v.tuple[v.kind === "lifecycle" ? 8 : 11] as unknown[] | null;
  assert.equal(receipt(golden.vectors[0])![2], "initialize");
  assert.equal(receipt(golden.vectors[1])![2], "rotate-release");
  assert.equal(receipt(golden.vectors[2])![2], "initialize");
  const recon = (v: GoldenVector) => v.tuple.slice(8, 13) as [boolean, string, string, unknown[] | null, unknown[][]];
  assert.deepEqual(recon(golden.vectors[3]).slice(0, 3), [true, "COMPLETE", "EXACT_RECEIPT"]);
  assert.equal(recon(golden.vectors[3])[4].length, 2);
  assert.deepEqual([...recon(golden.vectors[4]).slice(0, 4), recon(golden.vectors[4])[4].length], [true, "COMPLETE", "NOT_FOUND", null, 1]);
  assert.deepEqual([...recon(golden.vectors[5]).slice(0, 4), recon(golden.vectors[5])[4].length], [false, "COMPLETE", "NOT_FOUND", null, 0]);
  assert.deepEqual([...recon(golden.vectors[6]).slice(0, 4), recon(golden.vectors[6])[4].length], [true, "INCOMPLETE", "HISTORY_INCOMPLETE", null, 1]);
  assert.equal(recon(golden.vectors[7])[4].length, 1);
  const tie = recon(golden.vectors[8])[4];
  assert.equal(tie.length, 2);
  assert.equal(tie[0][2], tie[1][2]);
  assert.deepEqual([tie[0][0], tie[1][0]], ["release-a", "release-b"]);
  // The tie vector's INPUT is deliberately reversed; the constructor must emit canonical order.
  assert.deepEqual((golden.vectors[8].input.releases as { releaseId: string }[]).map((row) => row.releaseId), ["release-b", "release-a"]);
});

test("every golden vector reproduces independently and verifies", async () => {
  const { golden, manifest } = await load();
  for (const v of golden.vectors) {
    const key = golden.keys[v.keyRole];
    const statement = statementOf(v);
    // statement tuple, exact JSON tuple
    assert.deepEqual(resultStatementTuple(statement), v.tuple, v.name);
    assert.equal(v.tupleJson, JSON.stringify(v.tuple), v.name);
    assert.equal(new TextDecoder().decode(canonicalStatementBytes(statement)), v.tupleJson, v.name);
    // complete domain-prefixed signing bytes, reproduced with nothing from the module
    const independent = concat(Buffer.from(DOMAIN, "utf8"), Buffer.from(v.tupleJson, "utf8"));
    assert.equal(Buffer.from(independent).toString("hex"), v.signingBytesHex, v.name);
    assert.equal(Buffer.from(attestationSigningBytes(statement)).toString("hex"), v.signingBytesHex, v.name);
    assert.equal(sha256Hex(independent), v.signingBytesSha256, v.name);
    // raw public key, fingerprint, writer fingerprint inside the statement
    assert.equal(statement.writerKeyFingerprint, key.fingerprint, v.name);
    assert.equal(sha256Hex(fromHex(key.publicKeyHex)), key.fingerprint, v.name);
    // signature: Ed25519 is deterministic, so signing again reproduces it; raw WebCrypto verifies it too
    assert.equal(await rawSign(key.privateKeyPkcs8, independent), v.signature, v.name);
    const envelope = await signResultAttestation(statement, { privateKey: key.privateKeyPkcs8, publicKey: key.publicKey });
    assert.equal(envelope.signature, v.signature, v.name);
    const rawPublic = await crypto.subtle.importKey("raw", toArrayBuffer(fromHex(key.publicKeyHex)), { name: "Ed25519" }, false, ["verify"]);
    assert.equal(await crypto.subtle.verify("Ed25519", rawPublic, toArrayBuffer(Buffer.from(v.signature, "base64url")), toArrayBuffer(independent)), true, v.name);
    // canonical envelope
    assert.equal(new TextDecoder().decode(encodeResultAttestationEnvelope(envelope)), v.envelope, v.name);
    assert.deepEqual(parseResultAttestationEnvelope(enc.encode(v.envelope)).statement, statement, v.name);
    const verified = await verifyVector(manifest, v, enc.encode(v.envelope));
    assert.equal(isVerifiedAuthorityStatement(verified), true, v.name);
    assert.deepEqual(resultStatementTuple(verified.statement), v.tuple, v.name);
    // and no other vector's expectations accept this envelope
    for (const other of golden.vectors) {
      if (other !== v) await mustReject(`${v.name} under ${other.name} expectations`, () => verifyVector(manifest, v, enc.encode(v.envelope), { expectations: other.expectations }));
    }
  }
});

test("constructors canonicalise release order and the validator requires it", async () => {
  const { golden } = await load();
  const tie = golden.vectors[8];
  const statement = statementOf(tie) as Extract<ResultStatement, { kind: "reconciliation" }>;
  assert.deepEqual(statement.releases.map((row) => row.releaseId), ["release-a", "release-b"]);
  const unsorted = clone(tie.tuple);
  (unsorted[12] as unknown[]).reverse();
  await mustReject("unsorted rows signed validly", async () => parseResultAttestationEnvelope(await resigned(golden, "production", unsorted)));
  // activatedMs dominates releaseId; on an activatedMs tie releaseId decides by code-unit order (uppercase before lowercase).
  // keyId is the final tie-break but is unreachable for valid snapshots because release ids are unique.
  const base = clone(tie.input) as unknown as ReconciliationStatementInput;
  const order = (releases: { releaseId: string; keyId: string; activatedMs: number; retiredMs: number | null }[]) =>
    (makeReconciliationStatement({ ...base, releases }) as Extract<ResultStatement, { kind: "reconciliation" }>).releases.map((row) => row.releaseId);
  assert.deepEqual(order([{ releaseId: "a", keyId: "k2", activatedMs: 2_000, retiredMs: null }, { releaseId: "z", keyId: "k1", activatedMs: 1_000, retiredMs: 9_000 }]), ["z", "a"]);
  assert.deepEqual(order([{ releaseId: "z", keyId: "k1", activatedMs: 1_000, retiredMs: 9_000 }, { releaseId: "a", keyId: "k2", activatedMs: 2_000, retiredMs: null }]), ["z", "a"]);
  assert.deepEqual(order([{ releaseId: "b", keyId: "k1", activatedMs: 1_000, retiredMs: 9_000 }, { releaseId: "B", keyId: "k2", activatedMs: 1_000, retiredMs: null }]), ["B", "b"]);
  assert.deepEqual(order([{ releaseId: "B", keyId: "k2", activatedMs: 1_000, retiredMs: null }, { releaseId: "b", keyId: "k1", activatedMs: 1_000, retiredMs: 9_000 }]), ["B", "b"]);
  assert.deepEqual(order([{ releaseId: "r10", keyId: "k2", activatedMs: 5, retiredMs: null }, { releaseId: "r2", keyId: "k1", activatedMs: 5, retiredMs: 9 }]), ["r10", "r2"]);
});

test("statement domains: supported authority states only, strict receipt and row domains", async () => {
  const { golden } = await load();
  const recon = golden.vectors[3].input as unknown as ReconciliationStatementInput;
  const notFound = golden.vectors[4].input as unknown as ReconciliationStatementInput;
  const uninitialized = golden.vectors[5].input as unknown as ReconciliationStatementInput;
  const incomplete = golden.vectors[6].input as unknown as ReconciliationStatementInput;
  const lifecycle = golden.vectors[1].input as unknown as LifecycleStatementInput;
  const initLifecycle = golden.vectors[0].input as unknown as LifecycleStatementInput;
  const reject = (label: string, run: () => unknown) => assert.throws(run, /^Error: attestation-/u, label);
  const rec = (overrides: Record<string, unknown>, base = notFound) => () => makeReconciliationStatement({ ...base, ...overrides } as ReconciliationStatementInput);
  const life = (overrides: Record<string, unknown>, base = lifecycle) => () => makeLifecycleStatement({ ...base, ...overrides } as LifecycleStatementInput);
  const receiptOf = (overrides: Record<string, unknown>, base = lifecycle.receipt) => ({ ...base, ...overrides });
  const rowsOf = notFound.releases;
  // the four supported states
  for (const input of [recon, notFound, uninitialized, incomplete]) makeReconciliationStatement(input);
  // unsupported combinations, including UNAVAILABLE which has no signed variant
  reject("uninitialized EXACT_RECEIPT", rec({ initialized: false, status: "EXACT_RECEIPT", receipt: recon.receipt, releases: [] }));
  reject("uninitialized with rows", rec({ initialized: false }));
  reject("uninitialized INCOMPLETE", rec({ coverage: "INCOMPLETE", status: "HISTORY_INCOMPLETE", initialized: false, releases: [] }, uninitialized));
  reject("initialized with zero rows", rec({ releases: [] }));
  reject("initialized with three rows", rec({ releases: [...rowsOf, { releaseId: "r2", keyId: "k2", activatedMs: 9, retiredMs: 10 }, { releaseId: "r3", keyId: "k3", activatedMs: 9, retiredMs: 10 }] }));
  reject("EXACT_RECEIPT without receipt", rec({ receipt: null }, recon));
  reject("NOT_FOUND with receipt", rec({ receipt: recon.receipt }));
  reject("HISTORY_INCOMPLETE with receipt", rec({ receipt: recon.receipt }, incomplete));
  reject("INCOMPLETE NOT_FOUND", rec({ coverage: "INCOMPLETE" }));
  reject("COMPLETE HISTORY_INCOMPLETE", rec({ status: "HISTORY_INCOMPLETE" }));
  reject("INCOMPLETE EXACT_RECEIPT", rec({ coverage: "INCOMPLETE" }, recon));
  reject("UNAVAILABLE", rec({ status: "UNAVAILABLE", coverage: "INCOMPLETE" }));
  reject("UNAVAILABLE coverage", rec({ coverage: "UNAVAILABLE" }));
  // release row domains and source-proven snapshot invariants
  const row = (overrides: Record<string, unknown>) => ({ ...rowsOf[0], ...overrides });
  reject("row extra field", rec({ releases: [{ ...rowsOf[0], extra: 1 }] }));
  reject("row missing field", rec({ releases: [{ releaseId: "r", keyId: "k", activatedMs: 1 }] }));
  reject("row bad release id", rec({ releases: [row({ releaseId: "bad id" })] }));
  reject("row long release id", rec({ releases: [row({ releaseId: "r".repeat(129) })] }));
  reject("row bad key id", rec({ releases: [row({ keyId: "bad.key" })] }));
  reject("row long key id", rec({ releases: [row({ keyId: "k".repeat(65) })] }));
  reject("row negative time", rec({ releases: [row({ activatedMs: -1 })] }));
  reject("row negative zero", rec({ releases: [row({ activatedMs: -0 })] }));
  reject("row fractional", rec({ releases: [row({ activatedMs: 1.5 })] }));
  reject("row unsafe", rec({ releases: [row({ activatedMs: Number.MAX_SAFE_INTEGER + 1 })] }));
  reject("single retired row", rec({ releases: [row({ retiredMs: rowsOf[0].activatedMs + 1 })] }));
  reject("two unretired rows", rec({ releases: [row({}), row({ releaseId: "r2", keyId: "k2" })] }));
  reject("duplicate release ids", rec({ releases: [row({}), row({ keyId: "k2", retiredMs: rowsOf[0].activatedMs + 5 })] }));
  reject("duplicate key ids", rec({ releases: [row({}), row({ releaseId: "r2", retiredMs: rowsOf[0].activatedMs + 5 })] }));
  reject("retired not after activation", rec({ releases: [row({}), { releaseId: "r2", keyId: "k2", activatedMs: 500, retiredMs: 500 }] }));
  reject("retired before unretired activation", rec({ releases: [row({}), { releaseId: "r2", keyId: "k2", activatedMs: 1, retiredMs: rowsOf[0].activatedMs }] }));
  reject("unretired activated before retired", rec({ releases: [{ releaseId: "r2", keyId: "k2", activatedMs: rowsOf[0].activatedMs + 10, retiredMs: rowsOf[0].activatedMs + 20 }, row({})] }));
  reject("rows not an array", rec({ releases: null }));
  // receipt domains
  makeLifecycleStatement(initLifecycle);
  makeLifecycleStatement(lifecycle);
  const rot = lifecycle.receipt;
  reject("op domain", life({ receipt: receiptOf({ operation: "rotate" }) }));
  reject("version", life({ receipt: receiptOf({ version: 2 }) }));
  reject("sequence 0", life({ receipt: receiptOf({ sequence: 0 }) }));
  reject("sequence 4097", life({ receipt: receiptOf({ sequence: 4_097 }) }));
  makeLifecycleStatement({ ...lifecycle, receipt: receiptOf({ sequence: 4_096 }) });
  reject("rotate-release with sequence 1 (authority cannot produce it)", life({ receipt: receiptOf({ sequence: 1 }) }));
  makeLifecycleStatement({ ...lifecycle, receipt: receiptOf({ retiresMs: rot.activatesMs + 300_000 }) });
  reject("overlap 300001", life({ receipt: receiptOf({ retiresMs: rot.activatesMs + 300_001 }) }));
  reject("retires == activates", life({ receipt: receiptOf({ retiresMs: rot.activatesMs }) }));
  reject("retires < activates", life({ receipt: receiptOf({ retiresMs: rot.activatesMs - 1 }) }));
  reject("rotate without retires", life({ receipt: receiptOf({ retiresMs: null }) }));
  reject("rotate same release", life({ receipt: receiptOf({ nextReleaseId: rot.currentReleaseId }) }));
  reject("initialize different release", life({ receipt: receiptOf({ nextReleaseId: "release-other" }, initLifecycle.receipt) }, initLifecycle));
  reject("initialize with retires", life({ receipt: receiptOf({ retiresMs: initLifecycle.receipt.activatesMs + 1 }, initLifecycle.receipt) }, initLifecycle));
  reject("receipt digest != outer", life({ receipt: receiptOf({ digest: flipHex(rot.digest) }) }));
  reject("receipt environment != outer", life({ receipt: receiptOf({ environment: "staging" }) }));
  reject("receipt authority != outer", life({ receipt: receiptOf({ authorityId: ATTESTATION_AUTHORITY_IDS.staging }) }));
  reject("receipt policy", life({ receipt: receiptOf({ policyEpoch: "phase5c-i1-epoch-2" }) }));
  reject("receipt extra field", life({ receipt: receiptOf({ extra: 1 }) }));
  reject("receipt missing field", life({ receipt: { ...rot, nextKeyId: undefined } }));
  reject("receipt key id", life({ receipt: receiptOf({ nextKeyId: "a.b" }) }));
  reject("receipt release id", life({ receipt: receiptOf({ nextReleaseId: "a b" }) }));
  reject("receipt operator fingerprint case", life({ receipt: receiptOf({ operatorKeyFingerprint: rot.operatorKeyFingerprint.toUpperCase() }) }));
  reject("receipt appliedMs", life({ receipt: receiptOf({ appliedMs: 1.5 }) }));
  // outer fields
  reject("missing nonce", rec({ nonce: undefined }));
  reject("short nonce", rec({ nonce: notFound.nonce.slice(1) }));
  reject("upper nonce", rec({ nonce: notFound.nonce.toUpperCase() }));
  reject("trust epoch", rec({ trustEpoch: 2 }));
  reject("wrong authority for environment", rec({ authorityId: ATTESTATION_AUTHORITY_IDS.staging }));
  reject("environment case", rec({ environment: "Production" }));
  reject("policy epoch", rec({ policyEpoch: "phase5c-i1-epoch-2" }));
  reject("digest case", rec({ digest: notFound.digest.toUpperCase() }));
  reject("writer fingerprint", rec({ writerKeyFingerprint: "short" }));
  reject("observedAtMs", rec({ observedAtMs: -1 }));
  reject("undefined field", life({ observedAtMs: undefined }));
  // frozen outputs
  assert.ok(Object.isFrozen(makeLifecycleStatement(lifecycle)));
});

test("receipt and release-row conversion are single shared mappings", () => {
  const authorityReceipt: LifecycleReceipt = {
    digest: "a".repeat(64), version: 1, operation: "rotate-release", environment: "production", authorityId: ADMISSION_AUTHORITY_ID,
    policyEpoch: ADMISSION_POLICY_EPOCH, keyFingerprint: "b".repeat(64), sequence: 7, appliedMs: 11, currentReleaseId: "r1", nextReleaseId: "r2",
    nextKeyId: "k2", activatesMs: 12, retiresMs: 13 };
  const receipt = attestationReceiptFromLifecycleReceipt(authorityReceipt);
  assert.equal(receipt.operatorKeyFingerprint, "b".repeat(64));
  assert.deepEqual(Object.keys(receipt), RECEIPT_ORDER);
  assert.equal("keyFingerprint" in receipt, false);
  assert.deepEqual(attestationReleaseRowFromAuthority({ release_id: "r1", key_id: "k1", activated_ms: 5, retired_ms: null }), { releaseId: "r1", keyId: "k1", activatedMs: 5, retiredMs: null });
  assert.deepEqual(Object.keys(attestationReleaseRowFromAuthority({ release_id: "r1", key_id: "k1", activated_ms: 5, retired_ms: 6 })), ROW_ORDER);
});

// ---------------------------------------------------------------------------------------------------------------------
// Mutation matrix
// ---------------------------------------------------------------------------------------------------------------------
interface Leaf { path: number[]; cls: string; value: unknown }
function leaves(v: GoldenVector): Leaf[] {
  const order = v.kind === "lifecycle" ? LIFECYCLE_ORDER : RECONCILIATION_ORDER;
  const out: Leaf[] = [];
  v.tuple.forEach((value, index) => {
    if (order[index] === "receipt" && Array.isArray(value)) value.forEach((entry, at) => out.push({ path: [index, at], cls: `receipt.${RECEIPT_ORDER[at]}`, value: entry }));
    else if (order[index] === "releases" && Array.isArray(value) && value.length > 0) {
      value.forEach((row: unknown[], r) => row.forEach((entry, c) => out.push({ path: [index, r, c], cls: `row.${ROW_ORDER[c]}`, value: entry })));
    } else out.push({ path: [index], cls: order[index], value });
  });
  return out;
}
const setAt = (tuple: unknown[], path: number[], value: unknown): unknown[] => {
  const copy = clone(tuple);
  let node = copy as unknown[];
  for (const step of path.slice(0, -1)) node = node[step] as unknown[];
  node[path[path.length - 1]] = value;
  return copy;
};
const getAt = (tuple: unknown[], path: number[]): unknown => path.reduce<unknown>((node, step) => (node as unknown[])[step], tuple);
const numberJunk = [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, "1", null, true, [], {}];
const textJunk = (orig: string) => ["", orig + "x", 1, null, true, [], {}];
const hexJunk = (orig: string) => [orig.toUpperCase(), orig.slice(1), orig + "0", "g" + orig.slice(1), ...textJunk(orig)];

/** `consistent`: well-formed alternatives that MAY be self-consistent when validly signed (protected only by the signature
 * or by caller expectations). `rejected`: values that must fail even when validly signed. */
function alternatives(g: Golden, v: GoldenVector, leaf: Leaf): { consistent: unknown[]; rejected: unknown[] } {
  const { cls, value } = leaf;
  const other: Role = v.keyRole === "production" ? "staging" : "production";
  const num = value as number;
  // Receipt leaves: the receipt's own tuple (path minus the leaf index) gives sibling fields for cross-field rules.
  const sibling = (index: number) => getAt(v.tuple, [...leaf.path.slice(0, -1), index]);
  const oneRow = v.name === ONE_ROW_VECTOR;
  switch (cls) {
    case "version": return { consistent: [], rejected: [1, 3, "2", null, 2.5, -2, true] };
    case "trustEpoch": return { consistent: [], rejected: [0, 2, "1", null, 1.5, true] };
    case "environment": return { consistent: [other], rejected: ["", "Production", "prod", 1, null] };
    case "authorityId": return { consistent: [ATTESTATION_AUTHORITY_IDS[other]], rejected: textJunk(value as string) };
    case "policyEpoch": return { consistent: [], rejected: ["phase5c-i1-epoch-2", ...textJunk(value as string)] };
    case "kind": return { consistent: [v.kind === "lifecycle" ? "reconciliation" : "lifecycle"], rejected: ["settlement", "LIFECYCLE", "", 1, null] };
    case "digest": return { consistent: [flipHex(value as string)], rejected: hexJunk(value as string) };
    case "outcome": return { consistent: [], rejected: ["SUCCESS", "ALREADY_APPLIED", "applied", "", 1, null] };
    case "nonce": return { consistent: [flipHex(value as string)], rejected: hexJunk(value as string) };
    case "initialized": return { consistent: [!(value as boolean)], rejected: ["true", 1, 0, null] };
    case "coverage": return { consistent: [value === "COMPLETE" ? "INCOMPLETE" : "COMPLETE"], rejected: ["complete", "PARTIAL", "UNAVAILABLE", "", 1, null] };
    case "status": return { consistent: ["EXACT_RECEIPT", "NOT_FOUND", "HISTORY_INCOMPLETE"].filter((status) => status !== value), rejected: ["UNAVAILABLE", "exact_receipt", "SUCCESS", "", 1, null] };
    case "receipt": return { consistent: [], rejected: [0, {}, [], "x", [1, 2, 3], true] }; // receipt: null -> non-receipt junk; null->receipt is covered below
    case "releases": return { consistent: [], rejected: [null, {}, "x", [[]], [["r", "k", 1, null]], [["r", "k", 1, null], ["r", "k", 1, null], ["r3", "k3", 1, 2]]] };
    case "observedAtMs": return { consistent: [num + 1, num - 1], rejected: [...numberJunk, num - 300_001 + 1000, num + 60_001 + 1000] };
    case "writerKeyFingerprint": return { consistent: [], rejected: [flipHex(value as string), g.keys[other].fingerprint, ...hexJunk(value as string)] };
    case "receipt.digest": return { consistent: [], rejected: [flipHex(value as string), ...hexJunk(value as string)] };
    case "receipt.version": return { consistent: [], rejected: [0, 2, "1", null, 1.5] };
    case "receipt.operation": return { consistent: [], rejected: [value === "initialize" ? "rotate-release" : "initialize", "rotate", "", 1, null] };
    case "receipt.environment": return { consistent: [], rejected: [other, "", "Production", 1, null] };
    case "receipt.authorityId": return { consistent: [], rejected: [ATTESTATION_AUTHORITY_IDS[other], ...textJunk(value as string)] };
    case "receipt.policyEpoch": return { consistent: [], rejected: ["phase5c-i1-epoch-2", ...textJunk(value as string)] };
    case "receipt.operatorKeyFingerprint": return { consistent: [flipHex(value as string)], rejected: hexJunk(value as string) };
    case "receipt.sequence": // initialize is exactly 1, rotate-release >= 2; the one-row snapshot is bound to the sequence-1 initialize
      return sibling(2) === "initialize" ? { consistent: [], rejected: [0, 2, 4_097, ...numberJunk] } : { consistent: [num + 1], rejected: [0, 1, 4_097, ...numberJunk] };
    case "receipt.appliedMs": {
      const activates = sibling(12) as number;
      return { consistent: [num + 1, num - 1], rejected: [activates + 300_001, activates - 300_001, ...numberJunk] };
    }
    case "receipt.currentReleaseId": // initialize requires current == next
      return sibling(2) === "initialize" ? { consistent: [], rejected: [(value as string) + "-x", "", "r".repeat(129), "bad id!", 1, null, true] }
        : { consistent: [(value as string) + "-x"], rejected: ["", "r".repeat(129), "bad id!", 1, null, true] };
    case "receipt.nextReleaseId":
      return sibling(2) === "initialize" || oneRow ? { consistent: [], rejected: [(value as string) + "-x", "", "r".repeat(129), "bad id!", 1, null, true] }
        : { consistent: [(value as string) + "-x"], rejected: ["", "r".repeat(129), "bad id!", 1, null, true] };
    case "receipt.nextKeyId":
      return oneRow ? { consistent: [], rejected: [(value as string) + "_x", "", "k".repeat(65), "bad.key", 1, null, true] }
        : { consistent: [(value as string) + "_x"], rejected: ["", "k".repeat(65), "bad.key", 1, null, true] };
    case "receipt.activatesMs": {
      const applied = sibling(8) as number;
      return { consistent: oneRow ? [] : [num + 1], rejected: [...(oneRow ? [num + 1, num - 1] : []), applied + 300_001, applied - 300_001, ...numberJunk] };
    }
    case "receipt.retiresMs": {
      const activates = getAt(v.tuple, [...leaf.path.slice(0, -1), 12]) as number;
      return value === null // initialize requires retiresMs null
        ? { consistent: [], rejected: [activates + 1, ...numberJunk.filter((junk) => junk !== null)] }
        : { consistent: [num + 1], rejected: [null, activates, activates - 1, activates + 300_001, ...numberJunk.filter((junk) => junk !== null)] };
    }
    case "row.releaseId": return { consistent: oneRow ? [] : [(value as string) + "-x"], rejected: [...(oneRow ? [(value as string) + "-x"] : []), "", "r".repeat(129), "bad id!", 1, null, true] };
    case "row.keyId": return { consistent: oneRow ? [] : [(value as string) + "_x"], rejected: [...(oneRow ? [(value as string) + "_x"] : []), "", "k".repeat(65), "bad.key", 1, null, true] };
    case "row.activatedMs": return { consistent: oneRow ? [] : [num + 1, num - 1], rejected: [...(oneRow ? [num + 1, num - 1] : []), ...numberJunk] };
    case "row.retiredMs": {
      const activated = getAt(v.tuple, [...leaf.path.slice(0, -1), 2]) as number;
      return value === null
        ? { consistent: [], rejected: [activated + 1, ...numberJunk.filter((junk) => junk !== null)] } // nullability flip: zero unretired rows
        : { consistent: [num + 1], rejected: [null, activated, activated - 1, ...numberJunk.filter((junk) => junk !== null)] };
    }
    default: throw new Error(`no mutation plan for ${cls}`);
  }
}

/** Fields whose well-formed, self-consistent alternative is NOT bound by a caller expectation or domain rule: only the
 * signature protects them. Every other field must fail even when the mutated statement is validly re-signed. */
const ONE_ROW_VECTOR = "staging-reconciliation-exact-receipt-one-row";
const SIGNATURE_ONLY_CLASSES = [
  "observedAtMs",
  "receipt.activatesMs",
  "receipt.appliedMs",
  "receipt.currentReleaseId",
  "receipt.nextKeyId",
  "receipt.nextReleaseId",
  "receipt.operatorKeyFingerprint",
  "receipt.retiresMs",
  "receipt.sequence",
  "row.activatedMs",
  "row.keyId",
  "row.releaseId",
  "row.retiredMs",
];

test("isolated mutation of every tuple position fails verification", async () => {
  const { golden, manifest } = await load();
  const accepted = new Set<string>();
  const seenClasses = new Set<string>();
  let checks = 0;
  for (const v of golden.vectors) {
    for (const leaf of leaves(v)) {
      seenClasses.add(leaf.cls);
      const alt = alternatives(golden, v, leaf);
      for (const value of [...alt.consistent, ...alt.rejected]) {
        const mutated = setAt(v.tuple, leaf.path, value);
        assert.notEqual(JSON.stringify(mutated), JSON.stringify(v.tuple), `${v.name} ${leaf.cls}: mutation must differ`);
        const label = `${v.name} ${leaf.cls} -> ${JSON.stringify(value)}`;
        // 1. original signature over a mutated statement
        await mustReject(`stale signature: ${label}`, () => verifyVector(manifest, v, envelopeBytes(mutated, v.signature)));
        // 2. same mutation, validly re-signed by the real test key
        const fresh = await resigned(golden, v.keyRole, mutated);
        let ok = false;
        let failure: unknown;
        try { await verifyVector(manifest, v, fresh); ok = true; } catch (error) { failure = error; }
        const listedRejected = alt.rejected.some((candidate) => JSON.stringify(candidate) === JSON.stringify(value));
        if (ok) {
          accepted.add(leaf.cls);
          assert.ok(alt.consistent.some((candidate) => JSON.stringify(candidate) === JSON.stringify(value)), `re-signed malformed value accepted: ${label}`);
          // the signature alone must be what rejected the stale copy
          await mustReject(`stale signature is the failure: ${label}`, () => verifyVector(manifest, v, envelopeBytes(mutated, v.signature)), "attestation-signature");
        } else {
          // A validly re-signed mutation that fails must fail at a SEMANTIC layer (statement/receipt/releases/expectation/key/stale),
          // never as a signature failure: that is how the matrix tells semantic validation apart from signature verification.
          assert.ok(failure instanceof Error && /^attestation-[a-z-]+$/u.test(failure.message), `unexpected failure: ${label}: ${String(failure)}`);
          assert.notEqual((failure as Error).message, "attestation-signature", `validly signed mutation failed as a signature error: ${label}`);
          if (listedRejected) await mustReject(`re-signed: ${label}`, () => verifyVector(manifest, v, fresh));
          else assert.ok(alt.consistent.some((candidate) => JSON.stringify(candidate) === JSON.stringify(value)), `unlisted value: ${label}`);
        }
        checks += 1;
      }
    }
  }
  assert.deepEqual([...accepted].sort(), [...SIGNATURE_ONLY_CLASSES].sort());
  // every position of every tuple kind was mutated (top-level `receipt` is a leaf only where it is null)
  assert.deepEqual([...seenClasses].sort(), [...new Set([...LIFECYCLE_ORDER, ...RECONCILIATION_ORDER, ...RECEIPT_ORDER.map((f) => `receipt.${f}`), ...ROW_ORDER.map((f) => `row.${f}`)])].sort());
  assert.ok(checks > 1_000, `expected a broad matrix, ran ${checks}`);
});

test("nullability flips between receipt and non-receipt states fail even when re-signed", async () => {
  const { golden, manifest } = await load();
  const exact = golden.vectors[3];
  const notFound = golden.vectors[4];
  await mustReject("EXACT_RECEIPT receipt -> null", async () => verifyVector(manifest, exact, await resigned(golden, "production", setAt(exact.tuple, [11], null))));
  await mustReject("NOT_FOUND null -> receipt", async () => verifyVector(manifest, notFound, await resigned(golden, "production", setAt(notFound.tuple, [11], (() => {
    const receipt = clone(exact.tuple[11] as unknown[]); receipt[0] = notFound.expectations.digest; return receipt; })()))));
  const history = golden.vectors[6];
  await mustReject("HISTORY_INCOMPLETE null -> receipt", async () => verifyVector(manifest, history, await resigned(golden, "staging", setAt(history.tuple, [11], (() => {
    const receipt = clone(golden.vectors[7].tuple[11] as unknown[]); receipt[0] = history.expectations.digest; return receipt; })()))));
});

test("receipt and release replacement fail verification", async () => {
  const { golden, manifest } = await load();
  const [initialize, rotate] = golden.vectors;
  await mustReject("lifecycle receipt replaced (stale)", () => verifyVector(manifest, initialize, envelopeBytes(setAt(initialize.tuple, [8], rotate.tuple[8]), initialize.signature)));
  await mustReject("lifecycle receipt replaced (re-signed)", async () => verifyVector(manifest, initialize, await resigned(golden, "production", setAt(initialize.tuple, [8], rotate.tuple[8]))));
  const exact = golden.vectors[3];
  const notFound = golden.vectors[4];
  await mustReject("releases replaced (stale)", () => verifyVector(manifest, exact, envelopeBytes(setAt(exact.tuple, [12], notFound.tuple[12]), exact.signature)));
  await mustReject("releases swapped with empty (stale)", () => verifyVector(manifest, exact, envelopeBytes(setAt(exact.tuple, [12], []), exact.signature)));
  await mustReject("releases swapped with empty (re-signed)", async () => verifyVector(manifest, exact, await resigned(golden, "production", setAt(exact.tuple, [12], []))));
  await mustReject("releases replaced with other env rows (re-signed)", async () => verifyVector(manifest, exact, await resigned(golden, "production", setAt(exact.tuple, [12], [...(golden.vectors[8].tuple[12] as unknown[]), ...(notFound.tuple[12] as unknown[])]))));
  await mustReject("whole statement replaced by another vector", () => verifyVector(manifest, exact, envelopeBytes(notFound.tuple, exact.signature)));
});

test("tuple shortening, extension and reordering fail at every level", async () => {
  const { golden, manifest } = await load();
  for (const v of golden.vectors) {
    const arrays: number[][] = [[]];
    const receiptAt = v.kind === "lifecycle" ? 8 : 11;
    if (Array.isArray(v.tuple[receiptAt])) arrays.push([receiptAt]);
    if (v.kind === "reconciliation" && (v.tuple[12] as unknown[]).length > 0) {
      arrays.push([12]);
      (v.tuple[12] as unknown[]).forEach((_row, r) => arrays.push([12, r]));
    }
    for (const path of arrays) {
      const target = (path.length === 0 ? v.tuple : getAt(v.tuple, path)) as unknown[];
      const replace = (next: unknown[]) => (path.length === 0 ? next : setAt(v.tuple, path, next));
      const variants: [string, unknown[]][] = [
        ["drop first", target.slice(1)], ["drop last", target.slice(0, -1)], ["extend null", [...target, null]], ["extend 0", [...target, 0]],
        ["extend duplicate last", [...target, target[target.length - 1]]], ["empty", []],
      ];
      for (let at = 0; at + 1 < target.length; at += 1) {
        if (JSON.stringify(target[at]) === JSON.stringify(target[at + 1])) continue;
        const swapped = [...target]; [swapped[at], swapped[at + 1]] = [swapped[at + 1], swapped[at]];
        variants.push([`swap ${at}/${at + 1}`, swapped]);
      }
      for (const [name, next] of variants) {
        const mutated = replace(next);
        const label = `${v.name} [${path.join(",")}] ${name}`;
        await mustReject(`stale: ${label}`, () => verifyVector(manifest, v, envelopeBytes(mutated, v.signature)));
        const level = path.length === 0 ? "statement" : path[0] === receiptAt ? "receipt" : path.length === 1 ? "releases" : "row";
        let accepted = false;
        try { await verifyVector(manifest, v, await resigned(golden, v.keyRole, mutated)); accepted = true; } catch { accepted = false; }
        if (accepted) {
          // Only structurally different-but-still-valid shapes may survive re-signing, and then ONLY the signature binds them:
          //  - swapping adjacent release-id/key-id positions (shared alphabet) in a receipt or row;
          //  - dropping the retired row of a two-row snapshot, which leaves a valid one-row snapshot.
          const allowed = (level === "receipt" && ["swap 9/10", "swap 10/11"].includes(name)) || (level === "row" && name === "swap 0/1") ||
            (level === "releases" && v.tuple[11] === null && target.length === 2 && ((name === "drop first" && (target[1] as unknown[])[3] === null) || (name === "drop last" && (target[0] as unknown[])[3] === null)));
          assert.ok(allowed, `re-signed structural mutation accepted: ${label}`);
          await mustReject(`signature is the failure: ${label}`, () => verifyVector(manifest, v, envelopeBytes(mutated, v.signature)), "attestation-signature");
        }
      }
    }
    // a statement that is not a tuple at all
    const asObject = Object.fromEntries((v.kind === "lifecycle" ? LIFECYCLE_ORDER : RECONCILIATION_ORDER).map((field, index) => [field, v.tuple[index]]));
    await mustReject(`object statement ${v.name}`, () => verifyVector(manifest, v, envelopeBytes(asObject, v.signature)));
    await mustReject(`null statement ${v.name}`, () => verifyVector(manifest, v, envelopeBytes(null, v.signature)));
  }
});

test("wrong domain separator, version, trust epoch, kind, expectations", async () => {
  const { golden, manifest } = await load();
  const v = golden.vectors[0];
  const r = golden.vectors[3];
  for (const [label, domain] of [
    ["no trailing NUL", DOMAIN.slice(0, -1)], ["v1", DOMAIN.replace(":v2", ":v1")], ["space instead of NUL", DOMAIN.slice(0, -1) + " "],
    ["double NUL", DOMAIN + "\0"], ["empty", ""], ["ingress-style", "limitmark:ingress:v1\0"], ["uppercase", DOMAIN.toUpperCase()],
    ["prefix junk", "x" + DOMAIN], ["legacy command digest domain", "limitmark-lifecycle-command-digest-v1\n"],
  ] as const) {
    for (const target of [v, r]) {
      await mustReject(`domain ${label} ${target.name}`, async () => verifyVector(manifest, target, await resigned(golden, target.keyRole, target.tuple, domain)), "attestation-signature");
    }
  }
  // statement signed over the bare tuple JSON with no domain at all
  await mustReject("bare JSON signed", async () => verifyVector(manifest, v, envelopeBytes(v.tuple, await rawSign(golden.keys.production.privateKeyPkcs8, enc.encode(JSON.stringify(v.tuple))))), "attestation-signature");
  // caller expectations are separate and authoritative
  const expectation = v.expectations as Extract<ResultAttestationExpectations, { kind: "lifecycle" }>;
  const exact = r.expectations as Extract<ResultAttestationExpectations, { kind: "reconciliation" }>;
  const bytes = enc.encode(v.envelope);
  const rbytes = enc.encode(r.envelope);
  await mustReject("wrong digest", () => verifyVector(manifest, v, bytes, { expectations: { ...expectation, digest: flipHex(expectation.digest) } }), "attestation-expectation");
  await mustReject("wrong environment", () => verifyVector(manifest, v, bytes, { expectations: { ...expectation, environment: "staging", authorityId: ATTESTATION_AUTHORITY_IDS.staging } }), "attestation-expectation");
  await mustReject("wrong authority", () => verifyVector(manifest, v, bytes, { expectations: { ...expectation, authorityId: ATTESTATION_AUTHORITY_IDS.staging } }), "attestation-expectation");
  await mustReject("wrong policy", () => verifyVector(manifest, v, bytes, { expectations: { ...expectation, policyEpoch: "phase5c-i1-epoch-2" } }), "attestation-expectation");
  await mustReject("wrong kind", () => verifyVector(manifest, v, bytes, { expectations: { ...exact, digest: expectation.digest } }), "attestation-expectation");
  await mustReject("lifecycle expectation with nonce", () => verifyVector(manifest, v, bytes, { expectations: { ...expectation, nonce: exact.nonce } as unknown as ResultAttestationExpectations }), "attestation-expectation");
  await mustReject("reconciliation expectation without nonce", () => verifyVector(manifest, r, rbytes, { expectations: { ...exact, nonce: undefined } as unknown as ResultAttestationExpectations }), "attestation-expectation");
  await mustReject("wrong nonce", () => verifyVector(manifest, r, rbytes, { expectations: { ...exact, nonce: flipHex(exact.nonce) } }), "attestation-expectation");
  await mustReject("reconciliation kind for lifecycle envelope", () => verifyVector(manifest, r, bytes, { expectations: exact }), "attestation-expectation");
  await mustReject("malformed digest expectation", () => verifyVector(manifest, v, bytes, { expectations: { ...expectation, digest: "abc" } }), "attestation-expectation");
  await mustReject("extra expectation field", () => verifyVector(manifest, v, bytes, { expectations: { ...expectation, extra: 1 } as unknown as ResultAttestationExpectations }), "attestation-expectation");
  // wrong trust epoch / version at the statement layer, signed validly
  await mustReject("trust epoch 2 signed", async () => verifyVector(manifest, v, await resigned(golden, "production", setAt(v.tuple, [1], 2))), "attestation-statement");
  await mustReject("version 3 signed", async () => verifyVector(manifest, v, await resigned(golden, "production", setAt(v.tuple, [0], 3))), "attestation-statement");
  await mustReject("kind settlement signed", async () => verifyVector(manifest, v, await resigned(golden, "production", setAt(v.tuple, [5], "settlement"))), "attestation-statement");
  // a fully self-consistent statement for the other environment still fails the caller's expectations
  const staging = golden.vectors[2];
  await mustReject("staging statement presented for Production", () => verifyVector(manifest, v, enc.encode(staging.envelope)), "attestation-expectation");
  await mustReject("Production statement presented for staging", () => verifyVector(manifest, staging, enc.encode(v.envelope)), "attestation-expectation");
});

test("signature tampering, replacement and non-canonical forms", async () => {
  const { golden, manifest } = await load();
  for (const v of golden.vectors) {
    const signature = Buffer.from(v.signature, "base64url");
    for (const bit of [0, 7, 8, 255, 256, 400, 511]) {
      const flipped = Buffer.from(signature);
      flipped[bit >> 3] ^= 1 << (bit & 7);
      await mustReject(`${v.name} bit ${bit}`, () => verifyVector(manifest, v, envelopeBytes(v.tuple, encodeBase64url(flipped))), "attestation-signature");
    }
    const other = golden.vectors.find((candidate) => candidate !== v)!;
    await mustReject(`${v.name} signature replaced`, () => verifyVector(manifest, v, envelopeBytes(v.tuple, other.signature)), "attestation-signature");
    await mustReject(`${v.name} zero signature`, () => verifyVector(manifest, v, envelopeBytes(v.tuple, encodeBase64url(new Uint8Array(64)))), "attestation-signature");
    const variants: [string, string][] = [
      ["padded", v.signature + "=="], ["empty", ""], ["63 bytes", encodeBase64url(signature.subarray(0, 63))], ["65 bytes", encodeBase64url(Buffer.concat([signature, Buffer.from([0])]))],
      ["standard alphabet", Buffer.from(signature).toString("base64")], ["whitespace", v.signature.slice(0, 10) + " " + v.signature.slice(10)],
      ["trailing newline", v.signature + "\n"], ["invalid char", v.signature.slice(0, -1) + "!"], ["hex", signature.toString("hex")],
    ];
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = alphabet.indexOf(v.signature.at(-1)!);
    assert.equal(last & 3, 0, "canonical 64-byte signature ends with two zero bits");
    variants.push(["non-canonical trailing bits", v.signature.slice(0, -1) + alphabet[last | 1]]);
    for (const [label, text] of variants) {
      await mustReject(`${v.name} signature ${label}`, () => verifyVector(manifest, v, envelopeBytes(v.tuple, text)), "attestation-envelope");
    }
    for (const junk of [null, 0, true, [], {}, undefined]) {
      await mustReject(`${v.name} signature ${String(junk)}`, () => verifyVector(manifest, v, enc.encode(`{"statement":${JSON.stringify(v.tuple)},"signature":${junk === undefined ? "undefined" : JSON.stringify(junk)}}`)));
    }
  }
});

test("envelope parser is strict", async () => {
  const { golden, manifest } = await load();
  const v = golden.vectors[3];
  const statementJson = JSON.stringify(v.tuple);
  const good = `{"statement":${statementJson},"signature":"${v.signature}"}`;
  assert.equal(good, v.envelope);
  const accept = (text: string | Uint8Array) => verifyVector(manifest, v, typeof text === "string" ? enc.encode(text) : text);
  await accept(good);
  const cases: [string, string | Uint8Array][] = [
    ["missing signature", `{"statement":${statementJson}}`],
    ["missing statement", `{"signature":"${v.signature}"}`],
    ["empty object", "{}"],
    ["extra field", `{"statement":${statementJson},"signature":"${v.signature}","writer":"${v.tuple[14]}"}`],
    ["duplicated writer fingerprint outside statement", `{"statement":${statementJson},"signature":"${v.signature}","writerKeyFingerprint":"${v.tuple[14]}"}`],
    ["duplicate statement member", `{"statement":${statementJson},"statement":${statementJson},"signature":"${v.signature}"}`],
    ["duplicate signature member", `{"statement":${statementJson},"signature":"${v.signature}","signature":"${v.signature}"}`],
    ["duplicate member, differing value", `{"statement":${statementJson},"signature":"${golden.vectors[0].signature}","signature":"${v.signature}"}`],
    ["reordered members", `{"signature":"${v.signature}","statement":${statementJson}}`],
    ["BOM", concat(Uint8Array.from([0xef, 0xbb, 0xbf]), enc.encode(good))],
    ["malformed UTF-8 byte", concat(enc.encode(good.slice(0, 20)), Uint8Array.from([0xff]), enc.encode(good.slice(20)))],
    ["truncated multibyte", concat(enc.encode(good), Uint8Array.from([0xc3]))],
    ["overlong NUL encoding", concat(enc.encode(good.slice(0, 20)), Uint8Array.from([0xc0, 0x80]), enc.encode(good.slice(20)))],
    ["trailing content", good + "{}"],
    ["trailing garbage", good + "x"],
    ["trailing whitespace", good + "\n"],
    ["leading whitespace", " " + good],
    ["inner whitespace", good.replace('"statement":', '"statement": ')],
    ["two documents", good + good],
    ["empty input", new Uint8Array(0)],
    ["oversized", new Uint8Array(ATTESTATION_MAX_ENVELOPE_BYTES + 1).fill(0x20)],
    ["oversized valid prefix", concat(enc.encode(good), new Uint8Array(ATTESTATION_MAX_ENVELOPE_BYTES).fill(0x20))],
    ["array envelope", `[${statementJson},"${v.signature}"]`],
    ["null envelope", "null"],
    ["string envelope", JSON.stringify(good)],
    ["statement escaped as string", `{"statement":${JSON.stringify(statementJson)},"signature":"${v.signature}"}`],
    ["unsupported version", good.replace("[2,1,", "[3,1,")],
    ["unsupported kind", good.replace('"reconciliation"', '"settlement"')],
    ["float number", good.replace("[2,1,", "[2.0,1,")],
    ["exponent number", good.replace(String(v.tuple[13]), "1.79e12")],
    ["leading zero number", good.replace("[2,1,", "[02,1,")],
    ["negative zero number", good.replace(String(v.tuple[13]), "-0")],
    ["unicode-escaped member name", good.replace('"statement"', '"\\u0073tatement"')],
    ["unicode-escaped value", good.replace('"COMPLETE"', '"COMPLET\\u0045"')],
    ["NaN", good.replace(String(v.tuple[13]), "NaN")],
    ["single quotes", good.replaceAll('"', "'")],
    ["truncated", good.slice(0, -2)],
    ["deeply nested", "[".repeat(2_000) + "]".repeat(2_000)],
    ["legacy unsigned positive object", JSON.stringify({ version: 1, digest: v.expectations.digest, environment: "production", authorityId: ATTESTATION_AUTHORITY_IDS.production,
      policyEpoch: ATTESTATION_POLICY_EPOCH, observedAtMs: v.verifyAtMs, kind: "reconciliation", nonce: (v.expectations as { nonce: string }).nonce, initialized: true,
      coverage: "COMPLETE", status: "EXACT_RECEIPT", receipt: { digest: v.expectations.digest, version: 1 }, releases: [] })],
    ["legacy lifecycle SUCCESS object", JSON.stringify({ version: 1, digest: v.expectations.digest, environment: "production", status: "SUCCESS" })],
    ["legacy ALREADY_APPLIED object", JSON.stringify({ version: 1, digest: v.expectations.digest, environment: "production", status: "ALREADY_APPLIED" })],
  ];
  for (const [label, input] of cases) await mustReject(label, () => accept(input));
  assert.throws(() => parseResultAttestationEnvelope("x" as unknown as Uint8Array), /attestation-envelope/u);
  // the signed statement binds the nonce/digest to the envelope: copying another vector's signature over this tuple fails
  await mustReject("statement from envelope A with signature from B", () => accept(envelopeBytes(v.tuple, golden.vectors[4].signature)), "attestation-signature");
});

// ---------------------------------------------------------------------------------------------------------------------
// Keys, signing
// ---------------------------------------------------------------------------------------------------------------------
test("key import, fingerprint and signer guard rails", async () => {
  const { golden } = await load();
  const prod = golden.keys.production;
  const staging = golden.keys.staging;
  const v = golden.vectors[0];
  const statement = statementOf(v);
  // private key: exact 48-byte RFC 8410 PKCS#8, canonical, non-extractable signing key
  const privateKey = await importAttestationTestPrivateKey(prod.privateKeyPkcs8);
  assert.equal(privateKey.extractable, false);
  assert.deepEqual(privateKey.usages, ["sign"]);
  const publicKey = await importAttestationPublicKey(prod.publicKey);
  assert.equal(publicKey.extractable, false);
  assert.deepEqual(publicKey.usages, ["verify"]);
  const der = fromHex(PKCS8_PREFIX + RFC.production.seedHex);
  assert.equal(der.length, 48);
  const badPrivate: [string, string][] = [
    ["wrong prefix", encodeBase64url(Uint8Array.from(der, (byte, index) => (index === 0 ? 0x31 : byte)))],
    ["wrong inner prefix byte", encodeBase64url(Uint8Array.from(der, (byte, index) => (index === 15 ? 0x21 : byte)))],
    ["47 bytes", encodeBase64url(der.subarray(0, 47))], ["49 bytes", encodeBase64url(concat(der, Uint8Array.from([0])))],
    ["raw seed only", encodeBase64url(fromHex(RFC.production.seedHex))], ["padded", prod.privateKeyPkcs8 + "="], ["standard alphabet", Buffer.from(der).toString("base64")],
    ["empty", ""],
  ];
  for (const [label, text] of badPrivate) await assert.rejects(importAttestationTestPrivateKey(text), /attestation-key-material/u, label);
  // public key: canonical unpadded base64url of exactly 32 bytes
  const pub = fromHex(RFC.production.publicHex);
  for (const [label, text] of [["padded", prod.publicKey + "="], ["31 bytes", encodeBase64url(pub.subarray(0, 31))], ["33 bytes", encodeBase64url(concat(pub, Uint8Array.from([0])))],
    ["standard alphabet", Buffer.from(pub).toString("base64")], ["hex", RFC.production.publicHex], ["empty", ""], ["non-canonical", prod.publicKey.slice(0, -1) + "B"]] as const) {
    await assert.rejects(attestationKeyFingerprint(text), /attestation-key-material/u, label);
    await assert.rejects(importAttestationPublicKey(text), /attestation-key-material/u, label);
  }
  assert.equal(await attestationKeyFingerprint(prod.publicKey), prod.fingerprint);
  assert.match(prod.fingerprint, /^[a-f0-9]{64}$/u);
  assert.notEqual(prod.fingerprint, staging.fingerprint);
  // the signer refuses a key pair that does not match the statement's writer fingerprint
  await assert.rejects(signResultAttestation(statement, { privateKey: staging.privateKeyPkcs8, publicKey: staging.publicKey }), /attestation-key-material/u);
  await assert.rejects(signResultAttestation(statement, { privateKey: staging.privateKeyPkcs8, publicKey: prod.publicKey }), /attestation-key-material/u);
  await assert.rejects(signResultAttestation(statement, { privateKey: prod.privateKeyPkcs8, publicKey: staging.publicKey }), /attestation-key-material/u);
  await assert.rejects(signResultAttestation(statement, { privateKey: "x", publicKey: prod.publicKey }), /attestation-key-material/u);
  await assert.rejects(signResultAttestation({ ...statement, digest: "nope" } as unknown as ResultStatement, { privateKey: prod.privateKeyPkcs8, publicKey: prod.publicKey }), /attestation-statement/u);
  assert.equal((await signResultAttestation(statement, { privateKey: prod.privateKeyPkcs8, publicKey: prod.publicKey })).signature, v.signature);
  // the fingerprint is only a hash of the 32 bytes and judges nothing about key safety; the import is the safety gate
  assert.equal(await attestationKeyFingerprint(encodeBase64url(new Uint8Array(32))), sha256Hex(new Uint8Array(32)));
  await assert.rejects(importAttestationPublicKey(encodeBase64url(new Uint8Array(32))), /attestation-key-material/u);
});

// ---------------------------------------------------------------------------------------------------------------------
// Trust manifest
// ---------------------------------------------------------------------------------------------------------------------
async function manifestVariant(mutate: (manifest: ManifestJson) => void): Promise<string> {
  const { manifestText } = await load();
  const manifest = JSON.parse(manifestText) as ManifestJson;
  mutate(manifest);
  return JSON.stringify(manifest, null, 2);
}
const fourthKey = (): KeyJson => ({ keyFingerprint: sha256Hex(fromHex(RFC.fourth.publicHex)), publicKey: publicKeyText(RFC.fourth.publicHex), status: "active", notBeforeMs: 1_700_000_000_000, notAfterMs: null });
const thirdKey = (notBeforeMs = 1_700_000_000_000): KeyJson => ({ keyFingerprint: sha256Hex(fromHex(RFC.third.publicHex)), publicKey: publicKeyText(RFC.third.publicHex),
  status: "active", notBeforeMs, notAfterMs: null });

test("trust manifest: fixture parses; template is shape-only and never parses", async () => {
  const { golden, manifest, manifestText } = await load();
  assert.equal(manifest.manifestVersion, 1);
  assert.equal(manifest.attestationVersion, 2);
  assert.equal(manifest.trustEpoch, 1);
  assert.deepEqual(manifest.environments.map((section) => section.environment), ["production", "staging"]);
  assert.equal(manifest.environments[0].currentKeyFingerprint, golden.keys.production.fingerprint);
  assert.equal(manifest.environments[1].currentKeyFingerprint, golden.keys.staging.fingerprint);
  assert.ok(Object.isFrozen(manifest) && Object.isFrozen(manifest.environments[0].keys));
  // the same bytes parse identically
  await parseAuthorityResultTrustManifest(enc.encode(manifestText));
  const template = await readFile(new URL("../deployment/authority-result-trust.template.json", import.meta.url), "utf8");
  await assert.rejects(parseAuthorityResultTrustManifest(template), /attestation-manifest/u);
  const shape = JSON.parse(template) as ManifestJson;
  const real = JSON.parse(manifestText) as ManifestJson;
  assert.deepEqual(Object.keys(shape), Object.keys(real));
  shape.environments.forEach((section, index) => {
    assert.deepEqual(Object.keys(section), Object.keys(real.environments[index]));
    assert.deepEqual(Object.keys(section.keys[0]), Object.keys(real.environments[index].keys[0]));
    assert.equal(section.environment, real.environments[index].environment);
    assert.equal(section.authorityId, real.environments[index].authorityId);
  });
  // no operational material: every variable value is a placeholder
  assert.doesNotMatch(template, /[a-f0-9]{64}/u);
  assert.doesNotMatch(template.replace(/__REQUIRED_[A-Z0-9_]+__/gu, ""), /"[A-Za-z0-9_-]{32,}"/u);
  for (const match of template.matchAll(/"(?:currentKeyFingerprint|keyFingerprint|publicKey|notBeforeMs)":\s*"([^"]*)"/gu)) assert.match(match[1], /^__REQUIRED_[A-Z0-9_]+__$/u);
});

test("trust manifest: strict parsing invalidates the whole manifest", async () => {
  const { manifestText } = await load();
  const prodKey = (m: ManifestJson) => m.environments[0].keys[0];
  const variants: [string, (m: ManifestJson) => void][] = [
    ["manifestVersion 2", (m) => { m.manifestVersion = 2; }], ["attestationVersion 1", (m) => { m.attestationVersion = 1; }], ["attestationVersion string", (m) => { m.attestationVersion = "2"; }],
    ["trustEpoch 2", (m) => { m.trustEpoch = 2; }], ["trustEpoch 0", (m) => { m.trustEpoch = 0; }],
    ["extra top-level field", (m) => { m.extra = true; }], ["missing trustEpoch", (m) => { delete m.trustEpoch; }],
    ["environments reversed", (m) => { m.environments.reverse(); }], ["one environment", (m) => { m.environments.pop(); }],
    ["three environments", (m) => { m.environments.push(structuredClone(m.environments[0])); }], ["environments not an array", (m) => { (m as { environments: unknown }).environments = {}; }],
    ["duplicate production", (m) => { m.environments[1] = structuredClone(m.environments[0]); }],
    ["environment case", (m) => { m.environments[0].environment = "Production"; }],
    ["wrong authority", (m) => { m.environments[0].authorityId = ATTESTATION_AUTHORITY_IDS.staging; }],
    ["wrong policy", (m) => { m.environments[0].policyEpoch = "phase5c-i1-epoch-2"; }],
    ["extra env field", (m) => { m.environments[0].extra = 1; }], ["missing env field", (m) => { delete m.environments[0].policyEpoch; }],
    ["zero keys", (m) => { m.environments[0].keys = []; }],
    ["four keys", (m) => { m.environments[0].keys.push(thirdKey(), { ...thirdKey(), keyFingerprint: "1".repeat(64) }, { ...thirdKey(), keyFingerprint: "2".repeat(64) }); }],
    ["currentKeyFingerprint unknown", (m) => { m.environments[0].currentKeyFingerprint = flipHex(m.environments[0].currentKeyFingerprint as string); }],
    ["currentKeyFingerprint malformed", (m) => { m.environments[0].currentKeyFingerprint = "abc"; }],
    ["currentKeyFingerprint is other environment key", (m) => { m.environments[0].currentKeyFingerprint = m.environments[1].currentKeyFingerprint; }],
    ["current key retired", (m) => { prodKey(m).status = "retired"; prodKey(m).notAfterMs = 1_800_000_000_000; }],
    ["retired without notAfterMs", (m) => { m.environments[0].keys.push({ ...thirdKey(), status: "retired" }); }],
    ["status revoked", (m) => { prodKey(m).status = "revoked"; }], ["status uppercase", (m) => { prodKey(m).status = "ACTIVE"; }],
    ["key extra field", (m) => { prodKey(m).label = "x"; }], ["key missing notAfterMs", (m) => { delete prodKey(m).notAfterMs; }],
    ["fingerprint does not match key", (m) => { prodKey(m).keyFingerprint = flipHex(prodKey(m).keyFingerprint as string); m.environments[0].currentKeyFingerprint = prodKey(m).keyFingerprint; }],
    ["fingerprint uppercase", (m) => { prodKey(m).keyFingerprint = (prodKey(m).keyFingerprint as string).toUpperCase(); m.environments[0].currentKeyFingerprint = prodKey(m).keyFingerprint; }],
    ["publicKey padded", (m) => { prodKey(m).publicKey = (prodKey(m).publicKey as string) + "="; }],
    ["publicKey 31 bytes", (m) => { prodKey(m).publicKey = encodeBase64url(fromHex(RFC.production.publicHex).subarray(0, 31)); }],
    ["publicKey hex", (m) => { prodKey(m).publicKey = RFC.production.publicHex; }],
    ["publicKey non-canonical", (m) => { prodKey(m).publicKey = (prodKey(m).publicKey as string).slice(0, -1) + "B"; }],
    ["duplicate fingerprint within environment", (m) => { m.environments[0].keys.push(structuredClone(prodKey(m))); }],
    ["duplicate public key within environment", (m) => { m.environments[0].keys.push({ ...prodKey(m), keyFingerprint: flipHex(prodKey(m).keyFingerprint as string) }); }],
    ["production key reused in staging", (m) => { m.environments[1].keys[0] = structuredClone(prodKey(m)); m.environments[1].currentKeyFingerprint = prodKey(m).keyFingerprint; }],
    ["staging key added to production", (m) => { m.environments[0].keys.push(structuredClone(m.environments[1].keys[0])); }],
    ["same fingerprint across environments", (m) => { m.environments[1].keys.push({ ...thirdKey(), keyFingerprint: prodKey(m).keyFingerprint }); }],
    ["same public key across environments under another fingerprint", (m) => { m.environments[1].keys.push({ ...prodKey(m), keyFingerprint: "3".repeat(64) }); }],
    ["notBeforeMs negative", (m) => { prodKey(m).notBeforeMs = -1; }], ["notBeforeMs fractional", (m) => { prodKey(m).notBeforeMs = 1.5; }],
    ["notBeforeMs unsafe", (m) => { prodKey(m).notBeforeMs = Number.MAX_SAFE_INTEGER + 1; }], ["notBeforeMs string", (m) => { prodKey(m).notBeforeMs = "1700000000000"; }],
    ["notBeforeMs null", (m) => { prodKey(m).notBeforeMs = null; }],
    ["notAfterMs equal to notBeforeMs", (m) => { prodKey(m).notAfterMs = prodKey(m).notBeforeMs; }],
    ["notAfterMs before notBeforeMs", (m) => { prodKey(m).notAfterMs = 1; }], ["notAfterMs string", (m) => { prodKey(m).notAfterMs = "1"; }],
  ];
  for (const [label, mutate] of variants) {
    const text = await manifestVariant(mutate);
    assert.notEqual(text, JSON.stringify(JSON.parse(manifestText), null, 2), label);
    await assert.rejects(parseAuthorityResultTrustManifest(text), /attestation-manifest/u, label);
  }
  // text-level malformations
  const pretty = JSON.stringify(JSON.parse(manifestText), null, 2);
  const textCases: [string, string | Uint8Array][] = [
    ["duplicate top-level member", pretty.replace('"trustEpoch": 1,', '"trustEpoch": 1,\n  "trustEpoch": 1,')],
    ["duplicate key member", pretty.replace('"status": "active",', '"status": "active",\n          "status": "active",')],
    ["duplicate env member", pretty.replace('"environment": "production",', '"environment": "production",\n      "environment": "production",')],
    ["BOM", concat(Uint8Array.from([0xef, 0xbb, 0xbf]), enc.encode(pretty))], ["malformed UTF-8", concat(enc.encode(pretty), Uint8Array.from([0xff]))],
    ["trailing content", pretty + "x"], ["empty", ""], ["truncated", pretty.slice(0, -3)], ["array", "[]"], ["null", "null"],
    ["oversized", " ".repeat(20_000) + pretty], ["float version", pretty.replace('"manifestVersion": 1', '"manifestVersion": 1.0')],
    ["single-line comment", "// x\n" + pretty], ["public key from the authority test: Infinity", pretty.replace('"notAfterMs": null', '"notAfterMs": Infinity')],
  ];
  for (const [label, input] of textCases) await assert.rejects(parseAuthorityResultTrustManifest(input), /attestation-manifest/u, label);
  // one to three keys per environment are fine
  const two = await parseAuthorityResultTrustManifest(await manifestVariant((m) => { m.environments[0].keys.push(thirdKey()); }));
  assert.equal(two.environments[0].keys.length, 2);
  const three = await parseAuthorityResultTrustManifest(await manifestVariant((m) => { m.environments[0].keys.push(thirdKey(), fourthKey()); }));
  assert.equal(three.environments[0].keys.length, 3);
  // a hand-built (never parsed) manifest object is refused
  const { manifest, golden: g } = await load();
  const v = g.vectors[0];
  const handBuilt = JSON.parse(JSON.stringify(manifest)) as AuthorityResultTrustManifest;
  assert.throws(() => selectAttestationTrustKey(handBuilt, statementOf(v), v.verifyAtMs), /attestation-manifest/u);
  await mustReject("hand-built manifest in verify", () => verifyVector(handBuilt, v, enc.encode(v.envelope)), "attestation-manifest");
});

test("trust key selection: environment, epoch, status, validity windows and freshness", async () => {
  const { golden, manifest } = await load();
  const v = golden.vectors[0];
  const bytes = enc.encode(v.envelope);
  const observed = v.tuple[9] as number;
  const statement = statementOf(v);
  assert.equal(selectAttestationTrustKey(manifest, statement, v.verifyAtMs).keyFingerprint, golden.keys.production.fingerprint);
  const verifyWith = async (text: string, nowMs = v.verifyAtMs, target = v, payload: Uint8Array = bytes) => verifyVector(await parseAuthorityResultTrustManifest(text), target, payload, { nowMs });
  // freshness boundaries: age <= 300000, future skew <= 60000
  await verifyVector(manifest, v, bytes, { nowMs: observed + 300_000 });
  await mustReject("age 300001", () => verifyVector(manifest, v, bytes, { nowMs: observed + 300_001 }), "attestation-stale");
  await verifyVector(manifest, v, bytes, { nowMs: observed - 60_000 });
  await mustReject("future skew 60001", () => verifyVector(manifest, v, bytes, { nowMs: observed - 60_001 }), "attestation-stale");
  for (const nowMs of [-1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1, Infinity]) await mustReject(`now ${nowMs}`, () => verifyVector(manifest, v, bytes, { nowMs }));
  // unknown key
  const unknown = setAt(v.tuple, [10], flipHex(golden.keys.production.fingerprint));
  await mustReject("unknown writer key", async () => verifyVector(manifest, v, await resigned(golden, "production", unknown)), "attestation-key");
  // cross-environment key: the statement names the staging fingerprint and is signed by the staging key, but it is a Production statement
  const crossEnv = setAt(v.tuple, [10], golden.keys.staging.fingerprint);
  await mustReject("Production statement signed by staging key", async () => verifyVector(manifest, v, await resigned(golden, "staging", crossEnv)), "attestation-key");
  await mustReject("Production statement claiming Production key, signed by staging key", async () => verifyVector(manifest, v, await resigned(golden, "staging", v.tuple)), "attestation-signature");
  const stagingV = golden.vectors[2];
  const stagingWithProdKey = setAt(stagingV.tuple, [10], golden.keys.production.fingerprint);
  await mustReject("staging statement signed by Production key", async () => verifyVector(manifest, stagingV, await resigned(golden, "production", stagingWithProdKey)), "attestation-key");
  // retired / windows / status
  const retired = await manifestVariant((m) => { m.environments[0].keys.push(thirdKey()); m.environments[0].keys[0].status = "retired"; m.environments[0].keys[0].notAfterMs = observed + 10_000_000; m.environments[0].currentKeyFingerprint = thirdKey().keyFingerprint; });
  await mustReject("retired key", () => verifyWith(retired), "attestation-key");
  const notYet = await manifestVariant((m) => { m.environments[0].keys[0].notBeforeMs = observed + 1; });
  await mustReject("statement observed before notBefore", () => verifyWith(notYet), "attestation-key");
  const atNotBefore = await manifestVariant((m) => { m.environments[0].keys[0].notBeforeMs = observed; });
  await verifyWith(atNotBefore);
  await verifyWith(atNotBefore, observed - 60_000);
  await mustReject("local clock one ms before notBefore - skew", () => verifyWith(atNotBefore, observed - 60_001));
  const expiredAtObserved = await manifestVariant((m) => { m.environments[0].keys[0].notAfterMs = observed; });
  await mustReject("observedAtMs == notAfterMs", () => verifyWith(expiredAtObserved, observed - 1_000), "attestation-key");
  const expiresSoon = await manifestVariant((m) => { m.environments[0].keys[0].notAfterMs = observed + 1; });
  await verifyWith(expiresSoon, observed);
  await mustReject("local clock == notAfterMs", () => verifyWith(expiresSoon, observed + 1), "attestation-key");
  await mustReject("local clock past notAfterMs", () => verifyWith(expiresSoon, observed + 5_000), "attestation-key");
  const finite = await manifestVariant((m) => { m.environments[0].keys[0].notAfterMs = observed + 500_000; });
  await verifyWith(finite);
  // wrong epoch / environment / authority / policy on the manifest side are invalid manifests, never partial
  await assert.rejects(parseAuthorityResultTrustManifest(await manifestVariant((m) => { m.trustEpoch = 2; })), /attestation-manifest/u);
  await assert.rejects(parseAuthorityResultTrustManifest(await manifestVariant((m) => { m.environments[0].authorityId = "production-public-inquiries-v2"; })), /attestation-manifest/u);
  // multiple active keys: any active key may sign, but the statement must name the key that actually signed
  const two = await manifestVariant((m) => { m.environments[0].keys.push(thirdKey()); });
  const thirdPrivate = privateKeyText(RFC.third.seedHex);
  const signedByThird = async (tuple: unknown) => envelopeBytes(tuple, await rawSign(thirdPrivate, tupleMessage(tuple)));
  const claimsThird = setAt(v.tuple, [10], thirdKey().keyFingerprint);
  await verifyWith(two, v.verifyAtMs, v, await signedByThird(claimsThird));
  await mustReject("third key unknown under the original manifest", async () => verifyVector(manifest, v, await signedByThird(claimsThird)), "attestation-key");
  await mustReject("wrong active key: claims first key, signed by third", async () => verifyWith(two, v.verifyAtMs, v, await signedByThird(v.tuple)), "attestation-signature");
  await mustReject("wrong active key: claims third key, signed by first", async () => verifyWith(two, v.verifyAtMs, v, await resigned(golden, "production", claimsThird)), "attestation-signature");
  await mustReject("third key cannot sign for staging", async () => verifyWith(two, stagingV.verifyAtMs, stagingV, await signedByThird(setAt(stagingV.tuple, [10], thirdKey().keyFingerprint))), "attestation-key");
});

// ---------------------------------------------------------------------------------------------------------------------
// Authority-producible state invariants (cryptographic review B1/I4): receipts and snapshots the authority cannot produce
// are rejected at the SEMANTIC layer, before and independently of the signature.
// ---------------------------------------------------------------------------------------------------------------------
type Tuple = unknown[];
const PRODUCTION_ID = ATTESTATION_AUTHORITY_IDS.production;
const STAGING_ID = ATTESTATION_AUTHORITY_IDS.staging;
const edit = (tuple: Tuple, ...changes: [number[], unknown][]): Tuple => changes.reduce((current, [path, value]) => setAt(current, path, value), tuple);

/** The tuple is rejected with exactly `code`, both when validly re-signed and when carrying a stale (wrong) signature:
 * semantic validation precedes the signature check, so a semantic failure can never be mistaken for a signature failure. */
async function semanticReject(label: string, golden: Golden, manifest: AuthorityResultTrustManifest, v: GoldenVector, tuple: Tuple, code: string): Promise<void> {
  await mustReject(`${label} (re-signed)`, async () => verifyVector(manifest, v, await resigned(golden, v.keyRole, tuple)), code);
  await mustReject(`${label} (stale signature)`, () => verifyVector(manifest, v, envelopeBytes(tuple, v.signature)), code);
}
async function accepts(label: string, golden: Golden, manifest: AuthorityResultTrustManifest, v: GoldenVector, tuple: Tuple): Promise<void> {
  const verified = await verifyVector(manifest, v, await resigned(golden, v.keyRole, tuple));
  assert.deepEqual(resultStatementTuple(verified.statement), tuple, label);
  // and the stale-signature copy fails as a signature failure (validation passed, so the signature is the only gate)
  if (JSON.stringify(tuple) !== JSON.stringify(v.tuple)) await mustReject(`${label} (stale signature)`, () => verifyVector(manifest, v, envelopeBytes(tuple, v.signature)), "attestation-signature");
}

test("receipt sequence is exactly 1 for initialize and at least 2 for rotate-release", async () => {
  const { golden, manifest } = await load();
  const [initialize, rotate, , exactRotate, , , , oneRow] = golden.vectors;
  const stagingInit = golden.vectors[2];
  for (const [label, v, at] of [["lifecycle", initialize, [8, 7]], ["staging lifecycle", stagingInit, [8, 7]], ["reconciliation one-row", oneRow, [11, 7]]] as const) {
    for (const sequence of [0, 2, 3, 4_096, 4_097]) await semanticReject(`initialize ${label} sequence ${sequence}`, golden, manifest, v, edit(v.tuple, [[...at], sequence]), "attestation-receipt");
  }
  for (const [label, v, at] of [["lifecycle", rotate, [8, 7]], ["reconciliation", exactRotate, [11, 7]]] as const) {
    await semanticReject(`rotate-release ${label} sequence 1`, golden, manifest, v, edit(v.tuple, [[...at], 1]), "attestation-receipt");
    await semanticReject(`rotate-release ${label} sequence 0`, golden, manifest, v, edit(v.tuple, [[...at], 0]), "attestation-receipt");
    await accepts(`rotate-release ${label} sequence 2`, golden, manifest, v, edit(v.tuple, [[...at], 2]));
    await accepts(`rotate-release ${label} sequence 4096`, golden, manifest, v, edit(v.tuple, [[...at], 4_096]));
    await semanticReject(`rotate-release ${label} sequence 4097`, golden, manifest, v, edit(v.tuple, [[...at], 4_097]), "attestation-receipt");
  }
  // an initialize operation relabelled as rotate-release (and vice versa) cannot keep a coherent receipt
  await semanticReject("initialize relabelled rotate-release", golden, manifest, initialize, edit(initialize.tuple, [[8, 2], "rotate-release"]), "attestation-receipt");
  await semanticReject("rotate-release relabelled initialize", golden, manifest, rotate, edit(rotate.tuple, [[8, 2], "initialize"]), "attestation-receipt");
});

test("appliedMs and activatesMs: |applied - activates| <= 300000, inclusive, symmetric; no stronger ordering", async () => {
  const { golden, manifest } = await load();
  assert.equal(ATTESTATION_MAX_APPLIED_ACTIVATION_SKEW_MS, 300_000);
  const [initialize, rotate] = golden.vectors;
  for (const [label, v] of [["initialize", initialize], ["rotate-release", rotate]] as const) {
    const receipt = v.tuple[8] as number[];
    const activates = receipt[12];
    // applied before activation (activation in the future) and after activation, at and one past the boundary
    for (const [name, applied, ok] of [
      ["applied = activates", activates, true], ["activation 300000 in the future", activates - 300_000, true], ["activation 300001 in the future", activates - 300_001, false],
      ["activation 300000 in the past", activates + 300_000, true], ["activation 300001 in the past", activates + 300_001, false],
      ["activation 1 in the future", activates - 1, true], ["activation 1 in the past", activates + 1, true],
    ] as const) {
      const tuple = edit(v.tuple, [[8, 8], applied]);
      if (ok) await accepts(`${label} ${name}`, golden, manifest, v, tuple);
      else await semanticReject(`${label} ${name}`, golden, manifest, v, tuple, "attestation-receipt");
    }
  }
  // moving activatesMs instead of appliedMs gives the same relation (rotate keeps retires - activates in (0, 300000])
  const receipt = rotate.tuple[8] as number[];
  const applied = receipt[8];
  await accepts("rotate activates = applied + 300000", golden, manifest, rotate, edit(rotate.tuple, [[8, 12], applied + 300_000], [[8, 13], applied + 400_000]));
  await semanticReject("rotate activates = applied + 300001", golden, manifest, rotate, edit(rotate.tuple, [[8, 12], applied + 300_001], [[8, 13], applied + 400_000]), "attestation-receipt");
  await accepts("rotate activates = applied - 300000", golden, manifest, rotate, edit(rotate.tuple, [[8, 12], applied - 300_000], [[8, 13], applied - 200_000]));
  await semanticReject("rotate activates = applied - 300001", golden, manifest, rotate, edit(rotate.tuple, [[8, 12], applied - 300_001], [[8, 13], applied - 200_000]), "attestation-receipt");
  // The same relation holds inside a reconciliation receipt.
  const exact = golden.vectors[3];
  const exactReceipt = exact.tuple[11] as number[];
  await semanticReject("reconciliation receipt applied 300001 past activates", golden, manifest, exact, edit(exact.tuple, [[11, 8], exactReceipt[12] + 300_001]), "attestation-receipt");
});

test("observedAtMs earlier than receipt.appliedMs is deliberately NOT rejected (source does not prove the ordering)", async () => {
  const { golden, manifest } = await load();
  const initialize = golden.vectors[0];
  const observed = initialize.tuple[9] as number;
  const receipt = initialize.tuple[8] as number[];
  // appliedMs after observedAtMs, still within 300000 of activatesMs: accepted, bound only by the signature
  await accepts("observed before applied", golden, manifest, initialize, edit(initialize.tuple, [[8, 8], observed + 1_000]));
  assert.ok(observed + 1_000 - receipt[12] <= 300_000);
  const exact = golden.vectors[3];
  await accepts("reconciliation observed before applied", golden, manifest, exact, edit(exact.tuple, [[11, 8], (exact.tuple[13] as number) + 1_000]));
});

test("staging rotate-release is rejected by protocol decision; Production rotate remains valid", async () => {
  const { golden, manifest } = await load();
  const [, rotate, , exact] = golden.vectors;
  await verifyVector(manifest, rotate, enc.encode(rotate.envelope));
  await verifyVector(manifest, exact, enc.encode(exact.envelope));
  const stagingExpectations = (v: GoldenVector): ResultAttestationExpectations => ({ ...v.expectations, environment: "staging", authorityId: STAGING_ID });
  const toStaging = (tuple: Tuple, receiptAt: number): Tuple => edit(tuple, [[2], "staging"], [[3], STAGING_ID], [[receiptAt, 3], "staging"], [[receiptAt, 4], STAGING_ID],
    [[tuple.length - 1], golden.keys.staging.fingerprint]);
  const stagingRotate: GoldenVector = { ...rotate, keyRole: "staging", expectations: stagingExpectations(rotate) };
  const stagingExact: GoldenVector = { ...exact, keyRole: "staging", expectations: stagingExpectations(exact) };
  await semanticReject("staging rotate-release lifecycle", golden, manifest, stagingRotate, toStaging(rotate.tuple, 8), "attestation-receipt");
  await semanticReject("staging reconciliation EXACT_RECEIPT of a rotate-release", golden, manifest, stagingExact, toStaging(exact.tuple, 11), "attestation-receipt");
  // construction-time: no signer can even build one
  const lifecycleInput = clone(rotate.input) as unknown as LifecycleStatementInput;
  assert.throws(() => makeLifecycleStatement({ ...lifecycleInput, environment: "staging", authorityId: STAGING_ID, writerKeyFingerprint: golden.keys.staging.fingerprint,
    receipt: { ...lifecycleInput.receipt, environment: "staging", authorityId: STAGING_ID } }), /^Error: attestation-receipt$/u);
  // staging initialize remains valid
  await verifyVector(manifest, golden.vectors[2], enc.encode(golden.vectors[2].envelope));
});

test("one-row EXACT_RECEIPT means no rotation ever happened; two-row snapshots stay decoupled from the receipt", async () => {
  const { golden, manifest } = await load();
  const stagingOne = golden.vectors[7];
  const exactRotate = golden.vectors[3];
  // A Production one-row EXACT_RECEIPT of an initialization (same shape as the staging golden, retargeted).
  const productionOne: GoldenVector = { ...stagingOne, keyRole: "production", expectations: { ...stagingOne.expectations, environment: "production", authorityId: PRODUCTION_ID } };
  const prodTuple = edit(stagingOne.tuple, [[2], "production"], [[3], PRODUCTION_ID], [[11, 3], "production"], [[11, 4], PRODUCTION_ID], [[14], golden.keys.production.fingerprint]);
  await accepts("production one-row initialize", golden, manifest, productionOne, prodTuple);
  await verifyVector(manifest, stagingOne, enc.encode(stagingOne.envelope));
  const row = (prodTuple[12] as unknown[][])[0];
  const receipt = prodTuple[11] as unknown[];
  assert.deepEqual([row[0], row[1], row[2], row[3]], [receipt[10], receipt[11], receipt[12], null]);
  const cases: [string, Tuple, string][] = [
    ["row releaseId differs from receipt.nextReleaseId", edit(prodTuple, [[12, 0, 0], "release-other"]), "attestation-statement"],
    ["row keyId differs from receipt.nextKeyId", edit(prodTuple, [[12, 0, 1], "key_other"]), "attestation-statement"],
    ["row activatedMs differs from receipt.activatesMs (+1)", edit(prodTuple, [[12, 0, 2], (row[2] as number) + 1]), "attestation-statement"],
    ["row activatedMs differs from receipt.activatesMs (-1)", edit(prodTuple, [[12, 0, 2], (row[2] as number) - 1]), "attestation-statement"],
    ["receipt.nextKeyId differs from the row", edit(prodTuple, [[11, 11], "key_other"]), "attestation-statement"],
    ["receipt.activatesMs differs from the row", edit(prodTuple, [[11, 12], (receipt[12] as number) + 1]), "attestation-statement"],
    ["receipt release ids both differ from the row", edit(prodTuple, [[11, 9], "release-other"], [[11, 10], "release-other"]), "attestation-statement"],
    ["the single row is retired", edit(prodTuple, [[12, 0, 3], (row[2] as number) + 1]), "attestation-releases"],
  ];
  for (const [label, tuple, code] of cases) await semanticReject(`one-row ${label}`, golden, manifest, productionOne, tuple, code);
  // A one-row snapshot of a rotation: a valid rotate-release receipt whose snapshot dropped the retired row.
  const rotateRows = exactRotate.tuple[12] as unknown[][];
  assert.equal(rotateRows[0][3] !== null && rotateRows[1][3] === null, true);
  await semanticReject("one-row snapshot with a rotate-release receipt", golden, manifest, exactRotate, edit(exactRotate.tuple, [[12], [rotateRows[1]]]), "attestation-statement");
  // Two-row snapshots keep the historical/current distinction: the receipt is NOT tied to either row.
  await accepts("two rows, receipt next release absent from the snapshot", golden, manifest, exactRotate,
    edit(exactRotate.tuple, [[11, 10], "release-historic"], [[11, 11], "key_historic"]));
  await accepts("two rows, snapshot rows unrelated to the receipt", golden, manifest, exactRotate,
    edit(exactRotate.tuple, [[12, 0, 0], "release-x"], [[12, 0, 1], "key_x"], [[12, 1, 0], "release-y"], [[12, 1, 1], "key_y"]));
  // Receipt-less states are not constrained by this rule.
  await verifyVector(manifest, golden.vectors[4], enc.encode(golden.vectors[4].envelope));
});

// ---------------------------------------------------------------------------------------------------------------------
// Ed25519 public-key safety (cryptographic review I2). The test-side curve arithmetic is deliberately independent of the
// implementation: affine formulas, Euler-criterion square roots.
// ---------------------------------------------------------------------------------------------------------------------
const FIELD = (1n << 255n) - 19n;
const fmod = (value: bigint) => ((value % FIELD) + FIELD) % FIELD;
function fpow(base: bigint, exponent: bigint): bigint {
  let result = 1n; let square = fmod(base);
  for (let e = exponent; e > 0n; e >>= 1n) { if (e & 1n) result = fmod(result * square); square = fmod(square * square); }
  return result;
}
const finv = (value: bigint) => fpow(value, FIELD - 2n);
const EDWARDS_D = fmod(-121665n * finv(121666n));
type Affine = readonly [bigint, bigint];
const AFFINE_IDENTITY: Affine = [0n, 1n];
function affineAdd(a: Affine, b: Affine): Affine {
  const t = fmod(EDWARDS_D * a[0] * b[0] * a[1] * b[1]);
  return [fmod((a[0] * b[1] + b[0] * a[1]) * finv(1n + t)), fmod((a[1] * b[1] + a[0] * b[0]) * finv(1n - t))];
}
function affineEncode([x, y]: Affine): Uint8Array {
  const out = new Uint8Array(32);
  let value = y | ((x & 1n) << 255n);
  for (let i = 0; i < 32; i += 1) { out[i] = Number(value & 0xffn); value >>= 8n; }
  return out;
}
/** Returns the point, or null if y is not a curve y-coordinate. Callers pass canonical y (< p). */
function affineDecode(raw: Uint8Array): Affine | null {
  let value = 0n;
  for (let i = 31; i >= 0; i -= 1) value = (value << 8n) | BigInt(raw[i]);
  const y = value & ((1n << 255n) - 1n);
  const sign = value >> 255n;
  const y2 = fmod(y * y);
  const x2 = fmod((y2 - 1n) * finv(fmod(EDWARDS_D * y2 + 1n)));
  let x = fpow(x2, (FIELD + 3n) / 8n);
  if (fmod(x * x) !== x2) { if (fmod(x * x) !== fmod(-x2)) return null; x = fmod(x * fpow(2n, (FIELD - 1n) / 4n)); }
  if ((x & 1n) !== sign) x = fmod(-x);
  return [x, y];
}
const affineEquals = (a: Affine, b: Affine) => a[0] === b[0] && a[1] === b[1];
function affineScale(point: Affine, scalar: number): Affine { let out = AFFINE_IDENTITY; for (let i = 0; i < scalar; i += 1) out = affineAdd(out, point); return out; }

// The eight small-order points of edwards25519 (canonical encodings, hex).
const SMALL_ORDER_HEX = {
  "identity (order 1)": "0100000000000000000000000000000000000000000000000000000000000000",
  "(0,-1) (order 2)": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "(sqrt(-1),0) (order 4)": "0000000000000000000000000000000000000000000000000000000000000000",
  "(-sqrt(-1),0) (order 4)": "0000000000000000000000000000000000000000000000000000000000000080",
  "order 8 A": "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "order 8 B": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "order 8 C": "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "order 8 D": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
} as const;
const NON_CANONICAL_IDENTITY_HEX = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
const unsafeText = (raw: Uint8Array) => encodeBase64url(raw);

test("Ed25519 public-key safety: small-order, torsion and non-canonical keys are rejected; RFC and generated keys pass", async () => {
  const { golden } = await load();
  // The reference list really is the torsion subgroup (checked with independent arithmetic).
  const smallOrder = Object.entries(SMALL_ORDER_HEX).map(([name, hex]) => ({ name, raw: fromHex(hex), point: affineDecode(fromHex(hex)) }));
  const orders: number[] = [];
  for (const { name, point } of smallOrder) {
    assert.ok(point, name);
    const order = [1, 2, 4, 8].find((candidate) => affineEquals(affineScale(point, candidate), AFFINE_IDENTITY));
    assert.ok(order, `${name} has small order`);
    orders.push(order);
  }
  assert.deepEqual(orders.sort((a, b) => a - b), [1, 2, 4, 4, 8, 8, 8, 8]);
  const rejects = async (label: string, raw: Uint8Array) => {
    assert.throws(() => assertSafeEd25519PublicKey(raw), /^Error: attestation-key-material$/u, label);
    await assert.rejects(importAttestationPublicKey(unsafeText(raw)), /^Error: attestation-key-material$/u, label);
  };
  for (const { name, raw } of smallOrder) await rejects(name, raw);
  // every y >= p non-canonical alias, with both sign bits
  for (let alias = 0n; alias < 19n; alias += 1n) {
    for (const signBit of [0n, 1n]) {
      let value = (FIELD + alias) | (signBit << 255n);
      const raw = new Uint8Array(32);
      for (let i = 0; i < 32; i += 1) { raw[i] = Number(value & 0xffn); value >>= 8n; }
      await rejects(`non-canonical y = p + ${alias}, sign ${signBit}`, raw);
    }
  }
  await rejects("all 0xff", new Uint8Array(32).fill(0xff));
  await rejects("0xff ... 0x7f", Uint8Array.from({ length: 32 }, (_v, i) => (i === 31 ? 0x7f : 0xff)));
  await rejects("all zero", new Uint8Array(32));
  // Not a curve point: y values whose x^2 is a non-residue (found by the independent decoder).
  let offCurve = 0;
  for (let y = 2n; offCurve < 5 && y < 400n; y += 1n) {
    const raw = affineEncode([0n, y]);
    if (affineDecode(raw) === null) { await rejects(`off-curve y = ${y}`, raw); offCurve += 1; }
  }
  assert.equal(offCurve, 5);
  // Mixed order: a valid prime-order key plus a non-trivial torsion point is rejected too (it is not a clean key).
  const accepted: Uint8Array[] = Object.values(RFC).map((key) => fromHex(key.publicHex));
  for (const raw of accepted) {
    const base = affineDecode(raw)!;
    for (const { name, point } of smallOrder) {
      if (affineEquals(point!, AFFINE_IDENTITY)) continue;
      const mixed = affineAdd(base, point!);
      assert.ok(!affineEquals(mixed, base));
      await rejects(`RFC key + ${name}`, affineEncode(mixed));
    }
  }
  // Positives: the four RFC 8032 test keys, the base point, the negated RFC key, and fresh generated keys.
  for (const raw of accepted) { assertSafeEd25519PublicKey(raw); await importAttestationPublicKey(unsafeText(raw)); }
  assertSafeEd25519PublicKey(Uint8Array.from({ length: 32 }, (_v, i) => (i === 0 ? 0x58 : 0x66)));
  const first = affineDecode(accepted[0])!;
  const negated = affineEncode([fmod(-first[0]), first[1]]);
  assert.notDeepEqual([...negated], [...accepted[0]]);
  assertSafeEd25519PublicKey(negated);
  for (let i = 0; i < 20; i += 1) {
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    await importAttestationPublicKey(unsafeText(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))));
  }
  assert.throws(() => assertSafeEd25519PublicKey(new Uint8Array(31)), /attestation-key-material/u);
  assert.throws(() => assertSafeEd25519PublicKey(new Uint8Array(33)), /attestation-key-material/u);
  assert.equal(golden.keys.production.publicKeyHex, RFC.production.publicHex);
});

test("identity-point forgery: a trust manifest cannot carry the key, and signature verification refuses it", async () => {
  const { golden, manifestText } = await load();
  const identity = fromHex(SMALL_ORDER_HEX["identity (order 1)"]);
  const v = golden.vectors[0];
  // The reviewer's forgery: public key = identity encoding, signature = identity encoding || 32 zero bytes, over ANY message.
  const forgedSignature = encodeBase64url(concat(identity, new Uint8Array(32)));
  const forgedEnvelope = parseResultAttestationEnvelope(envelopeBytes(edit(v.tuple, [[10], sha256Hex(identity)]), forgedSignature));
  const zeroSignatureEnvelope = parseResultAttestationEnvelope(envelopeBytes(v.tuple, encodeBase64url(new Uint8Array(64))));
  const unsafeKeys = [...Object.entries(SMALL_ORDER_HEX), ["non-canonical identity", NON_CANONICAL_IDENTITY_HEX] as const];
  for (const [label, hex] of unsafeKeys) {
    assert.equal(await verifyAttestationSignature(forgedEnvelope, unsafeText(fromHex(hex))), false, `forged signature under ${label}`);
    assert.equal(await verifyAttestationSignature(zeroSignatureEnvelope, unsafeText(fromHex(hex))), false, `zero signature under ${label}`);
  }
  // the manifest that would trust such a key never parses, whatever fingerprint it claims
  for (const [label, hex] of unsafeKeys) {
    const text = await manifestVariant((m) => {
      const fingerprint = sha256Hex(fromHex(hex));
      m.environments[0].keys[0].publicKey = unsafeText(fromHex(hex));
      m.environments[0].keys[0].keyFingerprint = fingerprint;
      m.environments[0].currentKeyFingerprint = fingerprint;
    });
    await assert.rejects(parseAuthorityResultTrustManifest(text), /^Error: attestation-manifest$/u, label);
  }
  // a safe key in the same position parses (control)
  await parseAuthorityResultTrustManifest(manifestText);
});

// ---------------------------------------------------------------------------------------------------------------------
// Verified type, R07 composition boundary, signer snapshot, transport, manifest hygiene
// ---------------------------------------------------------------------------------------------------------------------
test("R06 verification returns an opaque branded result that is never Production positive acceptance", async () => {
  const { golden, manifest } = await load();
  const trustModule = await import("../src/lib/authority-result-trust");
  const attestationModule = await import("../src/lib/authority-result-attestation");
  for (const v of golden.vectors) {
    const verified = await verifyVector(manifest, v, enc.encode(v.envelope));
    assert.equal(isVerifiedAuthorityStatement(verified), true);
    assert.equal(Object.isFrozen(verified), true);
    assert.equal(Object.isFrozen(verified.statement), true);
    const receipt = (verified.statement as { receipt?: object | null }).receipt;
    if (receipt) assert.equal(Object.isFrozen(receipt), true);
    assert.equal(verified.layer, "R06-authority-signature");
    assert.equal(verified.acceptance, "NOT-PRODUCTION-POSITIVE-ACCEPTANCE");
    assert.equal(verified.signingKeyFingerprint, golden.keys[v.keyRole].fingerprint);
    assert.equal(verified.verifiedAtMs, v.verifyAtMs);
    assert.deepEqual(verified.expectations, v.expectations);
    assert.deepEqual(resultStatementTuple(verified.statement), v.tuple);
    // an unverified parsed statement, a hand-built literal and a copy of a verified result are not verified
    assert.equal(isVerifiedAuthorityStatement(parseResultAttestationEnvelope(enc.encode(v.envelope)).statement), false);
    assert.equal(isVerifiedAuthorityStatement(statementOf(v)), false);
    assert.equal(isVerifiedAuthorityStatement({ ...verified }), false);
    assert.equal(isVerifiedAuthorityStatement(structuredClone({ ...verified, statement: v.input })), false);
  }
  // type level: neither a statement nor a literal is assignable to the verified type (enforced by `npm run typecheck`)
  const sample = statementOf(golden.vectors[0]);
  // @ts-expect-error a parsed, unverified statement is not a VerifiedAuthorityStatement
  const unverifiedAsVerified: VerifiedAuthorityStatement = sample;
  // @ts-expect-error a structurally similar literal cannot forge the module-private brand
  const literalAsVerified: VerifiedAuthorityStatement = { layer: "R06-authority-signature", acceptance: "NOT-PRODUCTION-POSITIVE-ACCEPTANCE", statement: sample, signingKeyFingerprint: "", verifiedAtMs: 0, expectations: golden.vectors[0].expectations };
  assert.equal(isVerifiedAuthorityStatement(unverifiedAsVerified), false);
  assert.equal(isVerifiedAuthorityStatement(literalAsVerified), false);
  for (const value of [null, undefined, 0, "x", {}, [], Object.freeze({ layer: "R06-authority-signature" })]) assert.equal(isVerifiedAuthorityStatement(value), false);
  // R07 composition is documented as data and not implemented here
  assert.deepEqual([...PRODUCTION_POSITIVE_ACCEPTANCE_REQUIRES], ["verified-r06-authority-statement", "authenticated-r07-command-derived-expectation", "field-by-field-command-receipt-equality"]);
  // no API in either module is named or typed as final positive acceptance, and the old statement-returning name is gone
  const names = [...Object.keys(trustModule), ...Object.keys(attestationModule)];
  assert.equal(names.includes("verifyResultAttestation"), false);
  assert.deepEqual(names.filter((name) => /accept|positive/iu.test(name) && name !== "PRODUCTION_POSITIVE_ACCEPTANCE_REQUIRES"), []);
});

test("the signer snapshots the statement once: later mutation of a caller object cannot change what is signed or returned", async () => {
  const { golden, manifest } = await load();
  const v = golden.vectors[0];
  const key = golden.keys.production;
  const mutable = { ...statementOf(v) } as unknown as { observedAtMs: number; digest: string };
  assert.equal(Object.isFrozen(mutable), false);
  const pending = signResultAttestation(mutable as unknown as ResultStatement, { privateKey: key.privateKeyPkcs8, publicKey: key.publicKey });
  // mutate synchronously after the call started, before any await resolves
  mutable.observedAtMs += 123_456;
  mutable.digest = flipHex(mutable.digest);
  const envelope = await pending;
  assert.equal(envelope.signature, v.signature, "signature is over the original validated bytes");
  assert.deepEqual(resultStatementTuple(envelope.statement), v.tuple);
  assert.equal(Object.isFrozen(envelope.statement), true);
  assert.notEqual(envelope.statement as unknown, mutable);
  await verifyVector(manifest, v, encodeResultAttestationEnvelope(envelope));
  // an invalid mutable statement is refused before anything is signed
  await assert.rejects(signResultAttestation({ ...mutable, digest: "nope" } as unknown as ResultStatement, { privateKey: key.privateKeyPkcs8, publicKey: key.publicKey }), /attestation-statement/u);
  // verification also reads the statement once
  const unfrozen = { statement: { ...statementOf(v) } as ResultStatement, signature: v.signature };
  const verifying = verifyAttestationSignature(unfrozen, key.publicKey);
  (unfrozen.statement as unknown as { observedAtMs: number }).observedAtMs += 1;
  assert.equal(await verifying, true, "verified exactly the statement that was passed in at call time");
});

test("canonical envelope bytes must be relayed unchanged", async () => {
  const { golden, manifest } = await load();
  for (const v of golden.vectors) {
    const original = enc.encode(v.envelope);
    await verifyVector(manifest, v, original);
    await verifyVector(manifest, v, Uint8Array.from(original));
    assert.deepEqual([...encodeResultAttestationEnvelope(parseResultAttestationEnvelope(original))], [...original]);
    const parsed = JSON.parse(v.envelope) as { statement: unknown; signature: string };
    // semantically identical, byte-different forms are all refused
    for (const [label, text] of [
      ["pretty-printed", JSON.stringify(parsed, null, 2)], ["tab indented", JSON.stringify(parsed, null, "\t")], ["trailing newline", v.envelope + "\n"],
      ["CRLF terminated", v.envelope + "\r\n"], ["members swapped", JSON.stringify({ signature: parsed.signature, statement: parsed.statement })],
      ["unicode-escaped character", v.envelope.replace(/"([a-z])/u, (_m, c: string) => `"\\u00${c.charCodeAt(0).toString(16)}`)],
    ] as const) {
      await mustReject(`${v.name} ${label}`, () => verifyVector(manifest, v, enc.encode(text)), "attestation-envelope");
    }
  }
});

test("trust manifest hygiene: UTF-8 byte size, distinct placeholders, current-key and retired-key semantics", async () => {
  const { golden, manifestText } = await load();
  const pretty = JSON.stringify(JSON.parse(manifestText), null, 2);
  const bytes = (text: string) => enc.encode(text).length;
  const pad = (target: number) => pretty + " ".repeat(target - bytes(pretty));
  await parseAuthorityResultTrustManifest(pad(16_384));
  await assert.rejects(parseAuthorityResultTrustManifest(pad(16_385)), /attestation-manifest/u);
  await parseAuthorityResultTrustManifest(enc.encode(pad(16_384)));
  await assert.rejects(parseAuthorityResultTrustManifest(enc.encode(pad(16_385))), /attestation-manifest/u);
  // multi-byte text is measured in bytes, not UTF-16 code units: 9000 two-byte characters are 18000 bytes in 9000 units
  const multibyte = "é".repeat(9_000);
  assert.ok(multibyte.length <= 16_384 && bytes(multibyte) > 16_384);
  await assert.rejects(parseAuthorityResultTrustManifest(multibyte), /attestation-manifest/u);
  // Production and staging placeholders are distinct and unmistakable
  const template = await readFile(new URL("../deployment/authority-result-trust.template.json", import.meta.url), "utf8");
  const sections = (JSON.parse(template) as ManifestJson).environments;
  const placeholders: string[][] = sections.map((section) => JSON.stringify(section).match(/__REQUIRED_[A-Z0-9_]+__/gu) ?? []);
  assert.equal(placeholders[0].length, placeholders[1].length);
  assert.ok(placeholders[0].length >= 4);
  assert.deepEqual(placeholders[0].filter((entry) => placeholders[1].includes(entry)), []);
  for (const entry of placeholders[0]) assert.match(entry, /^__REQUIRED_PRODUCTION_[A-Z0-9_]+__$/u);
  for (const entry of placeholders[1]) assert.match(entry, /^__REQUIRED_STAGING_[A-Z0-9_]+__$/u);
  // currentKeyFingerprint selects the signer's key only: verification accepts any ACTIVE listed key, including a non-current one
  const v = golden.vectors[0];
  const two = await parseAuthorityResultTrustManifest(await manifestVariant((m) => { m.environments[0].keys.push(thirdKey()); m.environments[0].currentKeyFingerprint = thirdKey().keyFingerprint; }));
  assert.equal(two.environments[0].currentKeyFingerprint, thirdKey().keyFingerprint);
  assert.equal((await verifyVector(two, v, enc.encode(v.envelope))).signingKeyFingerprint, golden.keys.production.fingerprint, "non-current active key still verifies");
  // retired means immediately non-verifiable even though notAfterMs is far in the future
  const observed = v.tuple[9] as number;
  const retired = await parseAuthorityResultTrustManifest(await manifestVariant((m) => {
    m.environments[0].keys.push(thirdKey()); m.environments[0].currentKeyFingerprint = thirdKey().keyFingerprint;
    m.environments[0].keys[0].status = "retired"; m.environments[0].keys[0].notAfterMs = observed + 10 ** 9;
  }));
  await mustReject("retired key with a distant notAfterMs", () => verifyVector(retired, v, enc.encode(v.envelope)), "attestation-key");
});

// ---------------------------------------------------------------------------------------------------------------------
// Scope guards
// ---------------------------------------------------------------------------------------------------------------------
test("the protocol is wired only into the inert Slice 2A Authority producer, and ships no operational key material", async () => {
  const root = new URL("../", import.meta.url);
  const own = new Set(["src/lib/authority-result-attestation.ts", "src/lib/authority-result-trust.ts", "tests/authority-result-attestation.test.ts"]);
  // Slice 2A: the only files that may reference the frozen protocol besides itself. Everything else (relay, mailbox, observer,
  // result writer/reader, CLI, deployment, public routes) must not reference it yet.
  const producer = new Set(["workers/admission-service/authority-attestation.ts", "workers/admission-service/authority-attestation-signer.ts",
    "tests/i3b-authority.test.ts", "tests/support/authority-attestation-test-signers.ts"]);
  // Slice 2B: the inert verifier/composition side. Exactly this module and its focused test may consume the frozen protocol
  // (the module through the verifier API, the test through the signing helpers); nothing active may.
  const composition = new Set(["operator/authority-result-verifier.ts", "tests/authority-result-verifier.test.ts"]);
  // Pre-2C transport gate: a local-workerd-only harness and its integration test push the real Slice 2A attested results across a
  // real RPC boundary. Test-only: no wrangler config other than wrangler.attestation-rpc-transport.local.jsonc names the harness.
  const transportGate = new Set(["workers/attestation-rpc-transport-harness.ts", "tests/workers/attestation-rpc-transport.integration.ts"]);
  // The producer's own surface: no other file may import the producer modules or invoke the attested Authority RPCs.
  const producerSurface = new Set([...producer, ...transportGate, "workers/admission-service/index.ts"]);
  const offenders: string[] = [];
  const producerLeaks: string[] = [];
  for (const directory of ["src", "workers", "operator", "scripts", "deployment", "tests"]) {
    for (const entry of await readdir(new URL(directory, root), { recursive: true })) {
      const name = entry.replaceAll("\\", "/");
      const relative = `${directory}/${name}`;
      if (own.has(relative) || !/\.(ts|tsx|mts|js|mjs|json|jsonc)$/u.test(name) || name.includes("fixtures/")) continue;
      const text = await readFile(new URL(relative, root), "utf8");
      if (/authority-result-(attestation|trust)/u.test(text) && !producer.has(relative) && !composition.has(relative) && !transportGate.has(relative)) offenders.push(relative);
      if (/authority-attestation|FromOperatorAttested|attestAppliedLifecycle|attestReconciliation|AuthorityAttestationCoordinator/u.test(text) &&
          !producerSurface.has(relative)) producerLeaks.push(relative);
    }
  }
  assert.deepEqual(offenders, []);
  assert.deepEqual(producerLeaks, [], "no relay/mailbox/observer/CLI/result caller imports or invokes the attested Authority RPCs");
  // The Authority-side producer never learns the relay layer: it imports only the frozen protocol, the authority core and the command module.
  for (const file of ["workers/admission-service/authority-attestation.ts", "workers/admission-service/authority-attestation-signer.ts"]) {
    const imports = [...(await readFile(new URL(file, root), "utf8")).matchAll(/from "([^"]+)"/gu)].map((match) => match[1]);
    for (const specifier of imports) {
      assert.match(specifier, /^(?:\.\.\/\.\.\/src\/lib\/(?:authority-result-attestation|ingress-protocol)|\.\/(?:authority|operator-command|authority-attestation-signer))$/u, `${file} imports ${specifier}`);
    }
  }
  // the only private key material in the fixtures is the two public RFC 8032 test seeds
  const { golden, manifestText } = await load();
  const fixtureText = JSON.stringify(golden);
  for (const match of fixtureText.matchAll(/"(?:seedHex|privateKeyPkcs8)":"([^"]+)"/gu)) {
    assert.ok([RFC.production.seedHex, RFC.staging.seedHex, privateKeyText(RFC.production.seedHex), privateKeyText(RFC.staging.seedHex)].includes(match[1]));
  }
  assert.doesNotMatch(manifestText, /seed|private|pkcs8/iu);
});

// ---------------------------------------------------------------------------------------------------------------------
// Final review revision: staging snapshot coherence, two-row overlap bound, plain-array canonicalization, signer snapshot
// ---------------------------------------------------------------------------------------------------------------------
type Env = "production" | "staging";
/** Retargets a reconciliation vector to `env` (outer identity, receipt identity, writer key, expectations). */
function retarget(golden: Golden, v: GoldenVector, env: Env): { vector: GoldenVector; tuple: Tuple } {
  const authorityId = ATTESTATION_AUTHORITY_IDS[env];
  const changes: [number[], unknown][] = [[[2], env], [[3], authorityId], [[14], golden.keys[env].fingerprint]];
  if (v.tuple[11] !== null) changes.push([[11, 3], env], [[11, 4], authorityId]);
  return { vector: { ...v, keyRole: env, expectations: { ...v.expectations, environment: env, authorityId } }, tuple: edit(v.tuple, ...changes) };
}

test("staging initialized snapshots carry exactly one release row in every row-bearing state", async () => {
  const { golden, manifest } = await load();
  const T0 = golden.baseTimeMs;
  // A source-coherent extra retired row: activated before the unretired row, overlap 60000.
  const retiredRow = ["release-2025-12", "key_2025_12", T0 - 200_000, T0 - 40_000];
  const withRetired = (tuple: Tuple) => edit(tuple, [[12], [retiredRow, ...(tuple[12] as unknown[])]]);
  const cases: [string, GoldenVector][] = [
    ["EXACT_RECEIPT", golden.vectors[7]],           // staging golden, one row
    ["HISTORY_INCOMPLETE", golden.vectors[6]],      // staging golden, one row
    ["initialized NOT_FOUND", golden.vectors[4]],   // Production golden, one row (retargeted)
  ];
  for (const [status, source] of cases) {
    const staging = retarget(golden, source, "staging");
    const production = retarget(golden, source, "production");
    // one row: valid in both environments
    await (source.keyRole === "staging" ? verifyVector(manifest, staging.vector, enc.encode(source.envelope)) : accepts(`staging one-row ${status}`, golden, manifest, staging.vector, staging.tuple));
    if (source.keyRole === "production") await verifyVector(manifest, source, enc.encode(source.envelope));
    else await accepts(`production one-row ${status}`, golden, manifest, production.vector, production.tuple);
    // two rows: staging rejects, the identical Production snapshot is accepted
    await semanticReject(`staging two-row ${status}`, golden, manifest, staging.vector, withRetired(staging.tuple), "attestation-releases");
    await accepts(`production two-row ${status}`, golden, manifest, production.vector, withRetired(production.tuple));
  }
  // the Production two-row goldens stay valid, and the same snapshots retargeted to staging are rejected
  for (const v of [golden.vectors[3], golden.vectors[8]]) {
    await verifyVector(manifest, v, enc.encode(v.envelope));
    const staging = retarget(golden, v, "staging");
    // vector 3 carries a rotate-release receipt, which staging already rejects; strip to a receipt-less state to isolate the row rule
    const tuple = v.tuple[11] === null ? staging.tuple : edit(staging.tuple, [[10], "NOT_FOUND"], [[11], null]);
    await semanticReject(`staging two-row copy of ${v.name}`, golden, manifest, staging.vector, tuple, "attestation-releases");
  }
  // uninitialized staging NOT_FOUND with [] is preserved
  const uninitialized = retarget(golden, golden.vectors[5], "staging");
  await accepts("staging uninitialized NOT_FOUND", golden, manifest, uninitialized.vector, uninitialized.tuple);
  // construction-time: no signer can build a staging two-row snapshot
  const stagingInput = clone(golden.vectors[6].input) as unknown as ReconciliationStatementInput;
  const row = stagingInput.releases[0];
  assert.throws(() => makeReconciliationStatement({ ...stagingInput, releases: [row, { releaseId: "release-2025-12", keyId: "key_2025_12", activatedMs: row.activatedMs - 100_000, retiredMs: row.activatedMs + 60_000 }] }),
    /^Error: attestation-releases$/u);
});

test("two-row snapshots: 0 < retired.retiredMs - unretired.activatedMs <= 300000, exact boundaries", async () => {
  const { golden, manifest } = await load();
  // vector 3: retired row first; vector 8: activatedMs tie, retired row second
  for (const [v, retiredAt, unretiredAt] of [[golden.vectors[3], 0, 1], [golden.vectors[8], 1, 0]] as const) {
    const rows = v.tuple[12] as unknown[][];
    assert.equal(rows[retiredAt][3] !== null && rows[unretiredAt][3] === null, true);
    const activated = rows[unretiredAt][2] as number;
    const at = (overlap: number) => edit(v.tuple, [[12, retiredAt, 3], activated + overlap]);
    await accepts(`${v.name} overlap 1`, golden, manifest, v, at(1));
    await accepts(`${v.name} overlap 300000`, golden, manifest, v, at(300_000));
    await semanticReject(`${v.name} overlap 300001`, golden, manifest, v, at(300_001), "attestation-releases");
    await semanticReject(`${v.name} overlap 0`, golden, manifest, v, at(0), "attestation-releases");
    await semanticReject(`${v.name} overlap 86400000 (excessive)`, golden, manifest, v, at(86_400_000), "attestation-releases");
    await semanticReject(`${v.name} overlap 2^40 (excessive)`, golden, manifest, v, at(2 ** 40), "attestation-releases");
  }
  // construction-time boundary
  const input = clone(golden.vectors[8].input) as unknown as ReconciliationStatementInput;
  const withOverlap = (overlap: number) => ({ ...input, releases: input.releases.map((row) => (row.retiredMs === null ? row : { ...row, retiredMs: row.activatedMs + overlap })) });
  makeReconciliationStatement(withOverlap(300_000));
  assert.throws(() => makeReconciliationStatement(withOverlap(300_001)), /^Error: attestation-releases$/u);
});

// --- plain-array canonicalization probes ------------------------------------------------------------------------------
const EVIL_ROW = ["release-EVIL", "key_evil", 1, null];
/** An Array subclass whose serialization substitutes a well-formed but unvalidated row. */
class EvilJsonArray<T> extends Array<T> {
  toJSON(): unknown { return [EVIL_ROW]; }
}
/** An Array subclass whose `map`/`filter` results are EvilJsonArray (Symbol.species). */
class SpeciesArray<T> extends Array<T> {
  static override get [Symbol.species](): ArrayConstructor { return EvilJsonArray as unknown as ArrayConstructor; }
}
function asSubclass<T>(Kind: new () => T[], items: readonly T[]): T[] {
  const out = new Kind();
  for (const item of items) out.push(item);
  return out;
}
function withOwn<T extends object>(target: T, key: PropertyKey, value: unknown): T {
  Object.defineProperty(target, key, { value, enumerable: false, configurable: true, writable: true });
  return target;
}
/** A plain-looking array whose index 0 is an accessor: valid on the first read, `release-EVIL` afterwards. */
function flippingGetterArray(items: readonly unknown[], evil: unknown): unknown[] {
  const out = [...items];
  let reads = 0;
  Object.defineProperty(out, 0, { get: () => (reads++ === 0 ? items[0] : evil), enumerable: true, configurable: true });
  return out;
}

test("signing and encoding never emit bytes the validator did not see (Array subclass / toJSON / species / accessors)", async () => {
  const { golden, manifest } = await load();
  const v = golden.vectors[8]; // two-row Production snapshot
  const key = golden.keys.production;
  const keys = { privateKey: key.privateKeyPkcs8, publicKey: key.publicKey };
  const base = statementOf(v) as Extract<ResultStatement, { kind: "reconciliation" }>;
  const plainRows = base.releases.map((row) => ({ ...row }));
  const evilRowObject = { releaseId: "release-EVIL", keyId: "key_evil", activatedMs: 1, retiredMs: null };
  const releaseVariants: [string, unknown][] = [
    ["Array subclass with toJSON (review regression: replace a validated row with release-EVIL)", asSubclass(EvilJsonArray, plainRows)],
    ["Symbol.species subclass", asSubclass(SpeciesArray, plainRows)],
    ["plain array with own toJSON", withOwn([...plainRows], "toJSON", () => [evilRowObject])],
    ["plain array with own constructor (species via instance)", withOwn([...plainRows], "constructor", SpeciesArray)],
    ["plain array with symbol key", withOwn([...plainRows], Symbol("x"), 1)],
    ["plain array with extra named property", withOwn([...plainRows], "extra", 1)],
    ["accessor at index 0", flippingGetterArray(plainRows, evilRowObject)],
    ["sparse array", (() => { const a: unknown[] = []; a[1] = plainRows[1]; a.length = 2; return a; })()],
    ["array with a foreign prototype", Object.setPrototypeOf([...plainRows], Object.create(Array.prototype))],
  ];
  const signedEvil = (bytes: Uint8Array) => new TextDecoder().decode(bytes).includes("release-EVIL");
  for (const [label, releases] of releaseVariants) {
    const statement = { ...base, releases } as unknown as ResultStatement;
    // every byte-producing entry point refuses; nothing containing release-EVIL is ever produced or signed
    await assert.rejects(signResultAttestation(statement, keys), /^Error: attestation-releases$/u, `sign: ${label}`);
    assert.throws(() => canonicalStatementBytes(statement), /^Error: attestation-releases$/u, `canonical: ${label}`);
    assert.throws(() => attestationSigningBytes(statement), /^Error: attestation-releases$/u, `signing bytes: ${label}`);
    assert.throws(() => resultStatementTuple(statement), /^Error: attestation-releases$/u, `tuple: ${label}`);
    assert.throws(() => snapshotResultStatement(statement), /^Error: attestation-releases$/u, `snapshot: ${label}`);
    assert.throws(() => encodeResultAttestationEnvelope({ statement, signature: v.signature }), /^Error: attestation-releases$/u, `envelope: ${label}`);
    assert.equal(await verifyAttestationSignature({ statement, signature: v.signature }, key.publicKey), false, `verify: ${label}`);
    // the constructor refuses the same releases array as input (never adopts it)
    assert.throws(() => makeReconciliationStatement({ ...(clone(v.input) as unknown as ReconciliationStatementInput), releases: releases as AttestationReleaseRowList }),
      /^Error: attestation-releases$/u, `constructor: ${label}`);
  }
  // row-level: a row that is not a plain record (class instance / inherited toJSON) is refused
  const rowVariants: [string, unknown][] = [
    ["row with inherited toJSON", Object.assign(Object.create({ toJSON: () => evilRowObject }) as object, plainRows[0])],
    ["row with own toJSON", { ...plainRows[0], toJSON: () => evilRowObject }],
    ["row accessor", Object.defineProperty({ ...plainRows[0] }, "releaseId", { get: () => "release-EVIL", enumerable: true })],
  ];
  for (const [label, row] of rowVariants) {
    const statement = { ...base, releases: [row, plainRows[1]] } as unknown as ResultStatement;
    await assert.rejects(signResultAttestation(statement, keys), /^Error: attestation-releases$/u, `sign: ${label}`);
    assert.throws(() => canonicalStatementBytes(statement), /^Error: attestation-releases$/u, `canonical: ${label}`);
  }
  // receipt-level and statement-level analogues
  const exact = statementOf(golden.vectors[3]) as Extract<ResultStatement, { kind: "reconciliation" }>;
  const receiptVariants: [string, unknown][] = [
    ["receipt with own toJSON", { ...exact.receipt, toJSON: () => ({}) }],
    ["receipt with inherited toJSON", Object.assign(Object.create({ toJSON: () => ({}) }) as object, exact.receipt)],
    ["receipt given as an Array subclass tuple", asSubclass(EvilJsonArray, resultStatementTuple(exact)[11] as unknown[])],
  ];
  for (const [label, receipt] of receiptVariants) {
    const statement = { ...exact, receipt } as unknown as ResultStatement;
    await assert.rejects(signResultAttestation(statement, keys), /^Error: attestation-receipt$/u, `sign: ${label}`);
  }
  for (const [label, statement] of [
    ["statement with own toJSON", { ...base, toJSON: () => ({}) }],
    ["statement with inherited toJSON", Object.assign(Object.create({ toJSON: () => ({}) }) as object, base)],
    ["statement as Array subclass tuple", asSubclass(EvilJsonArray, [...resultStatementTuple(base)])],
  ] as const) {
    await assert.rejects(signResultAttestation(statement as unknown as ResultStatement, keys), /^Error: attestation-statement$/u, `sign: ${label}`);
  }
  for (const [label, envelope] of [
    ["envelope with own toJSON", { statement: base, signature: v.signature, toJSON: () => ({}) }],
    ["envelope with inherited toJSON", Object.assign(Object.create({ toJSON: () => ({}) }) as object, { statement: base, signature: v.signature })],
  ] as const) {
    assert.throws(() => encodeResultAttestationEnvelope(envelope as unknown as { statement: ResultStatement; signature: string }), /^Error: attestation-envelope$/u, label);
  }
  // parseResultStatementTuple: plain arrays only, at every tuple level
  const tuple = [...resultStatementTuple(base)] as unknown[];
  const exactTuple = [...resultStatementTuple(exact)] as unknown[];
  const tupleProbes: [string, unknown, string][] = [
    ["top-level Array subclass", asSubclass(EvilJsonArray, tuple), "attestation-statement"],
    ["top-level species subclass", asSubclass(SpeciesArray, tuple), "attestation-statement"],
    ["top-level own toJSON", withOwn([...tuple], "toJSON", () => []), "attestation-statement"],
    ["receipt tuple subclass", edit(exactTuple, [[11], asSubclass(EvilJsonArray, exactTuple[11] as unknown[])]), "attestation-receipt"],
    ["receipt tuple own toJSON", edit(exactTuple, [[11], withOwn([...(exactTuple[11] as unknown[])], "toJSON", () => [])]), "attestation-receipt"],
    ["releases subclass", edit(tuple, [[12], asSubclass(EvilJsonArray, tuple[12] as unknown[])]), "attestation-releases"],
    ["releases species", edit(tuple, [[12], asSubclass(SpeciesArray, tuple[12] as unknown[])]), "attestation-releases"],
    ["release row subclass", edit(tuple, [[12, 0], asSubclass(EvilJsonArray, (tuple[12] as unknown[][])[0])]), "attestation-releases"],
    ["release row own toJSON", edit(tuple, [[12, 0], withOwn([...(tuple[12] as unknown[][])[0]], "toJSON", () => EVIL_ROW)]), "attestation-releases"],
    ["release row accessor", edit(tuple, [[12, 0], flippingGetterArray((tuple[12] as unknown[][])[0], "release-EVIL")]), "attestation-releases"],
  ];
  for (const [label, value, code] of tupleProbes) assert.throws(() => parseResultStatementTuple(value), new RegExp(`^Error: ${code}$`, "u"), label);
  // sanity: the probes are real (JSON.stringify of the hostile structures would have produced release-EVIL)
  assert.equal(JSON.stringify(asSubclass(EvilJsonArray, plainRows)).includes("release-EVIL"), true);
  assert.equal(JSON.stringify(asSubclass(SpeciesArray, plainRows).map((row) => row)).includes("release-EVIL"), true);
  // and the valid statement still signs to the golden bytes
  const envelope = await signResultAttestation(base, keys);
  assert.equal(envelope.signature, v.signature);
  assert.equal(signedEvil(encodeResultAttestationEnvelope(envelope)), false);
  await verifyVector(manifest, v, encodeResultAttestationEnvelope(envelope));
});
type AttestationReleaseRowList = ReconciliationStatementInput["releases"];

test("proxies cannot split what is validated from what is signed: the snapshot is the only content", async () => {
  const { golden, manifest } = await load();
  const v = golden.vectors[8];
  const key = golden.keys.production;
  const keys = { privateKey: key.privateKeyPkcs8, publicKey: key.publicKey };
  const base = statementOf(v) as Extract<ResultStatement, { kind: "reconciliation" }>;
  const plainRows = base.releases.map((row) => ({ ...row }));
  // [[Get]] lies (what JSON.stringify / naive code would read); own descriptors tell the truth. The module reads descriptors
  // only, so it canonicalizes to the descriptor content: the golden bytes, never release-EVIL.
  const lyingGet = new Proxy([...plainRows], {
    get: (target, property, receiver) => (property === "0" ? { ...plainRows[0], releaseId: "release-EVIL" } : property === "toJSON" ? () => [EVIL_ROW] : Reflect.get(target, property, receiver)),
  });
  const viaGet = await signResultAttestation({ ...base, releases: lyingGet } as unknown as ResultStatement, keys);
  assert.equal(viaGet.signature, v.signature);
  assert.equal(new TextDecoder().decode(encodeResultAttestationEnvelope(viaGet)), v.envelope);
  // Descriptor reads that change between calls: whatever single snapshot is taken is what is validated, signed and returned.
  let reads = 0;
  const flipping = new Proxy([...plainRows], {
    getOwnPropertyDescriptor: (target, property) => {
      const descriptor = Reflect.getOwnPropertyDescriptor(target, property);
      if (property === "0" && descriptor && reads++ > 0) return { ...descriptor, value: { ...plainRows[0], releaseId: "release-EVIL" } };
      return descriptor;
    },
  });
  // The probe must really run: signing succeeds (no swallowed error) and the flip was actually triggered during signing.
  const produced = await signResultAttestation({ ...base, releases: flipping } as unknown as ResultStatement, keys);
  assert.ok(reads >= 2, `the flipping descriptor was not exercised (reads=${reads})`);
  const producedRows = (produced.statement as Extract<ResultStatement, { kind: "reconciliation" }>).releases.map((row) => row.releaseId);
  assert.ok(["release-a", "release-EVIL"].includes(producedRows[0]), `unexpected snapshot row ${producedRows[0]}`);
  const signedText = new TextDecoder().decode(canonicalStatementBytes(produced.statement));
  const rawPublic = await crypto.subtle.importKey("raw", toArrayBuffer(fromHex(key.publicKeyHex)), { name: "Ed25519" }, false, ["verify"]);
  assert.equal(await crypto.subtle.verify("Ed25519", rawPublic, toArrayBuffer(Buffer.from(produced.signature, "base64url")), toArrayBuffer(concat(enc.encode(DOMAIN), enc.encode(signedText)))), true,
    "the signature covers exactly the returned (validated) statement");
  assert.deepEqual(parseResultAttestationEnvelope(encodeResultAttestationEnvelope(produced)).statement, produced.statement);
  assert.equal(Object.isFrozen(produced.statement), true);
  // polluted prototypes: inherited toJSON hooks change nothing (hook-free encoder), and verification still passes
  const restore: (() => void)[] = [];
  const pollute = (target: object) => {
    Object.defineProperty(target, "toJSON", { value: () => [EVIL_ROW], configurable: true, writable: true, enumerable: false });
    restore.push(() => { delete (target as { toJSON?: unknown }).toJSON; });
  };
  let signature = "";
  let envelopeBytesOut: Uint8Array = new Uint8Array();
  let verified = false;
  try {
    pollute(Array.prototype);
    pollute(Object.prototype);
    const polluted = await signResultAttestation(base, keys);
    signature = polluted.signature;
    envelopeBytesOut = encodeResultAttestationEnvelope(polluted);
    verified = isVerifiedAuthorityStatement(await verifyVector(manifest, v, envelopeBytesOut));
  } finally {
    for (const undo of restore) undo();
  }
  assert.equal(signature, v.signature);
  assert.equal(new TextDecoder().decode(envelopeBytesOut), v.envelope);
  assert.equal(verified, true);
});

test("the signer reads the statement once, round-trips the exact wire bytes, and signs only those bytes", async () => {
  const { golden } = await load();
  for (const v of golden.vectors) {
    const key = golden.keys[v.keyRole];
    const source = statementOf(v);
    // count every way the signer could touch the caller object after the snapshot
    const touched: string[] = [];
    let snapshotTaken = false;
    const watched = new Proxy({ ...source } as object, {
      get: (target, property, receiver) => { if (snapshotTaken) touched.push(`get ${String(property)}`); return Reflect.get(target, property, receiver); },
      getOwnPropertyDescriptor: (target, property) => { if (snapshotTaken) touched.push(`descriptor ${String(property)}`); return Reflect.getOwnPropertyDescriptor(target, property); },
    });
    const pending = signResultAttestation(watched as ResultStatement, { privateKey: key.privateKeyPkcs8, publicKey: key.publicKey });
    snapshotTaken = true; // the synchronous part (snapshot, validation, encoding, wire round trip) has completed
    const envelope = await pending;
    assert.deepEqual(touched, [], `${v.name}: caller statement re-read after the snapshot`);
    assert.equal(envelope.signature, v.signature, v.name);
    // the returned envelope encodes to exactly the canonical wire bytes, which the strict parser accepts unchanged
    const wire = encodeResultAttestationEnvelope(envelope);
    assert.equal(new TextDecoder().decode(wire), v.envelope, v.name);
    assert.deepEqual(parseResultAttestationEnvelope(wire).statement, envelope.statement, v.name);
    assert.notEqual(envelope.statement as unknown, source);
    assert.equal(Object.isFrozen(envelope), true);
  }
});

test("verified results: runtime provenance is mandatory; copies typecheck-fail and never verify; deep immutability", async () => {
  const { golden, manifest } = await load();
  for (const v of [golden.vectors[3], golden.vectors[0]]) {
    const verified = await verifyVector(manifest, v, enc.encode(v.envelope));
    assert.equal(isVerifiedAuthorityStatement(verified), true);
    // copies lose verification at runtime
    const spread = { ...verified };
    assert.equal(isVerifiedAuthorityStatement(spread), false);
    assert.equal(isVerifiedAuthorityStatement(Object.assign({}, verified)), false);
    assert.equal(isVerifiedAuthorityStatement(structuredClone(verified)), false);
    assert.equal(isVerifiedAuthorityStatement(JSON.parse(JSON.stringify(verified))), false);
    assert.equal(isVerifiedAuthorityStatement(Object.create(Object.getPrototypeOf(verified) as object)), false);
    // a cast compiles but still fails the runtime check: consumers MUST call isVerifiedAuthorityStatement
    assert.equal(isVerifiedAuthorityStatement(spread as unknown as VerifiedAuthorityStatement), false);
    // type level: a spread copy is not assignable (ES-private brand is not copied by spread); enforced by `npm run typecheck`
    // @ts-expect-error a spread copy is not a VerifiedAuthorityStatement
    const spreadAsVerified: VerifiedAuthorityStatement = { ...verified };
    assert.equal(isVerifiedAuthorityStatement(spreadAsVerified), false);
    // deep immutability of the verified result
    const frozenDeep = (value: unknown): boolean => typeof value !== "object" || value === null ||
      (Object.isFrozen(value) && Object.values(value).every(frozenDeep));
    assert.equal(Object.isFrozen(verified), true);
    assert.equal(frozenDeep(verified.statement), true);
    assert.equal(frozenDeep(verified.expectations), true);
    assert.throws(() => { (verified as unknown as { verifiedAtMs: number }).verifiedAtMs = 0; }, TypeError);
  }
});

test("trust-key selection decides on a validated snapshot, never on repeated reads of a caller statement", async () => {
  const { golden, manifest } = await load();
  const v = golden.vectors[0];
  const statement = statementOf(v);
  const observed = statement.observedAtMs;
  const staleNow = observed + 300_001;
  assert.throws(() => selectAttestationTrustKey(manifest, statement, staleNow), /^Error: attestation-stale$/u);
  // Own descriptors carry the real (stale) observedAtMs and are what is validated; [[Get]] lies with a fresh time and an
  // unknown writer key. Selection must follow the validated snapshot.
  const lying = new Proxy({ ...statement } as object, {
    get: (target, property, receiver) => (property === "observedAtMs" ? staleNow : property === "writerKeyFingerprint" ? "f".repeat(64) : Reflect.get(target, property, receiver)),
  }) as ResultStatement;
  assert.throws(() => selectAttestationTrustKey(manifest, lying, staleNow), /^Error: attestation-stale$/u);
  assert.equal(selectAttestationTrustKey(manifest, lying, v.verifyAtMs).keyFingerprint, golden.keys.production.fingerprint);
});

// ---------------------------------------------------------------------------------------------------------------------
// Caller expectations provenance: one own-data snapshot at entry is what is validated, compared and returned
// ---------------------------------------------------------------------------------------------------------------------
test("expectations mutated while verification awaits cannot change what was compared or returned", async () => {
  const { golden, manifest } = await load();
  for (const v of [golden.vectors[0], golden.vectors[3]]) {
    const original = structuredClone(v.expectations);
    const callerOwned = structuredClone(v.expectations) as Record<string, unknown>;
    const pending = verifyAuthoritySignedStatement(enc.encode(v.envelope), callerOwned as unknown as ResultAttestationExpectations, manifest, v.verifyAtMs);
    // The synchronous snapshot has been taken; the signature check is now awaiting. Rewrite the caller's object.
    callerOwned.digest = flipHex(original.digest);
    callerOwned.environment = "staging";
    callerOwned.authorityId = ATTESTATION_AUTHORITY_IDS.staging;
    callerOwned.injected = "after-snapshot";
    const verified = await pending;
    assert.equal(isVerifiedAuthorityStatement(verified), true, v.name);
    assert.deepEqual(verified.expectations, original, `${v.name}: returned expectations are the entry snapshot`);
    assert.notEqual(verified.expectations as unknown, callerOwned);
    assert.equal(verified.statement.digest, original.digest);
    assert.equal(verified.statement.environment, original.environment);
    assert.equal("injected" in verified.expectations, false);
    assert.deepEqual(resultStatementTuple(verified.statement), v.tuple);
  }
});

test("expectations: accessors, extra/missing/symbol keys and inherited values are refused; proxies are read once", async () => {
  const { golden, manifest } = await load();
  const v = golden.vectors[0];
  const bytes = enc.encode(v.envelope);
  const base = v.expectations as Extract<ResultAttestationExpectations, { kind: "lifecycle" }>;
  const reject = (label: string, expectations: unknown) =>
    mustReject(label, () => verifyAuthoritySignedStatement(bytes, expectations as ResultAttestationExpectations, manifest, v.verifyAtMs), "attestation-expectation");
  // A getter that would answer differently on each read is refused without ever being invoked.
  let getterCalls = 0;
  const flippingGetter = { ...base };
  Object.defineProperty(flippingGetter, "digest", { enumerable: true, configurable: true, get: () => (getterCalls++ === 0 ? base.digest : flipHex(base.digest)) });
  await reject("getter-backed digest", flippingGetter);
  assert.equal(getterCalls, 0, "an expectation getter must never be invoked");
  const setterOnly = { ...base };
  Object.defineProperty(setterOnly, "digest", { enumerable: true, configurable: true, set: () => undefined });
  await reject("setter-only digest", setterOnly);
  const accessorPair = { ...base };
  let stored = base.digest;
  Object.defineProperty(accessorPair, "digest", { enumerable: true, configurable: true, get: () => stored, set: (next: string) => { stored = next; } });
  await reject("accessor pair digest", accessorPair);
  // shape
  await reject("extra own key", { ...base, extra: "x" });
  const hiddenExtra = { ...base };
  Object.defineProperty(hiddenExtra, "hidden", { value: "x", enumerable: false });
  await reject("non-enumerable extra own key", hiddenExtra);
  const nonEnumerableField = { ...base };
  Object.defineProperty(nonEnumerableField, "digest", { value: base.digest, enumerable: false });
  await reject("non-enumerable required field", nonEnumerableField);
  const missing: Record<string, unknown> = { ...base };
  delete missing.digest;
  await reject("missing key", missing);
  await reject("symbol key", { ...base, [Symbol("extra")]: "x" });
  await reject("undefined value", { ...base, digest: undefined });
  await reject("array", [base.kind, base.environment, base.authorityId, base.policyEpoch, base.digest]);
  await reject("null", null);
  // inherited values: a non-plain prototype is refused, and a polluted Object.prototype never fills a missing field
  await reject("inherited digest via prototype", Object.assign(Object.create({ digest: base.digest }) as object, missing));
  Object.defineProperty(Object.prototype, "digest", { value: base.digest, configurable: true, writable: true, enumerable: false });
  try { await reject("missing digest with polluted Object.prototype", missing); } finally { delete (Object.prototype as { digest?: unknown }).digest; }
  // a null-prototype record of exactly the fields is accepted
  const nullProto = Object.assign(Object.create(null) as object, base);
  assert.deepEqual((await verifyAuthoritySignedStatement(bytes, nullProto as ResultAttestationExpectations, manifest, v.verifyAtMs)).expectations, base);
  // Proxy with lying [[Get]]: never consulted; the own descriptors are what is compared and returned.
  let proxyGets = 0;
  const lyingGet = new Proxy({ ...base }, { get: (target, property, receiver) => { proxyGets += 1; return property === "digest" ? flipHex(base.digest) : Reflect.get(target, property, receiver) as unknown; } });
  const viaLyingGet = await verifyAuthoritySignedStatement(bytes, lyingGet, manifest, v.verifyAtMs);
  assert.equal(proxyGets, 0, "the expectations proxy [[Get]] must never be used");
  assert.deepEqual(viaLyingGet.expectations, base);
  // Proxy whose descriptors flip between reads: each is read exactly once, so compared == returned.
  const descriptorReads = new Map<string, number>();
  const flippingDescriptor = new Proxy({ ...base }, {
    getOwnPropertyDescriptor: (target, property) => {
      const count = (descriptorReads.get(String(property)) ?? 0) + 1;
      descriptorReads.set(String(property), count);
      const descriptor = Reflect.getOwnPropertyDescriptor(target, property);
      return property === "digest" && count > 1 && descriptor ? { ...descriptor, value: flipHex(base.digest) } : descriptor;
    },
  });
  const viaFlipping = await verifyAuthoritySignedStatement(bytes, flippingDescriptor, manifest, v.verifyAtMs);
  assert.equal(descriptorReads.get("digest"), 1, "each expectation descriptor is read exactly once");
  assert.equal(viaFlipping.expectations.digest, base.digest);
  assert.equal(viaFlipping.statement.digest, viaFlipping.expectations.digest);
  // A proxy whose traps throw fails closed as an expectation error.
  await reject("throwing ownKeys trap", new Proxy({ ...base }, { ownKeys: () => { throw new Error("trap"); } }));
});

test("verified expectations are a frozen module-owned snapshot, unaffected by later caller mutation", async () => {
  const { golden, manifest } = await load();
  for (const v of [golden.vectors[0], golden.vectors[3]]) {
    const callerOwned = structuredClone(v.expectations) as Record<string, unknown>;
    const verified = await verifyAuthoritySignedStatement(enc.encode(v.envelope), callerOwned as unknown as ResultAttestationExpectations, manifest, v.verifyAtMs);
    assert.equal(Object.isFrozen(verified.expectations), true);
    assert.notEqual(verified.expectations as unknown, callerOwned);
    assert.equal(Object.getPrototypeOf(verified.expectations), Object.prototype);
    callerOwned.digest = flipHex(v.expectations.digest);
    delete callerOwned.kind;
    assert.deepEqual(verified.expectations, v.expectations, v.name);
    assert.throws(() => { (verified.expectations as unknown as { digest: string }).digest = "x"; }, TypeError);
    assert.equal(verified.expectations.digest, v.expectations.digest);
  }
});
