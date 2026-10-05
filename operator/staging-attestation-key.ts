import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { chmod, lstat, open, realpath, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { attestationKeyFingerprint, isSafeTime } from "../src/lib/authority-result-attestation";
import { decodeCanonicalBase64url, encodeBase64url } from "../src/lib/ingress-protocol";
import { createAuthorityAttestationSigner } from "../workers/admission-service/authority-attestation-signer";
import { isWithin, readBounded, StagingRenderError } from "./staging-config-renderer";
import { assertCustodyProtected, KeyProtectionError } from "./staging-key-protection";
import { parseStrictJson } from "./lifecycle-submitter";
import { STAGING_GATE7_KEY_FINGERPRINT } from "./staging-gate7-continuity";

// R06 activation tooling (T1): local custody of the STAGING Authority-attestation signing key. Local only: this module never opens a
// socket or contacts a provider, and spawns nothing itself (the Windows key-protection check delegates to operator/staging-key-protection.ts,
// which runs two read-only OS tools). The key is the Ed25519 key the staging Authority Durable Object will use to sign
// result statements (workers/admission-service/authority-attestation-config.ts). It is DISTINCT from the Gate 7 operator key: a key
// whose fingerprint equals the pinned operator fingerprint is refused at generation and at every load.
//
// Custody files live in the operator's protected key directory, outside the repository:
//   staging-attestation-private-key.pkcs8.b64url   canonical unpadded base64url RFC 8410 PKCS#8 (48 bytes), no trailing newline
//   staging-attestation-key.meta.json              public facts only: createdAtMs, publicKey, keyFingerprint (never a secret)
// Both are created exclusively (never overwritten). Protection is VERIFIED, not assumed: on POSIX the private file must carry no group/other
// bits; on Windows -- where 0o600 protects nothing -- the NTFS DACL of the directory and the private file must name only SYSTEM,
// Administrators, Creator Owner and the current user (operator/staging-key-protection.ts). Nothing here returns, logs or embeds the private
// key except `readStagingAttestationKeyForSecretPut`, whose sole caller is the closed-set secret engine (operator/staging-attestation-secret-engine.ts;
// pinned structurally by tests/r06-activation-capability-guard.test.ts -- a static CI-time check; the hygiene test is only a textual tripwire).

export const STAGING_ATTESTATION_KEY_DIRECTORY_SEGMENTS = [".limitmark-keys", "staging"] as const;
export const STAGING_ATTESTATION_KEY_FILE = "staging-attestation-private-key.pkcs8.b64url";
export const STAGING_ATTESTATION_META_FILE = "staging-attestation-key.meta.json";
const MAX_KEY_FILE_BYTES = 256;
const MAX_META_BYTES = 1_024;
/** The meta record's creation time may lead the local clock by at most this much (the frozen protocol's own future-skew bound). */
const MAX_CREATED_FUTURE_SKEW_MS = 60_000;

export type StagingAttestationKeyMeta = {
  version: 1;
  environment: "staging";
  purpose: "authority-result-attestation";
  createdAtMs: number;
  publicKey: string;
  keyFingerprint: string;
};
const metaKeys = ["version", "environment", "purpose", "createdAtMs", "publicKey", "keyFingerprint"];

/** Error carrying only a fixed kebab-case code; never a value, path or key byte. */
export class AttestationKeyError extends Error {
  constructor(readonly code: string) { super(code); this.name = "AttestationKeyError"; }
}
const refuse = (code: string): never => { throw new AttestationKeyError(code); };

function mapped<T>(operation: () => Promise<T>, code: string): Promise<T> {
  return operation().catch((error: unknown) => {
    if (error instanceof AttestationKeyError) throw error;
    throw new AttestationKeyError(error instanceof StagingRenderError ? error.code : code);
  });
}

/** Runs the custody-protection check and maps its fixed codes into this module's error type. */
async function protect(directory: string, files: readonly string[]): Promise<void> {
  try { await assertCustodyProtected({ directory, files }); }
  catch (error) { if (error instanceof KeyProtectionError) throw new AttestationKeyError(error.code); throw new AttestationKeyError("custody-protection-unverifiable"); }
}

type Paths = { directory: string; keyPath: string; metaPath: string; realRoot: string };

/** The key directory must already exist, resolve (through symlinks) to a place outside the repository, and is never created here. */
async function resolvePaths(directory: string, repositoryRoot: string): Promise<Paths> {
  let realRoot: string, realDirectory: string;
  try { realRoot = await realpath(repositoryRoot); } catch { return refuse("repository-root-unavailable"); }
  try { realDirectory = await realpath(directory); } catch { return refuse("key-directory-must-already-exist"); }
  if (isWithin(realRoot, realDirectory)) refuse("key-directory-inside-repository");
  return { directory: realDirectory, keyPath: join(realDirectory, STAGING_ATTESTATION_KEY_FILE),
    metaPath: join(realDirectory, STAGING_ATTESTATION_META_FILE), realRoot };
}

type Material = { privateKey: string; publicKey: string; fingerprint: string };

function rawPublicFromPrivate(privateKey: KeyObject): { object: KeyObject; raw: Uint8Array } {
  const object = createPublicKey(privateKey);
  const x = object.export({ format: "jwk" }).x;
  let raw: Uint8Array;
  try { raw = decodeCanonicalBase64url(typeof x === "string" ? x : "", 32); }
  catch { return refuse("public-key-not-canonical-32-byte"); }
  if (encodeBase64url(raw) !== x) refuse("public-key-not-canonical-32-byte");
  return { object, raw };
}

/** Proves, with the exact runtime path the Authority Worker uses (key import, fingerprint pin, sign/verify self-test), that this
 * material would be accepted by a staging signer. */
async function proveSignerAcceptance(material: Material, nowMs: number): Promise<void> {
  try {
    const signer = createAuthorityAttestationSigner({ environment: "staging", writerKeyFingerprint: material.fingerprint,
      privateKey: material.privateKey, publicKey: material.publicKey });
    await signer.ready(nowMs);
  } catch { refuse("signer-self-test-failed"); }
}

async function describeMaterial(privateKeyText: string, nowMs: number, operatorFingerprint: string): Promise<Material> {
  let der: Uint8Array;
  try { der = decodeCanonicalBase64url(privateKeyText, 48); } catch { return refuse("private-key-not-canonical-pkcs8"); }
  let keyObject: KeyObject;
  try { keyObject = createPrivateKey({ key: Buffer.from(der), format: "der", type: "pkcs8" }); } catch { return refuse("private-key-not-pkcs8"); }
  if (keyObject.asymmetricKeyType !== "ed25519") refuse("private-key-not-ed25519");
  const { raw } = rawPublicFromPrivate(keyObject);
  const publicKey = encodeBase64url(raw);
  let fingerprint: string;
  try { fingerprint = await attestationKeyFingerprint(publicKey); } catch { return refuse("public-key-rejected-by-frozen-protocol"); }
  if (fingerprint === operatorFingerprint) refuse("attestation-key-must-differ-from-operator-key");
  const material = { privateKey: privateKeyText, publicKey, fingerprint };
  await proveSignerAcceptance(material, nowMs);
  return material;
}

/** `operatorFingerprint` defaults to the pinned Gate 7 operator key fingerprint; it is a parameter only so a test can prove the refusal. */
export type KeyRequest = { directory: string; repositoryRoot: string; nowMs: number; operatorFingerprint?: string };

export type StagingAttestationKeyPublic = { createdAtMs: number; publicKey: string; keyFingerprint: string };

/** Generates one fresh staging attestation key and writes the two custody files. Never overwrites; on any failure after the private
 * file was created, that file (created exclusively by this call) is removed again so no orphan key remains. */
export async function generateStagingAttestationKey(request: KeyRequest): Promise<StagingAttestationKeyPublic> {
  if (!isSafeTime(request.nowMs)) refuse("clock-unavailable");
  const paths = await resolvePaths(request.directory, request.repositoryRoot);
  // The directory must already be protected BEFORE any key exists in it.
  await protect(paths.directory, []);
  for (const path of [paths.keyPath, paths.metaPath]) {
    try { await lstat(path); refuse("custody-file-already-exists"); }
    catch (error) { if (error instanceof AttestationKeyError) throw error; if ((error as NodeJS.ErrnoException).code !== "ENOENT") refuse("custody-state-unavailable"); }
  }
  const { privateKey } = generateKeyPairSync("ed25519");
  const privateText = encodeBase64url(new Uint8Array(privateKey.export({ format: "der", type: "pkcs8" })));
  const material = await describeMaterial(privateText, request.nowMs, request.operatorFingerprint ?? STAGING_GATE7_KEY_FINGERPRINT);
  const meta: StagingAttestationKeyMeta = { version: 1, environment: "staging", purpose: "authority-result-attestation",
    createdAtMs: request.nowMs, publicKey: material.publicKey, keyFingerprint: material.fingerprint };

  let keyHandle;
  try { keyHandle = await open(paths.keyPath, "wx", 0o600); } catch { return refuse("custody-file-create-failed"); }
  try {
    await keyHandle.writeFile(new TextEncoder().encode(privateText));
    await keyHandle.close();
    try { await chmod(paths.keyPath, 0o600); } catch { /* best-effort; not every platform honours owner-only POSIX bits */ }
    // Verified, not assumed: the file as it now exists. On failure the catch below removes it again, so no unprotected key remains.
    await protect(paths.directory, [paths.keyPath]);
    let metaHandle;
    try { metaHandle = await open(paths.metaPath, "wx", 0o600); } catch { return refuse("custody-file-create-failed"); }
    try { await metaHandle.writeFile(new TextEncoder().encode(`${JSON.stringify(meta, null, 2)}\n`)); await metaHandle.close(); }
    catch { await metaHandle.close().catch(() => {}); await unlink(paths.metaPath).catch(() => {}); return refuse("custody-file-write-failed"); }
  } catch (error) {
    await keyHandle.close().catch(() => {});
    await unlink(paths.keyPath).catch(() => {});
    if (error instanceof AttestationKeyError) throw error;
    return refuse("custody-file-write-failed");
  }
  return { createdAtMs: meta.createdAtMs, publicKey: meta.publicKey, keyFingerprint: meta.keyFingerprint };
}

async function readCustodyFile(path: string, directory: string, name: string, maximum: number, beforeRead?: () => Promise<void>): Promise<Uint8Array> {
  let resolved: string;
  try { resolved = await realpath(path); } catch { return refuse("custody-file-unavailable"); }
  // A symlink at the exact name pointing elsewhere resolves to a different dirname/basename and is refused.
  if (dirname(resolved) !== directory || basename(resolved) !== name) refuse("custody-file-not-exact");
  if (beforeRead) await beforeRead();
  return mapped(() => readBounded(resolved, maximum, "custody-file-size"), "custody-file-unavailable");
}

function parseMeta(bytes: Uint8Array): StagingAttestationKeyMeta {
  let value: unknown;
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    if (text.charCodeAt(0) === 0xfeff) refuse("meta-bom");
    value = parseStrictJson(text);
  } catch (error) { if (error instanceof AttestationKeyError) throw error; return refuse("meta-not-strict-json"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) return refuse("meta-shape");
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== metaKeys.length || !metaKeys.every((key) => Object.hasOwn(record, key))) return refuse("meta-shape");
  if (record.version !== 1 || record.environment !== "staging" || record.purpose !== "authority-result-attestation" ||
      !isSafeTime(record.createdAtMs) || typeof record.publicKey !== "string" || typeof record.keyFingerprint !== "string" ||
      !/^[a-f0-9]{64}$/u.test(record.keyFingerprint)) return refuse("meta-shape");
  return record as unknown as StagingAttestationKeyMeta;
}

async function loadVerified(request: KeyRequest): Promise<{ material: Material; meta: StagingAttestationKeyMeta }> {
  if (!isSafeTime(request.nowMs)) refuse("clock-unavailable");
  const paths = await resolvePaths(request.directory, request.repositoryRoot);
  await protect(paths.directory, []);
  const keyBytes = await readCustodyFile(paths.keyPath, paths.directory, STAGING_ATTESTATION_KEY_FILE, MAX_KEY_FILE_BYTES,
    () => protect(paths.directory, [paths.keyPath]));
  const meta = parseMeta(await readCustodyFile(paths.metaPath, paths.directory, STAGING_ATTESTATION_META_FILE, MAX_META_BYTES));
  let privateText: string;
  try { privateText = new TextDecoder("utf-8", { fatal: true }).decode(keyBytes); } catch { return refuse("private-key-not-canonical-pkcs8"); }
  const material = await describeMaterial(privateText, request.nowMs, request.operatorFingerprint ?? STAGING_GATE7_KEY_FINGERPRINT);
  if (material.publicKey !== meta.publicKey || material.fingerprint !== meta.keyFingerprint) refuse("meta-does-not-match-private-key");
  if (meta.createdAtMs > request.nowMs + MAX_CREATED_FUTURE_SKEW_MS) refuse("meta-created-in-the-future");
  return { material, meta };
}

/** Verifies the custody files and returns PUBLIC facts only (the private key is read, proven, and dropped). */
export async function verifyStagingAttestationKey(request: KeyRequest): Promise<StagingAttestationKeyPublic> {
  const { meta } = await loadVerified(request);
  return { createdAtMs: meta.createdAtMs, publicKey: meta.publicKey, keyFingerprint: meta.keyFingerprint };
}

/** The ONLY function that returns the private key text. Its sole caller is the closed-set secret wrapper, which pipes it to a pinned
 * `wrangler secret put` stdin and never logs it. */
export async function readStagingAttestationKeyForSecretPut(request: KeyRequest):
  Promise<StagingAttestationKeyPublic & { privateKey: string }> {
  const { material, meta } = await loadVerified(request);
  return { createdAtMs: meta.createdAtMs, publicKey: meta.publicKey, keyFingerprint: meta.keyFingerprint, privateKey: material.privateKey };
}
