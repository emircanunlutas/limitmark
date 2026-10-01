import {
  ATTESTATION_AUTHORITY_IDS,
  ATTESTATION_POLICY_EPOCH,
  attestationKeyFingerprint,
  attestationSigningBytes,
  encodeResultAttestationEnvelope,
  importAttestationPublicKey,
  importAttestationTestPrivateKey,
  isLowerHex64,
  isSafeTime,
  parseResultAttestationEnvelope,
  snapshotResultStatement,
  verifyAttestationSignature,
  type AttestationEnvironment,
  type ResultStatement,
} from "../../src/lib/authority-result-attestation";
import { encodeBase64url, toArrayBuffer } from "../../src/lib/ingress-protocol";

/**
 * Authority-side signer for the FROZEN R06 attestation v2 protocol (Slice 2A).
 *
 * This module adds no cryptography of its own. Statement validation, canonical tuple/JSON encoding, the signing domain, the
 * envelope encoder, the strict wire parser and signature verification are the frozen Slice-1 functions; the only things done
 * here are (a) pinning one signer instance to one environment, (b) holding the private key as a non-extractable CryptoKey and
 * (c) sign-then-verify before returning. A signer never looks anything up from a provider or global environment: its key
 * material is handed to the factory by the caller.
 *
 * Key material comes only from the caller (see authority-attestation-config.ts for the active runtime bindings; tests inject the
 * frozen RFC 8032 vectors explicitly). `importAttestationTestPrivateKey` is the frozen protocol's name for the exact 48-byte
 * RFC 8410 PKCS#8 Ed25519 import; it is the same format an operational key uses. No key is provisioned, generated or defaulted here.
 */
export interface AuthorityAttestationSigner {
  /** The one environment this instance may sign for. */
  readonly environment: AttestationEnvironment;
  readonly authorityId: string;
  readonly policyEpoch: typeof ATTESTATION_POLICY_EPOCH;
  /** lowercaseHex(SHA-256(raw writer public key)): the value every statement this signer produces must carry. */
  readonly writerKeyFingerprint: string;
  /** Resolves only when the key material is imported, matches `writerKeyFingerprint` and has passed a sign/verify self-test.
   * `nowMs` is the explicit Authority clock reading at the time readiness is established. Rejects otherwise. */
  ready(nowMs: number): Promise<void>;
  /** Canonical frozen-protocol envelope bytes. Rejects unless `ready` has resolved and the statement is pinned to this signer. */
  sign(statement: ResultStatement): Promise<Uint8Array>;
}

export interface AuthorityAttestationSignerConfig {
  readonly environment: AttestationEnvironment;
  /** The writer-key fingerprint this environment is pinned to (what the trust manifest names). */
  readonly writerKeyFingerprint: string;
  /** Canonical base64url RFC 8410 PKCS#8 Ed25519 private key. */
  readonly privateKey: string;
  /** Canonical base64url raw 32-byte Ed25519 public key. */
  readonly publicKey: string;
}

/** Not an attestation domain: a signature over this can never be mistaken for an attestation signature. */
const SELF_TEST_MESSAGE = new TextEncoder().encode("limitmark:authority-attestation-signer-self-test:v1\0");

function fail(code: string): never { throw new Error(code); }

export function createAuthorityAttestationSigner(config: AuthorityAttestationSignerConfig): AuthorityAttestationSigner {
  // Each caller-supplied field is read exactly once.
  const environment: unknown = config.environment;
  const pinnedFingerprint: unknown = config.writerKeyFingerprint;
  const privateKeyText: unknown = config.privateKey;
  const publicKey: unknown = config.publicKey;
  if ((environment !== "production" && environment !== "staging") || !isLowerHex64(pinnedFingerprint) ||
      typeof privateKeyText !== "string" || typeof publicKey !== "string") fail("attestation-signer-config");
  // The raw private-key text lives only in this closure and is dropped as soon as it has been imported non-extractably.
  let rawPrivateKey: string | null = privateKeyText;
  let keys: { readonly signing: CryptoKey } | null = null;
  let loading: Promise<void> | null = null;

  async function load(): Promise<void> {
    if (rawPrivateKey === null) return fail("attestation-signer-not-ready");
    if (await attestationKeyFingerprint(publicKey as string) !== pinnedFingerprint) fail("attestation-signer-key");
    const verification = await importAttestationPublicKey(publicKey as string);
    const signing = await importAttestationTestPrivateKey(rawPrivateKey);
    const signature = await crypto.subtle.sign("Ed25519", signing, toArrayBuffer(SELF_TEST_MESSAGE));
    if (!await crypto.subtle.verify("Ed25519", verification, signature, toArrayBuffer(SELF_TEST_MESSAGE))) fail("attestation-signer-key");
    keys = Object.freeze({ signing });
    rawPrivateKey = null;
  }

  const signer: AuthorityAttestationSigner = {
    environment,
    authorityId: ATTESTATION_AUTHORITY_IDS[environment],
    policyEpoch: ATTESTATION_POLICY_EPOCH,
    writerKeyFingerprint: pinnedFingerprint,
    async ready(nowMs: number): Promise<void> {
      if (!isSafeTime(nowMs)) fail("attestation-signer-not-ready");
      if (keys) return;
      loading ??= load().finally(() => { loading = null; });
      await loading;
    },
    async sign(statement: ResultStatement): Promise<Uint8Array> {
      const loaded = keys;
      if (!loaded) return fail("attestation-signer-not-ready");
      // One read of the caller-owned statement; everything below uses only this validated, deep-frozen snapshot.
      const snapshot = snapshotResultStatement(statement);
      if (snapshot.environment !== environment || snapshot.authorityId !== ATTESTATION_AUTHORITY_IDS[environment] ||
          snapshot.policyEpoch !== ATTESTATION_POLICY_EPOCH || snapshot.writerKeyFingerprint !== pinnedFingerprint) fail("attestation-signer-statement");
      const signature = encodeBase64url(new Uint8Array(await crypto.subtle.sign("Ed25519", loaded.signing, toArrayBuffer(attestationSigningBytes(snapshot)))));
      const bytes = encodeResultAttestationEnvelope({ statement: snapshot, signature });
      // The exact bytes that would leave this signer must pass the strict wire parser and verify under the pinned public key.
      if (!await verifyAttestationSignature(parseResultAttestationEnvelope(bytes), publicKey as string)) fail("attestation-signer-key");
      return bytes;
    },
  };
  return Object.freeze(signer);
}
