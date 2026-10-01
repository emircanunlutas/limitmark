import type { AttestationEnvironment } from "../../src/lib/authority-result-attestation";
import type { AuthorityAttestationRuntime } from "./authority-attestation";
import { createAuthorityAttestationSigner } from "./authority-attestation-signer";

/**
 * Runtime configuration boundary for the Authority's R06 signer (Slice 2C).
 *
 * The CODE expects these three bindings per environment. Whether they have been PROVISIONED is a separate, later, provider-level
 * gate: nothing in this repository contains an operational key, and no value here is a default, a test key or a fallback.
 *
 *   production  AUTHORITY_ATTESTATION_PRIVATE_KEY          canonical base64url RFC 8410 PKCS#8 Ed25519 private key (SECRET)
 *               AUTHORITY_ATTESTATION_PUBLIC_KEY           canonical base64url raw 32-byte Ed25519 public key
 *               AUTHORITY_ATTESTATION_KEY_FINGERPRINT      lowercase hex SHA-256 of that raw public key: the pin the trust manifest names
 *   staging     AUTHORITY_STAGING_ATTESTATION_PRIVATE_KEY / _PUBLIC_KEY / _KEY_FINGERPRINT   (distinct names, distinct values)
 *
 * All three are delivered through the secret-binding channel (deployment/secret-matrix.json) so no rendered Worker config has to
 * learn them. A Production Authority reads only the production names and a staging Authority only the staging names; if the OTHER
 * environment's signer material is present at all the Authority is misconfigured and is left without a signer.
 *
 * Any absent, empty, non-string or malformed value leaves the Authority without a signer. A signer-less Authority answers every
 * attested operation UNAVAILABLE before it touches storage (see AuthorityAttestationCoordinator.prepareSigner), so a mutation can
 * never commit unless signed evidence could be produced for it. Key import, the public-key/fingerprint pin and the sign/verify
 * self-test run lazily inside `signer.ready()`, again before any storage access.
 */
export const ATTESTATION_SIGNER_BINDINGS = Object.freeze({
  production: Object.freeze({
    privateKey: "AUTHORITY_ATTESTATION_PRIVATE_KEY",
    publicKey: "AUTHORITY_ATTESTATION_PUBLIC_KEY",
    writerKeyFingerprint: "AUTHORITY_ATTESTATION_KEY_FINGERPRINT",
  }),
  staging: Object.freeze({
    privateKey: "AUTHORITY_STAGING_ATTESTATION_PRIVATE_KEY",
    publicKey: "AUTHORITY_STAGING_ATTESTATION_PUBLIC_KEY",
    writerKeyFingerprint: "AUTHORITY_STAGING_ATTESTATION_KEY_FINGERPRINT",
  }),
} as const);

function present(environment: Readonly<Record<string, unknown>>, name: string): string | undefined {
  const value = environment[name];
  return typeof value === "string" && value !== "" ? value : undefined;
}

/** Builds the attestation runtime for one Authority class from its Worker environment. Never throws; never falls back. */
export function authorityAttestationRuntimeFromEnvironment(environment: AttestationEnvironment, workerEnvironment: unknown): AuthorityAttestationRuntime {
  if (typeof workerEnvironment !== "object" || workerEnvironment === null) return {};
  const source = workerEnvironment as Readonly<Record<string, unknown>>;
  const own = ATTESTATION_SIGNER_BINDINGS[environment];
  const other = ATTESTATION_SIGNER_BINDINGS[environment === "production" ? "staging" : "production"];
  try {
    if (Object.values(other).some((name) => present(source, name) !== undefined)) return {};
    const privateKey = present(source, own.privateKey);
    const publicKey = present(source, own.publicKey);
    const writerKeyFingerprint = present(source, own.writerKeyFingerprint);
    if (privateKey === undefined || publicKey === undefined || writerKeyFingerprint === undefined) return {};
    return { signer: createAuthorityAttestationSigner({ environment, writerKeyFingerprint, privateKey, publicKey }) };
  } catch {
    return {};
  }
}
