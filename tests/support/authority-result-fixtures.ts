import { readFile } from "node:fs/promises";
import {
  attestationReceiptFromLifecycleReceipt,
  encodeResultAttestationEnvelope,
  makeLifecycleStatement,
  makeReconciliationStatement,
  signResultAttestation,
  type AttestationReceipt,
  type AttestationReleaseRow,
  type ResultStatement,
} from "../../src/lib/authority-result-attestation";
import { parseAuthorityResultTrustManifest, type AuthorityResultTrustManifest } from "../../src/lib/authority-result-trust";
import { encodeBase64url } from "../../src/lib/ingress-protocol";
import { authenticateSealedLifecycleArtifact, type AuthenticatedLifecycleCommand } from "../../operator/lifecycle-submitter";
import { STAGING_GATE7_CONTINUITY } from "../../operator/staging-gate7-continuity";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID, type LifecycleReceipt } from "../../workers/admission-service/authority";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION,
  signAuthorityInitializationCommand,
  signAuthorityReleaseRotationCommand,
  type AuthorityInitializationCommand,
  type AuthorityReleaseRotationCommand,
} from "../../workers/admission-service/operator-command";

/**
 * Shared fixtures for the R06 Slice 2C reader/CLI/workerd tests. Signing keys are ONLY the RFC 8032 test vectors frozen in
 * tests/fixtures/authority-result-attestation-v2.golden.json (TEST KEYS - NEVER PROVISION); the trust manifest is the frozen test
 * manifest. Nothing here is imported by any active runtime source (a source guard pins that).
 */
export type Role = "production" | "staging";
interface RfcKey { privateKeyPkcs8: string; publicKey: string; fingerprint: string }

let keysPromise: Promise<Record<Role, RfcKey>> | undefined;
export const rfcKeys = () => (keysPromise ??= readFile(new URL("../fixtures/authority-result-attestation-v2.golden.json", import.meta.url), "utf8")
  .then((value) => (JSON.parse(value) as { keys: Record<Role, RfcKey> }).keys));
let manifestPromise: Promise<AuthorityResultTrustManifest> | undefined;
export const trustManifest = () => (manifestPromise ??= readFile(new URL("../fixtures/authority-result-trust-v1.test.json", import.meta.url), "utf8")
  .then(parseAuthorityResultTrustManifest));
export const trustManifestText = () => readFile(new URL("../fixtures/authority-result-trust-v1.test.json", import.meta.url), "utf8");

export const authorityIds = { production: ADMISSION_AUTHORITY_ID, staging: STAGING_ADMISSION_AUTHORITY_ID } as const;
export const text = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
export const NONCE = "0123456789abcdef0123456789abcdef";
export const OTHER_NONCE = "fedcba9876543210fedcba9876543210";

export async function operatorKey() {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  return { privateKey: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))),
    publicKey: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))) };
}

export async function sign(role: Role, statement: ResultStatement): Promise<Uint8Array> {
  const key = (await rfcKeys())[role];
  return encodeResultAttestationEnvelope(await signResultAttestation(statement, { privateKey: key.privateKeyPkcs8, publicKey: key.publicKey }));
}
export const writer = async (role: Role) => (await rfcKeys())[role].fingerprint;

/** Fixtures whose timeline is anchored at `now`: commands issued at now-2s, applied at now-2s+4s, observed at now-1s. */
export function fixturesAt(now: number) {
  const ISSUED = now - 2_000;
  const OBSERVED = now - 1_000;
  const init = (release = "release-a", key = "key-a"): AuthorityInitializationCommand =>
    [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, release, key, ISSUED, true];
  const rotation = (): AuthorityReleaseRotationCommand =>
    [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "release-a", "release-b", "key-b",
      ISSUED, ISSUED + 60_000, ISSUED, true];
  async function sealedArtifact(operator: { privateKey: string }, which: "initialize" | "rotate-release", release = "release-a"): Promise<Uint8Array> {
    if (which === "initialize") { const command = init(release); return text({ command, signature: await signAuthorityInitializationCommand(command, operator.privateKey) }); }
    const command = rotation();
    return text({ command, signature: await signAuthorityReleaseRotationCommand(command, operator.privateKey) });
  }
  async function authenticated(operator: { privateKey: string; publicKey: string }, which: "initialize" | "rotate-release" = "initialize", release = "release-a") {
    return authenticateSealedLifecycleArtifact(await sealedArtifact(operator, which, release), operator.publicKey);
  }
  function receiptFor(command: AuthenticatedLifecycleCommand, over: Partial<AttestationReceipt> = {}): AttestationReceipt {
    const sequence = command.expected.operation === "initialize" ? 1 : 2;
    return { ...attestationReceiptFromLifecycleReceipt({ ...command.expected, sequence, appliedMs: ISSUED + 4_000 } as LifecycleReceipt), ...over };
  }
  function snapshotFor(receipt: AttestationReceipt): AttestationReleaseRow[] {
    const next: AttestationReleaseRow = { releaseId: receipt.nextReleaseId, keyId: receipt.nextKeyId, activatedMs: receipt.activatesMs, retiredMs: null };
    return receipt.operation === "initialize" ? [next]
      : [{ releaseId: receipt.currentReleaseId, keyId: "key-previous", activatedMs: receipt.activatesMs - 100_000, retiredMs: receipt.retiresMs }, next];
  }
  async function lifecycle(role: Role, receipt: AttestationReceipt, observedAtMs = OBSERVED, digest = receipt.digest) {
    return sign(role, makeLifecycleStatement({ trustEpoch: 1, environment: role, authorityId: authorityIds[role], policyEpoch: ADMISSION_POLICY_EPOCH as "phase5c-i1-epoch-1",
      digest, receipt: { ...receipt, digest }, observedAtMs, writerKeyFingerprint: await writer(role) }));
  }
  async function reconciliation(role: Role, state: "EXACT_RECEIPT" | "NOT_FOUND" | "HISTORY_INCOMPLETE", digest: string, receipt: AttestationReceipt | null,
    options: { nonce?: string; observedAtMs?: number; releases?: AttestationReleaseRow[] } = {}) {
    const common = { trustEpoch: 1 as const, environment: role, authorityId: authorityIds[role], policyEpoch: ADMISSION_POLICY_EPOCH as "phase5c-i1-epoch-1", digest,
      nonce: options.nonce ?? NONCE, observedAtMs: options.observedAtMs ?? OBSERVED, writerKeyFingerprint: await writer(role) };
    const rows = options.releases ?? (receipt ? snapshotFor(receipt) : [{ releaseId: "release-a", keyId: "key-a", activatedMs: ISSUED, retiredMs: null }]);
    if (state === "EXACT_RECEIPT") return sign(role, makeReconciliationStatement({ ...common, initialized: true, coverage: "COMPLETE", status: "EXACT_RECEIPT", receipt, releases: rows }));
    if (state === "NOT_FOUND") return sign(role, makeReconciliationStatement({ ...common, initialized: true, coverage: "COMPLETE", status: "NOT_FOUND", receipt: null, releases: rows }));
    return sign(role, makeReconciliationStatement({ ...common, initialized: true, coverage: "INCOMPLETE", status: "HISTORY_INCOMPLETE", receipt: null, releases: rows }));
  }
  // Gate 7 canonical staging evidence, anchored just after the pinned appliedMs.
  const gate7Receipt = (over: Partial<AttestationReceipt> = {}): AttestationReceipt =>
    ({ ...attestationReceiptFromLifecycleReceipt(STAGING_GATE7_CONTINUITY.receipt as unknown as LifecycleReceipt), ...over });
  const gate7Release = (): AttestationReleaseRow => ({ releaseId: "staging-gate7-initial", keyId: "staging-gate7-key-1", activatedMs: 1790251978099, retiredMs: null });
  return { ISSUED, OBSERVED, init, rotation, sealedArtifact, authenticated, receiptFor, snapshotFor, lifecycle, reconciliation, gate7Receipt, gate7Release };
}
