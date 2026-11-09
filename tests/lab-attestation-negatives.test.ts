import assert from "node:assert/strict";
import test from "node:test";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";
import { ATTESTATION_POLICY_EPOCH, ATTESTATION_TRUST_EPOCH, makeReconciliationStatement } from "../src/lib/authority-result-attestation";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, LAB_ADMISSION_AUTHORITY_ID, STAGING_ADMISSION_AUTHORITY_ID } from "../workers/admission-service/authority";
import { AuthorityAttestationCoordinator, LAB_ATTESTATION_IDENTITY, STAGING_ATTESTATION_IDENTITY } from "../workers/admission-service/authority-attestation";
import { createAuthorityAttestationSigner } from "../workers/admission-service/authority-attestation-signer";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, signAuthorityInitializationCommand, type AuthorityInitializationCommand } from "../workers/admission-service/operator-command";
import { generateLabKeyPair } from "../scripts/lab-authority-keygen";

// The three direct negative tests identified by the authority/attestation group review (test-only; no production file is modified).

const DIGEST = "a".repeat(64); const NONCE = "b".repeat(32); const OBSERVED = 1_760_000_000_000; const FINGERPRINT = "c".repeat(64);
type Environment = "production" | "staging" | "lab";
const AUTHORITY: Record<Environment, string> = { production: ADMISSION_AUTHORITY_ID, staging: STAGING_ADMISSION_AUTHORITY_ID, lab: LAB_ADMISSION_AUTHORITY_ID };
const row = (id: string, retiredMs: number | null) => ({ releaseId: id, keyId: `key-${id}`, activatedMs: OBSERVED - 10_000, retiredMs });
const statement = (environment: Environment, authorityId: string, releases: ReturnType<typeof row>[], initialized = true) => () => makeReconciliationStatement({
  trustEpoch: ATTESTATION_TRUST_EPOCH, environment, authorityId, policyEpoch: ATTESTATION_POLICY_EPOCH, digest: DIGEST, nonce: NONCE, initialized, coverage: "COMPLETE", status: "NOT_FOUND",
  receipt: null, releases, observedAtMs: OBSERVED, writerKeyFingerprint: FINGERPRINT } as never);

test("lab release-row cap is exactly one: one row is a valid initialized lab statement, zero or two are refused, while Production still allows its two-row rotation window", () => {
  assert.doesNotThrow(statement("lab", AUTHORITY.lab, [row("r1", null)]), "one active row");
  assert.throws(statement("lab", AUTHORITY.lab, []), /attestation-releases/u, "initialized without a row");
  assert.throws(statement("lab", AUTHORITY.lab, [row("r1", OBSERVED + 1_000), row("r2", null)]), /attestation-releases/u, "two rows (a rotation window) are not a lab state");
  assert.throws(statement("lab", AUTHORITY.lab, [row("r1", null), row("r2", null)]), /attestation-releases/u, "two active rows");
  assert.throws(statement("lab", AUTHORITY.lab, [row("r1", null)], false), /attestation-releases/u, "uninitialized with a row");
  assert.throws(statement("staging", AUTHORITY.staging, [row("r1", OBSERVED + 1_000), row("r2", null)]), /attestation-releases/u, "staging is also capped at one");
  assert.doesNotThrow(statement("production", AUTHORITY.production, [row("r1", OBSERVED + 1_000), row("r2", null)]), "control: Production keeps its two-row window");
});

test("a lab statement cannot bind to a Production or staging authority id, and no other environment can carry the lab id", () => {
  const releases = [row("r1", null)];
  for (const [environment, authorityId, label] of [
    ["lab", AUTHORITY.production, "lab + production id"], ["lab", AUTHORITY.staging, "lab + staging id"], ["production", AUTHORITY.lab, "production + lab id"], ["staging", AUTHORITY.lab, "staging + lab id"],
    ["lab", "", "lab + empty id"], ["lab", `${AUTHORITY.lab} `, "lab + padded id"], ["lab", AUTHORITY.lab.toUpperCase(), "lab + case variant"],
  ] as const) assert.throws(statement(environment, authorityId, releases), /./u, label);
  for (const environment of ["production", "staging", "lab"] as const) assert.doesNotThrow(statement(environment, AUTHORITY[environment], releases), `control: ${environment} with its own id`);
  assert.throws(statement("laboratory" as never, AUTHORITY.lab, releases), /./u, "unknown environment value");
});

test("a lab coordinator rejects a staging signer (and a staging coordinator rejects a lab signer): the signer must match the coordinator identity before any state is read or signed", async () => {
  const operator = generateLabKeyPair(); const key = generateLabKeyPair();
  const signer = (environment: Environment) => createAuthorityAttestationSigner({ environment, writerKeyFingerprint: key.fingerprint, privateKey: key.privatePkcs8, publicKey: key.publicKey });
  const labCommand: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "lab", LAB_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "lab-release-1", "lab-key-1", OBSERVED, false] as never;
  const stagingCommand: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging", STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "lab-release-1", "lab-key-1", OBSERVED, false] as never;
  for (const [identity, wrongSigner, command] of [[LAB_ATTESTATION_IDENTITY, signer("staging"), labCommand], [STAGING_ATTESTATION_IDENTITY, signer("lab"), stagingCommand]] as const) {
    const storage = new NodeSqliteDurableStorage();
    const coordinator = new AuthorityAttestationCoordinator(storage, identity, operator.publicKey, { signer: wrongSigner, now: () => OBSERVED });
    const answer = await coordinator.initialize(command, await signAuthorityInitializationCommand(command, operator.privatePkcs8));
    assert.notEqual(answer.status, "ATTESTED", `${identity.environment} coordinator with a ${wrongSigner.environment} signer`);
    const reconciliation = await coordinator.attestReconciliation(DIGEST, NONCE);
    assert.deepEqual([reconciliation.status, (reconciliation as { reason?: string }).reason], ["UNAVAILABLE", "signer-mismatch"], `${identity.environment}: reconciliation refused before signing`);
    const lifecycle = await coordinator.attestAppliedLifecycle(DIGEST);
    assert.equal(lifecycle.status === "ATTESTED", false, `${identity.environment}: lifecycle not attested`);
  }
});
