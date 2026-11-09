import assert from "node:assert/strict";
import test from "node:test";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, LAB_ADMISSION_AUTHORITY_ID, STAGING_ADMISSION_AUTHORITY_ID, inspectLifecycleAuthority } from "../workers/admission-service/authority";
import { AuthorityAttestationCoordinator, type AuthorityAttestationIdentity } from "../workers/admission-service/authority-attestation";
import { createAuthorityAttestationSigner } from "../workers/admission-service/authority-attestation-signer";
import { makeReconciliationStatement } from "../src/lib/authority-result-attestation";
import { generateLabKeyPair } from "../scripts/lab-authority-keygen";

// Probe for the review of `inspectLifecycleAuthority`: an UNKNOWN authority id is labelled environment "production" in the not-found answer. Deterministic, local, disposable.
// Finding: the label is only a presentation default of an informational answer. Every caller passes one of three fixed identities; the one place that puts the label into a SIGNED
// statement (attestReconciliation) is reachable only after the signer matches the coordinator identity, and the statement itself must carry the authority id that belongs to its environment.

const T0 = 1_800_000_000_000; const DIGEST = "a".repeat(64); const NONCE = "b".repeat(32);
const view = (value: unknown): Record<string, unknown> => value as Record<string, unknown>;

test("probe: every id other than the staging and lab ids is classified production, known or not (the default branch)", () => {
  const cases: [string, string][] = [[ADMISSION_AUTHORITY_ID, "production"], [STAGING_ADMISSION_AUTHORITY_ID, "staging"], [LAB_ADMISSION_AUTHORITY_ID, "lab"], ["unknown-authority-v1", "production"], ["", "production"], ["LAB-PUBLIC-INQUIRIES-V1", "production"], ["lab-public-inquiries-v1 ", "production"]];
  for (const [id, label] of cases) {
    const answer = view(inspectLifecycleAuthority(new NodeSqliteDurableStorage(), DIGEST, T0, id));
    assert.deepEqual([answer.environment, answer.authorityId, answer.initialized, answer.status], [label, id, false, "NOT_FOUND"], JSON.stringify(id));
  }
});

test("call path 1: the coordinator's inspection always uses its own frozen identity, and a signer that does not match that identity is refused before any inspection", async () => {
  const operator = generateLabKeyPair(); const attestation = generateLabKeyPair();
  const unknownIdentity = { environment: "production", authorityId: "unknown-authority-v1", policyEpoch: ADMISSION_POLICY_EPOCH } as AuthorityAttestationIdentity;
  const productionSigner = createAuthorityAttestationSigner({ environment: "production", writerKeyFingerprint: attestation.fingerprint, privateKey: attestation.privatePkcs8, publicKey: attestation.publicKey });
  const coordinator = new AuthorityAttestationCoordinator(new NodeSqliteDurableStorage(), unknownIdentity, operator.publicKey, { signer: productionSigner, now: () => T0 });
  const answer = await coordinator.attestReconciliation(DIGEST, NONCE);
  assert.notEqual(answer.status, "ATTESTED", "a coordinator for an unknown authority id never produces an attested statement");
  assert.deepEqual([answer.status, view(answer).reason], ["UNAVAILABLE", "signer-mismatch"]);
});

test("call path 2: a statement that pairs the production label with an unknown authority id is rejected by the statement validator, so the label cannot be laundered into a signed result", () => {
  const input = { trustEpoch: 1, environment: "production", authorityId: "unknown-authority-v1", policyEpoch: ADMISSION_POLICY_EPOCH, digest: DIGEST, nonce: NONCE, initialized: false, coverage: "COMPLETE", status: "NOT_FOUND", receipt: null, releases: [], observedAtMs: T0, writerKeyFingerprint: "c".repeat(64) };
  assert.throws(() => makeReconciliationStatement(input as never));
  assert.throws(() => makeReconciliationStatement({ ...input, authorityId: LAB_ADMISSION_AUTHORITY_ID } as never), /./u, "the lab id with the production label is also refused");
});

test("call path 3: the data-plane default (no expected id) is the Production authority by design, and the lab and staging Durable Objects always pass their own id", () => {
  // inspectLifecycleAuthority(storage, digest) with no id answers as production: that default is how the Production Durable Object calls it
  const answer = view(inspectLifecycleAuthority(new NodeSqliteDurableStorage(), DIGEST, T0));
  assert.deepEqual([answer.environment, answer.authorityId], ["production", ADMISSION_AUTHORITY_ID]);
});
