import assert from "node:assert/strict";
import { test } from "node:test";
import { verifyLifecycleResult } from "../operator/lifecycle-result";

const digest = "a".repeat(64);
const nonce = "b".repeat(32);
const now = 10_000;
const receipt = { digest, version: 1, operation: "initialize", environment: "production", authorityId: "production-public-inquiries-v1",
  policyEpoch: "phase5c-i1-epoch-1", keyFingerprint: "c".repeat(64), sequence: 1, appliedMs: 9_000,
  currentReleaseId: "release-a", nextReleaseId: "release-a", nextKeyId: "key-a", activatesMs: 9_000, retiresMs: null };
const base = { version: 1, digest, environment: "production", authorityId: "production-public-inquiries-v1",
  policyEpoch: "phase5c-i1-epoch-1", observedAtMs: now };
const bytes = (value: object) => new TextEncoder().encode(JSON.stringify(value));

test("only exact positive receipt becomes lifecycle success", () => {
  const result = { ...base, status: "SUCCESS", receipt };
  assert.equal(verifyLifecycleResult(bytes(result), "lifecycle", { digest }, now).status, "SUCCESS");
  assert.throws(() => verifyLifecycleResult(bytes({ ...base, status: "SUCCESS" }), "lifecycle", { digest }, now));
  assert.throws(() => verifyLifecycleResult(bytes({ ...result, receipt: { ...receipt, digest: "d".repeat(64) } }), "lifecycle", { digest }, now));
  assert.throws(() => verifyLifecycleResult(bytes({ ...result, unexpected: true }), "lifecycle", { digest }, now));
  assert.throws(() => verifyLifecycleResult(bytes(result), "lifecycle", { digest: "d".repeat(64) }, now));
});

test("read-only NOT_FOUND and stale observations never prove rollback", () => {
  const observation = { ...base, nonce, status: "NOT_FOUND", initialized: true, coverage: "COMPLETE", receipt: null, releases: [] };
  assert.equal(verifyLifecycleResult(bytes(observation), "reconciliation", { nonce }, now).status, "UNCONFIRMED");
  assert.throws(() => verifyLifecycleResult(bytes(observation), "reconciliation", { nonce: "c".repeat(32) }, now));
  assert.throws(() => verifyLifecycleResult(bytes(observation), "reconciliation", { nonce }, now + 300_001));
  assert.equal(verifyLifecycleResult(bytes({ ...observation, status: "EXACT_RECEIPT", receipt }), "reconciliation", { nonce }, now).status, "SUCCESS");
  for (const status of ["HISTORY_INCOMPLETE", "UNAVAILABLE"] as const)
    assert.equal(verifyLifecycleResult(bytes(status === "UNAVAILABLE" ? { ...base, nonce, status } :
      { ...observation, status, coverage: "INCOMPLETE" }), "reconciliation", { nonce }, now).status,
      "UNCONFIRMED", `${status} cannot justify a replay or settlement`);
});
