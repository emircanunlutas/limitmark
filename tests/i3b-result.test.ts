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

const environment = "production", authorityId = "production-public-inquiries-v1";
const exact = { ...base, nonce, status: "EXACT_RECEIPT", initialized: true, coverage: "COMPLETE", receipt, releases: [] };
const verify = (value: object, kind: "lifecycle" | "reconciliation", expectedOperation?: "initialize" | "rotate-release") =>
  verifyLifecycleResult(bytes(value), kind, kind === "lifecycle" ? { digest } : { nonce }, now, environment, authorityId, undefined, expectedOperation);

test("expected operation binds every present receipt and omission keeps the generic behavior", () => {
  const lifecycle = { ...base, status: "SUCCESS", receipt };
  const rotation = { ...receipt, operation: "rotate-release" };
  for (const [kind, build] of [["lifecycle", (r: object) => ({ ...lifecycle, receipt: r })],
    ["reconciliation", (r: object) => ({ ...exact, receipt: r })]] as const) {
    assert.equal(verify(build(receipt), kind, "initialize").status, "SUCCESS", `${kind} match`);
    assert.equal(verify(build(rotation), kind, "rotate-release").status, "SUCCESS", `${kind} rotate match`);
    assert.throws(() => verify(build(rotation), kind, "initialize"), /result-contract/u, `${kind} initialize expected, rotate-release receipt`);
    assert.throws(() => verify(build(receipt), kind, "rotate-release"), /result-contract/u, `${kind} rotate-release expected, initialize receipt`);
    assert.equal(verify(build(receipt), kind).status, "SUCCESS", `${kind} omitted, initialize`);
    assert.equal(verify(build(rotation), kind).status, "SUCCESS", `${kind} omitted, rotate-release`);
    assert.throws(() => verify(build({ ...receipt, operation: "other" }), kind), /result-contract/u, `${kind} unknown operation`);
    assert.throws(() => verify(build({ ...receipt, operation: undefined }), kind, "initialize"), /result-contract/u, `${kind} missing operation`);
  }
  // A non-positive lifecycle result still may not carry a contradicting receipt.
  assert.throws(() => verify({ ...base, status: "REFUSED", receipt: { ...receipt, operation: "rotate-release" } }, "lifecycle", "initialize"), /result-contract/u);
  // A malformed expectation never widens acceptance.
  assert.throws(() => verify({ ...base, status: "SUCCESS", receipt }, "lifecycle", "" as "initialize"), /result-contract/u);
  // Receipt-less results are unaffected by the expectation.
  assert.equal(verify({ ...exact, status: "NOT_FOUND", receipt: null }, "reconciliation", "initialize").status, "UNCONFIRMED");
});

test("EXACT_RECEIPT requires initialized true and COMPLETE coverage; other modes keep their shapes", () => {
  for (const operation of ["initialize", "rotate-release"] as const)
    assert.equal(verify({ ...exact, receipt: { ...receipt, operation } }, "reconciliation").status, "SUCCESS", `coherent ${operation}`);
  for (const [name, patch] of [["initialized false", { initialized: false }], ["INCOMPLETE coverage", { coverage: "INCOMPLETE" }],
    ["both", { initialized: false, coverage: "INCOMPLETE" }]] as const)
    assert.throws(() => verify({ ...exact, ...patch }, "reconciliation"), /result-integrity/u, name);
  // Legitimate non-exact states are still accepted, including uninitialized NOT_FOUND and INCOMPLETE history.
  const negative = { ...exact, receipt: null };
  assert.equal(verify({ ...negative, status: "NOT_FOUND", initialized: false }, "reconciliation").status, "UNCONFIRMED");
  assert.equal(verify({ ...negative, status: "NOT_FOUND" }, "reconciliation").status, "UNCONFIRMED");
  assert.equal(verify({ ...negative, status: "HISTORY_INCOMPLETE", coverage: "INCOMPLETE" }, "reconciliation").status, "UNCONFIRMED");
});
