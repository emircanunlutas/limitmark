import assert from "node:assert/strict";
import { test } from "node:test";
import {
  GATE6_IAM_TEST_KEY_PATTERN, GATE6_IAM_TEST_MAX_OBJECT_BYTES, GATE6_IAM_TEST_PREFIX,
  gate6IamTestFixtureBody, gate6IamTestKey, gate6IamTestNonce,
} from "../operator/gate6-iam-namespace";
import { processStagingInitializationSlot, processStagingSettlement, type StagingMailboxEnvironment } from "../workers/lifecycle-mailbox/staging-processor";

// F4: the synthetic Gate 6 IAM-test namespace itself, and the structural
// proof that the staging mailbox can never interpret anything under it as a
// lifecycle command.

test("gate6IamTestKey produces a bounded, collision-resistant key distinct from every real lifecycle key shape", () => {
  const nonceA = gate6IamTestNonce();
  const nonceB = gate6IamTestNonce();
  assert.match(nonceA, /^[a-f0-9]{32}$/u);
  assert.notEqual(nonceA, nonceB, "two nonces must not collide in a normal run");
  const key = gate6IamTestKey(nonceA);
  assert.equal(key, `gate6-iam-test/${nonceA}.json`);
  assert.ok(GATE6_IAM_TEST_KEY_PATTERN.test(key));
  const realLifecycleKeys = ["initialize.json", "rotate-release.json", "settle.json", "reconcile.json",
    `lifecycle/${"a".repeat(64)}.json`, `settlement/${"b".repeat(32)}.json`, `reconciliation/${"c".repeat(32)}.json`];
  for (const realKey of realLifecycleKeys) {
    assert.ok(!GATE6_IAM_TEST_KEY_PATTERN.test(realKey), `${realKey} must not match the Gate 6 IAM-test namespace`);
    assert.ok(!realKey.startsWith(GATE6_IAM_TEST_PREFIX));
  }
  assert.ok(!key.startsWith("lifecycle/") && !key.startsWith("settlement/") && !key.startsWith("reconciliation/") &&
    key !== "initialize.json" && key !== "rotate-release.json" && key !== "settle.json" && key !== "reconcile.json");
});

test("gate6IamTestKey rejects a non-nonce input outright", () => {
  for (const bad of ["", "not-hex", "a".repeat(31), "a".repeat(33), "../escape", "initialize"])
    assert.throws(() => gate6IamTestKey(bad));
});

test("gate6IamTestFixtureBody is small, harmless, strict JSON with no lifecycle-shaped fields", () => {
  const nonce = gate6IamTestNonce();
  const bytes = gate6IamTestFixtureBody(nonce, Date.now());
  assert.ok(bytes.byteLength <= GATE6_IAM_TEST_MAX_OBJECT_BYTES);
  const value = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
  assert.deepEqual(Object.keys(value).sort(), ["createdAtMs", "nonce", "purpose", "version"]);
  assert.equal(value.purpose, "gate6-iam-test");
  assert.equal(value.nonce, nonce);
  // Not shaped like a sealed lifecycle artifact ({command, signature}), a
  // control request ({version, digest, nonce}), or a lifecycle/settlement/
  // reconciliation result (which all carry status/environment/authorityId).
  assert.ok(!("command" in value) && !("signature" in value) && !("digest" in value) &&
    !("status" in value) && !("environment" in value) && !("authorityId" in value));
});

test("the staging mailbox only ever requests the two fixed lifecycle keys, never a Gate 6 IAM-test key", async () => {
  const requestedKeys: string[] = [];
  const env: StagingMailboxEnvironment = {
    REQUEST_BUCKET: { async get(key: string) { requestedKeys.push(key); return null; } } as unknown as StagingMailboxEnvironment["REQUEST_BUCKET"],
    RESULT_BUCKET: { async put() { throw new Error("must not be reached: no bytes were ever returned"); } } as unknown as StagingMailboxEnvironment["RESULT_BUCKET"],
    DISPATCH_GUARD: { getByName() { throw new Error("must not be reached: no bytes were ever returned"); } },
  };
  await processStagingInitializationSlot(env);
  await processStagingSettlement(env);
  assert.deepEqual([...requestedKeys].sort(), ["initialize.json", "settle.json"]);
  for (const key of requestedKeys) assert.ok(!GATE6_IAM_TEST_KEY_PATTERN.test(key) && !key.startsWith(GATE6_IAM_TEST_PREFIX));
});
