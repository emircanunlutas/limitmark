import assert from "node:assert/strict";
import { test } from "node:test";
import * as lifecycleResult from "../operator/lifecycle-result";
import { classifyUnsignedDiagnostic, commandDerivedReceiptFields, verifySettlementResult } from "../operator/lifecycle-result";
import { unsignedDiagnostic } from "../operator/attested-relay";

// R06 Slice 2C: the unsigned lifecycle/reconciliation verifiers were DELETED. What stays in operator/lifecycle-result.ts is settlement
// verification (guard state, independent of R06), the shared command-derived field list, and a diagnostic classifier that has no
// positive outcome. These tests pin that.

const digest = "a".repeat(64);
const nonce = "b".repeat(32);
const now = 1_790_000_000_000;
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const settlement = (over: Record<string, unknown> = {}) => ({ version: 1, digest, environment: "production", authorityId: "production-public-inquiries-v1",
  policyEpoch: "phase5c-i1-epoch-1", observedAtMs: now, nonce, settled: true, ...over });

test("the unsigned positive verifiers no longer exist", () => {
  assert.deepEqual(Object.keys(lifecycleResult).sort(), ["classifyUnsignedDiagnostic", "commandDerivedReceiptFields", "verifySettlementResult"]);
  assert.equal("verifyLifecycleResult" in lifecycleResult, false);
  assert.equal("verifyProductionLifecycleResult" in lifecycleResult, false);
});

test("settlement: SETTLED / UNCONFIRMED by the guard's own boolean, bound to digest, nonce, environment, authority and a fresh clock", () => {
  assert.deepEqual(verifySettlementResult(encode(settlement()), { digest, nonce }, now), { status: "SETTLED", digest, nonce });
  assert.deepEqual(verifySettlementResult(encode(settlement({ settled: false })), { digest, nonce }, now), { status: "UNCONFIRMED", digest, nonce });
  const contract = (error: unknown) => error instanceof Error && error.message === "result-contract";
  for (const [name, body] of Object.entries({
    "other digest": settlement({ digest: "c".repeat(64) }), "other nonce": settlement({ nonce: "d".repeat(32) }),
    "wrong environment": settlement({ environment: "staging" }), "wrong authority": settlement({ authorityId: "other" }),
    "wrong epoch": settlement({ policyEpoch: "other" }), "version 2": settlement({ version: 2 }), "extra member": settlement({ extra: true }),
    "non-boolean settled": settlement({ settled: "true" }), stale: settlement({ observedAtMs: now - 300_001 }), future: settlement({ observedAtMs: now + 60_001 }),
  })) assert.throws(() => verifySettlementResult(encode(body), { digest, nonce }, now), contract, name);
  assert.deepEqual(verifySettlementResult(encode(settlement({ observedAtMs: now - 300_000 })), { digest, nonce }, now).status, "SETTLED");
  assert.throws(() => verifySettlementResult(new Uint8Array(0), { digest, nonce }, now), /result-size/u);
  assert.throws(() => verifySettlementResult(new Uint8Array(8_193), { digest, nonce }, now), /result-size/u);
  assert.throws(() => verifySettlementResult(new Uint8Array([0xff]), { digest, nonce }, now));
  // staging settlement is verified against the staging identity only
  assert.equal(verifySettlementResult(encode(settlement({ environment: "staging", authorityId: "staging-public-inquiries-v1" })), { digest, nonce }, now,
    "staging", "staging-public-inquiries-v1").status, "SETTLED");
  assert.throws(() => verifySettlementResult(encode(settlement()), { digest, nonce }, now, "staging", "staging-public-inquiries-v1"), contract);
});

test("diagnostics: only the explicit unsigned relay diagnostic classifies, and it can only be non-positive", () => {
  for (const status of ["REFUSED", "UNAVAILABLE", "UNCONFIRMED"] as const) {
    assert.deepEqual(classifyUnsignedDiagnostic(encode(unsignedDiagnostic(digest, status, "some-reason")), { digest }),
      { status: "UNCONFIRMED", observation: "UNSIGNED_DIAGNOSTIC", relayStatus: status });
    assert.equal(classifyUnsignedDiagnostic(encode(unsignedDiagnostic(digest, status, undefined, nonce)), { digest, nonce })?.relayStatus, status);
  }
  // nonce discipline: a nonce-scoped diagnostic needs the expected nonce; a lifecycle diagnostic must not carry one that is wrong
  assert.equal(classifyUnsignedDiagnostic(encode(unsignedDiagnostic(digest, "UNAVAILABLE", undefined, nonce)), { digest, nonce: "e".repeat(32) }), null);
  assert.equal(classifyUnsignedDiagnostic(encode(unsignedDiagnostic(digest, "UNAVAILABLE")), { digest, nonce }), null);
  assert.equal(classifyUnsignedDiagnostic(encode(unsignedDiagnostic("c".repeat(64), "UNAVAILABLE")), { digest }), null);
  // the legacy positive objects (and every other shape) are NOT diagnostics
  const legacy = { version: 1, digest, environment: "production", authorityId: "production-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1", observedAtMs: now };
  const receipt = { digest, version: 1, operation: "initialize", environment: "production", authorityId: "production-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1",
    keyFingerprint: "c".repeat(64), sequence: 1, appliedMs: now, currentReleaseId: "r", nextReleaseId: "r", nextKeyId: "k", activatesMs: now, retiresMs: null };
  for (const body of [{ ...legacy, status: "SUCCESS", receipt }, { ...legacy, status: "ALREADY_APPLIED", receipt }, { ...legacy, status: "UNCONFIRMED" },
    { ...legacy, nonce, status: "EXACT_RECEIPT", initialized: true, coverage: "COMPLETE", receipt, releases: [] },
    { version: 1, digest, status: "SUCCESS" }, { version: 1, digest, status: "ALREADY_APPLIED" }, { version: 1, digest, status: "EXACT_RECEIPT" },
    { version: 1, digest, status: "REFUSED", receipt }, { version: 1, digest, status: "REFUSED", reason: "Not Valid" }, { version: 2, digest, status: "REFUSED" }])
    assert.equal(classifyUnsignedDiagnostic(encode(body), { digest, nonce }), null, JSON.stringify(body).slice(0, 80));
  for (const junk of [new Uint8Array(0), new Uint8Array([0xff]), new Uint8Array(8_193), new TextEncoder().encode("{"), new TextEncoder().encode("﻿{}"), encode([]), encode(null)])
    assert.equal(classifyUnsignedDiagnostic(junk, { digest }), null);
});

test("the shared command-derived field list is the frozen twelve fields", () => {
  assert.equal(Object.isFrozen(commandDerivedReceiptFields), true);
  assert.deepEqual([...commandDerivedReceiptFields].sort(), ["activatesMs", "authorityId", "currentReleaseId", "digest", "environment", "keyFingerprint",
    "nextKeyId", "nextReleaseId", "operation", "policyEpoch", "retiresMs", "version"]);
  assert.equal(commandDerivedReceiptFields.length, 12);
});
