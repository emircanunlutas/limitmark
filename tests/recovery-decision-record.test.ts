import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { encodeBase64url, toArrayBuffer } from "../src/lib/ingress-protocol";
import {
  RECOVERY_DECISION_FORMAT, RECOVERY_DECISION_MAX_LIFETIME_MS, RECOVERY_TIMING, decisionSigningBytes, parseDecisionRecord, registrySha256, verifyRecoveryDecisionRecord,
  type ApproverRegistry, type DecisionBody, type DecisionContext, type DecisionFailure,
} from "../operator/recovery-decision-record";

// Verification of the two-person decision record against fully synthetic keys. No signing helper exists in the module: the test signs with WebCrypto.

const ISSUED = 1_760_000_000_000;
const EXPIRY = ISSUED + RECOVERY_TIMING.commandLifetimeMs;
const FIRST = EXPIRY + RECOVERY_TIMING.firstReconciliationAfterExpiryMs;
const SECOND = FIRST + RECOVERY_TIMING.secondReconciliationAfterFirstMs;
const CREATED = SECOND + 120_000;
const NOW = CREATED + 60_000;
const ACCOUNT = "c".repeat(32);
const sha = (text: string) => createHash("sha256").update(text).digest("hex");
const EVIDENCE = { first: new TextEncoder().encode("first-reconciliation-bytes"), second: new TextEncoder().encode("second-reconciliation-bytes") };

type Person = { keyId: string; person: string; publicKey: string; privateKey: CryptoKey };
async function person(keyId: string, name: string): Promise<Person> {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  return { keyId, person: name, publicKey: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))), privateKey: pair.privateKey };
}
let alice: Person, bob: Person, carol: Person, aliceSecond: Person, operatorKey: string;
let registry: ApproverRegistry;
const entry = (p: Person, extra: Partial<ApproverRegistry["keys"][number]> = {}) => ({ keyId: p.keyId, person: p.person, publicKey: p.publicKey, status: "active" as const, notBeforeMs: 0, notAfterMs: null, ...extra });

test("setup", async () => {
  [alice, bob, carol, aliceSecond] = await Promise.all([person("alice-1", "alice"), person("bob-1", "bob"), person("carol-1", "carol"), person("alice-2", "alice")]);
  operatorKey = (await person("op", "operator")).publicKey;
  registry = { version: 1, keys: [entry(alice), entry(bob), entry(carol), entry(aliceSecond)] };
});

function body(overrides: Partial<DecisionBody> = {}, reg: ApproverRegistry = registry): DecisionBody {
  return {
    format: RECOVERY_DECISION_FORMAT, decisionId: "d".repeat(32), reason: "STRANDED_INITIALIZATION_LATCH", createdAtMs: CREATED, expiresAtMs: CREATED + 600_000,
    target: { environment: "production", accountId: ACCOUNT, authorityId: "production-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1" },
    guards: { original: "production-lifecycle-dispatch-v1", proposed: "production-lifecycle-dispatch-v2" },
    initializationCommand: { digest: "a".repeat(64), issuedAtMs: ISSUED },
    reconciliations: [{ nonce: "1".repeat(32), observedAtMs: FIRST, evidenceSha256: sha("first-reconciliation-bytes") }, { nonce: "2".repeat(32), observedAtMs: SECOND, evidenceSha256: sha("second-reconciliation-bytes") }],
    guardExportContentSha256: "e".repeat(64), evidenceBundleSha256: "f".repeat(64), approverRegistrySha256: registrySha256(reg), ...overrides,
  };
}
async function sign(b: DecisionBody, signer: Person, keyId = signer.keyId): Promise<{ keyId: string; signature: string }> {
  return { keyId, signature: encodeBase64url(new Uint8Array(await crypto.subtle.sign("Ed25519", signer.privateKey, toArrayBuffer(decisionSigningBytes(b, keyId))))) };
}
async function record(b: DecisionBody = body(), signers: [Person, Person] = [alice, bob]): Promise<string> {
  return JSON.stringify({ body: b, approvals: [await sign(b, signers[0]), await sign(b, signers[1])] });
}
const context = (overrides: Partial<DecisionContext> = {}): DecisionContext => ({
  registry, lifecycleOperatorPublicKey: operatorKey,
  expected: { environment: "production", accountId: ACCOUNT, authorityId: "production-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1", originalGuard: "production-lifecycle-dispatch-v1", strandedDigest: "a".repeat(64), issuedAtMs: ISSUED },
  guardAllowlist: ["production-lifecycle-dispatch-v1", "production-lifecycle-dispatch-v2"],
  consumed: { decisionIds: new Set(), guardGenerations: new Set(["production-lifecycle-dispatch-v1"]), strandedDigests: new Set() },
  nowMs: NOW, evidence: EVIDENCE, ...overrides,
});
const failures = async (text: string, ctx = context()): Promise<DecisionFailure[]> => { const v = await verifyRecoveryDecisionRecord(text, ctx); return v.valid ? [] : v.failures; };

test("a record signed by two different people with two active registered keys verifies; canonicalization ignores key order and whitespace", async () => {
  const verdict = await verifyRecoveryDecisionRecord(await record(), context());
  assert.deepEqual(verdict, { valid: true, decisionId: "d".repeat(32), people: ["alice", "bob"], keyIds: ["alice-1", "bob-1"] });
  // re-serialized with different key order and indentation: same canonical body, same signatures
  const parsed = JSON.parse(await record()) as { body: Record<string, unknown>; approvals: unknown[] };
  const reordered = JSON.stringify({ approvals: parsed.approvals, body: Object.fromEntries(Object.entries(parsed.body).reverse()) }, null, 3);
  assert.equal((await verifyRecoveryDecisionRecord(reordered, context())).valid, true);
});

test("two-person rule: one key twice, one person with two keys, a retired/revoked/not-yet-active/expired key, an unregistered key and the lifecycle operator key all fail", async () => {
  const b = body();
  assert.ok((await failures(JSON.stringify({ body: b, approvals: [await sign(b, alice), await sign(b, alice)] }))).includes("same-key"));
  assert.deepEqual(await failures(await record(b, [alice, aliceSecond])), ["same-person"]);
  const stranger = await person("mallory-1", "mallory");
  assert.ok((await failures(await record(b, [alice, stranger]))).includes("key-not-authorized"));
  for (const [name, extra] of [["retired", { status: "retired" as const }], ["revoked", { status: "revoked" as const }], ["future", { notBeforeMs: CREATED + 1 }], ["expired key", { notAfterMs: CREATED }]] as const) {
    const reg: ApproverRegistry = { version: 2, keys: [entry(alice), entry(bob, extra), entry(carol)] };
    assert.ok((await failures(await record(body({}, reg)), context({ registry: reg }))).includes("key-not-authorized"), name);
  }
  const reg: ApproverRegistry = { version: 3, keys: [entry(alice), entry(bob), entry(carol)] };
  assert.ok((await failures(await record(body({}, reg)), context({ registry: reg, lifecycleOperatorPublicKey: bob.publicKey }))).includes("key-is-operator-key"));
  assert.equal((await verifyRecoveryDecisionRecord(await record(body({}, reg), [alice, carol]), context({ registry: reg }))).valid, true);
});

test("signatures: any change to the signed body, a swapped keyId, a foreign or malformed signature, or a wrong registry hash fails", async () => {
  const b = body();
  const good = JSON.parse(await record(b)) as { body: DecisionBody; approvals: Array<{ keyId: string; signature: string }> };
  const withBody = (mutate: (copy: DecisionBody) => void) => { const copy = structuredClone(good); mutate(copy.body); return JSON.stringify(copy); };
  assert.ok((await failures(withBody((x) => { x.guards.proposed = "production-lifecycle-dispatch-v3"; }), context({ guardAllowlist: ["production-lifecycle-dispatch-v1", "production-lifecycle-dispatch-v2", "production-lifecycle-dispatch-v3"] }))).includes("signature"));
  assert.ok((await failures(withBody((x) => { x.expiresAtMs += 1; }))).includes("signature"));
  assert.ok((await failures(withBody((x) => { x.guardExportContentSha256 = "0".repeat(64); }))).includes("signature"));
  const swapped = structuredClone(good); swapped.approvals = [{ keyId: "bob-1", signature: good.approvals[0].signature }, { keyId: "alice-1", signature: good.approvals[1].signature }];
  assert.ok((await failures(JSON.stringify(swapped))).includes("signature"), "a signature is bound to its keyId and cannot be re-attributed");
  const foreign = structuredClone(good); foreign.approvals[1].signature = (await sign(b, carol)).signature;
  assert.ok((await failures(JSON.stringify(foreign))).includes("signature"));
  const malformed = structuredClone(good); malformed.approvals[1].signature = "AAAA";
  assert.ok((await failures(JSON.stringify(malformed))).includes("signature"));
  const otherRegistry: ApproverRegistry = { version: 9, keys: [...registry.keys] };
  assert.ok((await failures(await record(), context({ registry: otherRegistry }))).includes("registry-hash"), "signatures are judged only against the registry version the record pins");
  assert.ok((await failures(await record(), context({ registry: { version: 1, keys: [] } }))).includes("registry"));
});

test("binding: environment, account, Authority, original guard, stranded command, allowlist and generation reuse are all checked", async () => {
  const mismatch = async (overrides: Partial<DecisionBody>, expectedFailure: DecisionFailure, ctx = context()) => assert.ok((await failures(await record(body(overrides)), ctx)).includes(expectedFailure), expectedFailure);
  await mismatch({ target: { environment: "production", accountId: "d".repeat(32), authorityId: "production-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1" } }, "target");
  await mismatch({ target: { environment: "production", accountId: ACCOUNT, authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1" } }, "target");
  await mismatch({ guards: { original: "staging-lifecycle-dispatch-v1", proposed: "production-lifecycle-dispatch-v2" } }, "guard-identity");
  await mismatch({ guards: { original: "production-lifecycle-dispatch-v1", proposed: "production-lifecycle-dispatch-v1" } }, "guard-allowlist");
  await mismatch({ guards: { original: "production-lifecycle-dispatch-v1", proposed: "production-lifecycle-dispatch-v9" } }, "guard-allowlist");
  await mismatch({}, "guard-reused", context({ consumed: { decisionIds: new Set(), guardGenerations: new Set(["production-lifecycle-dispatch-v1", "production-lifecycle-dispatch-v2"]), strandedDigests: new Set() } }));
  await mismatch({ initializationCommand: { digest: "b".repeat(64), issuedAtMs: ISSUED } }, "command-binding");
  await mismatch({ initializationCommand: { digest: "a".repeat(64), issuedAtMs: ISSUED + 1 } }, "command-binding");
});

test("timing is re-checked from the approved parameters: early/late reconciliations, reused nonce or evidence, decision outside the window, lifetime and expiry", async () => {
  const rec = (first: number, second: number) => [{ nonce: "1".repeat(32), observedAtMs: first, evidenceSha256: sha("first-reconciliation-bytes") }, { nonce: "2".repeat(32), observedAtMs: second, evidenceSha256: sha("second-reconciliation-bytes") }] as DecisionBody["reconciliations"];
  const bad = async (overrides: Partial<DecisionBody>, expected: DecisionFailure, ctx = context()) => assert.ok((await failures(await record(body(overrides)), ctx)).includes(expected), JSON.stringify([expected, overrides]).slice(0, 120));
  await bad({ reconciliations: rec(FIRST - 1, SECOND) }, "timing");
  await bad({ reconciliations: rec(FIRST, FIRST + 59_999), createdAtMs: FIRST + 100_000, expiresAtMs: FIRST + 200_000 }, "timing");
  await bad({ createdAtMs: SECOND - 1 }, "timing");
  await bad({ createdAtMs: SECOND + 300_001, expiresAtMs: SECOND + 300_001 + 100_000 }, "timing");
  const same = body().reconciliations; same[1] = { ...same[1], nonce: same[0].nonce };
  await bad({ reconciliations: same }, "timing");
  await bad({ expiresAtMs: CREATED + RECOVERY_DECISION_MAX_LIFETIME_MS + 1 }, "lifetime");
  await bad({ expiresAtMs: CREATED }, "lifetime");
  await bad({}, "expired", context({ nowMs: CREATED + 600_000 }));
  await bad({}, "not-yet-valid", context({ nowMs: CREATED - 1 }));
});

test("replay prevention and evidence binding", async () => {
  assert.ok((await failures(await record(), context({ consumed: { decisionIds: new Set(["d".repeat(32)]), guardGenerations: new Set(["production-lifecycle-dispatch-v1"]), strandedDigests: new Set() } }))).includes("replay"));
  assert.ok((await failures(await record(), context({ consumed: { decisionIds: new Set(), guardGenerations: new Set(["production-lifecycle-dispatch-v1"]), strandedDigests: new Set(["a".repeat(64)]) } }))).includes("replay"), "one recovery per stranded digest");
  assert.ok((await failures(await record(), context({ evidence: { first: EVIDENCE.second, second: EVIDENCE.first } }))).includes("evidence-hash"));
  assert.ok((await failures(await record(), context({ evidence: { first: new Uint8Array([1]), second: EVIDENCE.second } }))).includes("evidence-hash"));
});

test("document strictness: unknown keys, extra approvals, duplicate keys, wrong format, BOM, oversize and non-JSON are refused before any signature work", async () => {
  const good = JSON.parse(await record()) as { body: Record<string, unknown>; approvals: unknown[] };
  const cases: Record<string, string> = {
    empty: "", garbage: "nope", array: "[]", extraTop: JSON.stringify({ ...good, extra: 1 }), extraBody: JSON.stringify({ ...good, body: { ...good.body, extra: 1 } }),
    oneApproval: JSON.stringify({ ...good, approvals: [good.approvals[0]] }), threeApprovals: JSON.stringify({ ...good, approvals: [...good.approvals, good.approvals[0]] }),
    wrongFormat: JSON.stringify({ ...good, body: { ...good.body, format: "limitmark-guard-recovery-decision-v0" } }),
    wrongReason: JSON.stringify({ ...good, body: { ...good.body, reason: "ANY" } }), floatTime: JSON.stringify({ ...good, body: { ...good.body, createdAtMs: 1.5 } }),
    stagingEnvironment: JSON.stringify({ ...good, body: { ...good.body, target: { ...(good.body.target as object), environment: "staging" } } }),
    duplicateKey: (await record()).replace('"approvals"', '"body":{},"approvals"'), bom: `﻿${await record()}`, oversize: `{"body":{},"approvals":[],"pad":"${"x".repeat(20_000)}"}`,
  };
  for (const [name, text] of Object.entries(cases)) assert.deepEqual(await failures(text), ["document"], name);
  assert.equal(parseDecisionRecord(await record())?.body.decisionId, "d".repeat(32));
});

test("the verifier is verification-only: no signing, persistence, network, process or replacement capability is present", async () => {
  const source = (await readFile(new URL("../operator/recovery-decision-record.ts", import.meta.url), "utf8")).replace(/\/\*[\s\S]*?\*\//gu, "");
  assert.doesNotMatch(source, /crypto\.subtle\.sign|createPrivateKey|writeFile|node:fs|node:child_process|fetch\(|process\.env|initializeAuthority|settle|processInitialization/u);
  assert.deepEqual([...source.matchAll(/^import .*? from "([^"]+)";$/gmu)].map((m) => m[1]).sort(), ["../src/lib/ingress-protocol", "./guard-ledger-export", "./lifecycle-submitter", "node:crypto"]);
});
