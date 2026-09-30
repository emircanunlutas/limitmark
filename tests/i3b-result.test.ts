import assert from "node:assert/strict";
import { test } from "node:test";
import { verifyLifecycleResult, verifyProductionLifecycleResult } from "../operator/lifecycle-result";

const digest = "a".repeat(64);
const nonce = "b".repeat(32);
const now = 10_000;
const receipt = { digest, version: 1, operation: "initialize", environment: "production", authorityId: "production-public-inquiries-v1",
  policyEpoch: "phase5c-i1-epoch-1", keyFingerprint: "c".repeat(64), sequence: 1, appliedMs: 9_000,
  currentReleaseId: "release-a", nextReleaseId: "release-a", nextKeyId: "key-a", activatesMs: 9_000, retiresMs: null };
const base = { version: 1, digest, environment: "production", authorityId: "production-public-inquiries-v1",
  policyEpoch: "phase5c-i1-epoch-1", observedAtMs: now };
const row = { release_id: "release-a", key_id: "key-a", activated_ms: 9_000, retired_ms: null };
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
  const observation = { ...base, nonce, status: "NOT_FOUND", initialized: true, coverage: "COMPLETE", receipt: null, releases: [row] };
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
const exact = { ...base, nonce, status: "EXACT_RECEIPT", initialized: true, coverage: "COMPLETE", receipt, releases: [row] };
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
  assert.equal(verify({ ...negative, status: "NOT_FOUND", initialized: false, releases: [] }, "reconciliation").status, "UNCONFIRMED");
  assert.equal(verify({ ...negative, status: "NOT_FOUND" }, "reconciliation").status, "UNCONFIRMED");
  assert.equal(verify({ ...negative, status: "HISTORY_INCOMPLETE", coverage: "INCOMPLETE" }, "reconciliation").status, "UNCONFIRMED");
});

// --- expectedReceipt: exact canonical receipt binding -----------------------------------------------

type Fields = typeof receipt;
const mutations: Record<keyof Fields, unknown> = { digest: "d".repeat(64), version: 2, operation: "rotate-release", environment: "staging",
  authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-2", keyFingerprint: "e".repeat(64), sequence: 2, appliedMs: 9_001,
  currentReleaseId: "release-b", nextReleaseId: "release-b", nextKeyId: "key-b", activatesMs: 9_001, retiresMs: 9_500 };
// Mutations that an earlier, pre-existing check (digest/version/environment/authority/epoch) already rejects even with no expectedReceipt.
const earlierRejection = new Set(["digest", "version", "environment", "authorityId", "policyEpoch"]);
const asReceipt = (value: object) => value as Parameters<typeof verifyLifecycleResult>[8];
const withExpected = (value: object, kind: "lifecycle" | "reconciliation", expectedReceipt?: object, operation?: "initialize" | "rotate-release") =>
  verifyLifecycleResult(bytes(value), kind, kind === "lifecycle" ? { digest } : { nonce }, now, environment, authorityId, undefined, operation,
    expectedReceipt === undefined ? undefined : asReceipt(expectedReceipt));

test("expectedReceipt: canonical lifecycle SUCCESS/ALREADY_APPLIED and reconciliation EXACT_RECEIPT pass, including exact replay", () => {
  for (const status of ["SUCCESS", "ALREADY_APPLIED"])
    for (let replay = 0; replay < 2; replay++)
      assert.equal(withExpected({ ...base, status, receipt }, "lifecycle", receipt).status, status, `lifecycle ${status} replay ${replay}`);
  assert.equal(withExpected(exact, "reconciliation", receipt).status, "SUCCESS");
  // The comparison is fieldwise: property insertion order of the result receipt is irrelevant.
  const reordered = Object.fromEntries(Object.entries(receipt).reverse());
  assert.equal(withExpected({ ...base, status: "SUCCESS", receipt: reordered }, "lifecycle", receipt).status, "SUCCESS");
});

test("expectedReceipt: every single-field deviation of a present receipt is refused (lifecycle and reconciliation)", () => {
  assert.deepEqual(Object.keys(mutations).sort(), Object.keys(receipt).sort(), "all fourteen receipt fields are covered");
  for (const field of Object.keys(receipt) as (keyof Fields)[]) {
    const altered = { ...receipt, [field]: mutations[field] };
    for (const [kind, value] of [["lifecycle", { ...base, status: "SUCCESS", receipt: altered }],
      ["lifecycle", { ...base, status: "ALREADY_APPLIED", receipt: altered }], ["reconciliation", { ...exact, receipt: altered }]] as const) {
      assert.throws(() => withExpected(value, kind, receipt), /result-contract/u, `${kind} ${field}`);
      // Fields not caught by an earlier check are accepted without the expectation: the new comparison alone rejects them.
      if (!earlierRejection.has(field)) assert.doesNotThrow(() => withExpected(value, kind), `${kind} ${field} is rejected only by expectedReceipt`);
      else assert.throws(() => withExpected(value, kind), /result-contract/u, `${kind} ${field} is rejected by an earlier check too`);
    }
    // A contradicting receipt on a non-positive lifecycle result is refused as well.
    assert.throws(() => withExpected({ ...base, status: "REFUSED", receipt: altered }, "lifecycle", receipt), /result-contract/u, `REFUSED ${field}`);
  }
});

test("expectedReceipt: a deviating or malformed expectation never widens acceptance", () => {
  const positive = { ...base, status: "SUCCESS", receipt };
  for (const field of Object.keys(receipt) as (keyof Fields)[]) {
    assert.throws(() => withExpected(positive, "lifecycle", { ...receipt, [field]: mutations[field] }), /result-contract/u, `expected ${field}`);
    const partial = Object.fromEntries(Object.entries(receipt).filter(([key]) => key !== field));
    assert.throws(() => withExpected(positive, "lifecycle", partial), /result-contract/u, `expected omits ${field}`);
    assert.throws(() => withExpected(positive, "lifecycle", { ...receipt, [field]: undefined }), /result-contract/u, `expected undefined ${field}`);
  }
  for (const malformed of [null, [], "x", {}, { ...receipt, extra: 1 }, { ...receipt, sequence: 0 }, { ...receipt, sequence: 4_097 },
    { ...receipt, digest: "A".repeat(64) }, { ...receipt, keyFingerprint: "nothex" }, { ...receipt, retiresMs: undefined }])
    assert.throws(() => withExpected(positive, "lifecycle", malformed as object), /result-contract/u, JSON.stringify(malformed));
  // Receipt-less results do not even read a malformed expectation into acceptance: it is still refused up front.
  assert.throws(() => withExpected({ ...exact, status: "NOT_FOUND", receipt: null }, "reconciliation", {}), /result-contract/u);
});

test("expectedReceipt: receipt-less results and settlement keep their behavior; other pins stay active", () => {
  const negative = { ...exact, receipt: null };
  assert.equal(withExpected({ ...negative, status: "NOT_FOUND" }, "reconciliation", receipt).status, "UNCONFIRMED");
  assert.equal(withExpected({ ...negative, status: "HISTORY_INCOMPLETE", coverage: "INCOMPLETE" }, "reconciliation", receipt).status, "UNCONFIRMED");
  assert.deepEqual(withExpected({ ...base, nonce, status: "UNAVAILABLE" }, "reconciliation", receipt), { status: "UNCONFIRMED", digest, observation: "UNAVAILABLE" });
  assert.equal(withExpected({ ...base, status: "UNCONFIRMED", reason: "dispatch-ambiguous" }, "lifecycle", receipt).status, "UNCONFIRMED");
  assert.deepEqual(verifyLifecycleResult(bytes({ ...base, nonce, settled: true }), "settlement", { nonce }, now, environment, authorityId,
    undefined, undefined, asReceipt(receipt)), { status: "SETTLED", digest, nonce });
  // A receipt-less positive result is still an integrity failure, not a pass: the expectation does not relax it.
  assert.throws(() => withExpected({ ...base, status: "SUCCESS" }, "lifecycle", receipt), /result-integrity/u);
  // expectedOperation and expectedKeyFingerprint still bind alongside the receipt, and a contradictory configuration fails closed.
  assert.throws(() => withExpected({ ...base, status: "SUCCESS", receipt }, "lifecycle", receipt, "rotate-release"), /result-contract/u);
  assert.throws(() => verifyLifecycleResult(bytes({ ...base, status: "SUCCESS", receipt }), "lifecycle", { digest }, now, environment, authorityId,
    "f".repeat(64), "initialize", asReceipt(receipt)), /result-contract/u);
  assert.equal(verifyLifecycleResult(bytes({ ...base, status: "SUCCESS", receipt }), "lifecycle", { digest }, now, environment, authorityId,
    receipt.keyFingerprint, "initialize", asReceipt(receipt)).status, "SUCCESS");
  // The expectation must be for the same environment/authority as the verifier is pinned to.
  assert.throws(() => withExpected({ ...base, status: "SUCCESS", receipt }, "lifecycle", { ...receipt, environment: "staging" }), /result-contract/u);
  // Omitting it preserves the generic behavior.
  assert.equal(withExpected({ ...base, status: "SUCCESS", receipt: { ...receipt, sequence: 7 } }, "lifecycle").status, "SUCCESS");
});

// --- reconciliation.releases[]: current authority snapshot coherence --------------------------------

const snapshot = (releases: unknown[], patch: object = {}) => ({ ...exact, receipt: null, status: "NOT_FOUND", releases, ...patch });
const two = [{ release_id: "release-old", key_id: "key-old", activated_ms: 1_000, retired_ms: 9_500 },
  { release_id: "release-new", key_id: "key-new", activated_ms: 9_000, retired_ms: null }];
const rejects = (value: object, pattern: RegExp, name: string) => assert.throws(() => verify(value, "reconciliation"), pattern, name);

test("release snapshot: legitimate current states pass for every reconciliation status", () => {
  assert.equal(verify(snapshot([row]), "reconciliation").status, "UNCONFIRMED");
  assert.equal(verify(snapshot(two), "reconciliation").status, "UNCONFIRMED");
  assert.equal(verify(snapshot(two, { status: "HISTORY_INCOMPLETE", coverage: "INCOMPLETE" }), "reconciliation").status, "UNCONFIRMED");
  assert.equal(verify({ ...exact, releases: two }, "reconciliation").status, "SUCCESS");
  // Equal activation timestamps are producible (rotation at the initialization instant) and ORDER BY leaves ties unordered.
  const tied = [{ ...two[0], activated_ms: 9_000 }, two[1]];
  assert.equal(verify(snapshot(tied), "reconciliation").status, "UNCONFIRMED");
  assert.equal(verify(snapshot([tied[1], tied[0]]), "reconciliation").status, "UNCONFIRMED");
  // Uninitialized NOT_FOUND carries no rows.
  assert.equal(verify(snapshot([], { initialized: false }), "reconciliation").status, "UNCONFIRMED");
});

test("release snapshot: current rows are independent of the historical receipt", () => {
  // The receipt names release-a/key-a; the current snapshot is an unrelated, later, valid rotation.
  const later = [{ release_id: "release-x", key_id: "key-x", activated_ms: 9_900, retired_ms: null }];
  assert.equal(verify({ ...exact, releases: later }, "reconciliation").status, "SUCCESS");
  assert.equal(verify({ ...exact, receipt: { ...receipt, operation: "rotate-release", sequence: 1 }, releases: two }, "reconciliation").status, "SUCCESS");
});

test("release snapshot: malformed rows are result-contract", () => {
  const bad = (patch: object) => snapshot([{ ...row, ...patch }]);
  for (const key of Object.keys(row)) {
    const rest: Record<string, unknown> = { ...row }; delete rest[key];
    rejects(snapshot([rest]), /result-contract/u, `missing ${key}`);
  }
  rejects(bad({ extra: 1 }), /result-contract/u, "extra field");
  rejects(snapshot([[]]), /result-contract/u, "array row");
  rejects(snapshot([null]), /result-contract/u, "null row");
  for (const release_id of ["", "a".repeat(129), "bad id", "x/y", 7, null]) rejects(bad({ release_id }), /result-contract/u, `release_id ${String(release_id)}`);
  for (const key_id of ["", "a".repeat(65), "bad.key", "a:b", 7, null]) rejects(bad({ key_id }), /result-contract/u, `key_id ${String(key_id)}`);
  for (const activated_ms of [-1, 1.5, "9000", null, Number.MAX_SAFE_INTEGER + 1]) rejects(bad({ activated_ms }), /result-contract/u, `activated_ms ${String(activated_ms)}`);
  for (const retired_ms of [-1, 1.5, "9500", Number.MAX_SAFE_INTEGER + 1]) rejects(bad({ retired_ms }), /result-contract/u, `retired_ms ${String(retired_ms)}`);
  // Domain boundaries mirror the authority validators.
  assert.equal(verify(snapshot([{ ...row, release_id: "A.b:c_d-1".padEnd(128, "z"), key_id: "K_-".padEnd(64, "z") }]), "reconciliation").status, "UNCONFIRMED");
});

test("release snapshot: states the authority cannot produce are result-integrity", () => {
  const [old, next] = two;
  rejects(snapshot([{ ...row, retired_ms: 9_500 }]), /result-integrity/u, "single retired row, none unretired");
  rejects(snapshot([{ ...old, retired_ms: old.activated_ms }, next]), /result-integrity/u, "retired at activation");
  rejects(snapshot([{ ...old, retired_ms: old.activated_ms - 1 }, next]), /result-integrity/u, "retired before activation");
  rejects(snapshot([old, { ...next, release_id: old.release_id }]), /result-integrity/u, "duplicate release_id");
  rejects(snapshot([old, { ...next, key_id: old.key_id }]), /result-integrity/u, "duplicate key_id");
  rejects(snapshot([{ ...old, retired_ms: null }, next]), /result-integrity/u, "two unretired rows");
  rejects(snapshot([old, { ...next, retired_ms: 9_900 }]), /result-integrity/u, "no unretired row");
  const third = { release_id: "release-third", key_id: "key-third", activated_ms: 9_500, retired_ms: null };
  rejects(snapshot([old, { ...next, retired_ms: 9_800 }, third]), /result-integrity/u, "three rows");
  rejects(snapshot([]), /result-integrity/u, "initialized with zero rows");
  rejects(snapshot([], { status: "HISTORY_INCOMPLETE", coverage: "INCOMPLETE" }), /result-integrity/u, "incomplete history with zero rows");
  rejects(snapshot([row], { initialized: false }), /result-integrity/u, "uninitialized with rows");
  rejects(snapshot([next, old]), /result-integrity/u, "reversed activation order");
  rejects(snapshot([old, { ...next, activated_ms: 9_500 }]), /result-integrity/u, "retired row not retired after successor activation");
  rejects(snapshot([old, { ...next, activated_ms: 9_600 }]), /result-integrity/u, "successor activates after predecessor retires");
  rejects(snapshot([{ ...old, activated_ms: 9_100 }, next]), /result-integrity/u, "retired row activated after the unretired row");
  rejects({ ...exact, releases: [{ ...row, retired_ms: 9_000 }] }, /result-integrity/u, "EXACT_RECEIPT with impossible snapshot");
});

test("release snapshot: error text carries no row values", () => {
  try { verify(snapshot([{ ...row, release_id: "secret-release-value", retired_ms: 1 }]), "reconciliation"); assert.fail("accepted"); }
  catch (error) { assert.equal((error as Error).message, "result-integrity"); }
});

// --- Production command-backed verification ----------------------------------------------------------------

const commandFields = ["digest", "version", "operation", "environment", "authorityId", "policyEpoch", "keyFingerprint",
  "currentReleaseId", "nextReleaseId", "nextKeyId", "activatesMs", "retiresMs"] as const;
const withoutAuthorityFields = (value: object) => Object.fromEntries(Object.entries(value).filter(([key]) => key !== "sequence" && key !== "appliedMs"));
const commandContext = withoutAuthorityFields(receipt);
type CommandOption = NonNullable<NonNullable<Parameters<typeof verifyProductionLifecycleResult>[3]>["command"]>;
const productionVerify = (value: object, kind: "lifecycle" | "reconciliation", command: object | null = commandContext) =>
  verifyProductionLifecycleResult(bytes(value), kind, kind === "lifecycle" ? { digest } : { digest, nonce }, { nowMs: now, command: command === null ? undefined : command as CommandOption });
const positives = [["lifecycle", { ...base, status: "SUCCESS", receipt }, "SUCCESS"], ["lifecycle", { ...base, status: "ALREADY_APPLIED", receipt }, "ALREADY_APPLIED"],
  ["reconciliation", exact, "SUCCESS"]] as const;

test("production: a positive result without authenticated command context is never success", () => {
  for (const [kind, value] of positives)
    assert.deepEqual(productionVerify(value, kind, null), { status: "UNCONFIRMED", digest, observation: "COMMAND_CONTEXT_REQUIRED" }, kind);
  // The generic verifier (staging and tests) is unchanged and still positive on its own.
  assert.equal(verifyLifecycleResult(bytes(positives[0][1]), "lifecycle", { digest }, now).status, "SUCCESS");
});

test("production: a matching authenticated command yields success, and sequence/appliedMs are not command-bound", () => {
  for (const [kind, value, status] of positives) {
    assert.equal(productionVerify(value, kind).status, status, kind);
    const reassigned = { ...value, receipt: { ...receipt, sequence: 4_096, appliedMs: 1 } };
    assert.equal(productionVerify(reassigned, kind).status, status, `${kind}: forged/replayed sequence and appliedMs are authority-derived`);
  }
  const rotation = { ...receipt, operation: "rotate-release", nextReleaseId: "release-b", nextKeyId: "key-b", retiresMs: 9_500 };
  const rotationContext = withoutAuthorityFields(rotation);
  assert.equal(productionVerify({ ...base, status: "SUCCESS", receipt: rotation }, "lifecycle", rotationContext).status, "SUCCESS");
  assert.throws(() => productionVerify({ ...base, status: "SUCCESS", receipt: rotation }, "lifecycle"), /result-contract/u, "initialize command cannot vouch for a rotation receipt");
});

test("production: every command-derived receipt field is bound, for every positive and non-positive result carrying a receipt", () => {
  assert.deepEqual([...commandFields].sort(), Object.keys(commandContext).sort(), "all twelve command-derived fields are covered");
  const other: Record<(typeof commandFields)[number], unknown> = { digest: "d".repeat(64), version: 2, operation: "rotate-release", environment: "staging",
    authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-2", keyFingerprint: "e".repeat(64), currentReleaseId: "release-z",
    nextReleaseId: "release-z", nextKeyId: "key-z", activatesMs: 9_001, retiresMs: 9_500 };
  for (const field of commandFields) {
    const altered = { ...receipt, [field]: other[field] };
    for (const [kind, value] of [...positives.map(([k, v]) => [k, { ...v, receipt: altered }] as const),
      ["lifecycle", { ...base, status: "REFUSED", receipt: altered }] as const])
      assert.throws(() => productionVerify(value, kind), /result-contract/u, `${kind} ${field}`);
    // A command context that itself deviates (wrong operator key, wrong ids...) rejects a coherent receipt the same way.
    assert.throws(() => productionVerify(positives[0][1], "lifecycle", { ...commandContext, [field]: other[field] }), /result-contract/u, `command ${field}`);
  }
  // The operator-key fingerprint specifically.
  assert.throws(() => productionVerify({ ...base, status: "SUCCESS", receipt: { ...receipt, keyFingerprint: "e".repeat(64) } }, "lifecycle"), /result-contract/u);
});

test("production: command context must be well formed and name the requested digest, and never widens acceptance", () => {
  assert.throws(() => productionVerify(positives[0][1], "lifecycle", { ...commandContext, digest: "d".repeat(64) }), /result-contract/u, "command digest != requested digest");
  for (const malformed of [{ ...commandContext, extra: 1 }, { ...commandContext, sequence: 1, appliedMs: 1 }, { ...commandContext, retiresMs: undefined },
    { ...commandContext, keyFingerprint: "nothex" }, { ...commandContext, version: 2 }])
    assert.throws(() => productionVerify(positives[0][1], "lifecycle", malformed), /result-contract/u, JSON.stringify(malformed));
  for (const field of commandFields) {
    const partial = Object.fromEntries(Object.entries(commandContext).filter(([key]) => key !== field));
    assert.throws(() => productionVerify(positives[0][1], "lifecycle", partial), /result-contract/u, `omits ${field}`);
  }
  // Another environment's command never authenticates a Production result.
  assert.throws(() => productionVerify(positives[0][1], "lifecycle", { ...commandContext, environment: "staging", authorityId: "staging-public-inquiries-v1" }), /result-contract/u);
  // Result-level checks still apply under a command: incoherent EXACT_RECEIPT, receipt-less positive, wrong nonce.
  assert.throws(() => productionVerify({ ...exact, initialized: false }, "reconciliation"), /result-integrity/u);
  assert.throws(() => productionVerify({ ...base, status: "SUCCESS" }, "lifecycle"), /result-integrity/u);
  assert.throws(() => productionVerify({ ...exact, nonce: "c".repeat(32) }, "reconciliation"), /result-contract/u);
});

test("production: receipt-less diagnostics and synthetic never-signed digests stay available and non-positive, with or without a command", () => {
  const negative = { ...exact, receipt: null };
  for (const command of [null, commandContext]) {
    assert.deepEqual(productionVerify({ ...negative, status: "NOT_FOUND" }, "reconciliation", command), { status: "UNCONFIRMED", digest, observation: "NOT_FOUND" });
    assert.deepEqual(productionVerify({ ...negative, status: "HISTORY_INCOMPLETE", coverage: "INCOMPLETE" }, "reconciliation", command),
      { status: "UNCONFIRMED", digest, observation: "HISTORY_INCOMPLETE" });
    assert.deepEqual(productionVerify({ ...base, nonce, status: "UNAVAILABLE" }, "reconciliation", command), { status: "UNCONFIRMED", digest, observation: "UNAVAILABLE" });
    assert.equal(productionVerify({ ...base, status: "UNCONFIRMED", reason: "dispatch-ambiguous" }, "lifecycle", command).status, "UNCONFIRMED");
    assert.equal(productionVerify({ ...base, status: "REFUSED" }, "lifecycle", command).status, "UNCONFIRMED");
  }
  // Synthetic digest: no command exists for it, so no receipt can ever be positive evidence.
  const synthetic = "5".repeat(64);
  const syntheticBase = { ...base, digest: synthetic };
  assert.deepEqual(verifyProductionLifecycleResult(bytes({ ...syntheticBase, nonce, status: "NOT_FOUND", initialized: true, coverage: "COMPLETE", receipt: null, releases: [row] }),
    "reconciliation", { digest: synthetic, nonce }, { nowMs: now }), { status: "UNCONFIRMED", digest: synthetic, observation: "NOT_FOUND" });
  assert.equal(verifyProductionLifecycleResult(bytes({ ...syntheticBase, nonce, status: "EXACT_RECEIPT", initialized: true, coverage: "COMPLETE",
    receipt: { ...receipt, digest: synthetic }, releases: [row] }), "reconciliation", { digest: synthetic, nonce }, { nowMs: now }).status, "UNCONFIRMED");
  // Settlement is guard state: command context neither required nor consulted.
  assert.deepEqual(verifyProductionLifecycleResult(bytes({ ...base, nonce, settled: true }), "settlement", { digest, nonce }, { nowMs: now }), { status: "SETTLED", digest, nonce });
});
