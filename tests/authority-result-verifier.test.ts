import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  RECEIPT_FIELDS,
  attestationKeyFingerprint,
  attestationReceiptFromLifecycleReceipt,
  encodeResultAttestationEnvelope,
  makeLifecycleStatement,
  makeReconciliationStatement,
  signResultAttestation,
  type AttestationReceipt,
  type AttestationReleaseRow,
  type ResultStatement,
} from "../src/lib/authority-result-attestation";
import {
  isVerifiedAuthorityStatement,
  parseAuthorityResultTrustManifest,
  verifyAuthoritySignedStatement,
  type AuthorityResultTrustManifest,
  type ResultAttestationExpectations,
  type VerifiedAuthorityStatement,
} from "../src/lib/authority-result-trust";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import {
  commandReceiptMismatches,
  composeProductionAuthorityResult,
  composeStagingAuthorityResult,
  isProductionAuthorityPositive,
  isStagingAuthorityPositive,
  verifyProductionAuthorityResult,
  verifyStagingAuthorityResult,
  type ProductionAuthorityResult,
} from "../operator/authority-result-verifier";
import { commandDerivedReceiptFields } from "../operator/lifecycle-result";
import {
  authenticateSealedLifecycleArtifact,
  isAuthenticatedLifecycleCommand,
  type AuthenticatedLifecycleCommand,
} from "../operator/lifecycle-submitter";
import { STAGING_GATE7_CONTINUITY } from "../operator/staging-gate7-continuity";
import {
  ADMISSION_AUTHORITY_ID,
  ADMISSION_POLICY_EPOCH,
  STAGING_ADMISSION_AUTHORITY_ID,
  type LifecycleReceipt,
} from "../workers/admission-service/authority";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION,
  signAuthorityInitializationCommand,
  signAuthorityReleaseRotationCommand,
  type AuthorityInitializationCommand,
  type AuthorityReleaseRotationCommand,
  type CommandDerivedReceipt,
} from "../workers/admission-service/operator-command";

// Frozen inputs (also pinned by tests/authority-result-attestation.test.ts). This file must never change them.
const GOLDEN_SHA256 = "2608a25a33945088310ed959861e610bacde68beec58e676512465fddbb64a40";
const MANIFEST_FIXTURE_SHA256 = "465e888e39617752da240eee09a78bbe99d948691bd1be7e8f0b851942750e14";
const THIRD_SEED_HEX = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"; // RFC 8032 test key 3 seed, TEST KEY - NEVER PROVISION.
const THIRD_PUBLIC_HEX = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"; // RFC 8032 test key 3, TEST KEY - NEVER PROVISION.

const NOW = 1_800_000_000_000;
const OBSERVED = NOW - 1_000;
const NONCE = "0123456789abcdef0123456789abcdef";
const OTHER_NONCE = "fedcba9876543210fedcba9876543210";
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const flipHex = (value: string) => (value[0] === "a" ? "b" : "a") + value.slice(1);
const sealed = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

// ---------------------------------------------------------------------------------------------------------------------
// Fixtures
interface RfcKey { privateKeyPkcs8: string; publicKey: string; fingerprint: string }
let rfcPromise: Promise<Record<"production" | "staging", RfcKey>> | undefined;
/** RFC 8032 test vectors frozen in the golden fixture (TEST KEYS - NEVER PROVISION). Nothing is generated or rewritten. */
const rfcKeys = () => (rfcPromise ??= readFile(new URL("./fixtures/authority-result-attestation-v2.golden.json", import.meta.url), "utf8")
  .then((text) => (JSON.parse(text) as { keys: Record<"production" | "staging", RfcKey> }).keys));
// ---------------------------------------------------------------------------------------------------------------------
let manifestPromise: Promise<AuthorityResultTrustManifest> | undefined;
const manifest = () => (manifestPromise ??= readFile(new URL("./fixtures/authority-result-trust-v1.test.json", import.meta.url), "utf8").then(parseAuthorityResultTrustManifest));

interface OperatorKey { privateKey: string; publicKey: string }
async function operatorKey(): Promise<OperatorKey> {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  return {
    privateKey: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))),
    publicKey: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))),
  };
}

const ISSUED = NOW - 2_000;
const initializeCommand = (environment: "production" | "staging" = "production", release = "release-a", key = "key-a"): AuthorityInitializationCommand =>
  [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", environment, environment === "production" ? ADMISSION_AUTHORITY_ID : STAGING_ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, release, key, ISSUED, true];
const rotateCommand = (): AuthorityReleaseRotationCommand =>
  [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "release-a", "release-b", "key-b",
    ISSUED, ISSUED + 60_000, ISSUED, true];

async function authenticated(operation: "initialize" | "rotate-release", operator: OperatorKey, options: { environment?: "production" | "staging"; release?: string; key?: string } = {}) {
  const environment = options.environment ?? "production";
  let bytes: Uint8Array;
  if (operation === "initialize") {
    const command = initializeCommand(environment, options.release, options.key);
    bytes = sealed({ command, signature: await signAuthorityInitializationCommand(command, operator.privateKey) });
  } else {
    const command = rotateCommand();
    bytes = sealed({ command, signature: await signAuthorityReleaseRotationCommand(command, operator.privateKey) });
  }
  return { bytes, command: await authenticateSealedLifecycleArtifact(bytes, operator.publicKey, { expectedEnvironment: environment }) };
}

/** Authority-assigned fields: the command never names them. */
const AUTHORITY_ASSIGNED = { initialize: { sequence: 1, appliedMs: ISSUED + 4_000 }, "rotate-release": { sequence: 2, appliedMs: ISSUED + 4_000 } } as const;

function attestedReceipt(command: AuthenticatedLifecycleCommand, overrides: Partial<AttestationReceipt> = {}): AttestationReceipt {
  const operation = command.expected.operation;
  const base = attestationReceiptFromLifecycleReceipt({ ...command.expected, ...AUTHORITY_ASSIGNED[operation] } as LifecycleReceipt);
  return { ...base, ...overrides };
}

/** A release snapshot that is valid R06 for `receipt` (one row for a sequence-1 initialization, otherwise the two rows one rotation writes). */
function snapshotFor(receipt: AttestationReceipt): AttestationReleaseRow[] {
  const next: AttestationReleaseRow = { releaseId: receipt.nextReleaseId, keyId: receipt.nextKeyId, activatedMs: receipt.activatesMs, retiredMs: null };
  if (receipt.operation === "initialize") return [next];
  return [{ releaseId: receipt.currentReleaseId, keyId: "key-previous", activatedMs: receipt.activatesMs - 100_000, retiredMs: receipt.retiresMs }, next];
}

type Role = "production" | "staging";
async function envelopeBytes(role: Role, statement: ResultStatement): Promise<Uint8Array> {
  const key = (await rfcKeys())[role];
  return encodeResultAttestationEnvelope(await signResultAttestation(statement, { privateKey: key.privateKeyPkcs8, publicKey: key.publicKey }));
}
const writer = async (role: Role) => (await rfcKeys())[role].fingerprint;
const authorityIds = { production: ADMISSION_AUTHORITY_ID, staging: STAGING_ADMISSION_AUTHORITY_ID } as const;

async function lifecycleStatement(role: Role, receipt: AttestationReceipt, digest = receipt.digest): Promise<ResultStatement> {
  return makeLifecycleStatement({ trustEpoch: 1, environment: role, authorityId: authorityIds[role], policyEpoch: ADMISSION_POLICY_EPOCH as "phase5c-i1-epoch-1",
    digest, receipt: { ...receipt, digest }, observedAtMs: OBSERVED, writerKeyFingerprint: await writer(role) });
}
async function reconciliationStatement(role: Role, state: "EXACT_RECEIPT" | "NOT_FOUND" | "HISTORY_INCOMPLETE" | "UNINITIALIZED", digest: string,
  receipt: AttestationReceipt | null, releases?: AttestationReleaseRow[], nonce = NONCE): Promise<ResultStatement> {
  const common = { trustEpoch: 1 as const, environment: role, authorityId: authorityIds[role], policyEpoch: ADMISSION_POLICY_EPOCH as "phase5c-i1-epoch-1",
    digest, nonce, observedAtMs: OBSERVED, writerKeyFingerprint: await writer(role) };
  const rows = releases ?? (receipt ? snapshotFor(receipt) : [{ releaseId: "release-a", keyId: "key-a", activatedMs: ISSUED, retiredMs: null }]);
  if (state === "EXACT_RECEIPT") return makeReconciliationStatement({ ...common, initialized: true, coverage: "COMPLETE", status: "EXACT_RECEIPT", receipt, releases: rows });
  if (state === "NOT_FOUND") return makeReconciliationStatement({ ...common, initialized: true, coverage: "COMPLETE", status: "NOT_FOUND", receipt: null, releases: rows });
  if (state === "HISTORY_INCOMPLETE") return makeReconciliationStatement({ ...common, initialized: true, coverage: "INCOMPLETE", status: "HISTORY_INCOMPLETE", receipt: null, releases: rows });
  return makeReconciliationStatement({ ...common, initialized: false, coverage: "COMPLETE", status: "NOT_FOUND", receipt: null, releases: [] });
}

const expectLifecycle = (role: Role, digest: string): ResultAttestationExpectations =>
  ({ kind: "lifecycle", environment: role, authorityId: authorityIds[role], policyEpoch: ADMISSION_POLICY_EPOCH, digest });
const expectReconciliation = (role: Role, digest: string, nonce = NONCE): ResultAttestationExpectations =>
  ({ kind: "reconciliation", environment: role, authorityId: authorityIds[role], policyEpoch: ADMISSION_POLICY_EPOCH, digest, nonce });

async function verifyProduction(bytes: Uint8Array, expectations: ResultAttestationExpectations, command?: AuthenticatedLifecycleCommand, nowMs = NOW) {
  return verifyProductionAuthorityResult({ bytes, expectations, trustManifest: await manifest(), nowMs, authenticatedCommand: command });
}
async function verifyStaging(bytes: Uint8Array, expectations: ResultAttestationExpectations, nowMs = NOW) {
  return verifyStagingAuthorityResult({ bytes, expectations, trustManifest: await manifest(), nowMs });
}
async function verifiedStatement(bytes: Uint8Array, expectations: ResultAttestationExpectations): Promise<VerifiedAuthorityStatement> {
  return verifyAuthoritySignedStatement(bytes, expectations, await manifest(), NOW);
}

/** Requires rejection with exactly `code`, so each failure is attributed to its intended layer. */
async function rejects(label: string, run: () => unknown, code: string | RegExp): Promise<void> {
  let failure: unknown;
  let accepted = false;
  try { await run(); accepted = true; } catch (error) { failure = error; }
  assert.equal(accepted, false, `ACCEPTED (must fail closed): ${label}`);
  assert.ok(failure instanceof Error, `${label}: ${String(failure)}`);
  if (typeof code === "string") assert.equal(failure.message, code, label);
  else assert.match(failure.message, code, label);
}
function assertPositive(result: ProductionAuthorityResult, kind: "lifecycle" | "reconciliation", label: string) {
  assert.equal(result.status, "POSITIVE", label);
  assert.equal(result.kind, kind, label);
  assert.equal(isProductionAuthorityPositive(result), true, label);
}

const productionBuilders = {
  lifecycle: async (receipt: AttestationReceipt) => ({ bytes: await envelopeBytes("production", await lifecycleStatement("production", receipt)), expectations: expectLifecycle("production", receipt.digest) }),
  reconciliation: async (receipt: AttestationReceipt, releases?: AttestationReleaseRow[]) => ({
    bytes: await envelopeBytes("production", await reconciliationStatement("production", "EXACT_RECEIPT", receipt.digest, receipt, releases)), expectations: expectReconciliation("production", receipt.digest) }),
} as const;
const kinds = ["lifecycle", "reconciliation"] as const;

// ---------------------------------------------------------------------------------------------------------------------
test("frozen golden and trust fixtures are byte-identical (2B changes neither protocol nor vectors)", async () => {
  assert.equal(sha256(new Uint8Array(await readFile(new URL("./fixtures/authority-result-attestation-v2.golden.json", import.meta.url)))), GOLDEN_SHA256);
  assert.equal(sha256(new Uint8Array(await readFile(new URL("./fixtures/authority-result-trust-v1.test.json", import.meta.url)))), MANIFEST_FIXTURE_SHA256);
});

// ---------------------------------------------------------------------------------------------------------------------
// R07 command provenance (mandatory finding)
// ---------------------------------------------------------------------------------------------------------------------
test("authenticateSealedLifecycleArtifact results carry runtime provenance; structural lookalikes never qualify", async () => {
  const operator = await operatorKey();
  const { bytes, command } = await authenticated("initialize", operator);
  assert.equal(isAuthenticatedLifecycleCommand(command), true);
  // The TYPE alone is structural: a lookalike has exactly the same keys and deep-equal content, yet is not authenticated.
  const lookalike = { command: [...command.command], signature: command.signature, digest: command.digest, expected: { ...command.expected } } as unknown as AuthenticatedLifecycleCommand;
  assert.deepEqual(Object.keys(lookalike), Object.keys(command));
  assert.deepEqual(lookalike, command);
  const forgeries: Record<string, unknown> = {
    "hand-built structural object": lookalike,
    "spread copy": { ...command },
    "Object.assign copy": Object.assign({}, command),
    "JSON round trip": JSON.parse(JSON.stringify(command)),
    "structuredClone": structuredClone(command),
    "prototype spoof": Object.create(command),
    "Proxy wrapper": new Proxy(command, {}),
    "spread with substituted expected": { ...command, expected: { ...command.expected, nextKeyId: "key-x" } },
    "null": null,
    "string": "authenticated",
    "array": [],
  };
  for (const [label, forged] of Object.entries(forgeries)) assert.equal(isAuthenticatedLifecycleCommand(forged), false, label);
  // A fresh, genuine authentication of the same bytes is a distinct genuine object.
  const again = await authenticateSealedLifecycleArtifact(bytes, operator.publicKey);
  assert.notEqual(again, command);
  assert.equal(isAuthenticatedLifecycleCommand(again), true);
  // Public behaviour of the existing API is unchanged for its callers.
  assert.deepEqual(Object.keys(command).sort(), ["command", "digest", "expected", "signature"]);
});

test("authenticated command context is immutable after authentication", async () => {
  const operator = await operatorKey();
  const { command } = await authenticated("rotate-release", operator);
  const snapshot = JSON.stringify(command);
  assert.throws(() => { (command as { digest: string }).digest = "0".repeat(64); }, TypeError);
  assert.throws(() => { (command.expected as { nextKeyId: string }).nextKeyId = "key-x"; }, TypeError);
  assert.throws(() => { (command.expected as { retiresMs: number | null }).retiresMs = 1; }, TypeError);
  assert.throws(() => { (command.command as unknown as unknown[])[5] = "release-x"; }, TypeError);
  assert.throws(() => { delete (command as { signature?: string }).signature; }, TypeError);
  assert.equal(JSON.stringify(command), snapshot);
  assert.equal(isAuthenticatedLifecycleCommand(command), true);
});

test("authentication refuses wrong operator key, tampered artifact and wrong environment", async () => {
  const operator = await operatorKey();
  const other = await operatorKey();
  const { bytes } = await authenticated("initialize", operator);
  await rejects("wrong operator key", () => authenticateSealedLifecycleArtifact(bytes, other.publicKey), "operator-signature");
  const parsed = JSON.parse(new TextDecoder().decode(bytes)) as { command: unknown[]; signature: string };
  parsed.command[5] = "release-tampered";
  await rejects("tampered sealed artifact", () => authenticateSealedLifecycleArtifact(sealed(parsed), operator.publicKey), "operator-signature");
  await rejects("staging artifact as Production", async () => authenticateSealedLifecycleArtifact((await authenticated("initialize", operator, { environment: "staging" })).bytes, operator.publicKey), "invalid-sealed-artifact");
});

test("composer refuses every non-genuine command context, for positive AND negative statements", async () => {
  const operator = await operatorKey();
  const { command } = await authenticated("initialize", operator);
  const receipt = attestedReceipt(command);
  const positive = await productionBuilders.lifecycle(receipt);
  const negative = {
    bytes: await envelopeBytes("production", await reconciliationStatement("production", "NOT_FOUND", receipt.digest, null)),
    expectations: expectReconciliation("production", receipt.digest) };
  const lookalike = { command: [...command.command], signature: command.signature, digest: command.digest, expected: { ...command.expected } } as unknown as AuthenticatedLifecycleCommand;
  for (const [label, forged] of Object.entries({ lookalike, spread: { ...command }, "JSON round trip": JSON.parse(JSON.stringify(command)), "prototype spoof": Object.create(command),
    "Proxy wrapper": new Proxy(command, {}), "wrong digest lookalike": { ...lookalike, digest: flipHex(command.digest) } })) {
    for (const [name, fixture] of Object.entries({ positive, negative })) {
      await rejects(`${label} / ${name}`, () => verifyProduction(fixture.bytes, fixture.expectations, forged as AuthenticatedLifecycleCommand), "result-command-provenance");
      await rejects(`${label} / ${name} (composer)`, async () => composeProductionAuthorityResult(await verifiedStatement(fixture.bytes, fixture.expectations), forged), "result-command-provenance");
    }
  }
  // The same fixtures succeed with the genuine command.
  assertPositive(await verifyProduction(positive.bytes, positive.expectations, command), "lifecycle", "genuine");
});

// ---------------------------------------------------------------------------------------------------------------------
// Production positive composition
// ---------------------------------------------------------------------------------------------------------------------
for (const operation of ["initialize", "rotate-release"] as const) {
  for (const kind of kinds) {
    test(`Production ${kind} ${operation}: R06 + matching authenticated command is POSITIVE; R06 alone and wrong command are not`, async () => {
      const operator = await operatorKey();
      const { command } = await authenticated(operation, operator);
      const receipt = attestedReceipt(command);
      const { bytes, expectations } = await productionBuilders[kind](receipt);

      // positive: retains the ORIGINAL authenticated command; the retained R06 statement is a genuine branded object
      const result = await verifyProduction(bytes, expectations, command);
      assertPositive(result, kind, "matching command");
      assert.equal(result.status === "POSITIVE" && result.command, command, "the original authenticated command is retained by identity");
      assert.equal(result.status === "POSITIVE" && isVerifiedAuthorityStatement(result.authority), true);
      assert.equal(result.authority.statement.digest, command.digest);
      assert.equal(result.authority.statement.kind, kind);

      // R06 alone is NEVER positive
      const alone = await verifyProduction(bytes, expectations);
      assert.equal(alone.status, "VERIFIED_NON_POSITIVE");
      assert.equal(alone.status === "VERIFIED_NON_POSITIVE" && alone.observation, "COMMAND_CONTEXT_REQUIRED");
      assert.equal(isProductionAuthorityPositive(alone), false);
      assert.equal(isVerifiedAuthorityStatement(alone.authority), true);
      assert.equal(Object.hasOwn(alone, "command"), false);

      // wrong operation: the OTHER operation's authenticated command
      const otherOperation = operation === "initialize" ? "rotate-release" : "initialize";
      const wrong = (await authenticated(otherOperation, operator)).command;
      await rejects("wrong operation command", () => verifyProduction(bytes, expectations, wrong), "result-contract");
      // wrong operator key: same command content signed and authenticated by a different operator key
      const attacker = await operatorKey();
      const forgedKey = (await authenticated(operation, attacker)).command;
      assert.equal(forgedKey.digest, command.digest, "the command digest does not depend on the operator key");
      assert.notEqual(forgedKey.expected.keyFingerprint, command.expected.keyFingerprint);
      await rejects("same command, different operator key", () => verifyProduction(bytes, expectations, forgedKey), "result-contract");
      // wrong environment: a genuinely authenticated STAGING command
      if (operation === "initialize") {
        const staging = (await authenticated("initialize", operator, { environment: "staging" })).command;
        await rejects("staging command", () => verifyProduction(bytes, expectations, staging), "result-contract");
      }
    });
  }
}

test("sequence and appliedMs stay Authority-assigned: valid R06 values that differ from anything command-side are not rejected", async () => {
  const operator = await operatorKey();
  for (const operation of ["initialize", "rotate-release"] as const) {
    const { command } = await authenticated(operation, operator);
    for (const kind of kinds) {
      for (const overrides of [{ appliedMs: command.expected.activatesMs + 299_999 }, { appliedMs: command.expected.activatesMs - 299_999 }, { appliedMs: command.expected.activatesMs },
        ...(operation === "rotate-release" ? [{ sequence: 3 }, { sequence: 4_096 }] : [])]) {
        const receipt = attestedReceipt(command, overrides);
        const { bytes, expectations } = await productionBuilders[kind](receipt);
        assertPositive(await verifyProduction(bytes, expectations, command), kind, `${operation} ${kind} ${JSON.stringify(overrides)}`);
      }
    }
  }
});

test("the shared binding list is exactly the twelve R07 command-derived fields, and the comparator reports each single-field substitution", async () => {
  assert.deepEqual([...commandDerivedReceiptFields], ["digest", "version", "operation", "environment", "authorityId", "policyEpoch", "keyFingerprint",
    "currentReleaseId", "nextReleaseId", "nextKeyId", "activatesMs", "retiresMs"]);
  assert.equal(commandDerivedReceiptFields.length, 12);
  const operator = await operatorKey();
  for (const operation of ["initialize", "rotate-release"] as const) {
    const { command } = await authenticated(operation, operator);
    const receipt = attestedReceipt(command);
    assert.deepEqual(commandReceiptMismatches(receipt, command.expected), [], `${operation} baseline`);
    const attestedName = (field: string) => (field === "keyFingerprint" ? "operatorKeyFingerprint" : field);
    // every receipt field is either command-derived (compared) or Authority-assigned (not compared); nothing is silently dropped
    assert.deepEqual([...RECEIPT_FIELDS].filter((field) => !commandDerivedReceiptFields.map(attestedName).includes(field)), ["sequence", "appliedMs"]);
    for (const field of commandDerivedReceiptFields) {
      const name = attestedName(field);
      const current = receipt[name as keyof AttestationReceipt];
      const substitute: unknown = typeof current === "number" ? current + 1 : current === null ? 1 : typeof current === "string" ? `${current}x` : "other";
      assert.deepEqual(commandReceiptMismatches({ ...receipt, [name]: substitute } as AttestationReceipt, command.expected), [field], `${operation} ${field}`);
    }
    for (const field of ["sequence", "appliedMs"] as const) {
      assert.deepEqual(commandReceiptMismatches({ ...receipt, [field]: receipt[field] + 7 }, command.expected), [], `${operation} ${field} is not command-bound`);
    }
    // only operation-dependent fields can fail against the other operation's command
    const mismatch = (otherCommand: AuthenticatedLifecycleCommand) => commandReceiptMismatches(receipt, otherCommand.expected);
    const opposite = (await authenticated(operation === "initialize" ? "rotate-release" : "initialize", operator)).command;
    assert.ok(mismatch(opposite).includes("operation"));
  }
});

/** "refused" when the mutation throws (a frozen target in strict mode), "applied" when it went through. */
function attemptMutation(mutate: () => unknown): "refused" | "applied" {
  try { mutate(); return "applied"; } catch (error) { assert.ok(error instanceof TypeError, String(error)); return "refused"; }
}

test("the shared R07 field list is runtime-frozen: the reviewed same-length substitution cannot weaken the Production composer", async () => {
  const operator = await operatorKey();
  const { command } = await authenticated("initialize", operator);
  // A validly signed, R06-verified receipt whose nextKeyId differs from the authenticated command.
  const fixture = await productionBuilders.lifecycle(attestedReceipt(command, { nextKeyId: "key-attacker" }));
  const verified = await verifiedStatement(fixture.bytes, fixture.expectations);
  const before = [...commandDerivedReceiptFields];
  const list = commandDerivedReceiptFields as unknown as string[];
  const index = list.indexOf("nextKeyId");
  try {
    // The reviewed attack: replace nextKeyId by a field that is still compared, keeping the length at twelve.
    assert.equal(attemptMutation(() => { list[index] = "digest"; }), "refused", "in-place substitution");
    await rejects("different nextKeyId after the attempted substitution", () => composeProductionAuthorityResult(verified, command), "result-contract");
    await rejects("different nextKeyId after the attempted substitution (verify API)", () => verifyProduction(fixture.bytes, fixture.expectations, command), "result-contract");
    for (const [label, mutate] of Object.entries({
      push: () => list.push("sequence"), pop: () => list.pop(), splice: () => list.splice(index, 1, "digest"), shift: () => list.shift(),
      "length truncation": () => { list.length = 11; }, sort: () => list.sort(), reverse: () => list.reverse(), fill: () => list.fill("digest"),
      defineProperty: () => Object.defineProperty(list, String(index), { value: "digest" }),
    })) assert.equal(attemptMutation(mutate), "refused", label);
  } finally {
    // Against an unfrozen list, undo whatever went through so the rest of this file still runs against the original list.
    if (!Object.isFrozen(list)) list.splice(0, list.length, ...before);
  }
  assert.equal(Object.isFrozen(commandDerivedReceiptFields), true);
  assert.deepEqual([...commandDerivedReceiptFields], before);
  assert.equal(new Set(commandDerivedReceiptFields).size, 12);
});

test("the comparator refuses to compare unless the field sets are exact: an extra, missing or renamed key fails closed", async () => {
  const operator = await operatorKey();
  for (const operation of ["initialize", "rotate-release"] as const) {
    const { command } = await authenticated(operation, operator);
    const receipt = attestedReceipt(command);
    const expected: Record<string, unknown> = { ...command.expected };
    const without = (record: Record<string, unknown>, field: string) => Object.fromEntries(Object.entries(record).filter(([key]) => key !== field));
    const badExpected: Record<string, Record<string, unknown>> = {
      "extra key": { ...expected, sequence: 1 },
      "missing nextKeyId": without(expected, "nextKeyId"),
      // twelve keys, but the operator key under the attested name: the only rename belongs to the receipt side
      "renamed keyFingerprint": { ...without(expected, "keyFingerprint"), operatorKeyFingerprint: expected.keyFingerprint },
    };
    for (const [label, value] of Object.entries(badExpected)) {
      await rejects(`${operation} expected ${label}`, () => commandReceiptMismatches(receipt, value as unknown as CommandDerivedReceipt), "result-contract");
    }
    const attested: Record<string, unknown> = { ...receipt };
    const badReceipts: Record<string, Record<string, unknown>> = {
      "extra key": { ...attested, extra: 1 },
      "missing sequence": without(attested, "sequence"),
      "missing nextKeyId": without(attested, "nextKeyId"),
      "renamed operatorKeyFingerprint": { ...without(attested, "operatorKeyFingerprint"), keyFingerprint: attested.operatorKeyFingerprint },
    };
    for (const [label, value] of Object.entries(badReceipts)) {
      await rejects(`${operation} receipt ${label}`, () => commandReceiptMismatches(value as unknown as AttestationReceipt, command.expected), "result-contract");
    }
    assert.deepEqual(commandReceiptMismatches(receipt, command.expected), [], `${operation} exact sets still compare`);
  }
});

test("end to end, every receipt field that a signed statement can vary independently breaks the binding", async () => {
  const operator = await operatorKey();
  const rotate = (await authenticated("rotate-release", operator)).command;
  const initialize = (await authenticated("initialize", operator)).command;
  const otherKey = await operatorKey();
  const otherFingerprint = (await authenticated("initialize", otherKey)).command.expected.keyFingerprint;
  // [command, label, receipt override, digest replaced?]
  const rotateCases: [string, Partial<AttestationReceipt>][] = [
    ["operatorKeyFingerprint", { operatorKeyFingerprint: otherFingerprint }],
    ["currentReleaseId", { currentReleaseId: "release-x" }], ["nextReleaseId", { nextReleaseId: "release-x" }], ["nextKeyId", { nextKeyId: "key-x" }],
    ["activatesMs", { activatesMs: rotate.expected.activatesMs + 1_000 }], ["retiresMs", { retiresMs: (rotate.expected.retiresMs as number) + 1_000 }],
    ["operation", { operation: "initialize", sequence: 1, currentReleaseId: "release-b", retiresMs: null }],
  ];
  const initializeCases: [string, Partial<AttestationReceipt>][] = [
    ["operatorKeyFingerprint", { operatorKeyFingerprint: otherFingerprint }],
    ["currentReleaseId+nextReleaseId (initialize requires them equal)", { currentReleaseId: "release-x", nextReleaseId: "release-x" }],
    ["nextKeyId", { nextKeyId: "key-x" }], ["activatesMs", { activatesMs: initialize.expected.activatesMs + 1_000 }],
    ["operation", { operation: "rotate-release", sequence: 2, nextReleaseId: "release-z", retiresMs: initialize.expected.activatesMs + 60_000 }],
  ];
  for (const [command, cases] of [[rotate, rotateCases], [initialize, initializeCases]] as const) {
    for (const [label, overrides] of cases) {
      const receipt = attestedReceipt(command, overrides);
      for (const kind of kinds) {
        const fixture = await productionBuilders[kind](receipt);
        await rejects(`${command.expected.operation}/${kind}/${label}`, () => verifyProduction(fixture.bytes, fixture.expectations, command), "result-contract");
        // and without any command it is merely non-positive
        assert.equal((await verifyProduction(fixture.bytes, fixture.expectations)).status, "VERIFIED_NON_POSITIVE");
      }
    }
  }
  // digest: the statement/expectations name a different digest than the command
  const swapped = flipHex(rotate.digest);
  for (const kind of kinds) {
    const receipt = attestedReceipt(rotate, { digest: swapped });
    const fixture = await productionBuilders[kind](receipt);
    await rejects(`digest/${kind}`, () => verifyProduction(fixture.bytes, fixture.expectations, rotate), "result-contract");
  }
});

test("the four constants an R06 statement pins (version, environment, authorityId, policyEpoch) cannot vary in a signed statement at all", async () => {
  const operator = await operatorKey();
  const { command } = await authenticated("rotate-release", operator);
  for (const overrides of [{ version: 2 }, { environment: "staging" }, { authorityId: STAGING_ADMISSION_AUTHORITY_ID }, { policyEpoch: "phase5c-i1-epoch-2" }]) {
    await rejects(JSON.stringify(overrides), () => lifecycleStatement("production", attestedReceipt(command, overrides as Partial<AttestationReceipt>)), /^attestation-receipt$/u);
  }
});

test("reconciliation: current releases may legitimately differ from the historical receipt (no receipt-to-releases equality is invented)", async () => {
  const operator = await operatorKey();
  const { command } = await authenticated("initialize", operator);
  const receipt = attestedReceipt(command);
  // A later rotation left two rows whose releases are NOT the initialization receipt's release.
  const rows: AttestationReleaseRow[] = [
    { releaseId: "release-a", keyId: "key-a", activatedMs: receipt.activatesMs, retiredMs: receipt.activatesMs + 120_000 },
    { releaseId: "release-later", keyId: "key-later", activatedMs: receipt.activatesMs + 60_000, retiredMs: null }];
  const { bytes, expectations } = await productionBuilders.reconciliation(receipt, rows);
  const result = await verifyProduction(bytes, expectations, command);
  assertPositive(result, "reconciliation", "historical receipt, different current rows");
  const rowsOfResult = result.authority.statement.kind === "reconciliation" ? result.authority.statement.releases : [];
  assert.deepEqual(rowsOfResult.map((row) => row.releaseId), ["release-a", "release-later"]);
});

// ---------------------------------------------------------------------------------------------------------------------
// Signed negative observations and synthetic digests
// ---------------------------------------------------------------------------------------------------------------------
test("signed NOT_FOUND / HISTORY_INCOMPLETE are verified non-positive observations that need no command", async () => {
  const operator = await operatorKey();
  const { command } = await authenticated("initialize", operator);
  const digest = command.digest;
  const states = ["NOT_FOUND", "HISTORY_INCOMPLETE", "UNINITIALIZED"] as const;
  for (const state of states) {
    const bytes = await envelopeBytes("production", await reconciliationStatement("production", state, digest, null));
    const expectations = expectReconciliation("production", digest);
    const result = await verifyProduction(bytes, expectations);
    assert.equal(result.status, "VERIFIED_NON_POSITIVE", state);
    assert.equal(result.status === "VERIFIED_NON_POSITIVE" && result.observation, state === "HISTORY_INCOMPLETE" ? "HISTORY_INCOMPLETE" : "NOT_FOUND", state);
    assert.equal(result.kind, "reconciliation");
    assert.equal(isVerifiedAuthorityStatement(result.authority), true);
    assert.equal(isProductionAuthorityPositive(result), false);
    // supplying the matching authenticated command never upgrades a negative observation
    assert.equal((await verifyProduction(bytes, expectations, command)).status, "VERIFIED_NON_POSITIVE", `${state} with command`);
    // the retained statement is the original branded object produced by the frozen verifier
    const verified = await verifiedStatement(bytes, expectations);
    const composed = composeProductionAuthorityResult(verified);
    assert.equal(composed.authority, verified, "identity is preserved, not cloned");
    // and a command for a different digest is still a contract failure, even for a negative: inconsistent OPTIONAL context is a
    // caller contract mismatch, not an Authority observation ...
    const otherDigest = (await authenticated("initialize", operator, { release: "release-other" })).command;
    await rejects(`${state} wrong-digest command`, () => verifyProduction(bytes, expectations, otherDigest), "result-contract");
    await rejects(`${state} wrong-digest command (composer)`, () => composeProductionAuthorityResult(verified, otherDigest), "result-contract");
    // ... so the same signed negative stays reportable once that context is omitted (Slice 2C must not discard it).
    const withoutContext = composeProductionAuthorityResult(verified);
    assert.equal(withoutContext.status === "VERIFIED_NON_POSITIVE" && withoutContext.observation, state === "HISTORY_INCOMPLETE" ? "HISTORY_INCOMPLETE" : "NOT_FOUND");
    assert.equal(withoutContext.authority, verified);
  }
});

test("synthetic digest diagnostics: negatives report without a command, a signed EXACT_RECEIPT never becomes positive without that exact command", async () => {
  const operator = await operatorKey();
  const synthetic = "ab".repeat(32);
  const notFound = await envelopeBytes("production", await reconciliationStatement("production", "NOT_FOUND", synthetic, null));
  const result = await verifyProduction(notFound, expectReconciliation("production", synthetic));
  assert.equal(result.status === "VERIFIED_NON_POSITIVE" && result.observation, "NOT_FOUND");

  const { command } = await authenticated("initialize", operator);
  // An EXACT_RECEIPT that unexpectedly exists for the synthetic digest (Authority receipts carry their own digest).
  const receipt = attestedReceipt(command, { digest: synthetic });
  const exact = await productionBuilders.reconciliation(receipt);
  const withoutCommand = await verifyProduction(exact.bytes, exact.expectations);
  assert.equal(withoutCommand.status, "VERIFIED_NON_POSITIVE");
  assert.equal(withoutCommand.status === "VERIFIED_NON_POSITIVE" && withoutCommand.observation, "COMMAND_CONTEXT_REQUIRED");
  await rejects("command for a different digest", () => verifyProduction(exact.bytes, exact.expectations, command), "result-contract");
  const lifecycle = await productionBuilders.lifecycle(receipt);
  assert.equal((await verifyProduction(lifecycle.bytes, lifecycle.expectations)).status, "VERIFIED_NON_POSITIVE");
  await rejects("lifecycle command for a different digest", () => verifyProduction(lifecycle.bytes, lifecycle.expectations, command), "result-contract");
});

test("R06 verification failures surface from the frozen layer: nonce, digest, freshness, environment, authority, key, epoch", async () => {
  const operator = await operatorKey();
  const { command } = await authenticated("initialize", operator);
  const receipt = attestedReceipt(command);
  const recon = await productionBuilders.reconciliation(receipt);
  const life = await productionBuilders.lifecycle(receipt);
  await rejects("wrong nonce", () => verifyProduction(recon.bytes, expectReconciliation("production", receipt.digest, OTHER_NONCE), command), "attestation-expectation");
  await rejects("wrong digest", () => verifyProduction(life.bytes, expectLifecycle("production", flipHex(receipt.digest)), command), "attestation-expectation");
  await rejects("stale statement", () => verifyProduction(life.bytes, life.expectations, command, OBSERVED + 300_001), "attestation-stale");
  await rejects("future statement", () => verifyProduction(life.bytes, life.expectations, command, OBSERVED - 60_001), "attestation-stale");
  assertPositive(await verifyProduction(life.bytes, life.expectations, command, OBSERVED + 300_000), "lifecycle", "age boundary");
  await rejects("wrong environment expectation", () => verifyProduction(life.bytes, expectLifecycle("staging", receipt.digest), command), "attestation-expectation");
  await rejects("wrong authority expectation", () => verifyProduction(life.bytes, { ...life.expectations, authorityId: STAGING_ADMISSION_AUTHORITY_ID }, command), "attestation-expectation");
  await rejects("wrong kind expectation", () => verifyProduction(life.bytes, expectReconciliation("production", receipt.digest), command), "attestation-expectation");
  await rejects("settlement is not an Authority statement kind", () => verifyProduction(life.bytes, { ...life.expectations, kind: "settlement" } as unknown as ResultAttestationExpectations, command), "attestation-expectation");
  // trust epoch is part of the signed statement and frozen at 1
  const productionWriter = await writer("production");
  await rejects("trust epoch 2", () => makeLifecycleStatement({ trustEpoch: 2 as unknown as 1, environment: "production", authorityId: ADMISSION_AUTHORITY_ID,
    policyEpoch: "phase5c-i1-epoch-1", digest: receipt.digest, receipt, observedAtMs: OBSERVED, writerKeyFingerprint: productionWriter }), "attestation-statement");
  // a statement naming a key that is not in the manifest
  const unknownKey = await attestationKeyFingerprint(Buffer.from(THIRD_PUBLIC_HEX, "hex").toString("base64url"));
  const unknown = makeLifecycleStatement({ trustEpoch: 1, environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: "phase5c-i1-epoch-1",
    digest: receipt.digest, receipt, observedAtMs: OBSERVED, writerKeyFingerprint: unknownKey });
  const thirdPublic = Buffer.from(THIRD_PUBLIC_HEX, "hex").toString("base64url");
  const thirdPrivate = Buffer.from("302e020100300506032b657004220420" + THIRD_SEED_HEX, "hex").toString("base64url");
  const unknownEnvelope = encodeResultAttestationEnvelope(await signResultAttestation(unknown, { privateKey: thirdPrivate, publicKey: thirdPublic }));
  await rejects("unknown key (validly signed by a key the manifest does not list)", () => verifyProduction(unknownEnvelope, life.expectations, command), "attestation-key");
  // staging key signing a production statement that names the production writer
  const prodStatement = await lifecycleStatement("production", receipt);
  const stagingKey = (await rfcKeys()).staging;
  const forgedSignature = encodeResultAttestationEnvelope({ statement: prodStatement,
    signature: (await signResultAttestation(await lifecycleStatement("staging", attestedReceipt(command, { environment: "staging", authorityId: STAGING_ADMISSION_AUTHORITY_ID, operatorKeyFingerprint: receipt.operatorKeyFingerprint })),
      { privateKey: stagingKey.privateKeyPkcs8, publicKey: stagingKey.publicKey })).signature });
  await rejects("signature by the wrong key", () => verifyProduction(forgedSignature, life.expectations, command), "attestation-signature");
  // retired key (immediately non-verifiable)
  const base = JSON.parse(await readFile(new URL("./fixtures/authority-result-trust-v1.test.json", import.meta.url), "utf8")) as { environments: { keys: Record<string, unknown>[]; currentKeyFingerprint: string }[] };
  const productionSection = base.environments[0];
  const retired = { ...productionSection.keys[0], status: "retired", notAfterMs: NOW + 1_000_000 };
  productionSection.keys = [{ keyFingerprint: unknownKey, publicKey: thirdPublic, status: "active", notBeforeMs: 1_700_000_000_000, notAfterMs: null }, retired];
  productionSection.currentKeyFingerprint = unknownKey;
  const retiredManifest = await parseAuthorityResultTrustManifest(JSON.stringify(base));
  await rejects("retired key", () => verifyProductionAuthorityResult({ bytes: life.bytes, expectations: life.expectations, trustManifest: retiredManifest, nowMs: NOW, authenticatedCommand: command }), "attestation-key");
  await rejects("manifest that was not parsed by the frozen parser", () => verifyProductionAuthorityResult({ bytes: life.bytes, expectations: life.expectations,
    trustManifest: JSON.parse(JSON.stringify(retiredManifest)) as AuthorityResultTrustManifest, nowMs: NOW, authenticatedCommand: command }), "attestation-manifest");
});

// ---------------------------------------------------------------------------------------------------------------------
// R06 provenance of the verified statement
// ---------------------------------------------------------------------------------------------------------------------
test("composers require a genuine branded VerifiedAuthorityStatement (frozen runtime provenance)", async () => {
  const operator = await operatorKey();
  const { command } = await authenticated("initialize", operator);
  const receipt = attestedReceipt(command);
  const { bytes, expectations } = await productionBuilders.lifecycle(receipt);
  const verified = await verifiedStatement(bytes, expectations);
  assertPositive(composeProductionAuthorityResult(verified, command), "lifecycle", "genuine");
  const prototypeSpoof = Object.create(verified) as unknown;
  const forgeries: Record<string, unknown> = {
    "hand-built lookalike": { layer: "R06-authority-signature", acceptance: "NOT-PRODUCTION-POSITIVE-ACCEPTANCE", statement: verified.statement,
      signingKeyFingerprint: verified.signingKeyFingerprint, verifiedAtMs: verified.verifiedAtMs, expectations: verified.expectations },
    "spread copy": { ...verified },
    "Object.assign copy": Object.assign({}, verified),
    "JSON round trip": JSON.parse(JSON.stringify(verified)),
    "structuredClone": structuredClone(verified),
    "prototype spoof": prototypeSpoof,
    "Proxy wrapper": new Proxy(verified, {}),
    "cast of the bare statement": { statement: verified.statement } as unknown as VerifiedAuthorityStatement,
    "null": null,
    "the statement itself": verified.statement,
  };
  for (const [label, forged] of Object.entries(forgeries)) {
    assert.equal(isVerifiedAuthorityStatement(forged), false, label);
    await rejects(`production ${label}`, () => composeProductionAuthorityResult(forged, command), "result-authority-provenance");
    await rejects(`production ${label} without command`, () => composeProductionAuthorityResult(forged), "result-authority-provenance");
    await rejects(`staging ${label}`, () => composeStagingAuthorityResult(forged), "result-authority-provenance");
  }
  // positive wrappers are themselves unforgeable
  const positive = composeProductionAuthorityResult(verified, command);
  for (const copy of [{ ...positive }, JSON.parse(JSON.stringify(positive)) as unknown, Object.create(positive) as unknown, Object.assign({}, positive),
    new Proxy(positive, {})]) assert.equal(isProductionAuthorityPositive(copy), false);
  assert.equal(isStagingAuthorityPositive(positive), false);
});

// ---------------------------------------------------------------------------------------------------------------------
// Staging
// ---------------------------------------------------------------------------------------------------------------------
const gate7Receipt = () => attestationReceiptFromLifecycleReceipt(STAGING_GATE7_CONTINUITY.receipt as unknown as LifecycleReceipt);
const stagingDigest = STAGING_GATE7_CONTINUITY.receipt.digest;
const stagingBuilders = {
  lifecycle: async (receipt: AttestationReceipt) => ({ bytes: await envelopeBytes("staging", await lifecycleStatement("staging", receipt)), expectations: expectLifecycle("staging", receipt.digest) }),
  reconciliation: async (receipt: AttestationReceipt, releases?: AttestationReleaseRow[]) => ({
    bytes: await envelopeBytes("staging", await reconciliationStatement("staging", "EXACT_RECEIPT", receipt.digest, receipt, releases)), expectations: expectReconciliation("staging", receipt.digest) }),
} as const;

test("Staging: signed R06 + canonical Gate 7 pins is POSITIVE for lifecycle and reconciliation", async () => {
  for (const kind of kinds) {
    const { bytes, expectations } = await stagingBuilders[kind](gate7Receipt());
    const result = await verifyStaging(bytes, expectations);
    assert.equal(result.status, "POSITIVE", kind);
    assert.equal(result.kind, kind);
    assert.equal(result.environment, "staging");
    assert.equal(isStagingAuthorityPositive(result), true);
    for (const copy of [{ ...result }, Object.create(result) as unknown, new Proxy(result, {})]) assert.equal(isStagingAuthorityPositive(copy), false, kind);
    assert.equal(isProductionAuthorityPositive(result), false);
    assert.equal(isVerifiedAuthorityStatement(result.authority), true);
    assert.equal(result.authority.statement.digest, stagingDigest);
  }
});

test("Staging: every Gate 7 receipt field is an independent pin (frozen validator or Gate 7 pin refuses each substitution)", async () => {
  const canonical = gate7Receipt();
  assert.equal(RECEIPT_FIELDS.length, 14);
  const otherFingerprint = flipHex(canonical.operatorKeyFingerprint);
  // Layer "R06": the frozen validator makes the statement unrepresentable. Layer "PIN": a valid statement the Gate 7 pins refuse.
  const cases: [string, Partial<AttestationReceipt>, "R06" | "PIN"][] = [
    ["digest", { digest: flipHex(canonical.digest) }, "PIN"],
    ["version", { version: 2 as unknown as 1 }, "R06"],
    ["operation", { operation: "rotate-release" }, "R06"],
    ["environment", { environment: "production" }, "R06"],
    ["authorityId", { authorityId: ADMISSION_AUTHORITY_ID }, "R06"],
    ["policyEpoch", { policyEpoch: "phase5c-i1-epoch-2" as "phase5c-i1-epoch-1" }, "R06"],
    ["operatorKeyFingerprint", { operatorKeyFingerprint: otherFingerprint }, "PIN"],
    ["sequence", { sequence: 2 }, "R06"],
    ["appliedMs", { appliedMs: canonical.appliedMs + 1 }, "PIN"],
    ["currentReleaseId+nextReleaseId", { currentReleaseId: "staging-other", nextReleaseId: "staging-other" }, "PIN"],
    ["currentReleaseId alone", { currentReleaseId: "staging-other" }, "R06"],
    ["nextKeyId", { nextKeyId: "staging-other-key" }, "PIN"],
    ["activatesMs", { activatesMs: canonical.activatesMs + 1 }, "PIN"],
    ["retiresMs", { retiresMs: canonical.activatesMs + 10 }, "R06"],
  ];
  // A refusal only proves the staging composer works if the same path ACCEPTS the canonical evidence: otherwise a composer that threw
  // (or was a no-op) for everything would pass every `rejects` below. So the loop is anchored by a signed canonical positive control,
  // and it must execute an explicit minimum number of signed PIN cases (each a valid, signed, R06-verified statement that only the
  // Gate 7 pin layer can refuse) as well as the R06-layer cases.
  for (const kind of kinds) {
    const control = await stagingBuilders[kind](canonical);
    assert.equal((await verifyStaging(control.bytes, control.expectations)).status, "POSITIVE", `positive control/${kind}`);
  }
  const executed = { R06: 0, PIN: 0 };
  for (const [field, overrides, layer] of cases) {
    const receipt = { ...canonical, ...overrides };
    for (const kind of kinds) {
      if (layer === "R06") {
        await rejects(`${field}/${kind}`, () => stagingBuilders[kind](receipt), /^attestation-(receipt|statement)$/u);
      } else {
        const fixture = await stagingBuilders[kind](receipt, kind === "reconciliation" ? snapshotFor(receipt) : undefined);
        assert.ok(fixture.bytes.byteLength > 0, `${field}/${kind}: a signed envelope was actually produced for the pin layer to refuse`);
        await rejects(`${field}/${kind}`, () => verifyStaging(fixture.bytes, fixture.expectations), "result-contract");
      }
      executed[layer]++;
    }
  }
  const expectedPerLayer = (layer: "R06" | "PIN") => cases.filter((entry) => entry[2] === layer).length * kinds.length;
  assert.equal(executed.PIN, expectedPerLayer("PIN"), "every PIN case ran for every kind");
  assert.equal(executed.R06, expectedPerLayer("R06"), "every R06 case ran for every kind");
  assert.ok(executed.PIN >= 12, `at least twelve signed Gate 7 pin cases must execute (ran ${executed.PIN}); the loop can never silently run zero`);
  assert.equal(executed.R06 + executed.PIN, cases.length * kinds.length);
});

test("Staging: a later mutation of the imported RECEIPT_FIELDS array cannot weaken the Gate 7 pins", async () => {
  // Signed and R06-verified BEFORE the mutation: the frozen protocol's own validator also reads RECEIPT_FIELDS.
  const canonical = await stagingBuilders.lifecycle(gate7Receipt());
  const canonicalVerified = await verifiedStatement(canonical.bytes, canonical.expectations);
  const wrong = await stagingBuilders.lifecycle({ ...gate7Receipt(), nextKeyId: "staging-attacker-key" });
  const wrongVerified = await verifiedStatement(wrong.bytes, wrong.expectations);
  const shared = RECEIPT_FIELDS as unknown as string[];
  const before = [...shared];
  // Premise: the frozen protocol export is a mutable array and 2B leaves it untouched. If the protocol ever freezes it, this
  // insulation test must be revisited deliberately.
  assert.equal(Object.isFrozen(shared), false);
  try {
    shared[shared.indexOf("nextKeyId")] = "digest"; // the same-length substitution
    await rejects("different nextKeyId after substitution", () => composeStagingAuthorityResult(wrongVerified), "result-contract");
    assert.equal(composeStagingAuthorityResult(canonicalVerified).status, "POSITIVE", "canonical evidence is unaffected (the local copy is used)");
    shared.splice(0, shared.length); // emptied entirely
    await rejects("different nextKeyId after emptying", () => composeStagingAuthorityResult(wrongVerified), "result-contract");
    assert.equal(composeStagingAuthorityResult(canonicalVerified).status, "POSITIVE");
  } finally {
    shared.splice(0, shared.length, ...before);
  }
  assert.deepEqual([...RECEIPT_FIELDS], before);
  // Unchanged Gate 7 semantics after restoration: the wrong receipt is still refused and the canonical one is positive.
  await rejects("different nextKeyId, restored", () => composeStagingAuthorityResult(wrongVerified), "result-contract");
  assert.equal(composeStagingAuthorityResult(canonicalVerified).status, "POSITIVE");
});

test("Staging: a wrong release row cannot be signed with the canonical receipt (R06 ties them) and a canonical row cannot rescue a wrong receipt", async () => {
  const canonical = gate7Receipt();
  const row = snapshotFor(canonical)[0];
  for (const wrong of [{ releaseId: "staging-other" }, { keyId: "staging-other-key" }, { activatedMs: row.activatedMs + 1 }, { retiredMs: row.activatedMs + 10 }]) {
    await rejects(JSON.stringify(wrong), () => stagingBuilders.reconciliation(canonical, [{ ...row, ...wrong }]), /^attestation-(releases|statement)$/u);
  }
  await rejects("two rows in staging", () => stagingBuilders.reconciliation(canonical, [{ releaseId: "old", keyId: "old-key", activatedMs: row.activatedMs - 10, retiredMs: row.activatedMs + 10 }, row]), "attestation-releases");
  const wrongReceipt = { ...canonical, nextKeyId: "staging-other-key" };
  const fixture = await stagingBuilders.reconciliation(wrongReceipt, [row].map((r) => ({ ...r, keyId: "staging-other-key" })));
  await rejects("canonical-looking row with wrong receipt", () => verifyStaging(fixture.bytes, fixture.expectations), "result-contract");
});

test("Staging: rotation is impossible, Production evidence is rejected, signed negatives stay non-positive", async () => {
  const operator = await operatorKey();
  const rotation = attestedReceipt((await authenticated("rotate-release", operator)).command, { environment: "staging", authorityId: STAGING_ADMISSION_AUTHORITY_ID });
  await rejects("staging rotate-release statement", () => lifecycleStatement("staging", rotation), "attestation-receipt");

  // Production-signed evidence, composed or verified through the staging API
  const { command } = await authenticated("initialize", operator);
  const production = await productionBuilders.lifecycle(attestedReceipt(command));
  await rejects("production bytes, production expectations", () => verifyStaging(production.bytes, production.expectations), "result-contract");
  await rejects("production bytes, staging expectations", () => verifyStaging(production.bytes, expectLifecycle("staging", command.digest)), "attestation-expectation");
  await rejects("production verified statement", async () => composeStagingAuthorityResult(await verifiedStatement(production.bytes, production.expectations)), "result-contract");
  // Staging-signed canonical evidence through the Production API
  const stagingCanonical = await stagingBuilders.lifecycle(gate7Receipt());
  await rejects("staging evidence in Production API", () => verifyProduction(stagingCanonical.bytes, stagingCanonical.expectations, command), "result-contract");
  await rejects("staging verified statement composed as Production", async () => composeProductionAuthorityResult(await verifiedStatement(stagingCanonical.bytes, stagingCanonical.expectations), command), "result-contract");

  // Signed negatives carry no receipt: no canonical equality is required, a synthetic digest is fine.
  for (const [state, digest] of [["NOT_FOUND", stagingDigest], ["HISTORY_INCOMPLETE", stagingDigest], ["NOT_FOUND", "cd".repeat(32)], ["UNINITIALIZED", "cd".repeat(32)]] as const) {
    const bytes = await envelopeBytes("staging", await reconciliationStatement("staging", state, digest, null));
    const result = await verifyStaging(bytes, expectReconciliation("staging", digest));
    assert.equal(result.status, "VERIFIED_NON_POSITIVE", `${state} ${digest.slice(0, 4)}`);
    assert.equal(result.status === "VERIFIED_NON_POSITIVE" && result.observation, state === "HISTORY_INCOMPLETE" ? "HISTORY_INCOMPLETE" : "NOT_FOUND");
    assert.equal(isStagingAuthorityPositive(result), false);
  }
  // An EXACT_RECEIPT for a synthetic staging digest is never positive (the Gate 7 pin names the canonical digest).
  const syntheticExact = await stagingBuilders.lifecycle({ ...gate7Receipt(), digest: "cd".repeat(32) });
  await rejects("synthetic staging digest EXACT_RECEIPT", () => verifyStaging(syntheticExact.bytes, syntheticExact.expectations), "result-contract");
  // Staging negatives still enforce target/environment/authority/trust
  const negative = await envelopeBytes("staging", await reconciliationStatement("staging", "NOT_FOUND", stagingDigest, null));
  await rejects("staging negative under production expectations", () => verifyStaging(negative, expectReconciliation("production", stagingDigest)), "attestation-expectation");
  await rejects("staging negative wrong nonce", () => verifyStaging(negative, expectReconciliation("staging", stagingDigest, OTHER_NONCE)), "attestation-expectation");
  await rejects("staging negative stale", () => verifyStaging(negative, expectReconciliation("staging", stagingDigest), OBSERVED + 300_001), "attestation-stale");
});

// ---------------------------------------------------------------------------------------------------------------------
// Downgrade closure
// ---------------------------------------------------------------------------------------------------------------------
test("legacy / unsigned positives and malformed envelopes have no path to either composition API", async () => {
  const operator = await operatorKey();
  const { command } = await authenticated("initialize", operator);
  const legacyReceipt = (role: Role, receipt: AttestationReceipt) => ({ digest: receipt.digest, version: 1, operation: receipt.operation, environment: role,
    authorityId: authorityIds[role], policyEpoch: ADMISSION_POLICY_EPOCH, keyFingerprint: receipt.operatorKeyFingerprint, sequence: receipt.sequence,
    appliedMs: receipt.appliedMs, currentReleaseId: receipt.currentReleaseId, nextReleaseId: receipt.nextReleaseId, nextKeyId: receipt.nextKeyId,
    activatesMs: receipt.activatesMs, retiresMs: receipt.retiresMs });
  const productionReceipt = attestedReceipt(command);
  const stagingReceipt = gate7Receipt();
  const legacyBase = (role: Role, digest: string) => ({ version: 1, digest, environment: role, authorityId: authorityIds[role], policyEpoch: ADMISSION_POLICY_EPOCH, observedAtMs: OBSERVED });
  const legacy = {
    "unsigned lifecycle SUCCESS": { role: "production" as const, kind: "lifecycle" as const, value: { ...legacyBase("production", command.digest), status: "SUCCESS", receipt: legacyReceipt("production", productionReceipt) } },
    "unsigned lifecycle ALREADY_APPLIED": { role: "production" as const, kind: "lifecycle" as const, value: { ...legacyBase("production", command.digest), status: "ALREADY_APPLIED", receipt: legacyReceipt("production", productionReceipt) } },
    "unsigned reconciliation EXACT_RECEIPT": { role: "production" as const, kind: "reconciliation" as const, value: { ...legacyBase("production", command.digest), nonce: NONCE, status: "EXACT_RECEIPT",
      initialized: true, coverage: "COMPLETE", receipt: legacyReceipt("production", productionReceipt), releases: [{ release_id: "release-a", key_id: "key-a", activated_ms: ISSUED, retired_ms: null }] } },
    "unsigned staging lifecycle SUCCESS": { role: "staging" as const, kind: "lifecycle" as const, value: { ...legacyBase("staging", stagingDigest), status: "SUCCESS", receipt: legacyReceipt("staging", stagingReceipt) } },
    "unsigned staging EXACT_RECEIPT": { role: "staging" as const, kind: "reconciliation" as const, value: { ...legacyBase("staging", stagingDigest), nonce: NONCE, status: "EXACT_RECEIPT",
      initialized: true, coverage: "COMPLETE", receipt: legacyReceipt("staging", stagingReceipt), releases: STAGING_GATE7_CONTINUITY.releases } },
  };
  for (const [label, item] of Object.entries(legacy)) {
    const bytes = sealed(item.value);
    const digest = item.value.digest;
    const expectations = item.kind === "lifecycle" ? expectLifecycle(item.role, digest) : expectReconciliation(item.role, digest);
    if (item.role === "production") {
      await rejects(`${label} with command`, () => verifyProduction(bytes, expectations, command), "attestation-envelope");
      await rejects(`${label} without command`, () => verifyProduction(bytes, expectations), "attestation-envelope");
    } else {
      await rejects(label, () => verifyStaging(bytes, expectations), "attestation-envelope");
    }
  }
  // malformed or unsupported signed envelopes
  const { bytes, expectations } = await productionBuilders.lifecycle(productionReceipt);
  const text = new TextDecoder().decode(bytes);
  const reserialized = sealed(JSON.parse(text));
  const garbage: Record<string, Uint8Array> = {
    empty: new Uint8Array(0), truncated: bytes.slice(0, bytes.length - 3), "trailing byte": new Uint8Array([...bytes, 0x0a]), "pretty printed": new TextEncoder().encode(JSON.stringify(JSON.parse(text), null, 1)),
    "bad signature length": new TextEncoder().encode(text.replace(/"signature":"[^"]+"/u, '"signature":"AAAA"')),
    "unsupported tuple version": new TextEncoder().encode(text.replace("[2,1,", "[1,1,")),
    "unsigned statement tuple only": sealed(JSON.parse(text).statement),
    "oversized": new Uint8Array(8_193).fill(0x20),
  };
  for (const [label, value] of Object.entries(garbage)) {
    await rejects(`production ${label}`, () => verifyProduction(value, expectations, command), /^attestation-[a-z-]+$/u);
    await rejects(`staging ${label}`, () => verifyStaging(value, expectations), /^attestation-[a-z-]+$/u);
  }
  assert.equal(new TextDecoder().decode(reserialized), text, "canonical envelope bytes are already compact JSON (control for the pretty-printed case)");
  // a signature over a tampered statement
  const tampered = new TextEncoder().encode(text.replace(`"${productionReceipt.nextKeyId}"`, '"key-zzz"'));
  await rejects("tampered statement", () => verifyProduction(tampered, expectations, command), "attestation-signature");
  // composers accept nothing but a genuine verified statement: a raw legacy result object or raw bytes is not one
  await rejects("raw bytes", () => composeProductionAuthorityResult(bytes, command), "result-authority-provenance");
  await rejects("raw legacy object", () => composeStagingAuthorityResult(legacy["unsigned staging lifecycle SUCCESS"].value), "result-authority-provenance");
  // no legacy verifier is reachable from the new module, and it never swallows a failure to try another path
  const source = await readFile(new URL("../operator/authority-result-verifier.ts", import.meta.url), "utf8");
  const code = source.replace(/\/\*[\s\S]*?\*\//gu, "").replace(/^\s*\/\/.*$/gmu, "");
  assert.equal(/\bcatch\b|\.catch\(|\btry\b/u.test(code), false, "no try/catch fallback");
  assert.equal(/verifyLifecycleResult|verifyProductionLifecycleResult|parseStrictJson/u.test(code), false, "no legacy result verifier");
});

// ---------------------------------------------------------------------------------------------------------------------
// Misuse and mutation
// ---------------------------------------------------------------------------------------------------------------------
test("caller-owned inputs are snapshotted before the first await; returned objects and branded evidence are immutable", async () => {
  const operator = await operatorKey();
  const { command } = await authenticated("initialize", operator);
  const receipt = attestedReceipt(command);
  const { bytes, expectations } = await productionBuilders.lifecycle(receipt);

  // expectations, bytes and the input record are all mutated right after the call, while it is awaiting
  const mutableExpectations = { ...expectations } as { -readonly [K in keyof ResultAttestationExpectations]: ResultAttestationExpectations[K] };
  const mutableBytes = new Uint8Array(bytes);
  const input = { bytes: mutableBytes, expectations: mutableExpectations as ResultAttestationExpectations, trustManifest: await manifest(), nowMs: NOW,
    authenticatedCommand: command as AuthenticatedLifecycleCommand | undefined };
  const pending = verifyProductionAuthorityResult(input);
  mutableExpectations.digest = flipHex(receipt.digest);
  mutableBytes.fill(0);
  input.authenticatedCommand = undefined;
  const result = await pending;
  assertPositive(result, "lifecycle", "original inputs decided the result");
  assert.equal(result.status === "POSITIVE" && result.command, command);
  assert.equal(result.authority.expectations.digest, receipt.digest, "the retained expectations are the frozen snapshot, not the mutated object");

  // the positive wrapper, the branded statement and the retained command cannot be modified
  assert.throws(() => { (result as { status: string }).status = "SUCCESS"; }, TypeError);
  assert.throws(() => { (result as unknown as { command: unknown }).command = undefined; }, TypeError);
  assert.throws(() => { delete (result as { authority?: unknown }).authority; }, TypeError);
  assert.throws(() => { (result.authority as unknown as { statement: unknown }).statement = {}; }, TypeError);
  assert.throws(() => { (result.authority.statement as unknown as { digest: string }).digest = "0".repeat(64); }, TypeError);
  assert.throws(() => { (result.authority.expectations as unknown as { digest: string }).digest = "0".repeat(64); }, TypeError);
  assert.throws(() => { (result as unknown as { extra: number }).extra = 1; }, TypeError);
  assert.equal(result.status === "POSITIVE" && result.command.expected.nextKeyId, receipt.nextKeyId);
  assert.equal(isProductionAuthorityPositive(result), true);
});

test("a verified statement cannot be reused with another command, nor a command with another statement; evidence cannot cross digest or environment", async () => {
  const operator = await operatorKey();
  const first = (await authenticated("initialize", operator)).command;
  const second = (await authenticated("initialize", operator, { release: "release-second", key: "key-second" })).command;
  assert.notEqual(first.digest, second.digest);
  const firstFixture = await productionBuilders.lifecycle(attestedReceipt(first));
  const secondFixture = await productionBuilders.reconciliation(attestedReceipt(second));
  const firstVerified = await verifiedStatement(firstFixture.bytes, firstFixture.expectations);
  const secondVerified = await verifiedStatement(secondFixture.bytes, secondFixture.expectations);
  assertPositive(composeProductionAuthorityResult(firstVerified, first), "lifecycle", "first/first");
  assertPositive(composeProductionAuthorityResult(secondVerified, second), "reconciliation", "second/second");
  await rejects("first statement, second command", () => composeProductionAuthorityResult(firstVerified, second), "result-contract");
  await rejects("second statement, first command", () => composeProductionAuthorityResult(secondVerified, first), "result-contract");
  // same digest evidence, different environment
  const stagingVerified = await verifiedStatement((await stagingBuilders.lifecycle(gate7Receipt())).bytes, expectLifecycle("staging", stagingDigest));
  await rejects("staging statement into Production", () => composeProductionAuthorityResult(stagingVerified, first), "result-contract");
  await rejects("production statement into staging", () => composeStagingAuthorityResult(firstVerified), "result-contract");
  // a signed NEGATIVE observation has no receipt to trip a pin, so the environment/digest checks alone must stop it crossing
  const productionNegative = await verifiedStatement(await envelopeBytes("production", await reconciliationStatement("production", "NOT_FOUND", first.digest, null)), expectReconciliation("production", first.digest));
  const stagingNegative = await verifiedStatement(await envelopeBytes("staging", await reconciliationStatement("staging", "HISTORY_INCOMPLETE", stagingDigest, null)), expectReconciliation("staging", stagingDigest));
  await rejects("production negative into staging", () => composeStagingAuthorityResult(productionNegative), "result-contract");
  await rejects("staging negative into Production", () => composeProductionAuthorityResult(stagingNegative), "result-contract");
  assert.equal(composeProductionAuthorityResult(productionNegative).status, "VERIFIED_NON_POSITIVE");
  assert.equal(composeStagingAuthorityResult(stagingNegative).status, "VERIFIED_NON_POSITIVE");
  // one verified statement yields independent frozen results; nothing is shared mutably
  const a = composeProductionAuthorityResult(firstVerified, first);
  const b = composeProductionAuthorityResult(firstVerified, first);
  assert.notEqual(a, b);
  assert.equal(a.authority, b.authority);
  assert.equal(a.authority, firstVerified);
});

// ---------------------------------------------------------------------------------------------------------------------
// Activation scope (R06 Slice 2C)
// ---------------------------------------------------------------------------------------------------------------------
test("2C: the composer module is consumed only through the reviewed reader (see tests/authority-activation-guards.test.ts)", async () => {
  const root = new URL("../", import.meta.url);
  const MODULE = /authority-result-verifier/u;
  // Relays, guards, observers, executors and the R2 writer must not reach the composers: they never decide acceptance.
  for (const path of ["workers/lifecycle-observer.ts", "workers/staging-lifecycle-observer.ts", "workers/lifecycle-mailbox/index.ts", "workers/lifecycle-mailbox/processor.ts",
    "workers/lifecycle-mailbox/dispatch-guard.ts", "workers/lifecycle-mailbox/staging-index.ts", "workers/lifecycle-mailbox/staging-processor.ts",
    "workers/lifecycle-mailbox/staging-dispatch-guard.ts", "workers/operator-lifecycle-executor.ts", "workers/staging-operator-lifecycle-executor.ts",
    "operator/r2-transport.ts", "operator/attested-relay.ts", "operator/lifecycle-submitter.ts"]) {
    const text = await readFile(new URL(path, root), "utf8");
    assert.equal(MODULE.test(text), false, path);
    assert.equal(/composeProductionAuthorityResult|composeStagingAuthorityResult|verifyProductionAuthorityResult|verifyStagingAuthorityResult/u.test(text), false, path);
  }
  // The composer itself imports no active transport, mailbox, observer, guard, R2 or CLI module.
  const own = await readFile(new URL("operator/authority-result-verifier.ts", root), "utf8");
  for (const match of own.matchAll(/from "([^"]+)"/gu)) {
    assert.match(match[1], /^(?:\.\.\/src\/lib\/authority-result-(?:attestation|trust)|\.\/lifecycle-(?:result|submitter)|\.\/staging-gate7-continuity|\.\.\/workers\/admission-service\/operator-command)$/u, `import ${match[1]}`);
  }
});
