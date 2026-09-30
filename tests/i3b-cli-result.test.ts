import assert from "node:assert/strict";
import { test } from "node:test";
import { createCliResultHarness } from "./workers/support/i3b-cli-result-harness";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, commandDigest, expectedCommandReceipt, signAuthorityInitializationCommand, signAuthorityReleaseRotationCommand,
  type AuthorityInitializationCommand, type AuthorityReleaseRotationCommand } from "../workers/admission-service/operator-command";

const digest = "a".repeat(64);
const nonce = "b".repeat(32);
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const envelope = () => ({ version: 1, digest, environment: "production", authorityId: "production-public-inquiries-v1",
  policyEpoch: "phase5c-i1-epoch-1", observedAtMs: Date.now(), status: "UNCONFIRMED" });

test("actual CLI read-result treats malformed, stale and mismatched HTTP-200 observations as UNCONFIRMED", async () => {
  const cli = await createCliResultHarness();
  try {
    const cases = [
      new TextEncoder().encode("{"),
      encode({ ...envelope(), extra: true }),
      encode({ ...envelope(), observedAtMs: Date.now() - 300_001 }),
      encode({ ...envelope(), digest: "c".repeat(64) }),
      encode({ ...envelope(), environment: "staging" }),
      encode({ ...envelope(), authorityId: "other" }),
      encode({ ...envelope(), policyEpoch: "other" }),
      encode({ ...envelope(), version: 2 }),
    ];
    for (const bytes of cases) {
      const result = await cli.run(bytes, "lifecycle", digest);
      assert.equal(result.exitCode, 3, result.stderr);
      assert.equal((JSON.parse(result.stdout) as { status: string }).status, "UNCONFIRMED");
      assert.deepEqual(result.methods, ["GET"], "reading a result never submits a mutation");
    }
    const wrongNonce = encode({ ...envelope(), nonce: "c".repeat(32), status: "UNAVAILABLE" });
    const result = await cli.run(wrongNonce, "reconciliation", digest, nonce);
    assert.equal(result.exitCode, 3, result.stderr);
    assert.equal((JSON.parse(result.stdout) as { status: string }).status, "UNCONFIRMED");
    assert.deepEqual(result.methods, ["GET"]);
  } finally { await cli.dispose(); }
});

// --- Production command-backed read-result -----------------------------------------------------------------

const row = { release_id: "release-a", key_id: "key-a", activated_ms: 1_000, retired_ms: null };
const asJson = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const parsed = (stdout: string) => JSON.parse(stdout) as Record<string, unknown>;

async function signedCommands(privateKey: string, publicKey: string) {
  // Issued in 1970-01-01: far outside submission freshness, which historical result verification must not require.
  const initialize: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, "release-a", "key-a", 1_000, true];
  const rotate: AuthorityReleaseRotationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production", ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, "release-a", "release-b", "key-b", 2_000, 3_000, 2_000, true];
  const seal = (command: unknown, signature: string) => asJson({ command, signature });
  return {
    initialize: { artifact: seal(initialize, await signAuthorityInitializationCommand(initialize, privateKey)), digest: await commandDigest(initialize),
      expected: await expectedCommandReceipt(initialize, publicKey) },
    rotate: { artifact: seal(rotate, await signAuthorityReleaseRotationCommand(rotate, privateKey)), digest: await commandDigest(rotate),
      expected: await expectedCommandReceipt(rotate, publicKey) },
    seal, initializeCommand: initialize,
  };
}
const result = (digest: string, observedAtMs = Date.now()) => ({ version: 1, digest, environment: "production", authorityId: "production-public-inquiries-v1",
  policyEpoch: "phase5c-i1-epoch-1", observedAtMs });
const lifecycleOf = (digest: string, status: string, receipt: unknown) => asJson({ ...result(digest), status, receipt });
const exactOf = (digest: string, receipt: unknown) => asJson({ ...result(digest), nonce, status: "EXACT_RECEIPT", initialized: true, coverage: "COMPLETE", receipt, releases: [row] });

test("actual CLI read-result accepts positive Production results only with a matching authenticated command", async () => {
  const cli = await createCliResultHarness();
  try {
    const commands = await signedCommands(cli.privateKey, cli.publicKey);
    for (const [name, command] of [["initialize", commands.initialize], ["rotate-release", commands.rotate]] as const) {
      const applied = { ...command.expected, sequence: 9, appliedMs: Date.now() };
      // Without --command no positive result is ever accepted; it resolves fail-closed.
      for (const [kind, body, nonceArg] of [["lifecycle", lifecycleOf(command.digest, "SUCCESS", applied), undefined],
        ["lifecycle", lifecycleOf(command.digest, "ALREADY_APPLIED", applied), undefined], ["reconciliation", exactOf(command.digest, applied), nonce]] as const) {
        const without = await cli.run(body, kind, command.digest, nonceArg);
        assert.equal(without.exitCode, 3, `${name} ${kind} without command: ${without.stderr}`);
        assert.deepEqual(parsed(without.stdout), { status: "UNCONFIRMED", digest: command.digest, observation: "COMMAND_CONTEXT_REQUIRED" });
        assert.deepEqual(without.methods, ["GET"]);
      }
      // With the matching sealed command (expired long ago) they succeed, whatever sequence/appliedMs the authority assigned.
      for (const [kind, body, nonceArg, status] of [["lifecycle", lifecycleOf(command.digest, "SUCCESS", applied), undefined, "SUCCESS"],
        ["lifecycle", lifecycleOf(command.digest, "ALREADY_APPLIED", { ...applied, sequence: 4_096, appliedMs: 5 }), undefined, "ALREADY_APPLIED"],
        ["reconciliation", exactOf(command.digest, applied), nonce, "SUCCESS"]] as const) {
        const withCommand = await cli.run(body, kind, command.digest, nonceArg, command.artifact);
        assert.equal(withCommand.exitCode, 0, `${name} ${kind} ${status}: ${withCommand.stderr}${withCommand.stdout}`);
        assert.equal(parsed(withCommand.stdout).status, status);
        assert.deepEqual(withCommand.methods, ["GET"], "reading never submits a mutation");
      }
    }
  } finally { await cli.dispose(); }
});

test("actual CLI read-result refuses or downgrades a command that does not match the result or the requested digest", async () => {
  const cli = await createCliResultHarness();
  try {
    const commands = await signedCommands(cli.privateKey, cli.publicKey);
    const { initialize, rotate } = commands;
    const applied = { ...initialize.expected, sequence: 1, appliedMs: Date.now() };
    const body = lifecycleOf(initialize.digest, "SUCCESS", applied);
    // Every command-derived receipt field mutated in an otherwise valid result is UNCONFIRMED, never success.
    const mutations: Record<string, unknown> = { operation: "rotate-release", currentReleaseId: "release-x", nextReleaseId: "release-x", nextKeyId: "key-x",
      activatesMs: 1_001, retiresMs: 2_000, keyFingerprint: "e".repeat(64) };
    for (const [field, value] of Object.entries(mutations)) {
      for (const [kind, mutated, nonceArg] of [["lifecycle", lifecycleOf(initialize.digest, "SUCCESS", { ...applied, [field]: value }), undefined],
        ["reconciliation", exactOf(initialize.digest, { ...applied, [field]: value }), nonce]] as const) {
        const run = await cli.run(mutated, kind, initialize.digest, nonceArg, initialize.artifact);
        assert.equal(run.exitCode, 3, `${kind} ${field}`);
        assert.deepEqual(parsed(run.stdout), { status: "UNCONFIRMED", kind });
      }
    }
    // A command for a different digest than the requested --digest is refused locally before any read.
    const mismatch = await cli.run(body, "lifecycle", initialize.digest, undefined, rotate.artifact);
    assert.equal(mismatch.exitCode, 2, mismatch.stdout);
    assert.equal(mismatch.stdout, "");
    assert.deepEqual(mismatch.methods.filter(Boolean), [], "no transport call");
    // Tampered, wrong-key and malformed sealed commands are refused locally too.
    const tampered = asJson({ command: [...commands.initializeCommand.slice(0, 5), "release-x", ...commands.initializeCommand.slice(6)],
      signature: (JSON.parse(new TextDecoder().decode(initialize.artifact)) as { signature: string }).signature });
    const foreign = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const foreignKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", foreign.privateKey)));
    const wrongKey = asJson({ command: commands.initializeCommand, signature: await signAuthorityInitializationCommand(commands.initializeCommand, foreignKey) });
    const stagingCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging", STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "release-a", "key-a", 1_000, true] as AuthorityInitializationCommand;
    const wrongEnvironment = asJson({ command: stagingCommand, signature: await signAuthorityInitializationCommand(stagingCommand, cli.privateKey) });
    for (const [name, artifact] of [["tampered", tampered], ["wrong key", wrongKey], ["wrong environment", wrongEnvironment],
      ["malformed", new TextEncoder().encode("{")]] as const) {
      const run = await cli.run(body, "lifecycle", initialize.digest, undefined, artifact);
      assert.equal(run.exitCode, 2, `${name}: ${run.stdout}`);
      assert.equal(run.stdout, "");
      assert.deepEqual(run.methods.filter(Boolean), [], `${name}: no transport call`);
    }
    // A command for another operation/release cannot vouch for this result.
    const crossed = await cli.run(lifecycleOf(rotate.digest, "SUCCESS", { ...rotate.expected, sequence: 1, appliedMs: 1 }), "lifecycle", rotate.digest, undefined, rotate.artifact);
    assert.equal(crossed.exitCode, 0, crossed.stderr);
    const swapped = await cli.run(lifecycleOf(rotate.digest, "SUCCESS", { ...initialize.expected, digest: rotate.digest, sequence: 1, appliedMs: 1 }),
      "lifecycle", rotate.digest, undefined, rotate.artifact);
    assert.equal(swapped.exitCode, 3, "a rotation command does not accept an initialize-shaped receipt");
  } finally { await cli.dispose(); }
});

test("actual CLI read-result keeps receiptless diagnostics and settlement available without command context", async () => {
  const cli = await createCliResultHarness();
  try {
    const synthetic = "5".repeat(64);
    const negative = (status: string, extra: object = {}) => asJson({ ...result(synthetic), nonce, status, initialized: true, coverage: "COMPLETE", receipt: null, releases: [row], ...extra });
    for (const [name, body, observation] of [["NOT_FOUND", negative("NOT_FOUND"), "NOT_FOUND"],
      ["HISTORY_INCOMPLETE", negative("HISTORY_INCOMPLETE", { coverage: "INCOMPLETE" }), "HISTORY_INCOMPLETE"],
      ["UNAVAILABLE", asJson({ ...result(synthetic), nonce, status: "UNAVAILABLE" }), "UNAVAILABLE"]] as const) {
      const run = await cli.run(body, "reconciliation", synthetic, nonce);
      assert.equal(run.exitCode, 3, name);
      assert.deepEqual(parsed(run.stdout), { status: "UNCONFIRMED", digest: synthetic, observation });
      assert.deepEqual(run.methods, ["GET"]);
    }
    // A synthetic digest has no signed command, so a receipt for it can never be positive evidence.
    const forged = await cli.run(asJson({ ...result(synthetic), nonce, status: "EXACT_RECEIPT", initialized: true, coverage: "COMPLETE", releases: [row],
      receipt: { digest: synthetic, version: 1, operation: "initialize", environment: "production", authorityId: "production-public-inquiries-v1",
        policyEpoch: "phase5c-i1-epoch-1", keyFingerprint: "c".repeat(64), sequence: 1, appliedMs: 1, currentReleaseId: "release-a", nextReleaseId: "release-a",
        nextKeyId: "key-a", activatesMs: 1_000, retiresMs: null } }), "reconciliation", synthetic, nonce);
    assert.equal(forged.exitCode, 3);
    assert.equal(parsed(forged.stdout).status, "UNCONFIRMED");
    // Settlement is guard state: unchanged without a command, and a command is refused rather than implied to authenticate it.
    const settled = await cli.run(asJson({ ...result(synthetic), nonce, settled: true }), "settlement", synthetic, nonce);
    assert.equal(settled.exitCode, 0, settled.stderr);
    assert.deepEqual(parsed(settled.stdout), { status: "SETTLED", digest: synthetic, nonce });
    const commands = await signedCommands(cli.privateKey, cli.publicKey);
    const withCommand = await cli.run(asJson({ ...result(commands.initialize.digest), nonce, settled: true }), "settlement", commands.initialize.digest, nonce, commands.initialize.artifact);
    assert.equal(withCommand.exitCode, 2);
    assert.deepEqual(withCommand.methods.filter(Boolean), []);
  } finally { await cli.dispose(); }
});
