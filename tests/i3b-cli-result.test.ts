import assert from "node:assert/strict";
import { test } from "node:test";
import { createCliResultHarness } from "./workers/support/i3b-cli-result-harness";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { unsignedDiagnostic } from "../operator/attested-relay";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, signAuthorityInitializationCommand, type AuthorityInitializationCommand } from "../workers/admission-service/operator-command";
import { NONCE, OTHER_NONCE, fixturesAt, text, writer } from "./support/authority-result-fixtures";

// The ACTUAL Production CLI (scripts/authority-submit.ts bundled with a synthetic read-only R2 transport and a sandboxed
// deployment/ directory). R06 Slice 2C: read-result accepts a positive only from an Authority-signed envelope AND an authenticated
// command; there is no unsigned path and no fallback. Statuses: POSITIVE (exit 0) / VERIFIED_NON_POSITIVE / UNCONFIRMED (exit 3).

const digest = "a".repeat(64);
const parsed = (stdout: string) => JSON.parse(stdout) as Record<string, unknown>;
const legacyEnvelope = () => ({ version: 1, digest, environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH, observedAtMs: Date.now() });

test("read-result treats malformed, stale, mismatched and legacy-shaped HTTP-200 objects as UNCONFIRMED, never positive", async () => {
  const cli = await createCliResultHarness();
  try {
    const cases = [new TextEncoder().encode("{"), new Uint8Array(0), new Uint8Array([0xff, 0xfe]), text({ ...legacyEnvelope(), status: "UNCONFIRMED" }),
      text({ ...legacyEnvelope(), extra: true, status: "UNCONFIRMED" }), text({ ...legacyEnvelope(), status: "SUCCESS" }), text({ statement: [], signature: "x" }),
      text(unsignedDiagnostic(digest, "REFUSED", "x")), text(unsignedDiagnostic("c".repeat(64), "REFUSED"))];
    for (const bytes of cases) {
      const result = await cli.run(bytes, "lifecycle", digest);
      assert.equal(result.exitCode, 3, `${new TextDecoder().decode(bytes).slice(0, 60)}: ${result.stderr}`);
      assert.equal(parsed(result.stdout).status, "UNCONFIRMED");
      assert.deepEqual(result.methods, ["GET"], "reading a result never submits a mutation");
    }
    // the explicit unsigned diagnostic is reported as such (still non-positive)
    const diagnostic = await cli.run(text(unsignedDiagnostic(digest, "UNAVAILABLE", "signer-unconfigured", NONCE)), "reconciliation", digest, NONCE);
    assert.equal(diagnostic.exitCode, 3);
    assert.deepEqual(parsed(diagnostic.stdout), { status: "UNCONFIRMED", environment: "production", kind: "reconciliation", digest, reason: "no-signed-evidence", relayStatus: "UNAVAILABLE" });
  } finally { await cli.dispose(); }
});

test("read-result: a signed Production positive needs the authenticated command; without it the result is VERIFIED_NON_POSITIVE/COMMAND_CONTEXT_REQUIRED", async () => {
  const cli = await createCliResultHarness();
  try {
    const fx = fixturesAt(Date.now());
    for (const which of ["initialize", "rotate-release"] as const) {
      const command = await fx.authenticated(cli, which);
      const sealed = await fx.sealedArtifact(cli, which);
      const receipt = fx.receiptFor(command);
      for (const [kind, bytes, nonceArg] of [["lifecycle", await fx.lifecycle("production", receipt), undefined],
        ["reconciliation", await fx.reconciliation("production", "EXACT_RECEIPT", receipt.digest, receipt), NONCE]] as const) {
        const without = await cli.run(bytes, kind, command.digest, nonceArg);
        assert.equal(without.exitCode, 3, `${which} ${kind} without command: ${without.stderr}${without.stdout}`);
        assert.deepEqual(parsed(without.stdout), { status: "VERIFIED_NON_POSITIVE", environment: "production", kind, digest: command.digest, observation: "COMMAND_CONTEXT_REQUIRED",
          observedAtMs: fx.OBSERVED, signingKeyFingerprint: await writer("production") });
        assert.deepEqual(without.methods, ["GET"]);
        const withCommand = await cli.run(bytes, kind, command.digest, nonceArg, sealed);
        assert.equal(withCommand.exitCode, 0, `${which} ${kind}: ${withCommand.stderr}${withCommand.stdout}`);
        const out = parsed(withCommand.stdout);
        assert.deepEqual([out.status, out.kind, out.digest, out.environment], ["POSITIVE", kind, command.digest, "production"]);
        assert.deepEqual(out.receipt, receipt);
        assert.deepEqual(withCommand.methods, ["GET"], "reading never submits a mutation");
      }
    }
  } finally { await cli.dispose(); }
});

test("read-result: command handling is deliberate. A mismatched optional command keeps a signed negative reportable and never vouches for a positive", async () => {
  const cli = await createCliResultHarness();
  try {
    const fx = fixturesAt(Date.now());
    const initialize = await fx.authenticated(cli, "initialize");
    const rotate = await fx.authenticated(cli, "rotate-release");
    const initSealed = await fx.sealedArtifact(cli, "initialize");
    const rotateSealed = await fx.sealedArtifact(cli, "rotate-release");
    // signed negative + a command for a DIFFERENT digest: the valid signed negative is not erased
    const negative = await fx.reconciliation("production", "NOT_FOUND", initialize.digest, null);
    const kept = await cli.run(negative, "reconciliation", initialize.digest, NONCE, rotateSealed);
    assert.equal(kept.exitCode, 3, kept.stderr);
    const keptOut = parsed(kept.stdout);
    assert.deepEqual([keptOut.status, keptOut.observation, keptOut.commandContext], ["VERIFIED_NON_POSITIVE", "NOT_FOUND", "MISMATCHED"]);
    assert.deepEqual(kept.methods, ["GET"]);
    // signed positive candidate + mismatched command: never positive
    const receipt = fx.receiptFor(initialize);
    const crossed = await cli.run(await fx.lifecycle("production", receipt), "lifecycle", initialize.digest, undefined, rotateSealed);
    assert.equal(crossed.exitCode, 3);
    const crossedOut = parsed(crossed.stdout);
    assert.deepEqual([crossedOut.status, crossedOut.observation, crossedOut.commandContext], ["VERIFIED_NON_POSITIVE", "COMMAND_CONTEXT_REQUIRED", "MISMATCHED"]);
    // a rotation command cannot vouch for an initialize-shaped signed receipt under the rotation's own digest
    const swapped = await cli.run(await fx.lifecycle("production", { ...receipt, digest: rotate.digest }, fx.OBSERVED, rotate.digest), "lifecycle", rotate.digest, undefined, rotateSealed);
    assert.equal(swapped.exitCode, 3);
    assert.equal(parsed(swapped.stdout).status, "UNCONFIRMED");
    // every command-derived field mutated in a genuinely signed result is UNCONFIRMED (command-mismatch), never success
    for (const mutation of [{ currentReleaseId: "release-x" }, { nextKeyId: "key-x" }, { activatesMs: receipt.activatesMs + 1 }, { operatorKeyFingerprint: "e".repeat(64) }, { operation: "rotate-release" as const }]) {
      let bytes: Uint8Array;
      try { bytes = await fx.lifecycle("production", fx.receiptFor(initialize, mutation)); } catch { continue; }
      const run = await cli.run(bytes, "lifecycle", initialize.digest, undefined, initSealed);
      assert.equal(run.exitCode, 3, JSON.stringify(mutation));
      assert.equal(parsed(run.stdout).status, "UNCONFIRMED");
    }
    // Tampered, wrong-key, wrong-environment and malformed commands are refused locally before any read (they cannot be authenticated at all).
    const tampered = text({ command: [...fx.init().slice(0, 5), "release-x", ...fx.init().slice(6)], signature: (JSON.parse(new TextDecoder().decode(initSealed)) as { signature: string }).signature });
    const foreign = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const foreignKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", foreign.privateKey)));
    const wrongKey = text({ command: fx.init(), signature: await signAuthorityInitializationCommand(fx.init(), foreignKey) });
    const stagingCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging", STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "release-a", "key-a", 1_000, true] as AuthorityInitializationCommand;
    const wrongEnvironment = text({ command: stagingCommand, signature: await signAuthorityInitializationCommand(stagingCommand, cli.privateKey) });
    for (const [name, artifact] of [["tampered", tampered], ["wrong key", wrongKey], ["wrong environment", wrongEnvironment], ["malformed", new TextEncoder().encode("{")]] as const) {
      const run = await cli.run(await fx.lifecycle("production", receipt), "lifecycle", initialize.digest, undefined, artifact);
      assert.equal(run.exitCode, 2, `${name}: ${run.stdout}`);
      assert.equal(run.stdout, "");
      assert.deepEqual(run.methods.filter(Boolean), [], `${name}: no transport call`);
    }
  } finally { await cli.dispose(); }
});

test("read-result: forged, stale, replayed and cross-target signed objects are never positive", async () => {
  const cli = await createCliResultHarness();
  try {
    const fx = fixturesAt(Date.now());
    const command = await fx.authenticated(cli, "initialize");
    const sealed = await fx.sealedArtifact(cli, "initialize");
    const receipt = fx.receiptFor(command);
    const good = await fx.lifecycle("production", receipt);
    assert.equal((await cli.run(good, "lifecycle", command.digest, undefined, sealed)).exitCode, 0);
    const flipped = good.slice(); flipped[flipped.length >> 1] ^= 1;
    const never = async (label: string, bytes: Uint8Array, kind: "lifecycle" | "reconciliation" = "lifecycle", nonce?: string) => {
      const run = await cli.run(bytes, kind, command.digest, nonce, sealed);
      assert.equal(run.exitCode, 3, `${label}: ${run.stdout}`);
      assert.equal(parsed(run.stdout).status, "UNCONFIRMED", label);
    };
    await never("one flipped byte", flipped);
    await never("truncated", good.slice(0, good.length - 3));
    await never("pretty-printed", new TextEncoder().encode(JSON.stringify(JSON.parse(new TextDecoder().decode(good)), null, 1)));
    await never("replayed envelope older than the freshness window", await fx.lifecycle("production", receipt, Date.now() - 301_000));
    await never("future-dated envelope", await fx.lifecycle("production", receipt, Date.now() + 120_000));
    await never("staging-signed statement", await fx.lifecycle("staging", { ...receipt, environment: "staging", authorityId: STAGING_ADMISSION_AUTHORITY_ID } as never));
    await never("another digest's signed envelope", await fx.lifecycle("production", fx.receiptFor(await fx.authenticated(cli, "initialize", "release-other"))));
    await never("old nonce replayed", await fx.reconciliation("production", "EXACT_RECEIPT", command.digest, receipt, { nonce: OTHER_NONCE }), "reconciliation", NONCE);
  } finally { await cli.dispose(); }
});

test("read-result: a missing, unresolved or malformed trust manifest is UNAVAILABLE before any read; settlement needs no trust manifest", async () => {
  const fx = fixturesAt(Date.now());
  for (const trust of ["absent", "template", "junk"] as const) {
    const cli = await createCliResultHarness({ trust });
    try {
      const command = await fx.authenticated(cli, "initialize");
      const bytes = await fx.lifecycle("production", fx.receiptFor(command));
      const run = await cli.run(bytes, "lifecycle", command.digest, undefined, await fx.sealedArtifact(cli, "initialize"));
      assert.equal(run.exitCode, 2, `${trust}: ${run.stdout}`);
      assert.equal(run.stdout, "");
      assert.match(run.stderr, /UNAVAILABLE/u);
      assert.deepEqual(run.methods.filter(Boolean), [], `${trust}: nothing was read`);
      // settlement is guard state: independent of the R06 trust manifest and of any command
      const settled = await cli.run(text({ version: 1, digest, environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
        observedAtMs: Date.now(), nonce: NONCE, settled: true }), "settlement", digest, NONCE);
      assert.equal(settled.exitCode, 0, `${trust}: ${settled.stderr}`);
      assert.deepEqual(parsed(settled.stdout), { status: "SETTLED", digest, nonce: NONCE });
    } finally { await cli.dispose(); }
  }
});

test("read-result: settlement stays independent of Authority evidence; a command is refused for settlement", async () => {
  const cli = await createCliResultHarness();
  try {
    const fx = fixturesAt(Date.now());
    const synthetic = "5".repeat(64);
    const body = (over: object = {}) => text({ version: 1, digest: synthetic, environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
      observedAtMs: Date.now(), nonce: NONCE, settled: true, ...over });
    const settled = await cli.run(body(), "settlement", synthetic, NONCE);
    assert.equal(settled.exitCode, 0, settled.stderr);
    assert.deepEqual(parsed(settled.stdout), { status: "SETTLED", digest: synthetic, nonce: NONCE });
    const unsettled = await cli.run(body({ settled: false }), "settlement", synthetic, NONCE);
    assert.equal(unsettled.exitCode, 3);
    assert.equal(parsed(unsettled.stdout).status, "UNCONFIRMED");
    // a signed APPLIED envelope is not settlement evidence
    const command = await fx.authenticated(cli, "initialize");
    const applied = await cli.run(await fx.lifecycle("production", fx.receiptFor(command)), "settlement", command.digest, NONCE);
    assert.equal(applied.exitCode, 3);
    assert.equal(parsed(applied.stdout).status, "UNCONFIRMED");
    const withCommand = await cli.run(body({ digest: command.digest }), "settlement", command.digest, NONCE, await fx.sealedArtifact(cli, "initialize"));
    assert.equal(withCommand.exitCode, 2);
    assert.deepEqual(withCommand.methods.filter(Boolean), []);
  } finally { await cli.dispose(); }
});
