import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../workers/admission-service/authority";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION,
  commandDigest,
  executeSignedAuthorityInitialization,
  executeSignedAuthorityReleaseRotation,
  expectedCommandReceipt,
  signAuthorityInitializationCommand,
  signAuthorityReleaseRotationCommand,
  type AuthorityInitializationCommand,
  type AuthorityReleaseRotationCommand,
} from "../workers/admission-service/operator-command";
import { MAX_SEALED_ARTIFACT_BYTES, authenticateSealedLifecycleArtifact, parseSealedLifecycleArtifact, submitSealedLifecycleArtifact, type AdmissionLifecycleBinding } from "../operator/lifecycle-submitter";

const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
async function fixture() {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const privateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  const publicKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const now = 1_000_000;
  const initialize: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, "release-a", "key-a", now, true];
  const rotate: AuthorityReleaseRotationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production", ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, "release-a", "release-b", "key-b", now, now + 60_000, now, true];
  return { privateKey, publicKey, now, initialize, rotate,
    initBytes: bytes({ command: initialize, signature: await signAuthorityInitializationCommand(initialize, privateKey) }),
    rotateBytes: bytes({ command: rotate, signature: await signAuthorityReleaseRotationCommand(rotate, privateKey) }) };
}

test("sealed input accepts only the pinned Production protocol and strict JSON", async () => {
  const f = await fixture();
  assert.equal(parseSealedLifecycleArtifact(f.initBytes, "initialize", f.now).command[1], "initialize");
  assert.equal(parseSealedLifecycleArtifact(f.rotateBytes, "rotate-release", f.now).command[1], "rotate-release");
  const reject = (value: Uint8Array, operation: "initialize" | "rotate-release" = "initialize", now = f.now) =>
    assert.throws(() => parseSealedLifecycleArtifact(value, operation, now), /invalid-sealed-artifact/u);
  reject(bytes({ command: f.initialize, signature: "bad" }));
  reject(new TextEncoder().encode('{"command":[],"command":[],"signature":"x"}'));
  reject(new TextEncoder().encode('{"command":[],"signature":"x","metadata":{"a":1,"a":2}}'));
  reject(new TextEncoder().encode("{"));
  reject(new Uint8Array([0xff]));
  reject(new Uint8Array(MAX_SEALED_ARTIFACT_BYTES + 1));
  reject(bytes({ command: f.initialize, signature: "x", reset: true }));
  reject(bytes({ command: [...f.initialize, "reset"], signature: "x" }));
  reject(bytes({ command: ["wrong", ...f.initialize.slice(1)], signature: "x" }));
  reject(f.initBytes, "rotate-release");
  const signature = JSON.parse(new TextDecoder().decode(f.initBytes)).signature as string;
  for (const [index, replacement] of [[2, "staging"], [3, "wrong-authority"], [4, "wrong-epoch"], [7, f.now - 300_001],
    [8, false]] as const) {
    const command = [...f.initialize]; (command as unknown as Array<unknown>)[index] = replacement;
    reject(bytes({ command, signature }));
  }
  reject(f.initBytes, "initialize", f.now + 300_001);
  reject(f.initBytes, "initialize", f.now - 300_001);
  const badOverlap = [...f.rotate]; (badOverlap as unknown as number[])[9] = f.now + 300_001;
  reject(bytes({ command: badOverlap, signature }), "rotate-release");
  const sameRelease = [...f.rotate]; (sameRelease as unknown as string[])[6] = "release-a";
  reject(bytes({ command: sameRelease, signature }), "rotate-release");
  reject(f.rotateBytes, "rotate-release", f.now + 300_001);
  reject(f.rotateBytes, "rotate-release", f.now - 300_001);
});

test("submitter calls only pinned lifecycle methods and verifies operator signature", async () => {
  const f = await fixture();
  const calls: string[] = [];
  const binding: AdmissionLifecycleBinding = {
    async initializeAuthorityFromOperatorAttested() { calls.push("initialize"); return { status: "ATTESTED", relayDisposition: "APPLIED", envelope: initEnvelope }; },
    async rotateAuthorityReleaseFromOperatorAttested() { calls.push("rotate"); return { status: "ATTESTED", relayDisposition: "APPLIED", envelope: rotateEnvelope }; },
  };
  // The relay is OPAQUE: these are not protocol envelopes at all, and they cross the submitter byte-for-byte (same instance).
  const initEnvelope = Uint8Array.from([0, 1, 2, 250, 251, 255]);
  const rotateEnvelope = Uint8Array.from([9, 8, 7]);
  const initialized = await submitSealedLifecycleArtifact(f.initBytes, "initialize", binding, f.publicKey, f.now);
  const rotated = await submitSealedLifecycleArtifact(f.rotateBytes, "rotate-release", binding, f.publicKey, f.now);
  assert.deepEqual(initialized, { status: "ATTESTED", relayDisposition: "APPLIED", envelope: initEnvelope });
  assert.deepEqual(rotated, { status: "ATTESTED", relayDisposition: "APPLIED", envelope: rotateEnvelope });
  assert.equal((initialized as { envelope: Uint8Array }).envelope, initEnvelope, "the exact bytes object is relayed, never copied or re-serialized");
  assert.deepEqual(calls, ["initialize", "rotate"]);
  const altered = bytes({ command: [...f.initialize.slice(0, 5), "changed", ...f.initialize.slice(6)],
    signature: JSON.parse(new TextDecoder().decode(f.initBytes)).signature });
  await assert.rejects(() => submitSealedLifecycleArtifact(altered, "initialize", binding, f.publicKey, f.now), /operator-signature/u);
  assert.deepEqual(calls, ["initialize", "rotate"]);
});

test("committed mutation with lost acknowledgement is UNCONFIRMED and never retried", async () => {
  const f = await fixture();
  let calls = 0;
  let committed = false;
  const binding: AdmissionLifecycleBinding = {
    async initializeAuthorityFromOperatorAttested() { calls += 1; committed = true; throw new Error("acknowledgement lost"); },
    async rotateAuthorityReleaseFromOperatorAttested() { calls += 1; committed = true; throw new Error("acknowledgement lost"); },
  };
  for (const [artifact, operation] of [[f.initBytes, "initialize"], [f.rotateBytes, "rotate-release"]] as const) {
    committed = false; calls = 0;
    const result = await submitSealedLifecycleArtifact(artifact, operation, binding, f.publicKey, f.now);
    assert.equal(committed, true);
    assert.equal(calls, 1);
    assert.deepEqual(result, { status: "UNCONFIRMED", instruction: "Inspect authoritative state before any retry; the mutation may have committed." });
    assert.doesNotMatch(JSON.stringify(result), /rollback|failed|not committed/iu);
  }
});

test("definite policy refusal stays distinct from ambiguous transport outcome", async () => {
  const f = await fixture();
  const binding: AdmissionLifecycleBinding = {
    async initializeAuthorityFromOperatorAttested() { return { status: "REFUSED" }; },
    async rotateAuthorityReleaseFromOperatorAttested() { return { status: "REFUSED" }; },
  };
  assert.deepEqual(await submitSealedLifecycleArtifact(f.initBytes, "initialize", binding, f.publicKey, f.now), { status: "REFUSED" });
  assert.deepEqual(await submitSealedLifecycleArtifact(f.rotateBytes, "rotate-release", binding, f.publicKey, f.now), { status: "REFUSED" });
  const unexpected = { ...binding, async initializeAuthorityFromOperatorAttested() { return { status: "unknown" } as never; } };
  assert.equal((await submitSealedLifecycleArtifact(f.initBytes, "initialize", unexpected, f.publicKey, f.now)).status, "UNCONFIRMED");
});

test("non-positive Authority answers keep their class: UNAVAILABLE and AMBIGUOUS are never rewritten as REFUSED", async () => {
  const f = await fixture();
  const answer = (value: unknown): AdmissionLifecycleBinding => ({
    async initializeAuthorityFromOperatorAttested() { return value; },
    async rotateAuthorityReleaseFromOperatorAttested() { return value; },
  });
  const run = (value: unknown) => submitSealedLifecycleArtifact(f.initBytes, "initialize", answer(value), f.publicKey, f.now);
  assert.deepEqual(await run({ status: "UNAVAILABLE", reason: "signer-unconfigured" }), { status: "UNAVAILABLE", reason: "signer-unconfigured" });
  assert.deepEqual(await run({ status: "AMBIGUOUS", reason: "post-commit-attestation-failed" }), { status: "AMBIGUOUS", reason: "post-commit-attestation-failed" });
  // Malformed positives are UNCONFIRMED, never ATTESTED and never REFUSED: non-Uint8Array, empty, oversize, number[], extra or missing keys.
  const envelope = Uint8Array.from([1, 2, 3]);
  for (const bad of [
    { status: "ATTESTED", relayDisposition: "APPLIED", envelope: [1, 2, 3] },
    { status: "ATTESTED", relayDisposition: "APPLIED", envelope: "AQID" },
    { status: "ATTESTED", relayDisposition: "APPLIED", envelope: new Uint8Array(0) },
    { status: "ATTESTED", relayDisposition: "APPLIED", envelope: new Uint8Array(8_193) },
    { status: "ATTESTED", relayDisposition: "APPLIED", envelope, receipt: {} },
    { status: "ATTESTED", relayDisposition: "WHATEVER", envelope },
    { status: "ATTESTED", envelope },
    { status: "REFUSED", reason: "x" },
    { status: "AMBIGUOUS" },
    { status: "UNAVAILABLE", reason: "Not Lowercase" },
    { status: "initialized", receipt: {} },
    null, "ATTESTED", [],
  ]) assert.equal((await run(bad)).status, "UNCONFIRMED", JSON.stringify(bad));
  // 8192 bytes is the exact upper bound.
  assert.equal((await run({ status: "ATTESTED", relayDisposition: "ALREADY_APPLIED", envelope: new Uint8Array(8_192) })).status, "ATTESTED");
});

test("lifecycle adapter makes one admission call for 429, 5xx, reset, timeout, retryable and malformed outcomes", async () => {
  const f = await fixture();
  for (const fault of [429, 500, 503, "timeout", "connection-reset", "retryable", "malformed"] as const) {
    let dispatches = 0;
    const binding: AdmissionLifecycleBinding = {
      async initializeAuthorityFromOperatorAttested() {
        dispatches++;
        if (fault === "retryable") return { status: "retryable" } as never;
        if (fault === "malformed") return null as never;
        throw Object.assign(new Error(String(fault)), { retryable: true, status: fault });
      },
      async rotateAuthorityReleaseFromOperatorAttested() { throw new Error("wrong operation"); },
    };
    const result = await submitSealedLifecycleArtifact(f.initBytes, "initialize", binding, f.publicKey, f.now);
    assert.equal(result.status, "UNCONFIRMED", String(fault));
    assert.equal(dispatches, 1, String(fault));
  }
});

test("staging rotation remains an explicit closed protocol gate", async () => {
  const f = await fixture();
  const staging = [...f.rotate]; (staging as unknown as string[])[2] = "staging";
  const productionSignature = await signAuthorityReleaseRotationCommand(f.rotate, f.privateKey);
  assert.throws(() => parseSealedLifecycleArtifact(bytes({ command: staging,
    signature: productionSignature }), "rotate-release", f.now));
  const gates = JSON.parse(await readFile(new URL("../deployment/lifecycle-environment-gates.json", import.meta.url), "utf8")) as
    { staging: { rotationImplemented: boolean; provisioningOpen: boolean } };
  assert.equal(gates.staging.rotationImplemented, false);
  assert.equal(gates.staging.provisioningOpen, false);
});

test("CLI inspection is read-only and ordinary terminal submission fails closed", async () => {
  const f = await fixture();
  const directory = await mkdtemp(join(tmpdir(), "i3a-submitter-"));
  const file = join(directory, "sealed.json");
  try {
    const run = (extra: string[]) => spawnSync(process.execPath,
      ["node_modules/tsx/dist/cli.mjs", "scripts/authority-submit.ts", "initialize", "--command", file, "--confirm-production", ...extra],
      { cwd: fileURLToPath(new URL("../", import.meta.url)), encoding: "utf8" });
    // Freshness is tied to wall time, so the fixture is replaced by a newly signed command.
    const fresh: AuthorityInitializationCommand = [f.initialize[0], f.initialize[1], f.initialize[2], f.initialize[3], f.initialize[4],
      f.initialize[5], f.initialize[6], Date.now(), true];
    const signature = await signAuthorityInitializationCommand(fresh, f.privateKey);
    await writeFile(file, bytes({ command: fresh, signature }));
    const inspected = run(["--inspect"]);
    assert.equal(inspected.status, 0, inspected.stderr);
    assert.equal(JSON.parse(inspected.stdout).status, "INSPECTED");
    assert.doesNotMatch(inspected.stdout, /signature|private/u);
    const unavailable = run([]);
    assert.equal(unavailable.status, 2);
    assert.match(unavailable.stderr, /UNAVAILABLE/u);
    assert.equal(unavailable.stderr.includes(signature), false);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("Production lifecycle remains absent from public fetch routing and deployment URLs", async () => {
  const worker = await readFile(new URL("../workers/admission-service/index.ts", import.meta.url), "utf8");
  const service = await readFile(new URL("../workers/admission-service/service.ts", import.meta.url), "utf8");
  const deployment = JSON.parse(await readFile(new URL("../deployment/admission-service.template.jsonc", import.meta.url), "utf8")) as Record<string, unknown>;
  const executor = JSON.parse(await readFile(new URL("../deployment/operator-lifecycle-executor.template.jsonc", import.meta.url), "utf8")) as Record<string, unknown>;
  assert.doesNotMatch(service, /initializeAuthorityFromOperator|rotateAuthorityReleaseFromOperator/u);
  assert.doesNotMatch(worker, /\/initialize|\/rotate|\/reset/u);
  assert.equal(deployment.workers_dev, false);
  assert.equal(deployment.preview_urls, false);
  assert.equal((deployment.durable_objects as { bindings: unknown[] }).bindings.length, 1);
  assert.equal(executor.routes, undefined);
  assert.equal(executor.workers_dev, false);
  assert.equal(executor.preview_urls, false);
  assert.deepEqual(executor.services, [{ binding: "ADMISSION_SERVICE", service: "__REQUIRED_REVIEWED_ADMISSION_SERVICE_NAME__",
    entrypoint: "AuthorityLifecycleOnly" }]);
  const executorSource = await readFile(new URL("../workers/operator-lifecycle-executor.ts", import.meta.url), "utf8");
  assert.doesNotMatch(executorSource, /getByName|env\.AUTHORITY\b|request\.url|pathname/u);
  assert.doesNotMatch(await readFile(new URL("../scripts/authority-submit.ts", import.meta.url), "utf8"), /AUTHORITY_OPERATOR_PRIVATE_KEY/u);
});

// --- Historical authentication is distinct from submission eligibility --------------------------------------

const expiredBy = (f: { now: number }) => f.now + 10 * 60_000;

test("historical authentication accepts an expired correctly signed command that stays ineligible for submission", async () => {
  const f = await fixture();
  const later = expiredBy(f);
  for (const [artifact, operation, command] of [[f.initBytes, "initialize", f.initialize], [f.rotateBytes, "rotate-release", f.rotate]] as const) {
    assert.throws(() => parseSealedLifecycleArtifact(artifact, operation, later), /invalid-sealed-artifact/u, `${operation} no longer parses for submission`);
    const binding: AdmissionLifecycleBinding = { async initializeAuthorityFromOperatorAttested() { throw new Error("must not dispatch"); },
      async rotateAuthorityReleaseFromOperatorAttested() { throw new Error("must not dispatch"); } };
    await assert.rejects(() => submitSealedLifecycleArtifact(artifact, operation, binding, f.publicKey, later), /invalid-sealed-artifact/u, `${operation} resubmission refused`);
    const authenticated = await authenticateSealedLifecycleArtifact(artifact, f.publicKey);
    assert.deepEqual(authenticated.command, command);
    assert.equal(authenticated.digest, await commandDigest(command), "digest recomputation is exact");
    assert.equal(authenticated.expected.digest, authenticated.digest);
    assert.equal((await authenticateSealedLifecycleArtifact(artifact, f.publicKey, { expectedOperation: operation })).digest, authenticated.digest);
  }
  // Submission freshness is unchanged: the boundary still admits exactly +/-5 minutes.
  assert.equal(parseSealedLifecycleArtifact(f.initBytes, "initialize", f.now + 300_000).command[1], "initialize");
  assert.throws(() => parseSealedLifecycleArtifact(f.initBytes, "initialize", f.now + 300_001), /invalid-sealed-artifact/u);
});

test("historical authentication rejects malformed, tampered, mis-signed, wrong-target and wrong-operation artifacts", async () => {
  const f = await fixture();
  const signature = JSON.parse(new TextDecoder().decode(f.initBytes)).signature as string;
  const other = await fixture();
  const auth = (value: Uint8Array, key = f.publicKey, options: { expectedOperation?: "initialize" | "rotate-release" } = {}) =>
    authenticateSealedLifecycleArtifact(value, key, options);
  // Malformed envelope and bytes.
  for (const malformed of [new TextEncoder().encode("{"), new Uint8Array([0xff]), new Uint8Array(0), new Uint8Array(MAX_SEALED_ARTIFACT_BYTES + 1),
    bytes({ command: f.initialize, signature: "bad" }), bytes({ command: f.initialize, signature, extra: 1 }),
    new TextEncoder().encode('{"command":[],"command":[],"signature":"x"}')])
    await assert.rejects(() => auth(malformed), /invalid-sealed-artifact/u);
  // Any change to a signed element breaks the signature (modified after signing).
  for (const [index, value] of [[5, "release-x"], [6, "key-x"], [7, f.now + 1]] as const) {
    const command = [...f.initialize] as unknown[]; command[index] = value;
    await assert.rejects(() => auth(bytes({ command, signature })), /operator-signature/u, `initialize field ${index}`);
  }
  const rotateSignature = JSON.parse(new TextDecoder().decode(f.rotateBytes)).signature as string;
  for (const [index, value] of [[5, "release-x"], [6, "release-y"], [7, "key-y"], [8, f.now + 1], [9, f.now + 61_000], [10, f.now + 1]] as const) {
    const command = [...f.rotate] as unknown[]; command[index] = value;
    await assert.rejects(() => auth(bytes({ command, signature: rotateSignature })), /operator-signature/u, `rotate field ${index}`);
  }
  // Signature by a different key, or verified against a different public key.
  await assert.rejects(() => auth(f.initBytes, other.publicKey), /operator-signature/u);
  await assert.rejects(() => auth(other.initBytes), /operator-signature/u);
  // Wrong operation expectation.
  await assert.rejects(() => auth(f.initBytes, f.publicKey, { expectedOperation: "rotate-release" }), /invalid-sealed-artifact/u);
  await assert.rejects(() => auth(f.rotateBytes, f.publicKey, { expectedOperation: "initialize" }), /invalid-sealed-artifact/u);
  // Wrong environment / authority / epoch / version, even when signed by the operator key (the schema rejects before any signature check).
  const staging: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging", STAGING_ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, "release-a", "key-a", f.now, true];
  const stagingBytes = bytes({ command: staging, signature: await signAuthorityInitializationCommand(staging, f.privateKey) });
  await assert.rejects(() => auth(stagingBytes), /invalid-sealed-artifact/u, "staging command never authenticates as Production");
  assert.equal((await authenticateSealedLifecycleArtifact(stagingBytes, f.publicKey, { expectedEnvironment: "staging" })).expected.environment, "staging");
  for (const [index, value] of [[2, "staging"], [3, "wrong-authority"], [4, "wrong-epoch"], [0, "wrong-version"]] as const) {
    const command = [...f.initialize] as unknown[]; command[index] = value;
    await assert.rejects(() => auth(bytes({ command, signature })), /invalid-sealed-artifact/u, `initialize field ${index}`);
  }
});

// --- Command -> receipt mapping ---------------------------------------------------------------------------

function decodeBase64urlBytes(value: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(value.replace(/-/gu, "+").replace(/_/gu, "/"), "base64"));
}

test("expectedCommandReceipt maps exactly the command-derived fields and matches what the authority writes", async () => {
  const f = await fixture();
  const fingerprint = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", decodeBase64urlBytes(f.publicKey))),
    (byte) => byte.toString(16).padStart(2, "0")).join("");
  const table = [
    { name: "initialize", command: f.initialize, fields: { operation: "initialize", environment: "production", authorityId: ADMISSION_AUTHORITY_ID,
      policyEpoch: ADMISSION_POLICY_EPOCH, currentReleaseId: "release-a", nextReleaseId: "release-a", nextKeyId: "key-a", activatesMs: f.now, retiresMs: null } },
    { name: "rotate-release", command: f.rotate, fields: { operation: "rotate-release", environment: "production", authorityId: ADMISSION_AUTHORITY_ID,
      policyEpoch: ADMISSION_POLICY_EPOCH, currentReleaseId: "release-a", nextReleaseId: "release-b", nextKeyId: "key-b", activatesMs: f.now, retiresMs: f.now + 60_000 } },
  ] as const;
  for (const row of table) {
    const expected = await expectedCommandReceipt(row.command, f.publicKey);
    assert.deepEqual(expected, { digest: await commandDigest(row.command), version: 1, keyFingerprint: fingerprint, ...row.fields }, row.name);
    assert.equal("sequence" in expected || "appliedMs" in expected, false, `${row.name}: authority-assigned fields are not command-derived`);
  }
  // The same mapping is what the authority persists; sequence/appliedMs are the only fields it adds.
  const storage = new NodeSqliteDurableStorage();
  try {
    const first = await executeSignedAuthorityInitialization(storage, f.initialize, await signAuthorityInitializationCommand(f.initialize, f.privateKey),
      f.publicKey, f.now + 5);
    const { sequence, appliedMs, ...initReceipt } = first.receipt!;
    assert.deepEqual(initReceipt, await expectedCommandReceipt(f.initialize, f.publicKey));
    assert.deepEqual([sequence, appliedMs], [1, f.now + 5], "authority-derived");
    const rotated = await executeSignedAuthorityReleaseRotation(storage, f.rotate, await signAuthorityReleaseRotationCommand(f.rotate, f.privateKey),
      f.publicKey, f.now + 9);
    const { sequence: rotateSequence, appliedMs: rotateApplied, ...rotateReceipt } = rotated.receipt!;
    assert.deepEqual(rotateReceipt, await expectedCommandReceipt(f.rotate, f.publicKey));
    assert.deepEqual([rotateSequence, rotateApplied], [2, f.now + 9]);
    // Exact replay: the stored receipt keeps its original authority-derived fields; the command-derived fields are unchanged.
    const replay = await executeSignedAuthorityInitialization(storage, f.initialize, await signAuthorityInitializationCommand(f.initialize, f.privateKey),
      f.publicKey, f.now + 20);
    assert.equal(replay.status, "already-initialized");
    assert.deepEqual(replay.receipt, first.receipt);
  } finally { storage.close(); }
});
