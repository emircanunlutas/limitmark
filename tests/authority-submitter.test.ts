import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH } from "../workers/admission-service/authority";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION,
  signAuthorityInitializationCommand,
  signAuthorityReleaseRotationCommand,
  type AuthorityInitializationCommand,
  type AuthorityReleaseRotationCommand,
} from "../workers/admission-service/operator-command";
import { MAX_SEALED_ARTIFACT_BYTES, parseSealedLifecycleArtifact, submitSealedLifecycleArtifact, type AdmissionLifecycleBinding } from "../operator/lifecycle-submitter";

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
    async initializeAuthorityFromOperator() { calls.push("initialize"); return { status: "initialized" }; },
    async rotateAuthorityReleaseFromOperator() { calls.push("rotate"); return { status: "rotated" }; },
  };
  assert.deepEqual(await submitSealedLifecycleArtifact(f.initBytes, "initialize", binding, f.publicKey, f.now), { status: "initialized" });
  assert.deepEqual(await submitSealedLifecycleArtifact(f.rotateBytes, "rotate-release", binding, f.publicKey, f.now), { status: "rotated" });
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
    async initializeAuthorityFromOperator() { calls += 1; committed = true; throw new Error("acknowledgement lost"); },
    async rotateAuthorityReleaseFromOperator() { calls += 1; committed = true; throw new Error("acknowledgement lost"); },
  };
  for (const [artifact, operation] of [[f.initBytes, "initialize"], [f.rotateBytes, "rotate-release"]] as const) {
    committed = false; calls = 0;
    const result = await submitSealedLifecycleArtifact(artifact, operation, binding, f.publicKey, f.now);
    assert.equal(committed, true);
    assert.equal(calls, 1);
    assert.deepEqual(result, { status: "unconfirmed", instruction: "Inspect authoritative state before any retry; the mutation may have committed." });
    assert.doesNotMatch(JSON.stringify(result), /rollback|failed|not committed/iu);
  }
});

test("definite policy refusal stays distinct from ambiguous transport outcome", async () => {
  const f = await fixture();
  const binding: AdmissionLifecycleBinding = {
    async initializeAuthorityFromOperator() { return { status: "refused" }; },
    async rotateAuthorityReleaseFromOperator() { return { status: "refused" }; },
  };
  assert.deepEqual(await submitSealedLifecycleArtifact(f.initBytes, "initialize", binding, f.publicKey, f.now), { status: "refused" });
  assert.deepEqual(await submitSealedLifecycleArtifact(f.rotateBytes, "rotate-release", binding, f.publicKey, f.now), { status: "refused" });
  const unexpected = { ...binding, async initializeAuthorityFromOperator() { return { status: "unknown" } as never; } };
  assert.equal((await submitSealedLifecycleArtifact(f.initBytes, "initialize", unexpected, f.publicKey, f.now)).status, "unconfirmed");
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
    assert.equal(JSON.parse(inspected.stdout).status, "inspected");
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
  assert.deepEqual(executor.services, [{ binding: "ADMISSION_SERVICE", service: "__REQUIRED_REVIEWED_ADMISSION_SERVICE_NAME__" }]);
  const executorSource = await readFile(new URL("../workers/operator-lifecycle-executor.ts", import.meta.url), "utf8");
  assert.doesNotMatch(executorSource, /getByName|env\.AUTHORITY\b|request\.url|pathname/u);
  assert.doesNotMatch(await readFile(new URL("../scripts/authority-submit.ts", import.meta.url), "utf8"), /AUTHORITY_OPERATOR_PRIVATE_KEY/u);
});
