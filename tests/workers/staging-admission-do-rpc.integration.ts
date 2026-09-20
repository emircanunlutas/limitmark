import assert from "node:assert/strict";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import type { Unstable_DevWorker } from "wrangler";
import { ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../../workers/admission-service/authority";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION,
  commandDigest,
  signAuthorityInitializationCommand,
  type AuthorityInitializationCommand,
} from "../../workers/admission-service/operator-command";
import { encodeBase64url } from "../../src/lib/ingress-protocol";

// Gate 4A: proves, against a real local workerd + Durable Object + SQLite
// runtime (not a Node shim, not source-text inspection), that the staging
// admission authority's read-only entrypoint is genuinely read-only against a
// never-initialized authority, that its lifecycle-only write entrypoint is
// dormant (never configured with ADMISSION_CURRENT_RPC_KEY, so every attempt
// fails closed before touching storage), and that both properties survive a
// restart over the same persisted storage. This file never submits a command
// that can succeed; lifecycle initialization remains Gate 7's alone.

const port = 8799;
const root = `http://127.0.0.1:${port}`;
const runtimeRoot = join(process.cwd(), ".wrangler", "tests", "staging-admission-do-rpc");
const persistPath = join(runtimeRoot, "state");

type RpcResult = { status: number; body: Record<string, unknown> };

async function start(publicKey: string): Promise<Unstable_DevWorker> {
  const { unstable_dev } = await import("wrangler");
  return unstable_dev("workers/staging-do-rpc-harness.ts", {
    config: "wrangler.staging-do-rpc.local.jsonc",
    ip: "127.0.0.1",
    port,
    local: true,
    moduleRoot: process.cwd(),
    persistTo: persistPath,
    logLevel: "none",
    // ADMISSION_CURRENT_RPC_KEY is deliberately never set: this is the exact
    // posture Gate 4 must deploy with (the read-only entrypoint needs no RPC
    // key at all; the write entrypoint must fail closed without one).
    vars: { AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey },
    experimental: { showInteractiveDevSession: false, watch: false },
  });
}

async function call(path: string, body: unknown): Promise<RpcResult> {
  const response = await fetch(`${root}/__local-staging-rpc/${path}`, {
    method: "POST",
    signal: AbortSignal.timeout(10_000),
    headers: { "content-type": "application/json", "x-local-staging-rpc-test": "phase5c-gate4a" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) as Record<string, unknown> : {} };
}

async function assertStagingHarness(): Promise<void> {
  const response = await fetch(`${root}/health`, { signal: AbortSignal.timeout(10_000) });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    harness: "staging-do-rpc",
    binding: "AUTHORITY",
    boundClass: "StagingAdmissionAuthority",
    extendsDurableObject: true,
    authorityName: STAGING_ADMISSION_AUTHORITY_ID,
    policyEpoch: ADMISSION_POLICY_EPOCH,
    readOnlyRpc: ["inspectLifecycle"],
    dormantLifecycleRpc: ["initializeAuthorityFromOperator", "rotateAuthorityReleaseFromOperator"],
  });
}

function assertNeverInitialized(result: RpcResult, digest: string): void {
  assert.equal(result.status, 200);
  const { observedAtMs, ...rest } = result.body;
  assert.equal(typeof observedAtMs, "number");
  assert.ok(Number.isSafeInteger(observedAtMs) && Math.abs((observedAtMs as number) - Date.now()) < 30_000);
  assert.deepEqual(rest, {
    version: 1, environment: "staging", authorityId: STAGING_ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
    initialized: false, coverage: "COMPLETE", status: "NOT_FOUND", receipt: null, releases: [],
  });
  void digest;
}

async function main() {
  await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  await mkdir(runtimeRoot, { recursive: true });
  process.env.XDG_CONFIG_HOME = join(runtimeRoot, "config");
  process.env.WRANGLER_SEND_METRICS = "false";

  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const publicKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const privateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  const digest = "a".repeat(64);

  const stagingCommand: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging",
    STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "gate4a-release", "gate4a-key", Date.now(), false];
  const stagingSignature = await signAuthorityInitializationCommand(stagingCommand, privateKey);
  const attemptedDigest = await commandDigest(stagingCommand);

  let worker: Unstable_DevWorker | undefined;
  try {
    worker = await start(publicKey);
    await assertStagingHarness();

    // 1. Read-only inspection against a genuinely never-initialized authority.
    assertNeverInitialized(await call("inspect", { digest }), digest);

    // 2. The lifecycle-only write entrypoint is reachable in principle (it is
    // exported and bound like any other RPC entrypoint) but fails closed
    // because ADMISSION_CURRENT_RPC_KEY was never configured -- proving the
    // write surface is dormant, not merely unexercised.
    const attemptInitialize = await call("attempt-initialize", { command: stagingCommand, signature: stagingSignature });
    assert.deepEqual(attemptInitialize.body, { status: "refused" });

    // 3. The attempt left zero trace: inspecting the exact digest the command
    // would have produced still reports a never-initialized authority.
    assertNeverInitialized(await call("inspect", { digest: attemptedDigest }), attemptedDigest);

    // 4. Rotation is unconditionally refused (Gate 9 -- CLOSED); no arguments
    // reach any parsing/verification/storage step.
    const attemptRotate = await call("attempt-rotate", {});
    assert.deepEqual(attemptRotate.body, { status: "refused" });
    assertNeverInitialized(await call("inspect", { digest }), digest);

    // 5. Restart proof: stop the actual local workerd, restart over the exact
    // same persisted SQLite state, and confirm the never-initialized result
    // -- and the refusal behavior -- are unchanged. Neither the reads above
    // nor the failed write attempts introduced any state to lose or corrupt.
    await worker.stop();
    worker = undefined;
    worker = await start(publicKey);
    await assertStagingHarness();
    assertNeverInitialized(await call("inspect", { digest }), digest);
    assert.deepEqual((await call("attempt-initialize", { command: stagingCommand, signature: stagingSignature })).body, { status: "refused" });
    assertNeverInitialized(await call("inspect", { digest: attemptedDigest }), attemptedDigest);
  } finally {
    try {
      if (worker) await worker.stop();
    } finally {
      await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
    }
  }
  console.log("Staging admission Durable Object RPC integration: PASS (actual StagingAdmissionAuthority class/RPC, never-initialized read-only proof, dormant lifecycle-only write surface, unchanged across restart)");
}

void main();
