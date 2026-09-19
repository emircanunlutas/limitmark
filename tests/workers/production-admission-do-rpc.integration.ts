import assert from "node:assert/strict";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import type { Unstable_DevWorker } from "wrangler";
import {
  ADMISSION_AUTHORITY_ID,
  ADMISSION_POLICY_EPOCH,
  admissionPolicy,
} from "../../workers/admission-service/authority";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION,
  signAuthorityInitializationCommand,
  signAuthorityReleaseRotationCommand,
  type AuthorityInitializationCommand,
  type AuthorityReleaseRotationCommand,
} from "../../workers/admission-service/operator-command";
import { encodeBase64url } from "../../src/lib/ingress-protocol";

type RpcResult = { status: number; body: Record<string, unknown> };
type PreInput = {
  releaseId: string;
  clientPseudonym: string;
  requestBinding: string;
  nonce: string;
  issuedAtMs: number;
};

const port = 8798;
const root = `http://127.0.0.1:${port}`;
const runtimeRoot = join(process.cwd(), ".wrangler", "tests", "production-admission-do-rpc");
const persistPath = join(runtimeRoot, "state");
const opaque = (length: number, seed: number) => {
  const bytes = Uint8Array.from({ length }, (_, index) => (seed + index * 29) & 255);
  new DataView(bytes.buffer).setUint32(length - 4, seed >>> 0);
  return encodeBase64url(bytes);
};

async function start(publicKey: string): Promise<Unstable_DevWorker> {
  const { unstable_dev } = await import("wrangler");
  return unstable_dev("workers/production-do-rpc-harness.ts", {
    config: "wrangler.production-do-rpc.local.jsonc",
    ip: "127.0.0.1",
    port,
    local: true,
    moduleRoot: process.cwd(),
    persistTo: persistPath,
    logLevel: "none",
    vars: {
      AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey,
      ADMISSION_CURRENT_RPC_KEY: encodeBase64url(new Uint8Array(32).fill(9)),
    },
    experimental: { showInteractiveDevSession: false, watch: false },
  });
}

async function call(path: string, body: unknown): Promise<RpcResult> {
  const response = await fetch(`${root}/__local-production-rpc/${path}`, {
    method: "POST",
    signal: AbortSignal.timeout(10_000),
    headers: { "content-type": "application/json", "x-local-production-rpc-test": "phase5c-i2" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) as Record<string, unknown> : {} };
}

const submit = (operation: "initialize" | "rotate", command: unknown, signature: string) =>
  call(`submit-${operation}`, { command, signature });

async function assertProductionHarness(): Promise<void> {
  const response = await fetch(`${root}/health`, { signal: AbortSignal.timeout(10_000) });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    harness: "production-do-rpc",
    binding: "AUTHORITY",
    boundClass: "ProductionAdmissionAuthority",
    extendsDurableObject: true,
    authorityName: ADMISSION_AUTHORITY_ID,
    dataRpc: ["claimPre", "consumePost"],
    lifecycleRpc: ["initializeAuthorityFromOperator", "rotateAuthorityReleaseFromOperator"],
    oldLocalHarnessFallback: false,
  });
}

async function synchronizedCalls(path: string, bodies: readonly unknown[]): Promise<RpcResult[]> {
  let release!: () => void;
  let allWaiting!: () => void;
  let waiting = 0;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const ready = new Promise<void>((resolve) => { allWaiting = resolve; });
  const operations = bodies.map(async (body) => {
    waiting += 1;
    if (waiting === bodies.length) allWaiting();
    await gate;
    return call(path, body);
  });
  await ready;
  release();
  return Promise.all(operations);
}

async function inBatches<T, U>(values: readonly T[], size: number, operation: (value: T) => Promise<U>): Promise<U[]> {
  const output: U[] = [];
  for (let offset = 0; offset < values.length; offset += size) {
    output.push(...await Promise.all(values.slice(offset, offset + size).map(operation)));
  }
  return output;
}

async function main() {
  await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  await mkdir(runtimeRoot, { recursive: true });
  process.env.XDG_CONFIG_HOME = join(runtimeRoot, "config");
  process.env.WRANGLER_SEND_METRICS = "false";

  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const privateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  const publicKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const currentRelease = "dpl_rpc_current";
  const nextRelease = "dpl_rpc_next";
  let sequence = 1_000;
  const freshClient = () => opaque(32, sequence++);
  const makePre = (releaseId: string, clientPseudonym = freshClient()): PreInput => ({
    releaseId,
    clientPseudonym,
    requestBinding: opaque(32, sequence++),
    nonce: opaque(16, sequence++),
    issuedAtMs: Date.now(),
  });
  let preAllowedCount = 0;
  let postAllowedCount = 0;
  const expectPreAllowed = async (input: PreInput) => {
    const result = await call("pre", { input });
    assert.equal(result.body.decision, "allowed");
    preAllowedCount += 1;
    return String(result.body.permit);
  };
  const expectPostAllowed = async (input: PreInput, permit: string) => {
    const result = await call("post", { input: { ...input, permit } });
    assert.equal(result.body.decision, "allowed");
    postAllowedCount += 1;
  };

  let worker: Unstable_DevWorker | undefined;
  try {
    worker = await start(publicKey);
    await assertProductionHarness();

    const initializedAt = Date.now();
    const initialize: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID,
      ADMISSION_POLICY_EPOCH, currentRelease, "rpc-current", initializedAt, true];
    const initializeSignature = await signAuthorityInitializationCommand(initialize, privateKey);
    const wrongEpoch = [...initialize] as unknown as AuthorityInitializationCommand;
    (wrongEpoch as unknown as string[])[4] = "wrong-epoch";
    assert.deepEqual((await call("initialize", { command: wrongEpoch, signature: initializeSignature })).body, { status: "refused" });
    const unconfirmed = [...initialize] as unknown as AuthorityInitializationCommand;
    (unconfirmed as unknown as boolean[])[8] = false;
    assert.deepEqual((await call("initialize", { command: unconfirmed, signature: initializeSignature })).body, { status: "refused" });
    assert.deepEqual((await submit("initialize", initialize, initializeSignature)).body, { status: "initialized" });
    assert.deepEqual((await submit("initialize", initialize, initializeSignature)).body, { status: "already-initialized" });

    // Establish every persistence-sensitive state before rotation.
    const quotaClient = freshClient();
    let quotaClientPreCount = 0;
    let quotaClientPostCount = 0;
    const consumedBeforeRotation = makePre(currentRelease, quotaClient);
    const consumedPermit = await expectPreAllowed(consumedBeforeRotation);
    quotaClientPreCount += 1;
    await expectPostAllowed(consumedBeforeRotation, consumedPermit);
    quotaClientPostCount += 1;
    assert.equal((await call("post", { input: { ...consumedBeforeRotation, permit: consumedPermit } })).body.decision, "replay");

    const unusedBeforeRotation = makePre(currentRelease, quotaClient);
    const unusedPermit = await expectPreAllowed(unusedBeforeRotation);
    quotaClientPreCount += 1;

    // Leave a small deterministic margin above the last PRE/POST observation.
    const activatesAtMs = Date.now() + 1_000;
    const retiresAtMs = activatesAtMs + 15_000;
    const rotate: AuthorityReleaseRotationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production", ADMISSION_AUTHORITY_ID,
      ADMISSION_POLICY_EPOCH, currentRelease, nextRelease, "rpc-next", activatesAtMs, retiresAtMs, activatesAtMs, true];
    const rotateSignature = await signAuthorityReleaseRotationCommand(rotate, privateKey);
    const wrongCurrent = [...rotate] as unknown as AuthorityReleaseRotationCommand;
    (wrongCurrent as unknown as string[])[5] = "dpl_wrong_current";
    assert.deepEqual((await submit("rotate", wrongCurrent,
      await signAuthorityReleaseRotationCommand(wrongCurrent, privateKey))).body, { status: "refused" });
    const wrongRotationEpoch = [...rotate] as unknown as AuthorityReleaseRotationCommand;
    (wrongRotationEpoch as unknown as string[])[4] = "wrong-epoch";
    assert.deepEqual((await call("rotate", { command: wrongRotationEpoch, signature: rotateSignature })).body, { status: "refused" });
    assert.deepEqual((await submit("rotate", rotate, rotateSignature)).body, { status: "rotated" });
    assert.deepEqual((await submit("rotate", rotate, rotateSignature)).body, { status: "already-rotated" });

    const conflict = [...rotate] as unknown as AuthorityReleaseRotationCommand;
    (conflict as unknown as string[])[7] = "rpc-conflict";
    const conflictSignature = await signAuthorityReleaseRotationCommand(conflict, privateKey);
    assert.deepEqual((await submit("rotate", conflict, conflictSignature)).body, { status: "refused" });
    const untilActivation = Math.max(0, activatesAtMs - Date.now() + 10);
    if (untilActivation) await new Promise((resolve) => setTimeout(resolve, untilActivation));
    await expectPreAllowed(makePre(nextRelease));
    await expectPreAllowed(makePre(currentRelease));

    // Restart the actual local workerd while retaining the exact same SQLite persistence root.
    await worker.stop();
    worker = undefined;
    worker = await start(publicKey);
    await assertProductionHarness();

    assert.equal((await call("pre", { input: { ...consumedBeforeRotation, issuedAtMs: Date.now() } })).body.decision, "replay");
    assert.equal((await call("post", { input: { ...consumedBeforeRotation, permit: consumedPermit } })).body.decision, "replay");

    // A synchronized race proves the retained unused permit has exactly one consumer after restart.
    const racedPost = { input: { ...unusedBeforeRotation, permit: unusedPermit } };
    const racedDecisions = (await synchronizedCalls("post", [racedPost, racedPost])).map((result) => result.body.decision).sort();
    assert.deepEqual(racedDecisions, ["allowed", "replay"]);
    postAllowedCount += 1;
    quotaClientPostCount += 1;
    assert.equal((await call("post", racedPost)).body.decision, "replay");

    await expectPreAllowed(makePre(nextRelease));

    // The pre-rotation POST-client observation must supply one of the five retained charges.
    const clientPostPermits: Array<{ input: PreInput; permit: string }> = [];
    while (clientPostPermits.length < admissionPolicy.post.client.limit - quotaClientPostCount + 1) {
      const input = makePre(nextRelease, quotaClient);
      clientPostPermits.push({ input, permit: await expectPreAllowed(input) });
      quotaClientPreCount += 1;
    }
    for (const candidate of clientPostPermits.slice(0, -1)) {
      await expectPostAllowed(candidate.input, candidate.permit);
      quotaClientPostCount += 1;
    }
    assert.equal(quotaClientPostCount, admissionPolicy.post.client.limit);
    assert.equal((await call("post", { input: { ...clientPostPermits.at(-1)!.input,
      permit: clientPostPermits.at(-1)!.permit } })).body.decision, "limited");

    // A different client is still allowed, proving the prior denial was client rather than global history.
    const independentPostInput = makePre(nextRelease);
    const independentPostPermit = await expectPreAllowed(independentPostInput);
    await expectPostAllowed(independentPostInput, independentPostPermit);

    // The pre-rotation PRE-client observations must likewise supply two of the thirty retained charges.
    while (quotaClientPreCount < admissionPolicy.pre.client.limit) {
      await expectPreAllowed(makePre(nextRelease, quotaClient));
      quotaClientPreCount += 1;
    }
    assert.equal((await call("pre", { input: makePre(nextRelease, quotaClient) })).body.decision, "limited");
    await expectPreAllowed(makePre(nextRelease)); // proves PRE global was not the saturated rule

    // Fill POST global to exactly its limit. If any pre-restart/rotation charge vanished, the probe is allowed.
    const postGlobalCandidates = Array.from({ length: admissionPolicy.post.global.limit - postAllowedCount + 1 },
      () => makePre(nextRelease));
    const postGlobalPreResults = await inBatches(postGlobalCandidates, 25, (input) => call("pre", { input }));
    for (const result of postGlobalPreResults) assert.equal(result.body.decision, "allowed");
    preAllowedCount += postGlobalPreResults.length;
    const postGlobalPermits = postGlobalPreResults.map((result) => String(result.body.permit));
    const postGlobalAllowedResults = await inBatches(postGlobalCandidates.slice(0, -1), 25,
      (input) => {
        const index = postGlobalCandidates.indexOf(input);
        return call("post", { input: { ...input, permit: postGlobalPermits[index] } });
      });
    for (const result of postGlobalAllowedResults) assert.equal(result.body.decision, "allowed");
    postAllowedCount += postGlobalAllowedResults.length;
    assert.equal(postAllowedCount, admissionPolicy.post.global.limit);
    assert.equal((await call("post", { input: { ...postGlobalCandidates.at(-1)!, permit: postGlobalPermits.at(-1)! } })).body.decision, "limited");

    // Fill PRE global to exactly its limit with distinct clients, independent of the saturated quota client.
    const remainingPre = admissionPolicy.pre.global.limit - preAllowedCount;
    assert.ok(remainingPre > 0);
    const preGlobalFill = Array.from({ length: remainingPre }, () => makePre(nextRelease));
    const preGlobalResults = await inBatches(preGlobalFill, 25, (input) => call("pre", { input }));
    for (const result of preGlobalResults) assert.equal(result.body.decision, "allowed");
    preAllowedCount += preGlobalResults.length;
    assert.equal(preAllowedCount, admissionPolicy.pre.global.limit);
    assert.equal((await call("pre", { input: makePre(nextRelease) })).body.decision, "limited");

    const waitMs = Math.max(0, retiresAtMs - Date.now() + 10);
    if (waitMs) await new Promise((resolve) => setTimeout(resolve, waitMs));
    assert.equal((await call("pre", { input: makePre(currentRelease) })).body.decision, "unavailable");
    assert.equal((await call("pre", { input: makePre(nextRelease) })).body.decision, "limited");
    assert.deepEqual(await call("rotate", { command: rotate, signature: rotateSignature }), { status: 200, body: { status: "already-rotated" } });
    assert.deepEqual((await call("rotate", { command: conflict, signature: conflictSignature })).body, { status: "refused" });

    const resetAttempt: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID,
      ADMISSION_POLICY_EPOCH, "dpl_reset", "rpc-reset", Date.now(), true];
    assert.deepEqual((await submit("initialize", resetAttempt,
      await signAuthorityInitializationCommand(resetAttempt, privateKey))).body, { status: "refused" });
    assert.equal((await call("reset", {})).status, 404);
  } finally {
    try {
      if (worker) await worker.stop();
    } finally {
      await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
    }
  }
  console.log("Production Durable Object RPC integration: PASS (actual Production class/RPC, pre-rotation PRE/POST state, independent quota scopes, permit/nonce replay, rotation, retirement and persisted restart)");
}

void main();
