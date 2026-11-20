import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { ChildProcess, fork } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, mkdir, rmdir } from "node:fs/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { test, type TestContext } from "node:test";
import { importPrivateKey, importPublicKey, issuePb } from "../defense/core/hop-proof";
import { buildApprovedRequest, HOP_BA_HEADER, HOP_PB_HEADER } from "../defense/core/semantic-request";
import { createBoundaryExecution, EXECUTION_HEADER, provisionExecutionGeneration } from "../defense/origin/execution-fence";
import { startFencedBoundary, startFencedOrigin, startFencedSupervisor } from "../lab/defense/fenced-supervisor";
import { forkWitnessProcess, signOwnership, startTerminationWitness, stopWitnessProcess, type WitnessResponse } from "../lab/defense/fenced-witness";
import { HopTrustRoot } from "../lab/defense/hop-keys";
import { openLifetime } from "../lab/defense/fenced-lifetime";
import type { Command, Reply } from "../lab/defense/fenced-process-main";
import fixture from "./fixtures/customer-origin-v1/ba0.json";

const policy = Buffer.from(JSON.stringify(fixture));
const scope = fixture.domain.backendRef;
const activation = { tenantId: fixture.tenantId, deploymentId: fixture.deploymentId, domainId: fixture.domain.id,
  revision: fixture.revision, expectedDigest: createHash("sha256").update(policy).digest("hex") };
const binding = fixture.channels[0];
const limits = { replayCapacity: 64, bodyDeadlineMs: 2_000, forwardTimeoutMs: 2_000, baLifetimeMs: 1_500 };
const timeout = { timeout: 30_000 };

async function supervised(t: TestContext, trust: HopTrustRoot, verified = true) {
  const ownershipRoot = await mkdtemp(path.join(tmpdir(), "limitmark-owner-"));
  const config = { trust, policy, activation, channel: binding.id, limits, ownershipRoot,
    executionModel: verified ? "process-local-synthetic" as const : undefined };
  const supervisor = await startFencedSupervisor(config);
  t.after(async () => {
    await supervisor.close();
    if (!verified) await rmdir(path.join(ownershipRoot, `${scope}.owner`));
    await rmdir(ownershipRoot);
  });
  return { supervisor, config };
}

function roundTrip(port: number, headers: Record<string, string>, target = "/gizlilik"): Promise<number | null> {
  return new Promise((resolve) => {
    const req = http.request({ host: "127.0.0.1", port, path: target, agent: false, headers: { host: binding.authority, ...headers } }, (res) => {
      res.once("error", () => resolve(null));
      res.once("end", () => resolve(res.statusCode ?? null));
      res.resume();
    });
    req.once("error", () => resolve(null));
    req.setTimeout(5_000, () => req.destroy());
    req.end();
  });
}

function client(trust: HopTrustRoot) {
  const privateKey = importPrivateKey(trust.keyMaterial().privateP);
  let hop = 0;
  return (port: number, target = "/gizlilik"): Promise<number | null> => {
    const approved = buildApprovedRequest({ method: "GET", target, headers: [["host", binding.authority]], bodyStatus: "none", body: null });
    assert.ok(approved.ok);
    const proof = issuePb({ kid: trust.kidP, privateKey, boundaryId: trust.boundaryId, lifetimeMs: 4_000, now: Date.now }, approved.approved,
      { corr: String(++hop).padStart(22, "N"), hop });
    return roundTrip(port, { [HOP_PB_HEADER]: proof.header }, target);
  };
}

function credentials(trust: HopTrustRoot, ownershipEpoch?: string) {
  const ownerKey = randomBytes(32);
  const keys = generateKeyPairSync("ed25519");
  const origin = { ...trust.appInit(limits), scope, ownershipEpoch, ownerKey: ownerKey.toString("base64url"),
    signingKey: keys.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url") };
  return { origin, boundary: (port: number, instance: string, owner = ownershipEpoch, epoch = 1) => ({ ...trust.boundaryInit(port, limits), policy: policy.toString("base64url"), activation,
    principal: binding.principal, audience: binding.audience, scheme: "http" as const,
    originKey: keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
    generation: provisionExecutionGeneration(ownerKey, { scope, epoch, originInstance: instance, ownershipEpoch: owner }) }) };
}

test("separate-process startup and replacement require authenticated readiness and preserve old in-flight accounting", timeout, async (t) => {
  const trust = new HopTrustRoot();
  const { supervisor } = await supervised(t, trust);
  const send = client(trust);
  const originPid = supervisor.origin.pid;
  assert.ok(originPid && originPid !== process.pid);
  const initial = await supervisor.prepare();
  assert.ok(initial.pid && initial.pid !== process.pid && initial.pid !== originPid);
  assert.equal(supervisor.port, null);
  await assert.rejects(supervisor.prepare(), /already pending/);
  assert.equal(await supervisor.activate(), true);
  assert.equal(await send(supervisor.port!), 200);
  assert.equal((await initial.stats()).capacity?.usage?.leases, 0);

  await initial.stop(true);
  assert.equal(supervisor.port, null);
  const old = await supervisor.prepare();
  assert.notEqual(old.pid, initial.pid);
  assert.equal(await supervisor.activate(), true);
  const oldPort = supervisor.port!;
  assert.equal(supervisor.origin.pid, originPid);
  await supervisor.origin.holdNext();
  const outstanding = send(oldPort);
  await supervisor.origin.waitHeld();
  const replacement = await supervisor.prepare();
  assert.notEqual(replacement.pid, old.pid);
  assert.equal(await supervisor.activate(), false);
  assert.equal(supervisor.port, null);
  assert.equal((await replacement.stats()).capacity?.state, "unavailable");
  assert.equal(await send(oldPort), null);
  await assert.rejects(old.stats(), /unavailable/);
  assert.equal((await supervisor.origin.stats()).admitted, 2);

  await old.stop(true);
  await outstanding;
  assert.equal(await supervisor.activate(), false);
  await supervisor.origin.release();
  assert.equal(await supervisor.activate(), true);
  assert.equal(await send(supervisor.port!), 200);
  assert.equal((await replacement.stats()).capacity?.usage?.leases, 0);
  assert.equal((await supervisor.origin.stats()).executed, 3);
  assert.equal(supervisor.origin.pid, originPid);
});

test("the origin rejects wrong ownership, duplicate generation sessions, and credentials from the lost origin", timeout, async (t) => {
  const trust = new HopTrustRoot();
  const ownershipEpoch = randomUUID();
  const material = credentials(trust, ownershipEpoch);
  const originClient = (port: number, instance: string) => {
    const config = material.boundary(port, instance, ownershipEpoch, 2);
    return createBoundaryExecution({ generation: config.generation, originKey: importPublicKey(config.originKey) }, scope, port, 2_000);
  };
  const origin = await startFencedOrigin(material.origin, 5_000);
  t.after(() => origin.stop());
  const bootstrap = material.boundary(origin.port, origin.instance);
  const wrongOwner = await startFencedBoundary(material.boundary(origin.port, origin.instance, randomUUID()), 5_000);
  t.after(() => wrongOwner.stop());
  assert.equal(await wrongOwner.reconcile(), null);
  const first = await startFencedBoundary(bootstrap, 5_000);
  t.after(() => first.stop());
  assert.ok(await first.reconcile());
  const duplicate = await startFencedBoundary(bootstrap, 5_000);
  t.after(() => duplicate.stop());
  assert.equal(await duplicate.reconcile(), null);
  assert.equal((await duplicate.stats()).capacity?.state, "unavailable");
  assert.ok(await first.reconcile());
  const oldClient = originClient(origin.port, origin.instance);
  assert.equal(await oldClient.reconcile(), true);

  await origin.stop(true);
  const replacementOrigin = await startFencedOrigin(material.origin, 5_000);
  t.after(() => replacementOrigin.stop());
  assert.notEqual(replacementOrigin.instance, origin.instance);
  const stale = await startFencedBoundary({ ...bootstrap, appPort: replacementOrigin.port }, 5_000);
  t.after(() => stale.stop());
  assert.equal(await stale.reconcile(), null);
  assert.equal((await stale.stats()).capacity?.state, "unavailable");
  const replacementClient = originClient(replacementOrigin.port, replacementOrigin.instance);
  assert.equal(await replacementClient.reconcile(), true);
  const direct = async (execution: typeof replacementClient, corr: string) => {
    const proofs = trust.mintChain({ method: "GET", target: "/gizlilik", host: binding.authority, body: Buffer.alloc(0) }, corr);
    return roundTrip(replacementOrigin.port, { [HOP_PB_HEADER]: proofs.pb.header, [HOP_BA_HEADER]: proofs.ba.header,
      [EXECUTION_HEADER]: execution.request(proofs.ba.header).header });
  };
  assert.equal(await direct(oldClient, "1".padStart(22, "N")), 503);
  assert.equal((await replacementOrigin.stats()).executed, 0);
  assert.equal(await direct(replacementClient, "2".padStart(22, "N")), 200);
});

test("a Boundary child refuses unsigned, forged, and absent readiness responses", timeout, async (t) => {
  const forgedProof = randomBytes(64).toString("base64url");
  let mode: "unsigned" | "forged" | "silent" = "unsigned";
  const peer = http.createServer((_req, res) => {
    if (mode !== "silent") res.writeHead(204, mode === "forged" ? { "x-limitmark-generation": forgedProof } : {}).end();
  });
  peer.listen(0, "127.0.0.1");
  await once(peer, "listening");
  t.after(() => new Promise<void>((resolve) => { peer.close(() => resolve()); peer.closeAllConnections(); }));
  const material = credentials(new HopTrustRoot());
  const bootstrap = material.boundary((peer.address() as AddressInfo).port, randomUUID());
  const child = await startFencedBoundary({ ...bootstrap, limits: { ...bootstrap.limits, forwardTimeoutMs: 100 } }, 5_000);
  t.after(() => child.stop());
  assert.equal(await child.reconcile(), null);
  mode = "forged";
  assert.equal(await child.reconcile(), null);
  mode = "silent";
  assert.equal(await child.reconcile(), null);
  assert.equal((await child.stats()).capacity?.state, "unavailable");
});

test("verified origin exit recovers idle and active work with a fresh origin and signed readiness", timeout, async (t) => {
  const trust = new HopTrustRoot();
  const { supervisor, config } = await supervised(t, trust);
  const send = client(trust);
  const activate = async () => {
    const boundary = await supervisor.prepare();
    assert.equal(supervisor.port, null);
    assert.equal(await supervisor.activate(), true);
    return boundary;
  };
  await activate();
  await assert.rejects(supervisor.recoverOrigin(), /termination cannot be verified/);
  const initial = supervisor.origin;
  await initial.stop(true);
  assert.equal(supervisor.port, null);
  await assert.rejects(startFencedSupervisor(config), /exclusive backend ownership/);
  await supervisor.recoverOrigin();
  assert.notEqual(supervisor.origin.pid, initial.pid);
  assert.notEqual(supervisor.origin.instance, initial.instance);
  const boundary = await activate();
  const port = supervisor.port!;
  assert.equal(await send(port), 200);

  const active = supervisor.origin;
  await supervisor.origin.holdNext();
  const outstanding = send(port);
  await supervisor.origin.waitHeld();
  await active.stop(true);
  assert.equal(supervisor.port, null);
  assert.notEqual(await outstanding, 200);
  await assert.rejects(supervisor.prepare(), /unavailable/);
  await assert.rejects(supervisor.activate(), /unavailable/);
  await supervisor.recoverOrigin();
  await boundary.stop();
  assert.equal(await send(port), null);
  assert.notEqual(supervisor.origin.instance, active.instance);
  const replacement = await activate();
  assert.equal(await send(supervisor.port!), 200);
  assert.equal((await replacement.stats()).capacity?.usage?.leases, 0);
});

test("process exit alone cannot authorize recovery for an unverified execution model", timeout, async (t) => {
  const trust = new HopTrustRoot();
  const { supervisor, config } = await supervised(t, trust, false);
  await supervisor.prepare();
  assert.equal(await supervisor.activate(), true);
  await supervisor.origin.stop(true);
  await assert.rejects(supervisor.recoverOrigin(), /termination cannot be verified/);
  assert.equal(supervisor.port, null);
  await supervisor.close();
  await assert.rejects(startFencedSupervisor(config), /exclusive backend ownership/);
});

test("the ownership marker coordinates OS supervisors across clean and unverified exits", timeout, async (t) => {
  const ownershipRoot = await mkdtemp(path.join(tmpdir(), "limitmark-owner-process-"));
  const marker = path.join(ownershipRoot, `${scope}.owner`);
  const children = new Set<ReturnType<typeof fork>>();
  t.after(async () => {
    await Promise.all([...children].map(async (child) => {
      const exit = once(child, "exit", { signal: AbortSignal.timeout(5_000) });
      child.kill("SIGKILL");
      await exit;
    }));
    await rmdir(marker).catch((error: NodeJS.ErrnoException) => { if (error.code !== "ENOENT") throw error; });
    await rmdir(ownershipRoot);
  });
  async function launch() {
    const child = fork(path.join(__dirname, "support", "fenced-owner-process.ts"), [], {
      execArgv: process.execArgv, stdio: ["ignore", "ignore", "ignore", "ipc"],
    });
    children.add(child);
    const exit = once(child, "exit");
    child.once("exit", () => children.delete(child));
    const result = once(child, "message", { signal: AbortSignal.timeout(10_000) });
    child.send({ ownershipRoot, policy: policy.toString("base64url"), activation, limits, channel: binding.id });
    const [state] = await result;
    return { child, exit, state };
  }
  const first = await launch();
  assert.equal(first.state, "ready");
  const competing = await launch();
  assert.equal(competing.state, "blocked");
  await competing.exit;
  first.child.send("stop");
  assert.deepEqual(await first.exit, [0, null]);

  const restarted = await launch();
  assert.equal(restarted.state, "ready");
  assert.notEqual(restarted.child.pid, first.child.pid);
  restarted.child.kill("SIGKILL");
  await restarted.exit;
  const unverified = await launch();
  assert.equal(unverified.state, "blocked");
  await unverified.exit;

  // An old marker has no age-based or PID-based escape hatch, even in an otherwise empty namespace.
  await rmdir(marker);
  await mkdir(marker);
  const stale = await launch();
  assert.equal(stale.state, "blocked");
  await stale.exit;
});

test("a pre-fork bootstrap failure releases the ownership marker", timeout, async (t) => {
  const trust = new HopTrustRoot();
  const ownershipRoot = await mkdtemp(path.join(tmpdir(), "limitmark-pre-fork-"));
  t.after(() => rmdir(ownershipRoot));
  const config = { trust, policy, activation, channel: binding.id, limits, ownershipRoot, executionModel: "process-local-synthetic" as const };
  const failure = new Error("origin bootstrap failed before fork");
  await assert.rejects(startFencedSupervisor({ ...config, trust: {
    appInit: () => { throw failure; }, boundaryInit: trust.boundaryInit.bind(trust),
  } }), (error) => error === failure);
  const replacement = await startFencedSupervisor(config);
  try { assert.equal(replacement.origin.alive, true); }
  finally { await replacement.close(); }
});

test("the witness rotates owner sessions after verifying session and active origin exit", timeout, async (t) => {
  const trust = new HopTrustRoot();
  const ownershipRoot = await mkdtemp(path.join(tmpdir(), "limitmark-witness-"));
  const config = { trust, policy, activation, channel: binding.id, limits, ownershipRoot };
  const witness = await startTerminationWitness(config);
  const contender = await startTerminationWitness(config);
  t.after(async () => { await contender.close(); await witness.close(); await rmdir(ownershipRoot); });
  const first = await witness.acquire(null);
  assert.ok(first);
  assert.equal(first.ownership.scope, scope);
  const initial = await witness.status();
  assert.equal(new Set([process.pid, witness.pid, initial.ownerPid, initial.originPid]).size, 4);
  assert.ok(initial.port);
  assert.equal(await contender.acquire(null), null);
  assert.equal(await witness.acquire(first.ownership.epoch), null);
  assert.equal(await witness.validate(first), true);
  assert.equal(await witness.validate({ ...first, signature: randomBytes(64).toString("base64url") }), false);
  const send = client(trust);
  assert.equal(await send(initial.port), 200);

  await witness.control("hold-next");
  const outstanding = send(initial.port);
  await witness.control("wait-held");
  await witness.control("kill-owner");
  const afterExit = await witness.status();
  assert.equal(afterExit.ownerAlive, false);
  assert.equal(afterExit.originAlive, true);
  assert.equal(afterExit.originInstance, initial.originInstance);
  assert.equal(afterExit.port, null);
  assert.equal(await witness.validate(first), false);
  assert.equal(await witness.acquire(null), null);
  assert.equal(await contender.acquire(null), null);
  // Existing admission is entirely between Boundary and origin until explicit, witnessed takeover.
  assert.equal(await send(initial.port), 200);

  const replacement = await witness.acquire(first.ownership.epoch);
  assert.ok(replacement);
  assert.equal(replacement.ownership.previous, first.ownership.epoch);
  assert.notEqual(replacement.ownership.epoch, first.ownership.epoch);
  assert.notEqual(await outstanding, 200);
  const recovered = await witness.status();
  assert.notEqual(recovered.originInstance, initial.originInstance);
  assert.notEqual(recovered.ownerPid, initial.ownerPid);
  assert.equal(await witness.validate(first), false);
  assert.equal(await witness.validate(replacement), true);
  assert.equal(await witness.acquire(first.ownership.epoch), null);
  assert.ok(recovered.port);
  assert.equal(await send(recovered.port), 200);
});

test("witness loss blocks acquisition but an already-established local data path can continue", timeout, async (t) => {
  const trust = new HopTrustRoot();
  const ownershipRoot = await mkdtemp(path.join(tmpdir(), "limitmark-witness-loss-"));
  const manifest = structuredClone(fixture);
  manifest.classes[0].maxActiveUnits = 1;
  const bytes = Buffer.from(JSON.stringify(manifest));
  const config = { trust, policy: bytes, activation: { ...activation, expectedDigest: createHash("sha256").update(bytes).digest("hex") },
    channel: binding.id, limits, ownershipRoot };
  const original = await startTerminationWitness(config);
  const successor = await startTerminationWitness(config);
  t.after(async () => {
    await successor.close();
    await assert.rejects(original.close(), /could not verify ownership release/); // The lifetime pipe still tears down the children.
    // Remove the disposable test namespace. No recovery is attempted in this namespace after evidence loss.
    await rmdir(path.join(ownershipRoot, `${scope}.owner`));
    await rmdir(ownershipRoot);
  });
  const grant = await original.acquire(null);
  assert.ok(grant);
  const { port } = await original.status();
  assert.ok(port);
  const send = client(trust);
  await original.control("hold-next");
  const held = send(port);
  await original.control("wait-held");
  assert.equal(await send(port), 503);
  const diagnostic = Promise.allSettled([original.control("wait-held")]);
  await original.crash();
  await diagnostic;
  await assert.rejects(original.acquire(grant.ownership.epoch), /witness unavailable/);
  assert.equal(await successor.acquire(null), null);
  assert.equal(await successor.acquire(grant.ownership.epoch), null);
  assert.equal(await successor.validate(grant), false);
  assert.equal(await send(port), 503);
  assert.equal(await send(port, "/test-talep-et"), 200);
  assert.notEqual(await held, 200);
});

test("a 30-second witness diagnostic timeout preserves ownership and allows verified shutdown", { timeout: 75_000 }, async (t) => {
  const trust = new HopTrustRoot();
  const ownershipRoot = await mkdtemp(path.join(tmpdir(), "limitmark-witness-timeout-"));
  const config = { trust, policy, activation, channel: binding.id, limits, ownershipRoot, timeout: 30_000 };
  const witness = await startTerminationWitness(config);
  const contender = await startTerminationWitness(config);
  t.after(async () => { await contender.close(); await witness.close(); await rmdir(ownershipRoot); });
  const grant = await witness.acquire(null);
  assert.ok(grant);
  const initial = await witness.status();
  assert.equal(initial.ownerAlive, true);
  assert.equal(initial.originAlive, true);
  await witness.control("hold-next");

  // Deliver the actual late diagnostic reply immediately before the fresh status reply.
  const emit = ChildProcess.prototype.emit;
  let late: WitnessResponse | undefined;
  let delivered = false;
  const mock = t.mock.method(ChildProcess.prototype, "emit", function (this: ChildProcess, event: string, ...args: unknown[]) {
    const message = args[0] as WitnessResponse | undefined;
    if (this.pid === witness.pid && event === "message") {
      if (message?.reply?.type === "error") { late = message; return true; }
      if (message?.reply?.type === "status" && late) {
        delivered = late.id !== message.id;
        Reflect.apply(emit, this, [event, late]);
      }
    }
    return Reflect.apply(emit, this, [event, ...args]);
  });
  try {
    await assert.rejects(witness.control("wait-held"), /command timed out/);
    assert.deepEqual(await witness.status(), initial);
    assert.equal(delivered, true);
  } finally { mock.mock.restore(); }

  assert.equal(await contender.acquire(null), null);
  assert.equal(await witness.acquire(grant.ownership.epoch), null);
  assert.equal(await witness.validate(grant), true);
  await witness.close();
  const replacement = await contender.acquire(null);
  assert.ok(replacement);
  assert.notEqual(replacement.ownership.epoch, grant.ownership.epoch);
});

test("a delayed diagnostic reply cannot kill charged work or satisfy a later exchange", timeout, async (t) => {
  const trust = new HopTrustRoot();
  const { supervisor } = await supervised(t, trust);
  const boundary = await supervisor.prepare();
  assert.equal(await supervisor.activate(), true);
  await supervisor.origin.holdNext();
  const outstanding = client(trust)(supervisor.port!);
  await supervisor.origin.waitHeld();

  const emit = ChildProcess.prototype.emit;
  let delayed: (() => void) | undefined;
  let intercept = true;
  const mock = t.mock.method(ChildProcess.prototype, "emit", function (this: ChildProcess, event: string, ...args: unknown[]) {
    const message = args[0] as { reply?: { type: string } } | undefined;
    if (intercept && this.pid === supervisor.origin.pid && event === "message" && message?.reply?.type === "origin-stats") {
      intercept = false;
      delayed = () => Reflect.apply(emit, this, [event, ...args]);
      return true;
    }
    return Reflect.apply(emit, this, [event, ...args]);
  });
  try {
    await assert.rejects(supervisor.origin.stats(), /timed out/);
    assert.ok(delayed);
    assert.equal(supervisor.origin.alive, true);
    assert.equal((await boundary.stats()).capacity?.usage?.ambiguous, 1);
    const release = supervisor.origin.release();
    delayed();
    await release;
    assert.equal((await supervisor.origin.stats()).executed, 1);
    assert.notEqual(await outstanding, 200);
    await supervisor.prepare();
    assert.equal(await supervisor.activate(), true);
  } finally { mock.mock.restore(); }
});

test("a retained origin survives asynchronous reply failure with a charged request in progress", timeout, async (t) => {
  const trust = new HopTrustRoot();
  const material = credentials(trust);
  const lifetime = await openLifetime();
  const child = fork(path.join(__dirname, "../lab/defense/fenced-process-main.ts"), [], {
    execArgv: [...process.execArgv, "--require", path.join(__dirname, "support/fenced-reply-failure.cjs")],
    stdio: ["ignore", "ignore", "ignore", "ipc"],
  });
  t.after(async () => { await stopWitnessProcess(child); await lifetime.close(); });
  let id = 0;
  async function exchange(command: Command) {
    const result = once(child, "message", { signal: AbortSignal.timeout(5_000) });
    child.send({ id: ++id, command });
    const [message] = await result;
    assert.equal(message.id, id);
    return message as { reply?: Reply; injectedFailure?: boolean };
  }
  const started = (await exchange({ type: "start-origin", config: { ...material.origin, lifetime: lifetime.descriptor } })).reply;
  assert.ok(started?.type === "origin");
  const boundary = await startFencedBoundary(material.boundary(started.port, started.instance), 5_000);
  t.after(() => boundary.stop());
  const port = await boundary.reconcile();
  assert.ok(port);
  await exchange({ type: "hold-next" });
  const request = client(trust)(port);
  const deadline = performance.now() + 2_000;
  for (;;) {
    const status = (await exchange({ type: "held" })).reply;
    if (status?.type === "held" && status.started) break;
    assert.ok(performance.now() < deadline, "origin entered charged work");
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.equal((await exchange({ type: "stats" })).injectedFailure, true);
  assert.equal((await boundary.stats()).capacity?.usage?.leases, 1);
  await exchange({ type: "release" });
  assert.equal(await request, 200);
  assert.equal((await boundary.stats()).capacity?.usage?.leases, 0);
});

test("failed acquisition releases its verified backend and close waits for a pending acquisition", timeout, async (t) => {
  const trust = new HopTrustRoot();
  const ownershipRoot = await mkdtemp(path.join(tmpdir(), "limitmark-witness-close-"));
  const config = { trust, policy, activation, channel: binding.id, limits, ownershipRoot };
  const broken = await startTerminationWitness({ ...config, trust: { appInit: trust.appInit.bind(trust),
    boundaryInit: (port, limits) => ({ ...trust.boundaryInit(port, limits), privateKeyB: "invalid" }) } });
  const healthy = await startTerminationWitness(config);
  t.after(async () => { await broken.close(); await healthy.close(); await rmdir(ownershipRoot); });
  await assert.rejects(broken.acquire(null), /acquisition failed/);
  assert.equal((await broken.status()).epoch, null);
  const acquisition = healthy.acquire(null);
  const closing = healthy.close();
  await assert.rejects(healthy.status(), /unavailable/);
  assert.ok(await acquisition);
  await closing;
  const replacement = await startTerminationWitness(config);
  try { assert.ok(await replacement.acquire(null)); } finally { await replacement.close(); }
});

test("an owner session process refuses missing or forged witness grants", timeout, async (t) => {
  const trusted = generateKeyPairSync("ed25519");
  const other = generateKeyPairSync("ed25519");
  const expected = { scope, epoch: randomUUID(), previous: null, challenge: randomUUID() };
  const witnessKey = trusted.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  for (const grant of [undefined, signOwnership(expected, other.privateKey)]) {
    const child = forkWitnessProcess(["owner"]);
    t.after(() => stopWitnessProcess(child));
    const reply = once(child, "message", { signal: AbortSignal.timeout(5_000) });
    const exit = once(child, "exit", { signal: AbortSignal.timeout(5_000) });
    child.send({ expected, grant, witnessKey });
    const [message] = await reply;
    assert.deepEqual(message, { type: "denied" });
    assert.deepEqual(await exit, [1, null]);
  }
});
