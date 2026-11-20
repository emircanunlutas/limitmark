import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { once } from "node:events";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { test, type TestContext } from "node:test";
import { createBoundary, type BoundaryOptions } from "../defense/boundary/boundary";
import { activateCustomerOriginPolicy } from "../defense/core/capacity-policy";
import type { CompiledCustomerOriginPolicy } from "../defense/core/capacity-port";
import { importPrivateKey, importPublicKey, issuePb } from "../defense/core/hop-proof";
import { JourneyLanes } from "../defense/core/lanes";
import type { BoundaryEvent, PlaneEvent } from "../defense/core/ledger";
import { buildApprovedRequest, HOP_BA_HEADER, HOP_PB_HEADER } from "../defense/core/semantic-request";
import { ShapeGate } from "../defense/layers/a7-shape-gate";
import { createAppGuard } from "../defense/origin/app-guard";
import { createBoundaryExecution, createExecutionFence, provisionExecutionGeneration, TERMINAL_HEADER } from "../defense/origin/execution-fence";
import { createSyntheticOrigin, type RequestFacts } from "../defense/origin/synthetic-origin";
import { createFront } from "../defense/plane/front";
import { L2Stage } from "../defense/plane/l2-stage";
import { SemanticGate } from "../defense/plane/semantic-gate";
import { HopTrustRoot } from "../lab/defense/hop-keys";
import fixture from "./fixtures/customer-origin-v1/ba0.json";

const authority = fixture.channels[0].authority;
const formType = "application/x-www-form-urlencoded";
const testOptions = { timeout: 10_000 };
const terminals = new WeakMap<http.ServerResponse, () => string>();
function complete(res: http.ServerResponse, body = "", status = 200) {
  res.setHeader(TERMINAL_HEADER, terminals.get(res)!());
  res.writeHead(status).end(body);
}

async function rig(t: TestContext, serve: (req: http.IncomingMessage, res: http.ServerResponse, facts: RequestFacts) => void, settings: {
  forgedPolicy?: boolean; signingKey?: boolean; onEvent?: (event: Omit<BoundaryEvent, "seq" | "t">) => void;
} = {}) {
  const root = new HopTrustRoot();
  const keys = root.keyMaterial();
  const clock = { now: Date.now(), mono: 100 };
  const now = () => clock.now;
  const hop = { keyP: importPublicKey(keys.publicP), kidP: root.kidP, boundaryId: root.boundaryId, kidB: root.kidB, appId: root.appId };
  const app = createAppGuard({ ...hop, keyB: importPublicKey(keys.publicB), replayCapacity: 64, bodyDeadlineMs: 2_000, now });
  const ownerKey = randomBytes(32);
  const originKeys = generateKeyPairSync("ed25519");
  const scope = fixture.domain.backendRef;
  const fence = createExecutionFence({ ownerKey, originKey: originKeys.privateKey, scope });
  const generation = (epoch: number) => ({ originKey: originKeys.publicKey, generation: provisionExecutionGeneration(ownerKey, { originInstance: fence.originInstance, scope, epoch }) });
  let arrivals = 0;
  const origin = http.createServer((req, res) => {
    if (fence.control(req, res)) return;
    const envelope = fence.extract(req);
    const ba = req.headers[HOP_BA_HEADER];
    void app.guard(req).then((result) => {
      const terminal = result.ok && envelope && typeof ba === "string" ? fence.accept(envelope, ba) : undefined;
      if (!result.ok || !terminal?.start()) { res.writeHead(503).end(); return; }
      terminals.set(res, terminal.finish);
      arrivals++;
      serve(req, res, result.facts);
    });
  });
  origin.listen(0, "127.0.0.1");
  await once(origin, "listening");
  t.after(() => new Promise<void>((resolve) => { origin.close(() => resolve()); origin.closeAllConnections(); }));
  const manifest = {
    ...fixture,
    capacity: { ...fixture.capacity, activeUnits: 2, executionTimeoutMs: 5_000, callerBudgetMs: 7_000 },
    classes: fixture.classes.map((cls) => ({ ...cls, reservedUnits: 0, maxActiveUnits: 2 })),
  };
  const bytes = Buffer.from(JSON.stringify(manifest));
  const activated = activateCustomerOriginPolicy(bytes, {
    tenantId: manifest.tenantId, deploymentId: manifest.deploymentId, domainId: manifest.domain.id,
    revision: manifest.revision, expectedDigest: createHash("sha256").update(bytes).digest("hex"),
  });
  // The forged handle has identical public fields and fails M2's private activation check.
  const policy: CompiledCustomerOriginPolicy = settings.forgedPolicy ? { ...activated } : activated;
  let aborted = Promise.withResolvers<void>();
  const options = {
    ...hop, appPort: (origin.address() as AddressInfo).port,
    keyB: settings.signingKey ? importPublicKey(keys.publicB) : importPrivateKey(keys.privateB), now, mono: () => clock.mono,
    limits: { replayCapacity: 64, bodyDeadlineMs: 2_000, forwardTimeoutMs: 5_000, baLifetimeMs: 1_500 },
    capacity: { policy, principal: manifest.channels[0].principal, audience: manifest.channels[0].audience, scheme: "http", backendRef: scope, execution: generation(1) },
    emit: (event) => { if (event.kind === "BOUNDARY_ABORTED") aborted.resolve(); settings.onEvent?.(event); return 1; },
  } satisfies BoundaryOptions;
  const boundary = createBoundary(options);
  t.after(() => boundary.close());
  const port = await boundary.listen();
  clock.now++;
  assert.equal(await boundary.reconcile(), !settings.forgedPolicy);
  const issuer = { kid: root.kidP, privateKey: importPrivateKey(keys.privateP), boundaryId: root.boundaryId, lifetimeMs: 4_000, now };
  let next = 0;
  function signed(method = "GET", target = "/gizlilik", body?: string, host = authority, to = port) {
    const headers = { host, ...(body === undefined ? {} : { "content-type": formType, origin: `http://${host}`, "content-length": String(Buffer.byteLength(body)) }) };
    const approved = buildApprovedRequest({ method, target, headers: Object.entries(headers), bodyStatus: body === undefined ? "none" : "complete", body: body === undefined ? null : Buffer.from(body) });
    assert.ok(approved.ok);
    const hop = ++next;
    const proof = issuePb(issuer, approved.approved, { hop, corr: String(hop).padStart(22, "N") });
    return request(to, method, target, { ...headers, [HOP_PB_HEADER]: proof.header }, body);
  }
  return { fence, generation, origin, boundary, options, issuer, port, signed, clock, arrivals: () => arrivals, usage: () => boundary.stats().capacity?.usage,
    nextAbort: () => { aborted = Promise.withResolvers<void>(); return aborted.promise; } };
}

function request(port: number, method: string, path: string, headers: Record<string, string> = {}, body?: string) {
  const client = http.request({ host: "127.0.0.1", port, method, path, headers, agent: false });
  const response = new Promise<{ status: number; body: string } | undefined>((resolve, reject) => {
    client.on("error", reject);
    client.on("close", () => resolve(undefined));
    client.on("response", (response) => {
      response.setEncoding("utf8");
      let payload = "";
      response.on("data", (data: string) => { payload += data; });
      response.on("end", () => resolve({ status: response.statusCode!, body: payload }));
    });
  });
  client.end(body);
  return { client, response };
}

test("capacity preserves L1/L2 pass and refusal paths and forwards an authenticated body", testOptions, async (t) => {
  const r = await rig(t, (_req, res, facts) => complete(res, facts.body?.toString() ?? "ok"));
  const events: Omit<PlaneEvent, "seq" | "t">[] = [];
  const lanes = new JourneyLanes({ filterBits: 2 ** 14, filterHashes: 7, epochMs: 60_000, credited: { capacity: 1, refillPerSecond: 1 },
    unverified: { capacity: 1, refillPerSecond: 1 }, maxUses: 1, ledgerCapacity: 128, mono: () => 100, key: Buffer.alloc(32, 3) });
  const front = createFront({ upstream: { host: "127.0.0.1", port: r.port }, layer: new SemanticGate(new ShapeGate()), l2: new L2Stage(lanes, { maxResponseBytes: 1_048_576 }),
    emit: (event) => events.push(event), hop: { issue: (approved, context) => issuePb(r.issuer, approved, context) } });
  t.after(() => front.close(500));
  const port = await front.listen();
  assert.deepEqual(await request(port, "GET", "/gizlilik", { host: authority }).response, { status: 200, body: "ok" });
  assert.ok(events.some((event) => event.kind === "L2_DECIDED" && event.outcome === "admitted"));
  assert.ok(((await request(port, "GET", "/admin", { host: authority }).response)?.status ?? 0) >= 400);
  assert.ok(events.some((event) => event.kind === "L1_REJECTED"));
  assert.equal(r.boundary.stats().arrived, 1);
  const form = "name=Capacity&email=c%40example.test&service=web&system=s&objective=o&environment=staging&authority=authorized";
  const headers = { host: authority, origin: `http://${authority}`, "content-type": formType, "content-length": String(Buffer.byteLength(form)) };
  assert.deepEqual(await request(port, "POST", "/api/public-inquiries", headers, form).response, { status: 200, body: form });
  assert.equal((await request(port, "POST", "/api/public-inquiries", headers, form).response)?.status, 503);
  assert.ok(events.some((event) => event.kind === "L2_DECIDED" && event.outcome === "shed"));
  assert.equal(r.boundary.stats().arrived, 2);
  assert.equal(r.usage()?.leases, 0);
  assert.equal(r.usage()?.preparationSlots, 0);
});

test("concurrent grants exhaust capacity without queuing, and cancelled clients release on origin completion", testOptions, async (t) => {
  const started = [Promise.withResolvers<http.ServerResponse>(), Promise.withResolvers<http.ServerResponse>()];
  let index = 0;
  const r = await rig(t, (_req, res) => { const waiter = started[index++]; if (waiter) waiter.resolve(res); else complete(res, "ok"); });
  const first = r.signed();
  const second = r.signed();
  const [one, two] = await Promise.all(started.map(({ promise }) => promise));
  assert.equal(r.usage()?.shared, 2);
  const refused = await Promise.all([r.signed().response, r.signed().response]);
  assert.deepEqual(refused.map((result) => result?.status), [503, 503]);
  assert.equal(r.arrivals(), 2);
  assert.equal(r.usage()?.queued, 0);
  assert.equal(r.usage()?.bytes, 0);
  assert.equal(r.usage()?.preparationSlots, 0);
  assert.equal(r.boundary.stats().capacity?.refused, 2);

  const aborted = r.nextAbort();
  // Either client may have reached the origin first. Close both, while both origin responses remain open.
  for (const client of [first, second]) {
    void client.response.catch(() => undefined);
    client.client.destroy();
  }
  await Promise.allSettled([first.response, second.response]);
  assert.equal(r.usage()?.shared, 2);
  complete(one, "one");
  complete(two, "two");
  await aborted;
  assert.equal((await r.signed().response)?.status, 200);
  assert.equal(r.usage()?.leases, 0);
  assert.equal(r.usage()?.shared, 0);
  assert.equal(r.usage()?.ambiguous, 0);
});

test("origin 5xx and connection refusal release capacity, while a reset after dispatch leaves an ambiguous charge", testOptions, async (t) => {
  let reset = false;
  const r = await rig(t, (req, res) => { if (reset) req.socket.destroy(); else complete(res, "", 500); });
  assert.equal((await r.signed().response)?.status, 500);
  assert.equal(r.usage()?.leases, 0);
  reset = true;
  assert.equal((await r.signed().response)?.status, 502);
  assert.equal(r.usage()?.leases, 1);
  assert.equal(r.usage()?.ambiguous, 1);
  await new Promise<void>((resolve) => r.origin.close(() => resolve()));
  for (let i = 0; i < 2; i++) assert.equal((await r.signed().response)?.status, 502);
  assert.equal(r.boundary.stats().forwardFailedByKind.refused, 2);
  assert.equal(r.usage()?.leases, 1);
  assert.equal(r.usage()?.shared, 1);
  assert.equal(r.usage()?.ambiguous, 1);
});

test("a failed controller initialization refuses authenticated traffic without changing PB rejection", testOptions, async (t) => {
  const r = await rig(t, (_req, res) => res.end(), { forgedPolicy: true });
  assert.equal((await request(r.port, "GET", "/gizlilik").response)?.status, 403);
  assert.equal((await r.signed().response)?.status, 503);
  assert.equal(r.arrivals(), 0);
  assert.equal(r.boundary.stats().appProofsIssued, 0);
  assert.deepEqual(r.boundary.stats().capacity, { state: "unavailable", refused: 1 });
});

test("an out-of-scope signed authority and a failed BA signer leave no origin charge", testOptions, async (t) => {
  const r = await rig(t, (_req, res) => res.end(), { signingKey: true });
  assert.equal((await r.signed("GET", "/gizlilik", undefined, "other.example").response)?.status, 503);
  assert.equal(r.boundary.stats().capacity?.refused, 1);
  for (let i = 0; i < 2; i++) assert.equal((await r.signed().response)?.status, 503);
  assert.equal(r.boundary.stats().capacity?.refused, 1);
  assert.equal(r.usage()?.leases, 0);
  assert.equal(r.usage()?.shared, 0);
  assert.equal(r.arrivals(), 0);
});

test("truncated upstream responses and timeouts fill capacity with ambiguous charges", testOptions, async (t) => {
  const hanging = Promise.withResolvers<void>();
  let truncate = true;
  const r = await rig(t, (req, res) => {
    if (!truncate) { hanging.resolve(); return; }
    res.writeHead(200, { "content-length": "8" });
    res.write("x", () => req.socket.destroy());
  });
  t.mock.timers.enable({ apis: ["setTimeout"] });
  assert.equal((await r.signed().response)?.status, 502);
  assert.equal(r.usage()?.ambiguous, 1);
  assert.equal(r.usage()?.leases, 1);

  truncate = false;
  const request = r.signed();
  await hanging.promise;
  t.mock.timers.tick(5_000);
  assert.equal((await request.response)?.status, 504);
  assert.equal(r.boundary.stats().forwardFailedByKind.timeout, 1);
  assert.equal(r.boundary.stats().forwardFailedByKind.reset, 1);
  assert.equal(r.usage()?.ambiguous, 2);
  assert.equal(r.usage()?.leases, 2);

  t.mock.timers.tick(60_000);
  r.clock.now += 60_000;
  r.clock.mono += 60_000;
  const refused = await Promise.all([r.signed().response, r.signed().response]);
  assert.deepEqual(refused.map((response) => response?.status), [503, 503]);
  assert.equal(r.arrivals(), 2);
  assert.equal(r.usage()?.shared, 2);
  assert.equal(r.usage()?.ambiguous, 2);
  assert.equal(r.usage()?.queued, 0);
  assert.equal(r.usage()?.preparationSlots, 0);
});

test("close-delimited responses are relayed but transport EOF alone leaves the charge held", testOptions, async (t) => {
  const r = await rig(t, (_req, res) => {
    res.useChunkedEncodingByDefault = false;
    res.setHeader("connection", "close");
    res.write("close-delimited");
    res.end();
  });
  assert.deepEqual(await r.signed().response, { status: 200, body: "close-delimited" });
  assert.equal(r.usage()?.leases, 1);
  assert.equal(r.usage()?.ambiguous, 1);
  assert.equal(r.boundary.stats().forwardResponded, 1);
});

test("shutdown drains started work after downstream close and retains charges that hit the forward deadline", testOptions, async (t) => {
  const firstArrival = Promise.withResolvers<http.ServerResponse>();
  const secondArrival = Promise.withResolvers<void>();
  let first = true;
  const r = await rig(t, (_req, res) => {
    if (first) { first = false; firstArrival.resolve(res); }
    else secondArrival.resolve();
  });
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const firstClient = r.signed();
  const originResponse = await firstArrival.promise;
  const secondClient = r.signed();
  await secondArrival.promise;
  const clients = Promise.allSettled([firstClient.response, secondClient.response]);
  const firstAbort = r.nextAbort();
  const closed = r.boundary.close();
  assert.equal(r.boundary.close(), closed);
  assert.equal(r.boundary.stats().capacity?.state, "unavailable");
  await assert.rejects(r.boundary.listen(), /closed/);
  t.mock.timers.tick(1_000);
  await clients;
  assert.equal(r.usage()?.leases, 2);
  complete(originResponse, "finished after downstream closed");
  await firstAbort;
  assert.equal(r.usage()?.leases, 1);
  assert.equal(r.usage()?.ambiguous, 0);
  t.mock.timers.tick(4_000);
  await closed;
  assert.equal(r.usage()?.closed, true);
  assert.equal(r.usage()?.shared, 1);
  assert.equal(r.usage()?.ambiguous, 1);
  assert.equal(r.boundary.stats().forwardResponded, 1);
  assert.equal(r.boundary.stats().forwardFailed, 1);
});

test("closing during startup prevents the boundary from publishing or reopening its listener", testOptions, async (t) => {
  const r = await rig(t, (_req, res) => res.end());
  await r.boundary.close();
  const starting = createBoundary(r.options);
  const listening = starting.listen();
  const closing = starting.close();
  await assert.rejects(listening, /closed/);
  await closing;
  await assert.rejects(starting.listen(), /closed/);
  assert.equal(starting.stats().capacity?.usage?.closed, true);
});

test("a request that loses its proof budget before the first write releases without reaching the origin", testOptions, async (t) => {
  let delay = true;
  const r = await rig(t, (_req, res) => complete(res, "ok"), { onEvent: (event) => {
    if (event.kind === "BOUNDARY_FORWARDED" && delay) {
      r.clock.now += 1_500;
      r.clock.mono += 1_500;
      delay = false;
    }
  } });
  assert.equal((await r.signed().response)?.status, 503);
  assert.equal(r.arrivals(), 0);
  assert.equal(r.usage()?.leases, 0);
  assert.equal(r.usage()?.ambiguous, 0);
  assert.equal((await r.signed().response)?.status, 200);
  assert.equal(r.arrivals(), 1);
  assert.equal(r.usage()?.leases, 0);
});

test("a rolled-back wall clock cannot extend M2's cutoff between grant and first write", testOptions, async (t) => {
  let delayed = false;
  let grants = 0;
  const r = await rig(t, (_req, res) => complete(res), { onEvent(event) {
    if (event.kind !== "BOUNDARY_FORWARDED" || !delayed) return;
    grants += r.usage()?.leases ?? 0;
    r.clock.mono += 60;
  } });
  const original = r.clock.now;
  r.clock.now += 3_850;
  assert.equal((await r.signed().response)?.status, 200);
  r.clock.now = original;
  delayed = true;
  assert.equal((await r.signed().response)?.status, 503);
  assert.equal(grants, 1);
  assert.equal(r.arrivals(), 1);
  assert.equal(r.usage()?.leases, 0);
  assert.equal(r.usage()?.ambiguous, 0);
});

test("a guarded synthetic app signs terminal evidence after the actual handler settles", testOptions, async (t) => {
  const r = await rig(t, (_req, res) => complete(res));
  const ownerKey = randomBytes(32);
  const keys = generateKeyPairSync("ed25519");
  const scope = r.options.capacity!.backendRef;
  const fence = createExecutionFence({ ownerKey, originKey: keys.privateKey, scope, maxExecutions: 2 });
  let fail = false;
  const { keyP, kidP, keyB, kidB, appId, boundaryId, now } = r.options;
  const app = createAppGuard({ keyP, kidP, keyB: createPublicKey(keyB), kidB, appId, boundaryId, now, replayCapacity: 64, bodyDeadlineMs: 2_000 });
  const origin = createSyntheticOrigin({ instance: "protected", executionFence: fence, guard: app.guard, onObservation: () => undefined,
    onApp: (event) => { if (fail && event.kind === "APP_EXECUTED") throw new Error("test origin failure"); } });
  t.after(() => origin.close());
  const appPort = await origin.listen();
  const priorOrigin = createBoundaryExecution({ originKey: keys.publicKey,
    generation: provisionExecutionGeneration(ownerKey, { scope, epoch: 1, originInstance: randomUUID() }) }, scope, appPort, 5_000);
  assert.equal(await priorOrigin.reconcile(), false);
  const boundary = createBoundary({ ...r.options, appPort, capacity: { ...r.options.capacity!, execution: {
    originKey: keys.publicKey, generation: provisionExecutionGeneration(ownerKey, { scope, epoch: 1, originInstance: fence.originInstance }),
  } } });
  t.after(() => boundary.close());
  const port = await boundary.listen();
  r.clock.now++;
  const send = () => r.signed("GET", "/gizlilik", undefined, authority, port).response;
  assert.equal((await send())?.status, 503);
  assert.equal(await boundary.reconcile(), true);
  assert.match((await send())?.body ?? "", /Gizlilik/);
  assert.equal(boundary.stats().capacity?.usage?.leases, 0);
  fail = true;
  assert.equal((await send())?.status, 500);
  assert.equal(boundary.stats().capacity?.usage?.leases, 0);
  assert.equal(origin.appStats().executed, 2);
  for (let i = 0; i < 3; i++) {
    assert.equal((await send())?.status, 503);
    assert.equal(boundary.stats().capacity?.usage?.leases, 0);
    assert.equal(boundary.stats().capacity?.usage?.ambiguous, 0);
  }
  assert.equal(origin.appStats().executed, 2);
});

test("replacement reconciliation fences late old work and waits for outstanding work after Boundary shutdown", testOptions, async (t) => {
  const arrived = Promise.withResolvers<http.ServerResponse>();
  let hold = true;
  const r = await rig(t, (_req, res) => { if (hold) arrived.resolve(res); else complete(res, "new"); });
  const replacement = createBoundary({ ...r.options, capacity: { ...r.options.capacity!, execution: r.generation(2) } });
  t.after(() => replacement.close());
  const port = await replacement.listen();
  r.clock.now++;
  const send = () => r.signed("GET", "/gizlilik", undefined, authority, port).response;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const old = r.signed();
  const oldResult = Promise.allSettled([old.response]);
  const outstanding = await arrived.promise;

  assert.equal(await replacement.reconcile(), false);
  assert.equal((await send())?.status, 503);
  assert.equal((await r.signed().response)?.status, 503);
  assert.equal(r.arrivals(), 1);
  const closing = r.boundary.close();
  await Promise.resolve();
  t.mock.timers.tick(5_000);
  await oldResult;
  await closing;
  assert.equal(await replacement.reconcile(), false);

  terminals.get(outstanding)!(); // Origin-owned work completes after the old Boundary has shut down.
  hold = false;
  assert.equal(await replacement.reconcile(), true);
  assert.deepEqual(await send(), { status: 200, body: "new" });
  assert.equal(replacement.stats().capacity?.usage?.leases, 0);

  const competing = createBoundaryExecution(r.generation(2), r.options.capacity!.backendRef, r.options.appPort, 5_000);
  assert.equal(await competing.reconcile(), false); // Reusing the ticket cannot reset accounting with a fresh session.
  const stale = createBoundaryExecution(r.generation(1), r.options.capacity!.backendRef, r.options.appPort, 5_000);
  assert.equal(await stale.reconcile(), false);
});

test("the origin rejects duplicate execution IDs and binds each acknowledgment to the exact request", testOptions, async (t) => {
  const r = await rig(t, (_req, res) => complete(res));
  const client = createBoundaryExecution(r.generation(2), r.options.capacity!.backendRef, r.options.appPort, 5_000);
  const wire = client.request("ba-one");
  assert.equal(r.fence.accept(wire.header, "ba-one"), undefined);
  assert.equal(await client.reconcile(), true);
  assert.equal(r.fence.accept(wire.header, "ba-two"), undefined);
  const accepted = r.fence.accept(wire.header, "ba-one");
  assert.ok(accepted);
  assert.equal(accepted.start(), true);
  assert.equal(r.fence.refusedAfterGuard(wire.header, "ba-one"), undefined);
  assert.equal(accepted.start(), false);
  assert.equal(r.fence.accept(wire.header, "ba-one"), undefined);
  const proof = accepted.finish();
  assert.equal(accepted.finish(), proof);
  assert.equal(wire.terminal(proof), true);
  assert.equal(client.request("ba-one").terminal(proof), false);
  assert.equal(r.fence.accept(wire.header, "ba-one"), undefined);
  const delayed = client.request("ba-delayed");
  const pending = r.fence.accept(delayed.header, "ba-delayed");
  assert.ok(pending);
  const successor = createBoundaryExecution(r.generation(3), r.options.capacity!.backendRef, r.options.appPort, 5_000);
  assert.equal(await successor.reconcile(), false);
  const early = successor.request("early");
  const earlyProof = r.fence.refusedAfterGuard(early.header, "early");
  assert.equal(early.evidence(earlyProof), "never-started");
  assert.equal(successor.request("early").evidence(earlyProof), undefined);
  const stale = client.request("stale");
  assert.equal(stale.evidence(r.fence.refusedAfterGuard(stale.header, "stale")), "never-started");
  assert.equal(r.fence.refusedAfterGuard(stale.header, "other"), undefined);
  assert.equal(pending.start(), false);
  assert.equal(delayed.terminal(pending.finish()), true);
  assert.equal(await successor.reconcile(), true);
  assert.equal(r.fence.accept(early.header, "early"), undefined);
});

test("HTTP success with missing, malformed or unauthenticated terminal evidence retains capacity", testOptions, async (t) => {
  for (const signature of [undefined, "malformed", randomBytes(64).toString("base64url")]) {
    const r = await rig(t, (_req, res) => {
      if (signature) res.setHeader(TERMINAL_HEADER, signature);
      res.end("ok");
    });
    assert.deepEqual(await r.signed().response, { status: 200, body: "ok" });
    assert.equal(r.usage()?.ambiguous, 1);
    assert.equal(r.usage()?.leases, 1);
  }
});
