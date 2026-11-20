import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { getEventListeners } from "node:events";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import v8 from "node:v8";
import vm from "node:vm";
import { createOriginCapacityBoundary } from "../defense/core/capacity-boundary";
import { createOriginCapacityState } from "../defense/core/origin-capacity";
import {
  activateCustomerOriginPolicy,
  classifyVerifiedCandidate,
  PolicyValidationError,
  validateCustomerOriginPolicyManifest,
} from "../defense/core/capacity-policy";
import type {
  AuthenticatedRequestData,
  CapacityLease,
  CompiledCustomerOriginPolicy,
  CustomerOriginPolicyManifest,
  AttemptStatus, CapacityAttempt, CapacityExecutionEvidence, CapacityExecutionIdentity,
  CapacitySettlementEvent, VerificationBody,
  OriginRequestVerifier,
  PolicyActivationRecord,
  VerifiedRequestFacts,
} from "../defense/core/capacity-port";

const FIXTURES = path.join(__dirname, "fixtures", "customer-origin-v1");
const ba0Bytes = readFileSync(path.join(FIXTURES, "ba0.json"));
const storefrontBytes = readFileSync(path.join(FIXTURES, "storefront.json"));

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function activationForBytes(bytes: Uint8Array): PolicyActivationRecord {
  const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as CustomerOriginPolicyManifest;
  return {
    tenantId: parsed.tenantId,
    deploymentId: parsed.deploymentId,
    domainId: parsed.domain.id,
    revision: parsed.revision,
    expectedDigest: sha256Hex(bytes),
  };
}

const ba0Policy = activateCustomerOriginPolicy(ba0Bytes, activationForBytes(ba0Bytes));
const storefrontPolicy = activateCustomerOriginPolicy(storefrontBytes, activationForBytes(storefrontBytes));

// The source adapter belongs to M3. It must order native cancellation before
// maintenance and dispatch, isolate signal inspection and registration, and
// detach listeners on every terminal path, including a partial registration
// that throws. It must bound notifications without retaining raw candidates.
// Integration also owns wake scheduling, dispatch-time freshness and start
// fencing, and authenticated execution and termination across restart or policy
// replacement. The tests here exercise the M2 capabilities those paths use.

type TestCandidate = { readonly tag: string };

class SyntheticTestVerifier implements OriginRequestVerifier<unknown> {
  private readonly issued = new WeakMap<object, AuthenticatedRequestData>();
  private seq = 1;

  issue(facts: VerifiedRequestFacts, proofExpiresAtWallMs: number): TestCandidate {
    const candidate: TestCandidate = Object.freeze({ tag: `cand-${this.seq++}` });
    this.issued.set(candidate, Object.freeze({ ...facts, proofExpiresAtWallMs }));
    return candidate;
  }

  /** Test seam to simulate a verifier returning extra caller-controlled fields alongside authenticated data. */
  issueWithExtraFields(
    facts: VerifiedRequestFacts,
    proofExpiresAtWallMs: number,
    extras: Record<string, unknown>,
  ): TestCandidate {
    const candidate: TestCandidate = Object.freeze({ tag: `cand-${this.seq++}` });
    this.issued.set(candidate, Object.freeze({ ...facts, proofExpiresAtWallMs, ...extras }) as AuthenticatedRequestData);
    return candidate;
  }

  verify(candidate: unknown): { readonly ok: true; readonly authenticated: AuthenticatedRequestData } | { readonly ok: false; readonly reason: "unverified" } {
    if (typeof candidate !== "object" || candidate === null) return { ok: false, reason: "unverified" };
    const authenticated = this.issued.get(candidate);
    if (authenticated === undefined) return { ok: false, reason: "unverified" };
    return { ok: true, authenticated };
  }
}

function makeFacts(
  policy: CompiledCustomerOriginPolicy,
  channelId: string,
  method: string,
  target: string,
  overrides: Partial<VerifiedRequestFacts> = {},
): VerifiedRequestFacts {
  const p = policy.manifest;
  const channel = p.channels.find((c) => c.id === channelId);
  assert.ok(channel, `unknown fixture channel ${channelId}`);
  return {
    tenantId: p.tenantId,
    deploymentId: p.deploymentId,
    domainId: p.domain.id,
    digest: policy.digest,
    principal: channel.principal,
    audience: channel.audience,
    scheme: channel.scheme,
    authority: channel.authority,
    method,
    target,
    mediaType: null,
    bodyBytes: 0,
    origin: null,
    ...overrides,
  };
}

type DeepMutable<T> = T extends readonly (infer U)[]
  ? DeepMutable<U>[]
  : T extends object
    ? { -readonly [K in keyof T]: DeepMutable<T[K]> }
    : T;
type MutableManifest = DeepMutable<CustomerOriginPolicyManifest> & Record<string, unknown>;

function cloneManifest(policy: CompiledCustomerOriginPolicy): MutableManifest {
  return JSON.parse(JSON.stringify(policy.manifest)) as MutableManifest;
}

function editStorefront(edit: (m: MutableManifest) => void): MutableManifest {
  const copy = cloneManifest(storefrontPolicy);
  edit(copy);
  return copy;
}

function activateFromEdited(manifest: MutableManifest): CompiledCustomerOriginPolicy {
  const bytes = Buffer.from(JSON.stringify(manifest), "utf8");
  return activateCustomerOriginPolicy(bytes, {
    tenantId: manifest.tenantId,
    deploymentId: manifest.deploymentId,
    domainId: manifest.domain.id,
    revision: manifest.revision,
    expectedDigest: sha256Hex(bytes),
  });
}

const ba0PostFacts: Partial<VerifiedRequestFacts> = {
  mediaType: "application/x-www-form-urlencoded",
  bodyBytes: 1024,
  origin: "http://127.0.0.1:18080",
};
const orderFacts: Partial<VerifiedRequestFacts> = {
  mediaType: "application/json",
  bodyBytes: 2048,
  origin: "https://shop.example.test",
};
const stockFacts: Partial<VerifiedRequestFacts> = {
  mediaType: "application/json",
  bodyBytes: 512,
  origin: null,
};


test("Finding 1: policy activation derives digest from immutable bytes and verifies trusted activation record", () => {
  assert.equal(ba0Policy.digest, sha256Hex(ba0Bytes));
  assert.equal(storefrontPolicy.digest, sha256Hex(storefrontBytes));
  assert.equal(ba0Policy.sharedUnits, 8);
  assert.equal(storefrontPolicy.sharedUnits, 7);

  const act = activationForBytes(storefrontBytes);
  // Digest mismatch against activation record fails closed.
  assert.throws(
    () => activateCustomerOriginPolicy(storefrontBytes, { ...act, expectedDigest: "0".repeat(64) }),
    /policy digest mismatch/,
  );
  // Scope or revision mismatch against activation record fails closed even when digest matches bytes.
  assert.throws(() => activateCustomerOriginPolicy(storefrontBytes, { ...act, tenantId: "other-tenant" }), /scope or revision mismatch/);
  assert.throws(() => activateCustomerOriginPolicy(storefrontBytes, { ...act, deploymentId: "other-deploy" }), /scope or revision mismatch/);
  assert.throws(() => activateCustomerOriginPolicy(storefrontBytes, { ...act, domainId: "other-domain" }), /scope or revision mismatch/);
  assert.throws(() => activateCustomerOriginPolicy(storefrontBytes, { ...act, revision: 2 }), /scope or revision mismatch/);

  // Whitespace change produces a distinct byte digest and cannot match the original activation record.
  const padded = Buffer.concat([ba0Bytes, Buffer.from(" ")]);
  assert.throws(() => activateCustomerOriginPolicy(padded, activationForBytes(ba0Bytes)), /policy digest mismatch/);
  const paddedPolicy = activateCustomerOriginPolicy(padded, activationForBytes(padded));
  assert.notEqual(paddedPolicy.digest, ba0Policy.digest);

  // Mutating the caller's input buffer after activation has zero effect on the compiled policy.
  const mutableCopy = Uint8Array.from(ba0Bytes);
  const activated = activateCustomerOriginPolicy(mutableCopy, activationForBytes(ba0Bytes));
  mutableCopy.fill(0);
  assert.equal(activated.digest, ba0Policy.digest);

  // All consumers require the activated capability, even for equal public fields.
  const verifier = new SyntheticTestVerifier();
  for (const forged of [{ ...storefrontPolicy }, Object.create(storefrontPolicy) as CompiledCustomerOriginPolicy]) {
    assert.throws(() => createOriginCapacityState(forged), PolicyValidationError);
    assert.throws(() => setup(forged, verifier), PolicyValidationError);
    assert.throws(() => classifyVerifiedCandidate(forged, verifier, null, 1_000), PolicyValidationError);
  }
});

test("policy decoder rejects oversize bytes, invalid UTF-8, invalid JSON, duplicate members and invalid manifests", () => {
  const act = activationForBytes(storefrontBytes);
  assert.throws(() => activateCustomerOriginPolicy(Buffer.alloc(262_145), act), PolicyValidationError);
  const badUtf8 = Buffer.from([0xff, 0xfe]);
  assert.throws(() => activateCustomerOriginPolicy(badUtf8, { ...act, expectedDigest: sha256Hex(badUtf8) }), /UTF-8/);
  const badJson = Buffer.from("{not-json");
  assert.throws(() => activateCustomerOriginPolicy(badJson, { ...act, expectedDigest: sha256Hex(badJson) }), /JSON/);

  const raw = JSON.stringify(storefrontPolicy.manifest);
  for (const mutated of [
    raw.replace('"revision":1', '"revision":1,"revision":1'),
    raw.replace('"revision":1', '"revision":2,"\\u0072evision":1'),
  ]) {
    const buf = Buffer.from(mutated, "utf8");
    assert.throws(() => activateCustomerOriginPolicy(buf, { ...act, expectedDigest: sha256Hex(buf) }), /duplicate JSON member/);
  }

  const badVariants: [string, (m: MutableManifest) => void, RegExp][] = [
    ["unknown version", (m) => { (m as Record<string, unknown>).version = "customer-origin-policy-v2"; }, /unsupported version/],
    ["unknown requestProfile", (m) => { (m as Record<string, unknown>).requestProfile = "streaming"; }, /requestProfile/],
    ["permissive unsupported mode", (m) => { (m as Record<string, unknown>).unsupported = "pass"; }, /unsupported policy/],
    ["extra top-level field", (m) => { m.extra = true; }, /unknown member/],
    ["multiple instances", (m) => { (m.domain as Record<string, unknown>).instances = 2; }, /instances/],
    ["extra domain field", (m) => { (m.domain as Record<string, unknown>).dynamicUpstream = true; }, /unknown member/],
    ["duplicate channel binding", (m) => { m.channels.push({ ...m.channels[0], id: "dup-bind" }); }, /duplicate channel binding/],
    ["reused operational principal", (m) => { m.channels[1].principal = m.channels[0].principal; }, /operational principal reuse/],
    ["reused operational audience", (m) => { m.channels[1].audience = m.channels[0].audience; }, /operational audience reuse/],
    ["overcommitted reservations", (m) => { m.capacity.activeUnits = 8; }, /overcommitted reservations/],
    ["class ceiling below floor", (m) => { m.classes[2].maxActiveUnits = 2; }, /invalid class ceiling/],
    ["class ceiling invades another floor", (m) => { m.classes[0].maxActiveUnits = 8; }, /invalid class ceiling/],
    ["per-class queue above domain queue", (m) => { m.classes[0].maxQueued = 11; }, /invalid class queue/],
    ["wait without queue", (m) => { m.classes[1].maxWaitMs = 1; }, /invalid class queue/],
    ["queue without wait", (m) => { m.classes[0].maxWaitMs = 0; }, /invalid class queue/],
    ["queue count/bytes disagree", (m) => { m.capacity.maxQueuedBytes = 0; }, /queue count\/bytes/],
    ["queue metadata cannot fit", (m) => { m.capacity.maxQueuedBytes = 512; }, /queue metadata cannot fit/],
    ["wait exceeds proof budget", (m) => { m.capacity.proofWindowMs = 350; }, /wait exceeds proof budget/],
    ["wait exceeds caller budget", (m) => { m.capacity.callerBudgetMs = 2349; }, /wait exceeds caller budget/],
    ["public channel mapped to operational class", (m) => { m.operations[4].channel = "shopper"; }, /channel lacks class access/],
    ["cost above reserved floor", (m) => { m.operations[3].costUnits = 5; }, /cost cannot fit/],
    ["cost above ceiling", (m) => { m.operations[0].costUnits = 6; }, /cost cannot fit/],
    ["read with body", (m) => { m.operations[0].body = m.operations[3].body; }, /read body unsupported/],
    ["method/effect mismatch", (m) => { m.operations[0].effect = "write"; }, /method\/effect mismatch/],
    ["body exceeds domain limit", (m) => { m.capacity.maxBodyBytes = 1024; }, /body exceeds domain/],
    ["wildcard path rejected", (m) => { m.operations[0].path = "/products/*"; }, /path invalid/],
    ["duplicate template parameter", (m) => { m.operations[0].path = "/products/:sku/:sku"; }, /duplicate parameter/],
    ["overlapping route templates", (m) => {
      m.operations.push({ ...m.operations[0], id: "overlap", path: "/products/special" });
    }, /overlapping operations/],
    ["uncovered operation", (m) => { m.journeys.pop(); }, /operation missing from journeys/],
    ["non-finite activeUnits", (m) => { m.capacity.activeUnits = Number.POSITIVE_INFINITY; }, /activeUnits/],
    ["fractional maxQueued", (m) => { m.classes[0].maxQueued = 1.5; }, /maxQueued/],
  ];
  for (const [name, edit, pattern] of badVariants) {
    assert.throws(() => validateCustomerOriginPolicyManifest(editStorefront(edit)), pattern, name);
  }
});

function setup(policy = ba0Policy, verifier: OriginRequestVerifier = new SyntheticTestVerifier()) {
  let mono = 0;
  let wall = 1000;
  let samples = 0;
  let clockHook: (() => void) | undefined;
  let verifyHook: ((body: VerificationBody) => void) | undefined;
  let evidenceHook: (() => void) | undefined;
  const proofs = new WeakMap<object, CapacityExecutionEvidence>();
  const boundary = createOriginCapacityBoundary(policy, {
    monotonicMs: () => mono,
    wallUpperMs() {
      samples++;
      clockHook?.();
      return wall;
    },
  }, {
    verify(candidate, activated, now, body) {
      assert.equal(activated, policy);
      assert.ok(body);
      verifyHook?.(body);
      return verifier.verify(candidate, activated, now, body);
    },
  }, {
    verify(_identity, proof: object) {
      evidenceHook?.();
      return proofs.get(proof) ?? null;
    },
  });
  function submit(candidate: unknown, body?: Uint8Array, callerDeadlineMonoMs?: number) {
    const attempt = boundary.request.begin();
    assert.ok(attempt);
    return { attempt, status: boundary.request.submit(attempt, { candidate, body, callerDeadlineMonoMs }) };
  }
  function attest(evidence: CapacityExecutionEvidence) {
    const proof = Object.freeze({});
    proofs.set(proof, evidence);
    return proof;
  }
  function event(lease: CapacityLease, kind: CapacityExecutionEvidence["kind"], hardStopMonoMs?: number) {
    const identity = boundary.execution.identity(lease);
    assert.ok(identity);
    const evidence: CapacityExecutionEvidence = kind === "ambiguous"
      ? { ...identity, kind, hardStopMonoMs } : { ...identity, kind };
    return boundary.execution.verify(lease, identity.execution, attest(evidence));
  }
  function settle(lease: CapacityLease, kind: CapacityExecutionEvidence["kind"] = "completed", hardStopMonoMs?: number) {
    const verified = event(lease, kind, hardStopMonoMs);
    assert.ok(verified);
    assert.equal(boundary.execution.settle(verified), true);
    return verified;
  }
  return {
    ...boundary, submit, attest, event, settle, samples: () => samples,
    time(next: number, wallUpper = 1000 + next) { mono = next; wall = wallUpper; },
    onClock(hook?: () => void) { clockHook = hook; },
    onVerify(hook?: (body: VerificationBody) => void) { verifyHook = hook; },
    onEvidence(hook?: () => void) { evidenceHook = hook; },
  };
}

function fixture(policy = ba0Policy) {
  const verifier = new SyntheticTestVerifier();
  const boundary = setup(policy, verifier);
  const send = (
    target: string, {
      channel = policy.manifest.channels[0].id, method = "GET", facts = {}, proof = 4500, deadline,
    }: {
      channel?: string; method?: string; facts?: Partial<VerifiedRequestFacts>; proof?: number; deadline?: number;
    } = {},
  ) => {
    const data = makeFacts(policy, channel, method, target, facts);
    return boundary.submit(verifier.issue(data, proof), data.bodyBytes ? new Uint8Array(data.bodyBytes) : undefined, deadline);
  };
  return { ...boundary, send };
}

type BoundaryFixture = ReturnType<typeof fixture>;

function granted(status: AttemptStatus | undefined, pool?: "reserved" | "shared") {
  assert.ok(status?.kind === "granted", JSON.stringify(status));
  if (pool !== undefined) assert.equal(status.pool, pool);
  return status.lease;
}

function queued(result: { attempt: CapacityAttempt; status?: AttemptStatus }, bytes?: number) {
  assert.ok(result.status?.kind === "queued", JSON.stringify(result.status));
  if (bytes !== undefined) assert.equal(result.status.bytes, bytes);
  return result.attempt;
}

function drain(s: Pick<BoundaryFixture, "maintenance" | "request" | "samples">, budget = 1) {
  for (let step = 0; step < 256; step++) {
    const before = s.samples();
    const work = s.maintenance.advance(budget);
    assert.ok(work <= budget);
    assert.ok(s.samples() - before <= Math.min(work + 1, budget));
    if (!s.request.hasPendingMaintenance()) return;
    assert.ok(work > 0);
  }
  assert.fail("maintenance did not converge within 256 calls");
}

const rejection = (reason: string) => ({ kind: "rejected", reason });
const expiration = (reason: string) => ({ kind: "expired", reason });
const cancelled = (reason = "cancelled") => ({ kind: "cancelled", reason });
const inquiry = { method: "POST", facts: ba0PostFacts };
const order = { method: "POST", facts: orderFacts };
const stock = { channel: "warehouse", method: "PATCH", facts: stockFacts };

test("raw facts, cloned or foreign verifier tokens, and verifier throws have no admission authority", () => {
  const verifier = new SyntheticTestVerifier();
  const s = setup(storefrontPolicy, verifier);
  const proof = 4000;
  const browse = makeFacts(storefrontPolicy, "shopper", "GET", "/products/lamp-7");
  const valid = verifier.issue(browse, proof);
  const foreign = new SyntheticTestVerifier().issue(browse, proof);
  const forged = {
    ...makeFacts(storefrontPolicy, "warehouse", "PATCH", "/inventory/lamp-7", stockFacts),
    proofExpiresAtWallMs: proof,
  };
  for (const candidate of [forged, null, foreign, { ...valid }]) {
    assert.deepEqual(s.submit(candidate).status, rejection("unverified"));
  }
  const throwing = setup(storefrontPolicy, { verify() { throw Error("verification failed"); } });
  assert.deepEqual(throwing.submit(valid).status, rejection("unverified"));
  assert.equal(throwing.request.snapshot().preparationSlots, 0);
  const extra = { candidate: verifier.issue(browse, 1100), proofExpiresAtWallMs: 999_999 };
  const attempt = s.request.begin()!;
  assert.deepEqual(s.request.submit(attempt, extra), expiration("proof-expired"));
  assert.equal(s.request.snapshot().leases, 0);
  assert.equal(s.request.snapshot().queued, 0);
  granted(s.submit(valid).status, "shared");
});

test("authenticated scope, channel, method, target and body fields keep their exact rejection reasons", () => {
  const s = fixture(storefrontPolicy);
  for (const field of ["tenantId", "deploymentId", "domainId", "digest"] as const) {
    assert.deepEqual(s.send("/checkout/cart-7", { facts: { [field]: "wrong" } }).status, rejection("scope-mismatch"), field);
  }
  for (const field of ["principal", "audience", "scheme", "authority"] as const) {
    assert.deepEqual(s.send("/checkout/cart-7", { facts: { [field]: "wrong" } }).status, rejection("untrusted-channel"), field);
  }
  const foreign = makeFacts(ba0Policy, "visitor", "GET", "/");
  assert.deepEqual(s.send("/products/lamp-7", { facts: foreign }).status, rejection("scope-mismatch"));
  for (const classification of [
    s.send("/products/.."), s.send("/products/%2f"), s.send("/products/lamp-7", { method: "HEAD" }),
    s.send("/orders", { ...order, facts: { ...orderFacts, bodyBytes: 8193 } }),
    s.send("/orders", { ...order, facts: { ...orderFacts, origin: "https://evil.example.test" } }),
    s.send("/orders", { ...order, facts: { ...orderFacts, mediaType: "text/plain" } }),
  ]) assert.deepEqual(classification.status, rejection("unsupported"));
  assert.equal(s.request.snapshot().leases, 0);
  assert.equal(s.request.snapshot().queued, 0);
});

test("public facts and caller-controlled priority claims never allocate operational capacity", () => {
  const verifier = new SyntheticTestVerifier();
  const s = setup(storefrontPolicy, verifier);
  const patch = makeFacts(storefrontPolicy, "shopper", "PATCH", "/inventory/lamp-7", stockFacts);
  const extras = { channel: "warehouse", classId: "inventory", access: "operational", priority: "operational" };
  assert.deepEqual(s.submit(verifier.issueWithExtraFields(patch, 4000, extras), new Uint8Array(512)).status, rejection("unsupported"));
  for (const facts of [{ ...patch, audience: "shop-operations" }, { ...patch, principal: "stock-service" }]) {
    assert.deepEqual(s.submit(verifier.issue(facts, 4000), new Uint8Array(512)).status, rejection("untrusted-channel"));
  }
  const candidate = verifier.issueWithExtraFields(makeFacts(storefrontPolicy, "shopper", "GET", "/products/lamp-7"), 4000, extras);
  const classification = classifyVerifiedCandidate(storefrontPolicy, verifier, candidate, 1000);
  assert.ok(classification.kind === "classified");
  assert.equal(classification.classId, "browse");
  assert.equal(classification.access, "public");
  const lease = granted(s.submit(candidate).status, "shared");
  assert.equal(s.request.snapshot().classes.find(({ id }) => id === "inventory")?.reserved, 0);
  s.settle(lease);
});

test("frozen lease identities and one-use settlement events reject forgery, foreign evidence and invalid kinds", () => {
  const s = fixture();
  const foreign = fixture();
  const lease = granted(s.send("/api/public-inquiries", inquiry).status, "reserved");
  const peer = granted(s.send("/api/public-inquiries", inquiry).status, "shared");
  const foreignLease = granted(foreign.send("/").status);
  const identity = s.execution.identity(lease)!;
  const other = s.execution.identity(peer)!;
  const outside = foreign.execution.identity(foreignLease)!;
  const completed = (subject: CapacityExecutionIdentity) => ({ ...subject, kind: "completed" as const });
  assert.deepEqual(Object.keys(s.request).sort(), [
    "attemptStatus", "begin", "cancel", "hasPendingMaintenance", "leaseState", "snapshot", "submit",
  ]);
  assert.ok(Object.isFrozen(lease));
  assert.ok(Object.isFrozen(identity));
  assert.deepEqual(Reflect.ownKeys(lease), []);
  assert.equal(Reflect.set(lease, "costUnits", 999), false);
  assert.equal(Reflect.set(lease, "state", "active"), false);
  const before = s.request.snapshot();
  for (const invalid of [foreignLease, { ...lease } as CapacityLease, Object.create(lease) as CapacityLease]) {
    assert.equal(s.request.leaseState(invalid), undefined);
    assert.equal(s.execution.identity(invalid), undefined);
    assert.equal(s.execution.verify(invalid, identity.execution, s.attest(completed(identity))), undefined);
  }
  for (const evidence of [
    completed({ ...identity, generation: outside.generation }),
    completed({ ...identity, lease: other.lease }),
    completed({ ...identity, execution: other.execution }),
    ...["bogus", "", "__proto__", "constructor", "ambiguous-confirmed", 123, null].map(
      (kind) => ({ ...identity, kind }) as CapacityExecutionEvidence,
    ),
  ]) {
    assert.equal(s.execution.verify(lease, identity.execution, s.attest(evidence)), undefined);
  }
  const proof = s.attest(completed(identity));
  assert.equal(s.execution.verify(lease, identity.execution, { ...proof }), undefined);
  assert.equal(s.execution.verify(lease, identity.execution, foreign.attest(completed(identity))), undefined);
  assert.equal(s.execution.verify(lease, other.execution, proof), undefined);
  assert.equal(s.execution.settle({} as CapacitySettlementEvent), false);
  assert.deepEqual(s.request.snapshot(), before);
  const event = s.execution.verify(lease, identity.execution, proof)!;
  assert.ok(Object.isFrozen(event));
  assert.equal(foreign.execution.settle(event), false);
  assert.equal(s.execution.settle(Object.create(event) as CapacitySettlementEvent), false);
  assert.equal(s.execution.settle(event), true);
  assert.equal(s.execution.settle(event), false);
  assert.equal(s.request.leaseState(lease), "settled");
  assert.equal(s.request.snapshot().leases, 1);
  s.settle(peer);
  foreign.settle(foreignLease);
  assert.equal(s.request.snapshot().leases, 0);
});

test("ambiguous occupancy survives arbitrary time and clears only on execution-specific evidence or an attested bound", () => {
  const s = fixture();
  const lease = granted(s.send("/api/public-inquiries", inquiry).status);
  const peer = granted(s.send("/api/public-inquiries", inquiry).status);
  const identity = s.execution.identity(lease)!;
  const old = s.event(lease, "completed")!;
  s.settle(lease, "ambiguous");
  assert.equal(s.execution.settle(old), false);
  assert.equal(s.event(lease, "ambiguous"), undefined);
  assert.equal(s.execution.verify(lease, identity.execution, {}), undefined);
  const wrong = s.attest({ ...s.execution.identity(peer)!, kind: "timeout-confirmed" });
  assert.equal(s.execution.verify(lease, identity.execution, wrong), undefined);
  s.time(50_000);
  drain(s);
  assert.equal(s.request.leaseState(lease), "ambiguous-held");
  assert.equal(s.request.snapshot().ambiguous, 2);
  assert.equal(s.request.snapshot().reserved + s.request.snapshot().shared, 4);
  const termination = s.settle(lease, "timeout-confirmed");
  assert.equal(s.execution.settle(termination), false);
  assert.equal(s.request.snapshot().ambiguous, 0);
  assert.equal(s.request.snapshot().leases, 1);

  const bounded = fixture();
  const running = granted(bounded.send("/api/public-inquiries", inquiry).status);
  assert.equal(bounded.event(running, "ambiguous", NaN), undefined);
  bounded.settle(running, "ambiguous", 2500);
  bounded.time(2499.5);
  drain(bounded);
  assert.equal(bounded.request.leaseState(running), "ambiguous-held");
  bounded.time(2500);
  drain(bounded);
  assert.equal(bounded.request.leaseState(running), "settled");
  assert.equal(bounded.request.snapshot().leases, 0);
  assert.equal(bounded.request.snapshot().ambiguous, 0);
});

test("reentrant evidence verification cannot double-settle during an attested stop or a nested verification", () => {
  const s = fixture();
  const lease = granted(s.send("/").status);
  const other = granted(s.send("/").status);
  s.settle(lease, "ambiguous", 10);
  s.time(10);
  let invoked = 0;
  const nested: (CapacitySettlementEvent | undefined)[] = [];
  s.onEvidence(() => {
    invoked++;
    nested.push(s.event(lease, "completed"), s.event(other, "completed"));
    drain(s);
  });
  assert.equal(s.event(lease, "completed"), undefined);
  assert.equal(invoked, 1);
  assert.deepEqual([...nested], [undefined, undefined]);
  assert.equal(s.request.leaseState(lease), "settled");
  assert.equal(s.request.snapshot().shared, 1);
  assert.equal(s.request.snapshot().ambiguous, 0);
  s.onEvidence(() => {
    invoked++;
    nested.push(s.event(other, "completed"));
  });
  const event = s.settle(other);
  assert.equal(invoked, 2);
  assert.deepEqual(nested, [undefined, undefined, undefined]);
  assert.equal(s.execution.settle(event), false);
  assert.equal(s.request.snapshot().shared, 0);
  assert.equal(s.request.snapshot().leases, 0);
});

test("BA0 reservations stay isolated and exact byte charges survive rejection, cancellation and settlement", () => {
  const reservation = fixture();
  for (let i = 0; i < 4; i++) granted(reservation.send("/").status, "shared");
  for (let i = 0; i < 5; i++) granted(reservation.send("/test-talep-et").status, i < 2 ? "reserved" : "shared");
  granted(reservation.send("/api/public-inquiries", inquiry).status, "reserved");
  queued(reservation.send("/api/public-inquiries", inquiry));
  assert.equal(reservation.request.snapshot().shared, 7);
  assert.equal(reservation.request.snapshot().reserved, 4);

  const s = fixture();
  const active = Array.from({ length: 3 }, (_, i) =>
    granted(s.send("/api/public-inquiries", inquiry).status, i === 0 ? "reserved" : "shared"));
  const sendBytes = (bodyBytes: number) => s.send("/api/public-inquiries", {
    ...inquiry, facts: { ...ba0PostFacts, bodyBytes },
  });
  const first = queued(sendBytes(32768), 34816);
  assert.deepEqual(sendBytes(28673).status, rejection("queue-bytes-exceeded"));
  const second = queued(sendBytes(28672), 30720);
  assert.equal(s.request.snapshot().bytes, 65536);
  assert.deepEqual(s.maintenance.retention(), {
    preparingBodyBytes: 0, preparingBodyLimit: 65536, queued: 61440, leased: 3072, pendingNotifications: 0,
  });
  assert.equal(s.request.cancel(first), true);
  assert.equal(s.request.cancel(first), false);
  assert.equal(s.request.snapshot().bytes, 30720);
  assert.equal(s.request.cancel(second), true);
  for (const lease of active) s.settle(lease);
  assert.equal(s.request.snapshot().leases, 0);
  assert.equal(s.request.snapshot().bytes, 0);
  assert.equal(s.maintenance.retention().queued + s.maintenance.retention().leased, 0);
});

function fillStorefront(s: BoundaryFixture) {
  const browse = Array.from({ length: 5 }, () => granted(s.send("/products/a").status, "shared"));
  const asset = Array.from({ length: 2 }, () => granted(s.send("/assets/a").status, "shared"));
  assert.deepEqual(s.send("/assets/b").status, rejection("queue-disabled"));
  for (let i = 0; i < 3; i++) granted(s.send("/checkout/a").status, "reserved");
  for (let i = 0; i < 2; i++) granted(s.send("/orders", order).status, "reserved");
  granted(s.send("/inventory/a", stock).status, "reserved");
  assert.equal(s.request.snapshot().reserved, 9);
  assert.equal(s.request.snapshot().shared, 7);
  assert.equal(s.request.snapshot().leases, 13);
  return { browse, asset };
}

test("Storefront floors remain exclusive at shared saturation and weighted leases never split pools", () => {
  fillStorefront(fixture(storefrontPolicy));
  const policy = activateFromEdited(editStorefront((manifest) => {
    manifest.classes[3].reservedUnits = 3;
    manifest.classes[3].maxActiveUnits = 5;
  }));
  const s = fixture(policy);
  granted(s.send("/orders", order).status, "reserved");
  granted(s.send("/orders", order).status, "shared");
  const orders = s.request.snapshot().classes.find(({ id }) => id === "orders");
  assert.equal(orders?.reserved, 2);
  assert.equal(orders?.shared, 2);
});

test("shared grants rotate among eligible FIFO heads and skip heavier heads until they fit", () => {
  const s = fixture(storefrontPolicy);
  const { browse, asset } = fillStorefront(s);
  const b0 = queued(s.send("/products/b0"));
  const b1 = queued(s.send("/products/b1"));
  const c0 = queued(s.send("/checkout/c0"));
  const c1 = queued(s.send("/checkout/c1"));
  const o0 = queued(s.send("/orders", order));
  const i0 = queued(s.send("/inventory/b", stock));
  const rotation = [b0, c0, b1];
  for (const [index, head] of rotation.entries()) {
    s.settle(browse[index]);
    assert.equal(s.request.attemptStatus(head)?.kind, "queued");
    drain(s);
    granted(s.request.attemptStatus(head), "shared");
    for (const waiting of [...rotation.slice(index + 1), c1]) {
      assert.equal(s.request.attemptStatus(waiting)?.kind, "queued");
    }
  }
  assert.equal(s.request.cancel(c1), true);
  assert.deepEqual(s.request.attemptStatus(c1), cancelled());
  s.settle(asset[0]);
  drain(s);
  assert.equal(s.request.attemptStatus(o0)?.kind, "queued");
  assert.equal(s.request.attemptStatus(i0)?.kind, "queued");
  s.settle(asset[1]);
  drain(s);
  granted(s.request.attemptStatus(o0), "shared");
  assert.equal(s.request.attemptStatus(i0)?.kind, "queued");
  s.maintenance.close();
  drain(s);
  assert.deepEqual(s.request.attemptStatus(i0), cancelled("controller-closed"));
  assert.equal(s.request.begin(), undefined);
  assert.equal(s.request.snapshot().bytes, 0);
});

test("proof expiry remains anchored before verification and through wall rollback", () => {
  const immediate = fixture();
  immediate.onVerify(() => immediate.time(120, 800));
  assert.deepEqual(immediate.send("/test-talep-et", { proof: 1110 }).status, expiration("proof-expired"));
  assert.equal(immediate.request.snapshot().leases, 0);

  for (const elapsed of [0, 4]) {
    const s = fixture();
    const active = Array.from({ length: 5 }, () => granted(s.send("/test-talep-et").status));
    s.onVerify(() => s.time(elapsed, 800));
    const proof = elapsed === 0 ? 1140 : 1110;
    const cutoff = proof - 1100;
    const waiter = queued(s.send("/test-talep-et", { proof }));
    s.onVerify();
    s.time(cutoff - 0.5, 800);
    drain(s);
    assert.equal(s.request.attemptStatus(waiter)?.kind, "queued");
    s.time(cutoff, 800);
    s.settle(active[0]);
    drain(s);
    assert.deepEqual(s.request.attemptStatus(waiter), expiration("proof-expired"));
    assert.equal(s.request.snapshot().leases, 4);
  }
});

test("a fresh preparation sample still fences proof consumed during reentrant maintenance", () => {
  const s = fixture();
  const active = Array.from({ length: 4 }, () => granted(s.send("/").status));
  const waiting = queued(s.send("/"));
  s.settle(active[0]);
  s.onVerify(() => {
    s.time(4, 800);
    drain(s);
    s.time(12, 800);
  });
  assert.deepEqual(s.send("/test-talep-et", { proof: 1110 }).status, expiration("proof-expired"));
  granted(s.request.attemptStatus(waiting), "shared");
  assert.equal(s.request.snapshot().classes.find(({ id }) => id === "form-read")?.reserved, 0);
});

test("a reentrant fill is accounted before the outer preparation can claim a queue slot", () => {
  const s = fixture();
  for (let i = 0; i < 4; i++) granted(s.send("/").status);
  const inner: (AttemptStatus | undefined)[] = [];
  s.onVerify(() => {
    s.onVerify();
    inner.push(s.send("/").status, s.send("/").status);
  });
  assert.deepEqual(s.send("/").status, rejection("class-queue-full"));
  assert.deepEqual(inner, [{ kind: "queued", bytes: 2048 }, { kind: "queued", bytes: 2048 }]);
  assert.equal(s.request.snapshot().leases, 4);
  assert.equal(s.request.snapshot().bytes, 4096);
  assert.equal(s.request.snapshot().preparationSlots, 0);
  assert.equal(s.maintenance.retention().preparingBodyBytes, 0);
});

test("forward wall evidence expires multiple waiters across bounded scans even after rollback", () => {
  const s = fixture();
  const active = Array.from({ length: 5 }, () => granted(s.send("/test-talep-et").status));
  const waiting = Array.from({ length: 4 }, () => queued(s.send("/test-talep-et", { proof: 1500 })));
  const isExpired = (attempt: CapacityAttempt) => s.request.attemptStatus(attempt)?.kind === "expired";
  s.time(0, 1400);
  for (let index = 0; index < 24 && !waiting.some(isExpired); index++) {
    assert.equal(s.maintenance.advance(1), 1);
  }
  assert.equal(waiting.filter(isExpired).length, 1);
  s.time(0, 1000);
  s.settle(active[0]);
  assert.equal(waiting.filter(isExpired).length, 1);
  for (let index = 0; index < 24 && s.request.hasPendingMaintenance(); index++) {
    const before = waiting.filter(isExpired).length;
    assert.equal(s.maintenance.advance(1), 1);
    assert.ok(waiting.filter(isExpired).length - before <= 1);
  }
  for (const attempt of waiting) assert.deepEqual(s.request.attemptStatus(attempt), expiration("proof-expired"));
  assert.equal(s.request.snapshot().leases, 4);
  assert.equal(s.request.snapshot().bytes, 0);
  assert.equal(s.request.hasPendingMaintenance(), false);
});

test("time regression rejects admission and maintenance without advancing the clock watermark", () => {
  const s = fixture();
  s.time(50);
  assert.equal(s.maintenance.advance(1), 0);
  s.time(30, 9000);
  assert.deepEqual(s.send("/").status, rejection("clock-invalid"));
  assert.equal(s.maintenance.advance(1), 1);
  assert.equal(s.request.snapshot().leases, 0);
  s.time(50);
  granted(s.send("/", { proof: 1200 }).status);
});

test("fractional caller cutoff accepts equality and rejects the next fractional sample on both paths", () => {
  for (const cutoff of [21, 21.25]) {
    for (const isQueued of [false, true]) {
      for (const decision of [cutoff, 21.5]) {
        const s = fixture();
        const expected = decision > cutoff ? "expired" : "granted";
        const deadline = cutoff + 2600;
        let status: AttemptStatus | undefined;
        if (isQueued) {
          const active = Array.from({ length: 5 }, () => granted(s.send("/test-talep-et").status));
          const waiter = queued(s.send("/test-talep-et", { deadline }));
          s.time(cutoff);
          drain(s);
          assert.equal(s.request.attemptStatus(waiter)?.kind, "queued");
          s.time(decision);
          s.settle(active[0]);
          drain(s);
          status = s.request.attemptStatus(waiter);
        } else {
          s.onVerify(() => s.time(decision));
          status = s.send("/test-talep-et", { deadline }).status;
        }
        if (expected === "expired") assert.deepEqual(status, expiration("caller-deadline-exceeded"));
        else granted(status, "reserved");
      }
    }
  }
});

test("an idle scan wakes for fractional caller-deadline expiry without a capacity change", () => {
  const s = fixture();
  const active = Array.from({ length: 5 }, () => granted(s.send("/test-talep-et").status));
  const waiter = queued(s.send("/test-talep-et", { deadline: 2621.25 }), 2048);

  s.time(21.25);
  drain(s, 1);
  assert.equal(s.maintenance.advance(1), 0);
  assert.equal(s.request.hasPendingMaintenance(), false);
  assert.deepEqual(s.request.attemptStatus(waiter), { kind: "queued", bytes: 2048 });
  const atEquality = s.request.snapshot();
  assert.equal(atEquality.queued, 1);
  assert.equal(atEquality.bytes, 2048);

  // Only a fresh time observation can wake the completed scan.
  s.time(21.5);
  assert.deepEqual(s.request.snapshot(), atEquality);
  drain(s, 1);

  assert.deepEqual(s.request.attemptStatus(waiter), expiration("caller-deadline-exceeded"));
  const after = s.request.snapshot();
  assert.equal(after.queued, 0);
  assert.equal(after.bytes, 0);
  assert.equal(after.leases, 5);
  assert.equal(after.reserved, atEquality.reserved);
  assert.equal(after.shared, atEquality.shared);
  for (const lease of active) assert.equal(s.request.leaseState(lease), "active");
});

test("observations sample no clock and leave due expiry, settlement and eligible grants to maintenance", () => {
  const s = fixture();
  const active = Array.from({ length: 5 }, () => granted(s.send("/test-talep-et").status));
  const waiter = queued(s.send("/test-talep-et"));
  s.settle(active[0], "ambiguous", 125);
  const samples = s.samples();
  const before = s.request.snapshot();
  s.time(150);
  let invoked = false;
  s.onClock(() => {
    invoked = true;
    s.request.cancel(waiter);
    s.maintenance.close();
    throw Error("clock failure");
  });
  const pending = s.request.hasPendingMaintenance();
  for (let i = 0; i < 3; i++) {
    assert.equal(s.request.hasPendingMaintenance(), pending);
    assert.deepEqual(s.request.snapshot(), before);
    assert.equal(s.request.attemptStatus(waiter)?.kind, "queued");
    assert.equal(s.request.leaseState(active[0]), "ambiguous-held");
  }
  assert.equal(invoked, false);
  assert.equal(s.samples(), samples);
  s.onClock();
  drain(s);
  assert.deepEqual(s.request.attemptStatus(waiter), expiration("wait-timeout"));
  assert.equal(s.request.leaseState(active[0]), "settled");
  assert.equal(s.request.snapshot().ambiguous, 0);
});

test("submission and settlement never sweep unrelated work, even with an expired waiter", () => {
  const s = fixture();
  const active = Array.from({ length: 5 }, () => granted(s.send("/test-talep-et").status));
  const stale = queued(s.send("/test-talep-et"));
  s.time(150);
  assert.deepEqual(s.submit(null).status, rejection("unverified"));
  assert.deepEqual(s.send("/", { facts: { tenantId: "other" } }).status, rejection("scope-mismatch"));
  assert.deepEqual(s.send("/", { facts: { principal: "other" } }).status, rejection("untrusted-channel"));
  assert.deepEqual(s.send("/nope").status, rejection("unsupported"));
  assert.deepEqual(s.send("/", { proof: 1200 }).status, expiration("proof-expired"));
  const stopped = s.request.begin()!;
  assert.equal(s.request.cancel(stopped), true);
  const calls = s.samples();
  let read = false;
  assert.deepEqual(s.request.submit(stopped, {
    get candidate() { read = true; return null; },
  }), cancelled());
  assert.equal(read, false);
  assert.equal(s.samples(), calls);
  granted(s.send("/").status);
  const beforeRelease = s.samples();
  s.settle(active[0]);
  assert.equal(s.samples(), beforeRelease);
  assert.equal(s.request.attemptStatus(stale)?.kind, "queued");
  drain(s);
  assert.deepEqual(s.request.attemptStatus(stale), expiration("wait-timeout"));
});

test("full Storefront queue expiry spends one shared budget for inspections and transitions", () => {
  const s = fixture(storefrontPolicy);
  fillStorefront(s);
  const waiting = [
    ...Array.from({ length: 2 }, () => queued(s.send("/products/w"))),
    ...Array.from({ length: 5 }, () => queued(s.send("/checkout/w"))),
    ...Array.from({ length: 3 }, () => queued(s.send("/orders", order))),
  ];
  s.time(250);
  assert.deepEqual(s.send("/products/new").status, rejection("class-queue-full"));
  assert.equal(s.request.snapshot().queued, 10);
  let passes = 0;
  for (const budget of [1, 3, 2]) {
    const before = s.request.snapshot().queued;
    const samples = s.samples();
    const used = s.maintenance.advance(budget);
    assert.ok(used <= budget);
    assert.ok(before - s.request.snapshot().queued <= used);
    assert.ok(s.samples() - samples <= budget);
    passes += before - s.request.snapshot().queued;
  }
  assert.ok(passes > 0 && passes < 10);
  drain(s, 3);
  for (const attempt of waiting) assert.deepEqual(s.request.attemptStatus(attempt), expiration("wait-timeout"));
  const snapshot = s.request.snapshot();
  assert.equal(snapshot.queued, 0);
  assert.equal(snapshot.bytes, 0);
  assert.equal(snapshot.reserved + snapshot.shared, 16);
  assert.equal(s.maintenance.retention().queued, 0);
});

test("clock recovery shares budget between mixed expiry and FIFO grants, with cancellation latched in a clock callback", () => {
  const s = fixture();
  const active = Array.from({ length: 5 }, () => granted(s.send("/test-talep-et").status));
  const stale = queued(s.send("/test-talep-et", { proof: 1120 }));
  const cancelledHead = queued(s.send("/test-talep-et"));
  const next = queued(s.send("/test-talep-et"));
  const last = queued(s.send("/test-talep-et"));
  for (const lease of active.slice(0, 3)) s.settle(lease);
  s.onClock(() => { throw Error("clock broken"); });
  assert.equal(s.maintenance.advance(1), 1);
  assert.equal(s.request.hasPendingMaintenance(), false);
  assert.equal(s.request.snapshot().queued, 4);
  s.time(30);
  let nested: number | undefined;
  let latch: boolean | undefined;
  s.onClock(() => {
    s.onClock();
    latch = s.request.cancel(cancelledHead);
    nested = s.maintenance.advance(5);
  });
  assert.equal(s.maintenance.advance(1), 1);
  assert.equal(latch, true);
  assert.equal(nested, 0);
  assert.deepEqual(s.request.attemptStatus(cancelledHead), cancelled());
  const live = [stale, next, last];
  const changed = () => live.filter((attempt) => s.request.attemptStatus(attempt)?.kind !== "queued").length;
  for (let step = 0; step < 32 && s.request.hasPendingMaintenance(); step++) {
    const before = changed();
    assert.equal(s.maintenance.advance(1), 1);
    assert.ok(changed() - before <= 1);
    if (s.request.attemptStatus(last)?.kind === "granted") assert.equal(s.request.attemptStatus(next)?.kind, "granted");
  }
  assert.deepEqual(s.request.attemptStatus(stale), expiration("proof-expired"));
  granted(s.request.attemptStatus(next), "reserved");
  granted(s.request.attemptStatus(last), "reserved");
  assert.equal(s.request.snapshot().queued, 0);
  assert.equal(s.request.snapshot().leases, 4);
});

test("reentrant verification close, cancel, deadline advance and clock regression allocate no lease", () => {
  const verifier = new SyntheticTestVerifier();
  const candidate = verifier.issue(makeFacts(ba0Policy, "visitor", "GET", "/"), 4500);
  for (const [action, expected] of [
    ["close", cancelled("controller-closed")],
    ["cancel", cancelled()],
    ["deadline", expiration("caller-deadline-exceeded")],
    ["regression", rejection("clock-invalid")],
  ] as const) {
    const s = setup(ba0Policy, verifier);
    s.time(10);
    const attempt = s.request.begin()!;
    let invocations = 0;
    s.onVerify(() => {
      invocations++;
      if (action === "close") s.maintenance.close();
      if (action === "cancel") s.request.cancel(attempt);
      if (action === "deadline") s.time(111);
      if (action === "regression") s.time(9);
    });
    assert.deepEqual(s.request.submit(attempt, { candidate, callerDeadlineMonoMs: 2710 }), expected);
    assert.equal(invocations, 1);
    assert.equal(s.request.snapshot().closed, action === "close");
    assert.equal(s.request.snapshot().leases, 0);
    assert.equal(s.request.snapshot().queued, 0);
    assert.equal(s.request.snapshot().preparationSlots, 0);
  }
});

test("clock callbacks cannot start nested maintenance and an invalid bracket cannot admit work", () => {
  const s = fixture();
  let nested: number | undefined;
  let duplicate: boolean | undefined;
  const lease = granted(s.send("/").status);
  const event = s.settle(lease);
  assert.equal(s.execution.identity(lease), undefined);
  s.onClock(() => {
    s.onClock();
    s.time(50);
    nested = s.maintenance.advance(5);
    duplicate = s.execution.settle(event);
  });
  assert.deepEqual(s.send("/").status, rejection("clock-invalid"));
  assert.equal(nested, 0);
  assert.equal(duplicate, false);
  assert.equal(s.request.snapshot().leases, 0);
  assert.equal(s.request.snapshot().shared, 0);
  granted(s.send("/").status);
});

test("cancellation wins before selected reserved and shared grants, including from the final clock callback", () => {
  for (const [policy, target, capacity, pool] of [
    [ba0Policy, "/test-talep-et", 5, "reserved"],
    [storefrontPolicy, "/products/a", 5, "shared"],
  ] as const) {
    for (const timing of ["after-release", "final-clock"] as const) {
      const s = fixture(policy);
      const active = Array.from({ length: capacity }, () => granted(s.send(target).status));
      const stopped = queued(s.send(target));
      const live = queued(s.send(target));
      s.settle(active[0]);
      assert.equal(s.request.attemptStatus(stopped)?.kind, "queued");
      if (timing === "after-release") {
        assert.equal(s.request.cancel(stopped), true);
      } else {
        // Count the four expiry checks and the priority scans through the selected head.
        const classIndex = policy.manifest.classes.findIndex(({ id }) => id === (pool === "reserved" ? "form-read" : "browse"));
        const inspectSteps = 5 + classIndex + (pool === "shared" ? policy.manifest.classes.length : 0);
        for (let i = 0; i < inspectSteps; i++) assert.equal(s.maintenance.advance(1), 1);
        assert.equal(s.request.attemptStatus(stopped)?.kind, "queued");
        s.onClock(() => {
          s.onClock();
          s.request.cancel(stopped);
        });
        assert.equal(s.maintenance.advance(1), 1);
        assert.deepEqual(s.request.attemptStatus(stopped), cancelled());
      }
      drain(s);
      assert.deepEqual(s.request.attemptStatus(stopped), cancelled());
      assert.equal(s.request.cancel(stopped), false);
      granted(s.request.attemptStatus(live), pool);
      assert.equal(s.request.snapshot().leases, capacity);
      assert.equal(s.request.snapshot().queued, 0);
    }
  }
});

test("signal-shaped input never invokes source callbacks or bypasses explicit cancellation and closure", () => {
  const verifier = new SyntheticTestVerifier();
  const candidate = verifier.issue(makeFacts(ba0Policy, "visitor", "GET", "/"), 4500);
  const s = setup(ba0Policy, verifier);
  const native = new AbortController();
  let reads = 0;
  const trapped = new Proxy(native.signal, {
    get() { reads++; throw Error("signal getter"); },
  });
  const input = { candidate, signal: trapped };
  const active = Array.from({ length: 4 }, () => granted(s.submit(candidate).status));
  const attempt = s.request.begin()!;
  const next = s.request.begin()!;
  assert.equal(s.request.submit(attempt, input)?.kind, "queued");
  const getterInput = { candidate, get signal() { reads++; throw Error("input getter"); } };
  assert.equal(s.request.submit(next, getterInput)?.kind, "queued");
  assert.equal(reads, 0);
  assert.equal(getEventListeners(native.signal, "abort").length, 0);
  const before = s.request.snapshot();
  native.abort();
  assert.deepEqual(s.request.snapshot(), before);
  assert.equal(s.request.cancel(next), true);
  assert.equal(s.request.cancel(next), false);
  assert.equal(s.request.snapshot().bytes, 2048);
  s.settle(active[0]);
  s.maintenance.close();
  drain(s);
  assert.deepEqual(s.request.attemptStatus(attempt), cancelled("controller-closed"));
  assert.equal(s.request.snapshot().queued, 0);
  assert.equal(s.request.snapshot().bytes, 0);
  assert.equal(s.request.snapshot().leases, 3);
  assert.equal(reads, 0);
});

test("a queued attempt does not retain a raw candidate, its megabyte of metadata, or caller body storage", async () => {
  v8.setFlagsFromString("--expose-gc");
  const collect = vm.runInNewContext("gc") as () => void;
  const verifier = new SyntheticTestVerifier();
  const facts = makeFacts(ba0Policy, "visitor", "POST", "/api/public-inquiries", { ...ba0PostFacts, bodyBytes: 1 });
  type Candidate = { proof: TestCandidate; metadata: Uint8Array };
  const base = setup(ba0Policy, {
    verify(candidate) {
      return verifier.verify((candidate as Candidate).proof);
    },
  });
  const wrap = (bytes: number): Candidate => ({ proof: verifier.issue(facts, 4500), metadata: new Uint8Array(bytes) });
  const active = Array.from({ length: 3 }, () => granted(base.submit(wrap(0), Uint8Array.of(9)).status));
  function enqueue() {
    const candidate = wrap(1_048_576);
    const body = Uint8Array.of(37);
    const attempt = queued(base.submit(candidate, body), 2049);
    body[0] = 88;
    return { attempt, references: [new WeakRef(candidate), new WeakRef(candidate.metadata), new WeakRef(body)] };
  }
  let savedByteAt: VerificationBody["byteAt"] | undefined;
  let verifiedByte: number | undefined;
  base.onVerify((body) => {
    verifiedByte = body.byteAt(0);
    savedByteAt = body.byteAt;
  });
  const { attempt, references } = enqueue();
  assert.equal(verifiedByte, 37);
  assert.equal(savedByteAt?.(0), undefined);
  for (let i = 0; i < 5; i++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
    collect();
  }
  for (const reference of references) assert.equal(reference.deref(), undefined);
  assert.equal(base.request.attemptStatus(attempt)?.kind, "queued");
  assert.equal(base.request.snapshot().bytes, 2049);
  assert.equal(base.maintenance.retention().queued, 1);
  const cancelledAttempt = queued(base.submit(wrap(0), Uint8Array.of(10)), 2049);
  assert.equal(base.request.cancel(cancelledAttempt), true);
  assert.equal(base.request.snapshot().bytes, 2049);
  base.settle(active[0]);
  drain(base);
  const lease = granted(base.request.attemptStatus(attempt), "reserved");
  const execution = base.execution.identity(lease)!.execution;
  assert.equal(base.execution.takeBody(lease, base.execution.identity(active[1])!.execution), undefined);
  assert.deepEqual(base.execution.takeBody(lease, execution), Uint8Array.of(37));
  assert.equal(base.execution.takeBody(lease, execution), undefined);
  assert.equal(base.maintenance.retention().queued, 0);
  base.settle(lease);
  for (const remaining of active.slice(1)) base.settle(remaining);
  assert.equal(base.maintenance.retention().leased, 0);
  assert.equal(base.request.snapshot().bytes, 0);
});
