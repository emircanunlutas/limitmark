import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { createOriginCapacityBoundary } from "../defense/core/capacity-boundary";
import { activateCustomerOriginPolicy } from "../defense/core/capacity-policy";
import type {
  AuthenticatedRequestData, CapacityAttempt, CapacityExecutionEvidence, CapacityExecutionIdentity,
  CapacityLease, CapacitySettlementEvent, CustomerOriginPolicyManifest, VerificationBody, VerifierResult,
} from "../defense/core/capacity-port";
import { OriginCapacityModel } from "./support/origin-capacity-model";

function setup() {
  const bytes = readFileSync(path.join(__dirname, "fixtures", "customer-origin-v1", "ba0.json"));
  const manifest = JSON.parse(bytes.toString()) as CustomerOriginPolicyManifest;
  const scope = { tenantId: manifest.tenantId, deploymentId: manifest.deploymentId, domainId: manifest.domain.id };
  const digest = createHash("sha256").update(bytes).digest("hex");
  const policy = activateCustomerOriginPolicy(bytes, { ...scope, revision: manifest.revision, expectedDigest: digest });
  let now = 0;
  let wall = 1000;
  let brackets = 0;
  let onWall: (() => void) | undefined;
  let onVerify: ((view: VerificationBody) => void) | undefined;
  let onEvidence: ((identity: CapacityExecutionIdentity) => void) | undefined;
  let result: ((facts: AuthenticatedRequestData) => VerifierResult) | undefined;

  const boundary = createOriginCapacityBoundary(policy, {
    monotonicMs: () => now,
    wallUpperMs: () => {
      brackets++;
      onWall?.();
      return wall;
    },
  }, {
    verify(target: string, activated, _verifiedAt, body) {
      assert.equal(activated, policy);
      assert.ok(body);
      onVerify?.(body);
      const facts: AuthenticatedRequestData = {
        ...scope, digest, principal: "demo-plane", audience: "demo-boundary", scheme: "http", authority: "127.0.0.1:18080",
        method: target === "/api/public-inquiries" ? "POST" : "GET", target,
        mediaType: target === "/api/public-inquiries" ? "application/x-www-form-urlencoded" : null,
        origin: target === "/api/public-inquiries" ? "http://127.0.0.1:18080" : null,
        bodyBytes: body.byteLength, proofExpiresAtWallMs: 1350,
      };
      return result ? result(facts) : { ok: true, authenticated: facts };
    },
  }, {
    verify(identity, evidence: ((id: CapacityExecutionIdentity) => CapacityExecutionEvidence) | null) {
      onEvidence?.(identity);
      return evidence?.(identity) ?? null;
    },
  });
  const { request, execution } = boundary;
  const submit = (target = "/", body?: Uint8Array, callerDeadlineMonoMs?: number) => {
    const attempt = request.begin()!;
    assert.ok(attempt);
    const status = request.submit(attempt, { candidate: target, body, callerDeadlineMonoMs });
    return { attempt, status };
  };
  const identityFor = (lease: CapacityLease) => execution.identity(lease)!;
  const settle = (lease: CapacityLease, kind: CapacityExecutionEvidence["kind"] = "completed", hardStopMonoMs?: number) => {
    const event = execution.verify(lease, identityFor(lease).execution, (identity) => ({
      ...identity, kind, ...(kind === "ambiguous" ? { hardStopMonoMs } : {}),
    }));
    assert.ok(event);
    assert.equal(execution.settle(event), true);
  };
  return {
    ...boundary, manifest, submit, settle, brackets: () => brackets,
    time: (next: number, nextWall = 1000 + next) => { now = next; wall = nextWall; },
    wallHook: (hook?: () => void) => { onWall = hook; },
    verifyHook: (hook?: (view: VerificationBody) => void) => { onVerify = hook; },
    evidenceHook: (hook?: (identity: CapacityExecutionIdentity) => void) => { onEvidence = hook; },
    result: (hook?: (facts: AuthenticatedRequestData) => VerifierResult) => { result = hook; },
  };
}

function granted(status: ReturnType<ReturnType<typeof setup>["submit"]>["status"]) {
  assert.ok(status?.kind === "granted");
  return status.lease;
}

test("admission brackets start at or after the preparation bracket's upper endpoint", () => {
  for (const lower of [0.5, 1, 1.25]) {
    const s = setup();
    s.wallHook(() => s.time(s.brackets() === 1 ? 1 : Math.max(1, lower), 1000));
    s.verifyHook(() => s.time(lower, 1000));
    const { status } = s.submit();
    if (lower === 0.5) assert.deepEqual(status, { kind: "rejected", reason: "clock-invalid" });
    else granted(status);
  }
});

test("verifier-result getters cannot recover bytes through saved body methods", () => {
  const s = setup();
  let alias: VerificationBody | undefined;
  let saved: VerificationBody["byteAt"] | undefined;
  const reads: (number | undefined)[] = [];
  s.verifyHook((view) => {
    alias = view;
    saved = view.byteAt;
    assert.equal(saved(0), 37);
  });
  s.result((facts) => ({
    get ok(): true {
      reads.push(saved!(0));
      return true;
    },
    get authenticated() {
      reads.push(alias!.byteAt(0));
      return facts;
    },
  }));
  granted(s.submit("/api/public-inquiries", Uint8Array.of(37)).status);
  assert.deepEqual(reads, [undefined, undefined]);
  assert.equal(saved!(0), undefined);

  s.verifyHook((view) => {
    saved = view.byteAt;
    throw Error("verifier failed");
  });
  assert.deepEqual(s.submit("/api/public-inquiries", Uint8Array.of(38)).status, {
    kind: "rejected", reason: "unverified",
  });
  assert.equal(saved!(0), undefined);
  assert.equal(s.maintenance.retention().preparingBodyBytes, 0);
  assert.equal(s.request.snapshot().preparationSlots, 0);
});

test("normalization reads external fields once and rejects getter throws, scope and size mismatches", () => {
  const s = setup();
  const fields = new Map<string, number>();
  const count = (key: string) => fields.set(key, (fields.get(key) ?? 0) + 1);
  s.result((facts) => new Proxy({
    ok: true as const,
    authenticated: new Proxy(facts, { get(target, key: keyof typeof facts) { count(key); return target[key]; } }),
  }, { get(target, key: "ok" | "authenticated") { count(key); return target[key]; } }));
  const attempt = s.request.begin()!;
  const input = new Proxy({ candidate: "/", body: undefined, callerDeadlineMonoMs: 2850 }, {
    get(target, key: "candidate" | "body" | "callerDeadlineMonoMs") { count(key); return target[key]; },
  });
  assert.equal(s.request.submit(attempt, input)?.kind, "granted");
  assert.equal(fields.size, 19);
  assert.ok([...fields.values()].every((reads) => reads === 1));

  s.result(() => ({ get ok(): true { throw Error("verifier result getter"); }, authenticated: {} as AuthenticatedRequestData }));
  assert.deepEqual(s.submit().status, { kind: "rejected", reason: "unverified" });
  s.result((facts) => ({ ok: true, authenticated: { ...facts, digest: "foreign" } }));
  assert.deepEqual(s.submit().status, { kind: "rejected", reason: "scope-mismatch" });
  s.result((facts) => ({ ok: true, authenticated: { ...facts, bodyBytes: 0 } }));
  assert.deepEqual(s.submit("/api/public-inquiries", Uint8Array.of(1)).status, { kind: "rejected", reason: "unsupported" });
  assert.equal(s.request.snapshot().preparationSlots, 0);
});

test("fresh brackets reject time consumed by sampling or preparation, and cancellation wins inside the final bracket", () => {
  const s = setup();
  let wallCalls = 0;
  s.wallHook(() => { if (++wallCalls === 2) s.time(120, 900); });
  assert.deepEqual(s.submit().status, { kind: "rejected", reason: "clock-invalid" });

  const elapsed = setup();
  elapsed.result((facts) => ({ ok: true, authenticated: { ...facts, proofExpiresAtWallMs: 1110 } }));
  elapsed.verifyHook(() => elapsed.time(120, 900));
  assert.deepEqual(elapsed.submit().status, { kind: "expired", reason: "proof-expired" });

  const cancelled = setup();
  const attempt = cancelled.request.begin()!;
  let inFinal = false;
  cancelled.verifyHook(() => { inFinal = true; });
  cancelled.wallHook(() => {
    if (inFinal) {
      assert.equal(cancelled.maintenance.advance(1), 0);
      assert.equal(cancelled.request.cancel(attempt), true);
    }
  });
  assert.deepEqual(cancelled.request.submit(attempt, { candidate: "/" }), { kind: "cancelled", reason: "cancelled" });
  assert.equal(cancelled.request.snapshot().leases, 0);
});

test("one fresh bracket per maintenance step protects both reserved and shared queued grants", () => {
  for (const [target, count] of [["/test-talep-et", 5], ["/", 4]] as const) {
    const s = setup();
    const active = Array.from({ length: count }, () => granted(s.submit(target).status));
    const waiting = [s.submit(target).attempt, s.submit(target).attempt];
    s.settle(active[0]);
    s.settle(active[count - 1]);
    let time = 0;
    s.wallHook(() => {
      // The callback changes decision time before the second grant can use
      // the first grant's bracket. Only the first waiter can obtain a lease.
      if (s.request.attemptStatus(waiting[0])?.kind === "granted") {
        time = 200;
      }
      s.time(time);
    });
    const before = s.brackets();
    assert.ok(s.maintenance.advance(64) <= 64);
    assert.ok(s.brackets() > before + 1);
    const first = s.request.attemptStatus(waiting[0]);
    assert.equal(first?.kind === "granted" && first.pool, target === "/" ? "shared" : "reserved");
    assert.equal(s.request.attemptStatus(waiting[1])?.kind, "queued");
    assert.ok(s.maintenance.advance(64) <= 64);
    assert.equal(s.request.attemptStatus(waiting[1])?.kind, "expired");
  }
});

test("regressing brackets cannot grant or reset budget-one reserved and shared scans", () => {
  for (const [target, count, pool] of [["/test-talep-et", 5, "reserved"], ["/", 4, "shared"]] as const) {
    const s = setup();
    const active = Array.from({ length: count }, () => granted(s.submit(target).status));
    const waiting = s.submit(target).attempt;
    s.settle(active[0]);
    s.time(0);
    s.wallHook(() => s.time(1, 1000));
    assert.equal(s.maintenance.advance(1), 1);
    s.wallHook();

    for (let step = 0; step < 32 && s.request.attemptStatus(waiting)?.kind === "queued"; step++) {
      s.wallHook(() => s.time(1, 5000));
      for (let invalid = 0; invalid < 2; invalid++) {
        s.time(0.5, 5000);
        assert.equal(s.maintenance.advance(1), 1);
        assert.equal(s.request.attemptStatus(waiting)?.kind, "queued");
        assert.equal(s.request.hasPendingMaintenance(), false);
      }
      s.wallHook();
      s.time(1, 1000);
      assert.equal(s.maintenance.advance(1), 1);
    }
    const status = s.request.attemptStatus(waiting);
    assert.equal(status?.kind === "granted" && status.pool, pool);

    const closing = s.submit(target).attempt;
    assert.equal(s.request.attemptStatus(closing)?.kind, "queued");
    s.maintenance.close();
    for (let step = 0; step < 8 && s.request.hasPendingMaintenance(); step++) {
      s.time(0.5);
      assert.equal(s.maintenance.advance(1), 1);
    }
    assert.deepEqual(s.request.attemptStatus(closing), { kind: "cancelled", reason: "controller-closed" });
  }
});

test("read-only observations use committed state and a fresh valid sample resumes a stalled scan", () => {
  const s = setup();
  const active = Array.from({ length: 4 }, () => granted(s.submit().status));
  const waiting = s.submit().attempt;
  s.settle(active[0]);
  assert.equal(s.maintenance.advance(1), 1);
  s.wallHook(() => { throw Error("clock unavailable"); });
  assert.equal(s.maintenance.advance(1), 1);
  const count = s.brackets();
  const snapshot = s.request.snapshot();
  assert.equal(s.request.attemptStatus(waiting)?.kind, "queued");
  assert.equal(s.request.hasPendingMaintenance(), false);
  assert.deepEqual(s.request.snapshot(), snapshot);
  assert.equal(s.brackets(), count);
  s.wallHook();
  s.time(2);
  assert.ok(s.maintenance.advance(32) <= 32);
  granted(s.request.attemptStatus(waiting));
});

test("forward wall evidence tightens a queued proof even when the wall rolls back before expiry", () => {
  const s = setup();
  const active = Array.from({ length: 4 }, () => granted(s.submit().status));
  const waiting = s.submit().attempt;
  s.time(1, 1245);
  assert.equal(s.maintenance.advance(1), 1);
  s.time(8, 1000);
  s.settle(active[0]);
  s.maintenance.advance(32);
  assert.deepEqual(s.request.attemptStatus(waiting), { kind: "expired", reason: "proof-expired" });
});

test("one owned body transfers through preparation, queue, lease, and trusted execution", () => {
  const s = setup();
  const path = "/api/public-inquiries";
  const active = Array.from({ length: 3 }, () => granted(s.submit(path).status));
  const input = Uint8Array.of(3, 4);
  let retainedView: VerificationBody | undefined;
  s.verifyHook((view) => {
    retainedView = view;
    assert.equal(s.maintenance.retention().preparingBodyBytes, 2);
    assert.equal(view.byteAt(0), 3);
    input[0] = 100;
  });
  const waiting = s.submit(path, input).attempt;
  assert.equal(retainedView?.byteAt(0), undefined);
  assert.deepEqual(s.maintenance.retention(), {
    preparingBodyBytes: 0, preparingBodyLimit: 65536, queued: 2, leased: 0, pendingNotifications: 0,
  });
  assert.equal(s.request.snapshot().bytes, 2050);
  s.settle(active[0]);
  s.maintenance.advance(32);
  const lease = granted(s.request.attemptStatus(waiting));
  const identity = s.execution.identity(lease)!;
  assert.equal(s.maintenance.retention().queued, 0);
  assert.equal(s.maintenance.retention().leased, 2);
  assert.equal(s.execution.takeBody(lease, s.execution.identity(active[1])!.execution), undefined);
  assert.deepEqual(s.execution.takeBody(lease, identity.execution), Uint8Array.of(3, 4));
  assert.equal(s.execution.takeBody(lease, identity.execution), undefined);
  assert.equal(s.maintenance.retention().leased, 0);
});

test("nested cancelled preparations hold their byte allowance until unwind; closed and cancelled payloads release once", () => {
  const s = setup();
  const target = "/api/public-inquiries";
  const body = new Uint8Array(32768);
  const first = s.request.begin()!;
  const second = s.request.begin()!;
  let nested = false;
  s.verifyHook(() => {
    if (!nested) {
      nested = true;
      assert.equal(s.request.cancel(first), true);
      assert.equal(s.request.submit(second, { candidate: target, body })?.kind, "granted");
    } else {
      assert.equal(s.request.snapshot().preparationSlots, 2);
      assert.equal(s.maintenance.retention().preparingBodyBytes, 65536);
      assert.deepEqual(s.submit(target, body).status, { kind: "rejected", reason: "preparation-bytes-exceeded" });
    }
  });
  assert.equal(s.request.submit(first, { candidate: target, body })?.kind, "cancelled");
  assert.equal(s.request.snapshot().preparationSlots, 0);
  assert.equal(s.maintenance.retention().preparingBodyBytes, 0);
  s.verifyHook();
  s.submit(target);
  s.submit(target);
  const queued = s.submit(target, Uint8Array.of(1)).attempt;
  assert.equal(s.request.cancel(queued), true);
  assert.equal(s.request.cancel(queued), false);
  const abandoned = s.request.begin()!;
  const closed = s.submit(target, Uint8Array.of(2)).attempt;
  s.maintenance.close();
  s.maintenance.advance(32);
  assert.equal(s.request.attemptStatus(abandoned)?.kind, "cancelled");
  assert.equal(s.request.attemptStatus(closed)?.kind, "cancelled");
  assert.equal(s.request.snapshot().preparationSlots, 0);
  assert.equal(s.maintenance.retention().queued, 0);
  assert.equal(s.maintenance.retention().leased, 32768);
});

test("execution evidence has generation and execution identity, expected state, and one-use authority", () => {
  const s = setup();
  const left = granted(s.submit().status);
  const right = granted(s.submit().status);
  const a = s.execution.identity(left)!;
  const b = s.execution.identity(right)!;
  const foreign = setup();
  const other = foreign.execution.identity(granted(foreign.submit().status))!;
  const completed = (id: CapacityExecutionIdentity) => ({ ...id, kind: "completed" as const });
  assert.equal(s.execution.verify(left, b.execution, completed), undefined);
  assert.equal(s.execution.verify(left, a.execution, () => completed({ ...a, generation: other.generation })), undefined);
  assert.equal(s.execution.verify(left, a.execution, () => completed({ ...a, execution: b.execution })), undefined);
  assert.equal(s.execution.verify(left, a.execution, () => ({
    ...a, get kind(): "completed" { throw Error("invalid evidence getter"); },
  })), undefined);
  assert.equal(s.execution.settle({} as CapacitySettlementEvent), false);

  const stale = s.execution.verify(left, a.execution, completed)!;
  const held = s.execution.verify(left, a.execution, (id) => ({ ...id, kind: "ambiguous", hardStopMonoMs: 10.5 }))!;
  assert.equal(foreign.execution.settle(held), false);
  assert.equal(s.execution.settle(stale), false);
  assert.equal(s.execution.settle(held), true);
  assert.equal(s.execution.settle(held), false);
  const terminal = s.execution.verify(left, a.execution, completed)!;
  s.time(10.25);
  s.maintenance.advance(32);
  assert.equal(s.request.leaseState(left), "ambiguous-held");
  s.time(10.5);
  s.evidenceHook(() => {
    assert.equal(s.execution.verify(right, b.execution, completed), undefined);
    s.maintenance.advance(32);
  });
  assert.equal(s.execution.verify(left, a.execution, completed), undefined);
  assert.equal(s.execution.settle(terminal), false);
  assert.equal(s.request.leaseState(left), "settled");
  assert.equal(s.request.snapshot().leases, 1);
});

test("boundary command states agree with the independent oracle under time, queue and settlement interleaving", () => {
  const s = setup();
  const model = new OriginCapacityModel(s.manifest);
  const attempts: CapacityAttempt[] = [];
  const add = (target: string, operation: string) => {
    const id = attempts.length;
    attempts.push(s.submit(target, undefined, 2850).attempt);
    model.admit(id, operation, 0);
    assert.deepEqual(s.request.snapshot(), model.snapshot());
  };
  for (let i = 0; i < 6; i++) add("/", "home");
  for (let i = 0; i < 6; i++) add("/test-talep-et", "inquiry-form");

  for (const [id, time] of [[0, 2], [6, 3], [1, 55]]) {
    s.time(time);
    model.observe(time, time, 1000 + time);
    s.settle(granted(s.request.attemptStatus(attempts[id])));
    model.settle(id, "terminal");
    assert.deepEqual(s.request.snapshot(), model.snapshot());
    for (let step = 0; step < 64 && s.request.hasPendingMaintenance(); step++) assert.equal(s.maintenance.advance(1), 1);
    model.drain();
    assert.equal(model.hasEligibleHead(), false);
    assert.deepEqual(s.request.snapshot(), model.snapshot());
    for (const [id, handle] of attempts.entries()) assert.equal(s.request.attemptStatus(handle)?.kind, model.rows.get(id)?.state);
  }
});

