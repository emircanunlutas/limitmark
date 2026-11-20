import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { activateCustomerOriginPolicy } from "../defense/core/capacity-policy";
import type { CapacityAttempt, CapacityLease, CustomerOriginPolicyManifest } from "../defense/core/capacity-port";
import { createOriginCapacityState } from "../defense/core/origin-capacity";
import { OriginCapacityModel } from "./support/origin-capacity-model";

function fixture(name = "ba0") {
  const mixed = name === "ba0-mixed";
  let bytes = readFileSync(path.join(__dirname, "fixtures", "customer-origin-v1", (mixed ? "ba0" : name) + ".json"));
  const manifest = JSON.parse(bytes.toString()) as CustomerOriginPolicyManifest;
  if (mixed) {
    const heavy = manifest.operations.find(({ id }) => id === "submit-inquiry")!;
    const light = { ...heavy, id: "submit-light", path: "/api/light", costUnits: 1 };
    const journeys = manifest.journeys.map((journey) => ({
      ...journey,
      steps: [...journey.steps, ...journey.steps.filter((step) => step.operationId === heavy.id)
        .map((step) => ({ ...step, operationId: light.id, target: light.path }))],
    }));
    bytes = Buffer.from(JSON.stringify({ ...manifest, operations: [...manifest.operations, light], journeys }));
  }
  return activateCustomerOriginPolicy(bytes, {
    tenantId: manifest.tenantId, deploymentId: manifest.deploymentId, domainId: manifest.domain.id,
    revision: manifest.revision, expectedDigest: createHash("sha256").update(bytes).digest("hex"),
  });
}

function setup(name?: string) {
  const policy = fixture(name);
  const state = createOriginCapacityState(policy);
  assert.equal(state.owner.observeTime(0, 0, 1000), true);
  const submit = (op: string, body = 0, proof = 180, expiry = 1350, caller = 2850) => {
    const attempt = state.owner.begin()!;
    assert.ok(attempt);
    assert.equal(state.owner.bind(attempt, op, body, proof, expiry, caller), true);
    return { attempt, status: state.owner.admit(attempt)! };
  };
  return { ...state, policy, submit };
}

function drain({ controller, owner }: ReturnType<typeof setup>) {
  let work = 0;
  while (controller.hasPendingMaintenance()) {
    assert.equal(owner.advance(1), 1);
    assert.ok(++work < 300, "budget-one drain should make progress");
  }
  assert.equal(owner.advance(1), 0);
  return work;
}

test("cancellation latches before binding, after binding, and while queued", () => {
  const { controller, owner, submit } = setup();
  const beforeBind = owner.begin()!;
  assert.equal(controller.cancel(beforeBind), true);
  assert.equal(owner.bind(beforeBind, "home", 0, 180, 1350, 2850), false);
  assert.equal(controller.snapshot().preparationSlots, 1);
  assert.equal(owner.finishPreparation(beforeBind), true);
  assert.equal(owner.finishPreparation(beforeBind), false);

  const beforeGrant = owner.begin()!;
  assert.equal(owner.bind(beforeGrant, "home", 0, 180, 1350, 2850), true);
  assert.equal(owner.bind(beforeGrant, "privacy", 0, 180, 1350, 2850), false);
  assert.equal(controller.cancel(beforeGrant), true);
  assert.deepEqual(owner.admit(beforeGrant), { kind: "cancelled", reason: "cancelled" });
  for (let i = 0; i < 4; i++) assert.equal(submit("home").status.kind, "granted");
  const { attempt, status } = submit("home");
  assert.deepEqual(status, { kind: "queued", bytes: 2048 });
  assert.equal(controller.cancel(attempt), true);
  assert.equal(controller.cancel(attempt), false);
  assert.deepEqual(owner.indexSizes(), { mono: 0, wall: 0, caller: 0, hardStop: 0 });
  assert.equal(controller.snapshot().bytes, 0);
  assert.equal(controller.snapshot().shared, 4);
});

test("a close fences a selected waiter and drains boundedly without releasing open leases", () => {
  const state = setup();
  const { controller, owner, submit } = state;
  const active = Array.from({ length: 4 }, () => submit("home"));
  const waiting = [submit("home").attempt, submit("home").attempt];
  const pendingPreparation = owner.begin()!;
  const first = active[0].status;
  assert.equal(first.kind, "granted");
  assert.equal(owner.settle(first.lease, owner.executionFor(first.lease)!, "terminal"), true);
  // Four expiry/root inspections and one reserved inspection per BA0 class precede the shared selection.
  for (let i = 0; i < 8; i++) assert.equal(owner.advance(1), 1);
  owner.close();
  assert.equal(owner.begin(), undefined);
  assert.equal(controller.snapshot().queued, 2);
  assert.equal(controller.snapshot().leases, 3);
  drain(state);
  for (const attempt of [...waiting, pendingPreparation]) {
    assert.deepEqual(controller.attemptStatus(attempt), { kind: "cancelled", reason: "controller-closed" });
  }
  assert.equal(owner.finishPreparation(pendingPreparation), true);
  assert.equal(controller.snapshot().leases, 3);
  assert.equal(controller.snapshot().bytes, 0);
  assert.throws(() => owner.advance(257), RangeError);
});

test("only the owning execution can settle and an ambiguous stop uses the lower time bound", () => {
  const state = setup();
  const { owner, controller, submit } = state;
  const first = submit("inquiry-form");
  const second = submit("inquiry-form");
  assert.equal(first.status.kind, "granted");
  assert.equal(second.status.kind, "granted");
  const lease = first.status.lease;
  const execution = owner.executionFor(lease)!;
  assert.equal(controller.cancel(first.attempt), false);
  assert.equal(owner.settle(lease, owner.executionFor(second.status.lease)!, "terminal"), false);
  assert.equal(setup().owner.settle(lease, execution, "terminal"), false);
  assert.equal(owner.settle(lease, execution, "ambiguous", 25.5), true);
  assert.equal(owner.settle(lease, execution, "terminal"), false);
  assert.equal(owner.settle(lease, execution, "ambiguous", 0), false);
  assert.equal(owner.observeTime(25.25, 25.5, 1025.5), true);
  drain(state);
  assert.equal(controller.leaseState(lease), "ambiguous-held");
  assert.equal(owner.observeTime(25.5, 25.5, 1025.5), true);
  drain(state);
  assert.equal(owner.settle(lease, execution, "verified-termination"), false);
  assert.equal(controller.leaseState(lease), "settled");
  assert.equal(controller.snapshot().reserved, 1);
});

test("forward observations survive partial expiry sweeps and rollback", () => {
  const state = setup();
  const { owner, controller, submit } = state;
  for (let i = 0; i < 4; i++) submit("home");
  const waiting = [submit("home").attempt, submit("home").attempt];
  assert.equal(owner.observeTime(1, 1, 1250), true);
  assert.equal(owner.advance(3), 3);
  assert.equal(owner.observeTime(2, 2, 1000), true);
  drain(state);
  for (const attempt of waiting) {
    assert.deepEqual(controller.attemptStatus(attempt), { kind: "expired", reason: "proof-expired" });
  }
  assert.equal(controller.snapshot().bytes, 0);
});

test("weighted requests fit one pool and queued bytes are checked independently of entry counts", () => {
  const { submit, controller } = setup();
  const active = Array.from({ length: 3 }, () => submit("submit-inquiry", 32768).status);
  assert.deepEqual(active.map((status) => status.kind === "granted" && status.pool), ["reserved", "shared", "shared"]);
  assert.deepEqual(submit("submit-inquiry", 32768).status, { kind: "queued", bytes: 34816 });
  assert.deepEqual(submit("submit-inquiry", 32768).status, { kind: "rejected", reason: "queue-bytes-exceeded" });
  const { reserved, shared, queued, bytes } = controller.snapshot();
  assert.deepEqual({ reserved, shared, queued, bytes }, { reserved: 2, shared: 4, queued: 1, bytes: 34816 });
});

test("preparation permits bound interrupted work, and transition inputs do not invoke getters", () => {
  const { owner, controller } = setup();
  const attempts = Array.from({ length: 32 }, () => owner.begin()!);
  assert.ok(attempts.every(Boolean));
  assert.equal(owner.begin(), undefined);
  for (const attempt of attempts) assert.equal(controller.cancel(attempt), true);
  assert.equal(owner.begin(), undefined);
  for (const attempt of attempts) assert.equal(owner.finishPreparation(attempt), true);

  const hostile = new Proxy({}, { get() { assert.fail("caller property read"); } });
  assert.equal(controller.cancel(hostile as CapacityAttempt), false);
  assert.equal(controller.leaseState(hostile as CapacityLease), undefined);
  const attempt = owner.begin()!;
  assert.equal(owner.bind(attempt, "home", 0, 180, 1350, hostile as number), false);
  assert.equal(owner.finishPreparation(attempt), true);
  assert.equal(controller.snapshot().preparationSlots, 0);
});

function release(state: ReturnType<typeof setup>, attempt: CapacityAttempt) {
  const status = state.controller.attemptStatus(attempt);
  assert.ok(status?.kind === "granted");
  assert.equal(state.owner.settle(status.lease, state.owner.executionFor(status.lease)!, "terminal"), true);
}

test("budget-one grant, expiry, and close progress across changing clock observations", () => {
  for (const mode of ["grant", "expire", "close"] as const) {
    const state = setup();
    const active = Array.from({ length: 4 }, () => state.submit("home"));
    const waiting = state.submit("home", 0, mode === "expire" ? 1 : 180).attempt;
    if (mode === "grant") release(state, active[0].attempt);
    if (mode === "close") state.owner.close();
    let steps = 0;
    while (state.controller.attemptStatus(waiting)?.kind === "queued" && steps < 64) {
      const now = ++steps / 16;
      assert.equal(state.owner.observeTime(now, now, 1000 + now), true);
      const pending = state.controller.hasPendingMaintenance();
      assert.equal(state.owner.advance(1), Number(pending));
    }
    const expected = { grant: "granted", expire: "expired", close: "cancelled" };
    assert.equal(state.controller.attemptStatus(waiting)?.kind, expected[mode]);
    assert.equal(state.controller.snapshot().queued, 0);
  }
});

test("a grant selected before expiry spends a work unit and cannot charge an expired waiter", () => {
  const state = setup();
  const active = Array.from({ length: 4 }, () => state.submit("home"));
  const waiting = state.submit("home", 0, 2).attempt;
  release(state, active[0].attempt);
  for (let i = 0; i < 8; i++) assert.equal(state.owner.advance(1), 1);
  assert.equal(state.owner.observeTime(2, 2, 1002), true);
  assert.equal(state.owner.advance(1), 1);
  assert.equal(state.controller.attemptStatus(waiting)?.kind, "queued");
  assert.equal(state.controller.snapshot().shared, 3);
  drain(state);
  assert.deepEqual(state.controller.attemptStatus(waiting), { kind: "expired", reason: "proof-expired" });
});

test("a mixed-weight shared grant exposes the next FIFO head to its reservation", () => {
  const state = setup("ba0-mixed");
  const model = new OriginCapacityModel(state.policy.manifest);
  const ops = ["submit-light", "submit-inquiry", "submit-inquiry", "submit-inquiry", "submit-light"];
  const attempts = ops.map((op, index) => {
    model.admit(index, op, 0);
    const { attempt } = state.submit(op);
    assert.deepEqual(state.controller.snapshot(), model.snapshot());
    return attempt;
  });
  release(state, attempts[1]);
  assert.equal(model.settle(1, "terminal"), true);
  assert.deepEqual(state.controller.snapshot(), model.snapshot());

  let used = 0;
  while (state.controller.attemptStatus(attempts[3])?.kind === "queued") {
    assert.equal(state.owner.advance(1), 1);
    assert.ok(++used < 64);
  }
  assert.equal(model.dispatchOne(), true);
  assert.equal(model.rows.get(3)?.pool, "shared");
  assert.equal(model.hasEligibleHead(), true);
  assert.equal(state.controller.attemptStatus(attempts[4])?.kind, "queued");
  assert.deepEqual(state.controller.snapshot(), model.snapshot());

  drain(state);
  model.drain();
  assert.equal(model.hasEligibleHead(), false);
  const tail = state.controller.attemptStatus(attempts[4]);
  assert.ok(tail?.kind === "granted");
  assert.equal(tail.pool, "reserved");
  assert.deepEqual(state.controller.snapshot(), model.snapshot());
});

test("unsafe timestamps fail closed and fractional caller equality stays exact on both grant paths", () => {
  const unsafe = setup();
  const deadline = 2 ** 56;
  const roundedCutoff = deadline - 100 - 2500;
  assert.equal(BigInt(roundedCutoff) + 2600n - BigInt(deadline), 8n);
  assert.equal(unsafe.owner.observeTime(roundedCutoff, roundedCutoff, 1000), false);
  const attempt = unsafe.owner.begin()!;
  assert.equal(unsafe.owner.bind(attempt, "home", 0, deadline, 1350, deadline), false);
  assert.deepEqual(unsafe.owner.admit(attempt), { kind: "rejected", reason: "deadline-invalid" });

  const max = 2 ** 42;
  const tick = 1 / 1024;
  const caller = max - 10 + tick;
  const cutoff = caller - 2600;
  for (const queued of [false, true]) {
    for (const delta of [-tick, 0, tick]) {
      const state = setup();
      const start = cutoff - 2;
      assert.equal(state.owner.observeTime(start, start, 1000), true);
      let target: CapacityAttempt;
      if (queued) {
        const active = Array.from({ length: 4 }, () => state.submit("home", 0, max, 1350, max));
        target = state.submit("home", 0, max, 1350, caller).attempt;
        assert.equal(state.controller.attemptStatus(target)?.kind, "queued");
        release(state, active[0].attempt);
      } else {
        target = state.owner.begin()!;
        assert.equal(state.owner.bind(target, "home", 0, max, 1350, caller), true);
      }
      assert.equal(state.owner.observeTime(cutoff + delta, cutoff + delta, 1000), true);
      if (queued) drain(state);
      else state.owner.admit(target);
      assert.equal(state.controller.attemptStatus(target)?.kind, delta > 0 ? "expired" : "granted");
    }
  }
  assert.equal(unsafe.owner.observeTime(max, max, 1000), true);
  assert.equal(unsafe.owner.observeTime(max + tick, max + tick, 1000), false);
});

test("Stage 1 seeded command traces agree with a recomputing list model", () => {
  for (const fixtureName of ["ba0", "storefront"]) {
    for (let seed = 1; seed <= 16; seed++) {
      const state = setup(fixtureName);
      const { owner, controller } = state;
      const model = new OriginCapacityModel(state.policy.manifest);
      const attempts = new Map<number, CapacityAttempt>();
      let random = seed;
      let time = 0;
      for (let command = 0; command < 96; command++) {
        random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
        const operation = state.policy.manifest.operations[(random >>> 16) % state.policy.manifest.operations.length];
        const which = (random >>> 8) % Math.max(1, command);
        const handle = attempts.get(which);
        const value = handle && controller.attemptStatus(handle);
        const action = random % 16;
        if (action < 9 && !model.closed) {
          const body = operation.body ? (random >>> 16) % operation.body.maxBytes : 0;
          const { attempt } = state.submit(operation.id, body);
          attempts.set(command, attempt);
          model.admit(command, operation.id, body);
        } else if (action === 9 && handle) {
          assert.equal(controller.cancel(handle), model.cancel(which));
        } else if (action >= 10 && action <= 12 && value?.kind === "granted") {
          const kind = action === 10 ? "terminal" : action === 11 ? "ambiguous" : "verified-termination";
          const hardStop = action === 11 ? time + 12 : undefined;
          assert.equal(owner.settle(value.lease, owner.executionFor(value.lease)!, kind, hardStop), model.settle(which, kind, hardStop));
        } else if (action === 13) {
          time += 3;
          assert.equal(owner.observeTime(time, time, 1000 + time), true);
          model.observe(time, time, 1000 + time);
        } else if (action === 14 && command > 90) {
          owner.close();
          model.closed = true;
        } else if (action === 15) {
          drain(state);
          model.drain();
          assert.equal(model.hasEligibleHead(), false);
          assert.equal(controller.hasPendingMaintenance(), false);
        }
        const label = fixtureName + " seed " + seed + " command " + command;
        assert.deepEqual(controller.snapshot(), model.snapshot(), label);
        const { queued } = model.snapshot();
        assert.deepEqual(owner.indexSizes(), {
          mono: queued, wall: queued, caller: queued,
          hardStop: [...model.rows.values()].filter((row) => row.lease === "ambiguous-held" && row.hardStop !== undefined).length,
        }, label);
        for (const [id, attempt] of attempts) {
          const actual = controller.attemptStatus(attempt);
          const expected = model.rows.get(id)!;
          assert.equal(actual?.kind, expected.state, label);
          if (actual?.kind === "granted") {
            assert.equal(actual.pool, expected.pool, label);
            assert.equal(controller.leaseState(actual.lease), expected.lease, label);
          }
        }
      }
    }
  }
});

