import assert from "node:assert/strict";
import { test } from "node:test";
import { ClockFence, ReplayGuard } from "../defense/core/replay-guard";

function rig(capacity = 4) {
  let now = 1_000;
  const guard = new ReplayGuard(capacity, () => now);
  return { guard, advance: (ms: number) => { now += ms; }, now: () => now };
}
const key = (index: number) => `pb:${String(index).padStart(22, "x")}`;
const want = (index: number, retainMs = 8_000) => ({ key: key(index), retainMs });

test("an id moves UNSEEN -> RESERVED -> COMMITTED, and after commit it is a replay", () => {
  const { guard } = rig();
  assert.equal(guard.stateOf(key(1)), "UNSEEN");
  const first = guard.reserve([want(1)]);
  assert.ok(first.ok);
  assert.equal(guard.stateOf(key(1)), "RESERVED");
  assert.equal(guard.stats().open, 1);
  first.ticket.commit();
  assert.equal(guard.stateOf(key(1)), "COMMITTED");
  assert.deepEqual(guard.reserve([want(1)]), { ok: false, reason: "replayed" });
  assert.deepEqual({ reserved: guard.stats().reserved, committed: guard.stats().committed, burned: guard.stats().burned, open: guard.stats().open }, { reserved: 1, committed: 1, burned: 0, open: 0 });
});

test("an id moves UNSEEN -> RESERVED -> BURNED, and a burned id is never reusable until its retention ends", () => {
  const { guard, advance } = rig();
  const reserved = guard.reserve([want(1)]);
  assert.ok(reserved.ok);
  reserved.ticket.burn();
  assert.equal(guard.stateOf(key(1)), "BURNED");
  assert.deepEqual(guard.reserve([want(1)]), { ok: false, reason: "replayed" });
  advance(7_999);
  assert.deepEqual(guard.reserve([want(1)]), { ok: false, reason: "replayed" }, "still burned just before retention ends");
  advance(300); // past the retention AND past the 250 ms purge throttle
  guard.reserve([want(99)]);
  assert.equal(guard.stateOf(key(1)), "UNSEEN", "only after its retention elapsed is the entry purged");
});

test("while RESERVED the id is already a replay for every concurrent presenter (the reservation is the lock)", () => {
  const { guard } = rig();
  const winner = guard.reserve([want(1)]);
  assert.ok(winner.ok);
  for (let index = 0; index < 8; index++) assert.deepEqual(guard.reserve([want(1)]), { ok: false, reason: "replayed" });
  assert.equal(guard.stats().replayRejected, 8);
  assert.equal(guard.stats().reserved, 1);
});

test("reserve is synchronous: it returns a result, never a promise, so no await can separate the lookup from the insert", () => {
  const { guard } = rig();
  const result = guard.reserve([want(1)]);
  assert.equal(result instanceof Promise, false);
  assert.notEqual(guard.reserve.constructor.name, "AsyncFunction");
});

test("a second transition on a ticket is a counted violation and never releases the id", () => {
  const { guard } = rig();
  const reserved = guard.reserve([want(1)]);
  assert.ok(reserved.ok);
  reserved.ticket.commit();
  reserved.ticket.burn();
  assert.equal(guard.stats().stateViolations, 1);
  assert.equal(guard.stateOf(key(1)), "BURNED", "a double transition burns, it never frees");
  assert.deepEqual(guard.reserve([want(1)]), { ok: false, reason: "replayed" });
});

test("reserving several ids is all-or-nothing: a replayed member creates nothing for the others", () => {
  const { guard } = rig();
  const first = guard.reserve([want(1)]);
  assert.ok(first.ok);
  first.ticket.commit();
  const blocked = guard.reserve([want(2), want(1), want(3)]);
  assert.deepEqual(blocked, { ok: false, reason: "replayed" });
  assert.equal(guard.stateOf(key(2)), "UNSEEN");
  assert.equal(guard.stateOf(key(3)), "UNSEEN");
  assert.deepEqual(guard.reserve([want(4), want(4)]), { ok: false, reason: "replayed" }, "the same id twice in one request is a replay too");
  assert.equal(guard.stateOf(key(4)), "UNSEEN");
});

test("capacity fails closed and NO unexpired entry is ever evicted to make room", () => {
  const { guard, advance } = rig(3);
  for (let index = 1; index <= 3; index++) { const reserved = guard.reserve([want(index)]); assert.ok(reserved.ok); reserved.ticket.commit(); }
  assert.equal(guard.stats().size, 3);
  assert.deepEqual(guard.reserve([want(4)]), { ok: false, reason: "full" });
  assert.equal(guard.stateOf(key(4)), "UNSEEN", "a full set creates nothing");
  assert.equal(guard.stats().capacityRejected, 1);
  for (let index = 1; index <= 3; index++) assert.equal(guard.stateOf(key(index)), "COMMITTED", `entry ${index} survived the exhaustion`);
  assert.deepEqual(guard.reserve([want(1)]), { ok: false, reason: "replayed" }, "an earlier id is still a replay, not a free slot");
  // an in-flight RESERVED entry is never purged even past its retention
  advance(60_000);
  const reservedAfter = guard.reserve([want(5)]);
  assert.ok(reservedAfter.ok, "expired entries are purged and the set accepts again");
  assert.equal(guard.stateOf(key(1)), "UNSEEN");
});

test("a RESERVED entry is never purged, even after its retention, until it settles", () => {
  const { guard, advance } = rig(2);
  const inFlight = guard.reserve([want(1, 100)]);
  assert.ok(inFlight.ok);
  advance(10_000);
  guard.reserve([want(2)]);
  assert.equal(guard.stateOf(key(1)), "RESERVED");
  assert.deepEqual(guard.reserve([want(1)]), { ok: false, reason: "replayed" });
});

test("entries with different retention coexist and purge independently of insertion order", () => {
  const { guard, advance } = rig(8);
  const long = guard.reserve([{ key: "pb:long", retainMs: 8_000 }]);
  const short = guard.reserve([{ key: "ba:short", retainMs: 5_000 }]);
  assert.ok(long.ok && short.ok);
  long.ticket.commit(); short.ticket.commit();
  advance(6_000);
  guard.reserve([want(9)]);
  assert.equal(guard.stateOf("ba:short"), "UNSEEN", "the shorter-lived entry expired even though it was inserted later");
  assert.equal(guard.stateOf("pb:long"), "COMMITTED", "the longer-lived one is untouched");
});

test("constructing a guard with a non-positive capacity is refused", () => {
  for (const bad of [0, -1, 1.5, Number.NaN]) assert.throws(() => new ReplayGuard(bad, () => 0));
});

test("the verifier-start fence is the verifier's own start, and a wall-clock step against the monotonic clock is detected", () => {
  let wall = 1_700_000_000_000;
  let mono = 500;
  const fence = new ClockFence(() => wall, () => mono);
  assert.equal(fence.fenceMs, 1_700_000_000_000);
  assert.equal(fence.stepDetected(), false);
  wall += 5_000; mono += 5_000;
  assert.equal(fence.stepDetected(), false, "time passing is not a step");
  wall += 251;
  assert.equal(fence.stepDetected(), true, "the wall clock moved relative to the monotonic clock");
  assert.equal(fence.stepMs(), 251);
  wall -= 600;
  assert.equal(fence.stepDetected(), true, "a backward step is detected too");
});
