import assert from "node:assert/strict";
import { test } from "node:test";
import { LayerComposer } from "../defense/core/composer";
import type { Layer, LayerRequest, LayerVerdict } from "../defense/core/types";
import { FAILURE_POLICIES, RESERVED_OUTCOMES } from "../defense/core/types";

const request: LayerRequest = { method: "GET", target: "/", headers: [["host", "127.0.0.1:1"]], bodyStatus: "none", body: null };
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const layer = (evaluate: (r: LayerRequest) => LayerVerdict | Promise<LayerVerdict>): Layer => ({ id: "a7.shape-gate", evaluate });
const options = { timeoutMs: 40, maxConcurrent: 4, failurePolicy: "fail_closed" as const };

test("a pass and a reject come back as explicit outcomes", async () => {
  const pass = new LayerComposer(layer(() => ({ kind: "pass" })), options);
  assert.deepEqual(await pass.run(request), { kind: "pass" });
  const reject = new LayerComposer(layer(() => ({ kind: "reject", reason: "a7.path_not_allowed" })), options);
  assert.deepEqual(await reject.run(request), { kind: "reject", reason: "a7.path_not_allowed" });
});

test("an injected throw (sync or async) is an explicit error and NEVER a pass: fail closed", async () => {
  const sync = new LayerComposer(layer(() => { throw new Error("boom"); }), options);
  assert.deepEqual(await sync.run(request), { kind: "error", errorKind: "throw" });
  const asyncThrow = new LayerComposer(layer(async () => { throw new Error("boom"); }), options);
  assert.deepEqual(await asyncThrow.run(request), { kind: "error", errorKind: "throw" });
  assert.equal(sync.stats().pass, 0);
  assert.equal(asyncThrow.stats().pass, 0);
});

test("a malformed verdict is an error, not a pass", async () => {
  for (const bad of [undefined, null, "pass", { kind: "degraded" }, { kind: "reject", reason: "not-in-the-enum" }, { kind: "reject" }, { kind: "error" }]) {
    const composer = new LayerComposer(layer(() => bad as unknown as LayerVerdict), options);
    assert.deepEqual(await composer.run(request), { kind: "error", errorKind: "invalid_verdict" }, JSON.stringify(bad));
  }
});

test("a hung layer becomes an explicit timeout error within its deadline", async () => {
  const composer = new LayerComposer(layer(() => new Promise<LayerVerdict>(() => undefined)), options);
  const started = performance.now();
  assert.deepEqual(await composer.run(request), { kind: "error", errorKind: "timeout" });
  assert.ok(performance.now() - started < 400);
});

test("a late async verdict after the deadline is discarded, not used", async () => {
  const composer = new LayerComposer(layer(async () => { await sleep(120); return { kind: "pass" }; }), options);
  assert.deepEqual(await composer.run(request), { kind: "error", errorKind: "timeout" });
  await sleep(150);
  assert.equal(composer.stats().pass, 0);
});

test("LIMITATION: the timeout does not interrupt synchronous CPU work; a late synchronous verdict is discarded, not preempted", async () => {
  const composer = new LayerComposer(layer(() => { const end = performance.now() + 80; while (performance.now() < end) { /* spin: nothing can interrupt this */ } return { kind: "pass" }; }), options);
  const started = performance.now();
  const outcome = await composer.run(request);
  assert.ok(performance.now() - started >= 79, "the spin ran to completion: the timeout cannot preempt it");
  assert.deepEqual(outcome, { kind: "error", errorKind: "timeout" }, "but its late verdict is never used");
  assert.equal(composer.stats().lateVerdictsDiscarded, 1);
});

test("saturation is shed explicitly (bulkhead), and every call returns exactly one outcome", async () => {
  const composer = new LayerComposer(layer(() => new Promise<LayerVerdict>(() => undefined)), { ...options, timeoutMs: 80, maxConcurrent: 2 });
  const outcomes = await Promise.all(Array.from({ length: 6 }, () => composer.run(request)));
  const shed = outcomes.filter((outcome) => outcome.kind === "shed").length;
  const timeouts = outcomes.filter((outcome) => outcome.kind === "error").length;
  assert.equal(shed, 4);
  assert.equal(timeouts, 2);
  assert.equal(outcomes.length, 6);
  const stats = composer.stats();
  assert.equal(stats.evaluated, stats.shed + stats.pass + stats.reject + stats.error.throw + stats.error.timeout + stats.error.invalid_verdict, "no evaluation is unaccounted for");
});

test("an abandoned (timed-out, unsettled) evaluation keeps occupying the bulkhead until it settles or is reclaimed", async () => {
  let release: (() => void) | null = null;
  const composer = new LayerComposer(layer(() => new Promise<LayerVerdict>((resolve) => { release = () => resolve({ kind: "pass" }); })), { timeoutMs: 20, maxConcurrent: 1, failurePolicy: "fail_closed", reclaimAfterMs: 200 });
  assert.deepEqual(await composer.run(request), { kind: "error", errorKind: "timeout" });
  assert.equal(composer.occupancy, 1, "still counted although it timed out");
  assert.deepEqual(await composer.run(request), { kind: "shed" });
  release!();
  await sleep(10);
  assert.equal(composer.occupancy, 0, "settling frees the slot");
  const hung = new LayerComposer(layer(() => new Promise<LayerVerdict>(() => undefined)), { timeoutMs: 20, maxConcurrent: 1, failurePolicy: "fail_closed", reclaimAfterMs: 60 });
  await hung.run(request);
  assert.equal(hung.occupancy, 1);
  await sleep(120);
  assert.equal(hung.occupancy, 0, "a never-settling evaluation is reclaimed after the reclaim window");
  assert.equal(hung.stats().abandonedReclaimed, 1);
});

test("there is exactly one failure policy and no configuration turns an error into a pass", () => {
  assert.deepEqual([...FAILURE_POLICIES], ["fail_closed"]);
  for (const policy of ["fail_open", "error_failopen", "quarantine", "degraded", "pass", ""]) {
    assert.throws(() => new LayerComposer(layer(() => ({ kind: "pass" })), { ...options, failurePolicy: policy as "fail_closed" }), /fail_closed/, policy);
  }
  // A degraded outcome is RESERVED for a later slice; it is not an outcome kind the composer can produce.
  assert.deepEqual([...RESERVED_OUTCOMES], ["degraded"]);
});

test("mixed concurrent faults never produce an unexplained disappearance", async () => {
  let index = 0;
  const composer = new LayerComposer(layer(() => {
    const mode = index++ % 5;
    if (mode === 0) return { kind: "pass" };
    if (mode === 1) return { kind: "reject", reason: "a7.body_too_large" };
    if (mode === 2) throw new Error("x");
    if (mode === 3) return new Promise<LayerVerdict>(() => undefined);
    return Promise.resolve({ kind: "pass" } as LayerVerdict);
  }), { timeoutMs: 30, maxConcurrent: 8, failurePolicy: "fail_closed" });
  const outcomes = await Promise.all(Array.from({ length: 60 }, () => composer.run(request)));
  assert.equal(outcomes.length, 60);
  for (const outcome of outcomes) assert.ok(["pass", "reject", "shed", "error"].includes(outcome.kind));
  const stats = composer.stats();
  assert.equal(stats.evaluated, 60);
  assert.equal(stats.pass + stats.reject + stats.shed + stats.error.throw + stats.error.timeout + stats.error.invalid_verdict, 60);
});
