import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import type { LaneDecision } from "../defense/core/lanes";
import type { LayerOutcome, LayerRequest } from "../defense/core/types";
import { CollapseOverride, MAX_OUTSTANDING_ARMS, armTagOf, fixtureDigestOf, type ArmSpec } from "../lab/defense/collapse/override";

const NONCE = "N".repeat(22);
const request = (overrides: Partial<LayerRequest> = {}): LayerRequest => ({ method: "POST", target: "/api/public-inquiries", headers: [], bodyStatus: "complete", body: Buffer.from("evil=1"), ...overrides });
const reject: LayerOutcome = { kind: "reject", reason: "a7.form_field_not_allowed" };
const spec = (overrides: Partial<ArmSpec> = {}, req: LayerRequest = request()): ArmSpec => ({
  armId: randomBytes(16).toString("base64url"), layer: "l1", nonce: NONCE, fixtureDigest: fixtureDigestOf(req), remotePort: 54_321, ttlMs: 5_000, ...overrides,
});
const ctx = (overrides: { request?: LayerRequest; nonce?: string; remotePort?: number | undefined } = {}) => ({ request: request(), nonce: NONCE, remotePort: 54_321 as number | undefined, ...overrides });

test("an armed L1 override delivers a pass for exactly the armed request, records the layer's real verdict as the shadow, and is one-shot", () => {
  const override = new CollapseOverride();
  assert.equal(override.arm(spec()), true);
  assert.deepEqual(override.l1({ ...ctx(), outcome: reject }), { shadow: "reject:a7.form_field_not_allowed" });
  assert.equal(override.l1({ ...ctx(), outcome: reject }), null, "consumed: a second identical request is not forced");
  const stats = override.stats();
  assert.deepEqual([stats.armed, stats.consumed, stats.outstanding, stats.expired], [1, 1, 0, 0]);
  assert.equal(stats.applied.length, 1);
});

test("a match needs the nonce, the connection AND the exact fixture bytes: any one differing leaves the verdict alone", () => {
  const override = new CollapseOverride();
  override.arm(spec());
  assert.equal(override.l1({ ...ctx({ nonce: "M".repeat(22) }), outcome: reject }), null, "a different nonce");
  assert.equal(override.l1({ ...ctx({ remotePort: 54_322 }), outcome: reject }), null, "a different connection");
  assert.equal(override.l1({ ...ctx({ request: request({ body: Buffer.from("evil=2") }) }), outcome: reject }), null, "different body bytes");
  assert.equal(override.l1({ ...ctx({ request: request({ target: "/other" }) }), outcome: reject }), null, "a different target");
  assert.equal(override.l1({ ...ctx({ request: request({ method: "PUT" }) }), outcome: reject }), null, "a different method");
  assert.equal(override.l2({ ...ctx(), decision: { class: "mutation", lane: "unverified", outcome: "shed", shedReason: "lane_budget" } }), null, "an L1 arm never forces L2");
  assert.deepEqual(override.l1({ ...ctx(), outcome: reject }), { shadow: "reject:a7.form_field_not_allowed" }, "the exact request still matches: nothing above consumed it");
});

test("an uncorrelated request (empty nonce) or one with no remote port can never match, however an arm is shaped", () => {
  const override = new CollapseOverride();
  override.arm(spec());
  assert.equal(override.l1({ ...ctx({ nonce: "" }), outcome: reject }), null);
  assert.equal(override.l1({ ...ctx({ remotePort: undefined }), outcome: reject }), null);
  assert.equal(override.stats().consumed, 0);
});

test("the override only ever converts a REFUSAL: an L1 pass, shed or error is never touched", () => {
  const override = new CollapseOverride();
  override.arm(spec());
  for (const outcome of [{ kind: "pass" }, { kind: "shed" }, { kind: "error", errorKind: "throw" }] as LayerOutcome[]) assert.equal(override.l1({ ...ctx(), outcome }), null, outcome.kind);
  assert.equal(override.stats().consumed, 0);
});

test("an L2 arm labels both a shed and an admit, with the shadow recording what L2 really decided; error and degraded are never overridden", () => {
  const override = new CollapseOverride();
  override.arm(spec({ layer: "l2" }));
  override.arm(spec({ layer: "l2", nonce: "Q".repeat(22), remotePort: 1 }));
  const shed: LaneDecision = { class: "mutation", lane: "unverified", outcome: "shed", shedReason: "lane_budget" };
  assert.deepEqual(override.l2({ ...ctx(), decision: shed }), { shadow: "shed:unverified:lane_budget" });
  const admit: LaneDecision = { class: "open", lane: "open", outcome: "admitted" };
  assert.deepEqual(override.l2({ ...ctx({ nonce: "Q".repeat(22), remotePort: 1 }), decision: admit }), { shadow: "admitted:open" });
  for (const decision of [{ class: "mutation", lane: null, outcome: "error", errorKind: "throw" }, { class: "open", lane: "open", outcome: "degraded" }] as LaneDecision[]) {
    assert.equal(override.l2({ ...ctx(), decision }), null, decision.outcome);
  }
});

test("arms expire, are capped, and a malformed arm is refused and counted: no arm exists unless the harness made a well-formed one", () => {
  const override = new CollapseOverride();
  override.arm(spec(), performance.now() - 20_000); // already past its expiry
  assert.equal(override.l1({ ...ctx(), outcome: reject }), null, "an expired arm never matches");
  assert.equal(override.stats().expired, 1);

  const capped = new CollapseOverride();
  for (let index = 0; index < MAX_OUTSTANDING_ARMS; index++) assert.equal(capped.arm(spec({ nonce: String(index).padStart(22, "A") })), true);
  assert.equal(capped.arm(spec()), false, "the outstanding-arm cap");

  const strict = new CollapseOverride();
  for (const bad of [spec({ nonce: "short" }), spec({ fixtureDigest: "zz" }), spec({ remotePort: 0 }), spec({ ttlMs: 60_000 }), spec({ armId: "x" })]) assert.equal(strict.arm(bad), false);
  const duplicate = spec();
  assert.equal(strict.arm(duplicate), true);
  assert.equal(strict.arm(duplicate), false, "an arm id is never reused");
  assert.equal(strict.stats().refused, 6);
});

test("the fixture digest is a pure function of method, target and body, and the arm tag in evidence is a short hash, never the id", () => {
  const base = fixtureDigestOf(request());
  assert.match(base, /^[0-9a-f]{64}$/);
  assert.equal(base, fixtureDigestOf(request()));
  for (const changed of [request({ method: "GET" }), request({ target: "/x" }), request({ body: Buffer.from("evil=2") }), request({ body: null })]) assert.notEqual(fixtureDigestOf(changed), base);
  const armId = randomBytes(16).toString("base64url");
  assert.match(armTagOf(armId), /^[0-9a-f]{8}$/);
  assert.equal(armTagOf(armId).includes(armId.slice(0, 6)), false);
});
