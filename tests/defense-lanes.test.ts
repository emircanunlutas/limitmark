import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import {
  JourneyLanes, L2_ERROR_KINDS, TokenBucket, UNIT, UseLedger, creditTagOf, extractSubmissionToken, failureDecision, isValidDecision, operationClassOf,
  proceeds, requiredLedgerCapacity, type L2Failure, type LaneDecision, type LanesConfig, type OperationClass,
} from "../defense/core/lanes";
import { FORM_ROUTE_TARGETS } from "../defense/core/enrollment";
import type { LayerRequest } from "../defense/core/types";

const root = path.join(__dirname, "..");
const code = (file: string) => readFileSync(path.join(root, file), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
const token = () => randomBytes(32).toString("base64url");

const post = (body: string): LayerRequest => ({ method: "POST", target: "/api/public-inquiries", headers: [], bodyStatus: "complete", body: Buffer.from(body, "latin1") });
const postToken = (value: string) => post(`name=A&email=a%40b.co&service=web&submissionToken=${value}`);
const get = (target: string): LayerRequest => ({ method: "GET", target, headers: [], bodyStatus: "none", body: null });

function rig(overrides: Partial<LanesConfig> = {}) {
  let now = 10_000;
  const config: LanesConfig = {
    filterBits: 2 ** 14, filterHashes: 7, epochMs: 2000, credited: { capacity: 8, refillPerSecond: 4 }, unverified: { capacity: 3, refillPerSecond: 0.5 },
    maxUses: 3, ledgerCapacity: 64, mono: () => now, key: Buffer.alloc(32, 9), ...overrides,
  };
  const lanes = new JourneyLanes(config);
  return { lanes, config, tick: (ms: number) => { now += ms; }, now: () => now };
}
/** Enrolls a genuine token the way the plane does after a delivered render. */
const enroll = (lanes: JourneyLanes) => { const value = token(); const result = lanes.enroll(value); assert.equal(result.ok, true); return value; };
const summary = (d: LaneDecision) => `${d.class}/${d.lane}/${d.outcome}${d.shedReason ? `/${d.shedReason}` : ""}`;

test("the class map is exact and rejects nothing: unrecognised requests are `unknown`, not refused", () => {
  assert.equal(operationClassOf("GET", "/"), "open");
  assert.equal(operationClassOf("GET", "/gizlilik"), "open");
  assert.equal(operationClassOf("GET", "/test-talep-et/tesekkurler"), "open");
  for (const target of FORM_ROUTE_TARGETS) assert.equal(operationClassOf("GET", target), "open");
  assert.equal(operationClassOf("POST", "/api/public-inquiries"), "mutation");
  for (const [method, target] of [["GET", "/admin"], ["POST", "/"], ["GET", "/api/public-inquiries"], ["POST", "/api/public-inquiries?x=1"], ["DELETE", "/"], ["GET", "/test-talep-et?hizmet=evil"]] as const) {
    assert.equal(operationClassOf(method, target), "unknown", `${method} ${target}`);
  }
});

test("an open request is admitted unconditionally and touches no state, whatever the lane and filter state", () => {
  const { lanes, tick } = rig();
  for (let i = 0; i < 200; i++) lanes.decide(postToken(token())); // drain the unverified bucket and more
  for (let i = 0; i < 5; i++) { tick(1); for (const target of ["/", "/gizlilik", "/test-talep-et/tesekkurler", ...FORM_ROUTE_TARGETS]) assert.deepEqual(lanes.decide(get(target)), { class: "open", lane: "open", outcome: "admitted" }); }
});

test("a fabricated token (well-formed, never enrolled) is unverified, never credited, and is bounded by the unverified bucket alone", () => {
  const { lanes } = rig();
  const outcomes = Array.from({ length: 10 }, () => summary(lanes.decide(postToken(token()))));
  assert.deepEqual(outcomes.slice(0, 3), Array(3).fill("mutation/unverified/admitted"));
  assert.deepEqual(outcomes.slice(3), Array(7).fill("mutation/unverified/shed/lane_budget"));
  assert.equal(lanes.snapshot().credited.takes, 0, "the credited bucket was never read");
});

test("a genuine token is credited, consumes one use per admission, and falls to the unverified lane after K", () => {
  const { lanes } = rig();
  const value = enroll(lanes);
  const seen = Array.from({ length: 5 }, () => lanes.decide(postToken(value)));
  assert.deepEqual(seen.map(summary), ["mutation/credited/admitted", "mutation/credited/admitted", "mutation/credited/admitted", "mutation/unverified/admitted", "mutation/unverified/admitted"]);
  assert.ok(seen[0].creditTag && seen[0].creditTag === seen[2].creditTag);
  assert.equal(seen[3].creditTag, undefined, "an exhausted token is not credited");
  assert.equal(lanes.snapshot().ledger.committedLive, 3);
});

test("P1: a credited request whose bucket is empty is SHED and never touches the unverified bucket; the reverse holds too", () => {
  const { lanes } = rig();
  const tokens = Array.from({ length: 10 }, () => enroll(lanes));
  const decisions = tokens.map((value) => lanes.decide(postToken(value)));
  assert.deepEqual(decisions.slice(0, 8).map(summary), Array(8).fill("mutation/credited/admitted"));
  assert.deepEqual(decisions.slice(8).map(summary), Array(2).fill("mutation/credited/shed/lane_budget"));
  const unverifiedBefore = lanes.snapshot().unverified;
  assert.equal(unverifiedBefore.takes, 0, "no credited shed fell through to the unverified bucket");
  assert.equal(unverifiedBefore.levelUnits, 3 * UNIT);
  // reverse: drain unverified, credited is untouched and still full minus what was used
  const credBefore = lanes.snapshot().credited;
  for (let i = 0; i < 20; i++) lanes.decide(postToken(token()));
  assert.deepEqual(lanes.snapshot().credited, credBefore, "unverified pressure never reads the credited bucket");
});

test("P1 property: over random interleavings each lane's admissions depend only on that lane's own arrivals", () => {
  for (let trial = 0; trial < 25; trial++) {
    const { lanes, tick } = rig({ epochMs: 600_000, ledgerCapacity: 5_000 });
    const genuine = Array.from({ length: 30 }, () => enroll(lanes));
    let creditedArrivals = 0; let unverifiedArrivals = 0; let creditedAdmitted = 0; let unverifiedAdmitted = 0;
    for (let step = 0; step < 120; step++) {
      tick(Math.floor(Math.random() * 400));
      if (Math.random() < 0.5 && creditedArrivals < genuine.length) { const d = lanes.decide(postToken(genuine[creditedArrivals++])); assert.equal(d.lane, "credited"); if (d.outcome === "admitted") creditedAdmitted++; }
      else { const d = lanes.decide(postToken(token())); unverifiedArrivals++; assert.equal(d.lane, "unverified"); if (d.outcome === "admitted") unverifiedAdmitted++; }
    }
    const snapshot = lanes.snapshot();
    assert.equal(snapshot.credited.takes, creditedArrivals);
    assert.equal(snapshot.unverified.takes, unverifiedArrivals);
    assert.equal(snapshot.credited.admitted, creditedAdmitted);
    assert.equal(snapshot.unverified.admitted, unverifiedAdmitted);
  }
});

test("the unknown class is quarantined with the unverified lane, never credited even with a genuine token in the body", () => {
  const { lanes } = rig();
  const value = enroll(lanes);
  const request: LayerRequest = { ...postToken(value), target: "/api/other" };
  assert.equal(summary(lanes.decide(request)), "unknown/unverified/admitted");
  assert.equal(lanes.snapshot().credited.takes, 0);
});

test("token extraction: exactly one well-formed, undecoded field, else no credit", () => {
  const value = token();
  assert.equal(extractSubmissionToken(postToken(value)), value);
  assert.equal(extractSubmissionToken(post(`submissionToken=${value}`)), value);
  assert.equal(extractSubmissionToken(post(`a=1&submissionToken=${value}&b=2`)), value);
  assert.equal(extractSubmissionToken(post(`submissionToken=${value}&submissionToken=${value}`)), null, "duplicated");
  assert.equal(extractSubmissionToken(post(`submissionToken=${value.slice(1)}`)), null, "short");
  assert.equal(extractSubmissionToken(post(`submissionToken=%41${value.slice(3)}`)), null, "encoded");
  assert.equal(extractSubmissionToken(post(`xsubmissionToken=${value}`)), null, "a different field name");
  assert.equal(extractSubmissionToken(post("")), null);
  assert.equal(extractSubmissionToken({ ...postToken(value), bodyStatus: "timeout", body: null }), null);
  assert.equal(extractSubmissionToken({ ...postToken(value), method: "GET" }), null);
  const big = post(`${"&".repeat(30_000)}submissionToken=${value}`);
  assert.equal(extractSubmissionToken(big), value, "linear in the body, no blow-up");
});

test("the bucket is exact integer arithmetic: capacity, refill, and no token ever comes back except by time", () => {
  let now = 0;
  const bucket = new TokenBucket(3, 0.5, () => now);
  assert.deepEqual([bucket.take().ok, bucket.take().ok, bucket.take().ok, bucket.take().ok], [true, true, true, false]);
  now += 1999; assert.equal(bucket.take().ok, false, "just short of one token");
  now += 1; assert.equal(bucket.take().ok, true, "one token after exactly 2 s at 0.5/s");
  assert.equal(bucket.levelUnits(), 0);
  now += 1_000_000; assert.equal(bucket.levelUnits(), 3 * UNIT, "capped at capacity");
  assert.throws(() => new TokenBucket(0, 1, () => 0));
  assert.throws(() => new TokenBucket(1, 0.0001, () => 0));
});

test("P3: nothing in the mechanism can return a token or a use: no refund, rollback, release, reservation or decrement exists", () => {
  const source = code("defense/core/lanes.ts");
  assert.doesNotMatch(source, /refund|rollback|roll_back|release|reservation|watchdog|autoCommit|\w--|--\w|\.committed\s*-=|\.committed--|this\.level\s*\+=\s*UNIT/i);
  assert.equal((source.match(/\blevel\s*-=/g) ?? []).length, 1, "exactly one place lowers a bucket level: take()");
  for (const method of ["refund", "give", "returnToken", "rollback", "release", "undo"]) assert.equal((TokenBucket.prototype as unknown as Record<string, unknown>)[method], undefined, method);
  for (const method of ["refund", "decrement", "rollback", "release", "uncommit"]) assert.equal((UseLedger.prototype as unknown as Record<string, unknown>)[method], undefined, method);
  // Behaviourally: after any sequence of decisions the buckets and ledger only ever moved one way except for time.
  const { lanes, tick } = rig();
  const value = enroll(lanes);
  const before = lanes.snapshot();
  lanes.decide(postToken(value));
  const after = lanes.snapshot();
  assert.equal(after.credited.levelUnits, before.credited.levelUnits - UNIT);
  assert.equal(after.ledger.committedLive, 1);
  tick(0);
  assert.equal(lanes.snapshot().ledger.committedLive, 1, "a committed use is permanent");
});

test("P3: a shed consumes nothing (no use, no bucket token beyond the failed take) and an exhausted token consumes no credited token", () => {
  const { lanes } = rig();
  const drain = Array.from({ length: 8 }, () => enroll(lanes));
  for (const value of drain) lanes.decide(postToken(value));
  const extra = enroll(lanes);
  const shed = lanes.decide(postToken(extra));
  assert.equal(summary(shed), "mutation/credited/shed/lane_budget");
  assert.equal(lanes.snapshot().ledger.committedLive, 8, "the shed request did not consume a use");
  assert.equal(lanes.snapshot().ledger.size, 8, "and did not allocate a ledger record");
});

test("P2: a use record outlives every moment its token can still test positive; expiry never resets the K allowance", () => {
  const { lanes, tick, config } = rig({ epochMs: 1000, credited: { capacity: 8, refillPerSecond: 4 }, ledgerCapacity: 64 });
  const value = enroll(lanes); // enrolled in epoch 0
  tick(900); // still epoch 0; first credited admission here
  assert.equal(lanes.decide(postToken(value)).lane, "credited");
  tick(1000); // epoch 1: previous generation still holds it
  assert.equal(lanes.decide(postToken(value)).lane, "credited");
  assert.equal(lanes.decide(postToken(value)).lane, "credited");
  assert.equal(lanes.decide(postToken(value)).lane, "unverified", "K = 3 uses are spent");
  tick(300); // t = 2200: epoch 2 -> the genuine enrollment's generation is zeroed
  assert.equal(lanes.filter.has(lanes.filter.digest(value)), false, "membership is gone");
  assert.equal(lanes.decide(postToken(value)).lane, "unverified", "and so the token is simply unverified: the allowance was never reopened");
  // The ledger record for epoch-0 first use is purgeable from epoch 2 on, i.e. only after membership became impossible.
  assert.equal(config.maxUses, 3);
  tick(3000);
  lanes.decide(get("/")); // an open request does not touch it; a mutation advances the purge
  lanes.decide(postToken(token()));
  assert.equal(lanes.snapshot().ledger.size, 0);
});

test("P2: while membership is still possible the record is never purged, even when the ledger is under pressure", () => {
  const ledger = new UseLedger(2, 3);
  ledger.commit("a", 5);
  ledger.commit("b", 5);
  assert.equal(ledger.canAllocate(6), false, "full and nothing is aged out: refused, never evicted");
  assert.equal(ledger.committed("a", 6), 1, "still live at epoch firstEpoch+1");
  assert.equal(ledger.canAllocate(7), true, "epoch firstEpoch+2: aged out, so a slot can be reclaimed");
  assert.equal(ledger.committed("a", 7), undefined);
  assert.equal(ledger.snapshot().fullRefusals, 1);
});

test("a ledger that is full fails closed: the request is an L2 error, nothing is consumed", () => {
  const { lanes } = rig();
  const value = enroll(lanes);
  (lanes as unknown as { ledger: UseLedger }).ledger = new UseLedger(1, 3);
  const other = enroll(lanes);
  assert.equal(lanes.decide(postToken(other)).outcome, "admitted");
  const full = lanes.decide(postToken(value));
  assert.deepEqual(full, { class: "mutation", lane: null, outcome: "error", errorKind: "ledger_full" });
  assert.equal(lanes.snapshot().credited.takes, 1, "no bucket token was taken for the refused request");
});

test("the constructor refuses a ledger smaller than the credited-admission bound", () => {
  const needed = requiredLedgerCapacity(8, 4, 2000);
  assert.equal(needed, 8 + 16 + 1);
  assert.throws(() => rig({ ledgerCapacity: needed - 1 }), /below the credited-admission bound/);
  assert.doesNotThrow(() => rig({ ledgerCapacity: needed }));
});

test("the credited-admission bound holds: ledger records never exceed the derived capacity under sustained genuine traffic", () => {
  const { lanes, tick, config } = rig({ epochMs: 1000, ledgerCapacity: requiredLedgerCapacity(8, 4, 1000) });
  let peak = 0;
  for (let step = 0; step < 400; step++) {
    tick(50);
    const value = lanes.enroll(token()); assert.equal(value.ok, true);
    // every genuine token is used right away: the maximum credited admission rate the bucket allows
  }
  const genuine: string[] = [];
  for (let step = 0; step < 1000; step++) { tick(20); const value = token(); lanes.enroll(value); genuine.push(value); lanes.decide(postToken(value)); peak = Math.max(peak, lanes.snapshot().ledger.size); }
  assert.ok(peak <= config.ledgerCapacity, `peak ${peak} within ${config.ledgerCapacity}`);
  assert.equal(lanes.snapshot().ledger.fullRefusals, 0);
});

test("degraded ⊆ normal: only a class whose healthy decision is an unconditional admit may degrade; mutation and unknown never do", () => {
  const failures: L2Failure[] = ["saturation", "throw", "timeout", "invalid_verdict"];
  for (const cls of ["open", "mutation", "unknown"] as OperationClass[]) {
    for (const failure of failures) {
      const decision = failureDecision(cls, failure);
      assert.equal(isValidDecision(decision), true, `${cls}/${failure}`);
      if (cls === "open") assert.deepEqual(decision, { class: "open", lane: "open", outcome: "degraded" });
      else {
        assert.equal(proceeds(decision), false, `${cls}/${failure} must not proceed`);
        assert.equal(decision.lane, null);
        assert.equal(decision.outcome, failure === "saturation" ? "shed" : "error");
      }
    }
  }
  // degraded is reachable only where the healthy decision is unconditionally "admitted": prove it over random states
  for (let trial = 0; trial < 50; trial++) {
    const { lanes, tick } = rig();
    for (let i = 0; i < Math.floor(Math.random() * 100); i++) { tick(Math.floor(Math.random() * 300)); if (Math.random() < 0.5) lanes.enroll(token()); lanes.decide(postToken(token())); }
    for (const target of ["/", "/gizlilik", "/test-talep-et/tesekkurler", ...FORM_ROUTE_TARGETS]) assert.deepEqual(lanes.decide(get(target)), { class: "open", lane: "open", outcome: "admitted" });
  }
});

test("the (class, lane, outcome) validity matrix is closed", () => {
  const ok: LaneDecision[] = [
    { class: "open", lane: "open", outcome: "admitted" }, { class: "open", lane: "open", outcome: "degraded" },
    { class: "mutation", lane: "credited", outcome: "admitted" }, { class: "mutation", lane: "credited", outcome: "shed", shedReason: "lane_budget" },
    { class: "mutation", lane: "unverified", outcome: "admitted" }, { class: "unknown", lane: "unverified", outcome: "shed", shedReason: "lane_budget" },
    { class: "mutation", lane: null, outcome: "shed", shedReason: "evaluator_saturation" }, { class: "mutation", lane: null, outcome: "error", errorKind: "throw" },
  ];
  for (const decision of ok) assert.equal(isValidDecision(decision), true, summary(decision));
  const bad: LaneDecision[] = [
    { class: "open", lane: "credited", outcome: "admitted" }, { class: "open", lane: "open", outcome: "shed", shedReason: "lane_budget" }, { class: "open", lane: null, outcome: "error", errorKind: "throw" },
    { class: "mutation", lane: "open", outcome: "admitted" }, { class: "mutation", lane: "credited", outcome: "degraded" }, { class: "mutation", lane: "unverified", outcome: "error", errorKind: "throw" },
    { class: "mutation", lane: "credited", outcome: "shed" }, { class: "mutation", lane: "credited", outcome: "shed", shedReason: "evaluator_saturation" },
    { class: "mutation", lane: null, outcome: "admitted" }, { class: "mutation", lane: null, outcome: "degraded" }, { class: "mutation", lane: null, outcome: "error" },
  ];
  for (const decision of bad) assert.equal(isValidDecision(decision), false, summary(decision));
  assert.deepEqual([...L2_ERROR_KINDS], ["throw", "timeout", "invalid_verdict", "ledger_full"]);
});

test("enrollment never refreshes: a second enrollment of the same token is refused and changes nothing", () => {
  const { lanes, tick } = rig();
  const value = token();
  const first = lanes.enroll(value);
  assert.equal(first.ok, true);
  const popcount = lanes.snapshot().filter.popcount;
  tick(1500);
  assert.deepEqual(lanes.enroll(value), { ok: false, reason: "already_enrolled" });
  assert.deepEqual(lanes.snapshot().filter.popcount, popcount, "no bit was set by the refused enrollment");
  assert.equal(first.ok && first.creditTag, creditTagOf(lanes.filter.digest(value)));
});

test("repeated pressure → recovery → pressure → recovery returns every piece of state to its initial digest, with equivalent attenuation each cycle", () => {
  const { lanes, tick } = rig({ epochMs: 2000 });
  const initial = lanes.snapshot();
  const attenuation: number[] = [];
  for (let cycle = 0; cycle < 4; cycle++) {
    // pressure: a fabricated flood, genuine journeys, a token farmer, some enrollments
    let hostileAdmitted = 0; const hostileTotal = 200;
    for (let i = 0; i < hostileTotal; i++) { if (lanes.decide(postToken(token())).outcome === "admitted") hostileAdmitted++; if (i % 10 === 0) tick(5); }
    const journeys = Array.from({ length: 5 }, () => enroll(lanes));
    for (const value of journeys) assert.equal(lanes.decide(postToken(value)).outcome, "admitted");
    for (let i = 0; i < 20; i++) { const farmed = enroll(lanes); lanes.decide(postToken(farmed)); }
    for (let i = 0; i < 300; i++) lanes.enroll(token());
    attenuation.push(1 - hostileAdmitted / hostileTotal);
    assert.notEqual(lanes.snapshot().digest, initial.digest, "pressure really moved state");
    // recovery: idle for two epochs plus the slowest refill (3 tokens at 0.5/s = 6 s)
    tick(7000);
    const quiet = lanes.snapshot();
    assert.equal(quiet.digest, initial.digest, `cycle ${cycle}: quiescent digest equals the initial digest`);
    assert.equal(quiet.credited.levelUnits, 8 * UNIT);
    assert.equal(quiet.unverified.levelUnits, 3 * UNIT);
    assert.deepEqual(quiet.filter.popcount, [0, 0]);
    assert.equal(quiet.ledger.size, 0);
    assert.equal(quiet.ledger.stateViolations, 0);
  }
  for (const value of attenuation) assert.ok(Math.abs(value - attenuation[0]) <= 0.05, `cycle attenuation ${value} vs ${attenuation[0]}`);
});

test("concurrent POSTs with one token are one atomic decision each: at most K credited, the rest unverified, never more", () => {
  const { lanes } = rig();
  const value = enroll(lanes);
  const decisions = Array.from({ length: 50 }, () => lanes.decide(postToken(value)));
  assert.equal(decisions.filter((d) => d.lane === "credited" && d.outcome === "admitted").length, 3);
  assert.equal(lanes.snapshot().ledger.committedLive, 3);
});

test("the mechanism holds no clock, timer, randomness or I/O of its own beyond the injected clock and the filter key", () => {
  for (const file of ["defense/core/lanes.ts", "defense/core/credit-filter.ts", "defense/core/enrollment.ts"]) {
    const source = code(file);
    assert.doesNotMatch(source, /Date\.now|performance\.now|setTimeout|setInterval|Math\.random|node:fs|node:net|node:http|child_process|await\b/, file);
  }
});

test("enrollment never loses a genuine credit: a new token that merely tests positive through the PREVIOUS generation (a false positive) is still inserted, and survives that generation's rotation", () => {
  const { lanes, tick } = rig({ filterBits: 64, epochMs: 1000 });
  for (let i = 0; i < 300; i++) lanes.enroll(token()); // epoch 0: saturate the tiny filter
  tick(1000); // epoch 1: the saturated generation is now the PREVIOUS one, the active one is empty
  let genuine = "";
  for (let attempt = 0; attempt < 200 && genuine === ""; attempt++) { const candidate = token(); if (lanes.filter.has(lanes.filter.digest(candidate))) genuine = candidate; }
  assert.notEqual(genuine, "", "a token that tests positive only through the previous generation");
  assert.equal(lanes.snapshot().filter.popcount[0], 0, "nothing is in the active generation yet");
  assert.equal(lanes.enroll(genuine).ok, true, "it is NOT skipped as 'already enrolled': those bits are about to age out");
  tick(999);
  assert.equal(lanes.filter.has(lanes.filter.digest(genuine)), true, "positive for the whole guaranteed epochMs");
  tick(1); // epoch 2: the saturated generation is zeroed; the genuine token lives in the generation that is now previous
  assert.equal(lanes.filter.has(lanes.filter.digest(genuine)), true, "and it is still there after the generation that produced the false positive was zeroed");
  tick(1000); // epoch 3
  assert.equal(lanes.filter.has(lanes.filter.digest(genuine)), false, "and it ages out on schedule");
});

test("a token already USED credited is never refreshed by a later observation, so no replay can extend a credit past its use record's retention (P2)", () => {
  const { lanes, tick } = rig({ epochMs: 1000 });
  const value = token();
  assert.equal(lanes.enroll(value).ok, true);
  assert.equal(lanes.decide(postToken(value)).lane, "credited");
  tick(1000);
  assert.deepEqual(lanes.enroll(value), { ok: false, reason: "already_enrolled" });
  assert.equal(lanes.snapshot().filter.popcount[0], 0, "nothing was inserted into the active generation");
  tick(1000); // epoch 2: the original enrollment is gone and so is the use record's protection window
  assert.equal(lanes.filter.has(lanes.filter.digest(value)), false);
});

test("a token already in the ACTIVE generation is a no-op (identical lifetime); an UNUSED one seen again only from the previous generation is re-enrolled, extending an unused credit by at most one epoch and reopening no use", () => {
  const { lanes, tick } = rig({ epochMs: 1000 });
  const value = token();
  lanes.enroll(value);
  const popcount = lanes.snapshot().filter.popcount[0];
  assert.deepEqual(lanes.enroll(value), { ok: false, reason: "already_enrolled" });
  assert.equal(lanes.snapshot().filter.popcount[0], popcount);
  tick(1000);
  assert.equal(lanes.enroll(value).ok, true, "unused and only in the previous generation");
  tick(1000);
  assert.equal(lanes.filter.has(lanes.filter.digest(value)), true, "one epoch longer than the original enrollment would have lived");
  assert.equal(lanes.decide(postToken(value)).lane, "credited", "and its first use still gets the full K allowance, recorded from this epoch");
});
