import assert from "node:assert/strict";
import { test } from "node:test";
import { characterize, FIELD_L2 } from "./support/l2-starvation-sim";

/**
 * CHARACTERIZATION of the L2 credited lane (`JourneyLanes`) at the BA0 field parameters, in virtual time. It records what the code at
 * 8b45d05 DOES when one actor mints free credit and posts at several times the credited refill, while an independent legitimate client
 * makes valid mutations. It is not a requirement and it defends nothing: the literals below are measurements taken from a run of the
 * unmodified code and pinned because the clocks are injected and the run is exact. A change to L2 that alters them is a reviewed
 * change to THIS file, not a regression to be hidden.
 *
 * What it does not do: no real network, no real time, no L1, no timers; `defense/` is imported, never modified. The sender is not an input
 * to L2, so "farmer" and "legitimate" are labels of the harness (which tokens each actor holds), not something the lanes can see.
 * Interpretation lives in docs/BA0_L2_CREDITED_LANE_CHARACTERIZATION.md.
 */
const measured = characterize();

test("inputs: the field parameters under test are the documented ones (credited 10 at 2/s, unverified 3 at 1/s, K = 3, 60 s epoch)", () => {
  assert.deepEqual(FIELD_L2.credited, { capacity: 10, refillPerSecond: 2 });
  assert.deepEqual(FIELD_L2.unverified, { capacity: 3, refillPerSecond: 1 });
  assert.equal(FIELD_L2.maxUses, 3);
  assert.equal(FIELD_L2.epochMs, 60_000);
});

test("accounting holds in every scenario: the credited bucket is the bound, no spill between lanes, renders cost nothing, nothing is double-counted", () => {
  assert.ok(measured.results.size >= 20, "the matrix actually ran");
  for (const [label, r] of measured.results) {
    const creditedDecisions = r.farmer.admittedCredited + r.farmer.shedCredited + r.legit.admittedCredited + r.legit.shedCredited;
    const unverifiedDecisions = r.farmer.admittedUnverified + r.farmer.shedUnverified + r.legit.admittedUnverified + r.legit.shedUnverified;
    assert.equal(r.credited.takes, r.credited.admitted + r.credited.shed, `${label}: credited takes = admitted + shed`);
    assert.equal(r.credited.takes, creditedDecisions, `${label}: every credited-lane decision is a credited bucket take`);
    assert.equal(r.unverified.takes, unverifiedDecisions, `${label}: every unverified-lane decision is an unverified bucket take (no spill)`);
    assert.equal(r.farmer.admittedCredited + r.legit.admittedCredited, r.credited.admitted, `${label}: both actors' credited admissions add up to the bucket's`);
    assert.ok(r.credited.admitted <= r.credited.capacityBound, `${label}: credited admissions ${r.credited.admitted} never exceed capacity + refill x time (${r.credited.capacityBound})`);
    assert.equal(r.farmer.errors + r.legit.errors, 0, `${label}: no L2 error`);
    assert.equal(r.farmer.attempts + r.legit.attempts, r.credited.takes + r.unverified.takes, `${label}: every POST took exactly one bucket token decision`);
    assert.equal(r.openRendersAdmitted, r.farmerRenders + r.journeys.length, `${label}: every render was an unconditional open admission`);
    assert.deepEqual(r.ledger.stateViolations + r.ledger.fullRefusals, 0, `${label}: the use ledger never filled or violated K`);
    assert.equal(r.poisoned, false, `${label}: the credit filter stayed far below its poisoning threshold at these render volumes`);
  }
});

test("control: with no farmer the same 30 legitimate journeys all complete on the first attempt and the credited bucket never empties", () => {
  assert.deepEqual(measured.control.legit, { attempts: 30, completed: 30, firstAttempt: 30, shedCredited: 0, shedUnverified: 0, shedReasons: {}, byWindow30s: [8, 7, 8, 7] });
  assert.equal(measured.control.buckets.creditedAdmitted, 30);
  assert.equal(measured.control.firstCreditedShedMs, null);
});

test("farmer at 4 POST/s that mints free credit (render per POST, or one render per K POSTs): credited capacity goes to the farmer; the legitimate client's mutations are shed", () => {
  for (const mint of ["per_post", "per_k"] as const) {
    const m = measured.mints[mint];
    assert.equal(m.farmer.attempts, 480);
    assert.equal(m.farmer.admittedCredited, 248, `${mint}: farmer credited admissions`);
    assert.equal(m.farmer.shedCredited, 232);
    assert.deepEqual(m.legit, { attempts: 30, completed: 1, firstAttempt: 1, shedCredited: 29, shedUnverified: 0, shedReasons: { lane_budget: 29 }, byWindow30s: [1, 0, 0, 0] }, `${mint}: legitimate outcome`);
    assert.deepEqual(m.buckets, { creditedTakes: 510, creditedAdmitted: 249, creditedShed: 261, creditedBound: 250, unverifiedTakes: 0, unverifiedAdmitted: 0, unverifiedShed: 0 });
    assert.equal(m.firstCreditedShedMs, 4_125, `${mint}: the initial 10-token burst is gone after about 4 s`);
    assert.equal(m.lastCreditedLegitAdmitMs, 125, `${mint}: the one legitimate admission is inside that initial burst; none after it, across both 60 s generations`);
  }
  assert.equal(measured.mints.per_post.farmer.renders, 480);
  assert.equal(measured.mints.per_k.farmer.renders, 160, "K = 3: a third of the renders buy the same credited admissions (the harness cap is K per render, not fewer renders)");
  assert.equal(measured.mints.per_post.openRendersAdmitted, 510, "the renders themselves are open GETs: unbudgeted, never shed");
});

test("the same 12 journeys over 60 s that an earlier exploratory probe used: 1 of 12 complete", () => {
  assert.deepEqual(measured.canary12In60s.legit, { attempts: 12, completed: 1, firstAttempt: 1, shedCredited: 11, shedUnverified: 0, shedReasons: { lane_budget: 11 }, byWindow30s: [1, 0] });
  assert.equal(measured.canary12In60s.farmer.admittedCredited, 128);
});

test("a farmer that mints NO credit (fabricated tokens, or one token reused past K) never touches the credited bucket the legitimate client uses", () => {
  for (const mint of ["none", "single_reuse"] as const) {
    const m = measured.mints[mint];
    assert.deepEqual(m.legit, { attempts: 30, completed: 30, firstAttempt: 30, shedCredited: 0, shedUnverified: 0, shedReasons: {}, byWindow30s: [8, 7, 8, 7] }, `${mint}: legitimate outcome`);
    assert.equal(m.firstCreditedShedMs, null);
    assert.equal(m.farmer.admittedUnverified, 122, `${mint}: the farmer is bounded by the unverified bucket alone (122 admitted of 480, at most capacity 3 + 1/s x 120 s)`);
    assert.equal(m.farmer.shedUnverified, mint === "none" ? 358 : 355);
  }
  assert.equal(measured.mints.none.farmer.admittedCredited, 0);
  assert.equal(measured.mints.single_reuse.farmer.admittedCredited, 3, "K = 3 credited uses of the one enrolled token, then it falls to the unverified lane");
});

test("onset: the legitimate client loses service when the farmer's POST rate reaches the credited refill rate (2/s); below it nothing is lost", () => {
  const completed = Object.fromEntries(Object.entries(measured.rates).map(([rate, row]) => [rate, row.legitCompleted]));
  assert.deepEqual(completed, { "0": 30, "1": 30, "1.9": 30, "2": 9, "2.1": 21, "3": 2, "4": 1, "8": 1, "20": 1 });
  const credited = Object.fromEntries(Object.entries(measured.rates).map(([rate, row]) => [rate, row.farmerCredited]));
  assert.deepEqual(credited, { "0": 0, "1": 120, "1.9": 218, "2": 240, "2.1": 228, "3": 247, "4": 248, "8": 248, "20": 248 });
  assert.equal(measured.rates["4"].firstCreditedShedMs, 4_125);
  assert.equal(measured.rates["20"].firstCreditedShedMs, 450);
});

test("arrival-phase sensitivity (120 single-attempt probes at steady state): a perfectly periodic 4/s farmer is a phase lock; a jittered or faster one leaves only short windows", () => {
  assert.deepEqual(measured.phase, { noFarmer: 120, periodic4: 0, jitter4: 20, jitter100: 1 });
});

test("retry sensitivity: a shed consumes nothing, so the same token can be retried; whether that helps depends on how fast the farmer polls and how fast the client retries", () => {
  assert.deepEqual(measured.retries, {
    periodic4_10msX500: { completed: 1, firstAttempt: 1, meanAttemptsPerJourneyX10: 4796, farmerCredited: 248 },
    jitter4_1sX5: { completed: 29, firstAttempt: 17, meanAttemptsPerJourneyX10: 19, farmerCredited: 220 },
    jitter4_20msX250: { completed: 30, firstAttempt: 17, meanAttemptsPerJourneyX10: 92, farmerCredited: 219 },
    jitter100_1sX5: { completed: 0, firstAttempt: 0, meanAttemptsPerJourneyX10: 50, farmerCredited: 249 },
    jitter100_20msX250: { completed: 30, firstAttempt: 0, meanAttemptsPerJourneyX10: 467, farmerCredited: 219 },
  });
});
