import assert from "node:assert/strict";
import { test } from "node:test";
import { UNIT } from "../defense/core/lanes";
import type { AppEvent, BoundaryEvent, PlaneEvent } from "../defense/core/ledger";
import type { Tick } from "../defense/core/telemetry";
import type { PlaneTick } from "../defense/plane/l2-protocol";
import { JOURNEY_STEPS } from "../lab/defense/canary";
import { BA0_FIELD_V1 as config } from "../lab/defense/field-thresholds";
import { fixturePlan, type FixtureEvidence } from "../lab/defense/customer-journey/adverse";
import { plan, type ClientRecord, type Phase } from "../lab/defense/customer-journey/canary";
import { evaluate, type Evidence } from "../lab/defense/customer-journey/evaluate";

function makeEvidence(adverseRun: boolean): Evidence {
  const pids = { runner: 1, plane: 2, boundary: 3, app: 4, canary: 5 };
  const ports = [30001, 30002, 30003];
  const startMs = 1_000;
  const baselineStart = 1_500;
  const windowStart = 20_000;
  const windowNoticeMs = 20_500;
  const recoveryStart = 206_000;
  const endMs = 220_000;

  let nonceSeq = 0;
  let planeSeq = 0;
  let boundarySeq = 0;
  let appSeq = 0;
  const nextNonce = () => `r${++nonceSeq}`;

  const planeEvents: PlaneEvent[] = [];
  const boundaryEvents: BoundaryEvent[] = [];
  const appEvents: AppEvent[] = [];
  const canaryRequests: ClientRecord[] = [];
  const journeys: Evidence["canary"]["journeys"] = [];

  const pushPlane = <T extends Record<string, unknown>>(event: T, t: number) => {
    planeEvents.push({ ...event, seq: ++planeSeq, t } as unknown as PlaneEvent);
  };
  const pushBoundary = <T extends Record<string, unknown>>(event: T, t: number) => {
    boundaryEvents.push({ ...event, seq: ++boundarySeq, t } as unknown as BoundaryEvent);
  };
  const pushApp = <T extends Record<string, unknown>>(event: T, t: number) => {
    appEvents.push({ ...event, seq: ++appSeq, t } as unknown as AppEvent);
  };

  let boundaryAdmitted = 0;
  let appExecuted = 0;
  let appMutations = 0;
  let creditedLseq = 0;
  let unverifiedLseq = 0;

  function recordCustomerJourney(phase: Phase, journey: number, startAt: number) {
    let creditTag = "";
    const steps: Evidence["canary"]["journeys"][number]["steps"] = [];
    for (const [i, name] of JOURNEY_STEPS.entries()) {
      const nonce = nextNonce();
      const post = name === "valid_post";
      const t0 = startAt + i * 10;
      const tEnd = t0 + 3;
      const pbTag = `pb-${nonce}`;
      const baTag = `ba-${nonce}`;
      if (name === "form") creditTag = `credit-${phase}-${journey}`;

      canaryRequests.push({
        nonce,
        meta: {
          lane: "protected", cls: "canary", scenario: `journey_${name}`,
          phase, journey, step: i + 1, method: post ? "POST" : "GET",
        },
        harness: [
          { kind: "SENT" },
          { kind: "CLIENT_COMPLETED", result: "response", status: 200 },
        ],
        latencyMs: 3,
      });

      steps.push({
        step: i + 1, name, status: 200, ok: true, failure: null, latencyMs: 3, headerNames: ["content-type"], bodyDigest: "ok",
      });

      pushPlane({ nonce, kind: "INGRESS_ACCEPTED", stripped: 0 }, t0);
      pushPlane({ nonce, kind: "L1_ENTERED" }, t0 + 0.2);
      pushPlane({ nonce, kind: "L1_PASSED" }, t0 + 0.4);
      pushPlane({ nonce, kind: "L2_ENTERED" }, t0 + 0.6);
      pushPlane({
        nonce, kind: "L2_DECIDED",
        class: post ? "mutation" : "open",
        lane: post ? "credited" : "open",
        outcome: "admitted",
        ...(post ? { creditTag, dt: Math.round(t0), lvl: 9 * UNIT, lseq: ++creditedLseq } : {}),
      }, t0 + 0.8);
      pushPlane({ nonce, kind: "EGRESS_ATTEMPTED" }, t0 + 1.0);
      const hop = planeSeq;
      pushPlane({ nonce, kind: "PROOF_ISSUED", pbTag }, t0 + 1.2);
      pushPlane({ nonce, kind: "EGRESS_RESPONDED", status: 200 }, t0 + 2.4);
      if (name === "form") pushPlane({ nonce, kind: "L2_ENROLLED", creditTag, fill: [7, 0] }, t0 + 2.6);
      pushPlane({ nonce, kind: "INGRESS_RESPONDED", status: 200 }, tEnd);

      pushBoundary({ nonce, kind: "BOUNDARY_ARRIVED" }, t0 + 1.3);
      pushBoundary({ nonce, kind: "BOUNDARY_ADMITTED", hop, pbTag }, t0 + 1.4);
      pushBoundary({ nonce, kind: "APP_PROOF_ISSUED", hop, pbTag, baTag }, t0 + 1.5);
      pushBoundary({ nonce, kind: "BOUNDARY_FORWARDED", hop, pbTag, baTag }, t0 + 1.6);
      pushBoundary({ nonce, kind: "BOUNDARY_FORWARD_RESPONDED", status: 200 }, t0 + 2.2);
      pushBoundary({ nonce, kind: "BOUNDARY_RESPONDED", status: 200 }, t0 + 2.3);
      boundaryAdmitted++;

      pushApp({ nonce, kind: "APP_ADMITTED", hop, pbTag, baTag, spoofed: 0 }, t0 + 1.7);
      pushApp({ nonce, kind: "APP_EXECUTED", hop, pbTag, baTag }, t0 + 1.8);
      if (post) {
        pushApp({ nonce, kind: "APP_MUTATED", hop, pbTag, baTag }, t0 + 1.9);
        appMutations++;
      }
      pushApp({ nonce, kind: "APP_COMPLETED", hop, pbTag, baTag, status: 200 }, t0 + 2.1);
      appExecuted++;
    }
    journeys.push({ lane: "protected", phase, journey, completed: true, steps });
  }

  for (let j = 1; j <= plan.baseline; j++) {
    recordCustomerJourney("baseline", j, baselineStart + (j - 1) * 1_000);
  }

  let fixture: FixtureEvidence | undefined;
  if (!adverseRun) {
    for (let j = 1; j <= plan.window; j++) {
      recordCustomerJourney("window", j, windowStart + (j - 1) * 4_000);
    }
  } else {
    const fixtureRequests: ClientRecord[] = [];
    const observations: FixtureEvidence["observations"] = [];

    function recordFixtureStep(group: number, index: number, atMs: number) {
      const scenario = fixturePlan.cases[index];
      const status = fixturePlan.expectedStatus[index];
      const post = index > 0;
      const admitted = status === 200;
      const nonce = nextNonce();
      const tEnd = atMs + 5;
      const pbTag = `pb-${nonce}`;
      const baTag = `ba-${nonce}`;

      fixtureRequests.push({
        nonce,
        meta: {
          lane: "protected", cls: "hostile", scenario,
          phase: "window", journey: group + 1, step: index + 1, method: post ? "POST" : "GET",
        },
        harness: [
          { kind: "SENT" },
          { kind: "CLIENT_COMPLETED", result: "response", status },
        ],
        latencyMs: 5,
      });
      observations.push({ startMs: atMs, endMs: tEnd, validatedFormError: admitted });

      pushPlane({ nonce, kind: "INGRESS_ACCEPTED", stripped: 0 }, atMs);
      pushPlane({ nonce, kind: "L1_ENTERED" }, atMs + 0.2);
      if (index === 0) {
        pushPlane({ nonce, kind: "L1_REJECTED", reason: "a7.path_not_allowed", stage: "pre_parse" }, atMs + 0.5);
        pushPlane({ nonce, kind: "INGRESS_RESPONDED", status }, tEnd);
        return;
      }
      pushPlane({ nonce, kind: "L1_PASSED" }, atMs + 0.4);
      pushPlane({ nonce, kind: "L2_ENTERED" }, atMs + 0.6);
      if (!admitted) {
        pushPlane({
          nonce, kind: "L2_DECIDED", class: "mutation", lane: "unverified", outcome: "shed", shedReason: "lane_budget",
          dt: Math.round(atMs), lvl: 0, lseq: ++unverifiedLseq,
        }, atMs + 0.8);
        pushPlane({ nonce, kind: "INGRESS_RESPONDED", status }, tEnd);
        return;
      }
      pushPlane({
        nonce, kind: "L2_DECIDED", class: "mutation", lane: "unverified", outcome: "admitted",
        dt: Math.round(atMs), lvl: 2 * UNIT, lseq: ++unverifiedLseq,
      }, atMs + 0.8);
      pushPlane({ nonce, kind: "EGRESS_ATTEMPTED" }, atMs + 1.0);
      const hop = planeSeq;
      pushPlane({ nonce, kind: "PROOF_ISSUED", pbTag }, atMs + 1.2);
      pushPlane({ nonce, kind: "EGRESS_RESPONDED", status: 200 }, atMs + 4.0);
      pushPlane({ nonce, kind: "INGRESS_RESPONDED", status: 200 }, tEnd);

      pushBoundary({ nonce, kind: "BOUNDARY_ARRIVED" }, atMs + 1.3);
      pushBoundary({ nonce, kind: "BOUNDARY_ADMITTED", hop, pbTag }, atMs + 1.4);
      pushBoundary({ nonce, kind: "APP_PROOF_ISSUED", hop, pbTag, baTag }, atMs + 1.5);
      pushBoundary({ nonce, kind: "BOUNDARY_FORWARDED", hop, pbTag, baTag }, atMs + 1.6);
      pushBoundary({ nonce, kind: "BOUNDARY_FORWARD_RESPONDED", status: 200 }, atMs + 3.4);
      pushBoundary({ nonce, kind: "BOUNDARY_RESPONDED", status: 200 }, atMs + 3.6);
      boundaryAdmitted++;

      pushApp({ nonce, kind: "APP_ADMITTED", hop, pbTag, baTag, spoofed: 0 }, atMs + 1.7);
      pushApp({ nonce, kind: "APP_EXECUTED", hop, pbTag, baTag }, atMs + 1.8);
      pushApp({ nonce, kind: "APP_COMPLETED", hop, pbTag, baTag, status: 200 }, atMs + 3.2);
      appExecuted++;
    }

    // Window journey 1 starts before the first fixture group.
    recordCustomerJourney("window", 1, windowStart);

    // Interleave each of the 4 fixture groups with a customer journey so credited POSTs overlap all 4 groups.
    const overlapJourneys = [2, 5, 8, 11];
    let nextWindowJourney = 2;
    for (const [group, offset] of fixturePlan.offsetsMs.entries()) {
      const groupStart = windowNoticeMs + offset + 100;
      const targetOverlap = overlapJourneys[group];
      while (nextWindowJourney < targetOverlap) {
        recordCustomerJourney("window", nextWindowJourney, groupStart - 2_000 + nextWindowJourney * 100);
        nextWindowJourney++;
      }
      recordFixtureStep(group, 0, groupStart);
      recordFixtureStep(group, 1, groupStart + 300);
      recordCustomerJourney("window", targetOverlap, groupStart + 400);
      nextWindowJourney = targetOverlap + 1;
      recordFixtureStep(group, 2, groupStart + 600);
      recordFixtureStep(group, 3, groupStart + 900);
      recordFixtureStep(group, 4, groupStart + 1_200);
    }

    // Final window journey starts shortly after the last fixture response.
    const lastFixtureEnd = observations.at(-1)!.endMs;
    recordCustomerJourney("window", 12, lastFixtureEnd + 1_000);
    fixture = { windowNoticeMs, requests: fixtureRequests, observations };
  }

  for (let j = 1; j <= plan.recovery; j++) {
    recordCustomerJourney("recovery", j, recoveryStart + (j - 1) * 1_000);
  }

  const directNonce = nextNonce();
  const direct: ClientRecord[] = [{
    nonce: directNonce,
    meta: {
      lane: "direct_app_rejected", cls: "canary", scenario: "unsigned",
      phase: "control", journey: null, step: null, method: "GET",
    },
    harness: [
      { kind: "SENT" },
      { kind: "CLIENT_COMPLETED", result: "response", status: 403 },
    ],
    latencyMs: 2,
  }];
  pushApp({ nonce: directNonce, kind: "APP_REFUSED", reason: "ob.proof_missing" }, endMs - 499);

  const ticks: Evidence["ticks"] = [];
  const host: Evidence["host"] = [];
  const tickCount = Math.floor((endMs - startMs) / 1_000) + 1;
  for (let i = 0; i < tickCount; i++) {
    const at = startMs + i * 1_000;
    const isFinal = i === tickCount - 1;
    const baseSample = { eldP50Ms: 0.2, eldP99Ms: 0.8, eldMaxMs: 1.0, rssMb: 80, cpuUserMs: 5, cpuSystemMs: 2 };
    const planeTick: PlaneTick = {
      type: "tick",
      role: "plane",
      tickSeq: i + 1,
      tMonoMs: at,
      final: isFinal,
      sample: baseSample,
      data: {
        channel: { dropped: 0 },
        l2: {
          lanes: {
            credited: { levelUnits: config.l2.credited.capacity * UNIT },
            unverified: { levelUnits: config.l2.unverified.capacity * UNIT },
            filter: { popcount: [0, 0] },
            ledger: { size: 0 },
          },
        },
      },
    } as unknown as PlaneTick;
    ticks.push({ at, tick: planeTick });
    ticks.push({
      at,
      tick: { type: "tick", role: "boundary", tickSeq: i + 1, tMonoMs: at, final: isFinal, sample: baseSample, data: {} } as Tick<unknown>,
    });
    ticks.push({
      at,
      tick: { type: "tick", role: "app", tickSeq: i + 1, tMonoMs: at, final: isFinal, sample: baseSample, data: {} } as Tick<unknown>,
    });
    host.push({
      at,
      loopbackPorts: [...ports],
      otherListeners: 0,
      sample: {
        eldP99Ms: 0.5,
        eldMaxMs: 0.7,
        proc: {
          host: {
            cpuBusyPct: i % 2 === 0 ? 1.2 : 0.4,
            memAvailablePct: 88.5,
            memAvailableMb: 7000,
            rxBytesDelta: 0,
            txBytesDelta: 0,
            tcpInUse: 3,
            tcpTimeWait: 0,
            tcpOrphan: 0,
            kernelAdvisory: { listenOverflows: 0, listenDrops: 0, retransSegs: 0, estabResets: 0, attemptFails: 0 },
          },
          perRole: Object.fromEntries(Object.keys(pids).map(role => [role, {
            alive: true, cpuMsDelta: 5, rssMb: 80, threads: 8, fds: 25, fdLimit: 1048576,
          }])),
        },
      },
    });
  }

  const windowEnd = adverseRun ? (fixture!.observations.at(-1)!.endMs + 1_100) : (windowStart + plan.window * 4_000);

  return {
    gitSha: "0".repeat(40),
    platform: "linux",
    runId: "test-run",
    pids,
    ports,
    startMs,
    endMs,
    canary: {
      pid: pids.canary,
      intervals: {
        baseline: { startMs: baselineStart, endMs: baselineStart + 12_000 },
        window: { startMs: windowStart, endMs: windowEnd },
        recovery: { startMs: recoveryStart, endMs: recoveryStart + 6_000 },
      },
      journeys,
      requests: canaryRequests,
    },
    direct,
    ...(fixture ? { fixture } : {}),
    plane: { type: "events", events: planeEvents, dropped: 0 },
    boundary: { type: "events", events: boundaryEvents, dropped: 0 },
    app: { type: "events", events: appEvents, dropped: 0 },
    planeFin: {
      drained: true,
      channel: { emitted: planeEvents.length, dropped: 0, sent: planeEvents.length, received: planeEvents.length, queued: 0, unacknowledged: 0, queueHighWater: 10, lastSeq: planeSeq },
    } as Evidence["planeFin"],
    boundaryFin: {
      type: "fin_result",
      drained: true,
      channel: { emitted: boundaryEvents.length, dropped: 0, sent: boundaryEvents.length, received: boundaryEvents.length, queued: 0, unacknowledged: 0, queueHighWater: 10, lastSeq: boundarySeq },
      stats: { admitted: boundaryAdmitted },
    } as unknown as Evidence["boundaryFin"],
    appFin: {
      type: "fin_result",
      drained: true,
      channel: { emitted: appEvents.length, dropped: 0, sent: appEvents.length, received: appEvents.length, queued: 0, unacknowledged: 0, queueHighWater: 10, lastSeq: appSeq },
      stats: { counters: { executed: appExecuted, stateMutations: appMutations, refused: 1 } },
    } as unknown as Evidence["appFin"],
    ticks,
    host,
  };
}

test("BA0 evaluator passes valid non-adverse and adverse evidence with finite derived resource metrics", () => {
  const baseline = evaluate(makeEvidence(false), false);
  assert.equal(baseline.verdict, "PASS", baseline.failures.join("; "));
  assert.deepEqual(baseline.failures, []);

  const adverse = evaluate(makeEvidence(true), true);
  assert.equal(adverse.verdict, "PASS", adverse.failures.join("; "));
  assert.deepEqual(adverse.failures, []);
  assert.ok(adverse.continuity);
  assert.equal(adverse.continuity.windowResources.hostCpuPeakPct, 1.2);
  assert.equal(adverse.continuity.windowResources.availableMemoryMinPct, 88.5);
  assert.equal(adverse.continuity.windowResources.planeRssPeakMiB, 80);
  assert.equal(adverse.continuity.windowResources.planeEventLoopP99PeakMs, 0.8);
});

test("BA0 adverse evaluator rejects evidence when cpuBusyPct is removed from all host samples and never emits NaN", () => {
  const evidence = makeEvidence(true);
  for (const h of evidence.host) {
    delete (h.sample.proc.host as unknown as Record<string, unknown>).cpuBusyPct;
  }
  const result = evaluate(evidence, true);
  assert.equal(result.verdict, "FAIL");
  assert.ok(result.failures.includes("invalid or missing host CPU sample"));
  assert.ok(result.failures.includes("invalid or missing host CPU observations in fixture window"));
  assert.equal(result.continuity?.windowResources.hostCpuPeakPct, null);
  assert.ok(!Number.isNaN(result.continuity?.windowResources.hostCpuPeakPct));
});

test("BA0 adverse evaluator rejects missing, non-numeric, NaN, infinite, and out-of-range CPU measurements", () => {
  const invalidValues: readonly [string, unknown][] = [
    ["undefined", undefined],
    ["null", null],
    ["numeric string", "1.2"],
    ["empty string", ""],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["-Infinity", Number.NEGATIVE_INFINITY],
    ["negative", -0.1],
    ["above 100", 100.1],
  ];

  for (const [label, value] of invalidValues) {
    const evidence = makeEvidence(true);
    const windowSample = evidence.host.find(h => h.at >= evidence.fixture!.windowNoticeMs)!;
    const hostRecord = windowSample.sample.proc.host as unknown as Record<string, unknown>;
    if (value === undefined) delete hostRecord.cpuBusyPct;
    else hostRecord.cpuBusyPct = value;

    const result = evaluate(evidence, true);
    assert.equal(result.verdict, "FAIL", `${label} must fail`);
    assert.ok(result.failures.includes("invalid or missing host CPU sample"), `${label} host validation`);
    assert.ok(result.failures.includes("invalid or missing host CPU observations in fixture window"), `${label} window metric validation`);
    assert.equal(result.continuity?.windowResources.hostCpuPeakPct, null, `${label} must not produce NaN/Infinity/invalid peak`);
  }
});

test("BA0 evaluator rejects invalid CPU evidence outside the fixture window in both non-adverse and adverse runs", () => {
  for (const adverseRun of [false, true]) {
    const evidence = makeEvidence(adverseRun);
    (evidence.host[0].sample.proc.host as unknown as Record<string, unknown>).cpuBusyPct = Number.NaN;
    const result = evaluate(evidence, adverseRun);
    assert.equal(result.verdict, "FAIL", `adverseRun=${adverseRun}`);
    assert.ok(result.failures.includes("invalid or missing host CPU sample"));
  }
});

test("BA0 derived window resource metrics fail and yield null rather than NaN or Infinity when memory or plane tick metrics are invalid", () => {
  const badMem = makeEvidence(true);
  const windowSample = badMem.host.find(h => h.at >= badMem.fixture!.windowNoticeMs)!;
  delete (windowSample.sample.proc.host as unknown as Record<string, unknown>).memAvailablePct;
  const memResult = evaluate(badMem, true);
  assert.equal(memResult.verdict, "FAIL");
  assert.ok(memResult.failures.includes("incomplete host or process sample"));
  assert.ok(memResult.failures.includes("invalid or missing host memory observations in fixture window"));
  assert.equal(memResult.continuity?.windowResources.availableMemoryMinPct, null);

  const badPlaneTick = makeEvidence(true);
  const windowTick = badPlaneTick.ticks.find(v => v.at >= badPlaneTick.fixture!.windowNoticeMs && v.tick.role === "plane")!;
  delete (windowTick.tick.sample as unknown as Record<string, unknown>).eldP99Ms;
  const tickResult = evaluate(badPlaneTick, true);
  assert.equal(tickResult.verdict, "FAIL");
  assert.ok(tickResult.failures.includes("invalid plane resource sample"));
  assert.ok(tickResult.failures.includes("invalid or missing plane resource observations in fixture window"));
  assert.equal(tickResult.continuity?.windowResources.planeEventLoopP99PeakMs, null);

  const emptyWindowHost = makeEvidence(true);
  emptyWindowHost.host = emptyWindowHost.host.filter(h => h.at < emptyWindowHost.fixture!.windowNoticeMs);
  const emptyResult = evaluate(emptyWindowHost, true);
  assert.equal(emptyResult.verdict, "FAIL");
  assert.equal(emptyResult.continuity?.windowResources.hostCpuPeakPct, null);
  assert.equal(emptyResult.continuity?.windowResources.availableMemoryMinPct, null);
});
