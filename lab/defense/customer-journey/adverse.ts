import { setTimeout as sleep } from "node:timers/promises";
import { UNIT } from "../../../defense/core/lanes";
import { protectedLineageComplete } from "../../../defense/core/lineage";
import type { PlaneTick } from "../../../defense/plane/l2-protocol";
import { trackedHttp } from "../client";
import { Collector, type LedgerRecord } from "../collector";
import { BA0_FIELD_V1 as config } from "../field-thresholds";
import { clientRecords, type ClientRecord } from "./canary";
import type { Evidence } from "./evaluate";

export const fixturePlan = {
  offsetsMs: [3300, 15300, 27300, 39300], minimumSpacingMs: 250, windowDeadlineMs: 44000,
  cases: ["unlisted_page", "incomplete_form", "incomplete_form", "incomplete_form", "incomplete_form"],
  expectedStatus: [404, 200, 200, 200, 503], maxInFlight: 1, maxRequests: 20,
} as const;
export type FixtureObservation = { startMs: number; endMs: number; validatedFormError: boolean };
export type FixtureEvidence = { windowNoticeMs: number; requests: ClientRecord[]; observations: FixtureObservation[] };

async function waitUntil(at: number, signal: AbortSignal) {
  while (performance.now() < at) await sleep(Math.ceil(at - performance.now()), undefined, { signal });
}

// Fixed inputs, one outstanding exchange, only the ephemeral loopback port of this run.
export async function runFixture(port: number, signal: AbortSignal): Promise<FixtureEvidence> {
  const collector = new Collector(null);
  const observations: FixtureObservation[] = [];
  const windowNoticeMs = performance.now();
  let previousEnd = windowNoticeMs;
  for (const [group, offset] of fixturePlan.offsetsMs.entries()) {
    for (const [index, scenario] of fixturePlan.cases.entries()) {
      await waitUntil(Math.max(windowNoticeMs + offset, previousEnd + fixturePlan.minimumSpacingMs), signal);
      signal.throwIfAborted();
      const startMs = performance.now();
      const remainingMs = Math.floor(windowNoticeMs + fixturePlan.windowDeadlineMs - startMs);
      if (remainingMs <= 0) throw new Error("fixture exhausted its window deadline");
      const post = scenario === "incomplete_form";
      const method = post ? "POST" : "GET";
      const spec = post ? { method, path: "/api/public-inquiries", body: "name=Local",
        headers: { origin: `http://127.0.0.1:${port}`, "content-type": "application/x-www-form-urlencoded" } }
        : { method, path: "/unlisted-local-page" };
      const exchange = await trackedHttp(collector, port, { lane: "protected", cls: "hostile", phase: "window", journey: group + 1,
        step: index + 1, method, scenario }, spec, Math.min(config.canary.timeoutMs, remainingMs));
      previousEnd = performance.now();
      let validatedFormError = false;
      if (post && exchange.status === 200) {
        try {
          const reply = JSON.parse(exchange.body.toString());
          validatedFormError = reply.kind === "state" && reply.state?.errors?.form === "invalid";
        } catch { /* The evaluator requires this specific response on an admitted POST. */ }
      }
      observations.push({ startMs, endMs: previousEnd, validatedFormError });
    }
  }
  return { windowNoticeMs, observations, requests: clientRecords(collector) };
}

function layerCounts(rows: LedgerRecord[]) {
  const plane = rows.flatMap(r => r.plane);
  const boundary = rows.flatMap(r => r.boundary);
  const app = rows.flatMap(r => r.app);
  const decisions = plane.filter(v => v.kind === "L2_DECIDED");
  const reasons: Record<string, number> = {};
  for (const v of plane) {
    const reason = v.kind === "L1_REJECTED" ? v.reason : v.kind === "L2_DECIDED" && v.outcome === "shed" ? v.shedReason : undefined;
    if (reason) reasons[reason] = (reasons[reason] ?? 0) + 1;
  }
  return { ingress: plane.filter(v => v.kind === "INGRESS_ACCEPTED").length, l1Passed: plane.filter(v => v.kind === "L1_PASSED").length,
    l1Rejected: plane.filter(v => v.kind === "L1_REJECTED").length, l2Entered: plane.filter(v => v.kind === "L2_ENTERED").length,
    l2Admitted: decisions.filter(v => v.outcome === "admitted").length, l2Refused: decisions.filter(v => v.outcome === "shed").length,
    boundary: boundary.filter(v => v.kind === "BOUNDARY_ADMITTED").length, executed: app.filter(v => v.kind === "APP_EXECUTED").length,
    mutations: app.filter(v => v.kind === "APP_MUTATED").length, reasons };
}

export function evaluateFixture(e: Evidence, rows: LedgerRecord[], customers: LedgerRecord[], failures: string[]) {
  const fixture = e.fixture;
  if (!fixture || !Array.isArray(fixture.requests) || !Array.isArray(fixture.observations)) {
    failures.push("missing mandatory fixture evidence"); return;
  }
  const check = (ok: boolean, reason: string) => { if (!ok) failures.push(reason); };
  const customer = layerCounts(customers);
  const adverse = layerCounts(rows);
  check(rows.length === 20 && fixture.observations.length === 20 && fixture.requests.length === 20, "fixture count");
  const seq = (r: LedgerRecord | undefined, kind: "INGRESS_ACCEPTED" | "INGRESS_RESPONDED") => r?.plane.find(v => v.kind === kind)?.seq;
  const window = customers.filter(r => r.meta.phase === "window");
  const windowStart = seq(window[0], "INGRESS_ACCEPTED");
  const windowEnd = seq(window.at(-1), "INGRESS_RESPONDED");
  let overlapGroups = 0;
  let lastFixtureEnd = 0;
  for (const [group, offset] of fixturePlan.offsetsMs.entries()) {
    const batch = rows.slice(group * 5, group * 5 + 5);
    const first = seq(batch[0], "INGRESS_ACCEPTED");
    const last = seq(batch[4], "INGRESS_RESPONDED");
    if (first !== undefined && last !== undefined) {
      check(windowStart !== undefined && first > windowStart && windowEnd !== undefined && last < windowEnd, "fixture outside customer window");
      if (window.some(r => r.meta.method === "POST" && r.plane.some(v => v.kind === "L2_DECIDED" && v.lane === "credited" &&
          v.outcome === "admitted" && v.seq > first && v.seq < last))) overlapGroups++;
    }
    for (const [index, scenario] of fixturePlan.cases.entries()) {
      const n = group * 5 + index;
      const r = batch[index];
      const sample = fixture.observations[n];
      const label = `fixture/${group + 1}/${index + 1}`;
      if (!r || !sample) { failures.push(`${label} missing evidence`); continue; }
      check(r.meta.journey === group + 1 && r.meta.step === index + 1 && r.meta.scenario === scenario &&
        r.meta.phase === "window" && r.meta.method === (index ? "POST" : "GET") && fixture.requests[n]?.nonce === r.nonce, `${label} identity`);
      check(Number.isFinite(sample.startMs) && sample.startMs >= fixture.windowNoticeMs + offset && sample.startMs >= lastFixtureEnd + fixturePlan.minimumSpacingMs &&
        sample.endMs >= sample.startMs && sample.endMs <= fixture.windowNoticeMs + fixturePlan.windowDeadlineMs, `${label} timing bounds`);
      lastFixtureEnd = sample.endMs;
      const status = fixturePlan.expectedStatus[index];
      const admitted = status === 200;
      const done = r.harness[1];
      check(done?.result === "response" && done.status === status && sample.validatedFormError === admitted, `${label} client outcome`);
      const d = r.plane.find(v => v.kind === "L2_DECIDED");
      if (index === 0) {
        check(r.plane.some(v => v.kind === "L1_REJECTED" && v.reason === "a7.path_not_allowed") &&
          !r.plane.some(v => v.kind === "L2_ENTERED" || v.kind === "L2_DECIDED"), `${label} L1 rejection`);
      } else {
        check(r.plane.some(v => v.kind === "L1_PASSED") && d?.class === "mutation" && d.lane === "unverified" &&
          (admitted ? d.outcome === "admitted" : d.outcome === "shed" && d.shedReason === "lane_budget"), `${label} L2 decision`);
      }
      if (admitted) {
        check(protectedLineageComplete({ ...r, expected: "protected" }) && r.app.some(v => v.kind === "APP_EXECUTED") &&
          r.app.some(v => v.kind === "APP_COMPLETED") && !r.app.some(v => v.kind === "APP_MUTATED"), `${label} validation-only execution`);
      } else {
        check(!r.plane.some(v => v.kind === "EGRESS_ATTEMPTED") && !r.boundary.length && !r.app.length, `${label} rejected request reached downstream`);
      }
    }
  }
  check(overlapGroups === 4, "credited customer submissions did not overlap all four fixture groups");
  check(customer.ingress === 150 && customer.l1Passed === 150 && customer.l2Admitted === 150 && customer.boundary === 150 &&
    customer.executed === 150 && customer.mutations === 30, "customer ledger totals");
  check(adverse.ingress === 20 && adverse.l1Passed === 16 && adverse.l1Rejected === 4 && adverse.l2Entered === 16 &&
    adverse.l2Admitted === 12 && adverse.l2Refused === 4 && adverse.boundary === 12 && adverse.executed === 12 && adverse.mutations === 0, "fixture ledger totals");
  const lastResponse = rows.at(-1)?.plane.find(v => v.kind === "INGRESS_RESPONDED");
  const nextHome = window.filter(r => r.meta.step === 1).map(r => r.plane.find(v => v.kind === "INGRESS_ACCEPTED"))
    .find(v => v && lastResponse && v.seq > lastResponse.seq);
  const residualDelayMs = nextHome && lastResponse ? nextHome.t - lastResponse.t : null;
  check(residualDelayMs !== null && residualDelayMs >= 0 && residualDelayMs <= config.canary.gapMs + config.telemetry.gapToleranceMs,
    "missing immediate post-fixture customer journey");
  const recoveryStart = customers.find(r => r.meta.phase === "recovery")?.plane.find(v => v.kind === "INGRESS_ACCEPTED")?.t;
  const planeTicks = e.ticks.filter(v => v.tick.role === "plane").map(v => v.tick as PlaneTick);
  const beforeRecovery = planeTicks.filter(t => recoveryStart !== undefined && t.tMonoMs <= recoveryStart).at(-1);
  const lanes = beforeRecovery?.data.l2?.lanes;
  const recovered = !!(lanes && beforeRecovery && recoveryStart !== undefined && recoveryStart - beforeRecovery.tMonoMs <= config.telemetry.gapToleranceMs &&
    lanes.credited.levelUnits === config.l2.credited.capacity * UNIT && lanes.unverified.levelUnits === config.l2.unverified.capacity * UNIT &&
    lanes.filter.popcount.every(count => count === 0) && lanes.filter.popcount.length === 2 && lanes.ledger.size === 0);
  check(recovered, "missing or incomplete lane recovery before the first recovery request");
  const samples = e.host.filter(h => h.at >= fixture.windowNoticeMs && h.at <= lastFixtureEnd);
  const windowTicks = e.ticks.filter(v => v.at >= fixture.windowNoticeMs && v.at <= lastFixtureEnd && v.tick.role === "plane");
  check(samples.length > 0 && windowTicks.length > 0, "missing resource observations in fixture window");
  return { customer, adverse, overlapGroups, residualDelayMs, recovered,
    creditedTokensBeforeRecovery: lanes ? lanes.credited.levelUnits / UNIT : null,
    unverifiedTokensBeforeRecovery: lanes ? lanes.unverified.levelUnits / UNIT : null, liveUseRecords: lanes?.ledger.size,
    windowResources: { samples: samples.length, hostCpuPeakPct: Math.max(...samples.map(h => h.sample.proc.host?.cpuBusyPct ?? NaN)),
      availableMemoryMinPct: Math.min(...samples.map(h => h.sample.proc.host?.memAvailablePct ?? NaN)),
      planeRssPeakMiB: Math.max(...windowTicks.map(v => v.tick.sample.rssMb)),
      planeEventLoopP99PeakMs: Math.max(...windowTicks.map(v => v.tick.sample.eldP99Ms)) } };
}
