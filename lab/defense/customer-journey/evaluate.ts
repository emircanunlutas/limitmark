import type { AppEvent, BoundaryEvent, EventFrame, PlaneEvent } from "../../../defense/core/ledger";
import { protectedLineageComplete } from "../../../defense/core/lineage";
import type { Tick } from "../../../defense/core/telemetry";
import { summarizeLatencies } from "../../policy/thresholds";
import { JOURNEY_STEPS } from "../canary";
import { Collector, type AppFin, type BoundaryFin, type PlaneFin } from "../collector";
import { TickMonitor, type HarnessSample } from "../field-monitor";
import { BA0_FIELD_V1 as config } from "../field-thresholds";
import { plan, type CanaryResult, type ClientRecord, type Phase } from "./canary";
import { evaluateFixture, isValidNonNegative, isValidPercent, isValidPositive, type FixtureEvidence } from "./adverse";

export type Evidence = {
  gitSha: string; platform: string; runId: string;
  pids: { runner: number; plane: number; boundary: number; app: number; canary: number };
  ports: number[]; startMs: number; endMs: number;
  canary: CanaryResult; direct: ClientRecord[];
  fixture?: FixtureEvidence;
  plane: EventFrame<PlaneEvent>; boundary: EventFrame<BoundaryEvent>; app: EventFrame<AppEvent>;
  planeFin: PlaneFin; boundaryFin: BoundaryFin; appFin: AppFin;
  ticks: { at: number; tick: Tick<unknown> }[];
  host: { at: number; sample: HarnessSample; loopbackPorts: number[]; otherListeners: number }[];
};

export function evaluate(e: Evidence, adverseRun = false) {
  const failures: string[] = [];
  const check = (ok: boolean, reason: string) => { if (!ok) failures.push(reason); };
  const collector = new Collector(null);
  collector.enableOriginStreams();
  collector.enableLaneStreams();
  const fixtureRequests = e.fixture?.requests ?? [];
  check(adverseRun === (e.fixture !== undefined), "fixture evidence does not match declared run mode");
  for (const r of [...e.canary.requests, ...fixtureRequests, ...e.direct]) {
    check(collector.sent(r.nonce, r.meta), `duplicate client request ${r.nonce}`);
    const [sent, done] = r.harness;
    if (r.harness.length !== 2 || sent?.kind !== "SENT" || done?.kind !== "CLIENT_COMPLETED" ||
        !done.result || !Number.isFinite(r.latencyMs) || r.latencyMs === null || r.latencyMs < 0) {
      failures.push(`missing client observation ${r.nonce}`);
      continue;
    }
    collector.clientCompleted(r.nonce, { ...done, result: done.result, latencyMs: r.latencyMs });
  }
  collector.ingestFrame(e.plane);
  collector.ingestBoundaryFrame(e.boundary);
  collector.ingestAppFrame(e.app);
  collector.planeFinished(e.planeFin);
  collector.boundaryFinished(e.boundaryFin);
  collector.appFinished(e.appFin);
  collector.freeze();
  const { anomalies, anomalyTotal } = collector.finalize();
  for (const a of anomalies) failures.push(`${a.nonce ?? "stream"} ${a.code}: ${a.detail}`);
  check(collector.parserRejectedTotal() === 0 && Object.keys(collector.boundaryInfo.anonymous).length === 0 &&
    Object.keys(collector.appInfo.anonymous).length === 0, "unaccounted anonymous events");

  const records = Array.from(collector.allRecords());
  const protectedRecords = records.filter(r => r.meta.lane === "protected" && r.meta.cls === "canary");
  const fixtureRecords = records.filter(r => r.meta.lane === "protected" && r.meta.cls === "hostile");
  const read = (kind: PlaneEvent["kind"]) => e.plane.events.filter(event => event.kind === kind).length;
  const totals = {
    ingress: read("INGRESS_ACCEPTED"), l1Passed: read("L1_PASSED"), l2Admitted: e.plane.events.filter(v => v.kind === "L2_DECIDED" && v.outcome === "admitted").length,
    boundaryAdmitted: e.boundaryFin.stats.admitted, executed: e.appFin.stats.counters.executed, mutations: e.appFin.stats.counters.stateMutations,
  };
  check(e.canary.requests.length === 150 && protectedRecords.length === 150 && e.canary.journeys.length === 30, "customer request or journey count");
  const expectedIngress = adverseRun ? 170 : 150;
  const expectedDownstream = adverseRun ? 162 : 150;
  check(totals.ingress === expectedIngress && totals.l1Passed === (adverseRun ? 166 : 150) && totals.l2Admitted === expectedDownstream &&
    totals.boundaryAdmitted === expectedDownstream && totals.executed === expectedDownstream && totals.mutations === 30, "chain totals");
  const counts = { successfulSteps: 0, successfulSubmissions: 0, falseRefusals: 0, challenges: 0, timeouts: 0, httpErrors: 0 };
  const latency = {} as Record<Phase, ReturnType<typeof summarizeLatencies>>;
  for (const phase of Object.keys(plan) as Phase[]) {
    const samples: number[] = [];
    for (let j = 1; j <= plan[phase]; j++) {
      const matches = e.canary.journeys.filter(r => r.phase === phase && r.journey === j);
      const journey = matches[0];
      const id = `${phase}/${j}`;
      check(matches.length === 1 && journey?.completed && journey.steps.length === 5, `${id} incomplete or duplicate journey`);
      let formCredit: string | undefined;
      for (const [i, name] of JOURNEY_STEPS.entries()) {
        const key = `${id}/${name}`;
        const step = journey?.steps[i];
        const rows = protectedRecords.filter(r => r.meta.phase === phase && r.meta.journey === j && r.meta.step === i + 1);
        const r = rows[0];
        if (!step || rows.length !== 1 || step.name !== name || step.step !== i + 1 || r.meta.scenario !== `journey_${name}`) {
          failures.push(`${key} missing or mismatched step`); continue;
        }
        const post = name === "valid_post";
        const decision = r.plane.find(v => v.kind === "L2_DECIDED");
        const client = r.harness[1];
        if (step.status !== null && step.status >= 400) counts.httpErrors++;
        if (client?.result === "timeout") counts.timeouts++;
        if (step.status === 403 || step.status === 429 || step.status === 503 || decision?.outcome !== "admitted") counts.falseRefusals++;
        if (step.status === 401 || step.status === 407 || step.headerNames.some(h => ["x-m1-challenge", "cf-mitigated", "www-authenticate", "proxy-authenticate"].includes(h))) counts.challenges++;
        const success = step.ok && step.failure === null && step.status === 200 && client?.result === "response" && client.status === step.status;
        if (success) { counts.successfulSteps++; if (post) counts.successfulSubmissions++; }
        check(success, `${key} client ${step.failure ?? step.status}`);
        check(Number.isFinite(step.latencyMs) && step.latencyMs >= 0 && step.latencyMs === r.latencyMs, `${key} latency`);
        samples.push(step.latencyMs);
        check(r.meta.method === (post ? "POST" : "GET") && decision?.lane === (post ? "credited" : "open") &&
          decision.outcome === "admitted" && protectedLineageComplete({ ...r, expected: "protected" }), `${key} layer admission or proof lineage`);
        for (const kind of ["APP_EXECUTED", "APP_COMPLETED", "APP_MUTATED"] as const) {
          check(r.app.filter(v => v.kind === kind).length === (kind === "APP_MUTATED" && !post ? 0 : 1), `${key} ${kind}`);
        }
        if (name === "form") formCredit = r.plane.find(v => v.kind === "L2_ENROLLED")?.creditTag;
        if (post) check(!!formCredit && formCredit === decision?.creditTag, `${key} issued form credit`);
      }
    }
    latency[phase] = summarizeLatencies(samples);
  }
  check(counts.successfulSteps === 150 && counts.successfulSubmissions === 30 && !counts.challenges && !counts.falseRefusals && !counts.timeouts && !counts.httpErrors, "customer outcomes");
  const { p95Factor, p95AddedMs } = config.canary.windowLatency;
  const windowLimitMs = Math.max(p95Factor * latency.baseline.p95, latency.baseline.p95 + p95AddedMs);
  check(latency.window.p95 <= windowLimitMs, "window p95 exceeds provisional limit");
  const { baseline, window, recovery } = e.canary.intervals;
  const quietMs = recovery.startMs - window.endMs;
  check(baseline.startMs <= baseline.endMs && baseline.endMs <= window.startMs && window.startMs <= window.endMs &&
    recovery.startMs <= recovery.endMs && quietMs >= config.recovery.quietMs, "phase ordering or quiet period");

  const direct = records.filter(r => r.meta.lane === "direct_app_rejected");
  const probe = direct[0];
  const directStatus = probe?.harness[1]?.status;
  check(e.direct.length === 1 && direct.length === 1 && records.length === expectedIngress + 1 && directStatus === 403 && probe.harness[1].result === "response" &&
    !probe.plane.length && !probe.boundary.length && probe.app.length === 1 && probe.app[0].kind === "APP_REFUSED" &&
    probe.app[0].reason === "ob.proof_missing" && e.appFin.stats.counters.refused === 1, "unsigned direct-origin control");

  check(e.platform === "linux" && Object.values(e.pids).every(p => Number.isInteger(p) && p > 0) &&
    new Set(Object.values(e.pids)).size === 5 && e.canary.pid === e.pids.canary, "process separation");
  let now = e.startMs;
  const monitor = new TickMonitor(config, () => now);
  monitor.setWindowActive(true);
  for (const { at, tick } of e.ticks) {
    now = at;
    for (const reason of monitor.observe(tick)) failures.push(reason.detail ?? reason.code);
    const sample = tick.sample;
    check(!!sample && isValidNonNegative(sample.eldP50Ms) && isValidNonNegative(sample.eldP99Ms) &&
      isValidNonNegative(sample.eldMaxMs) && isValidPositive(sample.rssMb) &&
      isValidNonNegative(sample.cpuUserMs) && isValidNonNegative(sample.cpuSystemMs) &&
      Object.values(sample).every(v => isValidNonNegative(v)), `invalid ${tick.role} resource sample`);
  }
  const gapLimit = config.telemetry.gapToleranceMs;
  function checkCoverage(times: number[], name: string) {
    check(times.length >= 2 && times[0] <= e.startMs + gapLimit && times.at(-1)! >= e.endMs - gapLimit &&
      times.every((at, i) => i === 0 || (at >= times[i-1] && at - times[i-1] <= gapLimit)), `${name} telemetry coverage`);
  }
  const ticks = { plane: 0, boundary: 0, app: 0 };
  for (const role of ["plane", "boundary", "app"] as const) {
    const stream = e.ticks.filter(v => v.tick.role === role);
    ticks[role] = stream.length;
    checkCoverage(stream.map(v => v.at), role);
    check(stream.every(({ tick }, i) => tick.tickSeq === i + 1 && tick.final === (i === stream.length - 1)), `${role} tick sequence or final`);
  }
  checkCoverage(e.host.map(h => h.at), "host");
  for (const h of e.host) {
    check(h.otherListeners === 0 && h.loopbackPorts.length === 3 && e.ports.every(port => h.loopbackPorts.includes(port)), "listener exposure");
    const host = h.sample?.proc?.host;
    check(!!host && isValidPercent(host.cpuBusyPct), "invalid or missing host CPU sample");
    check(!!host && isValidPercent(host.memAvailablePct) && isValidNonNegative(host.memAvailableMb) &&
      isValidNonNegative(h.sample.eldP99Ms) && isValidNonNegative(h.sample.eldMaxMs) &&
      Object.keys(e.pids).every(role => {
        const s = h.sample.proc.perRole?.[role];
        return s?.alive === true && isValidPositive(s.rssMb) && isValidPositive(s.fds) &&
          isValidPositive(s.fdLimit) && isValidNonNegative(s.cpuMsDelta);
      }), "incomplete host or process sample");
    if (h.sample?.proc?.perRole) {
      for (const reason of monitor.observeHarness(h.sample)) failures.push(reason.detail ?? reason.code);
    }
  }
  const continuity = adverseRun ? evaluateFixture(e, fixtureRecords, protectedRecords, failures) : undefined;
  return { verdict: failures.length ? "FAIL" : "PASS", failures, counts, totals, latency, windowLimitMs, quietMs, anomalyTotal, directStatus, ticks, hostSamples: e.host.length,
    ...(adverseRun ? { continuity } : {}) };
}
