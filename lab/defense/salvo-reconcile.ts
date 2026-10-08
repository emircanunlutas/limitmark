/** Offline salvo qualification only. Legacy C1/C2 interpretation is deliberately separate. */
import type { Identity } from "./accounting";
import type { Reason } from "./field-verdict";
import type { GeneratorReport } from "./generator-report";
import { workloadFingerprint } from "./generator-report";
import { BA0_FIELD_C2_SALVO_V1, ba0FieldFingerprint } from "./field-thresholds";
import { WORKLOADS } from "../policy/workloads";
import type { ServerLevelEvidence } from "./reconcile";
import { derivePairs, jointExercised, jointMaterial, pairFixtureLatencies, pairSummaries, SALVO_SPEC, sourceExercised, type JointDerivation, type PairDerivation } from "./salvo-spec";
import { canonicalJson } from "../policy/thresholds";

type Checks = Record<string, boolean>;
export type SalvoDiagnostics = {
  completion: { ok: boolean; failed: string[] }; phase: { ok: boolean; failed: string[] };
  generator: PairDerivation; server: PairDerivation; joint: JointDerivation;
};

export function reconcileSalvo(server: ServerLevelEvidence, report: GeneratorReport): {
  identities: Identity[]; reasons: Reason[]; diagnostics: SalvoDiagnostics;
} {
  const t = BA0_FIELD_C2_SALVO_V1; const spec = SALVO_SPEC;
  const g = report.salvo; const s = server.salvo?.phase; const input = server.reconcileInput;
  const gd = derivePairs(g?.pairs, true); const sd = derivePairs(server.salvo?.pairs, false);
  const finite = (n: unknown): n is number => typeof n === "number" && Number.isFinite(n);
  const near = (a: unknown, b: unknown) => finite(a) && finite(b) && Math.abs(a - b) <= t.qualification!.clockAgreementMs;
  const sum = (v: Record<string, number>) => Object.values(v).reduce((a, b) => a + b, 0);
  const identities: Identity[] = []; const reasons: Reason[] = [];
  const gate = (id: string, checks: Checks, code: Reason["code"] = "identity_failed") => {
    const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([key]) => key);
    identities.push({ id, description: id.replace(/\./g, " "), left: failed.length, right: 0, ok: failed.length === 0 });
    if (failed.length) reasons.push({ code, detail: id });
    return { ok: failed.length === 0, failed };
  };
  const params = ba0FieldFingerprint(t).sha256;
  const workload = workloadFingerprint(WORKLOADS["ba0-l7-pressure-c2-salvo"]);
  gate("g6.salvo_reviewed_binding", {
    reviewed: [server, report].every((side) => side.levelId === t.level.id && side.workers === 2
      && side.paramsFingerprintSha256 === params && side.workloadFingerprintSha256 === workload),
    planned: report.concurrency.planned === 2, drained: report.concurrency.inFlightNow === 0,
    rate: report.rate.ceilingPerSecond === 25,
  }, "identity_binding_mismatch");
  const fixtureIds = ["get_home", "get_privacy", "get_form", "post_inquiry"];
  gate("g1.salvo_fates", {
    count: report.attempted === 1500 && report.responses === 1500 && input.externalAccepted === 1500,
    transport: report.transportFailures === 0,
    histograms: sum(report.statuses) === 1500 && sum(report.outcomes) === 1500,
    fixtures: Object.keys(report.perFixture).length === 4 && fixtureIds.every((id) => report.perFixture[id]?.attempted === 375
      && report.perFixture[id]?.responses === 375 && report.perFixture[id]?.transportFailures === 0),
    fixtureLatency: g != null && gd.valid && canonicalJson(g.fixtureLatencyMs) === canonicalJson(pairFixtureLatencies(g.pairs)),
    recordSummaries: g != null && gd.valid && canonicalJson(report.latencyMs) === canonicalJson(pairSummaries(g.pairs).latencyMs)
      && canonicalJson(report.schedule.lagMs) === canonicalJson(pairSummaries(g.pairs).lagMs) && report.schedule.paced === spec.pairs,
    classes: input.classes.open === 1125 && input.classes.mutation === 375,
    connections: report.connections.new + report.connections.reused === 1500,
    protocol: report.retries === 0 && report.pipelining === false,
  }, "generator_report_mismatch");
  const unexpected = (table: Record<string, number>) => Object.entries(table).some(([status, count]) => count !== 0
    && (status === "429" || (Number(status) >= 500 && Number(status) <= 599 && status !== "503")));
  gate("g2.salvo_no_unexplained_status", {
    generator: !unexpected(report.statuses), server: !unexpected(input.statusHistogram),
    shed: input.status503.unexplained === 0, l1: input.l1Rejected === 0, egress: input.egressFailed === 0,
  }, "unexplained_traffic");
  const completion = gate("g6.salvo_completion", {
    state: report.stop.kind === "completed" && report.stop.detail === null,
    latch: g != null && g.stopLatchedMs === null,
    records: gd.valid && gd.scheduleValid,
    count: report.attempted === 1500 && report.responses === 1500 && report.transportFailures === 0,
    fullDuration: finite(g?.elapsedMs) && g.elapsedMs >= spec.durationMs && g.elapsedMs <= spec.maxElapsedMs,
    wallDuration: finite(g?.elapsedMs) && Math.abs(report.wallClockSeconds * 1000 - g.elapsedMs) <= 10,
    metadata: g != null && gd.firstMs !== null && g.firstDispatchMs === gd.firstMs && g.lastDispatchMs === gd.lastMs
      && g.lastSettlementMs === gd.settlementMs,
    drained: gd.settlementMs !== null && finite(g?.elapsedMs) && gd.settlementMs <= g.elapsedMs && report.concurrency.inFlightNow === 0,
  }, "generator_report_mismatch");
  // Each source must independently pass; the pairs both sources prove material form the joint set. Differing small miss sets are allowed.
  const joint = jointMaterial(gd, sd);
  gate("g5.salvo_exercised", {
    records: gd.valid && sd.valid, generator: sourceExercised(gd), server: sourceExercised(sd), joint: jointExercised(joint),
    maxima: gd.maxInFlight === 2 && sd.maxInFlight === 2 && report.concurrency.maxInFlightObserved === 2 && input.externalInFlightMax === 2,
  });
  const a = s?.armed; const c = s?.closed; const w = server.window;
  const validMark = (mark: typeof a) => mark != null && Number.isSafeInteger(mark.seq) && mark.seq >= 0
    && finite(mark.atMs) && mark.atMs >= 0 && Number.isFinite(Date.parse(mark.wallAt))
    && Number.isSafeInteger(mark.acceptedExternal) && mark.acceptedExternal >= 0
    && Number.isSafeInteger(mark.inFlightExternal) && mark.inFlightExternal >= 0;
  const start = Date.parse(report.startedAt); const end = Date.parse(report.endedAt);
  // Deliberately independent of completion, so an abort is not reported as a fictitious phase violation.
  const phase = gate("g6.salvo_measurement_phase", {
    evidence: s != null && gd.valid && sd.valid && validMark(a) && validMark(c),
    marks: a != null && c != null && a.phase === "armed" && c.phase === "closed" && c.seq >= a.seq
      && c.atMs >= a.atMs && c.atMs - a.atMs <= t.window.hardDeadlineMs,
    armedClean: a != null && a.acceptedExternal === 0 && a.inFlightExternal === 0,
    closedClean: c != null && c.inFlightExternal === 0 && s?.inFlightAtClose === 0,
    contamination: s != null && s.beforeArmed === 0 && s.afterClosed === 0 && s.faults === 0,
    conservation: s != null && c != null && s.inWindow === 1500 && s.inWindow === report.attempted
      && s.inWindow === input.externalAccepted && c.acceptedExternal === s.inWindow && s.settledInWindow === report.responses,
    sourceTimes: s != null && a != null && c != null && finite(s.firstIngressMs) && finite(s.lastIngressMs) && finite(s.lastSettlementMs)
      && s.firstIngressMs >= a.atMs && s.firstIngressMs - a.atMs <= t.window.startSlackMs
      && s.lastIngressMs >= s.firstIngressMs && s.lastSettlementMs >= s.lastIngressMs && s.lastSettlementMs <= c.atMs
      && s.lastSettlementMs - s.firstIngressMs <= spec.maxElapsedMs && c.atMs - s.firstIngressMs >= spec.durationMs,
    sourceRecords: s != null && finite(s.firstIngressMs) && finite(s.lastIngressMs) && finite(s.lastSettlementMs)
      && s.lastIngressMs - s.firstIngressMs === sd.lastMs && s.lastSettlementMs - s.firstIngressMs === sd.settlementMs,
    barrierClock: a != null && c != null && near(Date.parse(c.wallAt) - Date.parse(a.wallAt), c.atMs - a.atMs),
    generatorClock: near(end - start, g?.elapsedMs),
    firstClock: a != null && s != null && near(start + (gd.firstMs ?? NaN), Date.parse(a.wallAt) + (s.firstIngressMs ?? NaN) - a.atMs),
    lastClock: a != null && s != null && near(start + (gd.lastMs ?? NaN), Date.parse(a.wallAt) + (s.lastIngressMs ?? NaN) - a.atMs),
    settledClock: a != null && s != null && near(start + (gd.settlementMs ?? NaN), Date.parse(a.wallAt) + (s.lastSettlementMs ?? NaN) - a.atMs),
    pairClocks: gd.valid && sd.valid && g != null && server.salvo != null && a != null && s != null && g.pairs.every((p, i) => {
      const q = server.salvo!.pairs[i]; const sourceOrigin = Date.parse(a.wallAt) + s.firstIngressMs! - a.atMs;
      // Arrival order within a pair may reverse. Pair bounds still agree on the independently emitting clocks.
      return near(start + Math.min(...p.startsMs as number[]), sourceOrigin + Math.min(...q.startsMs as number[]))
        && near(start + Math.max(...p.startsMs as number[]), sourceOrigin + Math.max(...q.startsMs as number[]))
        && near(start + Math.max(...p.settledMs as number[]), sourceOrigin + Math.max(...q.settledMs as number[]));
    }),
    window: w != null && finite(w.elapsedMs) && w.elapsedMs >= spec.durationMs && near(Date.parse(w.closedAt) - Date.parse(w.openedAt), w.elapsedMs),
    windowOpen: w != null && a != null && s != null && near(Date.parse(w.openedAt), Date.parse(a.wallAt) + (s.firstIngressMs ?? NaN) - a.atMs),
    generatorWindow: w != null && start >= Date.parse(w.openedAt) - 2000 && end <= Date.parse(w.closedAt) + 2000,
    windowClose: w != null && c != null && near(Date.parse(w.closedAt), Date.parse(c.wallAt)),
  });
  return { identities, reasons, diagnostics: { completion, phase, generator: gd, server: sd, joint } };
}
