import { BA0_FIELD_C2_SALVO_V1, ba0FieldFingerprint } from "../../lab/defense/field-thresholds";
import { GENERATOR_REPORT_SCHEMA, workloadFingerprint, type GeneratorReport } from "../../lab/defense/generator-report";
import { SERVER_LEVEL_SCHEMA, type ServerLevelEvidence } from "../../lab/defense/reconcile";
import { pairFixtureLatencies, pairSummaries, type SalvoPair } from "../../lab/defense/salvo-spec";
import { WORKLOADS } from "../../lab/policy/workloads";
import { summarizeLatencies } from "../../lab/policy/thresholds";

export function pairRecords(offset = 0): SalvoPair[] {
  return Array.from({ length: 750 }, (_, index) => {
    const at = index * 80 + offset;
    return { index, startsMs: [at, at + 0.25], settledMs: [at + 6, at + 6.25] };
  });
}

export function salvoFixture(): { server: ServerLevelEvidence; report: GeneratorReport } {
  const params = ba0FieldFingerprint(BA0_FIELD_C2_SALVO_V1).sha256;
  const workload = workloadFingerprint(WORKLOADS["ba0-l7-pressure-c2-salvo"]);
  const common = { campaignId: "salvo-campaign", levelId: "ba0-l7-c2-salvo", gitSha: "a".repeat(40),
    paramsFingerprintSha256: params, workloadFingerprintSha256: workload, workers: 2 };
  const summary = summarizeLatencies(Array(1500).fill(6));
  const report: GeneratorReport = {
    ...common, schema: GENERATOR_REPORT_SCHEMA, runId: "20261007T100000Z-load-aaaaaa", targetId: "sut-test",
    startedAt: "2026-10-07T10:00:05.000Z", endedAt: "2026-10-07T10:01:05.000Z", wallClockSeconds: 60,
    attempted: 1500, responses: 1500, transportFailures: 0, outcomes: { ok: 1187, http_5xx: 313 }, statuses: { "200": 1187, "503": 313 },
    perFixture: Object.fromEntries(["get_home", "get_privacy", "get_form", "post_inquiry"].map((id) => [id, { attempted: 375, responses: 375, transportFailures: 0 }])),
    latencyMs: summary, bytes: { wireSent: 1, wireReceived: 1, contentReceived: 1 },
    concurrency: { planned: 2, inFlightNow: 0, maxInFlightObserved: 2 }, connections: { new: 2, reused: 1498 },
    rate: { achievedPerSecond: 25, ceilingPerSecond: 25 }, schedule: { paced: 750, lagMs: pairSummaries(pairRecords(1)).lagMs },
    generatorHealth: { eldP50Ms: 0, eldP99Ms: 1, eldMaxMs: 1, cpuUserMs: 1, cpuSystemMs: 1, rssMb: 20 },
    stop: { kind: "completed", detail: null }, retries: 0, pipelining: false,
    salvo: { elapsedMs: 60000, firstDispatchMs: 1, lastDispatchMs: 59921.25, lastSettlementMs: 59927.25,
      stopLatchedMs: null, pairs: pairRecords(1), fixtureLatencyMs: pairFixtureLatencies(pairRecords(1)) },
  };
  const server: ServerLevelEvidence = {
    ...common, schema: SERVER_LEVEL_SCHEMA, serverSide: { status: "complete", failureClass: null, reasons: [] },
    window: { openedAt: report.startedAt, closedAt: "2026-10-07T10:01:10.000Z", elapsedMs: 65000 },
    reconcileInput: { externalAccepted: 1500, statusHistogram: { ...report.statuses }, status503: { total: 313, expectedShed: 313, unexplained: 0 },
      classes: { open: 1125, mutation: 375 }, l1Rejected: 0, egressFailed: 0,
      connections: { acceptedRemote: 2, dropped: 0, clientErrorTotal: 0, clientErrorNoRequest: 0, parserRejected: 0, protocolRefused: 0 }, externalInFlightMax: 2 },
    salvo: { pairs: pairRecords(), phase: {
      armed: { phase: "armed", seq: 0, atMs: 0, wallAt: "2026-10-07T10:00:00.000Z", acceptedExternal: 0, inFlightExternal: 0 },
      closed: { phase: "closed", seq: 20000, atMs: 70000, wallAt: "2026-10-07T10:01:10.000Z", acceptedExternal: 1500, inFlightExternal: 0 },
      beforeArmed: 0, inWindow: 1500, afterClosed: 0, settledInWindow: 1500, inFlightAtClose: 0,
      firstIngressMs: 5001, lastIngressMs: 64921.25, lastSettlementMs: 64927.25, faults: 0,
      exposure: { binMs: 1000, overlapMs: Array(60).fill(0), overlappingStarts: Array(60).fill(0) },
    } },
  };
  return { server, report };
}

export function serialPair(p: SalvoPair): void {
  p.startsMs[1] = p.settledMs[0]! + 1;
  p.settledMs[1] = p.startsMs[1] + 6;
}

export function refreshFixture(c: ReturnType<typeof salvoFixture>): void {
  const gp = c.report.salvo!.pairs; const sp = c.server.salvo!.pairs;
  c.report.salvo!.firstDispatchMs = Math.min(...gp[0].startsMs as number[]);
  c.report.salvo!.lastDispatchMs = Math.max(...gp.at(-1)!.startsMs as number[]);
  c.report.salvo!.lastSettlementMs = Math.max(...gp.at(-1)!.settledMs as number[]);
  c.report.salvo!.fixtureLatencyMs = pairFixtureLatencies(gp);
  const summaries = pairSummaries(gp); c.report.latencyMs = summaries.latencyMs; c.report.schedule.lagMs = summaries.lagMs;
  c.server.salvo!.phase.lastIngressMs = c.server.salvo!.phase.firstIngressMs! + Math.max(...sp.at(-1)!.startsMs as number[]);
  c.server.salvo!.phase.lastSettlementMs = c.server.salvo!.phase.firstIngressMs! + Math.max(...sp.at(-1)!.settledMs as number[]);
}
