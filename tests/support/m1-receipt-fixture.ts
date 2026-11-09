import { GENERATOR_REPORT_SCHEMA, type GeneratorReport } from "../../lab/defense/generator-report";
import { FIELD_LEVELS, ba0FieldFingerprint } from "../../lab/defense/field-thresholds";
import { collectGitState } from "../../lab/evidence/manifest";
import type { EvidenceOptions } from "./m1-evidence-dir";
import { remoteWorkload, workload, type E } from "./m1-tally-fixture";

// A package that satisfies criterion 9, the receipt reconciliation AND the status overlay at once, by construction, so the unified acceptance can RECOMPUTE all three from bytes.
// Numbers: 5 canary requests (3 reach the Boundary and the App, 2 are shed by the plane) and 5 remote requests (2 admitted, 3 shed): Boundary and App see 3 canary + 2 remote = 5.

const CANARY_REACHED = 3; const REMOTE_REACHED = 2; const REACHED = CANARY_REACHED + REMOTE_REACHED;
const BOUNDARY_KINDS = ["BOUNDARY_ARRIVED", "BOUNDARY_ADMITTED", "APP_PROOF_ISSUED", "BOUNDARY_FORWARDED", "BOUNDARY_FORWARD_RESPONDED", "BOUNDARY_RESPONDED"];
const APP_KINDS = ["APP_ADMITTED", "APP_EXECUTED", "APP_COMPLETED"];

function journalRows(): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = [];
  for (let request = 1; request <= CANARY_REACHED; request++) {
    for (const k of BOUNDARY_KINDS) rows.push({ src: "b", rid: `canary-${request}`, k });
    for (const k of APP_KINDS) rows.push({ src: "a", rid: `canary-${request}`, k });
  }
  return rows;
}

/** Run slot n (1..3) of a campaign: its own campaign id, window (hour 10+n) and generator run. Slot 0 is the default single-run fixture. */
export const slotFacts = (slot: number) => ({
  campaignId: slot === 0 ? "campaign-a" : `campaign-slot-${slot}`, hour: 10 + slot, runId: `2026110${slot}T10000${slot}Z-load-aaaaa${slot}`,
  opened: `2026-11-08T${10 + slot}:00:00.000Z`, closed: `2026-11-08T${10 + slot}:01:00.000Z`, startedAt: `2026-11-08T${10 + slot}:00:05.000Z`, endedAt: `2026-11-08T${10 + slot}:00:35.000Z`,
});
export function slotMutations(slot: number): Record<string, (content: Record<string, unknown>) => void> {
  const facts = slotFacts(slot);
  return {
    "server-level.json": (c) => { c.campaignId = facts.campaignId; c.window = { openedAt: facts.opened, closedAt: facts.closed, elapsedMs: 60_000 }; },
    "core.json": (c) => { (c.level as { campaignId: string }).campaignId = facts.campaignId; },
  };
}

export function receiptValidOptions(): Pick<EvidenceOptions, "journalEvents" | "journalLine" | "mutate" | "artifacts"> {
  const canary = workload(); const rows = journalRows();
  const filler: E[] = rows.map(() => ({ kind: "FILLER" }));
  const channel = (emitted: number) => ({ emitted, dropped: 0, sent: emitted, received: emitted, queued: 0, unacknowledged: 0, queueHighWater: 3, lastSeq: emitted });
  return {
    journalEvents: [...canary, ...filler],
    journalLine: (line, index) => (index < canary.length ? line : JSON.stringify({ ...rows[index - canary.length], seq: index + 1 })),
    artifacts: { "canary.json": { clientObservedMutations: 0 } },
    mutate: {
      "external.json": (content) => {
        const counters = content.counters as { boundary: Record<string, number>; app: Record<string, number>; egress: Record<string, number> };
        counters.boundary = { arrived: REMOTE_REACHED, admitted: REMOTE_REACHED, rejected: 0, appProofsIssued: REMOTE_REACHED, relayed: REMOTE_REACHED, forwardResponded: REMOTE_REACHED, forwardFailed: 0, responded: REMOTE_REACHED, aborted: 0 };
        const l2 = counters as unknown as { l2: { shedByReason?: Record<string, number> } }; l2.l2.shedByReason = { "mutation.unverified.lane_budget": 3 };
        counters.app = { admitted: REMOTE_REACHED, refused: 0, executed: REMOTE_REACHED, mutated: 0, completed: REMOTE_REACHED, aborted: 0 };
      },
      "server-level.json": (content) => { const input = content.reconcileInput as { connections: Record<string, number> }; input.connections.parserRejected = 0; input.connections.protocolRefused = 0; },
      "kind-ledger.json": (content) => { const counts = content.counts as Record<string, number>; counts.EGRESS_FAILED ??= 0; },
      "processes.json": (content) => {
        content.boundary = { drained: true, channel: channel(6 * REACHED), stats: { arrived: REACHED, admitted: REACHED, rejected: 0, appProofsIssued: REACHED, relayed: REACHED, forwardResponded: REACHED, forwardFailed: 0, responded: REACHED, aborted: 0, parserRejected: 0, protocolRefused: 0 } };
        content.app = { drained: true, channel: channel(3 * REACHED), stats: { counters: { admitted: REACHED, refused: 0, executed: REACHED, stateMutations: 0, parserRejected: 0, protocolRefused: 0 }, served: { received: REACHED, completed: REACHED, aborted: 0, overloaded: 0 } } };
      },
    },
  };
}

/** The generator report that agrees with the remote workload of the fixture (5 requests: 2 x 200, 3 x 503) and with the package's level evidence. */
export function generatorReportFor(campaignId = "campaign-a", runId = "20261108T100000Z-load-aaaaaa", startedAt = "2026-11-08T10:00:05.000Z", endedAt = "2026-11-08T10:00:35.000Z"): GeneratorReport {
  const summary = (p99 = 5) => ({ count: 5, min: 1, mean: 3, p50: 3, p90: 4, p95: 5, p99, max: p99 });
  const pinned = ba0FieldFingerprint(FIELD_LEVELS["ba0-l7-c1"].thresholds);
  const remote = remoteWorkload(); const attempted = remote.filter((event) => event.kind === "INGRESS_ACCEPTED").length;
  return {
    schema: GENERATOR_REPORT_SCHEMA, campaignId, levelId: "ba0-l7-c1", runId, gitSha: collectGitState().gitSha, paramsFingerprintSha256: pinned.sha256, workloadFingerprintSha256: "c".repeat(64), targetId: "sut-test", workers: 1,
    startedAt, endedAt, wallClockSeconds: 30, attempted, responses: attempted, transportFailures: 0, outcomes: { ok: 2, http_5xx: 3 }, statuses: { "200": 2, "503": 3 },
    perFixture: { get_home: { attempted: 2, responses: 2, transportFailures: 0 }, post_inquiry: { attempted: 3, responses: 3, transportFailures: 0 } },
    latencyMs: summary(), bytes: { wireSent: 1, wireReceived: 1, contentReceived: 1 }, concurrency: { planned: 1, inFlightNow: 0, maxInFlightObserved: 1 }, connections: { new: 3, reused: 2 },
    rate: { achievedPerSecond: 1, ceilingPerSecond: 25 }, schedule: { paced: attempted, lagMs: summary(3) }, generatorHealth: { eldP50Ms: 0, eldP99Ms: 2, eldMaxMs: 5, cpuUserMs: 10, cpuSystemMs: 5, rssMb: 60 },
    stop: { kind: "completed", detail: null }, retries: 0, pipelining: false,
  };
}
