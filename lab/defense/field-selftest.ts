/**
 * Field qualification: synthetic, deterministic lifecycles for the external lane, and the EVIDENCE SELFTEST built on them.
 *
 * The factory below produces the exact plane, Boundary and App events a real request would (the same kinds, the same hop and proof tags, a
 * consistent L2 bucket replay), so the reducer, the accounting and the evidence writer can be exercised end to end without a network. The
 * selftest pushes one synthetic level through the REAL `writeFieldEvidence`, so a key or value the evidence scanner would refuse is found before
 * a field run, not at the end of one (the scanner refuses at the end of a run, which is the worst time).
 *
 * Nothing here opens a socket, forks a process or touches a provider.
 */
import type { AppEvent, BoundaryEvent, PlaneEvent } from "../../defense/core/ledger";
import { UNIT } from "../../defense/core/lanes";
import type { L2Params, PlaneTick } from "../../defense/plane/l2-protocol";
import { EvidenceRun, collectGitState, EVIDENCE_ROOT } from "../evidence/manifest";
import { journeyCompletionRates, type JourneyResult } from "./canary";
import { canaryCounts, deriveExternalAccounting } from "./external-accounting";
import { ExternalReducer } from "./external-reducer";
import { writeFieldEvidence, type FieldEvidenceBundle, type WriteResult } from "./field-evidence";
import { BA0_FIELD_V1, ba0FieldFingerprint } from "./field-thresholds";
import { decideServerSide } from "./field-verdict";
import { workloadFingerprint } from "./generator-report";
import { WORKLOADS } from "../policy/workloads";

export type LifecycleKind = "get_proxied" | "post_mutated" | "post_shed" | "l1_rejected" | "post_credited_mutated" | "get_egress_failed" | "get_503_proxied";

export type Lifecycle = { plane: PlaneEvent[]; boundary: BoundaryEvent[]; app: AppEvent[] };

/** A consistent token bucket simulation: its (dt, lvl, lseq) triples replay exactly under `auditBucket`. */
class BucketSim {
  private level: number;
  private last: number | null = null;
  private takes = 0;
  constructor(private readonly capacity: number, private readonly refillPerSecond: number) { this.level = capacity * UNIT; }
  take(dt: number): { ok: boolean; dt: number; lvl: number; lseq: number } {
    if (this.last === null) this.last = dt;
    this.level = Math.min(this.capacity * UNIT, this.level + (dt - this.last) * this.refillPerSecond * 1000);
    this.last = dt;
    this.takes++;
    const ok = this.level >= UNIT;
    if (ok) this.level -= UNIT;
    return { ok, dt, lvl: this.level, lseq: this.takes };
  }
}

export class ExternalEventFactory {
  private planeSeq = 0;
  private boundarySeq = 0;
  private appSeq = 0;
  private counter = 0;
  private readonly credited: BucketSim;
  private readonly unverified: BucketSim;
  /** The simulated clock in ms. */
  now = 0;

  constructor(l2: L2Params) {
    this.credited = new BucketSim(l2.credited.capacity, l2.credited.refillPerSecond);
    this.unverified = new BucketSim(l2.unverified.capacity, l2.unverified.refillPerSecond);
  }

  nonce(): string { return `u${String(++this.counter).padStart(21, "X")}`; }

  /** One request's events, with sequence numbers taken from this factory's three streams in call order. */
  lifecycle(kind: LifecycleKind, nonce: string = this.nonce()): Lifecycle {
    const plane: PlaneEvent[] = [];
    const boundary: BoundaryEvent[] = [];
    const app: AppEvent[] = [];
    const p = (event: Omit<PlaneEvent, "seq" | "t" | "nonce">): PlaneEvent => { const out = { ...event, nonce, seq: ++this.planeSeq, t: this.now } as PlaneEvent; plane.push(out); return out; };
    const b = (event: Omit<BoundaryEvent, "seq" | "t" | "nonce">): BoundaryEvent => { const out = { ...event, nonce, seq: ++this.boundarySeq, t: this.now } as BoundaryEvent; boundary.push(out); return out; };
    const a = (event: Omit<AppEvent, "seq" | "t" | "nonce">): AppEvent => { const out = { ...event, nonce, seq: ++this.appSeq, t: this.now } as AppEvent; app.push(out); return out; };

    p({ kind: "INGRESS_ACCEPTED", stripped: 0, ingress: "external" });
    p({ kind: "L1_ENTERED" });
    if (kind === "l1_rejected") {
      p({ kind: "L1_REJECTED", reason: "a7.path_not_allowed", stage: "pre_parse" });
      p({ kind: "INGRESS_RESPONDED", status: 404 });
      return { plane, boundary, app };
    }
    p({ kind: "L1_PASSED" });
    p({ kind: "L2_ENTERED" });
    const mutation = kind === "post_mutated" || kind === "post_shed" || kind === "post_credited_mutated";
    const bucket = kind === "post_credited_mutated" ? this.credited : this.unverified;
    const lane = kind === "post_credited_mutated" ? "credited" : "unverified";
    if (!mutation) p({ kind: "L2_DECIDED", class: "open", lane: "open", outcome: "admitted" });
    else {
      const taken = bucket.take(this.now);
      if (!taken.ok) {
        p({ kind: "L2_DECIDED", class: "mutation", lane, outcome: "shed", shedReason: "lane_budget", dt: taken.dt, lvl: taken.lvl, lseq: taken.lseq });
        p({ kind: "INGRESS_RESPONDED", status: 503 });
        return { plane, boundary, app };
      }
      p({ kind: "L2_DECIDED", class: "mutation", lane, outcome: "admitted", dt: taken.dt, lvl: taken.lvl, lseq: taken.lseq, ...(lane === "credited" ? { creditTag: "c".repeat(16) } : {}) });
    }
    const attempted = p({ kind: "EGRESS_ATTEMPTED" });
    const hop = attempted.seq;
    const pbTag = `pb${String(this.counter).padStart(14, "0")}`;
    const baTag = `ba${String(this.counter).padStart(14, "0")}`;
    p({ kind: "PROOF_ISSUED", pbTag });
    if (kind === "get_egress_failed") {
      p({ kind: "EGRESS_FAILED", egressError: "refused" });
      p({ kind: "INGRESS_RESPONDED", status: 502 });
      return { plane, boundary, app };
    }
    b({ kind: "BOUNDARY_ARRIVED" });
    b({ kind: "BOUNDARY_ADMITTED", hop, pbTag });
    b({ kind: "APP_PROOF_ISSUED", hop, pbTag, baTag });
    b({ kind: "BOUNDARY_FORWARDED", hop });
    const status = kind === "get_503_proxied" ? 503 : 200;
    a({ kind: "APP_ADMITTED", hop, pbTag, baTag, spoofed: 0 });
    a({ kind: "APP_EXECUTED", hop, pbTag, baTag });
    if (mutation) a({ kind: "APP_MUTATED", hop, pbTag, baTag });
    a({ kind: "APP_COMPLETED", hop, pbTag, baTag, status });
    b({ kind: "BOUNDARY_FORWARD_RESPONDED", hop, status });
    b({ kind: "BOUNDARY_RESPONDED", hop, status });
    p({ kind: "EGRESS_RESPONDED", status });
    p({ kind: "INGRESS_RESPONDED", status });
    return { plane, boundary, app };
  }
}

/** Feeds a lifecycle to a reducer in the order the three IPC pipes could deliver it (plane first, then downstream; any order is legal). */
export function feed(reducer: ExternalReducer, lifecycle: Lifecycle, downstreamFirst = false): void {
  const downstream = () => { for (const event of lifecycle.boundary) reducer.ingestBoundary(event); for (const event of lifecycle.app) reducer.ingestApp(event); };
  if (downstreamFirst) downstream();
  for (const event of lifecycle.plane) reducer.ingestPlane(event);
  if (!downstreamFirst) downstream();
}

// ---------------------------------------------------------------------------
// The evidence selftest
// ---------------------------------------------------------------------------

const journey = (lane: "control" | "protected", phase: string, index: number): JourneyResult => ({
  lane, phase, journey: index, completed: true,
  steps: ["homepage", "privacy", "form", "valid_post", "thank_you"].map((name, step) => ({
    step: step + 1, name: name as JourneyResult["steps"][number]["name"], ok: true, failure: null, status: 200, latencyMs: 3 + step, bodyDigest: "d".repeat(64), headerNames: ["content-type"],
  })),
});

/** A realistic plane tick, shaped exactly like `PlaneTickData`, for the telemetry ring. */
function syntheticPlaneTick(seq: number): PlaneTick {
  const composer = { evaluated: 4, pass: 4, reject: 0, shed: 0, error: { throw: 0, timeout: 0, invalid_verdict: 0 }, inFlight: 0, inFlightHighWater: 1, abandoned: 0, abandonedReclaimed: 0, lateVerdictsDiscarded: 0 };
  return {
    type: "tick", role: "plane", tickSeq: seq, tMonoMs: seq * 1000, final: false,
    sample: { eldP50Ms: 0.4, eldP99Ms: 1.2, eldMaxMs: 3.1, rssMb: 90, cpuUserMs: 12, cpuSystemMs: 4 },
    data: {
      ingressOpen: true, front: { accepted: 4, inFlight: 0, inFlightHighWater: 1, parserRejected: 0, proxied: 4, completed: 4, aborted: 0, strippedHeaders: 0 }, inFlightMax: 1, inFlightExternalMax: 1,
      external: { accepted: 4, inFlight: 0, inFlightHighWater: 1 },
      connections: {
        accepted: { local: 1, remote: 1 }, dropped: 0, active: 0, activeHighWater: 1, closed: { clean: 2, error: 0 }, closedWithoutRequest: 0, clientError: {}, clientErrorOverflow: 0,
        clientErrorAnswered: 0, clientErrorDestroyed: 0, clientErrorNoRequest: 0, clientErrorInRequest: 0, socketError: {}, socketErrorOverflow: 0, protocolRefused: { connect: 0, expectation: 0 },
      },
      l1Composer: composer, l1Occupancy: 0, l1: { evaluated: 4, grammarParses: 1 }, hop: { issued: 4, signFailures: 0, droppedUnbound: 0 },
      l2: {
        composer, occupancy: 0,
        lanes: {
          epoch: 0, credited: { capacity: 10, levelUnits: 10 * UNIT, takes: 0, admitted: 0, shed: 0 }, unverified: { capacity: 3, levelUnits: 3 * UNIT, takes: 0, admitted: 0, shed: 0 },
          filter: { epoch: 0, bitsPerGeneration: 2 ** 23, hashes: 7, popcount: [0, 0], fillRatio: [0, 0], fprEstimate: 0, inserts: 0, lookups: 0, hits: 0, rotations: 0 },
          poisoned: false, ledger: { size: 0, capacity: 512, highWater: 0, committedLive: 0, allocated: 0, purged: 0, fullRefusals: 0, stateViolations: 0 },
          decisions: { "open.open.admitted": 4 }, spentOnDiscard: { credited: 0, unverified: 0 }, digest: "0123456789abcdef",
        },
      },
      channel: { emitted: 40, dropped: 0, sent: 40, received: 40, queued: 0, unacknowledged: 0, queueHighWater: 3, lastSeq: 40 },
    },
  };
}

/** Builds one synthetic level's bundle from real components (the reducer, the accounting, the verdict). */
export function buildSelftestBundle(): FieldEvidenceBundle {
  const t = BA0_FIELD_V1;
  const factory = new ExternalEventFactory(t.l2);
  const reducer = new ExternalReducer({ allowedShed: t.allowedShed, report: () => undefined });
  for (let index = 0; index < 4; index++) feed(reducer, factory.lifecycle("get_proxied"), index % 2 === 1);
  for (let index = 0; index < 3; index++) { factory.now += 1_000; feed(reducer, factory.lifecycle("post_mutated")); }
  for (let index = 0; index < 4; index++) feed(reducer, factory.lifecycle("post_shed"));
  reducer.finalize();
  const counters = reducer.counters();
  const journeys = [...[1, 2].flatMap((index) => [journey("control", "baseline", index), journey("protected", "baseline", index)]), journey("protected", "window", 1), journey("protected", "residual", 1), journey("protected", "recovery", 1)];
  const canary = {
    jcr: journeyCompletionRates(journeys), journeys: journeys.length, legitimateRefusals: 0, l1FalseRejects: 0, l2NonAdmits: 0, parityMismatches: 0, parityCompared: 10,
    scheduleLagMs: { count: 3, p50: 1, p95: 2, p99: 3, max: 3 }, latencyMs: { baseline: { count: 10, p50: 5, p95: 8, p99: 9, max: 9 } }, windowLatencyOk: true, stepFailures: {}, clientObservedMutations: 0, interruptedJourneys: 0,
  };
  const accounting = deriveExternalAccounting({
    external: counters, externalDecisions: reducer.decisions(), canary: canaryCounts([], 0), planeFin: null, boundaryFin: null, appFin: null, connections: null, l2: t.l2, windowElapsedMs: 10_000,
    workers: 1, externalInFlightMax: 1, streams: { planeDropped: 0, boundaryDropped: 0, appDropped: 0, drained: true, finalTicks: { plane: true, boundary: true, app: true }, tickGaps: 0 },
  });
  const git = collectGitState();
  const serverSide = decideServerSide([], true);
  return {
    level: { id: t.level.id, campaignId: "selftest-campaign", workers: 1 }, parameters: ba0FieldFingerprint(t), workloadSha256: workloadFingerprint(WORKLOADS["ba0-l7-pressure-c1"]), thresholds: t, git,
    serverSide, firstReason: null, reasons: [], machine: { transitions: [{ state: "CREATED", atMs: 0 }, { state: "PREFLIGHT", atMs: 1 }, { state: "DONE", atMs: 9 }], phasesCompleted: true },
    sequence: [{ name: "close_ingress", ok: true, timedOut: false, skippedByCap: false, ms: 5, error: null }], preflight: null, exposure: { running: { checks: 10, violations: [] }, final: null },
    window: { openedAt: new Date(0).toISOString(), closedAt: new Date(60_000).toISOString(), elapsedMs: 60_000 }, external: counters, accounting, traces: reducer.traces(), canary,
    telemetry: { gaps: 0, gapDetails: [], finalTicks: { plane: true, boundary: true, app: true }, ring: { plane: [syntheticPlaneTick(1), syntheticPlaneTick(2)], boundary: [], app: [] }, harnessEld: { highTicks: 0, max: 2, ticks: 60 }, peaks: { hostCpuBusyPct: 12, planeEldP99Ms: 1.2 } },
    connections: { acceptedLocal: 1, acceptedRemote: 1, closedClean: 2, closedError: 0, active: 0, dropped: 0, clientErrorTotal: 0, clientErrorNoRequest: 0, protocolRefused: 0, parserRejected: 0 }, externalInFlightMax: 1,
    processes: { plane: null, boundary: null, app: null }, collector: { anomalyTotal: 0, anomalies: [], records: 0, journal: null }, recovery: { quietMs: t.recovery.quietMs, checked: true, ok: true, detail: "buckets full, no live credits" },
    reconcileInput: {
      externalAccepted: counters.accepted, statusHistogram: counters.statusHistogram, status503: { total: counters.status503.total, expectedShed: counters.status503.expectedShed, unexplained: counters.status503.unexplained },
      classes: counters.l2.classes, l1Rejected: 0, egressFailed: 0, connections: { acceptedRemote: 1, dropped: 0, clientErrorTotal: 0, clientErrorNoRequest: 0, parserRejected: 0, protocolRefused: 0 }, externalInFlightMax: 1,
    },
    anonymousRefusals: reducer.anonymousRefusals(),
  };
}

/** Runs the synthetic bundle through the real evidence writer. `ok` means every artifact was accepted by the evidence scanner. */
export async function runFieldSelftest(root: string = EVIDENCE_ROOT): Promise<WriteResult & { ok: boolean; directory: string }> {
  const evidence = new EvidenceRun("field-selftest", "selftest", new Date(), root);
  const result = writeFieldEvidence(evidence, buildSelftestBundle());
  return { ...result, ok: result.failed.length === 0, directory: evidence.directory };
}
