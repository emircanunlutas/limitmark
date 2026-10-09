/**
 * Field qualification: the parameter set `ba0-field-v1` for the FIRST external L7 qualification level (N = 1), and the preflight BUDGET
 * GATES that compare the planned level with evidence, modeled memory/journal, channel, Bloom and ledger budgets before any public bind.
 *
 * STATUS: provisional and uncalibrated. These are the reviewed first-level qualification parameters. They are NOT production defaults and
 * NOT calibrated production parameters; the Slice-3 attenuation figures were measured with a scaled-down filter and a two-second epoch and
 * do not transfer to this set. Changing any value changes the recorded fingerprint, and a VALID verdict is scoped to that fingerprint.
 *
 * A level is one reviewed (levelId, N). A higher level is a new reviewed code addition, never a flag, an environment variable or an
 * automatic step.
 */
import { createHash } from "node:crypto";
import { requiredLedgerCapacity } from "../../defense/core/lanes";
import type { L2Params } from "../../defense/plane/l2-protocol";
import { canonicalJson } from "../policy/thresholds";
import { BA0_ORIGIN_LOCAL_V1 } from "./origin-thresholds";
import { DEFAULT_EXTERNAL_LIMITS, type AllowedShed, type ExternalLimits } from "./external-reducer";
import { SALVO_DIAGNOSTIC_LIMITS } from "./salvo-diagnostics";
import { SALVO_SPEC } from "./salvo-spec";

const EPOCH_MS = 60_000;
const SETTLE_MARGIN_MS = 15_000;

export type Ba0FieldThresholds = {
  id: "ba0-field-v1" | "ba0-field-c2-v1" | "ba0-field-c2-salvo-v1";
  version: 1;
  description: string;
  calibration: "provisional-uncalibrated";
  status: "first level qualification parameters; not production defaults" | "second level qualification parameters; not production defaults";
  level: {
    id: "ba0-l7-c1" | "ba0-l7-c2" | "ba0-l7-c2-salvo";
    workers: 1 | 2;
    durationSeconds: number;
    maxRequestsPerSecond: number;
    maxTotalRequests: number;
    requestTimeoutMs: number;
    maxResponseBytes: number;
    /** The reviewed request cycle: the generator sends these in order, round robin. */
    fixtureCycle: readonly { method: "GET" | "POST"; path: string }[];
  };
  l2: L2Params;
  composer: { timeoutMs: number; maxConcurrent: number };
  hop: { pbLifetimeMs: number; baLifetimeMs: number; skewMs: number; replayCapacity: number; bodyDeadlineMs: number; forwardTimeoutMs: number };
  plane: { bodyDeadlineMs: number; egressTimeoutMs: number };
  channel: { queueCap: number; windowCap: number };
  collector: { maxRequests: number; maxEventsPerRecord: number; maxJournalBytes: number; maxAnomalies: number };
  external: ExternalLimits;
  /** The only shed this workload expects. Anything else that answers 503 is unexplained (D6). */
  allowedShed: readonly AllowedShed[];
  window: { startSlackMs: number; hardDeadlineMs: number; quiescenceMs: number; setupAllowanceMs: number; drainAllowanceMs: number };
  recovery: { epochMs: number; settleMarginMs: number; quietMs: number };
  canary: {
    baselineJourneys: number; gapMs: number; residualJourneys: number; residualGapMs: number; recoveryJourneys: number; timeoutMs: number;
    scheduleLagP99Ms: number; harnessEldP99Ms: number; jcrMinimum: number; windowLatency: { p95Factor: number; p95AddedMs: number };
  };
  telemetry: { tickMs: number; ringTicks: number; gapToleranceMs: number };
  ceilings: { hostCpuBusyPct: number; hostCpuTicks: number; memAvailablePct: number; planeEldP99Ms: number; planeEldTicks: number; rssMb: number; fdPct: number };
  generator: { scheduleLagP99Ms: number; eldP99Ms: number };
  exposure: { ambientAllowedPorts: readonly number[]; forbiddenAmbientPorts: readonly number[]; forbiddenPlanePorts: readonly number[] };
  stop: { closeIngressMs: number; drainMs: number; finalTelemetryMs: number; snapshotMs: number; finalizeMs: number; terminateMs: number; hardCapMs: number };
  targetMinRemainingMs: number;
  /** Present only for N=2: qualification rules, never enforcement inputs. */
  qualification?: { version: 1; exercise: "cycle-per-tick" | "salvo-pairs"; completion: "duration-completed" | "finite-schedule-duration"; clockAgreementMs: number };
  salvo?: typeof SALVO_SPEC;
};

export const BA0_FIELD_V1: Ba0FieldThresholds = Object.freeze({
  id: "ba0-field-v1",
  version: 1,
  description: "BA0 first external L7 qualification level (N equals 1): plain HTTP, one reviewed fixed Defense Plane ingress on a disposable host, one authorized generator /32, bounded and finite.",
  calibration: "provisional-uncalibrated",
  status: "first level qualification parameters; not production defaults",
  level: {
    id: "ba0-l7-c1", workers: 1, durationSeconds: 60, maxRequestsPerSecond: 25, maxTotalRequests: 1_500, requestTimeoutMs: 5_000, maxResponseBytes: 1_048_576,
    fixtureCycle: [{ method: "GET", path: "/" }, { method: "GET", path: "/gizlilik" }, { method: "GET", path: "/test-talep-et" }, { method: "POST", path: "/api/public-inquiries" }],
  },
  l2: {
    filterBits: 2 ** 23, filterHashes: 7, epochMs: EPOCH_MS,
    credited: { capacity: 10, refillPerSecond: 2 }, unverified: { capacity: 3, refillPerSecond: 1 },
    maxUses: 3, ledgerCapacity: 512, stage: { timeoutMs: 50, maxConcurrent: 64 },
  },
  composer: BA0_ORIGIN_LOCAL_V1.composer,
  hop: BA0_ORIGIN_LOCAL_V1.hop,
  plane: { bodyDeadlineMs: 5_000, egressTimeoutMs: 5_000 },
  channel: { queueCap: 16_384, windowCap: 8_192 },
  collector: { maxRequests: 4_000, maxEventsPerRecord: 32, maxJournalBytes: 48 * 1_048_576, maxAnomalies: 200 },
  external: DEFAULT_EXTERNAL_LIMITS,
  allowedShed: [{ class: "mutation", lane: "unverified", reason: "lane_budget" }],
  window: { startSlackMs: 20_000, hardDeadlineMs: 90_000, quiescenceMs: 5_000, setupAllowanceMs: 2_000, drainAllowanceMs: 2_000 },
  recovery: { epochMs: EPOCH_MS, settleMarginMs: SETTLE_MARGIN_MS, quietMs: 2 * EPOCH_MS + SETTLE_MARGIN_MS },
  canary: {
    baselineJourneys: 12, gapMs: 4_000, residualJourneys: 3, residualGapMs: 1_000, recoveryJourneys: 6, timeoutMs: 5_000,
    scheduleLagP99Ms: 100, harnessEldP99Ms: 100, jcrMinimum: 1, windowLatency: { p95Factor: 4, p95AddedMs: 150 },
  },
  telemetry: { tickMs: 1_000, ringTicks: 120, gapToleranceMs: 2_500 },
  ceilings: { hostCpuBusyPct: 80, hostCpuTicks: 3, memAvailablePct: 15, planeEldP99Ms: 250, planeEldTicks: 3, rssMb: 512, fdPct: 70 },
  generator: { scheduleLagP99Ms: 50, eldP99Ms: 100 },
  exposure: { ambientAllowedPorts: [22], forbiddenAmbientPorts: [3000], forbiddenPlanePorts: [22, 80, 443, 3000, 5432, 55416, 55417] },
  stop: { closeIngressMs: 1_000, drainMs: 10_000, finalTelemetryMs: 5_000, snapshotMs: 3_000, finalizeMs: 15_000, terminateMs: 6_000, hardCapMs: 45_000 },
  targetMinRemainingMs: 15 * 60_000,
}) as Ba0FieldThresholds;

/** All defense/canary parameters and evidence capacities are inherited; qualification requires N=2 exercise and phase evidence. */
export const BA0_FIELD_C2_V1: Ba0FieldThresholds = Object.freeze({
  ...BA0_FIELD_V1,
  id: "ba0-field-c2-v1",
  description: "BA0 second external L7 qualification level (N equals 2): two closed-loop workers sharing the same aggregate pacing and request ceilings as N equals 1; existing defense behaviour is observational.",
  status: "second level qualification parameters; not production defaults",
  level: Object.freeze({ ...BA0_FIELD_V1.level, id: "ba0-l7-c2", workers: 2 }),
  qualification: Object.freeze({ version: 1, exercise: "cycle-per-tick", completion: "duration-completed", clockAgreementMs: 2_000 }),
});

/** New arrival waveform; historical C1/C2 parameter objects remain byte-for-byte canonical equivalents. */
export const BA0_FIELD_C2_SALVO_V1: Ba0FieldThresholds = Object.freeze({
  ...BA0_FIELD_C2_V1, id: "ba0-field-c2-salvo-v1",
  description: "BA0 concurrency two salvo: 750 finite paired releases at 80 ms; unchanged defense; 25 requests per second campaign average with burst two.",
  level: Object.freeze({ ...BA0_FIELD_C2_V1.level, id: "ba0-l7-c2-salvo" }),
  qualification: Object.freeze({ version: 1, exercise: "salvo-pairs", completion: "finite-schedule-duration", clockAgreementMs: 2_000 }),
  salvo: SALVO_SPEC,
});

/** Shared selection only: both participants independently select the exact reviewed set before running. */
export const FIELD_LEVELS = Object.freeze({
  "ba0-l7-c1": Object.freeze({ workload: "ba0-l7-pressure-c1" as const, thresholds: BA0_FIELD_V1 }),
  "ba0-l7-c2": Object.freeze({ workload: "ba0-l7-pressure-c2" as const, thresholds: BA0_FIELD_C2_V1 }),
  "ba0-l7-c2-salvo": Object.freeze({ workload: "ba0-l7-pressure-c2-salvo" as const, thresholds: BA0_FIELD_C2_SALVO_V1 }),
});

export function fieldLevel(id: string): (typeof FIELD_LEVELS)[keyof typeof FIELD_LEVELS] | undefined {
  return Object.hasOwn(FIELD_LEVELS, id) ? FIELD_LEVELS[id as keyof typeof FIELD_LEVELS] : undefined;
}

export function fieldLevelForWorkload(id: string): (typeof FIELD_LEVELS)[keyof typeof FIELD_LEVELS] | undefined {
  return Object.values(FIELD_LEVELS).find((level) => level.workload === id);
}

export function ba0FieldFingerprint(set: Ba0FieldThresholds = BA0_FIELD_V1): { id: string; version: number; sha256: string } {
  return { id: set.id, version: set.version, sha256: createHash("sha256").update(canonicalJson(set)).digest("hex") };
}

// ---------------------------------------------------------------------------
// Budget gates
// ---------------------------------------------------------------------------

export type BudgetGate = { id: string; ok: boolean; detail: string };

/** Event-count bounds and byte ACCOUNTING ESTIMATES. Byte estimates are not enforced line/heap maxima or an RSS proof. */
export const BUDGET_CONSTANTS = Object.freeze({
  maxPlaneEventsPerRequest: 12,
  maxBoundaryEventsPerRequest: 7,
  maxAppEventsPerRequest: 5,
  maxHarnessEventsPerRequest: 2,
  journalBytesPerEventMax: 256,
  // Preserve the historical N=1 arithmetic. Its legacy "Max" name is an estimate: a credited line can exceed 256 bytes.
  n2JournalBytesPerEventEstimate: 512,
  memoryBytesPerEventMax: 512,
  memoryBudgetBytes: 256 * 1_048_576,
  canaryStepsPerJourney: 5,
});

const mib = (bytes: number): string => `${(bytes / 1_048_576).toFixed(1)} MiB`;

/**
 * The preflight budget gates. Pure. Every gate states the numbers it compared; a failing gate refuses the level before any public bind.
 * `targetRemainingMs` is the time left before the reviewed target expires (null when not applicable, for example in a unit test).
 */
export function evaluateBudgetGates(set: Ba0FieldThresholds, targetRemainingMs: number | null = null): BudgetGate[] {
  const gates: BudgetGate[] = [];
  const gate = (id: string, ok: boolean, detail: string) => gates.push({ id, ok, detail: detail.replace(/=/g, ":").replace(/%/g, " pct") });
  const k = BUDGET_CONSTANTS;
  const canaryRequestsPerJourney = k.canaryStepsPerJourney;
  const eventsPerRequest = k.maxPlaneEventsPerRequest + k.maxBoundaryEventsPerRequest + k.maxAppEventsPerRequest;
  const windowJourneysMax = Math.ceil(set.window.hardDeadlineMs / set.canary.gapMs) + 2;
  const protectedJourneys = set.canary.baselineJourneys + windowJourneysMax + set.canary.residualJourneys + set.canary.recoveryJourneys;
  // The control origin runs the same journeys at baseline and recovery only (parity).
  const controlJourneys = set.canary.baselineJourneys + set.canary.recoveryJourneys;
  const canaryRequests = (protectedJourneys + controlJourneys) * canaryRequestsPerJourney;
  const hostileRequests = set.level.maxTotalRequests;

  // ---- level arithmetic
  gate("level.total_equals_duration_times_rate", set.level.maxTotalRequests === set.level.durationSeconds * set.level.maxRequestsPerSecond,
    `${set.level.maxTotalRequests} requests vs ${set.level.durationSeconds} s x ${set.level.maxRequestsPerSecond} per second`);
  // Preserve the historical N=1 gate (including its id); N=2 must bind to its distinct reviewed level.
  if (set.level.id === "ba0-l7-c1") gate("level.n_equals_one", set.level.workers === 1, `workers ${set.level.workers}`);
  else gate("level.n_equals_two", (set.level.id === "ba0-l7-c2" || set.level.id === "ba0-l7-c2-salvo") && set.level.workers === 2, `workers ${set.level.workers}`);
  gate("level.window_covers_generator", set.window.hardDeadlineMs >= set.window.startSlackMs + set.level.durationSeconds * 1000 + set.window.setupAllowanceMs + set.window.drainAllowanceMs,
    `deadline ${set.window.hardDeadlineMs} ms vs slack ${set.window.startSlackMs} + generator ${set.level.durationSeconds * 1000} + allowances ${set.window.setupAllowanceMs + set.window.drainAllowanceMs}`);
  gate("level.request_timeout_within_boundary_chain", set.level.requestTimeoutMs >= set.plane.egressTimeoutMs, `generator timeout ${set.level.requestTimeoutMs} ms vs plane egress ${set.plane.egressTimeoutMs} ms`);

  // ---- recovery (D4): derived from the parameter set, never a constant
  gate("recovery.quiet_derived", set.recovery.quietMs === 2 * set.l2.epochMs + set.recovery.settleMarginMs && set.recovery.epochMs === set.l2.epochMs,
    `quiet ${set.recovery.quietMs} ms vs 2 x epoch ${set.l2.epochMs} + margin ${set.recovery.settleMarginMs}`);
  gate("recovery.margin_covers_inflight", set.recovery.settleMarginMs >= set.hop.pbLifetimeMs + set.plane.egressTimeoutMs, `margin ${set.recovery.settleMarginMs} ms vs PB lifetime plus egress timeout ${set.hop.pbLifetimeMs + set.plane.egressTimeoutMs} ms`);

  // ---- ledger (L2 use ledger)
  const neededLedger = requiredLedgerCapacity(set.l2.credited.capacity, set.l2.credited.refillPerSecond, set.l2.epochMs);
  gate("l2.ledger_capacity", set.l2.ledgerCapacity >= neededLedger, `capacity ${set.l2.ledgerCapacity} vs required ${neededLedger}`);

  // ---- Bloom fill under the worst case: every request of the level is a render, plus every canary journey's render
  const worstInserts = hostileRequests + (protectedJourneys + controlJourneys);
  const bits = set.l2.filterBits;
  const fill = (worstInserts * set.l2.filterHashes) / bits;
  const fpr = Math.pow(fill, set.l2.filterHashes);
  gate("l2.bloom_fill_ceiling", fill <= 0.01, `worst-case fill ${(fill * 100).toExponential(2)} pct of ${bits} bits (${worstInserts} inserts x ${set.l2.filterHashes} hashes)`);
  gate("l2.bloom_fpr_ceiling", fpr <= 1e-9, `worst-case false-positive estimate ${fpr.toExponential(2)}`);
  gate("l2.bloom_power_of_two", Number.isInteger(Math.log2(bits)), `bits ${bits}`);

  // ---- journal: what the collector writes live (the canary and harness events; external traces are written at finalization)
  const canaryEvents = canaryRequests * (eventsPerRequestForCanary() + k.maxHarnessEventsPerRequest);
  const salvo = set.level.id === "ba0-l7-c2-salvo";
  const n2 = set.level.id === "ba0-l7-c2" || salvo;
  const journalBytes = canaryEvents * (n2 ? k.n2JournalBytesPerEventEstimate : k.journalBytesPerEventMax);
  gate("journal.budget", journalBytes <= set.collector.maxJournalBytes / 2, `${n2 ? "modeled" : "predicted"} ${mib(journalBytes)} vs half of ${mib(set.collector.maxJournalBytes)}`);
  gate("collector.records_budget", canaryRequests + set.external.maxTraces < set.collector.maxRequests + set.external.maxTraces && canaryRequests <= set.collector.maxRequests, `canary requests ${canaryRequests} vs maxRequests ${set.collector.maxRequests}`);

  // ---- external lane memory bounds (explicit, finite)
  const perRequestBytes = 3 * set.external.maxEventsPerStream * k.memoryBytesPerEventMax;
  const stateBytes = (set.external.maxActive + set.external.maxOrphans) * perRequestBytes;
  const traceBytes = set.external.maxTraces * perRequestBytes;
  const decisionBytes = set.external.maxDecisions * k.memoryBytesPerEventMax;
  const recentBytes = set.external.recentRing * 64;
  const channelBytes = 3 * (set.channel.queueCap + set.channel.windowCap) * k.memoryBytesPerEventMax;
  // Conservative accounting: both participants, three representations, 512 bytes per bounded pair record.
  const pairBytes = salvo ? 2 * 3 * SALVO_SPEC.pairs * 512 : 0;
  const total = stateBytes + traceBytes + decisionBytes + recentBytes + channelBytes + pairBytes;
  gate("external.state_memory", stateBytes <= k.memoryBudgetBytes / 2, `active plus orphan state ${n2 ? "modeled" : "at most"} ${mib(stateBytes)}`);
  gate("external.trace_memory", traceBytes <= k.memoryBudgetBytes / 2, `retained traces ${n2 ? "modeled" : "at most"} ${mib(traceBytes)}`);
  gate("external.decisions_cover_level", set.external.maxDecisions >= hostileRequests + canaryRequests, `decision cap ${set.external.maxDecisions} vs ${hostileRequests} hostile plus ${canaryRequests} canary requests`);
  gate("memory.total_budget", total <= k.memoryBudgetBytes, `external lane plus channels ${n2 ? "modeled" : "at most"} ${mib(total)} vs ${mib(k.memoryBudgetBytes)}`);

  // ---- channel: the queue must absorb a collector stall at the level's peak event rate
  const peakEventsPerSecond = set.level.maxRequestsPerSecond * eventsPerRequest;
  const absorbSeconds = set.channel.queueCap / peakEventsPerSecond;
  gate("channel.absorbs_stall", absorbSeconds >= 10, `queue ${set.channel.queueCap} events absorbs ${absorbSeconds.toFixed(1)} s at ${peakEventsPerSecond} events per second`);
  gate("channel.window_within_queue", set.channel.windowCap <= set.channel.queueCap, `window ${set.channel.windowCap} vs queue ${set.channel.queueCap}`);

  // ---- hop replay state
  const replayNeeded = set.level.maxRequestsPerSecond * (set.hop.pbLifetimeMs / 1000) * 4;
  gate("hop.replay_capacity", set.hop.replayCapacity >= replayNeeded, `capacity ${set.hop.replayCapacity} vs ${replayNeeded} (rate x PB lifetime x 4)`);

  // Additional N=2 proofs only: historical N=1 gate output and interpretation stay unchanged.
  // Healthy evidence delivery allows a 10 s collector stall and a full telemetry tick before sweeping.
  // Longer stalls/losses remain explicit runtime anomalies, never an assumption of lossless delivery.
  if (n2) {
    const stallMs = 10_000;
    const burst = set.level.workers;
    // Salvo source ingress can bunch two successive pairs when network delay changes. Each non-final pair must settle
    // before the next release; the final pair can only arrive later. This whole-pair envelope includes that jitter.
    const arrivals = (ms: number) => salvo ? 2 * (1 + Math.ceil(ms / SALVO_SPEC.periodMs))
      : burst + Math.ceil(set.level.maxRequestsPerSecond * ms / 1000);
    const activeNeeded = arrivals(stallMs + set.external.downstreamGraceMs + set.telemetry.tickMs);
    const orphanNeeded = arrivals(stallMs + set.external.orphanGraceMs + set.telemetry.tickMs);
    gate("external.active_cover_stall", set.external.maxActive >= activeNeeded, `capacity ${set.external.maxActive} vs ${activeNeeded} including stall, grace, sweep and burst`);
    gate("external.orphans_cover_stall", set.external.maxOrphans >= orphanNeeded, `capacity ${set.external.maxOrphans} vs ${orphanNeeded} including stall, grace, sweep and burst`);
    gate("external.traces_cover_level", set.external.maxTraces >= hostileRequests, `capacity ${set.external.maxTraces} vs all ${hostileRequests} external requests`);
    gate("external.recent_cover_level", set.external.recentRing >= hostileRequests, `capacity ${set.external.recentRing} vs all ${hostileRequests} external nonces`);
    const streamMax = Math.max(k.maxPlaneEventsPerRequest, k.maxBoundaryEventsPerRequest, k.maxAppEventsPerRequest);
    gate("evidence.per_stream_events", set.external.maxEventsPerStream >= streamMax && set.collector.maxEventsPerRecord >= streamMax,
      `external ${set.external.maxEventsPerStream}, collector ${set.collector.maxEventsPerRecord} vs ${streamMax} events per stream`);
    // Charge ALL campaign canary events to one stall, stronger than assuming a canary peak rate.
    const stallEvents = (arrivals(stallMs) + canaryRequests) * eventsPerRequest;
    gate("channel.stall_with_canary_and_burst", set.channel.queueCap >= stallEvents, `queue ${set.channel.queueCap} vs ${stallEvents} events for stall, all canaries and burst`);
    const replayWithCanary = salvo ? 4 * arrivals(set.hop.pbLifetimeMs) + canaryRequests : replayNeeded + canaryRequests + burst;
    gate("hop.replay_with_canary_and_burst", set.hop.replayCapacity >= replayWithCanary, `capacity ${set.hop.replayCapacity} vs ${replayWithCanary}`);
    // The collector also derives up to two legacy origin events for each protected request.
    const journalWithOrigin = (canaryEvents + 2 * canaryRequests) * k.n2JournalBytesPerEventEstimate;
    gate("journal.with_origin_events", journalWithOrigin <= set.collector.maxJournalBytes / 2, `modeled ${mib(journalWithOrigin)} vs half of ${mib(set.collector.maxJournalBytes)}`);
    if (salvo) {
      gate("salvo.reviewed_schedule", canonicalJson(set.salvo) === canonicalJson(SALVO_SPEC)
        && set.level.durationSeconds * 1000 === SALVO_SPEC.durationMs
        && set.level.maxTotalRequests === SALVO_SPEC.pairs * SALVO_SPEC.requestsPerPair,
      `${SALVO_SPEC.pairs} pairs x 2 requests at ${SALVO_SPEC.periodMs} ms; full ${SALVO_SPEC.durationMs} ms phase`);
      gate("salvo.pair_memory", pairBytes <= k.memoryBudgetBytes - (total - pairBytes), `modeled pair records ${mib(pairBytes)} within remaining modeled budget`);
      // Pair records are JSON artifacts, not journal lines; charge them here as an additional conservative evidence allowance.
      const pairArtifactBytes = 2 * SALVO_SPEC.pairs * 512;
      gate("salvo.evidence_with_pairs", journalWithOrigin + pairArtifactBytes <= set.collector.maxJournalBytes / 2,
        `modeled journal plus both pair artifacts ${mib(journalWithOrigin + pairArtifactBytes)} vs half of ${mib(set.collector.maxJournalBytes)}`);
      // Per-request diagnostics (sibling artifacts). Additive gates only: the gates above are unchanged and still charge exactly what they always did.
      // The recorder adds no plane event, journal line, trace, queue entry or hop proof, so every channel, replay, trace and journal gate above is unaffected.
      const d = SALVO_DIAGNOSTIC_LIMITS; const requests = SALVO_SPEC.pairs * SALVO_SPEC.requestsPerPair;
      gate("salvo.diagnostic_cap_covers_level", d.maxRequests >= set.level.maxTotalRequests && d.maxRequests === requests, `diagnostic cap ${d.maxRequests} vs ${set.level.maxTotalRequests} requests`);
      // Server and generator, three representations each (live, snapshot copy, serialized text) at the per-record accounting estimate, plus the nonce index.
      const diagnosticMemory = 2 * 3 * requests * d.recordMemoryBytes + requests * d.nonceIndexBytes;
      gate("salvo.diagnostic_memory", diagnosticMemory <= k.memoryBudgetBytes - total, `modeled diagnostic records ${mib(diagnosticMemory)} within remaining modeled budget ${mib(k.memoryBudgetBytes - total)}`);
      const diagnosticArtifactBytes = requests * (d.serverRecordJsonBytes + d.generatorRecordJsonBytes);
      gate("salvo.evidence_with_diagnostics", journalWithOrigin + pairArtifactBytes + diagnosticArtifactBytes <= set.collector.maxJournalBytes / 2,
        `modeled journal, pair artifacts and diagnostic artifacts ${mib(journalWithOrigin + pairArtifactBytes + diagnosticArtifactBytes)} vs half of ${mib(set.collector.maxJournalBytes)}`);
    }
  }

  // ---- telemetry cadence
  gate("telemetry.cadence", Number.isSafeInteger(set.telemetry.tickMs) && set.telemetry.tickMs >= 100 && set.telemetry.tickMs <= 10_000 && set.telemetry.gapToleranceMs >= 2 * set.telemetry.tickMs, `tick ${set.telemetry.tickMs} ms, gap tolerance ${set.telemetry.gapToleranceMs} ms`);

  // ---- stop path budgets
  const stopSum = set.stop.closeIngressMs + set.stop.drainMs + set.stop.finalTelemetryMs + set.stop.snapshotMs + set.stop.finalizeMs + set.stop.terminateMs;
  gate("stop.steps_fit_hard_cap", stopSum <= set.stop.hardCapMs, `steps ${stopSum} ms vs cap ${set.stop.hardCapMs} ms`);

  // ---- expected shed bound
  gate("workload.allowed_shed_closed", set.allowedShed.length === 1 && set.allowedShed[0].class === "mutation" && set.allowedShed[0].reason === "lane_budget", `${set.allowedShed.length} allowed shed kind(s)`);

  // ---- target lifetime
  if (targetRemainingMs !== null) {
    const needed = Math.max(set.targetMinRemainingMs, set.window.hardDeadlineMs + set.recovery.quietMs + (set.canary.baselineJourneys + set.canary.recoveryJourneys) * set.canary.gapMs + set.stop.hardCapMs);
    gate("target.remaining_lifetime", targetRemainingMs >= needed, `remaining ${Math.round(targetRemainingMs / 1000)} s vs required ${Math.round(needed / 1000)} s`);
  }
  return gates;
}

/** Canary requests produce the full chain when they reach the application; the same bound as any request. */
function eventsPerRequestForCanary(): number {
  return BUDGET_CONSTANTS.maxPlaneEventsPerRequest + BUDGET_CONSTANTS.maxBoundaryEventsPerRequest + BUDGET_CONSTANTS.maxAppEventsPerRequest;
}

/** The first unmet gate ids, or an empty list. */
export const failedGates = (gates: readonly BudgetGate[]): string[] => gates.filter((entry) => !entry.ok).map((entry) => entry.id);
