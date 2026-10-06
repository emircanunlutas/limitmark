/**
 * Field qualification: the parameter set `ba0-field-v1` for the FIRST external L7 qualification level (N = 1), and the preflight BUDGET
 * GATES that prove, before the Plane binds its public address, that the planned level fits the evidence, memory, journal, channel, Bloom
 * and ledger budgets.
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

const EPOCH_MS = 60_000;
const SETTLE_MARGIN_MS = 15_000;

export type Ba0FieldThresholds = {
  id: "ba0-field-v1";
  version: 1;
  description: string;
  calibration: "provisional-uncalibrated";
  status: "first level qualification parameters; not production defaults";
  level: {
    id: "ba0-l7-c1";
    workers: 1;
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

export function ba0FieldFingerprint(set: Ba0FieldThresholds = BA0_FIELD_V1): { id: string; version: number; sha256: string } {
  return { id: set.id, version: set.version, sha256: createHash("sha256").update(canonicalJson(set)).digest("hex") };
}

// ---------------------------------------------------------------------------
// Budget gates
// ---------------------------------------------------------------------------

export type BudgetGate = { id: string; ok: boolean; detail: string };

/** Upper bounds used by the gates: the most events one request can produce in the three streams, and the most bytes one journal line or retained event takes. */
export const BUDGET_CONSTANTS = Object.freeze({
  maxPlaneEventsPerRequest: 12,
  maxBoundaryEventsPerRequest: 7,
  maxAppEventsPerRequest: 5,
  maxHarnessEventsPerRequest: 2,
  journalBytesPerEventMax: 256,
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
  gate("level.n_equals_one", set.level.workers === 1, `workers ${set.level.workers}`);
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
  const journalBytes = canaryEvents * k.journalBytesPerEventMax;
  gate("journal.budget", journalBytes <= set.collector.maxJournalBytes / 2, `predicted ${mib(journalBytes)} vs half of ${mib(set.collector.maxJournalBytes)}`);
  gate("collector.records_budget", canaryRequests + set.external.maxTraces < set.collector.maxRequests + set.external.maxTraces && canaryRequests <= set.collector.maxRequests, `canary requests ${canaryRequests} vs maxRequests ${set.collector.maxRequests}`);

  // ---- external lane memory bounds (explicit, finite)
  const perRequestBytes = 3 * set.external.maxEventsPerStream * k.memoryBytesPerEventMax;
  const stateBytes = (set.external.maxActive + set.external.maxOrphans) * perRequestBytes;
  const traceBytes = set.external.maxTraces * perRequestBytes;
  const decisionBytes = set.external.maxDecisions * k.memoryBytesPerEventMax;
  const recentBytes = set.external.recentRing * 64;
  const channelBytes = 3 * (set.channel.queueCap + set.channel.windowCap) * k.memoryBytesPerEventMax;
  const total = stateBytes + traceBytes + decisionBytes + recentBytes + channelBytes;
  gate("external.state_memory", stateBytes <= k.memoryBudgetBytes / 2, `active plus orphan state at most ${mib(stateBytes)}`);
  gate("external.trace_memory", traceBytes <= k.memoryBudgetBytes / 2, `retained traces at most ${mib(traceBytes)}`);
  gate("external.decisions_cover_level", set.external.maxDecisions >= hostileRequests + canaryRequests, `decision cap ${set.external.maxDecisions} vs ${hostileRequests} hostile plus ${canaryRequests} canary requests`);
  gate("memory.total_budget", total <= k.memoryBudgetBytes, `external lane plus channels at most ${mib(total)} vs ${mib(k.memoryBudgetBytes)}`);

  // ---- channel: the queue must absorb a collector stall at the level's peak event rate
  const peakEventsPerSecond = set.level.maxRequestsPerSecond * eventsPerRequest;
  const absorbSeconds = set.channel.queueCap / peakEventsPerSecond;
  gate("channel.absorbs_stall", absorbSeconds >= 10, `queue ${set.channel.queueCap} events absorbs ${absorbSeconds.toFixed(1)} s at ${peakEventsPerSecond} events per second`);
  gate("channel.window_within_queue", set.channel.windowCap <= set.channel.queueCap, `window ${set.channel.windowCap} vs queue ${set.channel.queueCap}`);

  // ---- hop replay state
  const replayNeeded = set.level.maxRequestsPerSecond * (set.hop.pbLifetimeMs / 1000) * 4;
  gate("hop.replay_capacity", set.hop.replayCapacity >= replayNeeded, `capacity ${set.hop.replayCapacity} vs ${replayNeeded} (rate x PB lifetime x 4)`);

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
