/**
 * Field qualification: the GENERATOR REPORT, the minimum contract an external generator reports so the server-side ledger can be reconciled
 * with the generator's own view. It is EVIDENCE ONLY: nothing in the report is an input to any enforcement decision, and the server never
 * trusts it for what it observed (the server-side ledger is authoritative; the report is compared against it offline).
 *
 * It carries no address, no host, no URL, no header and no body: counts, a status histogram, latency summaries and fingerprints.
 */
import { createHash } from "node:crypto";
import type { ClosedLoopResult } from "../load/closed-loop";
import { canonicalJson, type LatencySummary } from "../policy/thresholds";
import type { WorkloadSpec } from "../policy/workloads";

export const GENERATOR_REPORT_SCHEMA = "ba0-generator-report-v1" as const;

export type GeneratorReport = {
  schema: typeof GENERATOR_REPORT_SCHEMA;
  campaignId: string;
  levelId: string;
  runId: string;
  gitSha: string;
  paramsFingerprintSha256: string;
  workloadFingerprintSha256: string;
  targetId: string;
  workers: number;
  startedAt: string;
  endedAt: string;
  wallClockSeconds: number;
  attempted: number;
  responses: number;
  /** Timeouts, resets, refusals and other transport failures: the requests whose server-side fate this report cannot know (N_amb). */
  transportFailures: number;
  outcomes: Record<string, number>;
  statuses: Record<string, number>;
  perFixture: Record<string, { attempted: number; responses: number; transportFailures: number }>;
  latencyMs: LatencySummary;
  bytes: { wireSent: number; wireReceived: number; contentReceived: number };
  concurrency: { planned: number; inFlightNow: number; maxInFlightObserved: number };
  connections: { new: number; reused: number };
  rate: { achievedPerSecond: number; ceilingPerSecond: number };
  schedule: { paced: number; lagMs: LatencySummary };
  generatorHealth: { eldP50Ms: number; eldP99Ms: number; eldMaxMs: number; cpuUserMs: number; cpuSystemMs: number; rssMb: number };
  stop: { kind: string; detail: string | null };
  retries: 0;
  pipelining: false;
};

export const campaignIdPattern = /^[a-z0-9][a-z0-9-]{5,40}$/;

/** SHA-256 of the canonical JSON of the reviewed workload: the report and the server evidence must name the same one. */
export function workloadFingerprint(workload: WorkloadSpec): string {
  return createHash("sha256").update(canonicalJson(workload)).digest("hex");
}

export function buildGeneratorReport(input: {
  result: ClosedLoopResult;
  runId: string;
  campaignId: string;
  levelId: string;
  gitSha: string;
  paramsFingerprintSha256: string;
  workload: WorkloadSpec;
  targetId: string;
  ceilingRatePerSecond: number;
}): GeneratorReport {
  const { result } = input;
  return {
    schema: GENERATOR_REPORT_SCHEMA, campaignId: input.campaignId, levelId: input.levelId, runId: input.runId, gitSha: input.gitSha,
    paramsFingerprintSha256: input.paramsFingerprintSha256, workloadFingerprintSha256: workloadFingerprint(input.workload), targetId: input.targetId,
    workers: result.workers, startedAt: result.startedAt, endedAt: result.endedAt, wallClockSeconds: result.wallClockSeconds,
    attempted: result.attempted, responses: result.responses, transportFailures: result.transportFailures, outcomes: result.outcomes, statuses: result.statuses,
    perFixture: result.perFixture, latencyMs: result.latencyMs,
    bytes: { wireSent: result.wireBytesSent, wireReceived: result.wireBytesReceived, contentReceived: result.bodyBytesReceived },
    concurrency: result.concurrency, connections: result.connections,
    rate: { achievedPerSecond: result.wallClockSeconds > 0 ? Math.round((result.attempted / result.wallClockSeconds) * 100) / 100 : 0, ceilingPerSecond: input.ceilingRatePerSecond },
    schedule: result.schedule, generatorHealth: result.generatorHealth, stop: { kind: result.stop.kind, detail: result.stop.detail }, retries: 0, pipelining: false,
  };
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const isMeasurement = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0;
const isCount = (value: unknown): value is number => isMeasurement(value) && Number.isSafeInteger(value);

function need(ok: boolean, field: string): asserts ok {
  if (!ok) throw new Error(`generator report field ${field} is missing or malformed`);
}

function requireNumbers(value: unknown, field: string, keys: readonly string[], valid = isMeasurement): void {
  need(isRecord(value), field);
  for (const key of keys) need(valid(value[key]), `${field}.${key}`);
  need(Object.values(value).every(valid), field);
}

function requireSummary(value: unknown, field: string): void {
  need(isRecord(value) && isCount(value.count), `${field}.count`);
  for (const key of ["min", "mean", "p50", "p90", "p95", "p99", "max"]) need(isMeasurement(value[key]), `${field}.${key}`);
}

/** Parses and strictly shape-checks a report. Throws a plain Error naming the first bad field; never returns a half-valid report. */
export function parseGeneratorReport(text: string): GeneratorReport {
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw new Error("generator report is not JSON"); }
  if (typeof value !== "object" || value === null) throw new Error("generator report is not an object");
  const r = value as Record<string, unknown>;
  need(r.schema === GENERATOR_REPORT_SCHEMA, "schema");
  for (const field of ["campaignId", "levelId", "runId", "gitSha", "paramsFingerprintSha256", "workloadFingerprintSha256", "targetId", "startedAt", "endedAt"]) need(typeof r[field] === "string", field);
  need(/^[0-9a-f]{40}$/.test(r.gitSha as string), "gitSha");
  need(/^[0-9a-f]{64}$/.test(r.paramsFingerprintSha256 as string) && /^[0-9a-f]{64}$/.test(r.workloadFingerprintSha256 as string), "fingerprints");
  need(isCount(r.workers) && r.workers > 0, "workers");
  need(isMeasurement(r.wallClockSeconds), "wallClockSeconds");
  for (const field of ["attempted", "responses", "transportFailures"]) need(isCount(r[field]), field);
  requireNumbers(r.outcomes, "outcomes", [], isCount);
  requireNumbers(r.statuses, "statuses", [], isCount);
  need(isRecord(r.perFixture) && Object.keys(r.perFixture).length > 0, "perFixture");
  for (const row of Object.values(r.perFixture)) requireNumbers(row, "perFixture", ["attempted", "responses", "transportFailures"], isCount);
  requireSummary(r.latencyMs, "latencyMs");
  requireNumbers(r.bytes, "bytes", ["wireSent", "wireReceived", "contentReceived"], isCount);
  requireNumbers(r.concurrency, "concurrency", ["planned", "inFlightNow", "maxInFlightObserved"], isCount);
  requireNumbers(r.connections, "connections", ["new", "reused"], isCount);
  requireNumbers(r.rate, "rate", ["achievedPerSecond", "ceilingPerSecond"]);
  need(isRecord(r.schedule) && isCount(r.schedule.paced), "schedule.paced");
  requireSummary(r.schedule.lagMs, "schedule.lagMs");
  requireNumbers(r.generatorHealth, "generatorHealth", ["eldP50Ms", "eldP99Ms", "eldMaxMs", "cpuUserMs", "cpuSystemMs", "rssMb"]);
  const stop = r.stop as { kind?: unknown; detail?: unknown } | undefined;
  need(typeof stop === "object" && stop !== null && typeof stop.kind === "string" && (stop.detail === null || typeof stop.detail === "string"), "stop");
  need(r.retries === 0 && r.pipelining === false, "retries/pipelining");
  return value as GeneratorReport;
}
