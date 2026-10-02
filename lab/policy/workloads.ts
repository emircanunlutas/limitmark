/**
 * Reviewed, finite workload catalogue and the absolute ceilings above it.
 *
 * Nothing here is configurable from the CLI or the environment. A CLI value may
 * only LOWER a phase (never raise it) and a value above the reviewed workload is
 * refused, not clamped (see target-policy.ts `parseCliLimits`). Raising any
 * number below is a code change that tests/lab-workloads.test.ts pins.
 */

/** Absolute ceilings no workload, target or CLI input may exceed. */
export const HARD_CEILINGS = Object.freeze({
  maxRequestsPerSecond: 100,
  maxConcurrency: 50,
  maxDurationSeconds: 900,
  maxTotalRequests: 20_000,
  maxRequestTimeoutMs: 10_000,
  maxResponseBytes: 1_048_576,
  /** Cold-start warm-up GETs (one per distinct GET path) sent before a lab-managed run; outside the workload ceilings. */
  maxWarmupRequests: 3,
});

export type WorkloadId =
  | "connectivity-baseline"
  | "latency-measurement"
  | "controlled-concurrency"
  | "burst"
  | "sustained-soak"
  | "timeout-behaviour"
  | "demo-submission-post"
  | "app-restart"
  | "postgres-outage";

export type PhaseSpec = {
  name: string;
  durationSeconds: number;
  ratePerSecond: number;
  concurrency: number;
  timeoutMs: number;
};

export type ReviewedCeilings = {
  requestsPerSecond: number;
  concurrency: number;
  durationSeconds: number;
  totalRequests: number;
};

export type WorkloadSpec = {
  id: WorkloadId;
  description: string;
  /** http: guarded HTTP client against an allowlisted target. managed-*: lab-owned local process/container only. */
  engine: "http" | "managed-app" | "managed-postgres";
  methods: readonly ("GET" | "POST")[];
  paths: readonly string[];
  phases: readonly PhaseSpec[];
  ceilings: ReviewedCeilings;
  /** Failure workloads act on processes/containers the lab itself started. Never valid for a remote target. */
  localOnly: boolean;
};

const PUBLIC_PAGES = ["/", "/gizlilik", "/test-talep-et"] as const;

const catalogue = [
  {
    id: "connectivity-baseline",
    description: "Single-connection reachability and RTT baseline.",
    engine: "http", methods: ["GET"], paths: ["/"], localOnly: false,
    phases: [{ name: "baseline", durationSeconds: 30, ratePerSecond: 2, concurrency: 1, timeoutMs: 5_000 }],
    ceilings: { requestsPerSecond: 2, concurrency: 1, durationSeconds: 30, totalRequests: 60 },
  },
  {
    id: "latency-measurement",
    description: "Low-rate latency distribution over the public pages.",
    engine: "http", methods: ["GET"], paths: PUBLIC_PAGES, localOnly: false,
    phases: [{ name: "latency", durationSeconds: 60, ratePerSecond: 5, concurrency: 2, timeoutMs: 5_000 }],
    ceilings: { requestsPerSecond: 5, concurrency: 2, durationSeconds: 60, totalRequests: 300 },
  },
  {
    id: "controlled-concurrency",
    description: "Stepped concurrency 1,2,4,8,16 under one shared rate cap.",
    engine: "http", methods: ["GET"], paths: PUBLIC_PAGES, localOnly: false,
    phases: [1, 2, 4, 8, 16].map((concurrency) => ({
      name: `concurrency-${concurrency}`, durationSeconds: 20, ratePerSecond: 40, concurrency, timeoutMs: 5_000,
    })),
    ceilings: { requestsPerSecond: 40, concurrency: 16, durationSeconds: 100, totalRequests: 4_000 },
  },
  {
    id: "burst",
    description: "5 s warm-up, 10 s burst at 100 rps, 15 s cool-down.",
    engine: "http", methods: ["GET"], paths: ["/"], localOnly: false,
    phases: [
      { name: "warmup", durationSeconds: 5, ratePerSecond: 5, concurrency: 4, timeoutMs: 5_000 },
      { name: "burst", durationSeconds: 10, ratePerSecond: 100, concurrency: 50, timeoutMs: 5_000 },
      { name: "cooldown", durationSeconds: 15, ratePerSecond: 5, concurrency: 4, timeoutMs: 5_000 },
    ],
    ceilings: { requestsPerSecond: 100, concurrency: 50, durationSeconds: 30, totalRequests: 1_200 },
  },
  {
    id: "sustained-soak",
    description: "15 minutes at 20 rps / 20 connections.",
    engine: "http", methods: ["GET"], paths: PUBLIC_PAGES, localOnly: false,
    phases: [{ name: "soak", durationSeconds: 900, ratePerSecond: 20, concurrency: 20, timeoutMs: 5_000 }],
    ceilings: { requestsPerSecond: 20, concurrency: 20, durationSeconds: 900, totalRequests: 18_000 },
  },
  {
    id: "timeout-behaviour",
    description: "Deliberately tiny client timeouts, then a health probe proving the target was not wedged.",
    engine: "http", methods: ["GET"], paths: ["/"], localOnly: false,
    phases: [1, 2, 5, 10, 50].map((timeoutMs) => ({
      name: `timeout-${timeoutMs}ms`, durationSeconds: 10, ratePerSecond: 2, concurrency: 1, timeoutMs,
    })).concat([{ name: "health-probe", durationSeconds: 5, ratePerSecond: 1, concurrency: 1, timeoutMs: 5_000 }]),
    ceilings: { requestsPerSecond: 2, concurrency: 1, durationSeconds: 55, totalRequests: 110 },
  },
  {
    id: "demo-submission-post",
    description: "Synthetic demo-mode form POSTs (disposable lab targets only; the demo adapter persists nothing).",
    engine: "http", methods: ["POST"], paths: ["/api/public-inquiries"], localOnly: false,
    phases: [{ name: "demo-post", durationSeconds: 30, ratePerSecond: 5, concurrency: 4, timeoutMs: 5_000 }],
    ceilings: { requestsPerSecond: 5, concurrency: 4, durationSeconds: 30, totalRequests: 150 },
  },
  {
    id: "app-restart",
    description: "Kill and restart the lab-managed app process; measure connection failure and recovery.",
    engine: "managed-app", methods: ["GET"], paths: ["/"], localOnly: true,
    phases: [
      { name: "steady-before", durationSeconds: 5, ratePerSecond: 2, concurrency: 1, timeoutMs: 2_000 },
      { name: "down", durationSeconds: 10, ratePerSecond: 2, concurrency: 1, timeoutMs: 2_000 },
      { name: "recovery", durationSeconds: 60, ratePerSecond: 4, concurrency: 1, timeoutMs: 2_000 },
      { name: "steady-after", durationSeconds: 5, ratePerSecond: 2, concurrency: 1, timeoutMs: 2_000 },
    ],
    ceilings: { requestsPerSecond: 4, concurrency: 1, durationSeconds: 80, totalRequests: 340 },
  },
  {
    id: "postgres-outage",
    description: "Stop and start the lab PostgreSQL container; measure bounded failure and recovery of repository calls.",
    engine: "managed-postgres", methods: [], paths: [], localOnly: true,
    phases: [
      { name: "healthy-before", durationSeconds: 5, ratePerSecond: 2, concurrency: 1, timeoutMs: 5_000 },
      { name: "outage", durationSeconds: 15, ratePerSecond: 2, concurrency: 1, timeoutMs: 5_000 },
      { name: "recovery", durationSeconds: 60, ratePerSecond: 2, concurrency: 1, timeoutMs: 5_000 },
      { name: "healthy-after", durationSeconds: 5, ratePerSecond: 2, concurrency: 1, timeoutMs: 5_000 },
    ],
    ceilings: { requestsPerSecond: 2, concurrency: 1, durationSeconds: 85, totalRequests: 170 },
  },
] as const satisfies readonly WorkloadSpec[];

export const WORKLOADS: Readonly<Record<WorkloadId, WorkloadSpec>> = Object.freeze(
  Object.fromEntries(catalogue.map((workload) => [workload.id, deepFreeze(workload as WorkloadSpec)])) as Record<WorkloadId, WorkloadSpec>,
);

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export function isWorkloadId(value: string): value is WorkloadId {
  return Object.prototype.hasOwnProperty.call(WORKLOADS, value);
}

/** What the phases can actually emit; must stay within the reviewed ceilings. */
export function plannedEnvelope(workload: WorkloadSpec): ReviewedCeilings {
  return {
    requestsPerSecond: Math.max(...workload.phases.map((phase) => phase.ratePerSecond)),
    concurrency: Math.max(...workload.phases.map((phase) => phase.concurrency)),
    durationSeconds: workload.phases.reduce((sum, phase) => sum + phase.durationSeconds, 0),
    totalRequests: workload.phases.reduce((sum, phase) => sum + phase.durationSeconds * phase.ratePerSecond, 0),
  };
}

/** Returns human-readable violations; empty means the catalogue is coherent. */
export function validateWorkloadCatalogue(workloads: Readonly<Record<string, WorkloadSpec>> = WORKLOADS): string[] {
  const problems: string[] = [];
  for (const workload of Object.values(workloads)) {
    const planned = plannedEnvelope(workload);
    const reviewed = workload.ceilings;
    if (workload.phases.length < 1) problems.push(`${workload.id}: no phases`);
    if (planned.requestsPerSecond > reviewed.requestsPerSecond) problems.push(`${workload.id}: phase rate exceeds reviewed rate ceiling`);
    if (planned.concurrency > reviewed.concurrency) problems.push(`${workload.id}: phase concurrency exceeds reviewed ceiling`);
    if (planned.durationSeconds > reviewed.durationSeconds) problems.push(`${workload.id}: phases exceed reviewed duration ceiling`);
    if (planned.totalRequests > reviewed.totalRequests) problems.push(`${workload.id}: planned requests exceed reviewed ceiling`);
    if (reviewed.requestsPerSecond > HARD_CEILINGS.maxRequestsPerSecond) problems.push(`${workload.id}: reviewed rate exceeds hard ceiling`);
    if (reviewed.concurrency > HARD_CEILINGS.maxConcurrency) problems.push(`${workload.id}: reviewed concurrency exceeds hard ceiling`);
    if (reviewed.durationSeconds > HARD_CEILINGS.maxDurationSeconds) problems.push(`${workload.id}: reviewed duration exceeds hard ceiling`);
    if (reviewed.totalRequests > HARD_CEILINGS.maxTotalRequests) problems.push(`${workload.id}: reviewed total exceeds hard ceiling`);
    for (const phase of workload.phases) {
      for (const [key, value] of Object.entries({ d: phase.durationSeconds, r: phase.ratePerSecond, c: phase.concurrency, t: phase.timeoutMs })) {
        if (!Number.isSafeInteger(value) || value < 1) problems.push(`${workload.id}/${phase.name}: ${key} must be a positive integer`);
      }
      if (phase.timeoutMs > HARD_CEILINGS.maxRequestTimeoutMs) problems.push(`${workload.id}/${phase.name}: timeout exceeds hard ceiling`);
    }
    if (workload.engine === "http" && workload.methods.length === 0) problems.push(`${workload.id}: http workload without methods`);
    if (workload.engine !== "http" && !workload.localOnly) problems.push(`${workload.id}: managed workloads must be localOnly`);
    if (workload.methods.includes("POST") && workload.paths.some((path) => path !== "/api/public-inquiries")) problems.push(`${workload.id}: POST allowed on an unreviewed path`);
  }
  return problems;
}

const catalogueProblems = validateWorkloadCatalogue();
if (catalogueProblems.length > 0) {
  throw new Error(`lab workload catalogue is incoherent: ${catalogueProblems.join("; ")}`);
}
