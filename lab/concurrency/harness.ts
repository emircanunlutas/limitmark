/**
 * Bounded concurrency / idempotency harness for the repository and notification-outbox
 * properties, using the REAL repositories against a disposable lab PostgreSQL.
 *
 * Synthetic data only. Strict finite bounds (HARNESS_BOUNDS). Refuses to start unless the
 * positive disposable-database proof holds (same guard as the destructive DB tests).
 *
 *   tsx --conditions=react-server lab/concurrency/harness.ts 16|17
 */
import { spawn } from "node:child_process";
import path from "node:path";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "../../src/lib/db/schema";
import { PostgresInquiryRepository } from "../../src/lib/inquiry-repository";
import { PostgresNotificationOutboxRepository } from "../../src/lib/notification-outbox-repository";
import { createPayloadFingerprint } from "../../src/lib/payload-fingerprint";
import { requestSchema } from "../../src/lib/request-schema";
import { disposableTestDatabase, type DisposableTestDatabase } from "../../tests/support/test-database-guard";
import { applyKnownFaultVerdict, libraryFaults } from "../postgres/known-faults";
import { evidenceSafeError } from "../evidence/redact";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState } from "../evidence/manifest";
import { adminUrl, assertVersion, labDbDown, labDbUp, migratorUrl, runtimeUrl, teardownOnCrash, type PgVersion } from "../postgres/lab-db";

export const HARNESS_BOUNDS = Object.freeze({
  maxWorkers: 32,
  maxRounds: 20,
  maxJobs: 200,
  maxWallClockSeconds: 120,
});

type Check = { name: string; pass: boolean; detail?: string };
export type ScenarioResult = { scenario: string; pass: boolean; checks: Check[]; metrics: Record<string, number> };

const baseRequest = requestSchema.parse({
  name: "Concurrency Lab", email: "concurrency@example.test", company: "Synthetic Company", service: "web",
  system: "Synthetic system", objective: "Synthetic objective A", environment: "staging", authority: "authorized", protection: "unknown",
});

let sequence = 0;
const nextToken = () => (++sequence).toString(36).padStart(43, "x");
function submission(token: string, objective = baseRequest.objective) {
  const request = { ...baseRequest, objective };
  return { request, submissionToken: token, payloadFingerprint: createPayloadFingerprint(request) };
}

function bounded(name: string, value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new Error(`${name} ${value} outside harness bound 1..${maximum}`);
  return value;
}

type Context = {
  /** The guard that created `owner`: every TRUNCATE goes through gate.destructive(owner, ...). */
  gate: DisposableTestDatabase;
  owner: postgres.Sql;
  /** Superuser connection, used only to terminate runtime backends in the interruption scenario. */
  admin: postgres.Sql;
  runtime: postgres.Sql;
  inquiries: PostgresInquiryRepository;
  outbox: PostgresNotificationOutboxRepository;
  runtimeUrl: string;
  deadline: number;
};

async function reset(context: Context) {
  await context.gate.destructive(context.owner, (tx) => tx`TRUNCATE TABLE notification_outbox, admin_notes, inquiry_events, inquiries`);
}

async function counts(context: Context) {
  const [row] = await context.owner<{ i: string; e: string; o: string; orphanEvents: string; orphanOutbox: string }[]>`
    SELECT (SELECT count(*) FROM inquiries) AS i, (SELECT count(*) FROM inquiry_events) AS e, (SELECT count(*) FROM notification_outbox) AS o,
      (SELECT count(*) FROM inquiries q WHERE (SELECT count(*) FROM inquiry_events e WHERE e.inquiry_id = q.id) <> 1) AS "orphanEvents",
      (SELECT count(*) FROM inquiries q WHERE (SELECT count(*) FROM notification_outbox o WHERE o.inquiry_id = q.id) <> 1) AS "orphanOutbox"`;
  return { inquiries: Number(row.i), events: Number(row.e), outbox: Number(row.o), inquiriesWithoutExactlyOneEvent: Number(row.orphanEvents), inquiriesWithoutExactlyOneOutbox: Number(row.orphanOutbox) };
}

function assertDeadline(context: Context) {
  if (Date.now() > context.deadline) throw new Error("harness wall-clock bound exceeded");
}

export async function sameTokenSameFingerprint(context: Context, rounds = 20, workers = 16): Promise<ScenarioResult> {
  bounded("rounds", rounds, HARNESS_BOUNDS.maxRounds); bounded("workers", workers, HARNESS_BOUNDS.maxWorkers);
  await reset(context);
  const checks: Check[] = [];
  let created = 0, idempotent = 0, other = 0;
  for (let round = 0; round < rounds; round++) {
    assertDeadline(context);
    const token = nextToken();
    const results = await Promise.all(Array.from({ length: workers }, () => context.inquiries.create(submission(token))));
    created += results.filter((result) => result.status === "created").length;
    idempotent += results.filter((result) => result.status === "idempotent").length;
    other += results.filter((result) => result.status !== "created" && result.status !== "idempotent").length;
  }
  const total = await counts(context);
  checks.push({ name: "exactly one 'created' per token", pass: created === rounds, detail: `${created}/${rounds}` });
  checks.push({ name: "all other callers idempotent", pass: idempotent === rounds * (workers - 1) && other === 0, detail: `${idempotent} idempotent, ${other} other` });
  checks.push({ name: "one inquiry + event + outbox row per token", pass: total.inquiries === rounds && total.events === rounds && total.outbox === rounds });
  checks.push({ name: "no inquiry without exactly one event and one outbox job", pass: total.inquiriesWithoutExactlyOneEvent === 0 && total.inquiriesWithoutExactlyOneOutbox === 0 });
  return { scenario: "same-token-same-fingerprint", pass: checks.every((check) => check.pass), checks, metrics: { rounds, workers, created, idempotent, ...total } };
}

export async function mismatchedFingerprint(context: Context, rounds = 20, workers = 16): Promise<ScenarioResult> {
  bounded("rounds", rounds, HARNESS_BOUNDS.maxRounds); bounded("workers", workers, HARNESS_BOUNDS.maxWorkers);
  await reset(context);
  const checks: Check[] = [];
  let created = 0, conflicts = 0, idempotent = 0, winnerFingerprintStored = 0;
  for (let round = 0; round < rounds; round++) {
    assertDeadline(context);
    const token = nextToken();
    const results = await Promise.all(Array.from({ length: workers }, (_, index) => {
      const input = submission(token, index % 2 === 0 ? "Synthetic objective A" : "Synthetic objective B");
      return context.inquiries.create(input).then((result) => ({ result, objective: input.request.objective, fingerprint: input.payloadFingerprint }));
    }));
    const winners = results.filter(({ result }) => result.status === "created");
    created += winners.length;
    conflicts += results.filter(({ result }) => result.status === "conflict").length;
    idempotent += results.filter(({ result }) => result.status === "idempotent").length;
    const [stored] = await context.owner<{ payload_fingerprint: string; objective: string }[]>`SELECT payload_fingerprint, objective FROM inquiries WHERE submission_token = ${token}`;
    if (winners.length === 1 && stored) {
      const winner = results.find(({ result }) => result.status === "created")!;
      if (stored.payload_fingerprint === winner.fingerprint && stored.objective === winner.objective) winnerFingerprintStored++;
      // Every non-winner must be classified by its own fingerprint versus the stored one.
      for (const { result, fingerprint } of results) {
        if (result.status === "created") continue;
        const expected = fingerprint === stored.payload_fingerprint ? "idempotent" : "conflict";
        if (result.status !== expected) checks.push({ name: `round ${round}: non-winner classified ${expected}`, pass: false, detail: result.status });
      }
    }
  }
  const total = await counts(context);
  checks.push({ name: "exactly one 'created' per token", pass: created === rounds, detail: `${created}/${rounds}` });
  checks.push({ name: "stored payload is always the creator's, never overwritten", pass: winnerFingerprintStored === rounds });
  checks.push({ name: "mismatched fingerprints conflict, matching ones are idempotent", pass: conflicts + idempotent === rounds * (workers - 1) && conflicts > 0 });
  checks.push({ name: "mismatch created no extra rows", pass: total.inquiries === rounds && total.events === rounds && total.outbox === rounds });
  return { scenario: "mismatched-fingerprint", pass: checks.every((check) => check.pass), checks, metrics: { rounds, workers, created, conflicts, idempotent, ...total } };
}

async function seedPendingJobs(context: Context, jobs: number): Promise<string[]> {
  bounded("jobs", jobs, HARNESS_BOUNDS.maxJobs);
  await reset(context);
  const rows = await context.owner<{ id: string }[]>`
    INSERT INTO inquiries (name, email, service, system, objective, environment, authority, submission_token, payload_fingerprint)
    SELECT 'Lab', 'lab@example.test', 'web', 's', 'o', 'staging', 'owner', lpad(i::text, 43, 'y'), lpad(i::text, 64, '0')
    FROM generate_series(1, ${jobs}) AS i RETURNING id`;
  const ids = rows.map((row) => row.id);
  await context.owner`INSERT INTO notification_outbox (inquiry_id, event_type, available_at) SELECT id, 'inquiry_received', '2030-01-01T00:00:00Z' FROM inquiries`;
  return ids;
}

const T0 = new Date("2030-09-11T12:00:00.000Z");
const LEASE_MS = 60_000;

export async function outboxCompetingWorkers(context: Context, jobs = 100, workers = 8): Promise<ScenarioResult> {
  bounded("workers", workers, HARNESS_BOUNDS.maxWorkers);
  await seedPendingJobs(context, jobs);
  const claimedBy: string[][] = Array.from({ length: workers }, () => []);
  await Promise.all(Array.from({ length: workers }, async (_, worker) => {
    for (let guard = 0; guard < jobs; guard++) {
      assertDeadline(context);
      const batch = await context.outbox.claimBatch({ now: T0, lockedUntil: new Date(T0.getTime() + LEASE_MS), batchSize: 5 });
      if (batch.length === 0) return;
      claimedBy[worker].push(...batch.map((job) => job.outboxId));
    }
  }));
  const all = claimedBy.flat();
  const unique = new Set(all);
  const checks: Check[] = [];
  checks.push({ name: "no job claimed by two workers", pass: unique.size === all.length, detail: `${all.length} claims, ${unique.size} unique` });
  checks.push({ name: "every job claimed exactly once", pass: unique.size === jobs });
  const [attemptRow] = await context.owner<{ max: number; min: number }[]>`SELECT max(attempts)::int AS max, min(attempts)::int AS min FROM notification_outbox`;
  checks.push({ name: "attempts == 1 for every job", pass: attemptRow.max === 1 && attemptRow.min === 1 });
  checks.push({ name: "more than one worker obtained work", pass: claimedBy.filter((claims) => claims.length > 0).length > 1 });
  return { scenario: "outbox-competing-workers", pass: checks.every((check) => check.pass), checks, metrics: { jobs, workers, claims: all.length } };
}

export async function leaseRecovery(context: Context, jobs = 10): Promise<ScenarioResult> {
  await seedPendingJobs(context, jobs);
  const checks: Check[] = [];
  const lockA = new Date(T0.getTime() + LEASE_MS);
  const a = await context.outbox.claimBatch({ now: T0, lockedUntil: lockA, batchSize: jobs });
  checks.push({ name: "worker A claims all jobs", pass: a.length === jobs });
  // A "dies" here. While its lease is live nobody else may take the rows.
  const live = await context.outbox.claimBatch({ now: new Date(T0.getTime() + LEASE_MS / 2), lockedUntil: new Date(T0.getTime() + 2 * LEASE_MS), batchSize: jobs });
  checks.push({ name: "live leases are not stolen", pass: live.length === 0 });
  const recoverAt = new Date(T0.getTime() + LEASE_MS + 1);
  const lockB = new Date(recoverAt.getTime() + LEASE_MS);
  const b = await context.outbox.claimBatch({ now: recoverAt, lockedUntil: lockB, batchSize: jobs });
  checks.push({ name: "expired leases are reclaimed by worker B as a new attempt", pass: b.length === jobs && b.every((job) => job.attempts === 2) });
  const lateA = await Promise.all(a.map((job) => context.outbox.markSent({ outboxId: job.outboxId, attempts: job.attempts, lockedUntil: job.lockedUntil, now: recoverAt })));
  checks.push({ name: "stale worker A outcomes are rejected", pass: lateA.every((accepted) => accepted === false) });
  const okB = await Promise.all(b.map((job) => context.outbox.markSent({ outboxId: job.outboxId, attempts: job.attempts, lockedUntil: job.lockedUntil, now: recoverAt })));
  checks.push({ name: "worker B outcomes are accepted", pass: okB.every(Boolean) });
  const twice = await context.outbox.markSent({ outboxId: b[0].outboxId, attempts: b[0].attempts, lockedUntil: b[0].lockedUntil, now: recoverAt });
  checks.push({ name: "a sent job cannot be completed twice", pass: twice === false });
  const [final] = await context.owner<{ sent: string; attemptsMax: number }[]>`SELECT count(*) FILTER (WHERE status = 'sent') AS sent, max(attempts)::int AS "attemptsMax" FROM notification_outbox`;
  checks.push({ name: "all jobs sent with exactly two attempts", pass: Number(final.sent) === jobs && final.attemptsMax === 2 });
  return { scenario: "lease-recovery", pass: checks.every((check) => check.pass), checks, metrics: { jobs } };
}

/** A worker process claims a batch and is SIGKILLed before completing anything. */
export async function workerProcessKilled(context: Context, jobs = 10): Promise<ScenarioResult> {
  await seedPendingJobs(context, jobs);
  const checks: Check[] = [];
  const lockedUntil = new Date(T0.getTime() + LEASE_MS);
  const output = await new Promise<string>((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(REPOSITORY_ROOT, "node_modules", "tsx", "dist", "cli.mjs"), "--conditions=react-server", path.join(REPOSITORY_ROOT, "lab", "concurrency", "crash-worker.ts")], {
      cwd: REPOSITORY_ROOT,
      // Only what the worker needs; the runtime role cannot do DDL.
      env: { PATH: process.env.PATH ?? "", SystemRoot: process.env.SystemRoot ?? "", LAB_RUNTIME_URL: context.runtimeUrl, LAB_NOW: T0.toISOString(), LAB_LOCKED_UNTIL: lockedUntil.toISOString(), LAB_BATCH: "5" } as unknown as NodeJS.ProcessEnv,
      stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
    });
    let text = "";
    child.stdout.on("data", (chunk) => { text += chunk; });
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("crash worker exceeded 30s")); }, 30_000);
    child.on("close", (code, signal) => { clearTimeout(timer); resolve(signal === "SIGKILL" || code !== 0 ? text : `NOT-KILLED ${text}`); });
    child.on("error", reject);
  });
  const claimedIds = (JSON.parse(output.trim().split("\n").filter((line) => line.startsWith("["))[0] ?? "[]") as string[]);
  checks.push({ name: "worker claimed 5 jobs and was killed mid-flight", pass: claimedIds.length === 5 && !output.startsWith("NOT-KILLED"), detail: `${claimedIds.length} claimed` });
  const [state] = await context.owner<{ processing: string }[]>`SELECT count(*) FILTER (WHERE status = 'processing') AS processing FROM notification_outbox`;
  checks.push({ name: "killed worker leaves rows leased (processing), not lost", pass: Number(state.processing) === 5 });
  const recoverAt = new Date(T0.getTime() + LEASE_MS + 1);
  const recovered = await context.outbox.claimBatch({ now: recoverAt, lockedUntil: new Date(recoverAt.getTime() + LEASE_MS), batchSize: 100 });
  checks.push({ name: "after lease expiry every row is claimable again", pass: recovered.length === jobs });
  const crashedRecovered = recovered.filter((job) => claimedIds.includes(job.outboxId));
  checks.push({ name: "the interrupted rows come back as attempt 2", pass: crashedRecovered.length === 5 && crashedRecovered.every((job) => job.attempts === 2) });
  return { scenario: "worker-process-killed", pass: checks.every((check) => check.pass), checks, metrics: { jobs, killedWorkerClaims: claimedIds.length } };
}

/** Backend connections are terminated while creates are in flight; no partial writes may remain. */
export async function backendKilledDuringCreates(context: Context, workers = 16, perWorker = 5): Promise<ScenarioResult> {
  bounded("workers", workers, HARNESS_BOUNDS.maxWorkers); bounded("perWorker", perWorker, HARNESS_BOUNDS.maxRounds);
  await reset(context);
  const tokens = Array.from({ length: workers * perWorker }, () => nextToken());
  let killed = 0, firstAttemptErrors = 0;
  const killer = (async () => {
    await new Promise((resolve) => setTimeout(resolve, 15));
    try {
      const rows = await context.admin`SELECT pg_terminate_backend(pid) AS ok FROM pg_stat_activity WHERE usename = 'lab_runtime' AND datname = current_database() AND pid <> pg_backend_pid()`;
      killed = rows.length;
    } catch { killed = -1; }
  })();
  await Promise.all(Array.from({ length: workers }, async (_, worker) => {
    for (const token of tokens.slice(worker * perWorker, (worker + 1) * perWorker)) {
      // Interrupted callers retry the SAME token: idempotency must absorb the ambiguity.
      for (let attempt = 0; attempt < 4; attempt++) {
        try { await context.inquiries.create(submission(token)); break; }
        catch { if (attempt === 0) firstAttemptErrors++; await new Promise((resolve) => setTimeout(resolve, 50)); }
      }
    }
  }));
  await killer;
  const total = await counts(context);
  const checks: Check[] = [
    { name: "backends were actually terminated mid-run", pass: killed > 0, detail: String(killed) },
    { name: "every token ends up stored exactly once", pass: total.inquiries === tokens.length, detail: `${total.inquiries}/${tokens.length}` },
    { name: "no orphan / duplicate events or outbox jobs after interruption", pass: total.events === tokens.length && total.outbox === tokens.length && total.inquiriesWithoutExactlyOneEvent === 0 && total.inquiriesWithoutExactlyOneOutbox === 0 },
  ];
  return { scenario: "backend-killed-during-creates", pass: checks.every((check) => check.pass), checks, metrics: { workers, perWorker, backendsTerminated: killed, firstAttemptErrors, ...total } };
}

export async function runHarness(ownerUrl: string, runtimeConnectionUrl: string, proofToken: string, adminUrl: string): Promise<ScenarioResult[]> {
  // The destructive connection IS the proven connection: the owner client is created from the parsed fields by the
  // guard (no URL string reaches postgres.js) and every TRUNCATE re-proves inside its own transaction.
  const gate = disposableTestDatabase({ TEST_DATABASE_URL: ownerUrl, TEST_DATABASE_PROOF: proofToken });
  const owner = gate.connect({ max: 4 });
  if (!owner) throw new Error("no owner connection");
  try { await gate.assertProven(owner); } catch (error) { await owner.end({ timeout: 1 }).catch(() => undefined); throw error; }
  const admin = postgres(adminUrl, { max: 1, prepare: false, onnotice: () => undefined });
  const runtime = postgres(runtimeConnectionUrl, { max: HARNESS_BOUNDS.maxWorkers, prepare: false, connect_timeout: 5, onnotice: () => undefined });
  const database = drizzle(runtime, { schema });
  const context: Context = {
    gate, owner, admin, runtime, runtimeUrl: runtimeConnectionUrl,
    inquiries: new PostgresInquiryRepository(database), outbox: new PostgresNotificationOutboxRepository(database),
    deadline: Date.now() + HARNESS_BOUNDS.maxWallClockSeconds * 1000,
  };
  try {
    const results: ScenarioResult[] = [];
    for (const scenario of [sameTokenSameFingerprint, mismatchedFingerprint, outboxCompetingWorkers, leaseRecovery, workerProcessKilled, backendKilledDuringCreates]) {
      results.push(await scenario(context));
    }
    return results;
  } finally {
    await runtime.end({ timeout: 2 }); await owner.end({ timeout: 2 }); await admin.end({ timeout: 2 });
  }
}

async function main(): Promise<void> {
  const version: PgVersion = assertVersion(process.argv[2]);
  teardownOnCrash([version], { tolerateKnownPostgresJsFault: true });
  const evidence = new EvidenceRun("concurrency-harness", `concurrency-pg${version}`);
  const state = await labDbUp(version);
  let results: ScenarioResult[] = [];
  let failure: string | null = null;
  try {
    results = await runHarness(migratorUrl(state), runtimeUrl(state), state.proofToken, adminUrl(state));
  } catch (error) {
    failure = evidenceSafeError(error);
  } finally {
    await labDbDown(version).catch((error) => { failure ??= `teardown: ${evidenceSafeError(error)}`; });
  }
  const reasons = failure ? [failure] : results.filter((result) => !result.pass).map((result) => `${result.scenario} failed`);
  let verdict: "PASS" | "FAIL" | "ERROR" = failure ? "ERROR" : results.length === 6 && results.every((result) => result.pass) ? "PASS" : "FAIL";
  // The known postgres.js defect is a FINDING: a run that observed it can never be reported as a pass.
  ({ result: verdict } = applyKnownFaultVerdict(verdict, reasons, libraryFaults));
  const pass = verdict === "PASS";
  for (const result of results) console.log(`${result.pass ? "PASS" : "FAIL"}  ${result.scenario}${result.checks.filter((c) => !c.pass).map((c) => `\n      x ${c.name} ${c.detail ?? ""}`).join("")}`);
  evidence.addJsonArtifact("scenarios.json", { bounds: HARNESS_BOUNDS, scenarios: results });
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(state.serverVersion), target: { id: `postgres-lab-${version}`, class: "lab-local" },
    workload: { id: "concurrency-idempotency-harness", phases: results.map((result) => ({ name: result.scenario })) },
    ceilings: { scope: "per-process; not campaign- or fleet-wide", ...HARNESS_BOUNDS }, thresholds: null, engine: "node-postgres",
    result: verdict, resultReasons: reasons,
    metrics: { scenarios: results.length, passed: results.filter((result) => result.pass).length, postgresJsUncaughtNullSocketWrite: libraryFaults.postgresJsNullSocketWrite },
  });
  if (libraryFaults.postgresJsNullSocketWrite > 0) console.log(`FINDING: postgres.js threw ${libraryFaults.postgresJsNullSocketWrite} uncaught null-socket write TypeError(s) when backends were terminated`);
  console.log(`concurrency harness PG${version}: ${verdict}${reasons.length ? ` (${reasons.join("; ")})` : ""} evidence=${evidence.id}`);
  process.exit(pass ? 0 : 1);
}

if (require.main === module) {
  main().catch((error) => { console.error(error instanceof Error ? error.message : error); process.exit(1); });
}
