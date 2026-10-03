/**
 * PostgreSQL unavailability and recovery against the lab-owned container only.
 *
 * Probes are real `PostgresInquiryRepository.create` calls (synthetic data, runtime role, a pool
 * configured like src/lib/db/database.server.ts). The outage is injected with `docker stop`
 * (connection refused/reset) or `docker pause` (blackhole: exercises connect_timeout), and only on
 * a container carrying the lab disposable label and the postgres role label (read from the daemon).
 *
 * A probe that times out is NOT left running. `Promise.race` alone would only stop WAITING for it: the transaction
 * would stay queued inside the pool (a paused server accepts nothing, but resumes the whole backlog on `unpause`) while
 * the report says "concurrency one". On a timeout the whole pool is torn down (sockets destroyed, the server sees EOF
 * and rolls the transaction back) and replaced; server-side `statement_timeout` / `idle_in_transaction_session_timeout`
 * bound whatever the server still holds; and after the run no runtime backend may be left active or idle in a
 * transaction, which is verified, not assumed.
 */
import { performance } from "node:perf_hooks";
import { randomBytes } from "node:crypto";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "../../src/lib/db/schema";
import { PostgresInquiryRepository } from "../../src/lib/inquiry-repository";
import { createPayloadFingerprint } from "../../src/lib/payload-fingerprint";
import { requestSchema } from "../../src/lib/request-schema";
import { controlLabContainer } from "../host/docker";
import type { EffectiveLimits } from "../policy/target-policy";
import { summarizeLatencies, type PhaseStats, type ThresholdSet } from "../policy/thresholds";
import { evaluateRecovery, type RecoveryVerdict } from "./recovery";
import type { PgLabState } from "../postgres/lab-db";
import { migratorUrl, runtimeUrl } from "../postgres/lab-db";

export type OutageMode = "stop" | "pause";

const request = requestSchema.parse({
  name: "Outage Lab", email: "outage@example.test", company: "Synthetic Company", service: "web",
  system: "Synthetic system", objective: "Synthetic outage probe", environment: "staging", authority: "authorized", protection: "unknown",
});

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function categorize(error: unknown): string {
  const code = (error as { code?: unknown })?.code;
  if (typeof code === "string" && /^[A-Z0-9_]{3,40}$/.test(code)) return code;
  return error instanceof Error ? error.name.slice(0, 40) : "UNKNOWN";
}

export type PostgresOutageOutcome = {
  phases: PhaseStats[];
  verdict: RecoveryVerdict;
  recoverySeconds: number | null;
  maxProbeDurationDownMs: number;
  integrity: { inquiries: number; events: number; outbox: number; orphans: number };
  /** Probes that timed out and whose pool was torn down. */
  abandonedProbes: number;
  /** Highest number of probe operations unsettled at once (1 when nothing outlived its timeout). */
  maxUnsettledProbes: number;
  /** Runtime-role backends still active / idle-in-transaction after teardown; must be 0. */
  orphanedBackends: number;
  mode: OutageMode;
};

type PoolHandle = { client: postgres.Sql; repository: PostgresInquiryRepository };

export type CancellableProbe<H> = {
  /** The handle probes currently use. Replaced after a timeout. */
  current: H;
  open(): H;
  /** Destroys a handle's connections immediately (not a graceful drain). */
  destroy(handle: H): Promise<unknown>;
  /** Highest number of operations unsettled at once. */
  unsettled: number;
  maxUnsettled: number;
  abandoned: number;
};

/**
 * Runs one probe operation with a timeout that CANCELS the work instead of merely ceasing to wait for it: on timeout the
 * handle the operation runs on is destroyed (its sockets die, so the server rolls the transaction back), a fresh handle
 * replaces it, and the abandoned operation must settle (bounded) before the caller issues the next probe. A race alone would
 * leave the query running and queued behind later probes.
 */
export async function probeWithCancellation<H, T>(
  probe: CancellableProbe<H>, operation: (handle: H) => Promise<T>, timeoutMs: number, settleBudgetMs = 2_000,
): Promise<{ ok: true; value: T } | { ok: false; error: unknown; timedOut: boolean }> {
  const handle = probe.current;
  let timer: NodeJS.Timeout | undefined;
  probe.unsettled++; probe.maxUnsettled = Math.max(probe.maxUnsettled, probe.unsettled);
  const work = operation(handle).finally(() => { probe.unsettled--; });
  // The abandoned promise may reject later (its handle was destroyed); that rejection is expected and handled here.
  work.catch(() => undefined);
  try {
    const value = await Promise.race([
      work,
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error("probe timeout"), { code: "PROBE_TIMEOUT" })), timeoutMs); }),
    ]);
    return { ok: true, value };
  } catch (error) {
    const timedOut = (error as { code?: unknown })?.code === "PROBE_TIMEOUT";
    if (timedOut) {
      probe.abandoned++;
      if (probe.current === handle) probe.current = probe.open();
      void probe.destroy(handle).catch(() => undefined);
      await Promise.race([work.then(() => undefined, () => undefined), new Promise<void>((resolve) => setTimeout(resolve, settleBudgetMs))]);
    }
    return { ok: false, error, timedOut };
  } finally { clearTimeout(timer); }
}

export async function runPostgresOutage(state: PgLabState, limits: EffectiveLimits, set: ThresholdSet, mode: OutageMode): Promise<PostgresOutageOutcome> {
  const maxTimeoutMs = Math.max(...limits.phases.map((phase) => phase.timeoutMs));
  const handles: PoolHandle[] = [];
  // Same pool shape as the application (src/lib/db/database.server.ts), plus server-side bounds on what a dead client leaves behind.
  const open = (): PoolHandle => {
    const client = postgres(runtimeUrl(state), {
      max: 5, idle_timeout: 20, connect_timeout: 5, prepare: false, onnotice: () => undefined,
      connection: { statement_timeout: maxTimeoutMs, idle_in_transaction_session_timeout: maxTimeoutMs },
    });
    const handle = { client, repository: new PostgresInquiryRepository(drizzle(client, { schema })) };
    handles.push(handle);
    return handle;
  };
  const cancellable: CancellableProbe<PoolHandle> = { current: open(), open, destroy: (entry) => entry.client.end({ timeout: 0 }), unsettled: 0, maxUnsettled: 0, abandoned: 0 };
  const phases: PhaseStats[] = [];
  let startedAt = 0, firstOkAfterStart: number | null = null, consecutiveOk = 0, maxDown = 0;
  const thresholds = set.recovery["postgres-outage"];

  const probe = async (timeoutMs: number): Promise<{ ok: boolean; category: string; ms: number }> => {
    const started = performance.now();
    const token = randomBytes(32).toString("base64url");
    const outcome = await probeWithCancellation(cancellable, (entry) => entry.repository.create({ request, submissionToken: token, payloadFingerprint: createPayloadFingerprint(request) }), timeoutMs);
    return outcome.ok ? { ok: true, category: "ok", ms: performance.now() - started } : { ok: false, category: categorize(outcome.error), ms: performance.now() - started };
  };

  const deadline = performance.now() + limits.maxDurationSeconds * 1000 + 15_000;
  let attemptedTotal = 0;
  try {
    for (const phase of limits.phases) {
      if (phase.name === "outage") await controlLabContainer(mode === "pause" ? "pause" : "stop", state.container, "postgres");
      if (phase.name === "recovery") {
        await controlLabContainer(mode === "pause" ? "unpause" : "start", state.container, "postgres");
        startedAt = performance.now();
      }
      const latencies: number[] = [];
      const outcomes: Record<string, number> = {};
      let attempted = 0, succeeded = 0, failed = 0;
      const startedPhase = new Date();
      const end = performance.now() + phase.durationSeconds * 1000;
      const interval = 1000 / phase.ratePerSecond;
      const phaseCap = phase.durationSeconds * phase.ratePerSecond;
      while (performance.now() < end && performance.now() < deadline && attemptedTotal < limits.maxTotalRequests && attempted < phaseCap) {
        if (phase.name === "recovery" && consecutiveOk >= 5) break;
        const tickStart = performance.now();
        const result = await probe(phase.timeoutMs);
        attempted++; attemptedTotal++;
        latencies.push(result.ms);
        outcomes[result.category] = (outcomes[result.category] ?? 0) + 1;
        if (result.ok) succeeded++; else failed++;
        if (phase.name === "outage") maxDown = Math.max(maxDown, result.ms);
        if (phase.name === "recovery") {
          if (result.ok) { consecutiveOk++; firstOkAfterStart ??= performance.now(); } else consecutiveOk = 0;
        }
        await sleep(Math.max(0, interval - (performance.now() - tickStart)));
      }
      phases.push({
        name: phase.name, startedAt: startedPhase.toISOString(), endedAt: new Date().toISOString(),
        planned: { durationSeconds: phase.durationSeconds, ratePerSecond: phase.ratePerSecond, concurrency: 1, timeoutMs: phase.timeoutMs },
        attempted, succeeded, failed, outcomes, statuses: {}, droppedByConcurrencyCap: 0, bytesReceived: 0, latencyMs: summarizeLatencies(latencies),
      });
    }
  } finally {
    // Never leave the lab container stopped/paused.
    await controlLabContainer(mode === "pause" ? "unpause" : "start", state.container, "postgres").catch(() => undefined);
    await Promise.all(handles.map((entry) => entry.client.end({ timeout: 2 }).catch(() => undefined)));
  }

  const abandonedProbes = cancellable.abandoned, maxUnsettled = cancellable.maxUnsettled;
  const recoverySeconds = firstOkAfterStart === null ? null : Math.round((firstOkAfterStart - startedAt) / 10) / 100;
  // Integrity after recovery: nothing partial, and nothing of ours still running, using the owner role.
  const owner = postgres(migratorUrl(state), { max: 1, prepare: false, connect_timeout: 5, onnotice: () => undefined });
  let integrity = { inquiries: -1, events: -1, outbox: -1, orphans: -1 };
  let orphanedBackends = -1;
  try {
    const [row] = await owner<{ i: string; e: string; o: string; orphans: string }[]>`
      SELECT (SELECT count(*) FROM inquiries) AS i, (SELECT count(*) FROM inquiry_events) AS e, (SELECT count(*) FROM notification_outbox) AS o,
        (SELECT count(*) FROM inquiries q WHERE (SELECT count(*) FROM inquiry_events e WHERE e.inquiry_id = q.id) <> 1
           OR (SELECT count(*) FROM notification_outbox n WHERE n.inquiry_id = q.id) <> 1) AS orphans`;
    integrity = { inquiries: Number(row.i), events: Number(row.e), outbox: Number(row.o), orphans: Number(row.orphans) };
    // A backend whose client vanished while paused can need a moment to notice; poll briefly, then count what is left.
    for (let attempt = 0; attempt < 20; attempt++) {
      const [left] = await owner<{ n: string }[]>`
        SELECT count(*)::text AS n FROM pg_stat_activity
        WHERE usename = 'lab_runtime' AND datname = current_database() AND pid <> pg_backend_pid() AND state IN ('active', 'idle in transaction', 'idle in transaction (aborted)')`;
      orphanedBackends = Number(left.n);
      if (orphanedBackends === 0) break;
      await sleep(500);
    }
  } finally { await owner.end({ timeout: 2 }).catch(() => undefined); }

  const verdict = evaluateRecovery(thresholds, {
    phases, recoverySeconds, maxProbeDurationDownMs: maxDown,
    downPhase: "outage", recoveryPhase: "recovery", steadyPhases: ["healthy-before", "healthy-after"],
  });
  if (integrity.orphans !== 0 || integrity.inquiries !== integrity.events || integrity.inquiries !== integrity.outbox) {
    verdict.reasons.push("partial writes detected after recovery");
    if (verdict.result === "PASS") verdict.result = "FAIL";
  }
  if (orphanedBackends !== 0) {
    verdict.reasons.push(orphanedBackends < 0 ? "could not verify that no runtime backend work was left running" : `${orphanedBackends} runtime backend(s) still active or in a transaction after the run (timed-out work was not cancelled)`);
    if (verdict.result === "PASS") verdict.result = "FAIL";
  }
  if (maxUnsettled > 1) {
    verdict.reasons.push(`${maxUnsettled} probe operations were unsettled at once; the reported concurrency of one did not hold`);
    if (verdict.result === "PASS") verdict.result = "FAIL";
  }
  return { phases, verdict, recoverySeconds, maxProbeDurationDownMs: Math.round(maxDown), integrity, abandonedProbes, maxUnsettledProbes: maxUnsettled, orphanedBackends, mode };
}
