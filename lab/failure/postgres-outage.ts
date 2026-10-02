/**
 * PostgreSQL unavailability and recovery against the lab-owned container only.
 *
 * Probes are real `PostgresInquiryRepository.create` calls (synthetic data, runtime role, a pool
 * configured like src/lib/db/database.server.ts). The outage is injected with `docker stop`
 * (connection refused/reset) or `docker pause` (blackhole: exercises connect_timeout), and only on
 * a container carrying the lab name prefix and the disposable label.
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
  mode: OutageMode;
};

export async function runPostgresOutage(state: PgLabState, limits: EffectiveLimits, set: ThresholdSet, mode: OutageMode): Promise<PostgresOutageOutcome> {
  // Same pool shape as the application (src/lib/db/database.server.ts).
  const client = postgres(runtimeUrl(state), { max: 5, idle_timeout: 20, connect_timeout: 5, prepare: false, onnotice: () => undefined });
  const repository = new PostgresInquiryRepository(drizzle(client, { schema }));
  const phases: PhaseStats[] = [];
  let startedAt = 0, firstOkAfterStart: number | null = null, consecutiveOk = 0, maxDown = 0;
  const thresholds = set.recovery["postgres-outage"];

  const probe = async (timeoutMs: number): Promise<{ ok: boolean; category: string; ms: number }> => {
    const started = performance.now();
    const token = randomBytes(32).toString("base64url");
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        repository.create({ request, submissionToken: token, payloadFingerprint: createPayloadFingerprint(request) }),
        new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error("probe timeout"), { code: "PROBE_TIMEOUT" })), timeoutMs); }),
      ]);
      return { ok: true, category: "ok", ms: performance.now() - started };
    } catch (error) {
      return { ok: false, category: categorize(error), ms: performance.now() - started };
    } finally { clearTimeout(timer); }
  };

  const deadline = performance.now() + limits.maxDurationSeconds * 1000 + 15_000;
  let attemptedTotal = 0;
  try {
    for (const phase of limits.phases) {
      if (phase.name === "outage") await controlLabContainer(mode === "pause" ? "pause" : "stop", state.container);
      if (phase.name === "recovery") {
        await controlLabContainer(mode === "pause" ? "unpause" : "start", state.container);
        startedAt = performance.now();
      }
      const latencies: number[] = [];
      const outcomes: Record<string, number> = {};
      let attempted = 0, succeeded = 0, failed = 0;
      const startedPhase = new Date();
      const end = performance.now() + phase.durationSeconds * 1000;
      const interval = 1000 / phase.ratePerSecond;
      while (performance.now() < end && performance.now() < deadline && attemptedTotal < limits.maxTotalRequests) {
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
    await controlLabContainer(mode === "pause" ? "unpause" : "start", state.container).catch(() => undefined);
    await client.end({ timeout: 2 }).catch(() => undefined);
  }

  const recoverySeconds = firstOkAfterStart === null ? null : Math.round((firstOkAfterStart - startedAt) / 10) / 100;
  // Integrity after recovery: nothing partial, using the owner role.
  const owner = postgres(migratorUrl(state), { max: 1, prepare: false, connect_timeout: 5, onnotice: () => undefined });
  let integrity = { inquiries: -1, events: -1, outbox: -1, orphans: -1 };
  try {
    const [row] = await owner<{ i: string; e: string; o: string; orphans: string }[]>`
      SELECT (SELECT count(*) FROM inquiries) AS i, (SELECT count(*) FROM inquiry_events) AS e, (SELECT count(*) FROM notification_outbox) AS o,
        (SELECT count(*) FROM inquiries q WHERE (SELECT count(*) FROM inquiry_events e WHERE e.inquiry_id = q.id) <> 1
           OR (SELECT count(*) FROM notification_outbox n WHERE n.inquiry_id = q.id) <> 1) AS orphans`;
    integrity = { inquiries: Number(row.i), events: Number(row.e), outbox: Number(row.o), orphans: Number(row.orphans) };
  } finally { await owner.end({ timeout: 2 }).catch(() => undefined); }

  const verdict = evaluateRecovery(thresholds, {
    phases, recoverySeconds, maxProbeDurationDownMs: maxDown,
    downPhase: "outage", recoveryPhase: "recovery", steadyPhases: ["healthy-before", "healthy-after"],
  });
  if (integrity.orphans !== 0 || integrity.inquiries !== integrity.events || integrity.inquiries !== integrity.outbox) {
    verdict.reasons.push("partial writes detected after recovery");
    if (verdict.result === "PASS") verdict.result = "FAIL";
  }
  return { phases, verdict, recoverySeconds, maxProbeDurationDownMs: Math.round(maxDown), integrity, mode };
}
