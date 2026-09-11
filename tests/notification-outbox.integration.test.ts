import assert from "node:assert/strict";
import { after, before, beforeEach, test } from "node:test";
import { asc, eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";
import { inquiries, notificationOutbox } from "../src/lib/db/schema";
import * as schema from "../src/lib/db/schema";
import { PostgresInquiryRepository } from "../src/lib/inquiry-repository";
import { PostgresNotificationOutboxRepository } from "../src/lib/notification-outbox-repository";
import { createPayloadFingerprint } from "../src/lib/payload-fingerprint";
import { requestSchema } from "../src/lib/request-schema";
import { createExponentialRetryPolicy } from "../src/lib/notification-retry-policy";
import { processOutboxBatch } from "../src/lib/outbox-processor";
import { SyntheticNotificationAdapter } from "./support/synthetic-notification-adapter";

const databaseUrl = process.env.TEST_DATABASE_URL;
const integration = { skip: databaseUrl ? false : "TEST_DATABASE_URL is not configured" } as const;
const client = databaseUrl ? postgres(databaseUrl, { max: 12, prepare: false }) : null;
const database = client ? drizzle(client, { schema }) : null;
const now = new Date("2030-09-11T12:00:00.000Z");
const leaseDurationMs = 60_000;

const request = requestSchema.parse({
  name: "Outbox Integration",
  email: "outbox@example.test",
  company: "Synthetic Company",
  service: "web",
  system: "Synthetic system payload",
  objective: "Verify outbox processing",
  environment: "staging",
  authority: "authorized",
  protection: "unknown",
  notes: "Must remain unchanged",
});

let tokenSequence = 0;

async function createPendingJob() {
  tokenSequence++;
  const token = tokenSequence.toString(36).padStart(43, "0");
  const result = await new PostgresInquiryRepository(database!).create({
    request,
    submissionToken: token,
    payloadFingerprint: createPayloadFingerprint(request),
  });
  assert.equal(result.status, "created");
  const [job] = await database!.select().from(notificationOutbox)
    .where(eq(notificationOutbox.inquiryId, result.inquiryId));
  return { inquiryId: result.inquiryId, job };
}

async function addJobs(inquiryId: string, count: number) {
  if (count < 1) return [];
  return database!.insert(notificationOutbox).values(Array.from({ length: count }, () => ({
    inquiryId,
    eventType: "inquiry_received" as const,
    availableAt: now,
  }))).returning();
}

async function readJob(id: string) {
  const [job] = await database!.select().from(notificationOutbox).where(eq(notificationOutbox.id, id));
  return job;
}

function processor(adapter: SyntheticNotificationAdapter, overrides: Partial<Parameters<typeof processOutboxBatch>[0]> = {}) {
  return processOutboxBatch({
    repository: new PostgresNotificationOutboxRepository(database!),
    adapter,
    now,
    leaseDurationMs,
    retryPolicy: createExponentialRetryPolicy({ maxAttempts: 3, initialDelayMs: 1_000, maximumDelayMs: 8_000 }),
    ...overrides,
  });
}

before(async () => {
  if (!database) return;
  await migrate(database, { migrationsFolder: "drizzle" });
});

beforeEach(async () => {
  if (!client) return;
  tokenSequence = 0;
  await client`TRUNCATE TABLE notification_outbox, admin_notes, inquiry_events, inquiries`;
});

after(async () => {
  if (client) await client.end();
});

test("claim atomically moves a pending job to processing and starts one leased attempt", integration, async () => {
  const { job } = await createPendingJob();
  const lockedUntil = new Date(now.getTime() + leaseDurationMs);
  const claimed = await new PostgresNotificationOutboxRepository(database!).claimBatch({ now, lockedUntil, batchSize: 1 });
  assert.equal(claimed.length, 1);
  assert.equal(claimed[0].outboxId, job.id);
  assert.equal(claimed[0].attempts, 1);
  assert.equal(claimed[0].lockedUntil.getTime(), lockedUntil.getTime());
  const stored = await readJob(job.id);
  assert.equal(stored.status, "processing");
  assert.equal(stored.attempts, 1);
  assert.equal(stored.lockedUntil?.getTime(), lockedUntil.getTime());
});

test("successful delivery becomes sent with clean terminal metadata and minimal command", integration, async () => {
  const { job, inquiryId } = await createPendingJob();
  const adapter = new SyntheticNotificationAdapter();
  assert.deepEqual(await processor(adapter), { claimed: 1, sent: 1, retryable: 0, failed: 0, leaseLost: 0 });
  const stored = await readJob(job.id);
  assert.equal(stored.status, "sent");
  assert.equal(stored.attempts, 1);
  assert.equal(stored.sentAt?.getTime(), now.getTime());
  assert.equal(stored.lockedUntil, null);
  assert.equal(stored.lastErrorCode, null);
  assert.deepEqual(adapter.commands, [{
    idempotencyKey: job.id,
    inquiryId,
    eventType: "inquiry_received",
  }]);
});

test("retryable failure schedules deterministic backoff and clears the lease", integration, async () => {
  const { job } = await createPendingJob();
  const adapter = new SyntheticNotificationAdapter({ outcome: "retryable_failure", errorCode: "provider_unavailable" });
  assert.equal((await processor(adapter)).retryable, 1);
  const stored = await readJob(job.id);
  assert.equal(stored.status, "retryable");
  assert.equal(stored.attempts, 1);
  assert.equal(stored.availableAt.getTime(), now.getTime() + 1_000);
  assert.equal(stored.lockedUntil, null);
  assert.equal(stored.lastErrorCode, "provider_unavailable");
});

test("retry-budget exhaustion becomes terminal failed and cannot be reclaimed", integration, async () => {
  const { job } = await createPendingJob();
  const adapter = new SyntheticNotificationAdapter({ outcome: "retryable_failure", errorCode: "timeout" });
  await processor(adapter, { retryPolicy: createExponentialRetryPolicy({ maxAttempts: 1 }) });
  const stored = await readJob(job.id);
  assert.equal(stored.status, "failed");
  assert.equal(stored.attempts, 1);
  assert.equal(stored.lockedUntil, null);
  const reclaimed = await new PostgresNotificationOutboxRepository(database!).claimBatch({
    now: new Date(now.getTime() + 86_400_000),
    lockedUntil: new Date(now.getTime() + 86_460_000),
    batchSize: 1,
  });
  assert.equal(reclaimed.length, 0);
});

test("permanent delivery failure becomes failed immediately", integration, async () => {
  const { job } = await createPendingJob();
  const adapter = new SyntheticNotificationAdapter({ outcome: "permanent_failure", errorCode: "rejected" });
  assert.equal((await processor(adapter)).failed, 1);
  const stored = await readJob(job.id);
  assert.equal(stored.status, "failed");
  assert.equal(stored.attempts, 1);
  assert.equal(stored.lastErrorCode, "rejected");
});

test("two concurrent claimers partition eligible rows without duplicate claims", integration, async () => {
  const { inquiryId } = await createPendingJob();
  await addJobs(inquiryId, 7);
  const repositories = [
    new PostgresNotificationOutboxRepository(database!),
    new PostgresNotificationOutboxRepository(database!),
  ];
  const lockedUntil = new Date(now.getTime() + leaseDurationMs);
  const claims = await Promise.all(repositories.map((repository) => repository.claimBatch({ now, lockedUntil, batchSize: 8 })));
  const ids = claims.flat().map((job) => job.outboxId);
  assert.equal(ids.length, 8);
  assert.equal(new Set(ids).size, 8);
  const rows = await database!.select().from(notificationOutbox);
  assert.equal(rows.every((row) => row.status === "processing" && row.attempts === 1), true);
});

test("expired leases recover as a new attempt while live leases are not stolen", integration, async () => {
  const { job, inquiryId } = await createPendingJob();
  const [live] = await addJobs(inquiryId, 1);
  await database!.update(notificationOutbox).set({
    status: "processing",
    attempts: 1,
    lockedUntil: new Date(now.getTime() - 1),
  }).where(eq(notificationOutbox.id, job.id));
  await database!.update(notificationOutbox).set({
    status: "processing",
    attempts: 1,
    lockedUntil: new Date(now.getTime() + 1),
  }).where(eq(notificationOutbox.id, live.id));
  const claimed = await new PostgresNotificationOutboxRepository(database!).claimBatch({
    now,
    lockedUntil: new Date(now.getTime() + leaseDurationMs),
    batchSize: 2,
  });
  assert.deepEqual(claimed.map(({ outboxId }) => outboxId), [job.id]);
  assert.equal(claimed[0].attempts, 2);
  assert.equal((await readJob(live.id)).attempts, 1);
});

test("sent, failed, live processing, and future rows are never claimed", integration, async () => {
  const { job, inquiryId } = await createPendingJob();
  const extras = await addJobs(inquiryId, 3);
  await database!.update(notificationOutbox).set({ status: "sent", sentAt: now })
    .where(eq(notificationOutbox.id, job.id));
  await database!.update(notificationOutbox).set({ status: "failed" })
    .where(eq(notificationOutbox.id, extras[0].id));
  await database!.update(notificationOutbox).set({ status: "processing", lockedUntil: new Date(now.getTime() + 60_000) })
    .where(eq(notificationOutbox.id, extras[1].id));
  await database!.update(notificationOutbox).set({ availableAt: new Date(now.getTime() + 1) })
    .where(eq(notificationOutbox.id, extras[2].id));
  const claimed = await new PostgresNotificationOutboxRepository(database!).claimBatch({
    now,
    lockedUntil: new Date(now.getTime() + leaseDurationMs),
    batchSize: 10,
  });
  assert.equal(claimed.length, 0);
});

test("attempts increments exactly once for each claimed delivery attempt", integration, async () => {
  const { job } = await createPendingJob();
  await processor(new SyntheticNotificationAdapter({ outcome: "retryable_failure", errorCode: "timeout" }));
  assert.equal((await readJob(job.id)).attempts, 1);
  const secondNow = new Date(now.getTime() + 1_000);
  await processor(new SyntheticNotificationAdapter(), { now: secondNow });
  const stored = await readJob(job.id);
  assert.equal(stored.attempts, 2);
  assert.equal(stored.status, "sent");
});

test("an unexpected adapter throw is sanitized and remains recoverable", integration, async () => {
  const { job } = await createPendingJob();
  assert.equal((await processor(new SyntheticNotificationAdapter("throw"))).retryable, 1);
  const stored = await readJob(job.id);
  assert.equal(stored.status, "retryable");
  assert.equal(stored.lastErrorCode, "unknown");
  assert.equal(stored.lockedUntil, null);
});

test("batching claims only the requested bounded number of rows", integration, async () => {
  const { inquiryId } = await createPendingJob();
  await addJobs(inquiryId, 4);
  const summary = await processor(new SyntheticNotificationAdapter(), { batchSize: 2 });
  assert.deepEqual(summary, { claimed: 2, sent: 2, retryable: 0, failed: 0, leaseLost: 0 });
  const rows = await database!.select().from(notificationOutbox).orderBy(asc(notificationOutbox.createdAt));
  assert.equal(rows.filter((row) => row.status === "sent").length, 2);
  assert.equal(rows.filter((row) => row.status === "pending").length, 3);
});

test("overlapping processors never deliver the same outbox row", integration, async () => {
  const { inquiryId } = await createPendingJob();
  await addJobs(inquiryId, 5);
  const adapter = new SyntheticNotificationAdapter({ outcome: "delivered" }, 20);
  const summaries = await Promise.all([
    processor(adapter, { batchSize: 3 }),
    processor(adapter, { batchSize: 3 }),
  ]);
  assert.equal(summaries.reduce((sum, value) => sum + value.claimed, 0), 6);
  assert.equal(adapter.commands.length, 6);
  assert.equal(new Set(adapter.commands.map(({ idempotencyKey }) => idempotencyKey)).size, 6);
  const rows = await database!.select().from(notificationOutbox);
  assert.equal(rows.every((row) => row.status === "sent" && row.attempts === 1), true);
});

test("notification outcomes never modify the related inquiry payload", integration, async () => {
  const { inquiryId } = await createPendingJob();
  const [before] = await database!.select().from(inquiries).where(eq(inquiries.id, inquiryId));
  await processor(new SyntheticNotificationAdapter({ outcome: "permanent_failure", errorCode: "rejected" }));
  const [afterRow] = await database!.select().from(inquiries).where(eq(inquiries.id, inquiryId));
  assert.deepEqual(afterRow, before);
});

test("a stale worker outcome cannot overwrite a newer lease", integration, async () => {
  const { job } = await createPendingJob();
  const repository = new PostgresNotificationOutboxRepository(database!);
  const [first] = await repository.claimBatch({
    now,
    lockedUntil: new Date(now.getTime() + 1),
    batchSize: 1,
  });
  const recoveryNow = new Date(now.getTime() + 2);
  const [recovered] = await repository.claimBatch({
    now: recoveryNow,
    lockedUntil: new Date(recoveryNow.getTime() + leaseDurationMs),
    batchSize: 1,
  });
  assert.equal(recovered.outboxId, job.id);
  assert.equal(recovered.attempts, 2);
  assert.equal(await repository.markSent({ ...first, now: recoveryNow }), false);
  const stored = await readJob(job.id);
  assert.equal(stored.status, "processing");
  assert.equal(stored.attempts, 2);
  assert.equal(stored.lockedUntil?.getTime(), recovered.lockedUntil.getTime());
});
