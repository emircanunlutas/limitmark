import assert from "node:assert/strict";
import { after, before, beforeEach, test } from "node:test";
import { asc } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import { PostgresAdminNotificationDeliveryReadRepository } from "../src/lib/admin-notification-delivery-repository";
import { inquiries, notificationOutbox } from "../src/lib/db/schema";
import * as schema from "../src/lib/db/schema";
import { assessNotificationDeliveryHealth, toInquiryNotificationDelivery } from "../src/lib/notification-delivery-health";
import { disposableTestDatabase } from "./support/test-database-guard";

// Same fail-closed disposable-database guard as the other admin integration suites; skipped without one.
const testDatabase = disposableTestDatabase();
const integration = { skip: testDatabase.enabled ? false : "TEST_DATABASE_URL is not configured" } as const;
const client = testDatabase.connect({ max: 4 });
const database = client ? drizzle(client, { schema }) : null;
const repository = testDatabase.enabled ? new PostgresAdminNotificationDeliveryReadRepository(() => {
  const readClient = testDatabase.connect({ max: 1 })!;
  return { client: readClient, close: () => readClient.end({ timeout: 0 }) };
}) : null;
const signal = () => new AbortController().signal;

before(async () => {
  if (!database) return;
  await testDatabase.migrate(client, "drizzle");
});
beforeEach(async () => {
  if (!client) return;
  await testDatabase.destructive(client, (tx) => tx`TRUNCATE TABLE notification_outbox, admin_notes, inquiry_events, inquiries`);
});
after(async () => { if (client) await client.end(); });

const now = new Date("2026-11-24T12:00:00.000Z");
const minutes = (offset: number) => new Date(now.getTime() + offset * 60_000);
const micros = (date: Date) => BigInt(date.getTime()) * 1_000n;
const inquiryA = "00000000-0000-4000-8000-00000000000a";
const inquiryB = "00000000-0000-4000-8000-00000000000b";

function inquiry(id: string, index: number): typeof inquiries.$inferInsert {
  return {
    id, name: `Synthetic Person ${index}`, email: `person${index}@example.test`, service: "web", system: "Synthetic system",
    objective: "Synthetic objective", environment: "staging", authority: "authorized",
    submissionToken: `T${String(index).padStart(42, "0")}`, payloadFingerprint: index.toString(16).padStart(64, "0"),
  };
}

function outbox(index: number, inquiryId: string, overrides: Partial<typeof notificationOutbox.$inferInsert>): typeof notificationOutbox.$inferInsert {
  return {
    id: `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`, inquiryId, eventType: "inquiry_received",
    status: "pending", attempts: 0, createdAt: minutes(-120), availableAt: minutes(-1), ...overrides,
  };
}

async function seed() {
  await database!.insert(inquiries).values([inquiry(inquiryA, 1), inquiry(inquiryB, 2)]);
  await database!.insert(notificationOutbox).values([
    outbox(1, inquiryA, { status: "pending", availableAt: minutes(-5) }), // due, fresh
    outbox(2, inquiryA, { status: "retryable", attempts: 1, availableAt: minutes(-45), lastErrorCode: "timeout" }), // due, overdue
    outbox(3, inquiryA, { status: "retryable", attempts: 2, availableAt: minutes(50) }), // scheduled
    outbox(4, inquiryB, { status: "processing", attempts: 1, lockedUntil: minutes(3) }), // in progress
    outbox(5, inquiryB, { status: "processing", attempts: 1, lockedUntil: minutes(-10) }), // lease expired, fresh
    outbox(6, inquiryB, { status: "processing", attempts: 1, lockedUntil: minutes(-30) }), // lease expired, overdue (exact boundary)
    outbox(7, inquiryB, { status: "failed", attempts: 5, lastErrorCode: "rejected" }),
    outbox(8, inquiryB, { status: "sent", attempts: 1, sentAt: minutes(-100) }),
    outbox(9, inquiryB, { status: "processing", attempts: 1, lockedUntil: null, availableAt: minutes(-600) }), // no lease: never claimable, never overdue
  ]);
}

test("aggregate counts match the pure state model, including the exact 30-minute boundary", integration, async () => {
  await seed();
  assert.deepEqual(await repository!.getDeliveryCounts(now, signal()), {
    due: 2, scheduled: 1, inProgress: 1, leaseExpired: 2, leaseMissing: 1, failed: 1, overdue: 2, oldestDueAt: micros(minutes(-45)),
  });
  // One millisecond earlier, the exact-boundary lease (row 6) is no longer overdue.
  assert.equal((await repository!.getDeliveryCounts(new Date(now.getTime() - 1), signal())).overdue, 1);
});

test("PostgreSQL preserves the microsecond immediately after each classification boundary", integration, async () => {
  await database!.insert(inquiries).values(inquiry(inquiryA, 1));
  const scheduled = outbox(1, inquiryA, { availableAt: now });
  const held = outbox(2, inquiryA, { status: "processing", lockedUntil: now });
  const fresh = outbox(3, inquiryA, { availableAt: minutes(-30) });
  const expiredFresh = outbox(4, inquiryA, { status: "processing", lockedUntil: minutes(-30) });
  await database!.insert(notificationOutbox).values([scheduled, held, fresh, expiredFresh]);
  await testDatabase.destructive(client, (tx) =>
    tx`update notification_outbox
       set available_at = available_at + interval '1 microsecond',
           locked_until = locked_until + interval '1 microsecond'
       where inquiry_id = ${inquiryA}::uuid`);

  const counts = await repository!.getDeliveryCounts(now, signal());
  assert.deepEqual(counts, {
    due: 1, scheduled: 1, inProgress: 1, leaseExpired: 1, leaseMissing: 0, failed: 0,
    overdue: 0, oldestDueAt: micros(minutes(-30)) + 1n,
  });
  assert.equal(assessNotificationDeliveryHealth(counts, now).level, "clear");
  const detail = (await repository!.listInquiryDeliveries(inquiryA, 4, signal()))
    .map((row) => toInquiryNotificationDelivery(row, now));
  assert.deepEqual(detail.map(({ state, overdue }) => [state, overdue]), [
    ["scheduled", false], ["in_progress", false], ["due", false], ["lease_expired", false],
  ]);
});

test("an empty outbox is a consistent zero snapshot", integration, async () => {
  assert.deepEqual(await repository!.getDeliveryCounts(now, signal()), {
    due: 0, scheduled: 0, inProgress: 0, leaseExpired: 0, leaseMissing: 0, failed: 0, overdue: 0, oldestDueAt: null,
  });
});

test("per-inquiry reads are scoped, ordered, bounded and leave every row untouched", integration, async () => {
  await seed();
  const snapshot = () => database!.select().from(notificationOutbox).orderBy(asc(notificationOutbox.id));
  const before = await snapshot();
  const rows = await repository!.listInquiryDeliveries(inquiryA, 2, signal());
  assert.deepEqual(rows.map((row) => row.id), [outbox(1, inquiryA, {}).id, outbox(2, inquiryA, {}).id]);
  assert.deepEqual(Object.keys(rows[0]).sort(), ["attempts", "availableAt", "createdAt", "eventType", "id", "lastErrorCode", "lockedUntil", "sentAt", "status"]);
  assert.equal(rows[1].availableAt, micros(minutes(-45)));
  assert.equal((await repository!.listInquiryDeliveries(inquiryB, 100, signal())).length, 6);
  await repository!.getDeliveryCounts(now, signal());
  assert.deepEqual(await snapshot(), before);
  await assert.rejects(repository!.listInquiryDeliveries(inquiryA, 0, signal()), RangeError);
  await assert.rejects(repository!.listInquiryDeliveries(inquiryA, 101, signal()), RangeError);
});

test("the repository's transaction mode really is READ ONLY", integration, async () => {
  // Same BEGIN mode the repository uses: PostgreSQL itself refuses writes inside it.
  await assert.rejects(client!.begin("read only", (sql) => sql`delete from notification_outbox`), /read-only transaction/);
});
