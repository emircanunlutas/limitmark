import assert from "node:assert/strict";
import { after, before, beforeEach, test } from "node:test";
import { count, eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";
import { inquiries, inquiryEvents, notificationOutbox } from "../src/lib/db/schema";
import * as schema from "../src/lib/db/schema";
import { PostgresInquiryRepository } from "../src/lib/inquiry-repository";
import { createPayloadFingerprint } from "../src/lib/payload-fingerprint";
import { requestSchema } from "../src/lib/request-schema";

const databaseUrl = process.env.TEST_DATABASE_URL;
const integration = { skip: databaseUrl ? false : "TEST_DATABASE_URL is not configured" } as const;
const client = databaseUrl ? postgres(databaseUrl, { max: 12, prepare: false }) : null;
const database = client ? drizzle(client, { schema }) : null;

const validRequest = requestSchema.parse({
  name: "PostgreSQL Entegrasyon",
  email: "integration@example.test",
  company: "Sentetik Kuruluş",
  service: "web",
  system: "Yalnızca test veritabanı",
  objective: "Transaction davranışını doğrulamak",
  environment: "staging",
  authority: "authorized",
  protection: "unknown",
});

function input(token: string, objective = validRequest.objective) {
  const request = { ...validRequest, objective };
  return { request, submissionToken: token, payloadFingerprint: createPayloadFingerprint(request) };
}

async function totals() {
  const [inquiryCount, eventCount, outboxCount] = await Promise.all([
    database!.select({ value: count() }).from(inquiries),
    database!.select({ value: count() }).from(inquiryEvents),
    database!.select({ value: count() }).from(notificationOutbox),
  ]);
  return [inquiryCount[0].value, eventCount[0].value, outboxCount[0].value];
}

before(async () => {
  if (!database) return;
  await migrate(database, { migrationsFolder: "drizzle" });
});

beforeEach(async () => {
  if (!client) return;
  await client`TRUNCATE TABLE notification_outbox, admin_notes, inquiry_events, inquiries`;
});

after(async () => {
  if (client) await client.end();
});

test("migration creates constrained tables, non-cascading history, and append-only events", integration, async () => {
  const tables = await client!<{ table_name: string }[]>`
    SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name IN ('inquiries', 'inquiry_events', 'admin_notes', 'notification_outbox')
    ORDER BY table_name`;
  assert.deepEqual(tables.map((row) => row.table_name), ["admin_notes", "inquiries", "inquiry_events", "notification_outbox"]);

  const repository = new PostgresInquiryRepository(database!);
  const created = await repository.create(input("s".repeat(43)));
  assert.equal(created.status, "created");
  await assert.rejects(database!.update(inquiryEvents).set({ actorType: "admin", actorIdentifier: "synthetic-admin" }));
  await assert.rejects(database!.delete(inquiries).where(eq(inquiries.id, created.inquiryId)));
});

test("a valid submission atomically creates one inquiry, initial event, and pending outbox job", integration, async () => {
  const result = await new PostgresInquiryRepository(database!).create(input("a".repeat(43)));
  assert.equal(result.status, "created");
  assert.deepEqual(await totals(), [1, 1, 1]);
  const [event] = await database!.select().from(inquiryEvents);
  const [outbox] = await database!.select().from(notificationOutbox);
  assert.equal(event.eventType, "inquiry_received");
  assert.equal(event.actorType, "system");
  assert.equal(event.metadata, null);
  assert.equal(outbox.status, "pending");
  assert.equal(outbox.attempts, 0);
});

test("sequential identical submissions are idempotent", integration, async () => {
  const repository = new PostgresInquiryRepository(database!);
  assert.equal((await repository.create(input("b".repeat(43)))).status, "created");
  assert.equal((await repository.create(input("b".repeat(43)))).status, "idempotent");
  assert.deepEqual(await totals(), [1, 1, 1]);
});

test("concurrent identical submissions resolve the unique race as success", integration, async () => {
  const repository = new PostgresInquiryRepository(database!);
  const results = await Promise.all(Array.from({ length: 8 }, () => repository.create(input("c".repeat(43)))));
  assert.equal(results.filter((result) => result.status === "created").length, 1);
  assert.equal(results.filter((result) => result.status === "idempotent").length, 7);
  assert.deepEqual(await totals(), [1, 1, 1]);
});

test("same token with a different fingerprint conflicts without modifying the original", integration, async () => {
  const repository = new PostgresInquiryRepository(database!);
  await repository.create(input("d".repeat(43)));
  assert.equal((await repository.create(input("d".repeat(43), "Değiştirilmiş amaç"))).status, "conflict");
  assert.deepEqual(await totals(), [1, 1, 1]);
  const [stored] = await database!.select().from(inquiries);
  assert.equal(stored.objective, validRequest.objective);
});

for (const target of ["inquiry_events", "notification_outbox"] as const) {
  test(`failure while inserting ${target} rolls back the whole inquiry transaction`, integration, async () => {
    const triggerName = `test_fail_${target}`;
    await client!.unsafe(`CREATE TRIGGER ${triggerName} BEFORE INSERT ON ${target} FOR EACH ROW EXECUTE FUNCTION reject_inquiry_event_mutation()`);
    try {
      await assert.rejects(new PostgresInquiryRepository(database!).create(input((target === "inquiry_events" ? "e" : "f").repeat(43))));
      assert.deepEqual(await totals(), [0, 0, 0]);
    } finally {
      await client!.unsafe(`DROP TRIGGER ${triggerName} ON ${target}`);
    }
  });
}
