import assert from "node:assert/strict";
import { after, before, beforeEach, test } from "node:test";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";
import { ADMIN_INQUIRY_PAGE_SIZE, type AdminInquiryQuery } from "../src/lib/admin-inquiry-query";
import { PostgresAdminInquiryReadRepository } from "../src/lib/admin-inquiry-repository";
import { adminNotes, inquiries, inquiryEvents, notificationOutbox } from "../src/lib/db/schema";
import * as schema from "../src/lib/db/schema";

const databaseUrl = process.env.TEST_DATABASE_URL;
const integration = { skip: databaseUrl ? false : "TEST_DATABASE_URL is not configured" } as const;
const client = databaseUrl ? postgres(databaseUrl, { max: 8, prepare: false }) : null;
const database = client ? drizzle(client, { schema }) : null;
const repository = database ? new PostgresAdminInquiryReadRepository(database) : null;

before(async () => { if (database) await migrate(database, { migrationsFolder: "drizzle" }); });
beforeEach(async () => { if (client) await client`TRUNCATE TABLE notification_outbox, admin_notes, inquiry_events, inquiries`; });
after(async () => { if (client) await client.end(); });

function query(overrides: Partial<AdminInquiryQuery> = {}): AdminInquiryQuery {
  return { page: 1, status: null, search: "", ...overrides };
}

function row(index: number, overrides: Partial<typeof inquiries.$inferInsert> = {}): typeof inquiries.$inferInsert {
  const idTail = index.toString(16).padStart(12, "0");
  return {
    id: `00000000-0000-4000-8000-${idTail}`,
    createdAt: new Date(Date.UTC(2026, 0, 1, 0, index)),
    name: `Synthetic Person ${index}`,
    email: `person${index}@example.test`,
    company: `Synthetic Company ${index}`,
    service: "web",
    system: `Synthetic system ${index}`,
    objective: `Synthetic objective ${index}`,
    environment: "staging",
    authority: "authorized",
    protection: "unknown",
    provider: "",
    notes: "",
    submissionToken: `T${String(index).padStart(42, "0")}`,
    payloadFingerprint: index.toString(16).padStart(64, "0"),
    ...overrides,
  };
}

test("list is newest-first with an id tie-breaker and never exceeds its fixed page size", integration, async () => {
  const tiedAt = new Date("2026-01-02T00:00:00Z");
  await database!.insert(inquiries).values(Array.from({ length: 30 }, (_, index) => row(index + 1, index >= 28 ? { createdAt: tiedAt } : {})));
  const first = await repository!.listInquiries(query());
  assert.equal(first.items.length, ADMIN_INQUIRY_PAGE_SIZE);
  assert.equal(first.hasNextPage, true);
  assert.equal(first.items[0].id, row(30).id);
  assert.equal(first.items[1].id, row(29).id);
  const second = await repository!.listInquiries(query({ page: 2 }));
  assert.equal(second.items.length, 5);
  assert.equal(second.hasNextPage, false);
  assert.equal(new Set([...first.items, ...second.items].map((item) => item.id)).size, 30);
  const absurd = await repository!.listInquiries({ ...query(), page: Number.POSITIVE_INFINITY });
  assert.deepEqual(absurd.items.map((item) => item.id), first.items.map((item) => item.id));
});

test("status and conservative search return only intended fields", integration, async () => {
  await database!.insert(inquiries).values([
    row(1, { status: "completed", name: "Exact Needle", company: "100%_literal" }),
    row(2, { status: "received", email: "needle@example.test", company: "100XXliteral" }),
    row(3, { status: "declined", objective: "forbiddenneedle", notes: "needle only in notes" }),
  ]);
  const completed = await repository!.listInquiries(query({ status: "completed" }));
  assert.deepEqual(completed.items.map((item) => item.id), [row(1).id]);
  const needle = await repository!.listInquiries(query({ search: "needle" }));
  assert.deepEqual(new Set(needle.items.map((item) => item.id)), new Set([row(1).id, row(2).id]));
  const literalWildcard = await repository!.listInquiries(query({ search: "%_" }));
  assert.deepEqual(literalWildcard.items.map((item) => item.id), [row(1).id]);
  const uuidPrefix = await repository!.listInquiries(query({ search: row(2).id! }));
  assert.deepEqual(uuidPrefix.items.map((item) => item.id), [row(2).id]);
  const invalidStatus = await repository!.listInquiries({ ...query(), status: "scheduled" as "received" });
  assert.equal(invalidStatus.items.length, 3);
});

test("detail returns only the selected inquiry with deterministic history and plain note data", integration, async () => {
  const selected = row(10);
  const other = row(11);
  await database!.insert(inquiries).values([selected, other]);
  const eventTime = new Date("2026-01-03T00:00:00Z");
  await database!.insert(inquiryEvents).values([
    { id: "00000000-0000-4000-8000-000000000102", inquiryId: selected.id!, eventType: "notification_sent", actorType: "system", createdAt: eventTime, metadata: { rawSecret: "must-not-appear" } },
    { id: "00000000-0000-4000-8000-000000000101", inquiryId: selected.id!, eventType: "inquiry_received", actorType: "system", createdAt: eventTime },
    { id: "00000000-0000-4000-8000-000000000103", inquiryId: other.id!, eventType: "inquiry_received", actorType: "system", createdAt: eventTime },
  ]);
  await database!.insert(adminNotes).values({ inquiryId: selected.id!, authorIdentifier: "synthetic-admin@example.test", content: "<b>plain text</b>", createdAt: eventTime });
  await database!.insert(notificationOutbox).values({ inquiryId: selected.id!, eventType: "inquiry_received", status: "failed", lastErrorCode: "provider_unavailable" });

  const detail = await repository!.getInquiryDetail(selected.id!);
  assert.equal(detail?.inquiry.id, selected.id);
  assert.deepEqual(detail?.events.map((event) => event.id), ["00000000-0000-4000-8000-000000000101", "00000000-0000-4000-8000-000000000102"]);
  assert.equal(detail?.adminNotes[0].content, "<b>plain text</b>");
  assert.equal("metadata" in detail!.events[0], false);
  assert.equal("submissionToken" in detail!.inquiry, false);
  assert.equal("payloadFingerprint" in detail!.inquiry, false);
  assert.equal("notificationOutbox" in detail!, false);
  assert.equal(detail!.eventsTruncated, false);
  assert.equal(detail!.adminNotesTruncated, false);
  assert.equal(JSON.stringify(detail).includes("must-not-appear"), false);
  assert.equal(JSON.stringify(detail).includes("provider_unavailable"), false);
  assert.equal(await repository!.getInquiryDetail("00000000-0000-4000-8000-000000000099"), null);
});
