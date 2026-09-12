import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { after, before, beforeEach, test } from "node:test";
import { count, eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres, { type TransactionSql } from "postgres";
import { PostgresAdminInquiryMutationRepository } from "../src/lib/admin-inquiry-mutation-repository";
import { adminNotes, inquiries, inquiryEvents } from "../src/lib/db/schema";
import * as schema from "../src/lib/db/schema";

const databaseUrl = process.env.TEST_DATABASE_URL;
const integration = { skip: databaseUrl ? false : "TEST_DATABASE_URL is not configured" } as const;
const client = databaseUrl ? postgres(databaseUrl, { max: 12, prepare: false }) : null;
const database = client ? drizzle(client, { schema }) : null;
const repository = database ? new PostgresAdminInquiryMutationRepository(database) : null;
const inquiryId = "00000000-0000-4000-8000-000000000042";
const adminIdentity = { actorIdentifier: "verified-admin@example.test" } as const;

before(async () => { if (database) await migrate(database, { migrationsFolder: "drizzle" }); });
beforeEach(async () => { if (client) await client`TRUNCATE TABLE notification_outbox, admin_notes, inquiry_events, inquiries`; });
after(async () => { if (client) await client.end(); });

function row(overrides: Partial<typeof inquiries.$inferInsert> = {}): typeof inquiries.$inferInsert {
  return {
    id: inquiryId,
    name: "Synthetic Customer",
    email: "customer@example.test",
    company: "Synthetic Company",
    service: "web",
    system: "Synthetic system",
    objective: "Synthetic objective",
    environment: "staging",
    authority: "authorized",
    protection: "unknown",
    provider: "Synthetic provider",
    notes: "Customer supplied note",
    submissionToken: `T${"0".repeat(42)}`,
    payloadFingerprint: "a".repeat(64),
    ...overrides,
  };
}

function target(expectedRevision: number) { return { inquiryId, expectedRevision, identity: adminIdentity }; }

async function eventCount() {
  return (await database!.select({ value: count() }).from(inquiryEvents))[0].value;
}

async function payload() {
  const [stored] = await database!.select({
    name: inquiries.name, email: inquiries.email, company: inquiries.company, service: inquiries.service,
    system: inquiries.system, objective: inquiries.objective, environment: inquiries.environment,
    authority: inquiries.authority, protection: inquiries.protection, provider: inquiries.provider,
    notes: inquiries.notes, submissionToken: inquiries.submissionToken, payloadFingerprint: inquiries.payloadFingerprint,
  }).from(inquiries).where(eq(inquiries.id, inquiryId));
  return stored;
}

test("an allowed transition updates status and appends exactly one bounded admin event", integration, async () => {
  await database!.insert(inquiries).values(row());
  const beforePayload = await payload();
  assert.deepEqual(await repository!.changeStatus({ ...target(0), newStatus: "in_review" }), { status: "success", revision: 1 });
  const [stored] = await database!.select().from(inquiries);
  const [event] = await database!.select().from(inquiryEvents);
  assert.equal(stored.status, "in_review");
  assert.equal(stored.revision, 1);
  assert.deepEqual(event.metadata, { previousStatus: "received", newStatus: "in_review" });
  assert.equal(event.actorType, "admin");
  assert.equal(event.actorIdentifier, adminIdentity.actorIdentifier);
  assert.equal(await eventCount(), 1);
  assert.deepEqual(await payload(), beforePayload);
});

test("invalid and stale transitions change nothing and archived inquiries reject workflow transitions", integration, async () => {
  await database!.insert(inquiries).values(row());
  assert.deepEqual(await repository!.changeStatus({ ...target(0), newStatus: "completed" }), { status: "invalid" });
  assert.deepEqual(await repository!.changeStatus({ ...target(1), newStatus: "in_review" }), { status: "conflict" });
  assert.equal(await eventCount(), 0);
  assert.deepEqual(await repository!.archive(target(0)), { status: "success", revision: 1 });
  assert.deepEqual(await repository!.changeStatus({ ...target(1), newStatus: "in_review" }), { status: "invalid" });
  assert.equal(await eventCount(), 1);
});

test("concurrent competing compare-and-swap mutations allow at most one winner", integration, async () => {
  await database!.insert(inquiries).values(row());
  const results = await Promise.all([
    repository!.changeStatus({ ...target(0), newStatus: "in_review" }),
    repository!.changeStatus({ ...target(0), newStatus: "declined" }),
  ]);
  assert.equal(results.filter((result) => result.status === "success").length, 1);
  assert.equal(results.filter((result) => result.status === "conflict").length, 1);
  assert.equal(await eventCount(), 1);
});

test("event insertion failure rolls back the status compare-and-swap", integration, async () => {
  await database!.insert(inquiries).values(row());
  await client!.unsafe("CREATE TRIGGER test_fail_admin_event BEFORE INSERT ON inquiry_events FOR EACH ROW EXECUTE FUNCTION reject_inquiry_event_mutation()");
  try {
    await assert.rejects(repository!.changeStatus({ ...target(0), newStatus: "in_review" }));
    const [stored] = await database!.select().from(inquiries);
    assert.equal(stored.status, "received");
    assert.equal(stored.revision, 0);
    assert.equal(await eventCount(), 0);
  } finally {
    await client!.unsafe("DROP TRIGGER test_fail_admin_event ON inquiry_events");
  }
});

test("note and note_added event commit atomically without note content in metadata", integration, async () => {
  await database!.insert(inquiries).values(row());
  assert.deepEqual(await repository!.addNote({ ...target(0), content: "<b>internal plain text</b>" }), { status: "success", revision: 1 });
  const [note] = await database!.select().from(adminNotes);
  const [event] = await database!.select().from(inquiryEvents);
  assert.equal(note.content, "<b>internal plain text</b>");
  assert.equal(note.authorIdentifier, adminIdentity.actorIdentifier);
  assert.equal(event.eventType, "note_added");
  assert.equal(event.metadata, null);
  assert.equal(JSON.stringify(event).includes(note.content), false);
  assert.deepEqual(await repository!.addNote({ ...target(0), content: "stale" }), { status: "conflict" });
  assert.equal((await database!.select({ value: count() }).from(adminNotes))[0].value, 1);
});

test("invalid notes are rejected and an event failure rolls back both note and revision", integration, async () => {
  await database!.insert(inquiries).values(row());
  for (const content of ["", "   ", "x".repeat(10_001)]) {
    assert.deepEqual(await repository!.addNote({ ...target(0), content }), { status: "invalid" });
  }
  await client!.unsafe("CREATE TRIGGER test_fail_note_event BEFORE INSERT ON inquiry_events FOR EACH ROW EXECUTE FUNCTION reject_inquiry_event_mutation()");
  try {
    await assert.rejects(repository!.addNote({ ...target(0), content: "must roll back" }));
    assert.equal((await database!.select({ value: count() }).from(adminNotes))[0].value, 0);
    assert.equal((await database!.select().from(inquiries))[0].revision, 0);
  } finally {
    await client!.unsafe("DROP TRIGGER test_fail_note_event ON inquiry_events");
  }
});

test("archive preserves exact prior status and restore returns to it without duplicate events", integration, async () => {
  await database!.insert(inquiries).values(row({ status: "proposal_sent", revision: 7 }));
  const beforePayload = await payload();
  assert.deepEqual(await repository!.archive(target(7)), { status: "success", revision: 8 });
  let [stored] = await database!.select().from(inquiries);
  assert.equal(stored.status, "archived");
  assert.equal(stored.preArchiveStatus, "proposal_sent");
  assert.ok(stored.archivedAt instanceof Date);
  assert.deepEqual(await repository!.archive(target(7)), { status: "conflict" });
  assert.deepEqual(await repository!.archive(target(8)), { status: "invalid" });
  assert.equal(await eventCount(), 1);

  assert.deepEqual(await repository!.restore(target(8)), { status: "success", revision: 9 });
  [stored] = await database!.select().from(inquiries);
  assert.equal(stored.status, "proposal_sent");
  assert.equal(stored.preArchiveStatus, null);
  assert.equal(stored.archivedAt, null);
  assert.deepEqual(await repository!.restore(target(8)), { status: "conflict" });
  assert.deepEqual(await repository!.restore(target(9)), { status: "invalid" });
  assert.equal(await eventCount(), 2);
  const events = await database!.select().from(inquiryEvents);
  assert.deepEqual(events.map((event) => event.eventType), ["archived", "restored"]);
  assert.deepEqual(events.map((event) => event.metadata), [{ previousStatus: "proposal_sent" }, { restoredStatus: "proposal_sent" }]);
  assert.deepEqual(await payload(), beforePayload);
});

test("legacy archived rows without a durable prior status fail closed on restore", integration, async () => {
  await database!.insert(inquiries).values(row({ status: "archived", archivedAt: new Date(), preArchiveStatus: null }));
  assert.deepEqual(await repository!.restore(target(0)), { status: "invalid" });
  assert.equal(await eventCount(), 0);
});

test("append-only event enforcement remains intact", integration, async () => {
  await database!.insert(inquiries).values(row());
  await repository!.changeStatus({ ...target(0), newStatus: "in_review" });
  await assert.rejects(database!.update(inquiryEvents).set({ actorIdentifier: "tampered@example.test" }));
  await assert.rejects(database!.delete(inquiryEvents));
});

test("the Phase 4B migration preserves an existing baseline inquiry", integration, async () => {
  const temporarySchema = `phase4b_migration_${process.pid}`;
  const baseline = await readFile(new URL("../drizzle/0000_nebulous_nico_minoru.sql", import.meta.url), "utf8");
  const phase4b = await readFile(new URL("../drizzle/0001_new_nextwave.sql", import.meta.url), "utf8");
  const apply = async (sqlClient: TransactionSql, source: string) => {
    const scoped = source.replaceAll('"public".', `"${temporarySchema}".`);
    for (const statement of scoped.split("--> statement-breakpoint")) {
      if (statement.trim()) await sqlClient.unsafe(statement);
    }
  };
  await client!.unsafe(`DROP SCHEMA IF EXISTS "${temporarySchema}" CASCADE`);
  try {
    await client!.begin(async (transaction) => {
      await transaction.unsafe(`CREATE SCHEMA "${temporarySchema}"`);
      await transaction.unsafe(`SET LOCAL search_path TO "${temporarySchema}"`);
      await apply(transaction, baseline);
      await transaction`INSERT INTO inquiries (id, name, email, service, system, objective, environment, authority, submission_token, payload_fingerprint) VALUES (${inquiryId}, 'Migration Customer', 'migration@example.test', 'web', 'System', 'Objective', 'staging', 'authorized', ${`M${"0".repeat(42)}`}, ${"b".repeat(64)})`;
      const [beforeRow] = await transaction<{ name: string; objective: string }[]>`SELECT name, objective FROM inquiries WHERE id = ${inquiryId}`;
      await apply(transaction, phase4b);
      const [afterRow] = await transaction<{ name: string; objective: string; revision: number; pre_archive_status: string | null }[]>`SELECT name, objective, revision, pre_archive_status FROM inquiries WHERE id = ${inquiryId}`;
      assert.deepEqual(afterRow, { ...beforeRow, revision: 0, pre_archive_status: null });
    });
  } finally {
    await client!.unsafe(`DROP SCHEMA IF EXISTS "${temporarySchema}" CASCADE`);
  }
});
