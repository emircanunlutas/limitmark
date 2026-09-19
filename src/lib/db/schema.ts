import {
  check,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";
import { fieldLimits } from "../request-schema";

export const inquiryStatusValues = [
  "received",
  "in_review",
  "awaiting_scope",
  "proposal_sent",
  "approved",
  "declined",
  "completed",
  "archived",
] as const;

export const inquiryStatus = pgEnum("inquiry_status", inquiryStatusValues);

export const inquiryEventType = pgEnum("inquiry_event_type", [
  "inquiry_received",
  "status_changed",
  "note_added",
  "archived",
  "restored",
  "notification_sent",
  "notification_failed",
]);

export const inquiryActorType = pgEnum("inquiry_actor_type", ["system", "admin"]);
export const notificationStatus = pgEnum("notification_status", ["pending", "processing", "retryable", "sent", "failed"]);

export const inquiries = pgTable("inquiries", {
  id: uuid("id").primaryKey().defaultRandom(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  status: inquiryStatus("status").notNull().default("received"),
  revision: integer("revision").notNull().default(0),
  preArchiveStatus: inquiryStatus("pre_archive_status"),
  name: varchar("name", { length: fieldLimits.name }).notNull(),
  email: varchar("email", { length: fieldLimits.email }).notNull(),
  company: varchar("company", { length: fieldLimits.company }).notNull().default(""),
  service: varchar("service", { length: 16 }).notNull(),
  system: text("system").notNull(),
  objective: text("objective").notNull(),
  environment: varchar("environment", { length: 16 }).notNull(),
  authority: varchar("authority", { length: 16 }).notNull(),
  protection: varchar("protection", { length: 16 }).notNull().default("unknown"),
  provider: varchar("provider", { length: fieldLimits.provider }).notNull().default(""),
  notes: text("notes").notNull().default(""),
  submissionToken: varchar("submission_token", { length: 43 }).notNull().unique("inquiries_submission_token_unique"),
  payloadFingerprint: varchar("payload_fingerprint", { length: 64 }).notNull(),
  archivedAt: timestamp("archived_at", { withTimezone: true }),
}, (table) => [
  index("inquiries_created_at_id_idx").on(table.createdAt, table.id),
  index("inquiries_status_created_at_id_idx").on(table.status, table.createdAt, table.id),
  check("inquiries_name_nonempty", sql`char_length(${table.name}) > 0`),
  check("inquiries_system_length", sql`char_length(${table.system}) between 1 and ${sql.raw(String(fieldLimits.system))}`),
  check("inquiries_objective_length", sql`char_length(${table.objective}) between 1 and ${sql.raw(String(fieldLimits.objective))}`),
  check("inquiries_notes_length", sql`char_length(${table.notes}) <= ${sql.raw(String(fieldLimits.notes))}`),
  check("inquiries_service_valid", sql`${table.service} in ('web', 'network', 'protection', 'unsure')`),
  check("inquiries_environment_valid", sql`${table.environment} in ('production', 'staging', 'multiple', 'unknown')`),
  check("inquiries_authority_valid", sql`${table.authority} in ('owner', 'authorized', 'uncertain')`),
  check("inquiries_protection_valid", sql`${table.protection} in ('unknown', 'none', 'using')`),
  check("inquiries_submission_token_format", sql`${table.submissionToken} ~ '^[A-Za-z0-9_-]{43}$'`),
  check("inquiries_payload_fingerprint_format", sql`${table.payloadFingerprint} ~ '^[0-9a-f]{64}$'`),
  check("inquiries_revision_nonnegative", sql`${table.revision} >= 0`),
  check("inquiries_pre_archive_status_valid", sql`${table.preArchiveStatus} is null or ${table.preArchiveStatus} <> 'archived'`),
]);

export const inquiryEvents = pgTable("inquiry_events", {
  id: uuid("id").primaryKey().defaultRandom(),
  inquiryId: uuid("inquiry_id").notNull().references(() => inquiries.id, { onDelete: "restrict" }),
  eventType: inquiryEventType("event_type").notNull(),
  actorType: inquiryActorType("actor_type").notNull(),
  actorIdentifier: varchar("actor_identifier", { length: 254 }),
  metadata: jsonb("metadata").$type<Record<string, unknown>>(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("inquiry_events_inquiry_created_idx").on(table.inquiryId, table.createdAt),
  check("inquiry_events_actor_identifier", sql`(${table.actorType} = 'system' and ${table.actorIdentifier} is null) or (${table.actorType} = 'admin' and char_length(${table.actorIdentifier}) > 0)`),
  check("inquiry_events_metadata_small_object", sql`${table.metadata} is null or (jsonb_typeof(${table.metadata}) = 'object' and pg_column_size(${table.metadata}) <= 8192)`),
]);

export const adminNotes = pgTable("admin_notes", {
  id: uuid("id").primaryKey().defaultRandom(),
  inquiryId: uuid("inquiry_id").notNull().references(() => inquiries.id, { onDelete: "restrict" }),
  authorIdentifier: varchar("author_identifier", { length: 254 }).notNull(),
  content: text("content").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("admin_notes_inquiry_created_idx").on(table.inquiryId, table.createdAt),
  check("admin_notes_content_length", sql`char_length(${table.content}) between 1 and 10000`),
]);

export const notificationOutbox = pgTable("notification_outbox", {
  id: uuid("id").primaryKey().defaultRandom(),
  inquiryId: uuid("inquiry_id").notNull().references(() => inquiries.id, { onDelete: "restrict" }),
  eventType: inquiryEventType("event_type").notNull(),
  status: notificationStatus("status").notNull().default("pending"),
  attempts: integer("attempts").notNull().default(0),
  availableAt: timestamp("available_at", { withTimezone: true }).notNull().defaultNow(),
  lockedUntil: timestamp("locked_until", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  sentAt: timestamp("sent_at", { withTimezone: true }),
  lastErrorCode: varchar("last_error_code", { length: 100 }),
}, (table) => [
  index("notification_outbox_claim_idx").on(table.availableAt, table.lockedUntil).where(sql`${table.status} in ('pending', 'retryable')`),
  index("notification_outbox_processing_lease_idx").on(table.lockedUntil).where(sql`${table.status} = 'processing'`),
  index("notification_outbox_inquiry_idx").on(table.inquiryId),
  check("notification_outbox_attempts_nonnegative", sql`${table.attempts} >= 0`),
]);

export type InquiryInsert = typeof inquiries.$inferInsert;
