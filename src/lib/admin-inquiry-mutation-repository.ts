import "server-only";

import { and, eq, sql } from "drizzle-orm";
import type { PostgresJsDatabase } from "drizzle-orm/postgres-js";
import { adminNotes, inquiries, inquiryEvents } from "./db/schema";
import * as schema from "./db/schema";
import {
  canTransitionInquiryStatus,
  isActiveInquiryStatus,
  isInquiryStatus,
  type InquiryStatus,
} from "./inquiry-status-workflow";

export type AdminMutationResult = { status: "success"; revision: number } | { status: "conflict" } | { status: "invalid" };

export type AdminMutationIdentity = Readonly<{ actorIdentifier: string }>;
export type RevisionMutationInput = Readonly<{ inquiryId: string; expectedRevision: number; identity: AdminMutationIdentity }>;
export type StatusMutationInput = RevisionMutationInput & Readonly<{ newStatus: InquiryStatus }>;
export type NoteMutationInput = RevisionMutationInput & Readonly<{ content: string }>;

export interface AdminInquiryMutationRepository {
  changeStatus(input: StatusMutationInput): Promise<AdminMutationResult>;
  addNote(input: NoteMutationInput): Promise<AdminMutationResult>;
  archive(input: RevisionMutationInput): Promise<AdminMutationResult>;
  restore(input: RevisionMutationInput): Promise<AdminMutationResult>;
}

function validCommonInput(input: RevisionMutationInput): boolean {
  return Number.isSafeInteger(input.expectedRevision) && input.expectedRevision >= 0 && input.expectedRevision <= 2_147_483_646 &&
    input.identity.actorIdentifier.length >= 1 && input.identity.actorIdentifier.length <= 254;
}

export class PostgresAdminInquiryMutationRepository implements AdminInquiryMutationRepository {
  constructor(private readonly database: PostgresJsDatabase<typeof schema>) {}

  async changeStatus(input: StatusMutationInput): Promise<AdminMutationResult> {
    if (!validCommonInput(input) || !isInquiryStatus(input.newStatus)) return { status: "invalid" };
    return this.database.transaction(async (transaction) => {
      const [current] = await transaction.select({ status: inquiries.status, revision: inquiries.revision })
        .from(inquiries).where(eq(inquiries.id, input.inquiryId)).limit(1);
      if (!current) return { status: "invalid" };
      if (current.revision !== input.expectedRevision) return { status: "conflict" };
      if (!canTransitionInquiryStatus(current.status, input.newStatus)) return { status: "invalid" };

      const [updated] = await transaction.update(inquiries).set({
        status: input.newStatus,
        updatedAt: new Date(),
        revision: sql`${inquiries.revision} + 1`,
      }).where(and(
        eq(inquiries.id, input.inquiryId),
        eq(inquiries.revision, input.expectedRevision),
        eq(inquiries.status, current.status),
      )).returning({ revision: inquiries.revision });
      if (!updated) return { status: "conflict" };
      await transaction.insert(inquiryEvents).values({
        inquiryId: input.inquiryId,
        eventType: "status_changed",
        actorType: "admin",
        actorIdentifier: input.identity.actorIdentifier,
        metadata: { previousStatus: current.status, newStatus: input.newStatus },
      });
      return { status: "success", revision: updated.revision };
    });
  }

  async addNote(input: NoteMutationInput): Promise<AdminMutationResult> {
    if (!validCommonInput(input) || input.content !== input.content.trim() || input.content.length < 1 || input.content.length > 10_000) return { status: "invalid" };
    return this.database.transaction(async (transaction) => {
      const [updated] = await transaction.update(inquiries).set({
        updatedAt: new Date(),
        revision: sql`${inquiries.revision} + 1`,
      }).where(and(eq(inquiries.id, input.inquiryId), eq(inquiries.revision, input.expectedRevision)))
        .returning({ revision: inquiries.revision });
      if (!updated) {
        const [exists] = await transaction.select({ id: inquiries.id }).from(inquiries).where(eq(inquiries.id, input.inquiryId)).limit(1);
        return exists ? { status: "conflict" } : { status: "invalid" };
      }
      await transaction.insert(adminNotes).values({
        inquiryId: input.inquiryId,
        authorIdentifier: input.identity.actorIdentifier,
        content: input.content,
      });
      await transaction.insert(inquiryEvents).values({
        inquiryId: input.inquiryId,
        eventType: "note_added",
        actorType: "admin",
        actorIdentifier: input.identity.actorIdentifier,
      });
      return { status: "success", revision: updated.revision };
    });
  }

  async archive(input: RevisionMutationInput): Promise<AdminMutationResult> {
    if (!validCommonInput(input)) return { status: "invalid" };
    return this.database.transaction(async (transaction) => {
      const [current] = await transaction.select({ status: inquiries.status, revision: inquiries.revision })
        .from(inquiries).where(eq(inquiries.id, input.inquiryId)).limit(1);
      if (!current) return { status: "invalid" };
      if (current.revision !== input.expectedRevision) return { status: "conflict" };
      if (!isActiveInquiryStatus(current.status)) return { status: "invalid" };
      const [updated] = await transaction.update(inquiries).set({
        status: "archived",
        preArchiveStatus: current.status,
        archivedAt: new Date(),
        updatedAt: new Date(),
        revision: sql`${inquiries.revision} + 1`,
      }).where(and(
        eq(inquiries.id, input.inquiryId),
        eq(inquiries.revision, input.expectedRevision),
        eq(inquiries.status, current.status),
      )).returning({ revision: inquiries.revision });
      if (!updated) return { status: "conflict" };
      await transaction.insert(inquiryEvents).values({
        inquiryId: input.inquiryId,
        eventType: "archived",
        actorType: "admin",
        actorIdentifier: input.identity.actorIdentifier,
        metadata: { previousStatus: current.status },
      });
      return { status: "success", revision: updated.revision };
    });
  }

  async restore(input: RevisionMutationInput): Promise<AdminMutationResult> {
    if (!validCommonInput(input)) return { status: "invalid" };
    return this.database.transaction(async (transaction) => {
      const [current] = await transaction.select({
        status: inquiries.status,
        revision: inquiries.revision,
        preArchiveStatus: inquiries.preArchiveStatus,
      }).from(inquiries).where(eq(inquiries.id, input.inquiryId)).limit(1);
      if (!current) return { status: "invalid" };
      if (current.revision !== input.expectedRevision) return { status: "conflict" };
      if (current.status !== "archived" || !isActiveInquiryStatus(current.preArchiveStatus)) return { status: "invalid" };
      const restoredStatus = current.preArchiveStatus;
      const [updated] = await transaction.update(inquiries).set({
        status: restoredStatus,
        preArchiveStatus: null,
        archivedAt: null,
        updatedAt: new Date(),
        revision: sql`${inquiries.revision} + 1`,
      }).where(and(
        eq(inquiries.id, input.inquiryId),
        eq(inquiries.revision, input.expectedRevision),
        eq(inquiries.status, "archived"),
      )).returning({ revision: inquiries.revision });
      if (!updated) return { status: "conflict" };
      await transaction.insert(inquiryEvents).values({
        inquiryId: input.inquiryId,
        eventType: "restored",
        actorType: "admin",
        actorIdentifier: input.identity.actorIdentifier,
        metadata: { restoredStatus },
      });
      return { status: "success", revision: updated.revision };
    });
  }
}
