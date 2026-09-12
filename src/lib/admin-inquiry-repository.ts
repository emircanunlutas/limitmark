import "server-only";

import { and, desc, eq, ilike, or, sql, type SQL } from "drizzle-orm";
import type { PostgresJsDatabase } from "drizzle-orm/postgres-js";
import {
  ADMIN_INQUIRY_MAX_PAGE,
  ADMIN_INQUIRY_PAGE_SIZE,
  ADMIN_INQUIRY_SEARCH_MAX_LENGTH,
  adminInquiryStatuses,
  escapeLikeLiteral,
  type AdminInquiryQuery,
  type AdminInquiryStatusFilter,
} from "./admin-inquiry-query";
import { adminNotes, inquiries, inquiryEvents } from "./db/schema";
import * as schema from "./db/schema";
import { parseInquiryAuditDetail, type InquiryAuditDetail } from "./inquiry-audit";
import { isActiveInquiryStatus, type ActiveInquiryStatus, type InquiryStatus } from "./inquiry-status-workflow";

export type AdminInquiryListItem = { id: string; receivedAt: Date; status: string; name: string; email: string; company: string; service: string; environment: string };
export type AdminInquiryListResult = { items: AdminInquiryListItem[]; hasNextPage: boolean };
export type AdminInquiryEvent = { id: string; createdAt: Date; eventType: string; actorType: string; actorIdentifier: string | null; detail: InquiryAuditDetail | null };
export type AdminInquiryNote = { id: string; createdAt: Date; authorIdentifier: string; content: string };
export type AdminInquiryDetail = {
  inquiry: { id: string; receivedAt: Date; status: InquiryStatus; revision: number; archivedAt: Date | null; preArchiveStatus: ActiveInquiryStatus | null; name: string; email: string; company: string; service: string; system: string; objective: string; environment: string; authority: string; protection: string; provider: string; notes: string };
  events: AdminInquiryEvent[];
  adminNotes: AdminInquiryNote[];
  eventsTruncated: boolean;
  adminNotesTruncated: boolean;
};

export interface AdminInquiryReadRepository {
  listInquiries(query: AdminInquiryQuery): Promise<AdminInquiryListResult>;
  getInquiryDetail(id: string): Promise<AdminInquiryDetail | null>;
}

const DETAIL_HISTORY_LIMIT = 500;

export class PostgresAdminInquiryReadRepository implements AdminInquiryReadRepository {
  constructor(private readonly database: PostgresJsDatabase<typeof schema>) {}

  async listInquiries(query: AdminInquiryQuery): Promise<AdminInquiryListResult> {
    const page = Number.isSafeInteger(query.page)
      ? Math.min(Math.max(query.page, 1), ADMIN_INQUIRY_MAX_PAGE)
      : 1;
    const status = adminInquiryStatuses.includes(query.status as AdminInquiryStatusFilter)
      ? query.status
      : null;
    const search = typeof query.search === "string"
      ? query.search.trim().slice(0, ADMIN_INQUIRY_SEARCH_MAX_LENGTH)
      : "";
    const conditions: SQL[] = [];
    if (status) conditions.push(eq(inquiries.status, status));
    if (search) {
      const literal = escapeLikeLiteral(search);
      conditions.push(or(
        sql`${inquiries.id}::text ilike ${`${literal}%`} escape '\\'`,
        ilike(inquiries.name, `%${literal}%`), ilike(inquiries.email, `%${literal}%`), ilike(inquiries.company, `%${literal}%`),
      )!);
    }
    const rows = await this.database.select({
      id: inquiries.id, receivedAt: inquiries.createdAt, status: inquiries.status, name: inquiries.name,
      email: inquiries.email, company: inquiries.company, service: inquiries.service, environment: inquiries.environment,
    }).from(inquiries).where(conditions.length ? and(...conditions) : undefined)
      .orderBy(desc(inquiries.createdAt), desc(inquiries.id)).limit(ADMIN_INQUIRY_PAGE_SIZE + 1)
      .offset((page - 1) * ADMIN_INQUIRY_PAGE_SIZE);
    return { items: rows.slice(0, ADMIN_INQUIRY_PAGE_SIZE), hasNextPage: rows.length > ADMIN_INQUIRY_PAGE_SIZE };
  }

  async getInquiryDetail(id: string): Promise<AdminInquiryDetail | null> {
    const [inquiry] = await this.database.select({
      id: inquiries.id, receivedAt: inquiries.createdAt, status: inquiries.status, revision: inquiries.revision,
      archivedAt: inquiries.archivedAt, preArchiveStatus: inquiries.preArchiveStatus, name: inquiries.name, email: inquiries.email,
      company: inquiries.company, service: inquiries.service, system: inquiries.system, objective: inquiries.objective,
      environment: inquiries.environment, authority: inquiries.authority, protection: inquiries.protection,
      provider: inquiries.provider, notes: inquiries.notes,
    }).from(inquiries).where(eq(inquiries.id, id)).limit(1);
    if (!inquiry) return null;
    const [events, notes] = await Promise.all([
      this.database.select({ id: inquiryEvents.id, createdAt: inquiryEvents.createdAt, eventType: inquiryEvents.eventType, actorType: inquiryEvents.actorType, actorIdentifier: inquiryEvents.actorIdentifier, metadata: inquiryEvents.metadata })
        .from(inquiryEvents).where(eq(inquiryEvents.inquiryId, id)).orderBy(desc(inquiryEvents.createdAt), desc(inquiryEvents.id)).limit(DETAIL_HISTORY_LIMIT + 1),
      this.database.select({ id: adminNotes.id, createdAt: adminNotes.createdAt, authorIdentifier: adminNotes.authorIdentifier, content: adminNotes.content })
        .from(adminNotes).where(eq(adminNotes.inquiryId, id)).orderBy(desc(adminNotes.createdAt), desc(adminNotes.id)).limit(DETAIL_HISTORY_LIMIT + 1),
    ]);
    return {
      inquiry: { ...inquiry, preArchiveStatus: isActiveInquiryStatus(inquiry.preArchiveStatus) ? inquiry.preArchiveStatus : null },
      events: events.slice(0, DETAIL_HISTORY_LIMIT).reverse().map(({ metadata, ...event }) => ({
        ...event,
        detail: parseInquiryAuditDetail(event.eventType, metadata),
      })),
      adminNotes: notes.slice(0, DETAIL_HISTORY_LIMIT).reverse(),
      eventsTruncated: events.length > DETAIL_HISTORY_LIMIT,
      adminNotesTruncated: notes.length > DETAIL_HISTORY_LIMIT,
    };
  }
}
