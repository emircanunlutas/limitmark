import { fieldLimits } from "./request-schema";
import { inquiryStatusValues } from "./db/schema";

export const ADMIN_INQUIRY_PAGE_SIZE = 25;
export const ADMIN_INQUIRY_MAX_PAGE = 10_000;
export const ADMIN_INQUIRY_SEARCH_MAX_LENGTH = Math.max(fieldLimits.email, fieldLimits.company);

export const adminInquiryStatuses = inquiryStatusValues;

export type AdminInquiryStatusFilter = (typeof adminInquiryStatuses)[number];
export type AdminInquiryQuery = { page: number; status: AdminInquiryStatusFilter | null; search: string };
type SearchValue = string | string[] | undefined;

function first(value: SearchValue): string { return typeof value === "string" ? value : ""; }

export function normalizeAdminInquiryQuery(values: { page?: SearchValue; status?: SearchValue; q?: SearchValue }): AdminInquiryQuery {
  const rawPage = first(values.page);
  const parsedPage = /^\d+$/.test(rawPage) ? Number(rawPage) : 1;
  const page = Number.isSafeInteger(parsedPage) ? Math.min(Math.max(parsedPage, 1), ADMIN_INQUIRY_MAX_PAGE) : 1;
  const rawStatus = first(values.status);
  const status = adminInquiryStatuses.find((candidate) => candidate === rawStatus) ?? null;
  const search = first(values.q).trim().slice(0, ADMIN_INQUIRY_SEARCH_MAX_LENGTH);
  return { page, status, search };
}

/** Escape PostgreSQL LIKE metacharacters so an admin's search is always literal. */
export function escapeLikeLiteral(value: string): string { return value.replace(/[\\%_]/g, "\\$&"); }

export function buildAdminInquiryHref(query: Pick<AdminInquiryQuery, "status" | "search"> & { page?: number }): string {
  const parameters = new URLSearchParams();
  if (query.search) parameters.set("q", query.search);
  if (query.status) parameters.set("status", query.status);
  if (query.page && query.page > 1) parameters.set("page", String(query.page));
  const encoded = parameters.toString();
  return encoded ? `/admin?${encoded}` : "/admin";
}
