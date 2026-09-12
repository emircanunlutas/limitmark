import { isActiveInquiryStatus, isInquiryStatus, type InquiryStatus } from "./inquiry-status-workflow";

export type InquiryAuditDetail =
  | { kind: "status_changed"; previousStatus: InquiryStatus; newStatus: InquiryStatus }
  | { kind: "archived"; previousStatus: Exclude<InquiryStatus, "archived"> }
  | { kind: "restored"; restoredStatus: Exclude<InquiryStatus, "archived"> };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length && actual.every((key, index) => key === [...keys].sort()[index]);
}

export function parseInquiryAuditDetail(eventType: string, metadata: unknown): InquiryAuditDetail | null {
  if (!isRecord(metadata)) return null;
  if (eventType === "status_changed" && hasExactKeys(metadata, ["newStatus", "previousStatus"]) &&
      isInquiryStatus(metadata.previousStatus) && isInquiryStatus(metadata.newStatus)) {
    return { kind: "status_changed", previousStatus: metadata.previousStatus, newStatus: metadata.newStatus };
  }
  if (eventType === "archived" && hasExactKeys(metadata, ["previousStatus"]) && isActiveInquiryStatus(metadata.previousStatus)) {
    return { kind: "archived", previousStatus: metadata.previousStatus };
  }
  if (eventType === "restored" && hasExactKeys(metadata, ["restoredStatus"]) && isActiveInquiryStatus(metadata.restoredStatus)) {
    return { kind: "restored", restoredStatus: metadata.restoredStatus };
  }
  return null;
}
