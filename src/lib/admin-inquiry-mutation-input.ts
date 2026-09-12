import { isInquiryStatus, type InquiryStatus } from "./inquiry-status-workflow";

const inquiryUuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const maxIncrementableRevision = 2_147_483_646;

function stringField(formData: FormData, name: string): string | null {
  const value = formData.get(name);
  return typeof value === "string" ? value : null;
}

export type ParsedMutationTarget = { inquiryId: string; expectedRevision: number };

export function parseMutationTarget(formData: FormData): ParsedMutationTarget | null {
  const inquiryId = stringField(formData, "inquiryId")?.trim() ?? "";
  const revisionValue = stringField(formData, "expectedRevision")?.trim() ?? "";
  if (!inquiryUuidPattern.test(inquiryId) || !/^(0|[1-9]\d*)$/.test(revisionValue)) return null;
  const expectedRevision = Number(revisionValue);
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision > maxIncrementableRevision) return null;
  return { inquiryId, expectedRevision };
}

export function parseStatusMutation(formData: FormData): (ParsedMutationTarget & { newStatus: InquiryStatus }) | null {
  const target = parseMutationTarget(formData);
  const newStatus = stringField(formData, "newStatus");
  return target && isInquiryStatus(newStatus) ? { ...target, newStatus } : null;
}

export function parseNoteMutation(formData: FormData): (ParsedMutationTarget & { content: string }) | null {
  const target = parseMutationTarget(formData);
  const content = stringField(formData, "content")?.trim() ?? "";
  return target && content.length >= 1 && content.length <= 10_000 ? { ...target, content } : null;
}

export function hasArchiveConfirmation(formData: FormData): boolean {
  return stringField(formData, "confirmArchive") === "archive";
}
