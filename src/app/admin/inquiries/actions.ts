"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { requireAdmin } from "@/lib/admin-auth";
import { getAdminInquiryMutationRepository } from "@/lib/admin-inquiry-data";
import {
  hasArchiveConfirmation,
  parseMutationTarget,
  parseNoteMutation,
  parseStatusMutation,
  type ParsedMutationTarget,
} from "@/lib/admin-inquiry-mutation-input";
import { parseAdminInquiryReturnContext } from "@/lib/admin-inquiry-query";
import type { AdminInquiryMutationRepository, AdminMutationResult } from "@/lib/admin-inquiry-mutation-repository";

type MutationNotice = "conflict" | "invalid" | "service-unavailable";

function targetPath(inquiryId: string, outcome: { mutation: MutationNotice } | { receipt: string }, formData: FormData): string {
  const params = new URLSearchParams(outcome);
  const submitted = formData.getAll("from");
  const context = submitted.length === 1 ? parseAdminInquiryReturnContext(submitted[0]) : null;
  if (context) params.set("from", context.token);
  return `/admin/inquiries/${inquiryId}?${params}`;
}

async function runMutation(
  target: ParsedMutationTarget,
  formData: FormData,
  mutate: (repository: AdminInquiryMutationRepository, eventId: string) => Promise<AdminMutationResult>,
): Promise<never> {
  const repository = await getAdminInquiryMutationRepository().catch(() => null);
  if (!repository) redirect(targetPath(target.inquiryId, { mutation: "service-unavailable" }, formData));

  // Allocate before the transaction so a lost COMMIT reply can be checked by a read.
  const eventId = crypto.randomUUID();
  const receiptPath = targetPath(target.inquiryId, { receipt: eventId }, formData);
  let result: AdminMutationResult;
  try {
    result = await mutate(repository, eventId);
    if (result.status === "success") {
      revalidatePath("/admin");
      revalidatePath(`/admin/inquiries/${target.inquiryId}`);
    }
  } catch {
    redirect(receiptPath);
  }
  redirect(result.status === "success" ? receiptPath : targetPath(target.inquiryId, { mutation: result.status }, formData));
}

export async function changeInquiryStatusAction(formData: FormData): Promise<never> {
  const admin = await requireAdmin();
  const target = parseMutationTarget(formData);
  if (!target) redirect("/admin?mutation=invalid");
  const input = parseStatusMutation(formData);
  if (!input) redirect(targetPath(target.inquiryId, { mutation: "invalid" }, formData));
  return runMutation(input, formData, (repository, eventId) => repository.changeStatus({
    ...input,
    eventId,
    identity: { actorIdentifier: admin.email },
  }));
}

export async function addInquiryNoteAction(formData: FormData): Promise<never> {
  const admin = await requireAdmin();
  const target = parseMutationTarget(formData);
  if (!target) redirect("/admin?mutation=invalid");
  const input = parseNoteMutation(formData);
  if (!input) redirect(targetPath(target.inquiryId, { mutation: "invalid" }, formData));
  return runMutation(input, formData, (repository, eventId) => repository.addNote({
    ...input,
    eventId,
    identity: { actorIdentifier: admin.email },
  }));
}

export async function archiveInquiryAction(formData: FormData): Promise<never> {
  const admin = await requireAdmin();
  const input = parseMutationTarget(formData);
  if (!input) redirect("/admin?mutation=invalid");
  if (!hasArchiveConfirmation(formData)) redirect(targetPath(input.inquiryId, { mutation: "invalid" }, formData));
  return runMutation(input, formData, (repository, eventId) => repository.archive({
    ...input,
    eventId,
    identity: { actorIdentifier: admin.email },
  }));
}

export async function restoreInquiryAction(formData: FormData): Promise<never> {
  const admin = await requireAdmin();
  const input = parseMutationTarget(formData);
  if (!input) redirect("/admin?mutation=invalid");
  return runMutation(input, formData, (repository, eventId) => repository.restore({
    ...input,
    eventId,
    identity: { actorIdentifier: admin.email },
  }));
}
