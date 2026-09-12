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
import type { AdminMutationResult } from "@/lib/admin-inquiry-mutation-repository";

type MutationNotice = "success" | "conflict" | "invalid" | "unavailable";

function targetPath(inquiryId: string, notice: MutationNotice): string {
  return `/admin/inquiries/${inquiryId}?mutation=${notice}`;
}

async function runMutation(
  target: ParsedMutationTarget,
  mutate: () => Promise<AdminMutationResult>,
): Promise<never> {
  let result: AdminMutationResult;
  try {
    result = await mutate();
  } catch {
    redirect(targetPath(target.inquiryId, "unavailable"));
  }
  if (result.status === "success") {
    revalidatePath("/admin");
    revalidatePath(`/admin/inquiries/${target.inquiryId}`);
  }
  redirect(targetPath(target.inquiryId, result.status));
}

export async function changeInquiryStatusAction(formData: FormData): Promise<never> {
  const admin = await requireAdmin();
  const target = parseMutationTarget(formData);
  if (!target) redirect("/admin?mutation=invalid");
  const input = parseStatusMutation(formData);
  if (!input) redirect(targetPath(target.inquiryId, "invalid"));
  const repository = await getAdminInquiryMutationRepository();
  if (!repository) redirect(targetPath(input.inquiryId, "unavailable"));
  return runMutation(input, () => repository.changeStatus({
    ...input,
    identity: { actorIdentifier: admin.email },
  }));
}

export async function addInquiryNoteAction(formData: FormData): Promise<never> {
  const admin = await requireAdmin();
  const target = parseMutationTarget(formData);
  if (!target) redirect("/admin?mutation=invalid");
  const input = parseNoteMutation(formData);
  if (!input) redirect(targetPath(target.inquiryId, "invalid"));
  const repository = await getAdminInquiryMutationRepository();
  if (!repository) redirect(targetPath(input.inquiryId, "unavailable"));
  return runMutation(input, () => repository.addNote({
    ...input,
    identity: { actorIdentifier: admin.email },
  }));
}

export async function archiveInquiryAction(formData: FormData): Promise<never> {
  const admin = await requireAdmin();
  const input = parseMutationTarget(formData);
  if (!input) redirect("/admin?mutation=invalid");
  if (!hasArchiveConfirmation(formData)) redirect(targetPath(input.inquiryId, "invalid"));
  const repository = await getAdminInquiryMutationRepository();
  if (!repository) redirect(targetPath(input.inquiryId, "unavailable"));
  return runMutation(input, () => repository.archive({
    ...input,
    identity: { actorIdentifier: admin.email },
  }));
}

export async function restoreInquiryAction(formData: FormData): Promise<never> {
  const admin = await requireAdmin();
  const input = parseMutationTarget(formData);
  if (!input) redirect("/admin?mutation=invalid");
  const repository = await getAdminInquiryMutationRepository();
  if (!repository) redirect(targetPath(input.inquiryId, "unavailable"));
  return runMutation(input, () => repository.restore({
    ...input,
    identity: { actorIdentifier: admin.email },
  }));
}
