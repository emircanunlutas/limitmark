"use server";

import { redirect } from "next/navigation";
import { getSubmissionRuntimeMode } from "@/lib/submission-policy";
import { getFieldErrors, getRequestValues, readRequestFormData, requestSchema, type RequestState } from "@/lib/request-schema";
import { readSubmissionToken } from "@/lib/submission-token";

/** Validation-only compatibility boundary for browsers without JavaScript.
 * It can complete the explicitly non-persistent demo journey, but contains no
 * admission, Turnstile, repository, database, or persistent adapter call. */
export async function submitTestRequest(_previous?: RequestState, formData?: FormData): Promise<RequestState> {
  if (!formData) return { errors: {}, message: "Talep gönderimi şu anda kullanılamıyor. Bilgileriniz iletilmedi." };
  const raw = readRequestFormData(formData);
  const values = getRequestValues(raw);
  const submissionToken = readSubmissionToken(formData);
  const parsed = requestSchema.safeParse(raw);
  if (!parsed.success) return { errors: getFieldErrors(parsed.error), values, submissionToken: submissionToken ?? undefined };
  if (!submissionToken) return { errors: {}, values, message: "Talep gönderimi şu anda kullanılamıyor. Bilgileriniz iletilmedi." };
  if (getSubmissionRuntimeMode(process.env) !== "demo") return { errors: {}, values, submissionToken, message: "Talep gönderimi şu anda kullanılamıyor. Bilgileriniz iletilmedi." };
  redirect("/test-talep-et/tesekkurler");
}
