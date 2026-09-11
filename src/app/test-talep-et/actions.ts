"use server";

import { redirect } from "next/navigation";
import { headers } from "next/headers";
import { requestSchema, readRequestFormData, getFieldErrors, getRequestValues, type RequestState } from "@/lib/request-schema";
import { submitToAdapter } from "@/lib/submission-adapter";
import { readSubmissionToken } from "@/lib/submission-token";
import { readTurnstileToken } from "@/lib/turnstile";

export async function submitTestRequest(_previous: RequestState, formData: FormData): Promise<RequestState> {
  // This is a public inquiry, not authentication or execution authorization.
  // The server independently validates every field even when JS validation passes.
  const raw = readRequestFormData(formData);
  const values = getRequestValues(raw);
  const submissionToken = readSubmissionToken(formData);
  const result = requestSchema.safeParse(raw);
  if (!result.success) return { errors: getFieldErrors(result.error), values, submissionToken: submissionToken ?? undefined };
  if (!submissionToken) {
    return { errors: {}, values, message: "Talep gönderimi şu anda kullanılamıyor. Bilgileriniz iletilmedi. Lütfen sayfayı yenileyip tekrar deneyin." };
  }

  try {
    const submission = await submitToAdapter(result.data, submissionToken, {
      headers: await headers(),
      turnstileToken: readTurnstileToken(formData),
    });
    if (submission.status === "unavailable") {
      return { errors: {}, values, submissionToken, message: "Talep gönderimi şu anda kullanılamıyor. Bilgileriniz iletilmedi. Lütfen daha sonra tekrar deneyin." };
    }
    if (submission.status === "idempotency-conflict") {
      return { errors: {}, values, submissionToken, message: "Talebiniz iletilemedi. Lütfen sayfayı yenileyip bilgilerinizi yeniden gönderin." };
    }
  } catch {
    // Do not expose provider errors or log submitted personal information.
    return { errors: {}, values, submissionToken, message: "Talebiniz iletilemedi. Bilgileriniz bu sayfada duruyor; lütfen tekrar deneyin." };
  }

  // Keep the redirect outside the catch: Next.js uses a control-flow exception.
  redirect("/test-talep-et/tesekkurler");
}
