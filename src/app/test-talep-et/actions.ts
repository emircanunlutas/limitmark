"use server";

import { redirect } from "next/navigation";
import { requestSchema, readRequestFormData, getFieldErrors, getRequestValues, type RequestState } from "@/lib/request-schema";
import { submitToAdapter } from "@/lib/submission-adapter";

export async function submitTestRequest(_previous: RequestState, formData: FormData): Promise<RequestState> {
  // This is a public inquiry, not authentication or execution authorization.
  // The server independently validates every field even when JS validation passes.
  const raw = readRequestFormData(formData);
  const values = getRequestValues(raw);
  const result = requestSchema.safeParse(raw);
  if (!result.success) return { errors: getFieldErrors(result.error), values };

  try {
    const submission = await submitToAdapter(result.data);
    if (submission.status === "unavailable") {
      return { errors: {}, values, message: "Talep gönderimi şu anda kullanılamıyor. Bilgileriniz iletilmedi. Lütfen daha sonra tekrar deneyin." };
    }
  } catch {
    // Do not expose provider errors or log submitted personal information.
    return { errors: {}, values, message: "Talebiniz iletilemedi. Bilgileriniz bu sayfada duruyor; lütfen tekrar deneyin." };
  }

  // Keep the redirect outside the catch: Next.js uses a control-flow exception.
  redirect("/test-talep-et/tesekkurler");
}
