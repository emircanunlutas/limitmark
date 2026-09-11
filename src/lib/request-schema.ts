import { z } from "zod";

export const fieldLimits = { name: 100, email: 254, company: 160, system: 1000, objective: 2000, provider: 160, notes: 2000 } as const;
export const fieldLabels = {
  name: "Adınız", email: "E-posta adresiniz", company: "Şirket / kuruluş adı", service: "İlgilendiğiniz hizmet",
  system: "Test etmek istediğiniz sistem", objective: "Testten ne öğrenmek istiyorsunuz?", environment: "Test edilecek ortam",
  authority: "Bu sistem için test yetkiniz", protection: "Mevcut koruma hakkında bilginiz var mı?", provider: "Koruma hizmeti / sağlayıcı", notes: "Tercih ettiğiniz dönem ve diğer notlar",
} as const;

const text = (max: number, required = false) => {
  const schema = z.string({ error: "Lütfen geçerli bir metin girin." }).max(max, `En fazla ${max} karakter yazabilirsiniz.`).trim();
  return required ? schema.min(1, "Lütfen bu alanı doldurun.") : schema;
};

const multiline = (max: number, required = false) => z.string({ error: "Lütfen geçerli bir metin girin." })
  // Multipart form encoding uses CRLF; textarea maxlength counts each newline once.
  .transform((value) => value.replace(/\r\n?/g, "\n"))
  .pipe(text(max, required));

export const requestSchema = z.object({
  name: text(fieldLimits.name, true),
  email: text(fieldLimits.email, true).pipe(z.email({ error: "Geçerli bir e-posta adresi girin." })),
  company: text(fieldLimits.company).default(""),
  service: z.enum(["web", "network", "protection", "unsure"], { error: "Lütfen bir hizmet seçin." }),
  system: multiline(fieldLimits.system, true),
  objective: multiline(fieldLimits.objective, true),
  environment: z.enum(["production", "staging", "multiple", "unknown"], { error: "Lütfen test edilecek ortamı seçin." }),
  authority: z.enum(["owner", "authorized", "uncertain"], { error: "Lütfen yetki durumunuzu belirtin." }),
  protection: z.enum(["unknown", "none", "using"], { error: "Lütfen geçerli bir koruma seçeneği seçin." }).default("unknown"),
  provider: text(fieldLimits.provider).default(""),
  notes: multiline(fieldLimits.notes).default(""),
}).transform((data) => ({ ...data, provider: data.protection === "using" ? data.provider : "" }));

export type TestRequest = z.output<typeof requestSchema>;
export type RequestField = keyof typeof fieldLabels;
export type FieldErrors = Partial<Record<RequestField, string>>;
export type RequestState = { errors: FieldErrors; message?: string; values?: Partial<Record<RequestField, string>> };

// Re-render bounded, known text values after a non-JavaScript POST fails.
// Never reflect files, duplicate entries, or unrelated fields back into the form.
export function getRequestValues(data: Record<string, unknown>): NonNullable<RequestState["values"]> {
  const values: NonNullable<RequestState["values"]> = {};
  for (const field of Object.keys(fieldLabels) as RequestField[]) {
    const value = data[field];
    if (typeof value !== "string") continue;
    const limit = field in fieldLimits ? fieldLimits[field as keyof typeof fieldLimits] : 32;
    // Keep one excess character so restored over-limit input remains visibly invalid.
    values[field] = value.replace(/\r\n?/g, "\n").slice(0, limit + 1);
  }
  return values;
}

// Whitelist known fields. Never forward arbitrary FormData entries to an adapter.
// Repeated values remain arrays so the schema rejects ambiguous submissions.
export function readRequestFormData(data: FormData): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const field of Object.keys(fieldLabels)) {
    const values = data.getAll(field);
    if (values.length) result[field] = values.length === 1 ? values[0] : values;
  }
  return result;
}

export function getFieldErrors(error: z.ZodError): FieldErrors {
  const errors: FieldErrors = {};
  for (const issue of error.issues) {
    const field = issue.path[0];
    if (typeof field === "string" && Object.hasOwn(fieldLabels, field)) {
      const key = field as RequestField;
      errors[key] ??= issue.message;
    }
  }
  return errors;
}
