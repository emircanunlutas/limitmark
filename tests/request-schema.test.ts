import assert from "node:assert/strict";
import test from "node:test";
import { fieldLimits, getFieldErrors, getRequestValues, readRequestFormData, requestSchema } from "../src/lib/request-schema";
import { resolveService } from "../src/lib/services";
import { getSubmissionRuntimeMode, isDemoSubmissionAllowed } from "../src/lib/submission-policy";
import { getContactEmail } from "../src/lib/contact-email";

const valid = {
  name: "Örnek Talep", email: "qa@example.test", service: "unsure", system: "Kuruluşumuza ait hazırlık uygulaması",
  objective: "Yük altında erişilebilirliğini öğrenmek istiyoruz.", environment: "unknown", authority: "uncertain",
};

test("uncertain authority is accepted, optional fields may be omitted", () => {
  const data = requestSchema.parse(valid);
  assert.equal(data.authority, "uncertain");
  assert.equal(data.protection, "unknown");
  assert.equal(data.company, "");
});

test("every authority option is valid but there is no implicit authority", () => {
  for (const authority of ["owner", "authorized", "uncertain"]) assert.ok(requestSchema.safeParse({ ...valid, authority }).success);
  for (const authority of [undefined, "", "admin", true]) assert.equal(requestSchema.safeParse({ ...valid, authority }).success, false);
});

test("required whitespace and malformed email are rejected with field errors", () => {
  const result = requestSchema.safeParse({ ...valid, name: "  ", system: "\n", objective: " ", email: "invalid" });
  assert.equal(result.success, false);
  if (!result.success) assert.deepEqual(Object.keys(getFieldErrors(result.error)), ["name", "email", "system", "objective"]);
});

test("length limits are enforced server-side, including optional fields", () => {
  for (const [field, limit] of Object.entries(fieldLimits)) {
    const value = field === "email" ? `${"a".repeat(limit - 13)}@example.test` : "a".repeat(limit);
    assert.ok(requestSchema.safeParse({ ...valid, [field]: value }).success, `${field}: exact limit`);
    assert.equal(requestSchema.safeParse({ ...valid, [field]: "a".repeat(limit + 1) }).success, false, `${field}: above limit`);
  }
});

test("unknown enum values, files and duplicate fields cannot reach the adapter", () => {
  for (const field of ["service", "environment", "authority", "protection"]) assert.equal(requestSchema.safeParse({ ...valid, [field]: "injected" }).success, false);
  const form = new FormData();
  for (const [key, value] of Object.entries(valid)) form.set(key, value);
  form.append("name", "Duplicate");
  assert.equal(requestSchema.safeParse(readRequestFormData(form)).success, false);
  form.set("name", new File(["value"], "unexpected.txt"));
  assert.equal(requestSchema.safeParse(readRequestFormData(form)).success, false);
});

test("unknown data is stripped, no authorization or execution field can be smuggled", () => {
  const result = requestSchema.parse({ ...valid, execute: true, apiKey: "synthetic-test-value" });
  assert.equal("execute" in result, false);
  assert.equal("apiKey" in result, false);
  const form = new FormData();
  form.set("execute", "true");
  assert.deepEqual(readRequestFormData(form), {});
});

test("provider is kept only when protection is in use", () => {
  assert.equal(requestSchema.parse({ ...valid, protection: "using", provider: "  Example provider  " }).provider, "Example provider");
  assert.equal(requestSchema.parse({ ...valid, protection: "none", provider: "Stale value" }).provider, "");
});

test("populated optional disclosure fields survive FormData extraction and validation", () => {
  const form = new FormData();
  for (const [field, value] of Object.entries({ ...valid, protection: "using", provider: "Örnek sağlayıcı", notes: "Tercih ettiğimiz dönem henüz kesin değil." })) form.set(field, value);
  const parsed = requestSchema.parse(readRequestFormData(form));
  assert.equal(parsed.protection, "using");
  assert.equal(parsed.provider, "Örnek sağlayıcı");
  assert.equal(parsed.notes, "Tercih ettiğimiz dönem henüz kesin değil.");
});

test("service query state accepts known IDs and safely defaults otherwise", () => {
  for (const service of ["web", "network", "protection", "unsure"]) assert.equal(resolveService(service), service);
  for (const value of [undefined, "<script>", ["web", "network"]]) assert.equal(resolveService(value), "unsure");
});

test("production never silently accepts a demo submission", () => {
  assert.equal(isDemoSubmissionAllowed({ NODE_ENV: "development", REQUEST_SUBMISSION_MODE: "demo" }), true);
  assert.equal(isDemoSubmissionAllowed({ NODE_ENV: "production" }), false);
  assert.equal(isDemoSubmissionAllowed({ NODE_ENV: "production", REQUEST_SUBMISSION_MODE: "demo", ALLOW_DEMO_SUBMISSIONS: "true" }), true);
  assert.equal(isDemoSubmissionAllowed({ NODE_ENV: "production", ALLOW_DEMO_SUBMISSIONS: "false" }), false);
  assert.equal(isDemoSubmissionAllowed({ NODE_ENV: "development", REQUEST_SUBMISSION_MODE: "unconfigured" }), false);
  const production = { VERCEL: "1", VERCEL_ENV: "production", NODE_ENV: "production", ALLOW_DEMO_SUBMISSIONS: "true" };
  assert.equal(getSubmissionRuntimeMode(production), "unavailable");
  assert.equal(getSubmissionRuntimeMode({ ...production, REQUEST_SUBMISSION_MODE: "demo" }), "unavailable");
  assert.equal(isDemoSubmissionAllowed({ ...production, REQUEST_SUBMISSION_MODE: "demo" }), false);
  assert.equal(getSubmissionRuntimeMode({ VERCEL: "1", VERCEL_ENV: "preview", NODE_ENV: "production", REQUEST_SUBMISSION_MODE: "demo", ALLOW_DEMO_SUBMISSIONS: "true" }), "demo");
  assert.equal(getSubmissionRuntimeMode({ NODE_ENV: "development", REQUEST_SUBMISSION_MODE: "demo" }), "demo");
});

test("multipart CRLF and browser LF use the same multiline limits", () => {
  for (const field of ["system", "objective", "notes"] as const) {
    const value = "ğ".repeat(fieldLimits[field] - 2) + "\r\nb";
    const parsed = requestSchema.parse({ ...valid, [field]: value });
    assert.equal(parsed[field].length, fieldLimits[field]);
    assert.equal(parsed[field].includes("\r"), false);
    assert.equal(requestSchema.safeParse({ ...valid, [field]: value + "x" }).success, false);
  }
});

test("failed native submissions restore only bounded known scalar values", () => {
  const values = getRequestValues({ name: "a".repeat(500), system: "a\r\nb", email: ["a", "b"], company: new File(["x"], "x"), unrelated: "discard" });
  assert.deepEqual(values, { name: "a".repeat(101), system: "a\nb" });
});

test("ordinary Unicode and punctuation are preserved while outside whitespace is trimmed", () => {
  const value = `Çağrı O'Neil "Deneme" & <ölçüm> 日本語 🧪`;
  const parsed = requestSchema.parse({ ...valid, name: `  ${value}  `, system: `\n${value}\nikinci satır\n`, email: " qa@example.test " });
  assert.equal(parsed.name, value);
  assert.equal(parsed.system, `${value}\nikinci satır`);
  assert.equal(parsed.email, "qa@example.test");
  for (const email of ["a", "a@", "@example.test", "a b@example.test", "a@@example.test", "a@example", "a@example..test"]) {
    assert.equal(requestSchema.safeParse({ ...valid, email }).success, false, email);
  }
});

test("contact configuration accepts a mailbox but never a mailto URL or display address", () => {
  assert.equal(getContactEmail(" qa+inquiries@example.test "), "qa+inquiries@example.test");
  for (const value of [undefined, "", " ", "mailto:qa@example.test", "<qa@example.test>", "QA <qa@example.test>", "qa@example.test?subject=Hello", "qa@example.test#fragment", "qa@example..test"]) {
    assert.equal(getContactEmail(value), null, String(value));
  }
});
