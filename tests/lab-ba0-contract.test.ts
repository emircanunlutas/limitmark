import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { L1_LIMITS } from "../defense/core/types";
import { ALLOWED_FORM_FIELDS, ShapeGate } from "../defense/layers/a7-shape-gate";
import { SYNTHETIC_MAX_BODY_BYTES, SYNTHETIC_REDIRECT_LOCATION, parseStrictForm, validateSubmission } from "../defense/origin/synthetic-origin";
import { INGRESS_MAX_BODY_BYTES, INGRESS_MUTATION_CONTENT_TYPE, INGRESS_MUTATION_PATH } from "../src/lib/ingress-protocol";
import { parseStrictUrlEncodedForm } from "../src/lib/public-inquiry-body";
import { fieldLabels, fieldLimits, readRequestFormData, requestSchema } from "../src/lib/request-schema";
import { serviceOptions } from "../src/lib/services";
import { submissionTokenField, isSubmissionToken } from "../src/lib/submission-token";
import { generateSubmissionToken } from "../src/lib/submission-token.server";
import { turnstileResponseField } from "../src/lib/turnstile";
import { CORPUS, CORPUS_FIXED_COUNT } from "../lab/defense/hostile-corpus";

const root = path.join(__dirname, "..");
const read = (relative: string) => readFileSync(path.join(root, relative), "utf8");

test("the synthetic origin and L1 are pinned to the application's real form contract", () => {
  assert.deepEqual([...ALLOWED_FORM_FIELDS].sort(), [...Object.keys(fieldLabels), submissionTokenField, turnstileResponseField].sort());
  assert.equal(L1_LIMITS.maxBodyBytes, INGRESS_MAX_BODY_BYTES);
  assert.equal(SYNTHETIC_MAX_BODY_BYTES, INGRESS_MAX_BODY_BYTES);
  assert.equal(INGRESS_MUTATION_PATH, "/api/public-inquiries");
  assert.equal(INGRESS_MUTATION_CONTENT_TYPE, "application/x-www-form-urlencoded");
  for (const page of ["app/page.tsx", "app/gizlilik/page.tsx", "app/test-talep-et/page.tsx", "app/test-talep-et/tesekkurler/page.tsx", "app/api/public-inquiries/route.ts"]) assert.ok(existsSync(path.join(root, "src", page)), page);
  assert.ok(read("src/lib/public-inquiry-handler.server.ts").includes(`location: "${SYNTHETIC_REDIRECT_LOCATION}"`), "the redirect location the demo flow returns");
  assert.match(read("src/app/page.tsx"), /id="sss"/);
  assert.match(read("src/app/gizlilik/page.tsx"), /<h1>Gizlilik<\/h1>/);
  assert.match(read("src/app/test-talep-et/tesekkurler/page.tsx"), /Demo akışı tamamlandı\./);
  assert.match(read("src/components/request-form.tsx"), /name=\{submissionTokenField\}/);
});

test("the token the synthetic form page issues has exactly the application's token shape; L1's shape check matches the app's", () => {
  assert.equal(L1_LIMITS.submissionTokenLength, 43);
  assert.equal(isSubmissionToken(generateSubmissionToken()), true);
  assert.equal(isSubmissionToken("A".repeat(43)), true);
  assert.equal(isSubmissionToken("A".repeat(42)), false);
  const gate = new ShapeGate();
  const token = (value: string) => gate.evaluate({ method: "POST", target: "/api/public-inquiries", bodyStatus: "complete", body: new Uint8Array(Buffer.from(`submissionToken=${value}`)), headers: [["host", "h"], ["content-type", INGRESS_MUTATION_CONTENT_TYPE], ["content-length", String(`submissionToken=${value}`.length)]] }).kind;
  for (const value of [generateSubmissionToken(), "A".repeat(43), "a_b-".repeat(10) + "abc", "A".repeat(42), "A".repeat(44), "has space".padEnd(43, "x"), "A".repeat(43).replace("A", "+")]) {
    assert.equal(token(value) === "pass", isSubmissionToken(value), value);
  }
});

test("L1 query allow-list is the application's service ids", () => {
  const gate = new ShapeGate();
  const get = (target: string) => gate.evaluate({ method: "GET", target, headers: [["host", "h"]], bodyStatus: "none", body: null }).kind;
  for (const option of serviceOptions) assert.equal(get(`/test-talep-et?hizmet=${option.value}`), "pass", option.value);
  assert.equal(get("/test-talep-et?hizmet=nope"), "reject");
});

function formBody(overrides: Record<string, string | null>): string {
  const base: Record<string, string> = { name: "Ada", email: "ada@example.test", company: "Co", service: "web", system: "s", objective: "o", environment: "staging", authority: "owner", protection: "unknown", provider: "", notes: "", submissionToken: "A".repeat(43) };
  const merged: Record<string, string> = { ...base };
  for (const [key, value] of Object.entries(overrides)) { if (value === null) delete merged[key]; else merged[key] = value; }
  return new URLSearchParams(merged).toString();
}

test("the synthetic origin accepts and rejects exactly what the real request schema does", () => {
  const cases: Record<string, string | null>[] = [
    {}, { name: null }, { name: "   " }, { name: "x".repeat(100) }, { name: "x".repeat(101) }, { email: "not-an-email" }, { email: null }, { email: "a@b" }, { email: "a@b.co" },
    { service: "bogus" }, { service: null }, { system: null }, { system: "s".repeat(1000) }, { system: "s".repeat(1001) }, { objective: "o".repeat(2001) }, { environment: "bogus" },
    { authority: null }, { authority: "bogus" }, { protection: "bogus" }, { protection: null }, { company: "c".repeat(161) }, { provider: "p".repeat(161) }, { notes: "n".repeat(2001) },
    { notes: "line1\r\nline2" }, { protection: "using", provider: "Vendor" },
  ];
  for (const overrides of cases) {
    const body = formBody(overrides);
    const real = requestSchema.safeParse(readRequestFormData(parseStrictUrlEncodedForm(new TextEncoder().encode(body)))).success;
    const parsed = parseStrictForm(Buffer.from(body));
    assert.equal(parsed.ok, true);
    assert.equal(parsed.ok && validateSubmission(parsed.fields), real, JSON.stringify(overrides).slice(0, 80));
  }
  assert.ok(fieldLimits.name === 100 && fieldLimits.system === 1000 && fieldLimits.objective === 2000, "limits the origin mirrors");
});

test("the synthetic origin's strict parser and L1's grammar agree with the real strict parser: L1 pass implies the real parser accepts", () => {
  const bodies = [
    "", "name=A", "name=A&email=a%40b.co", "name=%zz", "name=%ff%fe", "evil=1", "name=a&name=b", "name", "=x", "name=A&&email=b", "name=%E2%9C%93", "name=a+b",
    "notes=" + "a".repeat(5000), "cf-turnstile-response=abc", "submissionToken=" + "A".repeat(43), "__proto__=x", "name=a%0D%0Ab", "name=%C3%28",
  ];
  const gate = new ShapeGate();
  for (const body of bodies) {
    let realAccepts = true;
    try { parseStrictUrlEncodedForm(new TextEncoder().encode(body)); } catch { realAccepts = false; }
    const originAccepts = parseStrictForm(Buffer.from(body)).ok;
    assert.equal(originAccepts, realAccepts, `origin parser vs real parser: ${body.slice(0, 40)}`);
    const l1 = gate.evaluate({ method: "POST", target: "/api/public-inquiries", bodyStatus: "complete", body: new Uint8Array(Buffer.from(body)), headers: [["host", "h"], ["content-type", INGRESS_MUTATION_CONTENT_TYPE], ["content-length", String(Buffer.byteLength(body))]] });
    if (l1.kind === "pass") assert.equal(realAccepts, true, `L1 passed a body the real parser refuses: ${body.slice(0, 40)}`);
  }
});

test("the hostile corpus is a fixed, deterministic list of unique cases", () => {
  assert.equal(CORPUS.length, CORPUS_FIXED_COUNT);
  assert.equal(new Set(CORPUS.map((entry) => entry.id)).size, CORPUS.length);
  for (const entry of CORPUS) assert.match(entry.id, /^[a-z0-9_]+$/);
  const built = CORPUS.map((entry) => entry.build({ port: 1234 }, "N".repeat(22)).head.toString("latin1"));
  assert.deepEqual(CORPUS.map((entry) => entry.build({ port: 1234 }, "N".repeat(22)).head.toString("latin1")), built, "building a case twice yields identical bytes");
  assert.ok(CORPUS.some((entry) => entry.expect.kind === "pass_stripped"), "the corpus pins what L1 must NOT reject as well as what it must");
});
