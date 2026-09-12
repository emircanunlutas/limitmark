import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { readBoundedPublicInquiryBody, parseStrictUrlEncodedForm } from "../src/lib/public-inquiry-body";
import { handlePublicInquiry } from "../src/lib/public-inquiry-handler.server";
import { createIngressEnvelope, encodeBase64url, INGRESS_BODY_ENCODING, INGRESS_ENVIRONMENT, INGRESS_HEADER, INGRESS_IDENTITY_VERSION,
  INGRESS_MUTATION_CONTENT_TYPE, INGRESS_MUTATION_PATH, INGRESS_VERSION, sha256Base64url, type IngressPayload } from "../src/lib/ingress-protocol";
import { importRequestBindingKey } from "../src/lib/ingress-verifier.server";

const token = "s".repeat(43);
function validBody(extra: Record<string, string> = {}) {
  return new URLSearchParams({ name: "Synthetic", email: "qa@example.test", service: "web", system: "Disposable",
    objective: "Review boundary", environment: "staging", authority: "authorized", protection: "unknown", provider: "", notes: "",
    submissionToken: token, ...extra }).toString();
}
function demoRequest(body = validBody(), changes: { origin?: string | null; contentType?: string; encoding?: string } = {}) {
  const headers = new Headers({ "content-type": changes.contentType ?? INGRESS_MUTATION_CONTENT_TYPE });
  if (changes.origin !== null) headers.set("origin", changes.origin ?? "http://localhost:3000");
  if (changes.encoding) headers.set("content-encoding", changes.encoding);
  return new Request("http://localhost:3000/api/public-inquiries", { method: "POST", body, headers });
}
const demoEnvironment = { NODE_ENV: "development", REQUEST_SUBMISSION_MODE: "demo" };

test("raw reader accepts exactly 32 KiB and rejects byte 32769, false length and truncation", async () => {
  assert.equal((await readBoundedPublicInquiryBody(new Request("https://limitmark.com/", { method: "POST", body: new Uint8Array(32_768) }))).length, 32_768);
  await assert.rejects(() => readBoundedPublicInquiryBody(new Request("https://limitmark.com/", { method: "POST", body: new Uint8Array(32_769) })), /overflow/);
  for (const claimed of ["2", "999", "01", "-1"]) {
    await assert.rejects(() => readBoundedPublicInquiryBody(new Request("https://limitmark.com/", { method: "POST", body: "x", headers: { "content-length": claimed } })), /length/);
  }
});

test("strict form parsing rejects duplicate/unknown fields and invalid raw or percent UTF-8", () => {
  for (const value of ["name=a&name=b", "unknown=x", "name=%", "name=%C3%28"]) assert.throws(() => parseStrictUrlEncodedForm(new TextEncoder().encode(value)));
  assert.throws(() => parseStrictUrlEncodedForm(Uint8Array.of(0xc3, 0x28)), /utf8/);
  assert.equal(parseStrictUrlEncodedForm(new TextEncoder().encode("name=A%2BB")).get("name"), "A+B");
});

test("demo Route Handler preserves local non-persistent UX but requires exact same origin", async () => {
  const success = await handlePublicInquiry(demoRequest(), { environment: demoEnvironment });
  assert.equal(success.status, 200);
  assert.deepEqual(await success.json(), { kind: "redirect", location: "/test-talep-et/tesekkurler" });
  const proxiedHeaders = new Headers({ "content-type": INGRESS_MUTATION_CONTENT_TYPE, origin: "http://127.0.0.1:3100",
    "x-forwarded-host": "127.0.0.1:3100", "x-forwarded-proto": "http" });
  assert.equal((await handlePublicInquiry(new Request("http://localhost:3000/api/public-inquiries", {
    method: "POST", body: validBody(), headers: proxiedHeaders,
  }), { environment: { ...demoEnvironment, PUBLIC_DEMO_ORIGIN: "http://127.0.0.1:3100" } })).status, 200);
  for (const origin of [null, "https://attacker.test", "http://localhost:3001"]) {
    assert.equal((await handlePublicInquiry(demoRequest(validBody(), { origin }), { environment: demoEnvironment })).status, 403);
  }
});

test("compressed, wrong content type, duplicate and unknown public bodies are rejected before adapter work", async () => {
  assert.equal((await handlePublicInquiry(demoRequest(validBody(), { encoding: "gzip" }), { environment: demoEnvironment })).status, 404);
  assert.equal((await handlePublicInquiry(demoRequest(validBody(), { contentType: "application/json" }), { environment: demoEnvironment })).status, 404);
  assert.equal((await handlePublicInquiry(demoRequest(`${validBody()}&name=again`), { environment: demoEnvironment })).status, 400);
  assert.equal((await handlePublicInquiry(demoRequest(`${validBody()}&unknown=x`), { environment: demoEnvironment })).status, 400);
});

test("former public Server Action has no persistence-capable dependencies", async () => {
  const source = await readFile(new URL("../src/app/test-talep-et/actions.ts", import.meta.url), "utf8");
  for (const forbidden of ["admission-client", "turnstile", "inquiry-repository", "submission-adapter"]) {
    assert.doesNotMatch(source, new RegExp(forbidden));
  }
  assert.match(source, /getSubmissionRuntimeMode\(process\.env\)/);
  assert.match(source, /!== "demo"/);
});

test("Production raw route verifies origin and signed bytes before PRE, then preserves PRE/Turnstile/POST/DB order", async () => {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const bodyText = validBody({ "cf-turnstile-response": "synthetic-challenge" });
  const body = new TextEncoder().encode(bodyText);
  const payload: IngressPayload = [INGRESS_VERSION, "current", INGRESS_ENVIRONMENT, "prj_limitmark", "dpl_reviewed", 100_000,
    "POST", "https", "limitmark.com", INGRESS_MUTATION_PATH, "", INGRESS_MUTATION_CONTENT_TYPE, INGRESS_BODY_ENCODING, body.length,
    await sha256Base64url(body), INGRESS_IDENTITY_VERSION, encodeBase64url(new Uint8Array(32).fill(1)), encodeBase64url(new Uint8Array(16).fill(2))];
  const envelope = await createIngressEnvelope(payload, pair.privateKey);
  const originSecret = "O".repeat(43);
  const headers = { origin: "https://limitmark.com", host: "limitmark.com", "x-forwarded-host": "limitmark.com",
    "x-limitmark-origin-secret": originSecret, "content-type": INGRESS_MUTATION_CONTENT_TYPE, "content-encoding": INGRESS_BODY_ENCODING, [INGRESS_HEADER]: envelope };
  const calls: string[] = [];
  const dependencies = {
    environment: { NODE_ENV: "production", REQUEST_SUBMISSION_MODE: "postgres", VERCEL: "1", VERCEL_ENV: "production", PUBLIC_ORIGIN_PROTECTION: "required", PUBLIC_ORIGIN_SECRET: originSecret },
    ingressPolicy: { audience: "prj_limitmark", deploymentId: "dpl_reviewed", publicKeys: new Map([["current", pair.publicKey]]),
      requestBindingKey: await importRequestBindingKey(encodeBase64url(new Uint8Array(32).fill(9))), now: () => 100_000 },
    admission: { async claimPre() { calls.push("pre"); return { decision: "allowed" as const, permit: encodeBase64url(new Uint8Array(32).fill(5)), expiresAtMs: 160_000 }; },
      async consumePost() { calls.push("post"); return { decision: "allowed" as const }; } },
    turnstile: { async verify() { calls.push("turnstile"); return "verified" as const; } },
    repository: { async create() { calls.push("db"); return { status: "created" as const }; } },
  };
  const response = await handlePublicInquiry(new Request("https://limitmark.com/api/public-inquiries", { method: "POST", body: bodyText, headers }), dependencies);
  assert.deepEqual(await response.json(), { kind: "redirect", location: "/test-talep-et/tesekkurler" });
  assert.deepEqual(calls, ["pre", "turnstile", "post", "db"]);

  calls.length = 0;
  const wrongOrigin = await handlePublicInquiry(new Request("https://limitmark.com/api/public-inquiries", { method: "POST", body: bodyText, headers: { ...headers, origin: "https://attacker.test" } }), dependencies);
  assert.equal(wrongOrigin.status, 503);
  assert.deepEqual(calls, []);
  const changed = await handlePublicInquiry(new Request("https://limitmark.com/api/public-inquiries", { method: "POST", body: `${bodyText}x`, headers }), dependencies);
  assert.equal(changed.status, 400);
  assert.deepEqual(calls, []);
  const oversized = new Uint8Array(65_809);
  oversized.set(body);
  oversized.fill(120, body.length);
  const overflow = await handlePublicInquiry(new Request("https://limitmark.com/api/public-inquiries", { method: "POST", body: oversized, headers }), dependencies);
  assert.equal(overflow.status, 413);
  assert.deepEqual(calls, []);
});
