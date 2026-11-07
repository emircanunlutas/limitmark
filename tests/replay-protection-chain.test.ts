import assert from "node:assert/strict";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { importRequestBindingKey, verifyMutationIngress } from "../src/lib/ingress-verifier.server";
import { executeVerifiedPublicInquiry } from "../src/lib/public-inquiry-flow.server";
import type { AdmissionClient } from "../src/lib/admission-client.server";
import { parseStrictUrlEncodedForm } from "../src/lib/public-inquiry-body";
import { createIngressSigner } from "../workers/ingress-signer/signer";
import {
  ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, PublicInquiryAdmissionAuthority, initializeAuthority,
} from "../workers/admission-service/authority";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";

// Chain under test: REAL laboratory signer -> REAL verifier -> REAL flow -> REAL admission authority (SQLite-backed Durable Object logic).
// Cryptographic request binding (signature over method/host/path/body digest/nonce) is stateless and proves WHAT was signed.
// One-time use is a separate property that only the authority's nonce table provides; these tests keep the two apart.

const releaseId = "lab-deployment";
const publicHost = "inquiry-lab.example";
const originHost = "origin-lab.run.app";
const hmacKey = encodeBase64url(Uint8Array.from({ length: 32 }, (_, index) => index));
const submissionToken = "s".repeat(43);
const T0 = 1_800_000_000_000;

function formBody(email = "qa@example.test") {
  return new URLSearchParams({ name: "Synthetic", email, service: "web", system: "Disposable", objective: "Review flow",
    environment: "staging", authority: "authorized", submissionToken, "cf-turnstile-response": "challenge" }).toString();
}

async function chain() {
  const clock = { value: T0 };
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const pkcs8 = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  const forwarded: Request[] = [];
  const signer = createIngressSigner({
    environment: "cloud-run-lab", publicHosts: [publicHost], targetOrigin: `https://${originHost}`, originHostname: originHost,
    audience: "lab-audience", deploymentId: releaseId, keyId: "lab-key", signingPrivateKeyPkcs8: pkcs8, identityHmacKey: hmacKey,
    originSecret: "o".repeat(43), cloudRunAuthorizationToken: async () => "Bearer eyJ.lab",
  }, {
    now: () => clock.value,
    fetch: async (input, init) => { forwarded.push(new Request(String(input), { ...init, duplex: "half" } as RequestInit)); return new Response("ok"); },
  });
  const storage = new NodeSqliteDurableStorage();
  initializeAuthority(storage, { environment: "staging", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
    releaseId, releaseKeyId: "test-key", nowMs: clock.value, confirmProduction: false });
  const bindingKey = await importRequestBindingKey(encodeBase64url(new Uint8Array(32).fill(9)));
  const policy = { audience: "lab-audience", deploymentId: releaseId, environment: "cloud-run-lab" as const, publicHostname: publicHost,
    originHostname: originHost, publicKeys: new Map([["lab-key", pair.publicKey]]), requestBindingKey: bindingKey, now: () => clock.value };
  const writes: string[] = [];
  const repository = { async create() { writes.push("row"); return { status: "created" as const }; } };
  const turnstile = { async verify() { return "verified" as const; } };

  // A fresh authority object per call models another Worker isolate reaching the same single named Durable Object.
  const admissionFor = (options: { fail?: boolean } = {}): AdmissionClient => {
    const authority = () => new PublicInquiryAdmissionAuthority({ storage }, { now: () => clock.value,
      ...(options.fail ? { faultAfterObservation: () => { throw new Error("replay-state-failure"); } } : {}) });
    return { async claimPre(input) { return authority().claimPre(input); }, async consumePost(input) { return authority().consumePost(input); } };
  };

  async function signed(body = formBody()) {
    const response = await signer(new Request(`https://${publicHost}/api/public-inquiries`, { method: "POST", body,
      headers: { "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": "203.0.113.9" } }));
    assert.equal(response.status, 200);
    const request = forwarded.at(-1)!;
    const bytes = new Uint8Array(await request.clone().arrayBuffer());
    return { headers: new Headers(request.headers), bytes, url: request.url };
  }
  const rebuild = (s: { headers: Headers; url: string }, bytes: Uint8Array, url = s.url) =>
    new Request(url, { method: "POST", headers: s.headers, body: bytes as BodyInit });

  async function submit(s: { headers: Headers; bytes: Uint8Array; url: string }, options: { bytes?: Uint8Array; url?: string; fail?: boolean } = {}) {
    const bytes = options.bytes ?? s.bytes;
    const request = rebuild(s, bytes, options.url);
    const ingress = await verifyMutationIngress(request, bytes, policy);
    return executeVerifiedPublicInquiry({ form: parseStrictUrlEncodedForm(bytes),
      ingress, admission: admissionFor({ fail: options.fail }), turnstile, repository });
  }
  return { clock, signed, rebuild, submit, writes, policy, forwarded };
}

test("exact replay: the verifier alone accepts the copy (binding is stateless) but the authority permits only one persistence", async () => {
  const c = await chain();
  const s = await c.signed();
  const first = await c.submit(s);
  assert.equal(first.kind, "redirect");
  // Cryptographic binding does NOT prevent reuse: an identical copy still verifies.
  await assert.doesNotReject(() => verifyMutationIngress(c.rebuild(s, s.bytes), s.bytes, c.policy));
  const second = await c.submit(s);
  assert.equal(second.kind, "state");
  assert.deepEqual(c.writes, ["row"], "replay must not create a second row");
});

test("replay after the freshness window is rejected by the verifier even though the nonce table was pruned", async () => {
  const c = await chain();
  const s = await c.signed();
  assert.equal((await c.submit(s)).kind, "redirect");
  c.clock.value = T0 + 31_000; // max age 30 s; nonce retained 120 s
  await assert.rejects(() => c.submit(s), /stale/);
  c.clock.value = T0 + 200_000; // nonce row pruned
  await assert.rejects(() => c.submit(s), /stale/);
  assert.equal(c.writes.length, 1);
});

test("modified-body replay is rejected before admission", async () => {
  const c = await chain();
  const s = await c.signed();
  await assert.rejects(() => c.submit(s, { bytes: new TextEncoder().encode(formBody("attacker@example.test")) }), /content-length|body-(length|digest)/);
  assert.equal(c.writes.length, 0);
  // Same-length edit still fails the digest.
  const same = new TextEncoder().encode(formBody().replace("Synthetic", "Syntheti!"));
  assert.equal(same.length, s.bytes.length);
  await assert.rejects(() => c.submit(s, { bytes: same }), /body-digest/);
  assert.equal(c.writes.length, 0);
});

test("cross-route and cross-origin replay of a signed envelope is rejected", async () => {
  const c = await chain();
  const s = await c.signed();
  await assert.rejects(() => c.submit(s, { url: `https://${originHost}/api/other` }), /ingress-path/);
  await assert.rejects(() => c.submit(s, { url: `https://${originHost}/api/public-inquiries?x=1` }), /ingress-query/);
  await assert.rejects(() => c.submit(s, { url: "https://other-origin.run.app/api/public-inquiries" }), /ingress-host/);
  const wrongForwarded = new Headers(s.headers); wrongForwarded.set("x-forwarded-host", "attacker.example");
  await assert.rejects(() => c.submit({ ...s, headers: wrongForwarded }), /ingress-host/);
  assert.equal(c.writes.length, 0);
});

test("expired and future-dated signed requests are rejected", async () => {
  const c = await chain();
  const old = await c.signed();
  c.clock.value = T0 + 30_001;
  await assert.rejects(() => c.submit(old), /stale/);
  c.clock.value = T0;
  const future = await c.signed();
  c.clock.value = T0 - 5_001; // verifier clock behind signer by more than the 5 s skew allowance
  await assert.rejects(() => c.submit(future), /future/);
  assert.equal(c.writes.length, 0);
});

test("concurrent duplicate submissions of one envelope persist exactly once, across independent authority instances", async () => {
  const c = await chain();
  const s = await c.signed();
  const results = await Promise.all(Array.from({ length: 8 }, () => c.submit(s)));
  assert.equal(results.filter((r) => r.kind === "redirect").length, 1);
  assert.equal(c.writes.length, 1);
});

test("replay-state failure fails closed: no Turnstile credit, no row, and the same envelope is not left half-claimed", async () => {
  const c = await chain();
  const s = await c.signed();
  const failed = await c.submit(s, { fail: true });
  assert.equal(failed.kind, "state");
  assert.equal(c.writes.length, 0);
  // The transaction rolled back, so a later healthy attempt can still use the (unexpired) envelope exactly once.
  assert.equal((await c.submit(s)).kind, "redirect");
  assert.equal((await c.submit(s)).kind, "state");
  assert.equal(c.writes.length, 1);
});

test("a regressing authority clock fails closed instead of reopening the nonce window", async () => {
  const c = await chain();
  const s = await c.signed();
  assert.equal((await c.submit(s)).kind, "redirect");
  c.clock.value = T0 - 1_000; // authority sees time go backwards (last_now_ms)
  const next = await c.signed(); // fresh envelope, issued 1 s before the authority's high-water mark
  assert.equal((await c.submit(next)).kind, "state");
  assert.equal(c.writes.length, 1);
});
