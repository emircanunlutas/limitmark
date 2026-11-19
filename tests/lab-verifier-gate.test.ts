import assert from "node:assert/strict";
import test from "node:test";
import {
  INGRESS_BODY_ENCODING, INGRESS_ENVIRONMENT, INGRESS_HEADER, INGRESS_IDENTITY_VERSION, INGRESS_MUTATION_CONTENT_TYPE, INGRESS_MUTATION_PATH, INGRESS_VERSION,
  LAB_INGRESS_ENVIRONMENT, createIngressEnvelope, encodeBase64url, sha256Base64url, type IngressPayload,
} from "../src/lib/ingress-protocol";
import { importRequestBindingKey, verifyMutationIngress, type IngressVerificationPolicy } from "../src/lib/ingress-verifier.server";
import { handlePublicInquiry } from "../src/lib/public-inquiry-handler.server";
import type { AdmissionClient } from "../src/lib/admission-client.server";

// Laboratory signed-envelope verifier tests. Synthetic keys and values only (the Ed25519 key pairs are generated in-process and never leave it).
// Next.js derives request.url from the bind address, so in the container the URL authority is https://0.0.0.0:8080.
const PUB = "lab.example.test", ORIGIN = "origin-lab.example.run.app", AUD = "lab-ingress-aud", DEP = "lab-deployment-1", NEXT_URL = "https://0.0.0.0:8080";
const NOW = 1_000_000, secret = "A".repeat(43);
const nonce = encodeBase64url(new Uint8Array(16).fill(4));
let bindingKey: CryptoKey, pair: CryptoKeyPair, other: CryptoKeyPair;
let labPolicy: IngressVerificationPolicy, prodPolicy: IngressVerificationPolicy;
test.before(async () => {
  bindingKey = await importRequestBindingKey(encodeBase64url(new Uint8Array(32).fill(9)));
  pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
  other = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
  labPolicy = { audience: AUD, deploymentId: DEP, environment: "cloud-run-lab", publicHostname: PUB, originHostname: ORIGIN,
    publicKeys: new Map([["k1", pair.publicKey]]), requestBindingKey: bindingKey, now: () => NOW };
  prodPolicy = { audience: "prj_limitmark", deploymentId: "dpl_reviewed", publicKeys: new Map([["k1", pair.publicKey]]), requestBindingKey: bindingKey, now: () => NOW };
});

type Change = { payload?: Record<number, unknown>; body?: string; url?: string; method?: string; headers?: Record<string, string | undefined>; key?: CryptoKey; prod?: boolean };
async function build(c: Change = {}) {
  const bodyText = c.body ?? "name=Synthetic";
  const body = new TextEncoder().encode(bodyText);
  const digest = await sha256Base64url(body);
  const client = encodeBase64url(new Uint8Array(32).fill(3));
  const payload: IngressPayload = c.prod
    ? [INGRESS_VERSION, "k1", INGRESS_ENVIRONMENT, "prj_limitmark", "dpl_reviewed", NOW, "POST", "https", "limitmark.com", INGRESS_MUTATION_PATH, "", INGRESS_MUTATION_CONTENT_TYPE, INGRESS_BODY_ENCODING, body.length, digest, INGRESS_IDENTITY_VERSION, client, nonce]
    : [INGRESS_VERSION, "k1", LAB_INGRESS_ENVIRONMENT, AUD, DEP, NOW, "POST", "https", PUB, INGRESS_MUTATION_PATH, "", INGRESS_MUTATION_CONTENT_TYPE, INGRESS_BODY_ENCODING, body.length, digest, INGRESS_IDENTITY_VERSION, client, nonce];
  for (const [i, v] of Object.entries(c.payload ?? {})) (payload as unknown as unknown[])[Number(i)] = v;
  const envelope = await createIngressEnvelope(payload, c.key ?? pair.privateKey);
  const h = new Headers({ "content-type": INGRESS_MUTATION_CONTENT_TYPE, "content-encoding": "identity", [INGRESS_HEADER]: envelope,
    host: c.prod ? "limitmark.com" : ORIGIN, "x-forwarded-host": c.prod ? "limitmark.com" : PUB });
  for (const [k, v] of Object.entries(c.headers ?? {})) { if (v === undefined) h.delete(k); else h.set(k, v); }
  const request = new Request(c.url ?? `${NEXT_URL}${INGRESS_MUTATION_PATH}`, { method: c.method ?? "POST", body: c.method === "GET" ? undefined : bodyText, headers: h });
  return { request, body };
}
const rejects = async (c: Change, re: RegExp, policy?: IngressVerificationPolicy) => { const { request, body } = await build(c); await assert.rejects(() => verifyMutationIngress(request, body, policy ?? labPolicy), re); };

test("lab: valid envelope with the realistic Next.js URL 0.0.0.0:8080 verifies", async () => {
  const { request, body } = await build();
  assert.equal(new URL(request.url).hostname, "0.0.0.0"); assert.equal(new URL(request.url).port, "8080");
  const result = await verifyMutationIngress(request, body, labPolicy);
  assert.equal(result.nonce, nonce); assert.equal(result.releaseId, DEP); assert.equal(result.keyId, "k1");
  assert.match(result.requestBinding, /^[A-Za-z0-9_-]{43}$/);
});
test("lab: missing, malformed, wrong-key and tampered signatures are rejected", async () => {
  const { request, body } = await build({ headers: { [INGRESS_HEADER]: undefined } });
  await assert.rejects(() => verifyMutationIngress(request, body, labPolicy), /ingress-missing/);
  await rejects({ headers: { [INGRESS_HEADER]: "not.an.envelope" } }, /./);
  await rejects({ key: other.privateKey }, /./);
  const good = await build(); const [p, s] = good.request.headers.get(INGRESS_HEADER)!.split(".");
  await rejects({ headers: { [INGRESS_HEADER]: `${p}.${s.slice(0, -2)}${s.endsWith("AA") ? "BB" : "AA"}` } }, /./);
});
test("lab: wrong signed public hostname, audience, deployment and environment are rejected", async () => {
  await rejects({ payload: { 8: "evil.example" } }, /ingress-host/);
  await rejects({ payload: { 3: "other" } }, /ingress-audience/);
  await rejects({ payload: { 4: "other" } }, /ingress-audience/);
});
test("lab: expired and future-dated envelopes are rejected", async () => {
  await rejects({ payload: { 5: NOW - 31_000 } }, /stale/);
  await rejects({ payload: { 5: NOW + 6_000 } }, /future/);
});
test("lab: method, scheme, path, query, content type, encoding, length and digest mismatches are rejected", async () => {
  await rejects({ method: "GET" }, /ingress-method/);
  await rejects({ url: `http://0.0.0.0:8080${INGRESS_MUTATION_PATH}` }, /ingress-scheme/);
  await rejects({ url: `${NEXT_URL}/api/other` }, /ingress-path/);
  await rejects({ url: `${NEXT_URL}${INGRESS_MUTATION_PATH}?x=1` }, /ingress-query/);
  await rejects({ headers: { "content-type": "application/json" } }, /ingress-content-type/);
  await rejects({ headers: { "content-encoding": "gzip" } }, /ingress-content-encoding/);
  await rejects({ payload: { 13: 3 } }, /ingress-body-length|content-length/);
  await rejects({ payload: { 14: "A".repeat(43) } }, /ingress-body-digest/);
  const { request } = await build();
  await assert.rejects(() => verifyMutationIngress(request, new TextEncoder().encode("name=Changed"), labPolicy), /body-length|body-digest/);
});
test("lab: wrong or missing Host and x-forwarded-host are rejected", async () => {
  for (const host of [undefined, "", PUB, "evil.example", `${ORIGIN}:8080`]) await rejects({ headers: { host } }, /ingress-host/);
  for (const xfh of [undefined, "", ORIGIN, "evil.example"]) await rejects({ headers: { "x-forwarded-host": xfh } }, /ingress-host/);
});
test("lab: nonce replay is not decided by the stateless verifier; the identical nonce and binding are produced for admission to decide", async () => {
  const { request, body } = await build();
  const a = await verifyMutationIngress(request.clone(), body, labPolicy);
  const b = await verifyMutationIngress(request.clone(), body, labPolicy);
  assert.equal(a.nonce, b.nonce); assert.equal(a.requestBinding, b.requestBinding);
});
test("a request cannot select the laboratory policy: the policy is server-side, signed fields and headers do not switch it", async () => {
  for (const headers of [{ "x-limitmark-runtime": "cloud-run-lab" }, { "x-limitmark-environment": "cloud-run-lab" }, { "x-environment": "cloud-run-lab" }]) {
    await rejects({ prod: true, url: `${NEXT_URL}${INGRESS_MUTATION_PATH}`, headers }, /ingress-host/, prodPolicy);
  }
  await rejects({ prod: true, url: `https://limitmark.com${INGRESS_MUTATION_PATH}?cloud-run-lab=1` }, /ingress-query/, prodPolicy);
  // a lab-signed payload (signed environment field) does not switch a production policy to lab behaviour: it fails the environment/audience check
  await rejects({ url: `${NEXT_URL}${INGRESS_MUTATION_PATH}` }, /ingress-audience/, prodPolicy);
  // a production-environment envelope is rejected by the laboratory policy
  await rejects({ prod: true }, /ingress-audience/, labPolicy);
});
test("production: URL hostname and port validation unchanged", async () => {
  const ok = await build({ prod: true, url: `https://limitmark.com${INGRESS_MUTATION_PATH}` });
  await assert.doesNotReject(() => verifyMutationIngress(ok.request, ok.body, prodPolicy));
  await rejects({ prod: true }, /ingress-host/, prodPolicy); // https://0.0.0.0:8080 URL
  await rejects({ prod: true, url: `https://limitmark.com:8443${INGRESS_MUTATION_PATH}` }, /ingress-host/, prodPolicy);
  await rejects({ prod: true, url: `https://evil.example${INGRESS_MUTATION_PATH}` }, /ingress-host/, prodPolicy);
  await rejects({ prod: true, url: `https://limitmark.com${INGRESS_MUTATION_PATH}`, headers: { host: "www.limitmark.com" } }, /ingress-host/, prodPolicy);
});
test("lab: changing only the Next.js-derived URL hostname does not select a different trusted origin; the trusted origin is the configured Host", async () => {
  for (const url of ["https://other-origin.run.app:8080", "https://localhost:8080", NEXT_URL]) {
    const { request, body } = await build({ url: `${url}${INGRESS_MUTATION_PATH}` });
    await assert.doesNotReject(() => verifyMutationIngress(request, body, labPolicy), url); // Host/x-forwarded-host still equal the configured values
  }
  await rejects({ url: `https://other-origin.run.app:8080${INGRESS_MUTATION_PATH}`, headers: { host: "other-origin.run.app" } }, /ingress-host/);
  await rejects({ headers: { host: "other-origin.run.app" } }, /ingress-host/);
  await rejects({ url: `${NEXT_URL}/api/other` }, /ingress-path/); // cross-route replay
  await rejects({ payload: { 8: "other.example" } }, /ingress-host/); // altered signed public hostname
});
test("laboratory policy with a missing hostname fails closed", async () => {
  const { request, body } = await build();
  await assert.rejects(() => verifyMutationIngress(request, body, { ...labPolicy, originHostname: undefined }), /ingress-host/);
  await assert.rejects(() => verifyMutationIngress(request, body, { ...labPolicy, publicHostname: undefined }), /ingress-host/);
});

// ---- Combined handler + verifier: real code, realistic Next.js URL, correctly signed envelope ----
const labEnv: Record<string, string | undefined> = { LIMITMARK_RUNTIME: "cloud-run-lab", REQUEST_SUBMISSION_MODE: "postgres", PUBLIC_ORIGIN_PROTECTION: "required",
  PUBLIC_ORIGIN_SECRET: secret, PUBLIC_ORIGIN_HOSTNAME: ORIGIN, PUBLIC_ORIGIN_PUBLIC_HOSTNAME: PUB };
const formBody = (extra: string) => `submissionToken=${encodeBase64url(new Uint8Array(32).fill(7))}&name=FQ1+Synthetic&email=qa%40example.test&company=&service=web&system=Disposable+lab+system&objective=Review+boundary&environment=staging&authority=authorized&protection=unknown&notes=${extra}`;
const SYNTHETIC_FORM = formBody("&cf-turnstile-response=synthetic-token");
function dependencies() {
  const calls: unknown[] = [];
  const admission = { async claimPre(input: unknown) { calls.push(input); return { decision: "denied" }; }, async consumePost() { throw new Error("must not be reached"); } } as unknown as AdmissionClient;
  return { calls, deps: { environment: labEnv, ingressPolicy: labPolicy, admission, turnstile: { verify: async () => "unavailable" as const }, repository: { create: async () => ({ status: "created" as const }) } } };
}
type Integrated = Change & { origin?: string; secretHeader?: string };
async function integrated(c: Integrated) {
  const { request } = await build({ ...c, body: SYNTHETIC_FORM, headers: { origin: c.origin ?? `https://${PUB}`, "x-limitmark-origin-secret": c.secretHeader ?? secret, ...c.headers } });
  const d = dependencies();
  const response = await handlePublicInquiry(request, d.deps);
  return { status: response.status, calls: d.calls };
}
test("integrated: correctly signed lab request at https://0.0.0.0:8080 passes both hostname gates and reaches the admission claim with the verified binding", async () => {
  const r = await integrated({});
  // The flow ran to its next stage: the admission stub denied the claim, which the handler renders as a 400 "state" response. Reaching claimPre (calls===1)
  // is the proof that both hostname gates and envelope verification passed; a gate or verifier rejection never calls admission.
  assert.equal(r.status, 400);
  assert.equal(r.calls.length, 1);
  const call = r.calls[0] as { nonce: string; releaseId: string; requestBinding: string };
  assert.equal(call.nonce, nonce); assert.equal(call.releaseId, DEP); assert.match(call.requestBinding, /^[A-Za-z0-9_-]{43}$/);
});
test("integrated: invalid requests are rejected at the correct boundary and never reach admission", async () => {
  const cases: Array<[string, Integrated, number]> = [
    ["wrong origin", { origin: "https://evil.example" }, 503], ["wrong origin secret", { secretHeader: "B".repeat(43) }, 503],
    ["wrong Host", { headers: { host: "evil.example" } }, 503], ["wrong x-forwarded-host", { headers: { "x-forwarded-host": "evil.example" } }, 503],
    ["no envelope", { headers: { [INGRESS_HEADER]: undefined } }, 400], ["wrong signing key", { key: other.privateKey }, 400],
    ["wrong signed public host", { payload: { 8: "evil.example" } }, 400], ["stale envelope", { payload: { 5: NOW - 60_000 } }, 400],
    ["wrong audience", { payload: { 3: "other" } }, 400], ["http scheme", { url: `http://0.0.0.0:8080${INGRESS_MUTATION_PATH}` }, 503],
  ];
  for (const [label, change, status] of cases) { const r = await integrated(change); assert.equal(r.status, status, label); assert.equal(r.calls.length, 0, label); }
  // body replaced after signing: digest mismatch
  const signed = await build({ body: SYNTHETIC_FORM });
  const d = dependencies();
  const headers = new Headers(signed.request.headers); headers.set("origin", `https://${PUB}`); headers.set("x-limitmark-origin-secret", secret);
  const response = await handlePublicInquiry(new Request(signed.request.url, { method: "POST", body: formBody("&cf-turnstile-response=other"), headers }), d.deps);
  assert.equal(response.status, 400); assert.equal(d.calls.length, 0);
});
