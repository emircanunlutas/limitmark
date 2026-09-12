import assert from "node:assert/strict";
import test from "node:test";
import {
  INGRESS_BODY_ENCODING, INGRESS_ENVIRONMENT, INGRESS_HEADER, INGRESS_IDENTITY_VERSION,
  INGRESS_MUTATION_CONTENT_TYPE, INGRESS_MUTATION_PATH, INGRESS_VERSION,
  createIngressEnvelope, encodeBase64url, sha256Base64url, type IngressPayload,
} from "../src/lib/ingress-protocol";
import { importRequestBindingKey, verifyMutationIngress } from "../src/lib/ingress-verifier.server";

async function signedRequest(changes: Partial<{ payload: Partial<Record<number, unknown>>; body: string; url: string; method: string; headers: Record<string, string>; now: number }> = {}) {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const bodyText = changes.body ?? "name=Synthetic";
  const body = new TextEncoder().encode(bodyText);
  const payload: IngressPayload = [INGRESS_VERSION, "current", INGRESS_ENVIRONMENT, "prj_limitmark", "dpl_reviewed", 100_000,
    "POST", "https", "limitmark.com", INGRESS_MUTATION_PATH, "", INGRESS_MUTATION_CONTENT_TYPE, INGRESS_BODY_ENCODING,
    body.length, await sha256Base64url(body), INGRESS_IDENTITY_VERSION, encodeBase64url(new Uint8Array(32).fill(3)), encodeBase64url(new Uint8Array(16).fill(4))];
  for (const [index, value] of Object.entries(changes.payload ?? {})) (payload as unknown as unknown[])[Number(index)] = value;
  const envelope = await createIngressEnvelope(payload, pair.privateKey);
  const request = new Request(changes.url ?? "https://limitmark.com/api/public-inquiries", {
    method: changes.method ?? "POST", body: changes.method === "GET" ? undefined : bodyText,
    headers: { host: "limitmark.com", "x-forwarded-host": "limitmark.com", "content-type": INGRESS_MUTATION_CONTENT_TYPE,
      "content-encoding": "identity", [INGRESS_HEADER]: envelope, ...changes.headers },
  });
  const bindingKey = await importRequestBindingKey(encodeBase64url(new Uint8Array(32).fill(9)));
  return { request, body, pair, policy: { audience: "prj_limitmark", deploymentId: "dpl_reviewed", publicKeys: new Map([["current", pair.publicKey]]), requestBindingKey: bindingKey, now: () => changes.now ?? 100_000 } };
}

test("Vercel verifier independently binds signature, audience, deployment, route and exact body", async () => {
  const valid = await signedRequest();
  const result = await verifyMutationIngress(valid.request, valid.body, valid.policy);
  assert.match(result.clientPseudonym, /^[A-Za-z0-9_-]{43}$/);
  assert.match(result.requestBinding, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(result.releaseId, "dpl_reviewed");
  const changed = new TextEncoder().encode("name=Changed");
  await assert.rejects(() => verifyMutationIngress(valid.request, changed, valid.policy), /body-length|body-digest/);
});

test("Vercel verifier rejects stale/future, wrong key/audience/deployment and request mismatches", async () => {
  for (const item of [
    await signedRequest({ now: 130_001 }), await signedRequest({ now: 94_999 }),
    await signedRequest({ url: "https://limitmark.com/api/public-inquiries?x=1" }),
    await signedRequest({ headers: { host: "deployment.vercel.app" } }),
    await signedRequest({ headers: { "x-forwarded-host": "www.limitmark.com" } }),
    await signedRequest({ headers: { "content-type": "application/json" } }),
    await signedRequest({ headers: { "content-encoding": "gzip" } }),
  ]) await assert.rejects(() => verifyMutationIngress(item.request, item.body, item.policy));

  const wrongAudience = await signedRequest();
  await assert.rejects(() => verifyMutationIngress(wrongAudience.request, wrongAudience.body, { ...wrongAudience.policy, audience: "other" }));
  await assert.rejects(() => verifyMutationIngress(wrongAudience.request, wrongAudience.body, { ...wrongAudience.policy, deploymentId: "other" }));
  const other = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  await assert.rejects(() => verifyMutationIngress(wrongAudience.request, wrongAudience.body, { ...wrongAudience.policy, publicKeys: new Map([["current", other.publicKey]]) }));
});

test("detectable duplicate/merged ingress headers and false Content-Length fail closed", async () => {
  const valid = await signedRequest();
  const mergedHeaders = new Headers(valid.request.headers);
  mergedHeaders.set(INGRESS_HEADER, `${mergedHeaders.get(INGRESS_HEADER)},${mergedHeaders.get(INGRESS_HEADER)}`);
  const merged = new Request(valid.request.url, { method: "POST", body: valid.body, headers: mergedHeaders });
  await assert.rejects(() => verifyMutationIngress(merged, valid.body, valid.policy));
  const lengthHeaders = new Headers(valid.request.headers); lengthHeaders.set("content-length", String(valid.body.length + 1));
  const falseLength = new Request(valid.request.url, { method: "POST", body: valid.body, headers: lengthHeaders });
  await assert.rejects(() => verifyMutationIngress(falseLength, valid.body, valid.policy), /content-length/);
});
