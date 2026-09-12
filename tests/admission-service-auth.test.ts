import assert from "node:assert/strict";
import test from "node:test";
import {
  ADMISSION_MAC_HEADER, ADMISSION_PRE_PATH, ADMISSION_RPC_CONTENT_TYPE, ADMISSION_RPC_VERSION,
  encodeAdmissionRpcPayload, importAdmissionRpcKey, signAdmissionRpc, type AdmissionRpcPayload,
} from "../src/lib/admission-protocol";
import { createProductionAdmissionClient } from "../src/lib/admission-client.server";
import { encodeBase64url, toArrayBuffer } from "../src/lib/ingress-protocol";
import { createAdmissionService } from "../workers/admission-service/service";
import type { VerifiedVercelOidcClaims, VercelOidcSignatureVerifier } from "../workers/admission-service/auth";

const keyText = encodeBase64url(new Uint8Array(32).fill(7));
const opaque = (length: number, fill: number) => encodeBase64url(new Uint8Array(length).fill(fill));
const policy = { issuer: "https://oidc.vercel.com/team", audience: "https://admission.limitmark.test", subject: "owner:team:project:prj_limitmark:environment:production", ownerId: "team", projectId: "prj_limitmark" };
const validClaims: VerifiedVercelOidcClaims = { issuer: policy.issuer, audience: [policy.audience], subject: policy.subject,
  ownerId: policy.ownerId, projectId: policy.projectId, environment: "production", issuedAtSeconds: 95, expiresAtSeconds: 200 };

async function serviceFixture(claims: Partial<VerifiedVercelOidcClaims> = {}, rpcKeyText = keyText) {
  const rpcKey = await importAdmissionRpcKey(rpcKeyText);
  const calls: string[] = [];
  const verifier: VercelOidcSignatureVerifier = { async verify(token) { if (token !== "vercel-token") throw new Error("signature"); return { ...validClaims, ...claims }; } };
  const service = createAdmissionService({ releaseId: "dpl_reviewed", rpcKey, oidcPolicy: policy, oidcVerifier: verifier, now: () => 100_000,
    authority: { claimPre() { calls.push("pre"); return { decision: "allowed", permit: opaque(32, 9), expiresAtMs: 160_000 }; }, consumePost() { calls.push("post"); return { decision: "allowed" }; } } });
  const payload: AdmissionRpcPayload = [ADMISSION_RPC_VERSION, "dpl_reviewed", opaque(16, 1), 100_000, opaque(32, 2), opaque(32, 3), opaque(16, 4), "-", 100_000];
  const body = encodeAdmissionRpcPayload(payload);
  const request = new Request(`https://admission.limitmark.test${ADMISSION_PRE_PATH}`, { method: "POST", body: toArrayBuffer(body),
    headers: { authorization: "Bearer vercel-token", "content-type": ADMISSION_RPC_CONTENT_TYPE, [ADMISSION_MAC_HEADER]: await signAdmissionRpc(ADMISSION_PRE_PATH, body, rpcKey) } });
  return { service, request, calls };
}

test("service requires both exact Vercel workload claims and release MAC before authority access", async () => {
  const valid = await serviceFixture();
  assert.equal((await valid.service(valid.request)).status, 200);
  assert.deepEqual(valid.calls, ["pre"]);
  for (const claims of [{ issuer: "https://attacker.test" }, { audience: ["wrong"] }, { subject: "wrong" }, { ownerId: "wrong" },
    { projectId: "wrong" }, { environment: "preview" }, { expiresAtSeconds: 99 }, { notBeforeSeconds: 101 }]) {
    const fixture = await serviceFixture(claims);
    assert.equal((await fixture.service(fixture.request)).status, 401);
    assert.deepEqual(fixture.calls, []);
  }
});

test("wrong release MAC and Access JWT substitution cannot reach the authority", async () => {
  const fixture = await serviceFixture();
  const headers = new Headers(fixture.request.headers);
  headers.set(ADMISSION_MAC_HEADER, opaque(32, 8));
  assert.equal((await fixture.service(new Request(fixture.request.url, { method: "POST", body: await fixture.request.clone().arrayBuffer(), headers }))).status, 401);
  headers.set("authorization", "Bearer cloudflare-access-jwt");
  assert.equal((await fixture.service(new Request(fixture.request.url, { method: "POST", body: await fixture.request.arrayBuffer(), headers }))).status, 401);
  assert.deepEqual(fixture.calls, []);
});

test("Preview/development cannot construct a Production admission client", async () => {
  const base = { VERCEL: "1", VERCEL_ENV: "production", VERCEL_DEPLOYMENT_ID: "dpl_reviewed", ADMISSION_RELEASE_ID: "dpl_reviewed",
    ADMISSION_SERVICE_URL: "https://admission.limitmark.test", ADMISSION_OIDC_AUDIENCE: policy.audience, ADMISSION_RELEASE_RPC_KEY: keyText };
  const oidc = { async getToken() { return "vercel-token"; } };
  for (const change of [{ VERCEL_ENV: "preview" }, { VERCEL_ENV: "development" }, { VERCEL: "0" }, { ADMISSION_RELEASE_ID: "other" }]) {
    assert.equal(await createProductionAdmissionClient({ ...base, ...change }, oidc), null);
  }
});

test("admission client never retries a possibly consuming lost response", async () => {
  let calls = 0;
  const client = await createProductionAdmissionClient({ VERCEL: "1", VERCEL_ENV: "production", VERCEL_DEPLOYMENT_ID: "dpl_reviewed", ADMISSION_RELEASE_ID: "dpl_reviewed",
    ADMISSION_SERVICE_URL: "https://admission.limitmark.test", ADMISSION_OIDC_AUDIENCE: policy.audience, ADMISSION_RELEASE_RPC_KEY: keyText },
  { async getToken() { return "vercel-token"; } }, async () => { calls++; throw new Error("lost-response"); });
  assert.ok(client);
  assert.equal((await client!.claimPre({ releaseId: "dpl_reviewed", clientPseudonym: opaque(32, 2), requestBinding: opaque(32, 3), nonce: opaque(16, 4), issuedAtMs: Date.now() })).decision, "unavailable");
  assert.equal(calls, 1);
});
