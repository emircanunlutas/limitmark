import assert from "node:assert/strict";
import test, { before } from "node:test";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import {
  createGoogleOidcVerifier,
  type GoogleOidcPolicy,
} from "../workers/admission-service/auth";
import { GoogleMetadataOidcTokenProvider } from "../src/lib/admission-client.server";
import {
  ADMISSION_KEY_ID_HEADER, ADMISSION_MAC_HEADER, ADMISSION_PRE_PATH, ADMISSION_RPC_CONTENT_TYPE, ADMISSION_RPC_VERSION,
  encodeAdmissionRpcPayload, importAdmissionRpcKey, signAdmissionRpc, type AdmissionRpcPayload,
} from "../src/lib/admission-protocol";
import { encodeBase64url, toArrayBuffer } from "../src/lib/ingress-protocol";
import { createLaboratoryAdmissionService } from "../workers/admission-service/service";

const policy: GoogleOidcPolicy = {
  issuer: "https://accounts.google.com",
  audience: "https://admission-lab.limitmark.test",
  serviceAccountEmail: "limitmark-lab@limitmark-field-qual.iam.gserviceaccount.com",
  serviceAccountSubject: "123456789012345678901",
};
const nowSeconds = 1_800_000_000;
let keys: Awaited<ReturnType<typeof generateKeyPair>>;
let jwk: JWK;

before(async () => {
  keys = await generateKeyPair("RS256", { extractable: true });
  jwk = { ...(await exportJWK(keys.publicKey)), kid: "google-primary", alg: "RS256", use: "sig" };
});

async function token(changes: { issuer?: string; audience?: string; email?: string; subject?: string; iat?: number; exp?: number; key?: CryptoKey } = {}): Promise<string> {
  return new SignJWT({
    email: changes.email ?? policy.serviceAccountEmail,
    email_verified: true,
    iat: changes.iat ?? nowSeconds,
    exp: changes.exp ?? nowSeconds + 600,
  }).setProtectedHeader({ alg: "RS256", kid: "google-primary", typ: "JWT" })
    .setIssuer(changes.issuer ?? policy.issuer)
    .setAudience(changes.audience ?? policy.audience)
    .setSubject(changes.subject ?? policy.serviceAccountSubject!)
    .sign(changes.key ?? keys.privateKey);
}

function verifier() {
  return createGoogleOidcVerifier(policy, {
    now: () => nowSeconds * 1_000,
    fetch: async () => new Response(JSON.stringify({ keys: [jwk] }), { status: 200 }),
  });
}

test("valid Google laboratory service-account identity verifies", async () => {
  const claims = await verifier().verify(await token(), nowSeconds * 1_000);
  assert.equal(claims.email, policy.serviceAccountEmail);
  assert.equal(claims.subject, policy.serviceAccountSubject);
});

test("issuer, audience, identity, time, and signature mismatches fail", async () => {
  const wrongKey = await generateKeyPair("RS256");
  for (const change of [
    { issuer: "https://accounts.google.invalid" },
    { audience: "wrong" },
    { email: "other@example.com" },
    { subject: "other-subject" },
    { iat: nowSeconds + 6 },
    { exp: nowSeconds - 6 },
    { key: wrongKey.privateKey },
  ]) await assert.rejects(async () => verifier().verify(await token(change), nowSeconds * 1_000));
});

test("metadata ID-token provider caches within validity and never exposes token contents", async () => {
  let calls = 0;
  const tokenValue = await token();
  const provider = new GoogleMetadataOidcTokenProvider(async (input, init) => {
    calls += 1;
    assert.match(String(input), /metadata\.google\.internal\/computeMetadata\/v1\/instance\/service-accounts\/default\/identity\?/u);
    assert.equal(new Headers(init?.headers).get("Metadata-Flavor"), "Google");
    return new Response(tokenValue, { status: 200 });
  }, () => nowSeconds * 1_000, "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity");
  assert.equal(await provider.getToken(policy.audience), tokenValue);
  assert.equal(await provider.getToken(policy.audience), tokenValue);
  assert.equal(calls, 1);
});

test("laboratory admission accepts only Google identity before shared PRE processing", async () => {
  const rpcKey = await importAdmissionRpcKey("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc");
  const calls: string[] = [];
  const service = createLaboratoryAdmissionService({
    releases: [{ role: "current", releaseId: "lab-release", keyId: "lab-key", rpcKey, activatedAtMs: 0 }],
    oidcPolicy: policy,
    oidcVerifier: { async verify(value) {
      if (value !== "google-token") throw new Error("identity");
      return { issuer: policy.issuer, audience: [policy.audience], subject: policy.serviceAccountSubject!, email: policy.serviceAccountEmail,
        issuedAtSeconds: nowSeconds, expiresAtSeconds: nowSeconds + 600 };
    } },
    now: () => nowSeconds * 1_000,
    authority: { claimPre() { calls.push("pre"); return { decision: "allowed", permit: "cGVybWl0", expiresAtMs: nowSeconds * 1_000 + 60_000 }; },
      consumePost() { calls.push("post"); return { decision: "allowed" }; } },
  });
  const opaque = (length: number) => encodeBase64url(new Uint8Array(length).fill(7));
  const payload: AdmissionRpcPayload = [ADMISSION_RPC_VERSION, "lab-release", opaque(16), nowSeconds * 1_000, opaque(32), opaque(32), opaque(16), "-", nowSeconds * 1_000];
  const body = encodeAdmissionRpcPayload(payload);
  const headers = {
    authorization: "Bearer google-token", "content-type": ADMISSION_RPC_CONTENT_TYPE,
    [ADMISSION_KEY_ID_HEADER]: "lab-key", [ADMISSION_MAC_HEADER]: await signAdmissionRpc(ADMISSION_PRE_PATH, body, rpcKey),
  };
  assert.equal((await service(new Request(`https://lab.limitmark.test${ADMISSION_PRE_PATH}`, { method: "POST", body: toArrayBuffer(body), headers }))).status, 200);
  assert.deepEqual(calls, ["pre"]);
  const rejected = new Headers(headers);
  rejected.set("authorization", "Bearer vercel-token");
  assert.equal((await service(new Request(`https://lab.limitmark.test${ADMISSION_PRE_PATH}`, { method: "POST", body: toArrayBuffer(body), headers: rejected }))).status, 401);
  assert.deepEqual(calls, ["pre"]);
});
