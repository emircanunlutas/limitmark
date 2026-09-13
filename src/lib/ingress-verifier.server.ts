import "server-only";

import {
  INGRESS_BODY_ENCODING,
  INGRESS_ENVIRONMENT,
  INGRESS_HEADER,
  INGRESS_IDENTITY_VERSION,
  INGRESS_MUTATION_CONTENT_TYPE,
  INGRESS_MUTATION_PATH,
  assertIngressFresh,
  decodeCanonicalBase64url,
  encodeBase64url,
  sha256Base64url,
  verifyIngressEnvelope,
  toArrayBuffer,
} from "./ingress-protocol";
import { importActiveIngressSigningKeys } from "./ingress-key-rollout";

export type IngressVerificationPolicy = {
  audience: string;
  deploymentId: string;
  publicKeys: ReadonlyMap<string, CryptoKey>;
  requestBindingKey: CryptoKey;
  now?: () => number;
};

export type VerifiedMutationIngress = {
  clientPseudonym: string;
  nonce: string;
  requestBinding: string;
  releaseId: string;
  issuedAtMs: number;
  keyId: string;
};

export async function importIngressPublicKeys(serializedRollout: string, nowMs = Date.now()): Promise<ReadonlyMap<string, CryptoKey>> {
  return importActiveIngressSigningKeys(serializedRollout, nowMs);
}

export async function importRequestBindingKey(rawBase64url: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toArrayBuffer(decodeCanonicalBase64url(rawBase64url, 32)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

export async function verifyMutationIngress(request: Request, body: Uint8Array, policy: IngressVerificationPolicy): Promise<VerifiedMutationIngress> {
  const header = request.headers.get(INGRESS_HEADER);
  if (header === null) throw new Error("ingress-missing");
  const { payload, payloadBytes } = await verifyIngressEnvelope(header, policy.publicKeys);
  const url = new URL(request.url);
  const forwardedHost = request.headers.get("x-forwarded-host");
  const contentLength = request.headers.get("content-length");
  if (payload[2] !== INGRESS_ENVIRONMENT || payload[3] !== policy.audience || payload[4] !== policy.deploymentId) throw new Error("ingress-audience");
  assertIngressFresh(payload[5], (policy.now ?? Date.now)());
  if (request.method !== "POST" || payload[6] !== request.method) throw new Error("ingress-method");
  if (url.protocol !== "https:" || payload[7] !== "https") throw new Error("ingress-scheme");
  if (url.hostname !== "limitmark.com" || url.port || payload[8] !== url.hostname || request.headers.get("host") !== "limitmark.com" || forwardedHost !== "limitmark.com") throw new Error("ingress-host");
  if (url.pathname !== INGRESS_MUTATION_PATH || payload[9] !== url.pathname) throw new Error("ingress-path");
  if (url.search !== "" || payload[10] !== "") throw new Error("ingress-query");
  if (request.headers.get("content-type") !== INGRESS_MUTATION_CONTENT_TYPE || payload[11] !== INGRESS_MUTATION_CONTENT_TYPE) throw new Error("ingress-content-type");
  if (request.headers.get("content-encoding") !== INGRESS_BODY_ENCODING || payload[12] !== INGRESS_BODY_ENCODING) throw new Error("ingress-content-encoding");
  if (contentLength !== null && (!/^(?:0|[1-9][0-9]*)$/.test(contentLength) || Number(contentLength) !== body.length)) throw new Error("ingress-content-length");
  if (payload[13] !== body.length) throw new Error("ingress-body-length");
  if (payload[14] !== await sha256Base64url(body)) throw new Error("ingress-body-digest");
  if (payload[15] !== INGRESS_IDENTITY_VERSION) throw new Error("ingress-identity-version");
  decodeCanonicalBase64url(payload[16], 32);
  decodeCanonicalBase64url(payload[17], 16);
  const bindingDomain = new TextEncoder().encode("limitmark:request-binding:v1\0");
  const bindingInput = new Uint8Array(bindingDomain.length + payloadBytes.length);
  bindingInput.set(bindingDomain);
  bindingInput.set(payloadBytes, bindingDomain.length);
  const requestBinding = encodeBase64url(new Uint8Array(await crypto.subtle.sign("HMAC", policy.requestBindingKey, toArrayBuffer(bindingInput))));
  return { clientPseudonym: payload[16], nonce: payload[17], requestBinding, releaseId: policy.deploymentId, issuedAtMs: payload[5], keyId: payload[1] };
}
