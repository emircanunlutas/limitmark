import {
  INGRESS_BODY_ENCODING,
  INGRESS_ENVIRONMENT,
  INGRESS_HEADER,
  INGRESS_IDENTITY_VERSION,
  INGRESS_MAX_BODY_BYTES,
  INGRESS_MAX_HEADER_BYTES,
  INGRESS_MUTATION_CONTENT_TYPE,
  INGRESS_MUTATION_PATH,
  INGRESS_NO_NONCE,
  INGRESS_VERSION,
  createIngressEnvelope,
  decodeCanonicalBase64url,
  encodeBase64url,
  sha256Base64url,
  toArrayBuffer,
  type IngressPayload,
} from "../../src/lib/ingress-protocol";
import { CLOUDFLARE_CLIENT_IP_HEADER, deriveClientPseudonym } from "./identity";

export type IngressSignerConfiguration = {
  environment: "production";
  publicHosts: readonly ["limitmark.com", "www.limitmark.com"];
  targetOrigin: "https://limitmark.com";
  audience: string;
  deploymentId: string;
  keyId: string;
  signingPrivateKeyPkcs8: string;
  identityHmacKey: string;
  originSecret: string;
  vercelBypassSecret: string;
};

const strippedHeaders = new Set([
  INGRESS_HEADER, "x-limitmark-client", "x-limitmark-origin-secret", "authorization",
  "proxy-authorization", "x-internal-service-auth", "x-admission-oidc", "x-admission-rpc",
  "x-vercel-protection-bypass", "x-vercel-set-bypass-cookie", "x-vercel-deployment-url",
  "x-matched-path", "x-now-route-matches", "x-forwarded-for", "x-real-ip", "true-client-ip",
  "cf-connecting-ip", "cf-connecting-ipv6", "cf-pseudo-ipv4", "forwarded",
  "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port", "host",
]);
const reservedQuery = new Set(["x-vercel-protection-bypass", "x-vercel-set-bypass-cookie", "__vercel_protection_bypass"]);

async function readBoundedBody(request: Request): Promise<Uint8Array> {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      length += item.value.length;
      if (length > INGRESS_MAX_BODY_BYTES) throw new Error("body-overflow");
      chunks.push(item.value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
  return body;
}

function sanitizeHeaders(input: Headers): Headers {
  const output = new Headers();
  input.forEach((value, name) => {
    const lower = name.toLowerCase();
    if (!strippedHeaders.has(lower) && !lower.startsWith("x-limitmark-internal-") && !lower.startsWith("x-vercel-")) output.append(lower, value);
  });
  return output;
}

async function importSigningKey(value: string, subtle: SubtleCrypto): Promise<CryptoKey> {
  return subtle.importKey("pkcs8", toArrayBuffer(decodeCanonicalBase64url(value)), { name: "Ed25519" }, false, ["sign"]);
}

export function createIngressSigner(configuration: IngressSignerConfiguration, dependencies: {
  fetch?: typeof fetch;
  now?: () => number;
  random?: (bytes: Uint8Array) => Uint8Array;
  subtle?: SubtleCrypto;
} = {}) {
  const requestFetch = dependencies.fetch ?? fetch;
  const now = dependencies.now ?? Date.now;
  const random = dependencies.random ?? ((bytes: Uint8Array) => crypto.getRandomValues(bytes));
  const subtle = dependencies.subtle ?? crypto.subtle;

  return async function handle(request: Request): Promise<Response> {
    try {
      if (configuration.environment !== "production" || configuration.targetOrigin !== "https://limitmark.com") return new Response(null, { status: 503 });
      if (new Set([configuration.signingPrivateKeyPkcs8, configuration.identityHmacKey, configuration.originSecret, configuration.vercelBypassSecret]).size !== 4) return new Response(null, { status: 503 });
      const approvedOrigin = new URL(configuration.targetOrigin);
      if (approvedOrigin.origin !== configuration.targetOrigin || approvedOrigin.pathname !== "/" || approvedOrigin.search || approvedOrigin.hash ||
          approvedOrigin.username || approvedOrigin.password || approvedOrigin.port) return new Response(null, { status: 503 });
      const url = new URL(request.url);
      if (url.protocol !== "https:" || !configuration.publicHosts.includes(url.hostname as never) || url.port || url.username || url.password) return new Response(null, { status: 404 });
      for (const name of reservedQuery) if (url.searchParams.has(name)) return new Response(null, { status: 404 });
      if (url.hostname === "www.limitmark.com" && (request.method === "GET" || request.method === "HEAD")) {
        return new Response(null, { status: 308, headers: { location: `https://limitmark.com${url.pathname}${url.search}` } });
      }
      if (request.headers.has("cf-worker") || request.headers.has("cf-ew-via")) return new Response(null, { status: 403 });
      if (request.method === "POST" && (url.hostname !== "limitmark.com" || url.pathname !== INGRESS_MUTATION_PATH || url.search !== "")) return new Response(null, { status: 404 });
      if (request.method !== "POST" && request.method !== "GET" && request.method !== "HEAD") return new Response(null, { status: 405 });
      if (request.method === "POST" && request.headers.get("content-type") !== INGRESS_MUTATION_CONTENT_TYPE) return new Response(null, { status: 415 });
      const contentEncoding = request.headers.get("content-encoding");
      if (contentEncoding !== null && contentEncoding !== "identity") return new Response(null, { status: 415 });

      const pseudonym = await deriveClientPseudonym(request.headers.get(CLOUDFLARE_CLIENT_IP_HEADER), configuration.identityHmacKey, subtle);
      if (!pseudonym) return new Response(null, { status: 403 });
      const body = request.method === "POST" ? await readBoundedBody(request) : new Uint8Array();
      const claimedLength = request.headers.get("content-length");
      if (claimedLength !== null && (!/^(?:0|[1-9][0-9]*)$/.test(claimedLength) || Number(claimedLength) !== body.length)) return new Response(null, { status: 400 });
      const nonce = request.method === "POST" ? encodeBase64url(random(new Uint8Array(16))) : INGRESS_NO_NONCE;
      const payload: IngressPayload = [
        INGRESS_VERSION, configuration.keyId, INGRESS_ENVIRONMENT, configuration.audience, configuration.deploymentId,
        now(), request.method, "https", url.hostname, url.pathname, url.search.slice(1),
        request.method === "POST" ? INGRESS_MUTATION_CONTENT_TYPE : "-", INGRESS_BODY_ENCODING,
        body.length, await sha256Base64url(body, subtle), INGRESS_IDENTITY_VERSION, pseudonym, nonce,
      ];
      const envelope = await createIngressEnvelope(payload, await importSigningKey(configuration.signingPrivateKeyPkcs8, subtle), subtle);
      if (envelope.length > INGRESS_MAX_HEADER_BYTES) return new Response(null, { status: 503 });
      const headers = sanitizeHeaders(request.headers);
      headers.set(INGRESS_HEADER, envelope);
      headers.set("x-limitmark-origin-secret", configuration.originSecret);
      headers.set("x-vercel-protection-bypass", configuration.vercelBypassSecret);
      headers.set("host", approvedOrigin.hostname);
      if (request.method === "POST") {
        headers.set("content-type", INGRESS_MUTATION_CONTENT_TYPE);
        headers.set("content-encoding", INGRESS_BODY_ENCODING);
        headers.set("content-length", String(body.length));
      } else {
        headers.delete("content-length");
        headers.delete("content-type");
        headers.delete("content-encoding");
      }
      const target = new URL(configuration.targetOrigin);
      target.pathname = url.pathname;
      target.search = url.search;
      if (target.origin !== approvedOrigin.origin || target.username || target.password || target.port || target.hostname !== approvedOrigin.hostname) {
        return new Response(null, { status: 503 });
      }
      const response = await requestFetch(target, { method: request.method, headers, body: request.method === "POST" ? toArrayBuffer(body) : undefined, redirect: "manual" });
      // Never reflect internal request credentials or attestation.
      const responseHeaders = new Headers(response.headers);
      for (const name of strippedHeaders) responseHeaders.delete(name);
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders });
    } catch {
      return new Response(null, { status: 503 });
    }
  };
}
