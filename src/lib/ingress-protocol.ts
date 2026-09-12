/** Runtime-neutral v1 ingress protocol shared by the signer and verifier. */

export const INGRESS_HEADER = "x-limitmark-ingress";
export const INGRESS_VERSION = "lm-ingress-v1";
export const INGRESS_ENVIRONMENT = "production";
export const INGRESS_IDENTITY_VERSION = "prod-ip-hmac-v1";
export const INGRESS_NO_NONCE = "-";
export const INGRESS_SIGNING_DOMAIN = "limitmark:ingress:ed25519:v1\0";
export const INGRESS_MAX_HEADER_BYTES = 2_048;
export const INGRESS_MAX_BODY_BYTES = 32_768;
export const INGRESS_FUTURE_SKEW_MS = 5_000;
export const INGRESS_MAX_AGE_MS = 30_000;
export const INGRESS_MUTATION_PATH = "/api/public-inquiries";
export const INGRESS_MUTATION_CONTENT_TYPE = "application/x-www-form-urlencoded";
export const INGRESS_BODY_ENCODING = "identity";
export const EMPTY_SHA256_BASE64URL = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

export const ingressFieldMaximums = {
  keyId: 32,
  audience: 96,
  deploymentId: 128,
  method: 8,
  scheme: 5,
  host: 253,
  path: 128,
  query: 256,
  contentType: 64,
  contentEncoding: 16,
  identityVersion: 32,
} as const;

export type IngressPayload = readonly [
  version: typeof INGRESS_VERSION,
  keyId: string,
  environment: typeof INGRESS_ENVIRONMENT,
  audience: string,
  deploymentId: string,
  issuedAtMs: number,
  method: string,
  scheme: "https",
  host: string,
  path: string,
  query: string,
  contentType: string,
  contentEncoding: typeof INGRESS_BODY_ENCODING,
  bodyLength: number,
  bodySha256: string,
  identityVersion: typeof INGRESS_IDENTITY_VERSION,
  clientPseudonym: string,
  nonce: string,
];

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const base64urlPattern = /^[A-Za-z0-9_-]+$/;

export class IngressProtocolError extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = "IngressProtocolError";
  }
}

export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}

function fail(code: string): never {
  throw new IngressProtocolError(code);
}

export function encodeBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

export function decodeCanonicalBase64url(value: string, expectedLength?: number): Uint8Array {
  if (!value || value.includes("=") || !base64urlPattern.test(value)) fail("base64url");
  if (value.length % 4 === 1) fail("base64url");
  let binary: string;
  try {
    binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4));
  } catch {
    fail("base64url");
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64url(bytes) !== value) fail("base64url-canonical");
  if (expectedLength !== undefined && bytes.length !== expectedLength) fail("byte-length");
  return bytes;
}

function boundedAscii(value: unknown, name: string, maximum: number, pattern: RegExp): asserts value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || !pattern.test(value)) fail(name);
}

function validatePayload(value: unknown): asserts value is IngressPayload {
  if (!Array.isArray(value) || value.length !== 18) fail("field-count");
  if (value[0] !== INGRESS_VERSION) fail("version");
  boundedAscii(value[1], "key-id", ingressFieldMaximums.keyId, /^[A-Za-z0-9_-]+$/);
  if (value[2] !== INGRESS_ENVIRONMENT) fail("environment");
  boundedAscii(value[3], "audience", ingressFieldMaximums.audience, /^[A-Za-z0-9_.:-]+$/);
  boundedAscii(value[4], "deployment", ingressFieldMaximums.deploymentId, /^[A-Za-z0-9_.:-]+$/);
  if (!Number.isSafeInteger(value[5]) || value[5] < 0) fail("issued-at");
  boundedAscii(value[6], "method", ingressFieldMaximums.method, /^(?:GET|HEAD|POST)$/);
  if (value[7] !== "https") fail("scheme");
  boundedAscii(value[8], "host", ingressFieldMaximums.host, /^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)$/);
  boundedAscii(value[9], "path", ingressFieldMaximums.path, /^\/[\x21-\x7e]*$/);
  if (typeof value[10] !== "string" || value[10].length > ingressFieldMaximums.query || /[\s#]/u.test(value[10])) fail("query");
  boundedAscii(value[11], "content-type", ingressFieldMaximums.contentType, /^[\x21-\x7e]+$/);
  if (value[12] !== INGRESS_BODY_ENCODING) fail("content-encoding");
  if (!Number.isSafeInteger(value[13]) || value[13] < 0 || value[13] > INGRESS_MAX_BODY_BYTES) fail("body-length");
  if (typeof value[14] !== "string") fail("body-digest");
  decodeCanonicalBase64url(value[14], 32);
  if (value[15] !== INGRESS_IDENTITY_VERSION) fail("identity-version");
  if (typeof value[16] !== "string") fail("identity");
  decodeCanonicalBase64url(value[16], 32);
  if (typeof value[17] !== "string") fail("nonce");
  if (value[17] !== INGRESS_NO_NONCE) decodeCanonicalBase64url(value[17], 16);

  if (value[6] === "POST") {
    if (value[8] !== "limitmark.com" || value[9] !== INGRESS_MUTATION_PATH || value[10] !== "" ||
        value[11] !== INGRESS_MUTATION_CONTENT_TYPE || value[17] === INGRESS_NO_NONCE) fail("mutation-policy");
  } else if (value[11] !== "-" || value[13] !== 0 || value[14] !== EMPTY_SHA256_BASE64URL || value[17] !== INGRESS_NO_NONCE) {
    fail("safe-read-policy");
  }
}

export function encodeIngressPayload(payload: IngressPayload): Uint8Array {
  validatePayload(payload);
  return encoder.encode(JSON.stringify(payload));
}

export function decodeIngressPayload(bytes: Uint8Array): IngressPayload {
  let text: string;
  try {
    text = decoder.decode(bytes);
  } catch {
    fail("utf8");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail("json");
  }
  validatePayload(parsed);
  if (JSON.stringify(parsed) !== text) fail("payload-canonical");
  return parsed;
}

export function signingInput(payloadBytes: Uint8Array): Uint8Array {
  const domain = encoder.encode(INGRESS_SIGNING_DOMAIN);
  const result = new Uint8Array(domain.length + payloadBytes.length);
  result.set(domain);
  result.set(payloadBytes, domain.length);
  return result;
}

export async function createIngressEnvelope(payload: IngressPayload, privateKey: CryptoKey, subtle: SubtleCrypto = crypto.subtle): Promise<string> {
  const payloadBytes = encodeIngressPayload(payload);
  const signature = new Uint8Array(await subtle.sign("Ed25519", privateKey, toArrayBuffer(signingInput(payloadBytes))));
  if (signature.length !== 64) fail("signature-length");
  const header = `${encodeBase64url(payloadBytes)}.${encodeBase64url(signature)}`;
  if (header.length > INGRESS_MAX_HEADER_BYTES) fail("header-length");
  return header;
}

export function splitIngressEnvelope(header: string): { payloadBytes: Uint8Array; payload: IngressPayload; signature: Uint8Array } {
  if (!header || header.length > INGRESS_MAX_HEADER_BYTES || header.trim() !== header || header.includes(",")) fail("header");
  const parts = header.split(".");
  if (parts.length !== 2) fail("envelope");
  const payloadBytes = decodeCanonicalBase64url(parts[0]);
  const signature = decodeCanonicalBase64url(parts[1], 64);
  return { payloadBytes, payload: decodeIngressPayload(payloadBytes), signature };
}

export async function verifyIngressEnvelope(header: string, publicKeys: ReadonlyMap<string, CryptoKey>, subtle: SubtleCrypto = crypto.subtle) {
  const decoded = splitIngressEnvelope(header);
  const key = publicKeys.get(decoded.payload[1]);
  if (!key) fail("key-id");
  const valid = await subtle.verify("Ed25519", key, toArrayBuffer(decoded.signature), toArrayBuffer(signingInput(decoded.payloadBytes)));
  if (!valid) fail("signature");
  return decoded;
}

export async function sha256Base64url(bytes: Uint8Array, subtle: SubtleCrypto = crypto.subtle): Promise<string> {
  return encodeBase64url(new Uint8Array(await subtle.digest("SHA-256", toArrayBuffer(bytes))));
}

export function assertIngressFresh(issuedAtMs: number, nowMs: number): void {
  if (!Number.isSafeInteger(nowMs) || issuedAtMs > nowMs + INGRESS_FUTURE_SKEW_MS) fail("future");
  if (issuedAtMs < nowMs - INGRESS_MAX_AGE_MS) fail("stale");
}
