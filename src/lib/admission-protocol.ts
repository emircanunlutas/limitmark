import { decodeCanonicalBase64url, encodeBase64url, toArrayBuffer } from "./ingress-protocol";

export const ADMISSION_RPC_VERSION = "lm-admission-rpc-v1";
export const ADMISSION_MAC_HEADER = "x-limitmark-admission-mac";
export const ADMISSION_KEY_ID_HEADER = "x-limitmark-admission-key-id";
export const ADMISSION_MAX_BODY_BYTES = 2_048;
export const ADMISSION_RPC_MAX_SKEW_MS = 5_000;
export const ADMISSION_PRE_PATH = "/v1/pre";
export const ADMISSION_POST_PATH = "/v1/post";
export const ADMISSION_RPC_CONTENT_TYPE = "application/json";

export type AdmissionRpcPayload = readonly [
  version: typeof ADMISSION_RPC_VERSION,
  releaseId: string,
  operationId: string,
  issuedAtMs: number,
  clientPseudonym: string,
  requestBinding: string,
  nonce: string,
  permit: string,
  ingressIssuedAtMs: number,
];

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function validate(payload: unknown): asserts payload is AdmissionRpcPayload {
  if (!Array.isArray(payload) || payload.length !== 9 || payload[0] !== ADMISSION_RPC_VERSION) throw new Error("rpc-shape");
  if (typeof payload[1] !== "string" || !/^[A-Za-z0-9_.:-]{1,128}$/.test(payload[1])) throw new Error("rpc-release");
  if (typeof payload[2] !== "string") throw new Error("rpc-operation");
  decodeCanonicalBase64url(payload[2], 16);
  if (!Number.isSafeInteger(payload[3]) || payload[3] < 0) throw new Error("rpc-time");
  for (const index of [4, 5] as const) {
    if (typeof payload[index] !== "string") throw new Error("rpc-binding");
    decodeCanonicalBase64url(payload[index], 32);
  }
  if (typeof payload[6] !== "string") throw new Error("rpc-nonce");
  decodeCanonicalBase64url(payload[6], 16);
  if (typeof payload[7] !== "string" || payload[7] !== "-" && (() => { try { decodeCanonicalBase64url(payload[7], 32); return false; } catch { return true; } })()) throw new Error("rpc-permit");
  if (!Number.isSafeInteger(payload[8]) || payload[8] < 0) throw new Error("rpc-ingress-time");
}

export function encodeAdmissionRpcPayload(payload: AdmissionRpcPayload): Uint8Array {
  validate(payload);
  const bytes = encoder.encode(JSON.stringify(payload));
  if (bytes.length > ADMISSION_MAX_BODY_BYTES) throw new Error("rpc-size");
  return bytes;
}

export function decodeAdmissionRpcPayload(bytes: Uint8Array): AdmissionRpcPayload {
  if (bytes.length < 1 || bytes.length > ADMISSION_MAX_BODY_BYTES) throw new Error("rpc-size");
  let text: string;
  try { text = decoder.decode(bytes); } catch { throw new Error("rpc-utf8"); }
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { throw new Error("rpc-json"); }
  validate(parsed);
  if (JSON.stringify(parsed) !== text) throw new Error("rpc-canonical");
  return parsed;
}

function macInput(path: string, body: Uint8Array): Uint8Array {
  if (path !== ADMISSION_PRE_PATH && path !== ADMISSION_POST_PATH) throw new Error("rpc-path");
  const prefix = encoder.encode(`limitmark:admission:rpc-mac:v1\0${path}\0`);
  const result = new Uint8Array(prefix.length + body.length);
  result.set(prefix); result.set(body, prefix.length);
  return result;
}

export async function importAdmissionRpcKey(base64url: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toArrayBuffer(decodeCanonicalBase64url(base64url, 32)), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function signAdmissionRpc(path: string, body: Uint8Array, key: CryptoKey): Promise<string> {
  return encodeBase64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, toArrayBuffer(macInput(path, body)))));
}

export async function verifyAdmissionRpcMac(path: string, body: Uint8Array, value: string, key: CryptoKey): Promise<boolean> {
  let signature: Uint8Array;
  try { signature = decodeCanonicalBase64url(value, 32); } catch { return false; }
  return crypto.subtle.verify("HMAC", key, toArrayBuffer(signature), toArrayBuffer(macInput(path, body)));
}
