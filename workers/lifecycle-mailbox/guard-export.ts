import { decodeCanonicalBase64url, encodeBase64url, toArrayBuffer } from "../../src/lib/ingress-protocol";
import { parseStrictJson } from "../../operator/lifecycle-submitter";

/**
 * Authenticated, read-only guard ledger export: the REQUEST side. The request is an operator-signed (same Ed25519 operator key the guard already
 * pins as AUTHORITY_OPERATOR_PUBLIC_KEY) statement bound to ONE environment, ONE Authority identity, ONE guard object, ONE Cloudflare account and ONE
 * nonce, valid for a short window. It is domain-separated from lifecycle commands: its signed bytes start with a distinct text prefix, whereas
 * every lifecycle command is signed over bare JSON starting with "[", so a signature for one can never verify as the other.
 *
 * Nothing here can mutate anything. A replayed request inside its window can only re-read the same read-only ledger; results are published
 * under the request nonce and never overwritten.
 */
export const GUARD_EXPORT_REQUEST_VERSION = "limitmark-guard-export-request-v1";
export const GUARD_EXPORT_OPERATION = "export-guard-ledger";
export const GUARD_EXPORT_SLOT = "export-ledger.json";
export const GUARD_EXPORT_REQUEST_LIMIT = 2_048;
/** Validity window around `issuedAtMs`, checked at the guard's clock AFTER the awaited signature verification. */
export const GUARD_EXPORT_FRESHNESS_MS = 120_000;
/** Bounded response: rows per table. A larger ledger answers TOO_LARGE with counts only (never a silently truncated list). */
export const GUARD_EXPORT_ROW_LIMIT = 24;
const DOMAIN = "limitmark-guard-export-request-domain-v1\n";

export type GuardExportRequest = readonly [
  version: typeof GUARD_EXPORT_REQUEST_VERSION,
  operation: typeof GUARD_EXPORT_OPERATION,
  environment: string,
  authorityId: string,
  guardObject: string,
  accountId: string,
  nonce: string,
  issuedAtMs: number,
];
export type GuardExportEnvelope = { request: GuardExportRequest; signature: string };

const nonceShape = /^[a-f0-9]{32}$/u;
const accountShape = /^[a-f0-9]{32}$/u;
const identityShape = /^[A-Za-z0-9_.:-]{1,128}$/u;

/** Shape-only validation (no identity comparison; the guard compares against its own pinned identity). */
export function canonicalGuardExportRequestBytes(request: GuardExportRequest): Uint8Array {
  if (!Array.isArray(request) || request.length !== 8 || request[0] !== GUARD_EXPORT_REQUEST_VERSION || request[1] !== GUARD_EXPORT_OPERATION ||
      typeof request[2] !== "string" || !identityShape.test(request[2]) || typeof request[3] !== "string" || !identityShape.test(request[3]) ||
      typeof request[4] !== "string" || !identityShape.test(request[4]) || typeof request[5] !== "string" || !accountShape.test(request[5]) ||
      typeof request[6] !== "string" || !nonceShape.test(request[6]) || !Number.isSafeInteger(request[7]) || request[7] < 0) throw new Error("export-request");
  return new TextEncoder().encode(DOMAIN + JSON.stringify(request));
}

export async function signGuardExportRequest(request: GuardExportRequest, privateKeyPkcs8: string): Promise<string> {
  const key = await crypto.subtle.importKey("pkcs8", toArrayBuffer(decodeCanonicalBase64url(privateKeyPkcs8)), { name: "Ed25519" }, false, ["sign"]);
  return encodeBase64url(new Uint8Array(await crypto.subtle.sign("Ed25519", key, toArrayBuffer(canonicalGuardExportRequestBytes(request)))));
}

export async function verifyGuardExportRequest(request: GuardExportRequest, signature: string, operatorPublicKey: string): Promise<void> {
  const key = await crypto.subtle.importKey("raw", toArrayBuffer(decodeCanonicalBase64url(operatorPublicKey, 32)), { name: "Ed25519" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("Ed25519", key, toArrayBuffer(decodeCanonicalBase64url(signature, 64)), toArrayBuffer(canonicalGuardExportRequestBytes(request)));
  if (!valid) throw new Error("export-signature");
}

/** Domain-separated identity of the exact signed bytes. */
export async function guardExportRequestDigest(request: GuardExportRequest): Promise<string> {
  const bytes = canonicalGuardExportRequestBytes(request);
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes))), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Strict envelope parsing: exactly {request, signature}, bounded, no BOM, strict JSON (duplicate keys refused by the shared parser). */
export function parseGuardExportEnvelope(source: string): GuardExportEnvelope {
  if (typeof source !== "string" || source.length === 0 || source.length > GUARD_EXPORT_REQUEST_LIMIT || source.charCodeAt(0) === 0xfeff) throw new Error("export-envelope");
  const value = parseStrictJson(source);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("export-envelope");
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 2 || !keys.includes("request") || !keys.includes("signature") || typeof record.signature !== "string" || !Array.isArray(record.request)) throw new Error("export-envelope");
  const request = record.request as unknown as GuardExportRequest;
  canonicalGuardExportRequestBytes(request);
  return { request, signature: record.signature };
}

// ------------------------------------------------------------------------------------------------------------------------- RESPONSE side

export type GuardExportLedger = {
  claims: Array<{ digest: string; operation: string; status: string }>;
  latch: { digest: string } | null;
  settlements: Array<{ digest: string; sequence: number; settledMs: number }>;
};
export type GuardExportRefusalReason = "configuration" | "unauthenticated" | "target-mismatch" | "stale-request" | "read-failed";
export type GuardExportOutcome =
  | { version: 1; status: "EXPORTED"; requestDigest: string; nonce: string; accountId: string; guardObject: string; authorityId: string; environment: string;
      observedAtMs: number; ledger: GuardExportLedger }
  | { version: 1; status: "TOO_LARGE"; requestDigest: string; nonce: string; counts: { claims: number; settlements: number }; observedAtMs: number }
  /** `nonce`/`requestDigest` are present ONLY when the signature verified (authenticated but ineligible). Unauthenticated requests carry neither. */
  | { version: 1; status: "REFUSED"; reason: GuardExportRefusalReason; nonce?: string; requestDigest?: string };
