/**
 * Slice 2: the two cryptographically distinct hop proofs.
 *
 *   PB  Plane -> Boundary   role "ba0-pb-v2"  domain "ba0:pb:ed25519:v2\0"  key K_P  kid "pb-..."  audience boundaryId  lifetime <= 5 s
 *   BA  Boundary -> App     role "ba0-ba-v2"  domain "ba0:ba:ed25519:v2\0"  key K_B  kid "ba-..."  audience appId       lifetime <= 2 s
 *
 * Both are `b64url(payload) "." b64url(sig64)` over a canonical JSON array, signed with Ed25519 over `domain || payload`. A BA carries the
 * Plane's PB (verbatim, in a second header) as LINEAGE evidence and commits to it by hash, so the App can check that the request was
 * approved by the Plane, not merely attested by the Boundary. Role string, signing domain, key pair, kid prefix, audience, header name,
 * replay set and lifetime all differ between the hops; each difference is independently sufficient to reject cross-hop use.
 *
 * Issuing authority is capability-shaped: `issuePb` accepts only an ApprovedRequest (minted by semantic-request.ts after the layer
 * approved it) and `issueBa` only a VerifiedPb (sealed by hop-admission.ts after a PB fully verified). There is no function in
 * defense/ that signs caller-chosen facts: test-only minting lives under lab/ and encodes independently. Key custody is the real control;
 * the capability check prevents accidental misuse and is pinned by a static test.
 *
 * Pure apart from the CSPRNG and the clock the caller passes in. Imports only node:crypto and its siblings.
 */
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";
import type { ObReason } from "./types";
import {
  BOUND_HEADER_NAMES, EMPTY_BODY_SHA256, FORM_CONTENT_TYPE, MAX_SEMANTIC_BODY, canonicalValue, isApprovedRequest, sha256B64,
  type ApprovedRequest, type HeaderPair,
} from "./semantic-request";

export type HopRole = "pb" | "ba";
export const PB_ROLE = "ba0-pb-v2";
export const BA_ROLE = "ba0-ba-v2";
export const PB_DOMAIN = "ba0:pb:ed25519:v2\0";
export const BA_DOMAIN = "ba0:ba:ed25519:v2\0";
export const PB_MAX_LIFETIME_MS = 5_000;
export const BA_MAX_LIFETIME_MS = 2_000;
export const HOP_SKEW_MS = 1_000;
export const PB_HEADER_MAX = 2_048;
export const BA_HEADER_MAX = 2_304;

const ROLE_STRING: Readonly<Record<HopRole, string>> = { pb: PB_ROLE, ba: BA_ROLE };
const DOMAIN: Readonly<Record<HopRole, string>> = { pb: PB_DOMAIN, ba: BA_DOMAIN };
const MAX_LIFETIME: Readonly<Record<HopRole, number>> = { pb: PB_MAX_LIFETIME_MS, ba: BA_MAX_LIFETIME_MS };
const HEADER_MAX: Readonly<Record<HopRole, number>> = { pb: PB_HEADER_MAX, ba: BA_HEADER_MAX };

export type RequestClaims = {
  method: "GET" | "POST";
  target: string;
  pairs: HeaderPair[];
  bodyLen: number;
  bodySha256: string;
};
type Common = { kid: string; aud: string; iat: number; exp: number; jti: string; hop: number; corr: string; request: RequestClaims };
export type PbClaims = Common & { role: "pb" };
export type BaClaims = Common & { role: "ba"; pbJti: string; pbSha256: string };
export type Claims = PbClaims | BaClaims;

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

const B64URL = /^[A-Za-z0-9_-]+$/;
const ID22 = /^[A-Za-z0-9_-]{22}$/;
const KID = /^[A-Za-z0-9_-]{1,32}$/;
const TARGET = /^\/[\x21-\x7e]{0,255}$/;

/** Canonical base64url only: anything that would not re-encode to the same text is refused. */
export function decodeCanonicalB64(value: string, expectedLength?: number): Buffer | null {
  if (!value || !B64URL.test(value) || value.length % 4 === 1) return null;
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) return null;
  return expectedLength !== undefined && bytes.length !== expectedLength ? null : bytes;
}

export const newId = (): string => randomBytes(16).toString("base64url");
/** The only form in which a jti ever appears in an event or in evidence: 16 characters of a role-separated hash. */
export const proofTag = (role: HopRole | "ln", jti: string): string => createHash("sha256").update(`${role}:${jti}`).digest("base64url").slice(0, 16);

export function importPublicKey(spkiB64: string): KeyObject {
  const der = decodeCanonicalB64(spkiB64);
  if (der === null) throw new Error("public key is not canonical base64url");
  return createPublicKey({ key: der, format: "der", type: "spki" });
}
export function importPrivateKey(pkcs8B64: string): KeyObject {
  const der = decodeCanonicalB64(pkcs8B64);
  if (der === null) throw new Error("private key is not canonical base64url");
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function claimsPayload(claims: Claims): unknown[] {
  const request = claims.request;
  const head = [ROLE_STRING[claims.role], claims.kid, claims.aud, claims.iat, claims.exp, claims.jti, claims.hop, claims.corr, request.method, request.target, request.pairs, request.bodyLen, request.bodySha256];
  return claims.role === "ba" ? [...head, claims.pbJti, claims.pbSha256] : head;
}

function encodeEnvelope(role: HopRole, claims: Claims, privateKey: KeyObject): string {
  const payload = Buffer.from(JSON.stringify(claimsPayload(claims)), "utf8");
  const signature = edSign(null, Buffer.concat([Buffer.from(DOMAIN[role], "utf8"), payload]), privateKey);
  return `${payload.toString("base64url")}.${signature.toString("base64url")}`;
}

// ---------------------------------------------------------------------------
// Decoding (structure only: no key, no clock)
// ---------------------------------------------------------------------------

export type Decoded = { claims: Claims; payload: Buffer; signature: Buffer };
export type DecodeResult = { ok: true; value: Decoded } | { ok: false; reason: ObReason };

const isInt = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const isString = (value: unknown): value is string => typeof value === "string";

function parseRequest(raw: unknown[]): RequestClaims | null {
  const [method, target, pairsRaw, bodyLen, bodySha256] = raw;
  if (method !== "GET" && method !== "POST") return null;
  if (!isString(target) || !TARGET.test(target)) return null;
  if (!Array.isArray(pairsRaw) || pairsRaw.length > BOUND_HEADER_NAMES.length) return null;
  const pairs: HeaderPair[] = [];
  let previous = "";
  for (const pair of pairsRaw) {
    if (!Array.isArray(pair) || pair.length !== 2 || !isString(pair[0]) || !isString(pair[1])) return null;
    if (!(BOUND_HEADER_NAMES as readonly string[]).includes(pair[0]) || pair[0] <= previous || canonicalValue(pair[1]) !== pair[1]) return null;
    previous = pair[0];
    pairs.push([pair[0], pair[1]] as const);
  }
  if (!isInt(bodyLen) || bodyLen > MAX_SEMANTIC_BODY || !isString(bodySha256) || decodeCanonicalB64(bodySha256, 32) === null) return null;
  const has = (name: string) => pairs.find(([key]) => key === name)?.[1];
  if (has("host") === undefined) return null;
  if (method === "GET" && (bodyLen !== 0 || bodySha256 !== EMPTY_BODY_SHA256 || has("content-type") !== undefined)) return null;
  if (method === "POST" && has("content-type") !== FORM_CONTENT_TYPE) return null;
  return { method, target, pairs, bodyLen, bodySha256 };
}

/**
 * Strict structural decode. Reason precedence: oversize, malformed, then role (the OTHER hop's role string is `ob.wrong_hop`, an unknown
 * one `ob.version_unsupported`). A re-serialisation that is not byte-identical to the signed text is malformed.
 */
export function decodeProof(header: string, expected: HopRole): DecodeResult {
  const fail = (reason: ObReason): DecodeResult => ({ ok: false, reason });
  if (header.length > HEADER_MAX[expected]) return fail("ob.proof_oversize");
  if (header.length === 0 || header.trim() !== header || header.includes(",")) return fail("ob.proof_malformed");
  const parts = header.split(".");
  if (parts.length !== 2) return fail("ob.proof_malformed");
  const payload = decodeCanonicalB64(parts[0]);
  const signature = decodeCanonicalB64(parts[1], 64);
  if (payload === null || signature === null) return fail("ob.proof_malformed");
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(payload); } catch { return fail("ob.proof_malformed"); }
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { return fail("ob.proof_malformed"); }
  if (!Array.isArray(parsed) || JSON.stringify(parsed) !== text) return fail("ob.proof_malformed");
  const roleString = parsed[0];
  if (roleString !== PB_ROLE && roleString !== BA_ROLE) return fail(isString(roleString) && roleString.startsWith("ba0-") ? "ob.version_unsupported" : "ob.proof_malformed");
  if (roleString !== ROLE_STRING[expected]) return fail("ob.wrong_hop");
  if (parsed.length !== (expected === "pb" ? 13 : 15)) return fail("ob.proof_malformed");
  const [, kid, aud, iat, exp, jti, hop, corr] = parsed;
  if (!isString(kid) || !KID.test(kid) || !isString(aud) || !ID22.test(aud) || !isInt(iat) || !isInt(exp) || !isString(jti) || !ID22.test(jti)) return fail("ob.proof_malformed");
  if (!isInt(hop) || hop < 1 || !isString(corr) || !ID22.test(corr)) return fail("ob.proof_malformed");
  const request = parseRequest(parsed.slice(8, 13));
  if (request === null) return fail("ob.proof_malformed");
  const common: Common = { kid, aud, iat, exp, jti, hop, corr, request };
  if (expected === "pb") return { ok: true, value: { claims: { role: "pb", ...common }, payload, signature } };
  const [pbJti, pbSha256] = [parsed[13], parsed[14]];
  if (!isString(pbJti) || !ID22.test(pbJti) || !isString(pbSha256) || decodeCanonicalB64(pbSha256, 32) === null) return fail("ob.proof_malformed");
  return { ok: true, value: { claims: { role: "ba", ...common, pbJti, pbSha256 }, payload, signature } };
}

// ---------------------------------------------------------------------------
// Window and signature
// ---------------------------------------------------------------------------

export type WindowContext = {
  /** The keys this verifier accepts for the role, by kid. A verifier is constructed with exactly the keys it needs. */
  keys: ReadonlyMap<string, KeyObject>;
  aud: string;
  nowMs: number;
  /** The verifier's own start (wall clock): a proof issued before it can only be a replay across a restart. */
  fenceMs: number;
};

/** kid, audience, lifetime shape, freshness, then the start fence. Null when the proof is acceptable (signature is checked separately). */
export function checkProofWindow(claims: Claims, context: WindowContext): ObReason | null {
  if (!context.keys.has(claims.kid)) return "ob.key_unknown";
  if (claims.aud !== context.aud) return "ob.audience_mismatch";
  if (claims.exp <= claims.iat || claims.exp - claims.iat > MAX_LIFETIME[claims.role]) return "ob.lifetime_invalid";
  if (claims.iat - HOP_SKEW_MS > context.nowMs) return "ob.not_yet_valid";
  if (context.nowMs > claims.exp + HOP_SKEW_MS) return "ob.expired";
  if (claims.iat < context.fenceMs) return "ob.before_fence";
  return null;
}

export function verifyProofSignature(role: HopRole, decoded: Decoded, key: KeyObject): boolean {
  try { return edVerify(null, Buffer.concat([Buffer.from(DOMAIN[role], "utf8"), decoded.payload]), key, decoded.signature); } catch { return false; }
}

// ---------------------------------------------------------------------------
// Capabilities and issuers
// ---------------------------------------------------------------------------

/** A Plane-to-Boundary proof that passed every check at a verifier, with the exact header it arrived in. Sealed by hop-admission only. */
export type VerifiedPb = { readonly claims: PbClaims; readonly header: string; readonly verifiedPb: true };
const verifiedRegistry = new WeakSet<object>();
export const isVerifiedPb = (value: unknown): value is VerifiedPb => typeof value === "object" && value !== null && verifiedRegistry.has(value);
/** Internal to hop-admission.ts (a static test pins every call site). Not an issuing path: it signs nothing. */
export function sealVerifiedPb(claims: PbClaims, header: string): VerifiedPb {
  const sealed = Object.freeze({ claims, header, verifiedPb: true as const });
  verifiedRegistry.add(sealed);
  return sealed;
}

export type Issued = { header: string; jti: string; tag: string };

export type PbIssuerConfig = { kid: string; privateKey: KeyObject; boundaryId: string; lifetimeMs: number; now: () => number };
export function issuePb(config: PbIssuerConfig, approved: ApprovedRequest, context: { hop: number; corr: string }): Issued {
  if (!isApprovedRequest(approved)) throw new Error("a Plane-to-Boundary proof can only be issued for an ApprovedRequest");
  if (!Number.isSafeInteger(config.lifetimeMs) || config.lifetimeMs < 1 || config.lifetimeMs > PB_MAX_LIFETIME_MS) throw new Error("PB lifetime out of range");
  const iat = config.now();
  const jti = newId();
  const claims: PbClaims = {
    role: "pb", kid: config.kid, aud: config.boundaryId, iat, exp: iat + config.lifetimeMs, jti, hop: context.hop, corr: context.corr,
    request: { method: approved.method, target: approved.target, pairs: approved.pairs.map(([name, value]) => [name, value] as const), bodyLen: approved.bodyLen, bodySha256: approved.bodySha256 },
  };
  return { header: encodeEnvelope("pb", claims, config.privateKey), jti, tag: proofTag("pb", jti) };
}

export type BaIssuerConfig = { kid: string; privateKey: KeyObject; appId: string; lifetimeMs: number; now: () => number };
export function issueBa(config: BaIssuerConfig, verified: VerifiedPb): Issued {
  if (!isVerifiedPb(verified)) throw new Error("a Boundary-to-App proof can only be issued for a VerifiedPb");
  if (!Number.isSafeInteger(config.lifetimeMs) || config.lifetimeMs < 1 || config.lifetimeMs > BA_MAX_LIFETIME_MS) throw new Error("BA lifetime out of range");
  const iat = config.now();
  const jti = newId();
  const source = verified.claims;
  const claims: BaClaims = {
    role: "ba", kid: config.kid, aud: config.appId, iat, exp: iat + config.lifetimeMs, jti, hop: source.hop, corr: source.corr,
    request: { method: source.request.method, target: source.request.target, pairs: source.request.pairs.map(([name, value]) => [name, value] as const), bodyLen: source.request.bodyLen, bodySha256: source.request.bodySha256 },
    pbJti: source.jti, pbSha256: sha256B64(Buffer.from(verified.header, "utf8")),
  };
  return { header: encodeEnvelope("ba", claims, config.privateKey), jti, tag: proofTag("ba", jti) };
}
