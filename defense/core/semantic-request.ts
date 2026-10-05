/**
 * Slice 2: the closed, canonical SEMANTIC REQUEST: the one representation of a request that the Defense Plane approves, that the hop
 * proofs bind, and that every downstream hop reconstructs and verifies.
 *
 * Principle: forward only what the protected application interprets, bind EVERYTHING that is forwarded, REFUSE (never repair) a header
 * the application interprets but we will not forward, and DROP the rest. One canonicalizer serves the plane and both verifiers; only the
 * disposition of an unbound header differs (the plane drops it, a verifier rejects the request that carries it), so the absence of
 * spoofable forwarding/internal headers is authenticated downstream rather than trusted.
 *
 * Bound set: host (required), origin (optional), content-type (POST only). Derived: content-length (re-emitted from the body length).
 * Nothing is normalised except: names are lowercased and leading/trailing SP/HTAB trimmed. Values are byte-exact otherwise; a value that
 * is not printable ASCII, is empty, or is longer than 255 is refused. Duplicates of a bound name are refused, never merged.
 *
 * Pure: no I/O. Branding: an `ApprovedRequest` can only be produced here (a registry the issuer checks).
 */
import { createHash } from "node:crypto";
import type { LayerRequest, ObReason, RejectReason } from "./types";
import { isSpoofableHeader } from "./types";

export type HeaderPair = readonly [name: string, value: string];

export const BOUND_HEADER_NAMES = ["content-type", "host", "origin"] as const;
export const FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";
export const MAX_SEMANTIC_TARGET = 256;
export const MAX_SEMANTIC_VALUE = 255;
export const MAX_SEMANTIC_BODY = 32_768;
export const EMPTY_BODY_SHA256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
export const HOP_PB_HEADER = "x-ba0-hop-pb";
export const HOP_BA_HEADER = "x-ba0-hop-ba";
/** The harness correlation tag: a measurement header, never semantics, never forwarded, never a decision input. */
export const MEASUREMENT_HEADER = "x-ba0-nonce";
export const MEASUREMENT_PATTERN = /^[A-Za-z0-9_-]{22}$/;

const SEMANTIC_VALUE = /^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/;
const SEMANTIC_TARGET = /^\/[\x21-\x7e]{0,255}$/;
const CONTENT_LENGTH = /^(?:0|[1-9][0-9]{0,8})$/;

/** The application interprets these but the plane will not forward them: a request carrying one is refused, not silently altered. */
export const REFUSED_HEADERS: ReadonlySet<string> = new Set([
  "content-encoding", "transfer-encoding", "expect", "upgrade", "te", "trailer", "range", "if-range", "proxy-authorization", "authorization",
]);

export type HeaderClass = "bound" | "derived" | "transport" | "measurement" | "proof" | "refused" | "spoofable" | "ingress_indicator" | "dropped";

/** Total classification of a header name. The policy is versioned by SEMANTIC_POLICY_VERSION and pinned to src/ by a contract test. */
export const SEMANTIC_POLICY_VERSION = 1;
export function classifyHeader(lowerName: string): HeaderClass {
  if ((BOUND_HEADER_NAMES as readonly string[]).includes(lowerName)) return "bound";
  if (lowerName === "content-length") return "derived";
  if (lowerName === "connection") return "transport";
  if (lowerName === MEASUREMENT_HEADER) return "measurement";
  if (lowerName === HOP_PB_HEADER || lowerName === HOP_BA_HEADER) return "proof";
  if (REFUSED_HEADERS.has(lowerName)) return "refused";
  if (isSpoofableHeader(lowerName)) return "spoofable";
  // The application treats these Cloudflare indicators as grounds for denial (client-identity.ts); they are never forwarded.
  if (lowerName.startsWith("cf-")) return "ingress_indicator";
  return "dropped";
}

const trimOws = (value: string): string => value.replace(/^[ \t]+|[ \t]+$/g, "");
const sha256B64 = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("base64url");
export { sha256B64 };

/** Canonical form of one header value: trimmed, non-empty printable ASCII, bounded. Null when it cannot be represented. */
export function canonicalValue(raw: string): string | null {
  const value = trimOws(raw);
  return value.length <= MAX_SEMANTIC_VALUE && SEMANTIC_VALUE.test(value) ? value : null;
}

export type SemanticRequest = {
  readonly method: "GET" | "POST";
  readonly target: string;
  /** Sorted by name, unique, closed names, canonical values. */
  readonly pairs: readonly HeaderPair[];
  readonly bodyLen: number;
  readonly bodySha256: string;
};

/** A SemanticRequest the Defense Plane approved. Only `buildApprovedRequest` mints one; the proof issuer refuses anything else. */
export type ApprovedRequest = SemanticRequest & { readonly approved: true };
const approvedRegistry = new WeakSet<object>();
export const isApprovedRequest = (value: unknown): value is ApprovedRequest => typeof value === "object" && value !== null && approvedRegistry.has(value);

export type ApprovalResult = { ok: true; approved: ApprovedRequest; dropped: number } | { ok: false; reason: RejectReason };

/**
 * The plane side: derives the approved representation from the very LayerRequest L1 evaluated. Total on that input; refuses on any
 * ambiguity. Deterministic, so calling it again after the layer verdict yields the same object the verdict approved.
 */
export function buildApprovedRequest(request: LayerRequest): ApprovalResult {
  const refuse = (reason: RejectReason): ApprovalResult => ({ ok: false, reason });
  if (request.method !== "GET" && request.method !== "POST") return refuse("a7.semantic_value_invalid");
  if (!SEMANTIC_TARGET.test(request.target)) return refuse("a7.semantic_value_invalid");
  const bound = new Map<string, string>();
  const lengths: string[] = [];
  const connections: string[] = [];
  let dropped = 0;
  for (const [rawName, rawValue] of request.headers) {
    const name = rawName.toLowerCase();
    switch (classifyHeader(name)) {
      case "bound": {
        if (bound.has(name)) return refuse("a7.semantic_duplicate");
        const value = canonicalValue(rawValue);
        if (value === null) return refuse("a7.semantic_value_invalid");
        bound.set(name, value);
        break;
      }
      case "derived": lengths.push(trimOws(rawValue)); break;
      case "transport": connections.push(trimOws(rawValue).toLowerCase()); break;
      case "refused": case "proof": case "spoofable": case "measurement": return refuse("a7.semantic_refused_header");
      case "ingress_indicator": case "dropped": dropped++; break;
    }
  }
  if (connections.length > 1 || (connections.length === 1 && connections[0] !== "close" && connections[0] !== "keep-alive")) return refuse("a7.semantic_refused_header");
  if (lengths.length > 1) return refuse("a7.semantic_duplicate");
  if (lengths.length === 1 && !CONTENT_LENGTH.test(lengths[0])) return refuse("a7.semantic_value_invalid");
  if (!bound.has("host")) return refuse("a7.semantic_value_invalid");

  let bodyLen = 0;
  let bodySha256 = EMPTY_BODY_SHA256;
  if (request.method === "POST") {
    if (bound.get("content-type") !== FORM_CONTENT_TYPE) return refuse("a7.semantic_value_invalid");
    if (request.bodyStatus !== "complete" || request.body === null || request.body.length > MAX_SEMANTIC_BODY) return refuse("a7.semantic_value_invalid");
    bodyLen = request.body.length;
    bodySha256 = sha256B64(request.body);
    if (lengths.length !== 1 || Number(lengths[0]) !== bodyLen) return refuse("a7.semantic_value_invalid");
  } else {
    if (bound.has("content-type")) return refuse("a7.semantic_value_invalid");
    if (lengths.length === 1 && lengths[0] !== "0") return refuse("a7.semantic_value_invalid");
  }
  const pairs = [...bound.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([name, value]) => Object.freeze([name, value] as const));
  const approved = Object.freeze({ method: request.method, target: request.target, pairs: Object.freeze(pairs), bodyLen, bodySha256, approved: true as const });
  approvedRegistry.add(approved);
  return { ok: true, approved, dropped };
}

/** The exact request headers a hop emits for a semantic request: the bound pairs plus a derived content-length. Never raw client headers. */
export function semanticWireHeaders(request: SemanticRequest): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of request.pairs) headers[name] = value;
  if (request.method === "POST") headers["content-length"] = String(request.bodyLen);
  return headers;
}

// ---------------------------------------------------------------------------
// Verifier side
// ---------------------------------------------------------------------------

export type HopScan = {
  pb: string[];
  ba: string[];
  nonces: string[];
  /** The canonical pairs observed on the wire (sorted). Meaningful only when no violation was found. */
  pairs: HeaderPair[];
  contentLengths: string[];
  /** The one violation the scan reports, by fixed precedence: duplicate > unbound > framing > value. Null when the set is clean. */
  violation: ObReason | null;
};

/**
 * The verifier side of the same canonicalizer, over the request's RAW header list (never Node's merged `headers`): every name must be
 * in the closed set, bound names occur once, values are canonical. It judges nothing about the proof; the caller compares the observed
 * pairs with the signed ones. `method` decides whether a content-length may or must be present.
 */
export function scanHopHeaders(rawHeaders: readonly string[], method: string): HopScan {
  const found = { duplicate: false, unbound: false, framing: false, value: false };
  const scan: HopScan = { pb: [], ba: [], nonces: [], pairs: [], contentLengths: [], violation: null };
  const bound = new Map<string, string>();
  let connections = 0;
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    const name = rawHeaders[index].toLowerCase();
    const raw = rawHeaders[index + 1];
    switch (classifyHeader(name)) {
      case "bound": {
        if (bound.has(name)) { found.duplicate = true; break; }
        const value = canonicalValue(raw);
        if (value === null) { found.value = true; break; }
        bound.set(name, value);
        break;
      }
      case "derived": scan.contentLengths.push(trimOws(raw)); break;
      case "transport": {
        connections++;
        const value = trimOws(raw).toLowerCase();
        if (connections > 1 || (value !== "close" && value !== "keep-alive")) found.framing = true;
        break;
      }
      case "measurement": scan.nonces.push(raw); break;
      case "proof": (name === HOP_PB_HEADER ? scan.pb : scan.ba).push(raw); break;
      default: found.unbound = true;
    }
  }
  if (scan.nonces.length > 1) found.duplicate = true;
  if (scan.nonces.length === 1 && !MEASUREMENT_PATTERN.test(scan.nonces[0])) found.value = true;
  if (scan.contentLengths.length > 1) found.framing = true;
  if (scan.contentLengths.length === 1 && !CONTENT_LENGTH.test(scan.contentLengths[0])) found.framing = true;
  if (method === "GET" && scan.contentLengths.length > 0) found.framing = true;
  if (method === "POST" && scan.contentLengths.length === 0) found.framing = true;
  scan.pairs = [...bound.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([name, value]) => [name, value] as const);
  scan.violation = found.duplicate ? "ob.header_duplicate" : found.unbound ? "ob.header_unbound" : found.framing ? "ob.framing_invalid" : found.value ? "ob.header_value_invalid" : null;
  return scan;
}

/** The measurement tag, or null unless the request carries exactly one well-formed one. Cheap; used only to attribute a refusal. */
export function readMeasurementTag(rawHeaders: readonly string[]): string | null {
  let found: string | null = null;
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    if (rawHeaders[index].toLowerCase() !== MEASUREMENT_HEADER) continue;
    if (found !== null || !MEASUREMENT_PATTERN.test(rawHeaders[index + 1])) return null;
    found = rawHeaders[index + 1];
  }
  return found;
}

/** Exact comparison of two pair lists as canonical text. */
export const samePairs = (a: readonly HeaderPair[], b: readonly HeaderPair[]): boolean => JSON.stringify(a) === JSON.stringify(b);
