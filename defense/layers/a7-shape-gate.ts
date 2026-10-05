/**
 * L1 `a7.shape-gate`: a pure, STATELESS decision on the shape and grammar of one request.
 *
 * It does not count, remember, score or rate-limit anything, and it has no notion of "who" sent the request or whether the harness
 * labelled it legitimate or hostile: its only input is a `LayerRequest`. Two identical requests always get the same answer.
 *
 * Event-loop safety: every size bound is checked BEFORE anything expensive. Stages 1-5 (method, target, headers, framing, content
 * type, body status) cost O(header bytes) at worst and run before the form grammar is touched; the grammar parser only ever sees a
 * body the front has already bounded to `L1_LIMITS.maxBodyBytes`, and `grammarParses` counts how many times it ran so a test can prove
 * an oversized body never reached it. (The composer's deadline cannot interrupt synchronous work; this ordering is what bounds it.)
 */
import type { Layer, LayerRequest, LayerVerdict, RejectReason } from "../core/types";
import { L1_LIMITS } from "../core/types";

const ROUTES: Readonly<Record<string, readonly string[]>> = {
  "/": ["GET"],
  "/gizlilik": ["GET"],
  "/test-talep-et": ["GET"],
  "/test-talep-et/tesekkurler": ["GET"],
  "/api/public-inquiries": ["POST"],
};
const SERVICE_VALUES: ReadonlySet<string> = new Set(["web", "network", "protection", "unsure"]);
const FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";

/** Equals the application's form field set plus its token and Turnstile fields; pinned by a contract test. */
export const ALLOWED_FORM_FIELDS: ReadonlySet<string> = new Set([
  "name", "email", "company", "service", "system", "objective", "environment", "authority", "protection", "provider", "notes",
  "submissionToken", "cf-turnstile-response",
]);

const HEADER_NAME = /^[a-z0-9!#$%&'*+.^_`|~-]{1,64}$/;
const HEADER_VALUE = /^[\t\x20-\x7e]*$/;
const HOST_VALUE = /^(?:[A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:]{2,45}\])(?::[0-9]{1,5})?$/;
const TARGET_CHARS = /^[\x21-\x7e]+$/;
const BODY_CHARS = /^[A-Za-z0-9\-._~*+%=&]*$/;
const CONTENT_LENGTH = /^(?:0|[1-9][0-9]{0,8})$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const HEX = /^[0-9A-Fa-f]{2}$/;

const reject = (reason: RejectReason): LayerVerdict => ({ kind: "reject", reason });
const PASS: LayerVerdict = { kind: "pass" };

function utf8Fatal(bytes: Uint8Array): boolean {
  try { new TextDecoder("utf-8", { fatal: true }).decode(bytes); return true; } catch { return false; }
}

/** Decodes an urlencoded component into bytes; null when a `%` is not followed by two hex digits. */
function decodeComponent(raw: string): Uint8Array | null {
  const out: number[] = [];
  for (let index = 0; index < raw.length; index++) {
    const character = raw[index];
    if (character === "%") {
      const pair = raw.slice(index + 1, index + 3);
      if (!HEX.test(pair)) return null;
      out.push(Number.parseInt(pair, 16));
      index += 2;
    } else if (character === "+") out.push(0x20);
    else out.push(raw.charCodeAt(index));
  }
  return Uint8Array.from(out);
}

export class ShapeGate implements Layer {
  readonly id = "a7.shape-gate" as const;
  private evaluatedCount = 0;
  private grammarParseCount = 0;

  /** Counters for self-checks only; they never influence a verdict. */
  stats(): { evaluated: number; grammarParses: number } {
    return { evaluated: this.evaluatedCount, grammarParses: this.grammarParseCount };
  }

  evaluate(request: LayerRequest): LayerVerdict {
    this.evaluatedCount++;

    // 1. method
    if (request.method !== "GET" && request.method !== "POST") return reject("a7.method_not_allowed");

    // 2. target: length, then alphabet, then structure (all bounded, no decoding)
    const target = request.target;
    if (Buffer.byteLength(target, "latin1") > L1_LIMITS.maxTargetBytes) return reject("a7.target_too_long");
    if (!TARGET_CHARS.test(target) || target[0] !== "/" || target.startsWith("//") || target.includes("\\") || target.includes("#") || target.includes("%")) return reject("a7.target_malformed");
    const queryStart = target.indexOf("?");
    const path = queryStart < 0 ? target : target.slice(0, queryStart);
    const query = queryStart < 0 ? "" : target.slice(queryStart + 1);
    if (path.split("/").some((segment) => segment === "." || segment === "..")) return reject("a7.target_malformed");
    if (!Object.hasOwn(ROUTES, path)) return reject("a7.path_not_allowed");
    if (!ROUTES[path].includes(request.method)) return reject("a7.method_not_allowed");
    if (queryStart >= 0) {
      const allowed = path === "/test-talep-et" && query.length <= L1_LIMITS.maxQueryBytes && query.startsWith("hizmet=") && SERVICE_VALUES.has(query.slice("hizmet=".length));
      if (!allowed) return reject("a7.query_not_allowed");
    }

    // 3. headers: count, bytes, name and value alphabets, Host
    if (request.headers.length > L1_LIMITS.maxHeaderCount) return reject("a7.header_count_exceeded");
    let headerBytes = 0;
    for (const [name, value] of request.headers) headerBytes += name.length + value.length + 4;
    if (headerBytes > L1_LIMITS.maxHeaderBytes) return reject("a7.header_bytes_exceeded");
    for (const [name, value] of request.headers) {
      if (!HEADER_NAME.test(name.toLowerCase())) return reject("a7.header_name_invalid");
      if (!HEADER_VALUE.test(value)) return reject("a7.header_value_invalid");
    }
    const named = (wanted: string) => request.headers.filter(([name]) => name.toLowerCase() === wanted).map(([, value]) => value);
    const hosts = named("host");
    if (hosts.length !== 1 || !HOST_VALUE.test(hosts[0])) return reject("a7.host_header_invalid");

    // 4. framing: a Content-Length only, never Transfer-Encoding, and no body on a GET
    const lengths = named("content-length");
    const hasTransferEncoding = named("transfer-encoding").length > 0;
    if (hasTransferEncoding || lengths.length > 1) return reject("a7.framing_invalid");
    if (lengths.length === 1 && !CONTENT_LENGTH.test(lengths[0])) return reject("a7.framing_invalid");
    const declared = lengths.length === 1 ? Number(lengths[0]) : null;
    if (request.method === "GET") {
      if (declared !== null && declared !== 0) return reject("a7.framing_invalid");
      return PASS;
    }
    if (declared === null) return reject("a7.framing_invalid");

    // 5. POST: content type, then body size/state, all decided without parsing the body
    const contentTypes = named("content-type");
    if (contentTypes.length !== 1 || contentTypes[0] !== FORM_CONTENT_TYPE) return reject("a7.content_type_invalid");
    if (declared > L1_LIMITS.maxBodyBytes || request.bodyStatus === "declared_oversize" || request.bodyStatus === "overflow") return reject("a7.body_too_large");
    if (request.bodyStatus === "timeout") return reject("a7.body_read_timeout");
    if (request.bodyStatus === "aborted") return reject("a7.body_incomplete");
    if (request.bodyStatus !== "complete" || request.body === null || request.body.length !== declared) return reject("a7.body_incomplete");

    // 6. grammar: only now, and only over a body already bounded to maxBodyBytes
    return this.parseForm(request.body);
  }

  private parseForm(body: Uint8Array): LayerVerdict {
    this.grammarParseCount++;
    const text = Buffer.from(body).toString("latin1");
    if (!BODY_CHARS.test(text)) return reject("a7.body_encoding_invalid");
    if (text === "") return PASS;
    // Count separators before splitting so an absurd number of fields is never materialised.
    let separators = 0;
    for (let index = 0; index < text.length; index++) if (text.charCodeAt(index) === 0x26) separators++;
    if (separators + 1 > L1_LIMITS.maxFormFields) return reject("a7.form_field_count_exceeded");
    const seen = new Set<string>();
    for (const pair of text.split("&")) {
      const separator = pair.indexOf("=");
      if (pair === "" || separator < 1) return reject("a7.form_grammar_invalid");
      const rawName = pair.slice(0, separator);
      const rawValue = pair.slice(separator + 1);
      if (rawName.length > L1_LIMITS.maxFieldNameBytes * 3) return reject("a7.form_field_not_allowed");
      if (rawValue.length > L1_LIMITS.maxFieldEncodedBytes) return reject("a7.form_field_too_long");
      const nameBytes = decodeComponent(rawName);
      const valueBytes = decodeComponent(rawValue);
      if (nameBytes === null || valueBytes === null || !utf8Fatal(nameBytes) || !utf8Fatal(valueBytes)) return reject("a7.body_encoding_invalid");
      const name = new TextDecoder().decode(nameBytes);
      if (!ALLOWED_FORM_FIELDS.has(name)) return reject("a7.form_field_not_allowed");
      if (seen.has(name)) return reject("a7.form_field_duplicate");
      seen.add(name);
      if (name === "submissionToken" && !TOKEN.test(new TextDecoder().decode(valueBytes))) return reject("a7.form_token_malformed");
    }
    return PASS;
  }
}
