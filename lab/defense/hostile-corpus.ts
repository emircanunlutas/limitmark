/**
 * Hostile corpus: a deterministic, FIXED-COUNT list of malformed and shape-abusive requests, sent over raw loopback TCP to the
 * protected plane only. No load ramp, no repetition, no external traffic. Each case states the outcome L1 must produce; the ledger
 * (not the client) decides whether it did, and any deviation makes the run INVALID.
 *
 * Cases that L1 deliberately does NOT reject (shape-valid but semantically wrong, or spoofed internal headers that are stripped) are
 * included on purpose: they pin the boundary of L1's scope, so a layer that over-reaches is caught as well as one that under-reaches.
 */
import { REJECT_STAGE, REJECT_STATUS, type RejectReason } from "../../defense/core/types";
import type { ExpectedLane } from "../../defense/core/ledger";
import { trackedRaw, type Exchange, type RawSpec } from "./client";
import type { Collector, LedgerRecord } from "./collector";
import { Collector as CollectorClass } from "./collector";

type Context = { port: number };
type Builder = (context: Context, nonce: string) => RawSpec;

export type Expectation =
  | { kind: "reject"; reason: RejectReason; /** The client may lose the response when the front closes on an unread body. */ clientMayReset?: boolean }
  | { kind: "reject_aborted"; reason: RejectReason }
  | { kind: "pass_through" }
  | { kind: "pass_stripped"; stripped: number }
  | { kind: "parser" };

export type CorpusCase = { id: string; family: string; method: "GET" | "POST" | "OTHER"; build: Builder; expect: Expectation };

const CRLF = "\r\n";
const FORM = "application/x-www-form-urlencoded";

function request(method: string, target: string, extra: string[], options: { body?: Buffer | string; host?: string | null; noConnection?: boolean } = {}): Builder {
  return (context, nonce) => {
    const body = options.body === undefined ? Buffer.alloc(0) : Buffer.from(options.body as string, typeof options.body === "string" ? "latin1" : undefined);
    const lines = [`${method} ${target} HTTP/1.1`];
    if (options.host !== null) lines.push(`Host: ${options.host ?? `127.0.0.1:${context.port}`}`);
    if (!options.noConnection) lines.push("Connection: close");
    lines.push(`X-Ba0-Nonce: ${nonce}`, ...extra);
    return { head: Buffer.concat([Buffer.from(lines.join(CRLF) + CRLF + CRLF, "latin1"), body]) };
  };
}

const formPost = (body: string, extra: string[] = [], contentType = FORM): Builder => (context, nonce) =>
  request("POST", "/api/public-inquiries", [`Content-Type: ${contentType}`, `Content-Length: ${Buffer.byteLength(body, "latin1")}`, `Origin: http://127.0.0.1:${context.port}`, ...extra], { body })(context, nonce);

const TOKEN = "A".repeat(43);
const reject = (reason: RejectReason, extra: { clientMayReset?: boolean } = {}): Expectation => ({ kind: "reject", reason, ...extra });
const pad = (count: number, size: number): string[] => Array.from({ length: count }, (_, index) => `X-Pad-${index}: ${"a".repeat(size)}`);

export const CORPUS: readonly CorpusCase[] = Object.freeze([
  // --- method
  { id: "method_options", family: "method", method: "OTHER", build: request("OPTIONS", "/", []), expect: reject("a7.method_not_allowed") },
  { id: "method_put_api", family: "method", method: "OTHER", build: request("PUT", "/api/public-inquiries", ["Content-Length: 0"]), expect: reject("a7.method_not_allowed") },
  { id: "method_delete_root", family: "method", method: "OTHER", build: request("DELETE", "/", []), expect: reject("a7.method_not_allowed") },
  { id: "method_trace", family: "method", method: "OTHER", build: request("TRACE", "/", []), expect: reject("a7.method_not_allowed") },
  { id: "method_post_on_page", family: "method", method: "POST", build: request("POST", "/", [`Content-Type: ${FORM}`, "Content-Length: 0"]), expect: reject("a7.method_not_allowed") },
  { id: "method_get_on_api", family: "method", method: "GET", build: request("GET", "/api/public-inquiries", []), expect: reject("a7.method_not_allowed") },
  { id: "method_unknown_token", family: "method", method: "OTHER", build: request("BREW", "/", []), expect: { kind: "parser" } },
  // --- target / path / query
  { id: "target_dotdot", family: "target", method: "GET", build: request("GET", "/../etc/passwd", []), expect: reject("a7.target_malformed") },
  { id: "target_double_slash", family: "target", method: "GET", build: request("GET", "//evil.example/", []), expect: reject("a7.target_malformed") },
  { id: "target_encoded_dotdot", family: "target", method: "GET", build: request("GET", "/%2e%2e/admin", []), expect: reject("a7.target_malformed") },
  { id: "target_encoded_nul", family: "target", method: "GET", build: request("GET", "/%00", []), expect: reject("a7.target_malformed") },
  { id: "target_backslash", family: "target", method: "GET", build: request("GET", "/a\\b", []), expect: reject("a7.target_malformed") },
  { id: "target_absolute_form", family: "target", method: "GET", build: request("GET", "http://evil.example/", []), expect: reject("a7.target_malformed") },
  { id: "target_too_long", family: "target", method: "GET", build: request("GET", `/${"a".repeat(3000)}`, []), expect: reject("a7.target_too_long") },
  { id: "path_admin", family: "path", method: "GET", build: request("GET", "/admin", []), expect: reject("a7.path_not_allowed") },
  { id: "path_cron", family: "path", method: "GET", build: request("GET", "/api/cron/process-notifications", []), expect: reject("a7.path_not_allowed") },
  { id: "path_next_image", family: "path", method: "GET", build: request("GET", "/_next/image?url=x", []), expect: reject("a7.path_not_allowed") },
  { id: "query_on_root", family: "query", method: "GET", build: request("GET", "/?x=1", []), expect: reject("a7.query_not_allowed") },
  { id: "query_unknown_service", family: "query", method: "GET", build: request("GET", "/test-talep-et?hizmet=evil", []), expect: reject("a7.query_not_allowed") },
  // --- headers
  { id: "headers_count", family: "headers", method: "GET", build: request("GET", "/", pad(60, 1)), expect: reject("a7.header_count_exceeded") },
  { id: "headers_bytes", family: "headers", method: "GET", build: request("GET", "/", pad(1, 9000)), expect: reject("a7.header_bytes_exceeded") },
  { id: "headers_overflow_parser", family: "headers", method: "GET", build: request("GET", "/", pad(1, 20_000)), expect: { kind: "parser" } },
  { id: "headers_obs_text", family: "headers", method: "GET", build: (context, nonce) => ({ head: Buffer.concat([request("GET", "/", [], {})(context, nonce).head.subarray(0, -2), Buffer.from("X-Odd: caf\xe9\r\n\r\n", "latin1")]) }), expect: reject("a7.header_value_invalid") },
  { id: "headers_invalid_name", family: "headers", method: "GET", build: request("GET", "/", ["X@Bad: 1"]), expect: { kind: "parser" } },
  { id: "host_missing", family: "headers", method: "GET", build: request("GET", "/", [], { host: null }), expect: reject("a7.host_header_invalid") },
  { id: "host_malformed", family: "headers", method: "GET", build: request("GET", "/", [], { host: "bad host" }), expect: reject("a7.host_header_invalid") },
  { id: "host_duplicate", family: "headers", method: "GET", build: (context, nonce) => request("GET", "/", [`Host: second.example`])(context, nonce), expect: reject("a7.host_header_invalid") },
  // --- framing
  { id: "framing_get_with_body", family: "framing", method: "GET", build: request("GET", "/", ["Content-Length: 5"], { body: "hello" }), expect: reject("a7.framing_invalid") },
  { id: "framing_post_no_length", family: "framing", method: "POST", build: request("POST", "/api/public-inquiries", [`Content-Type: ${FORM}`]), expect: reject("a7.framing_invalid") },
  { id: "framing_chunked_post", family: "framing", method: "POST", build: request("POST", "/api/public-inquiries", [`Content-Type: ${FORM}`, "Transfer-Encoding: chunked"], { body: "5\r\nname=\r\n0\r\n\r\n" }), expect: reject("a7.framing_invalid") },
  { id: "framing_cl_and_te", family: "framing", method: "POST", build: request("POST", "/api/public-inquiries", [`Content-Type: ${FORM}`, "Content-Length: 4", "Transfer-Encoding: chunked"], { body: "0\r\n\r\n" }), expect: { kind: "parser" } },
  { id: "framing_cl_not_numeric", family: "framing", method: "POST", build: request("POST", "/api/public-inquiries", [`Content-Type: ${FORM}`, "Content-Length: abc"]), expect: { kind: "parser" } },
  // --- body
  { id: "body_declared_oversize", family: "body", method: "POST", build: request("POST", "/api/public-inquiries", [`Content-Type: ${FORM}`, "Content-Length: 10485760"]), expect: reject("a7.body_too_large", { clientMayReset: true }) },
  { id: "body_oversize_sent", family: "body", method: "POST", build: formPost(`notes=${"a".repeat(40_000)}`), expect: reject("a7.body_too_large", { clientMayReset: true }) },
  { id: "body_slow_stall", family: "body", method: "POST", build: (context, nonce) => ({ head: request("POST", "/api/public-inquiries", [`Content-Type: ${FORM}`, "Content-Length: 200"], { body: "name=slow" })(context, nonce).head, tail: Buffer.from("x"), afterMs: 3_000 }), expect: reject("a7.body_read_timeout", { clientMayReset: true }) },
  { id: "body_client_vanishes", family: "body", method: "POST", build: (context, nonce) => ({ head: request("POST", "/api/public-inquiries", [`Content-Type: ${FORM}`, "Content-Length: 100"], { body: "name=gone" })(context, nonce).head, closeAfterMs: 100 }), expect: { kind: "reject_aborted", reason: "a7.body_incomplete" } },
  { id: "body_bad_percent", family: "body", method: "POST", build: formPost("name=%zz"), expect: reject("a7.body_encoding_invalid") },
  { id: "body_invalid_utf8", family: "body", method: "POST", build: formPost("name=%ff%fe"), expect: reject("a7.body_encoding_invalid") },
  { id: "body_raw_non_ascii", family: "body", method: "POST", build: formPost("name=caf\xe9"), expect: reject("a7.body_encoding_invalid") },
  { id: "form_unknown_field", family: "form", method: "POST", build: formPost("evil=1"), expect: reject("a7.form_field_not_allowed") },
  { id: "form_proto_pollution", family: "form", method: "POST", build: formPost("__proto__=x&constructor=y"), expect: reject("a7.form_field_not_allowed") },
  { id: "form_duplicate_field", family: "form", method: "POST", build: formPost("name=a&name=b"), expect: reject("a7.form_field_duplicate") },
  { id: "form_too_many_fields", family: "form", method: "POST", build: formPost(Array.from({ length: 200 }, () => "name=a").join("&")), expect: reject("a7.form_field_count_exceeded") },
  { id: "form_field_too_long", family: "form", method: "POST", build: formPost(`notes=${"a".repeat(13_000)}`), expect: reject("a7.form_field_too_long") },
  { id: "form_bad_token_shape", family: "form", method: "POST", build: formPost("submissionToken=short"), expect: reject("a7.form_token_malformed") },
  { id: "form_empty_name", family: "form", method: "POST", build: formPost("=x"), expect: reject("a7.form_grammar_invalid") },
  { id: "form_no_equals", family: "form", method: "POST", build: formPost("name"), expect: reject("a7.form_grammar_invalid") },
  { id: "content_type_json", family: "content_type", method: "POST", build: formPost("{}", [], "application/json"), expect: reject("a7.content_type_invalid") },
  { id: "content_type_multipart", family: "content_type", method: "POST", build: formPost("--x--", [], "multipart/form-data; boundary=x"), expect: reject("a7.content_type_invalid") },
  { id: "content_type_charset", family: "content_type", method: "POST", build: formPost("name=a", [], `${FORM}; charset=utf-8`), expect: reject("a7.content_type_invalid") },
  // --- shape-valid requests L1 must NOT reject (the boundary of its scope)
  { id: "scope_semantic_invalid_email", family: "scope", method: "POST", build: formPost(`name=A&email=not-an-email&service=web&system=s&objective=o&environment=staging&authority=owner&submissionToken=${TOKEN}`), expect: { kind: "pass_through" } },
  { id: "scope_missing_required_fields", family: "scope", method: "POST", build: formPost("name=A"), expect: { kind: "pass_through" } },
  { id: "scope_wrong_origin", family: "scope", method: "POST", build: (context, nonce) => request("POST", "/api/public-inquiries", [`Content-Type: ${FORM}`, "Content-Length: 6", "Origin: http://evil.example"], { body: "name=A" })(context, nonce), expect: { kind: "pass_through" } },
  // --- spoofed internal / forwarding headers: stripped, then forwarded
  { id: "spoof_internal_headers", family: "spoof", method: "GET", build: request("GET", "/", ["X-Ba0-Hop: 999", "X-BA0-Class: legitimate", "x-ba0-skip-layer: a7.shape-gate"]), expect: { kind: "pass_stripped", stripped: 3 } },
  { id: "spoof_forwarding_headers", family: "spoof", method: "GET", build: request("GET", "/gizlilik", ["X-Forwarded-For: 10.0.0.1", "X-Real-IP: 10.0.0.2", "Forwarded: for=10.0.0.3", "CF-Connecting-IP: 10.0.0.4", "X-Limitmark-Origin-Secret: not-a-secret", "X-Vercel-Protection-Bypass: x"]), expect: { kind: "pass_stripped", stripped: 6 } },
]);

export const CORPUS_FIXED_COUNT = 55;

export type CorpusRun = { cases: { id: string; nonce: string; exchange: Exchange }[] };

/** Sends every case once, in order. Raw bytes only; the label is registered in the collector, never sent. */
export async function runCorpus(collector: Collector, port: number, timeoutMs: number): Promise<CorpusRun> {
  const run: CorpusRun = { cases: [] };
  for (const entry of CORPUS) {
    const lane: ExpectedLane = entry.expect.kind === "parser" ? "pre_ingress" : "protected";
    const exchange = await trackedRaw(collector, port, { lane, phase: "corpus", cls: "hostile", scenario: entry.id, journey: null, step: null, method: entry.method }, (nonce) => entry.build({ port }, nonce), timeoutMs);
    run.cases.push({ id: entry.id, nonce: exchange.nonce, exchange });
  }
  return run;
}

/** The ledger's verdict on one case; null means the case behaved exactly as specified. */
export function verifyCase(entry: CorpusCase, record: LedgerRecord, exchange: Exchange): string | null {
  const expect = entry.expect;
  const kinds = record.plane.map((event) => event.kind);
  const verdict = record.plane.find((event) => event.kind === "L1_REJECTED");
  const accepted = record.plane.find((event) => event.kind === "INGRESS_ACCEPTED");
  const terminal = CollectorClass.terminalOf(record);
  const originReceipts = record.origin.filter((event) => event.kind === "ORIGIN_RECEIVED").length;
  if (expect.kind === "parser") {
    if (record.plane.length > 0 || record.origin.length > 0) return "parser case produced a lifecycle past the parser";
    if (exchange.result === "response" && exchange.status !== 400 && exchange.status !== 431) return `parser case answered ${exchange.status}`;
    return null;
  }
  if (expect.kind === "reject_aborted") {
    if (verdict?.reason !== expect.reason) return `expected ${expect.reason}, ledger has ${verdict?.reason ?? "no reject"}`;
    if (terminal !== "client_aborted") return `expected client_aborted, ledger terminal is ${terminal}`;
    return originReceipts === 0 ? null : "origin saw a request that L1 rejected";
  }
  if (expect.kind === "reject") {
    if (verdict?.reason !== expect.reason) return `expected ${expect.reason}, ledger has ${verdict?.reason ?? kinds[kinds.length - 1] ?? "nothing"}`;
    if (verdict.stage !== REJECT_STAGE[expect.reason]) return `stage ${verdict.stage} is not ${REJECT_STAGE[expect.reason]}`;
    if (terminal !== "rejected") return `terminal is ${terminal}`;
    if (originReceipts > 0) return "origin saw a request that L1 rejected";
    const status = REJECT_STATUS[expect.reason];
    if (exchange.result === "response" && exchange.status !== status) return `client saw ${exchange.status}, expected ${status}`;
    if (exchange.result !== "response" && !expect.clientMayReset) return `client saw ${exchange.result}, expected a ${status} response`;
    return null;
  }
  // pass_through / pass_stripped
  if (terminal !== "proxied") return `expected proxied, terminal is ${terminal}`;
  if (originReceipts !== 1) return `origin receipts ${originReceipts}`;
  if (record.origin.some((event) => (event.spoofed ?? 0) > 0)) return "a spoofable header reached the origin";
  if (expect.kind === "pass_stripped" && accepted?.stripped !== expect.stripped) return `stripped ${accepted?.stripped}, expected ${expect.stripped}`;
  if (expect.kind === "pass_through" && accepted?.stripped !== 0) return `unexpected stripped headers ${accepted?.stripped}`;
  return null;
}
