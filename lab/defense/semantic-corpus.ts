/**
 * BA0 Slice 2 Plane semantic corpus: a deterministic, FIXED-COUNT list of requests sent over raw loopback TCP to the Defense Plane only,
 * probing the canonical semantic request (defense/core/semantic-request.ts): duplicate bound headers, unrepresentable values, headers
 * the application interprets but the plane will not forward, and the positive cases that must still pass (client-supplied proof headers
 * stripped, whitespace and name-case variants canonicalised, unbound headers dropped).
 *
 * Each case states the exact outcome; the LEDGER (not the client) decides whether it happened. Nothing is repeated, nothing leaves
 * 127.0.0.1, and the label never goes on the wire.
 */
import type { RejectReason } from "../../defense/core/types";
import { trackedRaw, type Exchange, type RawSpec } from "./client";
import type { Collector, LedgerRecord } from "./collector";
import { Collector as CollectorClass } from "./collector";

const CRLF = "\r\n";
const FORM = "application/x-www-form-urlencoded";

export type SemanticExpect =
  | { kind: "reject"; reason: Extract<RejectReason, `a7.semantic_${string}`>; /** The client may see 100-continue first and drop the connection. */ lenient?: boolean }
  | { kind: "pass"; stripped: number; dropped: number };
export type SemanticCase = { id: string; method: "GET" | "POST" | "OTHER"; build: (context: { port: number }, nonce: string) => RawSpec; expect: SemanticExpect };

function request(method: string, target: string, extra: string[], options: { host?: string | null; connection?: string | null } = {}): SemanticCase["build"] {
  return (context, nonce) => {
    const lines = [`${method} ${target} HTTP/1.1`];
    if (options.host !== null) lines.push(`Host: ${options.host ?? `127.0.0.1:${context.port}`}`);
    if (options.connection !== null) lines.push(`Connection: ${options.connection ?? "close"}`);
    lines.push(`X-Ba0-Nonce: ${nonce}`, ...extra);
    return { head: Buffer.from(lines.join(CRLF) + CRLF + CRLF, "latin1") };
  };
}

const reject = (reason: Extract<RejectReason, `a7.semantic_${string}`>, lenient = false): SemanticExpect => ({ kind: "reject", reason, ...(lenient ? { lenient } : {}) });
const pass = (stripped: number, dropped: number): SemanticExpect => ({ kind: "pass", stripped, dropped });

export const SEMANTIC_CORPUS: readonly SemanticCase[] = Object.freeze([
  // --- duplicates are refused, never merged or resolved first/last-wins
  { id: "sem_dup_origin", method: "GET", build: request("GET", "/gizlilik", ["Origin: http://a.test", "Origin: http://b.test"]), expect: reject("a7.semantic_duplicate") },
  { id: "sem_dup_origin_case", method: "GET", build: request("GET", "/gizlilik", ["Origin: http://a.test", "ORIGIN: http://a.test"]), expect: reject("a7.semantic_duplicate") },
  // --- values that cannot be represented are refused, never repaired
  { id: "sem_ct_on_get", method: "GET", build: request("GET", "/", [`Content-Type: ${FORM}`]), expect: reject("a7.semantic_value_invalid") },
  { id: "sem_origin_empty", method: "GET", build: request("GET", "/", ["Origin:"]), expect: reject("a7.semantic_value_invalid") },
  { id: "sem_origin_too_long", method: "GET", build: request("GET", "/", [`Origin: http://${"a".repeat(300)}`]), expect: reject("a7.semantic_value_invalid") },
  // --- headers the application interprets but the plane will not forward are refused, never silently dropped
  { id: "sem_ce_identity", method: "GET", build: request("GET", "/", ["Content-Encoding: identity"]), expect: reject("a7.semantic_refused_header") },
  { id: "sem_ce_gzip", method: "GET", build: request("GET", "/", ["Content-Encoding: gzip"]), expect: reject("a7.semantic_refused_header") },
  { id: "sem_expect_continue", method: "GET", build: request("GET", "/", ["Expect: 100-continue"]), expect: reject("a7.semantic_refused_header") },
  { id: "sem_upgrade_header", method: "GET", build: request("GET", "/", ["Upgrade: websocket"]), expect: reject("a7.semantic_refused_header") },
  { id: "sem_te", method: "GET", build: request("GET", "/", ["TE: trailers"]), expect: reject("a7.semantic_refused_header") },
  { id: "sem_authorization", method: "GET", build: request("GET", "/", ["Authorization: Bearer not-a-secret"]), expect: reject("a7.semantic_refused_header") },
  { id: "sem_range", method: "GET", build: request("GET", "/", ["Range: bytes=0-1"]), expect: reject("a7.semantic_refused_header") },
  { id: "sem_connection_names_header", method: "GET", build: request("GET", "/", [], { connection: "origin" }), expect: reject("a7.semantic_refused_header") },
  { id: "sem_connection_two_tokens", method: "GET", build: request("GET", "/", [], { connection: "keep-alive, close" }), expect: reject("a7.semantic_refused_header") },
  // --- positive cases: they must still pass, as the canonical request
  // A client-supplied proof header is a spoofable internal header: stripped and counted, never forwarded; downstream sees only the plane's own proof.
  { id: "sem_client_proof_headers", method: "GET", build: request("GET", "/gizlilik", ["X-Ba0-Hop-Pb: forged.by.client", "X-Ba0-Hop-Ba: forged.by.client"]), expect: pass(2, 0) },
  // Name case and surrounding whitespace carry no meaning: the canonical request has lowercase names and trimmed values.
  { id: "sem_ows_and_name_case", method: "GET", build: (context, nonce) => request("GET", "/", [`hOsT:   127.0.0.1:${context.port}   `, `oRiGiN:\t http://127.0.0.1:${context.port}  `], { host: null })(context, nonce), expect: pass(0, 0) },
  // Headers the application never interprets are dropped (counted), never forwarded, and so never reach a hop that would reject them.
  { id: "sem_dropped_unbound", method: "GET", build: request("GET", "/gizlilik", ["Accept: text/html", "User-Agent: ba0-semantic", "Cookie: a=b", "Referer: http://x.test/"]), expect: pass(0, 4) },
  { id: "sem_dup_unbound_accept", method: "GET", build: request("GET", "/gizlilik", ["Accept: text/html", "Accept: text/plain"]), expect: pass(0, 2) },
]);

export const SEMANTIC_CORPUS_FIXED_COUNT = 18;
export const SEMANTIC_EXPECTED_DROPPED = SEMANTIC_CORPUS.reduce((total, entry) => total + (entry.expect.kind === "pass" ? entry.expect.dropped : 0), 0);

export type SemanticRun = { cases: { id: string; nonce: string; exchange: Exchange }[] };

export async function runSemanticCorpus(collector: Collector, port: number, timeoutMs: number): Promise<SemanticRun> {
  const run: SemanticRun = { cases: [] };
  for (const entry of SEMANTIC_CORPUS) {
    const exchange = await trackedRaw(collector, port, { lane: "protected", phase: "semantic", cls: "hostile", scenario: entry.id, journey: null, step: null, method: entry.method }, (nonce) => entry.build({ port }, nonce), timeoutMs);
    run.cases.push({ id: entry.id, nonce: exchange.nonce, exchange });
  }
  return run;
}

/** The ledger's verdict on one case; null means it behaved exactly as specified. */
export function verifySemantic(entry: SemanticCase, record: LedgerRecord, exchange: Exchange): string | null {
  const expect = entry.expect;
  const terminal = CollectorClass.terminalOf(record);
  const accepted = record.plane.find((event) => event.kind === "INGRESS_ACCEPTED");
  const receipts = record.origin.filter((event) => event.kind === "ORIGIN_RECEIVED").length;
  if (expect.kind === "reject") {
    const verdict = record.plane.find((event) => event.kind === "L1_REJECTED");
    if (verdict?.reason !== expect.reason) return `expected ${expect.reason}, ledger has ${verdict?.reason ?? "no reject"}`;
    if (verdict.stage !== "pre_parse") return `stage ${verdict.stage} is not pre_parse`;
    if (terminal !== "rejected" && !(expect.lenient && terminal === "client_aborted")) return `terminal is ${terminal}`;
    if (receipts > 0 || record.boundary.length > 0 || record.app.length > 0) return "a refused request reached the boundary or the application";
    if (!expect.lenient && !(exchange.result === "response" && exchange.status === 400)) return `client saw ${exchange.result}/${exchange.status}, expected 400`;
    return null;
  }
  if (terminal !== "proxied") return `expected proxied, terminal is ${terminal}`;
  if (receipts !== 1) return `origin receipts ${receipts}`;
  if (accepted?.stripped !== expect.stripped) return `stripped ${accepted?.stripped}, expected ${expect.stripped}`;
  if (record.app.some((event) => event.kind === "APP_MUTATED")) return "a semantic case mutated state";
  return exchange.result === "response" && exchange.status === 200 ? null : `client saw ${exchange.result}/${exchange.status}, expected 200`;
}
