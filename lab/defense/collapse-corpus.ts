/**
 * Slice 3 reviewed fixtures. FIXED, DIGEST-PINNED and local: no external traffic, no arbitrary or user-controlled fixture, no load ramp.
 *
 * Natural families (sent as ordinary traffic; L1 and L2 decide for themselves):
 *   F1  fabricated valid mutation   a well-formed, fully valid form POST whose token was never issued (L1 passes it by design)
 *   F2  token replay beyond K       a genuinely rendered token POSTed far more than K times
 *   F3  journey farmer              render, then POST the real token, repeated (a stateful automation)
 *   F4  render/filter poisoning     a bounded render flood against the credit filter, then a fabricated probe to measure false positives
 *
 * Forced families (C1/C2 only): requests L1 would REFUSE, delivered past L1 by the harness-only override (basis=simulated), each stating the
 * L1 reason the layer must really have computed (the shadow). They are fixed bytes: the collapse override matches on their digest.
 */
import { createHash, randomBytes } from "node:crypto";
import type { Exchange } from "./client";
import { trackedHttp } from "./client";
import type { Collector, RequestMeta } from "./collector";

const TOKEN_FIELD = /name="submissionToken" value="([A-Za-z0-9_-]{43})"/;
const FORM = "application/x-www-form-urlencoded";
const CRLF = "\r\n";

export const newToken = (): string => randomBytes(32).toString("base64url");
export const tokenFrom = (exchange: Exchange): string | null => TOKEN_FIELD.exec(exchange.body.toString("utf8"))?.[1] ?? null;
export const isRedirect = (exchange: Exchange): boolean => {
  if (exchange.result !== "response" || exchange.status !== 200) return false;
  try { return (JSON.parse(exchange.body.toString("utf8")) as { kind?: string }).kind === "redirect"; } catch { return false; }
};

/** A fully valid submission body (the same fields the canary posts) for the given token. */
export function validFormBody(token: string): string {
  return new URLSearchParams({
    name: "Hostile Fixture", email: "fixture@example.test", company: "Synthetic Co", service: "web", system: "synthetic fixture system", objective: "synthetic fixture objective",
    environment: "staging", authority: "authorized", protection: "unknown", provider: "", notes: "", submissionToken: token,
  }).toString();
}

export const FIXTURE_FAMILIES = ["f1_fabricated", "f2_replay", "f3_farmer", "f4_poison", "forced"] as const;
/** Scenario names of the fixture requests that are renders of the reviewed form route (each must get exactly one enrollment disposition). */
export const RENDER_SCENARIOS: ReadonlySet<string> = new Set(["journey_form", "f2_render", "f3_render", "f4_render"]);

const meta = (phase: string, scenario: string, method: "GET" | "POST"): RequestMeta => ({ lane: "protected", phase, cls: "hostile", scenario, journey: null, step: null, method });

export async function postFabricated(collector: Collector, port: number, phase: string, timeoutMs: number, scenario = "f1_fabricated", token = newToken()): Promise<Exchange> {
  return trackedHttp(collector, port, meta(phase, scenario, "POST"), { method: "POST", path: "/api/public-inquiries", headers: { origin: `http://127.0.0.1:${port}`, "content-type": FORM }, body: validFormBody(token) }, timeoutMs);
}

export async function render(collector: Collector, port: number, phase: string, scenario: string, timeoutMs: number): Promise<Exchange> {
  return trackedHttp(collector, port, meta(phase, scenario, "GET"), { method: "GET", path: "/test-talep-et" }, timeoutMs);
}

export type FloodResult = { exchange: Exchange; mutatedByClient: boolean };

/** `count` requests through a pool of `concurrency` workers; every request is tracked in the collector. */
export async function flood(count: number, concurrency: number, one: (index: number) => Promise<FloodResult>): Promise<FloodResult[]> {
  const results: FloodResult[] = new Array<FloodResult>(count);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, count) }, async () => {
    while (next < count) { const index = next++; results[index] = await one(index); }
  }));
  return results;
}

export async function runF1(collector: Collector, port: number, phase: string, count: number, concurrency: number, timeoutMs: number, scenario = "f1_fabricated"): Promise<FloodResult[]> {
  return flood(count, concurrency, async () => { const exchange = await postFabricated(collector, port, phase, timeoutMs, scenario); return { exchange, mutatedByClient: isRedirect(exchange) }; });
}

/** F2: renders `tokens` genuine tokens, then POSTs each `postsPerToken` times (sequentially: replays of one token). */
export async function runF2(collector: Collector, port: number, phase: string, tokens: number, postsPerToken: number, timeoutMs: number): Promise<FloodResult[]> {
  const out: FloodResult[] = [];
  for (let index = 0; index < tokens; index++) {
    const page = await render(collector, port, phase, "f2_render", timeoutMs);
    const token = tokenFrom(page);
    if (token === null) continue;
    for (let post = 0; post < postsPerToken; post++) { const exchange = await postFabricated(collector, port, phase, timeoutMs, "f2_post", token); out.push({ exchange, mutatedByClient: isRedirect(exchange) }); }
  }
  return out;
}

/** F3: a stateful farmer: render, POST the real token `postsPerToken` times, repeat. */
export async function runF3(collector: Collector, port: number, phase: string, journeys: number, postsPerToken: number, timeoutMs: number): Promise<FloodResult[]> {
  const out: FloodResult[] = [];
  for (let index = 0; index < journeys; index++) {
    const page = await render(collector, port, phase, "f3_render", timeoutMs);
    const token = tokenFrom(page);
    if (token === null) continue;
    for (let post = 0; post < postsPerToken; post++) { const exchange = await postFabricated(collector, port, phase, timeoutMs, "f3_post", token); out.push({ exchange, mutatedByClient: isRedirect(exchange) }); }
  }
  return out;
}

export async function runF4Renders(collector: Collector, port: number, phase: string, renders: number, concurrency: number, timeoutMs: number): Promise<number> {
  const results = await flood(renders, concurrency, async () => ({ exchange: await render(collector, port, phase, "f4_render", timeoutMs), mutatedByClient: false }));
  return results.filter((result) => result.exchange.result === "response" && result.exchange.status === 200).length;
}

// ---------------------------------------------------------------------------
// Forced fixtures (C1 / C2): exact bytes, with the L1 reason the layer must really compute
// ---------------------------------------------------------------------------

export type ForcedFixture = {
  id: string;
  method: "GET" | "POST" | "OTHER";
  rawMethod: string;
  target: string;
  /** Extra request header lines (the Host, Connection and correlation headers are added by the builder). */
  headers: readonly string[];
  /** Latin-1 body, or null. */
  body: string | null;
  /** The reject reason L1 (the real layer) must compute: recorded as the shadow of the simulated pass. */
  l1Reason: string;
  /** Every terminal explanation this fixture may legitimately end in (the ledger decides which). */
  terminals: readonly string[];
};

const FIXED_TOKEN = "A".repeat(43);
const POST_HEADERS = (port: string): string[] => [`Content-Type: ${FORM}`, `Origin: http://127.0.0.1:${port}`];

/** `{PORT}` in a header is replaced by the plane's port when the bytes are built; the digest pins the TEMPLATE, the override matches the built bytes. */
const post = (id: string, body: string, l1Reason: string, terminals: string[]): ForcedFixture => ({
  id, method: "POST", rawMethod: "POST", target: "/api/public-inquiries", headers: POST_HEADERS("{PORT}"), body, l1Reason, terminals,
});

const MUTATION_TERMINALS = ["app_executed_no_mutation", "l2_shed:unverified:lane_budget"];

export const FORCED_FIXTURES: readonly ForcedFixture[] = Object.freeze([
  post("fx_unknown_field", "evil=1", "a7.form_field_not_allowed", MUTATION_TERMINALS),
  post("fx_duplicate_field", "name=a&name=b", "a7.form_field_duplicate", MUTATION_TERMINALS),
  post("fx_token_shape", "submissionToken=short", "a7.form_token_malformed", MUTATION_TERMINALS),
  post("fx_bad_percent", "name=%zz", "a7.body_encoding_invalid", MUTATION_TERMINALS),
  post("fx_too_many_fields", Array.from({ length: 20 }, (_, index) => `name${index}=a`).join("&"), "a7.form_field_count_exceeded", MUTATION_TERMINALS),
  post("fx_valid_plus_extra", `${validFormBody(FIXED_TOKEN)}&evil=1`, "a7.form_field_not_allowed", MUTATION_TERMINALS),
  { id: "fx_path_admin", method: "GET", rawMethod: "GET", target: "/admin", headers: [], body: null, l1Reason: "a7.path_not_allowed", terminals: ["app_executed_no_mutation", "l2_shed:unverified:lane_budget"] },
  { id: "fx_query_root", method: "GET", rawMethod: "GET", target: "/?x=1", headers: [], body: null, l1Reason: "a7.query_not_allowed", terminals: ["app_executed_no_mutation", "l2_shed:unverified:lane_budget"] },
  { id: "fx_method_options", method: "OTHER", rawMethod: "OPTIONS", target: "/", headers: [], body: null, l1Reason: "a7.method_not_allowed", terminals: ["canon_refused", "l2_shed:unverified:lane_budget"] },
  { id: "fx_content_type_json", method: "POST", rawMethod: "POST", target: "/api/public-inquiries", headers: ["Content-Type: application/json", "Origin: http://127.0.0.1:{PORT}"], body: "{}", l1Reason: "a7.content_type_invalid", terminals: ["canon_refused", "l2_shed:unverified:lane_budget"] },
  { id: "fx_sem_dup_origin", method: "GET", rawMethod: "GET", target: "/gizlilik", headers: ["Origin: http://a.test", "Origin: http://b.test"], body: null, l1Reason: "a7.semantic_duplicate", terminals: ["canon_refused"] },
  { id: "fx_sem_refused_header", method: "GET", rawMethod: "GET", target: "/", headers: ["Authorization: Bearer fixture"], body: null, l1Reason: "a7.semantic_refused_header", terminals: ["canon_refused"] },
]);

/** The pinned identity of the forced set: any change to a fixture changes this digest and fails the contract test. */
export const FORCED_FIXTURE_SET_DIGEST = createHash("sha256").update(JSON.stringify(FORCED_FIXTURES)).digest("hex");

/** The exact request bytes of a forced fixture for a given plane port and correlation nonce. */
export function forcedRequestBytes(fixture: ForcedFixture, port: number, nonce: string): Buffer {
  const lines = [`${fixture.rawMethod} ${fixture.target} HTTP/1.1`, `Host: 127.0.0.1:${port}`, "Connection: close", `X-Ba0-Nonce: ${nonce}`];
  const body = fixture.body === null ? Buffer.alloc(0) : Buffer.from(fixture.body, "latin1");
  if (fixture.body !== null) lines.push(`Content-Length: ${body.length}`);
  for (const header of fixture.headers) lines.push(header.replace("{PORT}", String(port)));
  return Buffer.concat([Buffer.from(lines.join(CRLF) + CRLF + CRLF, "latin1"), body]);
}

/** What the plane will see as the request's identity (method, target, body), for the override's digest. */
export function forcedIdentity(fixture: ForcedFixture): { method: string; target: string; body: Uint8Array | null } {
  return { method: fixture.rawMethod, target: fixture.target, body: fixture.body === null ? null : new Uint8Array(Buffer.from(fixture.body, "latin1")) };
}
