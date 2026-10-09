/**
 * BA0 Slice 2 known-address direct corpus: a deterministic, FIXED-COUNT list of requests sent over raw loopback TCP straight at the
 * Origin Boundary's address (and, as a stricter extra, at the Protected App's own port). The harness is intentionally GIVEN both
 * addresses; the claim under test is that knowing them alone provides no path to application semantics or state.
 *
 *   - 107 requests lack a valid, request-bound, fresh, single-use proof chain and MUST be refused with an exact reason, with zero
 *     application admission, execution or mutation (lanes direct_boundary_rejected / direct_app_rejected).
 *   - 3 are labelled POSITIVE CONTROLS (lanes positive_control_boundary / positive_control_app): a genuine proof, minted by the lab
 *     trust root, is admitted exactly once and executes without mutating. They are separate lanes and never satisfy a protected identity.
 *
 * Nothing here is a load ramp: every case is sent once (a replay is part of its case), nothing leaves 127.0.0.1, and the label never goes
 * on the wire. The LEDGER, not the client, decides whether a case behaved as specified. Proof material is never written to evidence.
 */
import type { ExpectedLane } from "../../defense/core/ledger";
import type { ObReason } from "../../defense/core/types";
import { trackedRaw, newNonce, type Exchange, type RawSpec } from "./client";
import type { Collector, LedgerRecord, RequestMeta } from "./collector";
import { HopTrustRoot, type Minted, type OracleRequest } from "./hop-keys";

const CRLF = "\r\n";
const FORM = "application/x-www-form-urlencoded";
const HOST = "limitmark.test";
const ORIGIN = `http://${HOST}`;
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export type DirectContext = {
  boundaryPort: number;
  appPort: number;
  root: HopTrustRoot;
  collector: Collector;
  timeoutMs: number;
  /** Wall-clock instant just before the boundary was spawned (strictly before its verifier-start fence). */
  boundarySpawnedAtMs: number;
};
export type DirectExpect = { kind: "reject"; reason: ObReason } | { kind: "parser" } | { kind: "admit_once" };
export type DirectEntry = { id: string; family: string; target: "boundary" | "app"; lane: ExpectedLane; method: RequestMeta["method"]; expect: DirectExpect };
export type DirectExecuted = { id: string; nonce: string; exchange: Exchange };
export type DirectScenario = { name: string; phase: "startup" | "main"; entries: DirectEntry[]; run(context: DirectContext): Promise<DirectExecuted[]> };

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

type Header = [name: string, value: string];
const EMPTY = Buffer.alloc(0);
const req = (method: "GET" | "POST", target: string, extra: Partial<OracleRequest> = {}): OracleRequest => ({ method, target, host: HOST, body: EMPTY, ...extra });

const S_GET: OracleRequest = req("GET", "/gizlilik");
const S_GET_FORM: OracleRequest = req("GET", "/test-talep-et");
const S_GET_O: OracleRequest = req("GET", "/gizlilik", { origin: ORIGIN });
/** Shape-valid but semantically invalid form (no required fields): the application executes it and answers 200 with errors, mutating nothing. */
const S_POST: OracleRequest = req("POST", "/api/public-inquiries", { origin: ORIGIN, contentType: FORM, body: Buffer.from("name=A") });
const validForm = (token: string): Buffer => Buffer.from(new URLSearchParams({
  name: "Canary Journey", email: "canary@example.test", company: "Synthetic Co", service: "web", system: "synthetic canary system", objective: "synthetic canary objective",
  environment: "staging", authority: "authorized", protection: "unknown", provider: "", notes: "", submissionToken: token,
}).toString());
const FORM_A = validForm("A".repeat(43));
const FORM_B = validForm("B".repeat(43));

function baseHeaders(request: OracleRequest, tag: string): Header[] {
  const headers: Header[] = [["Host", request.host]];
  if (request.origin !== undefined) headers.push(["Origin", request.origin]);
  if (request.method === "POST") { headers.push(["Content-Type", request.contentType ?? FORM], ["Content-Length", String(request.body.length)]); }
  headers.push(["Connection", "close"], ["X-Ba0-Nonce", tag]);
  return headers;
}
const set = (headers: Header[], name: string, value: string): Header[] => headers.map(([n, v]) => (n.toLowerCase() === name.toLowerCase() ? [n, value] : [n, v]));
const drop = (headers: Header[], name: string): Header[] => headers.filter(([n]) => n.toLowerCase() !== name.toLowerCase());
const add = (headers: Header[], name: string, value: string): Header[] => [...headers, [name, value]];

function head(method: string, target: string, headers: Header[], body: Buffer = EMPTY): Buffer {
  const lines = [`${method} ${target} HTTP/1.1`, ...headers.map(([name, value]) => `${name}: ${value}`)];
  return Buffer.concat([Buffer.from(lines.join(CRLF) + CRLF + CRLF, "latin1"), body]);
}

const PB = "X-Ba0-Hop-Pb";
const BA = "X-Ba0-Hop-Ba";

async function fire(context: DirectContext, entry: DirectEntry, build: (nonce: string) => RawSpec): Promise<DirectExecuted> {
  const port = entry.target === "boundary" ? context.boundaryPort : context.appPort;
  const meta: RequestMeta = { lane: entry.lane, phase: "direct", cls: "hostile", scenario: entry.id, journey: null, step: null, method: entry.method };
  const exchange = await trackedRaw(context.collector, port, meta, build, context.timeoutMs);
  return { id: entry.id, nonce: exchange.nonce, exchange };
}

// ---------------------------------------------------------------------------
// Case construction
// ---------------------------------------------------------------------------

const bnd = (id: string, family: string, method: RequestMeta["method"], expect: DirectExpect, lane: ExpectedLane = "direct_boundary_rejected"): DirectEntry => ({ id, family, target: "boundary", lane, method, expect });
const app = (id: string, family: string, method: RequestMeta["method"], expect: DirectExpect, lane: ExpectedLane = "direct_app_rejected"): DirectEntry => ({ id, family, target: "app", lane, method, expect });
const rej = (reason: ObReason): DirectExpect => ({ kind: "reject", reason });

function single(entry: DirectEntry, build: (context: DirectContext, nonce: string) => RawSpec, phase: DirectScenario["phase"] = "main"): DirectScenario {
  return { name: entry.id, phase, entries: [entry], run: async (context) => [await fire(context, entry, (nonce) => build(context, nonce))] };
}

type BoundaryVariant = {
  signed: OracleRequest;
  /** What differs on the wire from what was signed. */
  wire?: Partial<OracleRequest>;
  mutate?: (headers: Header[]) => Header[];
  mint?: (context: DirectContext, nonce: string) => Partial<Parameters<HopTrustRoot["mintPb"]>[0]>;
};

/** A request to the boundary carrying a GENUINE (or deliberately altered) PB proof for `signed`, with `wire` and `mutate` altering what is sent. */
function proofCase(entry: DirectEntry, variant: BoundaryVariant, phase: DirectScenario["phase"] = "main"): DirectScenario {
  return single(entry, (context, nonce) => {
    const pb = context.root.mintPb({ request: variant.signed, corr: nonce, ...(variant.mint?.(context, nonce) ?? {}) });
    const wire: OracleRequest = { ...variant.signed, ...variant.wire };
    let headers = add(baseHeaders(wire, nonce), PB, pb.header);
    if (variant.mutate) headers = variant.mutate(headers);
    return { head: head(wire.method, wire.target, headers, wire.method === "POST" ? wire.body : EMPTY) };
  }, phase);
}

/** A request with no proof at all, to a port the harness knows. */
function bareCase(entry: DirectEntry, method: string, target: string, extra: Header[] = [], body: Buffer = EMPTY): DirectScenario {
  return single(entry, (context, nonce) => {
    const port = entry.target === "boundary" ? context.boundaryPort : context.appPort;
    const headers: Header[] = [["Host", `127.0.0.1:${port}`], ["Connection", "close"], ["X-Ba0-Nonce", nonce], ...extra];
    return { head: head(method, target, headers, body) };
  });
}

const rejectedAt = (reason: ObReason) => rej(reason);
const POST = "POST";

function noProofCases(): DirectScenario[] {
  const post = (extra: Header[] = [], body: Buffer = EMPTY): Header[] => [["Content-Type", FORM], ["Content-Length", String(body.length)], ...extra];
  return [
    bareCase(bnd("np_get_root", "no_proof", "GET", rejectedAt("ob.proof_missing")), "GET", "/"),
    bareCase(bnd("np_get_privacy", "no_proof", "GET", rejectedAt("ob.proof_missing")), "GET", "/gizlilik"),
    bareCase(bnd("np_get_form", "no_proof", "GET", rejectedAt("ob.proof_missing")), "GET", "/test-talep-et"),
    // The sharpest case: the exact bytes of a valid canary submission, sent directly at the known address.
    single(bnd("np_post_valid_form", "no_proof", POST, rejectedAt("ob.proof_missing")), (context, nonce) => ({
      head: head("POST", "/api/public-inquiries", [["Host", `127.0.0.1:${context.boundaryPort}`], ["Origin", `http://127.0.0.1:${context.boundaryPort}`], ...post([], FORM_A), ["Connection", "close"], ["X-Ba0-Nonce", nonce]], FORM_A),
    })),
    bareCase(bnd("np_post_empty", "no_proof", POST, rejectedAt("ob.proof_missing")), "POST", "/api/public-inquiries", post()),
    // Declared 10 MiB, none sent: the boundary must refuse without reading a body byte.
    bareCase(bnd("np_post_oversize_decl", "no_proof", POST, rejectedAt("ob.proof_missing")), "POST", "/api/public-inquiries", [["Content-Type", FORM], ["Content-Length", "10485760"]]),
    bareCase(bnd("np_options", "no_proof", "OTHER", rejectedAt("ob.proof_missing")), "OPTIONS", "/"),
    bareCase(bnd("np_trace", "no_proof", "OTHER", rejectedAt("ob.proof_missing")), "TRACE", "/"),
    bareCase(bnd("np_absolute_form", "no_proof", "GET", rejectedAt("ob.proof_missing")), "GET", "http://evil.example/"),
    bareCase(bnd("np_chunked_post", "no_proof", POST, rejectedAt("ob.proof_missing")), "POST", "/api/public-inquiries", [["Content-Type", FORM], ["Transfer-Encoding", "chunked"]], Buffer.from("5\r\nname=\r\n0\r\n\r\n")),
  ];
}

function spoofCases(): DirectScenario[] {
  return [
    bareCase(bnd("sp_plain_hop_nonce", "spoof", "GET", rejectedAt("ob.proof_missing")), "GET", "/gizlilik", [["X-Ba0-Hop", "1"]]),
    bareCase(bnd("sp_forwarding_headers", "spoof", "GET", rejectedAt("ob.proof_missing")), "GET", "/gizlilik", [["X-Forwarded-For", "10.0.0.1"], ["X-Real-IP", "10.0.0.2"], ["Forwarded", "for=10.0.0.3"], ["CF-Connecting-IP", "10.0.0.4"]]),
    // A static secret opens nothing: there is no static-secret path.
    bareCase(bnd("sp_static_secret_style", "spoof", "GET", rejectedAt("ob.proof_missing")), "GET", "/", [["Authorization", "Bearer not-a-secret"], ["X-Limitmark-Origin-Secret", "not-a-secret"], ["X-Vercel-Protection-Bypass", "x"]]),
    single(bnd("sp_expect_continue", "spoof", POST, rejectedAt("ob.expect_refused")), (context, nonce) => ({
      head: head("POST", "/api/public-inquiries", [["Host", `127.0.0.1:${context.boundaryPort}`], ["Expect", "100-continue"], ["Content-Type", FORM], ["Content-Length", "6"], ["Connection", "close"], ["X-Ba0-Nonce", nonce]], Buffer.from("name=A")),
    })),
  ];
}

function malformedCases(): DirectScenario[] {
  const entry = (id: string, reason: ObReason) => bnd(id, "malformed", "GET", rejectedAt(reason));
  const raw = (id: string, reason: ObReason, value: (valid: string) => string): DirectScenario => single(entry(id, reason), (context, nonce) => {
    const valid = context.root.mintPb({ request: S_GET, corr: nonce }).header;
    return { head: head("GET", S_GET.target, add(baseHeaders(S_GET, nonce), PB, value(valid))) };
  });
  const b64 = (text: string) => Buffer.from(text).toString("base64url");
  const nonCanonical = (header: string): string => {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = header[header.length - 1];
    return `${header.slice(0, -1)}${alphabet[(alphabet.indexOf(last) + 1) % 64]}`;
  };
  return [
    raw("mf_not_b64url", "ob.proof_malformed", () => "!!!not-a-proof!!!"),
    raw("mf_one_part", "ob.proof_malformed", (valid) => valid.split(".")[0]),
    raw("mf_three_parts", "ob.proof_malformed", (valid) => `${valid}.AAAA`),
    raw("mf_noncanonical_b64", "ob.proof_malformed", nonCanonical),
    raw("mf_short_signature", "ob.proof_malformed", (valid) => `${valid.split(".")[0]}.${valid.split(".")[1].slice(0, 80)}`),
    raw("mf_json_object", "ob.proof_malformed", (valid) => `${b64('{"a":1}')}.${valid.split(".")[1]}`),
    single(entry("mf_wrong_field_count", "ob.proof_malformed"), (context, nonce) => ({ head: head("GET", S_GET.target, add(baseHeaders(S_GET, nonce), PB, context.root.mintPb({ request: S_GET, corr: nonce, truncate: true }).header)) })),
    raw("mf_oversize", "ob.proof_oversize", () => `${"A".repeat(3_000)}.${"A".repeat(86)}`),
    single(entry("mf_duplicate_header", "ob.proof_duplicate"), (context, nonce) => {
      const a = context.root.mintPb({ request: S_GET, corr: nonce }).header;
      const b = context.root.mintPb({ request: S_GET, corr: nonce }).header;
      return { head: head("GET", S_GET.target, add(add(baseHeaders(S_GET, nonce), PB, a), PB, b)) };
    }),
  ];
}

function bindingCases(): DirectScenario[] {
  const c = (id: string, method: RequestMeta["method"], reason: ObReason) => bnd(id, "binding", method, rejectedAt(reason));
  return [
    proofCase(c("bd_wrong_method", POST, "ob.method_mismatch"), { signed: S_POST, wire: { method: "GET", body: EMPTY } }),
    proofCase(c("bd_wrong_path", "GET", "ob.target_mismatch"), { signed: S_GET, wire: { target: "/" } }),
    proofCase(c("bd_wrong_query", "GET", "ob.target_mismatch"), { signed: S_GET_FORM, wire: { target: "/test-talep-et?hizmet=web" } }),
    proofCase(c("bd_wrong_encoding", "GET", "ob.target_mismatch"), { signed: S_GET, wire: { target: "/%67izlilik" } }),
    proofCase(c("bd_body_same_len", POST, "ob.digest_mismatch"), { signed: S_POST, wire: { body: Buffer.from("name=B") } }),
    proofCase(c("bd_body_longer", POST, "ob.length_mismatch"), { signed: S_POST, wire: { body: Buffer.from("name=AAAA") } }),
    proofCase(c("bd_body_removed", POST, "ob.length_mismatch"), { signed: S_POST, wire: { body: EMPTY } }),
    // Credential from another request: same method and target, a different (valid) form.
    proofCase(c("bd_other_request_body", POST, "ob.digest_mismatch"), { signed: req("POST", "/api/public-inquiries", { origin: ORIGIN, contentType: FORM, body: FORM_A }), wire: { body: FORM_B } }),
  ];
}

function hopCases(): DirectScenario[] {
  const c = (id: string, family: string, reason: ObReason) => bnd(id, family, "GET", rejectedAt(reason));
  const now = () => Date.now();
  // ONE clock read per proof: reading it separately for iat and exp makes the lifetime drift by the elapsed milliseconds, and a case that sits exactly
  // at the maximum lifetime (tm_expired) would flip from ob.expired to ob.lifetime_invalid when the clock ticks between the reads.
  const issuedAt = (base: number, offsetMs: number, lifetimeMs: number) => ({ iat: base + offsetMs, exp: base + offsetMs + lifetimeMs });
  return [
    proofCase(c("hp_wrong_audience", "hop", "ob.audience_mismatch"), { signed: S_GET, mint: (context) => ({ aud: context.root.appId }) }),
    proofCase(c("hp_ba_role_in_pb_slot", "hop", "ob.wrong_hop"), { signed: S_GET, mint: () => ({ role: "ba0-ba-v2" }) }),
    proofCase(c("tm_expired", "time", "ob.expired"), { signed: S_GET, mint: () => issuedAt(now(), -20_000, 5_000) }),
    proofCase(c("tm_future", "time", "ob.not_yet_valid"), { signed: S_GET, mint: () => issuedAt(now(), 30_000, 4_000) }),
    proofCase(c("tm_lifetime_long", "time", "ob.lifetime_invalid"), { signed: S_GET, mint: () => issuedAt(now(), 0, 60_000) }),
    // Issued before the verifier started but not yet expired: only possible in the first seconds, so it runs at startup.
    proofCase(c("tm_before_fence", "time", "ob.before_fence"), { signed: S_GET, mint: (context) => ({ iat: context.boundarySpawnedAtMs - 50, exp: context.boundarySpawnedAtMs + 4_850 }) }, "startup"),
    proofCase(c("fg_attacker_same_kid", "forged", "ob.signature_invalid"), { signed: S_GET, mint: () => ({ key: "attacker" }) }),
    proofCase(c("fg_unknown_kid", "forged", "ob.key_unknown"), { signed: S_GET, mint: () => ({ kid: "pb-unknown" }) }),
  ];
}

function semanticCases(): DirectScenario[] {
  const sc = (id: string, method: RequestMeta["method"], reason: ObReason) => bnd(id, "semantic", method, rejectedAt(reason));
  const mismatch = "ob.header_mismatch" as const;
  const unbound = "ob.header_unbound" as const;
  const duplicate = "ob.header_duplicate" as const;
  const cases: DirectScenario[] = [
    // --- Content-Type
    proofCase(sc("sc_ct_altered", POST, mismatch), { signed: S_POST, mutate: (h) => set(h, "Content-Type", "text/plain") }),
    proofCase(sc("sc_ct_case_variant", POST, mismatch), { signed: S_POST, mutate: (h) => set(h, "Content-Type", "Application/X-WWW-Form-Urlencoded") }),
    proofCase(sc("sc_ct_param_variant", POST, mismatch), { signed: S_POST, mutate: (h) => set(h, "Content-Type", `${FORM}; charset=utf-8`) }),
    proofCase(sc("sc_ct_removed", POST, mismatch), { signed: S_POST, mutate: (h) => drop(h, "Content-Type") }),
    // --- Host / authority
    proofCase(sc("sc_host_altered_authority", "GET", mismatch), { signed: S_GET, mutate: (h) => set(h, "Host", "evil.test") }),
    proofCase(sc("sc_host_case_variant", "GET", mismatch), { signed: S_GET, mutate: (h) => set(h, "Host", "LIMITMARK.test") }),
    proofCase(sc("sc_host_default_port", "GET", mismatch), { signed: S_GET, mutate: (h) => set(h, "Host", `${HOST}:80`) }),
    proofCase(sc("sc_host_trailing_dot", "GET", mismatch), { signed: S_GET, mutate: (h) => set(h, "Host", `${HOST}.`) }),
    proofCase(sc("sc_host_empty", "GET", "ob.header_value_invalid"), { signed: S_GET, mutate: (h) => set(h, "Host", "") }),
    // --- Origin
    proofCase(sc("sc_origin_altered", "GET", mismatch), { signed: S_GET_O, mutate: (h) => set(h, "Origin", "http://evil.test") }),
    proofCase(sc("sc_origin_added_unsigned", "GET", mismatch), { signed: S_GET, mutate: (h) => add(h, "Origin", ORIGIN) }),
    proofCase(sc("sc_origin_removed_signed", "GET", mismatch), { signed: S_GET_O, mutate: (h) => drop(h, "Origin") }),
    proofCase(sc("sc_origin_trailing_slash", "GET", mismatch), { signed: S_GET_O, mutate: (h) => set(h, "Origin", `${ORIGIN}/`) }),
    proofCase(sc("sc_origin_case_variant", "GET", mismatch), { signed: S_GET_O, mutate: (h) => set(h, "Origin", `HTTP://${HOST}`) }),
    proofCase(sc("sc_origin_empty", "GET", "ob.header_value_invalid"), { signed: S_GET_O, mutate: (h) => set(h, "Origin", "") }),
  ];
  // --- injected forwarding / internal headers, each with an otherwise valid proof
  for (const [id, name, value] of [
    ["sc_inj_xff", "X-Forwarded-For", "10.0.0.1"], ["sc_inj_xfh", "X-Forwarded-Host", HOST], ["sc_inj_real_ip", "X-Real-IP", "10.0.0.2"],
    ["sc_inj_forwarded", "Forwarded", "for=10.0.0.3"], ["sc_inj_cf_ip", "CF-Connecting-IP", "10.0.0.4"], ["sc_inj_origin_secret", "X-Limitmark-Origin-Secret", "not-a-secret"],
    ["sc_inj_vercel_xff", "X-Vercel-Forwarded-For", "10.0.0.5"], ["sc_inj_method_override", "X-HTTP-Method-Override", "POST"], ["sc_inj_plain_hop", "X-Ba0-Hop", "1"],
    // --- injected headers that are not spoofable but are outside the closed set
    ["sc_inj_cookie", "Cookie", "a=b"], ["sc_inj_accept", "Accept", "text/html"], ["sc_inj_authorization", "Authorization", "Bearer not-a-secret"],
  ] as const) cases.push(proofCase(sc(id, "GET", unbound), { signed: S_GET, mutate: (h) => add(h, name, value) }));
  cases.push(
    // --- duplicate semantic headers
    proofCase(sc("sc_dup_host_differing", "GET", duplicate), { signed: S_GET, mutate: (h) => add(h, "Host", "evil.test") }),
    proofCase(sc("sc_dup_host_same", "GET", duplicate), { signed: S_GET, mutate: (h) => add(h, "Host", HOST) }),
    proofCase(sc("sc_dup_origin", "GET", duplicate), { signed: S_GET_O, mutate: (h) => add(h, "Origin", "http://evil.test") }),
    proofCase(sc("sc_dup_origin_case", "GET", duplicate), { signed: S_GET_O, mutate: (h) => add(h, "ORIGIN", ORIGIN) }),
    proofCase(sc("sc_dup_ct", POST, duplicate), { signed: S_POST, mutate: (h) => add(h, "Content-Type", "text/plain") }),
    proofCase(sc("sc_dup_ct_case", POST, duplicate), { signed: S_POST, mutate: (h) => add(h, "CONTENT-TYPE", FORM) }),
    // A duplicated Content-Length is refused by the HTTP parser itself, before any request exists (an anonymous, counted parser refusal).
    proofCase({ ...sc("sc_dup_content_length", POST, "ob.framing_invalid"), expect: { kind: "parser" } }, { signed: S_POST, mutate: (h) => add(h, "Content-Length", String(S_POST.body.length)) }),
    // --- other canonicalization variants
    proofCase(sc("sc_origin_internal_htab", "GET", "ob.header_value_invalid"), { signed: S_GET_O, mutate: (h) => set(h, "Origin", `${ORIGIN}\tx`) }),
    proofCase(sc("sc_host_userinfo", "GET", mismatch), { signed: S_GET, mutate: (h) => set(h, "Host", `user@${HOST}`) }),
  );
  return cases;
}

function crossHopBoundaryCases(): DirectScenario[] {
  const c = (id: string, reason: ObReason) => bnd(id, "cross_hop", "GET", rejectedAt(reason));
  return [
    single(c("xh_ba_only_at_boundary", "ob.proof_missing"), (context, nonce) => ({ head: head("GET", S_GET.target, add(baseHeaders(S_GET, nonce), BA, context.root.mintChain(S_GET, nonce).ba.header)) })),
    single(c("xh_ba_in_pb_slot", "ob.wrong_hop"), (context, nonce) => ({ head: head("GET", S_GET.target, add(baseHeaders(S_GET, nonce), PB, context.root.mintChain(S_GET, nonce).ba.header)) })),
    proofCase(c("xh_pb_signed_with_kb", "ob.signature_invalid"), { signed: S_GET, mint: () => ({ key: "B" }) }),
    single(c("xh_pb_plus_ba_header", "ob.header_unbound"), (context, nonce) => {
      const chain = context.root.mintChain(S_GET, nonce);
      return { head: head("GET", S_GET.target, add(add(baseHeaders(S_GET, nonce), PB, chain.pb.header), BA, chain.ba.header)) };
    }),
  ];
}

function replayBoundaryScenarios(): DirectScenario[] {
  const full = (request: OracleRequest, nonce: string, pb: string, body: Buffer = request.body): Buffer => head(request.method, request.target, add(baseHeaders({ ...request, body }, nonce), PB, pb), body);

  const stall: DirectScenario = {
    name: "replay_stall_race", phase: "main",
    entries: [
      bnd("rp_stall_winner", "replay", POST, { kind: "admit_once" }, "positive_control_boundary"),
      bnd("rp_stall_replay_1", "replay", POST, rej("ob.replayed")), bnd("rp_stall_replay_2", "replay", POST, rej("ob.replayed")), bnd("rp_stall_replay_3", "replay", POST, rej("ob.replayed")),
    ],
    async run(context) {
      let pb = "";
      const [winner, ...replays] = this.entries;
      // The winner presents the valid proof but stalls its body, holding the reservation (RESERVED) while the replays arrive.
      const first = fire(context, winner, (nonce) => {
        pb = context.root.mintPb({ request: S_POST, corr: nonce }).header;
        const whole = full(S_POST, nonce, pb);
        const split = whole.length - 3;
        return { head: whole.subarray(0, split), tail: whole.subarray(split), afterMs: 700 };
      });
      await sleep(250);
      const rest = await Promise.all(replays.map((entry) => fire(context, entry, (nonce) => ({ head: full(S_POST, nonce, pb) }))));
      return [await first, ...rest];
    },
  };

  const abort: DirectScenario = {
    name: "replay_abort_burn", phase: "main",
    entries: [bnd("rp_abort_burn", "replay", POST, rej("ob.content_incomplete")), bnd("rp_abort_replay", "replay", POST, rej("ob.replayed"))],
    async run(context) {
      let pb = "";
      const aborted = await fire(context, this.entries[0], (nonce) => {
        pb = context.root.mintPb({ request: S_POST, corr: nonce }).header;
        const whole = full(S_POST, nonce, pb);
        return { head: whole.subarray(0, whole.length - 3), closeAfterMs: 150 };
      });
      await sleep(100);
      const replay = await fire(context, this.entries[1], (nonce) => ({ head: full(S_POST, nonce, pb) }));
      return [aborted, replay];
    },
  };

  const sequential: DirectScenario = {
    name: "replay_sequential", phase: "main",
    entries: [
      bnd("rp_seq_first_use", "replay", POST, { kind: "admit_once" }, "positive_control_boundary"), bnd("rp_seq_immediate", "replay", POST, rej("ob.replayed")),
      bnd("rp_seq_after_delay", "replay", POST, rej("ob.replayed")), bnd("rp_seq_modified_body", "replay", POST, rej("ob.replayed")),
    ],
    async run(context) {
      let pb = "";
      const out: DirectExecuted[] = [];
      out.push(await fire(context, this.entries[0], (nonce) => { pb = context.root.mintPb({ request: S_POST, corr: nonce }).header; return { head: full(S_POST, nonce, pb) }; }));
      out.push(await fire(context, this.entries[1], (nonce) => ({ head: full(S_POST, nonce, pb) })));
      await sleep(300);
      out.push(await fire(context, this.entries[2], (nonce) => ({ head: full(S_POST, nonce, pb) })));
      // Replay precedes the digest check: the same proof with a same-length, different body is `replayed`, not `digest_mismatch`.
      out.push(await fire(context, this.entries[3], (nonce) => ({ head: full(S_POST, nonce, pb, Buffer.from("name=B")) })));
      return out;
    },
  };
  return [stall, abort, sequential];
}

// ---------------------------------------------------------------------------
// Protected App, known address
// ---------------------------------------------------------------------------

type AppHeaders = { ba?: string; pb?: string };

function appCase(entry: DirectEntry, signed: OracleRequest, proofs: (context: DirectContext, nonce: string) => AppHeaders, mutate?: (headers: Header[]) => Header[], wire: Partial<OracleRequest> = {}): DirectScenario {
  return single(entry, (context, nonce) => {
    const given = proofs(context, nonce);
    const wireRequest: OracleRequest = { ...signed, ...wire };
    let headers = baseHeaders(wireRequest, nonce);
    if (given.ba !== undefined) headers = add(headers, BA, given.ba);
    if (given.pb !== undefined) headers = add(headers, PB, given.pb);
    if (mutate) headers = mutate(headers);
    return { head: head(wireRequest.method, wireRequest.target, headers, wireRequest.method === "POST" ? wireRequest.body : EMPTY) };
  });
}

function appCases(): DirectScenario[] {
  const c = (id: string, family: string, method: RequestMeta["method"], reason: ObReason) => app(id, family, method, rejectedAt(reason));
  const chain = (request: OracleRequest) => (context: DirectContext, nonce: string): AppHeaders => { const made = context.root.mintChain(request, nonce); return { ba: made.ba.header, pb: made.pb.header }; };
  const other = req("GET", "/", {});
  return [
    // --- no proof / legacy
    bareCase(app("ap_np_get", "no_proof", "GET", rejectedAt("ob.proof_missing")), "GET", "/"),
    single(app("ap_np_post_valid_form", "no_proof", POST, rejectedAt("ob.proof_missing")), (context, nonce) => ({
      head: head("POST", "/api/public-inquiries", [["Host", `127.0.0.1:${context.appPort}`], ["Origin", `http://127.0.0.1:${context.appPort}`], ["Content-Type", FORM], ["Content-Length", String(FORM_A.length)], ["Connection", "close"], ["X-Ba0-Nonce", nonce]], FORM_A),
    })),
    bareCase(app("ap_plain_hop_nonce", "no_proof", "GET", rejectedAt("ob.proof_missing")), "GET", "/gizlilik", [["X-Ba0-Hop", "1"]]),
    // --- cross-hop: a Plane proof must never admit at the App, and a Boundary proof alone must never either
    appCase(c("ap_pb_only", "cross_hop", "GET", "ob.proof_missing"), S_GET, (context, nonce) => ({ pb: context.root.mintPb({ request: S_GET, corr: nonce }).header })),
    appCase(c("ap_pb_in_ba_slot", "cross_hop", "GET", "ob.wrong_hop"), S_GET, (context, nonce) => { const pb = context.root.mintPb({ request: S_GET, corr: nonce }).header; return { ba: pb, pb }; }),
    // A compromised Boundary holds K_B and nothing else: it signs a BA for an arbitrary valid submission. With no Plane lineage the App must refuse it.
    appCase(c("ap_compromised_boundary", "cross_hop", POST, "ob.lineage_missing"), req("POST", "/api/public-inquiries", { origin: ORIGIN, contentType: FORM, body: FORM_A }), (context, nonce) => ({
      ba: context.root.mintBa({ request: req("POST", "/api/public-inquiries", { origin: ORIGIN, contentType: FORM, body: FORM_A }), corr: nonce, pb: { header: "forged.lineage", jti: "A".repeat(22) } }).header,
    })),
    appCase(c("ap_ba_attacker_pb", "cross_hop", "GET", "ob.signature_invalid"), S_GET, (context, nonce) => {
      const pb = context.root.mintPb({ request: S_GET, corr: nonce, key: "attacker" });
      return { pb: pb.header, ba: context.root.mintBa({ request: S_GET, corr: nonce, hop: pb.hop, pb }).header };
    }),
    appCase(c("ap_ba_other_request_pb", "cross_hop", "GET", "ob.lineage_mismatch"), other, (context, nonce) => {
      const pb = context.root.mintPb({ request: S_GET, corr: nonce });
      return { pb: pb.header, ba: context.root.mintBa({ request: other, corr: nonce, hop: pb.hop, pb }).header };
    }),
    appCase(c("ap_ba_aud_boundary", "cross_hop", "GET", "ob.audience_mismatch"), S_GET, (context, nonce) => {
      const pb = context.root.mintPb({ request: S_GET, corr: nonce });
      return { pb: pb.header, ba: context.root.mintBa({ request: S_GET, corr: nonce, hop: pb.hop, pb, aud: context.root.boundaryId }).header };
    }),
    appCase(c("ap_ba_signed_with_kp", "cross_hop", "GET", "ob.signature_invalid"), S_GET, (context, nonce) => {
      const pb = context.root.mintPb({ request: S_GET, corr: nonce });
      return { pb: pb.header, ba: context.root.mintBa({ request: S_GET, corr: nonce, hop: pb.hop, pb, key: "P" }).header };
    }),
    appCase(c("ap_role_swap", "cross_hop", "GET", "ob.wrong_hop"), S_GET, (context, nonce) => {
      const pb = context.root.mintPb({ request: S_GET, corr: nonce });
      return { pb: pb.header, ba: context.root.mintBa({ request: S_GET, corr: nonce, hop: pb.hop, pb, role: "ba0-pb-v2" }).header };
    }),
    appCase(c("ap_domain_swap", "cross_hop", "GET", "ob.signature_invalid"), S_GET, (context, nonce) => {
      const pb = context.root.mintPb({ request: S_GET, corr: nonce });
      return { pb: pb.header, ba: context.root.mintBa({ request: S_GET, corr: nonce, hop: pb.hop, pb, domain: "ba0:pb:ed25519:v2\0" }).header };
    }),
    // --- semantic binding at the App, with a genuine chain
    appCase(c("ap_sem_origin_altered", "semantic", "GET", "ob.header_mismatch"), S_GET_O, chain(S_GET_O), (h) => set(h, "Origin", "http://evil.test")),
    appCase(c("ap_sem_inj_xfh", "semantic", "GET", "ob.header_unbound"), S_GET, chain(S_GET), (h) => add(h, "X-Forwarded-Host", HOST)),
    appCase(c("ap_sem_dup_host", "semantic", "GET", "ob.header_duplicate"), S_GET, chain(S_GET), (h) => add(h, "Host", "evil.test")),
    appCase(c("ap_sem_ct_altered", "semantic", POST, "ob.header_mismatch"), S_POST, chain(S_POST), (h) => set(h, "Content-Type", "text/plain")),
  ];
}

function appReplayScenarios(): DirectScenario[] {
  const wholeApp = (request: OracleRequest, nonce: string, ba: string, pb: string, body: Buffer = request.body): Buffer => head(request.method, request.target, add(add(baseHeaders({ ...request, body }, nonce), BA, ba), PB, pb), body);

  const lineage: DirectScenario = {
    name: "app_replay_lineage", phase: "main",
    entries: [
      app("ap_first_use", "replay", "GET", { kind: "admit_once" }, "positive_control_app"), app("ap_ba_replay", "replay", "GET", rej("ob.replayed")),
      app("ap_fresh_ba_same_pb", "replay", "GET", rej("ob.replayed")),
    ],
    async run(context) {
      let made: { pb: Minted; ba: Minted; corr: string } | null = null;
      const out: DirectExecuted[] = [];
      out.push(await fire(context, this.entries[0], (nonce) => {
        const chain = context.root.mintChain(S_GET, nonce);
        made = { ...chain, corr: nonce };
        return { head: wholeApp(S_GET, nonce, chain.ba.header, chain.pb.header) };
      }));
      const first = made!;
      out.push(await fire(context, this.entries[1], (nonce) => ({ head: wholeApp(S_GET, nonce, first.ba.header, first.pb.header) })));
      // A compromised Boundary re-relaying an approval it already used, with a FRESH BA of its own: the lineage replay set must stop it.
      out.push(await fire(context, this.entries[2], (nonce) => {
        const fresh = context.root.mintBa({ request: S_GET, corr: first.corr, hop: first.pb.hop, pb: first.pb });
        return { head: wholeApp(S_GET, nonce, fresh.header, first.pb.header) };
      }));
      return out;
    },
  };

  const abort: DirectScenario = {
    name: "app_replay_abort", phase: "main",
    entries: [app("ap_abort_burn", "replay", POST, rej("ob.content_incomplete")), app("ap_abort_replay", "replay", POST, rej("ob.replayed"))],
    async run(context) {
      let chain: { pb: Minted; ba: Minted } | null = null;
      const aborted = await fire(context, this.entries[0], (nonce) => {
        chain = context.root.mintChain(S_POST, nonce);
        const whole = wholeApp(S_POST, nonce, chain.ba.header, chain.pb.header);
        return { head: whole.subarray(0, whole.length - 3), closeAfterMs: 150 };
      });
      await sleep(100);
      const replay = await fire(context, this.entries[1], (nonce) => ({ head: wholeApp(S_POST, nonce, chain!.ba.header, chain!.pb.header) }));
      return [aborted, replay];
    },
  };
  return [lineage, abort];
}

export const DIRECT_SCENARIOS: readonly DirectScenario[] = Object.freeze([
  ...noProofCases(), ...spoofCases(), ...malformedCases(), ...bindingCases(), ...hopCases(), ...semanticCases(), ...crossHopBoundaryCases(), ...replayBoundaryScenarios(),
  ...appCases(), ...appReplayScenarios(),
]);

export const DIRECT_ENTRIES: readonly DirectEntry[] = Object.freeze(DIRECT_SCENARIOS.flatMap((scenario) => scenario.entries));
export const DIRECT_CORPUS_FIXED_COUNT = 110;
export const DIRECT_POSITIVE_CONTROLS = Object.freeze(DIRECT_ENTRIES.filter((entry) => entry.expect.kind === "admit_once").map((entry) => entry.id));
void newNonce;

/** Runs every scenario of a phase once, in order. Each request is sent once (a replay is its own case). */
export async function runDirectCorpus(context: DirectContext, phase: DirectScenario["phase"]): Promise<DirectExecuted[]> {
  const out: DirectExecuted[] = [];
  for (const scenario of DIRECT_SCENARIOS.filter((candidate) => candidate.phase === phase)) out.push(...(await scenario.run(context)));
  return out;
}

/** The ledger's verdict on one case; null means it behaved exactly as specified. The client's view is only a cross-check. */
export function verifyDirect(entry: DirectEntry, record: LedgerRecord, exchange: Exchange): string | null {
  const expect = entry.expect;
  const kinds = (events: readonly { kind: string }[]) => events.map((event) => event.kind);
  const clientOk = (status: number): boolean => exchange.result !== "response" || exchange.status === status;

  if (expect.kind === "parser") {
    if (record.boundary.length > 0 || record.app.length > 0 || record.origin.length > 0) return "a parser case produced a lifecycle past the parser";
    return exchange.result === "response" && exchange.status !== 400 && exchange.status !== 431 ? `parser case answered ${exchange.status}` : null;
  }
  if (expect.kind === "reject") {
    if (record.origin.length > 0) return "the application saw a request that had to be refused";
    if (record.app.some((event) => event.kind === "APP_ADMITTED" || event.kind === "APP_EXECUTED" || event.kind === "APP_MUTATED")) return "the application admitted, executed or mutated for a refused request";
    if (entry.target === "boundary") {
      if (record.app.length > 0) return `the app stream has events for a boundary refusal (${kinds(record.app).join(",")})`;
      const decision = record.boundary.find((event) => event.kind === "BOUNDARY_REJECTED");
      if (record.boundary.some((event) => event.kind === "BOUNDARY_ADMITTED")) return "the boundary admitted a request that had to be refused";
      if (!decision) return `no boundary refusal recorded (${kinds(record.boundary).join(",") || "no events"})`;
      if (decision.reason !== expect.reason) return `expected ${expect.reason}, boundary recorded ${decision.reason}`;
    } else {
      if (record.boundary.length > 0) return "the boundary saw a request sent to the app's own port";
      const decision = record.app.find((event) => event.kind === "APP_REFUSED");
      if (!decision) return `no app refusal recorded (${kinds(record.app).join(",") || "no events"})`;
      if (decision.reason !== expect.reason) return `expected ${expect.reason}, app recorded ${decision.reason}`;
    }
    return clientOk(403) ? null : `the client saw ${exchange.status}, expected 403`;
  }
  // positive control: admitted exactly once, executed, completed 200, and never mutated
  const executed = record.app.filter((event) => event.kind === "APP_EXECUTED").length;
  const completed = record.app.find((event) => event.kind === "APP_COMPLETED");
  if (record.app.filter((event) => event.kind === "APP_ADMITTED").length !== 1) return "the positive control was not admitted exactly once by the app";
  if (executed !== 1 || !completed || completed.status !== 200) return "the positive control did not execute and complete with 200";
  if (record.app.some((event) => event.kind === "APP_MUTATED")) return "a positive control mutated state";
  if (entry.target === "boundary" && !record.boundary.some((event) => event.kind === "BOUNDARY_ADMITTED")) return "the boundary did not admit the positive control";
  if (entry.target === "app" && record.boundary.length > 0) return "the boundary saw an app-port positive control";
  return exchange.result === "response" && exchange.status === 200 ? null : `the client saw ${exchange.result}/${exchange.status}, expected 200`;
}
