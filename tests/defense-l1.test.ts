import assert from "node:assert/strict";
import { test } from "node:test";
import { REJECT_REASONS, REJECT_STAGE, type BodyStatus, type LayerRequest, type RejectReason } from "../defense/core/types";
import { ShapeGate } from "../defense/layers/a7-shape-gate";

const TOKEN = "T".repeat(43);
const enc = (text: string) => new Uint8Array(Buffer.from(text, "latin1"));
const FORM = "application/x-www-form-urlencoded";

function get(target: string, extra: [string, string][] = [], host: string | null = "127.0.0.1:3000"): LayerRequest {
  return { method: "GET", target, headers: [...(host === null ? [] : [["host", host] as [string, string]]), ...extra], bodyStatus: "none", body: null };
}
function post(body: string, overrides: { headers?: [string, string][]; bodyStatus?: BodyStatus; target?: string; contentType?: string; declared?: number } = {}): LayerRequest {
  const bytes = enc(body);
  return {
    method: "POST", target: overrides.target ?? "/api/public-inquiries", bodyStatus: overrides.bodyStatus ?? "complete", body: overrides.bodyStatus && overrides.bodyStatus !== "complete" ? null : bytes,
    headers: overrides.headers ?? [["host", "127.0.0.1:3000"], ["content-type", overrides.contentType ?? FORM], ["content-length", String(overrides.declared ?? bytes.length)]],
  };
}
const verdict = (request: LayerRequest, gate = new ShapeGate()) => gate.evaluate(request);

test("valid requests pass", () => {
  for (const target of ["/", "/gizlilik", "/test-talep-et", "/test-talep-et?hizmet=web", "/test-talep-et/tesekkurler"]) assert.deepEqual(verdict(get(target)), { kind: "pass" }, target);
  assert.deepEqual(verdict(post(`name=A&email=a%40b.co&service=web&submissionToken=${TOKEN}`)), { kind: "pass" });
  assert.deepEqual(verdict(post("")), { kind: "pass" });
});

const cases: [string, LayerRequest, RejectReason][] = [
  ["method", { ...get("/"), method: "OPTIONS" }, "a7.method_not_allowed"],
  ["post on a page", { ...post("a=b"), target: "/" }, "a7.method_not_allowed"],
  ["get on the api", get("/api/public-inquiries"), "a7.method_not_allowed"],
  ["target too long", get(`/${"a".repeat(2100)}`), "a7.target_too_long"],
  ["dot segments", get("/../x"), "a7.target_malformed"],
  ["double slash", get("//x"), "a7.target_malformed"],
  ["percent in path", get("/%2e%2e/x"), "a7.target_malformed"],
  ["absolute form", get("http://x/"), "a7.target_malformed"],
  ["backslash", get("/a\\b"), "a7.target_malformed"],
  ["fragment", get("/#x"), "a7.target_malformed"],
  ["space in target", get("/a b"), "a7.target_malformed"],
  ["unknown path", get("/admin"), "a7.path_not_allowed"],
  ["query on root", get("/?a=b"), "a7.query_not_allowed"],
  ["bad service", get("/test-talep-et?hizmet=zzz"), "a7.query_not_allowed"],
  ["extra query", get("/test-talep-et?hizmet=web&x=1"), "a7.query_not_allowed"],
  ["too many headers", get("/", Array.from({ length: 60 }, (_, i) => [`x-${i}`, "1"] as [string, string])), "a7.header_count_exceeded"],
  ["header bytes", get("/", [["x-big", "a".repeat(9000)]]), "a7.header_bytes_exceeded"],
  ["header name", get("/", [["bad name", "1"]]), "a7.header_name_invalid"],
  ["header value control char", get("/", [["x-a", "a\u0001b"]]), "a7.header_value_invalid"],
  ["header value non-ascii", get("/", [["x-a", "café"]]), "a7.header_value_invalid"],
  ["host missing", get("/", [], null), "a7.host_header_invalid"],
  ["host malformed", get("/", [], "bad host"), "a7.host_header_invalid"],
  ["host duplicated", get("/", [["host", "b.example"]]), "a7.host_header_invalid"],
  ["get with body", get("/", [["content-length", "5"]]), "a7.framing_invalid"],
  ["transfer-encoding", get("/", [["transfer-encoding", "chunked"]]), "a7.framing_invalid"],
  ["post without length", post("a=b", { headers: [["host", "h"], ["content-type", FORM]] }), "a7.framing_invalid"],
  ["post with duplicate length", post("a=b", { headers: [["host", "h"], ["content-type", FORM], ["content-length", "3"], ["content-length", "3"]] }), "a7.framing_invalid"],
  ["post with non-numeric length", post("a=b", { headers: [["host", "h"], ["content-type", FORM], ["content-length", "3x"]] }), "a7.framing_invalid"],
  ["content type json", post("{}", { contentType: "application/json" }), "a7.content_type_invalid"],
  ["content type with charset", post("a=b", { contentType: `${FORM}; charset=utf-8` }), "a7.content_type_invalid"],
  ["declared oversize", post("", { bodyStatus: "declared_oversize", declared: 10_000_000 }), "a7.body_too_large"],
  ["overflow", post("", { bodyStatus: "overflow" }), "a7.body_too_large"],
  ["declared above the cap even if the front said complete", post("a=b", { declared: 40_000 }), "a7.body_too_large"],
  ["body timeout", post("", { bodyStatus: "timeout", declared: 10 }), "a7.body_read_timeout"],
  ["body aborted", post("", { bodyStatus: "aborted", declared: 10 }), "a7.body_incomplete"],
  ["bad percent", post("name=%zz"), "a7.body_encoding_invalid"],
  ["invalid utf-8", post("name=%ff%fe"), "a7.body_encoding_invalid"],
  ["raw non-ascii", post("name=café"), "a7.body_encoding_invalid"],
  ["unknown field", post("evil=1"), "a7.form_field_not_allowed"],
  ["__proto__", post("__proto__=x"), "a7.form_field_not_allowed"],
  ["duplicate field", post("name=a&name=b"), "a7.form_field_duplicate"],
  ["too many fields", post(Array.from({ length: 40 }, () => "name=a").join("&")), "a7.form_field_count_exceeded"],
  ["field too long", post(`notes=${"a".repeat(13_000)}`), "a7.form_field_too_long"],
  ["bad token shape", post("submissionToken=short"), "a7.form_token_malformed"],
  ["empty name", post("=x"), "a7.form_grammar_invalid"],
  ["no equals", post("name"), "a7.form_grammar_invalid"],
  ["empty pair", post("name=a&&notes=b"), "a7.form_grammar_invalid"],
];

for (const [label, request, reason] of cases) {
  test(`reject: ${label} -> ${reason}`, () => {
    assert.deepEqual(verdict(request), { kind: "reject", reason });
  });
}

test("every closed-enum reason is exercised by a case above", () => {
  const exercised = new Set(cases.map(([, , reason]) => reason));
  assert.deepEqual(REJECT_REASONS.filter((reason) => !exercised.has(reason)), []);
});

test("size bounds are decided BEFORE the grammar parser runs (event-loop safety): oversized input never reaches it", () => {
  const gate = new ShapeGate();
  const preParse = [
    post("", { bodyStatus: "declared_oversize", declared: 10_000_000 }), post("", { bodyStatus: "overflow" }), post("a=b", { declared: 40_000 }),
    post("", { bodyStatus: "timeout", declared: 10 }), post("", { bodyStatus: "aborted", declared: 10 }), post("a=b", { contentType: "text/plain" }),
    get(`/${"a".repeat(5000)}`), get("/", [["x-big", "a".repeat(9000)]]),
  ];
  for (const request of preParse) assert.equal(gate.evaluate(request).kind, "reject");
  assert.equal(gate.stats().grammarParses, 0, "none of the oversized or structurally invalid requests was parsed");
  gate.evaluate(post("name=a"));
  gate.evaluate(post("name=%zz"));
  assert.equal(gate.stats().grammarParses, 2, "only bodies that passed every bound reach the grammar parser");
});

test("a reason's declared stage is the truth: pre_parse rejects never invoke the grammar parser, grammar rejects invoke it exactly once", () => {
  for (const [label, request, reason] of cases) {
    const gate = new ShapeGate();
    assert.equal(gate.evaluate(request).kind, "reject", label);
    assert.equal(gate.stats().grammarParses, REJECT_STAGE[reason] === "grammar" ? 1 : 0, `${label} (${reason})`);
  }
});

test("L1 is stateless: the same request gets the same verdict regardless of history", () => {
  const gate = new ShapeGate();
  const first = Array.from({ length: 5 }, () => gate.evaluate(get("/admin")));
  for (let index = 0; index < 5000; index++) gate.evaluate(get("/admin"));
  const later = Array.from({ length: 5 }, () => gate.evaluate(get("/admin")));
  assert.deepEqual(later, first);
  assert.deepEqual(gate.evaluate(get("/")), { kind: "pass" }, "a flood of rejects never changes what a good request gets");
});

test("L1 cannot see a traffic class or a correlation id: its input type has no such field", () => {
  const request = get("/");
  assert.deepEqual(Object.keys(request).sort(), ["body", "bodyStatus", "headers", "method", "target"]);
});
