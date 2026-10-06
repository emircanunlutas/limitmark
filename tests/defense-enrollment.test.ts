import assert from "node:assert/strict";
import { test } from "node:test";
import { ENROLL_CONTENT_TYPE, ENROLL_SKIP_REASONS, FORM_ROUTE_TARGETS, evaluateObservation, isFormRoute, matchFormToken } from "../defense/core/enrollment";

const TOKEN = "T".repeat(43);
const HEADERS = ["Content-Type", ENROLL_CONTENT_TYPE];
const page = (input = `<input type="hidden" name="submissionToken" value="${TOKEN}"/>`, form = `<form class="request-form" action="">`) =>
  Buffer.from(`<!doctype html><html><body>${form}<input type="hidden" name="$ACTION_KEY" value="k1"/>${input}<div>x</div></form><script>self.__next_f.push(["submissionToken","${TOKEN}"])</script></body></html>`, "latin1");
const observe = (payload: Buffer, overrides: Partial<{ status: number; rawHeaders: string[] }> = {}) =>
  evaluateObservation({ status: 200, rawHeaders: HEADERS, payload, ...overrides }, 1_048_576);

test("the reviewed structure yields exactly the token; the flight-payload copy is not a second match", () => {
  assert.deepEqual(observe(page()), { ok: true, token: TOKEN });
  assert.deepEqual(observe(page(`<input type="hidden" name="submissionToken" value="${TOKEN}">`)), { ok: true, token: TOKEN });
});

test("every request-side route is exact: only the reviewed form route and nothing similar", () => {
  for (const target of FORM_ROUTE_TARGETS) assert.equal(isFormRoute("GET", target), true, target);
  for (const [method, target] of [["POST", "/test-talep-et"], ["GET", "/"], ["GET", "/gizlilik"], ["GET", "/test-talep-et?hizmet=evil"], ["GET", "/test-talep-et/"], ["GET", "/test-talep-et?x=1"]] as const) {
    assert.equal(isFormRoute(method, target), false, `${method} ${target}`);
  }
});

test("status must be exactly 200, the representation exactly the reviewed one, and the body within the bound", () => {
  assert.deepEqual(observe(page(), { status: 201 }), { ok: false, reason: "status_not_200" });
  assert.deepEqual(observe(page(), { status: 304 }), { ok: false, reason: "status_not_200" });
  assert.deepEqual(observe(page(), { rawHeaders: ["Content-Type", "text/html"] }), { ok: false, reason: "content_type" });
  assert.deepEqual(observe(page(), { rawHeaders: ["Content-Type", "text/html; charset=iso-8859-1"] }), { ok: false, reason: "content_type" });
  assert.deepEqual(observe(page(), { rawHeaders: [] }), { ok: false, reason: "content_type" });
  assert.deepEqual(observe(page(), { rawHeaders: [...HEADERS, ...HEADERS] }), { ok: false, reason: "content_type" }, "duplicate content-type");
  assert.deepEqual(observe(page(), { rawHeaders: [...HEADERS, "Content-Encoding", "gzip"] }), { ok: false, reason: "content_type" });
  assert.deepEqual(evaluateObservation({ status: 200, rawHeaders: HEADERS, payload: page() }, 100), { ok: false, reason: "body_too_large" });
  assert.deepEqual(observe(page(), { rawHeaders: ["content-type", "TEXT/HTML; CHARSET=UTF-8"] }), { ok: true, token: TOKEN }, "header name and value are compared case-insensitively");
});

test("zero or several matches enroll nothing, and so does any deviation from the reviewed structure", () => {
  const none = Buffer.from('<form class="request-form"><input type="text" name="other"/></form>');
  assert.deepEqual(observe(none), { ok: false, reason: "token_count_zero" });
  const two = Buffer.from(`<form class="request-form"><input type="hidden" name="submissionToken" value="${TOKEN}"/><input type="hidden" name="submissionToken" value="${"U".repeat(43)}"/></form>`);
  assert.deepEqual(observe(two), { ok: false, reason: "token_count_multiple" });
  const variants: [string, Buffer][] = [
    ["attribute order", page(`<input name="submissionToken" type="hidden" value="${TOKEN}"/>`)],
    ["type text", page(`<input type="text" name="submissionToken" value="${TOKEN}"/>`)],
    ["short token", page(`<input type="hidden" name="submissionToken" value="${"T".repeat(42)}"/>`)],
    ["long token", page(`<input type="hidden" name="submissionToken" value="${"T".repeat(44)}"/>`)],
    ["bad character", page(`<input type="hidden" name="submissionToken" value="${"T".repeat(42)}+"/>`)],
    ["single quotes", page(`<input type="hidden" name='submissionToken' value="${TOKEN}"/>`)],
    ["unterminated", page(`<input type="hidden" name="submissionToken" value="${TOKEN}" data-x="1"/>`)],
    ["wrong form", page(undefined, `<form class="other-form">`)],
    ["form class prefix", page(undefined, `<form id="x" class="request-form">`)],
  ];
  for (const [label, body] of variants) assert.equal(observe(body).ok, false, label);
  const closed = Buffer.from(`<form class="request-form"><div></div></form><input type="hidden" name="submissionToken" value="${TOKEN}"/>`);
  assert.deepEqual(observe(closed), { ok: false, reason: "token_count_zero" }, "the input must be inside the request form");
  const escaped = Buffer.from(`<form class="request-form"><input type="hidden" name="submissionToken" value="${TOKEN}"/></form>`.replace(/"/g, "&quot;"));
  assert.equal(observe(escaped).ok, false);
});

test("an attacker-influenced echo cannot create a second match or move the match: a second literal anywhere disqualifies", () => {
  const body = Buffer.from(`<form class="request-form"><input type="hidden" name="submissionToken" value="${TOKEN}"/></form><p>name="submissionToken"</p>`);
  assert.deepEqual(observe(body), { ok: false, reason: "token_count_multiple" });
});

test("the closed skip-reason list is exactly the reasons the contract and the caller can produce", () => {
  assert.deepEqual([...ENROLL_SKIP_REASONS].sort(), [
    "already_enrolled", "body_too_large", "content_type", "degraded", "delivery_incomplete", "not_get_form_route", "simulated", "status_not_200",
    "token_count_multiple", "token_count_zero", "upstream_failed",
  ]);
  assert.equal(matchFormToken(new Uint8Array(0)).ok, false);
});
