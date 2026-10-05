/**
 * Slice 3: the strict RESPONSE-OBSERVATION CONTRACT for journey-credit enrollment. Pure: no I/O, no clock, no state.
 *
 * A credit may be enrolled only from a response that satisfies ALL of this (the first failing condition names the skip reason):
 *
 *   request      GET of the exact reviewed form route, admitted by L2 as an ordinary (open, natural, non-degraded) decision
 *   status       exactly 200
 *   headers      exactly one Content-Type whose value is exactly `text/html; charset=utf-8`, and no Content-Encoding
 *   body         the completed response, within the response limit the front already enforces
 *   token        the literal `name="submissionToken"` occurs exactly once, and that occurrence is the reviewed structure:
 *                  <form class="request-form" ...> ... <input type="hidden" name="submissionToken" value="[43 b64url]"> or "/>"
 *                with no </form> between the form's opening tag and the input. Zero or several matches enroll nothing.
 *   delivery     (decided by the caller) the response was completely flushed to the client before enrollment
 *   freshness    (decided by the caller) a token already USED credited, or already in the active generation, is never enrolled again; a token
 *                that only tests positive through the previous generation is still enrolled (those bits are about to age out)
 *
 * The matcher is pinned to the application's form component by tests/lab-ba0-collapse-contract.test.ts and to the real built
 * application's output by the G1 check. It is deliberately NOT generalised: if the component changes shape, enrollment stops
 * (no credit) until a reviewer changes this file.
 */

/** Exact request targets of the reviewed form route. */
export const FORM_ROUTE_TARGETS: readonly string[] = Object.freeze([
  "/test-talep-et",
  "/test-talep-et?hizmet=web",
  "/test-talep-et?hizmet=network",
  "/test-talep-et?hizmet=protection",
  "/test-talep-et?hizmet=unsure",
]);
export const isFormRoute = (method: string, target: string): boolean => method === "GET" && FORM_ROUTE_TARGETS.includes(target);

export const ENROLL_CONTENT_TYPE = "text/html; charset=utf-8";
export const SUBMISSION_TOKEN_LENGTH = 43;

/** Closed list: every reason an enrollment can be skipped. Exactly one of enrolled | skipped (with one of these) per observed render. */
export const ENROLL_SKIP_REASONS = [
  "not_get_form_route", "degraded", "simulated", "upstream_failed", "status_not_200", "content_type", "body_too_large",
  "token_count_zero", "token_count_multiple", "delivery_incomplete", "already_enrolled",
] as const;
export type EnrollSkipReason = (typeof ENROLL_SKIP_REASONS)[number];

const NAME_LITERAL = Buffer.from('name="submissionToken"', "latin1");
const INPUT_HEAD = Buffer.from('<input type="hidden" ', "latin1");
const VALUE_HEAD = Buffer.from(' value="', "latin1");
const FORM_ANY = Buffer.from("<form ", "latin1");
const FORM_OPEN = Buffer.from('<form class="request-form"', "latin1");
const FORM_CLOSE = Buffer.from("</form>", "latin1");

const isTokenByte = (byte: number): boolean =>
  (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a) || (byte >= 0x30 && byte <= 0x39) || byte === 0x2d || byte === 0x5f;

export type TokenMatch = { ok: true; token: string } | { ok: false; reason: "token_count_zero" | "token_count_multiple" };

/** The one reviewed token in the response body, or why there is none. At most three linear passes (Buffer.indexOf), no allocation per byte. */
export function matchFormToken(payload: Uint8Array): TokenMatch {
  const body = Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
  const first = body.indexOf(NAME_LITERAL);
  if (first < 0) return { ok: false, reason: "token_count_zero" };
  if (body.indexOf(NAME_LITERAL, first + NAME_LITERAL.length) >= 0) return { ok: false, reason: "token_count_multiple" };

  // The single occurrence must be exactly `<input type="hidden" name="submissionToken" value="TOKEN"` + `>` or `/>`.
  const inputStart = first - INPUT_HEAD.length;
  if (inputStart < 0 || body.compare(INPUT_HEAD, 0, INPUT_HEAD.length, inputStart, first) !== 0) return { ok: false, reason: "token_count_zero" };
  const valueAt = first + NAME_LITERAL.length;
  if (body.compare(VALUE_HEAD, 0, VALUE_HEAD.length, valueAt, valueAt + VALUE_HEAD.length) !== 0) return { ok: false, reason: "token_count_zero" };
  const tokenStart = valueAt + VALUE_HEAD.length;
  const tokenEnd = tokenStart + SUBMISSION_TOKEN_LENGTH;
  if (tokenEnd + 2 > body.length) return { ok: false, reason: "token_count_zero" };
  for (let index = tokenStart; index < tokenEnd; index++) if (!isTokenByte(body[index])) return { ok: false, reason: "token_count_zero" };
  if (body[tokenEnd] !== 0x22) return { ok: false, reason: "token_count_zero" };
  const closes = body[tokenEnd + 1] === 0x3e || (body[tokenEnd + 1] === 0x2f && body[tokenEnd + 2] === 0x3e);
  if (!closes) return { ok: false, reason: "token_count_zero" };

  // The reviewed form context: the nearest preceding `<form ` is the request form, and it is not closed before the input.
  const formAt = body.lastIndexOf(FORM_ANY, inputStart);
  if (formAt < 0 || body.compare(FORM_OPEN, 0, FORM_OPEN.length, formAt, formAt + FORM_OPEN.length) !== 0) return { ok: false, reason: "token_count_zero" };
  const closeAt = body.indexOf(FORM_CLOSE, formAt);
  if (closeAt >= 0 && closeAt < inputStart) return { ok: false, reason: "token_count_zero" };

  return { ok: true, token: body.toString("latin1", tokenStart, tokenEnd) };
}

export type UpstreamObservation = {
  status: number;
  /** The upstream response's raw header list (name, value, name, value ...), so duplicates are visible. */
  rawHeaders: readonly string[];
  payload: Uint8Array;
};

export type ObservationVerdict = { ok: true; token: string } | { ok: false; reason: EnrollSkipReason };

/** The response half of the contract (status, headers, body, token). Delivery and freshness belong to the caller. */
export function evaluateObservation(observed: UpstreamObservation, maxBodyBytes: number): ObservationVerdict {
  if (observed.status !== 200) return { ok: false, reason: "status_not_200" };
  let contentTypes = 0;
  let representationOk = true;
  for (let index = 0; index + 1 < observed.rawHeaders.length; index += 2) {
    const name = observed.rawHeaders[index].toLowerCase();
    if (name === "content-encoding") representationOk = false;
    if (name === "content-type") {
      contentTypes++;
      if (observed.rawHeaders[index + 1].trim().toLowerCase() !== ENROLL_CONTENT_TYPE) representationOk = false;
    }
  }
  if (contentTypes !== 1 || !representationOk) return { ok: false, reason: "content_type" };
  if (observed.payload.byteLength > maxBodyBytes) return { ok: false, reason: "body_too_large" };
  const match = matchFormToken(observed.payload);
  return match.ok ? { ok: true, token: match.token } : { ok: false, reason: match.reason };
}
