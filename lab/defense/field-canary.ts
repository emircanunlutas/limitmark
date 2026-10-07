/**
 * Field qualification: the legitimate canary journey against a host:port the harness chose (the Defense Plane's reviewed bound address, or
 * the private loopback control origin). It is the Slice-1 five-step journey (`canary.ts`, byte-pinned and untouched) with ONE difference:
 * the destination host is a parameter instead of the literal 127.0.0.1. The checks, the token handling, the digests and the result shape are
 * the same; `tests/lab-ba0-field-canary.test.ts` runs both against the same origin and compares every step record, so the two cannot drift.
 *
 * A step is "ok" only when the response is a 200 with the expected content; any other status, a client timeout or reset, or content that is
 * not the expected page fails the journey. The canary shares NOTHING with the hostile generator (separate process, separate machine,
 * separate scheduler): it is the harness's own timers.
 */
import { createHash } from "node:crypto";
import type { Lane } from "../../defense/core/types";
import { JOURNEY_STEPS, type JourneyResult, type StepRecord } from "./canary";
import { trackedHttp, type Exchange } from "./client";
import type { Collector, RequestMeta } from "./collector";

const REDIRECT = "/test-talep-et/tesekkurler";
const TOKEN_FIELD = /name="submissionToken" value="([A-Za-z0-9_-]{43})"/;
const PARITY_IGNORED_HEADERS: ReadonlySet<string> = new Set(["date", "connection", "keep-alive", "transfer-encoding", "x-ba0-outcome"]);

const digest = (body: Buffer): string => createHash("sha256").update(body.toString("utf8").replace(/(name="submissionToken" value=")[A-Za-z0-9_-]{43}"/, '$1TOKEN"')).digest("hex");
const text = (exchange: Exchange): string => exchange.body.toString("utf8");

function formBody(token: string): string {
  return new URLSearchParams({
    name: "Canary Journey", email: "canary@example.test", company: "Synthetic Co", service: "web", system: "synthetic canary system", objective: "synthetic canary objective",
    environment: "staging", authority: "authorized", protection: "unknown", provider: "", notes: "", submissionToken: token,
  }).toString();
}

export type FieldJourneyInput = { lane: Lane; host: string; port: number; phase: string; journey: number; timeoutMs: number };

export async function runFieldJourney(collector: Collector, input: FieldJourneyInput): Promise<JourneyResult> {
  const steps: StepRecord[] = [];
  const meta = (step: number, method: "GET" | "POST"): RequestMeta => ({ lane: input.lane, phase: input.phase, cls: "canary", scenario: `journey_${JOURNEY_STEPS[step - 1]}`, journey: input.journey, step, method });
  const base = `http://${input.host}:${input.port}`;
  let token = "";

  const run = async (step: number, method: "GET" | "POST", path: string, check: (exchange: Exchange) => string | null, extra?: { headers?: Record<string, string>; body?: string }): Promise<boolean> => {
    const exchange = await trackedHttp(collector, input.port, meta(step, method), { method, path, headers: extra?.headers, body: extra?.body }, input.timeoutMs, input.host);
    let failure: string | null = null;
    if (exchange.result !== "response") failure = `client_${exchange.result}`;
    else if (exchange.status !== 200) failure = `status_${exchange.status}`;
    else failure = check(exchange);
    steps.push({
      step, name: JOURNEY_STEPS[step - 1], ok: failure === null, failure, status: exchange.status, latencyMs: exchange.latencyMs, bodyDigest: digest(exchange.body),
      headerNames: Object.keys(exchange.headers).filter((name) => !PARITY_IGNORED_HEADERS.has(name)).sort(),
    });
    return failure === null;
  };

  const completed =
    await run(1, "GET", "/", (e) => (text(e).includes('id="sss"') && text(e).includes('href="/gizlilik"') && text(e).includes('href="/test-talep-et"') ? null : "homepage_content")) &&
    await run(2, "GET", "/gizlilik", (e) => (text(e).includes("<h1>Gizlilik</h1>") ? null : "privacy_content")) &&
    await run(3, "GET", "/test-talep-et", (e) => { const match = TOKEN_FIELD.exec(text(e)); if (!match) return "form_token_missing"; token = match[1]; return null; }) &&
    await run(4, "POST", "/api/public-inquiries", (e) => {
      try { const parsed = JSON.parse(text(e)) as { kind?: string; location?: string }; return parsed.kind === "redirect" && parsed.location === REDIRECT ? null : "post_not_redirect"; } catch { return "post_not_json"; }
    }, { headers: { origin: base, "content-type": "application/x-www-form-urlencoded" }, body: formBody(token) }) &&
    await run(5, "GET", REDIRECT, (e) => (text(e).includes("Demo akışı tamamlandı.") ? null : "thank_you_content"));
  return { lane: input.lane, phase: input.phase, journey: input.journey, completed, steps };
}
