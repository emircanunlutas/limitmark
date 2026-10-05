/**
 * Canary journeys. A legitimate journey is successful ONLY if the complete flow succeeds:
 *
 *   1. homepage              (FAQ section and navigation present)
 *   2. navigation / privacy  (privacy page)
 *   3. form page             (a well-formed hidden submission token)
 *   4. valid POST            (redirect to the thank-you location)
 *   5. thank-you page
 *
 * Journey Completion Rate (JCR) = completed journeys / attempted journeys, per lane and phase. The same journey runs against the
 * control origin (direct, no plane) and the protected origin (through the plane) and the results are compared: status, a normalised
 * body hash and the response header NAME set must match, and latency degradation is measured separately.
 */
import { createHash } from "node:crypto";
import type { Collector, RequestMeta } from "./collector";
import { trackedHttp, type Exchange } from "./client";
import type { Lane } from "../../defense/core/types";

export const JOURNEY_STEPS = ["homepage", "privacy", "form", "valid_post", "thank_you"] as const;
const REDIRECT = "/test-talep-et/tesekkurler";
const TOKEN_FIELD = /name="submissionToken" value="([A-Za-z0-9_-]{43})"/;
/** Headers whose presence legitimately differs between a direct and a proxied response, or varies by connection. */
const PARITY_IGNORED_HEADERS: ReadonlySet<string> = new Set(["date", "connection", "keep-alive", "transfer-encoding", "x-ba0-outcome"]);

export type StepRecord = {
  step: number;
  name: (typeof JOURNEY_STEPS)[number];
  ok: boolean;
  failure: string | null;
  status: number | null;
  latencyMs: number;
  /** Hash of the body with the per-request token replaced; equal for equal content. Compared, and recorded only as a digest. */
  bodyDigest: string;
  headerNames: string[];
};
export type JourneyResult = { lane: Lane; phase: string; journey: number; completed: boolean; steps: StepRecord[] };

const digest = (body: Buffer): string => createHash("sha256").update(body.toString("utf8").replace(/(name="submissionToken" value=")[A-Za-z0-9_-]{43}"/, '$1TOKEN"')).digest("hex");
const text = (exchange: Exchange): string => exchange.body.toString("utf8");

function formBody(token: string): string {
  return new URLSearchParams({
    name: "Canary Journey", email: "canary@example.test", company: "Synthetic Co", service: "web", system: "synthetic canary system", objective: "synthetic canary objective",
    environment: "staging", authority: "authorized", protection: "unknown", provider: "", notes: "", submissionToken: token,
  }).toString();
}

export async function runJourney(collector: Collector, input: { lane: Lane; port: number; phase: string; journey: number; timeoutMs: number }): Promise<JourneyResult> {
  const steps: StepRecord[] = [];
  const meta = (step: number, method: "GET" | "POST"): RequestMeta => ({ lane: input.lane, phase: input.phase, cls: "canary", scenario: `journey_${JOURNEY_STEPS[step - 1]}`, journey: input.journey, step, method });
  const base = `http://127.0.0.1:${input.port}`;
  let token = "";

  const run = async (step: number, method: "GET" | "POST", path: string, check: (exchange: Exchange) => string | null, extra?: { headers?: Record<string, string>; body?: string }): Promise<boolean> => {
    const exchange = await trackedHttp(collector, input.port, meta(step, method), { method, path, headers: extra?.headers, body: extra?.body }, input.timeoutMs);
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

export type JcrEntry = { lane: Lane; phase: string; attempted: number; completed: number; rate: number };

export function journeyCompletionRates(results: readonly JourneyResult[]): JcrEntry[] {
  const groups = new Map<string, JcrEntry>();
  for (const result of results) {
    const key = `${result.lane}/${result.phase}`;
    const entry = groups.get(key) ?? { lane: result.lane, phase: result.phase, attempted: 0, completed: 0, rate: 0 };
    entry.attempted++;
    if (result.completed) entry.completed++;
    groups.set(key, entry);
  }
  return [...groups.values()].map((entry) => ({ ...entry, rate: entry.attempted === 0 ? 0 : entry.completed / entry.attempted })).sort((a, b) => `${a.phase}/${a.lane}`.localeCompare(`${b.phase}/${b.lane}`));
}

export type ParityReport = { compared: number; mismatches: { journey: number; step: number; aspect: "status" | "body" | "headers" | "completion" }[] };

/** Same journey, same step: the protected response must be indistinguishable from the control response in status, body and header names. */
export function compareParity(results: readonly JourneyResult[]): ParityReport {
  const byKey = new Map<string, JourneyResult>();
  for (const result of results) byKey.set(`${result.phase}/${result.journey}/${result.lane}`, result);
  const report: ParityReport = { compared: 0, mismatches: [] };
  for (const control of results.filter((result) => result.lane === "control")) {
    const guarded = byKey.get(`${control.phase}/${control.journey}/protected`);
    if (!guarded) { report.mismatches.push({ journey: control.journey, step: 0, aspect: "completion" }); continue; }
    if (control.completed !== guarded.completed) report.mismatches.push({ journey: control.journey, step: 0, aspect: "completion" });
    for (let index = 0; index < Math.min(control.steps.length, guarded.steps.length); index++) {
      const a = control.steps[index]; const b = guarded.steps[index];
      report.compared++;
      if (a.status !== b.status) report.mismatches.push({ journey: control.journey, step: a.step, aspect: "status" });
      if (a.bodyDigest !== b.bodyDigest) report.mismatches.push({ journey: control.journey, step: a.step, aspect: "body" });
      if (a.headerNames.join(",") !== b.headerNames.join(",")) report.mismatches.push({ journey: control.journey, step: a.step, aspect: "headers" });
    }
  }
  return report;
}

/** Latencies of every canary step, per lane, for the protected-versus-control envelope. */
export function latenciesByLane(results: readonly JourneyResult[]): Record<Lane, number[]> {
  const out: Record<Lane, number[]> = { control: [], protected: [] };
  for (const result of results) for (const step of result.steps) out[result.lane].push(step.latencyMs);
  return out;
}
