#!/usr/bin/env node
// Legitimate-user baseline for the LimitMark laboratory. READ-ONLY except for the submissions it is told to make.
// It never prints tokens. Usage (PowerShell):
//   $env:LAB_E2E_BASE_URL = "https://<lab public hostname>"
//   $env:LAB_E2E_TURNSTILE_TOKENS_FILE = "<file with one real, single-use Turnstile response token per line>"   # optional
//   node deployment/lab-e2e/legitimate-user-baseline.mjs --iterations 20 --expect healthy|degraded
import { readFileSync } from "node:fs";
import { classifyUnexpected, summarize } from "./summary.mjs";

const args = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, index, all) => value.startsWith("--") ? [...pairs, [value.slice(2), all[index + 1]]] : pairs, []));
const base = process.env.LAB_E2E_BASE_URL;
if (!base || !/^https:\/\/[a-z0-9.-]+$/iu.test(base)) { console.error("LAB_E2E_BASE_URL must be an https origin without a path"); process.exit(2); }
const iterations = Math.min(200, Math.max(1, Number(args.iterations ?? 10)));
const expect = args.expect === "degraded" ? "degraded" : "healthy";
const tokens = process.env.LAB_E2E_TURNSTILE_TOKENS_FILE ? readFileSync(process.env.LAB_E2E_TURNSTILE_TOKENS_FILE, "utf8").split(/\r?\n/u).filter(Boolean) : [];
const samples = [];
const created = []; // submission tokens that SHOULD have produced exactly one row (operator reconciles against PostgreSQL)

async function timed(scenario, run) {
  const started = performance.now();
  let status; let headers; let bodySnippet = ""; let ok = false; let location = null;
  try {
    const response = await run();
    status = response.status; headers = response.headers; location = response.headers.get("location");
    bodySnippet = (await response.text()).slice(0, 2048);
    ok = status >= 200 && status < 300;
    return { response, status, headers, bodySnippet, location, ok, finish: (verdict) => record(scenario, started, status, headers, bodySnippet, verdict ?? ok) };
  } catch {
    return { status: undefined, ok: false, bodySnippet, finish: () => record(scenario, started, undefined, undefined, "", false) };
  }
}
function record(scenario, started, status, headers, bodySnippet, ok) {
  const sample = { scenario, ok, status, latencyMs: Math.round(performance.now() - started), unexpected: status === undefined ? ["network-error"] : classifyUnexpected({ status, headers, bodySnippet }) };
  samples.push(sample);
  return sample;
}
const get = (path) => fetch(new URL(path, base), { redirect: "manual", headers: { "user-agent": "limitmark-lab-e2e/1" } });
function form(values) { return new URLSearchParams(values).toString(); }
const post = (body) => fetch(new URL("/api/public-inquiries", base), { method: "POST", redirect: "manual", body,
  headers: { "content-type": "application/x-www-form-urlencoded", origin: base, "user-agent": "limitmark-lab-e2e/1" } });
const valid = (token, submissionToken, email = "lab-e2e@example.test") => form({ name: "Lab E2E", email, service: "web", system: "Lab", objective: "Legitimate baseline", environment: "staging", authority: "authorized", submissionToken, "cf-turnstile-response": token });

for (let i = 0; i < iterations; i += 1) {
  const home = await timed("homepage", () => get("/")); home.finish();
  const assets = [...(home.bodySnippet ?? "").matchAll(/(?:src|href)="(\/_next\/static\/[^"]+)"/gu)].map((m) => m[1]).slice(0, 3);
  for (const asset of assets) (await timed("static-asset", () => get(asset))).finish();
  const nav = await timed("navigation", () => get("/test-talep-et"));
  nav.finish();
  const submissionToken = /name="submissionToken"[^>]*value="([^"]+)"/u.exec(nav.bodySnippet ?? "")?.[1] ?? /value="([^"]+)"[^>]*name="submissionToken"/u.exec(nav.bodySnippet ?? "")?.[1];

  // Invalid submission: must be refused WITHOUT a server error; expected outcome is a 2xx/4xx validation state, never a redirect to thanks.
  const invalid = await timed("invalid-submission", () => post(valid("x", submissionToken ?? "s".repeat(43), "not-an-email")));
  invalid.finish(invalid.status !== undefined && invalid.status < 500 && !String(invalid.location ?? "").includes("tesekkurler"));

  const token = tokens.shift();
  if (token && submissionToken) {
    const first = await timed("valid-submission", () => post(valid(token, submissionToken)));
    const accepted = (first.status === 303 || first.status === 302 || first.status === 307 || first.status === 200) && (String(first.location ?? "").includes("tesekkurler") || /tesekkurler/u.test(first.bodySnippet));
    first.finish(expect === "healthy" ? accepted : !accepted);
    if (accepted) created.push(submissionToken);
    const second = tokens.shift();
    if (second) {
      // Duplicate: same submission token, fresh Turnstile token. Must not create a second row (idempotent or refused).
      const duplicate = await timed("duplicate-submission", () => post(valid(second, submissionToken)));
      duplicate.finish(duplicate.status !== undefined && duplicate.status < 500);
    }
  }
}

const summary = summarize(samples);
const failing = Object.entries(summary).filter(([, v]) => expect === "healthy" ? v.successRate < 1 : false).map(([k]) => k);
console.log(JSON.stringify({ base, expect, iterations, tokensSupplied: tokens.length === 0 ? "consumed-or-none" : `${tokens.length} unused`, summary,
  createdSubmissionTokenCount: created.length, reconcile: "SELECT count(*) FROM inquiries WHERE submission_token = ANY(<created tokens>) must equal createdSubmissionTokenCount; duplicates must not add rows" }, null, 2));
process.exit(failing.length ? 1 : 0);
