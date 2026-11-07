import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import test from "node:test";
import { classifyUnexpected, percentile, summarize } from "../deployment/lab-e2e/summary.mjs";

test("percentiles use nearest rank and handle empty input", () => {
  assert.equal(percentile([], 50), null);
  const values = Array.from({ length: 100 }, (_, index) => index + 1);
  assert.deepEqual([50, 95, 99].map((p) => percentile(values, p)), [50, 95, 99]);
});

test("unexpected challenges, blocks and server errors are surfaced for a legitimate user", () => {
  assert.deepEqual(classifyUnexpected({ status: 200, headers: new Headers(), bodySnippet: "<h1>ok</h1>" }), []);
  assert.deepEqual(classifyUnexpected({ status: 403, headers: new Headers({ "cf-mitigated": "challenge" }), bodySnippet: "Just a moment..." }).sort(),
    ["blocked-403", "challenge-page", "cloudflare-mitigated"]);
  assert.deepEqual(classifyUnexpected({ status: 503, headers: new Headers(), bodySnippet: "" }), ["server-503"]);
});

test("summaries report success rate, latency percentiles and status histogram per scenario", () => {
  const out = summarize([{ scenario: "a", ok: true, status: 200, latencyMs: 10 }, { scenario: "a", ok: false, status: 503, latencyMs: 90, unexpected: ["server-503"] }]);
  assert.equal(out.a.successRate, 0.5);
  assert.deepEqual(out.a.statuses, { 200: 1, 503: 1 });
  assert.equal(out.a.latencyMs.p95, 90);
  assert.deepEqual(out.a.unexpected, { "server-503": 1 });
});

test("the baseline script refuses a non-https base URL", async () => {
  const token = "t".repeat(43);
  const server = createServer((req, res) => {
    if (req.method === "POST") { res.statusCode = 303; res.setHeader("location", "/test-talep-et/tesekkurler"); res.end(); return; }
    res.setHeader("content-type", "text/html");
    res.end(req.url === "/test-talep-et" ? `<input name="submissionToken" value="${token}">` : `<a href="/test-talep-et"></a><script src="/_next/static/a.js"></script>`);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  // The script requires https; the mock is http, so assert the guard and exercise the pure path instead.
  const refused = spawnSync(process.execPath, ["deployment/lab-e2e/legitimate-user-baseline.mjs"], { env: { ...process.env, LAB_E2E_BASE_URL: `http://127.0.0.1:${port}` }, encoding: "utf8" });
  assert.equal(refused.status, 2);
  assert.match(refused.stderr, /https origin/u);
  server.close();
});
