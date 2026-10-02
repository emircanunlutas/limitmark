import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { after, test } from "node:test";
import { executeHttpWorkload, sendAuthorized } from "../lab/load/engine";
import { authorizeRun, buildRegistry, type AuthorizedRun, type EffectiveLimits } from "../lab/policy/target-policy";
import { THRESHOLD_SETS, type HttpThresholds } from "../lab/policy/thresholds";
import type { WorkloadId } from "../lab/policy/workloads";

type Seen = { method: string; url: string; headers: http.IncomingHttpHeaders; body: string };
const servers: http.Server[] = [];

async function listen(handler: (request: http.IncomingMessage, response: http.ServerResponse, seen: Seen) => void) {
  const requests: Seen[] = [];
  let inFlight = 0, maxInFlight = 0;
  const server = http.createServer((request, response) => {
    inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
    response.on("close", () => { inFlight--; });
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const seen = { method: request.method ?? "", url: request.url ?? "", headers: request.headers, body: Buffer.concat(chunks).toString("utf8") };
      requests.push(seen);
      handler(request, response, seen);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  servers.push(server);
  return { port: (server.address() as AddressInfo).port, requests, maxInFlight: () => maxInFlight };
}

after(async () => { for (const server of servers) { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); } });

function runFor(port: number, workloadId: WorkloadId = "latency-measurement", phases?: EffectiveLimits["phases"], extra: Partial<EffectiveLimits> = {}): AuthorizedRun {
  const now = new Date();
  const registry = buildRegistry([{ id: "lab-test", class: "lab-local", scheme: "http", host: "127.0.0.1", port, allowedPaths: ["/", "/gizlilik", "/test-talep-et", "/api/public-inquiries"], allowedMethods: ["GET", "POST"] }], now);
  const run = authorizeRun({ targetId: "lab-test", workloadId, registry, now });
  return { ...run, limits: { ...run.limits, ...(phases ? { phases } : {}), ...extra } };
}

const phase = (over: Partial<EffectiveLimits["phases"][number]> = {}) => ({ name: "p", durationSeconds: 2, ratePerSecond: 10, concurrency: 2, timeoutMs: 1000, ...over });
const lenient: HttpThresholds = { ...THRESHOLD_SETS["local-loopback-v1"].http["latency-measurement"], stop: { errorRate: 2, afterSamples: 1_000_000, consecutiveFailures: 1_000_000, p99Ms: 1e9 } };

test("the sender refuses any request object the policy did not issue", () => {
  const run = runFor(65000);
  const forged = { method: "GET", url: "http://127.0.0.1:65000/", targetId: "lab-test", path: "/", scheme: "http", host: "127.0.0.1", port: 65000 };
  assert.throws(() => sendAuthorized(forged as never, run, { timeoutMs: 100, agent: new http.Agent() }), /did not authorize/);
  assert.throws(() => sendAuthorized({ ...run.authorizeRequest("GET", "/") } as never, run, { timeoutMs: 100, agent: new http.Agent() }), /did not authorize/);
  assert.throws(() => sendAuthorized(run.authorizeRequest("GET", "/"), run, { timeoutMs: 999_999, agent: new http.Agent() }), /hard ceiling/);
});

test("the engine never exceeds the phase rate or concurrency, and counts what it had to drop", async () => {
  const server = await listen((_request, response) => setTimeout(() => response.end("ok"), 250));
  const result = await executeHttpWorkload({ run: runFor(server.port, "latency-measurement", [phase({ durationSeconds: 2, ratePerSecond: 20, concurrency: 2 })], { maxTotalRequests: 1000 }), thresholds: lenient });
  assert.ok(server.maxInFlight() <= 2, `max in-flight ${server.maxInFlight()}`);
  assert.ok(result.phases[0].attempted <= 2 * 20 + 1, `attempted ${result.phases[0].attempted}`);
  assert.ok(result.phases[0].droppedByConcurrencyCap > 0, "saturation must be counted, not queued");
  assert.equal(server.requests.length, result.phases[0].attempted);
});

test("the engine stops at the total request ceiling", async () => {
  const server = await listen((_request, response) => response.end("ok"));
  const result = await executeHttpWorkload({ run: runFor(server.port, "latency-measurement", [phase({ durationSeconds: 3, ratePerSecond: 50, concurrency: 4 })], { maxTotalRequests: 7 }), thresholds: lenient });
  assert.equal(result.totalAttempted, 7);
  assert.equal(server.requests.length, 7);
  assert.equal(result.stopReason, "total request ceiling reached");
});

test("the engine stops at the global deadline even if phases are longer", async () => {
  const server = await listen((_request, response) => response.end("ok"));
  const started = Date.now();
  const result = await executeHttpWorkload({ run: runFor(server.port, "latency-measurement", [phase({ durationSeconds: 60, ratePerSecond: 5, concurrency: 1 })], { maxDurationSeconds: 1 }), thresholds: lenient });
  assert.ok(Date.now() - started < 6_000, "must stop near the 1 s cap + grace");
  assert.equal(result.stopReason, "global deadline reached");
});

test("redirects are never followed; out-of-allowlist redirects are counted as refused", async () => {
  const outside = await listen((_request, response) => response.end("outside"));
  const allowed = await listen((request, response) => { response.statusCode = 302; response.setHeader("location", "/gizlilik"); response.end(); void request; });
  const refused = await listen((_request, response) => { response.statusCode = 302; response.setHeader("location", `http://127.0.0.1:${outside.port}/x`); response.end(); });
  const one = [phase({ durationSeconds: 1, ratePerSecond: 5, concurrency: 1 })];
  const a = await executeHttpWorkload({ run: runFor(allowed.port, "latency-measurement", one), thresholds: lenient });
  assert.ok((a.phases[0].outcomes.redirect ?? 0) > 0);
  assert.ok(allowed.requests.every((seen) => seen.url !== "/gizlilik" || false) || allowed.requests.every((seen) => ["/", "/gizlilik", "/test-talep-et"].includes(seen.url)));
  assert.equal(allowed.requests.length, a.phases[0].attempted, "the redirect target must not be fetched automatically");
  const r = await executeHttpWorkload({ run: runFor(refused.port, "latency-measurement", one), thresholds: lenient });
  assert.ok((r.phases[0].outcomes.redirect_refused ?? 0) > 0);
  assert.equal(r.phases[0].succeeded, 0, "a refused redirect is a failure");
  assert.equal(outside.requests.length, 0, "no request may reach the redirect destination");
});

test("timeouts, refused connections and oversized bodies are classified", async () => {
  const hang = await listen(() => undefined);
  const t = await executeHttpWorkload({ run: runFor(hang.port, "latency-measurement", [phase({ durationSeconds: 1, ratePerSecond: 5, concurrency: 1, timeoutMs: 80 })]), thresholds: lenient });
  assert.ok((t.phases[0].outcomes.timeout ?? 0) > 0);
  assert.ok(t.phases[0].latencyMs.min >= 70);

  const closed = await new Promise<number>((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = (s.address() as AddressInfo).port; s.close(() => resolve(p)); }); });
  const c = await executeHttpWorkload({ run: runFor(closed, "latency-measurement", [phase({ durationSeconds: 1, ratePerSecond: 5, concurrency: 1 })]), thresholds: lenient });
  assert.ok((c.phases[0].outcomes.conn_refused ?? 0) > 0);

  const big = await listen((_request, response) => { response.write(Buffer.alloc(2 * 1024 * 1024, 97)); response.end(); });
  const b = await executeHttpWorkload({ run: runFor(big.port, "latency-measurement", [phase({ durationSeconds: 1, ratePerSecond: 2, concurrency: 1 })]), thresholds: lenient });
  assert.ok((b.phases[0].outcomes.body_too_large ?? 0) > 0);
  assert.ok(b.phases[0].bytesReceived < 3 * 1024 * 1024 * 3);
});

test("a failing target trips the STOP threshold quickly and the run ends", async () => {
  const closed = await new Promise<number>((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = (s.address() as AddressInfo).port; s.close(() => resolve(p)); }); });
  const strict = THRESHOLD_SETS["local-loopback-v1"].http["latency-measurement"];
  const result = await executeHttpWorkload({ run: runFor(closed, "latency-measurement", [phase({ durationSeconds: 30, ratePerSecond: 50, concurrency: 2 })]), thresholds: strict });
  assert.match(result.stopReason ?? "", /STOP threshold/);
  assert.ok(result.totalAttempted <= strict.stop.consecutiveFailures + 5, `attempted ${result.totalAttempted}`);
  assert.ok(result.wallClockSeconds < 10);
});

test("POST sends only the synthetic demo form with the fixed header set and nothing credential-like", async () => {
  const server = await listen((_request, response) => response.end("{}"));
  const run = runFor(server.port, "demo-submission-post", [phase({ durationSeconds: 1, ratePerSecond: 5, concurrency: 1 })]);
  await executeHttpWorkload({ run, thresholds: lenient });
  assert.ok(server.requests.length >= 3);
  for (const seen of server.requests) {
    assert.equal(seen.method, "POST");
    assert.equal(seen.url, "/api/public-inquiries");
    assert.equal(seen.headers["content-type"], "application/x-www-form-urlencoded");
    assert.equal(seen.headers.origin, `http://127.0.0.1:${server.port}`);
    assert.equal(seen.headers["user-agent"], "limitmark-lab/1");
    for (const forbidden of ["authorization", "cookie", "x-forwarded-for", "proxy-authorization"]) assert.equal(seen.headers[forbidden], undefined, forbidden);
    const form = new URLSearchParams(seen.body);
    assert.match(form.get("email") ?? "", /@example\.test$/);
    assert.match(form.get("submissionToken") ?? "", /^[A-Za-z0-9_-]{43}$/);
  }
  const tokens = new Set(server.requests.map((seen) => new URLSearchParams(seen.body).get("submissionToken")));
  assert.equal(tokens.size, server.requests.length, "every submission uses a fresh synthetic token");
});

test("only paths from the workload are ever requested", async () => {
  const server = await listen((_request, response) => response.end("ok"));
  await executeHttpWorkload({ run: runFor(server.port, "latency-measurement", [phase({ durationSeconds: 1, ratePerSecond: 20, concurrency: 2 })]), thresholds: lenient });
  const paths = new Set(server.requests.map((seen) => seen.url));
  for (const path of paths) assert.ok(["/", "/gizlilik", "/test-talep-et"].includes(path), path);
  assert.ok(server.requests.every((seen) => seen.method === "GET"));
});

test("k6 summaries are read correctly in both export formats (a bare boolean threshold is TRUE when crossed)", async () => {
  const { parseK6Summary } = await import("../lab/load/k6");
  // Real k6 v2 export from a healthy run: thresholds are bare `false` = not crossed, values are flat.
  const healthy = parseK6Summary({ metrics: {
    "http_req_failed{scenario:p0}": { thresholds: { "rate<0.05": false, "rate<=0.005": false }, value: 0 },
    "http_req_duration{scenario:p0}": { thresholds: { "p(99)<3000": false, "p(95)<=250": false }, "p(95)": 7.3, "p(99)": 8.9, med: 2.7, max: 17.9 },
    http_req_duration: { "p(95)": 7.3, "p(99)": 8.9, med: 2.7, max: 17.9 }, http_reqs: { count: 301 }, http_req_failed: { value: 0 },
  } } as never);
  assert.deepEqual(healthy.failed, { stop: [], pass: [] });
  assert.deepEqual(healthy.metrics, { requests: 301, failedRate: 0, p50Ms: 2.7, p95Ms: 7.3, p99Ms: 8.9, maxMs: 17.9 });
  const crossed = parseK6Summary({ metrics: { "http_req_duration{scenario:p0}": { thresholds: { "p(99)<3000": true, "p(95)<=250": true } } } } as never);
  assert.deepEqual(crossed.failed, { stop: ["http_req_duration p(99)<3000"], pass: ["http_req_duration p(95)<=250"] });
  // Object form (`ok`) used by other versions, with nested `values`.
  const objectForm = parseK6Summary({ metrics: { "http_req_failed{scenario:p0}": { thresholds: { "rate<=0.005": { ok: false } } }, http_reqs: { values: { count: 5 } } } } as never);
  assert.deepEqual(objectForm.failed.pass, ["http_req_failed rate<=0.005"]);
  assert.equal(objectForm.metrics.requests, 5);
});
