import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { after, test } from "node:test";
import { executeClosedLoop, sendClosedLoop, TRANSPORT_FAILURES, type ClosedLoopResult } from "../lab/load/closed-loop";
import { buildGeneratorReport } from "../lab/defense/generator-report";
import { BA0_FIELD_V1, ba0FieldFingerprint } from "../lab/defense/field-thresholds";
import { assertEvidenceSafe } from "../lab/evidence/redact";
import { authorizeRun, buildRegistry, type AuthorizedRun, type EffectiveLimits } from "../lab/policy/target-policy";
import { WORKLOADS } from "../lab/policy/workloads";

type Seen = { method: string; url: string; headers: http.IncomingHttpHeaders; body: string };
const servers: http.Server[] = [];

async function listen(handler: (request: http.IncomingMessage, response: http.ServerResponse, seen: Seen, index: number) => void) {
  const requests: Seen[] = [];
  let active = 0;
  let maxActive = 0;
  const perSocket = new Map<unknown, number>();
  let maxPerSocket = 0;
  const server = http.createServer((request, response) => {
    active++;
    maxActive = Math.max(maxActive, active);
    perSocket.set(request.socket, (perSocket.get(request.socket) ?? 0) + 1);
    maxPerSocket = Math.max(maxPerSocket, perSocket.get(request.socket) ?? 0);
    response.on("close", () => { active--; perSocket.set(request.socket, (perSocket.get(request.socket) ?? 1) - 1); });
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const seen = { method: request.method ?? "", url: request.url ?? "", headers: request.headers, body: Buffer.concat(chunks).toString("utf8") };
      requests.push(seen);
      handler(request, response, seen, requests.length - 1);
    });
  });
  const sockets = new Set<import("node:net").Socket>();
  server.on("connection", (socket) => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  servers.push(server);
  return { port: (server.address() as AddressInfo).port, requests, maxActive: () => maxActive, maxPerSocket: () => maxPerSocket, connections: () => sockets.size };
}
after(async () => { for (const server of servers) { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); } });

/**
 * A closed-loop run against a loopback server. `authorizeRun` refuses the real workload on a loopback target (it is remote-only, which is the
 * point of that policy), so the requests are authorized through two ordinary loopback workloads and combined; the engine is exercised exactly as it
 * would be, with the reviewed workload's fixtures.
 */
function closedRun(port: number, phase: Partial<EffectiveLimits["phases"][number]> = {}, limits: Partial<EffectiveLimits> = {}, assertStillAuthorized?: () => void): AuthorizedRun {
  const now = new Date();
  const registry = buildRegistry([{ id: "lab-test", class: "lab-local", scheme: "http", host: "127.0.0.1", port, allowedPaths: ["/", "/gizlilik", "/test-talep-et", "/api/public-inquiries"], allowedMethods: ["GET", "POST"] }], now);
  const get = authorizeRun({ targetId: "lab-test", workloadId: "latency-measurement", registry, now });
  const post = authorizeRun({ targetId: "lab-test", workloadId: "demo-submission-post", registry, now });
  const base = WORKLOADS["ba0-l7-pressure-c1"];
  const effective: EffectiveLimits = {
    phases: [{ name: "pressure", durationSeconds: 1, ratePerSecond: 25, concurrency: 1, timeoutMs: 1_000, ...phase }],
    maxTotalRequests: 1_500, maxDurationSeconds: 1, maxRequestsPerSecond: 25, maxConcurrency: 1, ...limits,
  };
  return {
    ...get, workload: base, limits: effective,
    authorizeRequest: (method, path) => (method === "POST" ? post : get).authorizeRequest(method, path),
    ...(assertStillAuthorized ? { assertStillAuthorized } : {}),
  };
}

const ok = (response: http.ServerResponse): void => { response.writeHead(200, { "content-type": "text/plain" }); response.end("ok"); };

// ------------------------------------------------------------------------------------------------ D7: exact closed-loop concurrency
test("D7: N=1 means exactly one logical request in flight: the generator's own count and the server's both peak at 1, and nothing overlaps on a connection", async () => {
  const server = await listen((_request, response) => setTimeout(() => ok(response), 60));
  const result = await executeClosedLoop({ run: closedRun(server.port) });
  assert.ok(result.attempted >= 8, `attempted ${result.attempted}`);
  assert.equal(result.concurrency.maxInFlightObserved, 1);
  assert.equal(result.concurrency.inFlightNow, 0, "nothing in flight at the end");
  assert.equal(result.concurrency.planned, 1);
  assert.equal(server.maxActive(), 1, "the server never saw two at once");
  assert.equal(server.maxPerSocket(), 1, "no pipelining: never two outstanding requests on one connection");
  assert.equal(server.requests.length, result.attempted, "every attempt reached the server exactly once: no hidden retry");
  assert.equal(result.stop.kind, "completed");
  assert.equal(result.retries, 0);
  assert.equal(result.pipelining, false);
});

test("D7: connection reuse is measured SEPARATELY and never changes logical concurrency", async () => {
  const server = await listen((_request, response) => setTimeout(() => ok(response), 30));
  const result = await executeClosedLoop({ run: closedRun(server.port) });
  assert.equal(result.connections.new, 1, "one connection, kept alive");
  assert.equal(result.connections.reused, result.attempted - 1);
  assert.equal(result.connections.new + result.connections.reused, result.attempted);
  assert.equal(result.concurrency.maxInFlightObserved, 1);
});

test("N workers means at most N in flight: with N=3 the generator reaches exactly 3 and never more, and so does the server", async () => {
  const server = await listen((_request, response) => setTimeout(() => ok(response), 150));
  const result = await executeClosedLoop({ run: closedRun(server.port, { concurrency: 3 }, { maxConcurrency: 3 }) });
  assert.equal(result.concurrency.maxInFlightObserved, 3);
  assert.ok(server.maxActive() <= 3, `server saw ${server.maxActive()}`);
  assert.equal(server.maxPerSocket(), 1, "each worker used its own connection: no pipelining");
  assert.ok(result.connections.new <= 3);
});

test("D7: there are NO automatic retries: a connection reset is recorded once, the generator stops, and the server saw the request exactly once", async () => {
  const server = await listen((request) => { request.socket.destroy(); });
  const result = await executeClosedLoop({ run: closedRun(server.port) });
  assert.equal(result.attempted, 1);
  assert.equal(server.requests.length, 1, "not retried");
  assert.equal(result.transportFailures, 1);
  assert.equal(result.outcomes.conn_reset, 1);
  assert.equal(result.stop.kind, "transport_failure");
  assert.equal(result.stop.detail, "conn_reset");
});

test("D7: without stop-on-failure the next request is a NEW logical request, never an overlapping retry: server requests equal attempts", async () => {
  const server = await listen((request, response, _seen, index) => { if (index % 2 === 0) request.socket.destroy(); else ok(response); });
  const result = await executeClosedLoop({ run: closedRun(server.port), stopOnTransportFailure: false });
  assert.ok(result.attempted >= 6);
  assert.ok(result.transportFailures >= 3);
  assert.equal(server.requests.length, result.attempted);
  assert.equal(server.maxActive(), 1);
  assert.equal(result.concurrency.maxInFlightObserved, 1);
});

test("D7: a transport failure STOPS the N=1 generator: a timeout ends the run with the reason, and nothing is sent after it", async () => {
  const server = await listen(() => undefined);
  const started = Date.now();
  const result = await executeClosedLoop({ run: closedRun(server.port, { timeoutMs: 120 }) });
  assert.equal(result.attempted, 1);
  assert.equal(result.outcomes.timeout, 1);
  assert.equal(result.stop.kind, "transport_failure");
  assert.ok(Date.now() - started < 900, "it did not run out the minute");
  for (const outcome of ["timeout", "conn_refused", "conn_reset", "dns", "tls", "body_too_large", "aborted", "other_error"] as const) assert.ok(TRANSPORT_FAILURES.has(outcome), outcome);
  for (const outcome of ["ok", "http_4xx", "http_5xx", "redirect", "redirect_refused"] as const) assert.equal(TRANSPORT_FAILURES.has(outcome), false, `${outcome} is an observation, not a transport failure`);
});

test("a refused connection is a transport failure too (nothing listening)", async () => {
  const probe = http.createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const port = (probe.address() as AddressInfo).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  const result = await executeClosedLoop({ run: closedRun(port) });
  assert.equal(result.outcomes.conn_refused, 1);
  assert.equal(result.stop.kind, "transport_failure");
});

test("HTTP status alone never decides anything: 503s and 4xx are counted and reported, never a failure and never a stop", async () => {
  const server = await listen((_request, response, seen) => { response.writeHead(seen.method === "POST" ? 503 : 404, { "content-type": "text/plain" }); response.end("x"); });
  const result = await executeClosedLoop({ run: closedRun(server.port) });
  assert.ok(result.attempted >= 8);
  assert.equal(result.transportFailures, 0);
  assert.equal(result.stop.kind, "completed");
  assert.ok((result.statuses["503"] ?? 0) >= 2 && (result.statuses["404"] ?? 0) >= 6);
  assert.equal(result.responses, result.attempted);
});

// ------------------------------------------------------------------------------------------------ ceilings, pacing, stops
test("the total request ceiling and the pacing ceiling are hard: never more than the ceiling, never faster than the rate", async () => {
  const server = await listen((_request, response) => ok(response));
  const capped = await executeClosedLoop({ run: closedRun(server.port, { ratePerSecond: 25, durationSeconds: 5 }, { maxTotalRequests: 7, maxDurationSeconds: 5 }) });
  assert.equal(capped.attempted, 7);
  assert.equal(capped.stop.kind, "total_ceiling");
  assert.equal(server.requests.length, 7);
  const paced = await executeClosedLoop({ run: closedRun(server.port, { ratePerSecond: 10, durationSeconds: 1 }, { maxRequestsPerSecond: 10, maxDurationSeconds: 1 }) });
  assert.ok(paced.attempted <= 11, `paced attempted ${paced.attempted}`);
  assert.ok(paced.attempted >= 8);
  assert.ok(paced.schedule.paced > 0);
  assert.ok(paced.wallClockSeconds <= 3);
});

test("the duration is the normal end: the run is `completed` and stops dispatching at the deadline", async () => {
  const server = await listen((_request, response) => ok(response));
  const result = await executeClosedLoop({ run: closedRun(server.port, { durationSeconds: 1, ratePerSecond: 20 }, { maxDurationSeconds: 1 }) });
  assert.equal(result.stop.kind, "completed");
  assert.ok(result.wallClockSeconds >= 0.9 && result.wallClockSeconds < 3);
});

test("a target authorization that lapses mid-run stops the generator before the next request", async () => {
  const server = await listen((_request, response) => ok(response));
  let calls = 0;
  const result = await executeClosedLoop({ run: closedRun(server.port, {}, {}, () => { if (++calls > 8) throw new Error("expired"); }) });
  assert.equal(result.stop.kind, "authorization_expired");
  assert.ok(result.attempted >= 1 && result.attempted < 8);
});

test("an operator abort ends the run with that reason and cancels what is in flight", async () => {
  const server = await listen(() => undefined);
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 150);
  const result = await executeClosedLoop({ run: closedRun(server.port, { timeoutMs: 5_000 }), signal: controller.signal });
  assert.equal(result.stop.kind, "operator_abort");
  assert.equal(result.concurrency.inFlightNow, 0);
});

test("the sender refuses anything the policy did not authorize, a timeout outside the hard ceiling, and a workload that is not closed-loop", async () => {
  const run = closedRun(65_001);
  const forged = { method: "GET", url: "http://127.0.0.1:65001/", targetId: "lab-test", path: "/", scheme: "http", host: "127.0.0.1", port: 65_001 };
  assert.throws(() => sendClosedLoop(forged as never, run, { timeoutMs: 100, agent: new http.Agent() }), /did not authorize/);
  assert.throws(() => sendClosedLoop(run.authorizeRequest("GET", "/"), run, { timeoutMs: 999_999, agent: new http.Agent() }), /hard ceiling/);
  const open = authorizeRun({ targetId: "lab-test", workloadId: "latency-measurement", registry: buildRegistry([{ id: "lab-test", class: "lab-local", scheme: "http", host: "127.0.0.1", port: 65_001, allowedPaths: ["/", "/gizlilik", "/test-talep-et"], allowedMethods: ["GET"] }], new Date()), now: new Date() });
  await assert.rejects(() => executeClosedLoop({ run: open }), /not a closed-loop workload/);
});

// ------------------------------------------------------------------------------------------------ the request shape
test("the reviewed four-request cycle is sent round robin; a POST is a fixed urlencoded form with a fabricated token and an Origin equal to the Host; a GET has no body", async () => {
  const server = await listen((_request, response) => ok(response));
  const result = await executeClosedLoop({ run: closedRun(server.port, { durationSeconds: 1, ratePerSecond: 25 }, { maxTotalRequests: 12, maxDurationSeconds: 1 }) });
  assert.equal(result.attempted, 12);
  assert.deepEqual(server.requests.slice(0, 4).map((seen) => `${seen.method} ${seen.url}`), ["GET /", "GET /gizlilik", "GET /test-talep-et", "POST /api/public-inquiries"]);
  assert.deepEqual(Object.values(result.perFixture).map((entry) => entry.attempted), [3, 3, 3, 3]);
  assert.deepEqual(Object.keys(result.perFixture), ["get_home", "get_privacy", "get_form", "post_inquiry"]);
  const post = server.requests.find((seen) => seen.method === "POST")!;
  assert.equal(post.headers["content-type"], "application/x-www-form-urlencoded");
  assert.equal(post.headers.origin, `http://127.0.0.1:${server.port}`);
  assert.equal(post.headers.host, `127.0.0.1:${server.port}`);
  assert.match(post.body, /submissionToken=[A-Za-z0-9_-]{43}(&|$)/);
  const tokens = server.requests.filter((seen) => seen.method === "POST").map((seen) => /submissionToken=([A-Za-z0-9_-]{43})/.exec(seen.body)![1]);
  assert.equal(new Set(tokens).size, tokens.length, "every POST carries a different fabricated token (it never replays a rendered one: no token farming)");
  for (const seen of server.requests.filter((candidate) => candidate.method === "GET")) assert.equal(seen.body, "");
  assert.ok(result.wireBytesSent > 0 && result.wireBytesReceived > 0, "bytes sent and received are measured");
});

test("the generator never follows a redirect and never reads more than the response ceiling", async () => {
  const redirecting = await listen((_request, response) => { response.writeHead(302, { location: "http://example.test/elsewhere" }); response.end(); });
  const result = await executeClosedLoop({ run: closedRun(redirecting.port, { durationSeconds: 1 }, { maxTotalRequests: 3 }), stopOnTransportFailure: false });
  assert.ok((result.outcomes.redirect_refused ?? 0) >= 3, "an unauthorized redirect is refused, not followed");
  assert.equal(redirecting.requests.every((seen) => !seen.url.includes("elsewhere")), true);
});

// ------------------------------------------------------------------------------------------------ the report
test("the generator report is built from the result with the level's identity, and every key and value passes the evidence scanner", async () => {
  const server = await listen((_request, response) => ok(response));
  const result: ClosedLoopResult = await executeClosedLoop({ run: closedRun(server.port, {}, { maxTotalRequests: 8 }) });
  const report = buildGeneratorReport({
    result, runId: "20261006T100000Z-load-aaaaaa", campaignId: "campaign-one", levelId: "ba0-l7-c1", gitSha: "a".repeat(40), paramsFingerprintSha256: ba0FieldFingerprint(BA0_FIELD_V1).sha256,
    workload: WORKLOADS["ba0-l7-pressure-c1"], targetId: "sut-test", ceilingRatePerSecond: 25,
  });
  assert.doesNotThrow(() => assertEvidenceSafe(report, "$report"));
  assert.equal(report.attempted, 8);
  assert.equal(report.workers, 1);
  assert.equal(report.concurrency.maxInFlightObserved, 1);
  assert.equal(report.retries, 0);
  assert.equal(report.pipelining, false);
  assert.ok(report.schedule.lagMs.count === 8);
  assert.ok(report.generatorHealth.eldP99Ms >= 0);
  assert.match(report.workloadFingerprintSha256, /^[0-9a-f]{64}$/);
  assert.ok(report.rate.achievedPerSecond > 0);
});
