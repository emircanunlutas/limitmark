import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { createSyntheticOrigin } from "../defense/origin/synthetic-origin";
import { runJourney } from "../lab/defense/canary";
import { Collector } from "../lab/defense/collector";
import { runFieldJourney } from "../lab/defense/field-canary";

/**
 * The field canary is the Slice-1 journey (`canary.ts`, byte-pinned and untouched) with the destination host as a parameter. These tests run BOTH
 * against the same origin and compare every step record, so the two cannot drift.
 */
test("the field journey and the Slice-1 journey produce identical step records against the same origin (only latency differs)", async () => {
  const origin = createSyntheticOrigin({ instance: "control", onObservation: () => undefined });
  const port = await origin.listen();
  const collector = new Collector(null);
  try {
    const slice1 = await runJourney(collector, { lane: "control", port, phase: "parity", journey: 1, timeoutMs: 2_000 });
    const field = await runFieldJourney(collector, { lane: "control", host: "127.0.0.1", port, phase: "parity", journey: 2, timeoutMs: 2_000 });
    assert.equal(slice1.completed, true);
    assert.equal(field.completed, true);
    const strip = (steps: typeof slice1.steps) => steps.map(({ latencyMs, ...rest }) => { void latencyMs; return rest; });
    assert.deepEqual(strip(field.steps), strip(slice1.steps));
    assert.deepEqual(field.steps.map((step) => step.name), ["homepage", "privacy", "form", "valid_post", "thank_you"]);
  } finally { await origin.close(); }
});

test("the field journey fails the same ways: a non-200 step, wrong content, a client timeout; and a failed step stops the journey there", async () => {
  const wrong = http.createServer((_request, response) => { response.writeHead(200, { "content-type": "text/html" }); response.end("<html>nothing</html>"); });
  await new Promise<void>((resolve) => wrong.listen(0, "127.0.0.1", resolve));
  const wrongPort = (wrong.address() as AddressInfo).port;
  const status = http.createServer((_request, response) => { response.writeHead(503); response.end("busy"); });
  await new Promise<void>((resolve) => status.listen(0, "127.0.0.1", resolve));
  const statusPort = (status.address() as AddressInfo).port;
  const hang = http.createServer(() => undefined);
  await new Promise<void>((resolve) => hang.listen(0, "127.0.0.1", resolve));
  const hangPort = (hang.address() as AddressInfo).port;
  const collector = new Collector(null);
  try {
    const content = await runFieldJourney(collector, { lane: "protected", host: "127.0.0.1", port: wrongPort, phase: "t", journey: 1, timeoutMs: 1_000 });
    assert.equal(content.completed, false);
    assert.equal(content.steps.length, 1);
    assert.equal(content.steps[0].failure, "homepage_content");
    const refused = await runFieldJourney(collector, { lane: "protected", host: "127.0.0.1", port: statusPort, phase: "t", journey: 2, timeoutMs: 1_000 });
    assert.equal(refused.steps[0].failure, "status_503", "a legitimate user's 503 fails the journey");
    const timeout = await runFieldJourney(collector, { lane: "protected", host: "127.0.0.1", port: hangPort, phase: "t", journey: 3, timeoutMs: 150 });
    assert.equal(timeout.steps[0].failure, "client_timeout");
  } finally {
    for (const server of [wrong, status, hang]) { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); }
  }
});

test("the destination host is a parameter: the Host header the origin sees is the one the journey was told to use", async () => {
  const seen: string[] = [];
  const server = http.createServer((request, response) => { seen.push(String(request.headers.host)); response.writeHead(200); response.end("x"); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  const collector = new Collector(null);
  try {
    await runFieldJourney(collector, { lane: "protected", host: "127.0.0.1", port, phase: "t", journey: 1, timeoutMs: 500 });
    assert.deepEqual(seen, [`127.0.0.1:${port}`]);
  } finally { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); }
});
