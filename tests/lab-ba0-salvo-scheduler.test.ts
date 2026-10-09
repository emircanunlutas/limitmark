import assert from "node:assert/strict";
import http from "node:http";
import { test } from "node:test";
import { BA0_FIELD_C2_SALVO_V1, ba0FieldFingerprint } from "../lab/defense/field-thresholds";
import { buildGeneratorReport } from "../lab/defense/generator-report";
import { derivePairs, sourceExercised } from "../lab/defense/salvo-spec";
import { executeClosedLoop, sendClosedLoop, type ClosedLoopOptions, type ClosedLoopSend } from "../lab/load/closed-loop";
import type { SalvoClock } from "../lab/load/salvo";
import { authorizeRun, buildRegistry, type AuthorizedRun } from "../lab/policy/target-policy";
import { WORKLOADS } from "../lab/policy/workloads";
import { assertEvidenceSafe } from "../lab/evidence/redact";

class Clock implements SalvoClock {
  time = 0; earlyWakes = 0;
  jobs: { at: number; finish(): void; signal: AbortSignal }[] = [];
  early = false; lateAt: number | null = null; lateBy = 0;
  now() { return this.time; }
  wall() { return new Date(Date.UTC(2026, 9, 7) + this.time); }
  sleep(ms: number, signal: AbortSignal) {
    if (signal.aborted) return Promise.resolve();
    return new Promise<void>((resolve) => {
      let at = this.time + ms;
      if (this.early && ms > 30 && ms < 100) { at -= .75; this.earlyWakes++; }
      const finish = () => { signal.removeEventListener("abort", finish); resolve(); };
      this.jobs.push({ at, finish, signal }); signal.addEventListener("abort", finish, { once: true });
    });
  }
  async drive<T>(operation: Promise<T>): Promise<T> {
    let done = false; let result: T | undefined; let failure: unknown;
    operation.then(v => { result = v; done = true; }, e => { failure = e; done = true; });
    for (let step = 0; step < 10000 && !done; step++) {
      for (let micro = 0; micro < 24; micro++) await Promise.resolve();
      if (done) break;
      this.jobs = this.jobs.filter(j => !j.signal.aborted);
      assert.ok(this.jobs.length, "scheduler must either complete or have a pending clock event");
      const at = Math.min(...this.jobs.map(j => j.at));
      this.time = at === this.lateAt ? at + this.lateBy : at;
      const ready = this.jobs.filter(j => j.at <= this.time); this.jobs = this.jobs.filter(j => j.at > this.time);
      ready.forEach(j => j.finish());
    }
    assert.ok(done, "finite scheduler completed within bounded test steps");
    if (failure) throw failure;
    return result!;
  }
}

function run(port = 1): AuthorizedRun {
  const now = new Date(); const registry = buildRegistry([{ id: "salvo-test", class: "lab-local", scheme: "http", host: "127.0.0.1", port,
    allowedPaths: ["/", "/gizlilik", "/test-talep-et", "/api/public-inquiries"], allowedMethods: ["GET", "POST"] }], now);
  const get = authorizeRun({ targetId: "salvo-test", workloadId: "latency-measurement", registry, now });
  const post = authorizeRun({ targetId: "salvo-test", workloadId: "demo-submission-post", registry, now });
  return { ...get, workload: WORKLOADS["ba0-l7-pressure-c2-salvo"],
    limits: { phases: [{ name: "pressure", durationSeconds: 60, ratePerSecond: 25, concurrency: 2, timeoutMs: 5000 }],
      maxTotalRequests: 1500, maxDurationSeconds: 60, maxConcurrency: 2, maxRequestsPerSecond: 25 },
    authorizeRequest: (method, route) => (method === "POST" ? post : get).authorizeRequest(method, route) };
}

function sender(clock: Clock, options: { latency?: (index: number) => number; fail?: number; expiry?: number } = {}) {
  const calls: { at: number; method: string; route: string; active: number }[] = []; let active = 0;
  const send: NonNullable<ClosedLoopOptions["send"]> = (request, _run, sendOptions) => {
    const index = calls.length;
    if (index === options.expiry) throw new Error("expired");
    calls.push({ at: clock.now(), method: request.method, route: request.path, active: ++active });
    return clock.sleep(options.latency?.(index) ?? 6, sendOptions.signal!).then(() => {
      active--;
      const failed = index === options.fail || sendOptions.signal!.aborted;
      return { outcome: failed ? "conn_reset" : "ok", status: failed ? null : 200, latencyMs: 6,
        wireBytesSent: 1, wireBytesReceived: failed ? 0 : 1, bodyBytesReceived: failed ? 0 : 1,
        reusedSocket: index >= 2 } satisfies ClosedLoopSend;
    });
  };
  return { send, calls };
}

test("finite salvo sends exactly 750 pairs / 1500 requests, two before await, exact fixtures, full phase and no request 1501 reservation", async () => {
  const clock = new Clock(); const s = sender(clock);
  const result = await clock.drive(executeClosedLoop({ run: run(), send: s.send, salvoClock: clock }));
  assert.equal(result.attempted, 1500); assert.equal(result.responses, 1500); assert.equal(result.stop.kind, "completed");
  assert.equal(result.salvo!.pairs.length, 750); assert.equal(result.schedule.paced, 750); assert.equal(result.salvo!.elapsedMs, 60000);
  assert.equal(result.salvo!.stopLatchedMs, null); assert.deepEqual(result.concurrency, { planned: 2, inFlightNow: 0, maxInFlightObserved: 2 });
  assert.deepEqual(Object.values(result.perFixture).map(f => f.attempted), [375, 375, 375, 375]);
  assert.deepEqual(s.calls.slice(0, 4).map(c => `${c.method} ${c.route}`), ["GET /", "GET /gizlilik", "GET /test-talep-et", "POST /api/public-inquiries"]);
  for (let k = 0; k < 750; k++) {
    assert.equal(s.calls[k * 2].at, k * 80); assert.equal(s.calls[k * 2 + 1].at, k * 80);
    assert.equal(s.calls[k * 2].active, 1); assert.equal(s.calls[k * 2 + 1].active, 2);
  }
  assert.equal(clock.jobs.filter(j => !j.signal.aborted).length, 0);
  assert.equal(sourceExercised(derivePairs(result.salvo!.pairs, true)), true);
  const report = buildGeneratorReport({ result, workload: WORKLOADS["ba0-l7-pressure-c2-salvo"], campaignId: "salvo-campaign", levelId: "ba0-l7-c2-salvo",
    runId: "20261007T000000Z-load-aaaaaa", gitSha: "a".repeat(40), paramsFingerprintSha256: ba0FieldFingerprint(BA0_FIELD_C2_SALVO_V1).sha256,
    targetId: "sut-test", ceilingRatePerSecond: 25 });
  assert.deepEqual(report.salvo, result.salvo); assert.equal(Object.hasOwn(report, "n2"), false);
  assert.doesNotThrow(() => assertEvidenceSafe(report));
});

test("early timer wakes cannot dispatch early, and do not change finite completion", async () => {
  const clock = new Clock(); clock.early = true; const s = sender(clock);
  const result = await clock.drive(executeClosedLoop({ run: run(), send: s.send, salvoClock: clock }));
  assert.ok(clock.earlyWakes > 0); assert.equal(result.stop.kind, "completed"); assert.equal(result.attempted, 1500);
  s.calls.forEach((c, i) => assert.equal(c.at, Math.floor(i / 2) * 80));
  assert.equal(result.salvo!.elapsedMs, 60000);
});

test("lateness under 40 ms preserves fixed later releases; 40 ms or more stops without catch-up", async () => {
  for (const delay of [39, 40, 120]) {
    const clock = new Clock(); clock.lateAt = 80; clock.lateBy = delay; const s = sender(clock);
    const result = await clock.drive(executeClosedLoop({ run: run(), send: s.send, salvoClock: clock }));
    if (delay === 39) { assert.equal(result.stop.kind, "completed"); assert.equal(s.calls[4].at, 160); }
    else { assert.equal(result.stop.kind, "schedule_incomplete"); assert.equal(result.attempted, 2); assert.equal(result.salvo!.stopLatchedMs, 80 + delay); }
  }
});

test("an active previous pair at the next release stops; it never queues, overlaps another pair or catches up", async () => {
  const clock = new Clock(); const s = sender(clock, { latency: () => 100 });
  const result = await clock.drive(executeClosedLoop({ run: run(), send: s.send, salvoClock: clock }));
  assert.equal(result.stop.kind, "schedule_incomplete"); assert.equal(result.stop.detail, "previous_pair_active");
  assert.equal(result.salvo!.stopLatchedMs, 80); assert.equal(s.calls.length, 2); assert.equal(result.concurrency.inFlightNow, 0);
});

test("an exactly settled release boundary is allowed; a request still active just beyond it stops", async () => {
  for (const latency of [80, 80.001]) {
    const clock = new Clock(); const s = sender(clock, { latency: () => latency });
    const result = await clock.drive(executeClosedLoop({ run: run(), send: s.send, salvoClock: clock }));
    if (latency === 80) { assert.equal(result.stop.kind, "completed"); assert.equal(result.attempted, 1500); assert.equal(result.salvo!.elapsedMs, 60000); }
    else { assert.equal(result.stop.kind, "schedule_incomplete"); assert.equal(result.attempted, 2); }
  }
});

test("a delayed watchdog waking after late clean settlements cannot hide a missed release", async () => {
  const clock = new Clock(); clock.lateAt = 80; clock.lateBy = 20;
  const s = sender(clock, { latency: i => i < 2 ? 100 : 6 });
  const result = await clock.drive(executeClosedLoop({ run: run(), send: s.send, salvoClock: clock }));
  assert.equal(result.attempted, 2); assert.equal(result.responses, 2); assert.equal(result.transportFailures, 0);
  assert.equal(result.stop.kind, "schedule_incomplete"); assert.equal(result.salvo!.stopLatchedMs, 100);
});

test("reviewed HTTP 503 responses remain observations and never stop the paired scheduler", async () => {
  const clock = new Clock(); const s = sender(clock);
  const send: NonNullable<ClosedLoopOptions["send"]> = async (...args) => {
    const response = await s.send(...args);
    return args[0].method === "POST" ? { ...response, status: 503, outcome: "http_5xx" } : response;
  };
  const result = await clock.drive(executeClosedLoop({ run: run(), send, salvoClock: clock }));
  assert.equal(result.stop.kind, "completed"); assert.equal(result.transportFailures, 0);
  assert.deepEqual(result.statuses, { "200": 1125, "503": 375 }); assert.equal(result.responses, 1500);
});

test("transport failure with the partner active latches failure, aborts the partner and sends nothing further", async () => {
  const clock = new Clock(); const s = sender(clock, { fail: 0, latency: i => i === 0 ? 2 : 20 });
  const result = await clock.drive(executeClosedLoop({ run: run(), send: s.send, salvoClock: clock, stopOnTransportFailure: false }));
  assert.equal(result.stop.kind, "transport_failure"); assert.equal(result.salvo!.stopLatchedMs, 2);
  assert.equal(result.attempted, 2); assert.equal(result.transportFailures, 2); assert.equal(result.concurrency.inFlightNow, 0);
});

test("authorization expiry before the partner dispatch is non-qualifying and preserves an explicit incomplete pair", async () => {
  const clock = new Clock(); const s = sender(clock, { expiry: 1 });
  const result = await clock.drive(executeClosedLoop({ run: run(), send: s.send, salvoClock: clock }));
  assert.equal(result.stop.kind, "authorization_expired"); assert.equal(s.calls.length, 1); assert.equal(result.attempted, 1);
  assert.equal(result.salvo!.pairs[0].settledMs[1], null); assert.equal(derivePairs(result.salvo!.pairs, true).valid, false);
});

test("abort during two active requests and abort at the full-duration boundary never become completed", async () => {
  for (const at of [2, 60000]) {
    const clock = new Clock(); const controller = new AbortController();
    void clock.sleep(at, new AbortController().signal).then(() => controller.abort());
    const s = sender(clock); const result = await clock.drive(executeClosedLoop({ run: run(), send: s.send, salvoClock: clock, signal: controller.signal }));
    assert.equal(result.stop.kind, "operator_abort"); assert.equal(result.salvo!.stopLatchedMs, at); assert.equal(result.concurrency.inFlightNow, 0);
    if (at === 60000) { assert.equal(result.attempted, 1500); assert.equal(result.responses, 1500); assert.equal(result.salvo!.elapsedMs, 60000); }
    else assert.equal(result.attempted, 2);
  }
});

test("authorization expiry during the final full-phase wait or final drain cannot become completed", async () => {
  for (const finalLatency of [6, 180]) {
    const clock = new Clock(); const r = run();
    const expiring = { ...r, assertStillAuthorized: () => { if (clock.time >= 59980) throw new Error("expired"); } };
    const s = sender(clock, { latency: i => i >= 1498 ? finalLatency : 6 });
    const result = await clock.drive(executeClosedLoop({ run: expiring, send: s.send, salvoClock: clock }));
    assert.equal(result.stop.kind, "authorization_expired"); assert.equal(result.attempted, 1500); assert.equal(result.responses, 1500);
    assert.equal(result.salvo!.stopLatchedMs, Math.max(60000, 59920 + finalLatency));
    assert.equal(result.concurrency.inFlightNow, 0);
  }
});

test("last-pair drain reaching the hard boundary latches deadline and cannot qualify", async () => {
  const clock = new Clock(); const s = sender(clock, { latency: i => i >= 1498 ? 5000 : 6 });
  const result = await clock.drive(executeClosedLoop({ run: run(), send: s.send, salvoClock: clock }));
  assert.equal(result.stop.kind, "deadline"); assert.equal(result.salvo!.elapsedMs, 64000); assert.equal(result.salvo!.stopLatchedMs, 64000);
  assert.equal(result.responses, 1498); assert.equal(result.transportFailures, 2); assert.equal(result.concurrency.inFlightNow, 0);
});

test("the new scheduler refuses reduced or mismatched limits instead of redefining the reviewed schedule", async () => {
  const original = run(); const altered = { ...original, limits: { ...original.limits, maxTotalRequests: 1499 } };
  await assert.rejects(executeClosedLoop({ run: altered }), /exact reviewed limits/);
});

test("authorization preparation cannot make a request dispatch after its lateness check", async () => {
  const clock = new Clock(); const s = sender(clock); const r = run();
  const delayed = { ...r, assertStillAuthorized: () => { clock.time += 40; } };
  const result = await clock.drive(executeClosedLoop({ run: delayed, send: s.send, salvoClock: clock }));
  assert.equal(s.calls.length, 0); assert.equal(result.stop.kind, "schedule_incomplete"); assert.equal(result.salvo!.stopLatchedMs, 40);
});

test("real loopback paired HTTP uses two keep-alive connections and never pipelines or serializes the pair", async () => {
  const sockets = new Set<unknown>(); const activePerSocket = new Map<unknown, number>(); let active = 0; let maxActive = 0; let maxPerSocket = 0;
  const server = http.createServer((request, response) => {
    sockets.add(request.socket); active++; maxActive = Math.max(maxActive, active);
    const n = (activePerSocket.get(request.socket) ?? 0) + 1; activePerSocket.set(request.socket, n); maxPerSocket = Math.max(maxPerSocket, n);
    setTimeout(() => { response.writeHead(200); response.end("ok"); }, 10);
    response.on("finish", () => { active--; activePerSocket.set(request.socket, activePerSocket.get(request.socket)! - 1); });
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const controller = new AbortController(); let responses = 0;
  try {
    const result = await executeClosedLoop({ run: run((server.address() as import("node:net").AddressInfo).port), signal: controller.signal,
      send: async (...args) => { const r = await sendClosedLoop(...args); if (++responses === 8) queueMicrotask(() => controller.abort()); return r; } });
    assert.equal(result.attempted, 8); assert.equal(result.responses, 8); assert.equal(result.transportFailures, 0);
    assert.deepEqual(result.connections, { new: 2, reused: 6 }); assert.equal(sockets.size, 2);
    assert.equal(maxActive, 2); assert.equal(maxPerSocket, 1); assert.equal(result.stop.kind, "operator_abort");
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
});
