import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import type { AppEvent, BoundaryEvent, PlaneEvent } from "../defense/core/ledger";
import { createAppGuard } from "../defense/origin/app-guard";
import { createBoundary } from "../defense/boundary/boundary";
import { JourneyLanes } from "../defense/core/lanes";
import { importPrivateKey, importPublicKey, issuePb, PB_MAX_LIFETIME_MS } from "../defense/core/hop-proof";
import type { PeerClass } from "../defense/core/ingress-class";
import { ShapeGate } from "../defense/layers/a7-shape-gate";
import { createSyntheticOrigin } from "../defense/origin/synthetic-origin";
import { createFront } from "../defense/plane/front";
import type { L2Params } from "../defense/plane/l2-protocol";
import { L2Stage } from "../defense/plane/l2-stage";
import { SemanticGate } from "../defense/plane/semantic-gate";
import { Collector } from "../lab/defense/collector";
import { canaryCounts, deriveExternalAccounting } from "../lab/defense/external-accounting";
import { ExternalReducer } from "../lab/defense/external-reducer";
import { runFieldJourney } from "../lab/defense/field-canary";
import { HopTrustRoot } from "../lab/defense/hop-keys";
import { BA0_ORIGIN_LOCAL_V1 } from "../lab/defense/origin-thresholds";
import { BA0_FIELD_C2_V1 } from "../lab/defense/field-thresholds";

/**
 * The whole external lane, end to end and in one process: the REAL plane front (with L1, the semantic gate, L2 and PB issuance), the REAL Origin
 * Boundary and the REAL guarded App, with their real events flowing into the REAL collector. A remote peer is simulated with the front's test seam
 * (a second host is not available); the canary is a real local registered request. What is proven: events from the three independent streams join
 * on the plane-minted nonce, in any arrival order; every lifecycle and App lineage validates; and the external counters, identities and bucket
 * replay all hold, with the canary's own accounting side by side.
 */
const L2: L2Params = {
  filterBits: 2 ** 13, filterHashes: 7, epochMs: 60_000, credited: { capacity: 10, refillPerSecond: 2 }, unverified: { capacity: 3, refillPerSecond: 1 },
  maxUses: 3, ledgerCapacity: 512, stage: { timeoutMs: 50, maxConcurrent: 64 },
};
const HOP = BA0_ORIGIN_LOCAL_V1.hop;
const FORM = "application/x-www-form-urlencoded";

async function chain(l2: L2Params = L2) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ba0-e2e-"));
  const collector = new Collector(path.join(dir, "journal.ndjson"), { maxRequests: 4_000, maxEventsPerRecord: 32, maxJournalBytes: 8 * 1_048_576, maxAnomalies: 200 });
  collector.enableOriginStreams();
  collector.enableLaneStreams();
  const reducer = new ExternalReducer({ allowedShed: [{ class: "mutation", lane: "unverified", reason: "lane_budget" }], report: (code, rid, detail) => collector.externalAnomaly(code, rid, detail) });
  collector.enableExternalLane(reducer);
  const root = new HopTrustRoot();
  const seqs = { plane: 0, boundary: 0, app: 0 };
  const planeEmit = (event: Omit<PlaneEvent, "seq" | "t">): number => { const seq = ++seqs.plane; collector.ingestFrame({ type: "events", events: [{ ...event, seq, t: 0 }], dropped: 0 }); return seq; };
  const boundaryEmit = (event: Omit<BoundaryEvent, "seq" | "t">): number => { const seq = ++seqs.boundary; collector.ingestBoundaryFrame({ type: "events", events: [{ ...event, seq, t: 0 }], dropped: 0 }); return seq; };
  const appEmit = (event: Omit<AppEvent, "seq" | "t">): void => { const seq = ++seqs.app; collector.ingestAppFrame({ type: "events", events: [{ ...event, seq, t: 0 }], dropped: 0 }); };

  const appInit = root.appInit({ replayCapacity: HOP.replayCapacity, bodyDeadlineMs: HOP.bodyDeadlineMs });
  const built = createAppGuard({
    keyB: importPublicKey(appInit.publicKeyB), kidB: appInit.kidB, keyP: importPublicKey(appInit.publicKeyP), kidP: appInit.kidP, appId: appInit.appId, boundaryId: appInit.boundaryId,
    replayCapacity: HOP.replayCapacity, bodyDeadlineMs: HOP.bodyDeadlineMs,
  });
  const app = createSyntheticOrigin({ instance: "protected", onObservation: () => undefined, guard: built.guard, onApp: appEmit });
  const appPort = await app.listen();
  const boundaryInit = root.boundaryInit(appPort, { replayCapacity: HOP.replayCapacity, bodyDeadlineMs: HOP.bodyDeadlineMs, forwardTimeoutMs: HOP.forwardTimeoutMs, baLifetimeMs: HOP.baLifetimeMs });
  const boundary = createBoundary({
    appPort, keyP: importPublicKey(boundaryInit.publicKeyP), kidP: boundaryInit.kidP, boundaryId: boundaryInit.boundaryId, keyB: importPrivateKey(boundaryInit.privateKeyB), kidB: boundaryInit.kidB,
    appId: boundaryInit.appId, limits: boundaryInit.limits, emit: boundaryEmit,
  });
  const boundaryPort = await boundary.listen();

  const planeHop = root.planeInit(HOP.pbLifetimeMs);
  const config = { kid: planeHop.kid, privateKey: importPrivateKey(planeHop.privateKey), boundaryId: planeHop.boundaryId, lifetimeMs: Math.min(planeHop.lifetimeMs, PB_MAX_LIFETIME_MS), now: () => Date.now() };
  const lanes = new JourneyLanes({ ...l2, mono: () => performance.now(), key: randomBytes(32) });
  const stage = new L2Stage(lanes, { composer: l2.stage, maxResponseBytes: 1_048_576 });
  let mode: PeerClass = "remote";
  const front = createFront({
    upstream: { host: "127.0.0.1", port: boundaryPort }, emit: planeEmit, layer: new SemanticGate(new ShapeGate()), hop: { issue: (approved, context) => issuePb(config, approved, context) }, l2: stage,
    composer: { timeoutMs: 250, maxConcurrent: 64, failurePolicy: "fail_closed" }, peerClass: () => mode,
  });
  const port = await front.listen();
  return {
    collector, reducer, front, boundary, app, stage, port, seqs, built,
    setMode: (next: PeerClass) => { mode = next; },
    close: async () => { await front.close(300); await boundary.close(); await app.close(); fs.rmSync(dir, { recursive: true, force: true }); },
  };
}

function request(port: number, method: string, target: string, body?: string): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { host: `127.0.0.1:${port}` };
    if (body !== undefined) { headers["content-type"] = FORM; headers.origin = `http://127.0.0.1:${port}`; headers["content-length"] = String(Buffer.byteLength(body)); }
    const req = http.request({ host: "127.0.0.1", port, method, path: target, headers, agent: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

const fabricated = (): string => new URLSearchParams({
  name: "Lab Synthetic", email: "lab@example.test", company: "Synthetic Co", service: "web", system: "synthetic lab system", objective: "synthetic lab objective",
  environment: "staging", authority: "authorized", protection: "unknown", provider: "", notes: "", submissionToken: randomBytes(32).toString("base64url"),
}).toString();

const settle = async (collector: Collector, reducer: ExternalReducer, ms = 400): Promise<void> => { await new Promise((resolve) => setTimeout(resolve, ms)); reducer.sweep(); void collector; };

function finish(c: Awaited<ReturnType<typeof chain>>) {
  // The three processes' final state, as their FIN messages would report it.
  const boundaryStats = c.boundary.stats();
  c.collector.planeFinished({
    drained: true, channel: { emitted: c.seqs.plane, dropped: 0, sent: c.seqs.plane, received: c.seqs.plane, queued: 0, unacknowledged: 0, queueHighWater: 0, lastSeq: c.seqs.plane },
    advisory: { l2: c.stage.stats() } as never,
  });
  c.collector.boundaryFinished({ drained: true, channel: { emitted: c.seqs.boundary, dropped: 0, sent: c.seqs.boundary, received: c.seqs.boundary, queued: 0, unacknowledged: 0, queueHighWater: 0, lastSeq: c.seqs.boundary }, stats: boundaryStats });
  c.collector.appFinished({ drained: true, channel: { emitted: c.seqs.app, dropped: 0, sent: c.seqs.app, received: c.seqs.app, queued: 0, unacknowledged: 0, queueHighWater: 0, lastSeq: c.seqs.app }, stats: { counters: c.app.appStats(), served: c.app.stats(), guard: c.built.stats() } });
  return boundaryStats;
}

test("remote requests and a local canary run through the real plane, Boundary and App; every lifecycle joins, validates and reconciles with no anomaly", async () => {
  const c = await chain();
  try {
    // ---- hostile-shaped traffic from a REMOTE peer: reads, renders, and fabricated-token POSTs
    c.setMode("remote");
    for (let index = 0; index < 3; index++) assert.equal((await request(c.port, "GET", "/")).status, 200);
    for (let index = 0; index < 2; index++) assert.equal((await request(c.port, "GET", "/test-talep-et")).status, 200);
    const posts = [];
    for (let index = 0; index < 6; index++) posts.push(await request(c.port, "POST", "/api/public-inquiries", fabricated()));
    const admitted = posts.filter((reply) => reply.status === 200).length;
    const shed = posts.filter((reply) => reply.status === 503).length;
    assert.equal(admitted + shed, 6);
    assert.ok(shed >= 1 && admitted >= 1, `the unverified budget (3) both admits and sheds: ${admitted} admitted, ${shed} shed`);
    for (const reply of posts) assert.equal(reply.headers["x-ba0-outcome"], undefined, "no decision label ever reaches a remote client");

    // ---- the independent canary: a LOCAL, registered journey through the same listener
    c.setMode("local");
    const journey = await runFieldJourney(c.collector, { lane: "protected", host: "127.0.0.1", port: c.port, phase: "window", journey: 1, timeoutMs: 5_000 });
    assert.equal(journey.completed, true, JSON.stringify(journey.steps.map((step) => [step.name, step.failure])));

    await settle(c.collector, c.reducer);
    const boundaryStats = finish(c);
    c.collector.freeze();
    const { anomalies, anomalyTotal } = c.collector.finalize();
    assert.deepEqual(anomalies, [], "no ledger anomaly of any kind: lifecycle, lineage, L2, streams");
    assert.equal(anomalyTotal, 0);

    const counters = c.reducer.counters();
    assert.equal(counters.accepted, 11);
    assert.equal(counters.reduced, 11);
    assert.equal(counters.terminal.unresolved ?? 0, 0);
    assert.equal(counters.l2.classes.open, 5);
    assert.equal(counters.l2.classes.mutation, 6);
    assert.equal(counters.status503.total, shed);
    assert.equal(counters.status503.expectedShed, shed, "every 503 is a server-attributed L2 budget shed");
    assert.equal(counters.status503.unexplained, 0);
    assert.equal(counters.app.mutated, admitted);
    assert.equal(counters.mutatedByLane.unverified, admitted);
    assert.equal(counters.egress.failed, 0);
    assert.equal(counters.boundary.arrived, 5 + admitted);
    assert.equal(counters.strippedHeaders, 0);

    const canary = canaryCounts([...c.collector.allRecords()], 1);
    assert.equal(canary.app.mutated, 1, "the canary's one valid POST");
    assert.equal(canary.planeAccepted, 5, "its five steps");
    const report = deriveExternalAccounting({
      external: counters, externalDecisions: c.reducer.decisions(), canary, planeFin: c.collector.channel.fin, boundaryFin: c.collector.boundaryInfo.fin, appFin: c.collector.appInfo.fin,
      connections: null, l2: L2, windowElapsedMs: 5_000, workers: 1, externalInFlightMax: 1,
      streams: { planeDropped: 0, boundaryDropped: 0, appDropped: 0, drained: true, finalTicks: { plane: true, boundary: true, app: true }, tickGaps: 0 },
    });
    const failed = report.identities.filter((entry) => !entry.ok);
    assert.deepEqual(failed, [], "every E-identity holds");
    assert.equal(report.buckets.unverified.mismatches, 0);
    assert.equal(report.buckets.unverified.gaps, 0);
    assert.equal(report.buckets.credited.decisions, 1, "the canary's credited admission is part of the replay");
    assert.equal(boundaryStats.rejected, 0);
  } finally { await c.close(); }
});

test("N=2 overlapping external lifecycles conserve exactly through the real unchanged defense chain", async () => {
  const t = BA0_FIELD_C2_V1;
  const c = await chain(t.l2);
  try {
    for (let pair = 0; pair < 3; pair++) {
      const replies = await Promise.all([request(c.port, "GET", "/gizlilik"), request(c.port, "POST", "/api/public-inquiries", fabricated())]);
      assert.ok(replies.every((reply) => reply.status === 200 || reply.status === 503));
      assert.ok(replies.every((reply) => reply.headers["x-ba0-outcome"] === undefined));
    }
    assert.equal(c.front.externalStats().inFlightHighWater, 2);
    assert.equal(c.front.externalStats().inFlight, 0);
    c.setMode("local");
    const journey = await runFieldJourney(c.collector, { lane: "protected", host: "127.0.0.1", port: c.port, phase: "recovery", journey: 1, timeoutMs: t.canary.timeoutMs });
    assert.equal(journey.completed, true);
    await settle(c.collector, c.reducer);
    finish(c);
    c.collector.freeze();
    const { anomalies, anomalyTotal } = c.collector.finalize();
    assert.deepEqual(anomalies, []);
    assert.equal(anomalyTotal, 0);
    const counters = c.reducer.counters();
    assert.equal(counters.accepted, 6);
    assert.equal(counters.reduced, 6);
    assert.equal(counters.terminal.unresolved ?? 0, 0);
    assert.equal(counters.status503.unexplained, 0);
    const accounting = deriveExternalAccounting({
      external: counters, externalDecisions: c.reducer.decisions(), canary: canaryCounts([...c.collector.allRecords()], 1),
      planeFin: c.collector.channel.fin, boundaryFin: c.collector.boundaryInfo.fin, appFin: c.collector.appInfo.fin,
      connections: null, l2: t.l2, windowElapsedMs: 5_000, workers: 2, externalInFlightMax: c.front.externalStats().inFlightHighWater,
      streams: { planeDropped: 0, boundaryDropped: 0, appDropped: 0, drained: true, finalTicks: { plane: true, boundary: true, app: true }, tickGaps: 0 },
    });
    assert.deepEqual(accounting.identities.filter((entry) => !entry.ok), []);
    assert.equal(accounting.buckets.unverified.mismatches, 0);
    assert.equal(accounting.buckets.credited.mismatches, 0);
    await c.collector.closeJournal();
  } finally { await c.close(); }
});

test("a remote request whose downstream events beat its plane ingress to the collector is still joined (separate pipes have no fixed order)", async () => {
  const c = await chain();
  try {
    c.setMode("remote");
    // Hold the plane's events back: capture them, deliver the downstream first, then the plane.
    const held: PlaneEvent[] = [];
    const originalIngest = c.collector.ingestFrame.bind(c.collector);
    (c.collector as unknown as { ingestFrame: typeof originalIngest }).ingestFrame = (frame) => { held.push(...frame.events); return frame.events.length; };
    const reply = await request(c.port, "GET", "/gizlilik");
    assert.equal(reply.status, 200);
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.ok(c.reducer.orphanCount >= 1, "downstream events wait as orphans for their ingress");
    assert.equal(c.reducer.activeCount, 0);
    (c.collector as unknown as { ingestFrame: typeof originalIngest }).ingestFrame = originalIngest;
    originalIngest({ type: "events", events: held, dropped: 0 });
    c.reducer.sweep();
    assert.equal(c.reducer.orphanCount, 0, "the ingress claimed them");
    assert.equal(c.reducer.counters().reduced, 1);
    c.reducer.finalize();
    assert.equal(c.collector.anomalyTotalSoFar, 0);
  } finally { await c.close(); }
});

test("bypass is still fatal: a Boundary or App event that no plane ingress ever claims is an anomaly at finalization", async () => {
  const c = await chain();
  try {
    c.collector.ingestAppFrame({ type: "events", events: [{ seq: 1, t: 0, nonce: "Z".repeat(22), kind: "APP_ADMITTED", hop: 7, pbTag: "p".repeat(16), baTag: "b".repeat(16), spoofed: 0 }], dropped: 0 });
    c.collector.ingestBoundaryFrame({ type: "events", events: [{ seq: 1, t: 0, nonce: "Y".repeat(22), kind: "BOUNDARY_ADMITTED", hop: 7, pbTag: "p".repeat(16) }], dropped: 0 });
    assert.equal(c.reducer.orphanCount, 2);
    c.collector.freeze();
    const { anomalies } = c.collector.finalize();
    assert.equal(anomalies.filter((anomaly) => anomaly.code === "external_unclaimed_downstream").length, 2);
  } finally { await c.close(); }
});

test("a local, unregistered request is STILL an anomaly (uncorrelated ingress): only a remote peer enters the external lane", async () => {
  const c = await chain();
  try {
    c.setMode("local");
    assert.equal((await request(c.port, "GET", "/gizlilik")).status, 200);
    await settle(c.collector, c.reducer, 200);
    assert.ok(c.collector.anomalyTotalSoFar >= 1);
    assert.equal(c.reducer.counters().accepted, 0);
  } finally { await c.close(); }
});
