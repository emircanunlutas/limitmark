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
import { ExternalReducer } from "../lab/defense/external-reducer";
import { HopTrustRoot } from "../lab/defense/hop-keys";
import { BA0_ORIGIN_LOCAL_V1 } from "../lab/defense/origin-thresholds";
import { BA0_FIELD_C2_SALVO_V1 } from "../lab/defense/field-thresholds";
import { n2ExerciseSpec } from "../lab/defense/n2-measurement";
import { evaluateSalvoDiagnostics } from "../lab/defense/salvo-diagnostic-check";
import { GENERATOR_PROVENANCE, SALVO_DIAGNOSTICS_SCHEMA, parseServerDiagnostics, type GeneratorSalvoDiagnostics } from "../lab/defense/salvo-diagnostics";
import { SalvoServerObserver } from "../lab/defense/salvo-measurement";
import { assertEvidenceSafe } from "../lab/evidence/redact";

/**
 * The recorder against GENUINE plane events: the real front (L1 semantic gate, L2 lanes, proof issuance), the real Origin Boundary and the real guarded
 * App on loopback, wired into the real collector exactly as the field run wires its observer (`collector.observePlaneEvents`). A remote peer is
 * simulated with the front's test seam. The independent ground truth is the HTTP client: what it dispatched in which slot and the status it received.
 */
const L2: L2Params = {
  filterBits: 2 ** 13, filterHashes: 7, epochMs: 60_000, credited: { capacity: 10, refillPerSecond: 2 }, unverified: { capacity: 3, refillPerSecond: 1 },
  maxUses: 3, ledgerCapacity: 512, stage: { timeoutMs: 50, maxConcurrent: 64 },
};
const HOP = BA0_ORIGIN_LOCAL_V1.hop;
const FORM = "application/x-www-form-urlencoded";

async function chain() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ba0-salvo-diag-"));
  const collector = new Collector(path.join(dir, "journal.ndjson"), { maxRequests: 4_000, maxEventsPerRecord: 32, maxJournalBytes: 8 * 1_048_576, maxAnomalies: 200 });
  collector.enableOriginStreams(); collector.enableLaneStreams();
  const reducer = new ExternalReducer({ allowedShed: [{ class: "mutation", lane: "unverified", reason: "lane_budget" }], report: (code, rid, detail) => collector.externalAnomaly(code, rid, detail) });
  collector.enableExternalLane(reducer);
  const root = new HopTrustRoot(); const seqs = { plane: 0, boundary: 0, app: 0 };
  const planeEvents: PlaneEvent[] = [];
  const planeEmit = (event: Omit<PlaneEvent, "seq" | "t">): number => {
    const seq = ++seqs.plane; const full = { ...event, seq, t: performance.now() } as PlaneEvent; planeEvents.push(full);
    collector.ingestFrame({ type: "events", events: [full], dropped: 0 }); return seq;
  };
  const boundaryEmit = (event: Omit<BoundaryEvent, "seq" | "t">): number => { const seq = ++seqs.boundary; collector.ingestBoundaryFrame({ type: "events", events: [{ ...event, seq, t: performance.now() }], dropped: 0 }); return seq; };
  const appEmit = (event: Omit<AppEvent, "seq" | "t">): void => { const seq = ++seqs.app; collector.ingestAppFrame({ type: "events", events: [{ ...event, seq, t: performance.now() }], dropped: 0 }); };
  const appInit = root.appInit({ replayCapacity: HOP.replayCapacity, bodyDeadlineMs: HOP.bodyDeadlineMs });
  const built = createAppGuard({ keyB: importPublicKey(appInit.publicKeyB), kidB: appInit.kidB, keyP: importPublicKey(appInit.publicKeyP), kidP: appInit.kidP, appId: appInit.appId, boundaryId: appInit.boundaryId,
    replayCapacity: HOP.replayCapacity, bodyDeadlineMs: HOP.bodyDeadlineMs });
  const app = createSyntheticOrigin({ instance: "protected", onObservation: () => undefined, guard: built.guard, onApp: appEmit });
  const appPort = await app.listen();
  const boundaryInit = root.boundaryInit(appPort, { replayCapacity: HOP.replayCapacity, bodyDeadlineMs: HOP.bodyDeadlineMs, forwardTimeoutMs: HOP.forwardTimeoutMs, baLifetimeMs: HOP.baLifetimeMs });
  const boundary = createBoundary({ appPort, keyP: importPublicKey(boundaryInit.publicKeyP), kidP: boundaryInit.kidP, boundaryId: boundaryInit.boundaryId, keyB: importPrivateKey(boundaryInit.privateKeyB),
    kidB: boundaryInit.kidB, appId: boundaryInit.appId, limits: boundaryInit.limits, emit: boundaryEmit });
  const boundaryPort = await boundary.listen();
  const planeHop = root.planeInit(HOP.pbLifetimeMs);
  const config = { kid: planeHop.kid, privateKey: importPrivateKey(planeHop.privateKey), boundaryId: planeHop.boundaryId, lifetimeMs: Math.min(planeHop.lifetimeMs, PB_MAX_LIFETIME_MS), now: () => Date.now() };
  const lanes = new JourneyLanes({ ...L2, mono: () => performance.now(), key: randomBytes(32) });
  const stage = new L2Stage(lanes, { composer: L2.stage, maxResponseBytes: 1_048_576 });
  const mode: PeerClass = "remote";
  const front = createFront({ upstream: { host: "127.0.0.1", port: boundaryPort }, emit: planeEmit, layer: new SemanticGate(new ShapeGate()),
    hop: { issue: (approved, context) => issuePb(config, approved, context) }, l2: stage, composer: { timeoutMs: 250, maxConcurrent: 64, failurePolicy: "fail_closed" }, peerClass: () => mode });
  const port = await front.listen();
  const finish = (): void => {
    // The three processes' final state, as their FIN messages would report it (same as the external e2e suite).
    const channel = (n: number) => ({ emitted: n, dropped: 0, sent: n, received: n, queued: 0, unacknowledged: 0, queueHighWater: 0, lastSeq: n });
    collector.planeFinished({ drained: true, channel: channel(seqs.plane), advisory: { l2: stage.stats() } as never });
    collector.boundaryFinished({ drained: true, channel: channel(seqs.boundary), stats: boundary.stats() });
    collector.appFinished({ drained: true, channel: channel(seqs.app), stats: { counters: app.appStats(), served: app.stats(), guard: built.stats() } });
  };
  return { collector, port, planeEvents, finish, close: async () => { await front.close(300); await boundary.close(); await app.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}

function request(port: number, method: string, target: string, body?: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { host: `127.0.0.1:${port}` };
    if (body !== undefined) { headers["content-type"] = FORM; headers.origin = `http://127.0.0.1:${port}`; headers["content-length"] = String(Buffer.byteLength(body)); }
    const req = http.request({ host: "127.0.0.1", port, method, path: target, headers, agent: false }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
    req.on("error", reject); req.end(body);
  });
}
const inquiry = (): string => new URLSearchParams({ name: "Lab Synthetic", email: "lab@example.test", company: "Synthetic Co", service: "web", system: "synthetic lab system", objective: "synthetic lab objective",
  environment: "staging", authority: "authorized", protection: "unknown", provider: "", notes: "", submissionToken: randomBytes(32).toString("base64url") }).toString();

test("recorder on genuine plane events: classes, lanes, fast sheds, statuses and sequences match what the client dispatched and received", async () => {
  const PAIRS = 24; const c = await chain();
  const recorderObserver = new SalvoServerObserver(n2ExerciseSpec(BA0_FIELD_C2_SALVO_V1));
  c.collector.observePlaneEvents((event) => recorderObserver.observe(event));      // the field run's wiring
  const truth: { pair: number; slot: 0 | 1; method: string; status: number; dispatchedAt: number; settledAt: number }[] = [];
  try {
    for (let pair = 0; pair < PAIRS; pair++) {
      const odd = pair % 2 === 1;
      const send = async (slot: 0 | 1, method: string, target: string, body?: string) => {
        const dispatchedAt = performance.now(); const status = await request(c.port, method, target, body);
        truth.push({ pair, slot, method, status, dispatchedAt, settledAt: performance.now() });
      };
      // Both sends begin before either response is awaited, as the salvo scheduler does; the next pair starts only after both settled.
      await Promise.all([send(0, "GET", "/"), odd ? send(1, "POST", "/api/public-inquiries", inquiry()) : send(1, "GET", "/test-talep-et")]);
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
    const diag = recorderObserver.snapshotDiagnostics();
    c.finish(); c.collector.freeze(); const { anomalies } = c.collector.finalize();
    assert.deepEqual(anomalies, [], "the extra observer disturbed nothing in the real collector");

    // ---- completeness and structure on real events
    assert.equal(parseServerDiagnostics(JSON.parse(JSON.stringify(diag))).ok, true);
    assert.equal(diag.requests.length, PAIRS * 2); assert.deepEqual({ ...diag.counters, unattributedEvents: 0 }, { observed: 48, recorded: 48, overflow: 0, duplicateIds: 0, duplicateEvents: 0, orderViolations: 0,
      ambiguousEvents: 0, unattributedEvents: 0, simulatedDecisions: 0, faults: 0 });
    assert.ok(diag.requests.every((r) => r.fin === "responded" && r.flags.length === 0 && r.l1 === "passed"));
    for (let i = 1; i < diag.requests.length; i++) { assert.ok(diag.requests[i].inSeq > diag.requests[i - 1].inSeq); assert.ok(diag.requests[i].inMs >= diag.requests[i - 1].inMs); }
    assert.ok(diag.requests.every((r) => r.outSeq! > r.inSeq && r.outMs! >= r.inMs));
    // The recorder's times are bit-identical to the existing pair records built from the same genuine events.
    const pairs = recorderObserver.snapshotSalvo().pairs;
    for (const r of diag.requests) { assert.equal(pairs[r.pair].startsMs[r.slot], r.inMs); assert.equal(pairs[r.pair].settledMs[r.slot], r.outMs); }

    // ---- the real decisions
    const posts = diag.requests.filter((r) => r.cls === "mutation"); const reads = diag.requests.filter((r) => r.cls === "open");
    assert.equal(posts.length, PAIRS / 2); assert.equal(reads.length, PAIRS * 2 - PAIRS / 2);
    const shed = posts.filter((r) => r.l2 === "shed"); const admitted = posts.filter((r) => r.l2 === "admitted");
    assert.ok(shed.length >= 1 && admitted.length >= 1 && shed.length + admitted.length === posts.length, `${admitted.length} admitted, ${shed.length} shed`);
    for (const r of shed) { assert.deepEqual([r.lane, r.shed, r.egress, r.status], ["unverified", "lane_budget", false, 503]); }   // a genuine fast shed: decided with no downstream I/O
    for (const r of [...admitted, ...reads]) { assert.deepEqual([r.egress, r.status, r.shed], [true, 200, "none"]); assert.equal(r.l2, "admitted"); }
    for (const r of reads) assert.equal(r.lane, "open");

    // ---- identity: server-observed classes, then the independent client ground truth joined by class (the real arrival order may be reversed)
    const generator: GeneratorSalvoDiagnostics = { schema: SALVO_DIAGNOSTICS_SCHEMA, side: "generator", provenance: GENERATOR_PROVENANCE, capacity: { maxRequests: 1500 },
      requests: truth.map((t) => ({ pair: t.pair, slot: t.slot, startMs: t.dispatchedAt, handoffMs: null, settledMs: t.settledAt, status: t.status })).sort((a, b) => a.pair - b.pair || a.slot - b.slot) };
    const check = evaluateSalvoDiagnostics({ server: diag, generator });
    assert.deepEqual(check.pairs.total, { consistent: 750 - 750 + PAIRS, inconsistent: 0, unknown: 750 - PAIRS });   // the 726 never-sent pairs are unknown, not consistent
    assert.equal(check.pairs.inconsistentIndices.length, 0);
    assert.equal(check.signature.compared, PAIRS); assert.equal(check.signature.incompatible, 0); assert.equal(check.signature.compatible, PAIRS);
    assert.equal(check.binding.pairs.verified, 0); assert.equal(check.binding.pairs.inferred, PAIRS); assert.equal(check.binding.status, "unverified", "only 24 of 750 pairs exist");
    assert.equal(check.signature.informative, shed.length, "exactly the pairs whose mutation was shed carry two different statuses");
    assert.equal(check.status.other, 0); assert.equal(check.status.fastShed503, shed.length); assert.equal(check.status.unexpected, 0);
    assert.equal(check.integrity, "unknown", "a 24-pair run is not a complete campaign, and is never reported consistent");
    // Zero-overlap explanations, when real timing produced any, are always attributable to the first-arrived request.
    for (const d of check.zeroOverlap.detail) assert.ok(d.cause !== "undetermined", JSON.stringify(d));

    // ---- no correlation key or request material reaches the evidence
    const text = JSON.stringify(diag); assert.doesNotThrow(() => assertEvidenceSafe(diag));
    for (const e of c.planeEvents) if (e.nonce) assert.ok(!text.includes(e.nonce), "a plane-minted correlation key leaked");
    assert.ok(!/Lab Synthetic|submissionToken|lab@example/.test(text));
  } finally { await c.close(); }
});
