import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { ANOMALY_CODES, EGRESS_ERROR_KINDS, TERMINAL_OUTCOMES, type EventFrame, type OriginEvent, type PlaneEvent } from "../defense/core/ledger";
import { REJECT_REASONS } from "../defense/core/types";
import { assertEvidenceSafe } from "../lab/evidence/redact";
import { deriveAccounting } from "../lab/defense/accounting";
import { Collector, DEFAULT_COLLECTOR_LIMITS, type PlaneFin, type RequestMeta } from "../lab/defense/collector";
import { BA0_LOCAL_V1, ba0Fingerprint, compareLatency, decideVerdict, type VerdictInput } from "../lab/defense/thresholds";

const meta = (lane: RequestMeta["lane"], method: RequestMeta["method"] = "GET", cls: RequestMeta["cls"] = "canary"): RequestMeta => ({ lane, phase: "baseline", cls, scenario: "t", journey: 1, step: 1, method });
const N = (index: number) => `${String(index).padStart(22, "x")}`;

type Script = { frames: PlaneEvent[]; planeSeq: number };
function builder() {
  const script: Script = { frames: [], planeSeq: 0 };
  const ev = (nonce: string | null, kind: PlaneEvent["kind"], extra: Partial<PlaneEvent> = {}): PlaneEvent => {
    const event: PlaneEvent = { seq: ++script.planeSeq, nonce, kind, t: 0, ...extra };
    script.frames.push(event);
    return event;
  };
  return { script, ev };
}
const origin = (nonce: string, kind: OriginEvent["kind"], hop: number | null, extra: Partial<OriginEvent> = {}, instance: OriginEvent["instance"] = "protected"): OriginEvent => ({ instance, nonce, kind, hop, ...extra });
const frame = (events: PlaneEvent[], dropped = 0): EventFrame => ({ type: "events", events, dropped });
const fin = (emitted: number, lastSeq = emitted, dropped = 0, drained = true): PlaneFin => ({ drained, channel: { emitted, dropped, sent: emitted - dropped, received: emitted - dropped, queued: 0, unacknowledged: 0, queueHighWater: 1, lastSeq }, advisory: {} as PlaneFin["advisory"] });

/** One protected+proxied, one protected+rejected, one control, one pre-ingress request: a fully consistent run. */
function consistentRun(collector: Collector) {
  const { script, ev } = builder();
  collector.sent(N(1), meta("protected"));
  collector.sent(N(2), meta("protected", "GET", "hostile"));
  collector.sent(N(3), meta("control"));
  collector.sent(N(4), meta("pre_ingress", "OTHER", "hostile"));
  ev(N(1), "INGRESS_ACCEPTED", { stripped: 0 }); ev(N(1), "L1_ENTERED"); ev(N(1), "L1_PASSED");
  const hop = ev(N(1), "EGRESS_ATTEMPTED").seq;
  collector.ingestOrigin(origin(N(1), "ORIGIN_RECEIVED", hop, { spoofed: 0 }));
  collector.ingestOrigin(origin(N(1), "ORIGIN_COMPLETED", hop, { status: 200 }));
  ev(N(1), "EGRESS_RESPONDED", { status: 200 }); ev(N(1), "INGRESS_RESPONDED", { status: 200 });
  ev(N(2), "INGRESS_ACCEPTED", { stripped: 0 }); ev(N(2), "L1_ENTERED"); ev(N(2), "L1_REJECTED", { reason: "a7.path_not_allowed", stage: "pre_parse" }); ev(N(2), "INGRESS_RESPONDED", { status: 404 });
  collector.ingestOrigin(origin(N(3), "ORIGIN_RECEIVED", null, { spoofed: 0 }, "control"));
  collector.ingestOrigin(origin(N(3), "ORIGIN_COMPLETED", null, { status: 200 }, "control"));
  ev(null, "PARSER_REJECTED", { code: "HPE_INVALID_METHOD" });
  collector.ingestFrame(frame(script.frames));
  collector.clientCompleted(N(1), { result: "response", status: 200, outcomeHeader: "proxied", latencyMs: 1 });
  collector.clientCompleted(N(2), { result: "response", status: 404, outcomeHeader: "rejected", latencyMs: 1 });
  collector.clientCompleted(N(3), { result: "response", status: 200, latencyMs: 1 });
  collector.clientCompleted(N(4), { result: "response", status: 400, latencyMs: 1 });
  return { script, planeEvents: script.planeSeq };
}

test("a fully consistent run has no anomaly and every accounting identity holds, with counters derived from the records", () => {
  const collector = new Collector(null);
  const { planeEvents } = consistentRun(collector);
  collector.planeFinished(fin(planeEvents));
  collector.freeze();
  const { anomalies, anomalyTotal } = collector.finalize();
  assert.deepEqual(anomalies, []);
  assert.equal(anomalyTotal, 0);
  const report = deriveAccounting(collector.allRecords(), collector.parserRejectedTotal());
  assert.equal(report.identitiesOk, true, JSON.stringify(report.identities.filter((identity) => !identity.ok)));
  assert.deepEqual(report.sent, { protected: 2, control: 1, preIngress: 1, total: 4 });
  assert.equal(report.ingress.accepted, 2);
  assert.deepEqual(report.ingress.terminal, { rejected: 1, shed: 0, error: 0, proxied: 1, egress_failed: 0, client_aborted: 0 });
  assert.equal(report.l1.rejectedByReason["a7.path_not_allowed"], 1);
  assert.equal(report.parser.planeReported, 1);
  assert.equal(report.egress.attempted, report.l1.passed, "an L1 pass is reconciled against egress, and egress against origin receipts");
  assert.equal(report.origin.protectedReceived, 1);
  assert.equal(report.delivery.l1PassedNotReceivedByOrigin, 0);
});

test("the plane crashing is INVALID, and what it had already delivered survives in the ledger", () => {
  const collector = new Collector(null);
  const { ev, script } = builder();
  collector.sent(N(1), meta("protected")); collector.sent(N(2), meta("protected"));
  ev(N(1), "INGRESS_ACCEPTED"); ev(N(1), "L1_ENTERED"); ev(N(1), "L1_REJECTED", { reason: "a7.path_not_allowed" }); ev(N(1), "INGRESS_RESPONDED", { status: 404 });
  collector.ingestFrame(frame(script.frames));
  collector.clientCompleted(N(1), { result: "response", status: 404, latencyMs: 1 });
  // request 2 was in the plane when it died: no plane events ever arrive, and the client saw a reset
  collector.clientCompleted(N(2), { result: "reset", latencyMs: 1 });
  collector.planeExited("plane exited unexpectedly: code none signal SIGKILL");
  collector.freeze();
  assert.equal(collector.recordFor(N(1))?.plane.length, 4, "delivered events survived");
  const { anomalies } = collector.finalize();
  const codes = anomalies.map((anomaly) => anomaly.code);
  assert.ok(codes.includes("plane_crashed"));
  assert.ok(codes.includes("ingress_loss"), "the lost request is visible through the harness's own SENT record");
  assert.ok(!codes.includes("plane_not_finalized"));
});

test("a plane that never reports FIN is INVALID, not success", () => {
  const collector = new Collector(null);
  consistentRun(collector);
  collector.freeze();
  assert.ok(collector.finalize().anomalies.some((anomaly) => anomaly.code === "plane_not_finalized"));
});

test("lost or unacknowledged events are detected: sequence gap, duplicate sequence, reported drops, FIN mismatch, undrained queue", () => {
  const gap = new Collector(null);
  gap.sent(N(1), meta("protected"));
  gap.ingestFrame(frame([{ seq: 1, nonce: N(1), kind: "INGRESS_ACCEPTED", t: 0 }, { seq: 4, nonce: N(1), kind: "L1_ENTERED", t: 0 }]));
  assert.ok(gap.finalize().anomalies.some((anomaly) => anomaly.code === "event_channel_loss" && /gap of 2/.test(anomaly.detail)));

  const duplicate = new Collector(null);
  duplicate.sent(N(1), meta("protected"));
  duplicate.ingestFrame(frame([{ seq: 1, nonce: N(1), kind: "INGRESS_ACCEPTED", t: 0 }, { seq: 1, nonce: N(1), kind: "INGRESS_ACCEPTED", t: 0 }]));
  assert.ok(duplicate.finalize().anomalies.some((anomaly) => anomaly.code === "duplicate_sequence"));

  for (const bad of [fin(10, 10, 3), fin(10, 12), fin(10, 10, 0, false)]) {
    const collector = new Collector(null);
    const { planeEvents } = consistentRun(collector);
    void planeEvents;
    collector.planeFinished(bad);
    collector.freeze();
    assert.ok(collector.finalize().anomalies.some((anomaly) => anomaly.code === "event_channel_loss"), JSON.stringify(bad.channel));
  }
});

test("work completing after the ledger froze is detected for every source", () => {
  const collector = new Collector(null);
  const { planeEvents } = consistentRun(collector);
  collector.planeFinished(fin(planeEvents));
  collector.freeze();
  collector.ingestOrigin(origin(N(1), "ORIGIN_COMPLETED", 1, { status: 200 }));
  collector.clientCompleted(N(1), { result: "response", status: 200, latencyMs: 1 });
  collector.ingestFrame(frame([{ seq: planeEvents + 1, nonce: N(1), kind: "INGRESS_RESPONDED", t: 0, status: 200 }]));
  assert.equal(collector.sent(N(9), meta("control")), false);
  const { anomalies } = collector.finalize();
  assert.ok(anomalies.filter((anomaly) => anomaly.code === "late_event_after_finalization").length >= 4);
});

test("fault-injected lifecycles make the run INVALID through the verdict, and the secondary identities fail too", () => {
  const collector = new Collector(null);
  const { ev, script } = builder();
  collector.sent(N(1), meta("protected"));
  ev(N(1), "INGRESS_ACCEPTED"); ev(N(1), "L1_ENTERED"); ev(N(1), "L1_PASSED");
  const hop = ev(N(1), "EGRESS_ATTEMPTED").seq;
  // duplicate origin processing, origin completes but the plane never records a response, and a second terminal
  collector.ingestOrigin(origin(N(1), "ORIGIN_RECEIVED", hop, { spoofed: 0 }));
  collector.ingestOrigin(origin(N(1), "ORIGIN_RECEIVED", hop, { spoofed: 0 }));
  collector.ingestOrigin(origin(N(1), "ORIGIN_COMPLETED", hop, { status: 200 }));
  collector.ingestFrame(frame(script.frames));
  collector.clientCompleted(N(1), { result: "reset", latencyMs: 1 });
  collector.planeFinished(fin(script.planeSeq));
  collector.freeze();
  const { anomalies, anomalyTotal } = collector.finalize();
  const codes = new Set(anomalies.map((anomaly) => anomaly.code));
  assert.ok(codes.has("duplicate_origin_processing"));
  assert.ok(codes.has("disappeared_after_ingress"));
  assert.ok(codes.has("unresolved_at_finalization"));
  const report = deriveAccounting(collector.allRecords(), 0);
  assert.equal(report.identitiesOk, false);
  const input: VerdictInput = { anomalyTotal, identitiesOk: report.identitiesOk, jcr: [{ phase: "baseline", lane: "protected", rate: 1 }], latencyOk: true, parityMismatches: 0, corpusViolations: 0, corpusCount: 55, expectedCorpusCount: 55 };
  assert.equal(decideVerdict(BA0_LOCAL_V1, input).verdict, "INVALID");
});

test("an unknown nonce and an uncorrelated (minted) ingress are anomalies", () => {
  const collector = new Collector(null);
  collector.ingestFrame(frame([{ seq: 1, nonce: "ughost", kind: "INGRESS_ACCEPTED", t: 0, uncorrelated: true }, { seq: 2, nonce: "stranger", kind: "INGRESS_ACCEPTED", t: 0 }]));
  collector.ingestOrigin(origin("stranger", "ORIGIN_RECEIVED", null));
  const codes = collector.finalize().anomalies.map((anomaly) => anomaly.code);
  assert.ok(codes.includes("uncorrelated_ingress"));
  assert.ok(codes.includes("unknown_nonce"));
});

test("a reused nonce and exhausted capacity are anomalies; memory stays bounded", () => {
  const collector = new Collector(null, { ...DEFAULT_COLLECTOR_LIMITS, maxRequests: 2, maxEventsPerRecord: 3 });
  assert.equal(collector.sent(N(1), meta("control")), true);
  assert.equal(collector.sent(N(1), meta("control")), false);
  assert.equal(collector.sent(N(2), meta("control")), true);
  assert.equal(collector.sent(N(3), meta("control")), false);
  assert.equal(collector.size, 2);
  for (let index = 0; index < 20; index++) collector.ingestOrigin(origin(N(1), "ORIGIN_RECEIVED", null, {}, "control"));
  assert.ok((collector.recordFor(N(1))?.origin.length ?? 99) <= 3);
  const codes = collector.finalize().anomalies.map((anomaly) => anomaly.code);
  assert.ok(codes.includes("duplicate_nonce_sent"));
  assert.ok(codes.includes("ledger_capacity_exceeded"));
});

test("the journal is bounded, append-only, evidence-safe, never carries a nonce, and overflow is itself INVALID", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "ba0-journal-"));
  try {
    const file = path.join(directory, "journal.ndjson");
    const collector = new Collector(file);
    const { planeEvents } = consistentRun(collector);
    collector.planeFinished(fin(planeEvents));
    collector.freeze();
    assert.deepEqual(collector.finalize().anomalies, []);
    const summary = await collector.closeJournal();
    const text = readFileSync(file, "utf8");
    const lines = text.trim().split("\n");
    assert.equal(lines.length, summary?.lines);
    assert.equal(Buffer.byteLength(text), summary?.bytes);
    for (const line of lines) { const parsed = JSON.parse(line) as Record<string, unknown>; assertEvidenceSafe(parsed); }
    for (const index of [1, 2, 3, 4]) assert.ok(!text.includes(N(index)), "evidence refers to requests by sequential record id, never the nonce");
    assert.match(lines[0], /"rid":"r1"/);

    const tiny = new Collector(path.join(directory, "tiny.ndjson"), { ...DEFAULT_COLLECTOR_LIMITS, maxJournalBytes: 200 });
    consistentRun(tiny);
    tiny.freeze();
    const overflow = await tiny.closeJournal();
    assert.equal(overflow?.overflow, true);
    assert.ok((overflow?.bytes ?? 0) <= 200);
    assert.ok(tiny.finalize().anomalies.some((anomaly) => anomaly.code === "journal_overflow"));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

// ---- thresholds and verdict

test("ba0-local-v1 is named, provisional and fingerprinted; changing any value changes the fingerprint", () => {
  const base = ba0Fingerprint();
  assert.equal(base.id, "ba0-local-v1");
  assert.match(base.sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(ba0Fingerprint(), base);
  assert.equal(BA0_LOCAL_V1.calibration, "provisional-uncalibrated");
  assert.equal(BA0_LOCAL_V1.latencyEnvelope.status, "provisional");
  assert.notEqual(ba0Fingerprint({ ...BA0_LOCAL_V1, latencyEnvelope: { ...BA0_LOCAL_V1.latencyEnvelope, maxRelativeP95Factor: 1.5 } }).sha256, base.sha256);
  assert.equal(BA0_LOCAL_V1.jcr.minimum, 1, "Slice 1 requires JCR = 100%");
});

const goodVerdict = (): VerdictInput => ({
  anomalyTotal: 0, identitiesOk: true, latencyOk: true, parityMismatches: 0, corpusViolations: 0, corpusCount: 55, expectedCorpusCount: 55,
  jcr: [{ phase: "baseline", lane: "control", rate: 1 }, { phase: "baseline", lane: "protected", rate: 1 }],
});

test("Slice 1 can only conclude BASELINE-VALID or INVALID, and any single failure is INVALID with its reason", () => {
  assert.deepEqual(decideVerdict(BA0_LOCAL_V1, goodVerdict()), { verdict: "BASELINE-VALID", reasons: [] });
  const variants: [Partial<VerdictInput>, string][] = [
    [{ anomalyTotal: 1 }, "ledger_anomalies_present"], [{ identitiesOk: false }, "accounting_identity_failed"], [{ latencyOk: false }, "latency_envelope_exceeded"],
    [{ parityMismatches: 1 }, "protected_control_parity_mismatch"], [{ corpusViolations: 1 }, "corpus_expectation_violated"], [{ corpusCount: 54 }, "corpus_count_mismatch"],
    [{ jcr: [{ phase: "baseline", lane: "protected", rate: 0.95 }] }, "jcr_below_minimum:protected.baseline"], [{ jcr: [] }, "jcr_not_measured"],
  ];
  for (const [patch, reason] of variants) {
    const result = decideVerdict(BA0_LOCAL_V1, { ...goodVerdict(), ...patch });
    assert.equal(result.verdict, "INVALID", reason);
    assert.ok(result.reasons.includes(reason), `${reason} in ${result.reasons}`);
  }
  for (const result of [decideVerdict(BA0_LOCAL_V1, goodVerdict()), decideVerdict(BA0_LOCAL_V1, { ...goodVerdict(), anomalyTotal: 5 })]) assert.ok(["BASELINE-VALID", "INVALID"].includes(result.verdict));
});

test("the latency envelope is absolute plus relative with a floor, and measures protected-versus-control degradation", () => {
  const envelope = BA0_LOCAL_V1.latencyEnvelope;
  const control = Array.from({ length: 100 }, () => 1);
  assert.equal(compareLatency(envelope, control, control.map((value) => value + 5)).ok, true);
  const slowAbsolute = compareLatency(envelope, control, control.map((value) => value + 200));
  assert.equal(slowAbsolute.ok, false);
  assert.ok(slowAbsolute.reasons.includes("latency_added_p95_exceeded"));
  assert.equal(compareLatency(envelope, control, control.map((value) => value * 5)).relativeP95, null, "below the floor the ratio is not meaningful and is not applied");
  const bigControl = Array.from({ length: 100 }, () => 20);
  const relative = compareLatency({ ...envelope, maxAddedP95Ms: 10_000, maxAddedP99Ms: 10_000 }, bigControl, bigControl.map((value) => value * 9));
  assert.ok(relative.reasons.includes("latency_relative_p95_exceeded"));
  assert.ok(compareLatency(envelope, [], []).reasons.includes("latency_samples_missing"));
});

test("every closed-enum value the evidence can carry passes the evidence redactor (no token-like or key=value look-alikes)", () => {
  assertEvidenceSafe({ values: [...ANOMALY_CODES, ...REJECT_REASONS, ...EGRESS_ERROR_KINDS, ...TERMINAL_OUTCOMES] });
  const reasons = ["ledger_anomalies_present", "accounting_identity_failed", "latency_envelope_exceeded", "protected_control_parity_mismatch", "corpus_expectation_violated", "corpus_count_mismatch", "jcr_not_measured", "jcr_below_minimum:protected.post_corpus", "latency_added_p95_exceeded", "latency_relative_p95_exceeded", "latency_samples_missing"];
  assertEvidenceSafe({ resultReasons: reasons.map((reason) => `ba0.${reason}`) });
  for (const identity of deriveAccounting([], 0).identities) assertEvidenceSafe({ identity });
});
