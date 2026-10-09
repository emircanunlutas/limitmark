import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import ts from "typescript";
import { requiredLedgerCapacity, LANES, L2_OUTCOMES, OPERATION_CLASSES, SHED_REASONS } from "../defense/core/lanes";
import { LagMonitor } from "../defense/core/telemetry";
import type { PlaneEvent } from "../defense/core/ledger";
import { reconcileLevel } from "../lab/defense/ba0-field-reconcile";
import { BA0_FIELD_C2_SALVO_V1, BA0_FIELD_C2_V1, BA0_FIELD_V1, evaluateBudgetGates, failedGates, ba0FieldFingerprint } from "../lab/defense/field-thresholds";
import { writeFieldEvidence } from "../lab/defense/field-evidence";
import { buildSelftestBundle } from "../lab/defense/field-selftest";
import { buildGeneratorReport, parseGeneratorReport, workloadFingerprint } from "../lab/defense/generator-report";
import { n2ExerciseSpec } from "../lab/defense/n2-measurement";
import { finalFrom } from "../lab/defense/reconcile";
import { evaluateSalvoDiagnostics } from "../lab/defense/salvo-diagnostic-check";
import {
  DIAG_CLASSES, DIAG_FLAGS, DIAG_L2, DIAG_LANES, DIAG_SHED, SALVO_DIAGNOSTIC_LIMITS,
  parseGeneratorDiagnostics, parseServerDiagnostics, type ServerSalvoDiagnostics,
} from "../lab/defense/salvo-diagnostics";
import { SalvoServerObserver } from "../lab/defense/salvo-measurement";
import { SALVO_SPEC, derivePairs } from "../lab/defense/salvo-spec";
import { EvidenceRun, collectEnvironment } from "../lab/evidence/manifest";
import { assertEvidenceSafe } from "../lab/evidence/redact";
import { executeClosedLoop, sendClosedLoop, TRANSPORT_FAILURES, type ClosedLoopOptions, type ClosedLoopSend } from "../lab/load/closed-loop";
import { syntheticSubmissionBody } from "../lab/load/engine";
import type { SalvoClock } from "../lab/load/salvo";
import { authorizeRun, buildRegistry, type AuthorizedRun } from "../lab/policy/target-policy";
import * as policyThresholds from "../lab/policy/thresholds";
import { WORKLOADS } from "../lab/policy/workloads";
import { BA0_ORIGIN_LOCAL_V1 } from "../lab/defense/origin-thresholds";
import { DEFAULT_EXTERNAL_LIMITS } from "../lab/defense/external-reducer";
import * as salvoSpecModule from "../lab/defense/salvo-spec";
import { N2ServerObserver } from "../lab/defense/n2-measurement";
import { refreshFixture, salvoFixture } from "./support/salvo-fixture";

const root = path.join(__dirname, "..");
const BASELINE = "dcf10af8229a5738b1852721fe12de86a488d07d";

import { campaign, generatorDiagnostics, observe, record, stream } from "./support/salvo-diagnostic-fixtures";

const clone = <T>(value: T): T => structuredClone(value);
const FORBIDDEN_FIELDS = ["body", "headers", "cookie", "authorization", "token", "url", "ip", "host", "origin", "secret", "nonce"];

// ------------------------------------------------------------------------------------------------------------------ 1, 13, 14: capacity
test("all 1,500 observations are recorded within the reviewed per-record and total evidence budgets", () => {
  const events = stream(campaign({ shedOdd: true }));
  const diag = record(events);
  assert.equal(diag.requests.length, 1500); assert.deepEqual(diag.counters, { observed: 1500, recorded: 1500, overflow: 0, duplicateIds: 0, duplicateEvents: 0,
    orderViolations: 0, ambiguousEvents: 0, unattributedEvents: 0, simulatedDecisions: 0, faults: 0 });
  const text = `${JSON.stringify(diag, null, 2)}\n`; const generatorText = `${JSON.stringify(generatorDiagnostics(), null, 2)}\n`;
  assert.ok(Buffer.byteLength(text) <= 1500 * SALVO_DIAGNOSTIC_LIMITS.serverRecordJsonBytes, `server artifact ${Buffer.byteLength(text)} bytes`);
  assert.ok(Buffer.byteLength(generatorText) <= 1500 * SALVO_DIAGNOSTIC_LIMITS.generatorRecordJsonBytes, `generator artifact ${Buffer.byteLength(generatorText)} bytes`);
  const gates = evaluateBudgetGates(BA0_FIELD_C2_SALVO_V1, 3_600_000);
  assert.deepEqual(failedGates(gates), []); assert.equal(gates.length, 37);
  for (const id of ["salvo.diagnostic_cap_covers_level", "salvo.diagnostic_memory", "salvo.evidence_with_diagnostics"]) assert.ok(gates.find((g) => g.id === id)?.ok, id);
});

test("maximum evidence: every field at its widest value stays within the per-record bound and the scanner accepts every name and value", () => {
  const worst = record(stream(campaign({ shedOdd: true })));
  for (const r of worst.requests) {
    r.cls = "mutation"; r.l1 = "rejected"; r.l2 = "degraded"; r.lane = "unverified"; r.shed = "evaluator_saturation"; r.egress = true; r.status = 599;
    r.inSeq = Number.MAX_SAFE_INTEGER; r.outSeq = Number.MAX_SAFE_INTEGER - 1; r.inMs = 64000.123456789123; r.outMs = 64000.987654321987; r.flags = [...DIAG_FLAGS];
  }
  const text = `${JSON.stringify(worst, null, 2)}\n`;
  assert.ok(Buffer.byteLength(text) <= 1500 * SALVO_DIAGNOSTIC_LIMITS.serverRecordJsonBytes, `${Buffer.byteLength(text) / 1500} bytes per record`);
  assert.doesNotThrow(() => assertEvidenceSafe(worst));
  const wide = generatorDiagnostics(); for (const r of wide.requests) { r.startMs = 59920.123456789123; r.handoffMs = 59920.987654321987; r.settledMs = 63999.123456789123; r.status = 599; }
  assert.ok(Buffer.byteLength(`${JSON.stringify(wide, null, 2)}\n`) <= 1500 * SALVO_DIAGNOSTIC_LIMITS.generatorRecordJsonBytes);
  assert.doesNotThrow(() => assertEvidenceSafe(wide));
  assert.equal(parseServerDiagnostics(worst).ok, true);
});

test("diagnostic overflow: the 1,501st external request is counted, never stored, and the evidence says the record set is incomplete", () => {
  const specs = campaign(); specs.push({ nonce: "overflow-a", cls: "open", at: 60000, end: 60006 }, { nonce: "overflow-b", cls: "open", at: 60001, end: 60007 });
  const diag = record(stream(specs));
  assert.equal(diag.requests.length, 1500); assert.equal(diag.counters.observed, 1502); assert.equal(diag.counters.overflow, 2);
  assert.equal(diag.counters.unattributedEvents, 2 * 7); // each overflow request's seven post-ingress lifecycle events are unattributed, not attached to anything
  assert.ok(diag.requests.every((r) => r.rid === `x${r.ord + 1}`));
  const check = evaluateSalvoDiagnostics({ server: diag });
  assert.equal(check.completeness.complete, false); assert.equal(check.completeness.overflow, 2); assert.equal(check.integrity, "unknown");
  assert.equal(parseServerDiagnostics({ ...diag, requests: [...diag.requests, diag.requests[0]] }).ok, false);
});

// ------------------------------------------------------------------------------------------------------------------ 2: reconstruction
test("pair index, arrival slot, ordinal and rid are reconstructed exactly and match the existing pair records bit for bit", () => {
  const events = stream(campaign({ shedOdd: true, reversed: (p) => p % 7 === 3 }));
  const diag = record(events); const observer = observe(events); const pairs = observer.snapshotSalvo().pairs;
  assert.equal(pairs.length, 750);
  for (const r of diag.requests) {
    assert.equal(r.pair, Math.floor(r.ord / 2)); assert.equal(r.slot, r.ord % 2); assert.equal(r.rid, `x${r.ord + 1}`);
    assert.equal(pairs[r.pair].startsMs[r.slot], r.inMs, `start ${r.rid}`); assert.equal(pairs[r.pair].settledMs[r.slot], r.outMs, `settle ${r.rid}`);
  }
  // Event sequences are the plane's own, strictly increasing between ingress and response.
  assert.ok(diag.requests.every((r) => r.outSeq! > r.inSeq && r.outMs! >= r.inMs));
  assert.equal(new Set(diag.requests.map((r) => r.inSeq)).size, 1500);
  const check = evaluateSalvoDiagnostics({ server: diag, serverPairs: pairs });
  assert.deepEqual(check.pairRecordAgreement.server, { compared: 1500, mismatched: 0 });
  // Tampering with one pair record is reported as a disagreement (never silently accepted).
  const tampered = clone(pairs); tampered[10].settledMs[1] = tampered[10].settledMs[1]! + 0.001;
  assert.equal(evaluateSalvoDiagnostics({ server: diag, serverPairs: tampered }).pairRecordAgreement.server !== "not_supplied" && (evaluateSalvoDiagnostics({ server: diag, serverPairs: tampered }).pairRecordAgreement.server as { mismatched: number }).mismatched, 1);
});

// ------------------------------------------------------------------------------------------------------------------ 3, 4, 5: composition
test("even pairs hold two open requests and odd pairs one open and one mutation, from server-observed classes", () => {
  const diag = record(stream(campaign({ shedOdd: true })));
  for (const r of diag.requests) assert.equal(r.cls, r.pair % 2 === 0 || r.slot === 0 ? "open" : "mutation", r.rid);
  const check = evaluateSalvoDiagnostics({ server: diag });
  assert.deepEqual(check.pairs.total, { consistent: 750, inconsistent: 0, unknown: 0 });
  assert.deepEqual(check.pairs.even, { consistent: 375, inconsistent: 0, unknown: 0 }); assert.deepEqual(check.pairs.odd, { consistent: 375, inconsistent: 0, unknown: 0 });
  assert.deepEqual(check.classTotals, { open: 1125, mutation: 375, unknown: 0 }); assert.equal(check.integrity, "consistent"); assert.equal(check.composition, "consistent"); assert.equal(check.influencesVerdict, false);
});

test("a wrong composition is reported inconsistent even when the arrival ordinal parity looks right", () => {
  const specs = campaign({ shedOdd: true });
  specs[2 * 10].cls = "mutation";           // even pair 10 gains a mutation (a request from the wrong pair arrived)
  specs[2 * 11 + 1].cls = "open";           // odd pair 11 loses its mutation
  specs[2 * 13].cls = "mutation";           // odd pair 13 has two mutations
  specs[2 * 14 + 1].cls = "mutation";       // even pair 14: open + mutation
  const check = evaluateSalvoDiagnostics({ server: record(stream(specs)) });
  assert.deepEqual(check.pairs.inconsistentIndices, [10, 11, 13, 14]); assert.equal(check.pairs.total.inconsistent, 4);
  assert.equal(check.pairs.even.inconsistent, 2); assert.equal(check.pairs.odd.inconsistent, 2); assert.equal(check.composition, "inconsistent");
  assert.equal(check.integrity, "consistent", "a workload-composition contradiction is not an integrity failure of the records themselves");
  assert.equal(check.binding.status, "contradicted"); assert.deepEqual(check.binding.contradictedIndices, [10, 11, 13, 14]);
});

test("reversed server arrival order keeps the pair identity; the arrival slot and the dispatch slot are different things", () => {
  const events = stream(campaign({ shedOdd: true, reversed: (p) => p % 2 === 1 }));
  const diag = record(events);
  for (const p of [1, 3, 749]) { assert.equal(diag.requests[2 * p].cls, "mutation"); assert.equal(diag.requests[2 * p + 1].cls, "open"); }
  const check = evaluateSalvoDiagnostics({ server: diag, generator: generatorDiagnostics() });
  assert.deepEqual(check.pairs.total, { consistent: 750, inconsistent: 0, unknown: 0 });
  // The generator's slot 1 (the mutation) is joined to the server's mutation record by class, not by arrival position.
  assert.equal(check.signature.status, "compatible"); assert.equal(check.signature.compared, 750); assert.equal(check.signature.informative, 375); assert.equal(check.signature.incompatible, 0);
  assert.equal(check.binding.status, "inferred"); assert.equal(check.binding.pairs.verified, 0);
  // A 503 attributed to the wrong request class is detected: swap the generator's statuses on one odd pair.
  const swapped = generatorDiagnostics((p, s) => (p === 5 ? (s === 0 ? 503 : 200) : p % 2 === 1 && s === 1 ? 503 : 200));
  const bad = evaluateSalvoDiagnostics({ server: diag, generator: swapped });
  assert.equal(bad.signature.status, "incompatible"); assert.deepEqual(bad.signature.incompatibleIndices, [5]); assert.equal(bad.integrity, "inconsistent"); assert.equal(bad.binding.status, "contradicted");
});

// ------------------------------------------------------------------------------------------------------------------ 6: fast shed
test("a fast shed that settles before the slower admitted request is stamped explains the zero-overlap pair and is identified as such", () => {
  const specs = campaign({ shedOdd: true, zeroOverlap: (p) => p === 63 });
  const events = stream(specs); const diag = record(events); const pairs = observe(events).snapshotSalvo().pairs;
  const [first, second] = [diag.requests[126], diag.requests[127]];
  assert.equal(first.cls, "mutation"); assert.equal(first.l2, "shed"); assert.equal(first.shed, "lane_budget"); assert.equal(first.egress, false); assert.equal(first.status, 503);
  assert.equal(second.cls, "open"); assert.equal(second.l2, "admitted"); assert.equal(second.egress, true); assert.equal(second.status, 200);
  assert.ok(first.outMs! < second.inMs, "the shed response precedes the second ingress");
  assert.equal(first.outSeq! < second.inSeq, true);
  // The existing qualification record agrees: overlap is zero for the pair, so it is NOT material on the server (the verdict machinery is untouched).
  const filled = pairs.map((p, i) => (i === 63 ? p : { ...p })); void filled;
  const check = evaluateSalvoDiagnostics({ server: diag, serverPairs: pairs });
  assert.equal(check.zeroOverlap.pairs, 1); assert.equal(check.zeroOverlap.fastShedFirst, 1);
  assert.deepEqual(check.zeroOverlap.detail, [{ pair: 63, cause: "fast_shed_first_arrival", firstMs: 0.7, separationMs: 0.9 }]);
  assert.equal(check.pairs.total.consistent, 750); assert.equal(check.integrity, "consistent");
});

test("a short first-arrived request that was NOT shed is classified separately; overlap below 75 percent is listed apart from zero overlap", () => {
  const specs = campaign({ shedOdd: false }); const fastRead = specs[2 * 40];
  fastRead.end = fastRead.at + 0.6; specs[2 * 40 + 1].at = fastRead.at + 1; specs[2 * 40 + 1].end = specs[2 * 40 + 1].at + 6;     // even pair 40: fast 200 then a later read
  specs[2 * 164].end = specs[2 * 164].at + 4.5; specs[2 * 164 + 1].at = specs[2 * 164].at + 1.2; specs[2 * 164 + 1].end = specs[2 * 164 + 1].at + 4.5;  // pair 164: ratio 0.733
  const check = evaluateSalvoDiagnostics({ server: record(stream(specs)) });
  assert.equal(check.zeroOverlap.pairs, 1); assert.equal(check.zeroOverlap.shortFirstNotShed, 1); assert.equal(check.zeroOverlap.fastShedFirst, 0);
  assert.equal(check.zeroOverlap.detail[0].cause, "short_first_arrival_not_shed");
  assert.deepEqual(check.partialOverlap, { belowRatio: 1, indices: [164] });
});

// ------------------------------------------------------------------------------------------------------------------ 7, 12: missing responses, partial
test("missing response events leave the request pending with null response fields; completeness and the overall status say so", () => {
  const specs = campaign({ shedOdd: true }); specs[2 * 100 + 1].fin = "pending"; specs[2 * 200].fin = "pending";
  const diag = record(stream(specs)); const p = diag.requests[2 * 100 + 1];
  assert.deepEqual([p.fin, p.status, p.outSeq, p.outMs], ["pending", null, null, null]);
  const check = evaluateSalvoDiagnostics({ server: diag });
  assert.equal(check.completeness.pending, 2); assert.equal(check.completeness.complete, false); assert.equal(check.integrity, "unknown"); assert.equal(check.composition, "consistent");
  assert.equal(check.pairs.total.consistent, 750); // the class was observed, so identity is established even though the response never was
  assert.equal(parseServerDiagnostics(diag).ok, true);
});

test("partial and aborted campaigns: an abort mid-campaign, an empty run and an aborted request never throw and never read as consistent", () => {
  const partial = campaign({ shedOdd: true }).slice(0, 41); partial[40].fin = "aborted";
  const diag = record(stream(partial));
  assert.equal(diag.requests.length, 41); assert.deepEqual([diag.requests[40].fin, diag.requests[40].status, diag.requests[40].outSeq === null], ["aborted", null, false]);
  const check = evaluateSalvoDiagnostics({ server: diag });
  assert.equal(check.completeness.aborted, 1); assert.equal(check.completeness.complete, false); assert.equal(check.integrity, "unknown");
  assert.ok(check.pairs.total.unknown >= 729);
  const empty = evaluateSalvoDiagnostics({ server: record([]) });
  assert.equal(empty.integrity, "unknown"); assert.equal(empty.composition, "unknown"); assert.equal(empty.pairs.total.consistent, 0);
  assert.equal(evaluateSalvoDiagnostics({}).integrity, "absent"); assert.equal(evaluateSalvoDiagnostics({}).binding.status, "unverified");
});

// ------------------------------------------------------------------------------------------------------------------ 8, 9, 10: adversarial streams
test("duplicate request identifiers: both requests are flagged, nothing is attached to either, the pair is unknown and the key is never recorded", () => {
  const specs = campaign({ shedOdd: true }); specs[2 * 20 + 1].nonce = specs[2 * 20].nonce;
  const diag = record(stream(specs));
  assert.equal(diag.counters.duplicateIds, 1); assert.ok(diag.counters.ambiguousEvents > 0);
  for (const r of diag.requests.slice(40, 42)) { assert.deepEqual(r.flags, ["dup_id"]); assert.equal(r.fin, "pending"); assert.equal(r.l2, "none"); assert.equal(r.status, null); }
  const check = evaluateSalvoDiagnostics({ server: diag });
  assert.deepEqual(check.pairs.unknownIndices, [20]); assert.equal(check.integrity, "unknown"); assert.equal(check.recorder.duplicateIds, 1); assert.deepEqual(check.findings.map((f) => f.code), ["incomplete_records", "reused_key"]);
  assert.ok(!JSON.stringify(diag).includes("nonce-secret"));
  // The existing observer treats the same stream as a fault; the diagnostics did not change that.
  assert.ok(observe(stream(specs)).snapshotSalvo().phase.faults > 0);
});

test("out-of-order sequences and times, repeated one-per-request events and events after the terminal are flagged and make the pair unknown", () => {
  const events = stream(campaign({ shedOdd: true }));
  const idx = (n: string, kind: string) => events.findIndex((e) => e.nonce === n && e.kind === kind);
  const nonce = (p: number, s: number) => `nonce-secret-token-${p}-${s}-aaaaaaaaaaaaaaaaaaaa`;
  events[idx(nonce(30, 0), "L1_PASSED")] = { ...events[idx(nonce(30, 0), "L1_PASSED")], seq: 0 };                       // sequence regression
  events[idx(nonce(31, 0), "L1_PASSED")] = { ...events[idx(nonce(31, 0), "L1_PASSED")], t: -5 };                          // time regression
  events.splice(idx(nonce(32, 0), "L2_DECIDED") + 1, 0, { ...events[idx(nonce(32, 0), "L2_DECIDED")], seq: 10_000_000, t: events[idx(nonce(32, 0), "L2_DECIDED")].t + 0.001 }); // repeated decision
  events.push({ ...events[idx(nonce(33, 0), "L1_PASSED")], seq: 10_000_001, t: 99_999 });                                  // recorded kind after the terminal
  const diag = record(events); const flags = (p: number, s: number) => diag.requests[2 * p + s].flags;
  assert.ok(flags(30, 0).includes("seq_order")); assert.ok(flags(31, 0).includes("time_order")); assert.ok(flags(32, 0).includes("dup_event")); assert.ok(flags(33, 0).includes("late_event"));
  assert.equal(diag.counters.duplicateEvents, 1); assert.ok(diag.counters.orderViolations >= 3);
  const check = evaluateSalvoDiagnostics({ server: diag });
  assert.deepEqual(check.pairs.unknownIndices, [30, 31, 32, 33]); assert.equal(check.composition, "unknown");
  // Sequence/time regressions are proven causality violations (inconsistent); repeats and late events cannot be attributed (unknown). The worst wins.
  assert.equal(check.integrity, "inconsistent"); assert.deepEqual(check.findings.map((f) => [f.code, f.severity]), [["event_order", "inconsistent"], ["repeated_event", "unknown"]]);
  assert.equal(check.recorder.flaggedRecords, 4);
});

test("missing or inconsistent correlation is reported unknown or inconsistent, never matched: unclassified requests, canary traffic, orphan events and parser events", () => {
  const specs = campaign({ shedOdd: true }); specs[2 * 50 + 1].l1 = "rejected"; specs[2 * 51].noL2 = true;
  const events = stream(specs);
  const extra: PlaneEvent[] = [
    { seq: 9_000_001, nonce: "canary-1", kind: "INGRESS_ACCEPTED", t: 1 }, { seq: 9_000_002, nonce: "canary-1", kind: "INGRESS_RESPONDED", t: 2, status: 200 },
    { seq: 9_000_003, nonce: "never-ingressed", kind: "INGRESS_RESPONDED", t: 3, status: 200 }, { seq: 9_000_004, nonce: null, kind: "PARSER_REJECTED", t: 4, code: "HPE_X" },
  ];
  const diag = record([...events, ...extra]);
  assert.equal(diag.requests.length, 1500); assert.equal(diag.counters.observed, 1500); assert.equal(diag.counters.unattributedEvents, 2);
  assert.equal(diag.requests[2 * 50 + 1].cls, "unknown"); assert.equal(diag.requests[2 * 50 + 1].l1, "rejected"); assert.equal(diag.requests[2 * 51].l2, "none");
  const check = evaluateSalvoDiagnostics({ server: diag });
  assert.deepEqual(check.pairs.unknownIndices, [50, 51]); assert.equal(check.pairs.total.consistent, 748); assert.equal(check.composition, "unknown");
  assert.equal(check.integrity, "consistent", "an unclassified request is unknown composition, not an integrity failure");
  // A generator row without a server counterpart, and statuses that cannot be compared, are left uncompared instead of agreed.
  const generator = generatorDiagnostics((p, s) => (p === 7 ? null : p % 2 === 1 && s === 1 ? 503 : 200));
  const crossed = evaluateSalvoDiagnostics({ server: diag, generator });
  assert.equal(crossed.signature.compared, 750 - 2 - 1); assert.equal(crossed.signature.status, "unknown"); assert.equal(crossed.binding.status, "unverified");
});

// ------------------------------------------------------------------------------------------------------------------ 11: statuses
test("unexpected HTTP statuses and decision/status incoherence are reported with bounded indices and change no verdict", () => {
  const specs = campaign({ shedOdd: true }); specs[2 * 3].status = 429; specs[2 * 8 + 1].status = 500; specs[2 * 9].status = 302;
  const check = evaluateSalvoDiagnostics({ server: record(stream(specs)) });
  assert.equal(check.status.unexpected, 3); assert.deepEqual(check.status.unexpectedIndices, [3, 8, 9]);
  assert.equal(check.status.other, 3); assert.equal(check.status.fastShed503 + check.status.admitted200 + check.status.other, 1500);
  const flood = campaign({ shedOdd: true }); for (const s of flood) s.status = 418;
  assert.equal(evaluateSalvoDiagnostics({ server: record(stream(flood)) }).status.unexpectedIndices.length, 32);  // bounded list
});

// ------------------------------------------------------------------------------------------------------------------ 15, 16: leakage, schema
test("no request body, header, cookie, token, address, URL or nonce can reach the evidence, even when the events carry them", () => {
  const hostile = stream(campaign({ shedOdd: true })).map((e) => ({ ...e, body: "SECRET-BODY", headers: { cookie: "sid=abc" }, authorization: "Bearer abc", url: "https://x.example/?token=abc", ip: "203.0.113.9", host: "h", origin: "o" }) as PlaneEvent);
  const diag = record(hostile); const text = JSON.stringify(diag);
  for (const needle of ["SECRET-BODY", "sid=abc", "Bearer", "x.example", "203.0.113.9", "nonce-secret"]) assert.ok(!text.includes(needle), needle);
  const keys = new Set<string>(); const walk = (v: unknown) => { if (v && typeof v === "object") for (const [k, c] of Object.entries(v)) { keys.add(k); walk(c); } }; walk(diag);
  for (const key of keys) for (const f of FORBIDDEN_FIELDS) assert.ok(!key.toLowerCase().includes(f), `${key} contains ${f}`);
  assert.doesNotThrow(() => assertEvidenceSafe(diag));
  assert.deepEqual(Object.keys(diag.requests[0]), ["rid", "ord", "pair", "slot", "cls", "l1", "l2", "lane", "shed", "egress", "fin", "status", "inSeq", "outSeq", "inMs", "outMs", "flags"]);
  // Vocabularies are closed and track the defense core.
  assert.deepEqual([...DIAG_CLASSES], [...OPERATION_CLASSES]); assert.deepEqual(DIAG_LANES.filter((l) => l !== "none"), [...LANES]);
  assert.deepEqual(DIAG_L2.filter((l) => l !== "none"), [...L2_OUTCOMES]); assert.deepEqual(DIAG_SHED.filter((l) => l !== "none"), [...SHED_REASONS]);
});

test("strict schema: the strict parsers accept exactly the versioned structures; the existing pair, spec and server-level shapes are unchanged", () => {
  const diag = record(stream(campaign({ shedOdd: true }))); const generator = generatorDiagnostics();
  assert.equal(parseServerDiagnostics(clone(diag)).ok, true); assert.equal(parseGeneratorDiagnostics(clone(generator)).ok, true);
  const mutations: [string, (d: ServerSalvoDiagnostics) => void][] = [
    ["extra top key", (d) => { (d as unknown as Record<string, unknown>).extra = 1; }], ["schema", (d) => { (d as { schema: string }).schema = "v2"; }],
    ["extra record key", (d) => { (d.requests[3] as unknown as Record<string, unknown>).nonce = "x"; }], ["bad enum", (d) => { (d.requests[3] as { l2: string }).l2 = "weird"; }],
    ["ordinal", (d) => { d.requests[3].ord = 4; }], ["rid", (d) => { d.requests[3].rid = "x9"; }], ["pending with status", (d) => { d.requests[3].fin = "pending"; }],
    ["provenance", (d) => { (d.provenance as { clock: string }).clock = "wall"; }], ["counters", (d) => { (d.counters as unknown as Record<string, unknown>).overflow = -1; }],
    ["too many", (d) => { d.requests.push(clone(d.requests[0])); }], ["flag", (d) => { (d.requests[3].flags as string[]).push("nope"); }],
  ];
  for (const [name, change] of mutations) { const copy = clone(diag); change(copy); assert.equal(parseServerDiagnostics(copy).ok, false, name); }
  const bad = clone(generator); bad.requests[1].pair = 0; bad.requests[1].slot = 0;
  assert.equal(parseGeneratorDiagnostics(bad).ok, false); assert.equal(parseGeneratorDiagnostics({ ...generator, extra: 1 }).ok, false);
  // Malformed input is reported malformed and never partially trusted.
  const malformed = evaluateSalvoDiagnostics({ server: { ...diag, requests: "no" }, generator: { nope: 1 } });
  assert.equal(malformed.integrity, "malformed"); assert.equal(malformed.inputs.generator, "malformed"); assert.equal(malformed.signature.status, "absent");
  // Sibling placement: pair records keep exactly their three keys and SALVO_SPEC is frozen with its reviewed keys.
  const pairs = observe(stream(campaign())).snapshotSalvo().pairs;
  assert.ok(pairs.every((p) => Object.keys(p).length === 3)); assert.ok(Object.isFrozen(SALVO_SPEC));
  assert.deepEqual(Object.keys(SALVO_SPEC), ["pairs", "requestsPerPair", "periodMs", "durationMs", "binMs", "bins", "dispatchLatenessExclusiveMs", "dispatchSeparationCapMs", "materialRatio", "jointMaterialPairs", "missingPerPlannedBin", "materialStartsPerActualBin", "maxElapsedMs", "rateInterpretation"]);
  assert.equal(derivePairs(pairs, false).valid, true);
});

test("the evidence writer adds the diagnostics as one isolated sibling artifact; the thirteen historical artifacts are byte-identical with and without it", () => {
  const c = salvoFixture(); const bundle = buildSelftestBundle();
  bundle.level = { id: c.server.levelId, campaignId: c.server.campaignId, workers: 2 };
  bundle.parameters = ba0FieldFingerprint(BA0_FIELD_C2_SALVO_V1); bundle.thresholds = BA0_FIELD_C2_SALVO_V1; bundle.workloadSha256 = c.server.workloadFingerprintSha256;
  bundle.salvo = c.server.salvo; bundle.window = c.server.window; bundle.reconcileInput = c.server.reconcileInput;
  const capture = (b: typeof bundle) => { const out: Record<string, string> = {}; const result = writeFieldEvidence({ addJsonArtifact: (name: string, value: unknown) => { assertEvidenceSafe(value); out[name] = JSON.stringify(value); } } as EvidenceRun, b); return { out, result }; };
  const without = capture(bundle); assert.equal(without.result.written.length, 13);
  const diag = record(stream(campaign({ shedOdd: true })));
  const withDiag = capture({ ...bundle, salvoDiagnostics: diag });
  assert.equal(withDiag.result.written.length, 14); assert.deepEqual(withDiag.result.failed, []); assert.equal(withDiag.result.written.at(-1), "salvo-diagnostics.json");
  for (const name of without.result.written) assert.equal(withDiag.out[name], without.out[name], name);
  assert.equal(withDiag.out["salvo-diagnostics.json"], JSON.stringify(diag));
  assert.ok(!Object.hasOwn(JSON.parse(withDiag.out["server-level.json"]), "salvoDiagnostics"));
  // A scanner refusal costs only this artifact.
  const poisoned = clone(diag); (poisoned.provenance as { clock: string }).clock = "https://x.example/?a=b";
  const refused = capture({ ...bundle, salvoDiagnostics: poisoned }); assert.equal(refused.result.written.length, 13); assert.equal(refused.result.failed.length, 1);
});

// ------------------------------------------------------------------------------------------------------------------ 17: generator write handoff
class Clock implements SalvoClock {
  time = 0; sleeps: [number, number][] = []; nowCalls = 0;
  jobs: { at: number; finish(): void; signal: AbortSignal }[] = [];
  now() { this.nowCalls++; return this.time; }
  wall() { return new Date(Date.UTC(2026, 9, 7) + this.time); }
  sleep(ms: number, signal: AbortSignal) {
    this.sleeps.push([this.time, ms]);
    if (signal.aborted) return Promise.resolve();
    return new Promise<void>((resolve) => {
      const finish = () => { signal.removeEventListener("abort", finish); resolve(); };
      this.jobs.push({ at: this.time + ms, finish, signal }); signal.addEventListener("abort", finish, { once: true });
    });
  }
  async drive<T>(operation: Promise<T>): Promise<T> {
    let done = false; let result: T | undefined; let failure: unknown;
    operation.then((v) => { result = v; done = true; }, (e) => { failure = e; done = true; });
    for (let step = 0; step < 10000 && !done; step++) {
      for (let micro = 0; micro < 24; micro++) await Promise.resolve();
      if (done) break;
      this.jobs = this.jobs.filter((j) => !j.signal.aborted);
      assert.ok(this.jobs.length, "scheduler must either complete or have a pending clock event");
      const at = Math.min(...this.jobs.map((j) => j.at)); this.time = at;
      const ready = this.jobs.filter((j) => j.at <= this.time); this.jobs = this.jobs.filter((j) => j.at > this.time); ready.forEach((j) => j.finish());
    }
    assert.ok(done); if (failure) throw failure; return result!;
  }
}

function run(port = 1): AuthorizedRun {
  const now = new Date(); const registry = buildRegistry([{ id: "salvo-test", class: "lab-local", scheme: "http", host: "127.0.0.1", port,
    allowedPaths: ["/", "/gizlilik", "/test-talep-et", "/api/public-inquiries"], allowedMethods: ["GET", "POST"] }], now);
  const get = authorizeRun({ targetId: "salvo-test", workloadId: "latency-measurement", registry, now });
  const post = authorizeRun({ targetId: "salvo-test", workloadId: "demo-submission-post", registry, now });
  return { ...get, workload: WORKLOADS["ba0-l7-pressure-c2-salvo"],
    limits: { phases: [{ name: "pressure", durationSeconds: 60, ratePerSecond: 25, concurrency: 2, timeoutMs: 5000 }], maxTotalRequests: 1500, maxDurationSeconds: 60, maxConcurrency: 2, maxRequestsPerSecond: 25 },
    authorizeRequest: (method, route) => (method === "POST" ? post : get).authorizeRequest(method, route) };
}

type SenderOptions = { handoff?: "never" | "before" | "twice" | "late"; latency?: number; expiry?: number };
function sender(clock: Clock, options: SenderOptions = {}) {
  const calls: { at: number; method: string }[] = [];
  const send: NonNullable<ClosedLoopOptions["send"]> = (request, _run, sendOptions) => {
    const index = calls.length;
    if (index === options.expiry) throw new Error("expired");
    calls.push({ at: clock.time, method: request.method });
    const latency = options.latency ?? 6;
    const resolved: ClosedLoopSend = { outcome: request.method === "POST" ? "http_5xx" : "ok", status: request.method === "POST" ? 503 : 200, latencyMs: latency, wireBytesSent: 1, wireBytesReceived: 1, bodyBytesReceived: 1, reusedSocket: index >= 2 };
    if (options.handoff === "before" || options.handoff === "twice") void clock.sleep(0.5, sendOptions.signal!).then(() => { sendOptions.onWriteHandoff?.(); if (options.handoff === "twice") sendOptions.onWriteHandoff?.(); });
    const settled = clock.sleep(latency, sendOptions.signal!).then(() => resolved);
    // "late": the callback arrives only after the scheduler has already observed the settlement (several microtasks later).
    if (options.handoff === "late") void settled.then(async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); sendOptions.onWriteHandoff?.(); });
    return settled;
  };
  return { send, calls };
}

test("write handoff is recorded once, at the sender's callback time, and only while the request is unsettled; no callback means null", async () => {
  const before = new Clock(); const sb = sender(before, { handoff: "before" });
  const result = await before.drive(executeClosedLoop({ run: run(), send: sb.send, salvoClock: before }));
  const rows = result.salvoDiagnostics!.requests; assert.equal(rows.length, 1500);
  for (const r of rows) { assert.equal(r.handoffMs, r.startMs + 0.5); assert.equal(r.settledMs, r.startMs + 6); assert.equal(r.status, r.slot === 1 && r.pair % 2 === 1 ? 503 : 200); }
  assert.equal(parseGeneratorDiagnostics(result.salvoDiagnostics).ok, true);
  const check = evaluateSalvoDiagnostics({ generator: result.salvoDiagnostics, generatorPairs: result.salvo!.pairs });
  assert.deepEqual(check.generator, { rows: 1500, handoffObserved: 1500, handoffMissing: 0, handoffBeforeStart: 0, handoffAfterSettlement: 0, settledBeforeStart: 0, unsettled: 0 });
  assert.deepEqual(check.pairRecordAgreement.generator, { compared: 1500, mismatched: 0 });
  for (const mode of ["never", "twice", "late"] as const) {
    const clock = new Clock(); const s = sender(clock, { handoff: mode });
    const r = await clock.drive(executeClosedLoop({ run: run(), send: s.send, salvoClock: clock }));
    const expected = mode === "never" || mode === "late" ? null : 0.5;
    assert.ok(r.salvoDiagnostics!.requests.every((row) => row.handoffMs === (expected === null ? null : row.startMs + expected)), mode);
  }
});

test("partial and refused dispatches: an unsent request leaves no row, an aborted one keeps an unsettled row, and rows never exceed the cap", async () => {
  const clock = new Clock(); const s = sender(clock, { expiry: 1 });
  const result = await clock.drive(executeClosedLoop({ run: run(), send: s.send, salvoClock: clock }));
  assert.equal(result.stop.kind, "authorization_expired"); assert.equal(result.attempted, 1);
  assert.deepEqual(result.salvoDiagnostics!.requests.map((r) => [r.pair, r.slot]), [[0, 0]]);
  const aborting = new Clock(); const controller = new AbortController(); void aborting.sleep(2, new AbortController().signal).then(() => controller.abort());
  const sa = sender(aborting, { latency: 50 });
  const sendAbortable: NonNullable<ClosedLoopOptions["send"]> = (...args) => sa.send(...args).then((r) => (args[2].signal!.aborted ? { ...r, outcome: "aborted", status: null } : r));
  const partial = await aborting.drive(executeClosedLoop({ run: run(), send: sendAbortable, salvoClock: aborting, signal: controller.signal }));
  assert.equal(partial.stop.kind, "operator_abort");
  assert.ok(partial.salvoDiagnostics!.requests.length === 2 && partial.salvoDiagnostics!.requests.every((r) => r.status === null && r.settledMs !== null));
  const full = new Clock(); const done = await full.drive(executeClosedLoop({ run: run(), send: sender(full).send, salvoClock: full }));
  assert.ok(done.salvoDiagnostics!.requests.length <= SALVO_DIAGNOSTIC_LIMITS.maxRequests);
});

test("real HTTP: finish proves OS handoff only. It fires for a peer that accepted the connection but never read, is not called after destroy, and precedes the response", async () => {
  // (a) a peer that accepts TCP and never reads: the request still reports a handoff, so handoff is not receipt.
  const deaf = net.createServer((socket) => { socket.pause(); });
  await new Promise<void>((resolve) => deaf.listen(0, "127.0.0.1", resolve));
  const deafPort = (deaf.address() as net.AddressInfo).port; const agent = new http.Agent({ keepAlive: false, maxSockets: 2 });
  try {
    const controller = new AbortController(); let handoffs = 0;
    const handoff = new Promise<void>((resolve) => {
      void sendClosedLoop(run(deafPort).authorizeRequest("GET", "/"), run(deafPort), { timeoutMs: 5000, agent, signal: controller.signal, onWriteHandoff: () => { handoffs++; resolve(); } });
    });
    await Promise.race([handoff, new Promise((_, reject) => setTimeout(() => reject(new Error("no handoff observed")), 3000))]);
    assert.equal(handoffs, 1); controller.abort();
  } finally { agent.destroy(); deaf.close(); }
  // (b) a request destroyed before any write completes reports no handoff; (c) with a real server the handoff precedes the response.
  const server = http.createServer((_req, res) => { setTimeout(() => { res.writeHead(200); res.end("ok"); }, 30); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as net.AddressInfo).port; const agent2 = new http.Agent({ keepAlive: true, maxSockets: 2 });
  try {
    const stamps: Record<string, number> = {}; const started = performance.now();
    const result = await sendClosedLoop(run(port).authorizeRequest("GET", "/"), run(port), { timeoutMs: 5000, agent: agent2, onWriteHandoff: () => { stamps.handoff = performance.now(); } });
    stamps.settled = performance.now();
    assert.equal(result.status, 200); assert.ok(stamps.handoff >= started && stamps.handoff < stamps.settled - 20, "handoff precedes the 30 ms server response");
    const pre = new AbortController(); pre.abort(); let called = 0;
    const aborted = await sendClosedLoop(run(port).authorizeRequest("GET", "/"), run(port), { timeoutMs: 5000, agent: agent2, signal: pre.signal, onWriteHandoff: () => { called++; } });
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(aborted.outcome, "aborted"); assert.equal(called, 0);
    let thrown = 0; const survived = await sendClosedLoop(run(port).authorizeRequest("GET", "/"), run(port), { timeoutMs: 5000, agent: agent2, onWriteHandoff: () => { thrown++; throw new Error("observer bug"); } });
    assert.equal(survived.status, 200); assert.equal(thrown, 1);   // an exception in the observation callback cannot change the send
    const plain = await sendClosedLoop(run(port).authorizeRequest("GET", "/"), run(port), { timeoutMs: 5000, agent: agent2 });
    assert.deepEqual([plain.outcome, plain.status], [survived.outcome, survived.status]);
  } finally { agent2.destroy(); server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); }
});

// ------------------------------------------------------------------------------------------------------------------ 18: pacing
function historic(file: string, dependencies: Record<string, unknown>): Record<string, unknown> {
  const source = execFileSync("git", ["show", `${BASELINE}:${file}`], { cwd: root, encoding: "utf8" });
  const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true } }).outputText;
  const exports: Record<string, unknown> = {};
  new Function("require", "exports", compiled)((name: string) => { if (!Object.hasOwn(dependencies, name)) throw new Error(`unreviewed historical dependency ${name}`); return dependencies[name]; }, exports);
  return exports;
}
const salvoDeps = { "node:http": http, "node:https": https, "../../defense/core/telemetry": { LagMonitor }, "../defense/salvo-spec": salvoSpecModule, "./engine": { syntheticSubmissionBody },
  "./closed-loop": { sendClosedLoop, TRANSPORT_FAILURES } };

test("the paired scheduler is pacing-identical to the baseline: same sleeps, same send timeline, same clock reads, same results", async () => {
  const baseline = historic("lab/load/salvo.ts", salvoDeps) as unknown as typeof import("../lab/load/salvo");
  const strip = (r: Awaited<ReturnType<typeof baseline.executeSalvo>>) => { const { generatorHealth, salvoDiagnostics, ...rest } = r as Record<string, unknown>; void generatorHealth; void salvoDiagnostics; return rest; };
  const { executeSalvo } = await import("../lab/load/salvo");
  const scenarios: SenderOptions[] = [{}, { latency: 80 }, { latency: 80.001 }, { expiry: 1 }, { latency: 41 }];
  for (const scenario of scenarios) {
    const a = new Clock(); const sa = sender(a, scenario); const old = await a.drive(baseline.executeSalvo({ run: run(), send: sa.send, salvoClock: a }));
    const b = new Clock(); const sb = sender(b, scenario); const now = await b.drive(executeSalvo({ run: run(), send: sb.send, salvoClock: b }));
    assert.deepEqual(strip(now), strip(old), JSON.stringify(scenario)); assert.deepEqual(sb.calls, sa.calls); assert.deepEqual(b.sleeps, a.sleeps);
    assert.equal(b.nowCalls, a.nowCalls, "no additional clock read without a handoff callback");
  }
  // With handoff callbacks the only difference is the observation itself: identical sleeps beyond the sender's own, identical send timeline and pair records.
  const a = new Clock(); const sa = sender(a, { handoff: "never" }); const old = await a.drive(baseline.executeSalvo({ run: run(), send: sa.send, salvoClock: a }));
  const b = new Clock(); const sb = sender(b, { handoff: "before" }); const now = await b.drive(executeSalvo({ run: run(), send: sb.send, salvoClock: b }));
  assert.deepEqual(sb.calls, sa.calls); assert.deepEqual(strip(now).salvo, strip(old).salvo);
  assert.equal(b.nowCalls - a.nowCalls, 1500, "exactly one clock read per observed handoff");
  // Static: the scheduler's waits and timers are textually unchanged.
  const before = execFileSync("git", ["show", `${BASELINE}:lab/load/salvo.ts`], { cwd: root, encoding: "utf8" }).replace(/\r\n/g, "\n");
  const after = readFileSync(path.join(root, "lab/load/salvo.ts"), "utf8").replace(/\r\n/g, "\n");
  for (const token of [/\bawait\b/g, /setTimeout/g, /clock\.sleep/g, /\buntil\(/g, /stopWith\(/g, /\bsetInterval\b/g]) assert.equal((after.match(token) ?? []).length, (before.match(token) ?? []).length, String(token));
});

// ------------------------------------------------------------------------------------------------------------------ 19, 20: immutability
test("the server observer's existing pair records and counters are identical to the baseline's on normal and adversarial streams", () => {
  const baselineClass = (historic("lab/defense/salvo-measurement.ts", { "./n2-measurement": { N2ServerObserver }, "./salvo-spec": salvoSpecModule }) as { SalvoServerObserver: typeof SalvoServerObserver }).SalvoServerObserver;
  const dup = campaign({ shedOdd: true }); dup[41].nonce = dup[40].nonce;
  const missing = campaign({ shedOdd: true }); missing[100].fin = "pending"; missing[301].fin = "aborted";
  const overflow = campaign(); overflow.push({ nonce: "o1", cls: "open", at: 70000, end: 70006 });
  const reversed = campaign({ shedOdd: true, reversed: (p) => p % 3 === 0, zeroOverlap: (p) => p % 11 === 1 });
  const disordered = stream(campaign({ shedOdd: true })); disordered[500] = { ...disordered[500], t: disordered[498].t - 1 };
  const canary = stream(campaign()); canary.splice(10, 0, { seq: 99_999_999, nonce: "canary", kind: "INGRESS_ACCEPTED", t: 5 }, { seq: 99_999_998, nonce: null, kind: "PARSER_REJECTED", t: 6 });
  for (const [name, events] of [["dup", stream(dup)], ["missing", stream(missing)], ["overflow", stream(overflow)], ["reversed", stream(reversed)], ["disordered", disordered], ["canary", canary]] as const) {
    const oldObserver = new baselineClass(n2ExerciseSpec(BA0_FIELD_C2_SALVO_V1)); const newObserver = new SalvoServerObserver(n2ExerciseSpec(BA0_FIELD_C2_SALVO_V1));
    for (const event of events) { oldObserver.observe(event); newObserver.observe(event); }
    assert.deepEqual(newObserver.snapshotSalvo(), oldObserver.snapshotSalvo(), name); assert.deepEqual(newObserver.snapshot(), oldObserver.snapshot(), name);
  }
});

test("files that decide admission, rejection, L1/L2, forwarding, canary behavior and every G1-G6 identity are byte-identical to the baseline commit", () => {
  const diff = (paths: string[]) => execFileSync("git", ["diff", BASELINE, "--", ...paths], { cwd: root, encoding: "utf8" });
  assert.equal(diff(["defense", "src", "workers", "lab/policy", "lab/defense/salvo-spec.ts", "lab/defense/salvo-reconcile.ts", "lab/defense/reconcile.ts", "lab/defense/field-verdict.ts",
    "lab/defense/n2-measurement.ts", "lab/defense/external-reducer.ts", "lab/defense/external-accounting.ts", "lab/defense/canary.ts", "lab/defense/field-canary.ts", "lab/defense/collector.ts",
    "lab/defense/exposure-proof.ts", "lab/evidence"]), "");
  const names = (value: ReturnType<typeof finalFrom>) => value.result.identities.map((i) => `${i.id}:${i.ok}`);
  const c = salvoFixture(); assert.equal(finalFrom(c.server, c.report, BA0_FIELD_C2_SALVO_V1.generator).decision.verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
  // The full ordered identity list of the baseline commit (the files that produce it are byte-identical, asserted above).
  assert.deepEqual(names(finalFrom(c.server, c.report, BA0_FIELD_C2_SALVO_V1.generator)), [
    "g6.salvo_reviewed_binding:true", "g1.salvo_fates:true", "g2.salvo_no_unexplained_status:true", "g6.salvo_completion:true", "g5.salvo_exercised:true",
    "g6.salvo_measurement_phase:true", "g6.binding_matches:true", "g1.attempted_equals_ingress_plus_preingress:true", "g1.preingress_is_zero:true",
    "g2.status_histogram_equal:true", "g2.generator_503_equals_expected_shed:true", "g3.gets_equal_open_class:true", "g3.posts_equal_mutation_class:true",
    "g3.unknown_class_is_zero:true", "g3.l1_rejects_is_zero:true", "g4.new_connections_equal_accepted:true", "g4.server_dropped_is_zero:true",
    "g5.generator_in_flight_within_n:true", "g5.server_external_in_flight_within_n:true", "g5.no_retries_no_pipelining:true", "g5.generator_not_saturated:true"]);
});

test("historical parameters, workloads and budget gates match the baseline; the salvo level gains exactly three additive gates and keeps its fingerprints", () => {
  const old = historic("lab/defense/field-thresholds.ts", { "node:crypto": { createHash }, "../../defense/core/lanes": { requiredLedgerCapacity }, "../policy/thresholds": policyThresholds,
    "./origin-thresholds": { BA0_ORIGIN_LOCAL_V1 }, "./external-reducer": { DEFAULT_EXTERNAL_LIMITS }, "./salvo-spec": salvoSpecModule }) as unknown as typeof import("../lab/defense/field-thresholds");
  for (const [now, then] of [[BA0_FIELD_V1, old.BA0_FIELD_V1], [BA0_FIELD_C2_V1, old.BA0_FIELD_C2_V1], [BA0_FIELD_C2_SALVO_V1, old.BA0_FIELD_C2_SALVO_V1]] as const) {
    assert.deepEqual(now, then); assert.equal(ba0FieldFingerprint(now).sha256, old.ba0FieldFingerprint(then).sha256);
  }
  for (const set of [BA0_FIELD_V1, BA0_FIELD_C2_V1]) assert.deepEqual(evaluateBudgetGates(set, 3_600_000), old.evaluateBudgetGates(set, 3_600_000));
  const before = old.evaluateBudgetGates(old.BA0_FIELD_C2_SALVO_V1, 3_600_000); const after = evaluateBudgetGates(BA0_FIELD_C2_SALVO_V1, 3_600_000);
  assert.equal(before.length, 34); assert.equal(after.length, 37);
  assert.deepEqual(after.filter((g) => before.some((b) => b.id === g.id)), before);   // every historical gate: same id, same result, same detail text
  assert.deepEqual(after.filter((g) => !before.some((b) => b.id === g.id)).map((g) => g.id), ["salvo.diagnostic_cap_covers_level", "salvo.diagnostic_memory", "salvo.evidence_with_diagnostics"]);
  assert.equal(ba0FieldFingerprint(BA0_FIELD_C2_SALVO_V1).sha256, "eda312909c18c7a7cd9c4525f2071b474f10b1b27c3b181e9e1a12ea27208f46");
  assert.equal(workloadFingerprint(WORKLOADS["ba0-l7-pressure-c2-salvo"]), "43ee3f7c0aaacea44384cc7e614eb58fe126bb042698417cf6c65f8f138d4264");
  // N=1/N=2 generator report builders emit no diagnostics key and are unchanged for those levels.
  const fixture = salvoFixture(); const result = { ...fixture.report, workers: 2, wireBytesSent: 1, wireBytesReceived: 1, bodyBytesReceived: 1, salvoDiagnostics: generatorDiagnostics() } as unknown as Parameters<typeof buildGeneratorReport>[0]["result"];
  for (const levelId of ["ba0-l7-c1", "ba0-l7-c2"]) assert.ok(!Object.hasOwn(buildGeneratorReport({ result, runId: "r", campaignId: "campaign-1", levelId, gitSha: "a".repeat(40), paramsFingerprintSha256: "b".repeat(64), workload: WORKLOADS["ba0-l7-pressure-c2"], targetId: "t", ceilingRatePerSecond: 25 }), "salvoDiagnostics"));
  const built = buildGeneratorReport({ result, runId: "r", campaignId: "campaign-1", levelId: "ba0-l7-c2-salvo", gitSha: "a".repeat(40), paramsFingerprintSha256: "b".repeat(64), workload: WORKLOADS["ba0-l7-pressure-c2-salvo"], targetId: "t", ceilingRatePerSecond: 25 });
  assert.deepEqual(built.salvoDiagnostics, result.salvoDiagnostics); assert.deepEqual(parseGeneratorReport(JSON.stringify(built)), built);
});

// ------------------------------------------------------------------------------------------------------------------ R2-shaped campaign end to end
const R2_ODD = Array.from({ length: 22 }, (_, k) => 63 + 32 * k);   // pair 63 plus 21 other odd pairs (synthetic: the raw R2 per-pair table is not in this repository)

function r2Shaped() {
  const zero = new Set(R2_ODD);
  const specs = campaign({ shedOdd: true, zeroOverlap: (p) => zero.has(p) });
  const partial = specs[2 * 164]; partial.end = partial.at + 4.5; specs[2 * 164 + 1].at = partial.at + 1.2; specs[2 * 164 + 1].end = specs[2 * 164 + 1].at + 4.5;     // even pair 164: 0.733
  const events = stream(specs); const c = salvoFixture();
  c.server.salvo!.pairs = observe(events).snapshotSalvo().pairs; refreshFixture(c);
  return { c, events, specs };
}

test("an R2-shaped campaign (750 generator pairs, 727 server pairs, 22 odd zero-overlap pairs and one partial even pair) stays INVALID at g5.salvo_exercised with or without diagnostics", () => {
  const { c, events } = r2Shaped();
  const before = finalFrom(c.server, c.report, BA0_FIELD_C2_SALVO_V1.generator);
  assert.equal(before.decision.verdict, "INVALID");
  assert.deepEqual(before.result.identities.filter((i) => !i.ok).map((i) => i.id), ["g5.salvo_exercised"]);
  assert.equal(before.result.salvo!.generator.materialIndices.length, 750); assert.equal(before.result.salvo!.server.materialIndices.length, 727); assert.equal(before.result.salvo!.joint.materialIndices.length, 727);
  const check = evaluateSalvoDiagnostics({ server: record(events), generator: generatorDiagnostics(undefined, 1), serverPairs: c.server.salvo!.pairs, generatorPairs: c.report.salvo!.pairs });
  // The diagnostics explain the 22 zero-overlap pairs and the partial one, and report a fully consistent composition. None of that revalidates anything.
  assert.equal(check.zeroOverlap.pairs, 22); assert.equal(check.zeroOverlap.fastShedFirst, 22); assert.deepEqual(check.partialOverlap, { belowRatio: 1, indices: [164] });
  assert.equal(check.integrity, "consistent"); assert.equal(check.binding.status, "inferred"); assert.equal(check.influencesVerdict, false);
  assert.deepEqual(finalFrom(c.server, c.report, BA0_FIELD_C2_SALVO_V1.generator), before);
});

test("offline reconcile on R2-shaped evidence: diagnostics add one separate artifact; the verdict, identities, reasons and exit code are those of evidence without diagnostics", () => {
  const { c, events } = r2Shaped(); const withDiag = clone(c.report); withDiag.salvoDiagnostics = generatorDiagnostics(undefined, 1);
  const directory = mkdtempSync(path.join(root, "artifacts", "lab", "salvo-diag-"));
  try {
    const make = (diagnostics: boolean) => {
      const bundle = buildSelftestBundle();
      bundle.level = { id: c.server.levelId, campaignId: c.server.campaignId, workers: 2 }; bundle.parameters = ba0FieldFingerprint(BA0_FIELD_C2_SALVO_V1);
      bundle.thresholds = BA0_FIELD_C2_SALVO_V1; bundle.workloadSha256 = c.server.workloadFingerprintSha256; bundle.salvo = c.server.salvo;
      bundle.git = { gitSha: c.server.gitSha, dirty: false, dirtyFileCount: 0, untrackedFileCount: 0 };
      bundle.serverSide = { status: "complete", failureClass: null, reasons: [] }; bundle.window = c.server.window; bundle.reconcileInput = c.server.reconcileInput;
      if (diagnostics) bundle.salvoDiagnostics = record(events);
      const evidence = new EvidenceRun("field-selftest", diagnostics ? "salvo-a" : "salvo-b", new Date(), directory);
      const written = writeFieldEvidence(evidence, bundle); assert.deepEqual(written.failed, []);
      evidence.addJsonArtifact("generator-report.json", diagnostics ? withDiag : c.report);
      evidence.finalize({ git: bundle.git, environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: bundle.parameters, engine: "salvo-test", result: "SERVER-COMPLETE", resultReasons: [], metrics: {} });
      return reconcileLevel({ serverId: evidence.id, reportPath: path.join(evidence.directory, "generator-report.json") }, directory);
    };
    const plain = make(false); const diag = make(true);
    assert.equal(plain.verdict, "INVALID"); assert.equal(diag.verdict, "INVALID"); assert.equal(plain.exit, diag.exit); assert.deepEqual(diag.reasons, plain.reasons);
    assert.equal(plain.diagnostics, undefined); assert.equal(existsSync(path.join(directory, plain.evidenceId!, "salvo-diagnostic-check.json")), false);   // historical-shaped input: no new artifact at all
    const finalOf = (id: string) => JSON.parse(readFileSync(path.join(directory, id, "final.json"), "utf8")) as { inputs: unknown } & Record<string, unknown>;
    const a = finalOf(plain.evidenceId!); const b = finalOf(diag.evidenceId!); delete a.inputs; delete b.inputs;     // inputs name the evidence run and report hashes, which differ by construction
    assert.deepEqual(b, a);
    const artifact = JSON.parse(readFileSync(path.join(directory, diag.evidenceId!, "salvo-diagnostic-check.json"), "utf8"));
    assert.equal(artifact.influencesVerdict, false); assert.equal(artifact.zeroOverlap.fastShedFirst, 22); assert.equal(artifact.integrity, "consistent"); assert.equal(artifact.binding.identityEvidence, "none"); assert.equal(artifact.binding.pairs.verified, 0);
    assert.equal(diag.diagnostics!.signature.status, "compatible");
    const sums = readFileSync(path.join(directory, diag.evidenceId!, "SHA256SUMS"), "utf8"); assert.match(sums, /salvo-diagnostic-check\.json/);
  } finally {
    const resolved = path.resolve(directory); assert.ok(resolved.startsWith(path.resolve(root, "artifacts", "lab") + path.sep)); rmSync(resolved, { recursive: true, force: true });
  }
});

test("a VALID-quality diagnostic result can never rescue an INVALID campaign, and an inconsistent one never invalidates a VALID one", () => {
  const { c } = r2Shaped(); assert.equal(finalFrom(c.server, c.report, BA0_FIELD_C2_SALVO_V1.generator).decision.verdict, "INVALID");
  const perfect = record(stream(campaign({ shedOdd: true }))); assert.equal(evaluateSalvoDiagnostics({ server: perfect, generator: generatorDiagnostics() }).integrity, "consistent");
  assert.equal(finalFrom(c.server, c.report, BA0_FIELD_C2_SALVO_V1.generator).decision.verdict, "INVALID");
  const valid = salvoFixture(); assert.equal(finalFrom(valid.server, valid.report, BA0_FIELD_C2_SALVO_V1.generator).decision.verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
  const specs = campaign({ shedOdd: true }); specs[0].cls = "mutation";
  assert.equal(evaluateSalvoDiagnostics({ server: record(stream(specs)) }).composition, "inconsistent");
  assert.equal(finalFrom(valid.server, valid.report, BA0_FIELD_C2_SALVO_V1.generator).decision.verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
  // No qualification module imports the diagnostics (static separation).
  for (const file of ["lab/defense/salvo-spec.ts", "lab/defense/salvo-reconcile.ts", "lab/defense/reconcile.ts", "lab/defense/field-verdict.ts"]) assert.ok(!/salvo-diagnostic/.test(readFileSync(path.join(root, file), "utf8")), file);
  void createHash; void LagMonitor;
});
