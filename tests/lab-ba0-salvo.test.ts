import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { test } from "node:test";
import ts from "typescript";
import type { PlaneEvent } from "../defense/core/ledger";
import { BA0_FIELD_V1, BA0_FIELD_C2_V1, BA0_FIELD_C2_SALVO_V1, FIELD_LEVELS, ba0FieldFingerprint, evaluateBudgetGates, failedGates } from "../lab/defense/field-thresholds";
import { buildGeneratorReport, parseGeneratorReport, workloadFingerprint } from "../lab/defense/generator-report";
import { finalFrom } from "../lab/defense/reconcile";
import { SalvoServerObserver } from "../lab/defense/salvo-measurement";
import { exercised, n2ExerciseSpec } from "../lab/defense/n2-measurement";
import { requiredLedgerCapacity } from "../defense/core/lanes";
import { BA0_ORIGIN_LOCAL_V1 } from "../lab/defense/origin-thresholds";
import { DEFAULT_EXTERNAL_LIMITS } from "../lab/defense/external-reducer";
import { decideFinal } from "../lab/defense/field-verdict";
import { EXPOSURE_STATEMENT } from "../lab/defense/exposure-proof";
import * as policyThresholds from "../lab/policy/thresholds";
import { derivePairs, plannedPairCounts, SALVO_SPEC, type SalvoPair } from "../lab/defense/salvo-spec";
import { assertEvidenceSafe } from "../lab/evidence/redact";
import { EvidenceRun, collectEnvironment } from "../lab/evidence/manifest";
import { buildSelftestBundle } from "../lab/defense/field-selftest";
import { writeFieldEvidence } from "../lab/defense/field-evidence";
import { reconcileLevel } from "../lab/defense/ba0-field-reconcile";
import { WORKLOADS } from "../lab/policy/workloads";
import { salvoFixture, pairRecords, refreshFixture, serialPair } from "./support/salvo-fixture";

const root = path.join(__dirname, "..");
const base = "aff793e4968cd5615e25665c5437e20d268d744f";
const evaluate = (c = salvoFixture()) => finalFrom(c.server, c.report, BA0_FIELD_C2_SALVO_V1.generator);
const invalid = (c: ReturnType<typeof salvoFixture>, id?: string) => {
  const result = evaluate(c); assert.notEqual(result.decision.verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
  if (id) assert.ok(result.result.identities.some((i) => i.id === id && !i.ok), id);
  return result;
};

test("salvo preregistration qualifies material fast requests with approximately 4.3 seconds, not latency inflation", () => {
  const c = salvoFixture(); const d = derivePairs(c.report.salvo!.pairs, true);
  assert.equal(evaluate(c).decision.verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
  assert.equal(d.materialIndices.length, 750); assert.equal(d.overlapMs.reduce((a, b) => a + b), 4312.5);
  assert.deepEqual(plannedPairCounts().slice(0, 4), [13, 12, 13, 12]);
  assert.doesNotThrow(() => assertEvidenceSafe(c.report));
  assert.doesNotThrow(() => assertEvidenceSafe(evaluate(c).result));
  assert.deepEqual(parseGeneratorReport(JSON.stringify(c.report)), c.report);
});

test("one incidental overlap and four overlaps concentrated in one second cannot qualify", () => {
  for (const kept of [0, 1, 4]) {
    const c = salvoFixture();
    for (const pairs of [c.report.salvo!.pairs, c.server.salvo!.pairs]) for (const pair of pairs.slice(kept)) serialPair(pair);
    refreshFixture(c); invalid(c, "g5.salvo_exercised");
    assert.equal(derivePairs(c.report.salvo!.pairs, true).materialIndices.length, kept);
  }
});

test("743 matching material pairs are accepted; 742 or one deficient planned bin fail", () => {
  const c = salvoFixture(); const removed = [0, 25, 50, 75, 100, 125, 150];
  for (const i of removed) { serialPair(c.report.salvo!.pairs[i]); serialPair(c.server.salvo!.pairs[i]); }
  refreshFixture(c); assert.equal(evaluate(c).decision.verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
  serialPair(c.report.salvo!.pairs[175]); serialPair(c.server.salvo!.pairs[175]); refreshFixture(c);
  invalid(c, "g5.salvo_exercised");
  const deficient = salvoFixture();
  for (const i of [1, 2]) { serialPair(deficient.report.salvo!.pairs[i]); serialPair(deficient.server.salvo!.pairs[i]); }
  refreshFixture(deficient); assert.equal(derivePairs(deficient.report.salvo!.pairs, true).materialIndices.length, 748);
  invalid(deficient, "g5.salvo_exercised");
});

test("positive but negligible overlap and dispatch separation over 0.5 ms fail material exposure", () => {
  for (const change of [
    (p: SalvoPair) => { p.settledMs[0] = p.startsMs[1]! + 0.001; },
    (p: SalvoPair) => { p.startsMs[1] = p.startsMs[0]! + 0.500001; },
  ]) {
    const c = salvoFixture(); c.report.salvo!.pairs.forEach(change); refreshFixture(c);
    invalid(c, "g5.salvo_exercised");
  }
});

test("weighted opportunity includes missed pairs; starts alone cannot hide missing long residency", () => {
  const c = salvoFixture();
  for (const pairs of [c.report.salvo!.pairs, c.server.salvo!.pairs]) {
    const p = pairs[0]; p.settledMs[0] = p.startsMs[0]! + 30;
    p.startsMs[1] = p.settledMs[0]! + 1; p.settledMs[1] = p.startsMs[1] + 30;
  }
  refreshFixture(c); assert.equal(derivePairs(c.report.salvo!.pairs, true).materialIndices.length, 749);
  invalid(c, "g5.salvo_exercised");
});

test("independent actual source-clock coverage cannot be replaced by planned-bin totals", () => {
  const c = salvoFixture();
  for (const [i, at] of [[10, 1000], [11, 1010], [12, 1020]]) {
    const p = c.server.salvo!.pairs[i]; p.startsMs = [at, at + .25]; p.settledMs = [at + 6, at + 6.25];
  }
  refreshFixture(c); const d = derivePairs(c.server.salvo!.pairs, false);
  assert.equal(d.valid, true); assert.equal(d.plannedMaterial[0], 13); assert.equal(d.actualMaterial[0], 10);
  invalid(c, "g5.salvo_exercised");
});

test("generator/server material pair-index sets must agree, even when each has sufficient totals", () => {
  for (const side of ["generator", "server", "different"] as const) {
    const c = salvoFixture();
    serialPair(c.report.salvo!.pairs[0]);
    if (side === "server") { c.report.salvo!.pairs = pairRecords(1); serialPair(c.server.salvo!.pairs[0]); }
    if (side === "different") serialPair(c.server.salvo!.pairs[25]);
    refreshFixture(c); const result = invalid(c, "g5.salvo_exercised");
    assert.equal(result.result.salvo!.matchingMaterialIndices, false);
  }
});

test("missing, duplicate, malformed, non-finite and unbounded pair records cannot qualify", () => {
  const changes: ((pairs: SalvoPair[]) => void)[] = [
    p => { p.pop(); }, p => { p.push(structuredClone(p[0])); }, p => { p[1].index = 0; },
    p => { p[0].startsMs[0] = NaN; }, p => { p[0].settledMs[0] = null; },
    p => { p[1].startsMs[0] = -1; }, p => { p[0].settledMs[0] = 64001; },
    p => { p[1].startsMs[0] = 1; }, p => { p[0].startsMs.push(1); },
  ];
  for (const change of changes) for (const source of ["generator", "server"]) {
    const c = salvoFixture(); change(source === "generator" ? c.report.salvo!.pairs : c.server.salvo!.pairs);
    invalid(c, "g5.salvo_exercised");
  }
});

test("fabricated aggregate totals cannot override invalid pair records or a deficient bin", () => {
  const c = salvoFixture(); c.report.salvo!.pairs.forEach(serialPair); refreshFixture(c);
  Object.assign(c.report.salvo!, { materialPairs: 750, totalOverlapMs: 99999, overlapMs: Array(60).fill(999) });
  invalid(c, "g5.salvo_exercised");
  c.report.salvo!.fixtureLatencyMs.get_home.mean = 999;
  invalid(c, "g1.salvo_fates");
});

test("every non-reviewed completion state, stop latch, incomplete duration and incomplete drain fail", () => {
  for (const kind of ["operator_abort", "authorization_expired", "transport_failure", "deadline", "total_ceiling", "schedule_incomplete", "unknown"]) {
    const c = salvoFixture(); c.report.stop.kind = kind; c.report.salvo!.stopLatchedMs = 10;
    const result = invalid(c, "g6.salvo_completion");
    assert.equal(result.result.salvo!.phase.ok, true, "full-duration abort is independently phase-consistent");
  }
  for (const change of [
    (c: ReturnType<typeof salvoFixture>) => { c.report.salvo!.stopLatchedMs = 0; },
    (c: ReturnType<typeof salvoFixture>) => { c.report.salvo!.elapsedMs = 59999; c.report.wallClockSeconds = 60; },
    (c: ReturnType<typeof salvoFixture>) => { c.report.salvo!.elapsedMs = 64001; },
    (c: ReturnType<typeof salvoFixture>) => { c.report.salvo!.lastSettlementMs = 60001; },
    (c: ReturnType<typeof salvoFixture>) => { c.report.concurrency.inFlightNow = 1; },
    (c: ReturnType<typeof salvoFixture>) => { c.report.salvo!.pairs[0].startsMs[0] = -.001; },
    (c: ReturnType<typeof salvoFixture>) => { c.report.salvo!.pairs[0].startsMs[0] = 40; },
  ]) { const c = salvoFixture(); change(c); invalid(c, "g6.salvo_completion"); }
});

test("offline records cannot excuse an active pair at the nominal next release with a later dispatch inside the lateness allowance", () => {
  const c = salvoFixture();
  for (const pairs of [c.report.salvo!.pairs, c.server.salvo!.pairs]) {
    const offset = pairs[0].startsMs[0]!;
    pairs[0].settledMs = [offset + 100, offset + 100.25];
    pairs[1].startsMs = [offset + 110, offset + 110.25]; pairs[1].settledMs = [offset + 116, offset + 116.25];
  }
  refreshFixture(c); const result = invalid(c, "g6.salvo_completion");
  assert.equal(result.result.salvo!.generator.valid, true); assert.equal(result.result.salvo!.generator.scheduleValid, false);
  assert.equal(result.result.salvo!.phase.ok, true);
});

test("phase-only contamination and timing disagreements fail with otherwise completed material exposure", () => {
  const changes = [
    (c: ReturnType<typeof salvoFixture>) => { c.server.salvo!.phase.beforeArmed = 1; },
    (c: ReturnType<typeof salvoFixture>) => { c.server.salvo!.phase.afterClosed = 1; },
    (c: ReturnType<typeof salvoFixture>) => { c.server.salvo!.phase.armed!.acceptedExternal = 1; },
    (c: ReturnType<typeof salvoFixture>) => { c.server.salvo!.phase.inFlightAtClose = 1; },
    (c: ReturnType<typeof salvoFixture>) => { c.server.salvo!.phase.closed!.inFlightExternal = 1; },
    (c: ReturnType<typeof salvoFixture>) => { c.server.salvo!.phase.faults = 1; },
    (c: ReturnType<typeof salvoFixture>) => { c.server.salvo!.phase.lastSettlementMs! += 1; },
    (c: ReturnType<typeof salvoFixture>) => { c.server.window!.openedAt = "2026-10-07T10:00:08.000Z"; },
    (c: ReturnType<typeof salvoFixture>) => { c.server.salvo!.phase.armed!.wallAt = "2026-10-07T09:59:57.000Z"; },
  ];
  for (const change of changes) {
    const c = salvoFixture(); change(c); const r = invalid(c, "g6.salvo_measurement_phase");
    assert.equal(r.result.salvo!.completion.ok, true);
  }
});

test("salvo cannot cross-reconcile with C1/C2 or accept historical fingerprints, worker counts or ceilings", () => {
  for (const level of ["ba0-l7-c1", "ba0-l7-c2"]) for (const side of ["server", "report"] as const) {
    const c = salvoFixture(); c[side].levelId = level; invalid(c, "g6.salvo_reviewed_binding");
  }
  for (const change of [
    (c: ReturnType<typeof salvoFixture>) => { c.report.workers = 1; },
    (c: ReturnType<typeof salvoFixture>) => { c.report.paramsFingerprintSha256 = c.server.paramsFingerprintSha256 = ba0FieldFingerprint(BA0_FIELD_C2_V1).sha256; },
    (c: ReturnType<typeof salvoFixture>) => { c.report.workloadFingerprintSha256 = c.server.workloadFingerprintSha256 = workloadFingerprint(WORKLOADS["ba0-l7-pressure-c2"]); },
    (c: ReturnType<typeof salvoFixture>) => { c.report.rate.ceilingPerSecond = 26; },
  ]) { const c = salvoFixture(); change(c); invalid(c, "g6.salvo_reviewed_binding"); }
});

test("existing transport, saturation, unexplained traffic and server-side legitimate/recovery/evidence failures remain non-qualifying", () => {
  for (const change of [
    (c: ReturnType<typeof salvoFixture>) => { c.report.transportFailures = 1; },
    (c: ReturnType<typeof salvoFixture>) => { c.report.schedule.lagMs.p99 = 51; },
    (c: ReturnType<typeof salvoFixture>) => { c.report.generatorHealth.eldP99Ms = 101; },
    (c: ReturnType<typeof salvoFixture>) => { c.report.statuses["429"] = 1; },
    (c: ReturnType<typeof salvoFixture>) => { c.server.reconcileInput.status503.unexplained = 1; },
    (c: ReturnType<typeof salvoFixture>) => { c.server.reconcileInput.egressFailed = 1; },
  ]) { const c = salvoFixture(); change(c); invalid(c); }
  for (const code of ["legitimate_journey_incomplete", "legitimate_refusal", "legitimate_l1_reject", "legitimate_l2_non_admit", "parity_mismatch", "recovery_failed", "evidence_gap", "accounting_mismatch"]) {
    const c = salvoFixture(); c.server.serverSide = { status: "invalid", failureClass: "measurement", reasons: [{ code }] }; invalid(c);
  }
});

test("source observer reconstructs bounded paired records from ordered source events, with correct drain and barriers", () => {
  const c = salvoFixture(); const observer = new SalvoServerObserver(n2ExerciseSpec(BA0_FIELD_C2_SALVO_V1));
  observer.arm(c.server.salvo!.phase.armed!); let seq = 0;
  const emit = (t: number, nonce: string, kind: PlaneEvent["kind"]) => observer.observe({ seq: ++seq, t, nonce, kind, ...(kind === "INGRESS_ACCEPTED" ? { ingress: "external" as const } : {}) });
  for (const p of pairRecords()) {
    emit(5001 + p.startsMs[0]!, `a${p.index}`, "INGRESS_ACCEPTED"); emit(5001 + p.startsMs[1]!, `b${p.index}`, "INGRESS_ACCEPTED");
    emit(5001 + p.settledMs[0]!, `a${p.index}`, "INGRESS_RESPONDED"); emit(5001 + p.settledMs[1]!, `b${p.index}`, "INGRESS_RESPONDED");
  }
  observer.close({ ...c.server.salvo!.phase.closed!, seq });
  const snapshot = observer.snapshotSalvo(); assert.deepEqual(snapshot.pairs, c.server.salvo!.pairs);
  assert.equal(snapshot.phase.inWindow, 1500); assert.equal(snapshot.phase.settledInWindow, 1500); assert.equal(snapshot.phase.faults, 0);
  c.server.salvo = snapshot; assert.equal(evaluate(c).decision.verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
  emit(71000, "extra", "INGRESS_ACCEPTED");
  assert.equal(observer.snapshotSalvo().pairs.length, 750); assert.ok(observer.snapshotSalvo().phase.faults > 0);
});

test("all salvo capacity and recovery gates pass without resizing; inherited defense parameters are exact", () => {
  const t = BA0_FIELD_C2_SALVO_V1; const gates = evaluateBudgetGates(t, 3600000);
  assert.deepEqual(failedGates(gates), []);
  assert.match(gates.find(g => g.id === "memory.total_budget")!.detail, /modeled 238.0 MiB/);
  assert.match(gates.find(g => g.id === "external.orphans_cover_stall")!.detail, /vs 528 /);
  assert.match(gates.find(g => g.id === "hop.replay_with_canary_and_burst")!.detail, /vs 832$/);
  for (const key of ["l2", "composer", "hop", "plane", "channel", "collector", "external", "allowedShed", "window", "canary", "recovery", "exposure", "telemetry", "ceilings"] as const) assert.deepEqual(t[key], BA0_FIELD_C2_V1[key], key);
  assert.equal(t.recovery.quietMs, 135000); assert.equal(t.canary.jcrMinimum, 1);
  assert.equal(ba0FieldFingerprint(t).sha256, "231a5ccd8574f3bb21d61ff160e424636076090bb451c7b43ef5651700ac400f");
  assert.equal(workloadFingerprint(WORKLOADS["ba0-l7-pressure-c2-salvo"]), "43ee3f7c0aaacea44384cc7e614eb58fe126bb042698417cf6c65f8f138d4264");
  for (const change of [
    (x: typeof t) => { x.channel.queueCap = 13727; }, (x: typeof t) => { x.hop.replayCapacity = 831; },
    (x: typeof t) => { x.external.maxActive = 401; }, (x: typeof t) => { x.external.maxOrphans = 527; },
    (x: typeof t) => { x.collector.maxJournalBytes = 1000000; }, (x: typeof t) => { x.recovery.quietMs--; },
    (x: typeof t) => { x.level.maxTotalRequests = 1501; },
  ]) { const copy = structuredClone(t); change(copy); assert.ok(failedGates(evaluateBudgetGates(copy)).length > 0); }
  assert.equal(SALVO_SPEC.pairs * SALVO_SPEC.requestsPerPair, 1500);
  writeFileSync(path.join(root, "artifacts", "lab", "salvo-capacity.json"), JSON.stringify({
    specimenBase: base, parameters: ba0FieldFingerprint(t), workloadSha256: workloadFingerprint(WORKLOADS["ba0-l7-pressure-c2-salvo"]),
    spec: SALVO_SPEC, gates,
    historical: { n1Parameters: ba0FieldFingerprint(BA0_FIELD_V1), c2Parameters: ba0FieldFingerprint(BA0_FIELD_C2_V1),
      n1WorkloadSha256: workloadFingerprint(WORKLOADS["ba0-l7-pressure-c1"]), c2WorkloadSha256: workloadFingerprint(WORKLOADS["ba0-l7-pressure-c2"]) },
  }, null, 2));
});

test("exact 0.5-ms separation and 0.75 residency boundaries pass; values below residency do not round into a pass", () => {
  const c = salvoFixture();
  for (const pairs of [c.report.salvo!.pairs, c.server.salvo!.pairs]) for (const p of pairs) {
    p.startsMs[1] = p.startsMs[0]! + .5; p.settledMs = [p.startsMs[0]! + 2, p.startsMs[1]! + 2];
  }
  refreshFixture(c); assert.equal(evaluate(c).decision.verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
  c.report.salvo!.pairs[0].settledMs[0]! -= .000001; refreshFixture(c);
  invalid(c, "g5.salvo_exercised");
});

test("real writer, checksums, offline parser and final artifact carry bounded evidence and separate completion/phase diagnostics", () => {
  const c = salvoFixture(); const bundle = buildSelftestBundle();
  bundle.level = { id: c.server.levelId, campaignId: c.server.campaignId, workers: 2 };
  bundle.parameters = ba0FieldFingerprint(BA0_FIELD_C2_SALVO_V1); bundle.thresholds = BA0_FIELD_C2_SALVO_V1;
  bundle.workloadSha256 = c.server.workloadFingerprintSha256; bundle.salvo = c.server.salvo;
  bundle.git = { gitSha: c.server.gitSha, dirty: false, dirtyFileCount: 0, untrackedFileCount: 0 };
  bundle.serverSide = { status: "complete", failureClass: null, reasons: [] }; bundle.window = c.server.window; bundle.reconcileInput = c.server.reconcileInput;
  const directory = mkdtempSync(path.join(root, "artifacts", "lab", "salvo-writer-"));
  try {
    const evidence = new EvidenceRun("field-selftest", "salvo", new Date(), directory);
    const written = writeFieldEvidence(evidence, bundle); assert.deepEqual(written.failed, []); assert.equal(written.written.length, 13);
    evidence.addJsonArtifact("generator-report.json", c.report);
    evidence.finalize({ git: bundle.git, environment: collectEnvironment(), target: null, workload: null, ceilings: null,
      thresholds: bundle.parameters, engine: "salvo-test", result: "SERVER-COMPLETE", resultReasons: [], metrics: {} });
    const outcome = reconcileLevel({ serverId: evidence.id, reportPath: path.join(evidence.directory, "generator-report.json") }, directory);
    assert.equal(outcome.verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
    const final = JSON.parse(readFileSync(path.join(directory, outcome.evidenceId!, "final.json"), "utf8"));
    assert.equal(final.salvo.completion.ok, true); assert.equal(final.salvo.phase.ok, true);
    assert.equal(final.salvo.generator.materialIndices.length, 750); assert.equal(final.salvo.matchingMaterialIndices, true);
  } finally {
    const resolved = path.resolve(directory);
    assert.ok(resolved.startsWith(path.resolve(root, "artifacts", "lab") + path.sep));
    rmSync(resolved, { recursive: true, force: true });
  }
});

function historicModule(file: string): Record<string, unknown> {
  const source = execFileSync("git", ["show", `${base}:${file}`], { cwd: root, encoding: "utf8" });
  const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  const exports: Record<string, unknown> = {};
  // Explicit statically imported dependencies: no runtime module loader or repository guard exception.
  const dependencies: Record<string, unknown> = {
    "node:crypto": { createHash }, "../../defense/core/lanes": { requiredLedgerCapacity },
    "../policy/thresholds": policyThresholds, "./origin-thresholds": { BA0_ORIGIN_LOCAL_V1 },
    "./external-reducer": { DEFAULT_EXTERNAL_LIMITS }, "./field-verdict": { decideFinal },
    "./generator-report": { workloadFingerprint }, "./field-thresholds": { BA0_FIELD_C2_V1, FIELD_LEVELS, ba0FieldFingerprint },
    "../policy/workloads": { WORKLOADS }, "./n2-measurement": { exercised, n2ExerciseSpec },
    "./reconcile": { SERVER_LEVEL_SCHEMA: "ba0-server-level-v1" }, "./exposure-proof": { EXPOSURE_STATEMENT },
  };
  new Function("require", "exports", compiled)((name: string) => {
    if (!Object.hasOwn(dependencies, name)) throw new Error("unreviewed historical dependency");
    return dependencies[name];
  }, exports);
  return exports;
}

test("exact aff793e historical C1/C2 parameters, workloads, budget outputs, report builder and reconcile results are immutable", () => {
  const oldT = historicModule("lab/defense/field-thresholds.ts") as unknown as typeof import("../lab/defense/field-thresholds");
  const oldW = historicModule("lab/policy/workloads.ts") as unknown as typeof import("../lab/policy/workloads");
  const oldR = historicModule("lab/defense/reconcile.ts") as unknown as typeof import("../lab/defense/reconcile");
  const oldG = historicModule("lab/defense/generator-report.ts") as unknown as typeof import("../lab/defense/generator-report");
  const oldE = historicModule("lab/defense/field-evidence.ts") as unknown as typeof import("../lab/defense/field-evidence");
  for (const [t, old] of [[BA0_FIELD_V1, oldT.BA0_FIELD_V1], [BA0_FIELD_C2_V1, oldT.BA0_FIELD_C2_V1]]) {
    assert.deepEqual(t, old); assert.deepEqual(evaluateBudgetGates(t), oldT.evaluateBudgetGates(old));
    const w = t.level.workers === 1 ? "ba0-l7-pressure-c1" : "ba0-l7-pressure-c2";
    assert.deepEqual(WORKLOADS[w], oldW.WORKLOADS[w]);
    const c = salvoFixture(); delete c.report.salvo; delete c.server.salvo;
    for (const side of [c.server, c.report]) { side.levelId = t.level.id; side.workers = t.level.workers;
      side.paramsFingerprintSha256 = ba0FieldFingerprint(t).sha256; side.workloadFingerprintSha256 = workloadFingerprint(WORKLOADS[w]); }
    c.report.concurrency.planned = t.level.workers;
    c.report.concurrency.maxInFlightObserved = c.server.reconcileInput.externalInFlightMax = t.level.workers;
    c.report.connections = { new: t.level.workers, reused: 1500 - t.level.workers };
    c.server.reconcileInput.connections.acceptedRemote = t.level.workers;
    if (t.level.workers === 2) {
      const exposure = () => ({ binMs: 1000, overlappingStarts: Array(60).fill(4), overlapMs: Array(60).fill(160) });
      c.report.n2 = { elapsedMs: 60000, firstDispatchMs: 0, lastDispatchMs: 59960, lastSettlementMs: 59990, exposure: exposure() };
      c.server.n2 = { ...salvoFixture().server.salvo!.phase, firstIngressMs: 5000, lastIngressMs: 64960, lastSettlementMs: 64990, exposure: exposure() };
    }
    for (const stop of ["completed", "total_ceiling", "operator_abort"]) {
      c.report.stop.kind = stop;
      assert.deepEqual(finalFrom(c.server, c.report, t.generator), oldR.finalFrom(c.server, c.report, t.generator));
      if (t.level.workers === 1 || stop === "completed") assert.equal(finalFrom(c.server, c.report, t.generator).decision.verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
    }
    const result = { ...c.report, workers: t.level.workers, wireBytesSent: 1, wireBytesReceived: 1, bodyBytesReceived: 1 } as unknown as Parameters<typeof buildGeneratorReport>[0]["result"];
    const input = { result, runId: c.report.runId, campaignId: c.report.campaignId, levelId: t.level.id, gitSha: c.report.gitSha,
      paramsFingerprintSha256: c.report.paramsFingerprintSha256, workload: WORKLOADS[w], targetId: "sut-test", ceilingRatePerSecond: 25 };
    assert.deepEqual(buildGeneratorReport(input), oldG.buildGeneratorReport(input));
    const bundle = buildSelftestBundle(); bundle.thresholds = t; bundle.parameters = ba0FieldFingerprint(t);
    bundle.level.id = t.level.id; bundle.level.workers = t.level.workers; bundle.workloadSha256 = workloadFingerprint(WORKLOADS[w]);
    if (t.level.workers === 2) bundle.n2 = c.server.n2;
    const capture = (writer: typeof writeFieldEvidence) => {
      const artifacts: Record<string, unknown> = {};
      writer({ addJsonArtifact: (name: string, value: unknown) => { assertEvidenceSafe(value); artifacts[name] = structuredClone(value); } } as EvidenceRun, bundle);
      return artifacts;
    };
    const beforeArtifacts = capture(oldE.writeFieldEvidence); const afterArtifacts = capture(writeFieldEvidence);
    assert.equal(Object.keys(afterArtifacts).length, 13); assert.deepEqual(afterArtifacts, beforeArtifacts);
  }
  const normalized = (s: string) => s.replace(/\r\n/g, "\n");
  const before = normalized(execFileSync("git", ["show", `${base}:lab/load/closed-loop.ts`], { encoding: "utf8" }));
  const after = normalized(readFileSync(path.join(root, "lab/load/closed-loop.ts"), "utf8"))
    .replace('  if (options.run.workload.id === "ba0-l7-pressure-c2-salvo") return executeSalvo(options);\n', "");
  assert.equal(after.slice(after.indexOf("export async function executeClosedLoop")), before.slice(before.indexOf("export async function executeClosedLoop")));
  assert.equal(execFileSync("git", ["diff", base, "--", "defense", "lab/defense/n2-measurement.ts"], { encoding: "utf8" }), "");
});

test("first-gcp-n2 authoritative values retain exactly the historical three failed identities and INVALID result", () => {
  const c = salvoFixture(); delete c.report.salvo; delete c.server.salvo;
  for (const side of [c.server, c.report]) {
    side.levelId = "ba0-l7-c2"; side.campaignId = "first-gcp-n2";
    side.paramsFingerprintSha256 = ba0FieldFingerprint(BA0_FIELD_C2_V1).sha256;
    side.workloadFingerprintSha256 = workloadFingerprint(WORKLOADS["ba0-l7-pressure-c2"]);
  }
  c.report.startedAt = "2026-10-07T17:19:42.165Z"; c.report.endedAt = "2026-10-07T17:20:42.212Z";
  c.report.wallClockSeconds = 60.05; c.report.stop.kind = "total_ceiling";
  c.report.concurrency.maxInFlightObserved = c.server.reconcileInput.externalInFlightMax = 1;
  c.report.connections = { new: 1, reused: 1499 }; c.server.reconcileInput.connections.acceptedRemote = 1;
  c.server.window = { openedAt: "2026-10-07T17:19:42.213Z", closedAt: "2026-10-07T17:20:50.215Z", elapsedMs: 68002 };
  const exposure = () => ({ binMs: 1000, overlapMs: Array(60).fill(0), overlappingStarts: Array(60).fill(0) });
  c.report.n2 = { elapsedMs: 60046.869124, firstDispatchMs: 1.068958, lastDispatchMs: 59959.977874, lastSettlementMs: 59962.94607, exposure: exposure() };
  c.server.n2 = {
    armed: { phase: "armed", seq: 552, atMs: 44906.919939, wallAt: "2026-10-07T17:19:38.296Z", acceptedExternal: 0, inFlightExternal: 0 },
    closed: { phase: "closed", seq: 14270, atMs: 116825.061249, wallAt: "2026-10-07T17:20:50.214Z", acceptedExternal: 1500, inFlightExternal: 0 },
    beforeArmed: 0, inWindow: 1500, afterClosed: 0, settledInWindow: 1500, inFlightAtClose: 0,
    firstIngressMs: 48789.980823, lastIngressMs: 108737.788243, lastSettlementMs: 108738.546035, faults: 0, exposure: exposure(),
  };
  const result = finalFrom(c.server, c.report, BA0_FIELD_C2_V1.generator);
  assert.equal(result.decision.verdict, "INVALID");
  assert.deepEqual(result.result.identities.filter(i => !i.ok).map(i => i.id), ["g6.n2_completion", "g5.n2_exercised", "g6.n2_measurement_phase"]);
  const old = historicModule("lab/defense/reconcile.ts") as unknown as typeof import("../lab/defense/reconcile");
  assert.deepEqual(result, old.finalFrom(c.server, c.report, BA0_FIELD_C2_V1.generator));
});
