import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { REPOSITORY_ROOT, verifyEvidenceDirectory, type EvidenceManifest } from "../lab/evidence/manifest";
import { runBa0, type Ba0Outcome } from "../lab/defense/ba0-run";
import { CORPUS_FIXED_COUNT } from "../lab/defense/hostile-corpus";
import { BA0_LOCAL_V1, ba0Fingerprint, type Ba0Thresholds } from "../lab/defense/thresholds";

const SMALL: Ba0Thresholds = { ...BA0_LOCAL_V1, journeys: { baselinePerLane: 3, postCorpusPerLane: 2 } };
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const json = <T>(outcome: Ba0Outcome, name: string): T => JSON.parse(readFileSync(path.join(outcome.evidenceDirectory, name), "utf8")) as T;
const cleanup = (outcome: Ba0Outcome) => rmSync(outcome.evidenceDirectory, { recursive: true, force: true });

test("a clean local baseline is BASELINE-VALID: JCR 100%, every lifecycle reconciled, every identity holds, and no defense PASS is claimed", { timeout: 120_000 }, async () => {
  const outcome = await runBa0({ thresholds: SMALL });
  try {
    assert.deepEqual(outcome.reasons, []);
    assert.equal(outcome.verdict, "BASELINE-VALID");
    assert.equal(outcome.anomalyTotal, 0);
    assert.equal(outcome.accounting.identitiesOk, true);
    const manifest = json<EvidenceManifest>(outcome, "manifest.json");
    assert.equal(manifest.result, "BASELINE-VALID");
    assert.notEqual(manifest.result, "PASS", "Slice 1 never claims a defense-qualification PASS");
    assert.equal((manifest.metrics as { defenseQualification: string }).defenseQualification, "not_claimed");
    assert.deepEqual(manifest.thresholds, ba0Fingerprint(SMALL));
    assert.deepEqual(verifyEvidenceDirectory(outcome.evidenceDirectory), []);

    const canary = json<{ journeyCompletionRate: { lane: string; phase: string; attempted: number; completed: number; rate: number }[]; parity: { mismatches: unknown[]; compared: number }; latency: { ok: boolean } }>(outcome, "canary.json");
    assert.equal(canary.journeyCompletionRate.length, 4);
    for (const entry of canary.journeyCompletionRate) { assert.equal(entry.rate, 1); assert.equal(entry.completed, entry.attempted); }
    assert.deepEqual(canary.parity.mismatches, []);
    assert.ok(canary.parity.compared > 0);
    assert.equal(canary.latency.ok, true);

    const corpus = json<{ executed: number; violations: number; fixedCount: number; outcomesByReason: { name: string; count: number }[] }>(outcome, "corpus.json");
    assert.equal(corpus.executed, CORPUS_FIXED_COUNT);
    assert.equal(corpus.violations, 0);
    assert.ok(corpus.outcomesByReason.some((row) => row.name === "parser_lane"));
    assert.ok(corpus.outcomesByReason.some((row) => row.name === "a7.body_too_large"));

    const resources = json<{ plane: Record<string, unknown>; not_measured: string[] }>(outcome, "resources.json");
    assert.equal(resources.plane.eventsDropped, 0);
    for (const name of ["n3.volumetric", "t4.transport", "pre_socket_loss"]) assert.ok(resources.not_measured.includes(name), name);
    const accounting = json<{ scope: string; eventChannel: { planeCrashed: string; lateEvents: number } }>(outcome, "accounting.json");
    assert.match(accounting.scope, /application plane only/);
    assert.match(accounting.scope, /implies nothing about network or transport health/);
    assert.equal(accounting.eventChannel.planeCrashed, "no");
    assert.equal(accounting.eventChannel.lateEvents, 0);
    assert.equal(outcome.accounting.l1.error, 0);
    assert.equal(outcome.accounting.origin.spoofedHeadersSeen, 0);
    assert.equal(outcome.accounting.origin.receivedWithoutL1Pass, 0);
    assert.deepEqual(outcome.accounting.residualHostileAtOrigin, { scope_semantic_invalid_email: 1, scope_missing_required_fields: 1, scope_wrong_origin: 1, spoof_internal_headers: 1, spoof_forwarding_headers: 1 }, "only the shape-valid and header-spoof cases reach the origin, and the spoofed headers were stripped");
  } finally { cleanup(outcome); }
});

test("the Defense Plane crashing mid-run is INVALID; what it delivered before the crash survives and the loss is detected", { timeout: 120_000 }, async () => {
  const outcome = await runBa0({
    thresholds: SMALL,
    hooks: { beforePhase: async (phase, handles) => { if (phase === "corpus") { handles.plane.crash(); await sleep(200); } } },
  });
  try {
    assert.equal(outcome.verdict, "INVALID");
    const codes = new Set(outcome.anomalies.map((anomaly) => anomaly.code));
    assert.ok(codes.has("plane_crashed"));
    assert.ok(codes.has("ingress_loss"), "requests sent to a dead plane are visible through the harness's own records");
    assert.ok(outcome.reasons.includes("ledger_anomalies_present"));
    const journal = readFileSync(path.join(outcome.evidenceDirectory, "ledger-journal.ndjson"), "utf8").trim().split("\n").map((line) => JSON.parse(line) as { src: string; k: string });
    assert.ok(journal.filter((entry) => entry.src === "p" && entry.k === "INGRESS_RESPONDED").length >= 12, "baseline plane events delivered before the crash survived");
    const manifest = json<EvidenceManifest>(outcome, "manifest.json");
    assert.equal(manifest.result, "INVALID");
  } finally { cleanup(outcome); }
});

test("an injected L1 exception is an explicit L1_ERROR that fails closed: it is accounted, answered 503 and never reaches egress", { timeout: 120_000 }, async () => {
  const outcome = await runBa0({
    thresholds: SMALL,
    hooks: { beforePhase: async (phase, handles) => { if (phase === "post_corpus") { handles.plane.injectFault("throw", 2); await sleep(150); } } },
  });
  try {
    assert.equal(outcome.accounting.l1.error, 2);
    assert.equal(outcome.accounting.l1.errorByKind.throw, 2);
    assert.equal(outcome.accounting.ingress.terminal.error, 2);
    assert.equal(outcome.accounting.egress.attempted, outcome.accounting.l1.passed, "an error never became a pass");
    assert.equal(outcome.anomalyTotal, 0, "the lifecycle is consistent: the fault is accounted for, not lost");
    assert.equal(outcome.accounting.identitiesOk, true);
    assert.equal(outcome.verdict, "INVALID");
    assert.ok(outcome.reasons.includes("jcr_below_minimum:protected.post_corpus"), outcome.reasons.join(","));
    const failed = outcome.journeys.filter((journey) => !journey.completed);
    assert.equal(failed.length, 2);
    for (const journey of failed) { assert.equal(journey.steps[0].status, 503); assert.equal(journey.lane, "protected"); }
  } finally { cleanup(outcome); }
});

test("an origin failure is attributed to egress (reset), separately from the L1 pass that preceded it, with no ledger anomaly", { timeout: 120_000 }, async () => {
  const outcome = await runBa0({
    thresholds: SMALL,
    hooks: { beforePhase: (phase, handles) => { if (phase === "baseline") handles.protectedOrigin.armFault({ kind: "reset", remaining: 2 }); } },
  });
  try {
    assert.equal(outcome.accounting.egress.failedByKind.reset, 2);
    assert.equal(outcome.accounting.egress.failed, 2);
    assert.equal(outcome.accounting.ingress.terminal.egress_failed, 2);
    assert.equal(outcome.accounting.delivery.egressFailedWithOriginReceipt, 2);
    assert.equal(outcome.anomalyTotal, 0);
    assert.equal(outcome.accounting.identitiesOk, true);
    assert.equal(outcome.verdict, "INVALID");
    assert.ok(outcome.reasons.includes("jcr_below_minimum:protected.baseline"));
  } finally { cleanup(outcome); }
});

test("lab:ba0 takes no arguments: anything is REFUSED before any socket is opened", () => {
  const result = spawnSync(process.execPath, [...process.execArgv, path.join(REPOSITORY_ROOT, "lab", "defense", "ba0-run.ts"), "--target", "x"], { cwd: REPOSITORY_ROOT, encoding: "utf8", timeout: 60_000 });
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stderr, /REFUSED/);
});
