import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { M1_EXIT, m1Reconcile, parseM1Arguments } from "../lab/defense/ba0-m1-reconcile";
import { reconcileLevel } from "../lab/defense/ba0-field-reconcile";
import { GENERATOR_REPORT_SCHEMA, type GeneratorReport } from "../lab/defense/generator-report";
import { M1_ALLOWED_STATUSES, evaluateStatusOverlay, m1Accepted, overlayIsWellFormed, type OverlayInput } from "../lab/defense/m1-status-contract";
import { SERVER_LEVEL_SCHEMA, type ServerLevelEvidence } from "../lab/defense/reconcile";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState } from "../lab/evidence/manifest";

// M1 criterion 8 (owner decision, 2026-11-08): every client-visible status in both views is 200 or 503; every 503 is an attributed expected shed.
// The overlay adds no verdict category, never upgrades a base verdict and never turns unreadable evidence into a pass.

const VALID = "EXTERNAL-L7-QUALIFICATION-VALID";
const clean = (): OverlayInput => ({
  baseVerdict: VALID, generatorStatuses: { "200": 80, "503": 20 }, serverStatusHistogram: { "200": 80, "503": 20 }, serverStatus503: { total: 20, expectedShed: 20, unexplained: 0 },
});
const sorted = (values: string[]): string[] => [...values].sort();

test("pinned allow-list is exactly {200, 503} (302/303 and 403/404 are not claimed)", () => {
  assert.deepEqual([...M1_ALLOWED_STATUSES], ["200", "503"]);
  assert.equal(Object.isFrozen(M1_ALLOWED_STATUSES), true);
});

// ---- A: clean fixture
test("A: a clean fixture (200 and attributed shed 503 only, base VALID) is PASS, evaluated, no reasons, and accepted", () => {
  const overlay = evaluateStatusOverlay(clean());
  assert.deepEqual(overlay, { evaluated: true, outcome: "PASS", reasons: [] });
  assert.equal(overlayIsWellFormed(overlay), true);
  assert.equal(m1Accepted(VALID, overlay), true);
  assert.equal(evaluateStatusOverlay({ ...clean(), generatorStatuses: { "200": 100 }, serverStatusHistogram: { "200": 100 }, serverStatus503: { total: 0, expectedShed: 0, unexplained: 0 } }).outcome, "PASS", "no shed at all is fine");
});

// ---- B: each foreign status, in either view, is REJECT naming the view
const FOREIGN = ["302", "303", "400", "403", "404", "413", "429", "500", "502", "504", "999"];
test("B: each of 11 foreign statuses injected into the generator view or the server view is REJECT with the matching reason (22 cases)", () => {
  for (const status of FOREIGN) {
    const generator = evaluateStatusOverlay({ ...clean(), generatorStatuses: { "200": 79, "503": 20, [status]: 1 } });
    assert.equal(generator.outcome, "REJECT", `generator ${status}`);
    assert.ok(generator.reasons.includes("m1.status_allowlist_generator"), `generator ${status}`);
    const serverSide = evaluateStatusOverlay({ ...clean(), serverStatusHistogram: { "200": 79, "503": 20, [status]: 1 } });
    assert.equal(serverSide.outcome, "REJECT", `server ${status}`);
    assert.ok(serverSide.reasons.includes("m1.status_allowlist_server"), `server ${status}`);
    for (const overlay of [generator, serverSide]) { assert.equal(overlay.evaluated, true); assert.equal(overlayIsWellFormed(overlay), true); assert.equal(m1Accepted(VALID, overlay), false); }
  }
});

test("B2: a foreign status with a zero count is not an observed status; a 3xx-looking key that never occurred does not reject", () => {
  assert.equal(evaluateStatusOverlay({ ...clean(), generatorStatuses: { "200": 80, "503": 20, "302": 0 } }).outcome, "PASS");
});

// ---- C: 503 attribution
test("C: an unattributed 503 or any 503 the server does not account as an expected shed is REJECT", () => {
  const unexplained = evaluateStatusOverlay({ ...clean(), serverStatus503: { total: 20, expectedShed: 19, unexplained: 1 } });
  assert.equal(unexplained.outcome, "REJECT");
  assert.deepEqual(sorted(unexplained.reasons), sorted(["m1.shed_unattributed", "m1.shed_total_not_expected", "m1.generator_503_not_attributed"]));
  const otherCause = evaluateStatusOverlay({ ...clean(), serverStatus503: { total: 20, expectedShed: 0, unexplained: 0 } });
  assert.equal(otherCause.outcome, "REJECT");
  assert.ok(otherCause.reasons.includes("m1.shed_total_not_expected"));
  assert.equal(evaluateStatusOverlay({ ...clean(), generatorStatuses: { "200": 79, "503": 21 } }).outcome, "REJECT", "generator saw a 503 the server did not attribute");
  assert.equal(evaluateStatusOverlay({ ...clean(), serverStatusHistogram: { "200": 79, "503": 21 } }).outcome, "REJECT", "server histogram disagrees with its own 503 total");
});

// ---- D: base verdict
test("D: a base INVALID or ABORTED can never be accepted, even when the status evidence is clean; the overlay never upgrades", () => {
  for (const base of ["INVALID", "ABORTED"]) {
    const overlay = evaluateStatusOverlay({ ...clean(), baseVerdict: base });
    assert.equal(overlay.outcome, "REJECT");
    assert.deepEqual(overlay.reasons, ["m1.base_verdict_not_valid"]);
    assert.equal(m1Accepted(base, overlay), false);
    assert.equal(m1Accepted(base, { evaluated: true, outcome: "PASS", reasons: [] }), false, "even a hand-written PASS cannot rescue a non-VALID base");
  }
  assert.equal(m1Accepted(VALID, { evaluated: true, outcome: "REJECT", reasons: ["m1.x"] }), false);
});

// ---- E: the all-404 origin (the audit's N-1 case)
test("E: an origin that answers 404 to everything is REJECT in both views", () => {
  const overlay = evaluateStatusOverlay({ baseVerdict: VALID, generatorStatuses: { "404": 100 }, serverStatusHistogram: { "404": 100 }, serverStatus503: { total: 0, expectedShed: 0, unexplained: 0 } });
  assert.equal(overlay.outcome, "REJECT");
  assert.ok(overlay.reasons.includes("m1.status_allowlist_generator") && overlay.reasons.includes("m1.status_allowlist_server"));
});

// ---- malformed or missing evidence is ERROR, never PASS
test("malformed evidence is ERROR (evaluated = false, reasons non-empty) and never PASS, for every field and every malformed shape", () => {
  const BAD: unknown[] = [null, undefined, "x", 7, true, [], [["200", 1]], { "200": -1 }, { "200": 1.5 }, { "200": "5" }, { "200": Number.NaN }, { "200": Infinity }, { abc: 1 }, { "2000": 1 }, { "": 1 }, { "200": 2 ** 60 }];
  const fields: Array<[keyof OverlayInput, string]> = [["generatorStatuses", "generator_statuses"], ["serverStatusHistogram", "server_status_histogram"]];
  for (const [field, name] of fields) for (const bad of BAD) {
    const overlay = evaluateStatusOverlay({ ...clean(), [field]: bad });
    assert.equal(overlay.outcome, "ERROR", `${field}=${String(JSON.stringify(bad))}`);
    assert.equal(overlay.evaluated, false);
    assert.ok(overlay.reasons.some((reason) => reason.endsWith(name)), `${field}: ${overlay.reasons.join(",")}`);
    assert.equal(overlayIsWellFormed(overlay), true);
    assert.equal(m1Accepted(VALID, overlay), false);
  }
  const BAD_SHED: unknown[] = [null, undefined, [], "x", {}, { total: 1 }, { total: 1, expectedShed: 1 }, { total: -1, expectedShed: 0, unexplained: 0 }, { total: "1", expectedShed: 1, unexplained: 0 }, { total: 1.5, expectedShed: 1, unexplained: 0 }, { total: Number.NaN, expectedShed: 0, unexplained: 0 }];
  for (const bad of BAD_SHED) {
    const overlay = evaluateStatusOverlay({ ...clean(), serverStatus503: bad });
    assert.equal(overlay.outcome, "ERROR", JSON.stringify(bad));
    assert.ok(overlay.reasons.includes("m1.evidence_malformed.server_status503"));
  }
  for (const bad of [null, undefined, "", "VALID", "valid", 0, {}, "EXTERNAL-L7-QUALIFICATION-INVALID"]) {
    const overlay = evaluateStatusOverlay({ ...clean(), baseVerdict: bad });
    assert.equal(overlay.outcome, "ERROR", String(bad));
    assert.ok(overlay.reasons.includes("m1.evidence_malformed.base_verdict"));
  }
  assert.deepEqual(evaluateStatusOverlay({ ...clean(), generatorStatuses: undefined }).reasons, ["m1.evidence_missing.generator_statuses"], "no generator report: the generator view is missing, which is ERROR");
  assert.equal(evaluateStatusOverlay(null as unknown as OverlayInput).outcome, "ERROR", "a non-object input cannot throw out of the evaluator");
  assert.equal(evaluateStatusOverlay(undefined as unknown as OverlayInput).outcome, "ERROR");
});

test("hostile object shapes (prototype tricks, getters that throw) are ERROR, never a throw and never PASS", () => {
  const thrower = { get "200"(): number { throw new Error("boom"); } };
  assert.equal(evaluateStatusOverlay({ ...clean(), generatorStatuses: thrower }).outcome, "ERROR");
  class Weird { "200" = 1; }
  assert.equal(evaluateStatusOverlay({ ...clean(), generatorStatuses: new Weird() }).outcome, "ERROR", "non-plain objects are not evidence");
  const proxy = new Proxy({}, { ownKeys: () => { throw new Error("boom"); } });
  assert.equal(evaluateStatusOverlay({ ...clean(), serverStatusHistogram: proxy }).outcome, "ERROR");
  assert.equal(evaluateStatusOverlay(JSON.parse('{"baseVerdict":"EXTERNAL-L7-QUALIFICATION-VALID","generatorStatuses":{"__proto__":{"200":1}},"serverStatusHistogram":{"200":1},"serverStatus503":{"total":0,"expectedShed":0,"unexplained":0}}')).outcome, "ERROR");
});

// ---- schema invariants
test("schema invariants: PASS => evaluated and empty reasons; REJECT => evaluated and reasons; ERROR => not evaluated and reasons; no extra keys", () => {
  assert.equal(overlayIsWellFormed({ evaluated: true, outcome: "PASS", reasons: [] }), true);
  assert.equal(overlayIsWellFormed({ evaluated: true, outcome: "REJECT", reasons: ["m1.status_allowlist_generator"] }), true);
  assert.equal(overlayIsWellFormed({ evaluated: false, outcome: "ERROR", reasons: ["m1.evaluation_failed"] }), true);
  for (const bad of [
    { evaluated: true, outcome: "PASS", reasons: ["m1.x"] }, { evaluated: false, outcome: "PASS", reasons: [] }, { evaluated: true, outcome: "REJECT", reasons: [] },
    { evaluated: false, outcome: "REJECT", reasons: ["m1.x"] }, { evaluated: true, outcome: "ERROR", reasons: ["m1.x"] }, { evaluated: false, outcome: "ERROR", reasons: [] },
    { evaluated: true, outcome: "VALID", reasons: [] }, { evaluated: true, outcome: "INVALID", reasons: ["m1.x"] }, { evaluated: true, outcome: "PASS", reasons: [], extra: 1 },
    { evaluated: "true", outcome: "PASS", reasons: [] }, { evaluated: true, outcome: "PASS" }, null, [], "PASS", { evaluated: false, outcome: "ERROR", reasons: ["not namespaced"] },
  ]) assert.equal(overlayIsWellFormed(bad), false, JSON.stringify(bad));
});

// ---- the CLI: round trip over REAL evidence directories written by the real EvidenceRun (so the evidence scanner is exercised)
const summary = (p99 = 5) => ({ count: 100, min: 1, mean: 3, p50: 3, p90: 4, p95: 5, p99, max: p99 });
function consistent(): { server: ServerLevelEvidence; report: GeneratorReport } {
  const server: ServerLevelEvidence = {
    schema: SERVER_LEVEL_SCHEMA, campaignId: "campaign-one", levelId: "ba0-l7-c1", gitSha: "a".repeat(40), paramsFingerprintSha256: "b".repeat(64), workloadFingerprintSha256: "c".repeat(64), workers: 1,
    serverSide: { status: "complete", failureClass: null, reasons: [] },
    window: { openedAt: "2026-10-06T10:00:00.000Z", closedAt: "2026-10-06T10:01:10.000Z", elapsedMs: 70_000 },
    reconcileInput: {
      externalAccepted: 100, statusHistogram: { "200": 80, "503": 20 }, status503: { total: 20, expectedShed: 20, unexplained: 0 }, classes: { open: 75, mutation: 25 }, l1Rejected: 0, egressFailed: 0,
      connections: { acceptedRemote: 1, dropped: 0, clientErrorTotal: 0, clientErrorNoRequest: 0, parserRejected: 0, protocolRefused: 0 }, externalInFlightMax: 1,
    },
  };
  const report: GeneratorReport = {
    schema: GENERATOR_REPORT_SCHEMA, campaignId: "campaign-one", levelId: "ba0-l7-c1", runId: "20261006T100000Z-load-aaaaaa", gitSha: "a".repeat(40), paramsFingerprintSha256: "b".repeat(64),
    workloadFingerprintSha256: "c".repeat(64), targetId: "sut-test", workers: 1, startedAt: "2026-10-06T10:00:05.000Z", endedAt: "2026-10-06T10:01:05.000Z", wallClockSeconds: 60,
    attempted: 100, responses: 100, transportFailures: 0, outcomes: { ok: 80, http_5xx: 20 }, statuses: { "200": 80, "503": 20 },
    perFixture: { get_home: { attempted: 25, responses: 25, transportFailures: 0 }, get_privacy: { attempted: 25, responses: 25, transportFailures: 0 }, get_form: { attempted: 25, responses: 25, transportFailures: 0 }, post_inquiry: { attempted: 25, responses: 25, transportFailures: 0 } },
    latencyMs: summary(), bytes: { wireSent: 1, wireReceived: 1, contentReceived: 1 }, concurrency: { planned: 1, inFlightNow: 0, maxInFlightObserved: 1 }, connections: { new: 1, reused: 99 },
    rate: { achievedPerSecond: 1.7, ceilingPerSecond: 25 }, schedule: { paced: 100, lagMs: summary(3) }, generatorHealth: { eldP50Ms: 0, eldP99Ms: 2, eldMaxMs: 5, cpuUserMs: 10, cpuSystemMs: 5, rssMb: 60 },
    stop: { kind: "completed", detail: null }, retries: 0, pipelining: false,
  };
  return { server, report };
}
const sha = (file: string): string => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const testRoot = (): string => { const root = path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-m1-${process.pid}-${Math.random().toString(16).slice(2, 8)}`); fs.mkdirSync(root, { recursive: true }); return root; };
function serverEvidence(root: string, server: unknown): string {
  const evidence = new EvidenceRun("field-level", "ba0-l7-c1", new Date(), root);
  evidence.addJsonArtifact("server-level.json", server as Record<string, unknown>);
  evidence.finalize({ git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: null, engine: "test", result: "SERVER-COMPLETE", resultReasons: [], metrics: {} });
  return evidence.id;
}
const readVerdict = (root: string, id: string): Record<string, unknown> => JSON.parse(fs.readFileSync(path.join(root, id, "m1-verdict.json"), "utf8")) as Record<string, unknown>;

test("CLI round trip: a VALID base plus a clean overlay is PASS/accepted, writes m1-verdict.json, and leaves the historical final.json byte-identical", () => {
  const root = testRoot(); const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "m1-report-"));
  try {
    const { server, report } = consistent();
    const id = serverEvidence(root, server);
    const reportPath = path.join(tmp, "generator-report.json");
    fs.writeFileSync(reportPath, JSON.stringify(report));
    const historical = reconcileLevel({ serverId: id, reportPath }, root);
    assert.equal(historical.verdict, VALID);
    const finalFile = path.join(root, historical.evidenceId!, "final.json");
    const finalSha = sha(finalFile);
    const overlay = m1Reconcile({ serverId: id, reportPath, finalId: historical.evidenceId }, root);
    assert.equal(overlay.exit, M1_EXIT.pass);
    assert.equal(overlay.accepted, true);
    assert.equal(overlay.baseVerdict, VALID);
    assert.equal(sha(finalFile), finalSha, "the historical final.json is untouched");
    const written = readVerdict(root, overlay.evidenceId!);
    assert.deepEqual(written.statusOverlay, { evaluated: true, outcome: "PASS", reasons: [] });
    assert.equal(written.baseVerdict, VALID);
    assert.equal(written.m1StatusContract, "accepted");
    assert.equal(JSON.stringify(written).includes("M1-INVALID"), false, "no new historical verdict category");
    assert.equal(Object.hasOwn(written, "finalVerdict"), false, "the overlay does not restate a final verdict");
    const manifest = JSON.parse(fs.readFileSync(path.join(root, overlay.evidenceId!, "manifest.json"), "utf8")) as { result: string };
    assert.equal(manifest.result, "PASS");
    assert.equal(fs.existsSync(path.join(root, overlay.evidenceId!, "final.json")), false, "no final.json is written by the overlay");
  } finally { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("CLI: foreign statuses (an all-404 origin) are REJECT and not accepted; a base INVALID is never accepted; both still keep the base reason visible via the unchanged historical verdict", () => {
  const root = testRoot(); const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "m1-report-"));
  try {
    const { server, report } = consistent();
    server.reconcileInput.statusHistogram = { "404": 100 }; server.reconcileInput.status503 = { total: 0, expectedShed: 0, unexplained: 0 };
    report.statuses = { "404": 100 }; report.outcomes = { http_4xx: 100 };
    const id = serverEvidence(root, server);
    const reportPath = path.join(tmp, "generator-report.json");
    fs.writeFileSync(reportPath, JSON.stringify(report));
    const overlay = m1Reconcile({ serverId: id, reportPath, finalId: null }, root);
    assert.equal(overlay.exit, M1_EXIT.reject);
    assert.equal(overlay.accepted, false);
    assert.equal(overlay.overlay?.outcome, "REJECT");
    assert.ok(overlay.reasons.includes("m1.status_allowlist_generator") && overlay.reasons.includes("m1.status_allowlist_server"));
    assert.equal(readVerdict(root, overlay.evidenceId!).m1StatusContract, "not_accepted");
    // base INVALID (generator disagrees with the ledger) with clean statuses
    const other = consistent();
    other.report.attempted = 101;
    const id2 = serverEvidence(root, other.server);
    fs.writeFileSync(reportPath, JSON.stringify(other.report));
    const invalid = m1Reconcile({ serverId: id2, reportPath, finalId: null }, root);
    assert.equal(invalid.baseVerdict, "INVALID");
    assert.equal(invalid.accepted, false);
    assert.equal(invalid.exit, M1_EXIT.reject);
    assert.ok(invalid.reasons.includes("m1.base_verdict_not_valid"));
    assert.equal(reconcileLevel({ serverId: id2, reportPath }, root).verdict, "INVALID", "the historical verdict is unchanged by the overlay");
  } finally { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("CLI: malformed evidence and a failed cross-check are ERROR (exit 4, never PASS); unusable inputs are REFUSED (exit 2) with no artifact", () => {
  const root = testRoot(); const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "m1-report-"));
  try {
    const reportPath = path.join(tmp, "generator-report.json");
    // malformed server histogram
    const bad = consistent();
    (bad.server.reconcileInput as unknown as Record<string, unknown>).statusHistogram = "not a histogram";
    const idBad = serverEvidence(root, bad.server);
    fs.writeFileSync(reportPath, JSON.stringify(bad.report));
    const malformed = m1Reconcile({ serverId: idBad, reportPath, finalId: null }, root);
    assert.equal(malformed.exit, M1_EXIT.error);
    assert.equal(malformed.overlay?.outcome, "ERROR");
    assert.equal(malformed.overlay?.evaluated, false);
    assert.equal(malformed.accepted, false);
    // generator report that is not a report
    const good = consistent();
    const idGood = serverEvidence(root, good.server);
    fs.writeFileSync(reportPath, "{ not json");
    const unparsable = m1Reconcile({ serverId: idGood, reportPath, finalId: null }, root);
    assert.equal(unparsable.exit, M1_EXIT.error);
    assert.equal(unparsable.accepted, false);
    // cross-check against a recorded final that says something else
    fs.writeFileSync(reportPath, JSON.stringify(good.report));
    const otherReport = { ...good.report, attempted: 101 };
    const otherPath = path.join(tmp, "other", "generator-report.json"); fs.mkdirSync(path.dirname(otherPath), { recursive: true }); fs.writeFileSync(otherPath, JSON.stringify(otherReport));
    const recordedInvalid = reconcileLevel({ serverId: idGood, reportPath: otherPath }, root);
    assert.equal(recordedInvalid.verdict, "INVALID");
    const mismatch = m1Reconcile({ serverId: idGood, reportPath, finalId: recordedInvalid.evidenceId }, root);
    assert.equal(mismatch.exit, M1_EXIT.error);
    assert.equal(mismatch.accepted, false);
    assert.ok(mismatch.reasons.includes("m1.base_verdict_cross_check_failed"));
    // refusals
    assert.equal(m1Reconcile({ serverId: "20260101T000000Z-nothing-000000", reportPath, finalId: null }, root).exit, M1_EXIT.refused);
    assert.equal(m1Reconcile({ serverId: idGood, reportPath: path.join(tmp, "missing", "generator-report.json"), finalId: null }, root).exit, M1_EXIT.refused);
    assert.equal(m1Reconcile({ serverId: idGood, reportPath, finalId: null }, root).exit, M1_EXIT.pass, "the same good inputs still pass");
  } finally { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("CLI arguments are strict: --server and --report are required, only --final is optional, no other flag, no duplicates", () => {
  assert.deepEqual(parseM1Arguments(["--server", "20261006T100000Z-level-aaaaaa", "--report", "x/generator-report.json"]), { serverId: "20261006T100000Z-level-aaaaaa", reportPath: "x/generator-report.json", finalId: null });
  assert.equal(parseM1Arguments(["--server", "20261006T100000Z-level-aaaaaa", "--report", "g/generator-report.json", "--final", "20261006T100000Z-final-bbbbbb"]).finalId, "20261006T100000Z-final-bbbbbb");
  for (const argv of [[], ["--server", "20261006T100000Z-level-aaaaaa"], ["--report", "g/generator-report.json"], ["--server", "x", "--report", "g/generator-report.json"],
    ["--server", "20261006T100000Z-level-aaaaaa", "--report", "g/other.json"], ["--server", "20261006T100000Z-level-aaaaaa", "--report", "g/generator-report.json", "--url", "http://x"],
    ["--server", "20261006T100000Z-level-aaaaaa", "--server", "20261006T100000Z-level-bbbbbb", "--report", "g/generator-report.json"]]) assert.throws(() => parseM1Arguments(argv), Error, JSON.stringify(argv));
});

// ---- the evidence scanner and the pinned-file integrity
test("the overlay artifact passes the real evidence scanner (it was written through EvidenceRun) and contains only closed keys", () => {
  const root = testRoot(); const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "m1-report-"));
  try {
    const { server, report } = consistent();
    const id = serverEvidence(root, server);
    const reportPath = path.join(tmp, "generator-report.json");
    fs.writeFileSync(reportPath, JSON.stringify(report));
    const outcome = m1Reconcile({ serverId: id, reportPath, finalId: null }, root);
    assert.notEqual(outcome.evidenceId, null);
    const written = readVerdict(root, outcome.evidenceId!);
    assert.deepEqual(Object.keys(written).sort(), ["allowedStatuses", "baseVerdict", "claims", "contract", "inputs", "m1StatusContract", "scope", "statusOverlay"]);
    assert.equal(written.allowedStatuses, "200,503");
  } finally { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("pinned-file integrity: the overlay lives in two NEW files outside every byte-pinned pathspec, and no pinned reconciliation file differs from the baselines or HEAD", () => {
  const git = (...args: string[]): string => execFileSync("git", args, { cwd: REPOSITORY_ROOT, encoding: "utf8" });
  for (const file of ["lab/defense/m1-status-contract.ts", "lab/defense/ba0-m1-reconcile.ts"]) {
    for (const baseline of ["64ccc9d", "dcf10af8", "aff793e"]) assert.throws(() => git("cat-file", "-e", `${baseline}:${file}`), Error, `${file} must not exist at ${baseline}`);
  }
  const guardSources = ["lab-ba0-canary-continuity", "lab-ba0-salvo-diagnostics", "lab-ba0-salvo"].map((name) => fs.readFileSync(path.join(REPOSITORY_ROOT, "tests", `${name}.test.ts`), "utf8")).join("\n");
  assert.equal(/m1-status-contract|ba0-m1-reconcile/u.test(guardSources), false, "no historical guard names the overlay files");
  const pinned = ["lab/defense/reconcile.ts", "lab/defense/ba0-field-reconcile.ts", "lab/defense/field-thresholds.ts", "lab/policy/workloads.ts", "lab/defense/field-verdict.ts"];
  for (const file of pinned) {
    const working = git("hash-object", file).trim();
    for (const baseline of ["64ccc9d"]) assert.equal(git("rev-parse", `${baseline}:${file}`).trim(), working, `${file} is byte-identical to ${baseline}`);
  }
  for (const baseline of ["64ccc9d", "dcf10af8", "aff793e"]) assert.equal(git("diff", "--name-only", baseline, "--", "lab/policy", "lab/evidence").split("\n").filter((line) => line.includes("m1-")).length, 0);
});

test("source scan: the overlay only reads pinned modules (imports finalFrom and types) and never writes to a final evidence file", () => {
  const cli = fs.readFileSync(path.join(REPOSITORY_ROOT, "lab", "defense", "ba0-m1-reconcile.ts"), "utf8");
  const pure = fs.readFileSync(path.join(REPOSITORY_ROOT, "lab", "defense", "m1-status-contract.ts"), "utf8");
  assert.equal(/final\.json["'`]\s*,\s*[^)]*\)\s*;?\s*$/mu.test(cli) && /writeFileSync|addJsonArtifact\("final\.json"/u.test(cli), false);
  assert.equal(/addJsonArtifact\("final\.json"/u.test(cli), false, "the overlay never writes final.json");
  assert.equal(/writeFileSync|appendFileSync|node:(?:http|https|net|child_process)/u.test(pure + cli), false, "no file writes of its own, no network, no process");
  assert.equal(/\bimport\b[^;]*from "(?:node:fs|node:child_process)"/u.test(pure), false, "the pure module imports no I/O");
});
