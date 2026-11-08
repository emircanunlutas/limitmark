import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { REPEAT_EXIT, extractRun, m1Repeatability, parseRepeatArguments } from "../lab/defense/ba0-m1-repeatability";
import { GENERATOR_REPORT_SCHEMA, type GeneratorReport } from "../lab/defense/generator-report";
import { M1_SHED_SHARE_TOLERANCE_POINTS, evaluateRepeatability, repeatabilityWellFormed, type RepeatabilityRun } from "../lab/defense/m1-repeatability";
import { BASE_VERDICT_VALID } from "../lab/defense/m1-status-contract";
import { SERVER_LEVEL_SCHEMA, type ServerLevelEvidence } from "../lab/defense/reconcile";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState } from "../lab/evidence/manifest";

// Criterion 7: three independent runs of the same commit, parameters and fixture cycle, all base VALID, identical shed-reason sets, shed shares within +/-5 points
// of the median. Missing or malformed evidence is never acceptance.

const REASON = "mutation.unverified.lane_budget";
const run = (index: number, overrides: Partial<RepeatabilityRun> = {}): RepeatabilityRun => ({
  serverRunId: `server-run-${index}`, generatorRunId: `generator-run-${index}`, campaignId: `campaign-${index}`, levelId: "ba0-l7-c1", gitSha: "a".repeat(40), paramsFingerprintSha256: "b".repeat(64),
  workloadFingerprintSha256: "c".repeat(64), workers: 1, windowOpenedAt: `2026-11-0${index + 1}T10:00:00Z`, windowClosedAt: `2026-11-0${index + 1}T10:01:10Z`, baseVerdict: BASE_VERDICT_VALID,
  shedReasonCounts: { [REASON]: 20 }, externalAccepted: 100, status503Total: 20, ...overrides,
});
const three = (...overrides: Partial<RepeatabilityRun>[]): RepeatabilityRun[] => [0, 1, 2].map((index) => run(index, overrides[index] ?? {}));

test("PASS: three distinct sequential runs, same commit/parameters/fixture, all VALID, same shed reasons, shares inside tolerance", () => {
  const result = evaluateRepeatability(three({ status503Total: 20 }, { status503Total: 22 }, { status503Total: 24 }));
  assert.equal(result.outcome, "PASS");
  assert.equal(result.evaluated, true);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.details?.medianShedSharePct, 22);
  assert.equal(repeatabilityWellFormed(result), true);
});

test("the +/-5 point tolerance is inclusive at exactly 5 and rejects beyond it, measured from the MEDIAN of the three", () => {
  assert.equal(M1_SHED_SHARE_TOLERANCE_POINTS, 5);
  assert.equal(evaluateRepeatability(three({ status503Total: 20 }, { status503Total: 20 }, { status503Total: 25 })).outcome, "PASS", "median 20, deviation exactly 5");
  const out = evaluateRepeatability(three({ status503Total: 20 }, { status503Total: 20 }, { status503Total: 26 }));
  assert.equal(out.outcome, "REJECT");
  assert.deepEqual(out.reasons, ["m1.repeat.shed_share_outside_tolerance"]);
  assert.equal(evaluateRepeatability(three({ status503Total: 10 }, { status503Total: 20 }, { status503Total: 30 })).outcome, "REJECT", "spread of 10 each side of the median");
});

test("each independence / identity axis fails on its own, with its own reason", () => {
  const cases: Array<[string, Partial<RepeatabilityRun>[], string]> = [
    ["commit", [{}, { gitSha: "d".repeat(40) }, {}], "m1.repeat.commit_differs"],
    ["parameters", [{}, {}, { paramsFingerprintSha256: "e".repeat(64) }], "m1.repeat.parameters_differ"],
    ["fixture cycle", [{ workloadFingerprintSha256: "f".repeat(64) }, {}, {}], "m1.repeat.fixture_cycle_differs"],
    ["level", [{}, { levelId: "ba0-l7-c2" }, {}], "m1.repeat.level_differs"],
    ["workers", [{}, {}, { workers: 2 }], "m1.repeat.workers_differ"],
    ["server run ids", [{}, { serverRunId: "server-run-0" }, {}], "m1.repeat.server_run_ids_not_distinct"],
    ["campaign ids", [{}, {}, { campaignId: "campaign-0" }], "m1.repeat.campaign_ids_not_distinct"],
    ["generator run ids", [{ generatorRunId: "generator-run-1" }, {}, {}], "m1.repeat.generator_run_ids_not_distinct"],
    ["shed reasons", [{}, { shedReasonCounts: { [REASON]: 20, "open.open.other_reason": 1 } }, {}], "m1.repeat.shed_reason_sets_differ"],
  ];
  for (const [name, overrides, reason] of cases) {
    const result = evaluateRepeatability(three(...overrides));
    assert.equal(result.outcome, "REJECT", name);
    assert.deepEqual(result.reasons, [reason], name);
  }
});

test("every base verdict must be VALID: one INVALID or ABORTED run fails the set", () => {
  for (const verdict of ["INVALID", "ABORTED", "EXTERNAL-L7-QUALIFICATION-INVALID", ""]) {
    const result = evaluateRepeatability(three({}, { baseVerdict: verdict }, {}));
    assert.ok(result.outcome === "REJECT" && result.reasons.includes("m1.repeat.base_verdict_not_valid"), verdict);
  }
});

test("windows must be strictly sequential: overlapping, nested or merely touching windows are not independent runs; input order does not matter", () => {
  const touching = evaluateRepeatability(three({}, { windowOpenedAt: "2026-11-01T10:01:10Z", windowClosedAt: "2026-11-01T10:02:00Z" }, {}));
  assert.ok(touching.reasons.includes("m1.repeat.windows_overlap"), "closed == next opened is not strictly before");
  const nested = evaluateRepeatability(three({ windowOpenedAt: "2026-11-01T09:00:00Z", windowClosedAt: "2026-11-01T12:00:00Z" }, { windowOpenedAt: "2026-11-01T10:00:00Z" }, {}));
  assert.ok(nested.reasons.includes("m1.repeat.windows_overlap"));
  const shuffled = evaluateRepeatability([run(2), run(0), run(1)]);
  assert.equal(shuffled.outcome, "PASS");
});

test("a set that is not exactly three well-formed runs is ERROR, never acceptance", () => {
  for (const input of [null, undefined, "x", {}, [], [run(0)], [run(0), run(1)], [run(0), run(1), run(2), run(3)]]) {
    const result = evaluateRepeatability(input);
    assert.equal(result.outcome, "ERROR", JSON.stringify(input)?.slice(0, 40));
    assert.equal(result.evaluated, false);
    assert.equal(repeatabilityWellFormed(result), true);
  }
  const malformed: Array<Partial<RepeatabilityRun> | Record<string, unknown>> = [
    { gitSha: "xyz" }, { paramsFingerprintSha256: "short" }, { workers: 0 }, { workers: 1.5 }, { externalAccepted: -1 }, { status503Total: Number.NaN }, { windowOpenedAt: "yesterday" },
    { windowClosedAt: "2026-10-01T00:00:00Z" }, { shedReasonCounts: { "bad key": 1 } }, { shedReasonCounts: { [REASON]: -1 } }, { shedReasonCounts: [] }, { serverRunId: "has space" }, { baseVerdict: 7 }, { campaignId: "" },
  ];
  for (const overrides of malformed) assert.equal(evaluateRepeatability(three({}, overrides as Partial<RepeatabilityRun>, {})).outcome, "ERROR", JSON.stringify(overrides));
  assert.equal(evaluateRepeatability(three({}, { externalAccepted: 0 }, {})).outcome, "ERROR", "a run that accepted nothing has no shed share");
  assert.equal(evaluateRepeatability([run(0), null, run(2)]).outcome, "ERROR", "a run whose evidence could not be read is not skipped");
});

test("hostile input never throws and never passes", () => {
  const thrower = [run(0), run(1), { get serverRunId(): string { throw new Error("boom"); } }];
  assert.equal(evaluateRepeatability(thrower).outcome, "ERROR");
  assert.equal(evaluateRepeatability(new Proxy([], { get: () => { throw new Error("boom"); } })).outcome, "ERROR");
});

// ---- the CLI over real evidence directories
const summary = (p99 = 5) => ({ count: 100, min: 1, mean: 3, p50: 3, p90: 4, p95: 5, p99, max: p99 });
function level(index: number, shed = 20): { server: ServerLevelEvidence; report: GeneratorReport } {
  const campaign = `campaign-${index}`;
  const server: ServerLevelEvidence = {
    schema: SERVER_LEVEL_SCHEMA, campaignId: campaign, levelId: "ba0-l7-c1", gitSha: "a".repeat(40), paramsFingerprintSha256: "b".repeat(64), workloadFingerprintSha256: "c".repeat(64), workers: 1,
    serverSide: { status: "complete", failureClass: null, reasons: [] },
    window: { openedAt: `2026-11-0${index + 1}T10:00:00.000Z`, closedAt: `2026-11-0${index + 1}T10:01:10.000Z`, elapsedMs: 70_000 },
    reconcileInput: {
      externalAccepted: 100, statusHistogram: { "200": 100 - shed, "503": shed }, status503: { total: shed, expectedShed: shed, unexplained: 0 }, classes: { open: 75, mutation: 25 }, l1Rejected: 0, egressFailed: 0,
      connections: { acceptedRemote: 1, dropped: 0, clientErrorTotal: 0, clientErrorNoRequest: 0, parserRejected: 0, protocolRefused: 0 }, externalInFlightMax: 1,
    },
  };
  const report: GeneratorReport = {
    schema: GENERATOR_REPORT_SCHEMA, campaignId: campaign, levelId: "ba0-l7-c1", runId: `2026110${index + 1}T100000Z-load-aaaaa${index}`, gitSha: "a".repeat(40), paramsFingerprintSha256: "b".repeat(64),
    workloadFingerprintSha256: "c".repeat(64), targetId: "sut-test", workers: 1, startedAt: `2026-11-0${index + 1}T10:00:05.000Z`, endedAt: `2026-11-0${index + 1}T10:01:05.000Z`, wallClockSeconds: 60,
    attempted: 100, responses: 100, transportFailures: 0, outcomes: { ok: 100 - shed, http_5xx: shed }, statuses: { "200": 100 - shed, "503": shed },
    perFixture: { get_home: { attempted: 25, responses: 25, transportFailures: 0 }, get_privacy: { attempted: 25, responses: 25, transportFailures: 0 }, get_form: { attempted: 25, responses: 25, transportFailures: 0 }, post_inquiry: { attempted: 25, responses: 25, transportFailures: 0 } },
    latencyMs: summary(), bytes: { wireSent: 1, wireReceived: 1, contentReceived: 1 }, concurrency: { planned: 1, inFlightNow: 0, maxInFlightObserved: 1 }, connections: { new: 1, reused: 99 },
    rate: { achievedPerSecond: 1.7, ceilingPerSecond: 25 }, schedule: { paced: 100, lagMs: summary(3) }, generatorHealth: { eldP50Ms: 0, eldP99Ms: 2, eldMaxMs: 5, cpuUserMs: 10, cpuSystemMs: 5, rssMb: 60 },
    stop: { kind: "completed", detail: null }, retries: 0, pipelining: false,
  };
  return { server, report };
}
const testRoot = (): string => { const root = path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-m1rep-${process.pid}-${Math.random().toString(16).slice(2, 8)}`); fs.mkdirSync(root, { recursive: true }); return root; };
function write(root: string, tmp: string, index: number, shed = 20, mutate?: (server: ServerLevelEvidence, report: GeneratorReport) => void): { serverId: string; reportPath: string } {
  const { server, report } = level(index, shed);
  mutate?.(server, report);
  const evidence = new EvidenceRun("field-level", "ba0-l7-c1", new Date(), root);
  evidence.addJsonArtifact("server-level.json", server);
  evidence.addJsonArtifact("external.json", { counters: { l2: { shedByReason: { [REASON]: shed } } } });
  evidence.finalize({ git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: null, engine: "test", result: "SERVER-COMPLETE", resultReasons: [], metrics: {} });
  const dir = path.join(tmp, `run-${index}-${evidence.id}`); fs.mkdirSync(dir, { recursive: true });
  const reportPath = path.join(dir, "generator-report.json");
  fs.writeFileSync(reportPath, JSON.stringify(report));
  return { serverId: evidence.id, reportPath };
}
const readOut = (root: string, id: string): Record<string, unknown> => JSON.parse(fs.readFileSync(path.join(root, id, "m1-repeatability.json"), "utf8")) as Record<string, unknown>;

test("CLI round trip over three real finalized evidence directories: PASS, a new m1-repeatability.json, inputs untouched", () => {
  const root = testRoot(); const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "m1-rep-"));
  try {
    const runs = [write(root, tmp, 0, 20), write(root, tmp, 1, 22), write(root, tmp, 2, 24)];
    const extracted = extractRun(runs[0].serverId, runs[0].reportPath, root);
    assert.equal(extracted?.baseVerdict, BASE_VERDICT_VALID);
    assert.deepEqual(extracted?.shedReasonCounts, { [REASON]: 20 });
    const outcome = m1Repeatability({ runs }, root);
    assert.equal(outcome.exit, REPEAT_EXIT.pass, JSON.stringify(outcome.result));
    const written = readOut(root, outcome.evidenceId!);
    assert.deepEqual(written.repeatability, { evaluated: true, outcome: "PASS", reasons: [] });
    assert.equal(JSON.stringify(written).includes("M1-INVALID"), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("CLI: a run with a base INVALID, a missing evidence directory, a tampered directory or a bad report never produces acceptance", () => {
  const root = testRoot(); const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "m1-rep-"));
  try {
    const good = [write(root, tmp, 0), write(root, tmp, 1)];
    const invalid = write(root, tmp, 2, 20, (_server, report) => { report.attempted = 101; });
    const rejected = m1Repeatability({ runs: [...good, invalid] }, root);
    assert.equal(rejected.exit, REPEAT_EXIT.reject);
    assert.ok(rejected.result?.reasons.includes("m1.repeat.base_verdict_not_valid"));
    const missing = m1Repeatability({ runs: [...good, { serverId: "20260101T000000Z-nothing-000000", reportPath: good[0].reportPath }] }, root);
    assert.equal(missing.exit, REPEAT_EXIT.error);
    assert.deepEqual(missing.result?.reasons, ["m1.repeat.evidence_malformed_run"]);
    const third = write(root, tmp, 2);
    fs.appendFileSync(path.join(root, third.serverId, "external.json"), " ");
    assert.equal(m1Repeatability({ runs: [...good, third] }, root).exit, REPEAT_EXIT.error, "a tampered directory fails its checksums");
    const fourth = write(root, tmp, 2);
    fs.writeFileSync(fourth.reportPath, "{ not json");
    assert.equal(m1Repeatability({ runs: [...good, fourth] }, root).exit, REPEAT_EXIT.error);
    const same = m1Repeatability({ runs: [good[0], good[1], good[1]] }, root);
    assert.equal(same.exit, REPEAT_EXIT.reject, "the same execution counted twice is not three independent runs");
    assert.ok(same.result?.reasons.includes("m1.repeat.server_run_ids_not_distinct"));
  } finally { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("CLI arguments are strict: exactly three --server/--report pairs, nothing else", () => {
  const pair = (n: number) => ["--server", `20261006T10000${n}Z-level-aaaaa${n}`, "--report", `r${n}/generator-report.json`];
  assert.equal(parseRepeatArguments([...pair(1), ...pair(2), ...pair(3)]).runs.length, 3);
  for (const argv of [[], pair(1), [...pair(1), ...pair(2)], [...pair(1), ...pair(2), ...pair(3), ...pair(4)], ["--report", "r/generator-report.json", "--server", "20261006T100001Z-level-aaaaa1", ...pair(2), ...pair(3)],
    [...pair(1), ...pair(2), "--server", "20261006T100003Z-level-aaaaa3", "--report", "r3/other.json"], [...pair(1), ...pair(2), "--url", "x", "--report", "r3/generator-report.json"]]) assert.throws(() => parseRepeatArguments(argv), Error, JSON.stringify(argv).slice(0, 80));
});

test("source scan: read-only on inputs, no network or process access, and the VALID label is never re-spelled", () => {
  const sources = ["m1-repeatability.ts", "ba0-m1-repeatability.ts"].map((name) => fs.readFileSync(path.join(REPOSITORY_ROOT, "lab", "defense", name), "utf8")).join("\n");
  assert.equal(/writeFileSync|appendFileSync|unlinkSync|rmSync|renameSync|node:(?:http|https|net|child_process)/u.test(sources), false);
  assert.equal(sources.includes('"EXTERNAL-L7-QUALIFICATION-VALID"'), false);
});
