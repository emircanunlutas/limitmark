import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { reconcileLevel, parseReconcileArguments } from "../lab/defense/ba0-field-reconcile";
import { BA0_FIELD_V1 } from "../lab/defense/field-thresholds";
import { GENERATOR_REPORT_SCHEMA, parseGeneratorReport, type GeneratorReport } from "../lab/defense/generator-report";
import { SERVER_LEVEL_SCHEMA, finalFrom, reconcile, type ServerLevelEvidence } from "../lab/defense/reconcile";
import { EvidenceRun, collectEnvironment, collectGitState, REPOSITORY_ROOT } from "../lab/evidence/manifest";

const LIMITS = BA0_FIELD_V1.generator;
const summary = (p99 = 5) => ({ count: 100, min: 1, mean: 3, p50: 3, p90: 4, p95: 5, p99, max: p99 });

/** A level whose two views agree exactly: 100 requests, 75 reads and 25 POSTs, 5 POSTs admitted, 20 shed with an expected L2 shed. */
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

const codes = (server: ServerLevelEvidence, report: GeneratorReport | null): string[] => reconcile(server, report, LIMITS).reasons.map((reason) => reason.code);
const failedIds = (server: ServerLevelEvidence, report: GeneratorReport): string[] => reconcile(server, report, LIMITS).identities.filter((entry) => !entry.ok).map((entry) => entry.id);

test("two views that agree produce no reasons, every identity holds, and the final verdict is VALID", () => {
  const { server, report } = consistent();
  const result = reconcile(server, report, LIMITS);
  assert.deepEqual(result.reasons, []);
  assert.deepEqual(result.identities.filter((entry) => !entry.ok), []);
  assert.equal(result.informational.windowConsistent, true);
  assert.match(result.informational.clockSkewAssumption, /not measured/);
  assert.equal(finalFrom(server, report, LIMITS).decision.verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
});

test("no generator report can only be INVALID (a measurement failure), never VALID", () => {
  const { server } = consistent();
  assert.deepEqual(codes(server, null), ["generator_report_missing"]);
  assert.equal(finalFrom(server, null, LIMITS).decision.verdict, "INVALID");
});

test("G1: the generator's attempts must equal the server's external ingress plus pre-ingress losses, exactly when the generator reports no ambiguity", () => {
  const { server, report } = consistent();
  server.reconcileInput.externalAccepted = 99;
  assert.ok(failedIds(server, report).includes("g1.attempted_equals_ingress_plus_preingress"));
  assert.ok(codes(server, report).includes("unexplained_traffic"));
  const extra = consistent();
  extra.server.reconcileInput.externalAccepted = 101;
  assert.ok(codes(extra.server, extra.report).includes("unexplained_traffic"), "the server saw MORE than the generator sent");
});

test("G1: a request the generator cannot place (a timeout or reset) is tolerated by the identity but still makes the level INVALID (N_amb must be zero)", () => {
  const { server, report } = consistent();
  report.transportFailures = 1;
  report.outcomes = { ok: 80, http_5xx: 19, timeout: 1 };
  report.statuses = { "200": 80, "503": 19 };
  report.perFixture.post_inquiry = { attempted: 25, responses: 24, transportFailures: 1 };
  server.reconcileInput.externalAccepted = 99;
  server.reconcileInput.statusHistogram = { "200": 80, "503": 19 };
  server.reconcileInput.status503 = { total: 19, expectedShed: 19, unexplained: 0 };
  server.reconcileInput.classes = { open: 75, mutation: 24 };
  assert.equal(failedIds(server, report).includes("g1.attempted_equals_ingress_plus_preingress"), false, "within the ambiguity");
  assert.ok(codes(server, report).includes("generator_ambiguity"));
  assert.equal(finalFrom(server, report, LIMITS).decision.verdict, "INVALID");
  assert.equal(finalFrom(server, report, LIMITS).decision.failureClass, "measurement");
});

test("G1: pre-ingress losses on the server (a parser or protocol refusal, a clientError with no request) are never silent", () => {
  for (const key of ["parserRejected", "protocolRefused", "clientErrorNoRequest"] as const) {
    const { server, report } = consistent();
    server.reconcileInput.connections[key] = 1;
    if (key === "clientErrorNoRequest") server.reconcileInput.connections.clientErrorTotal = 1;
    assert.ok(codes(server, report).includes("unexplained_traffic"), key);
  }
  const inRequest = consistent();
  inRequest.server.reconcileInput.connections.clientErrorTotal = 1;
  assert.ok(codes(inRequest.server, inRequest.report).includes("unexplained_traffic"), "a clientError during a request is still unexplained for this workload");
});

test("G2: the status histograms must agree status by status, and every generator 503 must be a server-attributed expected shed", () => {
  const { server, report } = consistent();
  report.statuses = { "200": 81, "503": 19 };
  assert.ok(failedIds(server, report).includes("g2.status_histogram_equal"));
  assert.ok(codes(server, report).includes("generator_report_mismatch"));
  const ratio = consistent();
  ratio.server.reconcileInput.status503 = { total: 20, expectedShed: 15, unexplained: 5 };
  assert.ok(failedIds(ratio.server, ratio.report).includes("g2.generator_503_equals_expected_shed"));
  assert.ok(codes(ratio.server, ratio.report).includes("unattributed_503"), "HTTP status alone never proves a defense shed");
  const missing = consistent();
  missing.server.reconcileInput.statusHistogram = { "200": 80 };
  assert.ok(failedIds(missing.server, missing.report).includes("g2.status_histogram_equal"), "a status only one side saw");
});

test("G3: reads equal the open class, POSTs equal the mutation class, and the unknown class and L1 rejects are zero", () => {
  let c = consistent();
  c.server.reconcileInput.classes = { open: 74, mutation: 25 };
  assert.ok(failedIds(c.server, c.report).includes("g3.gets_equal_open_class"));
  c = consistent();
  c.server.reconcileInput.classes = { open: 75, mutation: 26 };
  assert.ok(failedIds(c.server, c.report).includes("g3.posts_equal_mutation_class"));
  c = consistent();
  c.server.reconcileInput.classes = { open: 75, mutation: 24, unknown: 1 };
  assert.ok(failedIds(c.server, c.report).includes("g3.unknown_class_is_zero"));
  c = consistent();
  c.server.reconcileInput.l1Rejected = 1;
  assert.ok(failedIds(c.server, c.report).includes("g3.l1_rejects_is_zero"));
  for (const break_ of [() => { c = consistent(); c.server.reconcileInput.classes = { open: 74, mutation: 25 }; }]) { break_(); assert.ok(codes(c.server, c.report).includes("unexplained_traffic")); }
});

test("G4: the generator's new connections must equal the server's remote connections accepted plus dropped", () => {
  let c = consistent();
  c.report.connections = { new: 2, reused: 98 };
  assert.ok(failedIds(c.server, c.report).includes("g4.new_connections_equal_accepted"));
  c = consistent();
  c.server.reconcileInput.connections.acceptedRemote = 3;
  assert.ok(codes(c.server, c.report).includes("unexplained_traffic"));
  c = consistent();
  c.server.reconcileInput.connections.dropped = 1;
  c.report.connections = { new: 2, reused: 98 };
  assert.ok(failedIds(c.server, c.report).includes("g4.server_dropped_is_zero"), "equal counts but the listener dropped a connection");
});

test("G5: logical in-flight above N (generator or server), retries or pipelining, and a saturated generator are each a measurement failure", () => {
  let c = consistent();
  c.report.concurrency.maxInFlightObserved = 2;
  assert.ok(codes(c.server, c.report).includes("generator_in_flight_exceeded"));
  c = consistent();
  c.server.reconcileInput.externalInFlightMax = 2;
  assert.ok(codes(c.server, c.report).includes("generator_in_flight_exceeded"), "the server's own view catches pipelining or overlap");
  c = consistent();
  (c.report as { pipelining: boolean }).pipelining = true;
  assert.ok(failedIds(c.server, c.report).includes("g5.no_retries_no_pipelining"));
  c = consistent();
  c.report.schedule.lagMs = summary(LIMITS.scheduleLagP99Ms + 1);
  assert.ok(codes(c.server, c.report).includes("generator_saturation"));
  c = consistent();
  c.report.generatorHealth.eldP99Ms = LIMITS.eldP99Ms + 1;
  assert.ok(codes(c.server, c.report).includes("generator_saturation"));
});

test("G6: the campaign, level, commit, parameter and workload fingerprints and N must be identical in both inputs", () => {
  for (const mutate of [
    (c: ReturnType<typeof consistent>) => { c.report.campaignId = "campaign-two"; }, (c: ReturnType<typeof consistent>) => { c.report.levelId = "ba0-l7-c2"; },
    (c: ReturnType<typeof consistent>) => { c.report.gitSha = "d".repeat(40); }, (c: ReturnType<typeof consistent>) => { c.report.paramsFingerprintSha256 = "e".repeat(64); },
    (c: ReturnType<typeof consistent>) => { c.report.workloadFingerprintSha256 = "f".repeat(64); }, (c: ReturnType<typeof consistent>) => { c.report.workers = 2; },
  ]) {
    const c = consistent();
    mutate(c);
    assert.ok(codes(c.server, c.report).includes("identity_binding_mismatch"));
    assert.equal(finalFrom(c.server, c.report, LIMITS).decision.verdict, "INVALID");
  }
});

test("G6 (informational): a generator that ran outside the server's window is reported, never decided on; the clock-skew assumption is stated", () => {
  const { server, report } = consistent();
  report.startedAt = "2026-10-06T09:00:00.000Z";
  const result = reconcile(server, report, LIMITS);
  assert.equal(result.informational.windowConsistent, false);
  assert.deepEqual(result.reasons, []);
});

test("an aborted server-side level stays ABORTED when the reconcile adds nothing, and any measurement reason found at reconcile outranks the abort", () => {
  const { server, report } = consistent();
  server.serverSide = { status: "aborted", failureClass: "operational", reasons: [{ code: "operator_abort" }] };
  assert.equal(finalFrom(server, report, LIMITS).decision.verdict, "ABORTED");
  assert.equal(finalFrom(server, null, LIMITS).decision.verdict, "INVALID");
  const defenseFailed = consistent();
  defenseFailed.server.serverSide = { status: "invalid", failureClass: "defense", reasons: [{ code: "mutation_over_budget" }] };
  const decision = finalFrom(defenseFailed.server, defenseFailed.report, LIMITS).decision;
  assert.deepEqual([decision.verdict, decision.failureClass], ["INVALID", "defense"]);
});

// ------------------------------------------------------------------------------------------------ the report contract
test("the generator report is strictly shape-checked: it round-trips, and a missing or malformed field is refused by name", () => {
  const { report } = consistent();
  assert.deepEqual(parseGeneratorReport(JSON.stringify(report)), report);
  assert.throws(() => parseGeneratorReport("not json"), /not JSON/);
  assert.throws(() => parseGeneratorReport("[]"), /schema/);
  for (const field of ["campaignId", "gitSha", "statuses", "latencyMs", "concurrency", "connections", "schedule", "generatorHealth", "stop", "bytes", "rate"]) {
    const broken = JSON.parse(JSON.stringify(report)) as Record<string, unknown>;
    delete broken[field];
    assert.throws(() => parseGeneratorReport(JSON.stringify(broken)), /missing or malformed/, field);
  }
  const retries = { ...report, retries: 1 };
  assert.throws(() => parseGeneratorReport(JSON.stringify(retries)), /retries/);
  const badSha = { ...report, gitSha: "xyz" };
  assert.throws(() => parseGeneratorReport(JSON.stringify(badSha)), /gitSha/);
});

// ------------------------------------------------------------------------------------------------ the offline CLI
const testRoot = (): string => { const root = path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-${process.pid}-${Math.random().toString(16).slice(2, 8)}`); fs.mkdirSync(root, { recursive: true }); return root; };

function serverEvidence(root: string, server: ServerLevelEvidence): string {
  const evidence = new EvidenceRun("field-level", "ba0-l7-c1", new Date(), root);
  evidence.addJsonArtifact("server-level.json", server);
  evidence.finalize({ git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: null, engine: "test", result: "SERVER-COMPLETE", resultReasons: [], metrics: {} });
  return evidence.id;
}

test("the offline reconcile verifies the server evidence's checksums, compares it with the report and writes a final verdict; nothing else produces one", () => {
  const root = testRoot();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ba0-report-"));
  try {
    const { server, report } = consistent();
    const id = serverEvidence(root, server);
    const reportPath = path.join(tmp, "generator-report.json");
    fs.writeFileSync(reportPath, JSON.stringify(report));
    const valid = reconcileLevel({ serverId: id, reportPath }, root);
    assert.equal(valid.verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
    assert.equal(valid.exit, 0);
    const finalDir = path.join(root, valid.evidenceId!);
    const finalJson = JSON.parse(fs.readFileSync(path.join(finalDir, "final.json"), "utf8")) as { validScopedTo: Record<string, unknown>; claims: { notClaimed: string[] }; inputs: { server: Record<string, string>; generator: Record<string, string> } };
    assert.deepEqual(Object.keys(finalJson.validScopedTo).sort(), ["campaignId", "gitSha", "levelId", "paramsFingerprintSha256", "workers", "workloadFingerprintSha256"]);
    assert.ok(finalJson.claims.notClaimed.some((entry) => /DDoS resistance/.test(entry)));
    assert.ok(finalJson.claims.notClaimed.some((entry) => /network, transport, TLS or origin-network isolation/.test(entry)));
    assert.match(finalJson.inputs.generator.reportSha256, /^[0-9a-f]{64}$/);
    assert.match(finalJson.inputs.server.levelSha256, /^[0-9a-f]{64}$/);

    const broken = { ...report, attempted: 101 };
    fs.writeFileSync(reportPath, JSON.stringify(broken));
    const invalid = reconcileLevel({ serverId: id, reportPath }, root);
    assert.equal(invalid.verdict, "INVALID");
    assert.equal(invalid.exit, 1);

    const withoutReport = reconcileLevel({ serverId: id, reportPath: null }, root);
    assert.equal(withoutReport.verdict, "INVALID");
    assert.match(withoutReport.reasons.join(" "), /generator_report_missing/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("a server evidence that fails its checksums, is unfinalized or is not a level evidence is REFUSED, never reconciled", () => {
  const root = testRoot();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ba0-report-"));
  try {
    const { server, report } = consistent();
    const id = serverEvidence(root, server);
    const reportPath = path.join(tmp, "generator-report.json");
    fs.writeFileSync(reportPath, JSON.stringify(report));
    fs.appendFileSync(path.join(root, id, "server-level.json"), " ");
    const tampered = reconcileLevel({ serverId: id, reportPath }, root);
    assert.equal(tampered.verdict, "REFUSED");
    assert.match(tampered.reasons[0], /checksums/);
    assert.equal(reconcileLevel({ serverId: "20261006T100000Z-nothing-aaaaaa", reportPath }, root).verdict, "REFUSED");
    fs.writeFileSync(reportPath, "garbage");
    const other = serverEvidence(root, server);
    assert.equal(reconcileLevel({ serverId: other, reportPath }, root).verdict, "REFUSED", "an unusable generator report");
    const wrongSchema = serverEvidence(root, { ...server, schema: "other" as never });
    fs.writeFileSync(reportPath, JSON.stringify(report));
    assert.equal(reconcileLevel({ serverId: wrongSchema, reportPath }, root).verdict, "REFUSED");
  } finally { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("the reconcile command line accepts exactly --server and --report (a run id and a generator-report.json); no URL, host or other path", () => {
  assert.deepEqual(parseReconcileArguments(["--server", "20261006T100000Z-ba0-l7-c1-aaaaaa", "--report", "x/generator-report.json"]), { serverId: "20261006T100000Z-ba0-l7-c1-aaaaaa", reportPath: "x/generator-report.json" });
  assert.deepEqual(parseReconcileArguments(["--server", "20261006T100000Z-ba0-l7-c1-aaaaaa"]).reportPath, null);
  for (const argv of [[], ["--server"], ["--server", "x"], ["--server", "20261006T100000Z-ba0-l7-c1-aaaaaa", "--report", "notes.txt"], ["--server", "20261006T100000Z-ba0-l7-c1-aaaaaa", "--url", "http://x"],
    ["--server", "20261006T100000Z-ba0-l7-c1-aaaaaa", "--server", "20261006T100000Z-ba0-l7-c1-bbbbbb"], ["--server=20261006T100000Z-ba0-l7-c1-aaaaaa"], ["20261006T100000Z-ba0-l7-c1-aaaaaa"]]) {
    assert.throws(() => parseReconcileArguments(argv), Error, JSON.stringify(argv));
  }
});

test("EXTERNAL-L7-QUALIFICATION-VALID is produced by exactly the verdict module and the offline reconcile; the server-side runner and the generator never write it", () => {
  const dir = path.join(REPOSITORY_ROOT, "lab");
  const walk = (directory: string): string[] => fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => (entry.isDirectory() ? walk(path.join(directory, entry.name)) : entry.name.endsWith(".ts") ? [path.join(directory, entry.name)] : []));
  const producers = walk(dir).filter((file) => /"EXTERNAL-L7-QUALIFICATION-VALID"/.test(fs.readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1"))).map((file) => path.relative(REPOSITORY_ROOT, file).replace(/\\/g, "/")).sort();
  assert.deepEqual(producers, ["lab/defense/ba0-field-reconcile.ts", "lab/defense/field-verdict.ts", "lab/evidence/manifest.ts", "lab/run.ts"].filter((file) => producers.includes(file)));
  assert.ok(!producers.includes("lab/defense/ba0-field-run.ts"), "the server-side runner never concludes the final verdict");
  assert.ok(!producers.includes("lab/load/closed-loop.ts"));
  assert.ok(!producers.includes("lab/defense/generator-report.ts"));
});
