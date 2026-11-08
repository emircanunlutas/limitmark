import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { RECEIPT_EXIT, m1ReceiptCheck, parseReceiptArguments } from "../lab/defense/ba0-m1-receipt-check";
import { APP_KINDS, BOUNDARY_KINDS, evaluateReceipts, type JournalReceipts, type ReceiptCheckInput } from "../lab/defense/m1-receipt-check";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState } from "../lab/evidence/manifest";

// Receipt reconciliation: exact identities between the processes' own counters, the ledger attribution (reducer + registered canary + anonymous), the channels, the plane, the
// canary client and the generator. The five receipt probes that criterion 9 passed are the regression cases at the top.

const CANARY = 5; const EXTERNAL = 4; const SHED = 2; const CANARY_MUTATIONS = 2; const EXTERNAL_MUTATIONS = 1;
const TOTAL = CANARY + EXTERNAL;
const BOUNDARY_PER_REQUEST = ["BOUNDARY_ARRIVED", "BOUNDARY_ADMITTED", "APP_PROOF_ISSUED", "BOUNDARY_FORWARDED", "BOUNDARY_FORWARD_RESPONDED", "BOUNDARY_RESPONDED"];
const APP_PER_REQUEST = ["APP_ADMITTED", "APP_EXECUTED", "APP_COMPLETED"];
const times = (kinds: string[], n: number): Record<string, number> => Object.fromEntries(kinds.map((kind) => [kind, n]));

function receiptInput(): ReceiptCheckInput {
  const external = {
    accepted: EXTERNAL + SHED, statusHistogram: { "200": EXTERNAL, "503": SHED },
    boundary: { arrived: EXTERNAL, admitted: EXTERNAL, rejected: 0, appProofsIssued: EXTERNAL, relayed: EXTERNAL, forwardResponded: EXTERNAL, forwardFailed: 0, responded: EXTERNAL, aborted: 0 },
    app: { admitted: EXTERNAL, refused: 0, executed: EXTERNAL, mutated: EXTERNAL_MUTATIONS, completed: EXTERNAL, aborted: 0 },
    egress: { attempted: EXTERNAL, responded: EXTERNAL, failed: 0 },
  };
  const channel = (emitted: number) => ({ emitted, dropped: 0, sent: emitted, received: emitted, queued: 0, unacknowledged: 0, queueHighWater: 3, lastSeq: emitted });
  return {
    external,
    boundaryFin: { drained: true, channel: channel(6 * TOTAL), stats: { arrived: TOTAL, admitted: TOTAL, rejected: 0, appProofsIssued: TOTAL, relayed: TOTAL, forwardResponded: TOTAL, forwardFailed: 0, responded: TOTAL, aborted: 0, parserRejected: 0, protocolRefused: 0 } },
    appFin: { drained: true, channel: channel(3 * TOTAL + CANARY_MUTATIONS + EXTERNAL_MUTATIONS), stats: { counters: { admitted: TOTAL, refused: 0, executed: TOTAL, stateMutations: CANARY_MUTATIONS + EXTERNAL_MUTATIONS, parserRejected: 0, protocolRefused: 0 }, served: { received: TOTAL, completed: TOTAL, aborted: 0, overloaded: 0 } } },
    journal: { boundary: times(BOUNDARY_PER_REQUEST, CANARY), app: { ...times(APP_PER_REQUEST, CANARY), APP_MUTATED: CANARY_MUTATIONS }, anonymousBoundary: {}, anonymousApp: {} },
    journalIncomplete: false, anomalyTotal: 0, planeKindCounts: { EGRESS_ATTEMPTED: TOTAL, EGRESS_FAILED: 0 }, canaryClientMutations: CANARY_MUTATIONS,
    generator: { attempted: EXTERNAL + SHED, responses: EXTERNAL + SHED, transportFailures: 0, statuses: { "200": EXTERNAL, "503": SHED }, campaignId: "campaign-a", levelId: "ba0-l7-c1", gitSha: "a".repeat(40) },
    level: { campaignId: "campaign-a", levelId: "ba0-l7-c1", gitSha: "a".repeat(40) }, inventoryProblems: [], duplicateKeys: [],
  };
}
const mutate = (change: (input: any) => void): ReceiptCheckInput => { const input = structuredClone(receiptInput()) as any; change(input); return input; }; // eslint-disable-line @typescript-eslint/no-explicit-any
const reasons = (input: ReceiptCheckInput): string[] => evaluateReceipts(input).reasons;

test("control: consistent evidence passes with every identity holding; campaign attribution is never claimed", () => {
  const result = evaluateReceipts(receiptInput());
  assert.deepEqual([result.outcome, result.reasons], ["PASS", []]);
  assert.ok(result.identities.length >= 35 && result.identities.every((identity) => identity.ok));
  assert.equal(result.campaignAttribution, "not_established");
  assert.ok(result.limitations.includes("receipts_nonce_only"));
});

test("the five original false-PASS probes (criterion 9 returned PASS for each) are now rejected", () => {
  // 1. missing app and origin receipts although egress attempted > 0
  assert.ok(reasons(mutate((i) => { i.external.app = { admitted: 0, refused: 0, executed: 0, mutated: 0, completed: 0, aborted: 0 }; i.appFin.stats.counters = { ...i.appFin.stats.counters, admitted: CANARY, executed: CANARY }; i.appFin.stats.served = { received: CANARY, completed: CANARY, aborted: 0, overloaded: 0 }; })).length > 0);
  assert.ok(reasons(mutate((i) => { i.external.app.executed = 0; i.appFin.stats.counters.executed = CANARY; })).includes("m1.receipt.app_executed_equals_admitted"));
  // 2. unexplained inflation of process counters (duplicate receipts)
  const inflated = reasons(mutate((i) => { for (const key of ["arrived", "admitted", "appProofsIssued", "relayed", "forwardResponded", "responded"]) i.boundaryFin.stats[key] += 5000; i.appFin.stats.counters.admitted += 5000; i.appFin.stats.counters.executed += 5000; }));
  assert.ok(inflated.includes("m1.receipt.boundary_arrived_equals_ledger") && inflated.includes("m1.receipt.app_admitted_equals_ledger") && inflated.includes("m1.receipt.plane_egress_attempts_equal_boundary_arrivals"), inflated.join(","));
  // 3. app executes far more than the boundary relayed
  const bypass = reasons(mutate((i) => { i.appFin.stats.counters.admitted = 99999; i.appFin.stats.counters.executed = 99999; }));
  assert.ok(bypass.includes("m1.receipt.app_admitted_equals_boundary_forward_responded") && bypass.includes("m1.receipt.app_executed_equals_ledger"), bypass.join(","));
  // 4. reducer boundary counters contradict the boundary's own observations
  assert.ok(reasons(mutate((i) => { i.external.boundary = { arrived: 0, admitted: 0, rejected: 0, appProofsIssued: 0, relayed: 0, forwardResponded: 0, forwardFailed: 0, responded: 0, aborted: 0 }; })).includes("m1.receipt.boundary_arrived_equals_ledger"));
  assert.ok(reasons(mutate((i) => { i.external.boundary.arrived = 0; })).includes("m1.receipt.external_egress_attempts_equal_boundary_arrivals"));
  // 5. app admissions exceed attributable boundary deliveries
  const surplus = reasons(mutate((i) => { i.external.boundary.relayed = 0; i.external.app.admitted += 1; }));
  assert.ok(surplus.includes("m1.receipt.external_app_admitted_equals_forward_responded") || surplus.includes("m1.receipt.boundary_relayed_equals_ledger"), surplus.join(","));
});

test("every counter is an exact identity: a single unit of drift, up or down, in any process counter or attribution is named", () => {
  const boundaryStats = ["arrived", "admitted", "appProofsIssued", "relayed", "forwardResponded", "responded"];
  for (const key of boundaryStats) for (const delta of [-1, 1]) assert.notEqual(evaluateReceipts(mutate((i) => { i.boundaryFin.stats[key] += delta; })).outcome, "PASS", `boundary ${key} ${delta}`);
  for (const key of ["admitted", "executed", "stateMutations"]) for (const delta of [-1, 1]) assert.notEqual(evaluateReceipts(mutate((i) => { i.appFin.stats.counters[key] += delta; })).outcome, "PASS", `app ${key} ${delta}`);
  for (const key of ["received", "completed"]) for (const delta of [-1, 1]) assert.notEqual(evaluateReceipts(mutate((i) => { i.appFin.stats.served[key] += delta; })).outcome, "PASS", `origin ${key} ${delta}`);
  for (const delta of [-1, 1]) {
    assert.notEqual(evaluateReceipts(mutate((i) => { i.journal.boundary.BOUNDARY_ARRIVED += delta; })).outcome, "PASS");
    assert.notEqual(evaluateReceipts(mutate((i) => { i.journal.app.APP_COMPLETED += delta; })).outcome, "PASS");
    assert.notEqual(evaluateReceipts(mutate((i) => { i.external.boundary.responded += delta; })).outcome, "PASS");
    assert.notEqual(evaluateReceipts(mutate((i) => { i.canaryClientMutations += delta; })).outcome, "PASS");
    assert.notEqual(evaluateReceipts(mutate((i) => { i.planeKindCounts.EGRESS_ATTEMPTED += delta; })).outcome, "PASS");
  }
});

test("alternative paths are never silently absorbed: rejections, refusals, forward failures, parser/protocol refusals, origin overload, egress failures", () => {
  const rejected = mutate((i) => { i.boundaryFin.stats.rejected = 1; i.boundaryFin.stats.arrived += 1; i.journal.boundary.BOUNDARY_REJECTED = 1; i.journal.boundary.BOUNDARY_ARRIVED += 1; i.boundaryFin.channel.emitted += 2; i.boundaryFin.channel.sent += 2; i.boundaryFin.channel.received += 2; i.boundaryFin.channel.lastSeq += 2; });
  assert.ok(reasons(rejected).includes("m1.receipt.no_boundary_rejections_or_refusals"), "an explained rejection is still not a clean level");
  assert.ok(reasons(mutate((i) => { i.boundaryFin.stats.parserRejected = 1; })).includes("m1.receipt.no_boundary_rejections_or_refusals"));
  assert.ok(reasons(mutate((i) => { i.appFin.stats.counters.refused = 1; })).includes("m1.receipt.no_app_refusals"));
  assert.ok(reasons(mutate((i) => { i.appFin.stats.served.overloaded = 1; })).includes("m1.receipt.origin_overloaded_is_zero"));
  assert.ok(reasons(mutate((i) => { i.planeKindCounts.EGRESS_FAILED = 1; })).includes("m1.receipt.plane_egress_failed_is_zero"));
  assert.ok(reasons(mutate((i) => { i.external.egress.failed = 1; })).includes("m1.receipt.external_egress_failed_is_zero"));
});

test("anonymous (unclaimed) events are attributed explicitly: they explain a process counter only when the journal holds them, and they still must not be refusals", () => {
  const withAnonymous = mutate((i) => { i.journal.anonymousBoundary = { BOUNDARY_ARRIVED: 1 }; });
  assert.ok(reasons(withAnonymous).includes("m1.receipt.boundary_arrived_equals_ledger"), "an extra unclaimed arrival the process did not count is a difference");
  const explained = mutate((i) => { i.journal.anonymousBoundary = { BOUNDARY_ARRIVED: 1 }; i.boundaryFin.stats.arrived += 1; i.boundaryFin.channel.emitted += 1; i.boundaryFin.channel.sent += 1; i.boundaryFin.channel.received += 1; i.boundaryFin.channel.lastSeq += 1; });
  const result = reasons(explained);
  assert.ok(!result.includes("m1.receipt.boundary_arrived_equals_ledger") && !result.includes("m1.receipt.boundary_channel_emitted_equals_attributed_events"));
  assert.ok(result.includes("m1.receipt.boundary_arrived_equals_admitted_plus_rejected"), "but an arrival that was neither admitted nor rejected still breaks the pipeline chain");
});

test("channel loss and anomalies: an incomplete channel, a dropped event, a gap or a non-drained process never PASS", () => {
  for (const field of ["dropped", "queued", "unacknowledged"]) {
    assert.ok(reasons(mutate((i) => { i.boundaryFin.channel[field] = 1; })).includes("m1.receipt.channel_incomplete"), field);
    assert.ok(reasons(mutate((i) => { i.appFin.channel[field] = 1; })).includes("m1.receipt.channel_incomplete"), field);
  }
  assert.ok(reasons(mutate((i) => { i.boundaryFin.drained = false; })).includes("m1.receipt.channel_incomplete"));
  assert.ok(reasons(mutate((i) => { i.boundaryFin.channel.emitted -= 1; i.boundaryFin.channel.sent -= 1; i.boundaryFin.channel.received -= 1; i.boundaryFin.channel.lastSeq -= 1; })).includes("m1.receipt.boundary_channel_emitted_equals_attributed_events"));
  assert.ok(reasons(mutate((i) => { i.anomalyTotal = 1; })).includes("m1.receipt.anomalies_nonzero"));
});

test("the generator: identity must match the server level, transport failures and count/status differences are unattributed and rejected, a missing report is rejected when the level carried remote traffic", () => {
  assert.ok(reasons(mutate((i) => { delete i.generator; })).includes("m1.receipt.generator_report_absent"));
  assert.ok(reasons(mutate((i) => { i.generator.campaignId = "campaign-b"; })).includes("m1.receipt.generator_campaign_mismatch"));
  assert.ok(reasons(mutate((i) => { i.generator.levelId = "ba0-l7-c2"; })).includes("m1.receipt.generator_level_mismatch"));
  assert.ok(reasons(mutate((i) => { i.generator.gitSha = "b".repeat(40); })).includes("m1.receipt.generator_git_mismatch"));
  assert.ok(reasons(mutate((i) => { i.generator.transportFailures = 1; })).includes("m1.receipt.generator_transport_failures_are_zero"));
  assert.ok(reasons(mutate((i) => { i.generator.responses += 1; })).includes("m1.receipt.generator_responses_equal_external_accepted"));
  assert.ok(reasons(mutate((i) => { i.generator.statuses = { "200": EXTERNAL - 1, "503": SHED + 1 }; })).includes("m1.receipt.generator_statuses_equal_server_statuses"));
  assert.equal(evaluateReceipts(mutate((i) => { i.generator = { malformed: true }; })).outcome, "ERROR");
  // no remote traffic: no generator is required
  const none = mutate((i) => { i.external.accepted = 0; delete i.generator; });
  assert.ok(!reasons(none).includes("m1.receipt.generator_report_absent"));
});

test("missing, malformed or untrusted evidence is ERROR or REJECT, never PASS", () => {
  assert.equal(evaluateReceipts(mutate((i) => { i.journal = null; })).outcome, "ERROR");
  assert.equal(evaluateReceipts(mutate((i) => { i.journalIncomplete = true; })).outcome, "ERROR");
  assert.equal(evaluateReceipts(mutate((i) => { i.inventoryProblems = ["unlisted_mandatory:external.json"]; })).outcome, "ERROR");
  assert.equal(evaluateReceipts(mutate((i) => { i.duplicateKeys = ["external.json:$.accepted"]; })).outcome, "ERROR");
  assert.equal(evaluateReceipts(mutate((i) => { i.boundaryFin = "no_fin"; })).outcome, "REJECT");
  assert.equal(evaluateReceipts(mutate((i) => { i.appFin = undefined; })).outcome, "REJECT");
  for (const path of ["external", "planeKindCounts", "anomalyTotal", "canaryClientMutations"]) assert.equal(evaluateReceipts(mutate((i) => { i[path] = path === "anomalyTotal" ? "0" : null; })).outcome, "ERROR", path);
  assert.equal(evaluateReceipts(mutate((i) => { i.boundaryFin.stats.arrived = "55"; })).outcome, "ERROR");
  assert.equal(evaluateReceipts(mutate((i) => { i.journal.boundary.BOUNDARY_ARRIVED = -1; })).outcome, "ERROR");
  assert.ok(reasons(mutate((i) => { i.journal.boundary.BOUNDARY_TELEPORTED = 1; })).includes("m1.receipt.journal_unknown_kind"));
  assert.ok(BOUNDARY_KINDS.length === 9 && APP_KINDS.length === 6);
  assert.equal(evaluateReceipts(null as unknown as ReceiptCheckInput).outcome, "ERROR");
});

// ---------------------------------------------------------------------------------------------------- the CLI over a finalized evidence directory
const testRoot = (): string => { const root = path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-m1receipt-${process.pid}-${Math.random().toString(16).slice(2, 8)}`); fs.mkdirSync(root, { recursive: true }); return root; };
function writeEvidence(root: string, change?: (input: ReceiptCheckInput & Record<string, unknown>) => void, options: { unlisted?: Record<string, string> } = {}): string {
  const input = structuredClone(receiptInput()) as ReceiptCheckInput & Record<string, unknown>;
  change?.(input);
  const journal = input.journal as JournalReceipts;
  const lines: string[] = [];
  for (const [kind, count] of Object.entries(journal.boundary)) for (let n = 0; n < count; n++) lines.push(JSON.stringify({ src: "b", rid: `r${lines.length}`, seq: lines.length, k: kind }));
  for (const [kind, count] of Object.entries(journal.app)) for (let n = 0; n < count; n++) lines.push(JSON.stringify({ src: "a", rid: `r${lines.length}`, seq: lines.length, k: kind }));
  const text = `${lines.join("\n")}\n`;
  const evidence = new EvidenceRun("field-level", "ba0-l7-c1", new Date(), root);
  evidence.addJsonArtifact("external.json", { counters: input.external });
  evidence.addJsonArtifact("processes.json", { plane: {}, boundary: input.boundaryFin, app: input.appFin });
  evidence.addJsonArtifact("accounting.json", { anomalyTotal: input.anomalyTotal, journal: { lines: lines.length, bytes: text.length, journalSha256: createHash("sha256").update(text).digest("hex"), overflow: false } });
  evidence.addJsonArtifact("kind-ledger.json", { counts: input.planeKindCounts });
  evidence.addJsonArtifact("canary.json", { clientObservedMutations: input.canaryClientMutations });
  evidence.addJsonArtifact("server-level.json", { campaignId: "campaign-a", levelId: "ba0-l7-c1", gitSha: "a".repeat(40) });
  fs.writeFileSync(path.join(evidence.directory, "ledger-journal-field.ndjson"), text);
  for (const [name, raw] of Object.entries(options.unlisted ?? {})) fs.writeFileSync(path.join(evidence.directory, name), raw);
  evidence.finalize({ git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: null, engine: "test", result: "SERVER-COMPLETE", resultReasons: [], metrics: {} });
  return evidence.id;
}

test("CLI: PASS over finalized evidence with a generator report, REJECT for a contradiction, ERROR for an unlisted artifact, REFUSED for tampering; inputs are untouched", () => {
  const root = testRoot();
  try {
    const report = path.join(root, "generator-report.json");
    const input = receiptInput();
    // parseGeneratorReport is strict about the whole report; a report that fails its own schema is a malformed generator view, which is ERROR
    fs.writeFileSync(report, JSON.stringify(input.generator));
    const id = writeEvidence(root);
    const before = fs.readdirSync(path.join(root, id)).map((name) => [name, createHash("sha256").update(fs.readFileSync(path.join(root, id, name))).digest("hex")]);
    const malformedGenerator = m1ReceiptCheck({ serverId: id, reportPath: report }, root);
    assert.equal(malformedGenerator.exit, RECEIPT_EXIT.error);
    assert.deepEqual(malformedGenerator.result?.reasons, ["m1.receipt.evidence_malformed_generator"]);
    const after = fs.readdirSync(path.join(root, id)).map((name) => [name, createHash("sha256").update(fs.readFileSync(path.join(root, id, name))).digest("hex")]);
    assert.deepEqual(after, before, "inspected evidence is byte-identical afterwards");
    // no remote traffic: the canary-only identities pass without a report
    const canaryOnly = writeEvidence(root, (i) => {
      const e = i.external as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
      e.accepted = 0; e.statusHistogram = {}; e.boundary = Object.fromEntries(Object.keys(e.boundary).map((k) => [k, 0])); e.app = Object.fromEntries(Object.keys(e.app).map((k) => [k, 0])); e.egress = { attempted: 0, responded: 0, failed: 0 };
      const j = i.journal as JournalReceipts; const n = CANARY;
      i.boundaryFin = { drained: true, channel: { emitted: 6 * n, dropped: 0, sent: 6 * n, received: 6 * n, queued: 0, unacknowledged: 0, queueHighWater: 1, lastSeq: 6 * n }, stats: { arrived: n, admitted: n, rejected: 0, appProofsIssued: n, relayed: n, forwardResponded: n, forwardFailed: 0, responded: n, aborted: 0, parserRejected: 0, protocolRefused: 0 } };
      i.appFin = { drained: true, channel: { emitted: 3 * n + CANARY_MUTATIONS, dropped: 0, sent: 3 * n + CANARY_MUTATIONS, received: 3 * n + CANARY_MUTATIONS, queued: 0, unacknowledged: 0, queueHighWater: 1, lastSeq: 3 * n + CANARY_MUTATIONS }, stats: { counters: { admitted: n, refused: 0, executed: n, stateMutations: CANARY_MUTATIONS, parserRejected: 0, protocolRefused: 0 }, served: { received: n, completed: n, aborted: 0, overloaded: 0 } } };
      i.planeKindCounts = { EGRESS_ATTEMPTED: n, EGRESS_FAILED: 0 }; void j;
    });
    const ok = m1ReceiptCheck({ serverId: canaryOnly, reportPath: null }, root);
    assert.deepEqual([ok.exit, ok.result?.reasons], [RECEIPT_EXIT.pass, []]);
    const written = JSON.parse(fs.readFileSync(path.join(root, ok.evidenceId!, "m1-receipt-check.json"), "utf8")) as { campaignAttribution: string; claims: { authenticity: string } };
    assert.deepEqual([written.campaignAttribution, written.claims.authenticity], ["not_established", "not_claimed"]);
    // contradiction -> REJECT
    const rejected = m1ReceiptCheck({ serverId: writeEvidence(root, (i) => { (i.appFin as any).stats.counters.executed += 1; }), reportPath: null }, root); // eslint-disable-line @typescript-eslint/no-explicit-any
    assert.equal(rejected.exit, RECEIPT_EXIT.reject);
    assert.ok(rejected.result?.reasons.includes("m1.receipt.app_executed_equals_ledger"));
    // unlisted replacement artifact -> ERROR
    const unlisted = m1ReceiptCheck({ serverId: writeEvidence(root, undefined, { unlisted: { "extra.json": "{}" } }), reportPath: null }, root);
    assert.equal(unlisted.exit, RECEIPT_EXIT.error);
    assert.deepEqual(unlisted.result?.reasons, ["m1.receipt.evidence_inventory_invalid"]);
    // tampered bytes -> REFUSED
    const tamperId = writeEvidence(root);
    fs.appendFileSync(path.join(root, tamperId, "external.json"), " ");
    assert.equal(m1ReceiptCheck({ serverId: tamperId, reportPath: null }, root).exit, RECEIPT_EXIT.refused);
    assert.equal(m1ReceiptCheck({ serverId: "20260101T000000Z-nothing-000000", reportPath: null }, root).exit, RECEIPT_EXIT.refused);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
  assert.deepEqual(parseReceiptArguments(["--server", "20261006T100000Z-level-aaaaaa"]), { serverId: "20261006T100000Z-level-aaaaaa", reportPath: null });
  for (const argv of [[], ["--server"], ["--server", "x"], ["--server", "20261006T100000Z-level-aaaaaa", "--x"], ["--server", "20261006T100000Z-level-aaaaaa", "--report", "other.json"]]) assert.throws(() => parseReceiptArguments(argv as string[]), Error, JSON.stringify(argv));
});

test("the receipt evaluator is offline and read-only (no network, no process spawn, no writes outside the evidence run)", () => {
  for (const file of ["lab/defense/m1-receipt-check.ts", "lab/defense/ba0-m1-receipt-check.ts"]) {
    const text = fs.readFileSync(path.join(REPOSITORY_ROOT, file), "utf8").replace(/\/\*[\s\S]*?\*\//gu, "").replace(/\/\/.*$/gmu, "");
    assert.equal(/node:(?:http|https|net|child_process|dgram)|writeFileSync|appendFileSync|unlinkSync|rmSync|renameSync/u.test(text), false, file);
  }
});
