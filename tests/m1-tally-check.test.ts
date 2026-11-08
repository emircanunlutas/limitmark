import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { TALLY_EXIT, gatherTallyInput, m1TallyCheck, parseTallyArguments } from "../lab/defense/ba0-m1-tally-check";
import { EXTERNAL_UNOBSERVABLE_KINDS, evaluateTallyAgainstLedger, externalKindCounts, tallyCheckWellFormed, type TallyCheckInput } from "../lab/defense/m1-tally-check";
import { OutcomeCounters, type CountedEvent } from "../lab/defense/outcome-counters";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState } from "../lab/evidence/manifest";

// Criterion 9: the plane's own tally versus the collector ledger, per event kind. The tally side here is the REAL OutcomeCounters class fed real event shapes;
// the ledger side is built from the same events so the "agree" case is true by construction and every mutation below is a deliberate disagreement.

type E = CountedEvent & { kind: string };
const pass = (status: number): E[] => [
  { kind: "INGRESS_ACCEPTED" }, { kind: "L1_ENTERED" }, { kind: "L1_PASSED" }, { kind: "L2_ENTERED" }, { kind: "L2_DECIDED", class: "open", lane: "open", outcome: "admitted" },
  { kind: "EGRESS_ATTEMPTED" }, { kind: "PROOF_ISSUED" }, { kind: "EGRESS_RESPONDED", status }, { kind: "INGRESS_RESPONDED", status },
];
const shed: E[] = [
  { kind: "INGRESS_ACCEPTED" }, { kind: "L1_ENTERED" }, { kind: "L1_PASSED" }, { kind: "L2_ENTERED" },
  { kind: "L2_DECIDED", class: "mutation", lane: "unverified", outcome: "shed", shedReason: "lane_budget" }, { kind: "INGRESS_RESPONDED", status: 503 },
];
const enroll: E[] = [...pass(200), { kind: "L2_ENROLLED" }];
const workload = (): E[] => [...pass(200), ...pass(200), ...enroll, ...shed, ...shed];

function tallyOf(events: E[], options: { injectedFault?: () => void } = {}) {
  const counters = new OutcomeCounters(options);
  for (const event of events) counters.observe(event);
  return counters.snapshot();
}
const journalOf = (events: E[]): Record<string, number> => { const out: Record<string, number> = {}; for (const event of events) out[event.kind] = (out[event.kind] ?? 0) + 1; return out; };
const noExternal = { accepted: 0, strippedHeaders: 0, reduced: 0, l1: { entered: 0, passed: 0, rejected: 0, shed: 0, error: 0 }, l2: { entered: 0, decided: 0 }, egress: { attempted: 0, responded: 0, failed: 0 }, proofsIssued: 0, statusHistogram: {}, clientAborted: 0 };
const agree = (events: E[] = workload()): TallyCheckInput => ({ tally: tallyOf(events), tallyFromFinalTick: true, journalByKind: journalOf(events), journalIncomplete: false, external: noExternal });

test("agreement: the real tally of a mixed workload equals the ledger per kind, every identity holds -> PASS", () => {
  const result = evaluateTallyAgainstLedger(agree());
  assert.deepEqual(result, { evaluated: true, outcome: "PASS", reasons: [], differences: [], unobservable: [], ledgerSource: "journal-and-reducer" });
  assert.equal(tallyCheckWellFormed(result), true);
});

test("an absent tally is a failure (REJECT tally_missing), never skipped", () => {
  for (const tally of [null, undefined]) {
    const result = evaluateTallyAgainstLedger({ ...agree(), tally });
    assert.equal(result.outcome, "REJECT");
    assert.deepEqual(result.reasons, ["m1.tally.tally_missing"]);
  }
});

test("a malformed tally is ERROR (not evaluable), never PASS", () => {
  const good = tallyOf(workload());
  for (const bad of ["x", 7, [], { version: 2 }, { ...good, events: "no" }, { ...good, events: { ...good.events, L1_ENTERED: -1 } }, { ...good, unknown: 1.5 }, { ...good, faults: "0" }, { ...good, version: undefined }]) {
    const result = evaluateTallyAgainstLedger({ ...agree(), tally: bad });
    assert.equal(result.outcome, "ERROR", JSON.stringify(bad)?.slice(0, 60));
    assert.equal(result.evaluated, false);
    assert.equal(tallyCheckWellFormed(result), true);
  }
});

test("a non-zero faults count or a non-zero unknown count fails acceptance, with its own reason", () => {
  const faulty = evaluateTallyAgainstLedger({ ...agree(), tally: tallyOf(workload(), { injectedFault: () => { throw new Error("boom"); } }) });
  assert.equal(faulty.outcome, "REJECT");
  assert.ok(faulty.reasons.includes("m1.tally.faults_nonzero"));
  const counters = new OutcomeCounters();
  for (const event of workload()) counters.observe(event);
  counters.observe({ kind: "NOT_A_KIND" });
  const unknown = evaluateTallyAgainstLedger({ ...agree(), tally: counters.snapshot() });
  assert.equal(unknown.outcome, "REJECT");
  assert.ok(unknown.reasons.includes("m1.tally.unknown_nonzero"));
  assert.equal(unknown.reasons.filter((reason) => reason === "m1.tally.unknown_nonzero").length, 1, "one reason, not one per overlapping identity");
});

test("every disagreement is reported explicitly per kind with both numbers; nothing is absorbed", () => {
  const events = workload();
  const journal = journalOf(events);
  journal.INGRESS_RESPONDED -= 2; journal.L2_DECIDED -= 1; // events the channel dropped before the collector saw them
  const result = evaluateTallyAgainstLedger({ ...agree(), journalByKind: journal });
  assert.equal(result.outcome, "REJECT");
  assert.deepEqual(result.differences, [
    { kind: "INGRESS_RESPONDED", plane: journalOf(events).INGRESS_RESPONDED, ledger: journalOf(events).INGRESS_RESPONDED - 2 },
    { kind: "L2_DECIDED", plane: journalOf(events).L2_DECIDED, ledger: journalOf(events).L2_DECIDED - 1 },
  ].sort((a, b) => Object.keys(tallyOf(events).events).indexOf(a.kind) - Object.keys(tallyOf(events).events).indexOf(b.kind)));
  assert.ok(result.reasons.includes("m1.tally.difference_ingress_responded") && result.reasons.includes("m1.tally.difference_l2_decided"));
  const extra = evaluateTallyAgainstLedger({ ...agree(), journalByKind: { ...journalOf(events), EGRESS_FAILED: 3 } });
  assert.ok(extra.reasons.includes("m1.tally.difference_egress_failed"), "a ledger count the plane never tallied is also a difference");
});

test("a tally that violates its own identity fails even when it matches the ledger", () => {
  const snapshot = tallyOf(workload());
  const broken = { ...snapshot, events: { ...snapshot.events, L1_PASSED: snapshot.events.L1_PASSED + 1 } };
  const journal = { ...journalOf(workload()), L1_PASSED: broken.events.L1_PASSED };
  const result = evaluateTallyAgainstLedger({ ...agree(), tally: broken, journalByKind: journal });
  assert.equal(result.outcome, "REJECT");
  assert.ok(result.reasons.some((reason) => reason.startsWith("m1.tally.identity_i")), result.reasons.join(","));
});

test("a tally that is not the plane's final tick is not accepted", () => {
  const result = evaluateTallyAgainstLedger({ ...agree(), tallyFromFinalTick: false });
  assert.equal(result.outcome, "REJECT");
  assert.deepEqual(result.reasons, ["m1.tally.not_final_tick"]);
});

test("incomplete or unavailable ledger evidence is ERROR, never agreement by default", () => {
  assert.equal(evaluateTallyAgainstLedger({ ...agree(), journalByKind: null }).outcome, "ERROR");
  assert.deepEqual(evaluateTallyAgainstLedger({ ...agree(), journalIncomplete: true }).reasons, ["m1.tally.evidence_journal_incomplete"]);
  for (const external of [null, undefined, "x", {}, { ...noExternal, accepted: -1 }, { ...noExternal, l1: null }, { ...noExternal, statusHistogram: { "200": "5" } }]) {
    assert.equal(evaluateTallyAgainstLedger({ ...agree(), external }).outcome, "ERROR", JSON.stringify(external));
  }
  assert.equal(evaluateTallyAgainstLedger({ ...agree(), journalByKind: { INGRESS_ACCEPTED: -1 } }).outcome, "ERROR");
});

test("remote traffic: ledger = journal (canary) + external counters; the two kinds the reducer does not count are reported UNOBSERVABLE, never assumed equal", () => {
  const canary = [...pass(200), ...enroll];
  const remote = [...pass(200), ...pass(200), ...shed, ...shed, ...shed];
  const all = [...canary, ...remote];
  const statusHistogram: Record<string, number> = {};
  for (const event of remote) if (event.kind === "INGRESS_RESPONDED") statusHistogram[String(event.status)] = (statusHistogram[String(event.status)] ?? 0) + 1;
  const k = journalOf(remote);
  const external = {
    accepted: k.INGRESS_ACCEPTED, l1: { entered: k.L1_ENTERED, passed: k.L1_PASSED, rejected: 0, shed: 0, error: 0 }, l2: { entered: k.L2_ENTERED, decided: k.L2_DECIDED },
    egress: { attempted: k.EGRESS_ATTEMPTED, responded: k.EGRESS_RESPONDED, failed: 0 }, proofsIssued: k.PROOF_ISSUED, statusHistogram, clientAborted: 0,
  };
  const result = evaluateTallyAgainstLedger({ tally: tallyOf(all), tallyFromFinalTick: true, journalByKind: journalOf(canary), journalIncomplete: false, external });
  assert.equal(result.outcome, "REJECT");
  assert.deepEqual(result.differences, [], "every observable kind agrees");
  assert.deepEqual(result.unobservable, [...EXTERNAL_UNOBSERVABLE_KINDS]);
  assert.deepEqual(result.reasons, ["m1.tally.ledger_unobservable_l2_enrolled", "m1.tally.ledger_unobservable_l2_enroll_skipped"]);
  // a real disagreement on top of the limit is still reported
  const dropped = evaluateTallyAgainstLedger({ tally: tallyOf(all), tallyFromFinalTick: true, journalByKind: journalOf(canary), journalIncomplete: false, external: { ...external, l1: { ...external.l1, passed: external.l1.passed - 1 } } });
  assert.ok(dropped.reasons.includes("m1.tally.difference_l1_passed"));
  assert.ok(externalKindCounts(external) !== null);
});

test("hostile inputs never throw and never pass", () => {
  assert.equal(evaluateTallyAgainstLedger(null as unknown as TallyCheckInput).outcome, "ERROR");
  assert.equal(evaluateTallyAgainstLedger(undefined as unknown as TallyCheckInput).outcome, "ERROR");
  const thrower = { get tally(): unknown { throw new Error("boom"); } } as unknown as TallyCheckInput;
  assert.equal(evaluateTallyAgainstLedger(thrower).outcome, "ERROR");
});

// ---- the CLI over a finalized evidence directory written the way the field run writes it
const testRoot = (): string => { const root = path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-m1tally-${process.pid}-${Math.random().toString(16).slice(2, 8)}`); fs.mkdirSync(root, { recursive: true }); return root; };

function fieldLikeEvidence(root: string, events: E[], options: { final?: boolean; omitTally?: boolean; journalMutator?: (text: string) => string; overflow?: boolean; ledgerEvents?: E[] } = {}): string {
  const evidence = new EvidenceRun("field-level", "ba0-l7-c1", new Date(), root);
  const tick = { type: "tick", role: "plane", tickSeq: 9, tMonoMs: 1, final: options.final ?? true, data: { outcomes: options.omitTally ? null : tallyOf(events) } };
  evidence.addJsonArtifact("telemetry.json", { ring: { plane: [{ ...tick, tickSeq: 8, final: false, data: { outcomes: null } }, tick], boundary: [], app: [] } });
  evidence.addJsonArtifact("external.json", { counters: noExternal });
  const ledger = options.ledgerEvents ?? events;
  let text = ledger.map((event, index) => JSON.stringify({ src: "p", rid: `r${index}`, seq: index + 1, k: event.kind })).join("\n") + "\n";
  if (options.journalMutator) text = options.journalMutator(text);
  const recordedSha = createHash("sha256").update(options.journalMutator ? ledger.map((event, index) => JSON.stringify({ src: "p", rid: `r${index}`, seq: index + 1, k: event.kind })).join("\n") + "\n" : text).digest("hex");
  evidence.addJsonArtifact("accounting.json", { anomalyTotal: 0, journal: { lines: ledger.length, bytes: text.length, journalSha256: recordedSha, overflow: options.overflow ?? false } });
  fs.writeFileSync(path.join(evidence.directory, "ledger-journal-field.ndjson"), text);
  evidence.finalize({ git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: null, engine: "test", result: "SERVER-COMPLETE", resultReasons: [], metrics: {} });
  return evidence.id;
}
const readCheck = (root: string, id: string): Record<string, unknown> => JSON.parse(fs.readFileSync(path.join(root, id, "m1-tally-check.json"), "utf8")) as Record<string, unknown>;

test("CLI round trip over a finalized evidence directory: PASS, original artifacts untouched, a new m1-tally-check.json written", () => {
  const root = testRoot();
  try {
    const id = fieldLikeEvidence(root, workload());
    const before = fs.readdirSync(path.join(root, id)).map((name) => [name, createHash("sha256").update(fs.readFileSync(path.join(root, id, name))).digest("hex")]);
    const outcome = m1TallyCheck({ serverId: id }, root);
    assert.equal(outcome.exit, TALLY_EXIT.pass, JSON.stringify(outcome.result));
    assert.deepEqual(readCheck(root, outcome.evidenceId!).tallyCheck, { evaluated: true, outcome: "PASS", reasons: [] });
    const after = fs.readdirSync(path.join(root, id)).map((name) => [name, createHash("sha256").update(fs.readFileSync(path.join(root, id, name))).digest("hex")]);
    assert.deepEqual(after, before, "the inspected evidence is byte-identical afterwards");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("CLI failures: missing tally REJECT, non-final tick REJECT, journal digest mismatch / overflow ERROR, dropped ledger lines REJECT with the difference", () => {
  const root = testRoot();
  try {
    assert.equal(m1TallyCheck({ serverId: fieldLikeEvidence(root, workload(), { omitTally: true }) }, root).exit, TALLY_EXIT.reject);
    assert.deepEqual(m1TallyCheck({ serverId: fieldLikeEvidence(root, workload(), { final: false }) }, root).result?.reasons, ["m1.tally.not_final_tick"]);
    const tampered = m1TallyCheck({ serverId: fieldLikeEvidence(root, workload(), { journalMutator: (text) => text.replace("INGRESS_RESPONDED", "INGRESS_ABORTED") }) }, root);
    assert.equal(tampered.exit, TALLY_EXIT.error);
    assert.deepEqual(tampered.result?.reasons, ["m1.tally.evidence_journal_incomplete"]);
    assert.equal(m1TallyCheck({ serverId: fieldLikeEvidence(root, workload(), { overflow: true }) }, root).exit, TALLY_EXIT.error);
    const events = workload();
    const dropped = m1TallyCheck({ serverId: fieldLikeEvidence(root, events, { ledgerEvents: events.filter((event, index) => !(index === 8 && event.kind === "INGRESS_RESPONDED")) }) }, root);
    assert.equal(dropped.exit, TALLY_EXIT.reject);
    assert.deepEqual(dropped.result?.differences.map((difference) => difference.kind), ["INGRESS_RESPONDED"], "the dropped ledger event is named explicitly");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("CLI: unusable inputs are REFUSED with no artifact; arguments are strict", () => {
  const root = testRoot();
  try {
    assert.equal(m1TallyCheck({ serverId: "20260101T000000Z-nothing-000000" }, root).exit, TALLY_EXIT.refused);
    const id = fieldLikeEvidence(root, workload());
    fs.appendFileSync(path.join(root, id, "telemetry.json"), " ");
    const refused = m1TallyCheck({ serverId: id }, root);
    assert.equal(refused.exit, TALLY_EXIT.refused);
    assert.equal(refused.evidenceId, null);
    assert.equal(gatherTallyInput(path.join(root, id)).tallyFromFinalTick, true);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
  assert.deepEqual(parseTallyArguments(["--server", "20261006T100000Z-level-aaaaaa"]), { serverId: "20261006T100000Z-level-aaaaaa" });
  for (const argv of [[], ["--server"], ["--server", "x"], ["--server", "20261006T100000Z-level-aaaaaa", "--x"], ["--url", "20261006T100000Z-level-aaaaaa"]]) assert.throws(() => parseTallyArguments(argv), Error, JSON.stringify(argv));
});

test("source scan: the tally tooling is read-only on inputs (no writes except through a NEW EvidenceRun) and has no network or process access", () => {
  const sources = ["m1-tally-check.ts", "ba0-m1-tally-check.ts"].map((name) => fs.readFileSync(path.join(REPOSITORY_ROOT, "lab", "defense", name), "utf8")).join("\n");
  assert.equal(/writeFileSync|appendFileSync|unlinkSync|rmSync|renameSync|node:(?:http|https|net|child_process)/u.test(sources), false);
});
