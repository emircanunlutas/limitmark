import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { TALLY_EXIT, gatherTallyInput, m1TallyCheck, parseTallyArguments } from "../lab/defense/ba0-m1-tally-check";
import { evaluateTallyAgainstLedger, externalKindCounts, tallyCheckWellFormed, type TallyCheckInput } from "../lab/defense/m1-tally-check";
import { OutcomeCounters } from "../lab/defense/outcome-counters";
import { journalOf, ledgerArtifact, noExternal, remoteWorkload, tallyOf, validInput, workload, type E } from "./support/m1-tally-fixture";
import { writeFieldLikeEvidence } from "./support/m1-evidence-dir";
import { REPOSITORY_ROOT } from "../lab/evidence/manifest";

// Criterion 9: the plane's own tally versus the collector ledger, per event kind. Fixtures are shared (tests/support/m1-tally-fixture.ts): the tally side is the REAL
// OutcomeCounters class, the ledger side the REAL EventKindLedger, so the "agree" case is true by construction and every mutation is a deliberate disagreement.
const agree = (canary: E[] = workload()): TallyCheckInput => validInput(canary);
const everything = (): E[] => [...workload(), ...remoteWorkload()];

test("agreement: the real tally of a mixed workload equals the ledger per kind, every identity holds -> PASS", () => {
  const result = evaluateTallyAgainstLedger(agree());
  assert.deepEqual(result, { evaluated: true, outcome: "PASS", reasons: [], differences: [], ledgerSource: "kind-ledger" });
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
  const events = everything();
  const ledger = ledgerArtifact(events); // events the channel dropped before the collector saw them: the ledger holds fewer
  const counts = { ...ledger.counts, INGRESS_RESPONDED: ledger.counts.INGRESS_RESPONDED - 2, L2_DECIDED: ledger.counts.L2_DECIDED - 1 };
  const result = evaluateTallyAgainstLedger({ ...agree(), kindLedger: { ...ledger, counts } });
  assert.equal(result.outcome, "REJECT");
  assert.deepEqual(result.differences, [
    { kind: "INGRESS_RESPONDED", plane: journalOf(events).INGRESS_RESPONDED, ledger: journalOf(events).INGRESS_RESPONDED - 2 },
    { kind: "L2_DECIDED", plane: journalOf(events).L2_DECIDED, ledger: journalOf(events).L2_DECIDED - 1 },
  ].sort((a, b) => Object.keys(tallyOf(events).events).indexOf(a.kind) - Object.keys(tallyOf(events).events).indexOf(b.kind)));
  assert.ok(result.reasons.includes("m1.tally.difference_ingress_responded") && result.reasons.includes("m1.tally.difference_l2_decided"));
  const extra = evaluateTallyAgainstLedger({ ...agree(), kindLedger: { ...ledger, counts: { ...ledger.counts, EGRESS_FAILED: 3 } } });
  assert.ok(extra.reasons.includes("m1.tally.difference_egress_failed"), "a ledger count the plane never tallied is also a difference");
});

test("a tally that violates its own identity fails even when it matches the ledger", () => {
  const snapshot = tallyOf(everything());
  const broken = { ...snapshot, events: { ...snapshot.events, L1_PASSED: snapshot.events.L1_PASSED + 1 } };
  const ledger = ledgerArtifact(everything());
  const result = evaluateTallyAgainstLedger({ ...agree(), tally: broken, kindLedger: { ...ledger, counts: { ...ledger.counts, L1_PASSED: broken.events.L1_PASSED } } });
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

test("remote traffic: ledger = journal (canary) + external counters; a different remote share is a named disagreement", () => {
  const input = agree();
  assert.equal(evaluateTallyAgainstLedger(input).outcome, "PASS");
  const external = input.external as { l1: { passed: number } };
  const dropped = evaluateTallyAgainstLedger({ ...input, external: { ...external, l1: { ...external.l1, passed: external.l1.passed - 1 } } });
  assert.ok(dropped.reasons.includes("m1.tally.ledger_vs_reducer_l1_passed"));
  assert.ok(externalKindCounts(input.external) !== null);
  // the journal (canary) is not the external lane: dropping the remote share from the reducer does not let the canary satisfy criterion 9
  const canaryOnly = validInput(workload(), []);
  assert.ok(evaluateTallyAgainstLedger(canaryOnly).reasons.includes("m1.tally.external_lane_inactive"));
});

test("hostile inputs never throw and never pass", () => {
  assert.equal(evaluateTallyAgainstLedger(null as unknown as TallyCheckInput).outcome, "ERROR");
  assert.equal(evaluateTallyAgainstLedger(undefined as unknown as TallyCheckInput).outcome, "ERROR");
  const thrower = { get tally(): unknown { throw new Error("boom"); } } as unknown as TallyCheckInput;
  assert.equal(evaluateTallyAgainstLedger(thrower).outcome, "ERROR");
});

// ---- the CLI over a finalized evidence directory written the way the field run writes it (tests/support/m1-evidence-dir.ts)
const testRoot = (): string => { const root = path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-m1tally-${process.pid}-${Math.random().toString(16).slice(2, 8)}`); fs.mkdirSync(root, { recursive: true }); return root; };
const readCheck = (root: string, id: string): Record<string, unknown> => JSON.parse(fs.readFileSync(path.join(root, id, "m1-tally-check.json"), "utf8")) as Record<string, unknown>;

test("CLI round trip over a finalized evidence directory: PASS, original artifacts untouched, a new m1-tally-check.json written", () => {
  const root = testRoot();
  try {
    const id = writeFieldLikeEvidence(root);
    const before = fs.readdirSync(path.join(root, id)).map((name) => [name, createHash("sha256").update(fs.readFileSync(path.join(root, id, name))).digest("hex")]);
    const outcome = m1TallyCheck({ serverId: id }, root);
    assert.equal(outcome.exit, TALLY_EXIT.pass, JSON.stringify(outcome.result));
    assert.deepEqual(readCheck(root, outcome.evidenceId!).tallyCheck, { evaluated: true, outcome: "PASS", reasons: [] });
    const after = fs.readdirSync(path.join(root, id)).map((name) => [name, createHash("sha256").update(fs.readFileSync(path.join(root, id, name))).digest("hex")]);
    assert.deepEqual(after, before, "the inspected evidence is byte-identical afterwards");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("CLI failures: missing tally REJECT, non-final tick REJECT, journal digest mismatch / overflow ERROR, dropped ledger events REJECT with the difference", () => {
  const root = testRoot();
  try {
    assert.equal(m1TallyCheck({ serverId: writeFieldLikeEvidence(root, { omitTally: true }) }, root).exit, TALLY_EXIT.reject);
    assert.deepEqual(m1TallyCheck({ serverId: writeFieldLikeEvidence(root, { final: false }) }, root).result?.reasons, ["m1.tally.not_final_tick"]);
    const tampered = m1TallyCheck({ serverId: writeFieldLikeEvidence(root, { journalMutator: (text) => text.replace("INGRESS_RESPONDED", "INGRESS_ABORTED") }) }, root);
    assert.equal(tampered.exit, TALLY_EXIT.error);
    assert.deepEqual(tampered.result?.reasons, ["m1.tally.evidence_journal_incomplete"]);
    assert.equal(m1TallyCheck({ serverId: writeFieldLikeEvidence(root, { overflow: true }) }, root).exit, TALLY_EXIT.error);
    const all = everything();
    const lost = all.filter((event, index) => !(index === 8 && event.kind === "INGRESS_RESPONDED"));
    const dropped = m1TallyCheck({ serverId: writeFieldLikeEvidence(root, { ledgerEvents: lost }) }, root);
    assert.equal(dropped.exit, TALLY_EXIT.reject);
    assert.ok(dropped.result?.differences.map((difference) => difference.kind).includes("INGRESS_RESPONDED"), "the dropped ledger event is named explicitly");
    assert.equal(m1TallyCheck({ serverId: writeFieldLikeEvidence(root, { artifacts: { "kind-ledger.json": null } }) }, root).result?.reasons[0], "m1.tally.kind_ledger_absent");
    assert.ok(m1TallyCheck({ serverId: writeFieldLikeEvidence(root, { artifacts: { "server-level.json": null } }) }, root).result?.reasons.includes("m1.tally.level_evidence_missing"));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("CLI: unusable inputs are REFUSED with no artifact; arguments are strict", () => {
  const root = testRoot();
  try {
    assert.equal(m1TallyCheck({ serverId: "20260101T000000Z-nothing-000000" }, root).exit, TALLY_EXIT.refused);
    const id = writeFieldLikeEvidence(root);
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
