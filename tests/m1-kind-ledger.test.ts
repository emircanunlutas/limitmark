import assert from "node:assert/strict";
import { test } from "node:test";
import { EventKindLedger, KIND_LEDGER_KINDS, KIND_LEDGER_SCHEMA } from "../lab/defense/event-kind-ledger";
import { evaluateTallyAgainstLedger, type TallyCheckInput } from "../lab/defense/m1-tally-check";
import { OutcomeCounters, type CountedEvent } from "../lab/defense/outcome-counters";

// Per-kind collector ledger (criterion 9, additive). The tally side is the real OutcomeCounters; the ledger side is the real EventKindLedger fed numbered events.

type E = CountedEvent & { kind: string };
const pass = (status: number): E[] => [
  { kind: "INGRESS_ACCEPTED" }, { kind: "L1_ENTERED" }, { kind: "L1_PASSED" }, { kind: "L2_ENTERED" }, { kind: "L2_DECIDED", class: "open", lane: "open", outcome: "admitted" },
  { kind: "EGRESS_ATTEMPTED" }, { kind: "PROOF_ISSUED" }, { kind: "EGRESS_RESPONDED", status }, { kind: "INGRESS_RESPONDED", status },
];
const events = (): E[] => [...pass(200), ...pass(200), ...pass(200), { kind: "L2_ENROLLED" }, { kind: "L2_ENROLL_SKIPPED" }];
const numbered = (list: E[]) => list.map((event, index) => ({ ...event, seq: index + 1, nonce: "n" }));
const noExternal = { accepted: 0, strippedHeaders: 0, reduced: 0, l1: { entered: 0, passed: 0, rejected: 0, shed: 0, error: 0 }, l2: { entered: 0, decided: 0 }, egress: { attempted: 0, responded: 0, failed: 0 }, proofsIssued: 0, statusHistogram: {}, clientAborted: 0 };
const countsOf = (list: E[]): Record<string, number> => { const out: Record<string, number> = {}; for (const e of list) out[e.kind] = (out[e.kind] ?? 0) + 1; return out; };

function ledgerOf(list: unknown[]) {
  const ledger = new EventKindLedger();
  for (const event of list) ledger.observe(event);
  return ledger.artifact({ received: list.length, lastSeq: list.length, droppedReported: 0 });
}
function input(list: E[] = events()): TallyCheckInput {
  const counters = new OutcomeCounters();
  for (const e of list) counters.observe(e);
  const artifact = ledgerOf(numbered(list));
  return { tally: counters.snapshot(), tallyFromFinalTick: true, journalByKind: countsOf(list), journalIncomplete: false, external: noExternal, kindLedger: artifact, planeChannel: { lastSeq: list.length, dropped: 0 } };
}
const reasonsOf = (i: TallyCheckInput) => evaluateTallyAgainstLedger(i).reasons;

test("ledger: exact integer counts per kind, ENROLL kinds included, deterministic", () => {
  const a = ledgerOf(numbered(events())); const b = ledgerOf(numbered(events()));
  assert.deepEqual(a, b);
  assert.equal(a.schema, KIND_LEDGER_SCHEMA);
  assert.equal(a.counts.INGRESS_ACCEPTED, 3); assert.equal(a.counts.L2_ENROLLED, 1); assert.equal(a.counts.L2_ENROLL_SKIPPED, 1);
  assert.equal(a.total, 29); assert.equal(a.lastSeq, 29); assert.equal(a.missingSeqs, 0);
  assert.deepEqual(Object.keys(a.counts).sort(), [...KIND_LEDGER_KINDS].sort());
});

test("ledger: gaps, duplicates, reorders, unsupported kinds and malformed events are each counted, never absorbed", () => {
  const l = new EventKindLedger();
  l.observe({ seq: 1, kind: "L1_ENTERED", nonce: "a" });
  l.observe({ seq: 1, kind: "L1_ENTERED", nonce: "a" }); // duplicate
  l.observe({ seq: 4, kind: "L1_PASSED", nonce: null }); // gap of 2
  l.observe({ seq: 3, kind: "L1_PASSED", nonce: "a" }); // reorder
  l.observe({ seq: 5, kind: "NOT_A_KIND", nonce: "a" }); // unsupported
  for (const bad of [null, 7, "x", [], {}, { seq: 0, kind: "L1_ENTERED", nonce: null }, { seq: 1.5, kind: "L1_ENTERED", nonce: null }, { seq: 6, kind: 1, nonce: null }, { seq: 6, kind: "L1_ENTERED", nonce: 4 }]) l.observe(bad);
  const a = l.artifact({ received: 0, lastSeq: 0, droppedReported: 0 });
  assert.equal(a.total, 2); assert.equal(a.duplicatesOrReordered, 2); assert.equal(a.missingSeqs, 2); assert.deepEqual(a.gapRanges, [[2, 3]]);
  assert.equal(a.unsupported, 1); assert.equal(a.malformed, 9); assert.equal(a.anonymous, 1); assert.equal(a.lastSeq, 5);
});

test("agreement with the tally, the plane anchor, the journal and the reducer -> PASS from the kind ledger", () => {
  const result = evaluateTallyAgainstLedger(input());
  assert.deepEqual(result, { evaluated: true, outcome: "PASS", reasons: [], differences: [], unobservable: [], ledgerSource: "kind-ledger" });
});

test("remote-lane traffic: ENROLL kinds are verified through the kind ledger (the journal holds none of them)", () => {
  const list = events();
  const i = input(list);
  // simulate remote lane: the reducer counted every observable kind, the journal holds nothing
  const remote = { ...noExternal, accepted: 3, l1: { entered: 3, passed: 3, rejected: 0, shed: 0, error: 0 }, l2: { entered: 3, decided: 3 }, egress: { attempted: 3, responded: 3, failed: 0 }, proofsIssued: 3, statusHistogram: { "200": 3 } };
  const result = evaluateTallyAgainstLedger({ ...i, journalByKind: { L2_ENROLLED: 1 }, external: remote });
  assert.deepEqual(result.reasons.filter((r) => r.includes("unobservable")), []);
  assert.equal(result.ledgerSource, "kind-ledger");
});

test("mutations: every deliberate inconsistency is rejected with its own reason", () => {
  const base = input();
  const art = base.kindLedger as Record<string, unknown>;
  const counts = art.counts as Record<string, number>;
  const mutate = (patch: Record<string, unknown>, countsPatch: Record<string, number> = {}): TallyCheckInput => ({ ...base, kindLedger: { ...art, ...patch, counts: { ...counts, ...countsPatch } } });
  assert.ok(reasonsOf(mutate({}, { L2_ENROLLED: 0 })).includes("m1.tally.difference_l2_enrolled"));
  assert.ok(reasonsOf(mutate({}, { L1_ENTERED: counts.L1_ENTERED + 1 })).includes("m1.tally.difference_l1_entered"));
  assert.ok(reasonsOf(mutate({ missingSeqs: 1, lastSeq: 30 })).includes("m1.tally.ledger_sequence_gap"));
  assert.ok(reasonsOf(mutate({ duplicatesOrReordered: 1 })).includes("m1.tally.ledger_duplicates_or_reordered"));
  assert.ok(reasonsOf(mutate({ malformed: 1 })).includes("m1.tally.ledger_malformed_events"));
  assert.ok(reasonsOf(mutate({ unsupported: 1, lastSeq: 30 })).includes("m1.tally.ledger_unsupported_kinds"));
  assert.ok(reasonsOf(mutate({ total: 99 })).includes("m1.tally.ledger_internally_inconsistent"));
  assert.ok(reasonsOf(mutate({ lastSeq: 40 })).includes("m1.tally.ledger_internally_inconsistent"));
  assert.ok(reasonsOf(mutate({ firstSeq: 2 })).includes("m1.tally.ledger_internally_inconsistent"));
  // anchors
  assert.ok(reasonsOf({ ...base, planeChannel: { lastSeq: 30, dropped: 0 } }).includes("m1.tally.ledger_anchor_mismatch"));
  assert.ok(reasonsOf({ ...base, planeChannel: { lastSeq: 29, dropped: 2 } }).includes("m1.tally.ledger_anchor_mismatch"));
  assert.ok(reasonsOf({ ...base, planeChannel: undefined }).includes("m1.tally.ledger_completeness_unanchored"));
  // journal and reducer cross-checks
  assert.ok(reasonsOf({ ...base, journalByKind: { ...(base.journalByKind as Record<string, number>), L1_ENTERED: 9 } }).includes("m1.tally.ledger_vs_reducer_l1_entered"));
  // tally side
  assert.ok(evaluateTallyAgainstLedger({ ...base, tally: { ...(base.tally as object), faults: 1 } }).reasons.includes("m1.tally.faults_nonzero"));
  assert.ok(evaluateTallyAgainstLedger({ ...base, tally: { ...(base.tally as object), unknown: 1 } }).reasons.includes("m1.tally.unknown_nonzero"));
});

test("malformed kind ledger shapes are ERROR (never PASS); an absent one falls back to the stricter unobservable rule", () => {
  const base = input();
  const art = base.kindLedger as Record<string, unknown>;
  for (const bad of ["x", 3, [], { unreadable: true }, { ...art, schema: "other" }, { ...art, counts: { L1_ENTERED: 1 } }, { ...art, counts: { ...(art.counts as object), L1_ENTERED: 1.5 } }, { ...art, total: -1 }, { ...art, firstSeq: 0 }]) {
    const result = evaluateTallyAgainstLedger({ ...base, kindLedger: bad });
    assert.equal(result.outcome, "ERROR", JSON.stringify(bad)?.slice(0, 50));
  }
  assert.equal(evaluateTallyAgainstLedger({ ...base, planeChannel: "x" }).outcome, "ERROR");
  const fallback = evaluateTallyAgainstLedger({ ...base, kindLedger: undefined, external: { ...noExternal, accepted: 1, l1: { entered: 1, passed: 0, rejected: 0, shed: 0, error: 0 } } });
  assert.equal(fallback.ledgerSource, "journal-and-reducer");
  assert.ok(fallback.reasons.includes("m1.tally.ledger_unobservable_l2_enrolled"));
});
