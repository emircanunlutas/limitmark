import assert from "node:assert/strict";
import { test } from "node:test";
import { EventKindLedger, KIND_LEDGER_KINDS, KIND_LEDGER_SCHEMA } from "../lab/defense/event-kind-ledger";
import { evaluateTallyAgainstLedger, findDuplicateObjectKeys, tallyCheckWellFormed, type TallyCheckInput } from "../lab/defense/m1-tally-check";
import { OutcomeCounters } from "../lab/defense/outcome-counters";
import { enroll, ledgerArtifact, levelEvidence, noExternal, pass, planeFinOf, remoteWorkload, validInput, workload, type E } from "./support/m1-tally-fixture";

// Per-kind collector ledger and the criterion 9 false-PASS closure (F-1..F-4). The tally side is the real OutcomeCounters, the ledger side the real EventKindLedger.

const events = (): E[] => [...pass(200), ...pass(200), ...pass(200), { kind: "L2_ENROLLED" }, { kind: "L2_ENROLL_SKIPPED" }];
const reasonsOf = (i: TallyCheckInput): string[] => evaluateTallyAgainstLedger(i).reasons;
const clone = <T,>(value: T): T => structuredClone(value);
const plain = (value: unknown): Record<string, unknown> => value as Record<string, unknown>;

test("ledger: exact integer counts per kind, ENROLL kinds included, deterministic", () => {
  const a = ledgerArtifact(events()); const b = ledgerArtifact(events());
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

test("complete valid evidence -> PASS, with the source named", () => {
  for (const list of [events(), workload(), [...pass(200), ...enroll]]) {
    const result = evaluateTallyAgainstLedger(validInput(list));
    assert.deepEqual(result, { evaluated: true, outcome: "PASS", reasons: [], differences: [], ledgerSource: "kind-ledger" });
    assert.equal(tallyCheckWellFormed(result), true);
  }
});

// ---------------------------------------------------------------------------------------------- F-1: closed tally key set
test("F-1: a tally with ANY expected key missing is rejected for that key (previously PASS for PROOF_ISSUED, L2_ENROLLED, L2_ENROLL_SKIPPED, PARSER_REJECTED); no key is read as zero", () => {
  const base = validInput(events());
  for (const kind of KIND_LEDGER_KINDS) {
    const tally = clone(plain(base.tally)); delete plain(tally.events)[kind];
    const result = evaluateTallyAgainstLedger({ ...base, tally });
    assert.notEqual(result.outcome, "PASS", `deleting ${kind}`);
    assert.ok(result.reasons.includes(`m1.tally.tally_key_missing_${kind.toLowerCase()}`) || result.outcome === "ERROR", `${kind}: ${result.reasons.join(",")}`);
  }
  const emptyEvents = clone(plain(base.tally)); emptyEvents.events = {};
  assert.equal(evaluateTallyAgainstLedger({ ...base, tally: emptyEvents }).outcome, "REJECT");
});

test("F-1: an unexpected extra key (even with value zero) is rejected; so are invalid values", () => {
  const base = validInput(events());
  const extra = clone(plain(base.tally)); plain(extra.events).BOGUS = 0;
  assert.ok(reasonsOf({ ...base, tally: extra }).includes("m1.tally.tally_key_unexpected"));
  for (const bad of [-1, 1.5, NaN, Infinity, 2 ** 60, "3", null, undefined, true]) {
    const tally = clone(plain(base.tally)); plain(tally.events).L1_ENTERED = bad;
    assert.equal(evaluateTallyAgainstLedger({ ...base, tally }).outcome, "ERROR", String(bad));
  }
});

test("F-1: duplicate JSON keys are detected in the raw text (JSON.parse would keep the last silently) and reject", () => {
  assert.deepEqual(findDuplicateObjectKeys('{"a":1,"b":{"c":1,"c":2}}'), ["$.b:c"]);
  assert.deepEqual(findDuplicateObjectKeys('{"a":[{"x":1},{"x":2}],"b":"a\\"a","c":{"d":1}}'), [], "same key in different objects, escapes, nesting: no false positive");
  assert.deepEqual(findDuplicateObjectKeys('{"events":{"L1_ENTERED":1,"L1_ENTERED":0}}'), ["$.events:L1_ENTERED"]);
  assert.deepEqual(findDuplicateObjectKeys("not json"), []);
  assert.ok(reasonsOf({ ...validInput(events()), duplicateKeys: ["telemetry.json$.events:L1_ENTERED"] }).includes("m1.tally.duplicate_json_keys"));
});

// ---------------------------------------------------------------------------------------------- F-2: the kind ledger is mandatory
test("F-2: an absent kind ledger is REJECT in every circumstance (no weaker fallback), and a malformed or inconsistent one never passes", () => {
  const base = validInput(events());
  for (const absent of [undefined, null]) {
    const result = evaluateTallyAgainstLedger({ ...base, kindLedger: absent });
    assert.deepEqual([result.outcome, result.reasons, result.ledgerSource], ["REJECT", ["m1.tally.kind_ledger_absent"], "none"]);
  }
  // remote traffic accepted and no enrollment key in the tally: the old fallback passed; now it rejects
  const remote = { ...noExternal, accepted: 1, l1: { entered: 1, passed: 0, rejected: 0, shed: 0, error: 0 } };
  assert.equal(evaluateTallyAgainstLedger({ ...base, kindLedger: undefined, external: remote }).outcome, "REJECT");
  const art = plain(base.kindLedger);
  for (const bad of ["x", 3, [], { unreadable: true }, { ...art, schema: "other" }, { ...art, counts: { L1_ENTERED: 1 } }, { ...art, counts: { ...plain(art.counts), L1_ENTERED: 1.5 } }, { ...art, total: -1 }, { ...art, firstSeq: 0 }, { ...art, collector: undefined }, { ...art, collector: { received: 1 } }]) {
    assert.equal(evaluateTallyAgainstLedger({ ...base, kindLedger: bad }).outcome, "ERROR", JSON.stringify(bad)?.slice(0, 50));
  }
  const c = (patch: Record<string, unknown>, countsPatch: Record<string, number> = {}) => ({ ...base, kindLedger: { ...art, ...patch, counts: { ...plain(art.counts), ...countsPatch } } });
  assert.ok(reasonsOf(c({ total: 99 })).includes("m1.tally.ledger_internally_inconsistent"));
  assert.ok(reasonsOf(c({ lastSeq: 40 })).includes("m1.tally.ledger_internally_inconsistent"));
  assert.ok(reasonsOf(c({ firstSeq: 2 })).includes("m1.tally.ledger_internally_inconsistent"));
});

// ---------------------------------------------------------------------------------------------- F-3: the channel accounting contract
test("F-3: every channel identity is enforced; each contradiction rejects (previously PASS for emitted/unacknowledged/queued/collector.received)", () => {
  const base = validInput(events());
  const fin = (patch: Record<string, unknown>, channelPatch: Record<string, unknown> = {}) => ({ ...base, planeFin: { ...plain(base.planeFin), ...patch, channel: { ...plain(plain(base.planeFin).channel), ...channelPatch } } });
  const n = events().length + remoteWorkload().length;
  assert.ok(reasonsOf(fin({}, { emitted: 99 })).includes("m1.tally.channel_emitted_vs_lastseq"));
  assert.ok(reasonsOf(fin({}, { sent: n - 1 })).includes("m1.tally.channel_emitted_identity"));
  assert.ok(reasonsOf(fin({}, { queued: 1 })).includes("m1.tally.channel_emitted_identity"));
  assert.ok(reasonsOf(fin({}, { unacknowledged: 7 })).includes("m1.tally.channel_unacknowledged_identity"));
  assert.ok(reasonsOf(fin({}, { received: n - 1, unacknowledged: 1 })).includes("m1.tally.channel_not_quiescent"));
  assert.ok(reasonsOf(fin({ drained: false })).includes("m1.tally.channel_not_quiescent"));
  assert.ok(reasonsOf(fin({}, { dropped: 2, emitted: n + 2, lastSeq: n + 2 })).includes("m1.tally.channel_dropped_nonzero"));
  assert.ok(reasonsOf(fin({}, { lastSeq: n + 1, emitted: n + 1, sent: n + 1, received: n + 1 })).includes("m1.tally.ledger_anchor_mismatch"));
  assert.ok(reasonsOf(fin({}, { received: n - 3, unacknowledged: 3 })).includes("m1.tally.channel_received_vs_collector"));
  // the collector's own counters
  const art = plain(base.kindLedger); const col = (patch: Record<string, number>) => ({ ...base, kindLedger: { ...art, collector: { ...plain(art.collector), ...patch } } });
  assert.ok(reasonsOf(col({ received: 3 })).includes("m1.tally.collector_received_vs_ledger"));
  assert.ok(reasonsOf(col({ received: 3 })).includes("m1.tally.collector_received_vs_emitted"));
  assert.ok(reasonsOf(col({ lastSeq: 5 })).includes("m1.tally.collector_lastseq_mismatch"));
  assert.ok(reasonsOf(col({ droppedReported: 4 })).includes("m1.tally.collector_dropped_reported"));
  // missing final anchors: unanchored, never completeness by default; malformed anchors are ERROR
  for (const absent of [undefined, null]) assert.ok(reasonsOf({ ...base, planeFin: absent }).includes("m1.tally.ledger_completeness_unanchored"));
  for (const bad of ["no_fin", 3, { drained: true }, { drained: true, channel: {} }, { drained: "yes", channel: plain(base.planeFin).channel }, { drained: true, channel: { ...plain(plain(base.planeFin).channel), sent: -1 } }, { drained: true, channel: { ...plain(plain(base.planeFin).channel), lastSeq: 1.5 } }]) {
    assert.equal(evaluateTallyAgainstLedger({ ...base, planeFin: bad }).outcome, "ERROR", JSON.stringify(bad)?.slice(0, 60));
  }
});

test("channel loss and ordering faults reach REJECT from the evaluator (transit loss, trailing loss, shared anchor, duplicates, reorders)", () => {
  const list = [...pass(200), ...pass(200)];
  const tally = (() => { const c = new OutcomeCounters(); for (const e of list) c.observe(e); return c.snapshot(); })();
  const withLedger = (ledger: EventKindLedger, n: number, fin = planeFinOf(list.length)) => ({ ...validInput(list), tally, kindLedger: ledger.artifact({ received: n, lastSeq: n, droppedReported: 0 }), planeFin: fin });
  const lose = (skip: (i: number) => boolean, dup = false) => { const l = new EventKindLedger(); let n = 0; list.forEach((e, i) => { if (skip(i)) return; n++; l.observe({ ...e, seq: i + 1, nonce: "n" }); if (dup && i === 5) l.observe({ ...e, seq: i + 1, nonce: "n" }); }); return { l, n }; };
  const mid = lose((i) => i === 3); // one event lost in transit
  assert.ok(reasonsOf(withLedger(mid.l, mid.n)).includes("m1.tally.ledger_sequence_gap"));
  const tail = lose((i) => i === list.length - 1); // trailing loss: the plane anchor says 18
  assert.ok(reasonsOf(withLedger(tail.l, tail.n)).includes("m1.tally.ledger_anchor_mismatch"));
  const dup = lose(() => false, true);
  assert.ok(reasonsOf(withLedger(dup.l, dup.n + 1)).includes("m1.tally.ledger_duplicates_or_reordered"));
  const reorder = new EventKindLedger(); list.forEach((e, i) => reorder.observe({ ...e, seq: i === 4 ? 6 : i === 5 ? 5 : i + 1, nonce: "n" }));
  assert.ok(reasonsOf(withLedger(reorder, list.length)).some((r) => r === "m1.tally.ledger_duplicates_or_reordered" || r === "m1.tally.ledger_sequence_gap"));
});

// ---------------------------------------------------------------------------------------------- F-4: a completed, non-empty level
test("F-4: an empty level (previously PASS) and missing, incomplete or contradictory level evidence reject", () => {
  const empty = evaluateTallyAgainstLedger(validInput([], []));
  assert.equal(empty.outcome, "REJECT");
  assert.ok(empty.reasons.includes("m1.tally.level_empty"), empty.reasons.join(","));
  // zero events everywhere while the plane's anchor says events were emitted
  assert.ok(reasonsOf({ ...validInput([], []), planeFin: planeFinOf(18) }).includes("m1.tally.ledger_anchor_mismatch"));
  const base = validInput(events());
  for (const absent of [undefined, null]) assert.ok(reasonsOf({ ...base, level: absent }).includes("m1.tally.level_evidence_missing"));
  const lvl = (mutate: (l: ReturnType<typeof levelEvidence>) => void) => { const l = clone(levelEvidence()); mutate(l); return { ...base, level: l }; };
  assert.ok(reasonsOf(lvl((l) => { l.core.level.id = "ba0-other"; })).includes("m1.tally.level_identity_mismatch"));
  assert.ok(reasonsOf(lvl((l) => { l.serverLevel.serverSide.status = "stopped"; })).includes("m1.tally.level_not_complete"));
  assert.ok(reasonsOf(lvl((l) => { l.serverLevel.serverSide.failureClass = "defense" as unknown as null; })).includes("m1.tally.level_not_complete"));
  assert.ok(reasonsOf(lvl((l) => { (l.serverLevel.serverSide.reasons as unknown[]).push({ code: "x" }); })).includes("m1.tally.level_not_complete"));
  assert.ok(reasonsOf(lvl((l) => { l.core.machine.phasesCompleted = false; })).includes("m1.tally.level_not_complete"));
  assert.ok(reasonsOf(lvl((l) => { l.manifest.result = "SERVER-ABORTED"; })).includes("m1.tally.level_not_complete"));
  for (const bad of ["x", 3, { serverLevel: {}, core: {}, manifestResult: "SERVER-COMPLETE" }, { ...levelEvidence(), manifest: { result: 3, git: { gitSha: "a".repeat(40) } } }, { ...levelEvidence(), serverLevel: { ...levelEvidence().serverLevel, schema: "v0" } }]) {
    assert.equal(evaluateTallyAgainstLedger({ ...base, level: bad }).outcome, "ERROR", JSON.stringify(bad)?.slice(0, 50));
  }
});

// ---------------------------------------------------------------------------------------------- cross records and the lower bound
test("the journal and reducer cross-checks still reject; enrollment kinds use a lower bound only and equality with the tally still applies", () => {
  const base = validInput(events());
  const j = base.journalByKind as Record<string, number>;
  assert.equal(evaluateTallyAgainstLedger(base).outcome, "PASS");
  assert.ok(reasonsOf({ ...base, journalByKind: { ...j, L1_ENTERED: 9 } }).includes("m1.tally.ledger_vs_reducer_l1_entered"));
  const art = plain(base.kindLedger); const counts = plain(art.counts) as Record<string, number>;
  // a ledger enrollment count above the journal is allowed by the lower bound, but the tally must equal it
  const inflated = { ...base, kindLedger: { ...art, counts: { ...counts, L2_ENROLLED: counts.L2_ENROLLED + 4 } } };
  assert.ok(reasonsOf(inflated).includes("m1.tally.difference_l2_enrolled"));
  // the journal holding more enrollments than the ledger saw is impossible
  assert.ok(reasonsOf({ ...base, journalByKind: { ...j, L2_ENROLLED: counts.L2_ENROLLED + 3 } }).includes("m1.tally.ledger_vs_reducer_l2_enrolled"));
});

test("tally-side faults still reject: faults, unknown, final tick, absent tally", () => {
  const base = validInput(events());
  assert.ok(reasonsOf({ ...base, tally: { ...plain(base.tally), faults: 1 } }).includes("m1.tally.faults_nonzero"));
  assert.ok(reasonsOf({ ...base, tally: { ...plain(base.tally), unknown: 1 } }).includes("m1.tally.unknown_nonzero"));
  assert.ok(reasonsOf({ ...base, tallyFromFinalTick: false }).includes("m1.tally.not_final_tick"));
  assert.deepEqual(reasonsOf({ ...base, tally: undefined }), ["m1.tally.tally_missing"]);
});

test("hostile combinations of incomplete evidence never PASS and never throw", () => {
  const base = validInput(events());
  const fields = ["tally", "journalByKind", "external", "kindLedger", "planeFin", "level", "connections", "boundaryFin", "appFin"] as const;
  for (const field of fields) for (const value of [undefined, null, 0, "", [], {}, "x"]) {
    const input = { ...base, [field]: value } as unknown as TallyCheckInput;
    assert.notEqual(evaluateTallyAgainstLedger(input).outcome, "PASS", `${field}=${JSON.stringify(value)}`);
  }
  for (let mask = 1; mask < 2 ** fields.length; mask++) {
    const input: Record<string, unknown> = { ...base };
    fields.forEach((field, index) => { if (mask & (1 << index)) input[field] = undefined; });
    assert.notEqual(evaluateTallyAgainstLedger(input as unknown as TallyCheckInput).outcome, "PASS", `mask ${mask}`);
  }
  const thrower = { get tally(): unknown { throw new Error("boom"); } } as unknown as TallyCheckInput;
  assert.equal(evaluateTallyAgainstLedger(thrower).outcome, "ERROR");
});

test("duplicate-key detection: escaped spellings, whitespace, nested arrays and __proto__ are caught; distinct keys and invalid JSON are not mistaken for duplicates", () => {
  assert.deepEqual(findDuplicateObjectKeys('{"a":1,"\u0061":2}'), ["$:a"], "an escaped spelling of the same key is the same key");
  assert.deepEqual(findDuplicateObjectKeys('{\n "a" : 1 ,\n "a" : 2 }'), ["$:a"]);
  assert.deepEqual(findDuplicateObjectKeys('{"x":[{"k":1}],"x":2}'), ["$:x"]);
  assert.deepEqual(findDuplicateObjectKeys('{"__proto__":1,"__proto__":2}'), ["$:__proto__"]);
  assert.deepEqual(findDuplicateObjectKeys('{"a":true,"b":null,"c":-1.5e3,"c":2}'), ["$:c"]);
  assert.deepEqual(findDuplicateObjectKeys('{"a":1,"A":2}'), [], "keys differing in case are different keys");
  assert.deepEqual(findDuplicateObjectKeys('{"a":1,"a":2,}'), [], "invalid JSON is reported by the parser that every consumer runs, not here");
});
