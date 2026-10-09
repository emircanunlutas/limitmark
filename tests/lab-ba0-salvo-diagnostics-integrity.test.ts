import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { FINDING_CODES, SEVERITIES, evaluateSalvoDiagnostics, worstOf, type Severity, type SalvoDiagnosticConsistency } from "../lab/defense/salvo-diagnostic-check";
import { SALVO_SPEC } from "../lab/defense/salvo-spec";
import { assertEvidenceSafe } from "../lab/evidence/redact";
import { sendClosedLoop } from "../lab/load/closed-loop";
import { authorizeRun, buildRegistry, type AuthorizedRun } from "../lab/policy/target-policy";
import { campaign, generatorDiagnostics, generatorPairsFrom, observe, record, stream, type Spec } from "./support/salvo-diagnostic-fixtures";

const root = path.join(__dirname, "..");
const clone = <T>(value: T): T => structuredClone(value);
const SIGNALS = ["integrity", "composition", "binding", "signature"] as const;
const observable = (c: SalvoDiagnosticConsistency) => JSON.stringify(SIGNALS.map((k) => c[k]));

/** Invariants that must hold for every result, whatever the input. */
function invariants(c: SalvoDiagnosticConsistency): SalvoDiagnosticConsistency {
  assert.equal(c.influencesVerdict, false);
  assert.equal(c.binding.pairs.verified, 0, "no end-to-end identifier exists, so no pair can be verified");
  assert.equal(c.binding.identityEvidence, "none"); assert.notEqual(c.binding.status, "verified");
  assert.equal(c.binding.pairs.inferred + c.binding.pairs.unverified + c.binding.pairs.contradicted, SALVO_SPEC.pairs);
  if (c.integrity !== "absent") assert.equal(c.integrity, worstOf(...c.findings.map((f) => f.severity)), "integrity is exactly the worst finding");
  assert.equal(new Set(c.findings.map((f) => f.code)).size, c.findings.length); assert.ok(c.findings.every((f) => FINDING_CODES.includes(f.code)));
  assert.doesNotThrow(() => assertEvidenceSafe(c));
  return c;
}
const check = (input: Parameters<typeof evaluateSalvoDiagnostics>[0]) => invariants(evaluateSalvoDiagnostics(input));
const codes = (c: SalvoDiagnosticConsistency) => c.findings.map((f) => f.code);
const swapWindows = (specs: Spec[], pairA: number, pairB: number) => {
  const out = specs.map((s) => ({ ...s }));
  for (const slot of [0, 1]) { const a = out[2 * pairA + slot]; const b = out[2 * pairB + slot]; [a.at, b.at] = [b.at, a.at]; [a.end, b.end] = [b.end, a.end]; }
  return out;
};

// ============================================================================================================== BLOCKER-01: binding is never identity
test("binding: matching all 750 signatures yields at most `inferred`; identity evidence is none and `verified` is unreachable by construction", () => {
  const c = check({ server: record(stream(campaign({ shedOdd: true }))), generator: generatorDiagnostics() });
  assert.equal(c.signature.status, "compatible"); assert.equal(c.signature.compatible, 750);
  assert.equal(c.binding.status, "inferred"); assert.deepEqual(c.binding.pairs, { verified: 0, inferred: 750, unverified: 0, contradicted: 0 });
  assert.equal(c.binding.basis, "ordinal.and.composition"); assert.equal(c.binding.identityEvidence, "none");
  // Structural guard: the implementation contains no assignment of the `verified` state.
  const source = readFileSync(path.join(root, "lab/defense/salvo-diagnostic-check.ts"), "utf8").split("\n").filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l));
  assert.deepEqual(source.filter((l) => /["']verified["']/.test(l)).map((l) => l.trim()), ['export type BindingStatus = "verified" | "inferred" | "unverified" | "contradicted";']);
  // Without a generator there is nothing to bind to: unverified, never inferred.
  const alone = check({ server: record(stream(campaign({ shedOdd: true }))) });
  assert.equal(alone.binding.status, "unverified"); assert.equal(alone.binding.pairs.inferred, 0); assert.equal(alone.signature.status, "absent");
});

test("binding: shifted ordinals, a dropped plus an extra request, and swaps of equivalent pairs are INDISTINGUISHABLE from a correct sequence in every recorded field, and are never verified", () => {
  const base = campaign({ shedOdd: true }); const gen = generatorDiagnostics();
  const correct = check({ server: record(stream(base)), generator: gen });
  const shifted = base.slice(1); shifted.push({ nonce: "extra-open", cls: "open", at: 60_000, end: 60_006 });                       // first request lost, one extra: still 1,500 records
  const dropped = base.filter((_, i) => i !== 700); dropped.push({ nonce: "extra-open-2", cls: "open", at: 60_000, end: 60_006 });
  const evenSwap = swapWindows(base, 10, 12); const oddSwap = swapWindows(base, 11, 13);
  for (const [name, specs] of [["shifted", shifted], ["dropped_plus_extra", dropped], ["even_swap", evenSwap], ["odd_swap", oddSwap]] as const) {
    const c = check({ server: record(stream(specs)), generator: gen });
    assert.equal(c.binding.pairs.verified, 0, name); assert.equal(c.binding.status, "inferred", `${name}: assumptions satisfied, identity unproven`);
    // The honest limitation: nothing the diagnostics record separates these from the correct campaign.
    assert.equal(observable(c), observable(correct), `${name} cannot be told apart from a correct sequence by class/status signature`);
  }
  // Pair swaps of equivalent pairs change nothing at all in the server records.
  assert.deepEqual(record(stream(evenSwap)).requests, record(stream(base)).requests); assert.deepEqual(record(stream(oddSwap)).requests, record(stream(base)).requests);
});

test("binding: a swap that changes an observable status IS contradicted, and a class contradiction stays inconsistent", () => {
  const base = campaign({ shedOdd: true }); base[2 * 13 + 1].shed = false;                       // pair 13's mutation is admitted (200); pair 11's is shed (503)
  const gen = generatorDiagnostics((p, s) => (p % 2 === 1 && s === 1 ? (p === 13 ? 200 : 503) : 200));
  const aligned = check({ server: record(stream(base)), generator: gen });
  assert.equal(aligned.binding.status, "inferred");
  const swapped = check({ server: record(stream(swapWindows(base, 11, 13))), generator: gen });          // the two statuses now sit in each other's pair
  assert.equal(swapped.signature.status, "incompatible"); assert.deepEqual(swapped.signature.incompatibleIndices, [11, 13]);
  assert.equal(swapped.binding.status, "contradicted"); assert.deepEqual(swapped.binding.contradictedIndices, [11, 13]); assert.equal(swapped.integrity, "inconsistent");
  const wrongClass = campaign({ shedOdd: true }); wrongClass[2 * 10].cls = "mutation";
  const c = check({ server: record(stream(wrongClass)), generator: generatorDiagnostics() });
  assert.equal(c.composition, "inconsistent"); assert.deepEqual(c.pairs.inconsistentIndices, [10]); assert.equal(c.binding.status, "contradicted"); assert.deepEqual(c.binding.contradictedIndices, [10]);
});

test("binding: reversed arrival inside a correctly composed pair is permissible and binds by class, not by position", () => {
  const c = check({ server: record(stream(campaign({ shedOdd: true, reversed: (p) => p % 2 === 1 }))), generator: generatorDiagnostics() });
  assert.equal(c.composition, "consistent"); assert.equal(c.integrity, "consistent"); assert.equal(c.signature.status, "compatible"); assert.equal(c.binding.status, "inferred");
});

test("binding: unknown identity is not an integrity failure, and is reported per pair as `unverified`", () => {
  const specs = campaign({ shedOdd: true }); specs[2 * 50 + 1].l1 = "rejected";                      // a request that never reached L2: its class was never decided
  const c = check({ server: record(stream(specs)), generator: generatorDiagnostics() });
  assert.equal(c.integrity, "consistent", "the records are complete, well-formed and causally ordered");
  assert.equal(c.composition, "unknown"); assert.deepEqual(c.pairs.unknownIndices, [50]);
  assert.equal(c.binding.status, "unverified"); assert.equal(c.binding.pairs.unverified, 1); assert.equal(c.binding.pairs.inferred, 749); assert.equal(c.binding.pairs.contradicted, 0);
});

// ============================================================================================================== IMPORTANT-02: generator timestamps and causality
const withPairs = () => {
  const gen = generatorDiagnostics(); const events = stream(campaign({ shedOdd: true }));
  return { gen, server: record(events), serverPairs: observe(events).snapshotSalvo().pairs, generatorPairs: generatorPairsFrom(gen) };
};
const run = (m: ReturnType<typeof withPairs>) => check({ server: m.server, generator: m.gen, serverPairs: m.serverPairs, generatorPairs: m.generatorPairs });

test("generator timestamps (1) exact agreement with the authoritative pair records is consistent", () => {
  const c = run(withPairs());
  assert.deepEqual(c.pairRecordAgreement.generator, { compared: 1500, mismatched: 0 }); assert.deepEqual(c.pairRecordAgreement.server, { compared: 1500, mismatched: 0 });
  assert.equal(c.integrity, "consistent"); assert.deepEqual(c.findings, []);
});

test("generator timestamps (2, 3) one modified timestamp, or all 1,500, is inconsistent and says so", () => {
  const one = withPairs(); one.gen.requests[10].startMs += 0.001;
  const c1 = run(one); assert.deepEqual(c1.pairRecordAgreement.generator, { compared: 1500, mismatched: 1 }); assert.equal(c1.integrity, "inconsistent"); assert.deepEqual(codes(c1), ["generator_pair_mismatch"]);
  const allDiag = withPairs(); for (const r of allDiag.gen.requests) { r.startMs += 1; r.settledMs! += 1; if (r.handoffMs !== null) r.handoffMs += 1; }
  const c2 = run(allDiag); assert.deepEqual(c2.pairRecordAgreement.generator, { compared: 1500, mismatched: 1500 }); assert.equal(c2.integrity, "inconsistent");
  const allPairs = withPairs(); for (const p of allPairs.generatorPairs) p.startsMs = p.startsMs.map((x) => x! + 1);       // or the authoritative side moved instead
  assert.equal(run(allPairs).pairRecordAgreement.generator === "not_supplied" ? -1 : (run(allPairs).pairRecordAgreement.generator as { mismatched: number }).mismatched, 1500);
  // A settled pair-record slot with no diagnostic row is a disagreement; an unsent slot (a start without a settlement) is not.
  const orphan = withPairs(); orphan.gen.requests = orphan.gen.requests.filter((r) => !(r.pair === 3 && r.slot === 1));
  assert.deepEqual(codes(run(orphan)).filter((x) => x === "generator_pair_mismatch"), ["generator_pair_mismatch"]);
  const unsent = withPairs(); unsent.gen.requests = unsent.gen.requests.filter((r) => !(r.pair === 749 && r.slot === 1)); unsent.generatorPairs[749].settledMs[1] = null;
  assert.ok(!codes(run(unsent)).includes("generator_pair_mismatch"));
});

test("generator timestamps (4, 5, 6, 7) handoff before start is inconsistent; equal to or after start is consistent; missing is unknown, never invalid", () => {
  const m = withPairs(); const r = m.gen.requests[10];
  r.handoffMs = r.startMs - 0.001;
  let c = run(m); assert.equal(c.integrity, "inconsistent"); assert.deepEqual(codes(c), ["handoff_before_start"]);
  assert.equal((c.generator as { handoffBeforeStart: number }).handoffBeforeStart, 1);
  r.handoffMs = r.startMs; c = run(m); assert.equal(c.integrity, "consistent", "equal is allowed: a coarse clock can read the same value");
  r.handoffMs = r.startMs + 0.25; c = run(m); assert.equal(c.integrity, "consistent");
  r.handoffMs = null; c = run(m); assert.equal(c.integrity, "unknown"); assert.deepEqual(codes(c), ["handoff_missing"]);
  assert.equal((c.generator as { handoffMissing: number }).handoffMissing, 1);
  const none = withPairs(); for (const row of none.gen.requests) row.handoffMs = null;           // a sender that never reports a handoff: unobserved, not wrong
  assert.equal(run(none).integrity, "unknown"); assert.equal(run(none).binding.status, "inferred", "unknown handoff data does not touch the signature binding");
});

test("generator timestamps (8, 9) handoff after settlement and settlement before start are inconsistent; invalid timestamps are malformed", () => {
  const m = withPairs(); const r = m.gen.requests[20];
  r.handoffMs = r.settledMs! + 0.001; let c = run(m);
  assert.equal(c.integrity, "inconsistent"); assert.deepEqual(codes(c), ["handoff_after_settlement"]);
  r.handoffMs = r.settledMs!; assert.equal(run(m).integrity, "consistent", "handoff equal to settlement is allowed");
  const early = withPairs(); early.gen.requests[30].settledMs = early.gen.requests[30].startMs - 1; early.gen.requests[30].handoffMs = null;
  early.generatorPairs[15].settledMs[0] = early.gen.requests[30].settledMs;
  c = run(early); assert.equal(c.integrity, "inconsistent"); assert.ok(codes(c).includes("settled_before_start"));
  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1, "5" as unknown as number, null as unknown as number]) {
    const g = clone(withPairs().gen); g.requests[5].startMs = bad;
    const malformed = check({ generator: g }); assert.equal(malformed.integrity, "malformed", String(bad)); assert.equal(malformed.inputs.generator, "malformed"); assert.deepEqual(malformed.findings, [{ code: "generator_malformed", severity: "malformed" }]);
  }
  const g2 = clone(withPairs().gen); g2.requests[5].handoffMs = Number.NaN; assert.equal(check({ generator: g2 }).integrity, "malformed");
  const g3 = clone(withPairs().gen); g3.requests[5].status = 99; assert.equal(check({ generator: g3 }).integrity, "malformed");
});

test("generator timestamps (10) partial and aborted generator records are unknown, never consistent and never falsely inconsistent", () => {
  const partial = withPairs(); partial.gen.requests = partial.gen.requests.slice(0, 41);
  partial.generatorPairs.forEach((p, i) => { if (i > 20) { p.startsMs = [null, null]; p.settledMs = [null, null]; } });
  const last = partial.gen.requests[40]; last.settledMs = null; last.status = null; last.handoffMs = null; partial.generatorPairs[20].settledMs[0] = null;
  partial.generatorPairs[20].startsMs[1] = null; partial.generatorPairs[20].settledMs[1] = null;          // the partner slot was never dispatched
  let c = run(partial); assert.equal(c.integrity, "unknown"); assert.ok(codes(c).includes("generator_incomplete") && codes(c).includes("generator_unsettled"));
  assert.ok(!codes(c).includes("generator_pair_mismatch"), "an aborted run's unsettled slot agrees with its own pair record");
  const aborted = withPairs(); const row = aborted.gen.requests[100]; row.status = null;           // aborted: settled by the abort, no response
  c = run(aborted); assert.equal(c.integrity, "consistent"); assert.equal(c.signature.compared, 749, "the pair with an unknown status is uncompared, not agreed");
  assert.equal(c.binding.status, "unverified");
});

test("handoff lifecycle: a genuine sender never reports a handoff after its own settlement, even when the server answers before the body is written", async () => {
  // Early answer: the server replies and closes without reading a large body, so the response can settle the request before `finish` would.
  const server = http.createServer((_req, res) => { res.writeHead(503, { connection: "close" }); res.end(); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as net.AddressInfo).port;
  const now = new Date(); const registry = buildRegistry([{ id: "salvo-test", class: "lab-local", scheme: "http", host: "127.0.0.1", port, allowedPaths: ["/api/public-inquiries"], allowedMethods: ["POST"] }], now);
  const authorized = authorizeRun({ targetId: "salvo-test", workloadId: "demo-submission-post", registry, now }) as AuthorizedRun;
  const agent = new http.Agent({ keepAlive: false });
  try {
    let violations = 0; let calls = 0;
    for (let i = 0; i < 25; i++) {
      let settledAt: number | null = null;
      const done = sendClosedLoop(authorized.authorizeRequest("POST", "/api/public-inquiries"), authorized, { timeoutMs: 5000, agent, body: "a=".padEnd(2_000_000, "x"),
        onWriteHandoff: () => { calls++; if (settledAt !== null) violations++; } }).then((r) => { settledAt = performance.now(); return r; });
      await done; const before = calls; await new Promise((resolve) => setTimeout(resolve, 15));
      assert.equal(calls, before, "no handoff is reported after the send settled");
    }
    assert.equal(violations, 0); assert.ok(calls >= 0);
  } finally { agent.destroy(); server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); }
});

// ============================================================================================================== IMPORTANT-03: severity precedence
test("precedence: worstOf is malformed > inconsistent > unknown > consistent, over every pair and every ordering", () => {
  const rank = { consistent: 0, unknown: 1, inconsistent: 2, malformed: 3 } as const;
  for (const a of SEVERITIES) for (const b of SEVERITIES) {
    assert.equal(worstOf(a, b), rank[a] >= rank[b] ? a : b, `${a},${b}`); assert.equal(worstOf(a, b), worstOf(b, a));
    for (const c of SEVERITIES) assert.equal(worstOf(worstOf(a, b), c), worstOf(a, worstOf(b, c)));
  }
  const permutations = (xs: Severity[]): Severity[][] => (xs.length <= 1 ? [xs] : xs.flatMap((x, i) => permutations([...xs.slice(0, i), ...xs.slice(i + 1)]).map((p) => [x, ...p])));
  for (const p of permutations([...SEVERITIES])) assert.equal(worstOf(...p), "malformed");
  assert.equal(worstOf(), "consistent");
  for (const p of permutations(["unknown", "consistent", "inconsistent"])) assert.equal(worstOf(...p), "inconsistent");
});

test("precedence: evaluator transitions. A proven contradiction overrides unknown in either order; malformed is never downgraded", () => {
  const make = () => withPairs();
  // consistent -> unknown
  const lost = campaign({ shedOdd: true }).map((s, i) => (i === 200 ? { ...s, fin: "pending" as const } : s));
  const pending = make(); pending.server = record(stream(lost));
  assert.equal(check({ server: pending.server, generator: pending.gen }).integrity, "unknown");
  // With the observer's own pair records supplied, the same lost response is a PROVEN divergence (the observer keeps only two pending nonces and later pairs fault).
  const lostPairs = observe(stream(lost)).snapshotSalvo().pairs;
  assert.equal(check({ server: pending.server, serverPairs: lostPairs }).integrity, "inconsistent");
  // consistent -> inconsistent
  const tamper = make(); tamper.serverPairs[100].settledMs[0] = (tamper.serverPairs[100].settledMs[0] as number) + 1;
  assert.equal(run(tamper).integrity, "inconsistent");
  // unknown -> inconsistent (the reviewed case: an earlier uncertainty must not hide a later proven mismatch)
  const both = make(); both.server = pending.server; both.serverPairs = clone(make().serverPairs); both.serverPairs[300].settledMs[0] = (both.serverPairs[300].settledMs[0] as number) + 1;
  const bothResult = run(both); assert.equal(bothResult.integrity, "inconsistent"); assert.deepEqual(bothResult.findings.map((f) => [f.code, f.severity]), [["server_pair_mismatch", "inconsistent"], ["incomplete_records", "unknown"]]);
  // the reviewer's exact scenario: duplicate identifier (unknown) plus an authoritative pair mismatch
  const dupSpecs = campaign({ shedOdd: true }); dupSpecs[41].nonce = dupSpecs[40].nonce;
  const sp = observe(stream(campaign({ shedOdd: true }))).snapshotSalvo().pairs; sp[100].settledMs[0] = (sp[100].settledMs[0] as number) + 1;
  const dup = check({ server: record(stream(dupSpecs)), serverPairs: sp }); assert.equal(dup.integrity, "inconsistent"); assert.ok(codes(dup).includes("reused_key") && codes(dup).includes("server_pair_mismatch"));
  // inconsistent -> unknown: adding an unknown finding to an inconsistent result cannot lower it (pending is present in `both`)
  assert.equal(worstOf("inconsistent", "unknown"), "inconsistent"); assert.equal(bothResult.integrity, "inconsistent");
  // inconsistent -> malformed, and malformed -> inconsistent
  const inconsistentThenMalformed = check({ server: both.server, serverPairs: both.serverPairs, generator: { not: "a diagnostics document" } });
  assert.equal(inconsistentThenMalformed.integrity, "malformed"); assert.ok(codes(inconsistentThenMalformed).includes("server_pair_mismatch"), "the earlier finding is kept alongside the malformed one");
  const badHandoff = make(); badHandoff.gen.requests[10].handoffMs = badHandoff.gen.requests[10].startMs - 1;
  const malformedThenInconsistent = check({ server: { nope: 1 }, generator: badHandoff.gen });
  assert.equal(malformedThenInconsistent.integrity, "malformed"); assert.deepEqual(codes(malformedThenInconsistent), ["server_malformed", "handoff_before_start"]);
  assert.equal(malformedThenInconsistent.composition, "malformed");
});

test("precedence: combinations of duplicate ids, missing records, mismatches, handoff violations, signature disagreement and partial evidence take the worst finding", () => {
  type Model = ReturnType<typeof withPairs> & { specs: Spec[]; tamperServerPair?: number; dropPairRecords?: boolean };
  type Mutation = { name: string; expect: Severity; apply: (m: Model) => void };
  const mutations: Mutation[] = [
    { name: "missing response", expect: "unknown", apply: (m) => { m.specs[2 * 400].fin = "pending"; } },
    { name: "authoritative mismatch", expect: "inconsistent", apply: (m) => { m.tamperServerPair = 600; } },
    { name: "handoff before start", expect: "inconsistent", apply: (m) => { m.gen.requests[50].handoffMs = m.gen.requests[50].startMs - 1; } },
    { name: "signature disagreement", expect: "inconsistent", apply: (m) => { m.gen.requests[2 * 5].status = 503; } },
    { name: "missing handoff", expect: "unknown", apply: (m) => { m.gen.requests[60].handoffMs = null; } },
    { name: "partial generator", expect: "unknown", apply: (m) => { m.gen.requests.length = 1400; m.dropPairRecords = true; } },
  ];
  const evaluate = (selected: Mutation[]) => {
    const m: Model = { ...withPairs(), specs: campaign({ shedOdd: true }) };
    for (const x of selected) x.apply(m);
    // Authoritative server pair records are supplied only when a mismatch is being injected, and always from the unmutated campaign.
    const pairs = m.tamperServerPair === undefined ? undefined : observe(stream(campaign({ shedOdd: true }))).snapshotSalvo().pairs;
    if (pairs && m.tamperServerPair !== undefined) pairs[m.tamperServerPair].settledMs[0] = (pairs[m.tamperServerPair].settledMs[0] as number) + 1;
    return check({ server: record(stream(m.specs)), generator: m.gen, serverPairs: pairs, generatorPairs: m.dropPairRecords ? undefined : m.generatorPairs }).integrity as Severity;
  };
  for (const m of mutations) assert.equal(evaluate([m]), m.expect, m.name);
  // Every subset: the result is the worst member, independent of the order the mutations are applied in.
  for (let mask = 1; mask < 1 << mutations.length; mask++) {
    const selected = mutations.filter((_, i) => mask & (1 << i));
    const expected = worstOf(...selected.map((m) => m.expect));
    assert.equal(evaluate(selected), expected, selected.map((m) => m.name).join(" + "));
    assert.equal(evaluate([...selected].reverse()), expected, `reversed: ${selected.map((m) => m.name).join(" + ")}`);
  }
});

// ============================================================================================================== evidence form of the result
test("the check artifact stays small and scanner-safe even with every finding code and every bounded list full", () => {
  const messy = campaign({ shedOdd: true, zeroOverlap: (p) => p % 2 === 1 && p < 200 }); for (let p = 300; p < 400; p++) messy[2 * p].cls = "mutation";
  const gen = generatorDiagnostics(); for (let i = 0; i < 100; i++) gen.requests[i * 3].status = 418;
  const c = check({ server: record(stream(messy)), generator: gen });
  assert.ok(c.pairs.inconsistentIndices.length === 32 && c.zeroOverlap.detail.length === 64, "lists are bounded");
  const text = `${JSON.stringify(c, null, 2)}\n`; assert.ok(Buffer.byteLength(text) < 16 * 1024, `${Buffer.byteLength(text)} bytes`);
  const full = { ...c, findings: FINDING_CODES.map((code) => ({ code, severity: "malformed" as const })) };
  assert.doesNotThrow(() => assertEvidenceSafe(full)); assert.ok(Buffer.byteLength(JSON.stringify(full, null, 2)) < 16 * 1024);
});
