/**
 * Offline salvo DIAGNOSTIC check (schema ba0-salvo-diagnostic-check-v2). Pure and read-only.
 *
 * It is evaluated AFTER the qualification decision, writes only a separate artifact, and has no path back into `reconcileSalvo`, `derivePairs`,
 * `jointExercised`, `decideFinal` or any identity: `influencesVerdict` is the literal `false`. If a diagnostic result should ever disqualify future
 * evidence, that is a separate, reviewed qualification-policy revision (lab/README.md); it is NOT implemented here.
 *
 * Three questions, kept apart on purpose. None of them is proof of the next.
 *
 *   A. `integrity`   Are the supplied records well-formed, complete, free of causality violations and in agreement with the authoritative pair
 *                    records they were derived alongside?
 *   B. `composition` Are the server-observed classes and statuses compatible with the expected workload (even pair: two open; odd pair: one open
 *                    and one mutation; statuses 200 or 503)?
 *   C. `binding`     Is a given server request provably the same physical request as a given generator request?
 *
 * C is never established here. No end-to-end identifier travels with a request (adding one would change the traffic), so the generator's pair
 * index and the server's arrival ordinal are related only by an ASSUMED ordinal mapping. The workload is periodic, so a shifted, dropped-and-
 * replaced, or permuted sequence of equivalent pairs produces exactly the same observable class/status signatures as a correct one; nothing
 * recorded can distinguish them. `binding` therefore never reaches `verified`: its type pins `verified` to 0 and `identityEvidence` to "none".
 * `inferred` means only that the ordinal and workload-composition assumptions were satisfied and the signatures were compatible.
 *
 * Reporting precedence for A and B (not a confidence ordering, and unrelated to `binding`): malformed > inconsistent > unknown > consistent.
 * It is implemented once, in `worstOf`, and every status below is derived from it.
 */
import { SALVO_SPEC } from "./salvo-spec";
import {
  SALVO_DIAGNOSTIC_LIMITS, parseGeneratorDiagnostics, parseServerDiagnostics,
  type GeneratorSalvoDiagnostics, type SalvoServerObservation, type ServerSalvoDiagnostics,
} from "./salvo-diagnostics";

export const SALVO_DIAGNOSTIC_CHECK_SCHEMA = "ba0-salvo-diagnostic-check-v2" as const;
const LIST_MAX = 32;

// ---------------------------------------------------------------------------------------------------------------------------------- severity
export const SEVERITIES = ["consistent", "unknown", "inconsistent", "malformed"] as const;
export type Severity = (typeof SEVERITIES)[number];
const RANK: Readonly<Record<Severity, number>> = Object.freeze({ consistent: 0, unknown: 1, inconsistent: 2, malformed: 3 });
/** The single place the precedence is defined. A later, weaker finding can never lower an earlier, stronger one. */
export const worstOf = (...states: readonly Severity[]): Severity => states.reduce<Severity>((worst, next) => (RANK[next] > RANK[worst] ? next : worst), "consistent");

/** Closed vocabulary of reasons an integrity status is not `consistent`. */
export const FINDING_CODES = [
  "server_malformed", "generator_malformed",
  "server_pair_mismatch", "generator_pair_mismatch", "event_order", "server_causality", "settled_before_start", "handoff_before_start", "handoff_after_settlement",
  "signature_incompatible",
  "incomplete_records", "record_overflow", "recorder_fault", "reused_key", "repeated_event", "generator_incomplete", "generator_unsettled", "handoff_missing",
] as const;
export type FindingCode = (typeof FINDING_CODES)[number];
export type Finding = { code: FindingCode; severity: Exclude<Severity, "consistent"> };

export type PairState = "consistent" | "inconsistent" | "unknown";
type Tally = Record<PairState, number>;
const tally = (): Tally => ({ consistent: 0, inconsistent: 0, unknown: 0 });

export type BindingStatus = "verified" | "inferred" | "unverified" | "contradicted";
export type InputState = "absent" | "malformed" | "present";
export type ZeroOverlapCause = "fast_shed_first_arrival" | "short_first_arrival_not_shed" | "undetermined";

export type SalvoDiagnosticConsistency = {
  schema: typeof SALVO_DIAGNOSTIC_CHECK_SCHEMA;
  /** Always false: this result is not an input to any verdict. */
  influencesVerdict: false;
  inputs: { server: InputState; generator: InputState; serverReason: string | null; generatorReason: string | null };
  /** A. Well-formedness, completeness, causality and agreement with the authoritative pair records. `absent` only when nothing was supplied. */
  integrity: Severity | "absent";
  /** Why `integrity` is what it is (deduplicated, at most one entry per code). */
  findings: Finding[];
  /** B. Class/status compatibility with the expected workload composition. */
  composition: Severity | "absent";
  /** C. Cross-source request identity. `verified` is unreachable by construction: there is no end-to-end identifier. */
  binding: {
    status: BindingStatus;
    identityEvidence: "none";
    basis: "ordinal.and.composition";
    pairs: { verified: 0; inferred: number; unverified: number; contradicted: number };
    contradictedIndices: number[];
  };
  completeness: { recorded: number; expected: number; pending: number; aborted: number; overflow: number; complete: boolean };
  recorder: { duplicateIds: number; duplicateEvents: number; orderViolations: number; ambiguousEvents: number; faults: number; flaggedRecords: number };
  classTotals: { open: number; mutation: number; unknown: number };
  /** Per-pair composition (B). */
  pairs: { total: Tally; even: Tally; odd: Tally; inconsistentIndices: number[]; unknownIndices: number[] };
  status: { unexpected: number; unexpectedIndices: number[]; fastShed503: number; admitted200: number; other: number };
  /** Pairs whose server-observed lifetimes did not overlap, and why (derived from the diagnostics only; the qualification overlap is unchanged). */
  zeroOverlap: { pairs: number; fastShedFirst: number; shortFirstNotShed: number; undetermined: number; detail: { pair: number; cause: ZeroOverlapCause; firstMs: number | null; separationMs: number | null }[] };
  partialOverlap: { belowRatio: number; indices: number[] };
  /** The diagnostics' timestamps against the authoritative qualification pair records (they must be the identical numbers). */
  pairRecordAgreement: { server: { compared: number; mismatched: number } | "not_supplied"; generator: { compared: number; mismatched: number } | "not_supplied" };
  generator: { rows: number; handoffObserved: number; handoffMissing: number; handoffBeforeStart: number; handoffAfterSettlement: number; settledBeforeStart: number; unsettled: number } | "absent" | "malformed";
  /**
   * Agreement of class/status SIGNATURES between the two sources under the ASSUMED ordinal mapping. Compatible signatures are necessary for, and
   * far from sufficient for, identity: every equivalent pair has the same signature. Not evidence of which physical request is which.
   */
  signature: { status: "absent" | "compatible" | "incompatible" | "unknown"; compared: number; compatible: number; incompatible: number; informative: number; incompatibleIndices: number[] };
};

type Obs = SalvoServerObservation;
const expectedClasses = (pair: number) => (pair % 2 === 0 ? ["open", "open"] : ["mutation", "open"]);
const finished = (o: Obs | undefined): o is Obs & { outMs: number } => o !== undefined && o.fin !== "pending" && o.outMs !== null;
const capped = (list: number[], value: number) => { if (list.length < LIST_MAX) list.push(value); };
const round3 = (n: number) => Math.round(n * 1000) / 1000;

function pairState(pair: number, a: Obs | undefined, b: Obs | undefined): PairState {
  if (a === undefined || b === undefined) return "unknown";
  // A flagged request (reused key, repeated, late or out-of-order events) cannot establish a composition.
  if (a.flags.length > 0 || b.flags.length > 0 || a.cls === "unknown" || b.cls === "unknown") return "unknown";
  const seen = [a.cls, b.cls].sort().join("+");
  return seen === expectedClasses(pair).sort().join("+") ? "consistent" : "inconsistent";
}

/** Same definitions as the qualification derivation (P, O) but over diagnostics, and only to EXPLAIN a pair; never to qualify one. */
function lifetimes(a: Obs & { outMs: number }, b: Obs & { outMs: number }) {
  const first = a.inMs < b.inMs || (a.inMs === b.inMs && a.inSeq <= b.inSeq) ? a : b; const second = first === a ? b : a;
  const p = Math.min(a.outMs - a.inMs, b.outMs - b.inMs);
  const o = Math.max(0, Math.min(a.outMs, b.outMs) - Math.max(a.inMs, b.inMs));
  return { first, second, p, o };
}

type PairRow = { startsMs?: unknown; settledMs?: unknown } | undefined;
const slotOf = (row: PairRow, key: "startsMs" | "settledMs", slot: number): unknown => (Array.isArray(row?.[key]) ? (row![key] as unknown[])[slot] : undefined);

export function evaluateSalvoDiagnostics(input: { server?: unknown; generator?: unknown; serverPairs?: unknown; generatorPairs?: unknown }): SalvoDiagnosticConsistency {
  const result: SalvoDiagnosticConsistency = {
    schema: SALVO_DIAGNOSTIC_CHECK_SCHEMA, influencesVerdict: false,
    inputs: { server: "absent", generator: "absent", serverReason: null, generatorReason: null }, integrity: "absent", findings: [], composition: "absent",
    binding: { status: "unverified", identityEvidence: "none", basis: "ordinal.and.composition", pairs: { verified: 0, inferred: 0, unverified: 0, contradicted: 0 }, contradictedIndices: [] },
    completeness: { recorded: 0, expected: SALVO_DIAGNOSTIC_LIMITS.maxRequests, pending: 0, aborted: 0, overflow: 0, complete: false },
    recorder: { duplicateIds: 0, duplicateEvents: 0, orderViolations: 0, ambiguousEvents: 0, faults: 0, flaggedRecords: 0 },
    classTotals: { open: 0, mutation: 0, unknown: 0 },
    pairs: { total: tally(), even: tally(), odd: tally(), inconsistentIndices: [], unknownIndices: [] },
    status: { unexpected: 0, unexpectedIndices: [], fastShed503: 0, admitted200: 0, other: 0 },
    zeroOverlap: { pairs: 0, fastShedFirst: 0, shortFirstNotShed: 0, undetermined: 0, detail: [] },
    partialOverlap: { belowRatio: 0, indices: [] },
    pairRecordAgreement: { server: "not_supplied", generator: "not_supplied" },
    generator: "absent", signature: { status: "absent", compared: 0, compatible: 0, incompatible: 0, informative: 0, incompatibleIndices: [] },
  };
  const found = new Map<FindingCode, Finding["severity"]>();
  const note = (code: FindingCode, severity: Finding["severity"]) => { const prior = found.get(code); if (prior === undefined || RANK[severity] > RANK[prior]) found.set(code, severity); };

  let server: ServerSalvoDiagnostics | null = null; let generator: GeneratorSalvoDiagnostics | null = null;
  if (input.server !== undefined) {
    const parsed = parseServerDiagnostics(input.server);
    if (parsed.ok) { server = parsed.value; result.inputs.server = "present"; } else { result.inputs.server = "malformed"; result.inputs.serverReason = parsed.reason; note("server_malformed", "malformed"); }
  }
  if (input.generator !== undefined) {
    const parsed = parseGeneratorDiagnostics(input.generator);
    if (parsed.ok) { generator = parsed.value; result.inputs.generator = "present"; } else { result.inputs.generator = "malformed"; result.inputs.generatorReason = parsed.reason; result.generator = "malformed"; note("generator_malformed", "malformed"); }
  }
  const byOrd = new Map<number, Obs>();
  const pairBinding: BindingStatus[] = Array<BindingStatus>(SALVO_SPEC.pairs).fill("unverified");

  // ---------------------------------------------------------------------------------------------------------------- server: integrity (A) and composition (B)
  let composition: Severity = result.inputs.server === "malformed" ? "malformed" : "consistent";
  if (server !== null) {
    for (const o of server.requests) byOrd.set(o.ord, o);
    const c = server.counters;
    result.recorder = { duplicateIds: c.duplicateIds, duplicateEvents: c.duplicateEvents, orderViolations: c.orderViolations, ambiguousEvents: c.ambiguousEvents, faults: c.faults, flaggedRecords: 0 };
    result.completeness.recorded = server.requests.length; result.completeness.overflow = c.overflow;
    for (const o of server.requests) {
      result.classTotals[o.cls]++;
      if (o.fin === "pending") result.completeness.pending++; else if (o.fin === "aborted") result.completeness.aborted++;
      if (o.flags.length > 0) result.recorder.flaggedRecords++;
      if (o.flags.includes("dup_id")) note("reused_key", "unknown");
      if (o.flags.includes("dup_event") || o.flags.includes("late_event")) note("repeated_event", "unknown");
      if (o.flags.includes("seq_order") || o.flags.includes("time_order")) note("event_order", "inconsistent");
      // A terminal event cannot precede its ingress in sequence or in the plane's monotonic time.
      if (o.fin !== "pending" && (o.outSeq! <= o.inSeq || o.outMs! < o.inMs)) note("server_causality", "inconsistent");
      if (o.fin === "responded") {
        if (o.status !== 200 && o.status !== 503) { result.status.unexpected++; capped(result.status.unexpectedIndices, o.pair); }
        if (o.l2 === "shed" && !o.egress && o.status === 503) result.status.fastShed503++;
        else if (o.l2 === "admitted" && o.egress && o.status === 200) result.status.admitted200++;
        else result.status.other++;
      }
    }
    result.completeness.complete = server.requests.length === SALVO_DIAGNOSTIC_LIMITS.maxRequests && result.completeness.pending === 0 && result.completeness.aborted === 0 && c.overflow === 0;
    if (server.requests.length !== SALVO_DIAGNOSTIC_LIMITS.maxRequests || result.completeness.pending > 0 || result.completeness.aborted > 0) note("incomplete_records", "unknown");
    if (c.overflow > 0) note("record_overflow", "unknown");
    if (c.faults > 0) note("recorder_fault", "unknown");
    if (c.duplicateIds > 0) note("reused_key", "unknown");

    for (let pair = 0; pair < SALVO_SPEC.pairs; pair++) {
      const a = byOrd.get(2 * pair); const b = byOrd.get(2 * pair + 1);
      const state = pairState(pair, a, b);
      result.pairs.total[state]++; result.pairs[pair % 2 === 0 ? "even" : "odd"][state]++;
      if (state === "inconsistent") capped(result.pairs.inconsistentIndices, pair);
      if (state === "unknown") capped(result.pairs.unknownIndices, pair);
      if (state === "inconsistent") pairBinding[pair] = "contradicted";
      if (!finished(a) || !finished(b) || a.flags.length > 0 || b.flags.length > 0) continue;
      const { first, second, p, o } = lifetimes(a, b);
      if (p > 0 && o === 0) {
        const z = result.zeroOverlap; z.pairs++;
        const fast = first.l2 === "shed" && !first.egress && first.status === 503;
        const cause: ZeroOverlapCause = fast ? "fast_shed_first_arrival" : first.outMs <= second.inMs ? "short_first_arrival_not_shed" : "undetermined";
        if (cause === "fast_shed_first_arrival") z.fastShedFirst++; else if (cause === "short_first_arrival_not_shed") z.shortFirstNotShed++; else z.undetermined++;
        if (z.detail.length < 2 * LIST_MAX) z.detail.push({ pair, cause, firstMs: round3(first.outMs - first.inMs), separationMs: round3(second.inMs - first.inMs) });
      } else if (p > 0 && o < SALVO_SPEC.materialRatio * p) { result.partialOverlap.belowRatio++; capped(result.partialOverlap.indices, pair); }
    }
    const t = result.pairs.total;
    composition = worstOf(t.inconsistent > 0 ? "inconsistent" : "consistent", t.unknown > 0 ? "unknown" : "consistent", result.status.unexpected > 0 ? "inconsistent" : "consistent");

    if (Array.isArray(input.serverPairs)) {
      let mismatched = 0;
      for (const o of server.requests) {
        const row = input.serverPairs[o.pair] as PairRow;
        if (slotOf(row, "startsMs", o.slot) !== o.inMs || slotOf(row, "settledMs", o.slot) !== o.outMs) mismatched++;
      }
      result.pairRecordAgreement.server = { compared: server.requests.length, mismatched };
      if (mismatched > 0) note("server_pair_mismatch", "inconsistent");
    }
  }

  // ------------------------------------------------------------------------------------------------------------ generator: integrity (A), handoff causality
  const rows = new Map<number, GeneratorSalvoDiagnostics["requests"][number]>();
  if (generator !== null) {
    const g = { rows: generator.requests.length, handoffObserved: 0, handoffMissing: 0, handoffBeforeStart: 0, handoffAfterSettlement: 0, settledBeforeStart: 0, unsettled: 0 };
    for (const r of generator.requests) {
      rows.set(r.pair * 2 + r.slot, r);
      // Node: the request's `finish` follows its start by construction and the sender stops reporting once it has settled, so
      // start <= handoff <= settled holds for every genuine record. Equality is allowed (a coarse clock). A missing handoff is unknown, not invalid.
      if (r.handoffMs === null) g.handoffMissing++;
      else { g.handoffObserved++; if (r.handoffMs < r.startMs) g.handoffBeforeStart++; if (r.settledMs !== null && r.handoffMs > r.settledMs) g.handoffAfterSettlement++; }
      if (r.settledMs === null) g.unsettled++; else if (r.settledMs < r.startMs) g.settledBeforeStart++;
    }
    result.generator = g;
    if (g.handoffBeforeStart > 0) note("handoff_before_start", "inconsistent");
    if (g.handoffAfterSettlement > 0) note("handoff_after_settlement", "inconsistent");
    if (g.settledBeforeStart > 0) note("settled_before_start", "inconsistent");
    if (g.handoffMissing > 0) note("handoff_missing", "unknown");
    if (g.unsettled > 0) note("generator_unsettled", "unknown");
    if (g.rows !== SALVO_DIAGNOSTIC_LIMITS.maxRequests) note("generator_incomplete", "unknown");
    if (Array.isArray(input.generatorPairs)) {
      let mismatched = 0;
      for (const r of generator.requests) {
        const row = input.generatorPairs[r.pair] as PairRow;
        if (slotOf(row, "startsMs", r.slot) !== r.startMs || slotOf(row, "settledMs", r.slot) !== r.settledMs) mismatched++;
      }
      // A settled pair-record slot with no diagnostic row is also a disagreement (an unsent slot keeps a start but no settlement).
      input.generatorPairs.forEach((row: PairRow, index: number) => {
        for (const slot of [0, 1] as const) if (slotOf(row, "settledMs", slot) !== undefined && slotOf(row, "settledMs", slot) !== null && !rows.has(index * 2 + slot)) mismatched++;
      });
      result.pairRecordAgreement.generator = { compared: generator.requests.length, mismatched };
      if (mismatched > 0) note("generator_pair_mismatch", "inconsistent");
    }
  }

  // ---------------------------------------------------------------------------------------------- signatures under the assumed mapping, then binding (C)
  const sig = result.signature;
  if (server !== null && generator !== null) {
    for (let pair = 0; pair < SALVO_SPEC.pairs; pair++) {
      const a = byOrd.get(2 * pair); const b = byOrd.get(2 * pair + 1);
      const g0 = rows.get(pair * 2); const g1 = rows.get(pair * 2 + 1);
      // Only a pair with an established composition, both statuses known on both sides, is compared. Everything else stays uncompared.
      if (pairState(pair, a, b) !== "consistent" || !finished(a) || !finished(b) || a.status === null || b.status === null || !g0 || !g1 || g0.status === null || g1.status === null) continue;
      sig.compared++;
      let agrees: boolean;
      if (pair % 2 === 0) agrees = [a.status, b.status].sort().join() === [g0.status, g1.status].sort().join();
      else { const open = a.cls === "open" ? a : b; const mutation = open === a ? b : a; agrees = open.status === g0.status && mutation.status === g1.status; }
      if (g0.status !== g1.status) sig.informative++;
      if (agrees) { sig.compatible++; pairBinding[pair] = "inferred"; } else { sig.incompatible++; capped(sig.incompatibleIndices, pair); pairBinding[pair] = "contradicted"; }
    }
    sig.status = sig.incompatible > 0 ? "incompatible" : sig.compared === SALVO_SPEC.pairs ? "compatible" : "unknown";
    if (sig.incompatible > 0) note("signature_incompatible", "inconsistent");
  }
  const bind = result.binding;
  for (let pair = 0; pair < SALVO_SPEC.pairs; pair++) {
    const state = pairBinding[pair];
    if (state === "contradicted") { bind.pairs.contradicted++; capped(bind.contradictedIndices, pair); } else if (state === "inferred") bind.pairs.inferred++; else bind.pairs.unverified++;
  }
  // Run level: any contradiction wins; `inferred` only if every pair is inferred; otherwise unverified. Never `verified`.
  bind.status = bind.pairs.contradicted > 0 ? "contradicted" : bind.pairs.inferred === SALVO_SPEC.pairs ? "inferred" : "unverified";

  // ------------------------------------------------------------------------------------------------------------------------------------ final statuses
  result.findings = FINDING_CODES.filter((code) => found.has(code)).map((code) => ({ code, severity: found.get(code)! }));
  const supplied = result.inputs.server !== "absent" || result.inputs.generator !== "absent";
  result.integrity = supplied ? worstOf(...result.findings.map((f) => f.severity)) : "absent";
  result.composition = result.inputs.server === "absent" ? "absent" : composition;
  return result;
}
