/**
 * Slice 3 accounting, DERIVED from the correlated lifecycle records of one plane composition that has L2. Counters here are computed from
 * the records; the plane's own aggregate L2 counters are a SECONDARY cross-check, never the source of truth. A failing identity makes the
 * run INVALID.
 *
 * The bucket-replay audit is the strongest check: every L2 decision that took a bucket decision carries the bucket's own clock, its level
 * after the decision and its per-bucket decision number. Replaying those numbers against the configured capacity and refill proves, from
 * the ledger alone, that every admit consumed exactly one token, every shed happened with less than one token, no token ever came back
 * (P3), and no decision disappeared (a gap in the per-bucket numbering).
 */
import { terminalOutcomeL2, type PlaneEvent } from "../../defense/core/ledger";
import { UNIT } from "../../defense/core/lanes";
import { penetrationOf, type PenetrationRecord } from "../../defense/core/penetration";
import type { L2Params, PlaneL2Advisory } from "../../defense/plane/l2-protocol";
import type { Identity } from "./accounting";
import type { LedgerRecord } from "./collector";

export type BucketAudit = { decisions: number; admitted: number; shed: number; gaps: number; mismatches: number; firstMismatch: string | null };
export type LaneAccountingReport = {
  sent: { protected: number; control: number };
  ingress: { accepted: number };
  l1: { entered: number; passed: number; passedNatural: number; passedSimulated: number; rejected: number; shed: number; error: number };
  l2: { entered: number; decided: number; byKey: Record<string, number>; simulatedDecisions: number; spent: { credited: number; unverified: number }; touched: { credited: number; unverified: number } };
  enrollment: { expectedRenders: number; enrolled: number; skipped: Record<string, number>; missing: number; duplicated: number };
  credit: { creditedAdmitted: number; withEnrollment: number; falsePositive: number; falsePositiveByPhase: Record<string, number>; maxUsesPerTag: number; tagsOverK: number };
  ordering: { creditedWithEnrollment: number; violations: number };
  buckets: { credited: BucketAudit; unverified: BucketAudit };
  egress: { attempted: number; responded: number; failed: number };
  terminal: Record<string, number>;
  canaryPost: { total: number; credited: number; unverified: number; shed: number; other: number };
  identities: Identity[];
  identitiesOk: boolean;
};

const identity = (id: string, description: string, left: number, right: number): Identity => ({ id, description, left, right, ok: left === right });
const first = (events: readonly PlaneEvent[], kind: string): PlaneEvent | undefined => events.find((event) => event.kind === kind);

/** The REAL outcome and lane of a decision event: a simulated decision's real verdict is its shadow (`outcome:lane[:reason]`). */
export function realDecision(event: PlaneEvent): { outcome: string; lane: string } {
  if (event.basis === "simulated" && event.shadow) {
    const [outcome, lane] = event.shadow.split(":");
    return { outcome, lane: lane ?? "none" };
  }
  return { outcome: event.outcome ?? "none", lane: event.lane ?? "none" };
}

/** The bucket a decision event took a decision from: the lane that admitted or shed it, or, for a discarded decision, the lane it had consumed (spent) or merely taken a shed from (touched). */
export function bucketLaneOf(event: PlaneEvent): string { return event.spent ?? event.touched ?? realDecision(event).lane; }

/** Replays one lane's bucket from the ledger. Pure. */
export function auditBucket(decisions: readonly { event: PlaneEvent; bucketLane: string }[], lane: "credited" | "unverified", bucket: { capacity: number; refillPerSecond: number }): BucketAudit {
  const mine = decisions.filter((entry) => entry.bucketLane === lane).map((entry) => entry.event).sort((a, b) => (a.lseq ?? 0) - (b.lseq ?? 0));
  const audit: BucketAudit = { decisions: mine.length, admitted: 0, shed: 0, gaps: 0, mismatches: 0, firstMismatch: null };
  const capacityUnits = bucket.capacity * UNIT;
  const perMs = bucket.refillPerSecond * 1000;
  let previousLevel = capacityUnits;
  let previousDt = mine.length > 0 ? (mine[0].dt ?? 0) : 0;
  let expectedSeq = 1;
  const flag = (detail: string) => { audit.mismatches++; if (audit.firstMismatch === null) audit.firstMismatch = detail; };
  for (const event of mine) {
    if (event.lseq !== expectedSeq) { audit.gaps++; expectedSeq = (event.lseq ?? expectedSeq) ; }
    expectedSeq++;
    const dt = event.dt ?? 0;
    if (dt < previousDt) { flag(`clock went back at ${event.lseq}`); continue; }
    const before = Math.min(capacityUnits, previousLevel + (dt - previousDt) * perMs);
    const consumed = event.spent !== undefined || (event.touched === undefined && realDecision(event).outcome === "admitted");
    if (consumed) { audit.admitted++; if (before < UNIT) flag(`consumed with ${before} units at ${event.lseq}`); }
    else { audit.shed++; if (before >= UNIT) flag(`shed with ${before} units at ${event.lseq}`); }
    const expectedAfter = consumed ? before - UNIT : before;
    if (event.lvl !== expectedAfter) flag(`level ${event.lvl} expected ${expectedAfter} at ${event.lseq}`);
    previousLevel = event.lvl ?? expectedAfter;
    previousDt = dt;
  }
  return audit;
}

export function deriveLaneAccounting(input: {
  records: readonly LedgerRecord[];
  fin: PlaneL2Advisory | null;
  l2: L2Params;
  renderScenarios: ReadonlySet<string>;
  maxUses: number;
}): LaneAccountingReport {
  const { records } = input;
  const protectedRecords = records.filter((record) => record.meta.lane === "protected");
  const controlCount = records.filter((record) => record.meta.lane === "control").length;
  const l1 = { entered: 0, passed: 0, passedNatural: 0, passedSimulated: 0, rejected: 0, shed: 0, error: 0 };
  const byKey: Record<string, number> = {};
  const l2 = { entered: 0, decided: 0, byKey, simulatedDecisions: 0, spent: { credited: 0, unverified: 0 }, touched: { credited: 0, unverified: 0 } };
  const terminal: Record<string, number> = {};
  const egress = { attempted: 0, responded: 0, failed: 0 };
  let accepted = 0; let unresolved = 0; let proceeds = 0;
  const bucketed: { event: PlaneEvent; bucketLane: string }[] = [];
  const enrolledSeqByTag = new Map<string, number>();
  const creditedAdmissions: { tag: string | undefined; seq: number; phase: string }[] = [];
  const enrollment = { expectedRenders: 0, enrolled: 0, skipped: {} as Record<string, number>, missing: 0, duplicated: 0 };
  const canaryPost = { total: 0, credited: 0, unverified: 0, shed: 0, other: 0 };

  for (const record of protectedRecords) {
    const plane = record.plane;
    const kinds = new Set(plane.map((event) => event.kind));
    if (kinds.has("INGRESS_ACCEPTED")) accepted++;
    if (kinds.has("L1_ENTERED")) l1.entered++;
    const passed = first(plane, "L1_PASSED");
    if (passed) { l1.passed++; if (passed.basis === "simulated") l1.passedSimulated++; else l1.passedNatural++; }
    if (kinds.has("L1_REJECTED")) l1.rejected++;
    if (kinds.has("L1_SHED")) l1.shed++;
    if (kinds.has("L1_ERROR")) l1.error++;
    if (kinds.has("L2_ENTERED")) l2.entered++;
    const decided = first(plane, "L2_DECIDED");
    if (decided) {
      l2.decided++;
      const real = realDecision(decided);
      const key = `${decided.class}.${real.lane}.${real.outcome}`;
      byKey[key] = (byKey[key] ?? 0) + 1;
      if (decided.basis === "simulated") l2.simulatedDecisions++;
      if (decided.spent === "credited" || decided.spent === "unverified") l2.spent[decided.spent]++;
      if (decided.touched === "credited" || decided.touched === "unverified") l2.touched[decided.touched]++;
      if (decided.dt !== undefined) {
        const bucketLane = bucketLaneOf(decided);
        if (bucketLane === "credited" || bucketLane === "unverified") bucketed.push({ event: decided, bucketLane });
      }
      if (decided.outcome === "admitted" || decided.outcome === "degraded") proceeds++;
      if (realDecision(decided).lane === "credited" && realDecision(decided).outcome === "admitted") creditedAdmissions.push({ tag: decided.creditTag, seq: decided.seq, phase: record.meta.phase });
    }
    if (kinds.has("EGRESS_ATTEMPTED")) egress.attempted++;
    if (kinds.has("EGRESS_RESPONDED")) egress.responded++;
    if (kinds.has("EGRESS_FAILED")) egress.failed++;
    const outcome = terminalOutcomeL2(plane);
    if (outcome === null) { if (kinds.has("INGRESS_ACCEPTED")) unresolved++; } else terminal[outcome] = (terminal[outcome] ?? 0) + 1;

    const dispositions = plane.filter((event) => event.kind === "L2_ENROLLED" || event.kind === "L2_ENROLL_SKIPPED");
    if (dispositions.length > 1) enrollment.duplicated++;
    for (const disposition of dispositions) {
      if (disposition.kind === "L2_ENROLLED") { enrollment.enrolled++; if (disposition.creditTag) enrolledSeqByTag.set(disposition.creditTag, disposition.seq); }
      else enrollment.skipped[disposition.skipReason ?? "unknown"] = (enrollment.skipped[disposition.skipReason ?? "unknown"] ?? 0) + 1;
    }
    if (input.renderScenarios.has(record.meta.scenario) && decided && (decided.outcome === "admitted" || decided.outcome === "degraded") && decided.class === "open") {
      enrollment.expectedRenders++;
      if (dispositions.length === 0) enrollment.missing++;
    }
    if (record.meta.scenario === "journey_valid_post" && record.meta.cls === "canary") {
      canaryPost.total++;
      const real = decided ? realDecision(decided) : { outcome: "none", lane: "none" };
      if (real.outcome === "admitted" && real.lane === "credited") canaryPost.credited++;
      else if (real.outcome === "admitted" && real.lane === "unverified") canaryPost.unverified++;
      else if (real.outcome === "shed") canaryPost.shed++;
      else canaryPost.other++;
    }
  }

  // ---- credit: false positives (a credited admission whose tag no render enrolled), uses per tag, and G2 ordering
  const perTag = new Map<string, number>();
  let withEnrollment = 0; let falsePositive = 0; let violations = 0; let orderedChecks = 0;
  const falsePositiveByPhase: Record<string, number> = {};
  for (const admission of creditedAdmissions) {
    if (admission.tag === undefined) continue;
    perTag.set(admission.tag, (perTag.get(admission.tag) ?? 0) + 1);
    const enrolledAt = enrolledSeqByTag.get(admission.tag);
    if (enrolledAt === undefined) { falsePositive++; falsePositiveByPhase[admission.phase] = (falsePositiveByPhase[admission.phase] ?? 0) + 1; continue; }
    withEnrollment++;
    orderedChecks++;
    if (enrolledAt >= admission.seq) violations++;
  }
  const maxUsesPerTag = Math.max(0, ...perTag.values());
  const tagsOverK = [...perTag.values()].filter((count) => count > input.maxUses).length;

  const buckets = { credited: auditBucket(bucketed, "credited", input.l2.credited), unverified: auditBucket(bucketed, "unverified", input.l2.unverified) };
  const terminalTotal = Object.values(terminal).reduce((total, value) => total + value, 0);
  const decisionKeys = Object.entries(byKey);
  const countWhere = (outcome: string) => decisionKeys.filter(([key]) => key.endsWith(`.${outcome}`)).reduce((total, [, value]) => total + value, 0);

  const identities: Identity[] = [
    identity("ledger.sent_protected_equals_ingress_accepted", "every request sent to the plane is accepted at ingress", protectedRecords.length, accepted),
    identity("ledger.ingress_accepted_equals_terminal_plus_unresolved", "ingress equals the derived terminal outcomes plus unresolved work", accepted, terminalTotal + unresolved),
    identity("ledger.unresolved_is_zero", "no accepted request is unresolved at finalization", unresolved, 0),
    identity("ledger.l1_in_equals_ingress_accepted", "every accepted request enters L1", l1.entered, accepted),
    identity("ledger.l1_in_equals_outcomes", "L1 input equals its outcomes", l1.entered, l1.passed + l1.rejected + l1.shed + l1.error),
    identity("l2.entered_equals_l1_passed", "every L1 pass enters L2: nothing disappears between the layers", l2.entered, l1.passed),
    identity("l2.decided_equals_entered", "exactly one L2 decision follows every L2 entry", l2.decided, l2.entered),
    identity("l2.decisions_equal_outcomes", "the decision outcomes partition the decisions", l2.decided, countWhere("admitted") + countWhere("shed") + countWhere("error") + countWhere("degraded")),
    identity("egress.attempted_equals_l2_proceeds", "only an admitted or degraded decision proceeds to egress", egress.attempted, proceeds),
    identity("egress.attempted_equals_responded_plus_failed", "every egress attempt is attributed", egress.attempted, egress.responded + egress.failed),
    identity("enrollment.missing_is_zero", "every admitted open render has exactly one enrollment disposition", enrollment.missing, 0),
    identity("enrollment.duplicated_is_zero", "no request has two enrollment dispositions", enrollment.duplicated, 0),
    identity("credit.enrollment_precedes_decision", "every credited admission with an enrollment follows it in the plane's own sequence (G2)", violations, 0),
    identity("credit.uses_per_tag_within_k", "no credit tag was admitted credited more than K times", tagsOverK, 0),
    identity("bucket.credited_replay_exact", "the credited bucket replays exactly from the ledger", buckets.credited.mismatches, 0),
    identity("bucket.unverified_replay_exact", "the unverified bucket replays exactly from the ledger", buckets.unverified.mismatches, 0),
    identity("bucket.credited_decisions_gapless", "no credited bucket decision is missing from the ledger", buckets.credited.gaps, 0),
    identity("bucket.unverified_decisions_gapless", "no unverified bucket decision is missing from the ledger", buckets.unverified.gaps, 0),
  ];
  if (input.fin) {
    const aggregate = input.fin.l2.lanes;
    const plane = aggregate.decisions;
    const keys = new Set([...Object.keys(plane), ...Object.keys(byKey)]);
    let mismatch = 0;
    for (const key of keys) if ((plane[key] ?? 0) !== (byKey[key] ?? 0)) mismatch++;
    identities.push(
      identity("l2.plane_counters_equal_ledger", "the plane's own aggregate decision counters equal the ledger-derived counts (secondary cross-check)", mismatch, 0),
      identity("l2.state_violations_is_zero", "no ledger, bucket or filter state violation", aggregate.ledger.stateViolations, 0),
      identity("l2.spent_equals_plane_counter", "decisions discarded after consuming equal the plane's own count", l2.spent.credited + l2.spent.unverified, aggregate.spentOnDiscard.credited + aggregate.spentOnDiscard.unverified),
    );
  }

  return {
    sent: { protected: protectedRecords.length, control: controlCount }, ingress: { accepted }, l1, l2, enrollment,
    credit: { creditedAdmitted: creditedAdmissions.length, withEnrollment, falsePositive, falsePositiveByPhase, maxUsesPerTag, tagsOverK },
    ordering: { creditedWithEnrollment: orderedChecks, violations }, buckets, egress, terminal, canaryPost, identities, identitiesOk: identities.every((entry) => entry.ok),
  };
}

// ---------------------------------------------------------------------------
// Penetration table
// ---------------------------------------------------------------------------

export type PenetrationRow = { family: string; basis: "natural" | "simulated"; l1: string; l2: string; lane: string; deepest: string; terminal: string; count: number };

/** Aggregates the per-request penetration records by (family, basis, terminal explanation). Natural and simulated rows are never merged. */
export function penetrationTable(records: readonly LedgerRecord[], familyOf: (record: LedgerRecord) => string | null, l2Composition = true): { rows: PenetrationRow[]; perRecord: Map<string, PenetrationRecord> } {
  const rows = new Map<string, PenetrationRow>();
  const perRecord = new Map<string, PenetrationRecord>();
  for (const record of records) {
    if (record.meta.lane !== "protected") continue;
    const family = familyOf(record);
    if (family === null) continue;
    const view = { nonce: record.nonce, expected: record.meta.lane, harness: record.harness, plane: record.plane, origin: record.origin, boundary: record.boundary, app: record.app, ...(l2Composition ? { l2: true as const } : {}) };
    const pen = penetrationOf(view);
    perRecord.set(record.rid, pen);
    const key = `${family}|${pen.basis}|${pen.l1}|${pen.l2}|${pen.lane ?? "none"}|${pen.deepest}|${pen.terminal}`;
    const row = rows.get(key) ?? { family, basis: pen.basis, l1: pen.l1, l2: pen.l2, lane: pen.lane ?? "none", deepest: pen.deepest, terminal: pen.terminal, count: 0 };
    row.count++;
    rows.set(key, row);
  }
  return { rows: [...rows.values()].sort((a, b) => `${a.family}${a.basis}${a.terminal}`.localeCompare(`${b.family}${b.basis}${b.terminal}`)), perRecord };
}
