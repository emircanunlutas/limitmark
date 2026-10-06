/**
 * Slice 3: the per-request rules of the L2 stage over one request's plane stream. Pure. Used by the collector for every record of a run
 * whose plane composition has L2 (`LifecycleView.l2`). The Slice-1/2 validator (`ledger.ts`) is not changed by any of this.
 *
 * Every request that entered L2 has EXACTLY ONE correlated L2_DECIDED (the automaton forbids a second one and `missing_transition` flags
 * a missing one). Lane, outcome and basis are separate facts: this file checks that their combination is one the closed matrix allows, that
 * a decision which refused is never followed by egress, and that enrollment happened (or was skipped) for exactly the right reasons.
 */
import type { Anomaly, AnomalyCode, LifecycleView, PlaneEvent } from "./ledger";
import { isValidDecision, proceeds, type LaneDecision } from "./lanes";

export function decisionOf(event: PlaneEvent): LaneDecision | null {
  if (event.class === undefined || event.lane === undefined || event.outcome === undefined) return null;
  return {
    class: event.class, lane: event.lane, outcome: event.outcome, shedReason: event.shedReason, errorKind: event.l2ErrorKind, creditTag: event.creditTag,
    spent: event.spent, touched: event.touched, dt: event.dt, lvl: event.lvl, lseq: event.lseq, basis: event.basis, shadow: event.shadow,
  };
}

export function validateL2Lifecycle(view: LifecycleView, final: boolean): Anomaly[] {
  const found: Anomaly[] = [];
  if (view.l2 !== true || (view.expected !== "protected" && view.expected !== "external")) return found;
  const add = (code: AnomalyCode, detail: string) => found.push({ code, nonce: view.nonce, detail });
  const plane = view.plane;
  const has = (kind: string) => plane.some((event) => event.kind === kind);

  // A layer the request left evidence of having passed, but never traversed.
  if (has("EGRESS_ATTEMPTED") && !has("L1_ENTERED")) add("layer_skipped", "l1");
  if (has("EGRESS_ATTEMPTED") && has("L1_ENTERED") && !has("L2_ENTERED")) add("layer_skipped", "l2");

  const decidedEvent = plane.find((event) => event.kind === "L2_DECIDED");
  const entered = plane.filter((event) => event.kind === "L2_ENTERED").length;
  const decidedCount = plane.filter((event) => event.kind === "L2_DECIDED").length;
  if (decidedCount > entered) add("l2_decision_invalid", "decision without entry");
  if (final && entered === 1 && decidedCount === 0 && !has("INGRESS_ABORTED")) add("missing_transition", "L2_DECIDED");

  const decision = decidedEvent === undefined ? null : decisionOf(decidedEvent);
  if (decidedEvent && decision === null) add("l2_decision_invalid", "incomplete decision");
  if (decidedEvent && decision) {
    if (!isValidDecision(decision)) add("l2_decision_invalid", `${decision.class}/${decision.lane ?? "none"}/${decision.outcome}`);
    const bucketed = decision.lane === "credited" || decision.lane === "unverified";
    if (bucketed && (decision.dt === undefined || decision.lvl === undefined || decision.lseq === undefined)) add("l2_decision_invalid", "bucket decision without clock, level and number");
    if (!bucketed && decision.lane === "open" && (decision.dt !== undefined || decision.lseq !== undefined)) add("l2_decision_invalid", "open decision with bucket fields");
    if ((decision.lane === "credited" && decision.outcome === "admitted") !== (decision.creditTag !== undefined)) add("l2_decision_invalid", "credit tag must accompany exactly a credited admission");
    if ((decision.spent !== undefined || decision.touched !== undefined) && !(decision.outcome === "error" || decision.outcome === "shed")) add("l2_decision_invalid", "spent or touched on a decision that was not discarded");
    if ((decision.spent !== undefined || decision.touched !== undefined) && decision.lane !== null) add("l2_decision_invalid", "a discarded decision has no lane");
    if ((decision.basis === "simulated") !== (decision.shadow !== undefined)) add("l2_decision_invalid", "basis and shadow must come together");

    const attempted = has("EGRESS_ATTEMPTED");
    if (!proceeds(decision) && attempted) add("l2_refused_but_egressed", `${decision.outcome}`);
    if (final && proceeds(decision) && !attempted && !has("INGRESS_ABORTED")) add("missing_transition", "EGRESS_ATTEMPTED");
  }

  const dispositions = plane.filter((event) => event.kind === "L2_ENROLLED" || event.kind === "L2_ENROLL_SKIPPED");
  if (dispositions.length > 1) add("l2_enrollment_invalid", "more than one disposition");
  for (const disposition of dispositions) {
    if (!decision || decision.class !== "open" || !proceeds(decision)) { add("l2_enrollment_invalid", "disposition for a request that was not an admitted open render"); continue; }
    const simulated = plane.some((event) => event.basis === "simulated");
    if (disposition.kind === "L2_ENROLLED") {
      if (simulated || decision.outcome !== "admitted") add("l2_enrollment_invalid", "enrolled from a degraded or simulated decision");
      if (disposition.creditTag === undefined || disposition.fill === undefined) add("l2_enrollment_invalid", "enrollment without tag or fill");
      if (!plane.some((event) => event.kind === "EGRESS_RESPONDED")) add("l2_enrollment_invalid", "enrolled without an upstream response");
    } else {
      const reason = disposition.skipReason;
      if (reason === undefined) add("l2_enrollment_invalid", "skip without a reason");
      if ((reason === "degraded") !== (decision.outcome === "degraded")) add("l2_enrollment_invalid", "degraded skip and degraded decision disagree");
      if (reason === "simulated" && !simulated) add("l2_enrollment_invalid", "simulated skip without a simulated verdict");
    }
  }
  return found;
}
