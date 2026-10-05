/**
 * Slice 3: penetration depth and the terminal explanation of ONE request, derived from the plane, boundary and app streams. Pure.
 *
 * The record keeps natural and simulated apart on every layer: a verdict a harness-only override delivered is `simulated_pass` and the
 * whole request is `basis: "simulated"`, whatever depth it reached. A natural bypass is concluded ONLY from the layer's own PASS event with
 * no simulated label anywhere in the request; it is never inferred from a harness label plus an application mutation.
 *
 * Ordered stages: l1, l2, canon, pb, boundary, ba, app_admitted, app_executed, app_mutated. `deepest` is the last stage the request was
 * let through; `terminal` is exactly one explanation of why it went no further (or that it completed).
 */
import type { LifecycleView, PlaneEvent } from "./ledger";

export const PENETRATION_STAGES = ["l1", "l2", "canon", "pb", "boundary", "ba", "app_admitted", "app_executed", "app_mutated"] as const;
export type PenetrationStage = (typeof PENETRATION_STAGES)[number];
export type L1State = "natural_pass" | "simulated_pass" | "rejected" | "shed" | "error" | "skipped" | "not_reached";
export type L2State = "admitted" | "quarantined" | "shed" | "error" | "degraded" | "skipped" | "not_reached";

export type PenetrationRecord = {
  basis: "natural" | "simulated";
  l1: L1State;
  l2: L2State;
  /** Lane and outcome of the L2 decision, kept separate (null when there was none). */
  lane: string | null;
  deepest: PenetrationStage | "none";
  /** Exactly one explanation, e.g. `l1_rejected:a7.path_not_allowed`, `l2_shed:unverified:lane_budget`, `app_mutated`. */
  terminal: string;
};

const ev = (plane: readonly PlaneEvent[], kind: string): PlaneEvent | undefined => plane.find((event) => event.kind === kind);

export function penetrationOf(view: LifecycleView): PenetrationRecord {
  const plane = view.plane;
  const boundary = view.boundary ?? [];
  const app = view.app ?? [];
  const simulated = plane.some((event) => event.basis === "simulated");
  const l1Entered = ev(plane, "L1_ENTERED");
  const attempted = ev(plane, "EGRESS_ATTEMPTED");

  // ---- L1
  let l1: L1State = "not_reached";
  let terminal = "";
  const l1Passed = ev(plane, "L1_PASSED");
  const l1Rejected = ev(plane, "L1_REJECTED");
  if (!l1Entered) l1 = attempted ? "skipped" : "not_reached";
  else if (l1Passed) l1 = l1Passed.basis === "simulated" ? "simulated_pass" : "natural_pass";
  else if (l1Rejected) { l1 = "rejected"; terminal = `l1_rejected:${l1Rejected.reason ?? "unknown"}`; }
  else if (ev(plane, "L1_SHED")) { l1 = "shed"; terminal = "l1_shed"; }
  else if (ev(plane, "L1_ERROR")) { l1 = "error"; terminal = `l1_error:${ev(plane, "L1_ERROR")?.errorKind ?? "unknown"}`; }
  const deepestOf = (stage: PenetrationStage | "none"): PenetrationRecord["deepest"] => stage;
  if (l1 === "rejected" || l1 === "shed" || l1 === "error" || l1 === "not_reached") {
    return { basis: simulated ? "simulated" : "natural", l1, l2: "not_reached", lane: null, deepest: deepestOf("none"), terminal: terminal || "no_plane_decision" };
  }

  // ---- L2 (a composition without L2 has no L2 events: the request goes straight from L1 to egress)
  let l2: L2State = "not_reached";
  let lane: string | null = null;
  const decided = ev(plane, "L2_DECIDED");
  const l2Composition = view.l2 === true;
  if (l2Composition) {
    if (!ev(plane, "L2_ENTERED")) l2 = attempted ? "skipped" : "not_reached";
    else if (decided) {
      lane = decided.lane ?? null;
      if (decided.outcome === "admitted") l2 = decided.lane === "unverified" ? "quarantined" : "admitted";
      else if (decided.outcome === "degraded") l2 = "degraded";
      else if (decided.outcome === "shed") { l2 = "shed"; terminal = `l2_shed:${decided.lane ?? "none"}:${decided.shedReason ?? "unknown"}`; }
      else { l2 = "error"; terminal = `l2_error:${decided.l2ErrorKind ?? "unknown"}`; }
    }
    if (l2 === "shed" || l2 === "error") return { basis: simulated ? "simulated" : "natural", l1, l2, lane, deepest: "l1", terminal };
  }
  let deepest: PenetrationRecord["deepest"] = l2Composition && l2 !== "not_reached" && l2 !== "skipped" ? "l2" : "l1";
  if (!attempted) return { basis: simulated ? "simulated" : "natural", l1, l2, lane, deepest, terminal: terminal || (ev(plane, "INGRESS_ABORTED") ? "client_aborted" : "no_egress") };

  // ---- canonicalization, proof, boundary, proof to app, app
  const failed = ev(plane, "EGRESS_FAILED");
  const issued = ev(plane, "PROOF_ISSUED");
  if (!issued && failed && failed.failStage !== "sign") return { basis: simulated ? "simulated" : "natural", l1, l2, lane, deepest, terminal: failed.failStage === "canon" ? "canon_refused" : "plane_issue_refused" };
  deepest = "canon";
  if (!issued) return { basis: simulated ? "simulated" : "natural", l1, l2, lane, deepest, terminal: failed ? "sign_refused" : "no_proof" };
  deepest = "pb";
  const rejected = boundary.find((event) => event.kind === "BOUNDARY_REJECTED");
  if (rejected) return { basis: simulated ? "simulated" : "natural", l1, l2, lane, deepest, terminal: `boundary_rejected:${rejected.reason ?? "unknown"}` };
  if (!boundary.some((event) => event.kind === "BOUNDARY_ADMITTED")) return { basis: simulated ? "simulated" : "natural", l1, l2, lane, deepest, terminal: failed ? `egress_failed:${failed.egressError ?? "unknown"}` : "boundary_undecided" };
  deepest = "boundary";
  if (!boundary.some((event) => event.kind === "APP_PROOF_ISSUED")) return { basis: simulated ? "simulated" : "natural", l1, l2, lane, deepest, terminal: "app_proof_not_issued" };
  deepest = "ba";
  const refused = app.find((event) => event.kind === "APP_REFUSED");
  if (refused) return { basis: simulated ? "simulated" : "natural", l1, l2, lane, deepest, terminal: `app_refused:${refused.reason ?? "unknown"}` };
  if (!app.some((event) => event.kind === "APP_ADMITTED")) return { basis: simulated ? "simulated" : "natural", l1, l2, lane, deepest, terminal: failed ? `egress_failed:${failed.egressError ?? "unknown"}` : "app_undecided" };
  deepest = "app_admitted";
  if (!app.some((event) => event.kind === "APP_EXECUTED")) return { basis: simulated ? "simulated" : "natural", l1, l2, lane, deepest, terminal: "app_admitted_not_executed" };
  deepest = "app_executed";
  if (app.some((event) => event.kind === "APP_MUTATED")) return { basis: simulated ? "simulated" : "natural", l1, l2, lane, deepest: "app_mutated", terminal: "app_mutated" };
  return { basis: simulated ? "simulated" : "natural", l1, l2, lane, deepest, terminal: "app_executed_no_mutation" };
}

/** True only when L1's own PASS (no simulated label anywhere in the request) is the evidence. Never derived from a hostile label plus a mutation. */
export const isNaturalL1Bypass = (record: PenetrationRecord): boolean => record.basis === "natural" && record.l1 === "natural_pass";
