/**
 * Slice 2 lineage validation: a pure function over one request's plane, boundary and app streams.
 *
 * A protected request is clean only if the whole authenticated chain is present and its identifiers agree across three independent
 * processes:
 *
 *   Plane L1 PASS -> EGRESS_ATTEMPTED(hop) -> PROOF_ISSUED(pbTag)
 *     -> Boundary ADMITTED(hop, pbTag) -> APP_PROOF_ISSUED(hop, pbTag, baTag)
 *     -> App ADMITTED(hop, pbTag, baTag) -> EXECUTED -> [MUTATED] -> COMPLETED
 *
 * Any app admission, execution or mutation without that lineage is an anomaly, and so is any direct-rejected lane that reaches the
 * application. Positive controls (lab-minted) are separate lanes: they have no plane lineage by construction and live in a disjoint hop
 * range, so they can never satisfy a protected identity. Rules gated on the streams being present (a Slice-1 run has none).
 */
import {
  NEXT_APP_KINDS, NEXT_BOUNDARY_KINDS, ORACLE_HOP_BASE,
  type Anomaly, type AnomalyCode, type AppEvent, type AppEventKind, type BoundaryEvent, type BoundaryEventKind, type LifecycleView,
} from "./ledger";

const BOUNDARY_RANK: Readonly<Record<BoundaryEventKind, number>> = {
  BOUNDARY_ARRIVED: 1, BOUNDARY_REJECTED: 2, BOUNDARY_ADMITTED: 2, APP_PROOF_ISSUED: 3, BOUNDARY_FORWARDED: 4,
  BOUNDARY_FORWARD_RESPONDED: 5, BOUNDARY_FORWARD_FAILED: 5, BOUNDARY_RESPONDED: 6, BOUNDARY_ABORTED: 6,
  BOUNDARY_PARSER_REJECTED: 0, BOUNDARY_PROTOCOL_REFUSED: 0,
};
const APP_RANK: Readonly<Record<AppEventKind, number>> = { APP_ADMITTED: 1, APP_REFUSED: 1, APP_EXECUTED: 2, APP_MUTATED: 3, APP_COMPLETED: 4, APP_ABORTED: 4 };

function automaton<K extends string>(events: readonly { kind: K; seq: number }[], next: Readonly<Record<K | "START", readonly K[]>>, rank: Readonly<Record<K, number>>, add: (code: AnomalyCode, detail: string) => void): void {
  let previous: K | "START" = "START";
  let lastSeq = -1;
  const seen = new Set<K>();
  for (const event of events) {
    if (event.seq <= lastSeq) add("impossible_order", `seq ${event.kind}`);
    lastSeq = event.seq;
    if (!next[previous].includes(event.kind)) {
      if (previous !== "START" && next[previous].length === 0) add("duplicate_terminal", `${previous}>${event.kind}`);
      else if (seen.has(event.kind)) add("duplicate_event", `${previous}>${event.kind}`);
      else add(rank[event.kind] <= (previous === "START" ? 0 : rank[previous as K]) ? "impossible_order" : "missing_transition", `${previous}>${event.kind}`);
    }
    seen.add(event.kind);
    previous = event.kind;
  }
}

/**
 * True when a protected request's whole authenticated chain is present and every identifier agrees across the three processes.
 * The same predicate `validateOriginLineage` enforces, exposed so the accounting can COUNT complete lineages independently.
 */
export function protectedLineageComplete(view: LifecycleView): boolean {
  const boundary = view.boundary ?? [];
  const app = view.app ?? [];
  const attempted = view.plane.find((event) => event.kind === "EGRESS_ATTEMPTED");
  const issuedPb = view.plane.find((event) => event.kind === "PROOF_ISSUED");
  const admitted = boundary.find((event) => event.kind === "BOUNDARY_ADMITTED");
  const issuedBa = boundary.find((event) => event.kind === "APP_PROOF_ISSUED");
  const appAdmitted = app.find((event) => event.kind === "APP_ADMITTED");
  if (!attempted || !issuedPb || !admitted || !issuedBa || !appAdmitted || issuedPb.pbTag === undefined || issuedBa.baTag === undefined) return false;
  return admitted.hop === attempted.seq && admitted.pbTag === issuedPb.pbTag && issuedBa.hop === attempted.seq && issuedBa.pbTag === issuedPb.pbTag
    && appAdmitted.hop === attempted.seq && appAdmitted.pbTag === issuedPb.pbTag && appAdmitted.baTag === issuedBa.baTag;
}

export function validateOriginLineage(view: LifecycleView, final: boolean): Anomaly[] {
  const found: Anomaly[] = [];
  if (view.boundary === undefined && view.app === undefined) return found;
  const add = (code: AnomalyCode, detail: string) => found.push({ code, nonce: view.nonce, detail });
  const boundary: readonly BoundaryEvent[] = view.boundary ?? [];
  const app: readonly AppEvent[] = view.app ?? [];
  const lane = view.expected;

  const b = (kind: BoundaryEventKind) => boundary.find((event) => event.kind === kind);
  const a = (kind: AppEventKind) => app.find((event) => event.kind === kind);
  const arrived = b("BOUNDARY_ARRIVED");
  const rejected = b("BOUNDARY_REJECTED");
  const admitted = b("BOUNDARY_ADMITTED");
  const issuedBa = b("APP_PROOF_ISSUED");
  const forwardResponded = b("BOUNDARY_FORWARD_RESPONDED");
  const responded = b("BOUNDARY_RESPONDED");
  const boundaryAborted = b("BOUNDARY_ABORTED");
  const appAdmitted = a("APP_ADMITTED");
  const appRefused = a("APP_REFUSED");
  const executed = a("APP_EXECUTED");
  const mutations = app.filter((event) => event.kind === "APP_MUTATED");
  const completed = a("APP_COMPLETED");
  const appAborted = a("APP_ABORTED");

  automaton(boundary, NEXT_BOUNDARY_KINDS, BOUNDARY_RANK, add);
  automaton(app, NEXT_APP_KINDS, APP_RANK, add);
  if (mutations.length > 1) add("duplicate_event", "APP_MUTATED");

  const hops = [...boundary, ...app].flatMap((event) => (event.hop === undefined ? [] : [event.hop]));
  const isPositiveControl = lane === "positive_control_boundary" || lane === "positive_control_app";

  if (lane === "control" || lane === "pre_ingress") {
    if (boundary.length > 0 || app.length > 0) add("boundary_lane_mismatch", lane);
    return found;
  }

  if (lane === "direct_boundary_rejected" || lane === "direct_app_rejected") {
    if (lane === "direct_app_rejected" && boundary.length > 0) add("boundary_lane_mismatch", lane);
    if (admitted || issuedBa) add("direct_not_rejected", "boundary admitted a direct attempt");
    if (appAdmitted || executed || completed) add("direct_app_execution", "application admitted or executed a direct attempt");
    if (mutations.length > 0) add("direct_app_mutation", "application mutated state for a direct attempt");
    return found;
  }

  // protected lane and the two positive controls share the lineage chain; they differ in where the chain starts.
  const attempted = view.plane.find((event) => event.kind === "EGRESS_ATTEMPTED");
  const issuedPb = view.plane.find((event) => event.kind === "PROOF_ISSUED");
  const planeFailed = view.plane.find((event) => event.kind === "EGRESS_FAILED");
  const planeResponded = view.plane.find((event) => event.kind === "EGRESS_RESPONDED");

  if (lane === "protected") {
    if (hops.some((hop) => hop >= ORACLE_HOP_BASE)) add("hop_range_violation", "oracle-range hop in a protected lane");
    if (final && attempted && !issuedPb && !planeFailed) add("missing_transition", "PROOF_ISSUED");
    if (rejected) add("boundary_rejected_plane_egress", rejected.reason ?? "unknown");
    if (admitted && (!attempted || !issuedPb || admitted.hop !== attempted.seq || admitted.pbTag !== issuedPb.pbTag)) add("boundary_hop_mismatch", "ADMITTED does not match the plane's hop/proof");
    if (final && planeResponded && !admitted) add("plane_egress_not_admitted", "plane saw a response with no boundary admission");
  } else {
    if (hops.some((hop) => hop < ORACLE_HOP_BASE)) add("hop_range_violation", "plane-range hop in a positive control");
  }

  // The App's admission is legitimate only with the complete chain behind it.
  let lineage = false;
  if (appAdmitted) {
    if (lane === "positive_control_app") {
      lineage = boundary.length === 0 && appAdmitted.baTag !== undefined && appAdmitted.pbTag !== undefined;
    } else {
      const root = lane === "protected" ? issuedPb?.pbTag : admitted?.pbTag;
      const hop = lane === "protected" ? attempted?.seq : admitted?.hop;
      lineage = root !== undefined && hop !== undefined && !!admitted && !!issuedBa
        && admitted.hop === hop && admitted.pbTag === root && issuedBa.hop === hop && issuedBa.pbTag === root
        && appAdmitted.hop === hop && appAdmitted.pbTag === root && issuedBa.baTag !== undefined && appAdmitted.baTag === issuedBa.baTag;
    }
    if (!lineage) add("app_admit_without_lineage", lane);
  }
  if (executed && !(appAdmitted && lineage)) add("app_execution_without_lineage", lane);
  if (mutations.length > 0 && !(executed && lineage)) add("app_mutation_without_lineage", lane);
  if (lane === "positive_control_app" && boundary.length > 0) add("boundary_lane_mismatch", lane);

  if (!final) return found;

  if (arrived && !rejected && !admitted) add("boundary_decision_missing", "arrived without a decision");
  if (arrived && !(responded || boundaryAborted)) add("unresolved_at_finalization", "boundary");
  if (issuedBa && !appAdmitted && appRefused) add("app_refused_boundary_admitted", appRefused.reason ?? "unknown");
  if (forwardResponded && !appAdmitted) add("missing_transition", "APP_ADMITTED");
  if (appAdmitted && !(completed || appAborted)) add("unresolved_at_finalization", "app");
  if (forwardResponded && completed && forwardResponded.status !== completed.status) add("origin_status_mismatch", `${completed.status}>${forwardResponded.status}`);
  if (isPositiveControl && !(appAdmitted && lineage)) add("positive_control_failed", `${lane} was not admitted with a complete lineage`);
  return found;
}
