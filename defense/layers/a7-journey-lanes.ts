/**
 * L2 `a7.journey-lanes` as a Layer: the adapter that lets the accepted composer give the mechanism its own deadline and its own bulkhead.
 *
 * The layer verdict vocabulary is the existing one (pass | reject); the richer decision (class, lane, outcome, credit tag, bucket clock
 * and level) is handed to the stage through a WeakMap keyed by the very request object, never through shared mutable state. A decision
 * the composer later DISCARDS (a late verdict) has already consumed what it consumed: the stage reads it back and accounts for it.
 */
import type { Layer, LayerRequest, LayerVerdict } from "../core/types";
import type { JourneyLanes, LaneDecision } from "../core/lanes";

const PASS: LayerVerdict = { kind: "pass" };

export class JourneyLanesLayer implements Layer {
  readonly id = "a7.journey-lanes" as const;
  private readonly made = new WeakMap<LayerRequest, LaneDecision>();

  constructor(private readonly lanes: JourneyLanes) {}

  evaluate(request: LayerRequest): LayerVerdict {
    const decision = this.lanes.decide(request);
    this.made.set(request, decision);
    if (decision.outcome === "admitted") return PASS;
    if (decision.outcome === "shed") return { kind: "reject", reason: decision.lane === "credited" ? "a7.lane_credited_budget" : "a7.lane_unverified_budget" };
    // The only decision-level error is a full ledger: fail closed through the composer's error path.
    throw new Error("l2 decision error");
  }

  /** Removes and returns the decision this request's evaluation made, if it got as far as making one. */
  take(request: LayerRequest): LaneDecision | undefined {
    const decision = this.made.get(request);
    this.made.delete(request);
    return decision;
  }
}
