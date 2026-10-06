/**
 * The L2 stage of the Slice-3 Defense Plane: runs `a7.journey-lanes` through the accepted composer (its own deadline and bulkhead) and turns
 * EVERY outcome into exactly one `LaneDecision`. Nothing is thrown past it and nothing disappears.
 *
 * Failure policy (the design closure's, enforced by `failureDecision`): a failed or saturated evaluation of a mutation or unknown request
 * is a shed or an error, never an admit. Only an `open` operation (the four exact GET routes, whose healthy decision is already an
 * unconditional admit) may become `degraded`, and a degraded decision is never an `admitted` one and never enrolls credit.
 *
 * P3: whatever a decision consumed stays consumed. If the composer discards a decision (a late verdict), this stage reports what it had
 * consumed (`spent` / `touched`) so the accounting and the bucket replay stay exact; it refunds nothing.
 */
import { LayerComposer, type ComposerOptions, type ComposerStats } from "../core/composer";
import { evaluateObservation, isFormRoute, type EnrollSkipReason, type ObservationVerdict } from "../core/enrollment";
import type { EnrollmentEvent, EnrollmentObservation, L2Port } from "../core/l2-port";
import { failureDecision, operationClassOf, type JourneyLanes, type LaneDecision, type LanesSnapshot, type OperationClass } from "../core/lanes";
import type { Layer, LayerRequest } from "../core/types";
import { JourneyLanesLayer } from "../layers/a7-journey-lanes";

export type L2StageOptions = {
  composer?: Partial<ComposerOptions>;
  /** Harness-only seam: wraps the layer the composer runs (a fault wrapper). The normal entry passes nothing. */
  wrapLayer?: (layer: Layer) => Layer;
  /** The response bound the front already enforces; an enrollment scan never reads past it. */
  maxResponseBytes: number;
};

export type L2StageStats = { composer: ComposerStats; occupancy: number; lanes: LanesSnapshot };

class Observation implements EnrollmentObservation {
  private verdict: ObservationVerdict | null = null;
  private done = false;
  private readonly early: EnrollSkipReason | null;

  constructor(
    private readonly lanes: JourneyLanes,
    decision: LaneDecision,
    simulated: boolean,
    private readonly emit: (event: EnrollmentEvent) => void,
    private readonly maxBytes: number,
  ) {
    // Conditions on the L2 decision itself: degraded and simulated renders never enroll.
    this.early = decision.outcome === "degraded" ? "degraded" : simulated || decision.basis === "simulated" ? "simulated" : null;
  }

  onUpstream(response: { status: number; rawHeaders: readonly string[]; payload: Uint8Array }): void {
    if (this.done || this.early !== null || this.verdict !== null) return;
    this.verdict = evaluateObservation(response, this.maxBytes);
  }

  /** Called from the response's `finish`: the earliest sound point to enroll. Acts only when every earlier condition already holds. */
  onDelivered(): void {
    if (this.done || this.early !== null || this.verdict === null || !this.verdict.ok) return;
    this.done = true;
    const enrolled = this.lanes.enroll(this.verdict.token);
    if (enrolled.ok) this.emit({ kind: "L2_ENROLLED", creditTag: enrolled.creditTag, fill: this.lanes.filter.stats().popcount });
    else this.emit({ kind: "L2_ENROLL_SKIPPED", skipReason: enrolled.reason });
  }

  finalize(): void {
    if (this.done) return;
    this.done = true;
    const reason: EnrollSkipReason = this.early ?? (this.verdict === null ? "upstream_failed" : this.verdict.ok ? "delivery_incomplete" : this.verdict.reason);
    this.emit({ kind: "L2_ENROLL_SKIPPED", skipReason: reason });
  }
}

export class L2Stage implements L2Port {
  private readonly layer: JourneyLanesLayer;
  private readonly composer: LayerComposer;

  constructor(readonly lanes: JourneyLanes, private readonly options: L2StageOptions) {
    this.layer = new JourneyLanesLayer(lanes);
    const run: Layer = options.wrapLayer ? options.wrapLayer(this.layer) : this.layer;
    this.composer = new LayerComposer(run, { timeoutMs: 50, maxConcurrent: 64, failurePolicy: "fail_closed", ...options.composer });
  }

  async decide(request: LayerRequest): Promise<LaneDecision> {
    let cls: OperationClass;
    try { cls = operationClassOf(request.method, request.target); } catch { cls = "unknown"; }
    let decision: LaneDecision;
    try {
      const outcome = await this.composer.run(request);
      const made = this.layer.take(request);
      if (outcome.kind === "pass" || outcome.kind === "reject") {
        decision = made ?? failureDecision(cls, "invalid_verdict");
      } else if (outcome.kind === "shed") {
        decision = failureDecision(cls, "saturation");
      } else if (made?.outcome === "error") {
        decision = made; // a ledger refusal: nothing was consumed
      } else {
        decision = failureDecision(cls, outcome.errorKind);
        // P3: the discarded evaluation already took what it took. It is reported, never returned.
        if (made?.lane && made.outcome === "admitted") decision = { ...decision, spent: made.lane, dt: made.dt, lvl: made.lvl, lseq: made.lseq };
        else if (made?.lane && made.outcome === "shed") decision = { ...decision, touched: made.lane, dt: made.dt, lvl: made.lvl, lseq: made.lseq };
      }
    } catch {
      decision = failureDecision(cls, "throw");
    }
    this.lanes.record(decision);
    return decision;
  }

  observe(request: LayerRequest, decision: LaneDecision, context: { simulated: boolean; emit(event: EnrollmentEvent): void }): EnrollmentObservation | null {
    if (!isFormRoute(request.method, request.target)) return null;
    return new Observation(this.lanes, decision, context.simulated, context.emit, this.options.maxResponseBytes);
  }

  stats(): L2StageStats { return { composer: this.composer.stats(), occupancy: this.composer.occupancy, lanes: this.lanes.snapshot() }; }
}
