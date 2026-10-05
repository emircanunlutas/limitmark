/**
 * Slice 2 semantic gate: L1 (unchanged) AND "the request has exactly one canonical semantic representation" as ONE layer verdict.
 *
 * The shape gate judges the raw request first, so every Slice-1 rejection keeps its reason. Only a request L1 passed is then canonicalised;
 * if it cannot be (a duplicated bound header, a refused header, an unrepresentable value) the verdict is an ordinary `a7.semantic_*`
 * reject, counted and answered like any other L1 reject. The representation the plane signs and forwards is the pure function
 * `buildApprovedRequest` of this very request, so "approved" is a single decision, never L1 on one view and a forwarder on another.
 *
 * Installed only when the plane is configured to issue hop proofs; a Slice-1 run never constructs it.
 */
import { buildApprovedRequest } from "../core/semantic-request";
import type { Layer, LayerRequest, LayerVerdict } from "../core/types";

export class SemanticGate implements Layer {
  /** The composite is still the application-shape layer to the composer and the ledger. */
  readonly id = "a7.shape-gate" as const;
  constructor(private readonly inner: Layer) {}

  evaluate(request: LayerRequest): LayerVerdict | Promise<LayerVerdict> {
    const verdict = this.inner.evaluate(request);
    return verdict instanceof Promise ? verdict.then((resolved) => this.refine(request, resolved)) : this.refine(request, verdict);
  }

  private refine(request: LayerRequest, verdict: LayerVerdict): LayerVerdict {
    if (verdict.kind !== "pass") return verdict;
    const built = buildApprovedRequest(request);
    return built.ok ? verdict : { kind: "reject", reason: built.reason };
  }
}
