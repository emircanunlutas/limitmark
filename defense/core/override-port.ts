/**
 * Slice 3: the INTERFACE through which a HARNESS-ONLY implementation may deliver a different verdict than a layer computed.
 *
 * This file is types only: it has no runtime export. There is no implementation anywhere under `defense/`. The only implementation lives
 * under `lab/defense/collapse/` and is constructed only by the harness's own plane entry. The normal Slice-3 entry (`main-l2.ts`) and the
 * legacy entry (`main.ts`) never pass one, so their module graphs contain no force-pass code and no handler that could arm one.
 *
 * A port can only convert a layer's real REFUSAL into a pass (the layer still evaluated: the shadow verdict is always recorded and the
 * delivered verdict is permanently labelled `basis: "simulated"`). It receives no key, no proof, and no handle on any later stage.
 */
import type { LaneDecision } from "./lanes";
import type { LayerOutcome, LayerRequest } from "./types";

export type SimulatedOverride = { shadow: string };

export interface VerdictOverridePort {
  /** L1 computed a refusal; return a shadow label to deliver a pass instead, or null to leave the verdict alone. */
  l1(context: { request: LayerRequest; nonce: string; remotePort: number | undefined; outcome: LayerOutcome }): SimulatedOverride | null;
  /** L2 computed a shed or an admit; return a shadow label to deliver an admit labelled simulated, or null. */
  l2(context: { request: LayerRequest; nonce: string; remotePort: number | undefined; decision: LaneDecision }): SimulatedOverride | null;
}
