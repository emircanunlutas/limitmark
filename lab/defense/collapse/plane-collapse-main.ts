/**
 * HARNESS-ONLY plane entry for the collapse experiments (C1, C2, C2'). It is the Slice-3 plane composition (`defense/plane/runtime.ts`)
 * with exactly three things injected that no normal entry has:
 *
 *   - a verdict-override implementation (`override.ts`), armed only over this process's IPC pipe;
 *   - fault wrappers around L1 and around the L2 layer (real throw/hang, no forced verdict);
 *   - a read-only probe of the plane's own state.
 *
 * It is forked only by the BA0 collapse harness. `defense/plane/main.ts` and `defense/plane/main-l2.ts` never import this file or
 * anything it imports from `lab/`, so no production or default module graph contains a force-pass implementation or a handler for one.
 */
import type { Layer, LayerId, LayerRequest, LayerVerdict } from "../../../defense/core/types";
import { startPlane } from "../../../defense/plane/runtime";
import { CollapseOverride } from "./override";
import type { CollapseControl, CollapseMessage } from "./protocol";

type Fault = { kind: "throw" | "hang"; remaining: number } | null;

class FaultableLayer implements Layer {
  fault: Fault = null;
  constructor(readonly id: LayerId, private readonly inner: Layer) {}
  evaluate(request: LayerRequest): LayerVerdict | Promise<LayerVerdict> {
    if (this.fault && this.fault.remaining > 0) {
      this.fault.remaining--;
      if (this.fault.kind === "throw") throw new Error("injected layer failure");
      return new Promise<LayerVerdict>(() => undefined);
    }
    return this.inner.evaluate(request);
  }
}

const override = new CollapseOverride();
let l1Wrapper: FaultableLayer | null = null;
let l2Wrapper: FaultableLayer | null = null;

const handle = startPlane({
  verdictOverride: override,
  wrapL1: (layer) => { l1Wrapper = new FaultableLayer(layer.id, layer); return l1Wrapper; },
  wrapL2: (layer) => { l2Wrapper = new FaultableLayer(layer.id, layer); return l2Wrapper; },
});

const reply = (message: CollapseMessage) => handle.send(message);

process.on("message", (raw: CollapseControl) => {
  if (raw.type === "collapse:arm") {
    const { type: _type, ...spec } = raw;
    void _type;
    reply(override.arm(spec) ? { type: "collapse:armed", armId: spec.armId } : { type: "collapse:refused", armId: spec.armId });
  } else if (raw.type === "collapse:fault") {
    const wrapper = raw.layer === "l1" ? l1Wrapper : l2Wrapper;
    if (wrapper) wrapper.fault = { kind: raw.kind, remaining: raw.remaining };
  } else if (raw.type === "collapse:probe") {
    const stage = handle.stage();
    const front = handle.front();
    const channel = handle.channel();
    if (!stage || !front || !channel) return;
    const stats = stage.stats();
    reply({
      type: "collapse:probe_result", probeId: raw.probeId, lanes: stats.lanes, l2Occupancy: stats.occupancy, l1Occupancy: front.composerOccupancy(), front: front.stats(),
      l2Composer: stats.composer, channel: channel.stats(), arms: override.stats(),
    });
  }
});
