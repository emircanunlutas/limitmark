/**
 * Messages of the HARNESS-ONLY collapse plane entry. They are defined here, under lab/, and not in defense/: the normal Slice-3 plane has no
 * collapse message, no fault message and no probe, and ignores any message type it does not define.
 */
import type { ComposerStats } from "../../../defense/core/composer";
import type { ChannelStats } from "../../../defense/core/ledger";
import type { LanesSnapshot } from "../../../defense/core/lanes";
import type { FrontStats } from "../../../defense/plane/front";
import type { ArmSpec, ArmStats } from "./override";

export type CollapseControl =
  | ({ type: "collapse:arm" } & ArmSpec)
  /** A REAL fault inside a layer (no forced verdict): the next `remaining` evaluations of that layer throw or hang. */
  | { type: "collapse:fault"; layer: "l1" | "l2"; kind: "throw" | "hang"; remaining: number }
  /** Read-only snapshot of the plane's L2 state, for quiescence checks between cycles. */
  | { type: "collapse:probe"; probeId: number };

export type ProbeResult = {
  probeId: number;
  lanes: LanesSnapshot;
  /** L2 evaluator occupancy (running plus abandoned-and-unsettled), the L1 composer's occupancy, and the front's in-flight count. */
  l2Occupancy: number;
  l1Occupancy: number;
  front: FrontStats;
  l2Composer: ComposerStats;
  channel: ChannelStats;
  arms: ArmStats;
};

export type CollapseMessage =
  | { type: "collapse:armed"; armId: string }
  | { type: "collapse:refused"; armId: string }
  | ({ type: "collapse:probe_result" } & ProbeResult);
