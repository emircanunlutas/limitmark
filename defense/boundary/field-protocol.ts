/**
 * Field qualification: the field Origin Boundary entry's init extension and tick shape. Types only: importing this file never starts anything.
 *
 * The field entry (`main-field.ts`) is the unchanged Boundary plus one observation-only tick per interval. It adds NO control message: the
 * control surface is still exactly init | ack | fin | stop, and there is still no fault-injection or pass-through control of any kind.
 */
import type { ChannelStats } from "../core/ledger";
import type { Tick } from "../core/telemetry";
import type { BoundaryInit, BoundaryMessage, BoundaryStats } from "./protocol";

export type BoundaryFieldInit = BoundaryInit & { telemetry?: { tickMs: number } };

export type BoundaryTickData = {
  /** Requests that arrived and have not yet been answered or aborted (derived from the boundary's own exact counters). */
  inFlight: number;
  stats: BoundaryStats;
  channel: ChannelStats;
};
export type BoundaryTick = Tick<BoundaryTickData>;
export type BoundaryFieldMessage = BoundaryMessage | BoundaryTick;
