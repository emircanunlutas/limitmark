/**
 * Field qualification: the field Protected App entry's init extension and tick shape. Types only.
 *
 * The field entry (`app-main-field.ts`) is the unchanged App plus one observation-only tick per interval, and WITHOUT the lab fault control:
 * its control surface is exactly init | ack | fin | stop.
 */
import type { ChannelStats } from "../core/ledger";
import type { Tick } from "../core/telemetry";
import type { AppGuardStats } from "./app-guard";
import type { AppInit, AppMessage } from "./app-protocol";
import type { AppCounters, SyntheticOriginStats } from "./synthetic-origin";

export type AppFieldInit = AppInit & { telemetry?: { tickMs: number } };

export type AppTickData = {
  /** Requests the application admitted that have not completed or aborted yet (derived from its own exact counters). */
  inFlight: number;
  counters: AppCounters;
  served: SyntheticOriginStats;
  guard: AppGuardStats;
  channel: ChannelStats;
};
export type AppTick = Tick<AppTickData>;
export type AppFieldMessage = AppMessage | AppTick;
