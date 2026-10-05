/**
 * Slice 3: messages and parameters of the Slice-3 Defense Plane (`main-l2.ts`). Types only: importing this file never starts anything.
 *
 * The control surface of the normal Slice-3 plane is exactly init | ack | fin | stop. It has NO fault control, NO collapse control and NO
 * probe: any harness-only control is registered by the harness's own entry (lab/defense/collapse), not here. L2 is not optional: there is
 * no field that turns it off, and `PlaneL2Init.l2` is required.
 */
import type { ChannelStats } from "../core/ledger";
import type { LanesSnapshot } from "../core/lanes";
import type { ComposerStats } from "../core/composer";
import type { PlaneAdvisory, PlaneHopInit, PlaneInit } from "./protocol";

export type L2Params = {
  /** Bits per Bloom generation (a power of two) and hash count. */
  filterBits: number;
  filterHashes: number;
  /** Generation length = the guaranteed credit lifetime. */
  epochMs: number;
  credited: { capacity: number; refillPerSecond: number };
  unverified: { capacity: number; refillPerSecond: number };
  /** Uses per genuinely enrolled token. */
  maxUses: number;
  ledgerCapacity: number;
  /** The L2 evaluator's own deadline and bulkhead (the accepted composer). */
  stage?: { timeoutMs?: number; maxConcurrent?: number };
};

export type PlaneL2Init = PlaneInit & { hop: PlaneHopInit; l2: L2Params };

export type PlaneL2Advisory = PlaneAdvisory & {
  l2: { composer: ComposerStats; occupancy: number; lanes: LanesSnapshot };
  /** True only when a harness-only verdict-override implementation was injected. A normal entry always reports false. */
  overrideInjected: boolean;
  channelNow: ChannelStats;
};
