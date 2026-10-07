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
import type { ConnectionStats, ExternalStats, FrontStats, HopStats } from "./front";
import type { Tick } from "../core/telemetry";

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

export type PlaneL2Init = PlaneInit & {
  hop: PlaneHopInit;
  l2: L2Params;
  /**
   * Field qualification: the ONE reviewed fixed public bind. Absent in every Slice-3 composition (127.0.0.1, ephemeral port). The harness
   * decides whether to pass it; nothing a request carries can.
   */
  ingress?: { ip: string; port: number };
  /** Field qualification: emit one small observation-only tick per interval. Absent means no ticks and no timer. */
  telemetry?: { tickMs: number };
};

/** One 1-second plane tick: exact monotonic counters and bounded gauges. Observation only; no layer or lane ever reads any of it. */
export type PlaneTickData = {
  ingressOpen: boolean;
  front: FrontStats;
  /** In-flight maxima since the previous tick (all peers / remote peers only). */
  inFlightMax: number;
  inFlightExternalMax: number;
  external: ExternalStats;
  connections: ConnectionStats;
  l1Composer: ComposerStats;
  l1Occupancy: number;
  l1: { evaluated: number; grammarParses: number };
  hop: HopStats;
  l2: { composer: ComposerStats; occupancy: number; lanes: LanesSnapshot };
  channel: ChannelStats;
};
export type PlaneTick = Tick<PlaneTickData>;

/** N=2 observation barrier: source-clock/sequence watermark, with no admission or listener effect. IPC only. */
export type MeasurementBarrier = {
  phase: "armed" | "closed"; seq: number; atMs: number; wallAt: string; acceptedExternal: number; inFlightExternal: number;
};

export type PlaneL2Advisory = PlaneAdvisory & {
  l2: { composer: ComposerStats; occupancy: number; lanes: LanesSnapshot };
  /** True only when a harness-only verdict-override implementation was injected. A normal entry always reports false. */
  overrideInjected: boolean;
  channelNow: ChannelStats;
};
