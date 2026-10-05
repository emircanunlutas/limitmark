/**
 * Messages exchanged over the IPC pipe between the harness (parent) and the Defense Plane process. Types only: importing this file
 * never starts anything (main.ts is the process entry and runs on import).
 */
import type { ComposerOptions, ComposerStats } from "../core/composer";
import type { ChannelOptions, ChannelStats, EventFrame } from "../core/ledger";
import type { FrontStats } from "./front";

export type PlaneInit = {
  type: "init";
  upstreamPort: number;
  bodyDeadlineMs?: number;
  egressTimeoutMs?: number;
  composer?: Partial<ComposerOptions>;
  channel?: ChannelOptions;
};
export type PlaneControl =
  | PlaneInit
  | { type: "ack"; received: number }
  | { type: "fault"; kind: "throw" | "hang"; remaining: number }
  | { type: "fin" }
  | { type: "stop" };

/** Self-reported by the plane. ADVISORY: the authoritative record is the collector's ledger, not these numbers. */
export type PlaneAdvisory = {
  rssMaxMb: number;
  eventLoopDelayP99Ms: number;
  eventLoopDelayMaxMs: number;
  cpuUserMs: number;
  cpuSystemMs: number;
  front: FrontStats;
  composer: ComposerStats;
  l1: { evaluated: number; grammarParses: number };
};
export type PlaneMessage =
  | { type: "ready"; port: number }
  | EventFrame
  | { type: "fin_result"; drained: boolean; channel: ChannelStats; advisory: PlaneAdvisory };

