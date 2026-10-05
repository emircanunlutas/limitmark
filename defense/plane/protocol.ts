/**
 * Messages exchanged over the IPC pipe between the harness (parent) and the Defense Plane process. Types only: importing this file
 * never starts anything (main.ts is the process entry and runs on import).
 */
import type { ComposerOptions, ComposerStats } from "../core/composer";
import type { ChannelOptions, ChannelStats, EventFrame } from "../core/ledger";
import type { FrontStats, HopStats } from "./front";

/** Slice 2: the plane's ONLY key material. It holds K_P's private half and nothing about the App; delivered over IPC, never env/argv/file. */
export type PlaneHopInit = { privateKey: string; kid: string; boundaryId: string; lifetimeMs: number };

export type PlaneInit = {
  type: "init";
  upstreamPort: number;
  /** Slice 2: issue Plane-to-Boundary proofs and rebuild the forwarded request from the approved semantic request. */
  hop?: PlaneHopInit;
  bodyDeadlineMs?: number;
  egressTimeoutMs?: number;
  composer?: Partial<ComposerOptions>;
  channel?: ChannelOptions;
};
export type PlaneControl =
  | PlaneInit
  | { type: "ack"; received: number }
  | { type: "fault"; kind: "throw" | "hang" | "sign"; remaining: number }
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
  /** Present only in a Slice-2 run. */
  hop?: HopStats;
};
export type PlaneMessage =
  | { type: "ready"; port: number }
  | EventFrame
  | { type: "fin_result"; drained: boolean; channel: ChannelStats; advisory: PlaneAdvisory };

