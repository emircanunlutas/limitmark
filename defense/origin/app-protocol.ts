/**
 * Messages exchanged over the IPC pipe between the harness (parent) and the Protected App process. Types only.
 *
 * Key material: the App receives ONLY public keys (K_B to verify the Boundary's proof, K_P to verify the Plane's proof as lineage). It
 * holds zero private keys.
 */
import type { AppEvent, ChannelOptions, ChannelStats, EventFrame } from "../core/ledger";
import type { AppGuardStats } from "./app-guard";
import type { AppCounters, SyntheticOriginStats } from "./synthetic-origin";

export type AppInit = {
  type: "init";
  publicKeyB: string;
  kidB: string;
  publicKeyP: string;
  kidP: string;
  appId: string;
  boundaryId: string;
  limits: { replayCapacity: number; bodyDeadlineMs: number };
  maxConcurrent?: number;
  channel?: ChannelOptions;
};

export type AppFault = { kind: "reset" | "hang" | "delay"; remaining: number; delayMs?: number };
export type AppControl =
  | AppInit
  | { type: "ack"; received: number }
  | { type: "fault"; fault: AppFault }
  | { type: "fin" }
  | { type: "stop" };

/** The application's own authoritative counters, cross-checked against the ledger and never trusted alone. */
export type AppFinStats = { counters: AppCounters; served: SyntheticOriginStats; guard: AppGuardStats };

export type AppMessage =
  | { type: "ready"; port: number }
  | EventFrame<AppEvent>
  | { type: "fin_result"; drained: boolean; channel: ChannelStats; stats: AppFinStats };
