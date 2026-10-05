/**
 * Messages exchanged over the IPC pipe between the harness (parent) and the Origin Boundary process. Types only: importing this file never
 * starts anything (main.ts is the process entry and runs on import).
 *
 * Key material: the Boundary receives K_P's PUBLIC half (to verify the Plane's proof) and K_B's PRIVATE half (to issue the App proof). It
 * never receives K_P's private half. Delivered over IPC only: never env, argv, a file, a log or evidence.
 */
import type { BoundaryEvent, ChannelOptions, ChannelStats, EventFrame, EgressErrorKind } from "../core/ledger";
import type { ReplayStats } from "../core/replay-guard";
import type { ObReason } from "../core/types";

export type BoundaryLimits = {
  replayCapacity: number;
  bodyDeadlineMs: number;
  forwardTimeoutMs: number;
  baLifetimeMs: number;
};

export type BoundaryInit = {
  type: "init";
  appPort: number;
  /** K_P public (SPKI, base64url) and its kid: the only key this process verifies with. */
  publicKeyP: string;
  kidP: string;
  boundaryId: string;
  /** K_B private (PKCS8, base64url) and its kid: used only to issue the Boundary-to-App proof. */
  privateKeyB: string;
  kidB: string;
  appId: string;
  limits: BoundaryLimits;
  channel?: ChannelOptions;
};

export type BoundaryControl = BoundaryInit | { type: "ack"; received: number } | { type: "fin" } | { type: "stop" };

/** The boundary's own independent counters. The ledger is authoritative; these are cross-checked against it, never trusted alone. */
export type BoundaryStats = {
  arrived: number;
  admitted: number;
  rejected: number;
  rejectedByReason: Record<string, number>;
  appProofsIssued: number;
  relayed: number;
  forwardResponded: number;
  forwardFailed: number;
  forwardFailedByKind: Record<EgressErrorKind, number>;
  responded: number;
  aborted: number;
  parserRejected: number;
  protocolRefused: number;
  replay: ReplayStats;
  contentReadsStarted: number;
  contentBytesRead: number;
  clockStepMs: number;
  clockStep: boolean;
};

export type BoundaryMessage =
  | { type: "ready"; port: number }
  | EventFrame<BoundaryEvent>
  | { type: "fin_result"; drained: boolean; channel: ChannelStats; stats: BoundaryStats };

export type { ObReason };
