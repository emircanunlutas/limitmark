/**
 * Slice 3 plane runtime: the composition shared by the normal Slice-3 entry (`main-l2.ts`) and the harness-only collapse entry
 * (`lab/defense/collapse/plane-collapse-main.ts`). The legacy Slice-1/2 entry (`main.ts`) is NOT touched and does not use this file.
 *
 *   L1 (shape gate + semantic gate)  ->  L2 (journey lanes, ALWAYS present)  ->  canonicalization  ->  PB issuance  ->  Boundary
 *
 * `startPlane(deps)` takes optional INJECTED dependencies. The normal entry passes none. The injection seams are the only way a harness
 * can add a fault wrapper or a verdict override; nothing in this file implements either, and nothing here reads an environment variable,
 * a file or a request to decide whether to. Control messages handled here: init | ack | fin | stop. Unknown messages are ignored, so a
 * harness entry can register its own listener for its own message types without this file knowing they exist.
 */
import { randomBytes } from "node:crypto";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { BoundedEventChannel } from "../core/ledger";
import { JourneyLanes } from "../core/lanes";
import type { VerdictOverridePort } from "../core/override-port";
import type { Layer } from "../core/types";
import { PB_MAX_LIFETIME_MS, importPrivateKey, issuePb } from "../core/hop-proof";
import { ShapeGate } from "../layers/a7-shape-gate";
import { createFront, type Front, type HopIssuer } from "./front";
import { L2Stage } from "./l2-stage";
import type { PlaneL2Advisory, PlaneL2Init } from "./l2-protocol";
import type { PlaneMessage } from "./protocol";
import { SemanticGate } from "./semantic-gate";

export const MAX_RESPONSE_BYTES = 1_048_576;

export type PlaneRuntimeDeps = {
  /** Harness-only: wraps the L1 composite (a fault wrapper). The normal entry passes nothing. */
  wrapL1?: (layer: Layer) => Layer;
  /** Harness-only: wraps the layer the L2 composer runs (a fault wrapper). The normal entry passes nothing. */
  wrapL2?: (layer: Layer) => Layer;
  /** Harness-only: a verdict-override implementation (core/override-port.ts). The normal entry passes nothing. */
  verdictOverride?: VerdictOverridePort;
};

export type PlaneRuntimeHandle = {
  /** Present after `init`. The harness entry reads these for its own read-only probe. */
  stage(): L2Stage | null;
  front(): Front | null;
  channel(): BoundedEventChannel | null;
  send(message: unknown): void;
};

type Control = PlaneL2Init | { type: "ack"; received: number } | { type: "fin" } | { type: "stop" };

export function startPlane(deps: PlaneRuntimeDeps = {}): PlaneRuntimeHandle {
  if (typeof process.send !== "function") throw new Error("the defense plane must be started with an IPC channel");
  const send = (message: PlaneMessage | Record<string, unknown>) => { process.send!(message); };
  let channel: BoundedEventChannel | null = null;
  let front: Front | null = null;
  let gate: ShapeGate | null = null;
  let stage: L2Stage | null = null;
  const loop = monitorEventLoopDelay({ resolution: 10 });
  loop.enable();
  let rssMax = 0;
  const sample = setInterval(() => { rssMax = Math.max(rssMax, process.memoryUsage.rss()); }, 250);
  sample.unref();

  process.on("message", (raw: Control) => {
    void (async () => {
      if (raw.type === "init" && front === null) {
        const ch = new BoundedEventChannel({ send: (frame) => send(frame) }, raw.channel);
        channel = ch;
        gate = new ShapeGate();
        const semantic = new SemanticGate(gate);
        const l1: Layer = deps.wrapL1 ? deps.wrapL1(semantic) : semantic;
        const config = { kid: raw.hop.kid, privateKey: importPrivateKey(raw.hop.privateKey), boundaryId: raw.hop.boundaryId, lifetimeMs: Math.min(raw.hop.lifetimeMs, PB_MAX_LIFETIME_MS), now: () => Date.now() };
        const hop: HopIssuer = { issue: (approved, context) => issuePb(config, approved, context) };
        const lanes = new JourneyLanes({
          filterBits: raw.l2.filterBits, filterHashes: raw.l2.filterHashes, epochMs: raw.l2.epochMs, credited: raw.l2.credited, unverified: raw.l2.unverified,
          maxUses: raw.l2.maxUses, ledgerCapacity: raw.l2.ledgerCapacity, mono: () => performance.now(), key: randomBytes(32),
        });
        stage = new L2Stage(lanes, { composer: raw.l2.stage, wrapLayer: deps.wrapL2, maxResponseBytes: MAX_RESPONSE_BYTES });
        front = createFront({
          upstream: { host: "127.0.0.1", port: raw.upstreamPort }, emit: (event) => ch.emit(event), layer: l1, hop, l2: stage, verdictOverride: deps.verdictOverride,
          composer: raw.composer, bodyDeadlineMs: raw.bodyDeadlineMs, egressTimeoutMs: raw.egressTimeoutMs, maxResponseBytes: MAX_RESPONSE_BYTES,
        });
        send({ type: "ready", port: await front.listen() });
      } else if (raw.type === "ack") {
        channel?.acknowledge(raw.received);
      } else if (raw.type === "fin" && channel && front && gate && stage) {
        const drained = await channel.drain(3_000);
        rssMax = Math.max(rssMax, process.memoryUsage.rss());
        const cpu = process.cpuUsage();
        const advisory: PlaneL2Advisory = {
          rssMaxMb: Math.round(rssMax / 1_048_576), eventLoopDelayP99Ms: Math.round(loop.percentile(99) / 1e4) / 100,
          eventLoopDelayMaxMs: Math.round(loop.max / 1e4) / 100, cpuUserMs: Math.round(cpu.user / 1000), cpuSystemMs: Math.round(cpu.system / 1000),
          front: front.stats(), composer: front.layerComposerStats(), l1: gate.stats(), hop: front.hopStats(),
          l2: stage.stats(), overrideInjected: deps.verdictOverride !== undefined, channelNow: channel.stats(),
        };
        send({ type: "fin_result", drained, channel: channel.stats(), advisory });
      } else if (raw.type === "stop") {
        await front?.close();
        process.exit(0);
      }
    })();
  });
  process.on("disconnect", () => process.exit(1));
  return { stage: () => stage, front: () => front, channel: () => channel, send };
}
