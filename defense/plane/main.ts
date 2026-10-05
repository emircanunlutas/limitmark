/**
 * Defense Plane process entry. The plane runs as its OWN process so that authoritative measurement (the collector in the harness)
 * stays outside its failure domain: if this process crashes, everything it already delivered over the event channel survives in the
 * collector, and everything it had not delivered is lost AND detected (see lab/defense/collector.ts), never silently absent.
 *
 * Control channel (parent -> plane): init | ack | fault | fin | stop.   Event channel (plane -> parent): ready | events | fin_result.
 * It is a Node IPC pipe from the process that spawned this one. There is no network control surface, and nothing in an HTTP request
 * can arm a fault or change configuration.
 */
import { monitorEventLoopDelay } from "node:perf_hooks";
import { BoundedEventChannel } from "../core/ledger";
import type { Layer, LayerRequest, LayerVerdict } from "../core/types";
import { createFront, type Front, type HopIssuer } from "./front";
import type { PlaneControl, PlaneMessage } from "./protocol";
import { ShapeGate } from "../layers/a7-shape-gate";
import { SemanticGate } from "./semantic-gate";
import { PB_MAX_LIFETIME_MS, importPrivateKey, issuePb } from "../core/hop-proof";

/** Test-only fault wrapper around the real layer, armed ONLY by the parent's control channel. */
class FaultableLayer implements Layer {
  readonly id = "a7.shape-gate" as const;
  private armed: { kind: "throw" | "hang"; remaining: number } | null = null;
  constructor(private readonly inner: Layer) {}
  arm(fault: { kind: "throw" | "hang"; remaining: number }): void { this.armed = fault; }
  evaluate(request: LayerRequest): LayerVerdict | Promise<LayerVerdict> {
    if (this.armed && this.armed.remaining > 0) {
      this.armed.remaining--;
      if (this.armed.kind === "throw") throw new Error("injected layer failure");
      return new Promise<LayerVerdict>(() => undefined);
    }
    return this.inner.evaluate(request);
  }
}

function main(): void {
  if (typeof process.send !== "function") throw new Error("the defense plane must be started with an IPC channel");
  const send = (message: PlaneMessage) => { process.send!(message); };
  let channel: BoundedEventChannel | null = null;
  let front: Front | null = null;
  let layer: FaultableLayer | null = null;
  let gate: ShapeGate | null = null;
  /** Test-only: the next N proof issuances fail (armed only over this IPC pipe), to prove an unsigned request is never sent. */
  let signFaults = 0;
  let hopEnabled = false;
  const loop = monitorEventLoopDelay({ resolution: 10 });
  loop.enable();
  let rssMax = 0;
  const sample = setInterval(() => { rssMax = Math.max(rssMax, process.memoryUsage.rss()); }, 250);
  sample.unref();

  process.on("message", (raw: PlaneControl) => {
    void (async () => {
      if (raw.type === "init" && front === null) {
        const ch = new BoundedEventChannel({ send: (frame) => send(frame) }, raw.channel);
        channel = ch;
        gate = new ShapeGate();
        let hop: HopIssuer | undefined;
        if (raw.hop) {
          hopEnabled = true;
          const config = { kid: raw.hop.kid, privateKey: importPrivateKey(raw.hop.privateKey), boundaryId: raw.hop.boundaryId, lifetimeMs: Math.min(raw.hop.lifetimeMs, PB_MAX_LIFETIME_MS), now: () => Date.now() };
          hop = { issue: (approved, context) => { if (signFaults > 0) { signFaults--; throw new Error("injected signer failure"); } return issuePb(config, approved, context); } };
        }
        layer = new FaultableLayer(raw.hop ? new SemanticGate(gate) : gate);
        front = createFront({
          upstream: { host: "127.0.0.1", port: raw.upstreamPort },
          emit: (event) => ch.emit(event),
          layer,
          hop,
          composer: raw.composer,
          bodyDeadlineMs: raw.bodyDeadlineMs,
          egressTimeoutMs: raw.egressTimeoutMs,
        });
        send({ type: "ready", port: await front.listen() });
      } else if (raw.type === "ack") {
        channel?.acknowledge(raw.received);
      } else if (raw.type === "fault") {
        if (raw.kind === "sign") signFaults = raw.remaining; else layer?.arm({ kind: raw.kind, remaining: raw.remaining });
      } else if (raw.type === "fin" && channel && front && gate) {
        const drained = await channel.drain(3_000);
        rssMax = Math.max(rssMax, process.memoryUsage.rss());
        const cpu = process.cpuUsage();
        send({
          type: "fin_result", drained, channel: channel.stats(),
          advisory: {
            rssMaxMb: Math.round(rssMax / 1_048_576), eventLoopDelayP99Ms: Math.round(loop.percentile(99) / 1e4) / 100,
            eventLoopDelayMaxMs: Math.round(loop.max / 1e4) / 100, cpuUserMs: Math.round(cpu.user / 1000), cpuSystemMs: Math.round(cpu.system / 1000),
            front: front.stats(), composer: front.layerComposerStats(), l1: gate.stats(),
            ...(hopEnabled ? { hop: front.hopStats() } : {}),
          },
        });
      } else if (raw.type === "stop") {
        await front?.close();
        process.exit(0);
      }
    })();
  });
  process.on("disconnect", () => process.exit(1));
}

main();
