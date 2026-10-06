/**
 * Field qualification: the Origin Boundary process entry for a field level. It is `main.ts` plus ONE observation-only tick per interval.
 * `main.ts` itself is unchanged (Slice-2 acceptance pins it byte for byte); this entry adds no control message, no fault control and no
 * mode: it still listens on one fixed loopback port, takes only init | ack | fin | stop over its IPC pipe, and stops when that pipe closes.
 *
 * Telemetry never decides anything here: a tick that fails to build or send changes no admission.
 */
import { BoundedEventChannel, type BoundaryEvent } from "../core/ledger";
import { importPrivateKey, importPublicKey } from "../core/hop-proof";
import { ProcessSampler, TickSource } from "../core/telemetry";
import { createBoundary, type Boundary } from "./boundary";
import type { BoundaryControl } from "./protocol";
import type { BoundaryFieldInit, BoundaryFieldMessage, BoundaryTickData } from "./field-protocol";

function main(): void {
  if (typeof process.send !== "function") throw new Error("the origin boundary must be started with an IPC channel");
  const send = (message: BoundaryFieldMessage) => { process.send!(message); };
  let channel: BoundedEventChannel<BoundaryEvent> | null = null;
  let boundary: Boundary | null = null;
  let ticks: TickSource<BoundaryTickData> | null = null;
  let tickTimer: NodeJS.Timeout | null = null;

  process.on("message", (raw: BoundaryControl | BoundaryFieldInit) => {
    void (async () => {
      if (raw.type === "init" && boundary === null) {
        const ch = new BoundedEventChannel<BoundaryEvent>({ send: (frame) => send(frame) }, raw.channel);
        channel = ch;
        const created = createBoundary({
          appPort: raw.appPort,
          keyP: importPublicKey(raw.publicKeyP), kidP: raw.kidP, boundaryId: raw.boundaryId,
          keyB: importPrivateKey(raw.privateKeyB), kidB: raw.kidB, appId: raw.appId,
          limits: raw.limits,
          emit: (event) => ch.emit(event),
        });
        boundary = created;
        const ready = await created.listen();
        const tickMs = (raw as BoundaryFieldInit).telemetry?.tickMs;
        if (typeof tickMs === "number" && Number.isSafeInteger(tickMs) && tickMs >= 100 && tickMs <= 10_000) {
          ticks = new TickSource<BoundaryTickData>("boundary", new ProcessSampler(), () => {
            const stats = created.stats();
            return { inFlight: Math.max(0, stats.arrived - stats.responded - stats.aborted), stats, channel: ch.stats() };
          });
          tickTimer = setInterval(() => { try { send(ticks!.next()); } catch { /* a missing tick is a measurement gap, never a verdict */ } }, tickMs);
          tickTimer.unref();
        }
        send({ type: "ready", port: ready });
      } else if (raw.type === "ack") {
        channel?.acknowledge(raw.received);
      } else if (raw.type === "fin" && channel && boundary) {
        const drained = await channel.drain(3_000);
        if (ticks) { try { send(ticks.next(true)); } catch { /* see above */ } }
        send({ type: "fin_result", drained, channel: channel.stats(), stats: boundary.stats() });
      } else if (raw.type === "stop") {
        if (tickTimer) clearInterval(tickTimer);
        await boundary?.close();
        process.exit(0);
      }
    })();
  });
  // The harness is gone: stop listening at once. Closing is the safe state; there is no fallback mode.
  process.on("disconnect", () => process.exit(1));
}

main();
