/**
 * Origin Boundary process entry. It runs as its OWN process: separate from the Defense Plane, the Protected App and the harness, so the
 * authoritative ledger stays outside its failure domain. If this process crashes, what it already delivered survives in the collector and
 * what it had not is lost AND detected (lab/defense/collector.ts), never silently absent.
 *
 * Control channel (parent -> boundary): init | ack | fin | stop.   Event channel (boundary -> parent): ready | events | fin_result.
 * It is a Node IPC pipe from the process that spawned this one. There is no network control surface, nothing in an HTTP request can
 * change configuration, and there is deliberately NO fault-injection or pass-through control of any kind.
 */
import { BoundedEventChannel, type BoundaryEvent } from "../core/ledger";
import { importPrivateKey, importPublicKey } from "../core/hop-proof";
import { createBoundary, type Boundary } from "./boundary";
import type { BoundaryControl, BoundaryMessage } from "./protocol";

function main(): void {
  if (typeof process.send !== "function") throw new Error("the origin boundary must be started with an IPC channel");
  const send = (message: BoundaryMessage) => { process.send!(message); };
  let channel: BoundedEventChannel<BoundaryEvent> | null = null;
  let boundary: Boundary | null = null;

  process.on("message", (raw: BoundaryControl) => {
    void (async () => {
      if (raw.type === "init" && boundary === null) {
        const ch = new BoundedEventChannel<BoundaryEvent>({ send: (frame) => send(frame) }, raw.channel);
        channel = ch;
        boundary = createBoundary({
          appPort: raw.appPort,
          keyP: importPublicKey(raw.publicKeyP), kidP: raw.kidP, boundaryId: raw.boundaryId,
          keyB: importPrivateKey(raw.privateKeyB), kidB: raw.kidB, appId: raw.appId,
          limits: raw.limits,
          emit: (event) => ch.emit(event),
        });
        send({ type: "ready", port: await boundary.listen() });
      } else if (raw.type === "ack") {
        channel?.acknowledge(raw.received);
      } else if (raw.type === "fin" && channel && boundary) {
        const drained = await channel.drain(3_000);
        send({ type: "fin_result", drained, channel: channel.stats(), stats: boundary.stats() });
      } else if (raw.type === "stop") {
        await boundary?.close();
        process.exit(0);
      }
    })();
  });
  // The harness is gone: stop listening at once. Closing is the safe state; there is no fallback mode.
  process.on("disconnect", () => process.exit(1));
}

main();
