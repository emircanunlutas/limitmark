/**
 * Protected App process entry. It runs as its OWN process, holds only public keys, and listens on one 127.0.0.1 port that is reachable by
 * anyone on the host: its guard admits only a request that carries a valid Boundary-to-App proof with Plane lineage. Knowing this port is
 * therefore no more useful than knowing the Boundary's.
 *
 * Control channel (parent -> app): init | ack | fault | fin | stop.   Event channel (app -> parent): ready | events | fin_result.
 * `fault` arms an origin failure (reset/hang/delay) for the failure tests; it is reachable only over this IPC pipe.
 */
import { BoundedEventChannel, type AppEvent } from "../core/ledger";
import { importPublicKey } from "../core/hop-proof";
import { createAppGuard } from "./app-guard";
import type { AppControl, AppMessage } from "./app-protocol";
import { createSyntheticOrigin, type SyntheticOrigin } from "./synthetic-origin";

function main(): void {
  if (typeof process.send !== "function") throw new Error("the protected app must be started with an IPC channel");
  const send = (message: AppMessage) => { process.send!(message); };
  let channel: BoundedEventChannel<AppEvent> | null = null;
  let origin: SyntheticOrigin | null = null;
  let guardStats: (() => ReturnType<ReturnType<typeof createAppGuard>["stats"]>) | null = null;

  process.on("message", (raw: AppControl) => {
    void (async () => {
      if (raw.type === "init" && origin === null) {
        const ch = new BoundedEventChannel<AppEvent>({ send: (frame) => send(frame) }, raw.channel);
        channel = ch;
        const built = createAppGuard({
          keyB: importPublicKey(raw.publicKeyB), kidB: raw.kidB, keyP: importPublicKey(raw.publicKeyP), kidP: raw.kidP,
          appId: raw.appId, boundaryId: raw.boundaryId, replayCapacity: raw.limits.replayCapacity, bodyDeadlineMs: raw.limits.bodyDeadlineMs,
        });
        guardStats = built.stats;
        origin = createSyntheticOrigin({
          instance: "protected", maxConcurrent: raw.maxConcurrent,
          onObservation: () => undefined,
          guard: built.guard,
          onApp: (event) => { ch.emit(event); },
        });
        send({ type: "ready", port: await origin.listen() });
      } else if (raw.type === "ack") {
        channel?.acknowledge(raw.received);
      } else if (raw.type === "fault" && origin) {
        origin.armFault(raw.fault.kind === "delay" ? { kind: "delay", remaining: raw.fault.remaining, delayMs: raw.fault.delayMs ?? 100 } : { kind: raw.fault.kind, remaining: raw.fault.remaining });
      } else if (raw.type === "fin" && channel && origin && guardStats) {
        const drained = await channel.drain(3_000);
        send({ type: "fin_result", drained, channel: channel.stats(), stats: { counters: origin.appStats(), served: origin.stats(), guard: guardStats() } });
      } else if (raw.type === "stop") {
        await origin?.close();
        process.exit(0);
      }
    })();
  });
  process.on("disconnect", () => process.exit(1));
}

main();
