/**
 * Field qualification: the Protected App process entry for a field level. It is `app-main.ts` plus ONE observation-only tick per interval and
 * WITHOUT the lab fault control (`app-main.ts` itself is unchanged; Slice-2 acceptance pins it byte for byte). It holds only public keys,
 * listens on one fixed loopback port and takes only init | ack | fin | stop over its IPC pipe.
 *
 * Telemetry never decides anything here: a tick that fails to build or send changes no admission.
 */
import { BoundedEventChannel, type AppEvent } from "../core/ledger";
import { importPublicKey } from "../core/hop-proof";
import { ProcessSampler, TickSource } from "../core/telemetry";
import { createAppGuard } from "./app-guard";
import type { AppControl } from "./app-protocol";
import type { AppFieldInit, AppFieldMessage, AppTickData } from "./app-field-protocol";
import { createSyntheticOrigin, type SyntheticOrigin } from "./synthetic-origin";

function main(): void {
  if (typeof process.send !== "function") throw new Error("the protected app must be started with an IPC channel");
  const send = (message: AppFieldMessage) => { process.send!(message); };
  let channel: BoundedEventChannel<AppEvent> | null = null;
  let origin: SyntheticOrigin | null = null;
  let guardStats: (() => ReturnType<ReturnType<typeof createAppGuard>["stats"]>) | null = null;
  let ticks: TickSource<AppTickData> | null = null;
  let tickTimer: NodeJS.Timeout | null = null;

  process.on("message", (raw: AppControl | AppFieldInit) => {
    void (async () => {
      if (raw.type === "init" && origin === null) {
        const ch = new BoundedEventChannel<AppEvent>({ send: (frame) => send(frame) }, raw.channel);
        channel = ch;
        const built = createAppGuard({
          keyB: importPublicKey(raw.publicKeyB), kidB: raw.kidB, keyP: importPublicKey(raw.publicKeyP), kidP: raw.kidP,
          appId: raw.appId, boundaryId: raw.boundaryId, replayCapacity: raw.limits.replayCapacity, bodyDeadlineMs: raw.limits.bodyDeadlineMs,
        });
        guardStats = built.stats;
        const created = createSyntheticOrigin({
          instance: "protected", maxConcurrent: raw.maxConcurrent,
          onObservation: () => undefined,
          guard: built.guard,
          onApp: (event) => { ch.emit(event); },
        });
        origin = created;
        const ready = await created.listen();
        const tickMs = (raw as AppFieldInit).telemetry?.tickMs;
        if (typeof tickMs === "number" && Number.isSafeInteger(tickMs) && tickMs >= 100 && tickMs <= 10_000) {
          ticks = new TickSource<AppTickData>("app", new ProcessSampler(), () => {
            const served = created.stats();
            return { inFlight: Math.max(0, served.received - served.completed - served.aborted), counters: created.appStats(), served, guard: built.stats(), channel: ch.stats() };
          });
          tickTimer = setInterval(() => { try { send(ticks!.next()); } catch { /* a missing tick is a measurement gap, never a verdict */ } }, tickMs);
          tickTimer.unref();
        }
        send({ type: "ready", port: ready });
      } else if (raw.type === "ack") {
        channel?.acknowledge(raw.received);
      } else if (raw.type === "fin" && channel && origin && guardStats) {
        const drained = await channel.drain(3_000);
        if (ticks) { try { send(ticks.next(true)); } catch { /* see above */ } }
        send({ type: "fin_result", drained, channel: channel.stats(), stats: { counters: origin.appStats(), served: origin.stats(), guard: guardStats() } });
      } else if (raw.type === "stop") {
        if (tickTimer) clearInterval(tickTimer);
        await origin?.close();
        process.exit(0);
      }
    })();
  });
  process.on("disconnect", () => process.exit(1));
}

main();
