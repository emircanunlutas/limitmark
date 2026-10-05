/**
 * Harness-side controller for the collapse plane entry: arms one-shot verdict overrides, injects real layer faults and probes the plane's
 * state. Every message goes over the plane process's IPC pipe; nothing here touches the wire the traffic uses.
 */
import { randomBytes } from "node:crypto";
import type { PlaneProcess } from "../plane-process";
import { armTagOf, fixtureDigestOf, type ArmStats } from "./override";
import type { CollapseControl, CollapseMessage, ProbeResult } from "./protocol";

export type FixtureIdentity = { method: string; target: string; body: Uint8Array | null };
export type ArmRecord = { armTag: string; layer: "l1" | "l2"; granted: boolean };

export class CollapseController {
  private readonly waiting = new Map<string, (granted: boolean) => void>();
  private readonly probes = new Map<number, (result: ProbeResult) => void>();
  private probeCounter = 0;
  readonly records: ArmRecord[] = [];

  constructor(private readonly plane: PlaneProcess) {
    plane.onExtra((message) => {
      const typed = message as CollapseMessage;
      if (typed.type === "collapse:armed" || typed.type === "collapse:refused") {
        this.waiting.get(typed.armId)?.(typed.type === "collapse:armed");
        this.waiting.delete(typed.armId);
      } else if (typed.type === "collapse:probe_result") {
        this.probes.get(typed.probeId)?.(typed);
        this.probes.delete(typed.probeId);
      }
    });
  }

  /** Arms one verdict for the request the harness is about to send on this connection. Resolves when the plane acknowledged (or refused). */
  async arm(layer: "l1" | "l2", nonce: string, fixture: FixtureIdentity, remotePort: number, timeoutMs = 2_000): Promise<boolean> {
    const armId = randomBytes(16).toString("base64url");
    const granted = await new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => { this.waiting.delete(armId); resolve(false); }, timeoutMs);
      this.waiting.set(armId, (value) => { clearTimeout(timer); resolve(value); });
      const message: CollapseControl = { type: "collapse:arm", armId, layer, nonce, fixtureDigest: fixtureDigestOf(fixture), remotePort, ttlMs: 5_000 };
      this.plane.sendControl(message);
    });
    this.records.push({ armTag: armTagOf(armId), layer, granted });
    return granted;
  }

  fault(layer: "l1" | "l2", kind: "throw" | "hang", remaining: number): void {
    const message: CollapseControl = { type: "collapse:fault", layer, kind, remaining };
    this.plane.sendControl(message);
  }

  probe(timeoutMs = 3_000): Promise<ProbeResult | null> {
    const probeId = ++this.probeCounter;
    return new Promise((resolve) => {
      const timer = setTimeout(() => { this.probes.delete(probeId); resolve(null); }, timeoutMs);
      this.probes.set(probeId, (result) => { clearTimeout(timer); resolve(result); });
      const message: CollapseControl = { type: "collapse:probe", probeId };
      this.plane.sendControl(message);
    });
  }

  async armStats(): Promise<ArmStats | null> { return (await this.probe())?.arms ?? null; }
}
