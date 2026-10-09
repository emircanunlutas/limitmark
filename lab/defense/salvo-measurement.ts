import type { PlaneEvent } from "../../defense/core/ledger";
import type { LatencySummary } from "../policy/thresholds";
import { N2ServerObserver, type ExerciseSpec, type ServerN2Measurement } from "./n2-measurement";
import { SalvoRequestRecorder, type ServerSalvoDiagnostics } from "./salvo-diagnostics";
import { SALVO_SPEC, type SalvoPair } from "./salvo-spec";

export type GeneratorSalvoMeasurement = {
  elapsedMs: number; firstDispatchMs: number | null; lastDispatchMs: number | null; lastSettlementMs: number | null;
  stopLatchedMs: number | null; pairs: SalvoPair[]; fixtureLatencyMs: Record<string, LatencySummary>;
};
export type ServerSalvoMeasurement = { phase: ServerN2Measurement; pairs: SalvoPair[] };

/** Observes existing source events only. At most two nonce associations and 750 pair records; no new defense events. */
export class SalvoServerObserver extends N2ServerObserver {
  private readonly pairs: SalvoPair[] = [];
  private readonly pending = new Map<string, { pair: SalvoPair; slot: 0 | 1 }>();
  private origin: number | null = null;
  private ordinal = 0;
  private pairFaults = 0;
  /** Sibling per-request diagnostics. Observation only: it shares this event stream, never feeds a pair record or a verdict, and never throws. */
  private readonly requests = new SalvoRequestRecorder();
  constructor(spec: ExerciseSpec) { super(spec); }
  override observe(event: PlaneEvent): void {
    this.requests.observe(event);
    super.observe(event);
    if (event.kind === "INGRESS_ACCEPTED" && event.ingress === "external" && event.nonce !== null) {
      if (this.origin === null) this.origin = event.t;
      const index = Math.floor(this.ordinal / 2); const slot = (this.ordinal++ % 2) as 0 | 1;
      if (index >= SALVO_SPEC.pairs || this.pending.size >= 2 || this.pending.has(event.nonce)) { this.pairFaults++; return; }
      if (slot === 0) {
        if (this.pending.size !== 0) this.pairFaults++;
        this.pairs.push({ index, startsMs: [null, null], settledMs: [null, null] });
      }
      const pair = this.pairs[index];
      if (!pair) { this.pairFaults++; return; }
      pair.startsMs[slot] = event.t - this.origin;
      this.pending.set(event.nonce, { pair, slot });
    } else if ((event.kind === "INGRESS_RESPONDED" || event.kind === "INGRESS_ABORTED") && event.nonce !== null) {
      const entry = this.pending.get(event.nonce);
      if (entry) {
        entry.pair.settledMs[entry.slot] = event.t - this.origin!;
        this.pending.delete(event.nonce);
      }
    }
  }
  snapshotDiagnostics(): ServerSalvoDiagnostics { return this.requests.snapshot(); }
  snapshotSalvo(): ServerSalvoMeasurement {
    const phase = super.snapshot();
    phase.faults += this.pairFaults + this.pending.size;
    return { phase, pairs: this.pairs.map((p) => ({ index: p.index, startsMs: [...p.startsMs], settledMs: [...p.settledMs] })) };
  }
}
