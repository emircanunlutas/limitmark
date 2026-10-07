/** N=2 observation only. All intervals use the emitting process's monotonic clock, never IPC arrival times. */
import type { PlaneEvent } from "../../defense/core/ledger";
import type { MeasurementBarrier } from "../../defense/plane/l2-protocol";
import type { Ba0FieldThresholds } from "./field-thresholds";

export type ExerciseSpec = { durationMs: number; binMs: number; bins: number; startsPerBin: number; overlapMsPerBin: number };
export function n2ExerciseSpec(t: Ba0FieldThresholds): ExerciseSpec {
  const durationMs = t.level.durationSeconds * 1000;
  const binMs = t.telemetry.tickMs;
  // One fixed fixture cycle of renewals and one cycle of pacing-slot residency per telemetry interval.
  return { durationMs, binMs, bins: Math.ceil(durationMs / binMs), startsPerBin: t.level.fixtureCycle.length,
    overlapMsPerBin: t.level.fixtureCycle.length * 1000 / t.level.maxRequestsPerSecond };
}
export type OverlapExposure = { binMs: number; overlapMs: number[]; overlappingStarts: number[] };
export type GeneratorN2Measurement = {
  elapsedMs: number; firstDispatchMs: number | null; lastDispatchMs: number | null; lastSettlementMs: number | null;
  exposure: OverlapExposure;
};
export type ServerN2Measurement = {
  armed: MeasurementBarrier | null; closed: MeasurementBarrier | null;
  beforeArmed: number; inWindow: number; afterClosed: number; settledInWindow: number; inFlightAtClose: number;
  firstIngressMs: number | null; lastIngressMs: number | null; lastSettlementMs: number | null;
  faults: number; exposure: OverlapExposure;
};

/** Two arrays of exactly ceil(duration/tick) numbers; no request history. */
export class OverlapMeter {
  private readonly residence: number[];
  private readonly starts: number[];
  private last = 0;
  private active = 0;
  constructor(readonly spec: ExerciseSpec) {
    this.residence = Array(spec.bins).fill(0);
    this.starts = Array(spec.bins).fill(0);
  }
  change(at: number, active: number, isStart = false): void {
    const end = Math.min(at, this.spec.durationMs);
    if (this.active === 2) {
      let from = Math.max(0, this.last);
      while (from < end) {
        const bin = Math.floor(from / this.spec.binMs);
        const to = Math.min(end, (bin + 1) * this.spec.binMs);
        this.residence[bin] += to - from;
        from = to;
      }
    }
    if (isStart && active === 2 && at >= 0 && at < this.spec.durationMs) this.starts[Math.floor(at / this.spec.binMs)]++;
    this.last = at;
    this.active = active;
  }
  snapshot(): OverlapExposure {
    // Round DOWN: serialization must never turn insufficient residency into a pass.
    return { binMs: this.spec.binMs, overlapMs: this.residence.map((ms) => Math.floor(ms * 1000) / 1000), overlappingStarts: [...this.starts] };
  }
}

export function exercised(value: OverlapExposure | undefined, spec: ExerciseSpec, attempted: number): boolean {
  return value != null && value.binMs === spec.binMs && Array.isArray(value.overlapMs) && Array.isArray(value.overlappingStarts)
    && value.overlapMs.length === spec.bins && value.overlappingStarts.length === spec.bins
    && value.overlapMs.every((ms, i) => Number.isFinite(ms) && ms >= spec.overlapMsPerBin && ms <= Math.min(spec.binMs, spec.durationMs - i * spec.binMs))
    && value.overlappingStarts.every((n) => Number.isSafeInteger(n) && n >= spec.startsPerBin)
    && value.overlappingStarts.reduce((a, b) => a + b, 0) <= attempted;
}

/** Reconstructs exact external occupancy from the existing, gap-checked plane event stream. At most two nonces are retained. */
export class N2ServerObserver {
  private armed: MeasurementBarrier | null = null;
  private closed: MeasurementBarrier | null = null;
  private readonly active = new Set<string>();
  private first: number | null = null;
  private last: number | null = null;
  private settled: number | null = null;
  private before = 0;
  private within = 0;
  private after = 0;
  private terminals = 0;
  private faults = 0;
  private atClose = 0;
  private lastEventAt = 0;
  private readonly meter: OverlapMeter;
  constructor(spec: ExerciseSpec) { this.meter = new OverlapMeter(spec); }
  arm(mark: MeasurementBarrier): void { this.armed = mark; }
  close(mark: MeasurementBarrier): void { this.closed = mark; this.atClose = mark.inFlightExternal; }
  get earlyIngress(): number { return this.before + (this.armed?.acceptedExternal ?? 0); }
  observe(event: PlaneEvent): void {
    if (event.kind === "INGRESS_ACCEPTED" && event.ingress === "external" && event.nonce !== null) {
      if (!Number.isFinite(event.t) || event.t < this.lastEventAt) { this.faults++; return; }
      this.lastEventAt = event.t;
      if (this.armed === null || event.seq <= this.armed.seq || event.t < this.armed.atMs) this.before++;
      else if (this.closed !== null && (event.seq > this.closed.seq || event.t > this.closed.atMs)) this.after++;
      else this.within++;
      if (this.first === null) this.first = event.t;
      this.last = event.t;
      if (this.active.size >= 2 || this.active.has(event.nonce)) { this.faults++; return; }
      this.active.add(event.nonce);
      this.meter.change(event.t - this.first, this.active.size, true);
    } else if ((event.kind === "INGRESS_RESPONDED" || event.kind === "INGRESS_ABORTED") && event.nonce !== null && this.active.has(event.nonce)) {
      if (!Number.isFinite(event.t) || event.t < this.lastEventAt) { this.faults++; return; }
      this.lastEventAt = event.t;
      this.active.delete(event.nonce);
      this.meter.change(event.t - this.first!, this.active.size);
      this.settled = event.t;
      if (this.armed !== null && event.seq > this.armed.seq && (this.closed === null || event.seq <= this.closed.seq)) this.terminals++;
    }
  }
  snapshot(): ServerN2Measurement {
    return { armed: this.armed, closed: this.closed, beforeArmed: this.before, inWindow: this.within, afterClosed: this.after,
      settledInWindow: this.terminals, inFlightAtClose: this.atClose, firstIngressMs: this.first, lastIngressMs: this.last,
      lastSettlementMs: this.settled, faults: this.faults + this.active.size, exposure: this.meter.snapshot() };
  }
}
