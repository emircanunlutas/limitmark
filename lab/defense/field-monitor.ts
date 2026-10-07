/**
 * Field qualification: the per-tick MONITOR. Pure state over the ticks it is shown and an injected clock; it decides nothing about a request.
 * It turns the 1-second telemetry into the reasons a level must STOP or be invalidated, and keeps a bounded ring of recent ticks so a STOP
 * can dump the evidence that led to it.
 *
 *   - tick gaps: a missing sequence number, or silence longer than the tolerance, while the pressure window is open (a measurement failure);
 *     a missing FINAL tick at finalization is the same failure
 *   - resource ceilings: host CPU and memory, per-process resident memory and file descriptors, and the Plane's event-loop delay, each for the
 *     number of consecutive ticks the parameter set pins
 *   - the harness's own event-loop delay, counted so canary starvation can be told apart from a slow server
 *
 * Memory is bounded: the ring holds `ringTicks` ticks per role and nothing else grows with the run.
 */
import type { PlaneTick } from "../../defense/plane/l2-protocol";
import type { Tick, TickRole } from "../../defense/core/telemetry";
import type { Reason } from "./field-verdict";
import type { Ba0FieldThresholds } from "./field-thresholds";
import type { HostSample, PidSample, ProcSnapshot } from "./proc-sampler";

const ROLES: readonly TickRole[] = ["plane", "boundary", "app"];

export type HarnessSample = { eldP99Ms: number; eldMaxMs: number; proc: ProcSnapshot };

export class TickMonitor {
  private readonly last = new Map<TickRole, { seq: number; atMs: number }>();
  private readonly ringState = new Map<TickRole, Tick<unknown>[]>();
  private readonly finals = new Set<TickRole>();
  private windowActive = false;
  private gapCount = 0;
  private hostCpuHigh = 0;
  private planeEldHigh = 0;
  private harnessEldHighTicks = 0;
  private harnessEldMax = 0;
  private harnessTicks = 0;
  private sequenceGapDetails: string[] = [];

  constructor(private readonly thresholds: Ba0FieldThresholds, private readonly now: () => number) {}

  setWindowActive(active: boolean): void { this.windowActive = active; }
  get tickGaps(): number { return this.gapCount; }
  finalTicks(): Record<TickRole, boolean> { return { plane: this.finals.has("plane"), boundary: this.finals.has("boundary"), app: this.finals.has("app") }; }
  harnessEld(): { highTicks: number; max: number; ticks: number } { return { highTicks: this.harnessEldHighTicks, max: this.harnessEldMax, ticks: this.harnessTicks }; }
  ring(): Record<TickRole, readonly Tick<unknown>[]> { return { plane: this.ringState.get("plane") ?? [], boundary: this.ringState.get("boundary") ?? [], app: this.ringState.get("app") ?? [] }; }
  gapDetails(): readonly string[] { return this.sequenceGapDetails; }

  /** A tick arrived from a child process. Returns the reasons it raises. */
  observe(tick: Tick<unknown>): Reason[] {
    const reasons: Reason[] = [];
    const previous = this.last.get(tick.role);
    if (previous !== undefined && tick.tickSeq !== previous.seq + 1) {
      this.gapCount++;
      if (this.sequenceGapDetails.length < 16) this.sequenceGapDetails.push(`${tick.role} ${previous.seq}>${tick.tickSeq}`);
      if (this.windowActive) reasons.push({ code: "tick_gap", detail: `${tick.role} sequence ${previous.seq} to ${tick.tickSeq}` });
    }
    this.last.set(tick.role, { seq: tick.tickSeq, atMs: this.now() });
    if (tick.final) this.finals.add(tick.role);
    const ring = this.ringState.get(tick.role) ?? [];
    ring.push(tick);
    while (ring.length > this.thresholds.telemetry.ringTicks) ring.shift();
    this.ringState.set(tick.role, ring);

    const ceilings = this.thresholds.ceilings;
    if (tick.sample.rssMb >= ceilings.rssMb) reasons.push({ code: "resource_ceiling", detail: `${tick.role} resident memory ${tick.sample.rssMb} MiB` });
    if (tick.role === "plane" && !tick.final) {
      this.planeEldHigh = tick.sample.eldP99Ms >= ceilings.planeEldP99Ms ? this.planeEldHigh + 1 : 0;
      if (this.planeEldHigh >= ceilings.planeEldTicks) reasons.push({ code: "resource_ceiling", detail: `plane event-loop delay p99 ${tick.sample.eldP99Ms} ms for ${this.planeEldHigh} ticks` });
      const plane = tick as PlaneTick;
      if (plane.data.channel.dropped > 0) reasons.push({ code: "evidence_gap", detail: `plane dropped ${plane.data.channel.dropped} events` });
    }
    return reasons;
  }

  /** The harness's own 1-second sample (per-process /proc, host, harness event-loop delay). */
  observeHarness(sample: HarnessSample): Reason[] {
    const reasons: Reason[] = [];
    const ceilings = this.thresholds.ceilings;
    this.harnessTicks++;
    this.harnessEldMax = Math.max(this.harnessEldMax, sample.eldMaxMs);
    if (sample.eldP99Ms > this.thresholds.canary.harnessEldP99Ms) this.harnessEldHighTicks++;
    const host: HostSample | null = sample.proc.host;
    if (host !== null) {
      this.hostCpuHigh = host.cpuBusyPct >= ceilings.hostCpuBusyPct ? this.hostCpuHigh + 1 : 0;
      if (this.hostCpuHigh >= ceilings.hostCpuTicks) reasons.push({ code: "resource_ceiling", detail: `host cpu ${host.cpuBusyPct} pct for ${this.hostCpuHigh} ticks` });
      if (host.memAvailablePct < ceilings.memAvailablePct) reasons.push({ code: "resource_ceiling", detail: `host memory available ${host.memAvailablePct} pct` });
    }
    for (const [role, pid] of Object.entries(sample.proc.perRole)) {
      const entry: PidSample = pid;
      if (!entry.alive) continue;
      if (entry.rssMb >= ceilings.rssMb) reasons.push({ code: "resource_ceiling", detail: `${role} resident memory ${entry.rssMb} MiB` });
      if (entry.fdLimit !== null && entry.fdLimit > 0 && (100 * entry.fds) / entry.fdLimit >= ceilings.fdPct) reasons.push({ code: "resource_ceiling", detail: `${role} file descriptors ${entry.fds} of ${entry.fdLimit}` });
    }
    return reasons;
  }

  /** Silence from a child while the window is open is a gap, even when no sequence number was skipped. */
  checkSilence(): Reason[] {
    if (!this.windowActive) return [];
    const reasons: Reason[] = [];
    const now = this.now();
    for (const role of ROLES) {
      const seen = this.last.get(role);
      if (seen !== undefined && now - seen.atMs > this.thresholds.telemetry.gapToleranceMs) {
        this.gapCount++;
        reasons.push({ code: "tick_gap", detail: `${role} silent for ${Math.round(now - seen.atMs)} ms` });
        // Re-arm so one long silence is reported once, not on every check.
        this.last.set(role, { seq: seen.seq, atMs: now });
      }
    }
    return reasons;
  }

  /** At finalization: every role must have delivered its final tick. */
  finalReasons(): Reason[] {
    const missing = ROLES.filter((role) => !this.finals.has(role));
    return missing.length > 0 ? [{ code: "telemetry_incomplete", detail: `no final tick from ${missing.join(",")}` }] : [];
  }
}
