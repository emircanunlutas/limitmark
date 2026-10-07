/**
 * Field qualification: the 1-second telemetry TICK shape and the per-process sampler. Types and one small sampler; no I/O of its own.
 *
 * Telemetry is OBSERVATION ONLY. Nothing here is read by any layer, lane, gate or composer, and a tick that fails to build, send or arrive
 * changes no verdict: it makes the MEASUREMENT invalid (a tick gap), never an admission. A tick is a small bounded record (a handful of
 * counters and gauges), sent as its own IPC message outside the bounded event channel, so a telemetry problem can neither block nor
 * be blocked by the lifecycle events.
 */

const LAG_RESOLUTION_MS = 10;
/** At most this many lag samples are kept per interval (a ring); the maximum is tracked exactly, outside the ring. */
const LAG_RING = 1_024;

/**
 * Event-loop lag, measured by the plainest method: a timer that asks to fire every `resolutionMs` and records how much LATER than that it did
 * fire. A stalled loop fires it late once, by the length of the stall. (Node's own `monitorEventLoopDelay` histogram under-reports a long
 * stall in practice, which is why this does not use it.) Memory is bounded: a ring of samples and one exact maximum.
 */
export class LagMonitor {
  private readonly ring: number[] = [];
  private cursor = 0;
  private max = 0;
  private last = performance.now();
  private readonly timer: NodeJS.Timeout;

  constructor(private readonly resolutionMs = LAG_RESOLUTION_MS) {
    this.timer = setInterval(() => {
      const now = performance.now();
      const lag = Math.max(0, now - this.last - this.resolutionMs);
      this.last = now;
      if (lag > this.max) this.max = lag;
      if (this.ring.length < LAG_RING) this.ring.push(lag); else { this.ring[this.cursor] = lag; this.cursor = (this.cursor + 1) % LAG_RING; }
    }, resolutionMs);
    this.timer.unref();
  }

  /** The interval just ended: p50, p99 and the exact max in ms, then reset. */
  take(): { p50: number; p99: number; max: number } {
    const sorted = [...this.ring].sort((a, b) => a - b);
    const at = (p: number): number => (sorted.length === 0 ? 0 : sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))]);
    const out = { p50: at(50), p99: at(99), max: this.max };
    this.ring.length = 0;
    this.cursor = 0;
    this.max = 0;
    return out;
  }

  stop(): void { clearInterval(this.timer); }
}

export type ProcessSample = {
  /** Event-loop lag over the interval just ended, in ms (never negative). */
  eldP50Ms: number;
  eldP99Ms: number;
  eldMaxMs: number;
  rssMb: number;
  /** CPU consumed during the interval, in ms. */
  cpuUserMs: number;
  cpuSystemMs: number;
};

const round2 = (value: number): number => Math.round(value * 100) / 100;

export class ProcessSampler {
  private readonly lag = new LagMonitor();
  private lastCpu = process.cpuUsage();

  /** Reads and resets the interval. */
  sample(): ProcessSample {
    const cpu = process.cpuUsage(this.lastCpu);
    this.lastCpu = process.cpuUsage();
    const lag = this.lag.take();
    return {
      eldP50Ms: round2(lag.p50), eldP99Ms: round2(lag.p99), eldMaxMs: round2(lag.max),
      rssMb: Math.round(process.memoryUsage.rss() / 1_048_576), cpuUserMs: Math.round(cpu.user / 1000), cpuSystemMs: Math.round(cpu.system / 1000),
    };
  }

  stop(): void { this.lag.stop(); }
}

export type TickRole = "plane" | "boundary" | "app";

/** One tick. `tickSeq` is gapless per process, so a missing tick is detectable; `final` marks the last tick of a drained process. */
export type Tick<Data> = {
  type: "tick";
  role: TickRole;
  tickSeq: number;
  /** The sender's own monotonic clock (ms). Never compared with another process's clock. */
  tMonoMs: number;
  final: boolean;
  sample: ProcessSample;
  data: Data;
};

/** Builds ticks with a gapless sequence. */
export class TickSource<Data> {
  private seq = 0;
  constructor(private readonly role: TickRole, private readonly sampler: ProcessSampler, private readonly collect: () => Data) {}

  next(final = false): Tick<Data> {
    return { type: "tick", role: this.role, tickSeq: ++this.seq, tMonoMs: round2(performance.now()), final, sample: this.sampler.sample(), data: this.collect() };
  }
}
