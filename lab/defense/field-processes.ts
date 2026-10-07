/**
 * Field qualification: harness-side handles on the FIELD Origin Boundary and Protected App children. They mirror `origin-processes.ts`
 * (byte-pinned and untouched) with three differences: the entries are the field entries (`main-field.ts`, `app-main-field.ts`: the same
 * processes plus one observation-only tick per interval, and no lab fault control), the handle exposes the child's PID (the exposure proof and
 * the /proc sampler need it) and ticks are forwarded to a hook.
 *
 * Exactly like the Slice-2 handles: an exit the harness did not ask for is a crash, recorded in the collector (the run is INVALID by the
 * accounting); events already delivered survive and events not yet delivered are lost AND detected. There is no restart and no fallback.
 * Stopping is graceful first (`stop`, then a bounded wait); a kill is only the bounded last resort.
 */
import { fork, type ChildProcess } from "node:child_process";
import path from "node:path";
import type { AppEvent, BoundaryEvent, EventFrame } from "../../defense/core/ledger";
import type { BoundaryFieldInit, BoundaryTick } from "../../defense/boundary/field-protocol";
import type { AppFieldInit, AppTick } from "../../defense/origin/app-field-protocol";
import type { BoundaryInit, BoundaryMessage } from "../../defense/boundary/protocol";
import type { AppInit, AppMessage } from "../../defense/origin/app-protocol";
import { REPOSITORY_ROOT } from "../evidence/manifest";
import type { Collector } from "./collector";

const BOUNDARY_FIELD_ENTRY = path.join(REPOSITORY_ROOT, "defense", "boundary", "main-field.ts");
const APP_FIELD_ENTRY = path.join(REPOSITORY_ROOT, "defense", "origin", "app-main-field.ts");

type Hooks<Frame, Fin, Tick> = { frame: (frame: Frame) => number; fin: (fin: Fin) => void; exited: (detail: string) => void; tick: (tick: Tick) => void };

class FieldChild<Frame extends EventFrame<BoundaryEvent> | EventFrame<AppEvent>, Fin, Tick> {
  private exited = false;
  private stopping = false;
  private finWaiter: ((fin: Fin | null) => void) | null = null;
  private readonly exitWaiters: (() => void)[] = [];

  constructor(private readonly child: ChildProcess, readonly port: number, readonly spawnedAtMs: number, private readonly hooks: Hooks<Frame, Fin, Tick>, private readonly name: string) {
    child.on("message", (raw) => this.onMessage(raw as { type: string }));
    child.on("exit", (code, signal) => {
      this.exited = true;
      if (!this.stopping) this.hooks.exited(`${this.name} exited unexpectedly: code ${code ?? "none"} signal ${signal ?? "none"}`);
      this.finWaiter?.(null);
      for (const wake of this.exitWaiters.splice(0)) wake();
    });
  }

  static spawn<Frame extends EventFrame<BoundaryEvent> | EventFrame<AppEvent>, Fin, Tick, Self>(
    entry: string, init: object, name: string, hooks: Hooks<Frame, Fin, Tick>, make: (child: ChildProcess, port: number, spawnedAtMs: number) => Self, timeoutMs: number,
  ): Promise<Self> {
    const spawnedAtMs = Date.now();
    const child = fork(entry, [], { execArgv: process.execArgv, cwd: REPOSITORY_ROOT, stdio: ["ignore", "ignore", "ignore", "ipc"], serialization: "json" });
    return new Promise<Self>((resolve, reject) => {
      let instance: Self | null = null;
      const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error(`the ${name} did not become ready`)); }, timeoutMs);
      const early = (raw: unknown) => {
        const message = raw as { type: string; port?: number };
        if (message.type === "ready" && typeof message.port === "number") {
          clearTimeout(timer);
          child.off("message", early);
          instance = make(child, message.port, spawnedAtMs);
          resolve(instance);
        }
      };
      child.on("message", early);
      child.once("exit", () => { if (instance === null) { clearTimeout(timer); reject(new Error(`the ${name} exited before it was ready`)); } });
      child.send(init);
    });
  }

  private onMessage(message: { type: string }): void {
    if (message.type === "events") {
      const received = this.hooks.frame(message as unknown as Frame);
      this.send({ type: "ack", received });
    } else if (message.type === "fin_result") {
      const fin = message as unknown as Fin;
      this.hooks.fin(fin);
      this.finWaiter?.(fin);
    } else if (message.type === "tick") this.hooks.tick(message as unknown as Tick);
  }

  get pid(): number | undefined { return this.child.pid; }
  send(message: object): void { if (!this.exited && this.child.connected) this.child.send(message, () => undefined); }
  get hasExited(): boolean { return this.exited; }

  async finish(timeoutMs: number): Promise<Fin | null> {
    if (this.exited) return null;
    return new Promise<Fin | null>((resolve) => {
      const timer = setTimeout(() => { this.finWaiter = null; resolve(null); }, timeoutMs);
      this.finWaiter = (fin) => { clearTimeout(timer); this.finWaiter = null; resolve(fin); };
      this.send({ type: "fin" });
    });
  }

  /** Graceful stop; a kill is the bounded last fallback only. */
  async stop(timeoutMs = 5_000): Promise<void> {
    this.stopping = true;
    if (this.exited) return;
    this.send({ type: "stop" });
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => { this.child.kill("SIGKILL"); }, timeoutMs);
      this.exitWaiters.push(() => { clearTimeout(timer); resolve(); });
      if (this.exited) { clearTimeout(timer); resolve(); }
    });
  }
}

type BoundaryFinMessage = Extract<BoundaryMessage, { type: "fin_result" }>;
type AppFinMessage = Extract<AppMessage, { type: "fin_result" }>;

export class FieldBoundaryProcess extends FieldChild<EventFrame<BoundaryEvent>, BoundaryFinMessage, BoundaryTick> {
  static start(collector: Collector, init: Omit<BoundaryInit, "type"> & { telemetry: { tickMs: number } }, onTick: (tick: BoundaryTick) => void, timeoutMs = 20_000): Promise<FieldBoundaryProcess> {
    const hooks: Hooks<EventFrame<BoundaryEvent>, BoundaryFinMessage, BoundaryTick> = {
      frame: (frame) => collector.ingestBoundaryFrame(frame),
      fin: (fin) => collector.boundaryFinished({ drained: fin.drained, channel: fin.channel, stats: fin.stats }),
      exited: (detail) => collector.boundaryExited(detail),
      tick: onTick,
    };
    return FieldChild.spawn<EventFrame<BoundaryEvent>, BoundaryFinMessage, BoundaryTick, FieldBoundaryProcess>(
      BOUNDARY_FIELD_ENTRY, { type: "init", ...init } satisfies BoundaryFieldInit, "origin boundary", hooks,
      (child, port, spawnedAtMs) => new FieldBoundaryProcess(child, port, spawnedAtMs, hooks, "origin boundary"), timeoutMs,
    );
  }
}

export class FieldAppProcess extends FieldChild<EventFrame<AppEvent>, AppFinMessage, AppTick> {
  static start(collector: Collector, init: Omit<AppInit, "type"> & { telemetry: { tickMs: number } }, onTick: (tick: AppTick) => void, timeoutMs = 20_000): Promise<FieldAppProcess> {
    const hooks: Hooks<EventFrame<AppEvent>, AppFinMessage, AppTick> = {
      frame: (frame) => collector.ingestAppFrame(frame),
      fin: (fin) => collector.appFinished({ drained: fin.drained, channel: fin.channel, stats: fin.stats }),
      exited: (detail) => collector.appExited(detail),
      tick: onTick,
    };
    return FieldChild.spawn<EventFrame<AppEvent>, AppFinMessage, AppTick, FieldAppProcess>(
      APP_FIELD_ENTRY, { type: "init", ...init } satisfies AppFieldInit, "protected app", hooks,
      (child, port, spawnedAtMs) => new FieldAppProcess(child, port, spawnedAtMs, hooks, "protected app"), timeoutMs,
    );
  }
}
