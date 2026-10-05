/**
 * Harness-side handles on the two Slice-2 child processes: the Origin Boundary and the Protected App. Each is spawned with an IPC pipe;
 * everything it emits goes straight into the collector, which acknowledges each frame (flow control for the child's bounded queue).
 *
 * Exactly like the Defense Plane handle (plane-process.ts, untouched): an exit the harness did not ask for is a crash and is recorded in
 * the collector, which makes the run INVALID; events already delivered survive, events not yet delivered are lost AND detected.
 * There is no restart and no fallback: a dead boundary stays dead.
 */
import { fork, type ChildProcess } from "node:child_process";
import path from "node:path";
import type { AppEvent, BoundaryEvent, EventFrame } from "../../defense/core/ledger";
import type { BoundaryInit, BoundaryMessage } from "../../defense/boundary/protocol";
import type { AppControl, AppFault, AppInit, AppMessage } from "../../defense/origin/app-protocol";
import { REPOSITORY_ROOT } from "../evidence/manifest";
import type { Collector } from "./collector";

const BOUNDARY_ENTRY = path.join(REPOSITORY_ROOT, "defense", "boundary", "main.ts");
const APP_ENTRY = path.join(REPOSITORY_ROOT, "defense", "origin", "app-main.ts");

type FinMessage = { type: "fin_result"; drained: boolean; channel: never; stats: never };

class Child<Frame extends EventFrame<BoundaryEvent> | EventFrame<AppEvent>, Fin> {
  private exited = false;
  private stopping = false;
  private finWaiter: ((fin: Fin | null) => void) | null = null;
  private readonly exitWaiters: (() => void)[] = [];

  protected constructor(
    private readonly child: ChildProcess,
    readonly port: number,
    /** Wall-clock instant just before the process was spawned: strictly earlier than the verifier's own start fence. */
    readonly spawnedAtMs: number,
    private readonly hooks: { frame: (frame: Frame) => number; fin: (fin: Fin) => void; exited: (detail: string) => void },
    private readonly name: string,
  ) {
    child.on("message", (raw) => this.onMessage(raw as { type: string }));
    child.on("exit", (code, signal) => {
      this.exited = true;
      if (!this.stopping) this.hooks.exited(`${this.name} exited unexpectedly: code ${code ?? "none"} signal ${signal ?? "none"}`);
      this.finWaiter?.(null);
      for (const wake of this.exitWaiters.splice(0)) wake();
    });
  }

  protected static spawn<Frame extends EventFrame<BoundaryEvent> | EventFrame<AppEvent>, Fin, Self>(
    entry: string, init: object, name: string, hooks: { frame: (frame: Frame) => number; fin: (fin: Fin) => void; exited: (detail: string) => void },
    make: (child: ChildProcess, port: number, spawnedAtMs: number) => Self, timeoutMs: number,
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
      const fin = message as unknown as Fin & FinMessage;
      this.hooks.fin(fin);
      this.finWaiter?.(fin);
    }
  }

  send(message: object): void { if (!this.exited && this.child.connected) this.child.send(message, () => undefined); }
  get hasExited(): boolean { return this.exited; }

  /** Asks the child to drain its channel and report. Null when it is gone or does not answer in time. */
  async finish(timeoutMs: number): Promise<Fin | null> {
    if (this.exited) return null;
    return new Promise<Fin | null>((resolve) => {
      const timer = setTimeout(() => { this.finWaiter = null; resolve(null); }, timeoutMs);
      this.finWaiter = (fin) => { clearTimeout(timer); this.finWaiter = null; resolve(fin); };
      this.send({ type: "fin" });
    });
  }

  /** Simulates a crash: killed without any chance to flush. */
  crash(): void { if (!this.exited) this.child.kill("SIGKILL"); }

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

export class BoundaryProcess extends Child<EventFrame<BoundaryEvent>, BoundaryFinMessage> {
  static start(collector: Collector, init: Omit<BoundaryInit, "type">, timeoutMs = 20_000): Promise<BoundaryProcess> {
    return Child.spawn<EventFrame<BoundaryEvent>, BoundaryFinMessage, BoundaryProcess>(
      BOUNDARY_ENTRY, { type: "init", ...init } satisfies BoundaryInit, "origin boundary",
      {
        frame: (frame) => collector.ingestBoundaryFrame(frame),
        fin: (fin) => collector.boundaryFinished({ drained: fin.drained, channel: fin.channel, stats: fin.stats }),
        exited: (detail) => collector.boundaryExited(detail),
      },
      (child, port, spawnedAtMs) => new BoundaryProcess(child, port, spawnedAtMs, collector), timeoutMs,
    );
  }
  private constructor(child: ChildProcess, port: number, spawnedAtMs: number, collector: Collector) {
    super(child, port, spawnedAtMs, {
      frame: (frame) => collector.ingestBoundaryFrame(frame),
      fin: (fin) => collector.boundaryFinished({ drained: fin.drained, channel: fin.channel, stats: fin.stats }),
      exited: (detail) => collector.boundaryExited(detail),
    }, "origin boundary");
  }
}

export class AppProcess extends Child<EventFrame<AppEvent>, AppFinMessage> {
  static start(collector: Collector, init: Omit<AppInit, "type">, timeoutMs = 20_000): Promise<AppProcess> {
    return Child.spawn<EventFrame<AppEvent>, AppFinMessage, AppProcess>(
      APP_ENTRY, { type: "init", ...init } satisfies AppInit, "protected app",
      {
        frame: (frame) => collector.ingestAppFrame(frame),
        fin: (fin) => collector.appFinished({ drained: fin.drained, channel: fin.channel, stats: fin.stats }),
        exited: (detail) => collector.appExited(detail),
      },
      (child, port, spawnedAtMs) => new AppProcess(child, port, spawnedAtMs, collector), timeoutMs,
    );
  }
  private constructor(child: ChildProcess, port: number, spawnedAtMs: number, collector: Collector) {
    super(child, port, spawnedAtMs, {
      frame: (frame) => collector.ingestAppFrame(frame),
      fin: (fin) => collector.appFinished({ drained: fin.drained, channel: fin.channel, stats: fin.stats }),
      exited: (detail) => collector.appExited(detail),
    }, "protected app");
  }
  /** Arms an origin failure (reset/hang/delay) for the failure tests. Only reachable over this IPC pipe. */
  injectFault(fault: AppFault): void { this.send({ type: "fault", fault } satisfies AppControl); }
}
