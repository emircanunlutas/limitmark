/**
 * Harness-side handle on the Defense Plane child process. The plane is spawned with an IPC pipe; everything it emits goes straight
 * into the collector, which acknowledges each frame (flow control for the plane's bounded queue).
 *
 * The plane's process exit is observed here. An exit the harness did not ask for is a crash: it is recorded in the collector, and the
 * run is INVALID. Events the plane had already delivered are untouched; events it had not are lost and detected.
 */
import { fork, type ChildProcess } from "node:child_process";
import path from "node:path";
import { REPOSITORY_ROOT } from "../evidence/manifest";
import type { PlaneControl, PlaneInit, PlaneMessage } from "../../defense/plane/protocol";
import type { Collector, PlaneFin } from "./collector";

const PLANE_ENTRY = path.join(REPOSITORY_ROOT, "defense", "plane", "main.ts");

export type PlaneStartOptions = Omit<PlaneInit, "type">;

export class PlaneProcess {
  private exited = false;
  private stopping = false;
  private finWaiter: ((fin: PlaneFin | null) => void) | null = null;
  private readonly exitWaiters: (() => void)[] = [];

  private constructor(private readonly child: ChildProcess, private readonly collector: Collector, readonly port: number) {
    child.on("message", (raw) => this.onMessage(raw as PlaneMessage));
    child.on("exit", (code, signal) => {
      this.exited = true;
      if (!this.stopping) this.collector.planeExited(`plane exited unexpectedly: code ${code ?? "none"} signal ${signal ?? "none"}`);
      this.finWaiter?.(null);
      for (const wake of this.exitWaiters.splice(0)) wake();
    });
  }

  static async start(collector: Collector, options: PlaneStartOptions, timeoutMs = 20_000): Promise<PlaneProcess> {
    const child = fork(PLANE_ENTRY, [], { execArgv: process.execArgv, cwd: REPOSITORY_ROOT, stdio: ["ignore", "ignore", "ignore", "ipc"], serialization: "json" });
    return new Promise<PlaneProcess>((resolve, reject) => {
      let instance: PlaneProcess | null = null;
      const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("the defense plane did not become ready")); }, timeoutMs);
      const early = (raw: unknown) => {
        const message = raw as PlaneMessage;
        if (message.type === "ready") {
          clearTimeout(timer);
          child.off("message", early);
          instance = new PlaneProcess(child, collector, message.port);
          resolve(instance);
        }
      };
      child.on("message", early);
      child.once("exit", () => { if (instance === null) { clearTimeout(timer); reject(new Error("the defense plane exited before it was ready")); } });
      child.send({ type: "init", ...options } satisfies PlaneControl);
    });
  }

  private onMessage(message: PlaneMessage): void {
    if (message.type === "events") {
      const received = this.collector.ingestFrame(message);
      this.send({ type: "ack", received });
    } else if (message.type === "fin_result") {
      const fin: PlaneFin = { drained: message.drained, channel: message.channel, advisory: message.advisory };
      this.collector.planeFinished(fin);
      this.finWaiter?.(fin);
    }
  }

  private send(message: PlaneControl): void {
    if (!this.exited && this.child.connected) this.child.send(message, () => undefined);
  }

  get hasExited(): boolean { return this.exited; }

  /** Test/lab control: arms an L1 fault on the next `remaining` evaluations. Only reachable through this IPC pipe. */
  injectFault(kind: "throw" | "hang", remaining: number): void { this.send({ type: "fault", kind, remaining }); }

  /** Asks the plane to drain its channel and report its final state. Null when the plane is gone or does not answer in time. */
  async finish(timeoutMs: number): Promise<PlaneFin | null> {
    if (this.exited) return null;
    return new Promise<PlaneFin | null>((resolve) => {
      const timer = setTimeout(() => { this.finWaiter = null; resolve(null); }, timeoutMs);
      this.finWaiter = (fin) => { clearTimeout(timer); this.finWaiter = null; resolve(fin); };
      this.send({ type: "fin" });
    });
  }

  /** Simulates a crash: the process is killed without any chance to flush. */
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
