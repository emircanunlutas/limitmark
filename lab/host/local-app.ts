/**
 * Lifecycle for the lab-managed local application process (`next start` of the existing build).
 *
 *  - Spawns only the repository's own production server, on a loopback port that is a
 *    built-in lab-local fixture, with a SCRUBBED environment (no inherited secrets) and the
 *    non-persistent demo adapter.
 *  - Refuses to start if anything already listens on the port, and only ever kills the
 *    process tree it started itself.
 *  - Interruption cleanup: every started tree is tracked; SIGINT/SIGTERM/SIGHUP and a normal process exit kill all
 *    tracked trees synchronously. A detached (own process group) Linux child would otherwise outlive an interrupted run.
 */
import { execFile, execFileSync, spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { REPOSITORY_ROOT } from "../evidence/manifest";
import { BUILTIN_TARGETS } from "../policy/target-policy";

const LAB_PORTS = new Set(BUILTIN_TARGETS.filter((target) => target.class === "lab-local").map((target) => target.port));

export function portIsListening(port: number, timeoutMs = 400): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    const done = (value: boolean) => { socket.destroy(); resolve(value); };
    socket.setTimeout(timeoutMs, () => done(false));
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
  });
}

export function scrubbedAppEnvironment(port: number): Record<string, string> {
  const environment: Record<string, string> = {
    NODE_ENV: "production",
    NEXT_TELEMETRY_DISABLED: "1",
    REQUEST_SUBMISSION_MODE: "demo",
    ALLOW_DEMO_SUBMISSIONS: "true",
    PUBLIC_DEMO_ORIGIN: `http://127.0.0.1:${port}`,
    PUBLIC_ORIGIN_PROTECTION: "disabled",
    ENABLE_PERSISTENT_SUBMISSIONS: "false",
    ENABLE_REAL_NOTIFICATIONS: "false",
  };
  // Only what a Node process needs to start; never DATABASE_URL, CRON_SECRET, provider keys, ...
  for (const key of ["PATH", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "HOME", "USERPROFILE"]) {
    if (process.env[key]) environment[key] = process.env[key] as string;
  }
  return environment;
}

// ---------------------------------------------------------------------------
// Interruption cleanup
// ---------------------------------------------------------------------------

const trackedPids = new Set<number>();
let handlersInstalled = false;

/** Synchronously kills one process tree: the whole group on POSIX (the child is its own group leader), taskkill /T on Windows. */
export function killTreeSync(pid: number, kill: (pid: number, signal: NodeJS.Signals) => void = process.kill, platform: string = process.platform): void {
  try {
    if (platform === "win32") execFileSync("taskkill", ["/pid", String(pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
    else kill(-pid, "SIGKILL");
  } catch { /* already gone */ }
}

export function trackChildTree(pid: number): void {
  trackedPids.add(pid);
  installCleanupHandlers();
}

export function untrackChildTree(pid: number): void { trackedPids.delete(pid); }

export function trackedChildTrees(): number[] { return [...trackedPids]; }

/** Kills every tracked tree; used by the exit/signal handlers and by tests. */
export function killTrackedTreesSync(kill?: (pid: number, signal: NodeJS.Signals) => void, platform?: string): void {
  for (const pid of [...trackedPids]) { killTreeSync(pid, kill, platform); trackedPids.delete(pid); }
}

function installCleanupHandlers(): void {
  if (handlersInstalled) return;
  handlersInstalled = true;
  process.on("exit", () => killTrackedTreesSync());
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
    process.on(signal, () => {
      killTrackedTreesSync();
      // A listener suppresses Node's default termination. If nobody else handles the signal, finish the job.
      if (process.listenerCount(signal) <= 1) process.exit(128 + ({ SIGHUP: 1, SIGINT: 2, SIGTERM: 15 }[signal]));
    });
  }
}

export class LocalApp {
  private child: ChildProcess | null = null;

  constructor(readonly port: number) {
    if (!LAB_PORTS.has(port)) throw new Error(`port ${port} is not a built-in lab-local fixture`);
  }

  get running(): boolean { return this.child !== null && this.child.exitCode === null && !this.child.killed; }

  async start(): Promise<void> {
    if (!existsSync(path.join(REPOSITORY_ROOT, ".next", "BUILD_ID"))) throw new Error("no production build found; run `npm run build` first");
    if (await portIsListening(this.port)) throw new Error(`something already listens on 127.0.0.1:${this.port}; the lab will not touch it`);
    const child = spawn(process.execPath, [
      path.join(REPOSITORY_ROOT, "node_modules", "next", "dist", "bin", "next"), "start", "--hostname", "127.0.0.1", "--port", String(this.port),
    ], {
      cwd: REPOSITORY_ROOT, env: scrubbedAppEnvironment(this.port) as NodeJS.ProcessEnv, stdio: ["ignore", "ignore", "ignore"],
      detached: process.platform !== "win32", windowsHide: true,
    });
    child.on("exit", () => { if (this.child === child) this.child = null; if (child.pid) untrackChildTree(child.pid); });
    this.child = child;
    // Tracked from the moment it exists: an interruption between here and kill() still removes the whole tree.
    if (child.pid) trackChildTree(child.pid);
  }

  /** Abrupt termination of the whole tree this object started. */
  async kill(): Promise<void> {
    const child = this.child;
    if (!child?.pid) return;
    this.child = null;
    untrackChildTree(child.pid);
    if (process.platform === "win32") {
      await new Promise<void>((resolve) => execFile("taskkill", ["/pid", String(child.pid), "/T", "/F"], { windowsHide: true }, () => resolve()));
    } else {
      try { process.kill(-child.pid, "SIGKILL"); } catch { /* already gone */ }
    }
    for (let i = 0; i < 50 && await portIsListening(this.port); i++) await new Promise((r) => setTimeout(r, 100));
  }

  async waitUntilListening(timeoutMs = 60_000): Promise<number> {
    const started = Date.now();
    while (Date.now() - started < timeoutMs) {
      // A listener only counts if it is OUR process: if the child already exited, whatever answers is something else.
      if (!this.running) throw new Error("the lab-started application exited before it was listening");
      if (await portIsListening(this.port)) {
        if (!this.running) throw new Error("the lab-started application exited before it was listening");
        return Date.now() - started;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error("application did not start listening in time");
  }
}
