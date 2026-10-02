/**
 * Lifecycle for the lab-managed local application process (`next start` of the existing build).
 *
 *  - Spawns only the repository's own production server, on a loopback port that is a
 *    built-in lab-local fixture, with a SCRUBBED environment (no inherited secrets) and the
 *    non-persistent demo adapter.
 *  - Refuses to start if anything already listens on the port, and only ever kills the
 *    process tree it started itself.
 */
import { execFile, spawn, type ChildProcess } from "node:child_process";
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
    child.on("exit", () => { if (this.child === child) this.child = null; });
    this.child = child;
  }

  /** Abrupt termination of the whole tree this object started. */
  async kill(): Promise<void> {
    const child = this.child;
    if (!child?.pid) return;
    this.child = null;
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
      if (await portIsListening(this.port)) return Date.now() - started;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error("application did not start listening in time");
  }
}
