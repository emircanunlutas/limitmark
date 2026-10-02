/** Thin, shell-free Docker CLI wrapper. Only the lab tooling calls this. */
import { execFile } from "node:child_process";
import { assertLabContainer } from "../policy/target-policy";

export type DockerResult = { stdout: string; stderr: string };

export function docker(args: readonly string[], options: { env?: Record<string, string>; timeoutMs?: number; input?: string } = {}): Promise<DockerResult> {
  return new Promise((resolve, reject) => {
    const child = execFile("docker", [...args], {
      env: { ...process.env, ...options.env },
      timeout: options.timeoutMs ?? 120_000,
      maxBuffer: 16 * 1024 * 1024,
      windowsHide: true,
    }, (error, stdout, stderr) => {
      if (error) {
        // stderr from docker never contains our secrets (they travel via environment variables).
        reject(new Error(`docker ${args[0]} ${args[1] ?? ""} failed: ${(stderr || error.message).trim().split("\n").slice(-3).join(" | ")}`));
      } else resolve({ stdout, stderr });
    });
    if (options.input !== undefined) child.stdin?.end(options.input);
  });
}

export async function containerExists(name: string): Promise<boolean> {
  const { stdout } = await docker(["ps", "-a", "--filter", `name=^${name}$`, "--format", "{{.Names}}"]);
  return stdout.split("\n").map((line) => line.trim()).includes(name);
}

export async function containerLabels(name: string): Promise<Record<string, string>> {
  const { stdout } = await docker(["inspect", "--format", "{{json .Config.Labels}}", name]);
  return JSON.parse(stdout.trim() || "{}") as Record<string, string>;
}

/** Stop/start/kill only containers the lab created (name prefix + disposable label). */
export async function controlLabContainer(action: "stop" | "start" | "kill" | "pause" | "unpause", name: string): Promise<void> {
  assertLabContainer(name, await containerLabels(name));
  await docker([action, name], { timeoutMs: 60_000 });
}
