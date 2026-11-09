/**
 * Orchestrates the disposable LOOPBACK-ONLY observation arrangement:
 *
 *   canary (process) --> server-under-test stand-in (process) --> origin receipt collector (process) --> origin fixture (process)
 *
 * Four separate local processes. The observer's evidence (canary results, origin receipts, process metadata) is written to `observerDirectory`, which MUST be outside any SUT
 * evidence directory. Separate local processes are NOT independent organizational custody: the same operator starts all four, on one host, with one set of permissions.
 */
import { fork, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { REPOSITORY_ROOT } from "../../evidence/manifest";

export type FrontFaults = { drop?: string[]; fake?: string[]; duplicate?: string[]; rateLimit?: string[]; challenge?: string[]; slowMs?: Record<string, number> };
export type ObservationOptions = {
  observerDirectory: string;
  runId: string;
  campaignId: string;
  plan?: { baseline: number; window: number; recovery: number };
  timeoutMs?: number;
  faults?: FrontFaults;
};
export type ObservationFiles = { canaryFile: string; receiptsFile: string; metaFile: string };

const ENTRY = (name: string): string => path.join(REPOSITORY_ROOT, "lab", "m1", "observation", name);

function start(entry: string, config: unknown): Promise<{ child: ChildProcess; port: number; pid: number }> {
  return new Promise((resolve, reject) => {
    const child = fork(entry, [JSON.stringify(config)], { execArgv: process.execArgv, cwd: REPOSITORY_ROOT, stdio: ["ignore", "ignore", "ignore", "ipc"], serialization: "json" });
    const timer = setTimeout(() => { child.kill(); reject(new Error("observation process did not start")); }, 20_000);
    child.once("message", (message: { type?: string; port?: number; pid?: number }) => { if (message.type === "ready" && typeof message.port === "number") { clearTimeout(timer); resolve({ child, port: message.port, pid: message.pid ?? child.pid ?? 0 }); } });
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("exit", () => { clearTimeout(timer); });
  });
}
const stop = (child: ChildProcess): Promise<void> => new Promise((resolve) => {
  if (child.exitCode !== null || child.killed) { resolve(); return; }
  const timer = setTimeout(() => { child.kill(); resolve(); }, 3_000);
  child.once("exit", () => { clearTimeout(timer); resolve(); });
  try { child.send({ type: "stop" }); } catch { child.kill(); }
});

export async function runObservation(options: ObservationOptions): Promise<ObservationFiles> {
  mkdirSync(options.observerDirectory, { recursive: true });
  const files: ObservationFiles = { canaryFile: path.join(options.observerDirectory, "canary-results.json"), receiptsFile: path.join(options.observerDirectory, "origin-receipts.ndjson"), metaFile: path.join(options.observerDirectory, "observation-meta.json") };
  const children: ChildProcess[] = [];
  try {
    const site = await start(ENTRY("fixture-site.ts"), {}); children.push(site.child);
    const collector = await start(ENTRY("origin-collector.ts"), { upstreamPort: site.port, receiptsFile: files.receiptsFile }); children.push(collector.child);
    const front = await start(ENTRY("fixture-front.ts"), { upstreamPort: collector.port, faults: options.faults ?? {} }); children.push(front.child);
    const canary = fork(ENTRY("canary.ts"), [JSON.stringify({ frontPort: front.port, runId: options.runId, campaignId: options.campaignId, plan: options.plan ?? { baseline: 2, window: 3, recovery: 2 }, timeoutMs: options.timeoutMs ?? 5_000, outFile: files.canaryFile })],
      { execArgv: process.execArgv, cwd: REPOSITORY_ROOT, stdio: ["ignore", "ignore", "ignore", "ipc"], serialization: "json" });
    children.push(canary);
    await new Promise<void>((resolve, reject) => { canary.once("exit", (code) => (code === 0 ? resolve() : reject(new Error("canary failed")))); });
    writeFileSync(files.metaFile, `${JSON.stringify({
      schema: "m1-observation-meta-v1", loopbackOnly: true, runId: options.runId, campaignId: options.campaignId,
      processes: { canary: canary.pid ?? 0, serverUnderTestStandIn: front.pid, originReceiptCollector: collector.pid, originFixture: site.pid, harness: process.pid },
      custody: "separate local processes under one operator on one host: NOT independent organizational custody",
    })}\n`);
  } finally { await Promise.all(children.map(stop)); }
  if (!existsSync(files.canaryFile)) throw new Error("canary produced no result file");
  return files;
}

export const readObservation = (files: ObservationFiles): { canary: unknown; receipts: unknown[] | null; meta: unknown } => {
  const parse = (file: string): unknown => { try { return JSON.parse(readFileSync(file, "utf8")); } catch { return undefined; } };
  let receipts: unknown[] | null = null;
  try { receipts = readFileSync(files.receiptsFile, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line) as unknown); } catch { receipts = null; }
  return { canary: parse(files.canaryFile), receipts, meta: parse(files.metaFile) };
};
