/**
 * Standalone launcher for the two independent observers, written so that each can be started on its OWN machine (or container) by the observers' principal. Nothing here
 * provisions anything or reaches any address except the ones named on the command line, and every network setting is explicit:
 *
 *   tsx lab/m1/observation/launch.ts collector --run-id ID --campaign-id ID --listen-host IP --listen-port N --upstream-host IP --upstream-port N --output-dir DIR
 *                                              [--heartbeat-ms N] [--stop-file FILE] [--allow-private-network]
 *   tsx lab/m1/observation/launch.ts canary    --run-id ID --campaign-id ID --target-host IP --target-port N --output-dir DIR
 *                                              [--plan B,W,R] [--timeout-ms N] [--journey-gap-ms N] [--process NAME=PID ...] [--allow-private-network]
 *
 * collector: starts the receipt collector (the same code as the local harness), beats a heartbeat, and FINALIZES (writes the closing declaration) when the stop file appears
 *            or on SIGINT/SIGTERM. Exit 0 only after the declaration is on disk.
 * canary:    walks the legitimate-user journey against the target host and writes canary-results.json and observation-meta.json (the run window it observed). It does NOT write
 *            a heartbeat-gap limit: that number belongs to the verifier.
 * Address policy: loopback is always allowed; RFC 1918 private IPv4 literals only with --allow-private-network; everything else (public addresses, names, 0.0.0.0, link-local,
 * CGNAT, multicast) is refused. This launcher cannot target a public endpoint (public ingress is a separate, unapproved test category).
 * Exit codes: 0 done, 30 failed, 64 usage.
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { BA0_FIELD_V1 } from "../../defense/field-thresholds";
import { startCollector } from "./collector-core";
import { runCanary } from "./canary";

export type HostClass = "loopback" | "private" | "refused";
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/u;
export function classifyHost(host: string): HostClass {
  if (!IPV4.test(host)) return "refused";
  const [a, b] = host.split(".").map(Number) as [number, number];
  if (a === 127) return "loopback";
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
  return "refused";
}

class UsageError extends Error {}
export type LaunchIo = { stdout: (line: string) => void; stopSignal?: Promise<void> };
const RUN_ID = /^[A-Za-z0-9._-]{1,128}$/u; const CAMPAIGN_ID = /^[a-z0-9-]{1,31}$/u;
const BOOLEAN = new Set(["allow-private-network"]);

function parse(argv: readonly string[]): Map<string, string[]> {
  const flags = new Map<string, string[]>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (!arg.startsWith("--")) throw new UsageError(`unexpected argument ${arg}`);
    const name = arg.slice(2); const value = BOOLEAN.has(name) ? "true" : argv[++i];
    if (value === undefined || (!BOOLEAN.has(name) && value.startsWith("--"))) throw new UsageError(`--${name} needs a value`);
    flags.set(name, [...(flags.get(name) ?? []), value]);
  }
  return flags;
}
const text = (flags: Map<string, string[]>, name: string): string => { const v = flags.get(name); if (v === undefined || v.length !== 1) throw new UsageError(`--${name} is required exactly once`); return v[0]!; };
const optional = (flags: Map<string, string[]>, name: string): string | null => { const v = flags.get(name); if (v === undefined) return null; if (v.length !== 1) throw new UsageError(`--${name} given more than once`); return v[0]!; };
const integer = (raw: string, name: string, min: number, max: number): number => { if (!/^[0-9]{1,9}$/u.test(raw) || Number(raw) < min || Number(raw) > max) throw new UsageError(`--${name} must be an integer from ${min} to ${max}`); return Number(raw); };
function host(flags: Map<string, string[]>, name: string): { host: string; cls: HostClass } {
  const value = text(flags, name); const cls = classifyHost(value);
  if (cls === "refused") throw new UsageError(`--${name} ${JSON.stringify(value)} is not a loopback or private IPv4 literal`);
  if (cls === "private" && !flags.has("allow-private-network")) throw new UsageError(`--${name} is a private address: pass --allow-private-network to confirm a private-lane test`);
  return { host: value, cls };
}
function identity(flags: Map<string, string[]>): { runId: string; campaignId: string } {
  const runId = text(flags, "run-id"); const campaignId = text(flags, "campaign-id");
  if (!RUN_ID.test(runId)) throw new UsageError("--run-id is not a valid run identity"); if (!CAMPAIGN_ID.test(campaignId)) throw new UsageError("--campaign-id is not a valid campaign identity");
  return { runId, campaignId };
}

/** The meta record the canary side writes. `loopbackOnly` is derived from the addresses actually used, never asserted. */
export function buildMeta(input: { runId: string; campaignId: string; windowStartMs: number; windowEndMs: number; hosts: string[]; processes: Record<string, number> }): Record<string, unknown> {
  const loopbackOnly = input.hosts.every((h) => classifyHost(h) === "loopback");
  return {
    schema: "m1-observation-meta-v1", loopbackOnly, topology: loopbackOnly ? "loopback" : "private-lane", runId: input.runId, campaignId: input.campaignId,
    runWindow: { startMs: input.windowStartMs, endMs: input.windowEndMs }, processes: input.processes,
    custody: "written by the canary launcher; independence depends on separate principals, credentials and storage, not on separate processes",
  };
}

export async function runLauncher(argv: readonly string[], io: LaunchIo): Promise<number> {
  const command = argv[0] ?? "";
  try {
    const flags = parse(argv.slice(1));
    const allowed: Record<string, string[]> = {
      collector: ["run-id", "campaign-id", "listen-host", "listen-port", "upstream-host", "upstream-port", "output-dir", "heartbeat-ms", "stop-file", "allow-private-network"],
      canary: ["run-id", "campaign-id", "target-host", "target-port", "output-dir", "plan", "timeout-ms", "journey-gap-ms", "process", "allow-private-network"],
    };
    if (!(command in allowed)) throw new UsageError(`unknown command ${JSON.stringify(command)}`);
    for (const name of flags.keys()) if (!allowed[command]!.includes(name)) throw new UsageError(`--${name} is not a flag of ${command}`);
    const id = identity(flags);
    const outputDir = path.resolve(text(flags, "output-dir")); mkdirSync(outputDir, { recursive: true });
    if (command === "collector") {
      const listen = host(flags, "listen-host"); const upstream = host(flags, "upstream-host");
      const heartbeatMs = integer(optional(flags, "heartbeat-ms") ?? "100", "heartbeat-ms", 10, 60_000);
      const stopFile = optional(flags, "stop-file");
      const declarationFile = path.join(outputDir, "collector-declaration.json");
      const collector = await startCollector({ upstreamPort: integer(text(flags, "upstream-port"), "upstream-port", 1, 65_535), upstreamHost: upstream.host, receiptsFile: path.join(outputDir, "origin-receipts.ndjson"), runId: id.runId, campaignId: id.campaignId, declarationFile, heartbeatMs, listenHost: listen.host, listenPort: integer(text(flags, "listen-port"), "listen-port", 0, 65_535), heartbeatLogFile: path.join(outputDir, "collector-heartbeats.ndjson") });
      io.stdout(JSON.stringify({ event: "collector-ready", runId: id.runId, campaignId: id.campaignId, listenHost: collector.host, port: collector.port, pid: collector.pid, declarationFile }));
      await new Promise<void>((resolve) => {
        let done = false; const finish = () => { if (!done) { done = true; clearInterval(poll); resolve(); } };
        const poll = setInterval(() => { if (stopFile !== null && existsSync(stopFile)) finish(); }, 100);
        void io.stopSignal?.then(finish);
      });
      const declaration = await collector.stop();
      io.stdout(JSON.stringify({ event: "collector-finalized", receiptCount: declaration.receiptCount, lastSeq: declaration.lastSeq, heartbeats: declaration.heartbeatsMs.length, declarationFile }));
      return 0;
    }
    // canary
    const target = host(flags, "target-host"); const port = integer(text(flags, "target-port"), "target-port", 1, 65_535);
    const planParts = (optional(flags, "plan") ?? "2,3,2").split(",");
    if (planParts.length !== 3) throw new UsageError("--plan is BASELINE,WINDOW,RECOVERY");
    const [baseline, window, recovery] = planParts.map((p) => integer(p, "plan", 1, 10_000)) as [number, number, number];
    const processes: Record<string, number> = { canary: process.pid };
    for (const pair of flags.get("process") ?? []) { const [name, pid, ...rest] = pair.split("="); if (rest.length > 0 || !name || !pid || !/^[1-9][0-9]{0,9}$/u.test(pid) || name in processes) throw new UsageError(`--process ${pair} is not NAME=PID`); processes[name] = Number(pid); }
    const outFile = path.join(outputDir, "canary-results.json");
    const ran = await runCanary({ frontHost: target.host, frontPort: port, runId: id.runId, campaignId: id.campaignId, plan: { baseline, window, recovery }, timeoutMs: integer(optional(flags, "timeout-ms") ?? String(BA0_FIELD_V1.canary.timeoutMs), "timeout-ms", 100, 120_000), outFile, journeyGapMs: integer(optional(flags, "journey-gap-ms") ?? "0", "journey-gap-ms", 0, 60_000) });
    writeFileSync(path.join(outputDir, "observation-meta.json"), `${JSON.stringify(buildMeta({ ...id, windowStartMs: ran.startedAtMs, windowEndMs: ran.endedAtMs, hosts: [target.host], processes }))}\n`);
    io.stdout(JSON.stringify({ event: "canary-done", runId: id.runId, campaignId: id.campaignId, outFile, topology: target.cls === "loopback" ? "loopback" : "private-lane" }));
    return 0;
  } catch (error) {
    if (error instanceof UsageError) { io.stdout(JSON.stringify({ event: "usage", error: error.message })); return 64; }
    io.stdout(JSON.stringify({ event: "failed" })); return 30;
  }
}

// Entry guard without `require`/`import.meta` (the repository import scan must be able to prove every module reference).
if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  const stop = new Promise<void>((resolve) => { process.once("SIGINT", resolve); process.once("SIGTERM", resolve); });
  runLauncher(process.argv.slice(2), { stdout: (line) => process.stdout.write(`${line}\n`), stopSignal: stop }).then((code) => { process.exitCode = code; });
}
