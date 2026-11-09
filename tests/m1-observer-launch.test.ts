import assert from "node:assert/strict";
import { fork, spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { evaluateObservationFiles } from "../lab/m1/observation-bundle";
import { buildMeta, classifyHost, runLauncher } from "../lab/m1/observation/launch";

// Launch package for the two independent observers: explicit run identity, explicit network settings, explicit output destination, heartbeats, finalization. Everything here runs as
// isolated LOCAL processes on loopback; no cloud instance is launched and no non-loopback address is contacted. Separate processes are not separate custody.

const REPO = path.join(__dirname, ".."); const LAUNCH = path.join(REPO, "lab", "m1", "observation", "launch.ts"); const OBS = (n: string) => path.join(REPO, "lab", "m1", "observation", n);
const RUN = "launch-run-1"; const CAMPAIGN = "launch-c1";
const dirs: string[] = []; const children: ChildProcess[] = [];
const temp = (): string => { const d = fs.mkdtempSync(path.join(os.tmpdir(), "m1-launch-")); dirs.push(d); return d; };
test.after(() => { for (const c of children) { try { c.kill(); } catch { /* already gone */ } } for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); });

function forkFixture(entry: string, config: unknown): Promise<{ child: ChildProcess; port: number; pid: number }> {
  return new Promise((resolve, reject) => {
    const child = fork(OBS(entry), [JSON.stringify(config)], { execArgv: process.execArgv, cwd: REPO, stdio: ["ignore", "ignore", "ignore", "ipc"], serialization: "json" }); children.push(child);
    const timer = setTimeout(() => reject(new Error("fixture did not start")), 20_000);
    child.once("message", (m: { type?: string; port?: number; pid?: number }) => { if (m.type === "ready" && typeof m.port === "number") { clearTimeout(timer); resolve({ child, port: m.port, pid: m.pid ?? child.pid ?? 0 }); } });
  });
}
function launcher(args: string[]): { child: ChildProcess; lines: string[]; exited: Promise<number | null>; waitFor: (event: string) => Promise<Record<string, unknown>> } {
  const child = spawn(process.execPath, [...process.execArgv, LAUNCH, ...args], { cwd: REPO, stdio: ["ignore", "pipe", "ignore"] }); children.push(child);
  const lines: string[] = []; let buffer = "";
  const waiters: { event: string; resolve: (v: Record<string, unknown>) => void }[] = [];
  child.stdout!.on("data", (chunk: Buffer) => {
    buffer += chunk.toString("utf8"); let nl: number;
    while ((nl = buffer.indexOf("\n")) >= 0) { const line = buffer.slice(0, nl); buffer = buffer.slice(nl + 1); lines.push(line); try { const parsed = JSON.parse(line) as Record<string, unknown>; for (const w of waiters.filter((x) => x.event === parsed.event)) w.resolve(parsed); } catch { /* not JSON */ } }
  });
  const exited = new Promise<number | null>((resolve) => child.once("exit", (code) => resolve(code)));
  const waitFor = (event: string): Promise<Record<string, unknown>> => new Promise((resolve, reject) => { const hit = lines.map((l) => { try { return JSON.parse(l) as Record<string, unknown>; } catch { return null; } }).find((p) => p?.event === event); if (hit) resolve(hit); else { const timer = setTimeout(() => reject(new Error(`no ${event} event`)), 30_000); timer.unref(); waiters.push({ event, resolve: (v) => { clearTimeout(timer); resolve(v); } }); } });
  return { child, lines, exited, waitFor };
}

test("address policy: loopback and RFC 1918 literals only; public addresses, names, 0.0.0.0, link-local, CGNAT and multicast are refused", () => {
  for (const ok of ["127.0.0.1", "127.9.9.9"]) assert.equal(classifyHost(ok), "loopback");
  for (const ok of ["10.30.0.10", "172.16.0.4", "172.31.255.1", "192.168.1.1"]) assert.equal(classifyHost(ok), "private");
  for (const bad of ["8.8.8.8", "example.com", "localhost", "0.0.0.0", "169.254.169.254", "100.64.0.1", "224.0.0.1", "172.32.0.1", "172.15.0.1", "10.0.0", "10.0.0.256", "", "::1", "10.0.0.1 "]) assert.equal(classifyHost(bad), "refused", bad);
});

test("usage errors are explicit and nothing is contacted: missing or invalid identity, a public or named host, a private host without the explicit confirmation, unknown flags", async () => {
  const out: string[] = []; const run = (args: string[]) => runLauncher(args, { stdout: (l) => out.push(l) });
  const dir = temp(); const base = ["--run-id", RUN, "--campaign-id", CAMPAIGN, "--output-dir", dir];
  assert.equal(await run(["canary", ...base, "--target-host", "8.8.8.8", "--target-port", "80"]), 64);
  assert.equal(await run(["canary", ...base, "--target-host", "example.com", "--target-port", "80"]), 64);
  assert.equal(await run(["canary", ...base, "--target-host", "10.30.0.10", "--target-port", "80"]), 64, "private address without --allow-private-network");
  assert.equal(await run(["collector", ...base, "--listen-host", "0.0.0.0", "--listen-port", "0", "--upstream-host", "127.0.0.1", "--upstream-port", "9"]), 64);
  assert.equal(await run(["collector", "--run-id", "bad id!", "--campaign-id", CAMPAIGN, "--output-dir", dir, "--listen-host", "127.0.0.1", "--listen-port", "0", "--upstream-host", "127.0.0.1", "--upstream-port", "9"]), 64);
  assert.equal(await run(["collector", "--run-id", RUN, "--campaign-id", "UPPER", "--output-dir", dir, "--listen-host", "127.0.0.1", "--listen-port", "0", "--upstream-host", "127.0.0.1", "--upstream-port", "9"]), 64);
  assert.equal(await run(["canary", "--campaign-id", CAMPAIGN, "--output-dir", dir, "--target-host", "127.0.0.1", "--target-port", "80"]), 64, "no run id");
  assert.equal(await run(["canary", ...base, "--target-host", "127.0.0.1", "--target-port", "80", "--bogus", "1"]), 64);
  assert.equal(await run(["canary", ...base, "--target-host", "127.0.0.1", "--target-port", "80", "--plan", "1,2"]), 64);
  assert.equal(await run(["frobnicate"]), 64);
  assert.deepEqual(fs.readdirSync(dir).filter((n) => !["origin-receipts.ndjson", "collector-heartbeats.ndjson"].includes(n)), [], "no result file is written for a refused invocation");
});

test("collector finalization in process: a stop signal writes the closing declaration atomically, bound to the run and campaign, with heartbeats recorded and logged", async () => {
  const dir = temp(); const lines: string[] = [];
  let stop!: () => void; const stopSignal = new Promise<void>((resolve) => { stop = resolve; });
  const done = runLauncher(["collector", "--run-id", RUN, "--campaign-id", CAMPAIGN, "--output-dir", dir, "--listen-host", "127.0.0.1", "--listen-port", "0", "--upstream-host", "127.0.0.1", "--upstream-port", "9", "--heartbeat-ms", "20"], { stdout: (l) => lines.push(l), stopSignal });
  await new Promise((resolve) => setTimeout(resolve, 200)); stop();
  assert.equal(await done, 0);
  const declaration = JSON.parse(fs.readFileSync(path.join(dir, "collector-declaration.json"), "utf8")) as { runId: string; campaignId: string; receiptCount: number; lastSeq: number; heartbeatsMs: number[]; coverageStartMs: number; coverageEndMs: number };
  assert.deepEqual([declaration.runId, declaration.campaignId, declaration.receiptCount, declaration.lastSeq], [RUN, CAMPAIGN, 0, 0]);
  assert.ok(declaration.heartbeatsMs.length >= 3 && declaration.coverageEndMs > declaration.coverageStartMs);
  assert.ok(!fs.existsSync(path.join(dir, "collector-declaration.json.partial")), "the declaration is renamed into place, never left half-written");
  assert.ok(fs.readFileSync(path.join(dir, "collector-heartbeats.ndjson"), "utf8").split("\n").filter(Boolean).length >= 3);
  assert.deepEqual(lines.map((l) => (JSON.parse(l) as { event: string }).event), ["collector-ready", "collector-finalized"]);
});

test("isolated local processes: origin fixture, front stand-in, collector launcher and canary launcher produce evidence the UNCHANGED observation evaluator accepts, then finalization via the stop file", async () => {
  const dir = temp(); const stopFile = path.join(dir, "STOP");
  const site = await forkFixture("fixture-site.ts", {});
  const collector = launcher(["collector", "--run-id", RUN, "--campaign-id", CAMPAIGN, "--output-dir", dir, "--listen-host", "127.0.0.1", "--listen-port", "0", "--upstream-host", "127.0.0.1", "--upstream-port", String(site.port), "--heartbeat-ms", "50", "--stop-file", stopFile]);
  const ready = await collector.waitFor("collector-ready");
  const front = await forkFixture("fixture-front.ts", { upstreamPort: ready.port, faults: {} });
  const canary = launcher(["canary", "--run-id", RUN, "--campaign-id", CAMPAIGN, "--output-dir", dir, "--target-host", "127.0.0.1", "--target-port", String(front.port), "--process", `serverUnderTestStandIn=${front.pid}`, "--process", `originReceiptCollector=${ready.pid as number}`, "--process", `originFixture=${site.pid}`, "--process", `harness=${process.pid}`]);
  assert.equal(await canary.exited, 0); await canary.waitFor("canary-done");
  assert.ok(!fs.existsSync(path.join(dir, "collector-declaration.json")), "not finalized before the stop request");
  fs.writeFileSync(stopFile, "stop");
  assert.equal(await collector.exited, 0); await collector.waitFor("collector-finalized");
  front.child.kill(); site.child.kill();
  const bundle = evaluateObservationFiles({ runId: RUN, campaignId: CAMPAIGN }, dir, 1_000);
  assert.equal(bundle.result.outcome, "PASS", bundle.result.reasons.join(","));
  assert.deepEqual([bundle.completeness?.outcome, bundle.limitSource], ["PASS", "verifier"]);
  const meta = JSON.parse(fs.readFileSync(path.join(dir, "observation-meta.json"), "utf8")) as Record<string, unknown>;
  assert.equal(meta.loopbackOnly, true); assert.equal(meta.topology, "loopback"); assert.equal(meta.completeness, undefined, "the heartbeat-gap limit is never written by the observer");
  assert.ok(fs.readFileSync(path.join(dir, "collector-heartbeats.ndjson"), "utf8").length > 0);
  // run identity is explicit: the same evidence judged under another identity is rejected
  assert.notEqual(evaluateObservationFiles({ runId: "other-run", campaignId: CAMPAIGN }, dir, 1_000).result.outcome, "PASS");
  // heartbeat limit belongs to the verifier: an unmeetable limit rejects the same bytes
  assert.equal(evaluateObservationFiles({ runId: RUN, campaignId: CAMPAIGN }, dir, 1).result.outcome, "REJECT");
});

test("a collector that dies before finalizing leaves NO declaration, and the evidence is then never a PASS", async () => {
  const dir = temp(); const site = await forkFixture("fixture-site.ts", {});
  const collector = launcher(["collector", "--run-id", RUN, "--campaign-id", CAMPAIGN, "--output-dir", dir, "--listen-host", "127.0.0.1", "--listen-port", "0", "--upstream-host", "127.0.0.1", "--upstream-port", String(site.port), "--heartbeat-ms", "50"]);
  const ready = await collector.waitFor("collector-ready");
  const front = await forkFixture("fixture-front.ts", { upstreamPort: ready.port, faults: {} });
  const canary = launcher(["canary", "--run-id", RUN, "--campaign-id", CAMPAIGN, "--output-dir", dir, "--target-host", "127.0.0.1", "--target-port", String(front.port), "--process", `a=${front.pid}`, "--process", `b=${ready.pid as number}`, "--process", `c=${site.pid}`, "--process", `d=${process.pid}`]);
  assert.equal(await canary.exited, 0);
  collector.child.kill(); await collector.exited; front.child.kill(); site.child.kill();
  assert.ok(!fs.existsSync(path.join(dir, "collector-declaration.json")));
  const bundle = evaluateObservationFiles({ runId: RUN, campaignId: CAMPAIGN }, dir, 1_000);
  assert.notEqual(bundle.result.outcome, "PASS"); assert.equal(bundle.completeness?.outcome, "ERROR");
});

test("a private-lane meta is written truthfully (loopbackOnly false) and the UNCHANGED evaluator rejects it: remote observation evidence is a documented CODE blocker, not silently accepted", async () => {
  const dir = temp(); const lines: string[] = [];
  let stop!: () => void; const stopSignal = new Promise<void>((resolve) => { stop = resolve; });
  const site = await forkFixture("fixture-site.ts", {});
  const done = runLauncher(["collector", "--run-id", RUN, "--campaign-id", CAMPAIGN, "--output-dir", dir, "--listen-host", "127.0.0.1", "--listen-port", "0", "--upstream-host", "127.0.0.1", "--upstream-port", String(site.port), "--heartbeat-ms", "20"], { stdout: (l) => lines.push(l), stopSignal });
  const collectorPort = await new Promise<number>((resolve) => { const t = setInterval(() => { const l = lines.find((x) => x.includes("collector-ready")); if (l) { clearInterval(t); resolve((JSON.parse(l) as { port: number }).port); } }, 10); });
  const front = await forkFixture("fixture-front.ts", { upstreamPort: collectorPort, faults: {} });
  const out: string[] = [];
  assert.equal(await runLauncher(["canary", "--run-id", RUN, "--campaign-id", CAMPAIGN, "--output-dir", dir, "--target-host", "127.0.0.1", "--target-port", String(front.port), "--process", `a=${front.pid}`, "--process", `b=${process.pid + 1}`, "--process", `c=${site.pid}`, "--process", `d=${process.pid + 2}`], { stdout: (l) => out.push(l) }), 0);
  stop(); assert.equal(await done, 0); front.child.kill(); site.child.kill();
  const sane = evaluateObservationFiles({ runId: RUN, campaignId: CAMPAIGN }, dir, 1_000); assert.equal(sane.result.outcome, "PASS", `sanity: ${sane.result.reasons.join(",")}`);
  const meta = buildMeta({ runId: RUN, campaignId: CAMPAIGN, windowStartMs: 1, windowEndMs: 2, hosts: ["10.10.0.10"], processes: { canary: 1 } });
  assert.deepEqual([meta.loopbackOnly, meta.topology], [false, "private-lane"]);
  fs.writeFileSync(path.join(dir, "observation-meta.json"), `${JSON.stringify({ ...JSON.parse(fs.readFileSync(path.join(dir, "observation-meta.json"), "utf8")) as object, loopbackOnly: false, topology: "private-lane" })}\n`);
  const rejected = evaluateObservationFiles({ runId: RUN, campaignId: CAMPAIGN }, dir, 1_000);
  assert.notEqual(rejected.result.outcome, "PASS"); assert.ok(rejected.result.reasons.includes("m1.obs.meta_identity_mismatch"));
});
