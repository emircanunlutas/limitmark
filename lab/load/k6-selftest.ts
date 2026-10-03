/**
 * Real-k6 probes of the safety envelope, against a disposable fixture container (never a provider, never a remote host).
 *
 *   tsx --conditions=react-server lab/load/k6-selftest.ts
 *
 * Each case measures from the FIXTURE's side (what actually arrived) and requires the envelope to hold:
 *   overlap      phases never run together: peak concurrency is the largest phase, not a sum
 *   cap          1 s at 2 req/s emits at most 2 requests (it emitted 3)
 *   size         a 2 MiB response aborts the run after the first one(s), not after the whole schedule
 *   proxy        Docker's automatic proxy injection (client config) cannot redirect traffic
 *   wall-clock   a hung run is KILLED and its container verified removed
 *   donor        a container that is not a lab app container is refused as network-namespace donor
 *   destination  the audit's mid-phase reproduction: the published app container is KILLED during a phase and a stranger takes its loopback port;
 *                the Node engine's ownership lease must stop the run, and the stranger must receive only a bounded handful of requests
 * A "legacy replay" reruns the previous script (git HEAD) for the first three to show the premise was real.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import net from "node:net";
import http from "node:http";
import { assertSameLabAppContainer, containerExists, docker, inspectLabContainer, removeLabContainer } from "../host/docker";
import { executeHttpWorkload } from "./engine";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState } from "../evidence/manifest";
import { evidenceSafeError } from "../evidence/redact";
import { K6_IMAGE, runK6 } from "./k6";
import { PolicyRefusal, authorizeRun, buildRegistry, type AuthorizedRun, type EffectiveLimits } from "../policy/target-policy";
import { THRESHOLD_SETS } from "../policy/thresholds";

const FIXTURE_IMAGE = "node:22-bookworm";
const SERVER = `
const http = require("http");
let total = 0, inflight = 0, maxInflight = 0, big = 0, proxyHits = 0, bigMode = false;
const reset = () => { total = 0; inflight = 0; maxInflight = 0; big = 0; proxyHits = 0; bigMode = false; };
http.createServer((req, res) => {
  if (req.url === "/__stats") return res.end(JSON.stringify({ total, maxInflight, big, proxyHits }));
  if (req.url === "/__reset") { reset(); return res.end("ok"); }
  if (req.url === "/__big") { bigMode = true; return res.end("ok"); }
  total++; inflight++; maxInflight = Math.max(maxInflight, inflight);
  res.on("close", () => { inflight--; });
  if (bigMode && req.url === "/") { res.write(Buffer.alloc(2 * 1024 * 1024, 97)); big++; return res.end(); }
  if (req.url === "/gizlilik") return setTimeout(() => res.end("slow"), 700);
  if (req.url === "/test-talep-et") return;
  res.end("ok");
}).listen(3000, "0.0.0.0");
http.createServer((req, res) => { proxyHits++; res.end("proxy"); }).listen(3128, "0.0.0.0");
`;

type Check = { name: string; ok: boolean; detail: string };
const checks: Check[] = [];
const record = (name: string, ok: boolean, detail: string) => { checks.push({ name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name} - ${detail}`); };

async function startFixture(name: string, labels: string[], script: string): Promise<string> {
  const { stdout } = await docker(["run", "-d", "--name", name, ...labels.flatMap((label) => ["--label", label]), "--memory", "512m", FIXTURE_IMAGE, "node", "-e", script]);
  return stdout.trim().split("\n").pop() ?? "";
}

async function stats(fixture: string): Promise<{ total: number; maxInflight: number; big: number; proxyHits: number }> {
  const { stdout } = await docker(["exec", fixture, "node", "-e", "fetch('http://127.0.0.1:3000/__stats').then(r=>r.text()).then(t=>process.stdout.write(t))"]);
  return JSON.parse(stdout) as { total: number; maxInflight: number; big: number; proxyHits: number };
}
const reset = (fixture: string) => docker(["exec", fixture, "node", "-e", "fetch('http://127.0.0.1:3000/__reset').then(()=>0)"]);
/** From here every "/" answers with 2 MiB (chunked, no Content-Length) until the next reset. */
const bigMode = (fixture: string) => docker(["exec", fixture, "node", "-e", "fetch('http://127.0.0.1:3000/__big').then(()=>0)"]);

function runWith(phases: EffectiveLimits["phases"], paths: string[]): AuthorizedRun {
  const now = new Date();
  const run = authorizeRun({ targetId: "local-app", workloadId: "latency-measurement", registry: buildRegistry([], now), now });
  const total = phases.reduce((sum, entry) => sum + entry.durationSeconds * entry.ratePerSecond, 0);
  return { ...run, workload: { ...run.workload, paths }, limits: { ...run.limits, phases, maxTotalRequests: total, maxDurationSeconds: phases.reduce((sum, entry) => sum + entry.durationSeconds, 0) } };
}
const phase = (name: string, over: Partial<EffectiveLimits["phases"][number]> = {}) => ({ name, durationSeconds: 3, ratePerSecond: 40, concurrency: 4, timeoutMs: 2_000, ...over });
const thresholds = THRESHOLD_SETS["local-loopback-v1"].http["latency-measurement"];

/** Replays the PREVIOUS script and plan format (git HEAD), to show the problem existed. */
async function legacyReplay(fixture: string, phases: { name: string; seconds: number; rate: number; vus: number; timeoutMs: number }[], requests: { method: "GET"; path: string }[]): Promise<void> {
  const legacyScript = execFileSync("git", ["show", "4ad76375e38a3e0feaa7236fbc01e50f6d461c14:lab/load/k6/lab-load.js"], { cwd: REPOSITORY_ROOT, encoding: "utf8" });
  const directory = mkdtempSync(path.join(REPOSITORY_ROOT, "artifacts", "lab", "k6-legacy-"));
  try {
    writeFileSync(path.join(directory, "lab-load.js"), legacyScript);
    const plan = JSON.stringify({ schema: 1, baseUrl: "http://127.0.0.1:3000", requests, phases: phases.map((entry) => ({ ...entry, measured: false })), thresholds: { passErrorRate: 1, stopErrorRate: 2, passP95Ms: 60000, passP99Ms: 60000, stopP99Ms: 60000 } });
    writeFileSync(path.join(directory, "plan.json"), `${plan}\n`);
    const { createHash } = await import("node:crypto");
    const sha = createHash("sha256").update(`${plan}\n`).digest("hex");
    const fixtureId = (await docker(["inspect", "--format", "{{.Id}}", fixture])).stdout.trim();
    await docker(["run", "--rm", "--network", `container:${fixtureId}`, "-v", `${directory}:/lab`, "-e", "LAB_PLAN=/lab/plan.json", "-e", `LAB_PLAN_SHA256=${sha}`, K6_IMAGE, "run", "--quiet", "--no-usage-report", "/lab/lab-load.js"], { timeoutMs: 120_000 }).catch(() => undefined);
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

async function main(): Promise<void> {
  const evidence = new EvidenceRun("k6-selftest", "k6-selftest");
  mkdirSync(path.join(REPOSITORY_ROOT, "artifacts", "lab"), { recursive: true });
  const fixtureName = `limitmark-lab-fixture-${randomBytes(4).toString("hex")}`;
  const impostorName = `limitmark-lab-impostor-${randomBytes(4).toString("hex")}`;
  const wrongRoleName = `limitmark-lab-wrongrole-${randomBytes(4).toString("hex")}`;
  let failure: string | null = null;
  const dockerConfigDirectory = mkdtempSync(path.join(os.tmpdir(), "lab-docker-config-"));
  const originalDockerConfig = process.env.DOCKER_CONFIG;
  try {
    await startFixture(fixtureName, ["limitmark.lab=disposable", "limitmark.lab.role=app"], SERVER);
    for (let attempt = 0; attempt < 40; attempt++) { if (await stats(fixtureName).then(() => true, () => false)) break; await new Promise((resolve) => setTimeout(resolve, 500)); }

    // ---- overlap
    await reset(fixtureName);
    const overlapPhases = [phase("c4", { concurrency: 4 }), phase("c8", { concurrency: 8 })];
    const overlap = await runK6(runWith(overlapPhases, ["/gizlilik"]), thresholds, { netnsContainer: fixtureName, runId: evidence.id });
    const afterOverlap = await stats(fixtureName);
    record("overlap: peak server-side concurrency is the largest phase (<= 8), not a sum (12)", afterOverlap.maxInflight <= 8 && afterOverlap.maxInflight >= 4, `peak ${afterOverlap.maxInflight}, requests ${afterOverlap.total}, k6 ${overlap.result}, container removed ${overlap.containerRemoved}`);
    record("overlap: total never exceeds the scheduled caps", afterOverlap.total <= 240, `${afterOverlap.total} <= 240`);
    await reset(fixtureName);
    await legacyReplay(fixtureName, overlapPhases.map((entry) => ({ name: entry.name, seconds: entry.durationSeconds, rate: entry.ratePerSecond, vus: entry.concurrency, timeoutMs: entry.timeoutMs })), [{ method: "GET", path: "/gizlilik" }]);
    const legacyOverlap = await stats(fixtureName);
    record("legacy replay (previous script) overlapped phases", legacyOverlap.maxInflight > 8, `legacy peak ${legacyOverlap.maxInflight} (> 8 reproduces the audit finding)`);

    // ---- per-phase cap
    await reset(fixtureName);
    const capRun = await runK6(runWith([phase("tiny", { durationSeconds: 1, ratePerSecond: 2, concurrency: 1 })], ["/"]), thresholds, { netnsContainer: fixtureName, runId: evidence.id });
    const afterCap = await stats(fixtureName);
    record("cap: 1 s at 2 req/s emits at most 2 requests", afterCap.total <= 2 && afterCap.total >= 1, `${afterCap.total} request(s), k6 ${capRun.result}`);
    // The previous script's off-by-one depends on timing; replay it a few times and report the maximum (informational: the new bound is what is asserted).
    let legacyMost = 0;
    for (let trial = 0; trial < 4 && legacyMost <= 2; trial++) {
      await reset(fixtureName);
      await legacyReplay(fixtureName, [{ name: "tiny", seconds: 1, rate: 2, vus: 1, timeoutMs: 2000 }], [{ method: "GET", path: "/" }]);
      legacyMost = Math.max(legacyMost, (await stats(fixtureName)).total);
    }
    record("legacy replay (informational, timing-dependent): requests emitted by 1 s at 2 req/s", true, `legacy emitted up to ${legacyMost} (3 reproduces the audit finding; the bound asserted above is 2)`);

    // ---- response size
    await reset(fixtureName);
    await bigMode(fixtureName);
    const sizeRun = await runK6(runWith([phase("size", { durationSeconds: 3, ratePerSecond: 5, concurrency: 2, timeoutMs: 5_000 })], ["/"]), thresholds, { netnsContainer: fixtureName, runId: evidence.id });
    const afterSize = await stats(fixtureName);
    record("size: a 2 MiB response aborts the run (STOP) after at most the in-flight requests, not after the whole schedule", sizeRun.result === "STOP" && afterSize.total <= 4, `k6 ${sizeRun.result}, ${afterSize.total} request(s) of ${3 * 5} scheduled`);
    await reset(fixtureName);
    await bigMode(fixtureName);
    await legacyReplay(fixtureName, [{ name: "size", seconds: 3, rate: 5, vus: 2, timeoutMs: 5000 }], [{ method: "GET", path: "/" }]);
    const legacySize = await stats(fixtureName);
    record("legacy replay consumed every 2 MiB response", legacySize.big >= 10, `legacy served ${legacySize.big} oversized responses (>= 10 reproduces the audit finding)`);

    // ---- Docker automatic proxy injection
    writeFileSync(path.join(dockerConfigDirectory, "config.json"), JSON.stringify({ proxies: { default: { httpProxy: "http://127.0.0.1:3128", httpsProxy: "http://127.0.0.1:3128" } } }));
    process.env.DOCKER_CONFIG = dockerConfigDirectory;
    const donorId = (await docker(["inspect", "--format", "{{.Id}}", fixtureName])).stdout.trim();
    const legacyName = `limitmark-lab-k6-${randomBytes(6).toString("hex")}`;
    const legacyCreate = await docker(["create", "--name", legacyName, "--label", "limitmark.lab=disposable", "--label", "limitmark.lab.role=k6", "--network", `container:${donorId}`, K6_IMAGE, "version"]);
    const injectedEnv = (await docker(["inspect", "--format", "{{json .Config.Env}}", legacyCreate.stdout.trim()])).stdout;
    await removeLabContainer(legacyName, "k6");
    record("proxy: the docker CLI really injects proxy variables from its config into a container created the old way", /HTTP_PROXY=http:\/\/127\.0\.0\.1:3128/i.test(injectedEnv), "premise reproduced");
    await reset(fixtureName);
    const proxied = await runK6(runWith([phase("direct", { durationSeconds: 2, ratePerSecond: 10, concurrency: 2 })], ["/"]), thresholds, { netnsContainer: fixtureName, runId: evidence.id });
    const afterProxy = await stats(fixtureName);
    record("proxy: with injection configured, the authorized destination still receives the traffic and the proxy none", afterProxy.proxyHits === 0 && afterProxy.total >= 10, `target ${afterProxy.total}, proxy ${afterProxy.proxyHits}, k6 ${proxied.result}`);
    if (originalDockerConfig === undefined) delete process.env.DOCKER_CONFIG; else process.env.DOCKER_CONFIG = originalDockerConfig;

    // ---- wall-clock kill with verified removal
    await reset(fixtureName);
    const hung = await runK6(runWith([phase("hang", { durationSeconds: 20, ratePerSecond: 2, concurrency: 2, timeoutMs: 10_000 })], ["/test-talep-et"]), thresholds, { netnsContainer: fixtureName, runId: evidence.id, superviseMs: 4_000 });
    const leftovers = (await docker(["ps", "-a", "--filter", "label=limitmark.lab.role=k6", "--format", "{{.Names}}"])).stdout.trim();
    record("wall-clock: a hung k6 is killed (STOP) and its container is verified removed", hung.result === "STOP" && hung.stoppedBy === "wall-clock" && hung.containerRemoved && leftovers === "", `k6 ${hung.result}, stoppedBy ${hung.stoppedBy}, removed ${hung.containerRemoved}, leftovers "${leftovers}"`);

    // ---- destination ownership during a phase (real container, real published port, real stranger)
    {
      const port = 3100;
      const portFree = await new Promise<boolean>((resolve) => { const probe = net.createServer(); probe.once("error", () => resolve(false)); probe.listen(port, "127.0.0.1", () => probe.close(() => resolve(true))); });
      if (!portFree) record("destination: mid-phase replacement", false, "127.0.0.1:3100 is in use on this machine; free it and rerun");
      else {
        const appName = `limitmark-lab-app-${randomBytes(3).toString("hex")}`;
        const created = await docker(["run", "-d", "--name", appName, "--label", "limitmark.lab=disposable", "--label", "limitmark.lab.role=app", "-p", `127.0.0.1:${port}:3000`, "--memory", "256m", FIXTURE_IMAGE, "node", "-e", SERVER]);
        const appId = created.stdout.trim().split("\n").pop() ?? "";
        let strangerHits = 0, originalHits = 0;
        let stranger: http.Server | null = null;
        try {
          for (let attempt = 0; attempt < 60; attempt++) { if (await fetch(`http://127.0.0.1:${port}/`).then(() => true, () => false)) break; await new Promise((resolve) => setTimeout(resolve, 250)); }
          const now = new Date();
          const base = authorizeRun({ targetId: "local-app-alt", workloadId: "latency-measurement", registry: buildRegistry([], now), now });
          const phases = [{ name: "p", durationSeconds: 10, ratePerSecond: 20, concurrency: 2, timeoutMs: 2_000 }];
          const run: AuthorizedRun = { ...base, limits: { ...base.limits, phases, maxTotalRequests: 200, maxDurationSeconds: 10 } };
          const verify = async () => { assertSameLabAppContainer(await inspectLabContainer(appName, "app"), port, 3000, appId); };
          // At 2.5 s the container is killed and, as soon as the port is free, a stranger listens on it.
          const attack = (async () => {
            await new Promise((resolve) => setTimeout(resolve, 2_500));
            await docker(["kill", appId]);
            for (let attempt = 0; attempt < 100 && stranger === null; attempt++) {
              const candidate = http.createServer((_request, response) => { strangerHits++; response.end("stranger"); });
              const bound = await new Promise<boolean>((resolve) => { candidate.once("error", () => resolve(false)); candidate.listen(port, "127.0.0.1", () => resolve(true)); });
              if (bound) stranger = candidate; else await new Promise((resolve) => setTimeout(resolve, 50));
            }
          })();
          const started = Date.now();
          const outcome = await executeHttpWorkload({ run, thresholds, destination: { verify, intervalMs: 250, maxStaleMs: 750 } });
          await attack;
          originalHits = outcome.phases[0]?.attempted ?? 0;
          const settled = strangerHits;
          await new Promise((resolve) => setTimeout(resolve, 1_000));
          record(
            "destination: after the container is killed mid-phase and a stranger takes its port, the lease stops the run and the stranger receives only a bounded few requests",
            /destination ownership lost/.test(outcome.stopReason ?? "") && strangerHits <= 30 && strangerHits === settled && Date.now() - started < 8_000,
            `stopReason "${outcome.stopReason}", stranger received ${strangerHits} request(s) (the old phase-boundary check would let it receive up to ~150), attempted ${originalHits}, run lasted ${Date.now() - started} ms of a 10 s phase`,
          );
        } finally {
          if (stranger) await new Promise((resolve) => (stranger as http.Server).close(resolve));
          await removeLabContainer(appName, "app").catch(() => undefined);
        }
      }
    }

    // ---- donor identity
    await startFixture(impostorName, [], "setInterval(() => {}, 1000)");
    await startFixture(wrongRoleName, ["limitmark.lab=disposable", "limitmark.lab.role=postgres"], "setInterval(() => {}, 1000)");
    for (const [label, donor] of [["unlabelled container with the lab name prefix", impostorName], ["lab-labelled container with the wrong role", wrongRoleName]] as const) {
      const refused = await runK6(runWith([phase("x", { durationSeconds: 1, ratePerSecond: 1, concurrency: 1 })], ["/"]), thresholds, { netnsContainer: donor, runId: evidence.id }).then(() => false, (error) => error instanceof PolicyRefusal);
      record(`donor: ${label} is refused as a network-namespace donor`, refused, refused ? "PolicyRefusal" : "NOT refused");
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : error); // diagnostics on the console only; the evidence gets the sanitized form
    failure = evidenceSafeError(error);
  } finally {
    if (originalDockerConfig === undefined) delete process.env.DOCKER_CONFIG; else process.env.DOCKER_CONFIG = originalDockerConfig;
    rmSync(dockerConfigDirectory, { recursive: true, force: true });
    await removeLabContainer(fixtureName, "app").catch(() => undefined);
    for (const name of [impostorName, wrongRoleName]) await docker(["rm", "-f", name]).catch(() => undefined);
    for (const name of [fixtureName, impostorName, wrongRoleName]) if (await containerExists(name).catch(() => true)) failure ??= "a fixture container could not be removed";
  }
  const pass = !failure && checks.length > 0 && checks.every((entry) => entry.ok);
  evidence.addJsonArtifact("k6-selftest.json", { checks });
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(), target: { id: "k6-fixture", class: "lab-local", ownership: "lab-labelled-container" }, workload: { id: "k6-envelope-selftest", phases: [] },
    ceilings: { scope: "per-process; not campaign- or fleet-wide" }, thresholds: null, engine: "k6", result: failure ? "ERROR" : pass ? "PASS" : "FAIL",
    resultReasons: failure ? [failure] : checks.filter((entry) => !entry.ok).map((entry) => entry.name.slice(0, 120)), metrics: { checks: checks.length, passed: checks.filter((entry) => entry.ok).length },
  });
  console.log(`k6 self-test: ${failure ? `ERROR ${failure}` : pass ? "PASS" : "FAIL"} evidence=${evidence.id}`);
  process.exit(pass ? 0 : 1);
}

if (require.main === module) {
  main().catch((error) => { console.error(error instanceof Error ? error.message : error); process.exit(1); });
}
