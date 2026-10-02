/**
 * Linux parity checks in containers (Docker Desktop, WSL2 kernel). Everything is local:
 * the only network use is the package registries needed to build the image.
 *
 * What this CAN show: the repository installs, type-checks, lints, tests, builds and serves on
 * Linux (case-sensitive FS, Linux Node, Linux workerd), the DB suites pass on a Linux client
 * against PostgreSQL 16/17, and the app answers the same workloads from inside a container.
 * What it can NOT show: VM, kernel tuning, cloud network path, TLS/edge, disk/IO or real RTT.
 *
 *   tsx --conditions=react-server lab/linux/parity.ts [--skip-build]
 */
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { docker, containerExists } from "../host/docker";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState } from "../evidence/manifest";
import { labDbDown, labDbUp, migratorUrl, teardownOnCrash, type PgVersion } from "../postgres/lab-db";

const IMAGE = "limitmark-lab-parity:local";
const APP_CONTAINER = "limitmark-lab-app";

type StepResult = { id: string; ok: boolean; exitCode: number; seconds: number; counts?: Record<string, number>; note?: string };

const logDirectory = path.join(REPOSITORY_ROOT, "artifacts", "lab", "logs");

function runCapture(command: string, args: string[], logName: string, timeoutMs: number, env: Record<string, string> = {}): Promise<{ exitCode: number; output: string }> {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd: REPOSITORY_ROOT, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let output = "";
    child.stdout.on("data", (chunk) => { output += chunk; });
    child.stderr.on("data", (chunk) => { output += chunk; });
    const timer = setTimeout(() => { child.kill(); output += "\n[parity] timed out\n"; }, timeoutMs);
    child.on("close", (code) => {
      clearTimeout(timer);
      mkdirSync(logDirectory, { recursive: true });
      writeFileSync(path.join(logDirectory, logName), output);
      resolve({ exitCode: code ?? 1, output });
    });
    child.on("error", () => { clearTimeout(timer); resolve({ exitCode: 127, output }); });
  });
}

function nodeTestCounts(output: string): Record<string, number> | undefined {
  const read = (label: string) => Number(new RegExp(`(?:ℹ|#) ${label} (\\d+)`).exec(output)?.[1] ?? NaN);
  const counts = { tests: read("tests"), pass: read("pass"), fail: read("fail"), skipped: read("skipped") };
  return Number.isNaN(counts.tests) ? undefined : counts;
}

async function step(id: string, body: () => Promise<{ exitCode: number; output: string; note?: string; countsFrom?: "node-test" }>): Promise<StepResult> {
  const started = Date.now();
  const { exitCode, output, note, countsFrom } = await body();
  const result: StepResult = {
    id, ok: exitCode === 0, exitCode, seconds: Math.round((Date.now() - started) / 100) / 10,
    counts: countsFrom === "node-test" ? nodeTestCounts(output) : undefined, note,
  };
  console.log(`${result.ok ? "PASS" : "FAIL"}  ${id} (${result.seconds}s)${result.counts ? ` ${JSON.stringify(result.counts)}` : ""}`);
  return result;
}

const inContainer = (script: string, extra: string[] = []) => ["run", "--rm", "--memory", "4g", ...extra, IMAGE, "sh", "-c", script];

async function main(): Promise<void> {
  const skipBuild = process.argv.includes("--skip-build");
  const evidence = new EvidenceRun("linux-parity", "linux-parity");
  const results: StepResult[] = [];
  const versions: PgVersion[] = ["16", "17"];
  teardownOnCrash(versions);
  let containerFacts: Record<string, string> = {};

  if (!skipBuild) {
    results.push(await step("image-build-npm-ci-next-build", async () => {
      const r = await runCapture("docker", ["build", "-f", "lab/linux/Dockerfile", "-t", IMAGE, "."], `${evidence.id}-build.log`, 25 * 60_000);
      return r;
    }));
  }
  if (results.every((r) => r.ok)) {
    const facts = await docker(inContainer("echo \"$(. /etc/os-release; echo $PRETTY_NAME)|$(uname -sr)|$(node --version)|$(npm --version)\""));
    const [os, kernel, node, npm] = facts.stdout.trim().split("|");
    containerFacts = { containerOs: os, containerKernel: kernel.split(".").slice(0, 2).join("."), containerNode: node, containerNpm: npm };

    for (const [id, script, timeout, counts] of [
      ["typecheck", "npm run typecheck", 10, false],
      ["lint", "npm run lint", 10, false],
      ["npm-test", "npm test", 15, true],
      ["workerd-suites", "npm run test:workers", 25, false],
    ] as const) {
      results.push(await step(id, async () => ({
        ...(await runCapture("docker", inContainer(script), `${evidence.id}-${id}.log`, timeout * 60_000)),
        countsFrom: counts ? "node-test" as const : undefined,
      })));
    }

    for (const version of versions) {
      results.push(await step(`db-tests-pg${version}-from-linux-client`, async () => {
        const state = await labDbUp(version);
        try {
          // Share the PG container's network namespace: 127.0.0.1:5432 inside is the lab database.
          const url = migratorUrl(state).replace(`:${state.port}/`, ":5432/");
          const r = await runCapture("docker", inContainer("npm run test:db -- --test-reporter=spec", [
            "--network", `container:${state.container}`, "-e", `TEST_DATABASE_URL=${url}`, "-e", `TEST_DATABASE_PROOF=${state.proofToken}`,
          ]), `${evidence.id}-db-pg${version}.log`, 10 * 60_000);
          const counts = nodeTestCounts(r.output);
          const complete = counts !== undefined && counts.tests === 34 && counts.pass === 34 && counts.skipped === 0;
          return { exitCode: r.exitCode === 0 && complete ? 0 : 1, output: r.output, countsFrom: "node-test" as const, note: complete ? undefined : "did not run all 34 tests" };
        } finally { await labDbDown(version).catch(() => undefined); }
      }));
    }

    results.push(await step("app-in-container-http-workloads", async () => {
      if (await containerExists(APP_CONTAINER)) await docker(["rm", "-f", APP_CONTAINER]);
      await docker([
        "run", "-d", "--name", APP_CONTAINER, "--label", "limitmark.lab=disposable", "-p", "127.0.0.1:3100:3000",
        "--memory", "2g", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "-e", "NODE_ENV=production", "-e", "REQUEST_SUBMISSION_MODE=demo", "-e", "ALLOW_DEMO_SUBMISSIONS=true",
        "-e", "PUBLIC_DEMO_ORIGIN=http://127.0.0.1:3100", "-e", "PUBLIC_ORIGIN_PROTECTION=disabled",
        IMAGE, "node", "node_modules/next/dist/bin/next", "start", "--hostname", "0.0.0.0", "--port", "3000",
      ]);
      let exitCode = 0;
      let output = "";
      try {
        for (let attempt = 0; attempt < 60; attempt++) {
          const probe = await docker(["exec", APP_CONTAINER, "node", "-e", "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]).then(() => true, () => false);
          if (probe) break;
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
        const tsx = [path.join("node_modules", "tsx", "dist", "cli.mjs"), "--conditions=react-server", "lab/run.ts"];
        for (const workload of ["connectivity-baseline", "latency-measurement", "demo-submission-post"]) {
          const r = await runCapture(process.execPath, [...tsx, "--target", "local-app-alt", "--workload", workload], `${evidence.id}-app-${workload}.log`, 5 * 60_000);
          output += `${workload}:${r.exitCode};`;
          if (r.exitCode !== 0) exitCode = 1;
        }
        // k6 (Docker) joins the app container's network namespace: its 127.0.0.1:3000 is the container's app.
        const k6 = await runCapture(process.execPath, [...tsx, "--target", "local-app", "--workload", "latency-measurement", "--engine", "k6", "--k6-netns-container", APP_CONTAINER], `${evidence.id}-app-k6.log`, 5 * 60_000);
        output += `k6:${k6.exitCode};`;
        if (k6.exitCode !== 0) exitCode = 1;
      } finally { await docker(["rm", "-f", APP_CONTAINER]).catch(() => undefined); }
      return { exitCode, output, note: output };
    }));
  }

  const ok = results.length > 0 && results.every((r) => r.ok);
  evidence.addJsonArtifact("steps.json", JSON.parse(JSON.stringify({ steps: results })));
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(), target: { id: "linux-container", class: "lab-local" },
    workload: { id: "linux-parity", phases: results.map((r) => ({ name: r.id })) }, ceilings: null, thresholds: null, engine: "docker",
    result: ok ? "PASS" : "FAIL", resultReasons: results.filter((r) => !r.ok).map((r) => `${r.id} failed`),
    metrics: {
      steps: results.length, passed: results.filter((r) => r.ok).length, ...containerFacts,
      scope: "container parity only; does not prove VM, kernel or network parity",
    },
  });
  console.log(`linux parity: ${ok ? "PASS" : "FAIL"} evidence=${evidence.id}`);
  process.exit(ok ? 0 : 1);
}

if (require.main === module) {
  main().catch((error) => { console.error(error instanceof Error ? error.message : error); process.exit(1); });
}
