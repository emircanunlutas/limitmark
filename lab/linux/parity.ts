/**
 * Linux parity checks in containers (Docker Desktop, WSL2 kernel). Everything is local:
 * the only network use is the package registries needed to build the image.
 *
 * What this CAN show: the repository installs, type-checks, lints, tests, builds and serves on
 * Linux (case-sensitive FS, Linux Node, Linux workerd), the DB suites pass on a Linux client
 * against PostgreSQL 16/17, and the app answers the same workloads from inside a container.
 * What it can NOT show: VM, kernel tuning, cloud network path, TLS/edge, disk/IO or real RTT, nor a Linux-side HTTP
 * load driver (the Node HTTP drivers run on THIS host and are recorded as such).
 *
 * Provenance: the image carries the commit and the working-tree digest it was built from. `--skip-build` reuses an image
 * only if those labels equal the tree being reported; otherwise it refuses.
 *
 *   tsx --conditions=react-server lab/linux/parity.ts [--skip-build]
 */
import { spawn } from "node:child_process";
import path from "node:path";
import { confinedDockerInvocation, containerExists, docker, inspectContainer, removeLabContainer } from "../host/docker";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState, writeSanitizedLog } from "../evidence/manifest";
import { evidenceSafeError } from "../evidence/redact";
import { labDbDown, labDbUp, migratorUrl, teardownOnCrash, type PgVersion } from "../postgres/lab-db";
import { IMAGE_COMMIT_LABEL, IMAGE_TREE_LABEL, assertImageMatchesTree, collectTreeIdentity, type TreeIdentity } from "./provenance";
import { evaluateDbRun, evaluateNpmTestRun, type NodeTestCounts } from "./results";

const IMAGE = "limitmark-lab-parity:local";
const APP_CONTAINER = "limitmark-lab-app";

type StepResult = {
  id: string; ok: boolean; exitCode: number; seconds: number; counts?: NodeTestCounts; note?: string;
  /** Raw output lines replaced by a marker because they broke an evidence rule. */
  withheldLogLines?: number;
};

const logDirectory = path.join(REPOSITORY_ROOT, "artifacts", "lab", "logs");

/** Containers this process created, removed (ownership re-verified) on crash. */
const liveContainers = new Set<string>();

async function removeOwned(name: string, role: "app" | "parity"): Promise<boolean> {
  try { return await removeLabContainer(name, role); } catch { return false; }
}

type Captured = { exitCode: number; output: string; timedOut: boolean; terminated: boolean | null; withheld: number };

/**
 * Runs a command and records its output SANITIZED (never verbatim). When the command is a container run (`containerName`),
 * a timeout kills the container itself and then verifies that it is gone, instead of trusting that killing the client was enough.
 */
async function runCapture(command: string, args: string[], logName: string, timeoutMs: number, options: { containerName?: string; env?: Record<string, string> } = {}): Promise<Captured> {
  // A docker process is NEVER spawned from here directly: its command line and environment come from the single confinement
  // (verified local endpoint, no ambient selectors or proxies). If verification fails the step fails; nothing runs unconfined.
  let spawned: { command: string; args: string[]; env: NodeJS.ProcessEnv };
  if (command === "docker") {
    try {
      const invocation = await confinedDockerInvocation(args, options.env);
      spawned = { command: invocation.command, args: invocation.args, env: invocation.env as NodeJS.ProcessEnv };
    } catch (error) {
      const log = writeSanitizedLog(logDirectory, logName, `docker confinement refused: ${evidenceSafeError(error)}`);
      return { exitCode: 126, output: "", timedOut: false, terminated: null, withheld: log.withheldLines };
    }
  } else spawned = { command, args, env: { ...process.env, ...options.env } as NodeJS.ProcessEnv };
  return new Promise((resolve) => {
    const child = spawn(spawned.command, spawned.args, { cwd: REPOSITORY_ROOT, env: spawned.env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let output = "";
    let timedOut = false;
    child.stdout.on("data", (chunk) => { output += chunk; });
    child.stderr.on("data", (chunk) => { output += chunk; });
    if (options.containerName) liveContainers.add(options.containerName);
    const finish = async (exitCode: number) => {
      let terminated: boolean | null = null;
      if (options.containerName) {
        // Whatever the outcome, the container must not survive its step; verify instead of assuming.
        if (timedOut) {
          await removeOwned(options.containerName, "parity");
          terminated = await containerExists(options.containerName).then((exists) => !exists, () => false);
        } else terminated = true;
        liveContainers.delete(options.containerName);
      }
      const log = writeSanitizedLog(logDirectory, logName, output + (timedOut ? "\n[parity] timed out\n" : ""));
      resolve({ exitCode, output, timedOut, terminated, withheld: log.withheldLines });
    };
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
    child.on("close", (code) => { clearTimeout(timer); void finish(timedOut ? 124 : code ?? 1); });
    child.on("error", () => { clearTimeout(timer); void finish(127); });
  });
}

async function step(id: string, body: () => Promise<{ exitCode: number; output?: string; note?: string; counts?: NodeTestCounts; withheld?: number; failure?: string }>): Promise<StepResult> {
  const started = Date.now();
  const { exitCode, note, counts, withheld, failure } = await body();
  const result: StepResult = {
    id, ok: exitCode === 0 && failure === undefined, exitCode, seconds: Math.round((Date.now() - started) / 100) / 10,
    counts, note: failure ?? note, withheldLogLines: withheld,
  };
  console.log(`${result.ok ? "PASS" : "FAIL"}  ${id} (${result.seconds}s)${result.counts ? ` ${JSON.stringify(result.counts)}` : ""}${result.note ? ` - ${result.note}` : ""}`);
  return result;
}

let sequence = 0;
/** A uniquely named, labelled container for one `docker run` step. */
function parityRun(script: string, extra: string[] = []): { name: string; args: string[] } {
  const name = `limitmark-lab-parity-${process.pid}-${++sequence}`;
  return { name, args: ["run", "--rm", "--name", name, "--label", "limitmark.lab=disposable", "--label", "limitmark.lab.role=parity", "--memory", "4g", ...extra, IMAGE, "sh", "-c", script] };
}

async function main(): Promise<void> {
  const skipBuild = process.argv.includes("--skip-build");
  const evidence = new EvidenceRun("linux-parity", "linux-parity");
  const results: StepResult[] = [];
  const versions: PgVersion[] = ["16", "17"];
  teardownOnCrash(versions, {
    extraCleanup: async () => {
      await Promise.all([...liveContainers].map((name) => removeOwned(name, "parity")));
      await removeOwned(APP_CONTAINER, "app");
    },
  });
  let containerFacts: Record<string, string> = {};
  let provenance: Record<string, unknown> = { buildMode: skipBuild ? "reused" : "built" };
  const identity: TreeIdentity = collectTreeIdentity();

  if (!skipBuild) {
    results.push(await step("image-build-npm-ci-next-build", async () => {
      const r = await runCapture("docker", [
        "build", "--builder", "default", "-f", "lab/linux/Dockerfile", "-t", IMAGE,
        "--label", `${IMAGE_COMMIT_LABEL}=${identity.gitSha}`, "--label", `${IMAGE_TREE_LABEL}=${identity.treeSha256}`, ".",
      ], `${evidence.id}-build.log`, 25 * 60_000);
      // The tree must not have changed while it was being built, or the labels would describe the wrong tree.
      const after = collectTreeIdentity();
      const stable = after.treeSha256 === identity.treeSha256;
      return { exitCode: r.exitCode, withheld: r.withheld, failure: stable ? undefined : "the working tree changed during the build; the image does not correspond to one tree" };
    }));
  }
  if (results.every((r) => r.ok)) {
    // Provenance gate: the image under test must be the image of THIS tree, whether built now or reused.
    try {
      const { stdout } = await docker(["image", "inspect", IMAGE, "--format", "{{json .Config.Labels}}|{{.Id}}"]);
      const [labelsJson, imageId] = stdout.trim().split("|");
      const labels = JSON.parse(labelsJson || "null") as Record<string, string> | null;
      assertImageMatchesTree(labels, identity);
      provenance = { ...provenance, matchesWorkingTree: true, imageId, gitSha: identity.gitSha, treeSha256: identity.treeSha256, dirty: identity.dirty };
    } catch (error) {
      results.push(await step("image-provenance", async () => ({ exitCode: 1, failure: evidenceSafeError(error) })));
    }
  }
  if (results.every((r) => r.ok)) {
    const factsRun = parityRun("echo \"$(. /etc/os-release; echo $PRETTY_NAME)|$(uname -sr)|$(node --version)|$(npm --version)\"");
    const facts = await docker(factsRun.args);
    const [os, kernel, node, npm] = facts.stdout.trim().split("|");
    containerFacts = { containerOs: os, containerKernel: kernel.split(".").slice(0, 2).join("."), containerNode: node, containerNpm: npm };

    for (const [id, script, timeout] of [
      ["typecheck", "npm run typecheck", 10],
      ["lint", "npm run lint", 10],
      ["npm-test", "npm test", 15],
      ["workerd-suites", "npm run test:workers", 25],
    ] as const) {
      results.push(await step(id, async () => {
        const run = parityRun(script);
        const r = await runCapture("docker", run.args, `${evidence.id}-${id}.log`, timeout * 60_000, { containerName: run.name });
        const base = { exitCode: r.exitCode, withheld: r.withheld };
        const termination = r.timedOut && r.terminated !== true ? "timed out and container termination could not be verified" : undefined;
        if (id === "npm-test") {
          const verdict = evaluateNpmTestRun(r.output, r.exitCode);
          return { ...base, counts: verdict.counts, failure: termination ?? verdict.failure };
        }
        return { ...base, failure: termination ?? evaluateGenericRun(r.output) };
      }));
    }

    for (const version of versions) {
      results.push(await step(`db-tests-pg${version}-from-linux-client`, async () => {
        const state = await labDbUp(version);
        try {
          // Share the PG container's network namespace: 127.0.0.1:5432 inside is the lab database.
          const url = migratorUrl(state).replace(`:${state.port}/`, ":5432/");
          const run = parityRun("npm run test:db -- --test-reporter=spec", [
            "--network", `container:${(await inspectContainer(state.container)).id}`, "-e", `TEST_DATABASE_URL=${url}`, "-e", `TEST_DATABASE_PROOF=${state.proofToken}`,
          ]);
          const r = await runCapture("docker", run.args, `${evidence.id}-db-pg${version}.log`, 10 * 60_000, { containerName: run.name });
          const verdict = evaluateDbRun(r.output, r.exitCode);
          const termination = r.timedOut && r.terminated !== true ? "timed out and container termination could not be verified" : undefined;
          return { exitCode: r.exitCode, withheld: r.withheld, counts: verdict.counts, failure: termination ?? verdict.failure };
        } finally { await labDbDown(version).catch(() => undefined); }
      }));
    }

    results.push(await step("app-in-container-http-workloads", async () => {
      // Ownership first: an existing container with this name is removed only if its labels prove the lab created it.
      await removeLabContainer(APP_CONTAINER, "app");
      const created = await docker([
        "run", "-d", "--name", APP_CONTAINER, "--label", "limitmark.lab=disposable", "--label", "limitmark.lab.role=app", "-p", "127.0.0.1:3100:3000",
        "--memory", "2g", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "-e", "NODE_ENV=production", "-e", "REQUEST_SUBMISSION_MODE=demo", "-e", "ALLOW_DEMO_SUBMISSIONS=true",
        "-e", "PUBLIC_DEMO_ORIGIN=http://127.0.0.1:3100", "-e", "PUBLIC_ORIGIN_PROTECTION=disabled",
        IMAGE, "node", "node_modules/next/dist/bin/next", "start", "--hostname", "0.0.0.0", "--port", "3000",
      ]);
      const appId = created.stdout.trim().split("\n").pop() ?? "";
      let exitCode = 0;
      let output = "";
      let withheld = 0;
      try {
        for (let attempt = 0; attempt < 60; attempt++) {
          const probe = await docker(["exec", appId, "node", "-e", "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]).then(() => true, () => false);
          if (probe) break;
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
        const tsx = [path.join("node_modules", "tsx", "dist", "cli.mjs"), "--conditions=react-server", "lab/run.ts"];
        // The HTTP drivers run on THIS host against the container's published loopback port; the destination is proven by --app-container.
        for (const workload of ["connectivity-baseline", "latency-measurement", "demo-submission-post"]) {
          const r = await runCapture(process.execPath, [...tsx, "--target", "local-app-alt", "--workload", workload, "--app-container", APP_CONTAINER], `${evidence.id}-app-${workload}.log`, 5 * 60_000);
          output += `${workload}:${r.exitCode};`;
          withheld += r.withheld;
          if (r.exitCode !== 0) exitCode = 1;
        }
        // k6 (Docker) joins the app container's network namespace: its 127.0.0.1:3000 is the container's app.
        const k6 = await runCapture(process.execPath, [...tsx, "--target", "local-app", "--workload", "latency-measurement", "--engine", "k6", "--k6-netns-container", APP_CONTAINER], `${evidence.id}-app-k6.log`, 5 * 60_000);
        output += `k6:${k6.exitCode};`;
        withheld += k6.withheld;
        if (k6.exitCode !== 0) exitCode = 1;
      } finally {
        const gone = await removeOwned(APP_CONTAINER, "app");
        if (!gone) { output += "app-container-removal-not-verified;"; exitCode = 1; }
      }
      return { exitCode, note: output, withheld };
    }));
  }

  const ok = results.length > 0 && results.every((r) => r.ok);
  evidence.addJsonArtifact("steps.json", JSON.parse(JSON.stringify({ steps: results })));
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(), target: { id: "linux-container", class: "lab-local" },
    workload: { id: "linux-parity", phases: results.map((r) => ({ name: r.id })) }, ceilings: null, thresholds: null, engine: "docker",
    result: ok ? "PASS" : "FAIL", resultReasons: results.filter((r) => !r.ok).map((r) => `${r.id} failed`),
    metrics: {
      steps: results.length, passed: results.filter((r) => r.ok).length, ...containerFacts, provenance,
      // The image tests run in Linux containers; the Node HTTP load drivers and this orchestrator run on the host.
      httpDriverRuntime: `host-${process.platform}`,
      scope: "container parity only; does not prove VM, kernel, network or field parity",
    },
  });
  console.log(`linux parity: ${ok ? "PASS" : "FAIL"} evidence=${evidence.id}`);
  process.exit(ok ? 0 : 1);
}

/** Non-test steps (typecheck, lint, workerd): a clean exit is necessary, and the known postgres.js defect is never tolerated. */
function evaluateGenericRun(output: string): string | undefined {
  return /Cannot read properties of null \(reading 'write'\)/.test(output) ? "known postgres.js defect observed in the output (a finding; never a pass)" : undefined;
}

if (require.main === module) {
  main().catch((error) => { console.error(error instanceof Error ? error.message : error); process.exit(1); });
}
