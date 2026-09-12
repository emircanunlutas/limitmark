import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encodeBase64url } from "../../src/lib/ingress-protocol";

const port = 8797;
const root = `http://127.0.0.1:${port}`;
const releaseId = "dpl_local_review";
const processOutput = new WeakMap<ChildProcess, string[]>();
const opaque = (length: number, seed: number) => {
  const bytes = Uint8Array.from({ length }, (_, index) => (seed + index * 31) & 255);
  new DataView(bytes.buffer).setUint32(length - 4, seed >>> 0);
  return encodeBase64url(bytes);
};

async function waitForReady(child: ChildProcess): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null) throw new Error(`wrangler exited early: ${child.exitCode}\n${processOutput.get(child)?.join("") ?? ""}`);
    try { if ((await fetch(`${root}/health`)).ok) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("wrangler local runtime did not become ready");
}

function start(persistPath: string, configPath: string): ChildProcess {
  const child = spawn(process.execPath, [join(process.cwd(), "node_modules/wrangler/bin/wrangler.js"), "dev", "--config", configPath,
    "--ip", "127.0.0.1", "--port", String(port), "--persist-to", persistPath, "--show-interactive-dev-session=false"], {
    cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
    env: { ...process.env, XDG_CONFIG_HOME: join(persistPath, "config"), WRANGLER_SEND_METRICS: "false" },
  });
  const output: string[] = [];
  processOutput.set(child, output);
  child.stdout?.on("data", (chunk) => output.push(String(chunk)));
  child.stderr?.on("data", (chunk) => output.push(String(chunk)));
  return child;
}

async function stop(child: ChildProcess): Promise<void> {
  if (process.platform === "win32" && child.pid) {
    // The PID is the Wrangler process created above; terminate only its local
    // emulator subtree so workerd cannot retain the temporary SQLite files.
    spawnSync("taskkill.exe", ["/pid", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
  } else if (child.exitCode === null) child.kill("SIGTERM");
  if (child.exitCode !== null) return;
  await new Promise<void>((resolve) => { child.once("exit", () => resolve()); setTimeout(resolve, 3_000); });
}

async function call(path: string, body: unknown) {
  const response = await fetch(`${root}${path}`, { method: "POST", signal: AbortSignal.timeout(10_000), headers: { "content-type": "application/json", "x-local-authority-test": "phase5c-i1" }, body: JSON.stringify(body) });
  return { status: response.status, body: await response.json() as Record<string, unknown> };
}

async function main() {
  const temporary = await mkdtemp(join(tmpdir(), "limitmark-do-i1-"));
  const persistPath = join(temporary, "state");
  const configPath = join(process.cwd(), "wrangler.local.jsonc");
  const localConfiguration = JSON.parse(await readFile(configPath, "utf8")) as Record<string, unknown>;
  assert.equal(localConfiguration.workers_dev, false);
  assert.equal(localConfiguration.preview_urls, false);
  let worker = start(persistPath, configPath);
  try {
  await waitForReady(worker);
  const now = Date.now();
  assert.deepEqual(await call("/__local/init", { releaseId, nowMs: now }), { status: 200, body: { initialized: true } });
  const input = { releaseId, clientPseudonym: opaque(32, 1), requestBinding: opaque(32, 2), nonce: opaque(16, 3), issuedAtMs: Date.now() };
  const first = await call("/__local/pre", input);
  assert.equal(first.status, 200);
  assert.equal(first.body.decision, "allowed");
  assert.match(String(first.body.permit), /^[A-Za-z0-9_-]{43}$/);
  assert.equal((await call("/__local/pre", input)).body.decision, "replay");
  const post = { releaseId, clientPseudonym: input.clientPseudonym, requestBinding: input.requestBinding, nonce: input.nonce, permit: first.body.permit };
  assert.equal((await call("/__local/post", post)).body.decision, "allowed");
  assert.equal((await call("/__local/post", post)).body.decision, "replay");
  const unusedInput = { releaseId, clientPseudonym: opaque(32, 11), requestBinding: opaque(32, 12), nonce: opaque(16, 13), issuedAtMs: Date.now() };
  const unusedPre = await call("/__local/pre", unusedInput);
  assert.equal(unusedPre.body.decision, "allowed");
  const unusedPost = { releaseId, clientPseudonym: unusedInput.clientPseudonym, requestBinding: unusedInput.requestBinding,
    nonce: unusedInput.nonce, permit: unusedPre.body.permit };
  const concurrent: Array<{ status: number; body: Record<string, unknown> }> = [];
  for (let offset = 0; offset < 320; offset += 40) {
    concurrent.push(...await Promise.all(Array.from({ length: Math.min(40, 320 - offset) }, (_, relative) => {
      const index = offset + relative;
      return call("/__local/pre", { releaseId, clientPseudonym: opaque(32, 1000 + index), requestBinding: opaque(32, 2000 + index),
        nonce: opaque(16, 3000 + index), issuedAtMs: Date.now() });
    })));
  }
  assert.equal(concurrent.filter((result) => result.body.decision === "allowed").length, 298);
  assert.equal(concurrent.filter((result) => result.body.decision === "limited").length, 22);
  const beforeRestart = await call("/__local/state", {});
  assert.deepEqual(beforeRestart.body, { preClient: 300, preGlobal: 300, postClient: 1, postGlobal: 1, nonces: 300, postConsumed: 1 });

  await stop(worker);
  worker = start(persistPath, configPath);
  await waitForReady(worker);
  assert.deepEqual((await call("/__local/state", {})).body, beforeRestart.body);
  assert.equal((await call("/__local/pre", { ...input, issuedAtMs: Date.now() })).body.decision, "replay");
  assert.equal((await call("/__local/post", post)).body.decision, "replay");
  assert.equal((await call("/__local/post", unusedPost)).body.decision, "allowed");
  assert.equal((await call("/__local/pre", { ...unusedInput, issuedAtMs: Date.now() })).body.decision, "replay");
  assert.deepEqual((await call("/__local/state", {})).body,
    { preClient: 300, preGlobal: 300, postClient: 2, postGlobal: 2, nonces: 300, postConsumed: 2 });
  const afterRestartNew = { releaseId, clientPseudonym: opaque(32, 21), requestBinding: opaque(32, 22), nonce: opaque(16, 23), issuedAtMs: Date.now() };
  assert.equal((await call("/__local/pre", afterRestartNew)).body.decision, "limited");
  } finally {
    await stop(worker);
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    await rm(temporary, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
  }
  console.log("Cloudflare local DO integration: PASS (nonce, permit, PRE/POST history and consumed POST survived runtime restart)");
}

void main();
