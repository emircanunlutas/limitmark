// R10: the obsolete Gate 4B staging admission live verifier is RETIRED. Same
// harness as the Gate 8 Phase 1A closed-verifier test: the real script is
// bundled with esbuild and run with process.execPath in a throwaway directory;
// every provider-facing builtin (child_process, net, http, https, tls, dns, fs,
// worker_threads) is replaced by a trap that records its own import or use, and
// global fetch/WebSocket are trapped too. The former implementation imported
// node:child_process and the lifecycle contract at module load, so it could
// not produce the empty trace or the empty module graph asserted here. No
// Wrangler, network, credential or config is ever reachable.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { build, type Metafile, type Plugin } from "esbuild";

const root = process.cwd();
const script = "scripts/authority-staging-admission-live-verify.ts";
const refusal = "REFUSED: the Gate 4B staging admission live-verify entry point is RETIRED. The staging authority is initialized, " +
  "and the Wrangler preview transport it used can register a workers.dev subdomain and upload a temporary preview Worker. " +
  "No provider was contacted, nothing was spawned, and this is not a health check.\n";
const trapped = ["child_process", "net", "http", "https", "http2", "tls", "dns", "fs", "fs/promises", "worker_threads", "dgram"];
const banner = `const __r10Fs = require("node:fs");
globalThis.__r10RealRequire = require;
globalThis.__r10Trap = (event) => __r10Fs.appendFileSync(process.env.R10_TRACE, event + "\\n");
globalThis.fetch = (...args) => { globalThis.__r10Trap("fetch"); throw new Error("trapped"); };
globalThis.WebSocket = class { constructor() { globalThis.__r10Trap("websocket"); throw new Error("trapped"); } };`;

const trapPlugin: Plugin = { name: "r10-traps", setup(api) {
  api.onResolve({ filter: /^node:/ }, (args) => trapped.includes(args.path.slice(5))
    ? { path: args.path, namespace: "r10-trap" } : { path: args.path, external: true });
  api.onLoad({ filter: /.*/, namespace: "r10-trap" }, (args) => ({ loader: "js", contents:
    `globalThis.__r10Trap("import ${args.path}");
module.exports = Object.fromEntries(Object.keys(globalThis.__r10RealRequire("${args.path}")).map((name) => [name, () => {
  globalThis.__r10Trap("call ${args.path} " + name); throw new Error("trapped"); }]));` }));
} };

let directory: string;
let cli: string;
let metafile: Metafile;
before(async () => {
  directory = await mkdtemp(join(tmpdir(), "r10-live-verify-"));
  assert.ok(!resolve(directory).startsWith(resolve(root)), "sandbox must be outside the repository");
  const result = await build({ entryPoints: [resolve(root, script)], bundle: true, write: false, platform: "node", format: "cjs",
    target: "node24", plugins: [trapPlugin], banner: { js: banner }, metafile: true, logLevel: "silent" });
  metafile = result.metafile;
  cli = join(directory, "live-verify.cjs");
  await writeFile(cli, result.outputFiles[0].contents);
});
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });

type Run = { status: number | null; stdout: string; stderr: string; trace: string[]; created: string[] };
async function run(args: string[], extra: Record<string, string> = {}): Promise<Run> {
  const trace = join(directory, "trace.txt");
  await writeFile(trace, "");
  const before = (await readdir(directory)).sort();
  const environment: NodeJS.ProcessEnv = { ...process.env };
  for (const name of Object.keys(environment))
    if (/^(CLOUDFLARE_|CF_|WRANGLER_|AUTHORITY_|GATE8_|R10_)/iu.test(name)) delete environment[name];
  const result = spawnSync(process.execPath, [cli, ...args], { cwd: directory, encoding: "utf8", timeout: 20_000,
    env: Object.assign(environment, extra, { R10_TRACE: trace }) });
  const after = (await readdir(directory)).sort();
  return { status: result.status, stdout: result.stdout, stderr: result.stderr,
    trace: (await readFile(trace, "utf8")).split("\n").filter(Boolean), created: after.filter((name) => !before.includes(name)) };
}

const syntheticSecret = "r10-synthetic-secret-marker-4c1e";
const validDigest = "f14876a5367f3d5d97d562119203b346159117814b23232ff84958ee36d18bcf";
function assertRetired(result: Run, context: string): void {
  assert.equal(result.status, 2, `${context}: deterministic nonzero exit`);
  assert.equal(result.stdout, "", `${context}: no stdout`);
  assert.equal(result.stderr, refusal, `${context}: fixed refusal only`);
  assert.deepEqual(result.trace, [], `${context}: no spawn, socket, fetch, file or credential access`);
  assert.deepEqual(result.created, [], `${context}: no file or config state created`);
  assert.equal(`${result.stdout}${result.stderr}`.includes(syntheticSecret), false, `${context}: nothing inherited is echoed`);
}

test("R10-0 control: the traps do fire for code that reaches spawn, sockets, files or fetch", async () => {
  const result = await build({ stdin: { contents: `import { spawn } from "node:child_process"; import { connect } from "node:net";
import { readFileSync } from "node:fs";
for (const attempt of [() => spawn("wrangler"), () => connect(443), () => readFileSync("key"), () => fetch("https://example.invalid")])
  try { attempt(); } catch {}`, resolveDir: root, loader: "ts" }, bundle: true, write: false, platform: "node", format: "cjs",
  target: "node24", plugins: [trapPlugin], banner: { js: banner }, logLevel: "silent" });
  const control = join(directory, "control.cjs");
  await writeFile(control, result.outputFiles[0].contents);
  const trace = join(directory, "control-trace.txt");
  await writeFile(trace, "");
  spawnSync(process.execPath, [control], { cwd: directory, encoding: "utf8", timeout: 20_000, env: { ...process.env, R10_TRACE: trace } });
  assert.deepEqual((await readFile(trace, "utf8")).split("\n").filter(Boolean).sort(), ["call node:child_process spawn",
    "call node:fs readFileSync", "call node:net connect", "fetch", "import node:child_process", "import node:fs", "import node:net"]);
});

test("R10-1: the retired verifier refuses deterministically with no arguments", async () => {
  assertRetired(await run([]), "no arguments");
  assertRetired(await run([]), "repeat");
});

test("R10-2: the former valid invocation and every override attempt stay closed", async () => {
  const pinned = { CLOUDFLARE_ACCOUNT_ID: "a".repeat(32) };
  // The exact argv + account pin the former verifier accepted before launching `wrangler dev`.
  assertRetired(await run(["--digest", validDigest], pinned), "former valid invocation");
  for (const args of [["--force"], ["--override"], ["--unlock"], ["--open"], ["--digest", validDigest, "--force"],
    ["--config", "wrangler.staging-admission-live-readonly.local.jsonc"], ["--port", "8800"], ["--remote"], ["--", "--digest", validDigest]])
    assertRetired(await run(args, pinned), args.join(" "));
});

test("R10-3: no provider or operator environment variable opens it or is read", async () => {
  const environments: Array<Record<string, string>> = [
    { CLOUDFLARE_ACCOUNT_ID: "b".repeat(32), CLOUDFLARE_API_TOKEN: syntheticSecret, WRANGLER_SEND_METRICS: "true" },
    { LIVE_VERIFY_FORCE: "1", GATE4B_LIVE_VERIFY: "open", FORCE: "1" },
    { AUTHORITY_STAGING_OPERATOR_PRIVATE_KEY: syntheticSecret },
    { NODE_ENV: "production", CI: "true" },
  ];
  for (const extra of environments) assertRetired(await run(["--digest", validDigest], extra), Object.keys(extra).join(","));
});

test("R10-4: the bundled module graph is the script alone, with no import at all", () => {
  const inputs = Object.keys(metafile.inputs).map((path) => path.replace(/\\/gu, "/"));
  assert.deepEqual(inputs, [script], "no lifecycle contract, Wrangler, process, network or credential module");
  const imports = Object.values(metafile.inputs).flatMap((input) => input.imports.map((entry) => entry.path));
  assert.deepEqual(imports, [], `unexpected import: ${imports.join(", ")}`);
});

test("R10-5: the source is an unconditional refusal and the npm entry point is preserved", async () => {
  const source = await readFile(join(root, script), "utf8");
  const code = source.split("\n").filter((line) => line.trim() && !line.trim().startsWith("//"));
  assert.deepEqual(code, [`process.stderr.write(${JSON.stringify(refusal)});`, "process.exitCode = 2;"],
    "no import, argument/environment read, branch, mutable state or dormant launch code");
  const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8")) as { scripts: Record<string, string> };
  assert.equal(packageJson.scripts["authority:staging:admission:live-verify"], `tsx ${script}`);
});

test("R10-6: the fixed refusal is bounded and exposes no host, URL, token or snapshot data", () => {
  assert.ok(refusal.startsWith("REFUSED: ") && refusal.endsWith("\n") && refusal.length < 600);
  assert.equal(refusal.split("\n").length, 2, "exactly one line");
  assert.equal(/https?:|\/\/|[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev|[A-Za-z0-9_-]{32,}|[a-f0-9]{16,}/u.test(refusal), false);
  for (const internal of ["initialized\":", "NOT_FOUND", "releases", "staging-public-inquiries", "accountFingerprint"])
    assert.equal(refusal.includes(internal), false, `refusal must not carry ${internal}`);
  assert.match(refusal, /RETIRED/u);
  assert.match(refusal, /No provider was contacted/u);
});
