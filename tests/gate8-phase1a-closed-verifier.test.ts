// Gate 8 Phase 1A: the operator continuity verifier is structurally CLOSED. The
// real script is bundled with esbuild and run with process.execPath in a
// throwaway directory; every provider-facing builtin (child_process, net, http,
// https, tls, dns, fs, worker_threads) is replaced by a trap that records its
// own import or use, and global fetch/WebSocket are trapped too. No Wrangler,
// network, credential, key, manifest or artifact is ever reachable.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { build, type Metafile, type Plugin } from "esbuild";
import { STAGING_CONTINUITY_TRANSPORT_REFUSAL } from "../operator/staging-gate7-continuity";

const root = process.cwd();
const script = "scripts/authority-staging-continuity-verify.ts";
const trapped = ["child_process", "net", "http", "https", "http2", "tls", "dns", "fs", "fs/promises", "worker_threads", "dgram"];
const banner = `const __phase1aFs = require("node:fs");
globalThis.__phase1aRealRequire = require;
globalThis.__phase1aTrap = (event) => __phase1aFs.appendFileSync(process.env.PHASE1A_TRACE, event + "\\n");
globalThis.fetch = (...args) => { globalThis.__phase1aTrap("fetch"); throw new Error("trapped"); };
globalThis.WebSocket = class { constructor() { globalThis.__phase1aTrap("websocket"); throw new Error("trapped"); } };`;

const trapPlugin: Plugin = { name: "phase1a-traps", setup(api) {
  api.onResolve({ filter: /^node:/ }, (args) => trapped.includes(args.path.slice(5))
    ? { path: args.path, namespace: "phase1a-trap" } : { path: args.path, external: true });
  api.onLoad({ filter: /.*/, namespace: "phase1a-trap" }, (args) => ({ loader: "js", contents:
    `globalThis.__phase1aTrap("import ${args.path}");
module.exports = Object.fromEntries(Object.keys(globalThis.__phase1aRealRequire("${args.path}")).map((name) => [name, () => {
  globalThis.__phase1aTrap("call ${args.path} " + name); throw new Error("trapped"); }]));` }));
} };

let directory: string;
let cli: string;
let metafile: Metafile;
before(async () => {
  directory = await mkdtemp(join(tmpdir(), "gate8-phase1a-verifier-"));
  assert.ok(!resolve(directory).startsWith(resolve(root)), "sandbox must be outside the repository");
  const result = await build({ entryPoints: [resolve(root, script)], bundle: true, write: false, platform: "node", format: "cjs",
    target: "node24", plugins: [trapPlugin], banner: { js: banner }, metafile: true, logLevel: "silent" });
  metafile = result.metafile;
  cli = join(directory, "continuity-verify.cjs");
  await writeFile(cli, result.outputFiles[0].contents);
});
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });

type Run = { status: number | null; stdout: string; stderr: string; trace: string[] };
async function run(args: string[], extra: Record<string, string> = {}): Promise<Run> {
  const trace = join(directory, "trace.txt");
  await writeFile(trace, "");
  const environment: NodeJS.ProcessEnv = { ...process.env };
  for (const name of Object.keys(environment))
    if (/^(CLOUDFLARE_|CF_|WRANGLER_|AUTHORITY_|GATE8_|PHASE1A_)/iu.test(name)) delete environment[name];
  const result = spawnSync(process.execPath, [cli, ...args], { cwd: directory, encoding: "utf8", timeout: 20_000,
    env: Object.assign(environment, extra, { PHASE1A_TRACE: trace }) });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr,
    trace: (await readFile(trace, "utf8")).split("\n").filter(Boolean) };
}

const syntheticSecret = "phase1a-synthetic-secret-marker-7b2d";
function assertClosed(result: Run, context: string): void {
  assert.equal(result.status, 2, `${context}: deterministic nonzero exit`);
  assert.equal(result.stdout, "", `${context}: no stdout`);
  assert.equal(result.stderr, STAGING_CONTINUITY_TRANSPORT_REFUSAL, `${context}: fixed refusal only`);
  assert.deepEqual(result.trace, [], `${context}: no spawn, socket, fetch, file or credential access`);
  assert.equal(`${result.stdout}${result.stderr}`.includes(syntheticSecret), false, `${context}: nothing inherited is echoed`);
}

test("V0 control: the traps do fire for code that reaches spawn, sockets, files or fetch", async () => {
  const result = await build({ stdin: { contents: `import { spawn } from "node:child_process"; import { connect } from "node:net";
import { readFileSync } from "node:fs";
for (const attempt of [() => spawn("wrangler"), () => connect(443), () => readFileSync("key"), () => fetch("https://example.invalid")])
  try { attempt(); } catch {}`, resolveDir: root, loader: "ts" }, bundle: true, write: false, platform: "node", format: "cjs",
  target: "node24", plugins: [trapPlugin], banner: { js: banner }, logLevel: "silent" });
  const control = join(directory, "control.cjs");
  await writeFile(control, result.outputFiles[0].contents);
  const trace = join(directory, "control-trace.txt");
  await writeFile(trace, "");
  spawnSync(process.execPath, [control], { cwd: directory, encoding: "utf8", timeout: 20_000, env: { ...process.env, PHASE1A_TRACE: trace } });
  assert.deepEqual((await readFile(trace, "utf8")).split("\n").filter(Boolean).sort(), ["call node:child_process spawn",
    "call node:fs readFileSync", "call node:net connect", "fetch", "import node:child_process", "import node:fs", "import node:net"]);
});

test("V1: the verifier refuses deterministically with no arguments", async () => {
  const first = await run([]);
  assertClosed(first, "no arguments");
  assertClosed(await run([]), "repeat");
});

test("V2: no flag, override or digest/account/target argument opens it", async () => {
  for (const args of [["--force"], ["--override"], ["--skip-subdomain-check"], ["--unlock"], ["--open"],
    ["--digest", "f14876a5367f3d5d97d562119203b346159117814b23232ff84958ee36d18bcf"], ["--account", "a".repeat(32)],
    ["--target", "limitmark-admission-service-staging"], ["--config", "wrangler.staging-admission-live-readonly.local.jsonc"],
    ["--port", "8801"], ["--subdomain-verified"], ["--", "--force"]])
    assertClosed(await run(args), args.join(" "));
});

test("V3: no provider or operator environment variable opens it or is read", async () => {
  const environments: Array<Record<string, string>> = [
    { CLOUDFLARE_ACCOUNT_ID: "a".repeat(32) },
    { CLOUDFLARE_ACCOUNT_ID: "b".repeat(32), CLOUDFLARE_API_TOKEN: syntheticSecret, WRANGLER_SEND_METRICS: "true" },
    { STAGING_CONTINUITY_TRANSPORT: "OPEN", GATE8_CONTINUITY_TRANSPORT: "open", CONTINUITY_FORCE: "1", FORCE: "1" },
    { SKIP_SUBDOMAIN_CHECK: "1", WORKERS_DEV_SUBDOMAIN_VERIFIED: "true", AUTHORITY_STAGING_OPERATOR_PRIVATE_KEY: syntheticSecret },
    { NODE_ENV: "production", CI: "true" },
  ];
  for (const extra of environments) assertClosed(await run([], extra), Object.keys(extra).join(","));
});

test("V4: the bundled module graph contains no provider, process, network or credential code", () => {
  const inputs = Object.keys(metafile.inputs).map((path) => path.replace(/\\/gu, "/"));
  assert.deepEqual(inputs.sort(), ["deployment/lifecycle-private-contract.ts", "operator/staging-gate7-continuity.ts",
    "scripts/authority-staging-continuity-verify.ts", "src/lib/ingress-protocol.ts"]);
  const imports = Object.values(metafile.inputs).flatMap((input) => input.imports.map((entry) => entry.path));
  assert.equal(imports.some((path) => path.startsWith("node:") || /wrangler|undici|r2-transport|credential|manifest/iu.test(path)), false,
    `unexpected import: ${imports.join(", ")}`);
});

test("V5: the verifier source has one import, no branch, and no provider/escape surface", async () => {
  const source = await readFile(join(root, script), "utf8");
  const code = source.split("\n").filter((line) => line.trim() && !line.trim().startsWith("//"));
  assert.deepEqual(code, [
    'import { STAGING_CONTINUITY_TRANSPORT_REFUSAL } from "../operator/staging-gate7-continuity";',
    "process.stderr.write(STAGING_CONTINUITY_TRANSPORT_REFUSAL);",
    "process.exitCode = 2;",
  ], "unconditional refusal: no argument/environment read, no mutable state, no dormant launch code");
  const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8")) as { scripts: Record<string, string> };
  assert.equal(packageJson.scripts["authority:staging:continuity:verify"], `tsx ${script}`);
});

test("V6: the fixed refusal is bounded and exposes no host, URL, token or snapshot data", () => {
  const refusal = STAGING_CONTINUITY_TRANSPORT_REFUSAL;
  assert.ok(refusal.startsWith("REFUSED: ") && refusal.endsWith("\n") && refusal.length < 600);
  assert.equal(refusal.split("\n").length, 2, "exactly one line");
  assert.equal(/https?:|\/\/|[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev|[A-Za-z0-9_-]{32,}|[a-f0-9]{16,}/u.test(refusal), false);
  for (const internal of ["EXACT_RECEIPT", "keyFingerprint", "releases", "staging-gate7", "observedAtMs"])
    assert.equal(refusal.includes(internal), false, `refusal must not carry ${internal}`);
  assert.match(refusal, /CLOSED \/ TOOLING REQUIRED/u);
  assert.match(refusal, /no provider was contacted/u);
});
