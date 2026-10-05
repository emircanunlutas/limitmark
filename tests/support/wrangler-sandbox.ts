import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { REVIEWED_WRANGLER_VERSION } from "../../operator/staging-wrangler-pin";

// Gate 7B test-only Wrangler isolation, shared by every Gate 4/5/7 test that
// runs a staging deploy wrapper in "deploy" mode.
//
// Every staging deploy wrapper spawns exactly
//   realpath(join(process.cwd(), "node_modules", "wrangler", "bin", "wrangler.js"))
// so a wrapper started with its working directory set to a throwaway sandbox
// spawns the sandbox's file at that path, never the repository's pinned
// Wrangler. The sandbox file is a fake Wrangler: it only records its argv to
// a file and exits 0. It never loads Wrangler, reads auth or opens a socket.
// Nothing here changes the wrappers themselves.
//
// Fail-closed self-test, run before EVERY wrapper invocation, in the exact
// environment the wrapper will receive:
//   1. resolve the spawn target with the wrappers' own formula (realpath of
//      <sandbox>/node_modules/wrangler/bin/wrangler.js);
//   2. require it to be outside the repository and not the repository's real
//      Wrangler (exact resolved-path comparison, case-insensitive on Windows
//      -- no separator regex);
//   3. require its bytes to equal the fake's source exactly, BEFORE anything
//      executes it (so a real or altered Wrangler there is never run);
//   4. execute that exact file with the identical environment and require the
//      fake's own record (argv ["--gate7b-self-test"], exit 0).
// Any failure throws before the wrapper is started. The wrapper's child
// environment also drops every inherited CLOUDFLARE_* variable except the
// ones the test sets explicitly, and points XDG_CONFIG_HOME into the sandbox.

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const tsxCli = path.join(repositoryRoot, "node_modules", "tsx", "dist", "cli.mjs");
const wranglerSegments = ["node_modules", "wrangler", "bin", "wrangler.js"] as const;
const recordEnv = "LIMITMARK_FAKE_WRANGLER_RECORD";
const selfTestArg = "--gate7b-self-test";

export const FAKE_WRANGLER_SOURCE = `"use strict";
// Gate 7B test-only fake Wrangler (tests/support/wrangler-sandbox.ts). Records
// its argv and exits; it never loads Wrangler, reads credentials or uses the network.
const record = process.env.${recordEnv};
if (!record) { process.stderr.write("fake wrangler: no record path\\n"); process.exit(98); }
require("node:fs").writeFileSync(record, JSON.stringify({ argv: process.argv.slice(2) }), { flag: "wx" });
`;

/** R06 activation (T8): opt-in recording fake for the one wrapper that spawns Wrangler SEVERAL times and passes a value on stdin
 * (operator/staging-attestation-secret-engine.ts). It appends one JSON line per invocation -- argv, stdin text, the working directory and
 * the COMPLETE environment it received -- and never loads Wrangler, reads credentials or uses the network. The default fake above is unchanged.
 *
 * The wrapper's child environment is minimal and explicit (it deliberately does NOT contain a test-only record variable), so this fake finds
 * its record file and its optional fail-on control file relative to its OWN location: <sandbox>/node_modules/wrangler/bin/wrangler.js ->
 * <sandbox>/fake-wrangler-record.jsonl and <sandbox>/fake-wrangler-fail-on. */
export const FAKE_WRANGLER_RECORDING_SOURCE = `"use strict";
// Gate 7B / R06 test-only RECORDING fake Wrangler (tests/support/wrangler-sandbox.ts). It never loads Wrangler or touches the network.
const fs = require("node:fs");
const path = require("node:path");
const sandbox = path.resolve(__dirname, "..", "..", "..");
const record = path.join(sandbox, "fake-wrangler-record.jsonl");
let stdin = "";
try { stdin = fs.readFileSync(0, "utf8"); } catch { stdin = ""; }
fs.appendFileSync(record, JSON.stringify({ argv: process.argv.slice(2), stdin, cwd: process.cwd(), env: process.env }) + "\\n");
// One-shot sabotage hook for tests: <sandbox>/fake-wrangler-sabotage.json = {"path","content"[,"onInvocation"]} is applied during the first
// invocation that sees it (then removed), or -- when "onInvocation" is N -- during the Nth recorded invocation, so a test can change the
// filesystem between any two spawns of the same wrapper call.
try {
  const control = path.join(sandbox, "fake-wrangler-sabotage.json");
  const sabotage = JSON.parse(fs.readFileSync(control, "utf8"));
  const invocation = fs.readFileSync(record, "utf8").split("\\n").filter(Boolean).length;
  if (invocation >= (sabotage.onInvocation ?? 1)) {
    fs.rmSync(control);
    fs.mkdirSync(path.dirname(sabotage.path), { recursive: true });
    fs.writeFileSync(sabotage.path, sabotage.content);
  }
} catch { /* no sabotage requested */ }
let failOn = "";
try { failOn = fs.readFileSync(path.join(sandbox, "fake-wrangler-fail-on"), "utf8").trim(); } catch { failOn = ""; }
if (failOn && process.argv.includes(failOn)) process.exit(7);
`;

/** Main files the wrappers realpath() (existence only; never executed). */
const wrapperMainStubs = [
  ["workers", "admission-service", "index.ts"],
  ["workers", "staging-operator-lifecycle-executor.ts"],
  ["workers", "lifecycle-mailbox", "staging-index.ts"],
  ["workers", "staging-lifecycle-observer.ts"],
];

type PathApi = Pick<typeof path, "resolve" | "relative" | "isAbsolute" | "sep">;

/** Exact resolved-path equality; case-insensitive for Windows path semantics. */
export function sameResolvedPath(a: string, b: string, api: PathApi = path, caseInsensitive = process.platform === "win32"): boolean {
  const [x, y] = [api.resolve(a), api.resolve(b)];
  return caseInsensitive ? x.toLowerCase() === y.toLowerCase() : x === y;
}

/** True when `child` is `parent` or lies beneath it (resolved, not textual). */
export function isWithinPath(child: string, parent: string, api: PathApi = path, caseInsensitive = process.platform === "win32"): boolean {
  const fold = (value: string) => caseInsensitive ? api.resolve(value).toLowerCase() : api.resolve(value);
  const relative = api.relative(fold(parent), fold(child));
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${api.sep}`) && !api.isAbsolute(relative));
}

export type FakeWranglerRecord = { argv: string[] } | null;
export type FakeWranglerInvocation = { argv: string[]; stdin: string; cwd: string; env: Record<string, string> };
export type WrapperRun = { result: SpawnSyncReturns<string>; wrangler: FakeWranglerRecord;
  /** Recording sandbox only: every invocation in order (empty for the default single-record fake). */
  invocations: FakeWranglerInvocation[] };

export type WranglerSandbox = {
  root: string;
  /** The path at which the fake is installed (exposed for sabotage tests only). */
  fakeWranglerPath: string;
  writeDeploymentFile(name: string, contents: string): Promise<string>;
  /** Self-test, then run `node tsx <script> ...args` with cwd = sandbox root.
   * `script` is repository-relative or absolute. */
  runWrapper(script: string, args: string[], overrides?: Record<string, string | undefined>): Promise<WrapperRun>;
};

function childEnvironment(root: string, record: string, overrides: Record<string, string | undefined>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) if (key.toUpperCase().startsWith("CLOUDFLARE_")) delete env[key];
  delete env.NODE_TEST_CONTEXT;
  Object.assign(env, { XDG_CONFIG_HOME: path.join(root, "config"), WRANGLER_SEND_METRICS: "false", [recordEnv]: record }, overrides);
  for (const [key, value] of Object.entries(env)) if (value === undefined) delete env[key];
  return env;
}

async function readRecord(record: string): Promise<FakeWranglerRecord> {
  let text: string;
  try { text = await readFile(record, "utf8"); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return null; throw error; }
  finally { await rm(record, { force: true }); }
  return JSON.parse(text) as FakeWranglerRecord;
}

async function readInvocations(record: string): Promise<FakeWranglerInvocation[]> {
  let text: string;
  try { text = await readFile(record, "utf8"); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return []; throw error; }
  finally { await rm(record, { force: true }); }
  return text.split("\n").filter(Boolean).map((line) => JSON.parse(line) as FakeWranglerInvocation);
}

/** Exported for the broken-detector regression test; throws on any failure. `expectedSource` defaults to the single-record fake. */
export async function selfTestWranglerSandbox(root: string, env: Record<string, string | undefined>, expectedSource: string = FAKE_WRANGLER_SOURCE): Promise<void> {
  const recording = expectedSource === FAKE_WRANGLER_RECORDING_SOURCE;
  // The recording fake locates its record next to itself; the default fake still takes it from the environment.
  const record = recording ? path.join(root, "fake-wrangler-record.jsonl") : env[recordEnv];
  if (!record) throw new Error("wrangler-sandbox-self-test: no record path");
  let target: string;
  try { target = await realpath(path.join(root, ...wranglerSegments)); }
  catch { throw new Error("wrangler-sandbox-self-test: fake wrangler missing"); }
  let realWrangler: string | null = null;
  try { realWrangler = await realpath(path.join(repositoryRoot, ...wranglerSegments)); } catch { /* not installed: nothing to collide with */ }
  if (isWithinPath(target, repositoryRoot) || (realWrangler !== null && sameResolvedPath(target, realWrangler)))
    throw new Error("wrangler-sandbox-self-test: spawn target resolves to the repository or its real Wrangler");
  if (await readFile(target, "utf8") !== expectedSource)
    throw new Error("wrangler-sandbox-self-test: spawn target is not the fake wrangler");
  await rm(record, { force: true });
  const probe = spawnSync(process.execPath, [target, selfTestArg], { cwd: root, encoding: "utf8", env: env as NodeJS.ProcessEnv, timeout: 30_000 });
  const observed = recording ? JSON.stringify((await readInvocations(record)).map(({ argv, stdin }) => ({ argv, stdin }))) : JSON.stringify(await readRecord(record));
  const expected = recording ? JSON.stringify([{ argv: [selfTestArg], stdin: "" }]) : JSON.stringify({ argv: [selfTestArg] });
  if (probe.status !== 0 || observed !== expected)
    throw new Error("wrangler-sandbox-self-test: fake wrangler did not record the probe");
}

export async function withWranglerSandbox<T>(fn: (sandbox: WranglerSandbox) => Promise<T>, options: { recording?: boolean } = {}): Promise<T> {
  const fakeSource = options.recording ? FAKE_WRANGLER_RECORDING_SOURCE : FAKE_WRANGLER_SOURCE;
  const root = await realpath(await mkdtemp(path.join(tmpdir(), "gate7b-wrangler-sandbox-")));
  try {
    const fakeWranglerPath = path.join(root, ...wranglerSegments);
    await mkdir(path.dirname(fakeWranglerPath), { recursive: true });
    await writeFile(fakeWranglerPath, fakeSource);
    if (options.recording) {
      // The secret engine proves the reviewed Wrangler version at the point of use (package.json, lock and installed package).
      await writeFile(path.join(root, "node_modules", "wrangler", "package.json"), JSON.stringify({ name: "wrangler", version: REVIEWED_WRANGLER_VERSION }));
      await writeFile(path.join(root, "package.json"), JSON.stringify({ name: "sandbox", devDependencies: { wrangler: REVIEWED_WRANGLER_VERSION } }));
      await writeFile(path.join(root, "package-lock.json"), JSON.stringify({ packages: { "node_modules/wrangler": { version: REVIEWED_WRANGLER_VERSION } } }));
    }
    await mkdir(path.join(root, "deployment"));
    for (const segments of wrapperMainStubs) {
      await mkdir(path.join(root, ...segments.slice(0, -1)), { recursive: true });
      await writeFile(path.join(root, ...segments), "");
    }
    const record = path.join(root, options.recording ? "fake-wrangler-record.jsonl" : "fake-wrangler-record.json");
    const sandbox: WranglerSandbox = {
      root,
      fakeWranglerPath,
      async writeDeploymentFile(name, contents) {
        const file = path.join(root, "deployment", name);
        await writeFile(file, contents);
        return file;
      },
      async runWrapper(script, args, overrides = {}) {
        const env = childEnvironment(root, record, overrides);
        await selfTestWranglerSandbox(root, env, fakeSource);
        const scriptPath = path.isAbsolute(script) ? script : path.join(repositoryRoot, script);
        const result = spawnSync(process.execPath, [tsxCli, scriptPath, ...args], { cwd: root, encoding: "utf8", env, timeout: 120_000 });
        return options.recording ? { result, wrangler: null, invocations: await readInvocations(record) }
          : { result, wrangler: await readRecord(record), invocations: [] };
      },
    };
    return await fn(sandbox);
  } finally { await rm(root, { recursive: true, force: true }); }
}
