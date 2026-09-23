import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

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
export type WrapperRun = { result: SpawnSyncReturns<string>; wrangler: FakeWranglerRecord };

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

/** Exported for the broken-detector regression test; throws on any failure. */
export async function selfTestWranglerSandbox(root: string, env: Record<string, string | undefined>): Promise<void> {
  const record = env[recordEnv];
  if (!record) throw new Error("wrangler-sandbox-self-test: no record path");
  let target: string;
  try { target = await realpath(path.join(root, ...wranglerSegments)); }
  catch { throw new Error("wrangler-sandbox-self-test: fake wrangler missing"); }
  let realWrangler: string | null = null;
  try { realWrangler = await realpath(path.join(repositoryRoot, ...wranglerSegments)); } catch { /* not installed: nothing to collide with */ }
  if (isWithinPath(target, repositoryRoot) || (realWrangler !== null && sameResolvedPath(target, realWrangler)))
    throw new Error("wrangler-sandbox-self-test: spawn target resolves to the repository or its real Wrangler");
  if (await readFile(target, "utf8") !== FAKE_WRANGLER_SOURCE)
    throw new Error("wrangler-sandbox-self-test: spawn target is not the fake wrangler");
  await rm(record, { force: true });
  const probe = spawnSync(process.execPath, [target, selfTestArg], { cwd: root, encoding: "utf8", env: env as NodeJS.ProcessEnv, timeout: 30_000 });
  const observed = await readRecord(record);
  if (probe.status !== 0 || JSON.stringify(observed) !== JSON.stringify({ argv: [selfTestArg] }))
    throw new Error("wrangler-sandbox-self-test: fake wrangler did not record the probe");
}

export async function withWranglerSandbox<T>(fn: (sandbox: WranglerSandbox) => Promise<T>): Promise<T> {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), "gate7b-wrangler-sandbox-")));
  try {
    const fakeWranglerPath = path.join(root, ...wranglerSegments);
    await mkdir(path.dirname(fakeWranglerPath), { recursive: true });
    await writeFile(fakeWranglerPath, FAKE_WRANGLER_SOURCE);
    await mkdir(path.join(root, "deployment"));
    for (const segments of wrapperMainStubs) {
      await mkdir(path.join(root, ...segments.slice(0, -1)), { recursive: true });
      await writeFile(path.join(root, ...segments), "");
    }
    const record = path.join(root, "fake-wrangler-record.json");
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
        await selfTestWranglerSandbox(root, env);
        const scriptPath = path.isAbsolute(script) ? script : path.join(repositoryRoot, script);
        const result = spawnSync(process.execPath, [tsxCli, scriptPath, ...args], { cwd: root, encoding: "utf8", env, timeout: 120_000 });
        return { result, wrangler: await readRecord(record) };
      },
    };
    return await fn(sandbox);
  } finally { await rm(root, { recursive: true, force: true }); }
}
