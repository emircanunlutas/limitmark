import { lstat, readdir, readFile, realpath, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import { isWithin } from "./staging-config-renderer";

// R06 activation tooling (remediation B3 / hardening): the ONE Wrangler version this tooling is reviewed against, and the resolution of
// the repository-pinned local Wrangler executable. Local only: reads files, spawns nothing, contacts nothing.
//
// The composite preflight checks this pin once; the secret-put path checks it AGAIN immediately before every spawn through
// `resolveReviewedWrangler`, so a package swapped between preflight and put (or a stale preflight) is refused at the point of use.

/** The one Wrangler version this tooling's deploy wrappers are reviewed against (Gates 4/5/7 deployed with an earlier pin). */
export const REVIEWED_WRANGLER_VERSION = "4.143.1";

const MAX_MANIFEST_BYTES = 8 * 1024 * 1024;

export class WranglerPinError extends Error {
  constructor(readonly code: string) { super(code); this.name = "WranglerPinError"; }
}
const refuse = (code: string): never => { throw new WranglerPinError(code); };

async function readJsonFile(path: string, code: string): Promise<unknown> {
  try {
    const info = await stat(path);
    if (!info.isFile() || info.size < 1 || info.size > MAX_MANIFEST_BYTES) return refuse(code);
    return JSON.parse(await readFile(path, "utf8")) as unknown;
  } catch (error) { if (error instanceof WranglerPinError) throw error; return refuse(code); }
}

// ---------------------------------------------------------------------------
// Implicit dotenv loading (audit F1)
// ---------------------------------------------------------------------------

/** Wrangler 4.143.1 loads dotenv files from its working directory for EVERY command, independently of the environment the wrapper builds
 * for the child: its global yargs middleware calls `loadDotEnv((args["env-file"] ?? getDefaultEnvFiles(args.env)).map(path.resolve), {
 * includeProcessEnv: true })` and REPLACES `process.env` with the result (wrangler-dist/cli.js; verified against the installed package by
 * tests/r06-activation-secret-wrapper.test.ts). Whatever a `.env` or `.env.local` there defines -- `CLOUDFLARE_API_BASE_URL`,
 * `CLOUDFLARE_API_TOKEN`, `HTTPS_PROXY`, `WRANGLER_LOG`, `WRANGLER_OUTPUT_FILE_PATH`, `NODE_OPTIONS` for anything it spawns -- therefore
 * reaches Wrangler even though the wrapper refused the same names in the shell. `getDefaultEnvFiles(env)` is `[".env", ".env.local"]` plus
 * `.env.<env>` and `.env.<env>.local` when an environment is selected with `--env` (the wrapper never passes it and refuses CLOUDFLARE_ENV).
 *
 * Precedence between a dotenv file and the process environment is NOT relied on: the prohibition is on the files themselves. EVERY entry of
 * the working directory named `.env` or `.env.<anything>` refuses (file, directory, symlink, dangling symlink, any type; case-insensitively,
 * because Windows file systems are), which is a strict superset of anything `getDefaultEnvFiles` can return for any `--env` value. A listing
 * or probe that fails also refuses.
 *
 * ONE reviewed exception: `.env.example`, the git-tracked template (`!.env.example` in .gitignore), when it is a REGULAR FILE. Wrangler
 * would read it only for `--env example`, an argument the closed argv cannot carry; refusing it would make the tooling unusable in this
 * repository. The exact lowercase name only, and a directory, symlink or any other type under that name still refuses. */
export const WRANGLER_DOTENV_DEFAULT_FILES: readonly string[] = Object.freeze([".env", ".env.local"]);
export const DOTENV_TOLERATED_TEMPLATE = ".env.example";
const DOTENV_ENTRY = /^\.env(?:\..*)?$/iu;
export const isDotenvEntryName = (name: string): boolean => DOTENV_ENTRY.test(name);

/** Refuses (WranglerPinError) if `realRoot` -- the exact working directory the Wrangler child will get -- holds any implicit dotenv entry. */
export async function assertNoImplicitWranglerDotenv(realRoot: string): Promise<void> {
  let names: string[];
  try { names = await readdir(realRoot); } catch { return refuse("dotenv-search-unavailable"); }
  for (const name of names) {
    if (!isDotenvEntryName(name)) continue;
    if (name === DOTENV_TOLERATED_TEMPLATE) {
      try { if ((await lstat(join(realRoot, name))).isFile()) continue; } catch { return refuse("dotenv-search-unavailable"); }
    }
    return refuse("dotenv-entry-in-working-directory");
  }
  // A listing can omit what a probe sees (and the probe is what Wrangler itself performs): check the default names directly too.
  for (const name of WRANGLER_DOTENV_DEFAULT_FILES) {
    try { await lstat(join(realRoot, name)); }
    catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") continue;
      return refuse("dotenv-search-unavailable");
    }
    return refuse("dotenv-entry-in-working-directory");
  }
}

export type ReviewedWrangler = { bin: string; packageDirectory: string; version: string };

/** Resolves the repository-pinned local Wrangler for `root` and proves it is the exact reviewed version, consistently declared in
 * package.json, locked in package-lock.json and installed, with the executable inside the installed package. */
export async function resolveReviewedWrangler(root: string): Promise<ReviewedWrangler> {
  let realRoot: string, nodeModules: string, packageDirectory: string;
  try {
    realRoot = await realpath(root);
    nodeModules = await realpath(join(realRoot, "node_modules"));
    packageDirectory = await realpath(join(nodeModules, "wrangler"));
  } catch { return refuse("pinned-wrangler-unavailable"); }
  if (basename(packageDirectory) !== "wrangler" || !isWithin(nodeModules, packageDirectory)) refuse("pinned-wrangler-outside-node-modules");

  const installed = await readJsonFile(join(packageDirectory, "package.json"), "pinned-wrangler-unavailable") as { name?: unknown; version?: unknown } | null;
  if (installed === null || installed.name !== "wrangler") return refuse("pinned-wrangler-unavailable");
  const manifest = await readJsonFile(join(realRoot, "package.json"), "wrangler-version-not-the-reviewed-pin") as
    { dependencies?: Record<string, string>; devDependencies?: Record<string, string> } | null;
  const lock = await readJsonFile(join(realRoot, "package-lock.json"), "wrangler-version-not-the-reviewed-pin") as
    { packages?: Record<string, { version?: string }> } | null;
  const declared = manifest?.devDependencies?.wrangler ?? manifest?.dependencies?.wrangler;
  const locked = lock?.packages?.["node_modules/wrangler"]?.version;
  if (declared !== REVIEWED_WRANGLER_VERSION || locked !== REVIEWED_WRANGLER_VERSION || installed.version !== REVIEWED_WRANGLER_VERSION)
    refuse("wrangler-version-not-the-reviewed-pin");

  let bin: string;
  try { bin = await realpath(join(packageDirectory, "bin", "wrangler.js")); } catch { return refuse("pinned-wrangler-unavailable"); }
  if (basename(bin) !== "wrangler.js" || !isWithin(packageDirectory, bin)) refuse("pinned-wrangler-outside-node-modules");
  try { if (!(await stat(bin)).isFile()) refuse("pinned-wrangler-unavailable"); } catch (error) { if (error instanceof WranglerPinError) throw error; return refuse("pinned-wrangler-unavailable"); }
  return { bin, packageDirectory, version: REVIEWED_WRANGLER_VERSION };
}
