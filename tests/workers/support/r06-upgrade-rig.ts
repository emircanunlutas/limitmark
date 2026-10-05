import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { build, type Plugin } from "esbuild";
import { convertV4MiniflareOptions, Log, LogLevel, Miniflare, type V4MiniflareOptions } from "miniflare";
import { encodeBase64url } from "../../../src/lib/ingress-protocol";
import { STAGING_ADMISSION_AUTHORITY_ID } from "../../../workers/admission-service/authority";

/**
 * R06 activation (T7): the UPGRADE REHEARSAL rig. It runs the REAL staging Workers on local workerd (Miniflare) with persistent storage,
 * and lets each Worker be started from EITHER source revision independently:
 *
 *   old   the Gate 7-era revision, extracted from git history (the deployed-era worker sources are identical to it: nothing bundled
 *         into the Workers changed between Gate 4 and Gate 7)
 *   head  the working tree under test
 *
 * Each Worker's entry is the REAL deployed `main` (no harness subclass), so the Durable Object classes, entrypoints and bindings are the
 * ones a deployment would run. Between restarts the same `resourcePersistencePath` is reused, so Durable Object SQLite and R2 survive an
 * old -> HEAD code swap exactly as persisted state would survive a redeploy. Local resources only: no provider, no remote binding, no
 * network, no operational key (the signer, when present, is supplied through the real binding names from the frozen RFC 8032 TEST vectors).
 */
export type Version = "old" | "head";
export type WorkerName = "admission" | "mailbox" | "observer" | "executor";
export type Versions = Record<WorkerName, Version>;

const repositoryRoot = process.cwd();

/** The Gate 7-era source revision (full hash; `git rev-parse 2216dcb`). */
export const GATE7_ERA_COMMIT = "2216dcb03e3275e9cf16920fb206addc7a4aed79";
const extractedPaths = ["workers", "src/lib", "operator", "deployment"] as const;

const entries: Record<WorkerName, string> = {
  admission: "workers/admission-service/index.ts",
  mailbox: "workers/lifecycle-mailbox/staging-index.ts",
  observer: "workers/staging-lifecycle-observer.ts",
  executor: "workers/staging-operator-lifecycle-executor.ts",
};

function git(args: string[], maxBuffer = 16 * 1024 * 1024): { status: number | null; stdout: Buffer } {
  const result = spawnSync("git", args, { cwd: repositoryRoot, maxBuffer });
  return { status: result.status, stdout: result.stdout ?? Buffer.alloc(0) };
}

/** Extracts the source files the Workers bundle from the old revision into `directory`, using only read-only git plumbing. */
export async function extractRevision(commit: string, directory: string): Promise<void> {
  const verified = git(["rev-parse", "--verify", `${commit}^{commit}`]);
  if (verified.status !== 0 || verified.stdout.toString("utf8").trim() !== commit)
    throw new Error(`the upgrade rehearsal needs the full git history: commit ${commit} is not available in this clone`);
  const listing = git(["ls-tree", "-r", "--name-only", commit, "--", ...extractedPaths]);
  assert.equal(listing.status, 0, "git ls-tree failed");
  const files = listing.stdout.toString("utf8").split("\n").filter(Boolean);
  assert.ok(files.length > 20, "old revision listing is unexpectedly small");
  for (const file of files) {
    const content = git(["show", `${commit}:${file}`]);
    assert.equal(content.status, 0, `git show failed for ${file}`);
    const target = join(directory, ...file.split("/"));
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content.stdout);
  }
}

function localFiles(treeRoot: string): Plugin {
  const fallback = createRequire(join(repositoryRoot, "package.json"));
  return { name: "tree-files", setup(api) {
    api.onResolve({ filter: /.*/ }, async (args) => {
      if (args.path === "cloudflare:workers") return { path: args.path, external: true };
      const base = args.path.startsWith(".") || isAbsolute(args.path) ? resolve(args.resolveDir || treeRoot, args.path) : fallback.resolve(args.path);
      for (const path of [base, `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.json`, join(base, "index.ts")]) {
        try { await readFile(path); return { path, namespace: "tree-file" }; } catch { /* next */ }
      }
      throw new Error(`Unresolved local module: ${args.path}`);
    });
    api.onLoad({ filter: /.*/, namespace: "tree-file" }, async (args) => ({ contents: await readFile(args.path),
      resolveDir: dirname(args.path), loader: extname(args.path) === ".ts" ? "ts" : extname(args.path) === ".json" ? "json" : "js" }));
  } };
}

/** Bundles the four real Worker entries of one revision into `<runtimeRoot>/<version>-<worker>.mjs`. */
export async function bundleRevision(version: Version, treeRoot: string, runtimeRoot: string): Promise<void> {
  await mkdir(runtimeRoot, { recursive: true });
  await Promise.all((Object.entries(entries) as Array<[WorkerName, string]>).map(async ([name, entry]) => {
    const result = await build({ entryPoints: [resolve(treeRoot, entry)], outfile: join(runtimeRoot, `${version}-${name}.mjs`), bundle: true, write: false,
      plugins: [localFiles(treeRoot)], platform: "browser", format: "esm", target: "es2022", conditions: ["workerd", "worker", "browser"],
      external: ["cloudflare:workers"], logLevel: "silent" });
    await writeFile(join(runtimeRoot, `${version}-${name}.mjs`), result.outputFiles[0].contents);
  }));
}

export interface UpgradeRigOptions {
  runtimeRoot: string;
  /** Persistence directory name under runtimeRoot; reuse it across restarts to carry Durable Object and R2 state over. */
  state: string;
  versions: Versions;
  operatorPublicKey: string;
  /** Authority-attestation bindings to give the admission Worker (secret channel); `{}` is a signer-less Worker. */
  signerBindings?: Record<string, string>;
}

const date = "2026-09-13";
const GUARD_NAME = "staging-lifecycle-dispatch-v1";

export class UpgradeRig {
  constructor(readonly mf: Miniflare) {}

  static async start(options: UpgradeRigOptions): Promise<UpgradeRig> {
    const { runtimeRoot, versions, operatorPublicKey } = options;
    const script = (name: WorkerName) => join(runtimeRoot, `${versions[name]}-${name}.mjs`);
    const buckets = { REQUEST_BUCKET: "r06-requests", RESULT_BUCKET: "r06-results" };
    const reader = { name: "admission", entrypoint: "StagingAuthorityLifecycleReadOnly" };
    const workers = [
      { name: "mailbox", scriptPath: script("mailbox"), modules: true, compatibilityDate: date, unsafeRegisterWorker: false, routes: ["mailbox.local/*"],
        bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: operatorPublicKey, LIFECYCLE_ENVIRONMENT: "staging" }, r2Buckets: buckets,
        durableObjects: { DISPATCH_GUARD: { className: "StagingLifecycleDispatchGuard", useSQLite: true } },
        serviceBindings: { LIFECYCLE_EXECUTOR: { name: "executor", entrypoint: "StagingOperatorLifecycleExecutor" }, LIFECYCLE_READER: reader } },
      { name: "observer", scriptPath: script("observer"), modules: true, compatibilityDate: date, unsafeRegisterWorker: false, routes: ["observer.local/*"],
        r2Buckets: buckets, serviceBindings: { LIFECYCLE_READER: reader } },
      { name: "executor", scriptPath: script("executor"), modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
        bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: operatorPublicKey, OPERATOR_EXECUTOR_ENVIRONMENT: "staging" },
        serviceBindings: { ADMISSION_SERVICE: { name: "admission", entrypoint: "StagingAuthorityLifecycleOnly" } } },
      { name: "admission", scriptPath: script("admission"), modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
        bindings: { ...(options.signerBindings ?? {}), AUTHORITY_OPERATOR_PUBLIC_KEY: operatorPublicKey, ADMISSION_CURRENT_RPC_KEY: encodeBase64url(new Uint8Array(32).fill(9)) },
        durableObjects: { AUTHORITY: { className: "StagingAdmissionAuthority", useSQLite: true } } },
    ];
    assert.equal(/"remote"/u.test(JSON.stringify(workers)), false, "no remote (provider) binding in the rig");
    const converted = convertV4MiniflareOptions({ host: "127.0.0.1", port: 0, log: new Log(LogLevel.ERROR), unsafeTriggerHandlers: true,
      resourcePersistencePath: join(runtimeRoot, options.state), workers } as unknown as V4MiniflareOptions);
    converted.unsafeInspectDurableObjects = true;
    converted.telemetry = { enabled: false };
    const mf = new Miniflare(converted);
    await mf.ready;
    return new UpgradeRig(mf);
  }

  async scheduled(worker: "mailbox" | "observer"): Promise<void> {
    const response = await this.mf.dispatchFetch(`http://${worker}.local/cdn-cgi/local/scheduled`);
    assert.equal(response.status, 200);
  }
  private async sql(script: "mailbox" | "admission", className: string, name: string, query: string): Promise<Array<Record<string, unknown>>> {
    const storage = await this.mf.unsafeGetDurableObjectStorage(script, className, { name });
    return storage.exec(query) as Promise<Array<Record<string, unknown>>>;
  }
  authoritySql(query: string) { return this.sql("admission", "StagingAdmissionAuthority", STAGING_ADMISSION_AUTHORITY_ID, query); }
  guardSql(query: string) { return this.sql("mailbox", "StagingLifecycleDispatchGuard", GUARD_NAME, query); }
  private async dump(run: (query: string) => Promise<Array<Record<string, unknown>>>): Promise<Record<string, unknown>> {
    const tables = (await run("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '\\_%' ESCAPE '\\' ORDER BY name")).map((row) => String(row.name));
    return Object.fromEntries(await Promise.all(tables.map(async (table) => [table, await run(`SELECT * FROM ${table}`)])));
  }
  /** Every table of the Authority Durable Object and its rows (SQLite internals excluded): the whole committed Authority state. */
  authorityState() { return this.dump((query) => this.authoritySql(query)); }
  /** Every table of the dispatch-guard Durable Object and its rows. */
  guardState() { return this.dump((query) => this.guardSql(query)); }

  async put(key: string, value: unknown): Promise<void> {
    await (await this.mf.getR2Bucket("REQUEST_BUCKET", "mailbox")).put(key, typeof value === "string" ? value : JSON.stringify(value));
  }
  async result(key: string): Promise<Uint8Array | null> {
    const object = await (await this.mf.getR2Bucket("RESULT_BUCKET", "mailbox")).get(key);
    return object ? new Uint8Array(await object.arrayBuffer()) : null;
  }
  async resultMetadata(key: string): Promise<Record<string, string> | undefined> {
    return (await (await this.mf.getR2Bucket("RESULT_BUCKET", "mailbox")).head(key))?.customMetadata;
  }
  /** Reconcile through the real observer and return the stored object (null when the observer stored nothing). */
  async reconcile(digest: string, nonce: string): Promise<Uint8Array | null> {
    await this.put("reconcile.json", { version: 1, digest, nonce });
    await this.scheduled("observer");
    return this.result(`reconciliation/${nonce}.json`);
  }
  /** Settle through the real mailbox and return the stored settlement result. */
  async settle(digest: string, nonce: string): Promise<{ settled: boolean }> {
    await this.put("settle.json", { version: 1, digest, nonce });
    await this.scheduled("mailbox");
    const bytes = await this.result(`settlement/${nonce}.json`);
    assert.ok(bytes, "settlement result published");
    return JSON.parse(new TextDecoder().decode(bytes)) as { settled: boolean };
  }
  async dispose(): Promise<void> { await this.mf.dispose(); }
}

export async function removeRuntime(runtimeRoot: string): Promise<void> {
  await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
