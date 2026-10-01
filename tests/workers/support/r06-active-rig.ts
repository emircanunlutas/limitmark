import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { build, type Plugin } from "esbuild";
import { convertV4MiniflareOptions, Log, LogLevel, Miniflare, type V4MiniflareOptions } from "miniflare";
import { encodeBase64url } from "../../../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, STAGING_ADMISSION_AUTHORITY_ID } from "../../../workers/admission-service/authority";
import { ATTESTATION_SIGNER_BINDINGS } from "../../../workers/admission-service/authority-attestation-config";
import { rfcSignerBindings } from "../../support/authority-attestation-test-signers";

/**
 * The REAL activated chain on local workerd (Miniflare), Production or staging:
 *
 *   R2 request slot -> mailbox (scheduled) -> dispatch-guard Durable Object -> executor entrypoint -> lifecycle-only admission entrypoint
 *   -> Authority Durable Object (real SQLite, real signer from environment bindings) -> signed envelope bytes back through every hop
 *   -> mailbox result writer (R2) -> reader.
 *   R2 reconcile slot -> observer (scheduled) -> read-only admission entrypoint -> Authority.attestReconciliation -> R2.
 *
 * Only the Authority classes are subclassed (a test fault in front of the real signer; see workers/r06-active-path-harness.ts) and the
 * executor/admission hops are wrapped by the existing counting proxies. Local resources only: no provider, no remote binding, no network.
 */
export type Role = "production" | "staging";
export type SignerMode = "rfc" | "absent" | "malformed-fingerprint" | "other-environment" | "both-environments";

const root = process.cwd();
const date = "2026-09-13";
const localFiles: Plugin = { name: "workspace-files", setup(api) {
  api.onResolve({ filter: /.*/ }, async (args) => {
    if (args.path === "cloudflare:workers") return { path: args.path, external: true };
    const base = args.path.startsWith(".") || isAbsolute(args.path) ? resolve(args.resolveDir || root, args.path) :
      createRequire(args.importer || join(root, "package.json")).resolve(args.path);
    for (const path of [base, `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.json`, join(base, "index.ts")]) {
      try { await readFile(path); return { path, namespace: "workspace-file" }; } catch { /* next */ }
    }
    throw new Error(`Unresolved local module: ${args.path}`);
  });
  api.onLoad({ filter: /.*/, namespace: "workspace-file" }, async (args) => ({ contents: await readFile(args.path),
    resolveDir: dirname(args.path), loader: extname(args.path) === ".ts" ? "ts" : extname(args.path) === ".json" ? "json" : "js" }));
} };

const entries = (role: Role): Record<string, string> => ({
  mailbox: role === "production" ? "workers/lifecycle-mailbox/index.ts" : "workers/lifecycle-mailbox/staging-index.ts",
  observer: role === "production" ? "workers/lifecycle-observer.ts" : "workers/staging-lifecycle-observer.ts",
  executor: role === "production" ? "workers/operator-lifecycle-executor.ts" : "workers/staging-operator-lifecycle-executor.ts",
  admission: "workers/r06-active-path-harness.ts",
  proxy: "tests/workers/support/i3b-counting-executor.ts",
  admissionProxy: "tests/workers/support/i3b-counting-admission.ts",
  driver: "tests/workers/support/i3b-driver.ts",
});

export interface RigOptions { role: Role; operatorPublicKey: string; runtimeRoot: string; state: string; signer?: SignerMode; dropAck?: boolean; failBefore?: boolean;
  /** Admission Worker bindings to add (string) or withhold (undefined) AFTER the signer bindings are built: a healthy signer beside an invalid runtime-secret configuration. */
  admissionBindingOverrides?: Record<string, string | undefined> }

export class Rig {
  constructor(readonly mf: Miniflare, readonly role: Role) {}
  static async bundle(runtimeRoot: string, role: Role): Promise<void> {
    await mkdir(runtimeRoot, { recursive: true });
    await Promise.all(Object.entries(entries(role)).map(async ([name, entry]) => {
      const result = await build({ entryPoints: [resolve(root, entry)], outfile: join(runtimeRoot, `${role}-${name}.mjs`), bundle: true, write: false, plugins: [localFiles],
        platform: "browser", format: "esm", target: "es2022", conditions: ["workerd", "worker", "browser"], external: ["cloudflare:workers"], logLevel: "silent" });
      await writeFile(join(runtimeRoot, `${role}-${name}.mjs`), result.outputFiles[0].contents);
    }));
  }

  static async start(options: RigOptions): Promise<Rig> {
    const { role, operatorPublicKey, runtimeRoot } = options;
    const script = (name: string) => join(runtimeRoot, `${role}-${name}.mjs`);
    const other: Role = role === "production" ? "staging" : "production";
    const mode = options.signer ?? "rfc";
    const own = await rfcSignerBindings(role);
    const names = ATTESTATION_SIGNER_BINDINGS[role];
    const signerBindings: Record<string, string> = mode === "rfc" ? own : mode === "absent" ? {} :
      mode === "malformed-fingerprint" ? { ...own, [names.writerKeyFingerprint]: "NOT-A-FINGERPRINT" } :
      mode === "other-environment" ? await rfcSignerBindings(other) : { ...own, ...await rfcSignerBindings(other) };
    const authorityId = role === "production" ? ADMISSION_AUTHORITY_ID : STAGING_ADMISSION_AUTHORITY_ID;
    const admissionBindings: Record<string, string> = {
      ...signerBindings,
      AUTHORITY_OPERATOR_PUBLIC_KEY: operatorPublicKey,
      ADMISSION_CURRENT_RPC_KEY: encodeBase64url(new Uint8Array(32).fill(9)),
      ADMISSION_CURRENT_RELEASE_ID: "i3b-current", ADMISSION_CURRENT_KEY_ID: "i3b-key", ADMISSION_CURRENT_ACTIVATED_AT_MS: "1",
      VERCEL_OIDC_ISSUER: "https://oidc.vercel.com/synthetic", VERCEL_OIDC_AUDIENCE: "synthetic",
      VERCEL_OIDC_SUBJECT: "owner:synthetic:project:synthetic:environment:production", VERCEL_OWNER_ID: "synthetic", VERCEL_PROJECT_ID: "synthetic",
    };
    for (const [name, value] of Object.entries(options.admissionBindingOverrides ?? {})) { if (value === undefined) delete admissionBindings[name]; else admissionBindings[name] = value; }
    const buckets = { REQUEST_BUCKET: "r06-requests", RESULT_BUCKET: "r06-results" };
    const lifecycleEnvironment = role;
    const reader = { name: "admission", entrypoint: role === "production" ? "AuthorityLifecycleReadOnly" : "StagingAuthorityLifecycleReadOnly" };
    const writer = { name: "admission", entrypoint: role === "production" ? "AuthorityLifecycleOnly" : "StagingAuthorityLifecycleOnly" };
    const workers = [
      { name: "mailbox", scriptPath: script("mailbox"), modules: true, compatibilityDate: date, unsafeRegisterWorker: false, routes: ["mailbox.local/*"],
        bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: operatorPublicKey, LIFECYCLE_ENVIRONMENT: lifecycleEnvironment }, r2Buckets: buckets,
        durableObjects: { DISPATCH_GUARD: { className: role === "production" ? "LifecycleDispatchGuard" : "StagingLifecycleDispatchGuard", useSQLite: true } },
        serviceBindings: { LIFECYCLE_EXECUTOR: { name: "proxy", entrypoint: "CountingExecutor" }, LIFECYCLE_READER: reader } },
      { name: "observer", scriptPath: script("observer"), modules: true, compatibilityDate: date, unsafeRegisterWorker: false, routes: ["observer.local/*"],
        r2Buckets: buckets, serviceBindings: { LIFECYCLE_READER: reader } },
      { name: "proxy", scriptPath: script("proxy"), modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
        bindings: { DROP_ACK: options.dropAck ? "true" : "false", FAIL_BEFORE: options.failBefore ? "true" : "false" },
        serviceBindings: { EXECUTOR: { name: "executor", entrypoint: role === "production" ? "OperatorLifecycleExecutor" : "StagingOperatorLifecycleExecutor" } } },
      { name: "executor", scriptPath: script("executor"), modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
        bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: operatorPublicKey, OPERATOR_EXECUTOR_ENVIRONMENT: role },
        serviceBindings: { ADMISSION_SERVICE: { name: "admissionProxy", entrypoint: "CountingAdmission" } } },
      { name: "admissionProxy", scriptPath: script("admissionProxy"), modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
        serviceBindings: { ADMISSION: writer } },
      { name: "admission", scriptPath: script("admission"), modules: true, compatibilityDate: date, unsafeRegisterWorker: false, bindings: admissionBindings,
        durableObjects: { AUTHORITY: { className: role === "production" ? "FaultableProductionAuthority" : "FaultableStagingAuthority", useSQLite: true } } },
      { name: "driver", scriptPath: script("driver"), modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
        serviceBindings: { COUNTING_EXECUTOR: { name: "proxy", entrypoint: "CountingExecutor" }, COUNTING_ADMISSION: { name: "admissionProxy", entrypoint: "CountingAdmission" },
          LIFECYCLE_READER: reader } },
    ];
    assert.equal(/"remote"/u.test(JSON.stringify(workers)), false, "no remote (provider) binding in the rig");
    const options2 = convertV4MiniflareOptions({ host: "127.0.0.1", port: 0, log: new Log(LogLevel.ERROR), unsafeTriggerHandlers: true,
      resourcePersistencePath: join(runtimeRoot, options.state), workers } as unknown as V4MiniflareOptions);
    options2.unsafeInspectDurableObjects = true;
    options2.telemetry = { enabled: false };
    const mf = new Miniflare(options2);
    await mf.ready;
    void authorityId;
    return new Rig(mf, role);
  }

  get authorityId() { return this.role === "production" ? ADMISSION_AUTHORITY_ID : STAGING_ADMISSION_AUTHORITY_ID; }
  get authorityClass() { return this.role === "production" ? "FaultableProductionAuthority" : "FaultableStagingAuthority"; }
  get guardClass() { return this.role === "production" ? "LifecycleDispatchGuard" : "StagingLifecycleDispatchGuard"; }
  get guardName() { return this.role === "production" ? "production-lifecycle-dispatch-v1" : "staging-lifecycle-dispatch-v1"; }

  async scheduled(worker: "mailbox" | "observer"): Promise<void> {
    const response = await this.mf.dispatchFetch(`http://${worker}.local/cdn-cgi/local/scheduled`);
    assert.equal(response.status, 200);
  }
  async counts(): Promise<[number, number]> {
    const driver = await this.mf.getWorker("driver");
    const read = async (path: string) => Number((await (await driver.fetch(`http://localhost/${path}`)).json() as { count: number }).count);
    return [await read("count"), await read("admission-count")];
  }
  async sql(script: "mailbox" | "admission", className: string, name: string, query: string): Promise<Array<Record<string, unknown>>> {
    const storage = await this.mf.unsafeGetDurableObjectStorage(script, className, { name });
    return storage.exec(query) as Promise<Array<Record<string, unknown>>>;
  }
  authoritySql(query: string) { return this.sql("admission", this.authorityClass, this.authorityId, query); }
  guardSql(query: string) { return this.sql("mailbox", this.guardClass, this.guardName, query); }
  async authorityTables(): Promise<Record<string, unknown>> {
    const tables = (await this.authoritySql("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '\\_%' ESCAPE '\\' ORDER BY name")).map((row) => String(row.name));
    return Object.fromEntries(await Promise.all(tables.map(async (table) => [table, await this.authoritySql(`SELECT * FROM ${table}`)])));
  }
  async put(key: string, value: unknown): Promise<void> {
    await (await this.mf.getR2Bucket("REQUEST_BUCKET", "mailbox")).put(key, typeof value === "string" ? value : JSON.stringify(value));
  }
  async result(key: string): Promise<Uint8Array | null> {
    const object = await (await this.mf.getR2Bucket("RESULT_BUCKET", "mailbox")).get(key);
    return object ? new Uint8Array(await object.arrayBuffer()) : null;
  }
  async putResult(key: string, bytes: Uint8Array | string, customMetadata?: Record<string, string>): Promise<void> {
    await (await this.mf.getR2Bucket("RESULT_BUCKET", "mailbox")).put(key, bytes, customMetadata ? { customMetadata } : undefined);
  }
  async resultMetadata(key: string): Promise<Record<string, string> | undefined> {
    return (await (await this.mf.getR2Bucket("RESULT_BUCKET", "mailbox")).head(key))?.customMetadata;
  }
  async fault(fault: "none" | "sign" | "ready"): Promise<void> {
    const response = await (await this.mf.getWorker("admission")).fetch("http://localhost/__r06-fault", { method: "POST",
      headers: { "x-r06-active-path-test": "2c", "content-type": "application/json" }, body: JSON.stringify({ role: this.role, fault }) });
    assert.equal(response.status, 200);
  }
  /** Reconcile through the real observer chain and return the stored object. */
  async reconcile(digest: string, nonce: string): Promise<Uint8Array | null> {
    await this.put("reconcile.json", { version: 1, digest, nonce });
    await this.scheduled("observer");
    return this.result(`reconciliation/${nonce}.json`);
  }
  async settle(digest: string, nonce: string): Promise<boolean> {
    await this.put("settle.json", { version: 1, digest, nonce });
    await this.scheduled("mailbox");
    const bytes = await this.result(`settlement/${nonce}.json`);
    assert.ok(bytes, "settlement result published");
    return (JSON.parse(new TextDecoder().decode(bytes)) as { settled: boolean }).settled;
  }
  async dispose(): Promise<void> { await this.mf.dispose(); }
}

export async function removeRuntime(runtimeRoot: string): Promise<void> {
  await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
