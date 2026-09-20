import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { build, type Plugin } from "esbuild";
import { convertV4MiniflareOptions, Log, LogLevel, Miniflare, type V4MiniflareOptions } from "miniflare";
import { encodeBase64url } from "../../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../../workers/admission-service/authority";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION,
  signAuthorityInitializationCommand,
  signAuthorityReleaseRotationCommand,
  type AuthorityInitializationCommand,
  type AuthorityReleaseRotationCommand,
} from "../../workers/admission-service/operator-command";

const root = process.cwd();
const runtimeRoot = join(root, ".wrangler", "tests", `operator-executor-rpc-${process.pid}-${randomUUID()}`);
const bundles = {
  driver: join(runtimeRoot, "driver.mjs"),
  executor: join(runtimeRoot, "executor.mjs"),
  admission: join(runtimeRoot, "admission.mjs"),
  proxy: join(runtimeRoot, "ack-proxy.mjs"),
};
const opaque = (length: number, seed: number) => encodeBase64url(Uint8Array.from({ length }, (_, index) => (seed + index * 17) & 255));

async function bundle(): Promise<void> {
  const localFiles: Plugin = { name: "workspace-files", setup(buildApi) {
    buildApi.onResolve({ filter: /.*/ }, async (args) => {
      if (args.path === "cloudflare:workers") return { path: args.path, external: true };
      const base = args.path.startsWith(".") || isAbsolute(args.path)
        ? resolve(args.resolveDir || root, args.path)
        : createRequire(args.importer || join(root, "package.json")).resolve(args.path);
      for (const path of [base, `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.json`, join(base, "index.ts")]) {
        try { await readFile(path); return { path, namespace: "workspace-file" }; } catch { /* try next extension */ }
      }
      throw new Error(`Cannot resolve local module: ${args.path}`);
    });
    buildApi.onLoad({ filter: /.*/, namespace: "workspace-file" }, async (args) => ({
      contents: await readFile(args.path), resolveDir: dirname(args.path),
      loader: extname(args.path) === ".ts" ? "ts" : extname(args.path) === ".tsx" ? "tsx" : extname(args.path) === ".json" ? "json" : "js",
    }));
  } };
  const entries = [
    ["tests/workers/support/operator-executor-driver.ts", bundles.driver],
    ["workers/operator-lifecycle-executor.ts", bundles.executor],
    ["workers/admission-service/index.ts", bundles.admission],
    ["tests/workers/support/operator-ack-loss-proxy.ts", bundles.proxy],
  ] as const;
  await Promise.all(entries.map(async ([entryPoint, outfile]) => {
    const result = await build({ entryPoints: [resolve(root, entryPoint)], outfile, bundle: true, write: false, plugins: [localFiles],
    platform: "browser", format: "esm", target: "es2022", conditions: ["workerd", "worker", "browser"],
    external: ["cloudflare:workers"], logLevel: "silent" });
    assert.equal(result.outputFiles.length, 1);
    await writeFile(outfile, result.outputFiles[0].contents);
  }));
}

async function start(publicKey: string, persistence: string, dropAck: boolean): Promise<Miniflare> {
  const date = "2026-09-13";
  const admissionBindings = {
    AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey,
    ADMISSION_CURRENT_RPC_KEY: encodeBase64url(new Uint8Array(32).fill(9)),
    ADMISSION_CURRENT_RELEASE_ID: "executor-current",
    ADMISSION_CURRENT_KEY_ID: "executor-current-key",
    ADMISSION_CURRENT_ACTIVATED_AT_MS: "1",
    VERCEL_OIDC_ISSUER: "https://oidc.vercel.com/synthetic",
    VERCEL_OIDC_AUDIENCE: "synthetic",
    VERCEL_OIDC_SUBJECT: "owner:synthetic:project:synthetic:environment:production",
    VERCEL_OWNER_ID: "synthetic",
    VERCEL_PROJECT_ID: "synthetic",
  };
  const workers = [
    { name: "driver", scriptPath: bundles.driver, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      serviceBindings: { EXECUTOR: "executor", ADMISSION_SERVICE: "admission", ...(dropAck ? { ACK_PROXY: "ack-proxy" } : {}) },
      durableObjects: { AUTHORITY: { className: "ProductionAdmissionAuthority", scriptName: "admission", useSQLite: true } } },
    { name: "executor", scriptPath: bundles.executor, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey, OPERATOR_EXECUTOR_ENVIRONMENT: "production" },
      serviceBindings: { ADMISSION_SERVICE: dropAck ? "ack-proxy" : "admission" } },
    { name: "admission", scriptPath: bundles.admission, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      bindings: admissionBindings,
      durableObjects: { AUTHORITY: { className: "ProductionAdmissionAuthority", useSQLite: true } } },
    ...(dropAck ? [{ name: "ack-proxy", scriptPath: bundles.proxy, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      serviceBindings: { ADMISSION_SERVICE: "admission" } }] : []),
  ];
  const options = convertV4MiniflareOptions({ host: "127.0.0.1", port: 0, log: new Log(LogLevel.ERROR),
    resourcePersistencePath: persistence, workers } as V4MiniflareOptions);
  options.unsafeInspectDurableObjects = true;
  options.telemetry = { enabled: false };
  const mf = new Miniflare(options);
  await mf.ready;
  return mf;
}

async function call(mf: Miniflare, path: string, body?: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await mf.dispatchFetch(`http://localhost${path}`, body === undefined ? { method: "GET" } : {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) as Record<string, unknown> : {} };
}

const sealed = (command: unknown, signature: string) => JSON.stringify({ command, signature });
const submit = (mf: Miniflare, operation: "initialize" | "rotate", command: unknown, signature: string) =>
  call(mf, `/submit-${operation}`, { sealedJson: sealed(command, signature) });

async function rows(mf: Miniflare, query: string): Promise<Array<Record<string, unknown>>> {
  const storage = await mf.unsafeGetDurableObjectStorage("admission", "ProductionAdmissionAuthority", { name: ADMISSION_AUTHORITY_ID });
  return storage.exec(query) as Promise<Array<Record<string, unknown>>>;
}

async function assertExecutorHttpClosed(mf: Miniflare): Promise<void> {
  const executor = await mf.getWorker("executor");
  for (const method of ["GET", "POST", "PUT", "DELETE", "HEAD"]) {
    for (const path of ["/", "/submit-initialize", "/rotate?operation=rotate-release"]) {
      const response = await executor.fetch(`http://localhost${path}`, { method,
        headers: { "x-operator-command": "initialize", "content-type": "application/json" },
        ...(method === "POST" || method === "PUT" ? { body: JSON.stringify({ command: ["initialize"], signature: "forged" }) } : {}) });
      assert.equal(response.status, 404, `${method} ${path}`);
    }
  }
}

async function main(): Promise<void> {
  const resolved = resolve(runtimeRoot);
  const allowed = resolve(root, ".wrangler", "tests") + "\\";
  assert.ok(resolved.startsWith(allowed), "test resource path must remain inside the workspace");
  await mkdir(runtimeRoot, { recursive: true });
  process.env.WRANGLER_SEND_METRICS = "false";
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const forgedPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const privateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  const forgedPrivateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", forgedPair.privateKey)));
  const publicKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  let mf: Miniflare | undefined;
  try {
    await bundle();
    mf = await start(publicKey, join(runtimeRoot, "main-state"), false);
    await assertExecutorHttpClosed(mf);
    const now = Date.now();
    const initialize: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID,
      ADMISSION_POLICY_EPOCH, "executor-current", "executor-current-key", now, true];
    const initSignature = await signAuthorityInitializationCommand(initialize, privateKey);
    const forgedSignature = await signAuthorityInitializationCommand(initialize, forgedPrivateKey);
    assert.equal((await submit(mf, "initialize", initialize, forgedSignature)).body.error, "operator-signature");
    assert.deepEqual((await call(mf, "/direct-signature-check", { command: initialize, signature: forgedSignature })).body, { status: "refused" });
    assert.equal((await rows(mf, "SELECT name FROM sqlite_master WHERE type='table' AND name='authority_meta'")).length, 0);
    // A staging-flagged command must carry the distinct staging authority
    // identity (Gate 2); it is still refused by this Production executor.
    const staging: AuthorityInitializationCommand = [initialize[0], initialize[1], "staging", STAGING_ADMISSION_AUTHORITY_ID, initialize[4],
      initialize[5], initialize[6], initialize[7], false];
    assert.equal((await submit(mf, "initialize", staging, await signAuthorityInitializationCommand(staging, privateKey))).body.error,
      "invalid-sealed-artifact");
    assert.deepEqual((await call(mf, "/direct-signature-check", { command: staging,
      signature: await signAuthorityInitializationCommand(staging, privateKey) })).body, { status: "refused" });
    for (const index of [3, 4]) {
      const changed = [...initialize] as unknown as Array<unknown>;
      changed[index] = "wrong";
      assert.equal((await submit(mf, "initialize", changed, initSignature)).body.error, "invalid-sealed-artifact");
    }
    const stale = [...initialize] as unknown as Array<unknown>;
    stale[7] = now - 300_001;
    assert.equal((await submit(mf, "initialize", stale, initSignature)).body.error, "invalid-sealed-artifact");
    const initialized = (await submit(mf, "initialize", initialize, initSignature)).body;
    assert.equal(initialized.status, "initialized");
    assert.ok(initialized.receipt);
    const repeatedInit = (await submit(mf, "initialize", initialize, initSignature)).body;
    assert.equal(repeatedInit.status, "already-initialized");
    assert.deepEqual(repeatedInit.receipt, initialized.receipt);
    const conflict: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID,
      ADMISSION_POLICY_EPOCH, "executor-conflict", "executor-conflict-key", Date.now(), true];
    assert.deepEqual((await submit(mf, "initialize", conflict,
      await signAuthorityInitializationCommand(conflict, privateKey))).body, { status: "refused" });

    const preInput = (seed: number) => ({ releaseId: "executor-current", clientPseudonym: opaque(32, 1), requestBinding: opaque(32, seed + 1),
      nonce: opaque(16, seed + 2), issuedAtMs: Date.now() });
    const used = preInput(10);
    const usedPre = await call(mf, "/pre", { input: used });
    assert.equal(usedPre.body.decision, "allowed");
    const usedPermit = String(usedPre.body.permit);
    assert.equal((await call(mf, "/post", { input: { ...used, permit: usedPermit } })).body.decision, "allowed");
    const unused = preInput(20);
    const unusedPre = await call(mf, "/pre", { input: unused });
    assert.equal(unusedPre.body.decision, "allowed");
    const before = { observations: (await rows(mf, "SELECT * FROM observations")).length,
      nonces: (await rows(mf, "SELECT * FROM nonces")).length };
    const activatesAtMs = Date.now() + 1_000;
    const rotate: AuthorityReleaseRotationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production", ADMISSION_AUTHORITY_ID,
      ADMISSION_POLICY_EPOCH, "executor-current", "executor-next", "executor-next-key", activatesAtMs, activatesAtMs + 30_000, Date.now(), true];
    const rotationSignature = await signAuthorityReleaseRotationCommand(rotate, privateKey);
    const rotated = (await submit(mf, "rotate", rotate, rotationSignature)).body;
    assert.equal(rotated.status, "rotated");
    assert.ok(rotated.receipt);
    const repeatedRotation = (await submit(mf, "rotate", rotate, rotationSignature)).body;
    assert.equal(repeatedRotation.status, "already-rotated");
    assert.deepEqual(repeatedRotation.receipt, rotated.receipt);
    const rotationConflict = [...rotate] as unknown as AuthorityReleaseRotationCommand;
    (rotationConflict as unknown as string[])[7] = "executor-other-key";
    assert.deepEqual((await submit(mf, "rotate", rotationConflict,
      await signAuthorityReleaseRotationCommand(rotationConflict, privateKey))).body, { status: "refused" });
    assert.deepEqual({ observations: (await rows(mf, "SELECT * FROM observations")).length,
      nonces: (await rows(mf, "SELECT * FROM nonces")).length }, before);
    assert.equal((await call(mf, "/post", { input: { ...used, permit: usedPermit } })).body.decision, "replay");
    assert.equal((await call(mf, "/post", { input: { ...unused, permit: String(unusedPre.body.permit) } })).body.decision, "allowed");
    const snapshot = { meta: await rows(mf, "SELECT authority_id,policy_epoch FROM authority_meta"),
      releases: await rows(mf, "SELECT release_id,key_id,activated_ms,retired_ms FROM active_releases ORDER BY release_id"),
      observations: (await rows(mf, "SELECT * FROM observations")).length,
      nonces: (await rows(mf, "SELECT * FROM nonces")).length };
    await assertExecutorHttpClosed(mf);
    assert.deepEqual({ meta: await rows(mf, "SELECT authority_id,policy_epoch FROM authority_meta"),
      releases: await rows(mf, "SELECT release_id,key_id,activated_ms,retired_ms FROM active_releases ORDER BY release_id"),
      observations: (await rows(mf, "SELECT * FROM observations")).length,
      nonces: (await rows(mf, "SELECT * FROM nonces")).length }, snapshot);
    await mf.dispose(); mf = undefined;
    mf = await start(publicKey, join(runtimeRoot, "main-state"), false);
    assert.deepEqual(await rows(mf, "SELECT release_id,key_id,activated_ms,retired_ms FROM active_releases ORDER BY release_id"), snapshot.releases);
    assert.equal((await rows(mf, "SELECT * FROM nonces")).length, snapshot.nonces);
    assert.equal((await submit(mf, "rotate", rotate, rotationSignature)).body.status, "already-rotated");
    await mf.dispose(); mf = undefined;

    mf = await start(publicKey, join(runtimeRoot, "ack-state"), true);
    const ackCommand: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID,
      ADMISSION_POLICY_EPOCH, "ack-current", "ack-key", Date.now(), true];
    const ackSignature = await signAuthorityInitializationCommand(ackCommand, privateKey);
    const lost = await submit(mf, "initialize", ackCommand, ackSignature);
    assert.equal(lost.status, 200);
    assert.equal(lost.body.status, "unconfirmed");
    assert.match(String(lost.body.instruction), /may have committed/u);
    assert.deepEqual((await call(mf, "/dispatch-count")).body, { count: 1 });
    assert.deepEqual(await rows(mf, "SELECT authority_id,policy_epoch FROM authority_meta"),
      [{ authority_id: ADMISSION_AUTHORITY_ID, policy_epoch: ADMISSION_POLICY_EPOCH }]);
    assert.equal((await submit(mf, "initialize", ackCommand, ackSignature)).body.status, "already-initialized");
    assert.deepEqual((await call(mf, "/dispatch-count")).body, { count: 2 });
    await mf.dispose(); mf = undefined;
    mf = await start(publicKey, join(runtimeRoot, "ack-state"), true);
    assert.deepEqual(await rows(mf, "SELECT release_id FROM active_releases"), [{ release_id: "ack-current" }]);
    console.log("Operator executor multi-Worker RPC integration: PASS (actual executor/service binding/admission/SQLite, closure, restart, real lost acknowledgement)");
  } finally {
    if (mf) await mf.dispose();
    await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}

void main();
