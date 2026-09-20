// Gate 2 pre-commit correction: a durable, permanent workerd integration test
// exercising the ACTUAL staging runtime classes and real service/DO bindings
// (no mocks, no in-memory substitute for the final staging Durable Object, no
// Production runtime standing in for staging). Mirrors the structure of
// tests/workers/lifecycle-mailbox.integration.ts, reduced to staging's
// narrower surface (initialization + read-only reconciliation + settlement
// only; there is deliberately no staging rotation path anywhere below).
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { build, type Plugin } from "esbuild";
import { convertV4MiniflareOptions, Log, LogLevel, Miniflare, type V4MiniflareOptions } from "miniflare";
import { encodeBase64url } from "../../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, commandDigest, signAuthorityInitializationCommand,
  type AuthorityInitializationCommand } from "../../workers/admission-service/operator-command";

const root = process.cwd();
const runtimeRoot = join(root, ".wrangler", "tests", `i3b-staging-mailbox-${process.pid}-${randomUUID()}`);
const paths = Object.fromEntries(["mailbox", "observer", "executor", "admission", "driver"].map((name) => [name, join(runtimeRoot, `${name}.mjs`)]));
const entries: Record<string, string> = {
  mailbox: "workers/lifecycle-mailbox/staging-index.ts",
  observer: "workers/staging-lifecycle-observer.ts",
  executor: "workers/staging-operator-lifecycle-executor.ts",
  admission: "workers/admission-service/index.ts",
  driver: "tests/workers/support/staging-lifecycle-driver.ts",
};
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

async function bundle(): Promise<void> {
  await Promise.all(Object.entries(entries).map(async ([name, entry]) => {
    const result = await build({ entryPoints: [resolve(root, entry)], outfile: paths[name], bundle: true, write: false,
      plugins: [localFiles], platform: "browser", format: "esm", target: "es2022", conditions: ["workerd", "worker", "browser"],
      external: ["cloudflare:workers"], logLevel: "silent" });
    await writeFile(paths[name], result.outputFiles[0].contents);
  }));
}

async function start(publicKey: string, persistence: string): Promise<Miniflare> {
  const date = "2026-09-13";
  const admissionBindings = {
    AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey,
    ADMISSION_CURRENT_RPC_KEY: encodeBase64url(new Uint8Array(32).fill(7)),
    ADMISSION_CURRENT_RELEASE_ID: "staging-current", ADMISSION_CURRENT_KEY_ID: "staging-key",
    ADMISSION_CURRENT_ACTIVATED_AT_MS: "1", VERCEL_OIDC_ISSUER: "https://oidc.vercel.com/synthetic",
    VERCEL_OIDC_AUDIENCE: "synthetic", VERCEL_OIDC_SUBJECT: "owner:synthetic:project:synthetic:environment:production",
    VERCEL_OWNER_ID: "synthetic", VERCEL_PROJECT_ID: "synthetic",
  };
  const buckets = { REQUEST_BUCKET: "i3b-staging-requests", RESULT_BUCKET: "i3b-staging-results" };
  const workers = [
    { name: "mailbox", scriptPath: paths.mailbox, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      routes: ["mailbox.local/*"],
      bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey, LIFECYCLE_ENVIRONMENT: "staging" }, r2Buckets: buckets,
      durableObjects: { DISPATCH_GUARD: { className: "StagingLifecycleDispatchGuard", useSQLite: true } },
      serviceBindings: { LIFECYCLE_EXECUTOR: { name: "executor" },
        LIFECYCLE_READER: { name: "admission", entrypoint: "StagingAuthorityLifecycleReadOnly" } } },
    { name: "observer", scriptPath: paths.observer, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      routes: ["observer.local/*"],
      r2Buckets: buckets, serviceBindings: { LIFECYCLE_READER: { name: "admission", entrypoint: "StagingAuthorityLifecycleReadOnly" } } },
    { name: "executor", scriptPath: paths.executor, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey, OPERATOR_EXECUTOR_ENVIRONMENT: "staging" },
      serviceBindings: { ADMISSION_SERVICE: { name: "admission", entrypoint: "StagingAuthorityLifecycleOnly" } } },
    { name: "admission", scriptPath: paths.admission, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      bindings: admissionBindings, durableObjects: { AUTHORITY: { className: "StagingAdmissionAuthority", useSQLite: true } } },
    { name: "driver", scriptPath: paths.driver, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      serviceBindings: { STAGING_EXECUTOR: { name: "executor" },
        STAGING_ADMISSION_LIFECYCLE_ONLY: { name: "admission", entrypoint: "StagingAuthorityLifecycleOnly" } } },
  ];
  const options = convertV4MiniflareOptions({ host: "127.0.0.1", port: 0, log: new Log(LogLevel.ERROR), unsafeTriggerHandlers: true,
    resourcePersistencePath: persistence, workers } as unknown as V4MiniflareOptions);
  options.unsafeInspectDurableObjects = true;
  options.telemetry = { enabled: false };
  const mf = new Miniflare(options);
  await mf.ready;
  return mf;
}

async function scheduled(mf: Miniflare, worker: "mailbox" | "observer"): Promise<void> {
  const response = await mf.dispatchFetch(`http://${worker}.local/cdn-cgi/local/scheduled`);
  assert.equal(response.status, 200);
}
async function sql(mf: Miniflare, script: string, className: string, name: string, query: string): Promise<Array<Record<string, unknown>>> {
  const storage = await mf.unsafeGetDurableObjectStorage(script, className, { name });
  return storage.exec(query) as Promise<Array<Record<string, unknown>>>;
}

async function main(): Promise<void> {
  const resolved = resolve(runtimeRoot);
  assert.ok(resolved.startsWith(resolve(root, ".wrangler", "tests") + "\\"));
  await mkdir(runtimeRoot, { recursive: true });
  process.env.WRANGLER_SEND_METRICS = "false";
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const privateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  const publicKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  let mf: Miniflare | undefined;
  try {
    // Proof 1: the actual staging classes bundle and start in real workerd.
    await bundle();
    mf = await start(publicKey, join(runtimeRoot, "state"));

    // Proof 10: no public HTTP lifecycle path exists on any private staging Worker.
    const mailboxWorker = await mf.getWorker("mailbox");
    assert.equal((await mailboxWorker.fetch("http://localhost/initialize.json")).status, 404);
    const observerWorker = await mf.getWorker("observer");
    assert.equal((await observerWorker.fetch("http://localhost/reconcile.json")).status, 404);
    const executorWorker = await mf.getWorker("executor");
    assert.equal((await executorWorker.fetch("http://localhost/")).status, 404);

    const requests = await mf.getR2Bucket("REQUEST_BUCKET", "mailbox");
    const results = await mf.getR2Bucket("RESULT_BUCKET", "mailbox");
    const driver = await mf.getWorker("driver");

    const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging",
      STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "staging-current", "staging-key", Date.now(), false];
    const digest = await commandDigest(command);
    const signature = await signAuthorityInitializationCommand(command, privateKey);

    // Proof 6: a Production-flagged artifact sent into the staging runtime is rejected.
    const prodShaped: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production",
      ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "staging-current", "staging-key", Date.now(), true];
    const prodSignature = await signAuthorityInitializationCommand(prodShaped, privateKey);
    await requests.put("initialize.json", JSON.stringify({ command: prodShaped, signature: prodSignature }));
    await scheduled(mf, "mailbox");
    assert.equal((await sql(mf, "mailbox", "StagingLifecycleDispatchGuard", "staging-lifecycle-dispatch-v1", "SELECT * FROM claims")).length, 0,
      "a Production-flagged artifact never consumes a staging dispatch claim");
    assert.equal((await sql(mf, "admission", "StagingAdmissionAuthority", STAGING_ADMISSION_AUTHORITY_ID,
      "SELECT name FROM sqlite_master WHERE type='table' AND name='authority_meta'")).length, 0, "staging authority remains uninitialized");

    // Proof 3: a valid staging initialization is accepted, initializes only the
    // staging authority, and persists the exact staging lifecycle receipt.
    await requests.put("initialize.json", JSON.stringify({ command, signature }));
    await scheduled(mf, "mailbox");
    const claimRows = await sql(mf, "mailbox", "StagingLifecycleDispatchGuard", "staging-lifecycle-dispatch-v1", "SELECT digest,status FROM claims");
    assert.equal(claimRows.length, 1);
    assert.equal(claimRows[0].status, "SUCCESS");
    assert.equal(claimRows[0].digest, digest);
    const receiptRows = await sql(mf, "admission", "StagingAdmissionAuthority", STAGING_ADMISSION_AUTHORITY_ID,
      "SELECT digest,authority_id,environment,policy_epoch FROM lifecycle_receipts");
    assert.equal(receiptRows.length, 1);
    assert.equal(receiptRows[0].digest, digest);
    assert.equal(receiptRows[0].authority_id, STAGING_ADMISSION_AUTHORITY_ID, "initialization applied only to the staging authority identity");
    assert.equal(receiptRows[0].environment, "staging");
    const lifecycleResult = await results.get(`lifecycle/${digest}.json`);
    assert.ok(lifecycleResult, "the exact staging lifecycle receipt was published to the result bucket");
    const parsedResult = await lifecycleResult!.json() as { status: string; receipt: { authorityId: string; environment: string } };
    assert.equal(parsedResult.status, "SUCCESS");
    assert.equal(parsedResult.receipt.authorityId, STAGING_ADMISSION_AUTHORITY_ID);
    assert.equal(parsedResult.receipt.environment, "staging");

    // Proof 4: exact replay of the identical artifact is idempotent (no second dispatch/receipt).
    await requests.put("initialize.json", JSON.stringify({ command, signature }));
    await scheduled(mf, "mailbox");
    assert.equal((await sql(mf, "mailbox", "StagingLifecycleDispatchGuard", "staging-lifecycle-dispatch-v1", "SELECT * FROM claims")).length, 1,
      "replay does not create a second claim");
    assert.equal((await sql(mf, "admission", "StagingAdmissionAuthority", STAGING_ADMISSION_AUTHORITY_ID,
      "SELECT * FROM lifecycle_receipts")).length, 1, "replay does not create a second receipt");

    // Read-only reconciliation through the actual staging observer chain.
    const nonce = "a".repeat(32);
    await requests.put("reconcile.json", JSON.stringify({ version: 1, digest, nonce }));
    await scheduled(mf, "observer");
    const reconciliation = await results.get(`reconciliation/${nonce}.json`);
    assert.ok(reconciliation, "the staging observer published a reconciliation result through the real read-only chain");
    const parsedReconciliation = await reconciliation!.json() as { status: string; environment: string };
    assert.equal(parsedReconciliation.status, "EXACT_RECEIPT");
    assert.equal(parsedReconciliation.environment, "staging");

    // Proof 9: the actual bound guard DO stub exposes no internal helpers beyond
    // its designed RPC surface. These property names are not methods on
    // StagingLifecycleDispatchGuard at all; a real workerd RPC stub still
    // accepts the call syntactically (Proxy trap) and rejects only at invocation.
    const guardStub = (await mf.getDurableObjectNamespace("DISPATCH_GUARD", "mailbox")).getByName("staging-lifecycle-dispatch-v1") as
      unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
    for (const name of ["one", "afterClaimSync", "beforeExecutorCall", "sql", "exec", "ledger", "deleteClaim", "deleteLatch",
      "reset", "rearm", "clear", "transactionSync", "sync", "settlementResolution"])
      await assert.rejects(async () => guardStub[name]("x"), (error: unknown) => {
        assert.match(String(error), /RPC receiver does not implement the method/u);
        return true;
      }, `${name} must not be an RPC method on the staging guard`);

    // Proof 8: staging rotation fails closed over the ACTUAL workerd RPC surface.
    const beforeRotationClaims = await sql(mf, "mailbox", "StagingLifecycleDispatchGuard", "staging-lifecycle-dispatch-v1", "SELECT * FROM claims");
    const beforeRotationLatch = await sql(mf, "mailbox", "StagingLifecycleDispatchGuard", "staging-lifecycle-dispatch-v1", "SELECT * FROM latch");
    // 8a: the guard's own real processRotation() RPC method exists (it must
    // fail closed rather than being silently absent from this DO) but performs
    // no parsing, verification or storage access whatsoever.
    // The workerd RPC return value is a stub-wrapped object (carries a
    // non-enumerable inspect symbol); round-trip through JSON for a plain
    // structural comparison of the actual returned data.
    const rotationOutcome = JSON.parse(JSON.stringify(await guardStub.processRotation()));
    assert.deepEqual(rotationOutcome, { version: 1, digest: "", status: "REFUSED", reason: "staging-rotation-not-implemented" });
    assert.deepEqual(await sql(mf, "mailbox", "StagingLifecycleDispatchGuard", "staging-lifecycle-dispatch-v1", "SELECT * FROM claims"), beforeRotationClaims,
      "processRotation touches no claim state");
    assert.deepEqual(await sql(mf, "mailbox", "StagingLifecycleDispatchGuard", "staging-lifecycle-dispatch-v1", "SELECT * FROM latch"), beforeRotationLatch,
      "processRotation touches no latch state");
    // 8b: the staging executor's RPC surface has no submitRotationArtifact
    // method at all -- probed through a real service-bound RPC call, not a
    // source-text check.
    const executorProbe = await (await driver.fetch("http://localhost/probe-executor-rotation")).json() as { exposed: boolean; message?: string };
    assert.equal(executorProbe.exposed, false, "the staging executor RPC surface must not expose submitRotationArtifact");
    assert.match(String(executorProbe.message), /RPC receiver does not implement the method/u);
    // 8c: StagingAuthorityLifecycleOnly.rotateAuthorityReleaseFromOperator does
    // exist (mirroring the Production entrypoint shape) but performs no
    // parsing, no authority mutation and issues no receipt.
    const beforeReceipts = await sql(mf, "admission", "StagingAdmissionAuthority", STAGING_ADMISSION_AUTHORITY_ID, "SELECT * FROM lifecycle_receipts");
    const admissionProbe = await (await driver.fetch("http://localhost/probe-admission-rotation")).json() as { result: unknown };
    assert.deepEqual(admissionProbe.result, { status: "refused" });
    assert.deepEqual(await sql(mf, "admission", "StagingAdmissionAuthority", STAGING_ADMISSION_AUTHORITY_ID, "SELECT * FROM lifecycle_receipts"), beforeReceipts,
      "the staging admission entrypoint's rotation refusal inserts no receipt");
    // 8d: a mis-delivered rotate-release.json artifact in the staging request
    // bucket is never even read by the mailbox scheduled handler -- rejected
    // before reaching the guard layer at all, so no claim is created for it.
    await requests.put("rotate-release.json", JSON.stringify({ command: ["garbage"], signature: "not-a-signature" }));
    await scheduled(mf, "mailbox");
    assert.deepEqual(await sql(mf, "mailbox", "StagingLifecycleDispatchGuard", "staging-lifecycle-dispatch-v1", "SELECT * FROM claims"), beforeRotationClaims,
      "a rotate-release.json artifact produces no staging guard claim");

    await mf.dispose(); mf = undefined;

    // Proof 5: restart with retained SQLite storage preserves staging
    // initialization state and the exact receipt (no in-memory state survives;
    // a fresh Miniflare instance over the same persistence path simulates a
    // full process restart of every staging Worker and Durable Object).
    mf = await start(publicKey, join(runtimeRoot, "state"));
    assert.deepEqual(await sql(mf, "admission", "StagingAdmissionAuthority", STAGING_ADMISSION_AUTHORITY_ID, "SELECT digest FROM lifecycle_receipts"),
      receiptRows.map((row) => ({ digest: row.digest })));
    assert.deepEqual(await sql(mf, "mailbox", "StagingLifecycleDispatchGuard", "staging-lifecycle-dispatch-v1", "SELECT digest,status FROM claims"), claimRows);
    await (await mf.getR2Bucket("REQUEST_BUCKET", "mailbox")).put("initialize.json", JSON.stringify({ command, signature }));
    await scheduled(mf, "mailbox");
    assert.equal((await sql(mf, "admission", "StagingAdmissionAuthority", STAGING_ADMISSION_AUTHORITY_ID, "SELECT * FROM lifecycle_receipts")).length, 1,
      "restart plus replay does not redispatch");

    // Reconciliation still works after restart, through freshly re-acquired bindings.
    const nonceAfterRestart = "e".repeat(32);
    await (await mf.getR2Bucket("REQUEST_BUCKET", "mailbox")).put("reconcile.json", JSON.stringify({ version: 1, digest, nonce: nonceAfterRestart }));
    await scheduled(mf, "observer");
    const reconciliationAfterRestart = await (await mf.getR2Bucket("RESULT_BUCKET", "mailbox")).get(`reconciliation/${nonceAfterRestart}.json`);
    assert.ok(reconciliationAfterRestart, "the staging observer still reconciles correctly after a full restart");
    const parsedAfterRestart = await reconciliationAfterRestart!.json() as { status: string; environment: string };
    assert.equal(parsedAfterRestart.status, "EXACT_RECEIPT");
    assert.equal(parsedAfterRestart.environment, "staging");

    console.log("I3B staging workerd mailbox/guard/executor/admission/observer integration: PASS " +
      "(actual staging classes, cross-worker RPC, initialization, idempotent replay, restart persistence, " +
      "Production-artifact rejection, rotation fail-closed at the runtime RPC surface, no public lifecycle route)");
  } finally {
    if (mf) await mf.dispose();
    await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}
void main();
