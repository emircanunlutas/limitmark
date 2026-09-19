import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { build, type Plugin } from "esbuild";
import { convertV4MiniflareOptions, Log, LogLevel, Miniflare, type V4MiniflareOptions } from "miniflare";
import { encodeBase64url } from "../../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH } from "../../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, commandDigest, signAuthorityInitializationCommand,
  type AuthorityInitializationCommand } from "../../workers/admission-service/operator-command";
import { processSettlement, processSlot, type MailboxEnvironment } from "../../workers/lifecycle-mailbox/processor";
import { verifyLifecycleResult } from "../../operator/lifecycle-result";
import { createCliResultHarness } from "./support/i3b-cli-result-harness";

const root = process.cwd();
const runtimeRoot = join(root, ".wrangler", "tests", `i3b-mailbox-${process.pid}-${randomUUID()}`);
const paths = Object.fromEntries(["mailbox", "observer", "executor", "admission", "proxy", "admissionProxy", "driver"].map((name) => [name, join(runtimeRoot, `${name}.mjs`)]));
const entries: Record<string, string> = { mailbox: "workers/lifecycle-mailbox/index.ts", observer: "workers/lifecycle-observer.ts",
  executor: "workers/operator-lifecycle-executor.ts", admission: "workers/admission-service/index.ts",
  proxy: "tests/workers/support/i3b-counting-executor.ts",
  admissionProxy: "tests/workers/support/i3b-counting-admission.ts", driver: "tests/workers/support/i3b-driver.ts" };
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

async function start(publicKey: string, persistence: string, dropAck = false, failBefore = false): Promise<Miniflare> {
  const date = "2026-09-13";
  const admissionBindings = {
    AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey,
    ADMISSION_CURRENT_RPC_KEY: encodeBase64url(new Uint8Array(32).fill(9)),
    ADMISSION_CURRENT_RELEASE_ID: "i3b-current", ADMISSION_CURRENT_KEY_ID: "i3b-key",
    ADMISSION_CURRENT_ACTIVATED_AT_MS: "1", VERCEL_OIDC_ISSUER: "https://oidc.vercel.com/synthetic",
    VERCEL_OIDC_AUDIENCE: "synthetic", VERCEL_OIDC_SUBJECT: "owner:synthetic:project:synthetic:environment:production",
    VERCEL_OWNER_ID: "synthetic", VERCEL_PROJECT_ID: "synthetic",
  };
  const buckets = { REQUEST_BUCKET: "i3b-requests", RESULT_BUCKET: "i3b-results" };
  const workers = [
    { name: "mailbox", scriptPath: paths.mailbox, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      routes: ["mailbox.local/*"],
      bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey, LIFECYCLE_ENVIRONMENT: "production" }, r2Buckets: buckets,
      durableObjects: { DISPATCH_GUARD: { className: "LifecycleDispatchGuard", useSQLite: true } },
      serviceBindings: { LIFECYCLE_EXECUTOR: { name: "proxy", entrypoint: "CountingExecutor" },
        LIFECYCLE_READER: { name: "admission", entrypoint: "AuthorityLifecycleReadOnly" } } },
    { name: "observer", scriptPath: paths.observer, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      routes: ["observer.local/*"],
      r2Buckets: buckets, serviceBindings: { LIFECYCLE_READER: { name: "admission", entrypoint: "AuthorityLifecycleReadOnly" } } },
    { name: "proxy", scriptPath: paths.proxy, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      bindings: { DROP_ACK: dropAck ? "true" : "false", FAIL_BEFORE: failBefore ? "true" : "false" },
      serviceBindings: { EXECUTOR: { name: "executor", entrypoint: "OperatorLifecycleExecutor" } } },
    { name: "executor", scriptPath: paths.executor, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey, OPERATOR_EXECUTOR_ENVIRONMENT: "production" },
      serviceBindings: { ADMISSION_SERVICE: { name: "admissionProxy", entrypoint: "CountingAdmission" } } },
    { name: "admissionProxy", scriptPath: paths.admissionProxy, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      serviceBindings: { ADMISSION: { name: "admission", entrypoint: "AuthorityLifecycleOnly" } } },
    { name: "admission", scriptPath: paths.admission, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      bindings: admissionBindings, durableObjects: { AUTHORITY: { className: "ProductionAdmissionAuthority", useSQLite: true } } },
    { name: "driver", scriptPath: paths.driver, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      serviceBindings: { COUNTING_EXECUTOR: { name: "proxy", entrypoint: "CountingExecutor" },
        COUNTING_ADMISSION: { name: "admissionProxy", entrypoint: "CountingAdmission" } } },
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
async function count(mf: Miniflare): Promise<number> {
  const response = await (await mf.getWorker("driver")).fetch("http://localhost/count");
  return Number((await response.json() as { count: number }).count);
}
async function admissionCount(mf: Miniflare): Promise<number> {
  const response = await (await mf.getWorker("driver")).fetch("http://localhost/admission-count");
  return Number((await response.json() as { count: number }).count);
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
    await bundle();
    mf = await start(publicKey, join(runtimeRoot, "state"), true);
    const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production",
      ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "i3b-current", "i3b-key", Date.now(), true];
    const digest = await commandDigest(command);
    const signature = await signAuthorityInitializationCommand(command, privateKey);
    const requests = await mf.getR2Bucket("REQUEST_BUCKET", "mailbox");
    const results = await mf.getR2Bucket("RESULT_BUCKET", "mailbox");
    await requests.put("reconcile.json", JSON.stringify({ version: 1, digest, nonce: "c".repeat(32) }));
    await scheduled(mf, "observer");
    assert.equal((await (await results.get(`reconciliation/${"c".repeat(32)}.json`))?.json() as { status: string }).status, "NOT_FOUND");
    assert.equal((await sql(mf, "admission", "ProductionAdmissionAuthority", ADMISSION_AUTHORITY_ID,
      "SELECT name FROM sqlite_master WHERE type='table' AND name='authority_meta'")).length, 0);
    await requests.put("initialize.json", JSON.stringify({ command, signature: encodeBase64url(new Uint8Array(64)) }));
    await scheduled(mf, "mailbox");
    assert.equal(await count(mf), 0);
    assert.equal(await admissionCount(mf), 0);
    assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1", "SELECT * FROM claims")).length, 0);
    await requests.put("initialize.json", JSON.stringify({ command, signature }));
    const mailbox = await mf.getWorker("mailbox");
    assert.equal((await mailbox.fetch("http://localhost/initialize.json")).status, 404);
    assert.equal((await (await mf.getWorker("observer")).fetch("http://localhost/reconcile.json")).status, 404);
    await Promise.all([scheduled(mf, "mailbox"), scheduled(mf, "mailbox"), scheduled(mf, "mailbox")]);
    assert.equal(await count(mf), 1);
    assert.equal(await admissionCount(mf), 1, "one final-admission call per consumed digest");
    assert.equal((await sql(mf, "admission", "ProductionAdmissionAuthority", ADMISSION_AUTHORITY_ID,
      "SELECT * FROM lifecycle_receipts")).length, 1);
    assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1",
      "SELECT * FROM claims")).length, 1);
    const guardedStub = (await mf.getDurableObjectNamespace("DISPATCH_GUARD", "mailbox"))
      .getByName("production-lifecycle-dispatch-v1") as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
    for (const name of ["one", "process", "afterClaimSync", "beforeExecutorCall", "sql", "exec", "ledger",
      "deleteClaim", "deleteLatch", "reset", "rearm", "clear", "transactionSync", "sync", "settlementResolution"])
      await assert.rejects(async () => guardedStub[name]("DELETE FROM claims"), (error: unknown) => {
        assert.match(String(error), /RPC receiver does not implement the method/u);
        return true;
      }, `${name} must not be an RPC method`);
    assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1",
      "SELECT * FROM claims")).length, 1, "RPC abuse cannot delete the consumed claim");
    assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1",
      "SELECT * FROM latch")).length, 1, "RPC abuse cannot release the latch");
    await scheduled(mf, "mailbox");
    assert.equal(await count(mf), 1, "same signed digest remains consumed after attempted RPC abuse");
    assert.equal(await admissionCount(mf), 1);
    const lifecycle = await results.get(`lifecycle/${digest}.json`);
    assert.equal((await lifecycle?.json() as { status: string }).status, "UNCONFIRMED");
    const different: AuthorityInitializationCommand = [command[0], command[1], command[2], command[3], command[4], command[5],
      command[6], command[7] + 1, true];
    await requests.put("initialize.json", JSON.stringify({ command: different,
      signature: await signAuthorityInitializationCommand(different, privateKey) }));
    await scheduled(mf, "mailbox");
    assert.equal(await count(mf), 1, "different signed command is blocked while first digest is unresolved");
    assert.equal(await admissionCount(mf), 1);
    assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1",
      "SELECT * FROM claims")).length, 1);
    await requests.put("initialize.json", JSON.stringify({ command, signature }));
    const nonce = "a".repeat(32);
    await requests.put("reconcile.json", JSON.stringify({ version: 1, digest, nonce }));
    await scheduled(mf, "observer");
    const reconciliation = await results.get(`reconciliation/${nonce}.json`);
    assert.equal((await reconciliation?.json() as { status: string }).status, "EXACT_RECEIPT");
    const settlementNonce = "b".repeat(32);
    await requests.put("settle.json", JSON.stringify({ version: 1, digest, nonce: settlementNonce }));
    await scheduled(mf, "mailbox");
    const settlement = await results.get(`settlement/${settlementNonce}.json`);
    assert.equal((await settlement?.json() as { settled: boolean }).settled, true);
    await scheduled(mf, "mailbox");
    assert.equal((await (await results.get(`settlement/${settlementNonce}.json`))?.json() as { settled: boolean }).settled, true);
    assert.equal(await count(mf), 1);
    assert.equal(await admissionCount(mf), 1);
    await mf.dispose(); mf = undefined;
    mf = await start(publicKey, join(runtimeRoot, "state"), false);
    await scheduled(mf, "mailbox");
    assert.equal(await count(mf), 0);
    assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1",
      "SELECT * FROM claims")).length, 1);
    assert.equal((await sql(mf, "admission", "ProductionAdmissionAuthority", ADMISSION_AUTHORITY_ID,
      "SELECT digest FROM lifecycle_receipts")).length, 1);
    await mf.dispose(); mf = undefined;
    mf = await start(publicKey, join(runtimeRoot, "precall-state"), false, true);
    const precallRequests = await mf.getR2Bucket("REQUEST_BUCKET", "mailbox");
    await precallRequests.put("initialize.json", JSON.stringify({ command, signature }));
    await Promise.all([scheduled(mf, "mailbox"), scheduled(mf, "mailbox")]);
    assert.equal(await count(mf), 1);
    assert.equal(await admissionCount(mf), 0, "injected pre-admission failure never reached final adapter");
    assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1", "SELECT * FROM claims")).length, 1);
    assert.equal((await sql(mf, "admission", "ProductionAdmissionAuthority", ADMISSION_AUTHORITY_ID,
      "SELECT name FROM sqlite_master WHERE type='table' AND name='lifecycle_receipts'")).length, 0);
    await precallRequests.put("settle.json", JSON.stringify({ version: 1, digest, nonce: "d".repeat(32) }));
    await scheduled(mf, "mailbox");
    assert.equal((await (await (await mf.getR2Bucket("RESULT_BUCKET", "mailbox")).get(`settlement/${"d".repeat(32)}.json`))?.json() as { settled: boolean }).settled, false);
    assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1", "SELECT * FROM latch")).length, 1);
    await mf.dispose(); mf = undefined;
    mf = await start(publicKey, join(runtimeRoot, "precall-state"), false, false);
    await scheduled(mf, "mailbox");
    assert.equal(await count(mf), 0, "consumed-before-call remains permanently closed after restart");
    assert.equal(await admissionCount(mf), 0);
    await mf.dispose(); mf = undefined;
    for (const publicationFault of ["5xx", "timeout", "reset", "malformed"] as const) {
      mf = await start(publicKey, join(runtimeRoot, `publication-${publicationFault}`));
      const faultRequests = await mf.getR2Bucket("REQUEST_BUCKET", "mailbox");
      const faultResults = await mf.getR2Bucket("RESULT_BUCKET", "mailbox");
      await faultRequests.put("initialize.json", JSON.stringify({ command, signature }));
      const namespace = await mf.getDurableObjectNamespace("DISPATCH_GUARD", "mailbox");
      const fakeResult = {
        head: (key: string) => faultResults.head(key),
        put: async () => {
          if (publicationFault === "malformed") return { key: "wrong-key" };
          throw new Error(`injected-publication-${publicationFault}`);
        },
      };
      await assert.rejects(() => processSlot({ REQUEST_BUCKET: faultRequests, RESULT_BUCKET: fakeResult,
        DISPATCH_GUARD: namespace } as unknown as MailboxEnvironment, "initialize.json"));
      assert.equal(await count(mf), 1, `${publicationFault}: exactly one lifecycle dispatch`);
      assert.equal(await admissionCount(mf), 1, `${publicationFault}: exactly one final-admission call`);
      assert.equal((await sql(mf, "admission", "ProductionAdmissionAuthority", ADMISSION_AUTHORITY_ID,
        "SELECT digest FROM lifecycle_receipts")).length, 1, `${publicationFault}: authority committed`);
      assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1",
        "SELECT status FROM claims"))[0].status, "SUCCESS", `${publicationFault}: guard recorded terminal authority result`);
      assert.equal(await faultResults.get(`lifecycle/${digest}.json`), null, `${publicationFault}: no lifecycle result was published`);
      await scheduled(mf, "mailbox");
      assert.equal(await count(mf), 1, `${publicationFault}: duplicate schedule does not replay mutation`);
      assert.equal(await admissionCount(mf), 1);
      const nonce = publicationFault === "5xx" ? "1".repeat(32) : publicationFault === "timeout" ? "2".repeat(32) :
        publicationFault === "reset" ? "3".repeat(32) : "4".repeat(32);
      await faultRequests.put("reconcile.json", JSON.stringify({ version: 1, digest, nonce }));
      const authorityBefore = await Promise.all(["authority_meta", "active_releases", "nonces", "observations", "lifecycle_receipts"]
        .map((table) => sql(mf!, "admission", "ProductionAdmissionAuthority", ADMISSION_AUTHORITY_ID, `SELECT * FROM ${table}`)));
      await scheduled(mf, "observer");
      const reconciliation = await faultResults.get(`reconciliation/${nonce}.json`);
      assert.ok(reconciliation, `${publicationFault}: read-only observer reconstructed a result`);
      assert.equal(verifyLifecycleResult(new Uint8Array(await reconciliation.arrayBuffer()), "reconciliation", { digest, nonce }).status,
        "SUCCESS", `${publicationFault}: exact receipt proves commit`);
      assert.equal(await count(mf), 1, `${publicationFault}: reconstruction did not dispatch mutation`);
      assert.equal(await admissionCount(mf), 1);
      const authorityAfter = await Promise.all(["authority_meta", "active_releases", "nonces", "observations", "lifecycle_receipts"]
        .map((table) => sql(mf!, "admission", "ProductionAdmissionAuthority", ADMISSION_AUTHORITY_ID, `SELECT * FROM ${table}`)));
      assert.deepEqual(authorityAfter, authorityBefore, `${publicationFault}: reconstruction did not write authority state`);
      if (publicationFault === "5xx") {
        const settlementNonce = "5".repeat(32);
        await faultRequests.put("settle.json", JSON.stringify({ version: 1, digest, nonce: settlementNonce }));
        await assert.rejects(() => processSettlement({ REQUEST_BUCKET: faultRequests, RESULT_BUCKET: fakeResult,
          DISPATCH_GUARD: namespace } as unknown as MailboxEnvironment));
        assert.equal(await faultResults.get(`settlement/${settlementNonce}.json`), null, "lost settlement result is unconfirmed");
        assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1",
          "SELECT * FROM latch")).length, 0, "positive receipt released only the latch");
        assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1",
          "SELECT * FROM claims")).length, 1, "settlement publication failure retained consumed history");
        assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1",
          "SELECT * FROM settlements")).length, 1, "positive control resolution was durably recorded");
        await mf.dispose(); mf = undefined;
        mf = await start(publicKey, join(runtimeRoot, `publication-${publicationFault}`));
        await scheduled(mf, "mailbox");
        const recovered = await (await mf.getR2Bucket("RESULT_BUCKET", "mailbox")).get(`settlement/${settlementNonce}.json`);
        assert.equal((await recovered?.json() as { settled: boolean }).settled, true,
          "repeated settlement after restart recovers durable positive status");
        assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1",
          "SELECT * FROM claims")).length, 1);
        assert.equal(await count(mf), 0, "restart and settlement recovery do not redispatch");
        assert.equal(await admissionCount(mf), 0);
      }
      await mf.dispose(); mf = undefined;
    }
    mf = await start(publicKey, join(runtimeRoot, "unavailable-state"));
    const unavailableStorage = await mf.unsafeGetDurableObjectStorage("admission", "ProductionAdmissionAuthority", { name: ADMISSION_AUTHORITY_ID });
    await unavailableStorage.exec("CREATE TABLE authority_meta(singleton INTEGER PRIMARY KEY, authority_id TEXT NOT NULL, policy_epoch TEXT NOT NULL, last_now_ms INTEGER NOT NULL)");
    await unavailableStorage.exec("INSERT INTO authority_meta(singleton,authority_id,policy_epoch,last_now_ms) VALUES(1,'wrong-authority','wrong-epoch',0)");
    const unavailableRequests = await mf.getR2Bucket("REQUEST_BUCKET", "observer");
    const unavailableResults = await mf.getR2Bucket("RESULT_BUCKET", "observer");
    const unavailableNonce = "6".repeat(32);
    await unavailableRequests.put("reconcile.json", JSON.stringify({ version: 1, digest, nonce: unavailableNonce }));
    await scheduled(mf, "observer");
    const unavailableResult = await unavailableResults.get(`reconciliation/${unavailableNonce}.json`);
    assert.ok(unavailableResult, "actual unavailable authority inspection publishes a bounded observation");
    const unavailableBytes = new Uint8Array(await unavailableResult.arrayBuffer());
    assert.equal(verifyLifecycleResult(unavailableBytes, "reconciliation", { digest, nonce: unavailableNonce }).status,
      "UNCONFIRMED", "unavailable authority never proves refusal");
    assert.equal((JSON.parse(new TextDecoder().decode(unavailableBytes)) as { status: string }).status, "UNAVAILABLE");
    const cli = await createCliResultHarness();
    try {
      const observed = await cli.run(unavailableBytes, "reconciliation", digest, unavailableNonce);
      assert.equal(observed.exitCode, 3, observed.stderr);
      assert.equal((JSON.parse(observed.stdout) as { status: string }).status, "UNCONFIRMED");
      assert.deepEqual(observed.methods, ["GET"]);
    } finally { await cli.dispose(); }
    assert.equal(await count(mf), 0);
    assert.equal(await admissionCount(mf), 0);
    await mf.dispose(); mf = undefined;
    mf = await start(publicKey, join(runtimeRoot, "capacity-state"));
    const guardStorage = await mf.unsafeGetDurableObjectStorage("mailbox", "LifecycleDispatchGuard", { name: "production-lifecycle-dispatch-v1" });
    await guardStorage.exec("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO claims(digest,operation,status) SELECT printf('%064x',x),'initialize','CLAIMED' FROM n");
    await (await mf.getR2Bucket("REQUEST_BUCKET", "mailbox")).put("initialize.json", JSON.stringify({ command, signature }));
    await scheduled(mf, "mailbox");
    assert.equal(await count(mf), 0, "full ledger refuses before mutation dispatch");
    assert.equal(await admissionCount(mf), 0);
    assert.equal((await sql(mf, "mailbox", "LifecycleDispatchGuard", "production-lifecycle-dispatch-v1", "SELECT * FROM claims")).length, 4_096);
    console.log("I3B workerd mailbox/guard/executor/admission/observer integration: PASS (duplicate delivery, lost ack, publication faults, read-only reconstruction, positive-only settlement, consumed-before-call, capacity, restart)");
  } finally {
    if (mf) await mf.dispose();
    await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}
void main();
