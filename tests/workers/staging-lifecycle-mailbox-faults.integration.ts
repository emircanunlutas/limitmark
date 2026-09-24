// Gate 8 Phase 0: staging fault parity in real workerd. Mirrors the fault
// matrix of tests/workers/lifecycle-mailbox.integration.ts (Production twin)
// against the ACTUAL staging classes: staging mailbox + StagingLifecycleDispatchGuard,
// staging observer, StagingOperatorLifecycleExecutor, StagingAuthorityLifecycleOnly/
// StagingAuthorityLifecycleReadOnly and StagingAdmissionAuthority. The only
// non-production Workers are the existing test-only counting proxies
// (tests/workers/support/i3b-counting-executor.ts, i3b-counting-admission.ts,
// i3b-driver.ts) inserted between real service bindings; no fault hook is added
// to any deployed Worker. Local Miniflare only: synthetic keys, synthetic buckets,
// no remote binding, no Wrangler process, telemetry disabled, persistence under
// an isolated .wrangler/tests path.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve, sep } from "node:path";
import { build, type Plugin } from "esbuild";
import { convertV4MiniflareOptions, Log, LogLevel, Miniflare, type V4MiniflareOptions } from "miniflare";
import { encodeBase64url } from "../../src/lib/ingress-protocol";
import { ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, commandDigest, signAuthorityInitializationCommand,
  type AuthorityInitializationCommand } from "../../workers/admission-service/operator-command";
import { processStagingInitializationSlot, processStagingSettlement, type StagingMailboxEnvironment } from "../../workers/lifecycle-mailbox/staging-processor";
import { verifyLifecycleResult } from "../../operator/lifecycle-result";

// Inherited provider variables are dropped before anything else runs.
for (const name of Object.keys(process.env)) if (/^(CLOUDFLARE_|CF_)/iu.test(name)) delete process.env[name];
process.env.WRANGLER_SEND_METRICS = "false";

const root = process.cwd();
const testsRoot = resolve(root, ".wrangler", "tests");
const runtimeRoot = join(testsRoot, `i3b-staging-faults-${process.pid}-${randomUUID()}`);
const GUARD = "StagingLifecycleDispatchGuard";
const GUARD_OBJECT = "staging-lifecycle-dispatch-v1";
const AUTHORITY = "StagingAdmissionAuthority";
const paths = Object.fromEntries(["mailbox", "observer", "executor", "admission", "proxy", "admissionProxy", "driver"]
  .map((name) => [name, join(runtimeRoot, `${name}.mjs`)]));
const entries: Record<string, string> = {
  mailbox: "workers/lifecycle-mailbox/staging-index.ts",
  observer: "workers/staging-lifecycle-observer.ts",
  executor: "workers/staging-operator-lifecycle-executor.ts",
  admission: "workers/admission-service/index.ts",
  proxy: "tests/workers/support/i3b-counting-executor.ts",
  admissionProxy: "tests/workers/support/i3b-counting-admission.ts",
  driver: "tests/workers/support/i3b-driver.ts",
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

type Faults = { dropAck?: boolean; failBefore?: boolean };
async function start(publicKey: string, state: string, faults: Faults = {}): Promise<Miniflare> {
  const persistence = join(runtimeRoot, state);
  assert.ok(resolve(persistence).startsWith(resolve(runtimeRoot) + sep), "persistence stays under the isolated test root");
  const date = "2026-09-13";
  const admissionBindings = {
    AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey,
    ADMISSION_CURRENT_RPC_KEY: encodeBase64url(new Uint8Array(32).fill(7)),
    ADMISSION_CURRENT_RELEASE_ID: "synthetic-current", ADMISSION_CURRENT_KEY_ID: "synthetic-key",
    ADMISSION_CURRENT_ACTIVATED_AT_MS: "1", VERCEL_OIDC_ISSUER: "https://oidc.vercel.com/synthetic",
    VERCEL_OIDC_AUDIENCE: "synthetic", VERCEL_OIDC_SUBJECT: "owner:synthetic:project:synthetic:environment:production",
    VERCEL_OWNER_ID: "synthetic", VERCEL_PROJECT_ID: "synthetic",
  };
  const buckets = { REQUEST_BUCKET: "i3b-staging-fault-requests", RESULT_BUCKET: "i3b-staging-fault-results" };
  const workers = [
    { name: "mailbox", scriptPath: paths.mailbox, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      routes: ["mailbox.local/*"],
      bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey, LIFECYCLE_ENVIRONMENT: "staging" }, r2Buckets: buckets,
      durableObjects: { DISPATCH_GUARD: { className: GUARD, useSQLite: true } },
      serviceBindings: { LIFECYCLE_EXECUTOR: { name: "proxy", entrypoint: "CountingExecutor" },
        LIFECYCLE_READER: { name: "admission", entrypoint: "StagingAuthorityLifecycleReadOnly" } } },
    { name: "observer", scriptPath: paths.observer, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      routes: ["observer.local/*"],
      r2Buckets: buckets, serviceBindings: { LIFECYCLE_READER: { name: "admission", entrypoint: "StagingAuthorityLifecycleReadOnly" } } },
    { name: "proxy", scriptPath: paths.proxy, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      bindings: { DROP_ACK: faults.dropAck ? "true" : "false", FAIL_BEFORE: faults.failBefore ? "true" : "false" },
      serviceBindings: { EXECUTOR: { name: "executor" } } },
    { name: "executor", scriptPath: paths.executor, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey, OPERATOR_EXECUTOR_ENVIRONMENT: "staging" },
      serviceBindings: { ADMISSION_SERVICE: { name: "admissionProxy", entrypoint: "CountingAdmission" } } },
    { name: "admissionProxy", scriptPath: paths.admissionProxy, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      serviceBindings: { ADMISSION: { name: "admission", entrypoint: "StagingAuthorityLifecycleOnly" } } },
    { name: "admission", scriptPath: paths.admission, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      bindings: admissionBindings, durableObjects: { AUTHORITY: { className: AUTHORITY, useSQLite: true } } },
    { name: "driver", scriptPath: paths.driver, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      serviceBindings: { COUNTING_EXECUTOR: { name: "proxy", entrypoint: "CountingExecutor" },
        COUNTING_ADMISSION: { name: "admissionProxy", entrypoint: "CountingAdmission" } } },
  ];
  assert.equal(/"remote"/u.test(JSON.stringify(workers)), false, "no remote (provider) binding in the harness");
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
async function counter(mf: Miniflare, path: "count" | "admission-count"): Promise<number> {
  const response = await (await mf.getWorker("driver")).fetch(`http://localhost/${path}`);
  return Number((await response.json() as { count: number }).count);
}
async function counts(mf: Miniflare): Promise<[number, number]> {
  return [await counter(mf, "count"), await counter(mf, "admission-count")];
}
async function sql(mf: Miniflare, script: string, className: string, name: string, query: string): Promise<Array<Record<string, unknown>>> {
  const storage = await mf.unsafeGetDurableObjectStorage(script, className, { name });
  return storage.exec(query) as Promise<Array<Record<string, unknown>>>;
}
const guardSql = (mf: Miniflare, query: string) => sql(mf, "mailbox", GUARD, GUARD_OBJECT, query);
const authoritySql = (mf: Miniflare, query: string) => sql(mf, "admission", AUTHORITY, STAGING_ADMISSION_AUTHORITY_ID, query);
async function authorityTables(mf: Miniflare): Promise<Record<string, unknown>> {
  const tables = (await authoritySql(mf, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '\\_%' ESCAPE '\\' ORDER BY name"))
    .map((row) => String(row.name));
  return Object.fromEntries(await Promise.all(tables.map(async (table) => [table, await authoritySql(mf, `SELECT * FROM ${table}`)])));
}
async function latchDigest(mf: Miniflare): Promise<string | null> {
  const rows = await guardSql(mf, "SELECT digest FROM latch WHERE singleton=1");
  return rows.length ? String(rows[0].digest) : null;
}
async function readResult(mf: Miniflare, key: string): Promise<Uint8Array | null> {
  const object = await (await mf.getR2Bucket("RESULT_BUCKET", "mailbox")).get(key);
  return object ? new Uint8Array(await object.arrayBuffer()) : null;
}
const verify = (bytes: Uint8Array, kind: "lifecycle" | "reconciliation" | "settlement", expected: { digest: string; nonce?: string }) =>
  verifyLifecycleResult(bytes, kind, expected, Date.now(), "staging", STAGING_ADMISSION_AUTHORITY_ID);
async function put(mf: Miniflare, key: string, value: object): Promise<void> {
  await (await mf.getR2Bucket("REQUEST_BUCKET", "mailbox")).put(key, JSON.stringify(value));
}
async function reconcile(mf: Miniflare, digest: string, nonce: string) {
  await put(mf, "reconcile.json", { version: 1, digest, nonce });
  await scheduled(mf, "observer");
  const bytes = await readResult(mf, `reconciliation/${nonce}.json`);
  assert.ok(bytes, "observer published a reconciliation result");
  return { raw: JSON.parse(new TextDecoder().decode(bytes)) as { status: string; receipt: { sequence: number } | null },
    verified: verify(bytes, "reconciliation", { digest, nonce }) };
}
async function settle(mf: Miniflare, digest: string, nonce: string): Promise<boolean> {
  await put(mf, "settle.json", { version: 1, digest, nonce });
  await scheduled(mf, "mailbox");
  const bytes = await readResult(mf, `settlement/${nonce}.json`);
  assert.ok(bytes, "settlement result published");
  return (JSON.parse(new TextDecoder().decode(bytes)) as { settled: boolean }).settled;
}

type Signed = { command: AuthorityInitializationCommand; digest: string; artifact: { command: AuthorityInitializationCommand; signature: string } };
async function signed(privateKey: string, issuedAtMs: number, release: string): Promise<Signed> {
  const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging",
    STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, release, "synthetic-key", issuedAtMs, false];
  return { command, digest: await commandDigest(command),
    artifact: { command, signature: await signAuthorityInitializationCommand(command, privateKey) } };
}

async function main(): Promise<void> {
  assert.ok(resolve(runtimeRoot).startsWith(testsRoot + sep), "runtime root is isolated under .wrangler/tests");
  await mkdir(runtimeRoot, { recursive: true });
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const privateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  const publicKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const now = Date.now();
  const first = await signed(privateKey, now, "synthetic-release-1");
  const second = await signed(privateKey, now + 1, "synthetic-release-2");
  const third = await signed(privateKey, now + 2, "synthetic-release-3");
  let mf: Miniflare | undefined;
  try {
    await bundle();

    // --- 1. Concurrent same-digest delivery with lost acknowledgement after commit.
    mf = await start(publicKey, "commit-state", { dropAck: true });
    await put(mf, "initialize.json", first.artifact);
    await Promise.all([scheduled(mf, "mailbox"), scheduled(mf, "mailbox"), scheduled(mf, "mailbox")]);
    assert.deepEqual(await counts(mf), [1, 1], "exactly one executor and one admission dispatch");
    assert.equal((await authoritySql(mf, "SELECT * FROM lifecycle_receipts")).length, 1, "one receipt");
    assert.deepEqual(await guardSql(mf, "SELECT digest,status FROM claims"), [{ digest: first.digest, status: "CLAIMED" }],
      "an ambiguous dispatch leaves the consumed claim CLAIMED (never reset)");
    const lostAck = await readResult(mf, `lifecycle/${first.digest}.json`);
    assert.ok(lostAck);
    assert.equal(verify(lostAck, "lifecycle", { digest: first.digest }).status, "UNCONFIRMED", "lost ack stays ambiguous at transport");

    // --- 9. Exact replay: resolved by the read path, never a second dispatch.
    await scheduled(mf, "mailbox");
    await scheduled(mf, "mailbox");
    assert.deepEqual(await counts(mf), [1, 1], "exact replay does not redispatch");

    // A different command while the first is unresolved is blocked by the latch.
    await put(mf, "initialize.json", second.artifact);
    await scheduled(mf, "mailbox");
    assert.deepEqual(await counts(mf), [1, 1]);
    assert.equal((await guardSql(mf, "SELECT * FROM claims")).length, 1);
    assert.equal(await latchDigest(mf), first.digest);
    // Each mailbox tick processes settle.json before initialize.json, so the
    // slot is restored to the committed artifact before settlement (as in the
    // Production twin); the hazard below exercises the other ordering deliberately.
    await put(mf, "initialize.json", first.artifact);

    // --- 10. Read-only reconciliation: exact receipt for the committed digest,
    // NOT_FOUND for a synthetic digest, authority tables unchanged across reads.
    const beforeReads = await authorityTables(mf);
    const exact = await reconcile(mf, first.digest, "1".repeat(32));
    assert.equal(exact.raw.status, "EXACT_RECEIPT");
    assert.equal(exact.verified.status, "SUCCESS", "exact receipt proves commit despite the lost ack");
    assert.equal(exact.raw.receipt?.sequence, 1);
    const synthetic = await reconcile(mf, "d".repeat(64), "2".repeat(32));
    assert.equal(synthetic.raw.status, "NOT_FOUND");
    assert.deepEqual([synthetic.verified.status, (synthetic.verified as { observation?: string }).observation], ["UNCONFIRMED", "NOT_FOUND"]);
    assert.deepEqual(await authorityTables(mf), beforeReads, "reconciliation wrote no authority state");
    assert.deepEqual(await counts(mf), [1, 1], "reconciliation dispatched nothing");

    // --- 11. Positive-only settlement.
    assert.equal(await settle(mf, "e".repeat(64), "3".repeat(32)), false, "unknown digest cannot settle");
    assert.equal(await latchDigest(mf), first.digest, "latch still held");
    assert.equal(await settle(mf, first.digest, "4".repeat(32)), true, "positive exact receipt settles");
    assert.equal(await latchDigest(mf), null, "only the latch was released");
    assert.equal((await guardSql(mf, "SELECT * FROM claims")).length, 1, "consumed claim retained");
    assert.equal(await settle(mf, first.digest, "5".repeat(32)), true, "duplicate settlement is idempotent");
    assert.equal((await guardSql(mf, "SELECT * FROM settlements")).length, 1);
    assert.deepEqual(await counts(mf), [1, 1], "settlement never dispatches");
    await mf.dispose(); mf = undefined;

    // --- 8. HAZARD CHARACTERIZATION (current behavior, not a desired property):
    // after positive settlement, a fresh initialization for a new digest is
    // claimed, dispatched and refused as already initialized, and its latch can
    // never be released. Restarted without the lost-ack proxy so the real
    // authority refusal is observed.
    mf = await start(publicKey, "commit-state");
    const metaBefore = await authoritySql(mf, "SELECT * FROM authority_meta");
    const receiptsBefore = await authoritySql(mf, "SELECT digest,sequence FROM lifecycle_receipts");
    assert.deepEqual(receiptsBefore, [{ digest: first.digest, sequence: 1 }]);
    await put(mf, "initialize.json", second.artifact);
    await scheduled(mf, "mailbox");
    assert.deepEqual(await counts(mf), [1, 1], "digest 2 was claimed and dispatched to the authority");
    assert.deepEqual(await guardSql(mf, `SELECT status FROM claims WHERE digest='${second.digest}'`), [{ status: "REFUSED" }]);
    assert.equal(await latchDigest(mf), second.digest, "digest 2 now holds the latch");
    const refused = await readResult(mf, `lifecycle/${second.digest}.json`);
    assert.ok(refused);
    assert.equal((JSON.parse(new TextDecoder().decode(refused)) as { status: string }).status, "REFUSED");
    assert.equal(await settle(mf, second.digest, "6".repeat(32)), false, "digest 2 can never positively settle");
    await put(mf, "initialize.json", third.artifact);
    await scheduled(mf, "mailbox");
    assert.deepEqual(await counts(mf), [1, 1], "digest 3 is blocked (active-or-capacity) and never dispatched");
    assert.equal((await guardSql(mf, `SELECT * FROM claims WHERE digest='${third.digest}'`)).length, 0);
    assert.equal(await readResult(mf, `lifecycle/${third.digest}.json`), null, "UNAVAILABLE outcomes are not published");
    await mf.dispose(); mf = undefined;
    mf = await start(publicKey, "commit-state");
    assert.equal(await latchDigest(mf), second.digest, "hazard latch survives restart");
    await scheduled(mf, "mailbox");
    await put(mf, "initialize.json", first.artifact);
    await scheduled(mf, "mailbox");
    assert.deepEqual(await counts(mf), [0, 0], "no dispatch of any digest after restart");
    assert.deepEqual(await authoritySql(mf, "SELECT * FROM authority_meta"), metaBefore, "authority metadata unchanged");
    assert.deepEqual(await authoritySql(mf, "SELECT digest,sequence FROM lifecycle_receipts"), receiptsBefore,
      "authority still holds exactly the original receipt, sequence 1");
    assert.equal((await reconcile(mf, first.digest, "7".repeat(32))).verified.status, "SUCCESS");
    await mf.dispose(); mf = undefined;

    // --- 2/3. Consumed-before-call: the executor is never reached.
    mf = await start(publicKey, "precall-state", { failBefore: true });
    await put(mf, "initialize.json", first.artifact);
    await Promise.all([scheduled(mf, "mailbox"), scheduled(mf, "mailbox")]);
    assert.deepEqual(await counts(mf), [1, 0], "one guarded RPC attempt; the real executor and admission never ran");
    assert.deepEqual(await guardSql(mf, "SELECT digest,status FROM claims"), [{ digest: first.digest, status: "CLAIMED" }],
      "an ambiguous dispatch leaves the consumed claim CLAIMED (never reset)");
    assert.equal(await latchDigest(mf), first.digest, "claim consumed and latch held");
    assert.equal((await authoritySql(mf, "SELECT name FROM sqlite_master WHERE type='table' AND name='lifecycle_receipts'")).length, 0,
      "authority never initialized");
    const precall = await readResult(mf, `lifecycle/${first.digest}.json`);
    assert.ok(precall);
    assert.equal(verify(precall, "lifecycle", { digest: first.digest }).status, "UNCONFIRMED");
    assert.equal(await settle(mf, first.digest, "8".repeat(32)), false, "no receipt: cannot settle");
    await mf.dispose(); mf = undefined;
    mf = await start(publicKey, "precall-state");
    await scheduled(mf, "mailbox");
    assert.deepEqual(await counts(mf), [0, 0], "consumed-before-call remains permanently closed after restart");
    await put(mf, "initialize.json", second.artifact);
    await scheduled(mf, "mailbox");
    assert.deepEqual(await counts(mf), [0, 0], "a fresh different digest is blocked");
    assert.equal((await guardSql(mf, "SELECT * FROM claims")).length, 1);
    assert.equal(await latchDigest(mf), first.digest);
    await mf.dispose(); mf = undefined;

    // --- 5. Lifecycle result publication faults.
    const publicationNonces = { "5xx": "9".repeat(32), timeout: "a".repeat(32), reset: "b".repeat(32), malformed: "c".repeat(32) } as const;
    for (const fault of ["5xx", "timeout", "reset", "malformed"] as const) {
      mf = await start(publicKey, `publication-${fault}`);
      const faultRequests = await mf.getR2Bucket("REQUEST_BUCKET", "mailbox");
      const faultResults = await mf.getR2Bucket("RESULT_BUCKET", "mailbox");
      await faultRequests.put("initialize.json", JSON.stringify(first.artifact));
      const namespace = await mf.getDurableObjectNamespace("DISPATCH_GUARD", "mailbox");
      const failingResults = {
        head: (key: string) => faultResults.head(key),
        put: async () => {
          if (fault === "malformed") return { key: "wrong-key" };
          throw new Error(`injected-publication-${fault}`);
        },
      };
      const faultEnv = { REQUEST_BUCKET: faultRequests, RESULT_BUCKET: failingResults, DISPATCH_GUARD: namespace } as unknown as StagingMailboxEnvironment;
      await assert.rejects(() => processStagingInitializationSlot(faultEnv));
      assert.deepEqual(await counts(mf), [1, 1], `${fault}: exactly one dispatch`);
      assert.equal((await authoritySql(mf, "SELECT * FROM lifecycle_receipts")).length, 1, `${fault}: authority committed`);
      assert.deepEqual(await guardSql(mf, "SELECT status FROM claims"), [{ status: "SUCCESS" }], `${fault}: guard recorded the authority result`);
      assert.equal(await faultResults.get(`lifecycle/${first.digest}.json`), null, `${fault}: no lifecycle result was published`);
      await assert.rejects(() => processStagingInitializationSlot(faultEnv));
      await scheduled(mf, "mailbox");
      assert.deepEqual(await counts(mf), [1, 1], `${fault}: repeated polling does not redispatch`);
      const tablesBefore = await authorityTables(mf);
      const recovered = await reconcile(mf, first.digest, publicationNonces[fault]);
      assert.equal(recovered.verified.status, "SUCCESS", `${fault}: authoritative truth recovered through read-only reconciliation`);
      assert.deepEqual(await authorityTables(mf), tablesBefore, `${fault}: reconciliation wrote no authority state`);
      assert.deepEqual(await counts(mf), [1, 1]);
      if (fault === "5xx") {
        const nonce = "f".repeat(32);
        await faultRequests.put("settle.json", JSON.stringify({ version: 1, digest: first.digest, nonce }));
        await assert.rejects(() => processStagingSettlement(faultEnv));
        assert.equal(await faultResults.get(`settlement/${nonce}.json`), null, "lost settlement result stays unconfirmed");
        assert.equal(await latchDigest(mf), null, "positive receipt released only the latch");
        assert.equal((await guardSql(mf, "SELECT * FROM claims")).length, 1, "settlement publication failure retained the claim");
        assert.equal((await guardSql(mf, "SELECT * FROM settlements")).length, 1);
        await mf.dispose(); mf = undefined;
        mf = await start(publicKey, `publication-${fault}`);
        await scheduled(mf, "mailbox");
        const settlement = await readResult(mf, `settlement/${nonce}.json`);
        assert.ok(settlement);
        assert.equal(verify(settlement, "settlement", { digest: first.digest, nonce }).status, "SETTLED",
          "repeated settlement after restart recovers the durable positive status");
        assert.equal((await guardSql(mf, "SELECT * FROM claims")).length, 1);
        assert.deepEqual(await counts(mf), [0, 0], "restart and settlement recovery do not redispatch");
      }
      await mf.dispose(); mf = undefined;
    }

    // --- 6. Unavailable and HISTORY_INCOMPLETE authority reads: no claim, no mutation.
    for (const [state, seed, observed] of [
      ["unavailable-state", ["INSERT INTO authority_meta(singleton,authority_id,policy_epoch,last_now_ms) VALUES(1,'wrong-authority','wrong-epoch',0)"], "UNAVAILABLE"],
      ["history-state", [`INSERT INTO authority_meta(singleton,authority_id,policy_epoch,last_now_ms) VALUES(1,'${STAGING_ADMISSION_AUTHORITY_ID}','${ADMISSION_POLICY_EPOCH}',0)`,
        "CREATE TABLE active_releases(release_id TEXT PRIMARY KEY, key_id TEXT NOT NULL UNIQUE, activated_ms INTEGER NOT NULL, retired_ms INTEGER)"], "HISTORY_INCOMPLETE"],
    ] as const) {
      mf = await start(publicKey, state);
      await authoritySql(mf, "CREATE TABLE authority_meta(singleton INTEGER PRIMARY KEY, authority_id TEXT NOT NULL, policy_epoch TEXT NOT NULL, last_now_ms INTEGER NOT NULL)");
      for (const statement of seed) await authoritySql(mf, statement);
      const tablesBefore = await authorityTables(mf);
      const nonce = state === "unavailable-state" ? "a1".repeat(16) : "b2".repeat(16);
      const observation = await reconcile(mf, first.digest, nonce);
      assert.equal(observation.raw.status, observed);
      assert.deepEqual([observation.verified.status, (observation.verified as { observation?: string }).observation], ["UNCONFIRMED", observed],
        `${observed} never proves refusal or rollback`);
      await put(mf, "initialize.json", first.artifact);
      await scheduled(mf, "mailbox");
      assert.deepEqual(await counts(mf), [0, 0], `${observed}: no dispatch`);
      assert.equal((await guardSql(mf, "SELECT * FROM claims")).length, 0, `${observed}: no claim consumed`);
      assert.equal(await latchDigest(mf), null);
      assert.equal(await readResult(mf, `lifecycle/${first.digest}.json`), null);
      assert.deepEqual(await authorityTables(mf), tablesBefore, `${observed}: authority state untouched`);
      await mf.dispose(); mf = undefined;
    }

    // --- 7. Capacity: 4,096 preseeded claims, fresh valid digest refused before dispatch.
    mf = await start(publicKey, "capacity-state");
    await guardSql(mf, "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<4096) " +
      "INSERT INTO claims(digest,operation,status) SELECT printf('%064x',x),'initialize','CLAIMED' FROM n");
    await put(mf, "initialize.json", first.artifact);
    await scheduled(mf, "mailbox");
    assert.deepEqual(await counts(mf), [0, 0], "full ledger refuses before mutation dispatch");
    assert.equal((await guardSql(mf, "SELECT * FROM claims")).length, 4_096);
    assert.equal(await latchDigest(mf), null);
    await mf.dispose(); mf = undefined;

    console.log("I3B staging fault-parity workerd integration: PASS (concurrent delivery, lost ack after commit, exact replay, " +
      "read-only reconciliation, positive-only settlement, post-settlement latch hazard characterization, consumed-before-call " +
      "with restart, publication faults, unavailable/history-incomplete reads, capacity)");
  } finally {
    if (mf) await mf.dispose();
    await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}
void main().catch((error: unknown) => { console.error(error); process.exitCode = 1; });
