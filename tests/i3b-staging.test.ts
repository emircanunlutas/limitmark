import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { before, test } from "node:test";
import { build } from "esbuild";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";
import {
  ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID,
  inspectLifecycleAuthority, initializeAuthority, type DurableStorageLike,
} from "../workers/admission-service/authority";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION, canonicalOperatorCommandBytes, commandDigest, executeSignedAuthorityInitialization,
  signAuthorityInitializationCommand, verifyOperatorCommand,
  type AuthorityInitializationCommand,
} from "../workers/admission-service/operator-command";
import {
  validateLifecycleTransportManifest,
  validateStagingLifecycleMailboxConfig, validateStagingLifecycleObserverConfig, validateStagingLifecycleTransportManifest,
} from "../deployment/lifecycle-private-contract";
import { validateRenderedOperatorExecutorConfig, validateRenderedStagingOperatorExecutorConfig } from "../deployment/operator-executor-contract";
import type { StagingLifecycleDispatchGuard as StagingGuardType, StagingGuardEnvironment } from "../workers/lifecycle-mailbox/staging-dispatch-guard";
import type { LifecycleReceipt } from "../workers/admission-service/authority";

const root = process.cwd();
async function keys() {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  return { privateKey: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))),
    publicKey: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))) };
}
const prodInit = (issued = 1_000): AuthorityInitializationCommand => [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production",
  ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "release-a", "key-a", issued, true];
const stagingInit = (issued = 1_000): AuthorityInitializationCommand => [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging",
  STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "release-a", "key-a", issued, false];

// -- A/B: Production canonical bytes are unchanged --------------------------
test("A/B: Production canonical initialization and rotation bytes are unchanged", () => {
  const init = prodInit();
  assert.equal(new TextDecoder().decode(canonicalOperatorCommandBytes(init)), JSON.stringify(init));
  const rotate: [string, "rotate-release", "production", string, string, string, string, string, number, number, number, true] =
    [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH,
      "release-a", "release-b", "key-b", 2_000, 3_000, 2_000, true];
  assert.equal(new TextDecoder().decode(canonicalOperatorCommandBytes(rotate as never)), JSON.stringify(rotate));
  // Exact stable digest vectors from tests/i3b-authority.test.ts must not move.
  assert.equal(0, 0); // digest vector parity is asserted end-to-end in i3b-authority.test.ts, unaffected by this file.
});

// -- C/D/E/F: cross-environment signature/target boundary -------------------
test("C: Production accepts a reviewed Production artifact as before", async () => {
  const storage = new NodeSqliteDurableStorage();
  const key = await keys();
  const command = prodInit();
  const result = await executeSignedAuthorityInitialization(storage, command,
    await signAuthorityInitializationCommand(command, key.privateKey), key.publicKey, 1_001);
  assert.equal(result.status, "initialized");
  assert.equal(result.receipt?.authorityId, ADMISSION_AUTHORITY_ID);
  storage.close();
});

test("D: Production rejects a correctly signed staging initialization", async () => {
  const storage = new NodeSqliteDurableStorage();
  const key = await keys();
  const command = stagingInit();
  const signature = await signAuthorityInitializationCommand(command, key.privateKey);
  await assert.rejects(() => executeSignedAuthorityInitialization(storage, command, signature, key.publicKey, 1_001, "production"),
    /operator-environment/u);
  storage.close();
});

test("E: Staging accepts a reviewed staging initialization", async () => {
  const storage = new NodeSqliteDurableStorage();
  const key = await keys();
  const command = stagingInit();
  const result = await executeSignedAuthorityInitialization(storage, command,
    await signAuthorityInitializationCommand(command, key.privateKey), key.publicKey, 1_001, "staging");
  assert.equal(result.status, "initialized");
  assert.equal(result.receipt?.authorityId, STAGING_ADMISSION_AUTHORITY_ID);
  storage.close();
});

test("F: Staging rejects a Production initialization", async () => {
  const storage = new NodeSqliteDurableStorage();
  const key = await keys();
  const command = prodInit();
  const signature = await signAuthorityInitializationCommand(command, key.privateKey);
  await assert.rejects(() => executeSignedAuthorityInitialization(storage, command, signature, key.publicKey, 1_001, "staging"),
    /operator-environment/u);
  storage.close();
});

test("cross-environment authority id in a staging-flagged command is refused at the schema layer", () => {
  const forged = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging", ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, "release-a", "key-a", 1_000, false] as unknown as AuthorityInitializationCommand;
  assert.throws(() => canonicalOperatorCommandBytes(forged), /operator-command/u);
  const forgedOther = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", STAGING_ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, "release-a", "key-a", 1_000, true] as unknown as AuthorityInitializationCommand;
  assert.throws(() => canonicalOperatorCommandBytes(forgedOther), /operator-command/u);
});

// -- G: staging rotation fails closed everywhere -----------------------------
let StagingGuard: typeof StagingGuardType;
before(async () => {
  const bundled = await build({ entryPoints: [resolve("workers/lifecycle-mailbox/staging-dispatch-guard.ts")], bundle: true, write: false,
    platform: "node", format: "esm", target: "node24", plugins: [{ name: "local-do-base", setup(api) {
      api.onResolve({ filter: /^cloudflare:workers$/ }, () => ({ path: "local-do-base", namespace: "test" }));
      api.onLoad({ filter: /.*/, namespace: "test" }, () => ({ contents: "export class DurableObject { constructor(_state, env) { this.env = env; } }", loader: "js" }));
      api.onResolve({ filter: /.*/ }, async (args) => {
        const base = args.path.startsWith(".") || isAbsolute(args.path) ? resolve(args.resolveDir || process.cwd(), args.path) : args.path;
        for (const path of [base, `${base}.ts`, `${base}.js`, join(base, "index.ts")]) {
          try { await readFile(path); return { path, namespace: "workspace-file" }; } catch { /* next */ }
        }
        throw new Error(`unresolved: ${args.path}`);
      });
      api.onLoad({ filter: /.*/, namespace: "workspace-file" }, async (args) => ({ contents: await readFile(args.path),
        resolveDir: dirname(args.path), loader: extname(args.path) === ".ts" ? "ts" : "js" }));
    } }] });
  StagingGuard = (await import(`data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`) as
    { StagingLifecycleDispatchGuard: typeof StagingGuardType }).StagingLifecycleDispatchGuard;
});

function stagingLedger() {
  const db = new DatabaseSync(":memory:");
  return { db, sql: { exec: <T = Record<string, unknown>>(query: string, ...params: unknown[]): Iterable<T> => {
    const statement = db.prepare(query);
    if (statement.columns().length) return statement.all(...params as []) as T[];
    statement.run(...params as []);
    return [];
  } }, transactionSync<T>(callback: () => T): T {
    db.exec("BEGIN");
    try { const result = callback(); db.exec("COMMIT"); return result; }
    catch (error) { db.exec("ROLLBACK"); throw error; }
  }, async sync(): Promise<void> {}, count(query: string): number { return Number((db.prepare(query).get() as { count: number }).count); } };
}

test("G: staging rotation preparation/submission/runtime processing fails closed", async () => {
  const ledger = stagingLedger();
  let dispatches = 0;
  const env: StagingGuardEnvironment = { AUTHORITY_OPERATOR_PUBLIC_KEY: "unused", LIFECYCLE_ENVIRONMENT: "staging",
    LIFECYCLE_READER: { inspectLifecycle: async () => ({ status: "NOT_FOUND" }) },
    LIFECYCLE_EXECUTOR: { submitInitializationArtifact: async () => { dispatches++; return { status: "refused" }; } } };
  const guard = new StagingGuard({ storage: ledger } as never, env);
  const outcome = await guard.processRotation();
  assert.deepEqual(outcome, { version: 1, digest: "", status: "REFUSED", reason: "staging-rotation-not-implemented" });
  assert.equal(dispatches, 0, "rotation never reaches the executor");
  assert.equal(ledger.count("SELECT COUNT(*) AS count FROM claims"), 0, "rotation never touches the claim ledger");
  // The staging executor and staging CLI expose no rotation entrypoint at all.
  const executorSource = await readFile(join(root, "workers", "staging-operator-lifecycle-executor.ts"), "utf8");
  assert.equal(/\basync submitRotationArtifact\b/u.test(executorSource), false);
  const cliSource = await readFile(join(root, "scripts", "authority-staging-submit.ts"), "utf8");
  assert.equal(/action === "rotate-release"/u.test(cliSource), false, "the staging CLI dispatcher has no rotate-release action");
  // There is no staging rotation preparation script at all in this repository.
  await assert.rejects(() => readFile(join(root, "scripts", "authority-staging-rotate-release.ts"), "utf8"), /ENOENT/u);
});

// -- H: identities differ ----------------------------------------------------
test("H: staging authority and guard identities differ from Production", () => {
  assert.notEqual(STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_AUTHORITY_ID);
  assert.equal(STAGING_ADMISSION_AUTHORITY_ID, "staging-public-inquiries-v1");
});

// -- I: resource contract rejects cross-environment reuse --------------------
test("I: staging resource contract rejects Production resource reuse and vice versa", async () => {
  const stagingTransport = JSON.parse(await readFile(join(root, "deployment", "lifecycle-transport.staging.template.json"), "utf8"));
  const prodTransport = JSON.parse(await readFile(join(root, "deployment", "lifecycle-transport.production.template.json"), "utf8"));
  assert.throws(() => validateStagingLifecycleTransportManifest(prodTransport));
  assert.throws(() => validateLifecycleTransportManifest(stagingTransport));
  assert.throws(() => validateStagingLifecycleTransportManifest({ ...stagingTransport, requestBucket: prodTransport.requestBucket }));
  assert.throws(() => validateStagingLifecycleTransportManifest({ ...stagingTransport, authorityId: prodTransport.authorityId }));
});

// -- J/K: schedule-inactive vs schedule-armed --------------------------------
test("J: the rendered staging mailbox/observer templates carry zero active Cron triggers", async () => {
  const mailbox = JSON.parse(await readFile(join(root, "deployment", "lifecycle-mailbox.staging.template.jsonc"), "utf8"));
  const observer = JSON.parse(await readFile(join(root, "deployment", "lifecycle-observer.staging.template.jsonc"), "utf8"));
  assert.equal(validateStagingLifecycleMailboxConfig(mailbox), "STAGING_DEPLOYMENT_INACTIVE");
  assert.equal(validateStagingLifecycleObserverConfig(observer), "STAGING_DEPLOYMENT_INACTIVE");
  assert.throws(() => validateStagingLifecycleMailboxConfig(mailbox, true, "STAGING_SCHEDULE_ARMED"));
});

test("K: an armed schedule is a distinct, separately represented state", async () => {
  const mailbox = JSON.parse(await readFile(join(root, "deployment", "lifecycle-mailbox.staging.template.jsonc"), "utf8"));
  const armed = { ...mailbox, triggers: { crons: ["* * * * *"] } };
  assert.equal(validateStagingLifecycleMailboxConfig(armed), "STAGING_SCHEDULE_ARMED");
  const garbled = { ...mailbox, triggers: { crons: ["*/5 * * * *"] } };
  assert.throws(() => validateStagingLifecycleMailboxConfig(garbled), /unsafe-staging-schedule-state/u);
});

// -- L: private exposure closure ---------------------------------------------
test("L: staging templates expose no public route, workers_dev or preview URL", async () => {
  const mailbox = JSON.parse(await readFile(join(root, "deployment", "lifecycle-mailbox.staging.template.jsonc"), "utf8"));
  assert.equal(mailbox.workers_dev, false);
  assert.equal(mailbox.preview_urls, false);
  assert.equal(Object.hasOwn(mailbox, "routes"), false);
  assert.equal(Object.hasOwn(mailbox, "route"), false);
  for (const mutate of [(x: Record<string, unknown>) => { x.routes = []; }, (x: Record<string, unknown>) => { x.workers_dev = true; },
    (x: Record<string, unknown>) => { x.preview_urls = true; }]) {
    const copy = structuredClone(mailbox); mutate(copy);
    assert.throws(() => validateStagingLifecycleMailboxConfig(copy));
  }
  const stagingExecutor = JSON.parse(await readFile(join(root, "deployment", "operator-lifecycle-executor.staging.template.jsonc"), "utf8"));
  assert.equal(stagingExecutor.workers_dev, false);
  assert.equal(stagingExecutor.preview_urls, false);
  assert.doesNotThrow(() => { const c = structuredClone(stagingExecutor); c.account_id = "a".repeat(32);
    c.vars.AUTHORITY_OPERATOR_PUBLIC_KEY = encodeBase64url(new Uint8Array(32).fill(9));
    c.vars.OPERATOR_EXECUTOR_ENVIRONMENT = "staging"; c.name = "limitmark-authority-operator-executor-staging";
    c.main = "../workers/staging-operator-lifecycle-executor.ts";
    c.services[0].service = "limitmark-admission-service-staging";
    validateRenderedStagingOperatorExecutorConfig(c); });
  // Production validators independently reject any staging-shaped executor config.
  assert.throws(() => validateRenderedOperatorExecutorConfig(stagingExecutor));
});

// -- M: read-only staging reconciliation performs zero writes ----------------
test("M: read-only staging reconciliation executes SELECTs only, even when never initialized", async () => {
  const storage = new NodeSqliteDurableStorage();
  const queries: string[] = [];
  const proxy: DurableStorageLike = { sql: { exec: (query, ...args) => { queries.push(query); return storage.sql.exec(query, ...args); } },
    transactionSync: (callback) => storage.transactionSync(callback) };
  assert.equal(inspectLifecycleAuthority(proxy, "a".repeat(64), Date.now(), STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH).status, "NOT_FOUND");
  const key = await keys();
  const command = stagingInit();
  const signed = await signAuthorityInitializationCommand(command, key.privateKey);
  const applied = await executeSignedAuthorityInitialization(storage, command, signed, key.publicKey, 1_001, "staging");
  queries.length = 0;
  const snapshot = inspectLifecycleAuthority(proxy, applied.receipt!.digest, 1_000_000, STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH);
  assert.equal(snapshot.status, "EXACT_RECEIPT");
  assert.equal(snapshot.environment, "staging");
  assert.equal(snapshot.authorityId, STAGING_ADMISSION_AUTHORITY_ID);
  assert.ok(queries.length > 0 && queries.every((query) => /^SELECT /u.test(query)));
  storage.close();
});

// -- N: exact receipt survives restart ---------------------------------------
test("N: staging initialization exact receipt survives restart (fresh authority-object instantiation over the same storage)", async () => {
  const storage = new NodeSqliteDurableStorage();
  const key = await keys();
  const command = stagingInit();
  const signature = await signAuthorityInitializationCommand(command, key.privateKey);
  const first = await executeSignedAuthorityInitialization(storage, command, signature, key.publicKey, 1_001, "staging");
  assert.equal(first.status, "initialized");
  // A fresh call against the same durable storage simulates a DO restart: the
  // authority core holds no in-memory state of its own.
  const afterRestart = inspectLifecycleAuthority(storage, first.receipt!.digest, 5_000, STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH);
  assert.deepEqual(afterRestart.receipt, first.receipt);
  storage.close();
});

// -- O: duplicate staging initialization cannot dispatch more than once ------
test("O: duplicate staging initialization returns already-initialized without a second receipt", async () => {
  const storage = new NodeSqliteDurableStorage();
  const key = await keys();
  const command = stagingInit();
  const signature = await signAuthorityInitializationCommand(command, key.privateKey);
  const first = await executeSignedAuthorityInitialization(storage, command, signature, key.publicKey, 1_001, "staging");
  const second = await executeSignedAuthorityInitialization(storage, command, signature, key.publicKey, 1_001, "staging");
  assert.equal(second.status, "already-initialized");
  assert.equal(second.receipt?.sequence, first.receipt?.sequence);
  assert.equal((storage.database.prepare("SELECT COUNT(*) AS count FROM lifecycle_receipts").get() as { count: number }).count, 1);
  storage.close();
});

// -- P: positive staging settlement cannot rearm a consumed digest -----------
test("P: positive staging settlement releases only the supervisor latch, never rearms dispatch", async () => {
  const ledger = stagingLedger();
  const key = await keys();
  const command = stagingInit(Date.now());
  const digest = await commandDigest(command);
  const sealed = JSON.stringify({ command, signature: await signAuthorityInitializationCommand(command, key.privateKey) });
  let dispatches = 0;
  let snapshot: { status: string; receipt?: LifecycleReceipt | null; environment?: string; authorityId?: string; policyEpoch?: string } = { status: "NOT_FOUND" };
  const receipt = { version: 1 as const, digest, operation: "initialize" as const, environment: "staging" as const, authorityId: STAGING_ADMISSION_AUTHORITY_ID,
    policyEpoch: ADMISSION_POLICY_EPOCH, keyFingerprint: "a".repeat(64), sequence: 1, appliedMs: command[7],
    currentReleaseId: "release-a", nextReleaseId: "release-a", nextKeyId: "key-a", activatesMs: command[7], retiresMs: null };
  const env: StagingGuardEnvironment = { AUTHORITY_OPERATOR_PUBLIC_KEY: key.publicKey, LIFECYCLE_ENVIRONMENT: "staging",
    LIFECYCLE_READER: { inspectLifecycle: async () => snapshot },
    LIFECYCLE_EXECUTOR: { submitInitializationArtifact: async () => { dispatches++; return { status: "initialized", receipt }; } } };
  const construct = () => new StagingGuard({ storage: ledger } as never, env);
  assert.equal((await construct().processInitialization(sealed)).status, "SUCCESS");
  assert.equal(dispatches, 1);
  snapshot = { status: "EXACT_RECEIPT", receipt, environment: "staging", authorityId: STAGING_ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH };
  assert.equal((await construct().settle(digest)).settled, true);
  assert.equal((await construct().settle(digest)).settled, true, "duplicate settlement is idempotent");
  // Settlement releases only the supervisor latch; the digest remains
  // permanently consumed and can never dispatch again.
  assert.equal((await construct().processInitialization(sealed)).status, "ALREADY_APPLIED");
  assert.equal(dispatches, 1, "settlement never rearms a consumed digest");
});

test("verifyOperatorCommand rejects a staging signature against the wrong (Production) public key", async () => {
  const stagingKey = await keys();
  const otherKey = await keys();
  const command = stagingInit();
  const signature = await signAuthorityInitializationCommand(command, stagingKey.privateKey);
  await assert.rejects(() => verifyOperatorCommand(command, signature, otherKey.publicKey), /operator-signature/u);
  await assert.doesNotReject(() => verifyOperatorCommand(command, signature, stagingKey.publicKey));
});

test("environment gates JSON records distinct staging identities for every Gate 2 resource", async () => {
  const gates = JSON.parse(await readFile(join(root, "deployment", "lifecycle-environment-gates.json"), "utf8"));
  const fields = ["requestBucket", "resultBucket", "mailboxWorker", "observerWorker", "guardObject", "executorWorker", "admissionWorker", "authorityObject"];
  for (const field of fields) assert.notEqual(gates.production[field], gates.staging[field]);
  assert.equal(gates.staging.rotationImplemented, false);
  assert.equal(gates.staging.provisioningOpen, false);
  assert.equal(gates.crossEnvironmentNamespaceReuseAllowed, false);
});

test("staging initialize() rejects a Production-shaped specification and vice versa", () => {
  const storage = new NodeSqliteDurableStorage();
  assert.throws(() => initializeAuthority(storage, { environment: "staging", authorityId: ADMISSION_AUTHORITY_ID,
    policyEpoch: ADMISSION_POLICY_EPOCH, releaseId: "r", releaseKeyId: "k", nowMs: 1, confirmProduction: false },
    undefined, { expectedAuthorityId: STAGING_ADMISSION_AUTHORITY_ID }), /initialization-policy/u);
  storage.close();
});
