// Gate 8 Phase 0: staging fault parity at the guard boundary. Mirrors
// tests/i3b-dispatch-faults.test.ts (Production LifecycleDispatchGuard) against
// the real StagingLifecycleDispatchGuard class, bundled exactly as deployed
// except for a local DurableObject base. Crash points use the guard's existing
// constructor-only LocalFaultHooks, which workerd never supplies (it constructs
// Durable Objects with (state, env) only). Synthetic keys and identities only.
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { before, test } from "node:test";
import { readFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { build } from "esbuild";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID, type LifecycleReceipt } from "../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, commandDigest, signAuthorityInitializationCommand,
  type AuthorityInitializationCommand } from "../workers/admission-service/operator-command";
import type { GuardOutcome } from "../workers/lifecycle-mailbox/dispatch-guard";
import type { StagingLifecycleDispatchGuard, StagingGuardEnvironment } from "../workers/lifecycle-mailbox/staging-dispatch-guard";

type GuardClass = typeof StagingLifecycleDispatchGuard;
let Guard: GuardClass;

class FaultLedger {
  readonly db = new DatabaseSync(":memory:");
  failTransaction = false;
  failSql: RegExp | null = null;
  failSyncAt = 0;
  syncCalls = 0;
  readonly sql = { exec: <T = Record<string, unknown>>(query: string, ...params: unknown[]): Iterable<T> => {
    if (this.failSql?.test(query)) throw new Error("injected-sql");
    const statement = this.db.prepare(query);
    if (statement.columns().length) return statement.all(...params as []) as T[];
    statement.run(...params as []);
    return [];
  } };
  transactionSync<T>(callback: () => T): T {
    if (this.failTransaction) throw new Error("injected-transaction");
    this.db.exec("BEGIN");
    try { const result = callback(); this.db.exec("COMMIT"); return result; }
    catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }
  async sync(): Promise<void> {
    this.syncCalls++;
    if (this.failSyncAt === this.syncCalls) throw new Error("injected-sync-ambiguity");
  }
  count(query: string): number { return Number((this.db.prepare(query).get() as { count: number }).count); }
  row(query: string, ...params: unknown[]): Record<string, unknown> | undefined {
    return this.db.prepare(query).get(...params as []) as Record<string, unknown> | undefined;
  }
  close(): void { this.db.close(); }
}

type Snapshot = Awaited<ReturnType<StagingGuardEnvironment["LIFECYCLE_READER"]["inspectLifecycle"]>>;
type Signed = { command: AuthorityInitializationCommand; digest: string; sealed: string; receipt: LifecycleReceipt };
let privateKey: string;
let publicKey: string;
let first: Signed;
let second: Signed;
let third: Signed;
const staging = { environment: "staging", authorityId: STAGING_ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH } as const;
const absent: Snapshot = { status: "NOT_FOUND", ...staging };
const exactFor = (signed: Signed): Snapshot => ({ ...absent, status: "EXACT_RECEIPT", receipt: signed.receipt });

async function signed(issuedAtMs: number, release: string): Promise<Signed> {
  const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging",
    STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, release, "synthetic-key", issuedAtMs, false];
  const digest = await commandDigest(command);
  return { command, digest, sealed: JSON.stringify({ command, signature: await signAuthorityInitializationCommand(command, privateKey) }),
    receipt: { version: 1, digest, operation: "initialize", ...staging, keyFingerprint: "a".repeat(64), sequence: 1,
      appliedMs: issuedAtMs, currentReleaseId: release, nextReleaseId: release, nextKeyId: "synthetic-key", activatesMs: issuedAtMs,
      retiresMs: null } };
}

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
  Guard = (await import(`data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`) as
    { StagingLifecycleDispatchGuard: GuardClass }).StagingLifecycleDispatchGuard;
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  privateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  publicKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const now = Date.now();
  first = await signed(now, "synthetic-release-1");
  second = await signed(now + 1, "synthetic-release-2");
  third = await signed(now + 2, "synthetic-release-3");
});

type Response = "success" | "throw" | "malformed" | "null" | "refused";
function harness(ledger = new FaultLedger()) {
  const dispatched: string[] = [];
  let response: Response = "success";
  // Per-digest reader: models an authority whose only receipts are those listed.
  let receipts: Signed[] = [];
  let snapshotOverride: Snapshot | null = null;
  let readerFault = false;
  const env: StagingGuardEnvironment = { AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey, LIFECYCLE_ENVIRONMENT: "staging",
    LIFECYCLE_READER: { inspectLifecycle: async (digest: string) => {
      if (readerFault) throw new Error("authority-unavailable");
      if (snapshotOverride) return snapshotOverride;
      const found = receipts.find((entry) => entry.digest === digest);
      return found ? exactFor(found) : absent;
    } },
    LIFECYCLE_EXECUTOR: { submitInitializationArtifact: async (sealed: string) => {
      const match = [first, second, third].find((entry) => entry.sealed === sealed);
      dispatched.push(match?.digest ?? "unknown");
      if (response === "throw") throw new Error("lost-executor-ack");
      if (response === "malformed") return { status: "retryable" } as never;
      if (response === "null") return null as never;
      if (response === "refused") return { status: "refused" };
      return { status: "initialized", receipt: match!.receipt };
    } } };
  const construct = (point?: "afterClaimSync" | "beforeExecutorCall") => new Guard({ storage: ledger } as never, env, {
    afterClaimSync: async () => { if (point === "afterClaimSync") throw new Error("after-sync"); },
    beforeExecutorCall: async () => { if (point === "beforeExecutorCall") throw new Error("before-call"); },
  });
  return { ledger, construct, dispatched, get dispatches() { return dispatched.length; },
    set response(value: Response) { response = value; }, set receipts(value: Signed[]) { receipts = value; },
    set snapshot(value: Snapshot | null) { snapshotOverride = value; }, set readerFault(value: boolean) { readerFault = value; } };
}

const claims = (ledger: FaultLedger) => ledger.count("SELECT COUNT(*) AS count FROM claims");
const latches = (ledger: FaultLedger) => ledger.count("SELECT COUNT(*) AS count FROM latch");
function claimedAndLatched(ledger: FaultLedger, digest: string): void {
  assert.ok(ledger.row("SELECT digest FROM claims WHERE digest=?", digest), "claim persisted");
  assert.equal((ledger.row("SELECT digest FROM latch WHERE singleton=1") as { digest: string } | undefined)?.digest, digest, "latch held");
}
async function duplicateCannotDispatch(h: ReturnType<typeof harness>, entry: Signed): Promise<void> {
  const outcome = await h.construct().processInitialization(entry.sealed);
  assert.deepEqual([outcome.status, outcome.reason], ["UNCONFIRMED", "consumed"]);
}

test("staging guard prototype exposes only the three reviewed operations (no fault or reset method)", () => {
  assert.deepEqual(Object.getOwnPropertyNames(Guard.prototype).sort(),
    ["constructor", "processInitialization", "processRotation", "settle"].sort());
});

test("pre-claim interruption, invalid input and failed claim transaction never dispatch", async () => {
  const h = harness();
  try {
    assert.equal((await h.construct().processInitialization("invalid")).status, "REFUSED");
    h.readerFault = true;
    assert.deepEqual(statusReason(await h.construct().processInitialization(first.sealed)), ["UNAVAILABLE", "authority-read"]);
    h.readerFault = false;
    h.ledger.failTransaction = true;
    assert.equal((await h.construct().processInitialization(first.sealed)).reason, "claim-durability");
    h.ledger.failTransaction = false;
    h.ledger.failSql = /^INSERT INTO latch/u;
    assert.equal((await h.construct().processInitialization(first.sealed)).reason, "claim-durability");
    assert.equal(claims(h.ledger), 0, "partial claim transaction rolls back");
    assert.equal(h.dispatches, 0);
    h.ledger.failSql = null;
    assert.equal((await h.construct().processInitialization(first.sealed)).status, "SUCCESS");
    assert.equal(h.dispatches, 1, "only the later first durable claim dispatches");
  } finally { h.ledger.close(); }
});

test("unavailable, HISTORY_INCOMPLETE and wrong-identity reader paths never claim or dispatch", async () => {
  for (const snapshot of [{ ...absent, status: "HISTORY_INCOMPLETE" }, { ...absent, status: "UNAVAILABLE" },
    { ...absent, status: "SOMETHING_ELSE" }] as Snapshot[]) {
    const h = harness();
    try {
      h.snapshot = snapshot;
      assert.deepEqual(statusReason(await h.construct().processInitialization(first.sealed)), ["UNAVAILABLE", "authority-history"]);
      assert.equal(claims(h.ledger), 0);
      assert.equal(latches(h.ledger), 0);
      assert.equal(h.dispatches, 0);
    } finally { h.ledger.close(); }
  }
  const h = harness();
  try {
    // An exact receipt carrying a non-staging identity is not accepted as ALREADY_APPLIED, and
    // it is not NOT_FOUND either, so the guard fails closed without claiming.
    h.snapshot = { ...exactFor(first), environment: "production" };
    assert.deepEqual(statusReason(await h.construct().processInitialization(first.sealed)), ["UNAVAILABLE", "authority-history"]);
    assert.equal(claims(h.ledger), 0);
    assert.equal(h.dispatches, 0);
  } finally { h.ledger.close(); }
});

test("claim sync failure is ambiguous, never calls the executor, and the claim survives restart", async () => {
  const h = harness();
  try {
    h.ledger.failSyncAt = 1;
    assert.deepEqual(statusReason(await h.construct().processInitialization(first.sealed)), ["UNCONFIRMED", "claim-durability"]);
    assert.equal(h.dispatches, 0);
    claimedAndLatched(h.ledger, first.digest);
    h.ledger.failSyncAt = 0;
    await duplicateCannotDispatch(h, first);
    assert.equal(h.dispatches, 0);
  } finally { h.ledger.close(); }
});

test("consumed-before-call: claim and latch persist, zero dispatch, permanent across restart, fresh digest blocked", async () => {
  for (const point of ["afterClaimSync", "beforeExecutorCall"] as const) {
    const h = harness();
    try {
      const outcome = await h.construct(point).processInitialization(first.sealed);
      assert.deepEqual(statusReason(outcome), ["UNCONFIRMED", point === "afterClaimSync" ? "pre-dispatch" : "dispatch-ambiguous"]);
      assert.equal(h.ledger.syncCalls, 1, "claim was durably synced before the crash point");
      assert.equal(h.dispatches, 0, `${point}: executor never invoked`);
      claimedAndLatched(h.ledger, first.digest);
      // Restart: a fresh guard instance over the same durable ledger.
      await duplicateCannotDispatch(h, first);
      assert.deepEqual(statusReason(await h.construct().processInitialization(second.sealed)), ["UNAVAILABLE", "active-or-capacity"],
        "a fresh different digest is blocked by the held latch");
      assert.equal((await h.construct().settle(first.digest)).settled, false, "no receipt: latch cannot be released");
      claimedAndLatched(h.ledger, first.digest);
      assert.equal(claims(h.ledger), 1);
      assert.equal(h.dispatches, 0, `${point} remains permanently consumed`);
    } finally { h.ledger.close(); }
  }
});

test("begun RPC, lost acknowledgement, malformed and refused responses never redispatch", async () => {
  for (const response of ["throw", "malformed", "null", "refused"] as const) {
    const h = harness();
    try {
      h.response = response;
      const outcome = await h.construct().processInitialization(first.sealed);
      assert.equal(outcome.status, response === "refused" ? "REFUSED" : "UNCONFIRMED");
      assert.equal(h.dispatches, 1);
      claimedAndLatched(h.ledger, first.digest);
      await duplicateCannotDispatch(h, first);
      if (response === "throw") {
        // Lost ack after commit: the authority holds the receipt; only a read resolves it.
        h.receipts = [first];
        assert.equal((await h.construct().processInitialization(first.sealed)).status, "ALREADY_APPLIED");
        assert.equal((await h.construct().settle(first.digest)).settled, true);
        assert.equal(latches(h.ledger), 0);
        assert.equal(claims(h.ledger), 1);
      }
      assert.equal(h.dispatches, 1);
    } finally { h.ledger.close(); }
  }
});

test("authoritative response with failed result SQL/sync leaves a permanent claim and exact read-only recovery", async () => {
  for (const fault of ["sql", "sync"] as const) {
    const h = harness();
    try {
      if (fault === "sql") h.ledger.failSql = /^UPDATE claims/u;
      else h.ledger.failSyncAt = 2;
      assert.deepEqual(statusReason(await h.construct().processInitialization(first.sealed)), ["UNCONFIRMED", "result-durability"]);
      assert.equal(h.dispatches, 1);
      h.ledger.failSql = null; h.ledger.failSyncAt = 0;
      await duplicateCannotDispatch(h, first);
      h.receipts = [first];
      assert.equal((await h.construct().processInitialization(first.sealed)).status, "ALREADY_APPLIED");
      assert.equal(h.dispatches, 1);
    } finally { h.ledger.close(); }
  }
});

test("capacity: 4,096 preseeded claims refuse a fresh valid digest before any dispatch", async () => {
  const h = harness();
  try {
    h.construct();
    h.ledger.db.exec("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<4096) " +
      "INSERT INTO claims(digest,operation,status) SELECT printf('%064x',x),'initialize','CLAIMED' FROM n");
    assert.deepEqual(statusReason(await h.construct().processInitialization(first.sealed)), ["UNAVAILABLE", "active-or-capacity"]);
    assert.equal(h.dispatches, 0);
    assert.equal(claims(h.ledger), 4_096);
    assert.equal(latches(h.ledger), 0);
  } finally { h.ledger.close(); }
});

test("negative or unavailable reconciliation never settles or rearms an ambiguous claim", async () => {
  const h = harness();
  try {
    await h.construct("afterClaimSync").processInitialization(first.sealed);
    for (const snapshot of [absent, { ...absent, status: "HISTORY_INCOMPLETE" }, { ...absent, status: "UNAVAILABLE" },
      { ...exactFor(first), receipt: { ...first.receipt, digest: "b".repeat(64) } }] as Snapshot[]) {
      h.snapshot = snapshot;
      assert.equal((await h.construct().settle(first.digest)).settled, false);
      claimedAndLatched(h.ledger, first.digest);
    }
    h.snapshot = null;
    h.readerFault = true;
    assert.equal((await h.construct().settle(first.digest)).settled, false);
    assert.equal(h.dispatches, 0);
  } finally { h.ledger.close(); }
});

test("positive-only settlement: unknown/unresolved digests cannot release the latch; duplicate is idempotent; failure never rearms", async () => {
  const h = harness();
  try {
    assert.equal((await h.construct().processInitialization(first.sealed)).status, "SUCCESS");
    assert.equal((await h.construct().settle(first.digest)).settled, false, "no authority receipt observed yet");
    assert.equal((await h.construct().settle("b".repeat(64))).settled, false, "unknown digest");
    assert.equal((await h.construct().settle("not-a-digest")).settled, false);
    h.receipts = [first];
    h.ledger.failSql = /^DELETE FROM latch/u;
    assert.equal((await h.construct().settle(first.digest)).settled, false, "failed settlement transaction");
    claimedAndLatched(h.ledger, first.digest);
    h.ledger.failSql = null;
    h.ledger.failSyncAt = h.ledger.syncCalls + 1;
    assert.equal((await h.construct().settle(first.digest)).settled, false, "settlement sync failure is not reported as settled");
    assert.equal(claims(h.ledger), 1, "settlement never deletes consumption");
    h.ledger.failSyncAt = 0;
    assert.equal((await h.construct().settle(first.digest)).settled, true, "repeated control recovers committed resolution");
    assert.equal(latches(h.ledger), 0);
    assert.equal(claims(h.ledger), 1);
    assert.equal((await h.construct().settle(first.digest)).settled, true, "duplicate settlement is idempotent");
    assert.equal(h.ledger.count("SELECT COUNT(*) AS count FROM settlements"), 1);
    assert.equal((await h.construct().processInitialization(first.sealed)).status, "ALREADY_APPLIED");
    assert.equal(h.dispatches, 1, "settlement never redispatches");
  } finally { h.ledger.close(); }
});

test("exact replay after commit is resolved by the read path with no second dispatch", async () => {
  const h = harness();
  try {
    assert.equal((await h.construct().processInitialization(first.sealed)).status, "SUCCESS");
    h.receipts = [first];
    for (let index = 0; index < 3; index++)
      assert.equal((await h.construct().processInitialization(first.sealed)).status, "ALREADY_APPLIED");
    assert.equal(h.dispatches, 1);
  } finally { h.ledger.close(); }
});

// CHARACTERIZATION of the current Gate 7 hazard (Gate 8 Phase 0). This pins
// today's behavior; it is not a desired property. A future reviewed runtime
// pre-claim refusal would deliberately change this test.
test("HAZARD: a fresh initialization after positive settlement is claimed, refused, and latches the guard permanently", async () => {
  const h = harness();
  try {
    assert.equal((await h.construct().processInitialization(first.sealed)).status, "SUCCESS");
    h.receipts = [first];
    assert.equal((await h.construct().settle(first.digest)).settled, true);
    assert.equal(latches(h.ledger), 0, "latch released after positive settlement");
    // Authority is initialized: any new digest reads NOT_FOUND and is refused
    // by the authority as already initialized.
    h.response = "refused";
    assert.equal((await h.construct().processInitialization(second.sealed)).status, "REFUSED");
    assert.deepEqual(h.dispatched, [first.digest, second.digest], "digest 2 was claimed and dispatched");
    assert.equal((h.ledger.row("SELECT status FROM claims WHERE digest=?", second.digest) as { status: string }).status, "REFUSED");
    claimedAndLatched(h.ledger, second.digest);
    assert.equal((await h.construct().settle(second.digest)).settled, false, "no exact receipt can ever exist for digest 2");
    assert.deepEqual(statusReason(await h.construct().processInitialization(third.sealed)), ["UNAVAILABLE", "active-or-capacity"]);
    // Restart: fresh instance over the same ledger.
    claimedAndLatched(h.ledger, second.digest);
    await duplicateCannotDispatch(h, second);
    assert.deepEqual(statusReason(await h.construct().processInitialization(third.sealed)), ["UNAVAILABLE", "active-or-capacity"]);
    assert.equal((await h.construct().processInitialization(first.sealed)).status, "ALREADY_APPLIED");
    assert.equal(h.dispatches, 2, "digest 3 never dispatched");
  } finally { h.ledger.close(); }
});

test("staging rotation stays closed and touches no guard storage", async () => {
  const h = harness();
  try {
    h.construct();
    assert.deepEqual(await h.construct().processRotation(), { version: 1, digest: "", status: "REFUSED", reason: "staging-rotation-not-implemented" });
    assert.equal(claims(h.ledger), 0);
    assert.equal(h.dispatches, 0);
  } finally { h.ledger.close(); }
});

function statusReason(outcome: GuardOutcome): [string, string | undefined] { return [outcome.status, outcome.reason]; }
