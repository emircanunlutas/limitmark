import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { before, test } from "node:test";
import { readFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { build } from "esbuild";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, type LifecycleReceipt } from "../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, commandDigest, signAuthorityInitializationCommand,
  type AuthorityInitializationCommand } from "../workers/admission-service/operator-command";
import type { LifecycleDispatchGuard, GuardOutcome, GuardEnvironment } from "../workers/lifecycle-mailbox/dispatch-guard";

type GuardClass = typeof LifecycleDispatchGuard;
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
  close(): void { this.db.close(); }
}

let publicKey: string;
let command: AuthorityInitializationCommand;
let digest: string;
let sealed: string;
let receipt: LifecycleReceipt;
type Snapshot = Awaited<ReturnType<GuardEnvironment["LIFECYCLE_READER"]["inspectLifecycle"]>>;
const absent: Snapshot = { status: "NOT_FOUND", environment: "production", authorityId: ADMISSION_AUTHORITY_ID,
  policyEpoch: ADMISSION_POLICY_EPOCH };
let exact: Snapshot;
/** Opaque stand-in for the Authority's signed envelope: the guard must relay it without ever looking inside (it is not a protocol envelope). */
const ENVELOPE = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3]);
const reasonOf = (outcome: GuardOutcome): string | undefined => "reason" in outcome ? outcome.reason : undefined;

before(async () => {
  const bundled = await build({ entryPoints: [resolve("workers/lifecycle-mailbox/dispatch-guard.ts")], bundle: true, write: false,
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
    { LifecycleDispatchGuard: GuardClass }).LifecycleDispatchGuard;
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const privateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  publicKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  command = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH,
    "fault-release", "fault-key", Date.now(), true];
  digest = await commandDigest(command);
  sealed = JSON.stringify({ command, signature: await signAuthorityInitializationCommand(command, privateKey) });
  receipt = { version: 1, digest, operation: "initialize", environment: "production", authorityId: ADMISSION_AUTHORITY_ID,
    policyEpoch: ADMISSION_POLICY_EPOCH, keyFingerprint: "a".repeat(64), sequence: 1, appliedMs: command[7],
    currentReleaseId: "fault-release", nextReleaseId: "fault-release", nextKeyId: "fault-key", activatesMs: command[7], retiresMs: null };
  exact = { ...absent, status: "EXACT_RECEIPT", receipt };
});

function harness(ledger = new FaultLedger()) {
  let dispatches = 0;
  let response: "success" | "throw" | "malformed" | "null" | "refused" | "ambiguous" | "unavailable" | "legacy" | "custom" = "success";
  /** Raw (untrusted) Authority answers for the executor / the pre-claim probe, used by the malformed-ATTESTED cases. */
  let customResponse: unknown;
  let customProbe: { value: unknown } | null = null;
  let snapshot: Snapshot = absent;
  let readerFault = false;
  /** What the Authority's signed read-only recovery answers for the current `snapshot` (the pre-dispatch probe). */
  let probe: "from-snapshot" | "signer-unconfigured" | "legacy" = "from-snapshot";
  const env: GuardEnvironment = { AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey, LIFECYCLE_ENVIRONMENT: "production",
    LIFECYCLE_READER: {
      // The unsigned supervisory read serves settlement only.
      inspectLifecycle: async () => { if (readerFault) throw new Error("authority-unavailable"); return snapshot; },
      attestAppliedLifecycle: async () => {
        if (readerFault) throw new Error("authority-unavailable");
        if (customProbe) return customProbe.value;
        if (probe === "signer-unconfigured") return { status: "UNAVAILABLE", reason: "signer-unconfigured" };
        if (probe === "legacy") return { status: "EXACT_RECEIPT", receipt };
        if (snapshot.status === "EXACT_RECEIPT") return { status: "ATTESTED", relayDisposition: "ALREADY_APPLIED", envelope: ENVELOPE };
        return { status: "UNAVAILABLE", reason: snapshot.status === "NOT_FOUND" ? "receipt-not-found" :
          snapshot.status === "HISTORY_INCOMPLETE" ? "history-incomplete" : "authority-state-unavailable" };
      },
    },
    LIFECYCLE_EXECUTOR: {
      submitInitializationArtifact: async () => {
        dispatches++;
        if (response === "throw") throw new Error("lost-executor-ack");
        if (response === "malformed") return { status: "retryable" } as never;
        if (response === "null") return null as never;
        if (response === "refused") return { status: "REFUSED" };
        if (response === "ambiguous") return { status: "AMBIGUOUS", reason: "post-commit-attestation-failed" };
        if (response === "unavailable") return { status: "UNAVAILABLE", reason: "signer-unconfigured" };
        // The pre-2C unsigned positive: the guard must not honor it.
        if (response === "legacy") return { status: "initialized", receipt } as never;
        if (response === "custom") return customResponse as never;
        return { status: "ATTESTED", relayDisposition: "APPLIED", envelope: ENVELOPE };
      },
      submitRotationArtifact: async () => { dispatches++; throw new Error("wrong-operation"); },
    } };
  const construct = (point?: "afterClaimSync" | "beforeExecutorCall") => new Guard({ storage: ledger } as never, env, {
    afterClaimSync: async () => { if (point === "afterClaimSync") throw new Error("after-sync"); },
    beforeExecutorCall: async () => { if (point === "beforeExecutorCall") throw new Error("before-call"); },
  });
  return { ledger, construct, get dispatches() { return dispatches; }, set response(value: typeof response) { response = value; },
    set snapshot(value: Snapshot) { snapshot = value; }, set readerFault(value: boolean) { readerFault = value; },
    set probe(value: typeof probe) { probe = value; },
    set customResponse(value: unknown) { response = "custom"; customResponse = value; }, set customProbe(value: unknown) { customProbe = { value }; } };
}

function claimed(ledger: FaultLedger): void {
  assert.equal(ledger.count("SELECT COUNT(*) AS count FROM claims"), 1);
  assert.equal(ledger.count("SELECT COUNT(*) AS count FROM latch"), 1);
}
test("compiled guard prototype exposes only the three reviewed lifecycle operations", () => {
  assert.deepEqual(Object.getOwnPropertyNames(Guard.prototype).sort(),
    ["constructor", "processInitialization", "processRotation", "settle"].sort());
});
async function duplicateCannotDispatch(h: ReturnType<typeof harness>): Promise<GuardOutcome> {
  const outcome = await h.construct().processInitialization(sealed);
  assert.equal(outcome.status, "UNCONFIRMED");
  assert.equal(reasonOf(outcome), "consumed");
  return outcome;
}

test("G4 A/B: valid-command pre-claim interruption and failed claim transaction never dispatch", async () => {
  const h = harness();
  try {
    assert.equal((await h.construct().processInitialization("invalid")).status, "REFUSED");
    assert.equal(h.ledger.count("SELECT COUNT(*) AS count FROM claims"), 0);
    h.readerFault = true;
    assert.equal((await h.construct().processInitialization(sealed)).status, "UNAVAILABLE",
      "valid signed command interrupted before CLAIM remains unconsumed");
    assert.equal(h.ledger.count("SELECT COUNT(*) AS count FROM claims"), 0);
    assert.equal(h.dispatches, 0);
    h.readerFault = false;
    h.ledger.failTransaction = true;
    assert.equal(reasonOf(await h.construct().processInitialization(sealed)), "claim-durability");
    assert.equal(h.dispatches, 0);
    assert.equal(h.ledger.count("SELECT COUNT(*) AS count FROM claims"), 0);
    h.ledger.failTransaction = false;
    h.ledger.failSql = /^INSERT INTO latch/u;
    assert.equal(reasonOf(await h.construct().processInitialization(sealed)), "claim-durability");
    assert.equal(h.ledger.count("SELECT COUNT(*) AS count FROM claims"), 0, "partial claim transaction rolls back");
    h.ledger.failSql = null;
    assert.equal((await h.construct().processInitialization(sealed)).status, "ATTESTED");
    assert.equal(h.dispatches, 1, "only the later first durable claim dispatches");
  } finally { h.ledger.close(); }
});

test("G4 C: storage.sync failure is ambiguous, never calls executor, and persisted claim survives restart", async () => {
  const h = harness();
  try {
    h.ledger.failSyncAt = 1;
    const outcome = await h.construct().processInitialization(sealed);
    assert.deepEqual([outcome.status, reasonOf(outcome)], ["UNCONFIRMED", "claim-durability"]);
    assert.equal(h.dispatches, 0);
    claimed(h.ledger);
    h.ledger.failSyncAt = 0;
    await duplicateCannotDispatch(h);
    assert.equal(h.dispatches, 0);
  } finally { h.ledger.close(); }
});

test("G4 D/E/J: post-sync and pre-call crashes sacrifice a consumed command across restart", async () => {
  for (const point of ["afterClaimSync", "beforeExecutorCall"] as const) {
    const h = harness();
    try {
      const first = h.construct(point);
      assert.equal((await first.processInitialization(sealed)).status, "UNCONFIRMED");
      assert.equal(h.ledger.syncCalls, 1);
      assert.equal(h.dispatches, 0, point);
      claimed(h.ledger);
      await duplicateCannotDispatch(h);
      assert.equal(h.dispatches, 0, `${point} remains permanently consumed`);
    } finally { h.ledger.close(); }
  }
});

test("G4 F/H: begun RPC, lost acknowledgement, malformed response and retryable indications never redispatch", async () => {
  for (const response of ["throw", "malformed", "null", "refused"] as const) {
    const h = harness();
    try {
      h.response = response;
      const outcome = await h.construct().processInitialization(sealed);
      assert.equal(outcome.status, response === "refused" ? "REFUSED" : "UNCONFIRMED");
      assert.equal(h.dispatches, 1);
      claimed(h.ledger);
      await duplicateCannotDispatch(h);
      assert.equal(h.dispatches, 1);
      h.snapshot = response === "throw" ? exact : absent;
      const observed = await h.construct().processInitialization(sealed);
      assert.equal(observed.status, response === "throw" ? "ATTESTED" : "UNCONFIRMED");
      if (observed.status === "ATTESTED") assert.equal(observed.relayDisposition, "ALREADY_APPLIED");
      assert.equal(h.dispatches, 1);
    } finally { h.ledger.close(); }
  }
});

test("G4 G/J: authoritative response with failed result SQL/sync leaves permanent claim and exact read-only recovery", async () => {
  for (const fault of ["sql", "sync"] as const) {
    const h = harness();
    try {
      if (fault === "sql") h.ledger.failSql = /^UPDATE claims/u;
      else h.ledger.failSyncAt = 2;
      assert.deepEqual([...(statusReason(await h.construct().processInitialization(sealed)))], ["UNCONFIRMED", "result-durability"]);
      assert.equal(h.dispatches, 1);
      claimed(h.ledger);
      h.ledger.failSql = null; h.ledger.failSyncAt = 0;
      await duplicateCannotDispatch(h);
      h.snapshot = exact;
      assert.equal((await h.construct().processInitialization(sealed)).status, "ATTESTED");
      assert.equal(h.dispatches, 1);
    } finally { h.ledger.close(); }
  }
});
function statusReason(outcome: GuardOutcome): [string, string | undefined] { return [outcome.status, reasonOf(outcome)]; }

test("G4 J: terminal result and no-claim states remain distinct after guard instance restart", async () => {
  const h = harness();
  try {
    h.construct();
    assert.equal(h.ledger.count("SELECT COUNT(*) AS count FROM claims"), 0);
    assert.equal((await h.construct().processInitialization(sealed)).status, "ATTESTED");
    assert.equal((h.ledger.db.prepare("SELECT status FROM claims WHERE digest=?").get(digest) as { status: string }).status, "SUCCESS");
    await duplicateCannotDispatch(h);
    assert.equal(h.dispatches, 1);
  } finally { h.ledger.close(); }
});

test("every ambiguous durable claim remains consumed under negative or unavailable reconciliation", async () => {
  const h = harness();
  try {
    const first = h.construct("afterClaimSync");
    assert.equal((await first.processInitialization(sealed)).status, "UNCONFIRMED");
    claimed(h.ledger);
    for (const status of ["NOT_FOUND", "HISTORY_INCOMPLETE", "UNAVAILABLE"] as const) {
      h.snapshot = { ...absent, status };
      const result = await h.construct().processInitialization(sealed);
      assert.equal(result.status, status === "NOT_FOUND" ? "UNCONFIRMED" : "UNAVAILABLE");
      assert.equal((await h.construct().settle(digest)).settled, false);
      assert.equal(h.dispatches, 0, `${status} must never rearm the claim`);
      claimed(h.ledger);
    }
    h.readerFault = true;
    assert.equal((await h.construct().processInitialization(sealed)).status, "UNAVAILABLE");
    assert.equal((await h.construct().settle(digest)).settled, false);
    assert.equal(h.dispatches, 0);
    h.readerFault = false;
    h.snapshot = exact;
    assert.equal((await h.construct().processInitialization(sealed)).status, "ATTESTED");
    assert.equal(h.dispatches, 0, "a signed read is evidence only; it never dispatches");
  } finally { h.ledger.close(); }
});

test("positive settlement only releases latch; failures and negative snapshots never erase claims", async () => {
  for (const negative of [absent, { ...absent, status: "HISTORY_INCOMPLETE" }, { ...absent, status: "UNAVAILABLE" },
    { ...exact, receipt: { ...receipt, digest: "b".repeat(64) } }] as Snapshot[]) {
    const h = harness();
    try {
      await h.construct().processInitialization(sealed); h.snapshot = negative;
      assert.equal((await h.construct().settle(digest)).settled, false);
      claimed(h.ledger);
    } finally { h.ledger.close(); }
  }
  const h = harness();
  try {
    await h.construct().processInitialization(sealed);
    h.snapshot = exact;
    h.ledger.failSql = /^DELETE FROM latch/u;
    assert.equal((await h.construct().settle(digest)).settled, false);
    claimed(h.ledger);
    h.ledger.failSql = null;
    assert.equal((await h.construct().settle("b".repeat(64))).settled, false);
    claimed(h.ledger);
    assert.equal((await h.construct().settle(digest)).settled, true);
    assert.equal(h.ledger.count("SELECT COUNT(*) AS count FROM latch"), 0);
    assert.equal(h.ledger.count("SELECT COUNT(*) AS count FROM claims"), 1);
    assert.equal((await h.construct().settle(digest)).settled, true, "duplicate acknowledgement recovers durable settlement");
    assert.equal(h.dispatches, 1);
  } finally { h.ledger.close(); }
});

test("settlement durability acknowledgement loss never restores a consumed digest", async () => {
  const h = harness();
  try {
    assert.equal((await h.construct().processInitialization(sealed)).status, "ATTESTED");
    h.snapshot = exact;
    h.ledger.failSyncAt = 3;
    assert.equal((await h.construct().settle(digest)).settled, false, "sync failure is not reported as settled");
    assert.equal(h.ledger.count("SELECT COUNT(*) AS count FROM claims"), 1, "settlement never deletes consumption");
    h.ledger.failSyncAt = 0;
    assert.equal((await h.construct().settle(digest)).settled, true, "repeated control recovers committed resolution");
    assert.equal((await h.construct().processInitialization(sealed)).status, "ATTESTED");
    assert.equal(h.dispatches, 1, "lost settlement acknowledgement cannot redispatch mutation");
  } finally { h.ledger.close(); }
});

// --- R06 Slice 2C: opaque signed relay, AMBIGUOUS recovery, signer-unavailable pre-mutation, downgrade closure ---------------------

test("2C: an attested envelope crosses the guard as the exact same bytes and the claim records relay-local APPLIED", async () => {
  const h = harness();
  try {
    const outcome = await h.construct().processInitialization(sealed);
    assert.equal(outcome.status, "ATTESTED");
    if (outcome.status !== "ATTESTED") return;
    assert.equal(outcome.relayDisposition, "APPLIED");
    assert.equal(outcome.envelope, ENVELOPE, "same instance: not parsed, copied, canonicalized or re-serialized");
    assert.deepEqual(Object.keys(outcome).sort(), ["digest", "envelope", "relayDisposition", "status", "version"]);
    assert.equal(h.dispatches, 1);
  } finally { h.ledger.close(); }
});

test("2C: Authority AMBIGUOUS (committed, unsigned) is UNCONFIRMED, never REFUSED, never redispatched, and recoverable by a signed read", async () => {
  const h = harness();
  try {
    h.response = "ambiguous";
    const outcome = await h.construct().processInitialization(sealed);
    assert.deepEqual([outcome.status, reasonOf(outcome)], ["UNCONFIRMED", "attestation-ambiguous"]);
    assert.equal(h.dispatches, 1);
    claimed(h.ledger);
    assert.equal((h.ledger.db.prepare("SELECT status FROM claims WHERE digest=?").get(digest) as { status: string }).status, "UNCONFIRMED");
    // the replay (before the claim check) obtains signed evidence from the Authority's read-only path: no second mutation
    h.snapshot = exact;
    const recovered = await h.construct().processInitialization(sealed);
    assert.equal(recovered.status, "ATTESTED");
    if (recovered.status === "ATTESTED") assert.equal(recovered.relayDisposition, "ALREADY_APPLIED");
    assert.equal(h.dispatches, 1, "recovery never mutates again");
  } finally { h.ledger.close(); }
});

test("2C: Authority UNAVAILABLE after the claim is UNCONFIRMED (not REFUSED); before the claim it is UNAVAILABLE and consumes nothing", async () => {
  const post = harness();
  try {
    post.response = "unavailable";
    const outcome = await post.construct().processInitialization(sealed);
    assert.deepEqual([outcome.status, reasonOf(outcome)], ["UNCONFIRMED", "authority-signer-unconfigured"]);
    claimed(post.ledger);
  } finally { post.ledger.close(); }
  const pre = harness();
  try {
    pre.probe = "signer-unconfigured";
    const outcome = await pre.construct().processInitialization(sealed);
    assert.deepEqual([outcome.status, reasonOf(outcome)], ["UNAVAILABLE", "authority-history"]);
    assert.equal(pre.ledger.count("SELECT COUNT(*) AS count FROM claims"), 0, "a signer problem consumes no claim");
    assert.equal(pre.ledger.count("SELECT COUNT(*) AS count FROM latch"), 0);
    assert.equal(pre.dispatches, 0, "and never dispatches a mutation");
    pre.probe = "from-snapshot";
    assert.equal((await pre.construct().processInitialization(sealed)).status, "ATTESTED", "the same command is still submittable once the signer is healthy");
  } finally { pre.ledger.close(); }
});

test("2C: downgrade closure at the guard: an unsigned positive from the executor or the read path is never ATTESTED", async () => {
  const executor = harness();
  try {
    executor.response = "legacy";
    const outcome = await executor.construct().processInitialization(sealed);
    assert.deepEqual([outcome.status, reasonOf(outcome)], ["UNCONFIRMED", "dispatch-ambiguous"]);
    assert.equal("receipt" in outcome, false);
    assert.equal(executor.dispatches, 1);
  } finally { executor.ledger.close(); }
  const reader = harness();
  try {
    reader.probe = "legacy";
    const outcome = await reader.construct().processInitialization(sealed);
    assert.equal(outcome.status, "UNAVAILABLE", "an unsigned EXACT_RECEIPT answer neither short-circuits nor dispatches as success");
    assert.equal(reader.ledger.count("SELECT COUNT(*) AS count FROM claims"), 0);
    // the unsigned supervisory snapshot alone, with no signed read, can never produce a result
    reader.probe = "from-snapshot"; reader.snapshot = exact;
    assert.equal((await reader.construct().processInitialization(sealed)).status, "ATTESTED", "only the Authority-signed read yields evidence");
  } finally { reader.ledger.close(); }
});

/** ATTESTED-shaped Authority answers that are NOT exactly {status, relayDisposition, envelope: non-empty bounded Uint8Array}. The relay
 * checks transport shape only (isOpaqueEnvelope is unchanged and exact), so each of these must fail non-positive. */
const malformedAttested = (): Array<[string, unknown]> => [
  ["missing envelope", { status: "ATTESTED", relayDisposition: "APPLIED" }],
  ["undefined envelope", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: undefined }],
  ["null envelope", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: null }],
  ["array envelope", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: [0xde, 0xad] }],
  ["string envelope", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: "deadbeef" }],
  ["ArrayBuffer envelope", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: new ArrayBuffer(8) }],
  ["DataView envelope", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: new DataView(new ArrayBuffer(8)) }],
  ["array-like object envelope", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: { 0: 1, length: 1 } }],
  ["empty Uint8Array envelope", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: new Uint8Array(0) }],
  ["oversize Uint8Array envelope", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: new Uint8Array(8_193) }],
  ["extra semantic field: receipt", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: ENVELOPE, receipt }],
  ["extra semantic field: statement", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: ENVELOPE, statement: [2, 1] }],
  ["extra semantic field: observedAtMs", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: ENVELOPE, observedAtMs: Date.now() }],
  ["extra field: reason", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: ENVELOPE, reason: "ok" }],
  ["unexpected key", { status: "ATTESTED", relayDisposition: "APPLIED", envelope: ENVELOPE, extra: true }],
  ["missing relayDisposition", { status: "ATTESTED", envelope: ENVELOPE }],
  ["relayDisposition SUCCESS", { status: "ATTESTED", relayDisposition: "SUCCESS", envelope: ENVELOPE }],
  ["relayDisposition lowercase", { status: "ATTESTED", relayDisposition: "applied", envelope: ENVELOPE }],
  ["relayDisposition number", { status: "ATTESTED", relayDisposition: 1, envelope: ENVELOPE }],
  ["relayDisposition null", { status: "ATTESTED", relayDisposition: null, envelope: ENVELOPE }],
  ["array instead of record", ["ATTESTED", "APPLIED", ENVELOPE]],
];

test("2C: malformed ATTESTED executor answers fail non-positive at the guard and are never relayed as signed evidence", async () => {
  assert.ok(malformedAttested().length >= 20, "the malformed-ATTESTED matrix cannot silently shrink");
  for (const [label, answer] of malformedAttested()) {
    const h = harness();
    try {
      h.customResponse = answer;
      const outcome = await h.construct().processInitialization(sealed);
      assert.notEqual(outcome.status, "ATTESTED", `${label}: must never be treated as signed evidence`);
      assert.deepEqual(statusReason(outcome), ["UNCONFIRMED", "dispatch-ambiguous"], label);
      assert.equal("envelope" in outcome, false, `${label}: nothing opaque is carried`);
      assert.equal("relayDisposition" in outcome, false, label);
      assert.equal(h.dispatches, 1, `${label}: exactly the one dispatch`);
      claimed(h.ledger);
      assert.equal((h.ledger.db.prepare("SELECT status FROM claims WHERE digest=?").get(digest) as { status: string }).status, "UNCONFIRMED",
        `${label}: never recorded as a success or an already-applied`);
      await duplicateCannotDispatch(h);
      assert.equal(h.dispatches, 1, `${label}: no redispatch`);
    } finally { h.ledger.close(); }
  }
  // positive control: the exact shape IS relayed, so the cases above fail because of their shape and not because of the harness
  const control = harness();
  try {
    control.customResponse = { status: "ATTESTED", relayDisposition: "ALREADY_APPLIED", envelope: ENVELOPE };
    const outcome = await control.construct().processInitialization(sealed);
    assert.equal(outcome.status, "ATTESTED");
    if (outcome.status === "ATTESTED") assert.equal(outcome.relayDisposition, "ALREADY_APPLIED");
  } finally { control.ledger.close(); }
});

test("2C: malformed ATTESTED answers to the signed PRE-CLAIM probe are UNAVAILABLE, consume nothing and never short-circuit as evidence", async () => {
  for (const [label, answer] of malformedAttested()) {
    const h = harness();
    try {
      h.customProbe = answer;
      const outcome = await h.construct().processInitialization(sealed);
      assert.deepEqual(statusReason(outcome), ["UNAVAILABLE", "authority-history"], label);
      assert.equal(h.ledger.count("SELECT COUNT(*) AS count FROM claims"), 0, `${label}: no claim`);
      assert.equal(h.ledger.count("SELECT COUNT(*) AS count FROM latch"), 0, `${label}: no latch`);
      assert.equal(h.dispatches, 0, label);
    } finally { h.ledger.close(); }
  }
});
