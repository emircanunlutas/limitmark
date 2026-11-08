import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, test } from "node:test";
import { build } from "esbuild";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, LAB_ADMISSION_AUTHORITY_ID, STAGING_ADMISSION_AUTHORITY_ID } from "../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, signAuthorityInitializationCommand, type AuthorityInitializationCommand } from "../workers/admission-service/operator-command";
import type { GuardEnvironment, LifecycleDispatchGuard } from "../workers/lifecycle-mailbox/dispatch-guard";
import {
  GUARD_EXPORT_OPERATION, GUARD_EXPORT_REQUEST_VERSION, GUARD_EXPORT_ROW_LIMIT, guardExportRequestDigest, signGuardExportRequest, type GuardExportEnvelope, type GuardExportOutcome, type GuardExportRequest,
} from "../workers/lifecycle-mailbox/guard-export";
import { RESULT_LIMIT } from "../workers/lifecycle-mailbox/wire";
import { guardLedgerExportFromMailboxResult, serializeGuardLedgerExport, verifyGuardLedgerExport } from "../operator/guard-ledger-export";

// Authenticated, read-only guard ledger export: unit-level behavior of the REAL guard class (bundled; file-backed SQLite; synthetic keys; mocked bindings).
// The workerd integration (tests/workers/guard-export.integration.ts) covers the entrypoint, the observer slot and the service-binding surface.

const GUARD = "production-lifecycle-dispatch-v1";
const ACCOUNT = "c".repeat(32);
type GuardClass = typeof LifecycleDispatchGuard;
let Guard: GuardClass;
let directory: string;
let publicKey: string;
let privateKey: string;
let otherPrivateKey: string;
let counter = 0;

class RecordingLedger {
  readonly db: DatabaseSync;
  readonly statements: string[] = [];
  syncs = 0;
  transactions = 0;
  recording = false;
  readonly sql = { exec: <T = Record<string, unknown>>(query: string, ...params: unknown[]): Iterable<T> => {
    if (this.recording) this.statements.push(query.trim());
    const statement = this.db.prepare(query);
    if (statement.columns().length) return statement.all(...params as []) as T[];
    statement.run(...params as []);
    return [];
  } };
  constructor(path: string) { this.db = new DatabaseSync(path); }
  transactionSync<T>(callback: () => T): T {
    if (this.recording) this.transactions += 1;
    this.db.exec("BEGIN");
    try { const result = callback(); this.db.exec("COMMIT"); return result; } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }
  async sync(): Promise<void> { if (this.recording) this.syncs += 1; }
  dump(): string {
    return JSON.stringify(["claims", "latch", "settlements"].map((table) => this.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()));
  }
}

before(async () => {
  directory = await mkdtemp(join(tmpdir(), "limitmark-guard-export-method-"));
  const bundled = await build({ entryPoints: [resolve("workers/lifecycle-mailbox/dispatch-guard.ts")], bundle: true, write: false, platform: "node", format: "esm", target: "node24",
    plugins: [{ name: "local-do-base", setup(api) {
      api.onResolve({ filter: /^cloudflare:workers$/ }, () => ({ path: "local-do-base", namespace: "test" }));
      api.onLoad({ filter: /.*/, namespace: "test" }, () => ({ contents: "export class DurableObject { constructor(_state, env) { this.env = env; } }", loader: "js" }));
      api.onResolve({ filter: /.*/ }, async (args) => {
        const base = args.path.startsWith(".") || isAbsolute(args.path) ? resolve(args.resolveDir || process.cwd(), args.path) : args.path;
        for (const path of [base, `${base}.ts`, `${base}.js`, join(base, "index.ts")]) { try { await readFile(path); return { path, namespace: "workspace-file" }; } catch { /* next */ } }
        throw new Error(`unresolved: ${args.path}`);
      });
      api.onLoad({ filter: /.*/, namespace: "workspace-file" }, async (args) => ({ contents: await readFile(args.path), resolveDir: dirname(args.path), loader: extname(args.path) === ".ts" ? "ts" : "js" }));
    } }] });
  Guard = (await import(`data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`) as { LifecycleDispatchGuard: GuardClass }).LifecycleDispatchGuard;
  const keys = async () => {
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    return { priv: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))), pub: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))) };
  };
  const operator = await keys();
  privateKey = operator.priv; publicKey = operator.pub;
  otherPrivateKey = (await keys()).priv;
});
const opened: RecordingLedger[] = [];
after(async () => { for (const ledger of opened) ledger.db.close(); await rm(directory, { recursive: true, force: true }); });

const calls = { executor: 0, reader: 0 };
function guardFor(ledger: RecordingLedger, overrides: Partial<GuardEnvironment> = {}) {
  const env: GuardEnvironment = { AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey, LIFECYCLE_ENVIRONMENT: "production", CLOUDFLARE_ACCOUNT_ID: ACCOUNT,
    LIFECYCLE_READER: { inspectLifecycle: async () => { calls.reader += 1; return { status: "NOT_FOUND" }; }, attestAppliedLifecycle: async () => { calls.reader += 1; return { status: "UNAVAILABLE", reason: "receipt-not-found" }; } },
    LIFECYCLE_EXECUTOR: { submitInitializationArtifact: async () => { calls.executor += 1; throw new Error("lost"); }, submitRotationArtifact: async () => { calls.executor += 1; throw new Error("lost"); } },
    ...overrides };
  return new Guard({ storage: ledger } as never, env);
}
const freshLedger = () => { const ledger = new RecordingLedger(join(directory, `ledger-${counter++}.sqlite`)); opened.push(ledger); return ledger; };
const nonce = () => (counter++).toString(16).padStart(32, "0");
const request = (overrides: Partial<Record<number, unknown>> = {}): GuardExportRequest => {
  const base: unknown[] = [GUARD_EXPORT_REQUEST_VERSION, GUARD_EXPORT_OPERATION, "production", ADMISSION_AUTHORITY_ID, GUARD, ACCOUNT, nonce(), Date.now()];
  for (const [index, value] of Object.entries(overrides)) base[Number(index)] = value;
  return base as unknown as GuardExportRequest;
};
async function envelope(req: GuardExportRequest, key = privateKey): Promise<string> {
  return JSON.stringify({ request: req, signature: await signGuardExportRequest(req, key) } satisfies GuardExportEnvelope);
}
async function strand(ledger: RecordingLedger): Promise<string> {
  const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "r", "k", Date.now(), true];
  const sealed = JSON.stringify({ command, signature: await signAuthorityInitializationCommand(command, privateKey) });
  assert.equal((await guardFor(ledger).processInitialization(sealed)).status, "UNCONFIRMED");
  return sealed;
}

test("a valid operator-signed request exports the exact ledger, and the export is strictly read-only", async () => {
  const ledger = freshLedger();
  await strand(ledger);
  const before = ledger.dump();
  Object.assign(calls, { executor: 0, reader: 0 });
  const guard = guardFor(ledger);   // construction (idempotent CREATE TABLE IF NOT EXISTS, as on every activation) is not part of the export
  const req = request();
  const text0 = await envelope(req);
  ledger.recording = true;
  const outcome = await guard.exportLedger(text0);
  ledger.recording = false;
  assert.equal(outcome.status, "EXPORTED");
  if (outcome.status !== "EXPORTED") return;
  assert.deepEqual([outcome.environment, outcome.authorityId, outcome.guardObject, outcome.accountId, outcome.nonce], ["production", ADMISSION_AUTHORITY_ID, GUARD, ACCOUNT, req[6]]);
  assert.equal(outcome.requestDigest, await guardExportRequestDigest(req));
  assert.equal(outcome.ledger.claims.length, 1);
  assert.equal(outcome.ledger.claims[0].status, "CLAIMED");
  assert.deepEqual(outcome.ledger.latch, { digest: outcome.ledger.claims[0].digest });
  assert.deepEqual(outcome.ledger.settlements, []);
  // read-only: only SELECT statements, no sync, no transaction, no binding call, identical ledger afterwards
  assert.ok(ledger.statements.length >= 4);
  assert.ok(ledger.statements.every((statement) => /^SELECT\b/u.test(statement)), JSON.stringify(ledger.statements));
  assert.deepEqual([ledger.syncs, ledger.transactions, calls.executor, calls.reader], [0, 0, 0, 0]);
  assert.equal(ledger.dump(), before);
  // the offline verifier accepts exactly what the guard answered, for exactly this request
  const text = JSON.stringify(outcome);
  const document = guardLedgerExportFromMailboxResult(text, { environment: "production", guardObject: GUARD, accountId: ACCOUNT, requestDigest: outcome.requestDigest, nonce: req[6] });
  assert.equal(document.derived.strandedCandidate, true);
  assert.equal(document.derived.dispatchBlocked, true);
  assert.equal(document.provenance.kind, "mailbox-export");
  assert.equal(verifyGuardLedgerExport(serializeGuardLedgerExport(document), { environment: "production", guardObject: GUARD }).contentSha256, document.contentSha256);
});

test("export output is deterministic (apart from the guard clock) and replay-safe", async () => {
  const ledger = freshLedger();
  await strand(ledger);
  const text = await envelope(request());
  const a = await guardFor(ledger).exportLedger(text) as Extract<GuardExportOutcome, { status: "EXPORTED" }>;
  const b = await guardFor(ledger).exportLedger(text) as Extract<GuardExportOutcome, { status: "EXPORTED" }>;
  assert.deepEqual({ ...a, observedAtMs: 0 }, { ...b, observedAtMs: 0 });
  assert.equal(JSON.stringify(a.ledger), JSON.stringify(b.ledger));
});

test("authorization: every unauthenticated or malformed request is REFUSED(unauthenticated) with no nonce, no digest and no rows", async () => {
  const ledger = freshLedger();
  await strand(ledger);
  const good = request();
  const goodText = await envelope(good);
  const parsed = JSON.parse(goodText) as { request: unknown[]; signature: string };
  const wrongKey = await envelope(good, otherPrivateKey);
  const tamperedField = JSON.stringify({ ...parsed, request: parsed.request.map((value, index) => index === 7 ? (value as number) + 1 : value) });
  const tamperedNonce = JSON.stringify({ ...parsed, request: parsed.request.map((value, index) => index === 6 ? "d".repeat(32) : value) });
  // A genuine operator signature over a LIFECYCLE command can never authorize an export (domain separation), and vice versa.
  const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "r", "k", Date.now(), true];
  const lifecycleSignature = await signAuthorityInitializationCommand(command, privateKey);
  const rawJsonSignature = await (async () => {   // signature over the bare JSON of the export request (no domain prefix)
    const key = await crypto.subtle.importKey("pkcs8", Buffer.from(privateKey, "base64url"), { name: "Ed25519" }, false, ["sign"]);
    return Buffer.from(await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(JSON.stringify(good)))).toString("base64url");
  })();
  const cases: Record<string, string> = {
    empty: "", garbage: "not json", array: "[]", nullish: "null",
    unsigned: JSON.stringify({ request: good }), emptySignature: JSON.stringify({ request: good, signature: "" }),
    wrongKey, tamperedField, tamperedNonce,
    lifecycleSignatureReused: JSON.stringify({ request: good, signature: lifecycleSignature }),
    rawJsonSignature: JSON.stringify({ request: good, signature: rawJsonSignature }),
    extraKey: JSON.stringify({ ...parsed, extra: 1 }),
    duplicateKey: goodText.replace('"signature"', '"request":[],"signature"'),
    shortRequest: JSON.stringify({ ...parsed, request: parsed.request.slice(0, 7) }),
    longRequest: JSON.stringify({ ...parsed, request: [...parsed.request, 1] }),
    wrongVersion: JSON.stringify({ ...parsed, request: parsed.request.map((value, index) => index === 0 ? "limitmark-guard-export-request-v0" : value) }),
    wrongOperation: JSON.stringify({ ...parsed, request: parsed.request.map((value, index) => index === 1 ? "initialize" : value) }),
    badNonce: JSON.stringify({ ...parsed, request: parsed.request.map((value, index) => index === 6 ? "xyz" : value) }),
    badAccount: JSON.stringify({ ...parsed, request: parsed.request.map((value, index) => index === 5 ? "ABC" : value) }),
    injectionInGuard: JSON.stringify({ ...parsed, request: parsed.request.map((value, index) => index === 4 ? "x'; DELETE FROM claims; --" : value) }),
    floatTime: JSON.stringify({ ...parsed, request: parsed.request.map((value, index) => index === 7 ? 1.5 : value) }),
    negativeTime: JSON.stringify({ ...parsed, request: parsed.request.map((value, index) => index === 7 ? -1 : value) }),
    oversized: `{"request":[],"signature":"${"A".repeat(4_096)}"}`,
    bom: `﻿${goodText}`,
  };
  Object.assign(calls, { executor: 0, reader: 0 });
  const before = ledger.dump();
  for (const [name, text] of Object.entries(cases)) {
    const outcome = await guardFor(ledger).exportLedger(text);
    assert.deepEqual(outcome, { version: 1, status: "REFUSED", reason: "unauthenticated" }, name);
  }
  assert.equal(await guardFor(ledger).exportLedger(undefined as never).then((o) => JSON.stringify(o)), JSON.stringify({ version: 1, status: "REFUSED", reason: "configuration" }));
  assert.equal(await guardFor(ledger).exportLedger(42 as never).then((o) => JSON.stringify(o)), JSON.stringify({ version: 1, status: "REFUSED", reason: "configuration" }));
  assert.equal(ledger.dump(), before);
  assert.deepEqual([calls.executor, calls.reader], [0, 0]);
});

test("environment confusion: staging/lab/other targets and another account are refused after authentication, naming only the nonce", async () => {
  const ledger = freshLedger();
  await strand(ledger);
  const attempts: Array<[string, Partial<Record<number, unknown>>]> = [
    ["environment staging", { 2: "staging" }], ["environment lab", { 2: "lab" }], ["authority staging", { 3: STAGING_ADMISSION_AUTHORITY_ID }], ["authority lab", { 3: LAB_ADMISSION_AUTHORITY_ID }],
    ["guard staging", { 4: "staging-lifecycle-dispatch-v1" }], ["guard lab", { 4: "lab-lifecycle-dispatch-v1" }], ["guard other generation", { 4: "production-lifecycle-dispatch-v2" }],
    ["other account", { 5: "d".repeat(32) }],
  ];
  for (const [name, overrides] of attempts) {
    const req = request(overrides);
    const outcome = await guardFor(ledger).exportLedger(await envelope(req));
    assert.deepEqual(outcome, { version: 1, status: "REFUSED", reason: "target-mismatch", nonce: req[6], requestDigest: await guardExportRequestDigest(req) }, name);
    assert.equal(JSON.stringify(outcome).includes("claims"), false);
  }
  // the guard itself being configured for another environment, or without/with a malformed account pin, refuses everything (configuration)
  const valid = await envelope(request());
  for (const [name, env] of [["staging env", { LIFECYCLE_ENVIRONMENT: "staging" }], ["lab env", { LIFECYCLE_ENVIRONMENT: "lab" }], ["no account", { CLOUDFLARE_ACCOUNT_ID: undefined }],
    ["bad account", { CLOUDFLARE_ACCOUNT_ID: "nope" }], ["upper account", { CLOUDFLARE_ACCOUNT_ID: "C".repeat(32) }]] as const) {
    assert.deepEqual(await guardFor(ledger, env as Partial<GuardEnvironment>).exportLedger(valid), { version: 1, status: "REFUSED", reason: "configuration" }, name);
  }
  // an operator key different from the guard's pinned key cannot authorize
  assert.deepEqual(await guardFor(ledger, { AUTHORITY_OPERATOR_PUBLIC_KEY: encodeBase64url(new Uint8Array(32).fill(5)) }).exportLedger(valid), { version: 1, status: "REFUSED", reason: "unauthenticated" });
});

test("freshness: the signed issuedAtMs must be within the 120 s window at the guard clock; both directions", async () => {
  const ledger = freshLedger();
  await strand(ledger);
  const now = Date.now();
  for (const [offset, expected] of [[0, "EXPORTED"], [-60_000, "EXPORTED"], [60_000, "EXPORTED"], [-125_000, "REFUSED"], [125_000, "REFUSED"], [-3_600_000, "REFUSED"]] as const) {
    const req = request({ 7: now + offset });
    const outcome = await guardFor(ledger).exportLedger(await envelope(req));
    assert.equal(outcome.status, expected, String(offset));
    if (outcome.status === "REFUSED") assert.deepEqual(outcome, { version: 1, status: "REFUSED", reason: "stale-request", nonce: req[6], requestDigest: await guardExportRequestDigest(req) });
  }
});

test("bounded and honest: exactly the row limit exports, more answers TOO_LARGE with counts only, and the worst case fits the result object limit", async () => {
  const insert = (ledger: RecordingLedger, claims: number, settlements: number) => {
    for (let i = 0; i < claims; i++) ledger.db.prepare("INSERT INTO claims(digest,operation,status) VALUES(?,?,?)").run(i.toString(16).padStart(64, "a"), "rotate-release", "ALREADY_APPLIED");
    for (let i = 1; i <= settlements; i++) ledger.db.prepare("INSERT INTO settlements(digest,version,status,sequence,settled_ms) VALUES(?,1,'SETTLED',?,?)").run((i - 1).toString(16).padStart(64, "a"), i, 1_760_000_000_000 + i);
  };
  const full = freshLedger();
  guardFor(full);
  insert(full, GUARD_EXPORT_ROW_LIMIT, GUARD_EXPORT_ROW_LIMIT);
  const exported = await guardFor(full).exportLedger(await envelope(request()));
  assert.equal(exported.status, "EXPORTED");
  assert.ok(new TextEncoder().encode(JSON.stringify(exported)).byteLength <= RESULT_LIMIT, "worst case must fit one result object");
  const over = freshLedger();
  guardFor(over);
  insert(over, GUARD_EXPORT_ROW_LIMIT + 1, 3);
  const outcome = await guardFor(over).exportLedger(await envelope(request()));
  assert.equal(outcome.status, "TOO_LARGE");
  if (outcome.status === "TOO_LARGE") assert.deepEqual(outcome.counts, { claims: GUARD_EXPORT_ROW_LIMIT + 1, settlements: 3 });
  assert.equal(JSON.stringify(outcome).includes("aaaa"), false, "no row content when too large");
  const overSettlements = freshLedger();
  guardFor(overSettlements);
  insert(overSettlements, 1, GUARD_EXPORT_ROW_LIMIT + 1);
  assert.equal((await guardFor(overSettlements).exportLedger(await envelope(request()))).status, "TOO_LARGE");
});

test("an empty or settled ledger exports too, and exports never contain key material or signatures", async () => {
  const ledger = freshLedger();
  guardFor(ledger);
  const outcome = await guardFor(ledger).exportLedger(await envelope(request()));
  assert.equal(outcome.status, "EXPORTED");
  const text = JSON.stringify(outcome);
  for (const secret of [publicKey, privateKey, otherPrivateKey]) assert.equal(text.includes(secret), false);
  assert.equal(/signature|privateKey|secret|token/iu.test(text), false);
});

test("surface: the guard prototype is the three reviewed lifecycle operations plus exactly one read-only export; other guards expose no export", async () => {
  assert.deepEqual(Object.getOwnPropertyNames(Guard.prototype).sort(), ["constructor", "exportLedger", "processInitialization", "processRotation", "settle"]);
  const source = (await readFile("workers/lifecycle-mailbox/dispatch-guard.ts", "utf8")).replace(/\/\*[\s\S]*?\*\//gu, "").replace(/^\s*\/\/.*$/gmu, "");
  const start = source.indexOf("async exportLedger(");
  const body = source.slice(start, source.indexOf("async settle(", start));
  assert.ok(body.length > 500);
  assert.deepEqual([...body.matchAll(/exec[^(]*\(\s*"([A-Z]+)\b/gu)].map((m) => m[1]).sort(), ["SELECT", "SELECT"]);
  assert.doesNotMatch(body, /INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|REPLACE|PRAGMA|transactionSync|\.sync\(|LIFECYCLE_EXECUTOR|LIFECYCLE_READER|\.put\(|this\.env\.[A-Z_]*FOO/u);
  for (const other of ["lab-dispatch-guard.ts", "staging-dispatch-guard.ts"]) assert.doesNotMatch(await readFile(`workers/lifecycle-mailbox/${other}`, "utf8"), /exportLedger/u, other);
  // no generic SQL surface anywhere in the entrypoint
  const reader = await readFile("workers/lifecycle-mailbox/guard-reader.ts", "utf8");
  assert.deepEqual([...reader.replace(/\/\*[\s\S]*?\*\//gu, "").matchAll(/^\s+async (\w+)\(/gmu)].map((m) => m[1]), ["exportLedger"]);
});
