import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, test } from "node:test";
import { loadBundledGuard } from "./support/worker-bundle";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH } from "../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, commandDigest, signAuthorityInitializationCommand, type AuthorityInitializationCommand } from "../workers/admission-service/operator-command";
import type { LifecycleDispatchGuard, GuardEnvironment } from "../workers/lifecycle-mailbox/dispatch-guard";
import {
  GuardExportRefusal, buildGuardLedgerExport, canonicalJson, exportGuardLedger, normalizeGuardLedgerRows, serializeGuardLedgerExport,
  sqliteGuardLedgerSource, verifyGuardLedgerExport,
} from "../operator/guard-ledger-export";

// The ledgers exported here are produced by the REAL LifecycleDispatchGuard class (bundled, run on a file-backed SQLite store with synthetic keys
// and mocked executor/reader bindings), then read back by the read-only exporter. Nothing is live.

const root = process.cwd();
const tsx = join(root, "node_modules", "tsx", "dist", "cli.mjs");
const PRODUCTION = { environment: "production", guardObject: "production-lifecycle-dispatch-v1" } as const;
type GuardClass = typeof LifecycleDispatchGuard;
let Guard: GuardClass;
let directory: string;
let publicKey: string;
let privateKey: string;

class FileLedger {
  readonly db: DatabaseSync;
  readonly sql = { exec: <T = Record<string, unknown>>(query: string, ...params: unknown[]): Iterable<T> => {
    const statement = this.db.prepare(query);
    if (statement.columns().length) return statement.all(...params as []) as T[];
    statement.run(...params as []);
    return [];
  } };
  constructor(readonly path: string) { this.db = new DatabaseSync(path); }
  transactionSync<T>(callback: () => T): T {
    this.db.exec("BEGIN");
    try { const result = callback(); this.db.exec("COMMIT"); return result; } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }
  async sync(): Promise<void> { /* the file is durable once written */ }
  close(): void { this.db.close(); }
}

before(async () => {
  directory = await mkdtemp(join(tmpdir(), "limitmark-guard-export-"));
  Guard = await loadBundledGuard();
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  privateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  publicKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
});
after(async () => { await rm(directory, { recursive: true, force: true }); });

async function sealedCommand(issuedAtMs = Date.now()): Promise<{ sealed: string; digest: string }> {
  const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "export-release", "export-key", issuedAtMs, true];
  return { sealed: JSON.stringify({ command, signature: await signAuthorityInitializationCommand(command, privateKey) }), digest: await commandDigest(command) };
}
const ENVELOPE = Uint8Array.from([0xde, 0xad, 0xbe, 0xef]);
function guardFor(ledger: FileLedger, behaviour: { executor: "success" | "throw"; receiptFor?: string }) {
  const env: GuardEnvironment = { AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey, LIFECYCLE_ENVIRONMENT: "production",
    LIFECYCLE_READER: {
      inspectLifecycle: async () => behaviour.receiptFor
        ? { status: "EXACT_RECEIPT", environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
            receipt: { digest: behaviour.receiptFor } as never }
        : { status: "NOT_FOUND", environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH },
      attestAppliedLifecycle: async () => ({ status: "UNAVAILABLE", reason: "receipt-not-found" }),
    },
    LIFECYCLE_EXECUTOR: {
      submitInitializationArtifact: async () => { if (behaviour.executor === "throw") throw new Error("lost-executor-ack"); return { status: "ATTESTED", relayDisposition: "APPLIED", envelope: ENVELOPE } as never; },
      submitRotationArtifact: async () => { throw new Error("unused"); },
    } };
  return new Guard({ storage: ledger } as never, env);
}
const fileSha = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");

async function ledgerFile(name: string, scenario: "settled" | "stranded" | "empty"): Promise<{ path: string; digest: string; sealed: string }> {
  const path = join(directory, name);
  const ledger = new FileLedger(path);
  const { sealed, digest } = await sealedCommand();
  if (scenario === "settled") {
    const outcome = await guardFor(ledger, { executor: "success" }).processInitialization(sealed);
    assert.equal(outcome.status, "ATTESTED");
    assert.deepEqual(await guardFor(ledger, { executor: "success", receiptFor: digest }).settle(digest), { version: 1, settled: true });
  } else if (scenario === "stranded") {
    const outcome = await guardFor(ledger, { executor: "throw" }).processInitialization(sealed);
    assert.deepEqual([outcome.status, "reason" in outcome ? outcome.reason : ""], ["UNCONFIRMED", "dispatch-ambiguous"]);   // the relay outcome; the ledger row keeps its initial CLAIMED note
  } else {
    guardFor(ledger, { executor: "success" });   // construction creates the three empty tables
  }
  ledger.close();
  return { path, digest, sealed };
}

// ------------------------------------------------------------------------------------------------------------------------------------ export of real guard ledgers

test("a settled ledger exports with the single claim, its settlement, no latch and no blockage", async () => {
  const { path, digest } = await ledgerFile("settled.sqlite", "settled");
  const result = exportGuardLedger(sqliteGuardLedgerSource(path), PRODUCTION);
  assert.equal(result.ledger.claims.length, 1);
  assert.deepEqual(result.ledger.claims[0], { digest, operation: "initialize", status: "SUCCESS" });
  assert.equal(result.ledger.latch, null);
  assert.deepEqual(result.ledger.settlements.map((row) => [row.digest, row.sequence]), [[digest, 1]]);
  assert.deepEqual({ ...result.derived, claimsRemaining: 0, settlementsRemaining: 0 }, {
    claimCount: 1, settlementCount: 1, latchHeld: false, latchedDigest: null, latchedOperation: null, latchedStatus: null, dispatchBlocked: false,
    strandedCandidate: false, unsettledDigests: [], claimsRemaining: 0, settlementsRemaining: 0 });
  assert.deepEqual(result.target, { environment: "production", guardObject: "production-lifecycle-dispatch-v1", authorityId: "production-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1" });
  assert.equal(result.provenance.identityEvidence, "operator-asserted");
});

test("a stranded (consumed, never settled) ledger is reported as a blocked guard with a stranded candidate, and nothing more", async () => {
  const { path, digest } = await ledgerFile("stranded.sqlite", "stranded");
  const result = exportGuardLedger(sqliteGuardLedgerSource(path), PRODUCTION);
  assert.deepEqual(result.ledger.claims.map((row) => [row.digest, row.status]), [[digest, "CLAIMED"]], "an executor exception returns before the ledger note is updated");
  assert.deepEqual(result.ledger.latch, { digest });
  assert.equal(result.ledger.settlements.length, 0);
  assert.equal(result.derived.dispatchBlocked, true);
  assert.equal(result.derived.strandedCandidate, true);
  assert.deepEqual(result.derived.unsettledDigests, [digest]);
  assert.equal(result.derived.latchedStatus, "CLAIMED");
});

test("an untouched empty guard exports as empty and unblocked", async () => {
  const { path } = await ledgerFile("empty.sqlite", "empty");
  const result = exportGuardLedger(sqliteGuardLedgerSource(path), PRODUCTION);
  assert.deepEqual([result.derived.claimCount, result.derived.settlementCount, result.derived.latchHeld, result.derived.dispatchBlocked], [0, 0, false, false]);
});

// ------------------------------------------------------------------------------------------------------------------------------------ determinism and auditability

test("output is deterministic, self-verifying, and any edit of rows, derived fields, target or hash is detected", async () => {
  const { path, digest } = await ledgerFile("determinism.sqlite", "stranded");
  const first = serializeGuardLedgerExport(exportGuardLedger(sqliteGuardLedgerSource(path), PRODUCTION));
  const second = serializeGuardLedgerExport(exportGuardLedger(sqliteGuardLedgerSource(path), PRODUCTION));
  assert.equal(first, second);
  assert.ok(first.endsWith("}\n") && !first.includes("\n  "), "single canonical line");
  assert.equal(verifyGuardLedgerExport(first, PRODUCTION).contentSha256, JSON.parse(first).contentSha256);
  const document = JSON.parse(first);
  const tampered: Array<[string, (value: Record<string, any>) => void]> = [
    ["status edited", (value) => { value.ledger.claims[0].status = "SUCCESS"; }],
    ["latch removed", (value) => { value.ledger.latch = null; }],
    ["claim added", (value) => { value.ledger.claims.push({ digest: "a".repeat(64), operation: "initialize", status: "SUCCESS" }); }],
    ["derived edited", (value) => { value.derived.dispatchBlocked = false; }],
    ["hash edited", (value) => { value.contentSha256 = "0".repeat(64); }],
    ["target edited", (value) => { value.target.authorityId = "other"; }],
    ["provenance edited", (value) => { value.provenance.identityEvidence = "guard-reported"; }],
    ["extra key", (value) => { value.extra = 1; }],
    ["format edited", (value) => { value.format = "other"; }],
  ];
  for (const [name, edit] of tampered) {
    const copy = structuredClone(document);
    edit(copy);
    assert.throws(() => verifyGuardLedgerExport(`${canonicalJson(copy)}\n`, PRODUCTION), GuardExportRefusal, name);
  }
  assert.throws(() => verifyGuardLedgerExport(first, { environment: "staging", guardObject: "staging-lifecycle-dispatch-v1" }), GuardExportRefusal, "verified against another target");
  assert.throws(() => verifyGuardLedgerExport(`${first}${first}`, PRODUCTION), GuardExportRefusal);
  assert.ok(digest);
});

// ------------------------------------------------------------------------------------------------------------------------------------ read-only behaviour

test("exporting never changes the source: bytes, mtime, tables and side files are identical, and no table is ever created", async () => {
  const { path } = await ledgerFile("readonly.sqlite", "stranded");
  const before = { sha: fileSha(path), mtime: statSync(path).mtimeMs, entries: readdirSync(directory).sort() };
  for (let index = 0; index < 3; index++) exportGuardLedger(sqliteGuardLedgerSource(path), PRODUCTION);
  assert.deepEqual({ sha: fileSha(path), mtime: statSync(path).mtimeMs, entries: readdirSync(directory).sort() }, before);
  // a database that lacks the guard tables is refused, and the exporter does not create them
  const bare = join(directory, "bare.sqlite");
  const handle = new DatabaseSync(bare); handle.exec("CREATE TABLE unrelated(x INTEGER)"); handle.close();
  const bareBefore = fileSha(bare);
  assert.throws(() => exportGuardLedger(sqliteGuardLedgerSource(bare), PRODUCTION), (error: unknown) => error instanceof GuardExportRefusal && error.code === "source-incomplete");
  assert.equal(fileSha(bare), bareBefore);
  const check = new DatabaseSync(bare, { readOnly: true });
  assert.deepEqual((check.prepare("SELECT name FROM sqlite_master").all() as Array<{ name: string }>).map((row) => row.name), ["unrelated"]);
  check.close();
});

test("the exporter's only database access is read-only SQL, enforced at the connection and in the source", async () => {
  const { path } = await ledgerFile("writeprobe.sqlite", "stranded");
  const probe = new DatabaseSync(path, { readOnly: true });
  assert.throws(() => probe.exec("DELETE FROM claims"), /readonly|read-only|attempt to write/iu);
  probe.close();
  const source = (await readFile(join(root, "operator", "guard-ledger-export.ts"), "utf8")).replace(/\/\*[\s\S]*?\*\//gu, "").replace(/^\s*\/\/.*$/gmu, "");
  const statements = [...source.matchAll(/\.(?:prepare|exec)\(\s*[`"']([^`"']+)/gu)].map((match) => match[1].trim());
  assert.ok(statements.length >= 5);
  for (const statement of statements) assert.match(statement, /^(?:SELECT\b|PRAGMA query_only = ON$|PRAGMA table_info\()/u, statement);
  assert.doesNotMatch(source, /\b(?:INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|REPLACE|VACUUM|ATTACH)\b/u);
  assert.doesNotMatch(source, /writeFile|appendFile|unlink|rmSync|rename|mkdir|copyFile|child_process|fetch\(|https?:\/\/|node:net|node:http|process\.env/u);
  assert.match(source, /new DatabaseSync\(path, \{ readOnly: true \}\)/u);
});

// ------------------------------------------------------------------------------------------------------------------------------------ identity and fail-closed

test("environment and guard-object identity must match the reviewed pins exactly", async () => {
  const { path } = await ledgerFile("identity.sqlite", "empty");
  const attempts: Array<[string, string, string]> = [
    ["wrong object for production", "production", "staging-lifecycle-dispatch-v1"], ["lab object for production", "production", "lab-lifecycle-dispatch-v1"],
    ["production object for staging", "staging", "production-lifecycle-dispatch-v1"], ["unknown environment", "preview", "production-lifecycle-dispatch-v1"],
    ["empty environment", "", "production-lifecycle-dispatch-v1"], ["case drift", "Production", "production-lifecycle-dispatch-v1"], ["empty object", "production", ""],
    ["suffix drift", "production", "production-lifecycle-dispatch-v2"],
  ];
  for (const [name, environment, guardObject] of attempts) assert.throws(() => exportGuardLedger(sqliteGuardLedgerSource(path), { environment, guardObject }), GuardExportRefusal, name);
  for (const [environment, guardObject] of [["staging", "staging-lifecycle-dispatch-v1"], ["lab", "lab-lifecycle-dispatch-v1"]] as const) {
    assert.equal(exportGuardLedger(sqliteGuardLedgerSource(path), { environment, guardObject }).target.environment, environment);
  }
});

test("ambiguous, incomplete or invariant-violating ledgers are refused rather than exported", () => {
  const a = "a".repeat(64), b = "b".repeat(64), c = "c".repeat(64);
  const claim = (digest: string, status = "SUCCESS", operation = "initialize") => ({ digest, operation, status });
  const settlement = (digest: string, sequence: number) => ({ digest, sequence, settledMs: 1 });
  const ok = { claims: [claim(a)], latch: null, settlements: [settlement(a, 1)] };
  assert.doesNotThrow(() => normalizeGuardLedgerRows("production", ok));
  const refusals: Array<[string, unknown]> = [
    ["not an object", null], ["extra top-level key", { ...ok, extra: 1 }], ["missing latch", { claims: [], settlements: [] }],
    ["bad digest", { ...ok, claims: [claim("A".repeat(64))] }], ["short digest", { ...ok, claims: [claim("a".repeat(63))] }],
    ["unknown status", { ...ok, claims: [claim(a, "DONE")] }], ["unknown operation", { ...ok, claims: [claim(a, "SUCCESS", "reset")] }],
    ["extra claim column", { ...ok, claims: [{ ...claim(a), note: "x" }] }], ["duplicate claim", { claims: [claim(a), claim(a)], latch: null, settlements: [settlement(a, 1)] }],
    ["settlement sequence gap", { claims: [claim(a), claim(b)], latch: null, settlements: [settlement(a, 1), settlement(b, 3)] }],
    ["settlement without claim", { claims: [claim(a)], latch: null, settlements: [settlement(a, 1), settlement(b, 2)] }],
    ["latch without claim", { claims: [claim(a)], latch: { digest: b }, settlements: [settlement(a, 1)] }],
    ["latch and settlement both", { claims: [claim(a)], latch: { digest: a }, settlements: [settlement(a, 1)] }],
    ["unsettled claim without latch", { claims: [claim(a)], latch: null, settlements: [] }],
    ["two unsettled claims", { claims: [claim(a), claim(b)], latch: { digest: a }, settlements: [] }],
    ["latch names a settled digest while another claim is unsettled", { claims: [claim(a), claim(b)], latch: { digest: b }, settlements: [settlement(b, 1)] }],
    ["negative time", { ...ok, settlements: [{ ...settlement(a, 1), settledMs: -1 }] }], ["non-integer sequence", { ...ok, settlements: [{ ...settlement(a, 1.5), sequence: 1.5 }] }],
    ["over capacity", { claims: Array.from({ length: 4097 }, (_, index) => claim(index.toString(16).padStart(64, "0"))), latch: null, settlements: [] }],
  ];
  for (const [name, rows] of refusals) assert.throws(() => normalizeGuardLedgerRows("production", rows), GuardExportRefusal, name);
  assert.throws(() => normalizeGuardLedgerRows("staging", { claims: [claim(a, "SUCCESS", "rotate-release")], latch: null, settlements: [settlement(a, 1)] }), GuardExportRefusal, "staging/lab guards never rotate");
  assert.doesNotThrow(() => normalizeGuardLedgerRows("production", { claims: [claim(a, "SUCCESS", "rotate-release"), claim(b, "CLAIMED")], latch: { digest: b }, settlements: [settlement(a, 1)] }));
  assert.doesNotThrow(() => normalizeGuardLedgerRows("production", { claims: [claim(c, "UNCONFIRMED")], latch: { digest: c }, settlements: [] }));
});

test("a source with unexpected schema, an unreadable path or a non-file is refused with a fixed code and no row content", async () => {
  const extra = join(directory, "extra-column.sqlite");
  const handle = new DatabaseSync(extra);
  handle.exec("CREATE TABLE claims(digest TEXT PRIMARY KEY, operation TEXT NOT NULL, status TEXT NOT NULL, secret TEXT)");
  handle.exec("CREATE TABLE latch(singleton INTEGER PRIMARY KEY, digest TEXT NOT NULL)");
  handle.exec("CREATE TABLE settlements(digest TEXT PRIMARY KEY, version INTEGER, status TEXT, sequence INTEGER, settled_ms INTEGER)");
  handle.exec(`INSERT INTO claims VALUES('${"a".repeat(64)}','initialize','SUCCESS','TOP-SECRET-VALUE')`);
  handle.close();
  for (const [path, code] of [[extra, "source-schema"], [join(directory, "missing.sqlite"), "source-unreadable"], [directory, "source-not-file"]] as const) {
    assert.throws(() => exportGuardLedger(sqliteGuardLedgerSource(path), PRODUCTION), (error: unknown) => {
      assert.ok(error instanceof GuardExportRefusal);
      assert.equal(error.code, code);
      assert.ok(!String(error.message + error.stack).includes("TOP-SECRET-VALUE"));
      return true;
    });
  }
  const garbage = join(directory, "garbage.sqlite");
  await writeFile(garbage, "this is not a database");
  assert.throws(() => exportGuardLedger(sqliteGuardLedgerSource(garbage), PRODUCTION), GuardExportRefusal);
  assert.throws(() => buildGuardLedgerExport({ environment: "production", guardObject: PRODUCTION.guardObject, provenance: "live" as never, rows: { claims: [], latch: null, settlements: [] } }), GuardExportRefusal);
});

test("the export contains only digests, operations, statuses and counters: no key, signature, artifact or envelope material", async () => {
  const { path, sealed } = await ledgerFile("secrets.sqlite", "stranded");
  const text = serializeGuardLedgerExport(exportGuardLedger(sqliteGuardLedgerSource(path), PRODUCTION));
  const signature = (JSON.parse(sealed) as { signature: string }).signature;
  assert.ok(!text.includes(signature) && !text.includes(privateKey) && !text.includes(publicKey) && !text.includes("deadbeef"));
  const keys = new Set<string>();
  (function collect(value: unknown): void {
    if (Array.isArray(value)) value.forEach(collect);
    else if (value && typeof value === "object") for (const [key, inner] of Object.entries(value)) { keys.add(key); collect(inner); }
  })(JSON.parse(text));
  assert.doesNotMatch([...keys].join(" "), /secret|private|signature|token|password|envelope|artifact/iu);
});

// ------------------------------------------------------------------------------------------------------------------------------------ CLI

test("CLI: export to stdout and verify round-trip; every misuse is refused with a fixed code, empty stdout and an unchanged source", async () => {
  const { path } = await ledgerFile("cli.sqlite", "stranded");
  const before = fileSha(path);
  const run = (args: string[]) => spawnSync(process.execPath, [tsx, join(root, "scripts", "guard-ledger-export.ts"), ...args], { cwd: directory, encoding: "utf8" });
  const exported = run(["export", "--environment", "production", "--guard-object", PRODUCTION.guardObject, "--sqlite", path]);
  assert.equal(exported.status, 0, exported.stderr);
  assert.equal(exported.stdout, serializeGuardLedgerExport(exportGuardLedger(sqliteGuardLedgerSource(path), PRODUCTION)));
  const out = join(directory, "cli-export.json");
  await writeFile(out, exported.stdout);
  const verified = run(["verify", "--environment", "production", "--guard-object", PRODUCTION.guardObject, "--file", out]);
  assert.equal(verified.status, 0, verified.stderr);
  assert.match(verified.stdout, /^VERIFIED [a-f0-9]{64}\n$/u);
  await writeFile(out, exported.stdout.replace("CLAIMED", "SUCCESS"));
  const forged = run(["verify", "--environment", "production", "--guard-object", PRODUCTION.guardObject, "--file", out]);
  assert.equal(forged.status, 2); assert.equal(forged.stdout, ""); assert.match(forged.stderr, /REFUSED \(export-mismatch\)/u);
  const misuse: string[][] = [
    [], ["export"], ["export", "--environment", "production", "--sqlite", path], ["export", "--environment", "production", "--guard-object", "wrong", "--sqlite", path],
    ["export", "--environment", "production", "--guard-object", PRODUCTION.guardObject, "--sqlite", path, "--out", "x"], ["delete"],
    ["export", "--environment", "production", "--environment", "production", "--guard-object", PRODUCTION.guardObject, "--sqlite", path],
  ];
  for (const args of misuse) {
    const result = run(args);
    assert.equal(result.status, 2, JSON.stringify(args));
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /Guard ledger export: REFUSED \([a-z-]+\)\. Nothing was changed\./u);
  }
  assert.equal(fileSha(path), before);
  assert.ok(!existsSync(join(directory, "x")));
});
