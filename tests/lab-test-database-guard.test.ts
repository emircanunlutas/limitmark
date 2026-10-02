import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import {
  PROOF_PURPOSE, TestDatabaseRefusal, disposableTestDatabase, judgeProof, parseProofToken, parseTestDatabaseUrl, verifyDisposableDatabase,
  type ProofProbe, type ProofRows, type RefusalCode,
} from "./support/test-database-guard";

const TOKEN = "a".repeat(64);
const GOOD_URL = "postgres://lab_migrator:s3cretpass@127.0.0.1:55416/limitmark_lab_pg16";
const SYSID = "7123456789012345678";

function refusal(code: RefusalCode) {
  return (error: unknown) => error instanceof TestDatabaseRefusal && error.code === code;
}

const goodRows = (overrides: Partial<ProofRows> = {}): ProofRows => ({
  currentDatabase: "limitmark_lab_pg16",
  markers: [{ purpose: PROOF_PURPOSE, nonce: TOKEN, databaseName: "limitmark_lab_pg16", systemIdentifier: SYSID }],
  systemIdentifier: SYSID, foreignDatabases: 0, serverVersionNum: 160015, ...overrides,
});

function probeOf(rows: ProofRows | Error) {
  const calls: string[] = [];
  const probe: ProofProbe = {
    async read() { calls.push("read"); if (rows instanceof Error) throw rows; return rows; },
    async close() { calls.push("close"); },
  };
  return { probe, calls };
}

// -------------------------------------------------------------------- static shape
test("the URL guard accepts only a loopback limitmark_lab_* database with a lab_* role and an explicit port", () => {
  assert.deepEqual(parseTestDatabaseUrl(GOOD_URL), { host: "127.0.0.1", port: 55416, database: "limitmark_lab_pg16", user: "lab_migrator", password: "s3cretpass" });
  assert.equal(parseTestDatabaseUrl("postgresql://lab_runtime:x@127.0.0.1:5432/limitmark_lab_pg17").host, "127.0.0.1");
  assert.equal(parseTestDatabaseUrl("postgres://lab_migrator:x@[::1]:5432/limitmark_lab_pg17").host, "::1");
});

test("the URL guard refuses everything else, by a precise code", () => {
  const cases: [string, RefusalCode][] = [
    ["", "url-malformed"], ["not a url", "url-malformed"], [` ${GOOD_URL}`, "url-malformed"], [`${GOOD_URL} `, "url-malformed"], ["x".repeat(600), "url-malformed"],
    ["mysql://lab_migrator:x@127.0.0.1:3306/limitmark_lab_x", "url-scheme"], ["http://lab_migrator:x@127.0.0.1:5432/limitmark_lab_x", "url-scheme"],
    ["postgres://lab_migrator:x@db.example.com:5432/limitmark_lab_x", "url-host-not-loopback"],
    ["postgres://lab_migrator:x@10.0.0.5:5432/limitmark_lab_x", "url-host-not-loopback"],
    ["postgres://lab_migrator:x@0.0.0.0:5432/limitmark_lab_x", "url-host-not-loopback"],
    // Names are refused even when they usually resolve to loopback: the proven endpoint must be the used endpoint.
    ["postgres://lab_migrator:x@localhost:5432/limitmark_lab_x", "url-host-not-loopback"],
    ["postgres://lab_migrator:x@LOCALHOST:5432/limitmark_lab_x", "url-host-not-loopback"],
    ["postgres://lab_migrator:x@127.0.0.256:5432/limitmark_lab_x", "url-host-not-loopback"],
    ["postgres://lab_migrator:x@127.999.999.999:5432/limitmark_lab_x", "url-host-not-loopback"],
    ["postgres://lab_migrator:x@127.01.0.1:5432/limitmark_lab_x", "url-host-not-loopback"],
    ["postgres://lab_migrator:x@127.1:5432/limitmark_lab_x", "url-host-not-loopback"],
    ["postgres://lab_migrator:x@[::ffff:127.0.0.1]:5432/limitmark_lab_x", "url-host-not-loopback"],
    ["postgres://lab_migrator:x@127.0.0.1,db.example.com:5432/limitmark_lab_x", "url-host-not-loopback"],
    ["postgres://lab_migrator:x@127.0.0.1.evil.test:5432/limitmark_lab_x", "url-host-not-loopback"],
    ["postgres://lab_migrator:x@db.limitmark.com:5432/limitmark_lab_x", "url-host-not-loopback"],
    ["postgres://lab_migrator:x@127.0.0.1/limitmark_lab_x", "url-port"],
    ["postgres://lab_migrator:x@127.0.0.1:5432/limitmark_lab_x?host=db.example.com", "url-query-forbidden"],
    ["postgres://lab_migrator:x@127.0.0.1:5432/limitmark_lab_x?sslmode=disable", "url-query-forbidden"],
    ["postgres://lab_migrator:x@127.0.0.1:5432/limitmark_lab_x#frag", "url-query-forbidden"],
    ["postgres://lab_migrator:x@127.0.0.1:5432/postgres", "url-database-name"],
    ["postgres://lab_migrator:x@127.0.0.1:5432/production", "url-database-name"],
    ["postgres://lab_migrator:x@127.0.0.1:5432/limitmark", "url-database-name"],
    ["postgres://lab_migrator:x@127.0.0.1:5432/limitmark_lab_", "url-database-name"],
    ["postgres://lab_migrator:x@127.0.0.1:5432/LIMITMARK_LAB_X", "url-database-name"],
    ["postgres://lab_migrator:x@127.0.0.1:5432/limitmark_lab_x%3Bdrop", "url-database-name"],
    ["postgres://postgres:x@127.0.0.1:5432/limitmark_lab_x", "url-role-name"],
    ["postgres://app:x@127.0.0.1:5432/limitmark_lab_x", "url-role-name"],
    ["postgres://127.0.0.1:5432/limitmark_lab_x", "url-role-name"],
    ["postgres://lab_migrator@127.0.0.1:5432/limitmark_lab_x", "url-credentials-missing"],
  ];
  for (const [url, code] of cases) assert.throws(() => parseTestDatabaseUrl(url), refusal(code), `${url.slice(0, 80)} -> ${code}`);
});

test("refusal messages never contain the URL, password or proof token", () => {
  try { parseTestDatabaseUrl("postgres://lab_migrator:topsecretvalue@db.example.com:5432/limitmark_lab_x"); assert.fail("must throw"); }
  catch (error) { assert.doesNotMatch((error as Error).message, /topsecretvalue|db\.example\.com|lab_migrator/); }
  try { parseProofToken("zz"); assert.fail("must throw"); } catch (error) { assert.doesNotMatch((error as Error).message, /zz/); }
});

test("the proof token must be exactly 64 lowercase hex characters", () => {
  assert.equal(parseProofToken(TOKEN), TOKEN);
  assert.throws(() => parseProofToken(undefined), refusal("proof-token-missing"));
  assert.throws(() => parseProofToken(""), refusal("proof-token-missing"));
  for (const token of ["A".repeat(64), "a".repeat(63), "a".repeat(65), `${"a".repeat(63)}g`, ` ${TOKEN}`, `${TOKEN}\n`, "yes", "true", "1"]) {
    assert.throws(() => parseProofToken(token), refusal("proof-token-malformed"), token);
  }
});

// -------------------------------------------------------------------- positive proof (mutation style)
test("judgeProof accepts only a fully consistent marker", () => {
  const parsed = parseTestDatabaseUrl(GOOD_URL);
  assert.deepEqual(judgeProof(parsed, TOKEN, goodRows()), { serverVersionNum: 160015 });
});

test("every single mutation of the proof is refused", () => {
  const parsed = parseTestDatabaseUrl(GOOD_URL);
  const marker = goodRows().markers[0];
  const mutations: [string, ProofRows, RefusalCode][] = [
    ["connected to a different database than the URL names", goodRows({ currentDatabase: "limitmark_lab_other" }), "proof-marker-mismatch"],
    ["no marker row", goodRows({ markers: [] }), "proof-marker-missing"],
    ["two marker rows", goodRows({ markers: [marker, marker] }), "proof-marker-missing"],
    ["wrong purpose", goodRows({ markers: [{ ...marker, purpose: "something-else" }] }), "proof-marker-mismatch"],
    ["wrong nonce", goodRows({ markers: [{ ...marker, nonce: "b".repeat(64) }] }), "proof-marker-mismatch"],
    ["nonce differing in the last character", goodRows({ markers: [{ ...marker, nonce: `${"a".repeat(63)}b` }] }), "proof-marker-mismatch"],
    ["marker issued for another database", goodRows({ markers: [{ ...marker, databaseName: "limitmark_lab_pg17" }] }), "proof-marker-mismatch"],
    ["marker copied from another cluster", goodRows({ markers: [{ ...marker, systemIdentifier: "1" }] }), "proof-marker-mismatch"],
    ["a second database lives in the cluster", goodRows({ foreignDatabases: 1 }), "proof-cluster-not-dedicated"],
  ];
  for (const [name, rows, code] of mutations) assert.throws(() => judgeProof(parsed, TOKEN, rows), refusal(code), name);
  // A different environment token against a correct marker is refused too.
  assert.throws(() => judgeProof(parsed, "c".repeat(64), goodRows()), refusal("proof-marker-mismatch"));
});

test("verifyDisposableDatabase reads only, always closes, and turns every failure into a refusal", async () => {
  const good = probeOf(goodRows());
  assert.deepEqual(await verifyDisposableDatabase(GOOD_URL, TOKEN, () => good.probe), { database: "limitmark_lab_pg16", serverVersionNum: 160015 });
  assert.deepEqual(good.calls, ["read", "close"]);

  const unreachable = probeOf(Object.assign(new Error("ECONNREFUSED 127.0.0.1:55416 password=s3cretpass"), { code: "ECONNREFUSED" }));
  await assert.rejects(verifyDisposableDatabase(GOOD_URL, TOKEN, () => unreachable.probe), (error) => {
    assert.ok(error instanceof TestDatabaseRefusal);
    assert.equal(error.code, "proof-unverifiable");
    assert.doesNotMatch(error.message, /s3cretpass|55416/);
    return true;
  });
  assert.deepEqual(unreachable.calls, ["read", "close"]);

  let opened = 0;
  await assert.rejects(verifyDisposableDatabase(GOOD_URL, undefined, () => { opened++; return good.probe; }), refusal("proof-token-missing"));
  await assert.rejects(verifyDisposableDatabase("postgres://lab_migrator:x@db.example.com:5432/limitmark_lab_x", TOKEN, () => { opened++; return good.probe; }), refusal("url-host-not-loopback"));
  assert.equal(opened, 0, "static refusals must happen before any connection is opened");
});

// -------------------------------------------------------------------- the per-suite gate
test("an unset TEST_DATABASE_URL keeps the DB suites skipping (no proof demanded, no connection)", async () => {
  for (const environment of [{}, { TEST_DATABASE_URL: "" }, { TEST_DATABASE_PROOF: TOKEN }]) {
    let opened = 0;
    const gate = disposableTestDatabase(environment, () => { opened++; return probeOf(goodRows()).probe; });
    assert.equal(gate.url, null);
    await gate.assertProven();
    assert.equal(opened, 0);
  }
});

test("a set-but-unproven TEST_DATABASE_URL refuses synchronously at load, before any connection", () => {
  let opened = 0;
  const open = () => { opened++; return probeOf(goodRows()).probe; };
  assert.throws(() => disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL }, open), refusal("proof-token-missing"));
  assert.throws(() => disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL, TEST_DATABASE_PROOF: "nope" }, open), refusal("proof-token-malformed"));
  assert.throws(() => disposableTestDatabase({ TEST_DATABASE_URL: "postgres://u:p@prod.example.com:5432/app", TEST_DATABASE_PROOF: TOKEN }, open), refusal("url-host-not-loopback"));
  assert.throws(() => disposableTestDatabase({ TEST_DATABASE_URL: "postgres://lab_migrator:p@127.0.0.1:5432/app", TEST_DATABASE_PROOF: TOKEN }, open), refusal("url-database-name"));
  assert.equal(opened, 0);
});

test("assertProven is memoized and keeps refusing after the first refusal", async () => {
  let reads = 0;
  const rejecting: ProofProbe = { async read() { reads++; return goodRows({ markers: [] }); }, async close() { /* noop */ } };
  const gate = disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL, TEST_DATABASE_PROOF: TOKEN }, () => rejecting);
  await assert.rejects(gate.assertProven(), refusal("proof-marker-missing"));
  await assert.rejects(gate.assertProven(), refusal("proof-marker-missing"));
  await assert.rejects(gate.assertProven(), refusal("proof-marker-missing"));
  assert.equal(reads, 1);
  const ok = disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL, TEST_DATABASE_PROOF: TOKEN }, () => probeOf(goodRows()).probe);
  await ok.assertProven();
  await ok.assertProven();
});

// -------------------------------------------------------------------- the real suites are wired to the guard
const suites = ["persistence", "notification-outbox", "admin-inquiry-repository", "admin-inquiry-mutations"].map((name) => path.join(__dirname, `${name}.integration.test.ts`));

test("every TEST_DATABASE_URL-gated suite obtains its URL only through the guard", () => {
  for (const file of suites) {
    const source = readFileSync(file, "utf8");
    assert.match(source, /disposableTestDatabase\(\)/, file);
    assert.doesNotMatch(source, /process\.env\.TEST_DATABASE_URL/, `${file} reads the raw environment variable`);
    assert.doesNotMatch(source, /process\.env\[/, file);
  }
});

test("every migration and TRUNCATE in the gated suites is preceded by assertProven in the same hook", () => {
  for (const file of suites) {
    const source = readFileSync(file, "utf8");
    const hooks = [...source.matchAll(/\b(before|beforeEach)\(async \(\) => \{([\s\S]*?)\n\}\);/g)];
    assert.ok(hooks.length >= 2, `${file}: expected before and beforeEach hooks`);
    let destructive = 0;
    for (const [, name, body] of hooks) {
      const proofAt = body.indexOf("assertProven()");
      for (const pattern of [/TRUNCATE/, /migrate\(/]) {
        const at = body.search(pattern);
        if (at < 0) continue;
        destructive++;
        assert.ok(proofAt >= 0 && proofAt < at, `${file}: ${name} runs ${pattern} before assertProven()`);
      }
    }
    assert.ok(destructive >= 2, `${file}: expected destructive statements inside hooks`);
    // No TRUNCATE or migrate outside those guarded hooks.
    const outside = source.replace(/\b(before|beforeEach)\(async \(\) => \{[\s\S]*?\n\}\);/g, "").replace(/^\s*\/\/.*$/gm, "");
    assert.doesNotMatch(outside, /TRUNCATE|migrate\(database/, `${file}: destructive statement outside a guarded hook`);
  }
});

test("a marker that is internally consistent for a DIFFERENT database than the URL names is still refused", () => {
  const parsed = parseTestDatabaseUrl(GOOD_URL);
  const marker = { purpose: PROOF_PURPOSE, nonce: TOKEN, databaseName: "limitmark_lab_other", systemIdentifier: SYSID };
  assert.throws(() => judgeProof(parsed, TOKEN, goodRows({ currentDatabase: "limitmark_lab_other", markers: [marker] })), refusal("proof-marker-mismatch"));
});
