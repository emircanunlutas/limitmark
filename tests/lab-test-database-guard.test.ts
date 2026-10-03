import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import postgres from "postgres";
import {
  PROOF_PURPOSE, TestDatabaseRefusal, connectionOptions, disposableTestDatabase, judgeProof, parseProofToken, parseTestDatabaseUrl, verifyDisposableDatabase,
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
    assert.equal(gate.enabled, false);
    assert.equal(gate.connect(), null);
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

test("assertProven is NEVER memoized: every call re-reads the proof, so a refusal and a later change are both seen", async () => {
  let reads = 0;
  let rows = goodRows({ markers: [] });
  const probe: ProofProbe = { async read() { reads++; return rows; }, async close() { /* noop */ } };
  const gate = disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL, TEST_DATABASE_PROOF: TOKEN }, () => probe);
  await assert.rejects(gate.assertProven(), refusal("proof-marker-missing"));
  await assert.rejects(gate.assertProven(), refusal("proof-marker-missing"));
  rows = goodRows();
  await gate.assertProven();
  // Regression (Codex F1): once proven, a later dedication change must refuse; the old memoized proof kept passing.
  rows = goodRows({ foreignDatabases: 1 });
  await assert.rejects(gate.assertProven(), refusal("proof-cluster-not-dedicated"));
  rows = goodRows();
  await gate.assertProven();
  assert.equal(reads, 5);
});

// -------------------------------------------------------------------- F1: one connection representation
/** The reproduced Codex URL: WHATWG URL host is :55586 (proven), postgres.js tries :55587 first. */
const SPLIT_HOST_URL = "postgres://lab_migrator:a@127.0.0.1:55587,b@127.0.0.1:55586/limitmark_lab_pg16";

test("F1 regression: URLs that WHATWG URL and postgres.js read differently are refused, never normalised", () => {
  const hostile = [
    SPLIT_HOST_URL,
    "postgres://lab_migrator:pw@127.0.0.1:55587@127.0.0.1:55586/limitmark_lab_pg16", // second raw @ in userinfo
    "postgres://lab_migrator:p@w@127.0.0.1:55586/limitmark_lab_pg16",
    "postgres://lab_migrator:pw,x@127.0.0.1:55586/limitmark_lab_pg16", // comma in userinfo
    "postgres://lab_migrator:p%40w@127.0.0.1:55586/limitmark_lab_pg16", // percent-escape in userinfo
    "postgres://lab_migrator:pw@127.0.0.1:55586/limitmark_lab_pg16%41", // escape in the database name
    "postgres://lab_migrator:pw@[0:0:0:0:0:0:0:1]:55586/limitmark_lab_pg16", // other IPv6 spelling (postgres.js reads host "[")
    "postgres://lab_migrator:pw@127.0.0.1:55586/limitmark_lab_pg16/", // trailing path
    "postgres://lab_migrator:pw@127.0.0.1:055586/limitmark_lab_pg16", // leading-zero port
    "postgres://lab_migrator:pw@127.0.0.1:55586//limitmark_lab_pg16",
    "postgres://lab_migrator:pw:extra@127.0.0.1:55586/limitmark_lab_pg16",
    "postgres://lab_migrator:pw@127.0.0.1:55586/limitmark_lab_pg16\n",
  ];
  for (const url of hostile) assert.throws(() => parseTestDatabaseUrl(url), (error) => error instanceof TestDatabaseRefusal, url);
  assert.throws(() => parseTestDatabaseUrl(SPLIT_HOST_URL), refusal("url-noncanonical"));
  assert.throws(() => parseTestDatabaseUrl("postgres://lab_migrator:p@w@127.0.0.1:55586/limitmark_lab_pg16"), refusal("url-noncanonical"));
  let opened = 0;
  assert.throws(() => disposableTestDatabase({ TEST_DATABASE_URL: SPLIT_HOST_URL, TEST_DATABASE_PROOF: TOKEN }, () => { opened++; return probeOf(goodRows()).probe; }), refusal("url-noncanonical"));
  assert.equal(opened, 0);
});

test("F1 regression: the guarded client is built from the parsed fields, so postgres.js cannot reinterpret a URL", async () => {
  const gate = disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL, TEST_DATABASE_PROOF: TOKEN }, () => probeOf(goodRows()).probe);
  const client = gate.connect({ max: 3 });
  assert.ok(client);
  try {
    const parsed = parseTestDatabaseUrl(GOOD_URL);
    // postgres.js exposes the options it resolved: exactly one host, the proven host and port, nothing from env or a URL.
    assert.deepEqual(client.options.host, [parsed.host]);
    assert.deepEqual(client.options.port, [parsed.port]);
    assert.equal(client.options.database, parsed.database);
    assert.equal(client.options.user, parsed.user);
    assert.equal(client.options.max, 3);
    assert.equal(client.options.ssl, false);
    // For a literal ::1 the host is passed verbatim (no bracket parsing).
    const v6 = postgres(connectionOptions(parseTestDatabaseUrl("postgres://lab_migrator:x@[::1]:5432/limitmark_lab_pg17")));
    assert.deepEqual(v6.options.host, ["::1"]);
    await v6.end({ timeout: 0.1 });
  } finally { await client.end({ timeout: 0.1 }); }
  assert.throws(() => gate.connect({ max: 0 }), refusal("url-malformed"));
  assert.throws(() => gate.connect({ max: 17 }), refusal("url-malformed"));
});

test("F1 regression: destructive work refuses a client the guard did not create", async () => {
  const gate = disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL, TEST_DATABASE_PROOF: TOKEN }, () => probeOf(goodRows()).probe);
  const foreign = postgres({ host: "127.0.0.1", port: 55587, database: "limitmark_lab_pg16", username: "lab_migrator", password: "x", max: 1 });
  let ran = false;
  try {
    await assert.rejects(gate.destructive(foreign, async () => { ran = true; }), refusal("client-not-guard-created"));
    await assert.rejects(gate.destructive(null, async () => { ran = true; }), refusal("client-not-guard-created"));
    await assert.rejects(gate.assertProven(foreign), refusal("client-not-guard-created"));
    assert.equal(ran, false);
  } finally { await foreign.end({ timeout: 0.1 }); }
  const disabled = disposableTestDatabase({});
  await assert.rejects(disabled.destructive(null, async () => { ran = true; }), refusal("client-not-guard-created"));
  assert.equal(ran, false);
});

/** A guard-created client whose transactions are a fake, so the proof/work order can be observed without a server. */
function guardWithFakeTransactions(readProof: (tx: unknown) => Promise<ProofRows>) {
  const gate = disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL, TEST_DATABASE_PROOF: TOKEN }, { readProof: readProof as never });
  const client = gate.connect()!;
  const transactions: object[] = [];
  (client as unknown as { begin: unknown }).begin = async (...args: unknown[]) => {
    const work = args[args.length - 1] as (tx: unknown) => Promise<unknown>;
    const tx = { id: transactions.length };
    transactions.push(tx);
    return work(tx);
  };
  return { gate, client, transactions };
}

test("F1 regression: destructive() proves on the SAME transaction connection that then runs the work, and every time", async () => {
  const order: string[] = [];
  let rows = goodRows();
  const { gate, client, transactions } = guardWithFakeTransactions(async (tx) => { order.push(`proof@${(tx as { id: number }).id}`); return rows; });
  try {
    await gate.destructive(client, async (tx) => { order.push(`work@${(tx as unknown as { id: number }).id}`); });
    await gate.destructive(client, async (tx) => { order.push(`work@${(tx as unknown as { id: number }).id}`); });
    assert.deepEqual(order, ["proof@0", "work@0", "proof@1", "work@1"]);
    assert.equal(transactions.length, 2);

    // Stale-proof regression: after the cluster stops being dedicated the very next destructive step refuses and runs nothing.
    rows = goodRows({ foreignDatabases: 1 });
    order.length = 0;
    await assert.rejects(gate.destructive(client, async () => { order.push("work"); }), refusal("proof-cluster-not-dedicated"));
    assert.deepEqual(order, ["proof@2"]);
    // Marker removed, marker for another cluster, wrong token: all refuse, none runs work.
    for (const mutated of [goodRows({ markers: [] }), goodRows({ markers: [{ ...goodRows().markers[0], systemIdentifier: "1" }] }), goodRows({ markers: [{ ...goodRows().markers[0], nonce: "b".repeat(64) }] })]) {
      rows = mutated;
      await assert.rejects(gate.destructive(client, async () => { order.push("work"); }), (error) => error instanceof TestDatabaseRefusal);
    }
    assert.ok(!order.includes("work"));
    // An unreadable proof is a refusal too (never "assume fine").
    const failing = guardWithFakeTransactions(async () => { throw new Error("connection lost password=s3cretpass"); });
    await assert.rejects(failing.gate.destructive(failing.client, async () => { order.push("work"); }), (error) => {
      assert.ok(error instanceof TestDatabaseRefusal);
      assert.equal(error.code, "proof-unverifiable");
      assert.doesNotMatch(error.message, /s3cretpass/);
      return true;
    });
    assert.ok(!order.includes("work"));
    await failing.client.end({ timeout: 0.1 });
  } finally { await client.end({ timeout: 0.1 }); }
});

// -------------------------------------------------------------------- the real suites are wired to the guard
const suites = ["persistence", "notification-outbox", "admin-inquiry-repository", "admin-inquiry-mutations"].map((name) => path.join(__dirname, `${name}.integration.test.ts`));

test("every TEST_DATABASE_URL-gated suite obtains its client only through the guard", () => {
  for (const file of suites) {
    const source = readFileSync(file, "utf8");
    assert.match(source, /disposableTestDatabase\(\)/, file);
    assert.doesNotMatch(source, /process\.env\.TEST_DATABASE_URL/, `${file} reads the raw environment variable`);
    assert.doesNotMatch(source, /process\.env\[/, file);
  }
});

test("F1: suites never open their own client or read the URL; destructive SQL runs through destructive(); migrations run inside the proving transaction (testDatabase.migrate)", () => {
  for (const file of suites) {
    const source = readFileSync(file, "utf8").replace(/^\s*\/\/.*$/gm, "");
    assert.doesNotMatch(source, /\bpostgres\(/, `${file} opens its own postgres.js client`);
    assert.doesNotMatch(source, /testDatabase\.url\b|databaseUrl/, `${file} reads the URL string`);
    assert.match(source, /testDatabase\.connect\(/, file);
    assert.doesNotMatch(source, /\bclient!?(?:`|\.unsafe\(|\.begin\()/, `${file}: a statement runs on the raw client`);
    for (const statement of source.matchAll(/(TRUNCATE|CREATE TRIGGER|DROP TRIGGER|DROP SCHEMA|CREATE SCHEMA)/g)) {
      const before = source.slice(Math.max(0, (statement.index ?? 0) - 220), statement.index);
      assert.match(before, /testDatabase\.destructive\(client,/, `${file}: ${statement[1]} is not inside destructive()`);
    }
    const hooks = [...source.matchAll(/\bbefore\(async \(\) => \{([\s\S]*?)\n\}\);/g)];
    assert.equal(hooks.length, 1, file);
    const body = hooks[0][1];
    assert.match(body, /await testDatabase\.migrate\(client, "drizzle"\)/, `${file}: migrations must go through testDatabase.migrate(client, ...)`);
    assert.doesNotMatch(source, /postgres-js\/migrator|\bmigrate\(database/, `${file}: drizzle migrator used directly (separate proof and migration connections)`);
    assert.doesNotMatch(source.replace(hooks[0][0], ""), /\bmigrate\(/, `${file}: migrate outside the guarded hook`);
  }
});

test("a marker that is internally consistent for a DIFFERENT database than the URL names is still refused", () => {
  const parsed = parseTestDatabaseUrl(GOOD_URL);
  const marker = { purpose: PROOF_PURPOSE, nonce: TOKEN, databaseName: "limitmark_lab_other", systemIdentifier: SYSID };
  assert.throws(() => judgeProof(parsed, TOKEN, goodRows({ currentDatabase: "limitmark_lab_other", markers: [marker] })), refusal("proof-marker-mismatch"));
});

test("F1 (fuzz finding): malformed percent-escapes are a refusal, never a raw URIError", () => {
  for (const url of [
    "postgres://lab_migrator:pw%zz@127.0.0.1:55416/limitmark_lab_pg16", "postgres://lab_migrator:pw%@127.0.0.1:55416/limitmark_lab_pg16", "postgres://lab%@127.0.0.1:55416/limitmark_lab_pg16",
    "postgres://lab_migrator:pw@127.0.0.1:55416/limitmark_lab_%a,b_pg17",
  ]) assert.throws(() => parseTestDatabaseUrl(url), (error) => error instanceof TestDatabaseRefusal, url);
});

test("F1 (property): every URL the guard accepts is canonical, i.e. identical for the guard, WHATWG URL and postgres.js", () => {
  let seed = 4242;
  const rand = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 2 ** 32; };
  const tokens = ["@", ",", ":", "/", "?", "#", "%40", "%2C", "[", "]", "\\", " ", "..", "0", "a", "127.0.0.1", "[::1]", "=", "&", "%"];
  const bases = [GOOD_URL, "postgresql://lab_runtime:pw@[::1]:5432/limitmark_lab_pg17", "postgres://lab_migrator:a@127.0.0.1:55587,b@127.0.0.1:55586/limitmark_lab_pg16"];
  let accepted = 0;
  for (let n = 0; n < 20_000; n++) {
    let url = bases[Math.floor(rand() * bases.length)];
    for (let step = 0; step < 1 + Math.floor(rand() * 3); step++) {
      const at = Math.floor(rand() * (url.length + 1));
      url = rand() < 0.5 ? url.slice(0, at) + tokens[Math.floor(rand() * tokens.length)] + url.slice(at) : url.slice(0, at) + url.slice(at + 1 + Math.floor(rand() * 3));
    }
    let parsed;
    try { parsed = parseTestDatabaseUrl(url); } catch (error) { assert.ok(error instanceof TestDatabaseRefusal, `raw exception for ${JSON.stringify(url)}`); continue; }
    accepted++;
    assert.equal(url.replace(/^postgresql:/, "postgres:"), `postgres://${parsed.user}:${parsed.password}@${parsed.host === "::1" ? "[::1]" : parsed.host}:${parsed.port}/${parsed.database}`);
    if (parsed.host !== "::1") {
      const sql = postgres(url, { max: 1 });
      assert.deepEqual([sql.options.host, sql.options.port, sql.options.database, sql.options.user, sql.options.pass], [[parsed.host], [parsed.port], parsed.database, parsed.user, parsed.password], url);
      void sql.end({ timeout: 0 });
    }
  }
  assert.ok(accepted > 10, "the property must actually see accepted URLs");
});

test("F1 (adversarial finding): a connection failure before the proof is a refusal; the work's own errors propagate unchanged", async () => {
  const gate = disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL, TEST_DATABASE_PROOF: TOKEN }, { readProof: (async () => goodRows()) as never });
  const client = gate.connect()!;
  try {
    (client as unknown as { begin: unknown }).begin = async () => { throw Object.assign(new Error("password authentication failed for user lab_migrator"), { code: "28P01" }); };
    await assert.rejects(gate.destructive(client, async () => undefined), (error) => error instanceof TestDatabaseRefusal && error.code === "proof-unverifiable" && !/password/.test(error.message));
    await assert.rejects(gate.assertProven(client), refusal("proof-unverifiable"));
    (client as unknown as { begin: unknown }).begin = async (...args: unknown[]) => (args[args.length - 1] as (tx: unknown) => Promise<unknown>)({});
    const boom = new Error("the suite's own failure");
    await assert.rejects(gate.destructive(client, async () => { throw boom; }), (error) => error === boom);
  } finally { await client.end({ timeout: 0.1 }); }
});

// -------------------------------------------------------------------- round 2: migrations are bound to the proving connection
import { applyMigrationsOn } from "./support/test-database-guard";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";

function tinyMigrations(): string {
  const folder = mkdtempSync(path.join(os.tmpdir(), "mig-"));
  mkdirSync(path.join(folder, "meta"));
  writeFileSync(path.join(folder, "0000_a.sql"), 'CREATE TABLE "a" (id int);--> statement-breakpoint\nCREATE TABLE "b" (id int);');
  writeFileSync(path.join(folder, "meta", "_journal.json"), JSON.stringify({ version: "7", dialect: "postgresql", entries: [{ idx: 0, version: "7", when: 1700000000000, tag: "0000_a", breakpoints: true }] }));
  return folder;
}

/** A transaction that records every statement with the id of the transaction (= connection) it ran on. */
function recordingTransactions(options: { pids?: string[] } = {}) {
  const log: { tx: number; sql: string }[] = [];
  const pids = [...(options.pids ?? [])];
  let next = 0;
  const makeTx = () => {
    const id = next++;
    return { id, unsafe: async (sql: string) => { log.push({ tx: id, sql }); if (/pg_backend_pid/.test(sql)) return [{ pid: pids.length ? pids.shift() : 4242 }]; return []; } };
  };
  return { log, makeTx, count: () => next };
}

test("F1 round 2 regression: EVERY migration statement runs on the transaction that proved the database (no separate migration connection)", async () => {
  const folder = tinyMigrations();
  const recorder = recordingTransactions();
  let proofOn = -1;
  const gate = disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL, TEST_DATABASE_PROOF: TOKEN }, { readProof: (async (tx: { id: number }) => { proofOn = tx.id; return goodRows(); }) as never });
  const client = gate.connect()!;
  try {
    (client as unknown as { begin: unknown }).begin = async (...args: unknown[]) => (args[args.length - 1] as (tx: unknown) => Promise<unknown>)(recorder.makeTx());
    await gate.migrate(client, folder);
    assert.equal(recorder.count(), 1, "exactly one transaction was opened for proof AND migration");
    assert.equal(proofOn, 0);
    assert.ok(recorder.log.length >= 6);
    assert.ok(recorder.log.every((entry) => entry.tx === proofOn), "a statement ran outside the proving transaction");
    const text = recorder.log.map((entry) => entry.sql).join("\n");
    assert.match(text, /CREATE TABLE "a"/);
    assert.match(text, /CREATE TABLE "b"/);
    assert.match(text, /insert into "drizzle"."__drizzle_migrations"/);
  } finally { await client.end({ timeout: 0.1 }); rmSync(folder, { recursive: true, force: true }); }
});

test("F1 round 2 regression: if the proof no longer holds (stale/other cluster) NO migration statement runs at all", async () => {
  const folder = tinyMigrations();
  const recorder = recordingTransactions();
  for (const rows of [goodRows({ foreignDatabases: 1 }), goodRows({ markers: [] }), goodRows({ markers: [{ ...goodRows().markers[0], systemIdentifier: "1" }] })]) {
    const gate = disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL, TEST_DATABASE_PROOF: TOKEN }, { readProof: (async () => rows) as never });
    const client = gate.connect()!;
    (client as unknown as { begin: unknown }).begin = async (...args: unknown[]) => (args[args.length - 1] as (tx: unknown) => Promise<unknown>)(recorder.makeTx());
    try { await assert.rejects(gate.migrate(client, folder), (error) => error instanceof TestDatabaseRefusal); } finally { await client.end({ timeout: 0.1 }); }
  }
  assert.equal(recorder.log.length, 0, "no statement of any kind was issued");
  rmSync(folder, { recursive: true, force: true });
});

test("F1 round 2 regression: pooling/reconnection cannot move migration SQL onto an unproven connection (a pool that hands out DIFFERENT connections per call, and a session that changes mid-migration)", async () => {
  const folder = tinyMigrations();
  // A pool/driver that gives a fresh connection to every acquisition: only the proving transaction may be used for migration SQL.
  const recorder = recordingTransactions();
  let proofTx = -1;
  const gate = disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL, TEST_DATABASE_PROOF: TOKEN }, { readProof: (async (tx: { id: number }) => { proofTx = tx.id; return goodRows(); }) as never });
  const client = gate.connect()!;
  const pooled = { unsafeCalls: 0 };
  (client as unknown as Record<string, unknown>).begin = async (...args: unknown[]) => (args[args.length - 1] as (tx: unknown) => Promise<unknown>)(recorder.makeTx());
  (client as unknown as Record<string, unknown>).unsafe = async () => { pooled.unsafeCalls++; return []; }; // the pool: any use of it would be a different connection
  try {
    await gate.migrate(client, folder);
    assert.equal(pooled.unsafeCalls, 0, "migration SQL was sent through the pool instead of the proving transaction");
    assert.ok(recorder.log.every((entry) => entry.tx === proofTx));
  } finally { await client.end({ timeout: 0.1 }); }
  // A reconnection in the middle (the backend pid changes between the first and last check) aborts the migration instead of committing it.
  const moving = recordingTransactions({ pids: ["100", "200"] });
  const gate2 = disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL, TEST_DATABASE_PROOF: TOKEN }, { readProof: (async () => goodRows()) as never });
  const client2 = gate2.connect()!;
  (client2 as unknown as Record<string, unknown>).begin = async (...args: unknown[]) => (args[args.length - 1] as (tx: unknown) => Promise<unknown>)(moving.makeTx());
  try { await assert.rejects(gate2.migrate(client2, folder), refusal("proof-marker-mismatch")); } finally { await client2.end({ timeout: 0.1 }); rmSync(folder, { recursive: true, force: true }); }
  void applyMigrationsOn;
});

test("F1 round 2: a client the guard did not create cannot migrate, and a disabled gate refuses", async () => {
  const gate = disposableTestDatabase({ TEST_DATABASE_URL: GOOD_URL, TEST_DATABASE_PROOF: TOKEN }, () => probeOf(goodRows()).probe);
  const foreign = postgres({ host: "127.0.0.1", port: 55587, database: "limitmark_lab_pg16", username: "lab_migrator", password: "x", max: 1 });
  try { await assert.rejects(gate.migrate(foreign, "drizzle"), refusal("client-not-guard-created")); } finally { await foreign.end({ timeout: 0.1 }); }
  await assert.rejects(disposableTestDatabase({}).migrate(null, "drizzle"), refusal("client-not-guard-created"));
});
