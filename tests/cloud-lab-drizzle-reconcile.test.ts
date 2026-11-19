import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
// @ts-expect-error plain ESM script without type declarations
import { buildBaselineSql, readMigrations } from "../deployment/terraform/cloud-lab/drizzle-baseline.mjs";

const directory = "deployment/terraform/cloud-lab/";
const read = (path: string) => readFileSync(path, "utf8").replace(/\r\n/gu, "\n");
const journal = JSON.parse(read("drizzle/meta/_journal.json")) as { entries: Array<{ tag: string; when: number }> };
const baseline = buildBaselineSql("drizzle") as string;
const reconcile = read(`${directory}drizzle-reconcile.sh`);
const fingerprintSql = read(`${directory}drizzle-schema-fingerprint.sql`);
const expected = read(`${directory}drizzle-expected-schema.txt`);

test("baseline rows use drizzle-orm's exact format: sha256 of the file and the journal timestamp", () => {
  const migrations = readMigrations("drizzle") as Array<{ tag: string; when: number; hash: string }>;
  assert.equal(migrations.length, journal.entries.length);
  for (const [index, entry] of journal.entries.entries()) {
    const sql = read(`drizzle/${entry.tag}.sql`);
    assert.equal(migrations[index].hash, createHash("sha256").update(sql).digest("hex"));
    assert.equal(migrations[index].when, entry.when);
    assert.ok(baseline.includes(`('${migrations[index].hash}', ${entry.when})`));
  }
});

test("baseline only records history: guarded, transactional, idempotent and no application DDL or DML", () => {
  assert.match(baseline, /ON_ERROR_STOP on\nBEGIN;/u);
  assert.match(baseline, /COMMIT;\n$/u);
  assert.match(baseline, /CREATE SCHEMA IF NOT EXISTS drizzle;/u);
  assert.match(baseline, /CREATE TABLE IF NOT EXISTS drizzle\.__drizzle_migrations/u);
  assert.match(baseline, /WHERE NOT EXISTS \(SELECT 1 FROM drizzle\.__drizzle_migrations m WHERE m\.hash = v\.hash AND m\.created_at = v\.created_at\)/u);
  assert.match(baseline, /refusing to record history: application tables missing/u);
  assert.match(baseline, /do not match the migration journal/u);
  assert.equal(/\b(DROP|TRUNCATE|DELETE|UPDATE|ALTER)\b/u.test(baseline), false);
  assert.equal(/\bpublic\.\w+\s*\(/u.test(baseline), false);
  assert.equal(/\b(INSERT INTO|CREATE TABLE(?! IF NOT EXISTS))\s+(?!drizzle\.)/u.test(baseline), false);
});

test("reconcile proves the schema before recording anything and aborts on any difference", () => {
  assert.match(reconcile, /set -euo pipefail/u);
  const proof = reconcile.indexOf("diff -u");
  const record = reconcile.indexOf('-f "$baseline"');
  assert.ok(proof > 0 && record > proof, "schema proof must precede the baseline");
  assert.match(reconcile, /empty schema fingerprint/u);
  assert.match(reconcile, /exit 3/u);
  assert.equal(/PASSWORD|PGPASSWORD=/u.test(reconcile), false);
});

test("fingerprint query is read-only and the expected schema covers every migrated table and constraint", () => {
  assert.equal(/\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT)\b/u.test(fingerprintSql.replace(/^--.*$/gmu, "")), false);
  const tables = new Set(journal.entries.flatMap((entry) => [...read(`drizzle/${entry.tag}.sql`).matchAll(/CREATE TABLE "(\w+)"/gu)].map((m) => m[1])));
  assert.ok(tables.size >= 4);
  for (const table of tables) assert.ok(expected.includes(`relation r ${table}`), table);
  assert.ok((expected.match(/^constraint /gmu) ?? []).length >= 20);
  assert.ok(expected.includes("inquiries_environment_valid"));
  assert.equal(expected.endsWith("\n"), true);
});
