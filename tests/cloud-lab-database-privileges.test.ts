import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path: string) => readFileSync(path, "utf8").replace(/\r\n/gu, "\n");
const directory = "deployment/terraform/cloud-lab/";
const grantsSql = read(`${directory}postgres-runtime-grants.sql`);
const bootstrap = read(`${directory}postgres-bootstrap.sh`);
const repository = read("src/lib/inquiry-repository.ts");
const schema = read("src/lib/db/schema.ts");

/** Tables that exist in the schema but are intentionally unreachable from the public inquiry runtime. */
const noRuntimeAccess = new Set(["admin_notes"]);

const grantsCode = grantsSql.split("\n").filter((line) => !line.trim().startsWith("--")).join("\n");
const statements = grantsCode
  .split(";").map((statement) => statement.replace(/\s+/gu, " ").trim()).filter(Boolean);
const grants = statements.filter((statement) => /^GRANT /iu.test(statement));

function grantedPrivileges(table: string): string[] {
  return grants.flatMap((grant) => {
    const match = grant.match(/^GRANT (.+) ON public\.(\w+) TO :"app_role"$/iu);
    return match && match[2] === table ? [match[1].toUpperCase()] : [];
  });
}

const tableVariables = new Map([...schema.matchAll(/export const (\w+) = pgTable\("(\w+)"/gu)].map((m) => [m[1], m[2]] as const));

test("every schema table is either granted to the runtime or explicitly marked as having no runtime access", () => {
  assert.ok(tableVariables.size >= 4);
  for (const table of tableVariables.values()) {
    const granted = grantedPrivileges(table).length > 0;
    assert.equal(granted !== noRuntimeAccess.has(table), true, `${table} must be granted XOR listed in noRuntimeAccess`);
  }
  for (const table of noRuntimeAccess) assert.ok([...tableVariables.values()].includes(table), `${table} no longer exists`);
});

test("grants match exactly the operations PostgresInquiryRepository performs", () => {
  const inserted = new Set([...repository.matchAll(/\.insert\((\w+)\)/gu)].map((m) => tableVariables.get(m[1])!));
  const selected = new Set([...repository.matchAll(/\.from\((\w+)\)/gu)].map((m) => tableVariables.get(m[1])!));
  assert.deepEqual([...inserted].sort(), ["inquiries", "inquiry_events", "notification_outbox"]);
  assert.deepEqual([...selected], ["inquiries"]);
  assert.equal(/\.(update|delete)\(|\.execute\(|sql`/u.test(repository), false, "repository gained a verb that needs a new privilege review");

  for (const table of inserted) assert.ok(grantedPrivileges(table).includes("INSERT"), `${table} INSERT`);
  assert.deepEqual(grantedPrivileges("inquiry_events"), ["INSERT"]);
  assert.deepEqual(grantedPrivileges("notification_outbox"), ["INSERT"]);
  assert.deepEqual(grantedPrivileges("inquiries").sort(), ["INSERT", "SELECT (ID, SUBMISSION_TOKEN, PAYLOAD_FINGERPRINT)"]);
});

test("no broad, mutating, sequence, schema-creating or default-privilege grants exist", () => {
  for (const grant of grants) {
    assert.match(grant, /^GRANT (INSERT|SELECT \([a-z_, ]+\)) ON public\.\w+ TO :"app_role"$/iu, grant);
  }
  assert.equal(/\b(UPDATE|DELETE|TRUNCATE|REFERENCES|TRIGGER|ALL PRIVILEGES|USAGE|CREATE)\b/iu.test(grants.join(" ")), false);
  assert.equal(/ALTER DEFAULT PRIVILEGES[^;]*\bGRANT\b/iu.test(grantsCode), false);
  assert.equal(/\bON ALL (TABLES|SEQUENCES)\b[^;]*\bTO\b/iu.test(grantsCode), false);
  assert.equal(/\b(SUPERUSER|CREATEDB|CREATEROLE|OWNER TO)\b/iu.test(grantsCode), false);
  assert.match(grantsSql, /REVOKE ALL ON ALL TABLES IN SCHEMA public FROM :"app_role"/u);
  assert.match(grantsSql, /ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM :"app_role"/u);
  assert.equal(/gen_random_uuid|defaultRandom/u.test(schema) && !/serial|identity|generatedAlways/iu.test(schema), true, "a sequence-backed column needs a sequence privilege review");
});

test("bootstrap gives the runtime role only CONNECT and schema USAGE and never elevated role attributes", () => {
  const sql = bootstrap.slice(bootstrap.indexOf("<<'SQL'"), bootstrap.indexOf("\nSQL\n"));
  const appGrants = [...sql.matchAll(/^GRANT (.+?) TO "\$\{database_user\}";$/gmu)].map((m) => m[1]);
  assert.deepEqual(appGrants, ['CONNECT ON DATABASE "${database_name}"', 'USAGE ON SCHEMA public']);
  assert.equal(((sql.match(/NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION/gu)) ?? []).length, 2);
  assert.equal(/(?<!NO)(SUPERUSER|CREATEDB|CREATEROLE|REPLICATION|BYPASSRLS)/u.test(sql), false);
  assert.match(sql, /OWNER TO "\$\{migration_user\}"/u);
  assert.equal(/OWNER[^\n]*\$\{database_user\}/u.test(sql), false);
  assert.match(sql, /REVOKE ALL ON SCHEMA public FROM PUBLIC/u);
});
