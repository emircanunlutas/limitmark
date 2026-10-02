/**
 * Adversarial self-test of the TEST_DATABASE_URL guard against a REAL disposable PostgreSQL.
 *
 * For every hostile configuration it runs the actual destructive integration suite in a child
 * process and requires (a) the process fails and (b) a canary row planted in the lab database
 * is still there, i.e. no TRUNCATE ever executed.
 *
 *   tsx --conditions=react-server lab/postgres/guard-selftest.ts 16|17
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import path from "node:path";
import postgres from "postgres";
import { PROOF_PURPOSE, PROOF_SCHEMA, PROOF_TABLE } from "../../tests/support/test-database-guard";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState } from "../evidence/manifest";
import { assertVersion, labDbDown, labDbUp, migratorUrl, teardownOnCrash, type PgLabState, type PgVersion } from "./lab-db";

type Case = { name: string; environment: (state: PgLabState) => Record<string, string> | Promise<Record<string, string>> };

function runSuite(environment: Record<string, string>): Promise<{ exitCode: number; output: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      path.join(REPOSITORY_ROOT, "node_modules", "tsx", "dist", "cli.mjs"),
      "--conditions=react-server", "--test", "--test-reporter=spec", "tests/persistence.integration.test.ts",
    ], { cwd: REPOSITORY_ROOT, env: { ...process.env, ...environment }, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let output = "";
    child.stdout.on("data", (chunk) => { output += chunk; });
    child.stderr.on("data", (chunk) => { output += chunk; });
    child.on("error", reject);
    child.on("close", (code) => resolve({ exitCode: code ?? 1, output }));
  });
}

async function main(): Promise<void> {
  const version: PgVersion = assertVersion(process.argv[2]);
  teardownOnCrash([version]);
  const evidence = new EvidenceRun("guard-selftest", `guard-selftest-pg${version}`);
  const state = await labDbUp(version);
  const results: { case: string; refused: boolean; canaryIntact: boolean; ranTests: boolean }[] = [];
  let failure: string | null = null;
  try {
    const owner = postgres(migratorUrl(state), { max: 1, prepare: false });
    const admin = postgres(`postgres://lab_admin:${state.adminPassword}@127.0.0.1:${state.port}/${state.database}`, { max: 1, prepare: false });
    await owner`INSERT INTO inquiries (name, email, service, system, objective, environment, authority, submission_token, payload_fingerprint)
      VALUES ('canary', 'canary@example.test', 'web', 'canary', 'canary', 'staging', 'owner', ${"c".repeat(43)}, ${"c".repeat(64)})`;
    const canary = async () => Number((await owner`SELECT count(*) FROM inquiries WHERE name = 'canary'`)[0].count);
    const good = migratorUrl(state);
    const url = (parts: Partial<{ host: string; db: string; query: string; user: string }> = {}) =>
      `postgres://${parts.user ?? "lab_migrator"}:${state.migratorPassword}@${parts.host ?? "127.0.0.1"}:${state.port}/${parts.db ?? state.database}${parts.query ?? ""}`;

    const cases: Case[] = [
      { name: "proof token missing", environment: () => ({ TEST_DATABASE_URL: good, TEST_DATABASE_PROOF: "" }) },
      { name: "proof token malformed", environment: () => ({ TEST_DATABASE_URL: good, TEST_DATABASE_PROOF: "not-a-token" }) },
      { name: "proof token wrong (well-formed, random)", environment: () => ({ TEST_DATABASE_URL: good, TEST_DATABASE_PROOF: randomBytes(32).toString("hex") }) },
      { name: "non-loopback host", environment: () => ({ TEST_DATABASE_URL: url({ host: "192.0.2.10" }), TEST_DATABASE_PROOF: state.proofToken }) },
      { name: "query-string host override", environment: () => ({ TEST_DATABASE_URL: url({ query: "?host=192.0.2.10" }), TEST_DATABASE_PROOF: state.proofToken }) },
      { name: "database name outside limitmark_lab_*", environment: () => ({ TEST_DATABASE_URL: url({ db: "postgres" }), TEST_DATABASE_PROOF: state.proofToken }) },
      { name: "role outside lab_*", environment: () => ({ TEST_DATABASE_URL: url({ user: "postgres" }), TEST_DATABASE_PROOF: state.proofToken }) },
      {
        name: "database without a marker",
        environment: async () => {
          await admin.unsafe("CREATE DATABASE limitmark_lab_nomarker");
          await admin.unsafe("GRANT CONNECT ON DATABASE limitmark_lab_nomarker TO lab_migrator");
          return { TEST_DATABASE_URL: url({ db: "limitmark_lab_nomarker" }), TEST_DATABASE_PROOF: state.proofToken };
        },
      },
      {
        name: "marker issued for a different cluster (copied marker)",
        environment: async () => {
          // Plant a marker with the right nonce but a foreign system identifier in the second database.
          const other = postgres(`postgres://lab_admin:${state.adminPassword}@127.0.0.1:${state.port}/limitmark_lab_nomarker`, { max: 1, prepare: false });
          try {
            await other.unsafe(`CREATE SCHEMA ${PROOF_SCHEMA}`);
            await other.unsafe(`CREATE TABLE ${PROOF_SCHEMA}.${PROOF_TABLE} (id boolean PRIMARY KEY DEFAULT true CHECK (id), purpose text, nonce text, database_name text, system_identifier text, created_at timestamptz DEFAULT now())`);
            await other.unsafe(`INSERT INTO ${PROOF_SCHEMA}.${PROOF_TABLE} (purpose, nonce, database_name, system_identifier) VALUES ('${PROOF_PURPOSE}', '${state.proofToken}', 'limitmark_lab_nomarker', '1')`);
            await other.unsafe(`GRANT USAGE ON SCHEMA ${PROOF_SCHEMA} TO lab_migrator`);
            await other.unsafe(`GRANT SELECT ON ${PROOF_SCHEMA}.${PROOF_TABLE} TO lab_migrator`);
          } finally { await other.end({ timeout: 2 }); }
          return { TEST_DATABASE_URL: url({ db: "limitmark_lab_nomarker" }), TEST_DATABASE_PROOF: state.proofToken };
        },
      },
      {
        // Same cluster now hosts a second database, so even the genuinely proven database must refuse.
        name: "cluster is not dedicated (a second database exists)",
        environment: () => ({ TEST_DATABASE_URL: good, TEST_DATABASE_PROOF: state.proofToken }),
      },
    ];

    for (const testCase of cases) {
      const environment = await testCase.environment(state);
      const outcome = await runSuite(environment);
      const ranTests = /✔ /.test(outcome.output);
      const intact = (await canary()) === 1;
      results.push({ case: testCase.name, refused: outcome.exitCode !== 0, canaryIntact: intact, ranTests });
      console.log(`${outcome.exitCode !== 0 && intact && !ranTests ? "REFUSED" : "!! NOT REFUSED"}  ${testCase.name}`);
    }
    await owner.end({ timeout: 2 }); await admin.end({ timeout: 2 });
  } catch (error) {
    failure = error instanceof Error ? error.message.slice(0, 300) : "unknown error";
  } finally {
    await labDbDown(version).catch((error) => { failure ??= `teardown: ${(error as Error).message}`; });
  }
  const allRefused = results.length === 10 && results.every((entry) => entry.refused && entry.canaryIntact && !entry.ranTests);
  evidence.addJsonArtifact("guard-cases.json", { cases: results });
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(state.serverVersion), target: { id: `postgres-lab-${version}`, class: "lab-local" },
    workload: { id: "test-database-guard-selftest", phases: [] }, ceilings: null, thresholds: null, engine: "node-test",
    result: failure ? "ERROR" : allRefused ? "PASS" : "FAIL",
    resultReasons: failure ? [failure] : allRefused ? [] : ["at least one hostile configuration was not refused"],
    metrics: { cases: results.length, refused: results.filter((entry) => entry.refused).length, canaryIntact: results.filter((entry) => entry.canaryIntact).length },
  });
  console.log(`guard self-test: ${failure ? `ERROR ${failure}` : allRefused ? "PASS" : "FAIL"} evidence=${evidence.id}`);
  process.exit(!failure && allRefused ? 0 : 1);
}

if (require.main === module) {
  main().catch((error) => { console.error(error instanceof Error ? error.message : error); process.exit(1); });
}
