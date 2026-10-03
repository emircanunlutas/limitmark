/**
 * Adversarial self-test of the TEST_DATABASE_URL guard against a REAL disposable PostgreSQL.
 *
 * For every hostile configuration it runs the actual destructive integration suite in a child
 * process and requires (a) the process fails, (b) no test ran, and (c) a canary row planted in EACH of
 * the two lab databases (the proven one and an UNPROVEN one on a second cluster) is still there, i.e.
 * no TRUNCATE ever executed anywhere.
 *
 * Two cases are the reproduced Codex findings:
 *  - wrong endpoint: a URL that WHATWG URL reads as the proven cluster and postgres.js reads as the unproven one;
 *  - stale proof: a proof established on a guard-created client must refuse once the cluster stops being dedicated.
 *
 *   tsx --conditions=react-server lab/postgres/guard-selftest.ts 16|17
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import net from "node:net";
import path from "node:path";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";
import * as schema from "../../src/lib/db/schema";
import { PROOF_PURPOSE, PROOF_SCHEMA, PROOF_TABLE, TestDatabaseRefusal, disposableTestDatabase } from "../../tests/support/test-database-guard";
import { evidenceSafeError } from "../evidence/redact";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState } from "../evidence/manifest";
import { containerExists } from "../host/docker";
import { adminUrl, assertVersion, labDbDown, labDbUp, migratorUrl, readState, teardownOnCrash, type PgLabState, type PgVersion } from "./lab-db";

type Case = {
  name: string;
  environment: (state: PgLabState) => Record<string, string> | Promise<Record<string, string>>;
  /** Restores anything the case changed so the next case starts from the same state. */
  after?: () => Promise<void>;
};

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

const canaryInsert = (name: string, fill: string) => `INSERT INTO inquiries (name, email, service, system, objective, environment, authority, submission_token, payload_fingerprint)
  VALUES ('${name}', 'canary@example.test', 'web', 'canary', 'canary', 'staging', 'owner', '${fill.repeat(43)}', '${fill.repeat(64)}')`;

/** A loopback TCP relay whose target can be swapped; swapping also cuts every live relayed connection (the pool must reconnect). */
async function startRelay(initialPort: number): Promise<{ port: number; retarget(port: number): void; close(): void }> {
  let target = initialPort;
  const sockets = new Set<net.Socket>();
  const server = net.createServer((client) => {
    const upstream = net.connect(target, "127.0.0.1");
    sockets.add(client); sockets.add(upstream);
    client.pipe(upstream); upstream.pipe(client);
    const drop = () => { client.destroy(); upstream.destroy(); sockets.delete(client); sockets.delete(upstream); };
    client.on("error", drop); upstream.on("error", drop); client.on("close", drop); upstream.on("close", drop);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: (server.address() as net.AddressInfo).port,
    retarget(port) { target = port; for (const socket of sockets) socket.destroy(); sockets.clear(); },
    close() { for (const socket of sockets) socket.destroy(); server.close(); },
  };
}

type CaseResult = { case: string; refused: boolean; canaryIntact: boolean; unprovenCanaryIntact: boolean; ranTests: boolean };

async function main(): Promise<void> {
  const version: PgVersion = assertVersion(process.argv[2]);
  const otherVersion: PgVersion = version === "16" ? "17" : "16";
  teardownOnCrash([version, otherVersion]);
  const evidence = new EvidenceRun("guard-selftest", `guard-selftest-pg${version}`);
  const state = await labDbUp(version);
  const results: CaseResult[] = [];
  let failure: string | null = null;
  let discrepancyReproduced: boolean | null = null;
  let legacyMigrationPremise: boolean | null = null;
  // Codex F5: tearing one version down must not remove the other version's container or state file.
  let siblingSurvivedTeardown: boolean | null = null;
  const openClients: postgres.Sql[] = [];
  const client = (url: string) => { const sql = postgres(url, { max: 1, prepare: false, onnotice: () => undefined }); openClients.push(sql); return sql; };
  try {
    const otherState = await labDbUp(otherVersion);
    const owner = client(migratorUrl(state));
    const admin = client(adminUrl(state));
    const otherAdmin = client(adminUrl(otherState, otherState.database));

    // The UNPROVEN endpoint: a second cluster holding a database with the SAME name as the proven one, a canary, and no marker.
    await otherAdmin.unsafe(`CREATE DATABASE ${state.database} OWNER lab_migrator`);
    const unprovenAdmin = client(adminUrl(otherState, state.database));
    const unprovenOwner = client(`postgres://lab_migrator:${otherState.migratorPassword}@127.0.0.1:${otherState.port}/${state.database}`);

    // ---- Round 2 (migrations): the connection that proves the database must be the connection that migrates it, even when the POOL RECONNECTS to a different
    // server behind the same host:port. A loopback TCP relay stands in for "the server behind the endpoint was replaced": it relays to the proven cluster, then is
    // flipped to the unproven one and the live connections are cut, so the next connection the pool opens lands on the UNPROVEN database. (Mutating
    // client.options after creation does nothing: postgres.js copies its options into each connection, which is itself a binding.)
    const migrationFolder = path.join(REPOSITORY_ROOT, "drizzle");
    await otherAdmin.unsafe(`ALTER ROLE lab_migrator PASSWORD '${state.migratorPassword}'`);
    const relay = await startRelay(state.port);
    const relayedUrl = `postgres://lab_migrator:${state.migratorPassword}@127.0.0.1:${relay.port}/${state.database}`;
    let provenMigratedOk = false, reconnectRefused = false, unprovenTouchedByGuard = true, legacyMigratedUnproven = false;
    // Connections cut by the relay fail once (CONNECTION_CLOSED); "the pool reconnects" means issuing harmless queries until it has a live connection again.
    const reconnect = async (pool: postgres.Sql) => { for (let attempt = 0; attempt < 8; attempt++) { try { await pool`SELECT 1`; return; } catch { /* dead idle connection discarded; retry */ } } throw new Error("the pool did not reconnect"); };
    let reconnectCode: string = "none";
    const touchedProbe = async () => Boolean((await unprovenAdmin`SELECT (to_regclass('public.inquiries') IS NOT NULL OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'drizzle')) AS touched`)[0].touched);
    try {
      const gateM = disposableTestDatabase({ TEST_DATABASE_URL: relayedUrl, TEST_DATABASE_PROOF: state.proofToken });
      const pooled = gateM.connect({ max: 3 })!;
      try {
        // Positive control while the relay points at the proven cluster.
        await gateM.migrate(pooled, migrationFolder); provenMigratedOk = true;
        // The server behind the endpoint is replaced, and every pooled connection is dropped.
        relay.retarget(otherState.port);
        await reconnect(pooled);
        try { await gateM.migrate(pooled, migrationFolder); } catch (error) { reconnectRefused = error instanceof TestDatabaseRefusal; if (error instanceof TestDatabaseRefusal) reconnectCode = error.code; }
        unprovenTouchedByGuard = await touchedProbe();
        // The previous sequence, for the record: prove first (relay still on the proven side), then migrate through a separate acquisition after the swap.
        relay.retarget(state.port);
        await reconnect(pooled);
        await gateM.assertProven(pooled);
        relay.retarget(otherState.port);
        await reconnect(pooled);
        const legacyDrizzle = drizzle(pooled, { schema });
        await migrate(legacyDrizzle, { migrationsFolder: migrationFolder });
        legacyMigratedUnproven = await touchedProbe();
      } finally { await pooled.end({ timeout: 1 }).catch(() => undefined); }
    } finally {
      relay.close();
      await otherAdmin.unsafe(`ALTER ROLE lab_migrator PASSWORD '${otherState.migratorPassword}'`);
    }
    await migrate(drizzle(unprovenOwner, { schema }), { migrationsFolder: migrationFolder });
    await unprovenAdmin.unsafe(canaryInsert("canary-unproven", "d"));
    await owner.unsafe(canaryInsert("canary", "c"));
    const canary = async () => Number((await owner`SELECT count(*) FROM inquiries WHERE name = 'canary'`)[0].count);
    const unprovenCanary = async () => Number((await unprovenAdmin`SELECT count(*) FROM inquiries WHERE name = 'canary-unproven'`)[0].count);
    const good = migratorUrl(state);
    const url = (parts: Partial<{ host: string; db: string; query: string; user: string }> = {}) =>
      `postgres://${parts.user ?? "lab_migrator"}:${state.migratorPassword}@${parts.host ?? "127.0.0.1"}:${state.port}/${parts.db ?? state.database}${parts.query ?? ""}`;

    // ---- Codex F1 fixture: userinfo/host-list discrepancy. WHATWG URL: password `${shared}@127.0.0.1:<other>,b`, host 127.0.0.1:<proven>.
    // postgres.js: password `${shared}`, host list [<other>, <proven>] and it dials the FIRST. Credentials are arranged so a
    // legacy guard+suite would authenticate to both ends and TRUNCATE the unproven database.
    const shared = randomBytes(12).toString("hex");
    const splitUrl = `postgres://lab_migrator:${shared}@127.0.0.1:${otherState.port},b@127.0.0.1:${state.port}/${state.database}`;
    const setRolePasswords = async (provenPassword: string, unprovenPassword: string) => {
      await admin.unsafe(`ALTER ROLE lab_migrator PASSWORD '${provenPassword}'`);
      await otherAdmin.unsafe(`ALTER ROLE lab_migrator PASSWORD '${unprovenPassword}'`);
    };

    const cases: Case[] = [
      { name: "proof token missing", environment: () => ({ TEST_DATABASE_URL: good, TEST_DATABASE_PROOF: "" }) },
      { name: "proof token malformed", environment: () => ({ TEST_DATABASE_URL: good, TEST_DATABASE_PROOF: "not-a-token" }) },
      { name: "proof token wrong (well-formed, random)", environment: () => ({ TEST_DATABASE_URL: good, TEST_DATABASE_PROOF: randomBytes(32).toString("hex") }) },
      { name: "non-loopback host", environment: () => ({ TEST_DATABASE_URL: url({ host: "192.0.2.10" }), TEST_DATABASE_PROOF: state.proofToken }) },
      { name: "query-string host override", environment: () => ({ TEST_DATABASE_URL: url({ query: "?host=192.0.2.10" }), TEST_DATABASE_PROOF: state.proofToken }) },
      { name: "database name outside limitmark_lab_*", environment: () => ({ TEST_DATABASE_URL: url({ db: "postgres" }), TEST_DATABASE_PROOF: state.proofToken }) },
      { name: "role outside lab_*", environment: () => ({ TEST_DATABASE_URL: url({ user: "postgres" }), TEST_DATABASE_PROOF: state.proofToken }) },
      {
        // Codex F1: the guard proves the endpoint WHATWG URL sees; legacy postgres.js dials the other one. Both canaries must survive.
        name: "wrong endpoint: proven via one URL reading, dialled via another (host list + raw @ in userinfo)",
        environment: async () => {
          await setRolePasswords(`${shared}@127.0.0.1:${otherState.port},b`, shared);
          // Premise check: with the legacy "hand the URL string to postgres.js" behaviour this really lands on the unproven cluster.
          const legacy = postgres(splitUrl, { max: 1, prepare: false, connect_timeout: 5, onnotice: () => undefined });
          try {
            const [row] = await legacy<{ n: string }[]>`SELECT count(*)::text AS n FROM inquiries WHERE name = 'canary-unproven'`;
            discrepancyReproduced = Number(row.n) === 1;
          } catch { discrepancyReproduced = false; } finally { await legacy.end({ timeout: 1 }).catch(() => undefined); }
          return { TEST_DATABASE_URL: splitUrl, TEST_DATABASE_PROOF: state.proofToken };
        },
        after: () => setRolePasswords(state.migratorPassword, otherState.migratorPassword),
      },
      { name: "comma host list pointing at the unproven endpoint first", environment: () => ({ TEST_DATABASE_URL: `postgres://lab_migrator:${state.migratorPassword}@127.0.0.1:${otherState.port},127.0.0.1:${state.port}/${state.database}`, TEST_DATABASE_PROOF: state.proofToken }) },
      { name: "percent-escaped userinfo", environment: () => ({ TEST_DATABASE_URL: `postgres://lab_migrator:${state.migratorPassword.slice(0, 4)}%40${state.migratorPassword.slice(4)}@127.0.0.1:${state.port}/${state.database}`, TEST_DATABASE_PROOF: state.proofToken }) },
      { name: "IPv6 loopback spelling the driver would misparse", environment: () => ({ TEST_DATABASE_URL: `postgres://lab_migrator:${state.migratorPassword}@[0:0:0:0:0:0:0:1]:${state.port}/${state.database}`, TEST_DATABASE_PROOF: state.proofToken }) },
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
          const planted = postgres(`postgres://lab_admin:${state.adminPassword}@127.0.0.1:${state.port}/limitmark_lab_nomarker`, { max: 1, prepare: false });
          try {
            await planted.unsafe(`CREATE SCHEMA ${PROOF_SCHEMA}`);
            await planted.unsafe(`CREATE TABLE ${PROOF_SCHEMA}.${PROOF_TABLE} (id boolean PRIMARY KEY DEFAULT true CHECK (id), purpose text, nonce text, database_name text, system_identifier text, created_at timestamptz DEFAULT now())`);
            await planted.unsafe(`INSERT INTO ${PROOF_SCHEMA}.${PROOF_TABLE} (purpose, nonce, database_name, system_identifier) VALUES ('${PROOF_PURPOSE}', '${state.proofToken}', 'limitmark_lab_nomarker', '1')`);
            await planted.unsafe(`GRANT USAGE ON SCHEMA ${PROOF_SCHEMA} TO lab_migrator`);
            await planted.unsafe(`GRANT SELECT ON ${PROOF_SCHEMA}.${PROOF_TABLE} TO lab_migrator`);
          } finally { await planted.end({ timeout: 2 }); }
          return { TEST_DATABASE_URL: url({ db: "limitmark_lab_nomarker" }), TEST_DATABASE_PROOF: state.proofToken };
        },
      },
      {
        // Same cluster now hosts a second database, so even the genuinely proven database must refuse.
        name: "cluster is not dedicated (a second database exists)",
        environment: () => ({ TEST_DATABASE_URL: good, TEST_DATABASE_PROOF: state.proofToken }),
      },
    ];

    // ---- Codex F1 stale proof: runs BEFORE the cases that leave extra databases behind.
    {
      const name = "stale proof: the cluster stops being dedicated after the first proof";
      const gate = disposableTestDatabase({ TEST_DATABASE_URL: good, TEST_DATABASE_PROOF: state.proofToken });
      const guarded = gate.connect({ max: 2 })!;
      let refused = false, ranWork = false, provenFirst = false;
      try {
        await gate.destructive(guarded, async (tx) => { provenFirst = true; await tx`SELECT 1`; });
        await admin.unsafe("CREATE DATABASE limitmark_lab_stale");
        try {
          await gate.destructive(guarded, async (tx) => { ranWork = true; await tx`TRUNCATE TABLE notification_outbox, admin_notes, inquiry_events, inquiries`; });
        } catch (error) { refused = error instanceof TestDatabaseRefusal && error.code === "proof-cluster-not-dedicated"; }
        // The pooled client that already proved itself must also fail an explicit re-proof.
        refused &&= await gate.assertProven(guarded).then(() => false, (error) => error instanceof TestDatabaseRefusal);
      } finally {
        await admin.unsafe("DROP DATABASE IF EXISTS limitmark_lab_stale").catch(() => undefined);
        await guarded.end({ timeout: 2 });
      }
      const intact = (await canary()) === 1;
      const unprovenIntact = (await unprovenCanary()) === 1;
      const ok = refused && provenFirst && !ranWork;
      results.push({ case: name, refused: ok, canaryIntact: intact, unprovenCanaryIntact: unprovenIntact, ranTests: ranWork });
      console.log(`${ok && intact && unprovenIntact ? "REFUSED" : "!! NOT REFUSED"}  ${name}`);
    }

    {
      // The positive half, on the proven database through the guard: idempotent, one transaction, same bookkeeping as drizzle's migrator.
      const gateOk = disposableTestDatabase({ TEST_DATABASE_URL: good, TEST_DATABASE_PROOF: state.proofToken });
      const provenClient = gateOk.connect({ max: 4 })!;
      let migratedOk = false;
      try { await gateOk.migrate(provenClient, migrationFolder); migratedOk = true; } catch { migratedOk = false; }
      await provenClient.end({ timeout: 1 }).catch(() => undefined);
      const name = "migration bound to the proving connection: after the pool reconnects to a replaced (unproven) server the guarded migration refuses and leaves it untouched";
      const ok = reconnectRefused && !unprovenTouchedByGuard && provenMigratedOk && migratedOk;
      legacyMigrationPremise = legacyMigratedUnproven;
      results.push({ case: name, refused: ok, canaryIntact: (await canary()) === 1, unprovenCanaryIntact: (await unprovenCanary()) === 1, ranTests: false });
      console.log(`${ok ? "REFUSED" : "!! NOT REFUSED"}  ${name} (refused=${reconnectRefused} [${reconnectCode}], unproven touched by the guard=${unprovenTouchedByGuard}, proven migrate ok=${provenMigratedOk && migratedOk}, previous prove-then-migrate sequence migrated the unproven server=${legacyMigratedUnproven})`);
    }

    for (const testCase of cases) {
      const environment = await testCase.environment(state);
      let outcome: { exitCode: number; output: string };
      try { outcome = await runSuite(environment); } finally { await testCase.after?.(); }
      const ranTests = /✔ /.test(outcome.output);
      const intact = (await canary()) === 1;
      const unprovenIntact = (await unprovenCanary()) === 1;
      results.push({ case: testCase.name, refused: outcome.exitCode !== 0, canaryIntact: intact, unprovenCanaryIntact: unprovenIntact, ranTests });
      console.log(`${outcome.exitCode !== 0 && intact && unprovenIntact && !ranTests ? "REFUSED" : "!! NOT REFUSED"}  ${testCase.name}`);
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : error, (error as { cause?: Error })?.cause?.message ?? "");
    failure = evidenceSafeError(error);
  } finally {
    await Promise.all(openClients.map((sql) => sql.end({ timeout: 2 }).catch(() => undefined)));
    await labDbDown(version).catch((error) => { failure ??= `teardown: ${evidenceSafeError(error)}`; });
    siblingSurvivedTeardown = readState(otherVersion) !== null && await containerExists(`limitmark-lab-pg${otherVersion}`).catch(() => false);
    await labDbDown(otherVersion).catch((error) => { failure ??= `teardown: ${evidenceSafeError(error)}`; });
  }
  const EXPECTED_CASES = 16;
  const allRefused = results.length === EXPECTED_CASES && results.every((entry) => entry.refused && entry.canaryIntact && entry.unprovenCanaryIntact && !entry.ranTests) && siblingSurvivedTeardown === true;
  evidence.addJsonArtifact("guard-cases.json", { cases: results, legacyUrlParsingReachedUnprovenEndpoint: discrepancyReproduced, legacyMigrationSequenceReachedUnprovenServer: legacyMigrationPremise });
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(state.serverVersion), target: { id: `postgres-lab-${version}`, class: "lab-local" },
    workload: { id: "test-database-guard-selftest", phases: [] }, ceilings: null, thresholds: null, engine: "node-test",
    result: failure ? "ERROR" : allRefused ? "PASS" : "FAIL",
    resultReasons: failure ? [failure] : allRefused ? [] : [siblingSurvivedTeardown === true ? "at least one hostile configuration was not refused" : "tearing down one lab version removed (or lost the state of) the other"],
    metrics: {
      cases: results.length, expectedCases: EXPECTED_CASES, refused: results.filter((entry) => entry.refused).length,
      canaryIntact: results.filter((entry) => entry.canaryIntact).length, unprovenCanaryIntact: results.filter((entry) => entry.unprovenCanaryIntact).length,
      legacyParsingPremiseReproduced: discrepancyReproduced === true, siblingSurvivedTeardown: siblingSurvivedTeardown === true,
    },
  });
  console.log(`guard self-test: ${failure ? `ERROR ${failure}` : allRefused ? "PASS" : "FAIL"} (legacy URL parsing reached the unproven endpoint: ${String(discrepancyReproduced)}) evidence=${evidence.id}`);
  process.exit(!failure && allRefused ? 0 : 1);
}

if (require.main === module) {
  main().catch((error) => { console.error(error instanceof Error ? error.message : error); process.exit(1); });
}
