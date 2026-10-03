/**
 * Disposable PostgreSQL lab lifecycle: up | down | status | env.
 *
 *   tsx lab/postgres/lab-db.ts up 16
 *   tsx lab/postgres/lab-db.ts down 16
 *
 * `up` is deterministic: fresh tmpfs container, random per-run passwords and proof token,
 * roles, the disposable-database marker, drizzle migrations as the migration role, and
 * self-checks (role separation + the TEST_DATABASE_URL guard) before it reports ready.
 * Secrets exist only in this process, in the container environment, and in a 0600 state file
 * under the gitignored artifacts/lab/ tree.
 */
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";
import * as schema from "../../src/lib/db/schema";
import { PROOF_PURPOSE, PROOF_SCHEMA, PROOF_TABLE, verifyDisposableDatabase } from "../../tests/support/test-database-guard";
import { containerExists, docker } from "../host/docker";
import { REPOSITORY_ROOT } from "../evidence/manifest";
import { isPostgresJsNullSocketWrite, libraryFaults } from "./known-faults";

export type PgVersion = "16" | "17";
export const PG_PORTS: Record<PgVersion, number> = { "16": 55416, "17": 55417 };
const COMPOSE_FILE = path.join(REPOSITORY_ROOT, "lab", "postgres", "compose.yaml");
const STATE_DIRECTORY = path.join(REPOSITORY_ROOT, "artifacts", "lab", "pg");

export type PgLabState = {
  version: PgVersion;
  container: string;
  port: number;
  database: string;
  proofToken: string;
  adminPassword: string;
  migratorPassword: string;
  runtimePassword: string;
  startedAt: string;
  serverVersion: string;
};

export function assertVersion(value: string | undefined): PgVersion {
  if (value !== "16" && value !== "17") throw new Error("PostgreSQL version must be 16 or 17");
  return value;
}

const statePath = (version: PgVersion) => path.join(STATE_DIRECTORY, `pg${version}.json`);

export function readState(version: PgVersion): PgLabState | null {
  return existsSync(statePath(version)) ? (JSON.parse(readFileSync(statePath(version), "utf8")) as PgLabState) : null;
}

const url = (state: PgLabState, role: "lab_admin" | "lab_migrator" | "lab_runtime", password: string, database = state.database) =>
  `postgres://${role}:${password}@127.0.0.1:${state.port}/${database}`;
export const migratorUrl = (state: PgLabState) => url(state, "lab_migrator", state.migratorPassword);
export const runtimeUrl = (state: PgLabState) => url(state, "lab_runtime", state.runtimePassword);
export const adminUrl = (state: PgLabState, database = state.database) => url(state, "lab_admin", state.adminPassword, database);

const random = (bytes: number) => randomBytes(bytes).toString("hex");
const composeEnv = (password: string) => ({ LAB_PG_ADMIN_PASSWORD: password });

async function connectAdmin(state: PgLabState, attempts = 60): Promise<ReturnType<typeof postgres>> {
  // The image's init phase runs a socket-only temporary server; TCP only answers once the real one is up.
  for (let attempt = 0; attempt < attempts; attempt++) {
    const sql = postgres(adminUrl(state), { max: 1, connect_timeout: 3, prepare: false, onnotice: () => undefined });
    try { await sql`SELECT 1`; return sql; } catch { await sql.end({ timeout: 1 }).catch(() => undefined); await new Promise((r) => setTimeout(r, 500)); }
  }
  throw new Error("PostgreSQL did not accept TCP connections in time");
}

export async function labDbUp(version: PgVersion): Promise<PgLabState> {
  const service = `pg${version}`;
  const container = `limitmark-lab-${service}`;
  if (existsSync(statePath(version)) || await containerExists(container)) {
    throw new Error(`${container} already exists; run 'npm run lab:db:down -- ${version}' first`);
  }
  const state: PgLabState = {
    version, container, port: PG_PORTS[version], database: `limitmark_lab_${service}`,
    proofToken: random(32), adminPassword: random(24), migratorPassword: random(24), runtimePassword: random(24),
    startedAt: new Date().toISOString(), serverVersion: "unknown",
  };
  try {
    await docker(["compose", "-f", COMPOSE_FILE, "up", "-d", "--wait", "--wait-timeout", "90", service], { env: composeEnv(state.adminPassword), timeoutMs: 180_000 });
    const admin = await connectAdmin(state);
    try {
      state.serverVersion = (await admin`SHOW server_version`)[0].server_version as string;
      const db = state.database;
      // Roles: a DDL-owning migration role and a DML-only runtime role, mirroring DATABASE_MIGRATION_URL / DATABASE_URL.
      await admin.unsafe(`CREATE ROLE lab_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '${state.migratorPassword}'`);
      await admin.unsafe(`CREATE ROLE lab_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '${state.runtimePassword}'`);
      await admin.unsafe(`REVOKE ALL ON DATABASE ${db} FROM PUBLIC`);
      await admin.unsafe(`GRANT CONNECT, CREATE ON DATABASE ${db} TO lab_migrator`);
      await admin.unsafe(`GRANT CONNECT ON DATABASE ${db} TO lab_runtime`);
      await admin.unsafe(`REVOKE ALL ON SCHEMA public FROM PUBLIC`);
      await admin.unsafe(`GRANT USAGE, CREATE ON SCHEMA public TO lab_migrator`);
      await admin.unsafe(`GRANT USAGE ON SCHEMA public TO lab_runtime`);
      // The runtime never deletes or truncates (see src/): SELECT/INSERT/UPDATE only, applied to tables the migrator creates.
      await admin.unsafe(`ALTER DEFAULT PRIVILEGES FOR ROLE lab_migrator IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO lab_runtime`);
      // Positive disposable proof, created here and never by the tests.
      await admin.unsafe(`CREATE SCHEMA ${PROOF_SCHEMA} AUTHORIZATION lab_admin`);
      await admin.unsafe(`CREATE TABLE ${PROOF_SCHEMA}.${PROOF_TABLE} (
        id boolean PRIMARY KEY DEFAULT true CHECK (id),
        purpose text NOT NULL, nonce text NOT NULL, database_name text NOT NULL,
        system_identifier text NOT NULL, created_at timestamptz NOT NULL DEFAULT now())`);
      await admin`INSERT INTO ${admin(PROOF_SCHEMA)}.${admin(PROOF_TABLE)} (purpose, nonce, database_name, system_identifier)
        VALUES (${PROOF_PURPOSE}, ${state.proofToken}, current_database(), (SELECT system_identifier::text FROM pg_control_system()))`;
      await admin.unsafe(`GRANT USAGE ON SCHEMA ${PROOF_SCHEMA} TO lab_migrator`);
      await admin.unsafe(`GRANT SELECT ON ${PROOF_SCHEMA}.${PROOF_TABLE} TO lab_migrator`);
      // pg_control_system() is superuser-restricted by default; the guard connects as lab_migrator and needs it.
      await admin.unsafe(`GRANT EXECUTE ON FUNCTION pg_control_system() TO lab_migrator`);
    } finally { await admin.end({ timeout: 2 }); }

    const migrationClient = postgres(migratorUrl(state), { max: 1, prepare: false, onnotice: () => undefined });
    try { await migrate(drizzle(migrationClient, { schema }), { migrationsFolder: path.join(REPOSITORY_ROOT, "drizzle") }); }
    finally { await migrationClient.end({ timeout: 2 }); }

    await selfCheck(state);
    mkdirSync(STATE_DIRECTORY, { recursive: true });
    writeFileSync(statePath(version), `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    try { chmodSync(statePath(version), 0o600); } catch { /* best effort on Windows */ }
    return state;
  } catch (error) {
    await labDbDown(version).catch(() => undefined);
    throw error;
  }
}

/** Role separation and the TEST_DATABASE_URL guard must hold before the lab reports ready. */
async function selfCheck(state: PgLabState): Promise<void> {
  const runtime = postgres(runtimeUrl(state), { max: 1, prepare: false, onnotice: () => undefined });
  try {
    for (const statement of ["CREATE TABLE lab_runtime_must_not_ddl (id int)", "TRUNCATE TABLE inquiries CASCADE", "DELETE FROM inquiries"]) {
      let denied = false;
      try { await runtime.unsafe(statement); } catch (error) { denied = (error as { code?: string }).code === "42501"; }
      if (!denied) throw new Error(`role separation failed: runtime role was able to run "${statement}"`);
    }
    // Runtime can still do its real work.
    await runtime.begin(async (tx) => {
      await tx`SELECT count(*) FROM inquiries`;
      await tx`UPDATE inquiries SET notes = notes WHERE false`;
    });
  } finally { await runtime.end({ timeout: 2 }); }
  await verifyDisposableDatabase(migratorUrl(state), state.proofToken);
}

export async function labDbDown(version: PgVersion): Promise<void> {
  const service = `pg${version}`;
  // `down` only needs the variable to interpolate; no secret is required to remove containers.
  await docker(["compose", "-f", COMPOSE_FILE, "rm", "-f", "-s", "-v", service], { env: composeEnv("teardown-placeholder"), timeoutMs: 120_000 });
  await docker(["compose", "-f", COMPOSE_FILE, "down", "--remove-orphans", "--volumes"], { env: composeEnv("teardown-placeholder"), timeoutMs: 120_000 }).catch(() => undefined);
  rmSync(statePath(version), { force: true });
  if (await containerExists(`limitmark-lab-${service}`)) throw new Error("teardown incomplete: container still exists");
}

/** Any crash path (unhandled rejection, SIGINT) still removes the disposable container. */
export function teardownOnCrash(versions: readonly PgVersion[], options: { tolerateKnownPostgresJsFault?: boolean; /** Removes anything else the tool owns (for example parity containers); must verify ownership itself. */ extraCleanup?: () => Promise<void> } = {}): void {
  let running = false;
  const handler = (reason: unknown) => {
    if (options.tolerateKnownPostgresJsFault && isPostgresJsNullSocketWrite(reason)) { libraryFaults.postgresJsNullSocketWrite++; return; }
    if (running) return;
    running = true;
    console.error(reason instanceof Error ? reason.stack : reason);
    Promise.all([...versions.map((version) => labDbDown(version).catch(() => undefined)), options.extraCleanup?.().catch(() => undefined)]).finally(() => process.exit(1));
  };
  process.on("unhandledRejection", handler);
  process.on("uncaughtException", handler);
  process.on("SIGINT", handler);
  process.on("SIGTERM", handler);
}

export async function labDbStatus(version: PgVersion): Promise<{ running: boolean; healthy: boolean; version: string | null }> {
  const state = readState(version);
  if (!state || !(await containerExists(state.container))) return { running: false, healthy: false, version: null };
  try {
    const { stdout } = await docker(["inspect", "--format", "{{.State.Health.Status}}", state.container]);
    return { running: true, healthy: stdout.trim() === "healthy", version: state.serverVersion };
  } catch { return { running: true, healthy: false, version: state.serverVersion }; }
}

/** Environment for the guarded DB tests. Passwords stay in memory of the caller. */
export function testEnvironment(state: PgLabState): Record<string, string> {
  return { TEST_DATABASE_URL: migratorUrl(state), TEST_DATABASE_PROOF: state.proofToken };
}

async function main(): Promise<void> {
  const [command, versionArg] = process.argv.slice(2);
  const version = assertVersion(versionArg);
  if (command === "up") {
    const state = await labDbUp(version);
    console.log(`PostgreSQL ${state.serverVersion} lab ready: container=${state.container} port=127.0.0.1:${state.port} database=${state.database}`);
  } else if (command === "down") {
    await labDbDown(version);
    console.log(`PostgreSQL ${version} lab removed`);
  } else if (command === "status") {
    console.log(JSON.stringify(await labDbStatus(version)));
  } else {
    throw new Error("usage: lab-db.ts up|down|status 16|17");
  }
}

if (require.main === module) {
  main().catch((error) => { console.error(error instanceof Error ? error.message : error); process.exit(1); });
}
