import { timingSafeEqual } from "node:crypto";
import { readMigrationFiles } from "drizzle-orm/migrator";
import postgres from "postgres";

/**
 * Fail-closed guard for every TEST_DATABASE_URL-gated test.
 *
 * Those tests run `TRUNCATE`, `CREATE TRIGGER` and migrations. A hostname or a
 * database name alone is only a naming convention, so the guard requires a
 * POSITIVE PROOF that the target is a disposable lab database:
 *
 *   1. static shape checks (loopback host, `limitmark_lab_*` database, `lab_*`
 *      role, no query string that could redirect the connection);
 *   2. a proof token in TEST_DATABASE_PROOF (64 hex chars, supplied only by the
 *      lab runner);
 *   3. a marker row inside the database itself, written by the lab bootstrap
 *      (never by the tests), whose nonce equals the token, whose database name
 *      equals current_database() and whose system identifier equals this
 *      cluster's pg_control_system() identifier -- so a copied/restored marker
 *      does not validate on another cluster;
 *   4. the cluster contains no other non-template database besides `postgres`.
 *
 * Any missing, malformed or unverifiable element refuses BEFORE any destructive
 * SQL. If TEST_DATABASE_URL is unset the DB tests keep skipping, as before.
 *
 * ONE CONNECTION REPRESENTATION. The URL string is parsed exactly once, here, under a canonical grammar that
 * has no ambiguous delimiter (no `@`, `,`, `:` or percent-escape inside userinfo, one literal loopback host).
 * No other component ever sees the string: `connect()` builds the postgres.js client from the parsed FIELDS,
 * so postgres.js never re-interprets a URL and cannot reach a different endpoint than the one proven.
 * Destructive statements run through `destructive()`, which re-reads and re-judges the proof INSIDE the
 * transaction, on the very connection that then executes the statement. Nothing is memoized: a proof that no
 * longer holds (for example a second database appeared in the cluster) refuses on the next destructive step.
 */

export const PROOF_PURPOSE = "limitmark-disposable-test-database-v1";
export const PROOF_SCHEMA = "limitmark_lab_proof";
export const PROOF_TABLE = "disposable_database_marker";
export const PROOF_TOKEN_ENV = "TEST_DATABASE_PROOF";
const DATABASE_NAME = /^limitmark_lab_[a-z0-9_]{1,40}$/;
const ROLE_NAME = /^lab_[a-z0-9_]{1,40}$/;
const TOKEN = /^[0-9a-f]{64}$/;

/**
 * The only accepted spelling of the URL. Userinfo is `[A-Za-z0-9._~-]` only: no `@`, `:`, `,`, `%`, `/`, `?`
 * or `#`, so WHATWG URL, postgres.js, libpq and psql cannot split it differently. The host is a dotted-quad
 * 127.x.y.z or the literal `[::1]`; the port is explicit; the database is a plain identifier.
 */
const CANONICAL_URL = /^postgres(?:ql)?:\/\/([A-Za-z0-9_]{1,41}):([A-Za-z0-9._~-]{1,200})@(127(?:\.(?:0|[1-9]\d{0,2})){3}|\[::1\]):([1-9]\d{0,4})\/([A-Za-z0-9_]{1,52})$/;

export type RefusalCode =
  | "url-malformed"
  | "url-scheme"
  | "url-host-not-loopback"
  | "url-query-forbidden"
  | "url-database-name"
  | "url-role-name"
  | "url-port"
  | "url-credentials-missing"
  | "url-noncanonical"
  | "client-not-guard-created"
  | "proof-token-missing"
  | "proof-token-malformed"
  | "proof-marker-missing"
  | "proof-marker-mismatch"
  | "proof-cluster-not-dedicated"
  | "proof-unverifiable";

export class TestDatabaseRefusal extends Error {
  constructor(readonly code: RefusalCode, detail: string) {
    // Never include the URL, password or token in the message.
    super(`TEST_DATABASE_URL refused (${code}): ${detail}`);
    this.name = "TestDatabaseRefusal";
  }
}

export type ParsedTestDatabaseUrl = {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
};

/**
 * Loopback IP LITERALS only. A name such as `localhost` is refused: it is resolved separately by each
 * connection and can map to a different address (for example ::1) than the one proven.
 */
function loopbackHost(hostname: string): string | null {
  const host = hostname.toLowerCase();
  if (host === "[::1]" || host === "::1") return "::1";
  const match = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  return match && match.slice(1).every((octet) => Number(octet) <= 255 && String(Number(octet)) === octet) ? host : null;
}

export function parseTestDatabaseUrl(value: string): ParsedTestDatabaseUrl {
  if (value.length > 512 || value !== value.trim()) throw new TestDatabaseRefusal("url-malformed", "unexpected length or whitespace");
  let url: URL;
  try { url = new URL(value); } catch { throw new TestDatabaseRefusal("url-malformed", "not a URL"); }
  if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") throw new TestDatabaseRefusal("url-scheme", "must be postgres: or postgresql:");
  // A query string can carry host=/port=/dbname= overrides in some drivers.
  if (url.search || url.hash) throw new TestDatabaseRefusal("url-query-forbidden", "query string and fragment are not allowed");
  if (url.hostname.includes(",") || !url.hostname) throw new TestDatabaseRefusal("url-host-not-loopback", "single loopback host required");
  const host = loopbackHost(url.hostname);
  if (!host) throw new TestDatabaseRefusal("url-host-not-loopback", "host must be loopback (the lab database is never reachable off-host)");
  const port = Number(url.port);
  if (!url.port || !Number.isInteger(port) || port < 1 || port > 65535) throw new TestDatabaseRefusal("url-port", "an explicit port is required");
  const decode = (part: string): string => {
    try { return decodeURIComponent(part); } catch { throw new TestDatabaseRefusal("url-malformed", "malformed percent-escape"); }
  };
  const database = decode(url.pathname.slice(1));
  if (!DATABASE_NAME.test(database)) throw new TestDatabaseRefusal("url-database-name", "database name must match limitmark_lab_*");
  const user = decode(url.username);
  if (!ROLE_NAME.test(user)) throw new TestDatabaseRefusal("url-role-name", "role must match lab_*");
  const password = decode(url.password);
  if (!password) throw new TestDatabaseRefusal("url-credentials-missing", "role password required");
  // Parser-differential defence. postgres.js splits userinfo at the FIRST `@` and honours a comma-separated host
  // list, WHATWG URL splits at the LAST `@`: `lab_x:a@127.0.0.1:P1,b@127.0.0.1:P2/db` is host P2 to this guard and
  // host P1 to postgres.js. The raw string must therefore also match ONE strict grammar, and the fields that
  // grammar yields must equal the fields parsed above. Anything else is refused, not "normalised".
  const raw = CANONICAL_URL.exec(value);
  if (!raw || raw[1] !== user || raw[2] !== password || raw[3] !== (host === "::1" ? "[::1]" : host) || Number(raw[4]) !== port || raw[5] !== database) {
    throw new TestDatabaseRefusal("url-noncanonical", "the URL must be scheme://role:password@loopback-literal:port/database with no escapes or extra delimiters");
  }
  return { host, port, database, user, password };
}

export function parseProofToken(token: string | undefined): string {
  if (token === undefined || token === "") throw new TestDatabaseRefusal("proof-token-missing", `${PROOF_TOKEN_ENV} is required`);
  if (!TOKEN.test(token)) throw new TestDatabaseRefusal("proof-token-malformed", `${PROOF_TOKEN_ENV} must be 64 lowercase hex characters`);
  return token;
}

/**
 * The postgres.js options for a parsed URL. This is the ONLY way the test tooling opens a connection to a
 * guarded database: explicit fields, never a URL string, so no second URL parser is involved.
 */
export function connectionOptions(parsed: ParsedTestDatabaseUrl, overrides: { max?: number } = {}): postgres.Options<Record<string, postgres.PostgresType>> {
  const max = overrides.max ?? 1;
  if (!Number.isSafeInteger(max) || max < 1 || max > 16) throw new TestDatabaseRefusal("url-malformed", "pool size must be 1..16");
  return {
    // Arrays bypass postgres.js's own `host.split(",")` / `split(":")` parsing, which turns "::1" into an empty host.
    host: [parsed.host] as unknown as string, // typings only declare string; the runtime accepts an array
    port: [parsed.port] as unknown as number,
    database: parsed.database,
    username: parsed.user,
    password: parsed.password,
    ssl: false,
    max,
    connect_timeout: 5,
    idle_timeout: 5,
    prepare: false,
    onnotice: () => undefined,
  };
}

export type ProofRows = {
  currentDatabase: string;
  markers: { purpose: string; nonce: string; databaseName: string; systemIdentifier: string }[];
  systemIdentifier: string;
  foreignDatabases: number;
  serverVersionNum: number;
};

export interface ProofProbe {
  read(): Promise<ProofRows>;
  close(): Promise<void>;
}

/** Reads the proof rows over `runner`, always a transaction, so it is bound to one connection. Never writes. */
export type ProofReader = (runner: postgres.TransactionSql) => Promise<ProofRows>;

function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/** Pure decision over rows read from the database. Exported for mutation tests. */
export function judgeProof(parsed: ParsedTestDatabaseUrl, token: string, rows: ProofRows): { serverVersionNum: number } {
  if (rows.currentDatabase !== parsed.database) throw new TestDatabaseRefusal("proof-marker-mismatch", "connected database differs from the URL");
  if (rows.markers.length !== 1) throw new TestDatabaseRefusal("proof-marker-missing", "exactly one disposable marker is required");
  const [marker] = rows.markers;
  if (marker.purpose !== PROOF_PURPOSE) throw new TestDatabaseRefusal("proof-marker-mismatch", "marker purpose differs");
  if (!constantTimeEqual(marker.nonce, token)) throw new TestDatabaseRefusal("proof-marker-mismatch", "proof token does not match the marker");
  if (marker.databaseName !== rows.currentDatabase) throw new TestDatabaseRefusal("proof-marker-mismatch", "marker was issued for a different database");
  if (marker.systemIdentifier !== rows.systemIdentifier) throw new TestDatabaseRefusal("proof-marker-mismatch", "marker was issued for a different cluster");
  if (rows.foreignDatabases !== 0) throw new TestDatabaseRefusal("proof-cluster-not-dedicated", "the cluster hosts other databases");
  return { serverVersionNum: rows.serverVersionNum };
}

/** The one proof query set. It runs on whatever connection the caller passes, so the proof binds to that connection. */
export const readProofRows: ProofReader = async (runner) => {
  const [current] = await runner<{ db: string; sysid: string; foreign: string; ver: string }[]>`
    SELECT current_database() AS db,
           (SELECT system_identifier::text FROM pg_control_system()) AS sysid,
           (SELECT count(*) FROM pg_database WHERE NOT datistemplate AND datname NOT IN ('postgres', current_database()))::text AS foreign,
           current_setting('server_version_num') AS ver`;
  let markers: ProofRows["markers"];
  try {
    // A savepoint keeps an "undefined table" error from aborting an enclosing transaction.
    markers = await runner.savepoint(async (inner) => {
      const rows = await inner.unsafe<{ purpose: string; nonce: string; database_name: string; system_identifier: string }[]>(
        `SELECT purpose, nonce, database_name, system_identifier FROM ${PROOF_SCHEMA}.${PROOF_TABLE}`,
      );
      return rows.map((row) => ({ purpose: row.purpose, nonce: row.nonce, databaseName: row.database_name, systemIdentifier: row.system_identifier }));
    }) as ProofRows["markers"];
  } catch (error) {
    // 42P01 undefined_table / 3F000 invalid_schema_name / 42501 insufficient_privilege: no readable marker at all.
    const code = (error as { code?: string }).code;
    if (code === "42P01" || code === "3F000" || code === "42501") markers = [];
    else throw error;
  }
  return {
    currentDatabase: current.db,
    markers,
    systemIdentifier: current.sysid,
    foreignDatabases: Number(current.foreign),
    serverVersionNum: Number(current.ver),
  };
};

function openPostgresProbe(parsed: ParsedTestDatabaseUrl): ProofProbe {
  const sql = postgres(connectionOptions(parsed));
  return {
    read: () => sql.begin("read only", (tx) => readProofRows(tx)),
    close: () => sql.end({ timeout: 2 }),
  };
}

export async function verifyDisposableDatabase(
  url: string,
  token: string | undefined,
  openProbe: (parsed: ParsedTestDatabaseUrl) => ProofProbe = openPostgresProbe,
): Promise<{ database: string; serverVersionNum: number }> {
  const parsed = parseTestDatabaseUrl(url);
  const proof = parseProofToken(token);
  const probe = openProbe(parsed);
  try {
    const rows = await probe.read();
    const { serverVersionNum } = judgeProof(parsed, proof, rows);
    return { database: parsed.database, serverVersionNum };
  } catch (error) {
    if (error instanceof TestDatabaseRefusal) throw error;
    throw new TestDatabaseRefusal("proof-unverifiable", "the database could not be queried for its marker");
  } finally {
    await probe.close().catch(() => undefined);
  }
}

export type DisposableTestDatabase = {
  /** False only when TEST_DATABASE_URL is unset (the gated tests skip). The URL string is deliberately not exposed. */
  enabled: boolean;
  /**
   * The ONLY way to obtain a client for the guarded database: built from the parsed fields, never from the URL
   * string. null when disabled.
   */
  connect(options?: { max?: number }): postgres.Sql | null;
  /**
   * Fresh proof, never memoized. With a guard-created `client` the proof is read over that client's own
   * connection; without one, over a short-lived dedicated connection.
   */
  assertProven(client?: postgres.Sql | null): Promise<void>;
  /**
   * Runs `work` in a transaction whose FIRST act is to re-read and re-judge the proof on that same transaction
   * connection. A destructive statement can only execute on a connection that has just proven itself.
   */
  destructive<T>(client: postgres.Sql | null, work: (tx: postgres.TransactionSql) => Promise<T>): Promise<T>;
  /**
   * Applies the drizzle migrations in `migrationsFolder` INSIDE the proving transaction: the exact connection that read and judged the proof is
   * the one that executes every migration statement (schema/table bookkeeping, the migration SQL, the history rows), in one transaction. There is
   * no proof transaction followed by a separately acquired migration connection, so pooling or reconnection cannot move migration SQL onto an
   * unproven connection. Equivalent to drizzle's migrator (same bookkeeping table, same hashes), so lab-created databases stay compatible.
   */
  migrate(client: postgres.Sql | null, migrationsFolder: string): Promise<void>;
};

const MIGRATIONS_SCHEMA = "drizzle";
const MIGRATIONS_TABLE = "__drizzle_migrations";

/** The migration SQL, run on ONE already-proven transaction. Exported so tests can drive it with a recording transaction. */
export async function applyMigrationsOn(tx: postgres.TransactionSql, migrationsFolder: string): Promise<void> {
  const migrations = readMigrationFiles({ migrationsFolder });
  const pid = async () => String((await tx.unsafe<{ pid: number }[]>("SELECT pg_backend_pid() AS pid"))[0].pid);
  // The session that proved itself is the session that migrates: asserted at the start and again before the bookkeeping is committed.
  const session = await pid();
  await tx.unsafe(`CREATE SCHEMA IF NOT EXISTS "${MIGRATIONS_SCHEMA}"`);
  await tx.unsafe(`CREATE TABLE IF NOT EXISTS "${MIGRATIONS_SCHEMA}"."${MIGRATIONS_TABLE}" (id SERIAL PRIMARY KEY, hash text NOT NULL, created_at bigint)`);
  const [last] = await tx.unsafe<{ created_at: string }[]>(`select id, hash, created_at from "${MIGRATIONS_SCHEMA}"."${MIGRATIONS_TABLE}" order by created_at desc limit 1`);
  for (const migration of migrations) {
    if (last && Number(last.created_at) >= migration.folderMillis) continue;
    for (const statement of migration.sql) await tx.unsafe(statement);
    await tx.unsafe(`insert into "${MIGRATIONS_SCHEMA}"."${MIGRATIONS_TABLE}" ("hash", "created_at") values($1, $2)`, [migration.hash, migration.folderMillis]);
  }
  if ((await pid()) !== session) throw new TestDatabaseRefusal("proof-marker-mismatch", "the migration ran on a different session than the one that proved the database");
}

type GuardDependencies = { openProbe?: (parsed: ParsedTestDatabaseUrl) => ProofProbe; readProof?: ProofReader };

/**
 * Called synchronously at module load of each DB test. A SET-but-malformed URL or
 * token throws immediately so the file cannot reach any SQL.
 */
export function disposableTestDatabase(
  environment: Record<string, string | undefined> = process.env,
  dependencies: GuardDependencies | ((parsed: ParsedTestDatabaseUrl) => ProofProbe) = {},
): DisposableTestDatabase {
  const { openProbe, readProof = readProofRows }: GuardDependencies = typeof dependencies === "function" ? { openProbe: dependencies } : dependencies;
  const url = environment.TEST_DATABASE_URL;
  if (url === undefined || url === "") {
    const disabled = async (): Promise<never> => { throw new TestDatabaseRefusal("client-not-guard-created", "no guarded database is configured"); };
    return { enabled: false, connect: () => null, assertProven: async () => undefined, destructive: disabled, migrate: disabled };
  }
  const parsed = parseTestDatabaseUrl(url);
  const token = parseProofToken(environment[PROOF_TOKEN_ENV]);
  const ownClients = new WeakSet<object>();

  const requireOwnClient = (client: postgres.Sql | null | undefined): postgres.Sql => {
    if (!client || !ownClients.has(client)) throw new TestDatabaseRefusal("client-not-guard-created", "destructive work needs the client created by this guard's connect()");
    return client;
  };
  const prove = async (runner: postgres.TransactionSql) => {
    let rows: ProofRows;
    try { rows = await readProof(runner); }
    catch (error) {
      if (error instanceof TestDatabaseRefusal) throw error;
      throw new TestDatabaseRefusal("proof-unverifiable", "the database could not be queried for its marker");
    }
    judgeProof(parsed, token, rows);
  };

  const destructive: DisposableTestDatabase["destructive"] = async (client, work) => {
    const own = requireOwnClient(client);
    let proven = false;
    try {
      return await own.begin(async (tx) => {
        await prove(tx);
        proven = true;
        return work(tx);
      }) as never;
    } catch (error) {
      // Whatever fails BEFORE the proof held (connecting, authenticating, reading the marker) is a refusal; the work's own errors propagate unchanged.
      if (!proven && !(error instanceof TestDatabaseRefusal)) throw new TestDatabaseRefusal("proof-unverifiable", "the database could not be queried for its marker");
      throw error;
    }
  };

  return {
    enabled: true,
    destructive,
    migrate: (client, migrationsFolder) => destructive(client, (tx) => applyMigrationsOn(tx, migrationsFolder)),
    connect(options = {}) {
      const client = postgres(connectionOptions(parsed, options));
      ownClients.add(client);
      return client;
    },
    async assertProven(client) {
      if (client !== undefined && client !== null) {
        const own = requireOwnClient(client);
        // A connection failure is "could not prove", never a raw driver error that a caller might treat as unrelated.
        await own.begin("read only", (tx) => prove(tx)).catch((error: unknown) => {
          if (error instanceof TestDatabaseRefusal) throw error;
          throw new TestDatabaseRefusal("proof-unverifiable", "the database could not be queried for its marker");
        });
        return;
      }
      await verifyDisposableDatabase(url, token, openProbe);
    },
  };
}
