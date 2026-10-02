import { timingSafeEqual } from "node:crypto";
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
 */

export const PROOF_PURPOSE = "limitmark-disposable-test-database-v1";
export const PROOF_SCHEMA = "limitmark_lab_proof";
export const PROOF_TABLE = "disposable_database_marker";
export const PROOF_TOKEN_ENV = "TEST_DATABASE_PROOF";
const DATABASE_NAME = /^limitmark_lab_[a-z0-9_]{1,40}$/;
const ROLE_NAME = /^lab_[a-z0-9_]{1,40}$/;
const TOKEN = /^[0-9a-f]{64}$/;

export type RefusalCode =
  | "url-malformed"
  | "url-scheme"
  | "url-host-not-loopback"
  | "url-query-forbidden"
  | "url-database-name"
  | "url-role-name"
  | "url-port"
  | "url-credentials-missing"
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
 * Loopback IP LITERALS only. The proof probe connects to exactly this address and the suites connect with the
 * same URL string, so the proven endpoint is the used endpoint. A name such as `localhost` is refused: it is
 * resolved separately by each connection and can map to a different address (for example ::1) than the one proven.
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
  const database = decodeURIComponent(url.pathname.slice(1));
  if (!DATABASE_NAME.test(database)) throw new TestDatabaseRefusal("url-database-name", "database name must match limitmark_lab_*");
  const user = decodeURIComponent(url.username);
  if (!ROLE_NAME.test(user)) throw new TestDatabaseRefusal("url-role-name", "role must match lab_*");
  const password = decodeURIComponent(url.password);
  if (!password) throw new TestDatabaseRefusal("url-credentials-missing", "role password required");
  return { host, port, database, user, password };
}

export function parseProofToken(token: string | undefined): string {
  if (token === undefined || token === "") throw new TestDatabaseRefusal("proof-token-missing", `${PROOF_TOKEN_ENV} is required`);
  if (!TOKEN.test(token)) throw new TestDatabaseRefusal("proof-token-malformed", `${PROOF_TOKEN_ENV} must be 64 lowercase hex characters`);
  return token;
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

function openPostgresProbe(parsed: ParsedTestDatabaseUrl): ProofProbe {
  const sql = postgres({
    host: parsed.host,
    port: parsed.port,
    database: parsed.database,
    username: parsed.user,
    password: parsed.password,
    max: 1,
    connect_timeout: 5,
    idle_timeout: 5,
    prepare: false,
    onnotice: () => undefined,
  });
  return {
    async read() {
      return sql.begin("read only", async (tx) => {
        const [current] = await tx<{ db: string; sysid: string; foreign: string; ver: string }[]>`
          SELECT current_database() AS db,
                 (SELECT system_identifier::text FROM pg_control_system()) AS sysid,
                 (SELECT count(*) FROM pg_database WHERE NOT datistemplate AND datname NOT IN ('postgres', current_database()))::text AS foreign,
                 current_setting('server_version_num') AS ver`;
        let markers: ProofRows["markers"];
        try {
          const rows = await tx.unsafe<{ purpose: string; nonce: string; database_name: string; system_identifier: string }[]>(
            `SELECT purpose, nonce, database_name, system_identifier FROM ${PROOF_SCHEMA}.${PROOF_TABLE}`,
          );
          markers = rows.map((row) => ({ purpose: row.purpose, nonce: row.nonce, databaseName: row.database_name, systemIdentifier: row.system_identifier }));
        } catch (error) {
          // 42P01 undefined_table / 3F000 invalid_schema_name: no marker at all.
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
      });
    },
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
  /** null only when TEST_DATABASE_URL is unset (the gated tests skip). */
  url: string | null;
  /** Memoized. Rejects (and keeps rejecting) unless the positive proof holds. */
  assertProven(): Promise<void>;
};

/**
 * Called synchronously at module load of each DB test. A SET-but-malformed URL or
 * token throws immediately so the file cannot reach any SQL.
 */
export function disposableTestDatabase(
  environment: Record<string, string | undefined> = process.env,
  openProbe?: (parsed: ParsedTestDatabaseUrl) => ProofProbe,
): DisposableTestDatabase {
  const url = environment.TEST_DATABASE_URL;
  if (url === undefined || url === "") return { url: null, assertProven: async () => undefined };
  parseTestDatabaseUrl(url);
  const token = parseProofToken(environment[PROOF_TOKEN_ENV]);
  let verification: Promise<unknown> | undefined;
  return {
    url,
    assertProven() {
      verification ??= verifyDisposableDatabase(url, token, openProbe);
      return verification.then(() => undefined);
    },
  };
}
