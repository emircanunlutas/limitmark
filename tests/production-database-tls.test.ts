import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import postgres from "postgres";
import { getDatabaseClientOptions } from "../src/lib/db/database.server";
import { getDatabaseRuntimeConfiguration } from "../src/lib/database-runtime-config";
import { getPublicSubmissionConfiguration } from "../src/lib/public-submission-config";
import { encodeBase64url, INGRESS_VERSION } from "../src/lib/ingress-protocol";

// CHARACTERIZATION of the production PostgreSQL transport-security posture as it is TODAY (investigation only; nothing here changes it).
// These tests pin facts a production decision depends on. When the posture is changed on purpose (separate decision), update them deliberately.

const url = (query = "") => `postgresql://app:synthetic@db.example.test:5432/limitmark${query}`;
const ssl = (query: string) => {
  const sql = postgres(url(query), getDatabaseClientOptions(5));
  try { return (sql.options as unknown as { ssl: unknown }).ssl; } finally { void sql.end({ timeout: 0 }); }
};

test("production client options carry no TLS setting; TLS exists only through the connection string or the lab-only tls argument", () => {
  assert.equal("ssl" in getDatabaseClientOptions(5), false);
  const lab = getDatabaseClientOptions(5, { ca: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----", servername: "db.example.test" });
  assert.equal((lab as { ssl: { rejectUnauthorized: boolean } }).ssl.rejectUnauthorized, true);
});

test("postgres.js 3.4.9 maps sslmode in DATABASE_URL: none -> plaintext, require/prefer/allow -> encrypted WITHOUT certificate verification, verify-* -> verified", async () => {
  assert.equal(ssl(""), false, "no sslmode: the connection is not encrypted");
  assert.equal(ssl("?sslmode=disable"), false, "sslmode=disable is accepted and behaves like no TLS");
  for (const mode of ["require", "prefer", "allow"]) assert.equal(ssl(`?sslmode=${mode}`), mode);
  for (const mode of ["verify-full", "verify-ca"]) assert.equal(ssl(`?sslmode=${mode}`), mode);
  assert.equal(ssl("?sslrootcert=system"), "verify-full");
  // The semantics live in the driver's connection code: only these three string modes switch certificate verification off.
  const connection = await readFile(new URL("../node_modules/postgres/src/connection.js", import.meta.url), "utf8");
  assert.match(connection, /if \(ssl === 'require' \|\| ssl === 'allow' \|\| ssl === 'prefer'\)\s*options\.rejectUnauthorized = false\s*else if \(typeof ssl === 'object'\)\s*Object\.assign\(options, ssl\)/u);
});

test("nothing in the production configuration path requires or validates TLS for DATABASE_URL", () => {
  for (const query of ["", "?sslmode=disable", "?sslmode=require", "?sslmode=verify-full"]) {
    assert.equal(getDatabaseRuntimeConfiguration({ DATABASE_URL: url(query) }).available, true, query || "(no query)");
  }
  const bytes = (fill: number) => encodeBase64url(new Uint8Array(32).fill(fill));
  const environment = {
    VERCEL: "1", VERCEL_ENV: "production", VERCEL_PROJECT_ID: "prj_x", VERCEL_DEPLOYMENT_ID: "dpl_x", REQUEST_SUBMISSION_MODE: "postgres", ENABLE_PERSISTENT_SUBMISSIONS: "true",
    RATE_LIMIT_PROVIDER: "cloudflare-do", PUBLIC_ORIGIN_PROTECTION: "required", PUBLIC_ORIGIN_SECRET: bytes(1), INGRESS_PROTOCOL: INGRESS_VERSION, INGRESS_AUDIENCE: "prj_x",
    INGRESS_PUBLIC_KEYS: JSON.stringify([{ role: "current", keyId: "k", publicKey: bytes(9), activatesAtMs: 0 }]), INGRESS_REQUEST_BINDING_KEY: bytes(2), SUBMISSION_TOKEN_SECRET: bytes(3),
    ADMISSION_SERVICE_URL: "https://admission.example.test", ADMISSION_OIDC_AUDIENCE: "https://admission.example.test", ADMISSION_RELEASE_ID: "dpl_x", ADMISSION_RELEASE_KEY_ID: "k",
    ADMISSION_RELEASE_RPC_KEY: bytes(4), TURNSTILE_MODE: "enabled", TURNSTILE_SITE_KEY: "0x4AAAAAAAsite-key-value", TURNSTILE_SECRET_KEY: "0x4AAAAAAAsecret-key-value", TURNSTILE_EXPECTED_HOSTNAME: "limitmark.com",
  };
  for (const query of ["", "?sslmode=disable", "?sslmode=require"]) {
    assert.equal(getPublicSubmissionConfiguration({ ...environment, DATABASE_URL: url(query) }, ["cloudflare-do"]).enabled, true, `${query || "(no query)"}: enabled despite a non-verifying transport`);
  }
});

test("the production runtime factory opens the database without the TLS argument (same as the Phase 5C path)", async () => {
  const factory = (await readFile(new URL("../src/lib/public-inquiry-production-runtime.server.ts", import.meta.url), "utf8")).replace(/\/\*[\s\S]*?\*\//gu, "");
  assert.match(factory, /getDatabase\(configuration\.databaseUrl, configuration\.poolMax\)/u);
  assert.doesNotMatch(factory, /DatabaseTlsConfiguration|DATABASE_CA|ca:/u);
});
