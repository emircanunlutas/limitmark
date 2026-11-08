import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createProductionRuntimeDependencies } from "../src/lib/public-inquiry-production-runtime.server";
import { assessProductionDatabaseTls, assessProductionTelemetry } from "../src/lib/production-launch-policy";
import { INGRESS_VERSION, encodeBase64url } from "../src/lib/ingress-protocol";

const root = fileURLToPath(new URL("..", import.meta.url));
const url = (query = "", host = "db.example.test") => `postgresql://app:synthetic@${host}:5432/limitmark${query}`;
const verdict = (databaseUrl: string, environments: Record<string, string | undefined>[] = [{}]) => assessProductionDatabaseTls(databaseUrl, environments);

test("production database TLS: only the driver's effective verify-full mode is accepted", () => {
  assert.deepEqual(verdict(url("?sslmode=verify-full")), { ok: true });
  assert.deepEqual(verdict(url("?sslrootcert=system")), { ok: true }, "sslrootcert=system makes the driver choose verify-full");
  assert.deepEqual(verdict(url("?sslmode=verify-full&sslrootcert=system")), { ok: true });
  for (const [query, refusal] of [
    ["", "database-tls-not-verified"], ["?sslmode=disable", "database-tls-not-verified"], ["?sslmode=require", "database-tls-not-verified"],
    ["?sslmode=prefer", "database-tls-not-verified"], ["?sslmode=allow", "database-tls-not-verified"], ["?sslmode=verify-ca", "database-tls-not-verified"],
    ["?ssl=true", "database-tls-not-verified"], ["?ssl=require", "database-tls-not-verified"], ["?sslmode=bogus", "database-tls-not-verified"],
    ["?sslmode=verify-full&sslrootcert=/etc/ssl/ca.pem", "database-tls-parameter"], ["?sslmode=verify-full&sslcert=/c.pem", "database-tls-parameter"],
    ["?sslmode=verify-full&sslkey=/k.pem", "database-tls-parameter"], ["?sslmode=verify-full&host=/var/run/postgresql", "database-socket"],
    ["?sslmode=verify-full&hostaddr=10.0.0.1", "database-socket"],
  ] as const) assert.deepEqual(verdict(url(query)), { ok: false, refusal }, query);
  // sslmode wins over a conflicting ssl parameter in the driver; the effective value is what is judged.
  assert.deepEqual(verdict(url("?ssl=verify-full&sslmode=require")), { ok: false, refusal: "database-tls-not-verified" });
  assert.deepEqual(verdict(url("?ssl=require&sslmode=verify-full")), { ok: true });
});

test("production database TLS: process-wide verification overrides, unix sockets and malformed URLs are refused", () => {
  assert.deepEqual(verdict(url("?sslmode=verify-full"), [{}, { NODE_TLS_REJECT_UNAUTHORIZED: "0" }]), { ok: false, refusal: "database-tls-environment" });
  assert.deepEqual(verdict(url("?sslmode=verify-full"), [{ NODE_TLS_REJECT_UNAUTHORIZED: "0" }]), { ok: false, refusal: "database-tls-environment" });
  assert.deepEqual(verdict(url("?sslmode=verify-full"), [{ NODE_TLS_REJECT_UNAUTHORIZED: "1" }]), { ok: true });
  assert.deepEqual(verdict("postgresql://app:x@%2Fvar%2Frun%2Fpostgresql/db?sslmode=verify-full"), { ok: false, refusal: "database-socket" });
  assert.deepEqual(verdict("not a url"), { ok: false, refusal: "database-url" });
  assert.deepEqual(verdict("mysql://app:x@db.example.test/db?sslmode=verify-full"), { ok: false, refusal: "database-url" });
  assert.deepEqual(verdict(""), { ok: false, refusal: "database-url" });
});

test("production database TLS: refusals never echo the connection string or credentials", () => {
  const result = JSON.stringify([verdict(url("")), verdict("postgresql://u:topsecret@h/db"), verdict("garbage-with-topsecret")]);
  assert.doesNotMatch(result, /topsecret|synthetic|db\.example/u);
});

test("production telemetry: OpenTelemetry metrics must be off; any enabling value or endpoint/service override refuses", () => {
  assert.deepEqual(assessProductionTelemetry({}), { ok: true });
  assert.deepEqual(assessProductionTelemetry({ PUBLIC_INQUIRY_OTEL_METRICS: "false" }), { ok: true });
  assert.deepEqual(assessProductionTelemetry({ PUBLIC_INQUIRY_OTEL_METRICS: "" }), { ok: true });
  for (const environment of [
    { PUBLIC_INQUIRY_OTEL_METRICS: "true" }, { PUBLIC_INQUIRY_OTEL_METRICS: "TRUE" }, { PUBLIC_INQUIRY_OTEL_METRICS: "1" }, { PUBLIC_INQUIRY_OTEL_METRICS: "yes" },
    { PUBLIC_INQUIRY_OTEL_METRICS_ENDPOINT: "https://collector.example.test" }, { PUBLIC_INQUIRY_OTEL_METRICS_SERVICE: "x" },
  ]) assert.deepEqual(assessProductionTelemetry(environment), { ok: false, refusal: "telemetry-enabled" }, JSON.stringify(environment));
});

const bytes = (fill: number) => encodeBase64url(new Uint8Array(32).fill(fill));
const productionEnvironment = (extra: Record<string, string> = {}, databaseUrl = url("?sslmode=verify-full")) => ({
  VERCEL: "1", VERCEL_ENV: "production", VERCEL_PROJECT_ID: "prj_x", VERCEL_DEPLOYMENT_ID: "dpl_x", REQUEST_SUBMISSION_MODE: "postgres", ENABLE_PERSISTENT_SUBMISSIONS: "true",
  RATE_LIMIT_PROVIDER: "cloudflare-do", PUBLIC_ORIGIN_PROTECTION: "required", PUBLIC_ORIGIN_SECRET: bytes(1), INGRESS_PROTOCOL: INGRESS_VERSION, INGRESS_AUDIENCE: "prj_x",
  INGRESS_PUBLIC_KEYS: JSON.stringify([{ role: "current", keyId: "k", publicKey: bytes(9), activatesAtMs: 0 }]), INGRESS_REQUEST_BINDING_KEY: bytes(2), SUBMISSION_TOKEN_SECRET: bytes(3),
  ADMISSION_SERVICE_URL: "https://admission.example.test", ADMISSION_OIDC_AUDIENCE: "https://admission.example.test", ADMISSION_RELEASE_ID: "dpl_x", ADMISSION_RELEASE_KEY_ID: "k",
  ADMISSION_RELEASE_RPC_KEY: bytes(4), TURNSTILE_MODE: "enabled", TURNSTILE_SITE_KEY: "0x4AAAAAAAsite-key-value", TURNSTILE_SECRET_KEY: "0x4AAAAAAAsecret-key-value", TURNSTILE_EXPECTED_HOSTNAME: "limitmark.com",
  DATABASE_URL: databaseUrl, ...extra,
});

test("the production factory refuses non-verifying database TLS and enabled telemetry before building anything, even with an injected provider", async () => {
  const providers = ["cloudflare-do"] as const;
  for (const query of ["", "?sslmode=require", "?sslmode=disable"]) {
    assert.deepEqual(await createProductionRuntimeDependencies(productionEnvironment({}, url(query)), { providers }), { enabled: false, reason: "database-tls" }, query || "(none)");
  }
  assert.deepEqual(await createProductionRuntimeDependencies(productionEnvironment({ PUBLIC_INQUIRY_OTEL_METRICS: "true" }), { providers }), { enabled: false, reason: "telemetry" });
  // With the shipped (empty) registry the launch gate still wins first; this policy adds nothing that could open it.
  assert.deepEqual(await createProductionRuntimeDependencies(productionEnvironment()), { enabled: false, reason: "configuration" });
});

// ---- real TLS behavior of the installed driver (local loopback server, locally generated throwaway CA; nothing leaves the machine) ----

type Pki = { ca: string; leaf: (san: string) => { key: string; cert: string } };
function openssl(directory: string): Pki | null {
  try {
    const run = (...args: string[]) => execFileSync("openssl", args, { cwd: directory, stdio: "pipe" });
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=Synthetic Test CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign");
    return {
      ca: join(directory, "ca.pem"),
      leaf(san) {
        run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", `${san}.key`, "-out", `${san}.csr`, "-subj", `/CN=${san}`);
        writeFileSync(join(directory, `${san}.cnf`), `subjectAltName=DNS:${san}
basicConstraints=CA:FALSE
`);
        run("x509", "-req", "-in", `${san}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", `${san}.pem`, "-days", "2", "-extfile", `${san}.cnf`);
        return { key: join(directory, `${san}.key`), cert: join(directory, `${san}.pem`) };
      },
    };
  } catch { return null; }
}

const childScript = `
import postgres from "postgres";
const sql = postgres(process.argv[1], { max: 1, connect_timeout: 3, idle_timeout: 1, fetch_types: false });
try { await sql\`select 1\`; console.log(JSON.stringify({ outcome: "connected" })); }
catch (error) { console.log(JSON.stringify({ outcome: "failed", code: String(error?.code ?? error?.errno ?? error?.name) })); }
await sql.end({ timeout: 0 }).catch(() => undefined);
process.exit(0);
`;

/** PostgreSQL ErrorResponse: 'E', int32 length (self-inclusive), severity FATAL, SQLSTATE 28000, a fixed message, terminator. */
const FATAL_ERROR_RESPONSE = (() => {
  const body = Buffer.from("SFATAL\0C28000\0Msynthetic test server rejects after the handshake\0\0", "latin1");
  const length = Buffer.alloc(4);
  length.writeInt32BE(body.length + 4);
  return Buffer.concat([Buffer.from("E", "latin1"), length, body]);
})();

async function withTlsServer<T>(files: { key: string; cert: string }, body: (port: number, handshakes: () => number) => Promise<T>): Promise<T> {
  let completed = 0;
  const server = net.createServer((socket) => {
    socket.once("data", (chunk) => {
      // PostgreSQL SSLRequest: length 8, code 80877103. Answer 'S', then terminate TLS with the throwaway certificate.
      if (chunk.length < 8 || chunk.readInt32BE(4) !== 80877103) { socket.destroy(); return; }
      socket.write("S");
      const secure = new tls.TLSSocket(socket, { isServer: true, key: readFileSync(files.key), cert: readFileSync(files.cert) });
      // After the handshake the fixture answers with a FATAL ErrorResponse and then closes. Closing without any protocol reply made postgres.js treat the
      // connection as never established and reconnect in a tight loop on Linux (hundreds of connections until the 20 s child timeout); a protocol-level rejection
      // ends the client's attempt deterministically on every platform. Certificate verification is unchanged: only handshakes that complete are counted.
      secure.on("secure", () => { completed += 1; secure.write(FATAL_ERROR_RESPONSE, () => secure.destroy()); });
      secure.on("error", () => undefined);
    });
    socket.on("error", () => undefined);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try { return await body((server.address() as net.AddressInfo).port, () => completed); }
  finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
}

function client(databaseUrl: string, extraEnvironment: Record<string, string> = {}): Promise<{ outcome: string; code?: string }> {
  // ASYNC on purpose: the TLS server lives in this process, so a synchronous child call would block it and every connection would just time out.
  return new Promise((resolve, reject) => {
    const { NODE_EXTRA_CA_CERTS: _drop, NODE_TLS_REJECT_UNAUTHORIZED: _drop2, ...base } = process.env;
    void _drop; void _drop2;
    execFile(process.execPath, ["--input-type=module", "-e", childScript, databaseUrl], { cwd: root, env: { ...base, ...extraEnvironment }, encoding: "utf8", timeout: 20_000 }, (error, stdout, stderr) => {
      if (error) { reject(new Error(`client failed: ${stderr.slice(0, 300)}`)); return; }
      resolve(JSON.parse(stdout.trim().split(/\r?\n/u).pop()!));
    });
  });
}

test("driver behavior (real handshake): verify-full rejects an untrusted CA and a wrong hostname, accepts a CA added by NODE_EXTRA_CA_CERTS; require does not verify", async (context) => {
  const directory = mkdtempSync(join(tmpdir(), "limitmark-tls-"));
  try {
    const pki = openssl(directory);
    if (!pki) { context.skip("openssl is not available"); return; }
    const target = (port: number, host: string, query: string) => `postgresql://app:synthetic@${host}:${port}/limitmark${query}`;
    await withTlsServer(pki.leaf("localhost"), async (port, handshakes) => {
      // 1. untrusted issuer: verify-full fails and the handshake never completes.
      let before = handshakes();
      assert.equal((await client(target(port, "localhost", "?sslmode=verify-full"))).outcome, "failed");
      assert.equal(handshakes(), before, "an untrusted issuer never completes the handshake");
      // 2. a custom CA is honored through the process trust store (NODE_EXTRA_CA_CERTS), for the matching DNS name.
      before = handshakes();
      await client(target(port, "localhost", "?sslmode=verify-full"), { NODE_EXTRA_CA_CERTS: pki.ca });
      assert.ok(handshakes() > before, "trusted CA + matching hostname: the TLS handshake completes");
      // 3. require encrypts but verifies nothing (the reason it is refused).
      before = handshakes();
      await client(target(port, "localhost", "?sslmode=require"));
      assert.ok(handshakes() > before, "sslmode=require completes a handshake with an untrusted certificate");
      // 4. a CA FILE named in the URL is not a CA setting of this driver: it does not make the driver trust it, and policy refuses the parameter.
      const rootFile = `?sslmode=verify-full&sslrootcert=${encodeURIComponent(pki.ca)}`;
      assert.deepEqual(verdict(target(port, "localhost", rootFile)), { ok: false, refusal: "database-tls-parameter" });
      before = handshakes();
      await client(target(port, "localhost", rootFile));
      assert.equal(handshakes(), before, "a CA file in the URL is not trusted by the driver");
      // 5. FINDING: for an IP-literal host postgres.js passes no servername, so Node verifies the certificate against "localhost", not the IP.
      before = handshakes();
      await client(target(port, "127.0.0.1", "?sslmode=verify-full"), { NODE_EXTRA_CA_CERTS: pki.ca });
      assert.ok(handshakes() > before, "an IP-literal host is NOT verified against the IP (accepted because the certificate names localhost)");
      assert.deepEqual(verdict(target(port, "127.0.0.1", "?sslmode=verify-full")), { ok: false, refusal: "database-host-literal" }, "policy therefore refuses IP-literal hosts");
    });
    // 6. hostname mismatch: the CA is trusted but the certificate does not name the host we dialed.
    await withTlsServer(pki.leaf("other.test"), async (port, handshakes) => {
      const before = handshakes();
      assert.equal((await client(target(port, "localhost", "?sslmode=verify-full"), { NODE_EXTRA_CA_CERTS: pki.ca })).outcome, "failed");
      assert.equal(handshakes(), before, "a trusted CA does not excuse a certificate that does not name the host");
      await client(target(port, "localhost", "?sslmode=require"));
      assert.ok(handshakes() > before, "sslmode=require ignores the same mismatch");
    });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("first production release: public-CA only -- the policy and the factory contain no private-CA, pinned-CA or TLS-object path", async () => {
  const { readFile } = await import("node:fs/promises");
  for (const file of ["src/lib/production-launch-policy.ts", "src/lib/public-inquiry-production-runtime.server.ts"]) {
    const source = (await readFile(new URL(`../${file}`, import.meta.url), "utf8")).replace(/\/\*[\s\S]*?\*\//gu, "").replace(/^\s*\/\/.*$/gmu, "");
    assert.doesNotMatch(source, /DatabaseTlsConfiguration|DATABASE_CA|rejectUnauthorized|\bca:|NODE_EXTRA_CA_CERTS|readFile|tls\.connect|checkServerIdentity/u, file);
  }
  // a custom CA in the URL, or a TLS object, can never satisfy the policy
  for (const query of ["?sslmode=verify-full&sslrootcert=/ca.pem", "?sslmode=verify-ca", "?sslmode=require&sslrootcert=system&ssl=false"]) {
    const verdictFor = verdict(url(query));
    if (query.includes("sslrootcert=system")) assert.deepEqual(verdictFor, { ok: true }, "system trust store override resolves to verify-full by the driver itself");
    else assert.equal(verdictFor.ok, false, query);
  }
});
