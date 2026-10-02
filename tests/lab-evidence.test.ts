import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import {
  EVIDENCE_ROOT, EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState, resolveEvidenceDirectory, sha256Hex, verifyEvidenceDirectory,
  type EvidenceManifest,
} from "../lab/evidence/manifest";
import { EvidenceViolation, assertEvidenceSafe } from "../lab/evidence/redact";

const refused = (error: unknown) => error instanceof EvidenceViolation;

test("evidence refuses every credential, header, cookie, identity and request-body carrier key", () => {
  const keys = [
    "authorization", "Authorization", "proxy-authorization", "cookie", "set-cookie", "Cookie", "password", "dbPassword", "secret", "clientSecret", "apiKey", "api_key", "x-api-key",
    "token", "accessToken", "submissionToken", "bearer", "credentials", "privateKey", "requestBody", "body", "payload", "formPayload", "x-forwarded-for", "forwarded",
    "clientIp", "remoteAddress", "ip", "address", "headers", "host", "hostname", "origin", "url", "connectionString", "databaseUrl", "email", "userEmail",
  ];
  for (const key of keys) assert.throws(() => assertEvidenceSafe({ metrics: { [key]: "x" } }), refused, key);
});

test("evidence refuses secrets and identities hiding in values", () => {
  const values = [
    "Bearer abcdefghijklmnop", "bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijk.signature", "Basic dXNlcjpwYXNzd29yZA==", "postgres://lab_migrator:hunter2@127.0.0.1:5432/db",
    "https://user:pw@example.test/", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk", "-----BEGIN PRIVATE KEY-----", "AKIAABCDEFGHIJKLMNOP", "re_abcdefghijklmnopqrstuvwx",
    "session=abcdef123456", "__Host-session=abcdef123456", "203.0.113.7", "client 198.51.100.4 failed", "10.0.0.1", "2001:db8::1", "fe80::1", "someone@example.test",
    "a".repeat(64), "A1b2".repeat(12), "x".repeat(600),
  ];
  for (const value of values) assert.throws(() => assertEvidenceSafe({ note: value }), refused, value.slice(0, 40));
  assert.throws(() => assertEvidenceSafe({ metrics: { list: ["fine", "203.0.113.7"] } }), refused);
  assert.throws(() => assertEvidenceSafe({ metrics: { nested: { deeper: { value: undefined } } } }), refused);
  assert.throws(() => assertEvidenceSafe({ metrics: { fn: () => 1 } }), refused);
});

test("evidence accepts the aggregates it is meant to carry", () => {
  assert.doesNotThrow(() => assertEvidenceSafe({
    schemaVersion: 1, runId: "20261002T203758Z-connectivity-baseline-056e00", result: "PASS", startedAt: "2026-10-02T20:37:58.040Z",
    git: { gitSha: "d7d6a7a35b3a47866f99257ae7c3eb5039defa81", dirty: false },
    thresholds: { id: "local-loopback-v1", version: 1, sha256: "8".repeat(64) },
    environment: { kernelRelease: "6.18.40.1-microsoft-standard-WSL2", nodeVersion: "v22.22.0", os: "Ubuntu 24.04.1 LTS" },
    metrics: { p95: 6.67, outcomes: { ok: 55, timeout: 2 }, path: "/test-talep-et" }, target: { id: "local-app", class: "lab-local", scheme: "http", port: 3000 },
  }));
});

test("environment versions that look like dotted quads are tolerated only inside `environment`", () => {
  assert.doesNotThrow(() => assertEvidenceSafe({ environment: { kernelRelease: "5.15.153.1-microsoft-standard-WSL2" } }));
  assert.throws(() => assertEvidenceSafe({ metrics: { kernelRelease: "5.15.153.1-microsoft-standard-WSL2" } }), refused);
  assert.throws(() => assertEvidenceSafe({ environment: { note: "Bearer abcdefghijklmnop" } }), refused);
  assert.throws(() => assertEvidenceSafe({ environment: { gitSha: "a".repeat(64) } }), refused);
});

test("the writer records the required fields, hashes every artifact and refuses unsafe content before touching disk", () => {
  const run = new EvidenceRun("unit-test", "evidence-test");
  try {
    assert.ok(run.directory.startsWith(path.join(REPOSITORY_ROOT, "artifacts", "lab")));
    assert.throws(() => run.addJsonArtifact("leak.json", { headers: { cookie: "a=b" } }), refused);
    assert.equal(existsSync(path.join(run.directory, "leak.json")), false, "a refused artifact must not reach disk");
    assert.throws(() => run.addJsonArtifact("../escape.json", {}), /plain \.json/);
    run.addJsonArtifact("phases.json", { phases: [{ name: "baseline", attempted: 3 }] });
    const manifest: EvidenceManifest = run.finalize({
      git: collectGitState(), environment: collectEnvironment("16.15"), target: { id: "local-app", class: "lab-local", scheme: "http", port: 3000 },
      workload: { id: "burst", phases: [{ name: "burst" }] }, ceilings: { hard: { maxConcurrency: 50 } },
      thresholds: { id: "local-loopback-v1", version: 1, sha256: "1".repeat(64) }, engine: "node-http", result: "PASS", resultReasons: [], metrics: { attempted: 3 },
    });
    for (const field of ["gitSha", "dirty"]) assert.ok(field in manifest.git);
    for (const field of ["os", "kernelRelease", "nodeVersion", "dockerVersion", "postgresVersion"]) assert.ok(field in manifest.environment, field);
    assert.equal(manifest.environment.postgresVersion, "16.15");
    assert.match(manifest.git.gitSha, /^[0-9a-f]{40}$/);
    assert.equal(manifest.target?.id, "local-app");
    assert.equal(manifest.thresholds?.id, "local-loopback-v1");
    assert.ok(manifest.startedAt <= manifest.endedAt);
    assert.equal(manifest.artifacts[0].sha256, sha256Hex(readFileSync(path.join(run.directory, "phases.json"))));
    assert.deepEqual(verifyEvidenceDirectory(run.directory), []);
    // Tampering is detected.
    writeFileSync(path.join(run.directory, "phases.json"), "{}\n");
    assert.deepEqual(verifyEvidenceDirectory(run.directory), ["phases.json"]);
    writeFileSync(path.join(run.directory, "manifest.json"), "{}\n");
    assert.deepEqual(verifyEvidenceDirectory(run.directory).sort(), ["manifest.json", "phases.json"]);
    assert.throws(() => run.finalize({} as never), /already finalized/);
  } finally { rmSync(run.directory, { recursive: true, force: true }); }
});

test("the manifest writer refuses a manifest that carries unsafe metrics", () => {
  const run = new EvidenceRun("unit-test", "evidence-refusal");
  try {
    assert.throws(() => run.finalize({
      git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: null, engine: "x",
      result: "ERROR", resultReasons: ["Bearer abcdefghijklmnop"], metrics: {},
    }), refused);
    assert.equal(existsSync(path.join(run.directory, "manifest.json")), false);
  } finally { rmSync(run.directory, { recursive: true, force: true }); }
});

test("evidence can only be written under the gitignored artifacts/lab tree", () => {
  for (const id of ["../../src", "..", "/etc", "a/b", "", "x", "run id with spaces", "C:\\temp"]) assert.throws(() => resolveEvidenceDirectory(id), /plain run id/, id);
  assert.throws(() => resolveEvidenceDirectory("20261002T203758Z-ok-run", path.join(REPOSITORY_ROOT, "src")), /plain run id/);
  assert.ok(resolveEvidenceDirectory("20261002T203758Z-ok-run").startsWith(EVIDENCE_ROOT));
  for (const probe of ["artifacts/lab/evidence/some-run/manifest.json", "artifacts/lab/pg/pg16.json", "artifacts/lab/targets.json", "artifacts/lab/k6/run/plan.json", "artifacts/lab/logs/x.log"]) {
    // `git check-ignore -q` exits 0 only when the path is ignored.
    assert.doesNotThrow(() => execFileSync("git", ["check-ignore", "-q", probe], { cwd: REPOSITORY_ROOT, stdio: "ignore" }), `${probe} must be gitignored`);
  }
});

test("credentials embedded in a URL are refused even without an IP address or e-mail shape", () => {
  for (const value of ["postgres://u:hunter2@db-host/app", "https://svc:pw12345@internal/x", "redis://default:abcdef@cache:6379"]) {
    assert.throws(() => assertEvidenceSafe({ note: value }), refused, value);
  }
});
