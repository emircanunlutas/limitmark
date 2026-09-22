import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createGate6VerifyHarness } from "./workers/support/gate6-verify-harness";

// Gate 6A / F5-F7, F9, F12(G,J,K,M): CLI-level proof of the IAM verification
// harness's role separation, closed operation allowlist, ALLOW/DENY
// classification, single-call-per-invocation (no hidden retry -- relevant to
// the revocation procedure in F9), and that preflight mode never contacts a
// provider transport at all. The synthetic operator/r2-transport substituted
// by the harness never opens a socket; it answers from a per-invocation
// allow-list and traces every (method, bucket, key) it was asked to sign.

let harness: Awaited<ReturnType<typeof createGate6VerifyHarness>>;
before(async () => { harness = await createGate6VerifyHarness(); });
after(() => harness.dispose());
const REQUEST_BUCKET = "limitmark-lifecycle-requests-staging";
const RESULT_BUCKET = "limitmark-lifecycle-results-staging";
const PRODUCTION_REQUEST_BUCKET = "limitmark-lifecycle-requests-production";
const PRODUCTION_RESULT_BUCKET = "limitmark-lifecycle-results-production";

test("request-write: the one allowed operation matches when the credential effectively allows it", async () => {
  const result = await harness.run(["--role", "request-write", "--operation", "write-request-fixture",
    "--credentials", harness.credentialsPath, "--mode", "run"], [`PUT ${REQUEST_BUCKET}`]);
  assert.equal(result.exitCode, 0, result.stdout + result.stderr);
  const line = JSON.parse(result.stdout);
  assert.equal(line.status, "MATCH");
  assert.equal(line.observed, "GRANTED");
  assert.equal(result.traceLines.length, 1);
  assert.match(result.traceLines[0], new RegExp(`^PUT ${REQUEST_BUCKET} gate6-iam-test/[a-f0-9]{32}\\.json$`));
});

test("request-write: result-write, result-read and cross-environment are denied and match expectation with no excess grant", async () => {
  for (const operation of ["deny-result-write", "deny-result-read", "deny-cross-environment-write"]) {
    const result = await harness.run(["--role", "request-write", "--operation", operation,
      "--credentials", harness.credentialsPath, "--mode", "run"], [`PUT ${REQUEST_BUCKET}`]);
    const line = JSON.parse(result.stdout);
    assert.equal(line.status, "MATCH", `${operation}: ${result.stdout}`);
    assert.equal(line.observed, "DENIED");
    assert.equal(result.exitCode, 0);
  }
});

test("an excess grant is reported as MISMATCH, not silently accepted", async () => {
  // Simulates an over-scoped credential: the effective policy grants the
  // request-write credential a result-bucket write it must never have.
  const result = await harness.run(["--role", "request-write", "--operation", "deny-result-write",
    "--credentials", harness.credentialsPath, "--mode", "run"], [`PUT ${RESULT_BUCKET}`]);
  const line = JSON.parse(result.stdout);
  assert.equal(line.status, "MISMATCH");
  assert.equal(line.observed, "GRANTED");
  assert.equal(result.exitCode, 2, "an excess right must be a nonzero, distinguishable exit code");
});

test("result-read: the one allowed operation requires an explicit fixture nonce and matches when allowed", async () => {
  const nonce = "b".repeat(32);
  const result = await harness.run(["--role", "result-read", "--operation", "read-result-fixture",
    "--credentials", harness.credentialsPath, "--mode", "run", "--fixture-nonce", nonce], [`GET ${RESULT_BUCKET}`]);
  assert.equal(result.exitCode, 0, result.stdout + result.stderr);
  const line = JSON.parse(result.stdout);
  assert.equal(line.status, "MATCH");
  assert.equal(line.key, `gate6-iam-test/${nonce}.json`);
});

test("result-read: request writes, request reads, result writes and cross-environment reads are denied", async () => {
  for (const operation of ["deny-result-write", "deny-request-write", "deny-request-read", "deny-cross-environment-read"]) {
    const result = await harness.run(["--role", "result-read", "--operation", operation,
      "--credentials", harness.credentialsPath, "--mode", "run"], [`GET ${RESULT_BUCKET}`]);
    const line = JSON.parse(result.stdout);
    assert.equal(line.status, "MATCH", `${operation}: ${result.stdout}`);
    assert.equal(line.observed, "DENIED");
  }
});

test("role separation: an operation from the other role's table is refused before any manifest load or transport call", async () => {
  const result = await harness.run(["--role", "request-write", "--operation", "read-result-fixture",
    "--credentials", harness.credentialsPath, "--mode", "run"]);
  assert.notEqual(result.exitCode, 0);
  assert.equal(result.traceLines.length, 0, "no transport call may occur for a rejected operation");
});

test("unknown operations and unknown roles are refused by the closed allowlist, never passed through", async () => {
  const badOperation = await harness.run(["--role", "request-write", "--operation", "delete-everything",
    "--credentials", harness.credentialsPath, "--mode", "run"]);
  assert.notEqual(badOperation.exitCode, 0);
  const badRole = await harness.run(["--role", "admin", "--operation", "write-request-fixture",
    "--credentials", harness.credentialsPath, "--mode", "run"]);
  assert.notEqual(badRole.exitCode, 0);
  assert.equal(badOperation.traceLines.length + badRole.traceLines.length, 0);
});

test("preflight mode resolves and prints the planned request without ever calling the R2 transport", async () => {
  const result = await harness.run(["--role", "request-write", "--operation", "write-request-fixture",
    "--credentials", harness.credentialsPath, "--mode", "preflight"]);
  assert.equal(result.exitCode, 0, result.stdout + result.stderr);
  const line = JSON.parse(result.stdout);
  assert.equal(line.status, "PASS");
  assert.equal(line.providerContact, "none");
  assert.equal(result.traceLines.length, 0, "preflight must never invoke the transport");
});

test("each invocation performs at most one bounded transport call -- no automatic retry, relevant to safe revocation checks", async () => {
  const before = await harness.run(["--role", "request-write", "--operation", "write-request-fixture",
    "--credentials", harness.credentialsPath, "--mode", "run"], [`PUT ${REQUEST_BUCKET}`]);
  assert.equal(before.traceLines.length, 1);
  // A second, separate, operator-initiated invocation (e.g. after revocation)
  // is exactly one more bounded call -- never a loop inside the tool itself.
  const after = await harness.run(["--role", "request-write", "--operation", "write-request-fixture",
    "--credentials", harness.credentialsPath, "--mode", "run"], []);
  assert.equal(after.traceLines.length, 1);
  const afterLine = JSON.parse(after.stdout);
  // "write-request-fixture" always expects ALLOW by its reviewed contract, so
  // this reads as MISMATCH -- the tool has no notion of "a revocation just
  // happened"; the operator reads `observed` for a revocation check, which
  // must be DENIED (never a retried GRANTED).
  assert.equal(afterLine.observed, "DENIED", "post-revocation re-check must observe a denial, not a retried success");
});

test("cross-environment probes target only the fixed literal Production bucket names, never an operator-suppliable one", async () => {
  const writeProbe = await harness.run(["--role", "request-write", "--operation", "deny-cross-environment-write",
    "--credentials", harness.credentialsPath, "--mode", "preflight"]);
  assert.equal(JSON.parse(writeProbe.stdout).bucket, PRODUCTION_REQUEST_BUCKET);
  const readProbe = await harness.run(["--role", "result-read", "--operation", "deny-cross-environment-read",
    "--credentials", harness.credentialsPath, "--mode", "preflight"]);
  assert.equal(JSON.parse(readProbe.stdout).bucket, PRODUCTION_RESULT_BUCKET);
});

test("no credential value or accountId ever appears in stdout or stderr", async () => {
  const result = await harness.run(["--role", "request-write", "--operation", "write-request-fixture",
    "--credentials", harness.credentialsPath, "--mode", "run"], [`PUT ${REQUEST_BUCKET}`]);
  const combined = result.stdout + result.stderr;
  assert.ok(!combined.includes("synthetic-gate6-access"));
  assert.ok(!combined.includes("synthetic-gate6-secret"));
  assert.ok(!combined.includes("a".repeat(32)), "raw accountId must never be printed, only its fingerprint");
});
