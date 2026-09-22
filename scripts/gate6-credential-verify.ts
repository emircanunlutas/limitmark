import { createHash } from "node:crypto";
import { oneR2Request } from "../operator/r2-transport";
import { loadStagingLifecycleTransportManifest, readStagingR2Credential } from "../operator/staging-credential-io";
import { GATE6_IAM_TEST_KEY_PATTERN, gate6IamTestFixtureBody, gate6IamTestKey, gate6IamTestNonce } from "../operator/gate6-iam-namespace";

// Gate 6A IAM verification harness. Bounded, closed-set local/operator-side
// tooling that exercises the *effective* permissions of one already-issued
// staging R2 credential without ever printing it. Reuses the single reviewed
// SigV4/R2 transport primitive (operator/r2-transport.ts) rather than a
// second signer, and the single reviewed staging manifest loader
// (operator/staging-credential-io.ts) rather than an operator-suppliable
// account/bucket -- so there is no arbitrary URL, bucket, key, method or
// environment reachable from this CLI's argument surface at all: --role and
// --operation each select from a fixed, closed table below, and the target
// account/bucket names always come from the same reviewed
// deployment/lifecycle-transport.staging.json this repository's other
// staging tooling already pins. `--mode preflight` resolves and prints
// everything above without ever calling oneR2Request; `--mode run` performs
// exactly the one bounded request the resolved operation names. Neither mode
// creates or revokes a credential, and neither mode is reachable for a
// Production bucket name except as the deliberate, expected-DENY
// cross-environment probe below.

const roles = ["request-write", "result-read"] as const;
type Role = (typeof roles)[number];
type Expectation = "ALLOW" | "DENY";
type BucketRef = "request" | "result" | "production-request" | "production-result";
type OperationSpec = { method: "PUT" | "GET"; bucket: BucketRef; expect: Expectation; needsFixtureNonce?: boolean };

// These literal Production bucket names exist only so the deliberate
// cross-environment probes below have a fixed, reviewed target to prove
// denied against -- this file has no other reference to a Production
// resource and no way to reach one for any other operation.
const PRODUCTION_REQUEST_BUCKET = "limitmark-lifecycle-requests-production";
const PRODUCTION_RESULT_BUCKET = "limitmark-lifecycle-results-production";

// F6/F7: derived literally from the Gate 6 runbook contract (credential
// custody matrix and the "Request credential scope"/"Result reader scope"
// rows). Request-write GET/LIST/DELETE denial is deliberately NOT asserted
// here: the committed contract requires only PUT for its allowed operation
// and denial of result write/read/other-bucket/config-management, and
// inventing a stricter rule the contract does not require is out of scope
// (see PHASE5C_I3_PROVISIONING_RUNBOOK.md Gate 6A note, F6). Worker/config/
// token-management denial is not expressible through this R2 SigV4 surface
// at all -- see the runbook's Provider Permission Expressiveness section.
const operationsByRole: Record<Role, Record<string, OperationSpec>> = {
  "request-write": {
    "write-request-fixture": { method: "PUT", bucket: "request", expect: "ALLOW" },
    "deny-result-write": { method: "PUT", bucket: "result", expect: "DENY" },
    "deny-result-read": { method: "GET", bucket: "result", expect: "DENY" },
    "deny-cross-environment-write": { method: "PUT", bucket: "production-request", expect: "DENY" },
  },
  "result-read": {
    "read-result-fixture": { method: "GET", bucket: "result", expect: "ALLOW", needsFixtureNonce: true },
    "deny-result-write": { method: "PUT", bucket: "result", expect: "DENY" },
    "deny-request-write": { method: "PUT", bucket: "request", expect: "DENY" },
    "deny-request-read": { method: "GET", bucket: "request", expect: "DENY" },
    "deny-cross-environment-read": { method: "GET", bucket: "production-result", expect: "DENY" },
  },
};

function fail(message: string): never { throw new Error(message); }

function parseArgs(): { role: Role; operation: string; credentials: string; mode: "preflight" | "run"; fixtureNonce?: string } {
  const args = process.argv.slice(2);
  const result: Record<string, string> = {};
  const allowed = ["--role", "--operation", "--credentials", "--mode", "--fixture-nonce"];
  for (let index = 0; index < args.length; index++) {
    const name = args[index];
    if (!allowed.includes(name) || Object.hasOwn(result, name)) fail("gate6-verify-usage");
    const value = args[++index];
    if (!value || value.startsWith("--")) fail("gate6-verify-usage");
    result[name] = value;
  }
  const role = result["--role"];
  const mode = result["--mode"];
  const operation = result["--operation"];
  const credentials = result["--credentials"];
  if (!(roles as readonly string[]).includes(role) || (mode !== "preflight" && mode !== "run") || !operation || !credentials)
    fail("gate6-verify-usage");
  const spec = operationsByRole[role as Role][operation];
  if (!spec) fail("gate6-verify-unknown-operation");
  const fixtureNonce = result["--fixture-nonce"];
  if (spec.needsFixtureNonce && !fixtureNonce) fail("gate6-verify-fixture-nonce-required");
  if (!spec.needsFixtureNonce && fixtureNonce !== undefined) fail("gate6-verify-usage");
  if (fixtureNonce !== undefined && !/^[a-f0-9]{32}$/u.test(fixtureNonce)) fail("gate6-verify-usage");
  return { role: role as Role, operation, credentials, mode, fixtureNonce };
}

function resolveBucket(ref: BucketRef, manifest: { requestBucket: string; resultBucket: string }): string {
  if (ref === "request") return manifest.requestBucket;
  if (ref === "result") return manifest.resultBucket;
  if (ref === "production-request") return PRODUCTION_REQUEST_BUCKET;
  return PRODUCTION_RESULT_BUCKET;
}

function fingerprint(value: string): string { return createHash("sha256").update(value).digest("hex").slice(0, 16); }

function classify(statusCode: number): "GRANTED" | "DENIED" | "AMBIGUOUS" {
  if (statusCode >= 200 && statusCode < 300) return "GRANTED";
  if (statusCode === 403) return "DENIED";
  return "AMBIGUOUS";
}

async function main(): Promise<void> {
  const { role, operation, credentials, mode, fixtureNonce } = parseArgs();
  const spec = operationsByRole[role][operation];
  const manifest = await loadStagingLifecycleTransportManifest();
  const bucket = resolveBucket(spec.bucket, manifest);
  const nonce = fixtureNonce ?? gate6IamTestNonce();
  const key = gate6IamTestKey(nonce);
  if (!GATE6_IAM_TEST_KEY_PATTERN.test(key)) fail("gate6-verify-namespace-contract");
  const body = spec.method === "PUT" && !spec.needsFixtureNonce ? gate6IamTestFixtureBody(nonce, Date.now()) : undefined;
  const evidence = { role, operation, method: spec.method, bucket, key, expect: spec.expect, accountFingerprint: fingerprint(manifest.accountId) };
  if (mode === "preflight") {
    process.stdout.write(`${JSON.stringify({ status: "PASS", mode, ...evidence, providerContact: "none" })}\n`);
    return;
  }
  const credential = await readStagingR2Credential(credentials);
  let response;
  try {
    response = await oneR2Request(spec.method, { accountId: manifest.accountId, bucket }, credential, key, body,
      spec.method === "GET" ? 8_192 : 1_024);
  } catch {
    process.stdout.write(`${JSON.stringify({ status: "UNAVAILABLE", ...evidence })}\n`);
    process.exitCode = 3;
    return;
  }
  const observed = classify(response.statusCode);
  const matches = (spec.expect === "ALLOW" && observed === "GRANTED") || (spec.expect === "DENY" && observed === "DENIED");
  const verdict = matches ? "MATCH" : observed === "AMBIGUOUS" ? "AMBIGUOUS" : "MISMATCH";
  process.stdout.write(`${JSON.stringify({ status: verdict, ...evidence, observed, httpStatus: response.statusCode })}\n`);
  process.exitCode = verdict === "MATCH" ? 0 : verdict === "AMBIGUOUS" ? 1 : 2;
}

main().catch((error: unknown) => {
  process.stderr.write(error instanceof Error && error.message === "operator-unavailable"
    ? "UNAVAILABLE: local staging transport contract or credential is absent. No IAM probe was invoked.\n"
    : "REFUSED: invalid operator input or local staging contract. No IAM probe was invoked.\n");
  process.exitCode = 2;
});
