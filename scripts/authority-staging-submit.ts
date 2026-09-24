import { createHash, randomBytes } from "node:crypto";
import { MAX_SEALED_ARTIFACT_BYTES, parseSealedLifecycleArtifact } from "../operator/lifecycle-submitter";
import { commandDigest, verifyOperatorCommand } from "../workers/admission-service/operator-command";
import { oneR2Request } from "../operator/r2-transport";
import { boundedFile, loadStagingLifecycleTransportManifest, readStagingR2Credential } from "../operator/staging-credential-io";
import { parseControl } from "../workers/lifecycle-mailbox/wire";
import { verifyLifecycleResult } from "../operator/lifecycle-result";
import { refuseClosedStagingInitialization } from "../operator/staging-initialization-lock";

// Gate 2 staging capability. Structurally mirrors scripts/authority-submit.ts
// (Production) but is a separate, explicitly self-identifying tool: its only
// mutation-capable action is `initialize`, gated by --confirm-staging rather
// than --confirm-production, and it loads only the distinct rendered staging
// manifest. There is no "rotate-release" action here at all (STAGING ROTATION
// — NOT IMPLEMENTED / GATE 9 — CLOSED): attempting it is not a code path this
// file exposes, so it fails at argument dispatch, before any transport call.
// Since Gate 8 Phase 0 the `initialize` action itself is permanently refused
// (operator/staging-initialization-lock.ts); submitInitialize is retained as
// the historical Gate 7 implementation and is never reached.

const digestPattern = /^[a-f0-9]{64}$/u;
const noncePattern = /^[a-f0-9]{32}$/u;
function fail(): never { throw new Error("operator-input"); }
function argsFor(allowed: readonly string[]): Record<string, string | true> {
  const args = process.argv.slice(3);
  const result: Record<string, string | true> = {};
  for (let index = 0; index < args.length; index++) {
    const name = args[index];
    if (!allowed.includes(name) || result[name] !== undefined) fail();
    if (name === "--confirm-staging" || name === "--inspect") result[name] = true;
    else {
      const value = args[++index];
      if (!value || value.startsWith("--") || value === "-") fail();
      result[name] = value;
    }
  }
  return result;
}
function pathArg(args: Record<string, string | true>, key: string): string {
  const value = args[key];
  if (typeof value !== "string") fail();
  return value;
}
function staging(args: Record<string, string | true>): void { if (args["--confirm-staging"] !== true) fail(); }
function print(value: object): void { process.stdout.write(`${JSON.stringify(value)}\n`); }
function terminal(status: "SUCCESS" | "ALREADY_APPLIED" | "REFUSED" | "UNAVAILABLE" | "UNCONFIRMED", value: object): void {
  print({ status, environment: "staging", ...value });
  if (status !== "SUCCESS" && status !== "ALREADY_APPLIED") process.exitCode = status === "UNCONFIRMED" ? 3 : 2;
}
async function submitInitialize(): Promise<void> {
  const args = argsFor(["--command", "--request-credentials", "--confirm-staging", "--inspect"]);
  staging(args);
  const bytes = await boundedFile(pathArg(args, "--command"), MAX_SEALED_ARTIFACT_BYTES);
  const artifact = parseSealedLifecycleArtifact(bytes, "initialize", Date.now(), "staging");
  if (args["--inspect"] === true) {
    print({ status: "INSPECTED", operation: "initialize", environment: artifact.command[2], authorityId: artifact.command[3],
      policyEpoch: artifact.command[4] });
    return;
  }
  if (typeof args["--request-credentials"] !== "string") throw new Error("operator-unavailable");
  const target = await loadStagingLifecycleTransportManifest();
  await verifyOperatorCommand(artifact.command, artifact.signature, target.operatorPublicKey);
  const digest = await commandDigest(artifact.command);
  const rawHash = createHash("sha256").update(bytes).digest("hex");
  const token = await readStagingR2Credential(pathArg(args, "--request-credentials"));
  try {
    const response = await oneR2Request("PUT", { accountId: target.accountId, bucket: target.requestBucket }, token, "initialize.json", bytes, 1_024);
    terminal("UNCONFIRMED", { digest, rawHash, transport: response.statusCode >= 200 && response.statusCode < 300 ? "ACCEPTED" : "AMBIGUOUS" });
  } catch { terminal("UNCONFIRMED", { digest, rawHash, transport: "AMBIGUOUS" }); }
}
async function control(operation: "reconcile" | "settle"): Promise<void> {
  const args = argsFor(["--digest", "--request-credentials", "--confirm-staging"]);
  staging(args);
  const digest = pathArg(args, "--digest");
  if (!digestPattern.test(digest)) fail();
  const target = await loadStagingLifecycleTransportManifest();
  const token = await readStagingR2Credential(pathArg(args, "--request-credentials"));
  const nonce = randomBytes(16).toString("hex");
  const bytes = new TextEncoder().encode(JSON.stringify({ version: 1, digest, nonce }));
  parseControl(bytes);
  try {
    const response = await oneR2Request("PUT", { accountId: target.accountId, bucket: target.requestBucket }, token,
      operation === "reconcile" ? "reconcile.json" : "settle.json", bytes, 1_024);
    print({ status: response.statusCode >= 200 && response.statusCode < 300 ? "REQUESTED" : "UNCONFIRMED", operation, digest, nonce, environment: "staging" });
    if (response.statusCode < 200 || response.statusCode >= 300) process.exitCode = 3;
  } catch { terminal("UNCONFIRMED", { operation, digest, nonce }); }
}
async function readResult(): Promise<void> {
  const args = argsFor(["--kind", "--digest", "--nonce", "--result-credentials"]);
  const kind = pathArg(args, "--kind");
  const digest = args["--digest"];
  const nonce = args["--nonce"];
  if (!["lifecycle", "reconciliation", "settlement"].includes(kind) ||
      kind === "lifecycle" && (typeof digest !== "string" || !digestPattern.test(digest) || nonce !== undefined) ||
      kind !== "lifecycle" && (typeof nonce !== "string" || !noncePattern.test(nonce) || typeof digest !== "string" || !digestPattern.test(digest))) fail();
  const target = await loadStagingLifecycleTransportManifest();
  const token = await readStagingR2Credential(pathArg(args, "--result-credentials"));
  const key = kind === "lifecycle" ? `lifecycle/${digest}.json` : `${kind}/${nonce}.json`;
  let result;
  try { result = await oneR2Request("GET", { accountId: target.accountId, bucket: target.resultBucket }, token, key, undefined, 8_192); }
  catch { terminal("UNCONFIRMED", { kind }); return; }
  if (result.statusCode !== 200) { terminal("UNCONFIRMED", { kind }); return; }
  let verified: ReturnType<typeof verifyLifecycleResult>;
  try {
    verified = verifyLifecycleResult(result.body, kind as "lifecycle" | "reconciliation" | "settlement",
      kind === "lifecycle" ? { digest: digest as string } : { digest: digest as string, nonce: nonce as string }, Date.now(),
      "staging", "staging-public-inquiries-v1");
  } catch {
    terminal("UNCONFIRMED", { kind });
    return;
  }
  if (verified.status === "SETTLED") print({ ...verified, environment: "staging" });
  else if (verified.status === "SUCCESS" || verified.status === "ALREADY_APPLIED") terminal(verified.status, verified);
  else terminal("UNCONFIRMED", verified);
}
async function main(): Promise<void> {
  const action = process.argv[2];
  // Gate 8 Phase 0: staging initialization is permanently closed after Gate 7.
  // Refused unconditionally (including --inspect) before any argument, artifact,
  // manifest, credential or transport access. reconcile/settle/read-result stay open.
  if (action === "initialize") { refuseClosedStagingInitialization(); await submitInitialize(); }
  else if (action === "reconcile" || action === "settle") await control(action);
  else if (action === "read-result") await readResult();
  else fail();
}
main().catch((error: unknown) => {
  process.stderr.write(error instanceof Error && error.message === "operator-unavailable"
    ? "UNAVAILABLE: local staging transport contract or credential is absent. No lifecycle RPC was invoked.\n"
    : "REFUSED: invalid operator input or local staging contract. No lifecycle RPC was invoked.\n");
  process.exitCode = 2;
});
