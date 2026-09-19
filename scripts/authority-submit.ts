import { createHash, randomBytes } from "node:crypto";
import { open } from "node:fs/promises";
import { resolve } from "node:path";
import { MAX_SEALED_ARTIFACT_BYTES, parseSealedLifecycleArtifact, parseStrictJson, type LifecycleOperation } from "../operator/lifecycle-submitter";
import { commandDigest, verifyOperatorCommand } from "../workers/admission-service/operator-command";
import { oneR2Request, type R2Credential } from "../operator/r2-transport";
import { validateLifecycleTransportManifest } from "../deployment/lifecycle-private-contract";
import { parseControl } from "../workers/lifecycle-mailbox/wire";
import { verifyLifecycleResult } from "../operator/lifecycle-result";

type Manifest = { accountId: string; requestBucket: string; resultBucket: string; operatorPublicKey: string; authorityId: string; policyEpoch: string };
const digestPattern = /^[a-f0-9]{64}$/u;
const noncePattern = /^[a-f0-9]{32}$/u;
function fail(): never { throw new Error("operator-input"); }
function argsFor(allowed: readonly string[]): Record<string, string | true> {
  const args = process.argv.slice(3);
  const result: Record<string, string | true> = {};
  for (let index = 0; index < args.length; index++) {
    const name = args[index];
    if (!allowed.includes(name) || result[name] !== undefined) fail();
    if (name === "--confirm-production" || name === "--inspect") result[name] = true;
    else {
      const value = args[++index];
      if (!value || value.startsWith("--") || value === "-") fail();
      result[name] = value;
    }
  }
  return result;
}
async function boundedFile(path: string, maximum: number): Promise<Uint8Array> {
  const file = await open(resolve(path), "r");
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > maximum) fail();
    const buffer = Buffer.alloc(maximum + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, length);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length !== stat.size) fail();
    return buffer.subarray(0, length);
  } finally { await file.close(); }
}
function strictObject(bytes: Uint8Array): Record<string, unknown> {
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  if (source.charCodeAt(0) === 0xfeff) fail();
  const value = parseStrictJson(source);
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  return value as Record<string, unknown>;
}
async function manifest(): Promise<Manifest> {
  // This fixed path is the only target. The unresolved template is refused.
  let bytes: Uint8Array;
  try { bytes = await boundedFile("deployment/lifecycle-transport.production.json", 2_048); }
  catch { throw new Error("operator-unavailable"); }
  const value = strictObject(bytes);
  validateLifecycleTransportManifest(value, false);
  return value as Manifest;
}
async function credential(path: string): Promise<R2Credential> {
  let bytes: Uint8Array;
  try { bytes = await boundedFile(path, 1_024); }
  catch { throw new Error("operator-unavailable"); }
  const value = strictObject(bytes);
  if (Object.keys(value).length !== 2 || typeof value.accessKeyId !== "string" || typeof value.secretAccessKey !== "string" ||
      !value.accessKeyId || !value.secretAccessKey) fail();
  return value as R2Credential;
}
function pathArg(args: Record<string, string | true>, key: string): string {
  const value = args[key];
  if (typeof value !== "string") fail();
  return value;
}
function production(args: Record<string, string | true>): void { if (args["--confirm-production"] !== true) fail(); }
function print(value: object): void { process.stdout.write(`${JSON.stringify(value)}\n`); }
function terminal(status: "SUCCESS" | "ALREADY_APPLIED" | "REFUSED" | "UNAVAILABLE" | "UNCONFIRMED", value: object): void {
  print({ status, ...value });
  if (status !== "SUCCESS" && status !== "ALREADY_APPLIED") process.exitCode = status === "UNCONFIRMED" ? 3 : 2;
}
async function submit(operation: LifecycleOperation): Promise<void> {
  const args = argsFor(["--command", "--request-credentials", "--confirm-production", "--inspect"]);
  production(args);
  const bytes = await boundedFile(pathArg(args, "--command"), MAX_SEALED_ARTIFACT_BYTES);
  const artifact = parseSealedLifecycleArtifact(bytes, operation);
  if (args["--inspect"] === true) {
    print({ status: "INSPECTED", operation, environment: artifact.command[2], authorityId: artifact.command[3],
      policyEpoch: artifact.command[4] });
    return;
  }
  if (typeof args["--request-credentials"] !== "string") throw new Error("operator-unavailable");
  const target = await manifest();
  await verifyOperatorCommand(artifact.command, artifact.signature, target.operatorPublicKey);
  const digest = await commandDigest(artifact.command);
  const rawHash = createHash("sha256").update(bytes).digest("hex");
  const token = await credential(pathArg(args, "--request-credentials"));
  const key = operation === "initialize" ? "initialize.json" : "rotate-release.json";
  try {
    const response = await oneR2Request("PUT", { accountId: target.accountId, bucket: target.requestBucket }, token, key, bytes, 1_024);
    terminal("UNCONFIRMED", { digest, rawHash, transport: response.statusCode >= 200 && response.statusCode < 300 ? "ACCEPTED" : "AMBIGUOUS" });
  } catch { terminal("UNCONFIRMED", { digest, rawHash, transport: "AMBIGUOUS" }); }
}
async function control(operation: "reconcile" | "settle"): Promise<void> {
  const args = argsFor(["--digest", "--request-credentials", "--confirm-production"]);
  production(args);
  const digest = pathArg(args, "--digest");
  if (!digestPattern.test(digest)) fail();
  const target = await manifest();
  const token = await credential(pathArg(args, "--request-credentials"));
  const nonce = randomBytes(16).toString("hex");
  const bytes = new TextEncoder().encode(JSON.stringify({ version: 1, digest, nonce }));
  parseControl(bytes);
  try {
    const response = await oneR2Request("PUT", { accountId: target.accountId, bucket: target.requestBucket }, token,
      operation === "reconcile" ? "reconcile.json" : "settle.json", bytes, 1_024);
    print({ status: response.statusCode >= 200 && response.statusCode < 300 ? "REQUESTED" : "UNCONFIRMED", operation, digest, nonce });
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
  const target = await manifest();
  const token = await credential(pathArg(args, "--result-credentials"));
  const key = kind === "lifecycle" ? `lifecycle/${digest}.json` : `${kind}/${nonce}.json`;
  let result;
  try { result = await oneR2Request("GET", { accountId: target.accountId, bucket: target.resultBucket }, token, key, undefined, 8_192); }
  catch { terminal("UNCONFIRMED", { kind }); return; }
  if (result.statusCode !== 200) { terminal("UNCONFIRMED", { kind }); return; }
  let verified: ReturnType<typeof verifyLifecycleResult>;
  try {
    verified = verifyLifecycleResult(result.body, kind as "lifecycle" | "reconciliation" | "settlement",
      kind === "lifecycle" ? { digest: digest as string } : { digest: digest as string, nonce: nonce as string });
  } catch {
    // Invalid result bytes are failed observations, never proof that an
    // earlier accepted lifecycle command was refused or rolled back.
    terminal("UNCONFIRMED", { kind });
    return;
  }
  if (verified.status === "SETTLED") print(verified);
  else if (verified.status === "SUCCESS" || verified.status === "ALREADY_APPLIED") terminal(verified.status, verified);
  else terminal("UNCONFIRMED", verified);
}
async function main(): Promise<void> {
  const action = process.argv[2];
  if (action === "initialize" || action === "rotate-release") await submit(action);
  else if (action === "reconcile" || action === "settle") await control(action);
  else if (action === "read-result") await readResult();
  else fail();
}
main().catch((error: unknown) => {
  process.stderr.write(error instanceof Error && error.message === "operator-unavailable"
    ? "UNAVAILABLE: local transport contract or credential is absent. No lifecycle RPC was invoked.\n"
    : "REFUSED: invalid operator input or local contract. No lifecycle RPC was invoked.\n");
  process.exitCode = 2;
});
