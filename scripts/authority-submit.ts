import { open } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { MAX_SEALED_ARTIFACT_BYTES, parseSealedLifecycleArtifact, type LifecycleOperation } from "../operator/lifecycle-submitter";

function fail(message: string): never { throw new Error(message); }

async function main(): Promise<void> {
  const operation: LifecycleOperation = process.argv[2] === "initialize" ? "initialize" : process.argv[2] === "rotate-release" ? "rotate-release" : fail("Unsupported lifecycle operation");
  const args = process.argv.slice(3);
  const allowed = new Set(["--command", "--confirm-production", "--inspect"]);
  if (args.some((value, index) => value.startsWith("--") && !allowed.has(value) ||
      value === "--command" && (index === args.length - 1 || args[index + 1].startsWith("--")))) fail("Invalid submitter arguments");
  if (args.filter((value) => value === "--command").length !== 1 || args.filter((value) => value === "--confirm-production").length !== 1 ||
      args.filter((value) => value === "--inspect").length > 1 || !args.includes("--confirm-production")) fail("Explicit command path and Production confirmation required");
  const commandIndex = args.indexOf("--command");
  if (args.length !== (args.includes("--inspect") ? 4 : 3) || commandIndex < 0) fail("Invalid submitter arguments");
  const path = args[commandIndex + 1];
  if (!path || path === "-" || path.startsWith("--")) fail("Explicit sealed artifact file required");
  const file = await open(isAbsolute(path) ? path : resolve(path), "r");
  let bytes: Uint8Array;
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > MAX_SEALED_ARTIFACT_BYTES) fail("Invalid sealed artifact size");
    const bounded = Buffer.alloc(MAX_SEALED_ARTIFACT_BYTES + 1);
    let length = 0;
    while (length < bounded.length) {
      const result = await file.read(bounded, length, bounded.length - length, length);
      if (result.bytesRead === 0) break;
      length += result.bytesRead;
    }
    if (length !== stat.size) fail("Sealed artifact changed while reading");
    bytes = bounded.subarray(0, length);
  } finally { await file.close(); }
  const artifact = parseSealedLifecycleArtifact(bytes, operation);
  if (args.includes("--inspect")) {
    process.stdout.write(`${JSON.stringify({ status: "inspected", operation, environment: artifact.command[2],
      authorityId: artifact.command[3], policyEpoch: artifact.command[4], issuedAtMs: operation === "initialize" ? artifact.command[7] : artifact.command[10] })}\n`);
    return;
  }
  // A local shell has no Cloudflare service-binding stub. A separately authorized,
  // private provider job must call submitSealedLifecycleArtifact with that binding.
  process.stderr.write("UNAVAILABLE: private provider executor is not configured. No lifecycle RPC was invoked.\n");
  process.exitCode = 2;
}

main().catch(() => { process.stderr.write("REFUSED: invalid sealed artifact or submitter arguments. No lifecycle RPC was invoked.\n"); process.exitCode = 1; });
