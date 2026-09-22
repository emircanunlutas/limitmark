import { basename, dirname, join, resolve } from "node:path";
import { open, realpath } from "node:fs/promises";
import { validateRenderedStagingOperatorExecutorConfig } from "../deployment/operator-executor-contract";
import { parseStrictJson } from "../operator/lifecycle-submitter";

/** Gate 2 staging capability. Structurally identical to
 * scripts/authority-executor-preflight.ts (Production) but pinned to the
 * distinct staging executor identity and source file; a Production-rendered
 * config cannot pass this preflight and vice versa. Gate 5A: accepts only the
 * one reviewed rendered filename
 * (deployment/operator-lifecycle-executor.staging.jsonc) -- the same
 * exact-filename invariant Gate 4B established for the staging admission
 * config, so this preflight can never PASS a filename its deploy wrapper
 * would refuse. */
const exactRenderedConfigName = "operator-lifecycle-executor.staging.jsonc";
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== "--config" || !args[1] || args[1].startsWith("--")) throw new Error("explicit-rendered-config-required");
  const root = process.cwd();
  const configPath = await realpath(resolve(args[1]));
  if (dirname(configPath) !== await realpath(join(root, "deployment")) || basename(configPath) !== exactRenderedConfigName)
    throw new Error("exact-staging-executor-rendered-config-required");
  const file = await open(configPath, "r");
  let data: Uint8Array;
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > 16_384) throw new Error("invalid-executor-config-size");
    data = new Uint8Array(stat.size + 1);
    let length = 0;
    while (length < data.length) {
      const result = await file.read(data, length, data.length - length, length);
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    if (length !== stat.size) throw new Error("executor-config-changed-while-reading");
    data = data.subarray(0, length);
  } finally { await file.close(); }
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("executor-config-bom");
  const config: unknown = parseStrictJson(source);
  validateRenderedStagingOperatorExecutorConfig(config);
  const expectedMain = await realpath(join(root, "workers", "staging-operator-lifecycle-executor.ts"));
  const resolvedMain = await realpath(resolve(dirname(configPath), "../workers/staging-operator-lifecycle-executor.ts"));
  if (resolvedMain !== expectedMain) throw new Error("executor-main-mismatch");
  process.stdout.write("Private staging operator executor preflight: PASS (local validation only; no deployment).\n");
}

main().catch(() => { process.stderr.write("Private staging operator executor preflight: REFUSED.\n"); process.exitCode = 1; });
