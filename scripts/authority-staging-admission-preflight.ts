import { basename, dirname, join, resolve } from "node:path";
import { open, realpath } from "node:fs/promises";
import { validateStagingAdmissionServiceConfig } from "../deployment/lifecycle-private-contract";
import { parseStrictJson } from "../operator/lifecycle-submitter";

/** Gate 4 staging capability. Structurally identical to
 * scripts/authority-staging-executor-preflight.ts but pinned to the distinct
 * staging admission-service identity (Worker name, DO binding/class,
 * migration tag, key placeholder) and the shared admission-service source
 * file; a Production-rendered config, or one carrying any route/custom-domain
 * member, cannot pass this preflight. Never deploys, never contacts
 * Cloudflare, never touches the authority (no initialize/rotate path is
 * reachable from this script). Gate 4B: accepts only the one rendered
 * filename the .gitignore rule and runbook name
 * (deployment/admission-service.staging.jsonc) -- the exact same invariant
 * scripts/authority-staging-admission-deploy.ts enforces, so this standalone
 * preflight can never PASS a filename the deploy wrapper would refuse. */
const exactRenderedConfigName = "admission-service.staging.jsonc";
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== "--config" || !args[1] || args[1].startsWith("--")) throw new Error("explicit-rendered-config-required");
  const root = process.cwd();
  const configPath = await realpath(resolve(args[1]));
  if (dirname(configPath) !== await realpath(join(root, "deployment")) || basename(configPath) !== exactRenderedConfigName)
    throw new Error("exact-staging-admission-rendered-config-required");
  const file = await open(configPath, "r");
  let data: Uint8Array;
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > 16_384) throw new Error("invalid-admission-config-size");
    data = new Uint8Array(stat.size + 1);
    let length = 0;
    while (length < data.length) {
      const result = await file.read(data, length, data.length - length, length);
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    if (length !== stat.size) throw new Error("admission-config-changed-while-reading");
    data = data.subarray(0, length);
  } finally { await file.close(); }
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("admission-config-bom");
  const config: unknown = parseStrictJson(source);
  validateStagingAdmissionServiceConfig(config, false);
  const expectedMain = await realpath(join(root, "workers", "admission-service", "index.ts"));
  const resolvedMain = await realpath(resolve(dirname(configPath), "../workers/admission-service/index.ts"));
  if (resolvedMain !== expectedMain) throw new Error("admission-main-mismatch");
  process.stdout.write("Private staging admission-service preflight: PASS (local validation only; no deployment; authority not contacted).\n");
}

main().catch(() => { process.stderr.write("Private staging admission-service preflight: REFUSED.\n"); process.exitCode = 1; });
