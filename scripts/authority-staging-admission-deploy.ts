import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { open, realpath } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { validateStagingAdmissionServiceConfig } from "../deployment/lifecycle-private-contract";
import { parseStrictJson } from "../operator/lifecycle-submitter";

// Gate 4B deploy wrapper. Narrowly scoped to exactly one Worker
// (limitmark-admission-service-staging): it never accepts --env, --route,
// --var, a binding override, a custom-domain override, an alternate Worker
// name, an alternate config path outside deployment/, or any other Wrangler
// argument -- the only argv it can ever construct is
// `wrangler deploy --config <reviewed rendered config>`. It never adds
// account_id to the config; instead it requires CLOUDFLARE_ACCOUNT_ID (the
// mechanism the installed Wrangler's own config types document as the
// supported non-interactive account pin -- see
// node_modules/wrangler/wrangler-dist/experimental-config.d.mts) in the
// process environment, validates its format, and lets Wrangler consume it
// directly; the raw value is never logged, only a one-way fingerprint. Mode
// "preflight" performs every non-provider check and prints the exact command
// that would run without spawning Wrangler at all; mode "deploy" performs the
// identical checks and then, only then, spawns the repository-pinned local
// Wrangler binary. Refusal always happens before any spawn.

function fingerprint(accountId: string): string {
  return createHash("sha256").update(accountId).digest("hex").slice(0, 16);
}

function accountId(): string {
  const value = process.env.CLOUDFLARE_ACCOUNT_ID;
  if (typeof value !== "string" || !/^[a-f0-9]{32}$/u.test(value) || /^0{32}$/u.test(value))
    throw new Error("missing-or-malformed-account-pin");
  return value;
}

// The one rendered filename the reviewed .gitignore rule and runbook name
// (deployment/admission-service.staging.jsonc). realpath() canonicalizes
// through any symlink before this comparison, so a symlink placed at that
// exact path but pointing elsewhere resolves to its real target's own
// dirname/basename and is rejected the same way any other alternate name is.
const exactRenderedConfigName = "admission-service.staging.jsonc";

async function renderedConfigPath(root: string, argPath: string): Promise<string> {
  const configPath = await realpath(resolve(argPath));
  if (dirname(configPath) !== await realpath(join(root, "deployment")) || basename(configPath) !== exactRenderedConfigName)
    throw new Error("exact-staging-admission-rendered-config-required");
  return configPath;
}

async function readBoundedConfig(configPath: string): Promise<unknown> {
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
  return parseStrictJson(source);
}

async function main(): Promise<void> {
  const mode = process.argv[2];
  const args = process.argv.slice(3);
  if ((mode !== "preflight" && mode !== "deploy") || args.length !== 2 || args[0] !== "--config" || !args[1] || args[1].startsWith("--"))
    throw new Error("explicit-mode-and-rendered-config-required");
  const root = process.cwd();
  const pin = accountId();
  const configPath = await renderedConfigPath(root, args[1]);
  const config = await readBoundedConfig(configPath);
  validateStagingAdmissionServiceConfig(config, false);
  const expectedMain = await realpath(join(root, "workers", "admission-service", "index.ts"));
  const resolvedMain = await realpath(resolve(dirname(configPath), "../workers/admission-service/index.ts"));
  if (resolvedMain !== expectedMain) throw new Error("admission-main-mismatch");
  const wranglerBin = await realpath(join(root, "node_modules", "wrangler", "bin", "wrangler.js"));
  const wranglerArgv = ["deploy", "--config", configPath];
  const evidence = { worker: "limitmark-admission-service-staging", config: configPath, accountFingerprint: fingerprint(pin), plannedCommand: ["wrangler", ...wranglerArgv] };
  if (mode === "preflight") {
    process.stdout.write(`${JSON.stringify({ status: "PASS", mode, ...evidence, providerContact: "none" })}\n`);
    return;
  }
  process.stderr.write(`Gate 4B deploy: invoking pinned Wrangler for account fingerprint ${evidence.accountFingerprint}.\n`);
  const result = spawnSync(process.execPath, [wranglerBin, ...wranglerArgv], { stdio: "inherit" });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
}

main().catch(() => { process.stderr.write("Gate 4B staging admission deploy: REFUSED (no Wrangler invocation occurred).\n"); process.exitCode = 2; });
