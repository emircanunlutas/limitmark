import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { open, realpath } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { validateStagingLifecycleMailboxConfig, validateStagingLifecycleObserverConfig } from "../deployment/lifecycle-private-contract";
import { validateRenderedStagingOperatorExecutorConfig } from "../deployment/operator-executor-contract";
import { parseStrictJson } from "../operator/lifecycle-submitter";

// Gate 5A deploy wrapper. Reuses the exact Gate 4B security pattern
// (scripts/authority-staging-admission-deploy.ts) generalized to the three
// Gate 5 Workers, with one narrow, closed-set "resource" selector in place of
// three near-duplicate files -- the operator surface stays exactly as
// mode-pinned as three separate wrappers would be: <resource> is one of
// "executor"/"mailbox"/"observer" and each hardcodes its own exact Worker
// name, exact rendered filename, exact main path and exact validator (with
// the mailbox/observer calls additionally pinned to
// requireScheduleState="STAGING_DEPLOYMENT_INACTIVE", so an active-Cron
// config can never reach a spawn either). It never adds account_id to any
// config; it requires CLOUDFLARE_ACCOUNT_ID in the process environment (never
// a CLI flag, never logged -- only a one-way SHA-256 fingerprint, truncated
// to 16 hex characters, is ever printed). Gate 7B: all three rendered
// configs carry their own account_id, which the pinned Wrangler resolves
// BEFORE CLOUDFLARE_ACCOUNT_ID, so the config's account_id must equal the
// environment pin; a mismatch is refused before any preflight PASS or
// Wrangler spawn. Mode "preflight" performs every non-provider check and prints the exact command
// that would run without spawning Wrangler; mode "deploy" performs the
// identical checks and then, only then, spawns the
// repository-pinned local Wrangler binary with exactly
// `deploy --config <path>` -- no --env, --route, --var, binding/domain
// override, alternate name or alternate config is constructible. Refusal
// always happens before any spawn. This wrapper deploys exactly ONE Worker
// per invocation by design (see the Gate 5 deployment-order contract in the
// runbook): there is no "deploy all three" mode, so the operator cannot
// perform three irreversible provider mutations without inspecting each one
// first.

type Resource = "executor" | "mailbox" | "observer";
const resources = ["executor", "mailbox", "observer"] as const;

type ResourceSpec = { worker: string; configName: string; mainSegments: readonly string[]; validate: (config: unknown) => void };
const resourceSpec: Record<Resource, ResourceSpec> = {
  executor: {
    worker: "limitmark-authority-operator-executor-staging",
    configName: "operator-lifecycle-executor.staging.jsonc",
    mainSegments: ["workers", "staging-operator-lifecycle-executor.ts"],
    validate: (config) => validateRenderedStagingOperatorExecutorConfig(config),
  },
  mailbox: {
    worker: "limitmark-lifecycle-mailbox-staging",
    configName: "lifecycle-mailbox.staging.jsonc",
    mainSegments: ["workers", "lifecycle-mailbox", "staging-index.ts"],
    validate: (config) => { validateStagingLifecycleMailboxConfig(config, false, "STAGING_DEPLOYMENT_INACTIVE"); },
  },
  observer: {
    worker: "limitmark-lifecycle-observer-staging",
    configName: "lifecycle-observer.staging.jsonc",
    mainSegments: ["workers", "staging-lifecycle-observer.ts"],
    validate: (config) => { validateStagingLifecycleObserverConfig(config, false, "STAGING_DEPLOYMENT_INACTIVE"); },
  },
};

function fingerprint(accountId: string): string {
  return createHash("sha256").update(accountId).digest("hex").slice(0, 16);
}

function accountId(): string {
  const value = process.env.CLOUDFLARE_ACCOUNT_ID;
  if (typeof value !== "string" || !/^[a-f0-9]{32}$/u.test(value) || /^0{32}$/u.test(value))
    throw new Error("missing-or-malformed-account-pin");
  return value;
}

async function renderedConfigPath(root: string, spec: ResourceSpec, argPath: string): Promise<string> {
  const configPath = await realpath(resolve(argPath));
  if (dirname(configPath) !== await realpath(join(root, "deployment")) || basename(configPath) !== spec.configName)
    throw new Error("exact-staging-gate5-rendered-config-required");
  return configPath;
}

async function readBoundedConfig(configPath: string): Promise<unknown> {
  const file = await open(configPath, "r");
  let data: Uint8Array;
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > 16_384) throw new Error("invalid-gate5-config-size");
    data = new Uint8Array(stat.size + 1);
    let length = 0;
    while (length < data.length) {
      const result = await file.read(data, length, data.length - length, length);
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    if (length !== stat.size) throw new Error("gate5-config-changed-while-reading");
    data = data.subarray(0, length);
  } finally { await file.close(); }
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("gate5-config-bom");
  return parseStrictJson(source);
}

async function main(): Promise<void> {
  const resource = process.argv[2];
  const mode = process.argv[3];
  const args = process.argv.slice(4);
  if (!(resources as readonly string[]).includes(resource) || (mode !== "preflight" && mode !== "deploy") ||
      args.length !== 2 || args[0] !== "--config" || !args[1] || args[1].startsWith("--"))
    throw new Error("explicit-resource-mode-and-rendered-config-required");
  const spec = resourceSpec[resource as Resource];
  const root = process.cwd();
  const pin = accountId();
  const configPath = await renderedConfigPath(root, spec, args[1]);
  const config = await readBoundedConfig(configPath);
  spec.validate(config);
  if ((config as Record<string, unknown>).account_id !== pin) throw new Error("gate5-account-pin-mismatch");
  const expectedMain = await realpath(join(root, ...spec.mainSegments));
  const resolvedMain = await realpath(resolve(dirname(configPath), "..", ...spec.mainSegments));
  if (resolvedMain !== expectedMain) throw new Error("gate5-main-mismatch");
  const wranglerBin = await realpath(join(root, "node_modules", "wrangler", "bin", "wrangler.js"));
  const wranglerArgv = ["deploy", "--config", configPath];
  const evidence = { resource, worker: spec.worker, config: configPath, accountFingerprint: fingerprint(pin), plannedCommand: ["wrangler", ...wranglerArgv] };
  if (mode === "preflight") {
    process.stdout.write(`${JSON.stringify({ status: "PASS", mode, ...evidence, providerContact: "none" })}\n`);
    return;
  }
  process.stderr.write(`Gate 5A deploy: invoking pinned Wrangler for ${resource} (account fingerprint ${evidence.accountFingerprint}).\n`);
  const result = spawnSync(process.execPath, [wranglerBin, ...wranglerArgv], { stdio: "inherit" });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
}

main().catch(() => { process.stderr.write("Gate 5A staging deploy: REFUSED (no Wrangler invocation occurred).\n"); process.exitCode = 2; });
