import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { open, realpath } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { validateStagingLifecycleMailboxConfig, validateStagingLifecycleObserverConfig } from "../deployment/lifecycle-private-contract";
import { parseStrictJson } from "../operator/lifecycle-submitter";

// Gate 7A deploy wrapper. A separate file from scripts/authority-staging-
// gate5-deploy.ts by design, so Gate 5's inactive-only deploy surface is
// provably unchanged (it is not imported, referenced or modified by this
// file): this wrapper's entire purpose is the opposite requirement -- deploy
// the mailbox/observer Worker with the reviewed ARMED schedule -- and mixing
// the two into one mode-selectable tool would recreate exactly the generic
// schedule-state argument F2 rules out. Only two resources exist here
// ("mailbox-arm"/"observer-arm"); there is no "executor-arm" because the
// executor config carries no `triggers` member at all. Each hardcodes its own
// exact Worker name, exact rendered filename (the Gate 7A *.armed.jsonc file
// produced only by scripts/authority-staging-gate7-arm.ts) and exact
// validator, pinned to requireScheduleState="STAGING_SCHEDULE_ARMED" -- an
// inactive config, or any `triggers` shape other than the two reviewed ones,
// is refused before any spawn. It never adds account_id to any config; it
// requires CLOUDFLARE_ACCOUNT_ID in the process environment (never a CLI
// flag, never logged -- only a one-way SHA-256 fingerprint, truncated to 16
// hex characters, is ever printed) and lets Wrangler consume it directly.
// Mode "preflight" performs every non-provider check and prints the exact
// command that would run without spawning Wrangler; mode "deploy" performs
// the identical checks and then, only then, spawns the repository-pinned
// local Wrangler binary with exactly `deploy --config <path>` -- no --env,
// --route, --var, binding/domain override, alternate name, alternate config
// or --cron is constructible. Refusal always happens before any spawn. This
// wrapper deploys exactly ONE Worker per invocation; there is no "deploy
// both" mode.

type Resource = "mailbox-arm" | "observer-arm";
const resources = ["mailbox-arm", "observer-arm"] as const;

type ResourceSpec = { worker: string; configName: string; mainSegments: readonly string[]; validate: (config: unknown) => void };
const resourceSpec: Record<Resource, ResourceSpec> = {
  "mailbox-arm": {
    worker: "limitmark-lifecycle-mailbox-staging",
    configName: "lifecycle-mailbox.staging.armed.jsonc",
    mainSegments: ["workers", "lifecycle-mailbox", "staging-index.ts"],
    validate: (config) => { validateStagingLifecycleMailboxConfig(config, false, "STAGING_SCHEDULE_ARMED"); },
  },
  "observer-arm": {
    worker: "limitmark-lifecycle-observer-staging",
    configName: "lifecycle-observer.staging.armed.jsonc",
    mainSegments: ["workers", "staging-lifecycle-observer.ts"],
    validate: (config) => { validateStagingLifecycleObserverConfig(config, false, "STAGING_SCHEDULE_ARMED"); },
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
    throw new Error("exact-staging-gate7-armed-rendered-config-required");
  return configPath;
}

async function readBoundedConfig(configPath: string): Promise<unknown> {
  const file = await open(configPath, "r");
  let data: Uint8Array;
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > 16_384) throw new Error("invalid-gate7-config-size");
    data = new Uint8Array(stat.size + 1);
    let length = 0;
    while (length < data.length) {
      const result = await file.read(data, length, data.length - length, length);
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    if (length !== stat.size) throw new Error("gate7-config-changed-while-reading");
    data = data.subarray(0, length);
  } finally { await file.close(); }
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("gate7-config-bom");
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
  const expectedMain = await realpath(join(root, ...spec.mainSegments));
  const resolvedMain = await realpath(resolve(dirname(configPath), "..", ...spec.mainSegments));
  if (resolvedMain !== expectedMain) throw new Error("gate7-main-mismatch");
  const wranglerBin = await realpath(join(root, "node_modules", "wrangler", "bin", "wrangler.js"));
  const wranglerArgv = ["deploy", "--config", configPath];
  const evidence = { resource, worker: spec.worker, config: configPath, accountFingerprint: fingerprint(pin), plannedCommand: ["wrangler", ...wranglerArgv] };
  if (mode === "preflight") {
    process.stdout.write(`${JSON.stringify({ status: "PASS", mode, ...evidence, providerContact: "none" })}\n`);
    return;
  }
  process.stderr.write(`Gate 7A deploy: invoking pinned Wrangler for ${resource} (account fingerprint ${evidence.accountFingerprint}).\n`);
  const result = spawnSync(process.execPath, [wranglerBin, ...wranglerArgv], { stdio: "inherit" });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
}

main().catch(() => { process.stderr.write("Gate 7A staging deploy: REFUSED (no Wrangler invocation occurred).\n"); process.exitCode = 2; });
