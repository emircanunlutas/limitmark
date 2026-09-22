import { basename, dirname, join, resolve } from "node:path";
import { readFile, realpath } from "node:fs/promises";
import { parseStrictJson } from "../operator/lifecycle-submitter";
import {
  validateLifecycleMailboxConfig, validateLifecycleObserverConfig, validateLifecycleTransportManifest,
  validateStagingLifecycleMailboxConfig, validateStagingLifecycleObserverConfig, validateStagingLifecycleTransportManifest,
} from "../deployment/lifecycle-private-contract";

const modes = ["mailbox", "observer", "transport", "staging-mailbox", "staging-observer", "staging-transport"] as const;
// Gate 5A: the two reviewed Gate 5 rendered filenames. Production modes and
// staging-transport are unchanged -- this repository has no reviewed
// deployment plan for them yet, so only directory placement is enforced for
// those, exactly as before.
const exactStagingRenderedConfigName: Partial<Record<(typeof modes)[number], string>> = {
  "staging-mailbox": "lifecycle-mailbox.staging.jsonc",
  "staging-observer": "lifecycle-observer.staging.jsonc",
};

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length !== 3 || args[1] !== "--config" || !(modes as readonly string[]).includes(args[0]))
    throw new Error("explicit-lifecycle-config-required");
  const mode = args[0] as (typeof modes)[number];
  const configPath = await realpath(resolve(args[2]));
  const exactName = exactStagingRenderedConfigName[mode];
  if (dirname(configPath) !== await realpath(join(process.cwd(), "deployment")) ||
      (exactName !== undefined && basename(configPath) !== exactName))
    throw new Error("config-location");
  const data = await readFile(configPath);
  if (!data.length || data.length > 16_384) throw new Error("config-size");
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("config-bom");
  const config = parseStrictJson(source);
  if (mode === "mailbox") validateLifecycleMailboxConfig(config, false);
  else if (mode === "observer") validateLifecycleObserverConfig(config, false);
  else if (mode === "transport") validateLifecycleTransportManifest(config, false);
  else if (mode === "staging-transport") validateStagingLifecycleTransportManifest(config, false);
  else {
    // Gate 5A: Gate 5 deployment must only ever render/preflight the inactive
    // schedule state; a rendered config carrying an active Cron, or any
    // other `triggers` shape, is refused here rather than merely reported.
    if (mode === "staging-mailbox") validateStagingLifecycleMailboxConfig(config, false, "STAGING_DEPLOYMENT_INACTIVE");
    else validateStagingLifecycleObserverConfig(config, false, "STAGING_DEPLOYMENT_INACTIVE");
    process.stdout.write("Private lifecycle contract preflight: PASS (local validation only). Schedule state: STAGING_DEPLOYMENT_INACTIVE\n");
    return;
  }
  process.stdout.write("Private lifecycle contract preflight: PASS (local validation only).\n");
}
main().catch(() => { process.stderr.write("Private lifecycle contract preflight: REFUSED.\n"); process.exitCode = 1; });
