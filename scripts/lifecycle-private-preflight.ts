import { readFile, realpath } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { parseStrictJson } from "../operator/lifecycle-submitter";
import {
  validateLifecycleMailboxConfig, validateLifecycleObserverConfig, validateLifecycleTransportManifest,
  validateStagingLifecycleMailboxConfig, validateStagingLifecycleObserverConfig, validateStagingLifecycleTransportManifest,
} from "../deployment/lifecycle-private-contract";

const modes = ["mailbox", "observer", "transport", "staging-mailbox", "staging-observer", "staging-transport"] as const;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length !== 3 || args[1] !== "--config" || !(modes as readonly string[]).includes(args[0]))
    throw new Error("explicit-lifecycle-config-required");
  const configPath = await realpath(resolve(args[2]));
  if (dirname(configPath) !== await realpath(join(process.cwd(), "deployment"))) throw new Error("config-location");
  const data = await readFile(configPath);
  if (!data.length || data.length > 16_384) throw new Error("config-size");
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("config-bom");
  const config = parseStrictJson(source);
  const mode = args[0];
  if (mode === "mailbox") validateLifecycleMailboxConfig(config, false);
  else if (mode === "observer") validateLifecycleObserverConfig(config, false);
  else if (mode === "transport") validateLifecycleTransportManifest(config, false);
  else if (mode === "staging-transport") validateStagingLifecycleTransportManifest(config, false);
  else {
    // Gate 2: report which of the two reviewed schedule states this rendered
    // config is in. Any other `triggers` shape fails closed.
    const scheduleState = mode === "staging-mailbox"
      ? validateStagingLifecycleMailboxConfig(config, false)
      : validateStagingLifecycleObserverConfig(config, false);
    process.stdout.write(`Private lifecycle contract preflight: PASS (local validation only). Schedule state: ${scheduleState}\n`);
    return;
  }
  process.stdout.write("Private lifecycle contract preflight: PASS (local validation only).\n");
}
main().catch(() => { process.stderr.write("Private lifecycle contract preflight: REFUSED.\n"); process.exitCode = 1; });
