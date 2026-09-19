import { readFile, realpath } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { parseStrictJson } from "../operator/lifecycle-submitter";
import { validateLifecycleMailboxConfig, validateLifecycleObserverConfig, validateLifecycleTransportManifest } from "../deployment/lifecycle-private-contract";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length !== 3 || args[1] !== "--config" || !["mailbox", "observer", "transport"].includes(args[0]))
    throw new Error("explicit-lifecycle-config-required");
  const configPath = await realpath(resolve(args[2]));
  if (dirname(configPath) !== await realpath(join(process.cwd(), "deployment"))) throw new Error("config-location");
  const data = await readFile(configPath);
  if (!data.length || data.length > 16_384) throw new Error("config-size");
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("config-bom");
  const config = parseStrictJson(source);
  if (args[0] === "mailbox") validateLifecycleMailboxConfig(config, false);
  else if (args[0] === "observer") validateLifecycleObserverConfig(config, false);
  else validateLifecycleTransportManifest(config, false);
  process.stdout.write("Private lifecycle contract preflight: PASS (local validation only).\n");
}
main().catch(() => { process.stderr.write("Private lifecycle contract preflight: REFUSED.\n"); process.exitCode = 1; });
