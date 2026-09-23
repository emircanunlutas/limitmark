import { basename, dirname, join, resolve } from "node:path";
import { readFile, realpath } from "node:fs/promises";
import { parseStrictJson } from "../operator/lifecycle-submitter";
import {
  validateLifecycleMailboxConfig, validateLifecycleObserverConfig, validateLifecycleTransportManifest,
  validateStagingLifecycleMailboxConfig, validateStagingLifecycleObserverConfig, validateStagingLifecycleTransportManifest,
} from "../deployment/lifecycle-private-contract";

const modes = ["mailbox", "observer", "transport", "staging-mailbox", "staging-observer", "staging-transport",
  "staging-mailbox-arm", "staging-observer-arm"] as const;
// Gate 5A closed the two reviewed Gate 5 rendered filenames. Gate 6A closes
// the third: staging-transport now also accepts only the exact reviewed
// rendered filename. Gate 7A adds the two ARMED modes: a distinct exact
// rendered filename per resource (produced only by
// scripts/authority-staging-gate7-arm.ts), requiring STAGING_SCHEDULE_ARMED
// rather than STAGING_DEPLOYMENT_INACTIVE. The existing staging-mailbox/
// staging-observer modes are unchanged by this addition -- they still require
// STAGING_DEPLOYMENT_INACTIVE and still refuse an armed config outright (see
// below), so an operator cannot satisfy Gate 5's inactive preflight with a
// Gate 7A armed file or vice versa. Production modes (mailbox/observer/
// transport) are still unchanged -- this repository has no reviewed
// deployment plan for them yet, so only directory placement is enforced for
// those.
const exactStagingRenderedConfigName: Partial<Record<(typeof modes)[number], string>> = {
  "staging-mailbox": "lifecycle-mailbox.staging.jsonc",
  "staging-observer": "lifecycle-observer.staging.jsonc",
  "staging-transport": "lifecycle-transport.staging.json",
  "staging-mailbox-arm": "lifecycle-mailbox.staging.armed.jsonc",
  "staging-observer-arm": "lifecycle-observer.staging.armed.jsonc",
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
    // Gate 7A: the two "-arm" modes are the mirror image -- they require
    // STAGING_SCHEDULE_ARMED and refuse an inactive (or any other) shape.
    const requireScheduleState = mode.endsWith("-arm") ? "STAGING_SCHEDULE_ARMED" : "STAGING_DEPLOYMENT_INACTIVE";
    if (mode === "staging-mailbox" || mode === "staging-mailbox-arm") validateStagingLifecycleMailboxConfig(config, false, requireScheduleState);
    else validateStagingLifecycleObserverConfig(config, false, requireScheduleState);
    process.stdout.write(`Private lifecycle contract preflight: PASS (local validation only). Schedule state: ${requireScheduleState}\n`);
    return;
  }
  process.stdout.write("Private lifecycle contract preflight: PASS (local validation only).\n");
}
main().catch(() => { process.stderr.write("Private lifecycle contract preflight: REFUSED.\n"); process.exitCode = 1; });
