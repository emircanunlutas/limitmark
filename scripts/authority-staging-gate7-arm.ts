import { createHash } from "node:crypto";
import { open, realpath, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import {
  validateStagingLifecycleMailboxConfig, validateStagingLifecycleObserverConfig,
  type StagingScheduleState,
} from "../deployment/lifecycle-private-contract";
import { parseStrictJson } from "../operator/lifecycle-submitter";

// Gate 7A schedule-arming render. Local-only, deterministic, no provider
// contact: reads the exact reviewed Gate 5 STAGING_DEPLOYMENT_INACTIVE
// rendered config for one resource ("mailbox" or "observer") and writes a
// second, separate, exact-named rendered file that is identical in every
// field except `triggers`, which becomes the one reviewed armed shape
// (`{ crons: ["* * * * *"] }`) -- the same literal already recognized by
// deployment/lifecycle-private-contract.ts's STAGING_SCHEDULE_ARMED state.
// There is no CLI-provided cron: the target shape is not a parameter, it is
// the one constant this file contains. The operator never hand-edits JSON --
// this transform is the only reviewed path from an inactive rendered config
// to an armed one. Both the source and the produced file are validated
// against the exact, existing contract validators (fail closed on any
// unexpected shape, including an already-armed or garbled source); the
// destination path is fixed by this script, never by argv, and is a third
// exact rendered filename, distinct from the Gate 5 inactive one, git-ignored
// like the other rendered staging configs. This script never overwrites an
// existing armed file and never spawns Wrangler or contacts Cloudflare --
// only scripts/authority-staging-gate7-deploy.ts (a separate, later step)
// does that, and only after its own independent validation.

type Resource = "mailbox" | "observer";
const resources = ["mailbox", "observer"] as const;

type ResourceSpec = {
  sourceName: string;
  destName: string;
  validate: (config: unknown, template: boolean, requireScheduleState?: StagingScheduleState) => StagingScheduleState;
};
const resourceSpec: Record<Resource, ResourceSpec> = {
  mailbox: { sourceName: "lifecycle-mailbox.staging.jsonc", destName: "lifecycle-mailbox.staging.armed.jsonc", validate: validateStagingLifecycleMailboxConfig },
  observer: { sourceName: "lifecycle-observer.staging.jsonc", destName: "lifecycle-observer.staging.armed.jsonc", validate: validateStagingLifecycleObserverConfig },
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

async function readBoundedConfig(configPath: string): Promise<unknown> {
  const file = await open(configPath, "r");
  let data: Uint8Array;
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > 16_384) throw new Error("invalid-gate7-source-size");
    data = new Uint8Array(stat.size + 1);
    let length = 0;
    while (length < data.length) {
      const result = await file.read(data, length, data.length - length, length);
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    if (length !== stat.size) throw new Error("gate7-source-changed-while-reading");
    data = data.subarray(0, length);
  } finally { await file.close(); }
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("gate7-source-bom");
  return parseStrictJson(source);
}

async function main(): Promise<void> {
  const resource = process.argv[2];
  if (!(resources as readonly string[]).includes(resource) || process.argv.length !== 3)
    throw new Error("explicit-resource-required");
  const spec = resourceSpec[resource as Resource];
  const root = process.cwd();
  const pin = accountId();
  const deploymentDir = await realpath(join(root, "deployment"));

  const sourcePath = await realpath(join(deploymentDir, spec.sourceName));
  if (dirname(sourcePath) !== deploymentDir || basename(sourcePath) !== spec.sourceName)
    throw new Error("exact-staging-gate5-rendered-config-required");
  const source = await readBoundedConfig(sourcePath);
  spec.validate(source, false, "STAGING_DEPLOYMENT_INACTIVE");
  if (!source || typeof source !== "object" || Array.isArray(source)) throw new Error("unsafe-gate7-source-shape");
  if ((source as Record<string, unknown>).account_id !== pin) throw new Error("gate7-account-pin-mismatch");

  const armed: Record<string, unknown> = { ...(source as Record<string, unknown>), triggers: { crons: ["* * * * *"] } };
  spec.validate(armed, false, "STAGING_SCHEDULE_ARMED");

  const destPath = join(deploymentDir, spec.destName);
  await writeFile(destPath, JSON.stringify(armed), { flag: "wx" });

  process.stdout.write(`${JSON.stringify({
    status: "PASS", resource, source: sourcePath, dest: destPath,
    scheduleState: "STAGING_SCHEDULE_ARMED", accountFingerprint: fingerprint(pin), providerContact: "none",
  })}\n`);
}

main().catch((error: unknown) => {
  const code = typeof error === "object" && error && "code" in error && (error as NodeJS.ErrnoException).code === "EEXIST"
    ? "armed-config-already-exists (remove it first; this tool never overwrites)"
    : error instanceof Error ? error.message : "unknown";
  process.stderr.write(`Gate 7A schedule-arming render: REFUSED (${code}). No file was written.\n`);
  process.exitCode = 2;
});
