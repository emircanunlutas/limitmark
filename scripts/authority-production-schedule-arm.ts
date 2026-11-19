import { createHash } from "node:crypto";
import { open, realpath, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import {
  validateLifecycleMailboxConfig, validateLifecycleObserverConfig,
  type ProductionScheduleState,
} from "../deployment/lifecycle-private-contract";
import { parseStrictJson } from "../operator/lifecycle-submitter";

// Production schedule-arming render. LOCAL ONLY: no provider contact, no Wrangler, no deployment, no Cron is activated by running this.
//
// Production mailbox/observer rollouts are INACTIVE by default (the tracked templates carry `crons: []`, and the production preflight modes
// `mailbox`/`observer` refuse any armed config). This is the one reviewed path from an inactive rendered config to an armed one, and it is a
// SEPARATE, explicitly authorized step: it requires the literal flag `--confirm-production-arm`, an exact `CLOUDFLARE_ACCOUNT_ID` pin, and it
// writes a distinct exact-named file. The target cron is not a parameter; it is the single constant below. Source and result are validated by
// the existing production contract validators (an already-armed or garbled source is refused). The destination is fixed here, never taken from
// argv, is git-ignored like the other rendered production configs, and is never overwritten. Deploying the armed file is a further step that this
// repository has no wrapper for and that needs its own authorization.

type Resource = "mailbox" | "observer";
const resources = ["mailbox", "observer"] as const;
const ARMED_TRIGGERS = { crons: ["* * * * *"] };

type ResourceSpec = {
  sourceName: string;
  destName: string;
  validate: (config: unknown, template: boolean, requireScheduleState?: ProductionScheduleState) => ProductionScheduleState;
};
const resourceSpec: Record<Resource, ResourceSpec> = {
  mailbox: { sourceName: "lifecycle-mailbox.production.jsonc", destName: "lifecycle-mailbox.production.armed.jsonc", validate: validateLifecycleMailboxConfig },
  observer: { sourceName: "lifecycle-observer.production.jsonc", destName: "lifecycle-observer.production.armed.jsonc", validate: validateLifecycleObserverConfig },
};

function fingerprint(accountId: string): string {
  return createHash("sha256").update(accountId).digest("hex").slice(0, 16);
}

function accountId(): string {
  const value = process.env.CLOUDFLARE_ACCOUNT_ID;
  if (typeof value !== "string" || !/^[a-f0-9]{32}$/u.test(value) || /^0{32}$/u.test(value)) throw new Error("missing-or-malformed-account-pin");
  return value;
}

async function readBoundedConfig(configPath: string): Promise<unknown> {
  const file = await open(configPath, "r");
  let data: Uint8Array;
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > 16_384) throw new Error("invalid-production-source-size");
    data = new Uint8Array(stat.size + 1);
    let length = 0;
    while (length < data.length) {
      const result = await file.read(data, length, data.length - length, length);
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    if (length !== stat.size) throw new Error("production-source-changed-while-reading");
    data = data.subarray(0, length);
  } finally { await file.close(); }
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("production-source-bom");
  return parseStrictJson(source);
}

async function main(): Promise<void> {
  const resource = process.argv[2];
  if (!(resources as readonly string[]).includes(resource) || process.argv.length !== 4 || process.argv[3] !== "--confirm-production-arm")
    throw new Error("explicit-resource-and-confirmation-required");
  const spec = resourceSpec[resource as Resource];
  const pin = accountId();
  const deploymentDir = await realpath(join(process.cwd(), "deployment"));

  const sourcePath = await realpath(join(deploymentDir, spec.sourceName));
  if (dirname(sourcePath) !== deploymentDir || basename(sourcePath) !== spec.sourceName) throw new Error("exact-production-inactive-rendered-config-required");
  const source = await readBoundedConfig(sourcePath);
  spec.validate(source, false, "PRODUCTION_DEPLOYMENT_INACTIVE");
  if (!source || typeof source !== "object" || Array.isArray(source)) throw new Error("unsafe-production-source-shape");
  if ((source as Record<string, unknown>).account_id !== pin) throw new Error("production-account-pin-mismatch");

  const armed: Record<string, unknown> = { ...(source as Record<string, unknown>), triggers: ARMED_TRIGGERS };
  spec.validate(armed, false, "PRODUCTION_SCHEDULE_ARMED");

  await writeFile(join(deploymentDir, spec.destName), JSON.stringify(armed), { flag: "wx" });
  process.stdout.write(`${JSON.stringify({
    status: "PASS", resource, source: sourcePath, dest: join(deploymentDir, spec.destName),
    scheduleState: "PRODUCTION_SCHEDULE_ARMED", accountFingerprint: fingerprint(pin), providerContact: "none", deployed: false,
  })}\n`);
}

main().catch((error: unknown) => {
  const code = typeof error === "object" && error && "code" in error && (error as NodeJS.ErrnoException).code === "EEXIST"
    ? "armed-config-already-exists (remove it first; this tool never overwrites)"
    : error instanceof Error ? error.message : "unknown";
  process.stderr.write(`Production schedule-arming render: REFUSED (${code}). No file was written.\n`);
  process.exitCode = 2;
});
