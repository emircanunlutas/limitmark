import { basename, dirname, join, resolve } from "node:path";
import { readFile, realpath } from "node:fs/promises";
import { parseStrictJson } from "../operator/lifecycle-submitter";
import { validateRecoveryEvidencePosture } from "../deployment/lifecycle-private-contract";

// LOCAL validation only (no network, no Wrangler, no provider contact): the two rendered configs of the recovery-evidence posture.
//   tsx scripts/lifecycle-recovery-posture.ts --observer deployment/lifecycle-observer.production.armed.jsonc --mailbox deployment/lifecycle-mailbox.production.jsonc
async function load(path: string, exactName?: string): Promise<unknown> {
  const real = await realpath(resolve(path));
  if (dirname(real) !== await realpath(join(process.cwd(), "deployment")) || (exactName !== undefined && basename(real) !== exactName)) throw new Error("config-location");
  const data = await readFile(real);
  if (!data.length || data.length > 16_384) throw new Error("config-size");
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("config-bom");
  return parseStrictJson(source);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== "--observer" || args[2] !== "--mailbox") throw new Error("explicit-recovery-posture-configs-required");
  const observer = await load(args[1], "lifecycle-observer.production.armed.jsonc");
  // The mailbox must NOT be the armed file: its exact armed rendered name is refused here, and its schedule is validated to be inactive.
  if (basename(args[3]) === "lifecycle-mailbox.production.armed.jsonc") throw new Error("config-location");
  const mailbox = await load(args[3]);
  validateRecoveryEvidencePosture(observer, mailbox, false);
  process.stdout.write("Recovery-evidence posture: PASS (local validation only). Observer: PRODUCTION_SCHEDULE_ARMED. Mailbox: PRODUCTION_DEPLOYMENT_INACTIVE.\n");
}

main().catch((error) => {
  process.stderr.write(`Recovery-evidence posture: REFUSED (${error instanceof Error ? error.message : "unreadable"}). Nothing was changed.\n`);
  process.exitCode = 2;
});
