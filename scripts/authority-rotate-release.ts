import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH } from "../workers/admission-service/authority";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION,
  signAuthorityReleaseRotationCommand,
  type AuthorityReleaseRotationCommand,
} from "../workers/admission-service/operator-command";

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function exactTime(name: string): number {
  const value = argument(name) ?? "";
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value)) throw new Error("Refusing rotation time");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error("Refusing rotation time");
  return parsed;
}

async function main() {
  if (argument("environment") !== "production" || argument("authority-id") !== ADMISSION_AUTHORITY_ID ||
      argument("policy-epoch") !== ADMISSION_POLICY_EPOCH || !process.argv.includes("--confirm-production-authority-rotation")) {
    throw new Error("Refusing rotation arguments");
  }
  const activatesAtMs = exactTime("activates-at-ms");
  const previousRetiresAtMs = exactTime("previous-retires-at-ms");
  const issuedAtMs = Date.now();
  const command: AuthorityReleaseRotationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production",
    ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, argument("current-release-id") ?? "", argument("next-release-id") ?? "",
    argument("next-release-key-id") ?? "", activatesAtMs, previousRetiresAtMs, issuedAtMs, true];
  const privateKey = process.env.AUTHORITY_OPERATOR_PRIVATE_KEY;
  if (!privateKey) throw new Error("AUTHORITY_OPERATOR_PRIVATE_KEY is required in the operator process only");
  const signature = await signAuthorityReleaseRotationCommand(command, privateKey);
  process.stdout.write(`${JSON.stringify({ command, signature })}\n`);
}

main().catch(() => { process.stderr.write("Authority release-rotation request was not created.\n"); process.exitCode = 1; });
