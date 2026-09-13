import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH } from "../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, signAuthorityInitializationCommand, type AuthorityInitializationCommand } from "../workers/admission-service/operator-command";

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

async function main() {
  const environment = argument("environment");
  const releaseId = argument("release-id") ?? "";
  const releaseKeyId = argument("release-key-id") ?? "";
  const expectedAuthority = argument("authority-id");
  const expectedEpoch = argument("policy-epoch");
  const confirmProduction = process.argv.includes("--confirm-production-authority-initialization");
  if ((environment !== "production" && environment !== "staging") || expectedAuthority !== ADMISSION_AUTHORITY_ID || expectedEpoch !== ADMISSION_POLICY_EPOCH ||
      environment === "production" && !confirmProduction) throw new Error("Refusing initialization arguments");
  const nowMs = Date.now();
  const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", environment, ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, releaseId, releaseKeyId, nowMs, confirmProduction];
  const privateKey = process.env.AUTHORITY_OPERATOR_PRIVATE_KEY;
  if (!privateKey) throw new Error("AUTHORITY_OPERATOR_PRIVATE_KEY is required in the operator process only");
  const signature = await signAuthorityInitializationCommand(command, privateKey);
  // This sealed request contains policy metadata and a signature, never the private key or any runtime secret.
  process.stdout.write(`${JSON.stringify({ command, signature })}\n`);
}

main().catch(() => { process.stderr.write("Authority initialization request was not created.\n"); process.exitCode = 1; });
