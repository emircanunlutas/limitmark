import { LAB_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH } from "../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, signAuthorityInitializationCommand, type AuthorityInitializationCommand } from "../workers/admission-service/operator-command";

// Lab environment. Like scripts/authority-staging-initialize.ts this tool has no --environment flag: it can only ever prepare a LAB
// initialization command, for the distinct lab authority identity, signed with the distinct lab operator key
// (AUTHORITY_LAB_OPERATOR_PRIVATE_KEY, never AUTHORITY_OPERATOR_PRIVATE_KEY). The command carries confirmProduction=false, which the
// lab Authority requires and the Production Authority rejects. There is no lab rotation tool (lab rotation is not implemented).

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

async function main() {
  const releaseId = argument("release-id") ?? "";
  const releaseKeyId = argument("release-key-id") ?? "";
  if (argument("authority-id") !== LAB_ADMISSION_AUTHORITY_ID || argument("policy-epoch") !== ADMISSION_POLICY_EPOCH ||
      !process.argv.includes("--confirm-lab-authority-initialization")) throw new Error("Refusing lab initialization arguments");
  const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "lab", LAB_ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, releaseId, releaseKeyId, Date.now(), false];
  const privateKey = process.env.AUTHORITY_LAB_OPERATOR_PRIVATE_KEY;
  if (!privateKey) throw new Error("AUTHORITY_LAB_OPERATOR_PRIVATE_KEY is required in the operator process only");
  const signature = await signAuthorityInitializationCommand(command, privateKey);
  // This sealed request contains policy metadata and a signature, never the private key or any runtime secret.
  process.stdout.write(`${JSON.stringify({ command, signature })}\n`);
}

main().catch(() => { process.stderr.write("Lab authority initialization request was not created.\n"); process.exitCode = 1; });
