import { STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH } from "../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, signAuthorityInitializationCommand, type AuthorityInitializationCommand } from "../workers/admission-service/operator-command";

// Gate 2 staging capability. Unlike scripts/authority-initialize.ts this script
// has no `--environment` flag at all: it can only ever prepare a staging
// initialization command, using its own distinct authority identity and its
// own distinct offline signing key (AUTHORITY_STAGING_OPERATOR_PRIVATE_KEY).
// There is deliberately no staging rotation preparation script anywhere in
// this repository (STAGING ROTATION — NOT IMPLEMENTED / GATE 9 — CLOSED).

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

async function main() {
  const releaseId = argument("release-id") ?? "";
  const releaseKeyId = argument("release-key-id") ?? "";
  const expectedAuthority = argument("authority-id");
  const expectedEpoch = argument("policy-epoch");
  if (expectedAuthority !== STAGING_ADMISSION_AUTHORITY_ID || expectedEpoch !== ADMISSION_POLICY_EPOCH ||
      !process.argv.includes("--confirm-staging-authority-initialization")) throw new Error("Refusing staging initialization arguments");
  const nowMs = Date.now();
  const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging", STAGING_ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, releaseId, releaseKeyId, nowMs, false];
  const privateKey = process.env.AUTHORITY_STAGING_OPERATOR_PRIVATE_KEY;
  if (!privateKey) throw new Error("AUTHORITY_STAGING_OPERATOR_PRIVATE_KEY is required in the operator process only");
  const signature = await signAuthorityInitializationCommand(command, privateKey);
  // This sealed request contains policy metadata and a signature, never the private key or any runtime secret.
  process.stdout.write(`${JSON.stringify({ command, signature })}\n`);
}

main().catch(() => { process.stderr.write("Staging authority initialization request was not created.\n"); process.exitCode = 1; });
