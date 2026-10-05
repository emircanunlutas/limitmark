import { homedir } from "node:os";
import { join } from "node:path";
import {
  AttestationKeyError, STAGING_ATTESTATION_KEY_DIRECTORY_SEGMENTS, STAGING_ATTESTATION_KEY_FILE, STAGING_ATTESTATION_META_FILE,
  generateStagingAttestationKey,
} from "../operator/staging-attestation-key";

// R06 activation (T1): generate the staging Authority-attestation signing key into the operator's protected key directory
// (%USERPROFILE%/.limitmark-keys/staging, outside the repository, which must already exist). No arguments: the destination is fixed, an
// existing custody file is never overwritten, the key is never printed, and no provider is contacted. It prints only public facts.

async function main(): Promise<void> {
  if (process.argv.length !== 2) throw new AttestationKeyError("no-arguments-accepted");
  const result = await generateStagingAttestationKey({
    directory: join(homedir(), ...STAGING_ATTESTATION_KEY_DIRECTORY_SEGMENTS), repositoryRoot: process.cwd(), nowMs: Date.now(),
  });
  process.stdout.write(`${JSON.stringify({ status: "GENERATED", environment: "staging", keyFingerprint: result.keyFingerprint, publicKey: result.publicKey,
    createdAtMs: result.createdAtMs, custodyFiles: [STAGING_ATTESTATION_KEY_FILE, STAGING_ATTESTATION_META_FILE], providerContact: "none" })}\n`);
}

main().catch((error: unknown) => {
  const code = error instanceof AttestationKeyError && /^[a-z0-9-]{1,80}$/u.test(error.code) ? error.code : "unexpected-failure";
  process.stderr.write(`Staging attestation key generation: REFUSED (${code}). No key was written.\n`);
  process.exitCode = 2;
});
