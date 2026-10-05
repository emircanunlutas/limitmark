import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { STAGING_ATTESTATION_KEY_DIRECTORY_SEGMENTS } from "./staging-attestation-key";
import {
  ATTESTATION_SECRET_ORDER, ATTESTATION_SECRET_WORKER, AttestationSecretError, createAttestationSecretTooling,
  type AttestationSecretDescription, type AttestationSecretInput, type AttestationSecretSubmission,
} from "./staging-attestation-secret-engine";
import { STAGING_RENDER_PINS } from "./staging-config-renderer";

// R06 activation tooling: the PRODUCTION binding of the closed-set attestation-secret engine (operator/staging-attestation-secret-engine.ts).
// It provisions the three staging Authority-attestation bindings on the staging admission Worker through exactly one argv shape,
//
//     <pinned local wrangler.js> secret put <ONE OF THE THREE REVIEWED NAMES> --name limitmark-admission-service-staging
//
// with the value on stdin, private key LAST, so the private key never exists on the Worker without its pin and any partial set yields
// "no signer" (fail-closed; workers/admission-service/authority-attestation-config.ts).
//
// Everything that decides what is spawned is FIXED HERE, not chosen by a caller:
//   - the repository root is derived from THIS module's own location (operator/ -> repository root), never from the working directory or an argument;
//   - the account pin is STAGING_RENDER_PINS; the key directory is the operator's %USERPROFILE%/.limitmark-keys/staging; the clock is Date.now();
//   - the Worker name, the three secret names, their order and the Wrangler executable are literals/derivations inside the engine.
// The two exported functions take only an environment. There is no plan object to build, edit or pass in, so no caller can substitute a
// root, Worker, order, secret name or executable. `submitAttestationSecrets` is the provider mutation reserved for the explicit activation
// gate; its only caller is scripts/authority-staging-attestation-secret.ts (pinned structurally by tests/r06-activation-capability-guard.test.ts; the hygiene test is only a textual tripwire).

const tooling = createAttestationSecretTooling({
  root: dirname(dirname(fileURLToPath(import.meta.url))),
  pins: STAGING_RENDER_PINS,
  keyDirectory: () => join(homedir(), ...STAGING_ATTESTATION_KEY_DIRECTORY_SEGMENTS),
  clock: () => Date.now(),
});

export { ATTESTATION_SECRET_ORDER, ATTESTATION_SECRET_WORKER, AttestationSecretError };
export type { AttestationSecretDescription, AttestationSecretInput, AttestationSecretSubmission };

/** Every local check and the public description of what `submit` would do. Never spawns. */
export const preflightAttestationSecrets = (input: AttestationSecretInput): Promise<AttestationSecretDescription> => tooling.preflight(input);

/** The provider mutation: re-derives the whole closed plan, then runs the pinned Wrangler once per name. Success is not provider evidence. */
export const submitAttestationSecrets = (input: AttestationSecretInput): Promise<AttestationSecretSubmission> => tooling.submit(input);
