import { AttestationKeyError } from "../operator/staging-attestation-key";
import { AttestationSecretError, preflightAttestationSecrets, submitAttestationSecrets } from "../operator/staging-attestation-secret";

// R06 activation (T1): the closed-set CLI over operator/staging-attestation-secret.ts, which provisions the three staging
// Authority-attestation bindings on the staging admission Worker -- exactly `wrangler secret put <NAME> --name
// limitmark-admission-service-staging` with the value on stdin, three reviewed names, fixed order, private key last. The argument
// surface is closed: `preflight` (no arguments) or `put --confirm-staging`.
//
// The CLI chooses NOTHING about what is spawned: the root, account pin, key directory, Worker, names, order and executable are fixed inside
// the module; the only input is the process environment, which the module reduces to a minimal explicit child environment (or refuses).
// `preflight` performs every local check and prints the plan without ever spawning Wrangler. `put` performs the identical checks, re-derives
// them, and then, only then, spawns the repository-pinned local Wrangler binary, stopping at the first failure. Success output is NOT
// evidence of provider state: verify with the name-only `wrangler secret list` in the runbook. `put` is a provider mutation reserved for
// the explicit activation gate; this wrapper authorizes nothing by existing.

async function main(): Promise<void> {
  const mode = process.argv[2];
  const args = process.argv.slice(3);
  if (mode === "preflight" ? args.length !== 0 : mode === "put" ? args.length !== 1 || args[0] !== "--confirm-staging" : true)
    throw new AttestationSecretError("explicit-mode-required");
  const evidence = await preflightAttestationSecrets({ env: process.env });
  if (mode === "preflight") {
    process.stdout.write(`${JSON.stringify({ status: "PASS", mode, ...evidence, providerContact: "none" })}\n`);
    return;
  }
  process.stderr.write(`R06 attestation secrets: invoking pinned Wrangler for ${evidence.plannedSecretNames.length} secrets (account fingerprint ${evidence.accountFingerprint}).\n`);
  const result = await submitAttestationSecrets({ env: process.env });
  if (result.stoppedAt !== null) {
    process.stderr.write(`R06 attestation secrets: STOPPED at ${result.stoppedAt}; submitted before it: [${result.submitted.join(", ")}]. Nothing further was attempted. ` +
      "Inspect the name-only secret list before any retry; do not assume a partial state.\n");
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`${JSON.stringify({ status: "SUBMITTED", mode, submittedSecretNames: result.submitted,
    note: "not provider evidence; verify with the name-only secret list", providerContact: "wrangler-secret-put" })}\n`);
}

main().catch((error: unknown) => {
  const code = error instanceof AttestationSecretError || error instanceof AttestationKeyError ? error.code : "unexpected-failure";
  process.stderr.write(`R06 attestation secrets: REFUSED (${/^[a-z0-9-]{1,80}$/u.test(code) ? code : "unexpected-failure"}). No Wrangler invocation occurred.\n`);
  process.exitCode = 2;
});
