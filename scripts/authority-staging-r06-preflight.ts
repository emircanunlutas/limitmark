import { homedir } from "node:os";
import { join } from "node:path";
import { STAGING_ATTESTATION_KEY_DIRECTORY_SEGMENTS } from "../operator/staging-attestation-key";
import { R06PreflightError, defaultGit, runR06ActivationPreflight } from "../operator/staging-r06-preflight";

// R06 activation (T4): the composite LOCAL preflight (see operator/staging-r06-preflight.ts). The only argument is the reviewed commit,
// `--expected-head <40-hex>`, supplied by the operator from the independent review. It reads local files and runs read-only `git`; it
// never spawns Wrangler, never contacts a provider and AUTHORIZES NOTHING.

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== "--expected-head") throw new R06PreflightError("expected-head-argument-required");
  const root = process.cwd();
  const result = await runR06ActivationPreflight({
    root, expectedHead: args[1], env: process.env, keyDirectory: join(homedir(), ...STAGING_ATTESTATION_KEY_DIRECTORY_SEGMENTS),
    nowMs: Date.now(), git: defaultGit(root),
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch((error: unknown) => {
  const code = error instanceof R06PreflightError && /^[a-z0-9-]{1,80}$/u.test(error.code) ? error.code : "unexpected-failure";
  process.stderr.write(`R06 activation preflight: REFUSED (${code}). Nothing was started and no provider was contacted.\n`);
  process.exitCode = 2;
});
