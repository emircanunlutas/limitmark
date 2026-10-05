import { homedir } from "node:os";
import { join } from "node:path";
import { STAGING_ATTESTATION_KEY_DIRECTORY_SEGMENTS } from "../operator/staging-attestation-key";
import { R06_RENDER_MODES, R06RenderError, renderR06Artifact } from "../operator/staging-r06-renderer";

// R06 activation (T2/T3): the canonical local procedure for rendering the two R06 activation artifacts from their committed templates
// (see operator/staging-r06-renderer.ts). Exactly one argument, a closed mode: staging-admission | staging-trust. There is no output
// path, key, account, Worker, bucket or cron argument; outputs are the exact deployment/ filenames and are never overwritten. No
// provider is contacted and no operator private key is read.

async function main(): Promise<void> {
  const mode = process.argv[2];
  if (process.argv.length !== 3 || !(R06_RENDER_MODES as readonly string[]).includes(mode)) throw new R06RenderError("explicit-r06-render-mode-required");
  const result = await renderR06Artifact({ mode, root: process.cwd(), keyDirectory: join(homedir(), ...STAGING_ATTESTATION_KEY_DIRECTORY_SEGMENTS), nowMs: Date.now() });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch((error: unknown) => {
  const code = error instanceof R06RenderError && /^[a-z0-9-]{1,80}$/u.test(error.code) ? error.code : "unexpected-failure";
  process.stderr.write(`R06 render: REFUSED (${code}). No file was written.\n`);
  process.exitCode = 2;
});
