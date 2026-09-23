import { homedir } from "node:os";
import { join } from "node:path";
import { STAGING_RENDER_MODES, STAGING_RENDER_PINS, StagingRenderError, renderStagingConfig } from "../operator/staging-config-renderer";

// Gate 7C: the canonical local procedure for reconstructing a rendered
// staging config from its committed template (see
// operator/staging-config-renderer.ts). Exactly one argument, a closed mode:
// staging-transport | staging-mailbox | staging-observer. There is no output
// path, environment, account, key, Worker name, bucket or cron argument; the
// output is always the exact rendered filename under ./deployment, the
// account comes only from CLOUDFLARE_ACCOUNT_ID, and the key is always the
// existing protected staging PKCS8 file below. Existing outputs are never
// overwritten. No provider is contacted and no key is ever generated.

const STAGING_KEY_PATH_SEGMENTS = [".limitmark-keys", "staging", "staging-operator-private-key.pkcs8.b64url"] as const;

async function main(): Promise<void> {
  const mode = process.argv[2];
  if (process.argv.length !== 3 || !(STAGING_RENDER_MODES as readonly string[]).includes(mode))
    throw new StagingRenderError("explicit-staging-render-mode-required");
  const result = await renderStagingConfig({
    mode, root: process.cwd(), keyPath: join(homedir(), ...STAGING_KEY_PATH_SEGMENTS),
    accountId: process.env.CLOUDFLARE_ACCOUNT_ID, pins: STAGING_RENDER_PINS,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch((error: unknown) => {
  const code = error instanceof StagingRenderError && /^[a-z0-9-]{1,80}$/u.test(error.code) ? error.code : "unexpected-failure";
  process.stderr.write(`Staging config render: REFUSED (${code}). No file was written.\n`);
  process.exitCode = 2;
});
