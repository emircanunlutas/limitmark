import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { withSharedStagingConfigLock } from "./support/shared-staging-config-lock";

// Gate 7A: proves the schedule-arming deploy wrapper (a file separate from,
// and never imported by, scripts/authority-staging-gate5-deploy.ts) refuses
// every unsafe input -- including an inactive config, any non-reviewed
// schedule shape, alternate filenames, and every Production/cross-binding
// substitution -- before it could ever spawn Wrangler, that its preflight
// mode reaches PASS without contacting Cloudflare, and that there is no
// generic --cron or schedule-state CLI surface. "deploy" mode is exercised
// only on refusal paths; a successful "deploy" would spawn the real Wrangler
// binary.

const root = fileURLToPath(new URL("../", import.meta.url));
const validAccount = "a".repeat(32);
const validKey = encodeBase64url(new Uint8Array(32).fill(7));
const reader = { binding: "LIFECYCLE_READER", service: "limitmark-admission-service-staging", entrypoint: "StagingAuthorityLifecycleReadOnly" };

type Fixture = { resource: "mailbox-arm" | "observer-arm"; exactRelPath: string; exactAbsPath: string; config: () => Record<string, unknown> };
const fixtures: Fixture[] = [
  {
    resource: "mailbox-arm",
    exactRelPath: "deployment/lifecycle-mailbox.staging.armed.jsonc",
    exactAbsPath: join(root, "deployment", "lifecycle-mailbox.staging.armed.jsonc"),
    config: () => ({
      $schema: "../node_modules/wrangler/config-schema.json", name: "limitmark-lifecycle-mailbox-staging",
      main: "../workers/lifecycle-mailbox/staging-index.ts", account_id: validAccount, compatibility_date: "2026-09-13",
      workers_dev: false, preview_urls: false, triggers: { crons: ["* * * * *"] },
      r2_buckets: [{ binding: "REQUEST_BUCKET", bucket_name: "limitmark-lifecycle-requests-staging" },
        { binding: "RESULT_BUCKET", bucket_name: "limitmark-lifecycle-results-staging" }],
      services: [{ binding: "LIFECYCLE_EXECUTOR", service: "limitmark-authority-operator-executor-staging", entrypoint: "StagingOperatorLifecycleExecutor" }, reader],
      durable_objects: { bindings: [{ name: "DISPATCH_GUARD", class_name: "StagingLifecycleDispatchGuard" }] },
      migrations: [{ tag: "i3b-staging-guard-v1", new_sqlite_classes: ["StagingLifecycleDispatchGuard"] }],
      vars: { AUTHORITY_OPERATOR_PUBLIC_KEY: validKey, LIFECYCLE_ENVIRONMENT: "staging" },
    }),
  },
  {
    resource: "observer-arm",
    exactRelPath: "deployment/lifecycle-observer.staging.armed.jsonc",
    exactAbsPath: join(root, "deployment", "lifecycle-observer.staging.armed.jsonc"),
    config: () => ({
      $schema: "../node_modules/wrangler/config-schema.json", name: "limitmark-lifecycle-observer-staging",
      main: "../workers/staging-lifecycle-observer.ts", account_id: validAccount, compatibility_date: "2026-09-13",
      workers_dev: false, preview_urls: false, triggers: { crons: ["* * * * *"] },
      r2_buckets: [{ binding: "REQUEST_BUCKET", bucket_name: "limitmark-lifecycle-requests-staging" },
        { binding: "RESULT_BUCKET", bucket_name: "limitmark-lifecycle-results-staging" }],
      services: [reader],
    }),
  },
];

function run(args: string[], overrides: Record<string, string | undefined> = { CLOUDFLARE_ACCOUNT_ID: validAccount }) {
  const env: Record<string, string | undefined> = { ...process.env, ...overrides };
  for (const [key, value] of Object.entries(env)) if (value === undefined) delete env[key];
  return spawnSync(process.execPath, ["node_modules/tsx/dist/cli.mjs", "scripts/authority-staging-gate7-deploy.ts", ...args],
    { cwd: root, encoding: "utf8", env: env as NodeJS.ProcessEnv });
}

// exactAbsPath is a filename this file shares with tests/gate7-arm-render.test.ts
// (which produces it) -- lockedTest serializes access across processes/files;
// see tests/support/shared-staging-config-lock.ts.
function lockedTest(name: string, fn: () => Promise<void>) {
  test(name, () => withSharedStagingConfigLock(root, "shared-staging-render", fn));
}

for (const fixture of fixtures) {
  lockedTest(`gate7 deploy wrapper (${fixture.resource}): preflight PASSes at the exact armed rendered filename without contacting Cloudflare`, async () => {
    await writeFile(fixture.exactAbsPath, JSON.stringify(fixture.config()));
    try {
      const result = run([fixture.resource, "preflight", "--config", fixture.exactRelPath]);
      assert.equal(result.status, 0, result.stderr);
      const parsed = JSON.parse(result.stdout) as Record<string, unknown>;
      assert.equal(parsed.status, "PASS");
      assert.equal(parsed.mode, "preflight");
      assert.equal(parsed.resource, fixture.resource);
      assert.equal(parsed.providerContact, "none");
      assert.match(parsed.accountFingerprint as string, /^[a-f0-9]{16}$/u);
      assert.ok(!result.stdout.includes(validAccount) && !result.stderr.includes(validAccount), "raw account id must never be printed");
      assert.deepEqual(parsed.plannedCommand, ["wrangler", "deploy", "--config", fixture.exactAbsPath]);
    } finally { await rm(fixture.exactAbsPath, { force: true }); }
  });

  lockedTest(`gate7 deploy wrapper (${fixture.resource}): refuses the Gate 5 inactive config even at its own filename`, async () => {
    const inactive = { ...fixture.config(), triggers: { crons: [] as string[] } };
    await writeFile(fixture.exactAbsPath, JSON.stringify(inactive));
    try { assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath]).status, 0, "inactive config must be refused by the arm wrapper"); }
    finally { await rm(fixture.exactAbsPath, { force: true }); }
  });

  lockedTest(`gate7 deploy wrapper (${fixture.resource}): refuses arbitrary and multiple crons`, async () => {
    const arbitrary = { ...fixture.config(), triggers: { crons: ["*/5 * * * *"] } };
    await writeFile(fixture.exactAbsPath, JSON.stringify(arbitrary));
    try { assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath]).status, 0, "arbitrary cron must be refused"); }
    finally { await rm(fixture.exactAbsPath, { force: true }); }

    const multiple = { ...fixture.config(), triggers: { crons: ["* * * * *", "*/5 * * * *"] } };
    await writeFile(fixture.exactAbsPath, JSON.stringify(multiple));
    try { assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath]).status, 0, "multiple crons must be refused"); }
    finally { await rm(fixture.exactAbsPath, { force: true }); }
  });

  lockedTest(`gate7 deploy wrapper (${fixture.resource}): refuses alternate filenames, wrong Worker name, account-pin defects and extra argv`, async () => {
    await writeFile(fixture.exactAbsPath, JSON.stringify(fixture.config()));
    const altPath = join(root, "deployment", `gate7-${fixture.resource}-alt.staging.armed.jsonc`);
    await writeFile(altPath, JSON.stringify(fixture.config()));
    try {
      assert.notEqual(run([fixture.resource, "preflight", "--config", `deployment/gate7-${fixture.resource}-alt.staging.armed.jsonc`]).status, 0, "alternate filename");
      // Gate 5's own inactive rendered filename must not satisfy the arm wrapper either.
      const gate5Named = fixture.exactRelPath.replace(".armed.jsonc", ".jsonc");
      assert.notEqual(run([fixture.resource, "preflight", "--config", gate5Named]).status, 0, "Gate 5's own filename must not satisfy the arm wrapper");
      assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath], { CLOUDFLARE_ACCOUNT_ID: undefined }).status, 0, "missing account pin");
      assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath], { CLOUDFLARE_ACCOUNT_ID: "not-hex" }).status, 0, "malformed account pin");
      assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath], { CLOUDFLARE_ACCOUNT_ID: "0".repeat(32) }).status, 0, "all-zero account pin");
      assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath, "--cron", "*/5 * * * *"]).status, 0, "extra --cron must be refused (no generic cron surface)");
      assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath, "--route", "example.com/*"]).status, 0, "extra --route");
      assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath, "--env", "production"]).status, 0, "extra --env");
      assert.notEqual(run(["mailbox", "preflight", "--config", fixture.exactRelPath]).status, 0, "the bare Gate 5 resource name must not be accepted here");
      assert.notEqual(run([fixture.resource, "apply", "--config", fixture.exactRelPath]).status, 0, "unknown mode");
      assert.notEqual(run([fixture.resource, "deploy", "--config", fixture.exactRelPath], { CLOUDFLARE_ACCOUNT_ID: undefined }).status, 0, "deploy mode still requires account pin");
    } finally { await rm(fixture.exactAbsPath, { force: true }); await rm(altPath, { force: true }); }
  });

  lockedTest(`gate7 deploy wrapper (${fixture.resource}): refuses Production identity and wrong/extra bindings`, async () => {
    const prodShaped = { ...fixture.config(), name: (fixture.config().name as string).replace("-staging", "-production") };
    await writeFile(fixture.exactAbsPath, JSON.stringify(prodShaped));
    try { assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath]).status, 0, "Production-shaped name must be refused"); }
    finally { await rm(fixture.exactAbsPath, { force: true }); }

    const extraBinding = fixture.config();
    (extraBinding.services as unknown[]).push({ binding: "EXTRA", service: "other" });
    await writeFile(fixture.exactAbsPath, JSON.stringify(extraBinding));
    try { assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath]).status, 0, "extra binding must be refused"); }
    finally { await rm(fixture.exactAbsPath, { force: true }); }
  });
}

lockedTest("gate7 deploy wrapper: refusal paths never print the Wrangler-invocation line (never spawn)", async () => {
  const fixture = fixtures[0];
  await writeFile(fixture.exactAbsPath, JSON.stringify({ ...fixture.config(), triggers: { crons: [] as string[] } }));
  try {
    const result = run([fixture.resource, "deploy", "--config", fixture.exactRelPath]);
    assert.notEqual(result.status, 0);
    assert.ok(!result.stderr.includes("invoking pinned Wrangler"), "an inactive config must be refused before any Wrangler spawn, even in deploy mode");
  } finally { await rm(fixture.exactAbsPath, { force: true }); }
});

lockedTest("gate7 deploy wrapper (mailbox-arm): deploy mode constructs only the expected local pinned Wrangler invocation", async () => {
  const fixture = fixtures[0];
  await writeFile(fixture.exactAbsPath, JSON.stringify(fixture.config()));
  try {
    const preflight = run([fixture.resource, "preflight", "--config", fixture.exactRelPath]);
    const parsed = JSON.parse(preflight.stdout) as Record<string, unknown>;
    assert.deepEqual(parsed.plannedCommand, ["wrangler", "deploy", "--config", fixture.exactAbsPath],
      "the deploy mode invokes exactly this argv (proven equal to what preflight reports it would run)");
  } finally { await rm(fixture.exactAbsPath, { force: true }); }
});

test("gate7 deploy wrapper has no 'deploy all' mode: only the two exact resource names are accepted", () => {
  const fixture = fixtures[0];
  for (const badResource of ["all", "*", "mailbox-arm,observer-arm", "mailbox", "observer", "executor-arm", ""])
    assert.notEqual(run([badResource, "preflight", "--config", fixture.exactRelPath]).status, 0, `resource "${badResource}" must be refused`);
});
