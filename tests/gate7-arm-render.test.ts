import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { withAbsentFixturePaths } from "./support/rendered-artifact-guard";
import { withSharedStagingConfigLock } from "./support/shared-staging-config-lock";

// Gate 7A: proves the local, deterministic INACTIVE-to-ARMED render (used
// only to produce the *.armed.jsonc rendered configs the Gate 7A deploy
// wrapper accepts) changes only `triggers`, refuses every unsafe input
// before writing anything, never overwrites an existing armed file, never
// contacts Cloudflare, and accepts no CLI-provided cron.

const root = fileURLToPath(new URL("../", import.meta.url));
const validAccount = "a".repeat(32);
const validKey = encodeBase64url(new Uint8Array(32).fill(7));
const reader = { binding: "LIFECYCLE_READER", service: "limitmark-admission-service-staging", entrypoint: "StagingAuthorityLifecycleReadOnly" };

type Fixture = { resource: "mailbox" | "observer"; sourcePath: string; destPath: string; config: () => Record<string, unknown> };
const fixtures: Fixture[] = [
  {
    resource: "mailbox",
    sourcePath: join(root, "deployment", "lifecycle-mailbox.staging.jsonc"),
    destPath: join(root, "deployment", "lifecycle-mailbox.staging.armed.jsonc"),
    config: () => ({
      $schema: "../node_modules/wrangler/config-schema.json", name: "limitmark-lifecycle-mailbox-staging",
      main: "../workers/lifecycle-mailbox/staging-index.ts", account_id: validAccount, compatibility_date: "2026-09-13",
      workers_dev: false, preview_urls: false, triggers: { crons: [] as string[] },
      r2_buckets: [{ binding: "REQUEST_BUCKET", bucket_name: "limitmark-lifecycle-requests-staging" },
        { binding: "RESULT_BUCKET", bucket_name: "limitmark-lifecycle-results-staging" }],
      services: [{ binding: "LIFECYCLE_EXECUTOR", service: "limitmark-authority-operator-executor-staging", entrypoint: "StagingOperatorLifecycleExecutor" }, reader],
      durable_objects: { bindings: [{ name: "DISPATCH_GUARD", class_name: "StagingLifecycleDispatchGuard" }] },
      migrations: [{ tag: "i3b-staging-guard-v1", new_sqlite_classes: ["StagingLifecycleDispatchGuard"] }],
      vars: { AUTHORITY_OPERATOR_PUBLIC_KEY: validKey, LIFECYCLE_ENVIRONMENT: "staging" },
    }),
  },
  {
    resource: "observer",
    sourcePath: join(root, "deployment", "lifecycle-observer.staging.jsonc"),
    destPath: join(root, "deployment", "lifecycle-observer.staging.armed.jsonc"),
    config: () => ({
      $schema: "../node_modules/wrangler/config-schema.json", name: "limitmark-lifecycle-observer-staging",
      main: "../workers/staging-lifecycle-observer.ts", account_id: validAccount, compatibility_date: "2026-09-13",
      workers_dev: false, preview_urls: false, triggers: { crons: [] as string[] },
      r2_buckets: [{ binding: "REQUEST_BUCKET", bucket_name: "limitmark-lifecycle-requests-staging" },
        { binding: "RESULT_BUCKET", bucket_name: "limitmark-lifecycle-results-staging" }],
      services: [reader],
    }),
  },
];

function run(args: string[], overrides: Record<string, string | undefined> = { CLOUDFLARE_ACCOUNT_ID: validAccount }) {
  const env: Record<string, string | undefined> = { ...process.env, ...overrides };
  for (const [key, value] of Object.entries(env)) if (value === undefined) delete env[key];
  return spawnSync(process.execPath, ["node_modules/tsx/dist/cli.mjs", "scripts/authority-staging-gate7-arm.ts", ...args],
    { cwd: root, encoding: "utf8", env: env as NodeJS.ProcessEnv });
}

async function cleanup(fixture: Fixture) {
  await rm(fixture.sourcePath, { force: true });
  await rm(fixture.destPath, { force: true });
}

// The source/dest paths below are exact, contractually fixed filenames
// shared with other test files (Gate 5's own tests, and the Gate 7A deploy
// wrapper's tests) -- lockedTest serializes access to them across processes;
// see tests/support/shared-staging-config-lock.ts.
// Gate 7B: every path a test writes is first proven absent under the lock; a
// real operator-rendered artifact at any of them skips the test without
// touching it (tests/support/rendered-artifact-guard.ts).
function lockedTest(name: string, paths: readonly string[], fn: () => Promise<void>) {
  test(name, (t) => withSharedStagingConfigLock(root, "shared-staging-render", () => withAbsentFixturePaths(t, root, paths, fn)));
}

for (const fixture of fixtures) {
  lockedTest(`gate7 arm render (${fixture.resource}): produces the exact armed config, changing only triggers`, [fixture.sourcePath, fixture.destPath], async () => {
    await writeFile(fixture.sourcePath, JSON.stringify(fixture.config()));
    try {
      const result = run([fixture.resource]);
      assert.equal(result.status, 0, result.stderr);
      const parsed = JSON.parse(result.stdout) as Record<string, unknown>;
      assert.equal(parsed.status, "PASS");
      assert.equal(parsed.scheduleState, "STAGING_SCHEDULE_ARMED");
      assert.equal(parsed.providerContact, "none");
      assert.match(parsed.accountFingerprint as string, /^[a-f0-9]{16}$/u);
      assert.ok(!result.stdout.includes(validAccount) && !result.stderr.includes(validAccount), "raw account id must never be printed");
      assert.ok(!result.stdout.includes(validKey) && !result.stderr.includes(validKey), "operator public key must never be printed");

      const written = JSON.parse(await readFile(fixture.destPath, "utf8")) as Record<string, unknown>;
      const expected = { ...fixture.config(), triggers: { crons: ["* * * * *"] } };
      assert.deepEqual(written, expected, "every field except triggers must be preserved exactly");
    } finally { await cleanup(fixture); }
  });

  lockedTest(`gate7 arm render (${fixture.resource}): refuses to overwrite an existing armed file`, [fixture.sourcePath, fixture.destPath], async () => {
    await writeFile(fixture.sourcePath, JSON.stringify(fixture.config()));
    await writeFile(fixture.destPath, JSON.stringify({ ...fixture.config(), triggers: { crons: ["* * * * *"] } }));
    try {
      const result = run([fixture.resource]);
      assert.notEqual(result.status, 0, "must refuse when the armed file already exists");
      assert.match(result.stderr, /already-exists|EEXIST/u);
    } finally { await cleanup(fixture); }
  });

  lockedTest(`gate7 arm render (${fixture.resource}): refuses an already-armed or garbled source`, [fixture.sourcePath, fixture.destPath], async () => {
    const armedSource = { ...fixture.config(), triggers: { crons: ["* * * * *"] } };
    await writeFile(fixture.sourcePath, JSON.stringify(armedSource));
    try { assert.notEqual(run([fixture.resource]).status, 0, "already-armed source must be refused"); }
    finally { await cleanup(fixture); }

    const garbled = { ...fixture.config(), triggers: { crons: ["*/5 * * * *"] } };
    await writeFile(fixture.sourcePath, JSON.stringify(garbled));
    try { assert.notEqual(run([fixture.resource]).status, 0, "arbitrary cron source must be refused"); }
    finally { await cleanup(fixture); }

    const multiCron = { ...fixture.config(), triggers: { crons: ["* * * * *", "*/5 * * * *"] } };
    await writeFile(fixture.sourcePath, JSON.stringify(multiCron));
    try { assert.notEqual(run([fixture.resource]).status, 0, "multiple crons in source must be refused"); }
    finally { await cleanup(fixture); }
  });

  lockedTest(`gate7 arm render (${fixture.resource}): refuses account-pin mismatch and missing/malformed pin`, [fixture.sourcePath, fixture.destPath], async () => {
    await writeFile(fixture.sourcePath, JSON.stringify(fixture.config()));
    try {
      assert.notEqual(run([fixture.resource], { CLOUDFLARE_ACCOUNT_ID: "b".repeat(32) }).status, 0, "mismatched account pin must be refused");
      assert.notEqual(run([fixture.resource], { CLOUDFLARE_ACCOUNT_ID: undefined }).status, 0, "missing account pin must be refused");
      assert.notEqual(run([fixture.resource], { CLOUDFLARE_ACCOUNT_ID: "not-hex" }).status, 0, "malformed account pin must be refused");
      const destExists = await readFile(fixture.destPath, "utf8").then(() => true, () => false);
      assert.equal(destExists, false, "no armed file must ever be written on refusal");
    } finally { await cleanup(fixture); }
  });

  lockedTest(`gate7 arm render (${fixture.resource}): refuses when only the tracked template exists (no rendered source yet)`, [fixture.sourcePath, fixture.destPath], async () => {
    assert.notEqual(run([fixture.resource]).status, 0, "missing rendered source must be refused");
  });

  lockedTest(`gate7 arm render (${fixture.resource}): refuses Production-shaped source`, [fixture.sourcePath, fixture.destPath], async () => {
    const prodShaped = { ...fixture.config(), name: (fixture.config().name as string).replace("-staging", "-production") };
    await writeFile(fixture.sourcePath, JSON.stringify(prodShaped));
    try { assert.notEqual(run([fixture.resource]).status, 0, "Production-shaped name must be refused"); }
    finally { await cleanup(fixture); }
  });

  lockedTest(`gate7 arm render (${fixture.resource}): no CLI-provided cron surface exists`, [fixture.sourcePath, fixture.destPath], async () => {
    await writeFile(fixture.sourcePath, JSON.stringify(fixture.config()));
    try {
      assert.notEqual(run([fixture.resource, "--cron", "*/5 * * * *"]).status, 0, "extra --cron argument must be refused");
      assert.notEqual(run([fixture.resource, "*/5 * * * *"]).status, 0, "positional cron argument must be refused");
    } finally { await cleanup(fixture); }
  });
}

test("gate7 arm render: only mailbox/observer resources are accepted", () => {
  for (const badResource of ["executor", "all", "*", ""])
    assert.notEqual(run([badResource]).status, 0, `resource "${badResource}" must be refused`);
});
