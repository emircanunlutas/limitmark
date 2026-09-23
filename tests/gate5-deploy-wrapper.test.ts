import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { withSharedStagingConfigLock } from "./support/shared-staging-config-lock";

// Gate 5A: proves the generalized Gate 5 deploy wrapper (one Worker per
// invocation, closed resource set) refuses every unsafe input -- including
// every alternate rendered filename and every active-schedule config --
// before it could ever spawn Wrangler, and that its preflight mode reaches
// PASS without contacting Cloudflare, for all three resources. "deploy" mode
// is exercised only on refusal paths; a successful "deploy" would spawn the
// real Wrangler binary.

const root = fileURLToPath(new URL("../", import.meta.url));
const validAccount = "a".repeat(32);
const validKey = encodeBase64url(new Uint8Array(32).fill(7));

const reader = { binding: "LIFECYCLE_READER", service: "limitmark-admission-service-staging", entrypoint: "StagingAuthorityLifecycleReadOnly" };

type Fixture = { resource: "executor" | "mailbox" | "observer"; exactRelPath: string; exactAbsPath: string; config: () => Record<string, unknown> };
const fixtures: Fixture[] = [
  {
    resource: "executor",
    exactRelPath: "deployment/operator-lifecycle-executor.staging.jsonc",
    exactAbsPath: join(root, "deployment", "operator-lifecycle-executor.staging.jsonc"),
    config: () => ({
      $schema: "../node_modules/wrangler/config-schema.json", name: "limitmark-authority-operator-executor-staging",
      main: "../workers/staging-operator-lifecycle-executor.ts", account_id: "a".repeat(32), compatibility_date: "2026-09-13",
      workers_dev: false, preview_urls: false,
      services: [{ binding: "ADMISSION_SERVICE", service: "limitmark-admission-service-staging", entrypoint: "StagingAuthorityLifecycleOnly" }],
      vars: { AUTHORITY_OPERATOR_PUBLIC_KEY: validKey, OPERATOR_EXECUTOR_ENVIRONMENT: "staging" },
    }),
  },
  {
    resource: "mailbox",
    exactRelPath: "deployment/lifecycle-mailbox.staging.jsonc",
    exactAbsPath: join(root, "deployment", "lifecycle-mailbox.staging.jsonc"),
    config: () => ({
      $schema: "../node_modules/wrangler/config-schema.json", name: "limitmark-lifecycle-mailbox-staging",
      main: "../workers/lifecycle-mailbox/staging-index.ts", account_id: "a".repeat(32), compatibility_date: "2026-09-13",
      workers_dev: false, preview_urls: false, triggers: { crons: [] },
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
    exactRelPath: "deployment/lifecycle-observer.staging.jsonc",
    exactAbsPath: join(root, "deployment", "lifecycle-observer.staging.jsonc"),
    config: () => ({
      $schema: "../node_modules/wrangler/config-schema.json", name: "limitmark-lifecycle-observer-staging",
      main: "../workers/staging-lifecycle-observer.ts", account_id: "a".repeat(32), compatibility_date: "2026-09-13",
      workers_dev: false, preview_urls: false, triggers: { crons: [] },
      r2_buckets: [{ binding: "REQUEST_BUCKET", bucket_name: "limitmark-lifecycle-requests-staging" },
        { binding: "RESULT_BUCKET", bucket_name: "limitmark-lifecycle-results-staging" }],
      services: [reader],
    }),
  },
];

function run(args: string[], overrides: Record<string, string | undefined> = { CLOUDFLARE_ACCOUNT_ID: validAccount }) {
  const env: Record<string, string | undefined> = { ...process.env, ...overrides };
  for (const [key, value] of Object.entries(env)) if (value === undefined) delete env[key];
  return spawnSync(process.execPath, ["node_modules/tsx/dist/cli.mjs", "scripts/authority-staging-gate5-deploy.ts", ...args],
    { cwd: root, encoding: "utf8", env: env as NodeJS.ProcessEnv });
}

for (const fixture of fixtures) {
  test(`gate5 deploy wrapper (${fixture.resource}): preflight PASSes at the exact rendered filename without contacting Cloudflare`, () =>
    withSharedStagingConfigLock(root, "shared-staging-render", async () => {
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
  }));

  test(`gate5 deploy wrapper (${fixture.resource}): refuses alternate filenames, account-pin defects and extra argv`, () =>
    withSharedStagingConfigLock(root, "shared-staging-render", async () => {
    await writeFile(fixture.exactAbsPath, JSON.stringify(fixture.config()));
    const altPath = join(root, "deployment", `gate5-${fixture.resource}-alt.staging.jsonc`);
    await writeFile(altPath, JSON.stringify(fixture.config()));
    try {
      assert.notEqual(run([fixture.resource, "preflight", "--config", `deployment/gate5-${fixture.resource}-alt.staging.jsonc`]).status, 0, "alternate filename");
      const outsidePath = join(root, `${fixture.resource}.staging-outside.jsonc`);
      await writeFile(outsidePath, JSON.stringify(fixture.config()));
      try { assert.notEqual(run([fixture.resource, "preflight", "--config", `../${fixture.exactRelPath}`]).status, 0, "path outside deployment/"); }
      finally { await rm(outsidePath, { force: true }); }
      assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath], { CLOUDFLARE_ACCOUNT_ID: undefined }).status, 0, "missing account pin");
      assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath], { CLOUDFLARE_ACCOUNT_ID: "not-hex" }).status, 0, "malformed account pin");
      assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath], { CLOUDFLARE_ACCOUNT_ID: "A".repeat(32) }).status, 0, "uppercase account pin");
      assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath], { CLOUDFLARE_ACCOUNT_ID: "0".repeat(32) }).status, 0, "all-zero account pin");
      assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath, "--route", "example.com/*"]).status, 0, "extra --route");
      assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath, "--env", "production"]).status, 0, "extra --env");
      assert.notEqual(run([fixture.resource, "preflight", "--config", fixture.exactRelPath, "--var", "X=1"]).status, 0, "extra --var");
      assert.notEqual(run(["render", "preflight", "--config", fixture.exactRelPath]).status, 0, "unknown resource");
      assert.notEqual(run([fixture.resource, "apply", "--config", fixture.exactRelPath]).status, 0, "unknown mode");
      assert.notEqual(run([fixture.resource, "deploy", "--config", fixture.exactRelPath], { CLOUDFLARE_ACCOUNT_ID: undefined }).status, 0, "deploy mode still requires account pin");
    } finally { await rm(fixture.exactAbsPath, { force: true }); await rm(altPath, { force: true }); }
  }));
}

test("gate5 deploy wrapper has no 'deploy all' mode: only the three exact resource names are accepted", () => {
  const executor = fixtures[0];
  for (const badResource of ["all", "*", "executor,mailbox,observer", ""])
    assert.notEqual(run([badResource, "preflight", "--config", executor.exactRelPath]).status, 0, `resource "${badResource}" must be refused`);
});

test("gate5 deploy wrapper refuses raw templates for every resource", () => {
  const templates: Record<string, string> = {
    executor: "deployment/operator-lifecycle-executor.staging.template.jsonc",
    mailbox: "deployment/lifecycle-mailbox.staging.template.jsonc",
    observer: "deployment/lifecycle-observer.staging.template.jsonc",
  };
  for (const [resource, templatePath] of Object.entries(templates))
    assert.notEqual(run([resource, "preflight", "--config", templatePath]).status, 0, `${resource} raw template must be refused`);
});

test("gate5 deploy wrapper refuses an active-schedule mailbox/observer config even with an otherwise-valid, correctly-named file", () =>
  withSharedStagingConfigLock(root, "shared-staging-render", async () => {
  for (const resource of ["mailbox", "observer"] as const) {
    const fixture = fixtures.find((f) => f.resource === resource)!;
    const active = fixture.config();
    active.triggers = { crons: ["* * * * *"] };
    await writeFile(fixture.exactAbsPath, JSON.stringify(active));
    try { assert.notEqual(run([resource, "preflight", "--config", fixture.exactRelPath]).status, 0, `${resource} active Cron must be refused`); }
    finally { await rm(fixture.exactAbsPath, { force: true }); }
    const garbled = fixture.config();
    garbled.triggers = { crons: ["*/5 * * * *"] };
    await writeFile(fixture.exactAbsPath, JSON.stringify(garbled));
    try { assert.notEqual(run([resource, "preflight", "--config", fixture.exactRelPath]).status, 0, `${resource} malformed schedule must be refused`); }
    finally { await rm(fixture.exactAbsPath, { force: true }); }
  }
}));

test("gate5 deploy wrapper refuses cross-environment/Production substitutions", () =>
  withSharedStagingConfigLock(root, "shared-staging-render", async () => {
  const executor = fixtures[0];
  const prodShaped = executor.config();
  prodShaped.services = [{ binding: "ADMISSION_SERVICE", service: "limitmark-admission-service-production", entrypoint: "AuthorityLifecycleOnly" }];
  (prodShaped.vars as Record<string, unknown>).OPERATOR_EXECUTOR_ENVIRONMENT = "production";
  await writeFile(executor.exactAbsPath, JSON.stringify(prodShaped));
  try { assert.notEqual(run(["executor", "preflight", "--config", executor.exactRelPath]).status, 0, "Production-shaped executor config must be refused"); }
  finally { await rm(executor.exactAbsPath, { force: true }); }

  const mailbox = fixtures[1];
  const extraBinding = mailbox.config();
  (extraBinding.services as unknown[]).push({ binding: "EXTRA", service: "other" });
  await writeFile(mailbox.exactAbsPath, JSON.stringify(extraBinding));
  try { assert.notEqual(run(["mailbox", "preflight", "--config", mailbox.exactRelPath]).status, 0, "extra binding must be refused"); }
  finally { await rm(mailbox.exactAbsPath, { force: true }); }

  const observer = fixtures[2];
  const unknownField = observer.config();
  unknownField.unsafe_future_capability = { anything: true };
  await writeFile(observer.exactAbsPath, JSON.stringify(unknownField));
  try { assert.notEqual(run(["observer", "preflight", "--config", observer.exactRelPath]).status, 0, "unknown future capability field must be refused"); }
  finally { await rm(observer.exactAbsPath, { force: true }); }
}));
