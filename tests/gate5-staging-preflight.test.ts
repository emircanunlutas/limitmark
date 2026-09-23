import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { withAbsentFixturePaths } from "./support/rendered-artifact-guard";
import { withSharedStagingConfigLock } from "./support/shared-staging-config-lock";

// Gate 5A: proves the standalone preflight scripts (used independently of the
// deploy wrapper, e.g. for local review before a config is ever handed to a
// deploy) enforce the identical exact-rendered-filename invariant, and that
// the staging mailbox/observer preflight enforces STAGING_DEPLOYMENT_INACTIVE
// rather than merely reporting whichever schedule state a config happens to
// carry.

const root = fileURLToPath(new URL("../", import.meta.url));
const validKey = encodeBase64url(new Uint8Array(32).fill(7));
const reader = { binding: "LIFECYCLE_READER", service: "limitmark-admission-service-staging", entrypoint: "StagingAuthorityLifecycleReadOnly" };

// Gate 7B: every path a test below writes is first proven absent under the
// shared lock; a real operator-rendered artifact at any of them skips the test
// without touching it (tests/support/rendered-artifact-guard.ts).
function guardedTest(name: string, paths: readonly string[], fn: () => Promise<void>) {
  test(name, (t) => withSharedStagingConfigLock(root, "shared-staging-render", () => withAbsentFixturePaths(t, root, paths, fn)));
}
const deploymentPaths = (...names: string[]) => names.map((name) => join(root, "deployment", name));

function runExecutorPreflight(args: string[]) {
  return spawnSync(process.execPath, ["node_modules/tsx/dist/cli.mjs", "scripts/authority-staging-executor-preflight.ts", ...args],
    { cwd: root, encoding: "utf8" });
}
function runLifecyclePreflight(args: string[]) {
  return spawnSync(process.execPath, ["node_modules/tsx/dist/cli.mjs", "scripts/lifecycle-private-preflight.ts", ...args],
    { cwd: root, encoding: "utf8" });
}

guardedTest("standalone staging executor preflight accepts only the exact rendered filename",
  deploymentPaths("operator-lifecycle-executor.staging.jsonc", "operator-lifecycle-executor.staging.custom.jsonc"), async () => {
  const exactPath = join(root, "deployment", "operator-lifecycle-executor.staging.jsonc");
  const altPath = join(root, "deployment", "operator-lifecycle-executor.staging.custom.jsonc");
  const config = {
    $schema: "../node_modules/wrangler/config-schema.json", name: "limitmark-authority-operator-executor-staging",
    main: "../workers/staging-operator-lifecycle-executor.ts", account_id: "a".repeat(32), compatibility_date: "2026-09-13",
    workers_dev: false, preview_urls: false,
    services: [{ binding: "ADMISSION_SERVICE", service: "limitmark-admission-service-staging", entrypoint: "StagingAuthorityLifecycleOnly" }],
    vars: { AUTHORITY_OPERATOR_PUBLIC_KEY: validKey, OPERATOR_EXECUTOR_ENVIRONMENT: "staging" },
  };
  await writeFile(exactPath, JSON.stringify(config));
  await writeFile(altPath, JSON.stringify(config));
  try {
    assert.equal(runExecutorPreflight(["--config", "deployment/operator-lifecycle-executor.staging.jsonc"]).status, 0, "exact filename must PASS");
    assert.notEqual(runExecutorPreflight(["--config", "deployment/operator-lifecycle-executor.staging.custom.jsonc"]).status, 0, "alternate filename must be refused");
    assert.notEqual(runExecutorPreflight(["--config", "deployment/operator-lifecycle-executor.staging.template.jsonc"]).status, 0, "raw template must be refused");
  } finally { await rm(exactPath, { force: true }); await rm(altPath, { force: true }); }
});

guardedTest("standalone lifecycle preflight: staging-mailbox accepts only the exact filename and requires STAGING_DEPLOYMENT_INACTIVE",
  deploymentPaths("lifecycle-mailbox.staging.jsonc", "lifecycle-mailbox.staging.custom.jsonc"), async () => {
  const exactPath = join(root, "deployment", "lifecycle-mailbox.staging.jsonc");
  const altPath = join(root, "deployment", "lifecycle-mailbox.staging.custom.jsonc");
  const base = {
    $schema: "../node_modules/wrangler/config-schema.json", name: "limitmark-lifecycle-mailbox-staging",
    main: "../workers/lifecycle-mailbox/staging-index.ts", account_id: "a".repeat(32), compatibility_date: "2026-09-13",
    workers_dev: false, preview_urls: false, triggers: { crons: [] as string[] },
    r2_buckets: [{ binding: "REQUEST_BUCKET", bucket_name: "limitmark-lifecycle-requests-staging" },
      { binding: "RESULT_BUCKET", bucket_name: "limitmark-lifecycle-results-staging" }],
    services: [{ binding: "LIFECYCLE_EXECUTOR", service: "limitmark-authority-operator-executor-staging", entrypoint: "StagingOperatorLifecycleExecutor" }, reader],
    durable_objects: { bindings: [{ name: "DISPATCH_GUARD", class_name: "StagingLifecycleDispatchGuard" }] },
    migrations: [{ tag: "i3b-staging-guard-v1", new_sqlite_classes: ["StagingLifecycleDispatchGuard"] }],
    vars: { AUTHORITY_OPERATOR_PUBLIC_KEY: validKey, LIFECYCLE_ENVIRONMENT: "staging" },
  };
  await writeFile(exactPath, JSON.stringify(base));
  await writeFile(altPath, JSON.stringify(base));
  try {
    const pass = runLifecyclePreflight(["staging-mailbox", "--config", "deployment/lifecycle-mailbox.staging.jsonc"]);
    assert.equal(pass.status, 0, pass.stderr);
    assert.match(pass.stdout, /STAGING_DEPLOYMENT_INACTIVE/u);
    assert.notEqual(runLifecyclePreflight(["staging-mailbox", "--config", "deployment/lifecycle-mailbox.staging.custom.jsonc"]).status, 0,
      "alternate filename must be refused");
  } finally { await rm(exactPath, { force: true }); await rm(altPath, { force: true }); }

  const active = { ...base, triggers: { crons: ["* * * * *"] } };
  await writeFile(exactPath, JSON.stringify(active));
  try { assert.notEqual(runLifecyclePreflight(["staging-mailbox", "--config", "deployment/lifecycle-mailbox.staging.jsonc"]).status, 0, "active Cron must be refused"); }
  finally { await rm(exactPath, { force: true }); }

  const garbled = { ...base, triggers: { crons: ["*/5 * * * *"] } };
  await writeFile(exactPath, JSON.stringify(garbled));
  try { assert.notEqual(runLifecyclePreflight(["staging-mailbox", "--config", "deployment/lifecycle-mailbox.staging.jsonc"]).status, 0, "malformed schedule must be refused"); }
  finally { await rm(exactPath, { force: true }); }
});

guardedTest("standalone lifecycle preflight: staging-observer accepts only the exact filename and requires STAGING_DEPLOYMENT_INACTIVE",
  deploymentPaths("lifecycle-observer.staging.jsonc", "lifecycle-observer.staging.custom.jsonc"), async () => {
  const exactPath = join(root, "deployment", "lifecycle-observer.staging.jsonc");
  const altPath = join(root, "deployment", "lifecycle-observer.staging.custom.jsonc");
  const base = {
    $schema: "../node_modules/wrangler/config-schema.json", name: "limitmark-lifecycle-observer-staging",
    main: "../workers/staging-lifecycle-observer.ts", account_id: "a".repeat(32), compatibility_date: "2026-09-13",
    workers_dev: false, preview_urls: false, triggers: { crons: [] as string[] },
    r2_buckets: [{ binding: "REQUEST_BUCKET", bucket_name: "limitmark-lifecycle-requests-staging" },
      { binding: "RESULT_BUCKET", bucket_name: "limitmark-lifecycle-results-staging" }],
    services: [reader],
  };
  await writeFile(exactPath, JSON.stringify(base));
  await writeFile(altPath, JSON.stringify(base));
  try {
    const pass = runLifecyclePreflight(["staging-observer", "--config", "deployment/lifecycle-observer.staging.jsonc"]);
    assert.equal(pass.status, 0, pass.stderr);
    assert.match(pass.stdout, /STAGING_DEPLOYMENT_INACTIVE/u);
    assert.notEqual(runLifecyclePreflight(["staging-observer", "--config", "deployment/lifecycle-observer.staging.custom.jsonc"]).status, 0,
      "alternate filename must be refused");
  } finally { await rm(exactPath, { force: true }); await rm(altPath, { force: true }); }

  const active = { ...base, triggers: { crons: ["* * * * *"] } };
  await writeFile(exactPath, JSON.stringify(active));
  try { assert.notEqual(runLifecyclePreflight(["staging-observer", "--config", "deployment/lifecycle-observer.staging.jsonc"]).status, 0, "active Cron must be refused"); }
  finally { await rm(exactPath, { force: true }); }
});

test("Production lifecycle preflight modes are unaffected by the Gate 5A staging changes", async () => {
  const mailboxTemplate = JSON.parse(await (await import("node:fs/promises")).readFile(join(root, "deployment", "lifecycle-mailbox.template.jsonc"), "utf8"));
  const observerTemplate = JSON.parse(await (await import("node:fs/promises")).readFile(join(root, "deployment", "lifecycle-observer.template.jsonc"), "utf8"));
  mailboxTemplate.account_id = "a".repeat(32);
  mailboxTemplate.main = "../workers/lifecycle-mailbox/index.ts";
  mailboxTemplate.vars.AUTHORITY_OPERATOR_PUBLIC_KEY = validKey;
  observerTemplate.account_id = "a".repeat(32);
  observerTemplate.main = "../workers/lifecycle-observer.ts";
  // Production configs may render under any filename in deployment/ today (unchanged behavior).
  const mailboxPath = join(root, "deployment", "gate5-production-mailbox-check.jsonc");
  const observerPath = join(root, "deployment", "gate5-production-observer-check.jsonc");
  await writeFile(mailboxPath, JSON.stringify(mailboxTemplate));
  await writeFile(observerPath, JSON.stringify(observerTemplate));
  try {
    assert.equal(runLifecyclePreflight(["mailbox", "--config", "deployment/gate5-production-mailbox-check.jsonc"]).status, 0);
    assert.equal(runLifecyclePreflight(["observer", "--config", "deployment/gate5-production-observer-check.jsonc"]).status, 0);
  } finally { await rm(mailboxPath, { force: true }); await rm(observerPath, { force: true }); }
});
