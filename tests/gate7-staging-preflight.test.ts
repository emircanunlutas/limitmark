import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { withSharedStagingConfigLock } from "./support/shared-staging-config-lock";

// Gate 7A: proves the standalone lifecycle-private-preflight.ts "-arm" modes
// form the exact mirror image of Gate 5A's inactive modes -- the full 2x2
// matrix (inactive/armed config x inactive/arm mode) plus arbitrary-cron
// rejection -- and that they accept only the distinct exact armed rendered
// filename, never the Gate 5 inactive one.

const root = fileURLToPath(new URL("../", import.meta.url));
const validKey = encodeBase64url(new Uint8Array(32).fill(7));
const reader = { binding: "LIFECYCLE_READER", service: "limitmark-admission-service-staging", entrypoint: "StagingAuthorityLifecycleReadOnly" };

function runLifecyclePreflight(args: string[]) {
  return spawnSync(process.execPath, ["node_modules/tsx/dist/cli.mjs", "scripts/lifecycle-private-preflight.ts", ...args],
    { cwd: root, encoding: "utf8" });
}

const mailboxBase = {
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
const observerBase = {
  $schema: "../node_modules/wrangler/config-schema.json", name: "limitmark-lifecycle-observer-staging",
  main: "../workers/staging-lifecycle-observer.ts", account_id: "a".repeat(32), compatibility_date: "2026-09-13",
  workers_dev: false, preview_urls: false, triggers: { crons: [] as string[] },
  r2_buckets: [{ binding: "REQUEST_BUCKET", bucket_name: "limitmark-lifecycle-requests-staging" },
    { binding: "RESULT_BUCKET", bucket_name: "limitmark-lifecycle-results-staging" }],
  services: [reader],
};

const resources = [
  { mode: "mailbox", base: mailboxBase, inactivePath: "deployment/lifecycle-mailbox.staging.jsonc", armedPath: "deployment/lifecycle-mailbox.staging.armed.jsonc" },
  { mode: "observer", base: observerBase, inactivePath: "deployment/lifecycle-observer.staging.jsonc", armedPath: "deployment/lifecycle-observer.staging.armed.jsonc" },
] as const;

// inactivePath/armedPath are filenames shared with tests/gate5-*-preflight.test.ts
// and tests/gate7-arm-render.test.ts -- lockedTest serializes access across
// processes/files; see tests/support/shared-staging-config-lock.ts.
function lockedTest(name: string, fn: () => Promise<void>) {
  test(name, () => withSharedStagingConfigLock(root, "shared-staging-render", fn));
}

for (const resource of resources) {
  lockedTest(`gate7 arm preflight (${resource.mode}): the full inactive/armed x inactive-mode/arm-mode matrix`, async () => {
    const inactiveAbs = join(root, resource.inactivePath);
    const armedAbs = join(root, resource.armedPath);
    const armMode = `staging-${resource.mode}-arm`;
    const inactiveMode = `staging-${resource.mode}`;
    try {
      // armed config + inactive mode = REFUSE
      await writeFile(inactiveAbs, JSON.stringify({ ...resource.base, triggers: { crons: ["* * * * *"] } }));
      assert.notEqual(runLifecyclePreflight([inactiveMode, "--config", resource.inactivePath]).status, 0,
        "an armed config must be refused by the inactive-mode preflight");
      await rm(inactiveAbs, { force: true });

      // inactive config + arm mode = REFUSE
      await writeFile(armedAbs, JSON.stringify({ ...resource.base, triggers: { crons: [] as string[] } }));
      assert.notEqual(runLifecyclePreflight([armMode, "--config", resource.armedPath]).status, 0,
        "an inactive config must be refused by the arm-mode preflight");
      await rm(armedAbs, { force: true });

      // armed config + arm mode = PASS
      await writeFile(armedAbs, JSON.stringify({ ...resource.base, triggers: { crons: ["* * * * *"] } }));
      const pass = runLifecyclePreflight([armMode, "--config", resource.armedPath]);
      assert.equal(pass.status, 0, pass.stderr);
      assert.match(pass.stdout, /STAGING_SCHEDULE_ARMED/u);
      await rm(armedAbs, { force: true });

      // inactive config + inactive mode = PASS (unchanged Gate 5A behavior)
      await writeFile(inactiveAbs, JSON.stringify({ ...resource.base, triggers: { crons: [] as string[] } }));
      const gate5Pass = runLifecyclePreflight([inactiveMode, "--config", resource.inactivePath]);
      assert.equal(gate5Pass.status, 0, gate5Pass.stderr);
      assert.match(gate5Pass.stdout, /STAGING_DEPLOYMENT_INACTIVE/u);
    } finally { await rm(inactiveAbs, { force: true }); await rm(armedAbs, { force: true }); }
  });

  lockedTest(`gate7 arm preflight (${resource.mode}): arbitrary cron is refused in arm mode too`, async () => {
    const armedAbs = join(root, resource.armedPath);
    const armMode = `staging-${resource.mode}-arm`;
    await writeFile(armedAbs, JSON.stringify({ ...resource.base, triggers: { crons: ["*/5 * * * *"] } }));
    try { assert.notEqual(runLifecyclePreflight([armMode, "--config", resource.armedPath]).status, 0, "arbitrary cron must be refused"); }
    finally { await rm(armedAbs, { force: true }); }

    await writeFile(armedAbs, JSON.stringify({ ...resource.base, triggers: { crons: ["* * * * *", "*/5 * * * *"] } }));
    try { assert.notEqual(runLifecyclePreflight([armMode, "--config", resource.armedPath]).status, 0, "multiple crons must be refused"); }
    finally { await rm(armedAbs, { force: true }); }
  });

  lockedTest(`gate7 arm preflight (${resource.mode}): the arm mode accepts only its own exact armed filename, never the Gate 5 inactive one`, async () => {
    const inactiveAbs = join(root, resource.inactivePath);
    const armMode = `staging-${resource.mode}-arm`;
    await writeFile(inactiveAbs, JSON.stringify({ ...resource.base, triggers: { crons: ["* * * * *"] } }));
    try { assert.notEqual(runLifecyclePreflight([armMode, "--config", resource.inactivePath]).status, 0,
      "the arm mode must not accept a config at the Gate 5 inactive filename, even if armed"); }
    finally { await rm(inactiveAbs, { force: true }); }
  });
}
