import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { withAbsentFixturePaths } from "./support/rendered-artifact-guard";
import { withSharedStagingConfigLock } from "./support/shared-staging-config-lock";

// Gate 6A / F1: proves the standalone lifecycle preflight's staging-transport
// mode now enforces the same exact-rendered-filename invariant (directory
// placement *and* basename, both checked after realpath() canonicalization)
// already closed for staging-mailbox/staging-observer at Gate 5A and for the
// staging admission config at Gate 4B, and that Production-transport
// substitution and an unresolved template are both refused by content.

const root = fileURLToPath(new URL("../", import.meta.url));
const validKey = encodeBase64url(new Uint8Array(32).fill(7));

// Gate 7B: every path a test below writes is first proven absent under the
// shared lock; a real operator-rendered artifact at any of them skips the test
// without touching it (tests/support/rendered-artifact-guard.ts).
function guardedTest(name: string, paths: readonly string[], fn: () => Promise<void>) {
  test(name, (t) => withSharedStagingConfigLock(root, "shared-staging-render", () => withAbsentFixturePaths(t, root, paths, fn)));
}
const exactManifestPath = join(root, "deployment", "lifecycle-transport.staging.json");

function runLifecyclePreflight(args: string[]) {
  return spawnSync(process.execPath, ["node_modules/tsx/dist/cli.mjs", "scripts/lifecycle-private-preflight.ts", ...args],
    { cwd: root, encoding: "utf8" });
}

const stagingManifest = {
  version: 1, environment: "staging", accountId: "a".repeat(32),
  requestBucket: "limitmark-lifecycle-requests-staging", resultBucket: "limitmark-lifecycle-results-staging",
  authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1", operatorPublicKey: validKey,
};

guardedTest("standalone staging-transport preflight accepts only the exact rendered filename",
  [exactManifestPath, join(root, "deployment", "lifecycle-transport.staging.custom.json")], async () => {
  const exactPath = join(root, "deployment", "lifecycle-transport.staging.json");
  const altPath = join(root, "deployment", "lifecycle-transport.staging.custom.json");
  await writeFile(exactPath, JSON.stringify(stagingManifest));
  await writeFile(altPath, JSON.stringify(stagingManifest));
  try {
    const pass = runLifecyclePreflight(["staging-transport", "--config", "deployment/lifecycle-transport.staging.json"]);
    assert.equal(pass.status, 0, pass.stderr);
    assert.notEqual(runLifecyclePreflight(["staging-transport", "--config", "deployment/lifecycle-transport.staging.custom.json"]).status, 0,
      "alternate filename must be refused");
  } finally { await rm(exactPath, { force: true }); await rm(altPath, { force: true }); }
});

test("standalone staging-transport preflight refuses the raw unresolved template", () => {
  assert.notEqual(runLifecyclePreflight(["staging-transport", "--config", "deployment/lifecycle-transport.staging.template.json"]).status, 0,
    "the raw template carries __REQUIRED_ placeholders and must fail content validation");
});

guardedTest("standalone staging-transport preflight refuses a Production-shaped manifest rendered at the staging path", [exactManifestPath], async () => {
  const exactPath = join(root, "deployment", "lifecycle-transport.staging.json");
  const productionShaped = {
    version: 1, environment: "production", accountId: "a".repeat(32),
    requestBucket: "limitmark-lifecycle-requests-production", resultBucket: "limitmark-lifecycle-results-production",
    authorityId: "production-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1", operatorPublicKey: validKey,
  };
  await writeFile(exactPath, JSON.stringify(productionShaped));
  try {
    assert.notEqual(runLifecyclePreflight(["staging-transport", "--config", "deployment/lifecycle-transport.staging.json"]).status, 0,
      "a Production-shaped manifest must never pass the staging-transport validator, even at the exact staging path");
  } finally { await rm(exactPath, { force: true }); }
});

guardedTest("standalone staging-transport preflight refuses a config placed outside deployment/",
  [join(root, "lifecycle-transport.staging.json")], async () => {
  const outsidePath = join(root, "lifecycle-transport.staging.json");
  await writeFile(outsidePath, JSON.stringify(stagingManifest));
  try {
    assert.notEqual(runLifecyclePreflight(["staging-transport", "--config", "lifecycle-transport.staging.json"]).status, 0,
      "a config with the exact right basename but the wrong directory must be refused");
  } finally { await rm(outsidePath, { force: true }); }
});

test("Production lifecycle preflight modes are unaffected by the Gate 6A staging-transport change", async () => {
  const productionTemplate = JSON.parse(await (await import("node:fs/promises"))
    .readFile(join(root, "deployment", "lifecycle-transport.production.template.json"), "utf8"));
  productionTemplate.accountId = "a".repeat(32);
  productionTemplate.operatorPublicKey = validKey;
  const path = join(root, "deployment", "gate6-production-transport-check.json");
  await writeFile(path, JSON.stringify(productionTemplate));
  try {
    assert.equal(runLifecyclePreflight(["transport", "--config", "deployment/gate6-production-transport-check.json"]).status, 0);
  } finally { await rm(path, { force: true }); }
});
