import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { realpath, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { withAbsentFixturePaths } from "./support/rendered-artifact-guard";
import { withSharedStagingConfigLock } from "./support/shared-staging-config-lock";
import { withWranglerSandbox } from "./support/wrangler-sandbox";

// Gate 4B: proves the deploy wrapper (and the standalone preflight it must
// never be looser than) refuses every unsafe input -- including every
// alternate rendered filename -- before either script could ever spawn
// Wrangler, and that preflight mode reaches PASS without contacting
// Cloudflare. Gate 7B: "deploy" mode runs only inside the test-only Wrangler
// sandbox (tests/support/wrangler-sandbox.ts), where the wrapper's pinned
// Wrangler path resolves to a self-tested fake recorder -- the real Wrangler
// binary is never reachable from any test here.

const root = fileURLToPath(new URL("../", import.meta.url));
const validAccount = "a".repeat(32);
const validKey = encodeBase64url(new Uint8Array(32).fill(7));
// The one filename the reviewed .gitignore rule and runbook name; the same
// filename the deploy wrapper's and preflight's exact-rendered-config
// invariant require.
const exactRelPath = "deployment/admission-service.staging.jsonc";
const exactAbsPath = join(root, "deployment", "admission-service.staging.jsonc");

// Gate 7B: every path a test below writes is first proven absent (a real
// operator-rendered artifact at any of them skips the test untouched), under
// the shared lock so the Gate 7B regression test can serialize with it.
function guardedTest(name: string, paths: readonly string[], fn: () => Promise<void>) {
  test(name, (t) => withSharedStagingConfigLock(root, "shared-staging-render", () => withAbsentFixturePaths(t, root, paths, fn)));
}
const alternateWrittenPaths = ["deployment/admission-service.staging.local.jsonc", "deployment/admission-service.staging.custom.jsonc",
  "deployment/gate4-deploy-test-tampered.jsonc", "admission-service.staging.jsonc"].map((relPath) => join(root, relPath));
const customAbsPath = join(root, "deployment", "admission-service.staging.custom.jsonc");

function validConfig(extra: Record<string, unknown> = {}) {
  return {
    $schema: "../node_modules/wrangler/config-schema.json", name: "limitmark-admission-service-staging",
    main: "../workers/admission-service/index.ts", compatibility_date: "2026-09-13", workers_dev: false, preview_urls: false,
    durable_objects: { bindings: [{ name: "AUTHORITY", class_name: "StagingAdmissionAuthority" }] },
    migrations: [{ tag: "staging-admission-v1", new_sqlite_classes: ["StagingAdmissionAuthority"] }],
    vars: { AUTHORITY_OPERATOR_PUBLIC_KEY: validKey }, ...extra,
  };
}

function run(args: string[], overrides: Record<string, string | undefined> = { CLOUDFLARE_ACCOUNT_ID: validAccount }) {
  const env: Record<string, string | undefined> = { ...process.env, ...overrides };
  for (const [key, value] of Object.entries(env)) if (value === undefined) delete env[key];
  return spawnSync(process.execPath, ["node_modules/tsx/dist/cli.mjs", "scripts/authority-staging-admission-deploy.ts", ...args],
    { cwd: root, encoding: "utf8", env: env as NodeJS.ProcessEnv });
}

function runPreflightScript(args: string[]) {
  return spawnSync(process.execPath, ["node_modules/tsx/dist/cli.mjs", "scripts/authority-staging-admission-preflight.ts", ...args],
    { cwd: root, encoding: "utf8" });
}

guardedTest("staging admission deploy wrapper preflight PASSes at the exact rendered filename without contacting Cloudflare and never leaks the account id", [exactAbsPath], async () => {
  await writeFile(exactAbsPath, JSON.stringify(validConfig()));
  try {
    const result = run(["preflight", "--config", exactRelPath]);
    assert.equal(result.status, 0, result.stderr);
    const parsed = JSON.parse(result.stdout) as Record<string, unknown>;
    assert.equal(parsed.status, "PASS");
    assert.equal(parsed.mode, "preflight");
    assert.equal(parsed.worker, "limitmark-admission-service-staging");
    assert.equal(parsed.providerContact, "none");
    assert.match(parsed.accountFingerprint as string, /^[a-f0-9]{16}$/u);
    assert.ok(!result.stdout.includes(validAccount) && !result.stderr.includes(validAccount), "raw account id must never be printed");
    assert.deepEqual(parsed.plannedCommand, ["wrangler", "deploy", "--config", exactAbsPath]);
  } finally { await rm(exactAbsPath, { force: true }); }
});

guardedTest("staging admission deploy wrapper refuses every alternate rendered filename, even with otherwise-valid content", alternateWrittenPaths, async () => {
  const alternates = ["deployment/admission-service.staging.template.jsonc", "deployment/admission-service.staging.local.jsonc",
    "deployment/admission-service.staging.custom.jsonc", "deployment/gate4-deploy-test-tampered.jsonc"];
  const written: string[] = [];
  try {
    for (const relPath of alternates) {
      if (relPath.endsWith(".template.jsonc")) continue; // real committed template; content is the placeholder, not written here
      const absPath = join(root, relPath);
      await writeFile(absPath, JSON.stringify(validConfig()));
      written.push(absPath);
    }
    for (const relPath of alternates)
      assert.notEqual(run(["preflight", "--config", relPath]).status, 0, `alternate filename must be refused: ${relPath}`);
    // Same exact basename, but outside deployment/ (repo root instead).
    const outsidePath = join(root, "admission-service.staging.jsonc");
    await writeFile(outsidePath, JSON.stringify(validConfig()));
    written.push(outsidePath);
    assert.notEqual(run(["preflight", "--config", "admission-service.staging.jsonc"]).status, 0, "same basename outside deployment/ must be refused");
  } finally { for (const absPath of written) await rm(absPath, { force: true }); }
});

guardedTest("staging admission deploy wrapper still rejects unsafe content at the exact rendered filename", [exactAbsPath], async () => {
  await writeFile(exactAbsPath, JSON.stringify(validConfig({ routes: [{ pattern: "example.com/*" }] })));
  try { assert.notEqual(run(["preflight", "--config", exactRelPath]).status, 0, "unsafe content at the correct filename must still be refused"); }
  finally { await rm(exactAbsPath, { force: true }); }
});

guardedTest("staging admission deploy wrapper refuses every other unsafe input before any provider contact", [exactAbsPath], async () => {
  await writeFile(exactAbsPath, JSON.stringify(validConfig()));
  try {
    assert.notEqual(run(["preflight", "--config", exactRelPath], { CLOUDFLARE_ACCOUNT_ID: undefined }).status, 0, "missing account pin");
    assert.notEqual(run(["preflight", "--config", exactRelPath], { CLOUDFLARE_ACCOUNT_ID: "not-hex" }).status, 0, "malformed account pin");
    assert.notEqual(run(["preflight", "--config", exactRelPath], { CLOUDFLARE_ACCOUNT_ID: "0".repeat(32) }).status, 0, "all-zero account pin");
    assert.notEqual(run(["preflight", "--config", exactRelPath], { CLOUDFLARE_ACCOUNT_ID: "a".repeat(31) }).status, 0, "short account pin");
    assert.notEqual(run(["preflight", "--config", `../${exactRelPath}`]).status, 0, "path outside deployment/");
    assert.notEqual(run(["preflight", "--config", "deployment/does-not-exist.jsonc"]).status, 0, "nonexistent config");
    assert.notEqual(run(["preflight", exactRelPath]).status, 0, "missing --config flag");
    assert.notEqual(run(["preflight", "--config", exactRelPath, "--route", "example.com/*"]).status, 0, "extra Wrangler-shaped arg");
    assert.notEqual(run(["render", "--config", exactRelPath]).status, 0, "unknown mode");
  } finally { await rm(exactAbsPath, { force: true }); }
});

const deployScript = "scripts/authority-staging-admission-deploy.ts";

test("staging admission deploy wrapper: deploy mode still requires the account pin and never starts Wrangler", () =>
  withWranglerSandbox(async (sandbox) => {
    await sandbox.writeDeploymentFile("admission-service.staging.jsonc", JSON.stringify(validConfig()));
    const { result, wrangler } = await sandbox.runWrapper(deployScript, ["deploy", "--config", exactRelPath], { CLOUDFLARE_ACCOUNT_ID: undefined });
    assert.notEqual(result.status, 0, "deploy mode still requires account pin");
    assert.equal(wrangler, null, "no Wrangler process may be started");
  }));

test("staging admission deploy wrapper: deploy mode invokes exactly the planned argv on the (sandboxed, fake) pinned Wrangler", () =>
  withWranglerSandbox(async (sandbox) => {
    const config = await sandbox.writeDeploymentFile("admission-service.staging.jsonc", JSON.stringify(validConfig()));
    const { result, wrangler } = await sandbox.runWrapper(deployScript, ["deploy", "--config", exactRelPath], { CLOUDFLARE_ACCOUNT_ID: validAccount });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(wrangler, { argv: ["deploy", "--config", await realpath(config)] });
    assert.ok(!result.stdout.includes(validAccount) && !result.stderr.includes(validAccount), "raw account id must never be printed");
  }));

guardedTest("standalone preflight script enforces the identical exact-filename invariant as the deploy wrapper", [exactAbsPath, customAbsPath], async () => {
  await writeFile(exactAbsPath, JSON.stringify(validConfig()));
  const altPath = join(root, "deployment", "admission-service.staging.custom.jsonc");
  await writeFile(altPath, JSON.stringify(validConfig()));
  try {
    assert.equal(runPreflightScript(["--config", exactRelPath]).status, 0, "exact filename must PASS");
    assert.notEqual(runPreflightScript(["--config", "deployment/admission-service.staging.custom.jsonc"]).status, 0,
      "an alternate filename the deploy wrapper refuses must not PASS the standalone preflight either");
    assert.notEqual(runPreflightScript(["--config", "deployment/admission-service.staging.template.jsonc"]).status, 0, "raw template");
  } finally { await rm(exactAbsPath, { force: true }); await rm(altPath, { force: true }); }
});
