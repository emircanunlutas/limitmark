import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";

// Gate 4B: proves the deploy wrapper (and the standalone preflight it must
// never be looser than) refuses every unsafe input -- including every
// alternate rendered filename -- before either script could ever spawn
// Wrangler, and that preflight mode reaches PASS without contacting
// Cloudflare. "deploy" mode is never exercised on the happy path here -- only
// its refusal paths -- because a successful "deploy" invocation would spawn
// the real Wrangler binary.

const root = fileURLToPath(new URL("../", import.meta.url));
const validAccount = "a".repeat(32);
const validKey = encodeBase64url(new Uint8Array(32).fill(7));
// The one filename the reviewed .gitignore rule and runbook name; the same
// filename the deploy wrapper's and preflight's exact-rendered-config
// invariant require.
const exactRelPath = "deployment/admission-service.staging.jsonc";
const exactAbsPath = join(root, "deployment", "admission-service.staging.jsonc");

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

test("staging admission deploy wrapper preflight PASSes at the exact rendered filename without contacting Cloudflare and never leaks the account id", async () => {
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

test("staging admission deploy wrapper refuses every alternate rendered filename, even with otherwise-valid content", async () => {
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

test("staging admission deploy wrapper still rejects unsafe content at the exact rendered filename", async () => {
  await writeFile(exactAbsPath, JSON.stringify(validConfig({ routes: [{ pattern: "example.com/*" }] })));
  try { assert.notEqual(run(["preflight", "--config", exactRelPath]).status, 0, "unsafe content at the correct filename must still be refused"); }
  finally { await rm(exactAbsPath, { force: true }); }
});

test("staging admission deploy wrapper refuses every other unsafe input before any provider contact", async () => {
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
    assert.notEqual(run(["deploy", "--config", exactRelPath], { CLOUDFLARE_ACCOUNT_ID: undefined }).status, 0, "deploy mode still requires account pin");
  } finally { await rm(exactAbsPath, { force: true }); }
});

test("standalone preflight script enforces the identical exact-filename invariant as the deploy wrapper", async () => {
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
