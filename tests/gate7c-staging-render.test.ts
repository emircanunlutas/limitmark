import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, type KeyObject } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  validateStagingLifecycleMailboxConfig, validateStagingLifecycleObserverConfig, validateStagingLifecycleTransportManifest,
} from "../deployment/lifecycle-private-contract";
import { parseStrictJson } from "../operator/lifecycle-submitter";
import {
  STAGING_RENDER_MODES, STAGING_RENDER_PINS, StagingRenderError, renderStagingConfig, stagingRenderSpec,
  type StagingRenderMode, type StagingRenderPins,
} from "../operator/staging-config-renderer";
import { encodeBase64url } from "../src/lib/ingress-protocol";

// Gate 7C: proves the deterministic staging renderer. Every write in this
// file happens inside a fresh mkdtemp() root (plus a separate mkdtemp() key
// directory); the repository's own deployment/ directory is only ever READ
// (to copy the three committed staging templates) and never written, so real
// operator-rendered artifacts there are untouched. Keys are synthetic,
// generated per run; the operator's protected key is never read -- every
// spawned CLI below runs with HOME/USERPROFILE pointed at a temporary
// directory and a synthetic account that is refused before any key access.

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const templateNames = STAGING_RENDER_MODES.map((mode) => stagingRenderSpec(mode).templateName);
const account = "0123456789abcdef0123456789abcdef";
const plain = (value: unknown) => JSON.parse(JSON.stringify(value)) as unknown;
const fp16 = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest("hex").slice(0, 16);

type Env = { root: string; keyDir: string; keyPath: string; publicKey: string; pins: StagingRenderPins; cleanup: () => Promise<void> };

function pkcs8(key: KeyObject): string { return encodeBase64url(new Uint8Array(key.export({ format: "der", type: "pkcs8" }))); }

async function makeEnv(): Promise<Env> {
  const root = await mkdtemp(join(tmpdir(), "gate7c-root-"));
  const keyDir = await mkdtemp(join(tmpdir(), "gate7c-key-"));
  await mkdir(join(root, "deployment"));
  for (const name of templateNames) await copyFile(join(repoRoot, "deployment", name), join(root, "deployment", name));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const keyPath = join(keyDir, "staging-operator-private-key.pkcs8.b64url");
  await writeFile(keyPath, pkcs8(privateKey));
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
  return {
    root, keyDir, keyPath, publicKey: encodeBase64url(new Uint8Array(raw)),
    pins: { accountFingerprint: fp16(account), keyFingerprint: fp16(raw) },
    cleanup: async () => { await rm(root, { recursive: true, force: true }); await rm(keyDir, { recursive: true, force: true }); },
  };
}

async function withEnv(fn: (env: Env) => Promise<void>): Promise<void> {
  const env = await makeEnv();
  try { await fn(env); } finally { await env.cleanup(); }
}

const render = (env: Env, mode: string, overrides: Partial<Parameters<typeof renderStagingConfig>[0]> = {}) =>
  renderStagingConfig({ mode, root: env.root, keyPath: env.keyPath, accountId: account, pins: env.pins, ...overrides });

async function refusesWith(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => error instanceof StagingRenderError && error.code === code, `expected refusal ${code}`);
}

async function outputAbsent(env: Env, mode: StagingRenderMode): Promise<void> {
  await assert.rejects(readFile(join(env.root, "deployment", stagingRenderSpec(mode).outputName)), /ENOENT/u, "no output may be written");
}

function runPreflight(env: Env, mode: string, name: string) {
  return spawnSync(process.execPath, [join(repoRoot, "node_modules/tsx/dist/cli.mjs"), join(repoRoot, "scripts/lifecycle-private-preflight.ts"),
    mode, "--config", `deployment/${name}`], { cwd: env.root, encoding: "utf8" });
}

function runCli(env: Env, args: string[], accountId: string | null = account) {
  const childEnv: NodeJS.ProcessEnv = { ...process.env, HOME: env.keyDir, USERPROFILE: env.keyDir };
  for (const name of Object.keys(childEnv)) if (name.toUpperCase() === "CLOUDFLARE_ACCOUNT_ID") delete childEnv[name];
  if (accountId !== null) childEnv.CLOUDFLARE_ACCOUNT_ID = accountId;
  return spawnSync(process.execPath, [join(repoRoot, "node_modules/tsx/dist/cli.mjs"), join(repoRoot, "scripts/authority-staging-render.ts"), ...args],
    { cwd: env.root, encoding: "utf8", env: childEnv });
}

test("the closed mode table reaches only the three exact staging templates and outputs", () => {
  assert.deepEqual([...STAGING_RENDER_MODES], ["staging-transport", "staging-mailbox", "staging-observer"]);
  assert.deepEqual(STAGING_RENDER_MODES.map((mode) => [stagingRenderSpec(mode).templateName, stagingRenderSpec(mode).outputName]), [
    ["lifecycle-transport.staging.template.json", "lifecycle-transport.staging.json"],
    ["lifecycle-mailbox.staging.template.jsonc", "lifecycle-mailbox.staging.jsonc"],
    ["lifecycle-observer.staging.template.jsonc", "lifecycle-observer.staging.jsonc"],
  ]);
  assert.deepEqual(STAGING_RENDER_PINS, { accountFingerprint: "0df3a690b3154513", keyFingerprint: "74f6e266c7cbdced" });
  assert.equal(stagingRenderSpec("staging-observer").usesPublicKey, false);
});

test("staging-transport renders the exact contract manifest, byte-for-byte from the template", () => withEnv(async (env) => {
  const result = await render(env, "staging-transport");
  assert.deepEqual(result, { status: "PASS", mode: "staging-transport", output: "deployment/lifecycle-transport.staging.json",
    accountFingerprint: env.pins.accountFingerprint, keyFingerprint: env.pins.keyFingerprint, scheduleState: null, providerContact: "none" });
  const bytes = await readFile(join(env.root, "deployment", "lifecycle-transport.staging.json"));
  assert.notEqual(bytes[0], 0xef, "no BOM");
  const template = await readFile(join(repoRoot, "deployment", "lifecycle-transport.staging.template.json"), "utf8");
  const expectedText = template.replace('"__REQUIRED_CLOUDFLARE_ACCOUNT_ID__"', JSON.stringify(account))
    .replace('"__REQUIRED_STAGING_OPERATOR_ED25519_PUBLIC_KEY__"', JSON.stringify(env.publicKey));
  assert.equal(bytes.toString("utf8"), expectedText, "only the two reviewed placeholders change");
  const manifest = parseStrictJson(bytes.toString("utf8"));
  assert.deepEqual(plain(manifest), { version: 1, environment: "staging", accountId: account, requestBucket: "limitmark-lifecycle-requests-staging",
    resultBucket: "limitmark-lifecycle-results-staging", authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1",
    operatorPublicKey: env.publicKey });
  validateStagingLifecycleTransportManifest(manifest, false);
  const preflight = runPreflight(env, "staging-transport", "lifecycle-transport.staging.json");
  assert.equal(preflight.status, 0, preflight.stderr);
}));

test("staging-mailbox renders an inactive config carrying only the derived public key", () => withEnv(async (env) => {
  const result = await render(env, "staging-mailbox");
  assert.equal(result.scheduleState, "STAGING_DEPLOYMENT_INACTIVE");
  assert.equal(result.keyFingerprint, env.pins.keyFingerprint);
  const text = await readFile(join(env.root, "deployment", "lifecycle-mailbox.staging.jsonc"), "utf8");
  const template = await readFile(join(repoRoot, "deployment", "lifecycle-mailbox.staging.template.jsonc"), "utf8");
  const expectedText = template.replace('"__REQUIRED_RENDERED_STAGING_MAILBOX_MAIN__.ts"', '"../workers/lifecycle-mailbox/staging-index.ts"')
    .replace('"__REQUIRED_CLOUDFLARE_ACCOUNT_ID__"', JSON.stringify(account))
    .replace('"__REQUIRED_STAGING_OPERATOR_ED25519_PUBLIC_KEY__"', JSON.stringify(env.publicKey));
  assert.equal(text, expectedText);
  const config = parseStrictJson(text) as Record<string, unknown>;
  assert.deepEqual(plain(config.triggers), { crons: [] });
  assert.deepEqual(plain(config.vars), { AUTHORITY_OPERATOR_PUBLIC_KEY: env.publicKey, LIFECYCLE_ENVIRONMENT: "staging" });
  assert.equal(validateStagingLifecycleMailboxConfig(config, false, "STAGING_DEPLOYMENT_INACTIVE"), "STAGING_DEPLOYMENT_INACTIVE");
  const preflight = runPreflight(env, "staging-mailbox", "lifecycle-mailbox.staging.jsonc");
  assert.equal(preflight.status, 0, preflight.stderr);
  assert.match(preflight.stdout, /STAGING_DEPLOYMENT_INACTIVE/u);
}));

test("staging-observer renders an inactive config with no vars and never reads the key", () => withEnv(async (env) => {
  const result = await render(env, "staging-observer", { keyPath: join(env.keyDir, "does-not-exist") });
  assert.equal(result.keyFingerprint, null);
  assert.equal(result.scheduleState, "STAGING_DEPLOYMENT_INACTIVE");
  const text = await readFile(join(env.root, "deployment", "lifecycle-observer.staging.jsonc"), "utf8");
  const config = parseStrictJson(text) as Record<string, unknown>;
  assert.equal(Object.hasOwn(config, "vars"), false);
  assert.equal(text.includes("AUTHORITY_OPERATOR_PUBLIC_KEY"), false);
  assert.equal(text.includes(env.publicKey), false);
  assert.deepEqual(plain(config.triggers), { crons: [] });
  assert.equal(config.main, "../workers/staging-lifecycle-observer.ts");
  assert.equal(validateStagingLifecycleObserverConfig(config, false, "STAGING_DEPLOYMENT_INACTIVE"), "STAGING_DEPLOYMENT_INACTIVE");
  const preflight = runPreflight(env, "staging-observer", "lifecycle-observer.staging.jsonc");
  assert.equal(preflight.status, 0, preflight.stderr);
}));

test("account pin: wrong fingerprint, malformed, all-zero and missing accounts refuse", () => withEnv(async (env) => {
  for (const mode of STAGING_RENDER_MODES) {
    await refusesWith(render(env, mode, { pins: { ...env.pins, accountFingerprint: "0".repeat(16) } }), "account-fingerprint-mismatch");
    for (const bad of [undefined, "", account.toUpperCase(), "0".repeat(32), `${account}0`, account.slice(1)])
      await refusesWith(render(env, mode, { accountId: bad }), "missing-or-malformed-account-pin");
    await outputAbsent(env, mode);
  }
}));

test("key continuity: wrong fingerprint, malformed, non-Ed25519, missing and repository-contained keys refuse", () => withEnv(async (env) => {
  for (const mode of ["staging-transport", "staging-mailbox"] as const) {
    await refusesWith(render(env, mode, { pins: { ...env.pins, keyFingerprint: "f".repeat(16) } }), "staging-key-fingerprint-mismatch");
    const other = generateKeyPairSync("ed25519").privateKey;
    await writeFile(join(env.keyDir, "other"), pkcs8(other));
    await refusesWith(render(env, mode, { keyPath: join(env.keyDir, "other") }), "staging-key-fingerprint-mismatch");
    await writeFile(join(env.keyDir, "newline"), `${await readFile(env.keyPath, "utf8")}\n`);
    await refusesWith(render(env, mode, { keyPath: join(env.keyDir, "newline") }), "staging-key-not-canonical-base64url");
    await writeFile(join(env.keyDir, "garbage"), encodeBase64url(new Uint8Array(48).fill(9)));
    await refusesWith(render(env, mode, { keyPath: join(env.keyDir, "garbage") }), "staging-key-not-pkcs8");
    await writeFile(join(env.keyDir, "p256"), pkcs8(generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey));
    await refusesWith(render(env, mode, { keyPath: join(env.keyDir, "p256") }), "staging-key-not-ed25519");
    await writeFile(join(env.keyDir, "x25519"), pkcs8(generateKeyPairSync("x25519").privateKey));
    await refusesWith(render(env, mode, { keyPath: join(env.keyDir, "x25519") }), "staging-key-not-ed25519");
    await writeFile(join(env.keyDir, "empty"), "");
    await refusesWith(render(env, mode, { keyPath: join(env.keyDir, "empty") }), "staging-key-file-size");
    await refusesWith(render(env, mode, { keyPath: join(env.keyDir, "missing") }), "staging-key-file-unavailable");
    await writeFile(join(env.root, "inside.pkcs8.b64url"), await readFile(env.keyPath));
    await refusesWith(render(env, mode, { keyPath: join(env.root, "inside.pkcs8.b64url") }), "staging-key-file-inside-repository");
    await outputAbsent(env, mode);
  }
}));

test("template placeholders: duplicate, missing, unexpected, misplaced and Production-shaped templates refuse", () => withEnv(async (env) => {
  const mailboxTemplate = join(env.root, "deployment", "lifecycle-mailbox.staging.template.jsonc");
  const original = await readFile(mailboxTemplate, "utf8");
  const cases: [string, string][] = [
    [original.replace('"LIFECYCLE_ENVIRONMENT": "staging"', '"LIFECYCLE_ENVIRONMENT": "__REQUIRED_CLOUDFLARE_ACCOUNT_ID__"'), "template-placeholder-not-exactly-once"],
    [original.replace('"__REQUIRED_CLOUDFLARE_ACCOUNT_ID__"', JSON.stringify(account)), "template-placeholder-not-exactly-once"],
    [original.replace('"2026-09-13"', '"__REQUIRED_COMPATIBILITY_DATE__"'), "template-unexpected-placeholder"],
    [original.replace('"triggers": { "crons": [] }', '"triggers": { "crons": ["* * * * *"] }'), "template-shape-not-reviewed"],
    [original.replace("limitmark-lifecycle-requests-staging", "limitmark-lifecycle-requests-production"), "template-shape-not-reviewed"],
    [original.replace('"preview_urls": false,', '"preview_urls": false, "routes": [],'), "template-shape-not-reviewed"],
    [original.replace('"main": "__REQUIRED_RENDERED_STAGING_MAILBOX_MAIN__.ts"', '"main": "__REQUIRED_CLOUDFLARE_ACCOUNT_ID__"')
      .replace('"account_id": "__REQUIRED_CLOUDFLARE_ACCOUNT_ID__"', '"account_id": "__REQUIRED_RENDERED_STAGING_MAILBOX_MAIN__.ts"'), "template-shape-not-reviewed"],
    [`// comment\n${original}`, "template-not-strict-json"],
    [`﻿${original}`, "template-bom"],
  ];
  for (const [source, code] of cases) {
    await writeFile(mailboxTemplate, source);
    await refusesWith(render(env, "staging-mailbox"), code);
    await outputAbsent(env, "staging-mailbox");
  }
  const transportTemplate = join(env.root, "deployment", "lifecycle-transport.staging.template.json");
  await copyFile(join(repoRoot, "deployment", "lifecycle-transport.production.template.json"), transportTemplate);
  await assert.rejects(render(env, "staging-transport"), StagingRenderError);
  await outputAbsent(env, "staging-transport");
}));

test("Production and unknown modes are unreachable", () => withEnv(async (env) => {
  for (const mode of ["transport", "mailbox", "observer", "production-transport", "staging-executor", "staging-admission", "staging-mailbox-arm", ""])
    await refusesWith(render(env, mode), "unknown-staging-render-mode");
}));

test("an existing output is refused without modification, before any key access", () => withEnv(async (env) => {
  for (const mode of STAGING_RENDER_MODES) {
    const output = join(env.root, "deployment", stagingRenderSpec(mode).outputName);
    const sentinel = Buffer.from(`gate7c-sentinel-${mode}\n`);
    await writeFile(output, sentinel);
    await refusesWith(render(env, mode, { keyPath: join(env.keyDir, "missing") }), "output-already-exists");
    assert.deepEqual(await readFile(output), sentinel);
  }
}));

test("a symlinked deployment directory is refused", async (t) => {
  await withEnv(async (env) => {
    const elsewhere = await mkdtemp(join(tmpdir(), "gate7c-elsewhere-"));
    try {
      await rm(join(env.root, "deployment"), { recursive: true });
      try { await symlink(elsewhere, join(env.root, "deployment"), "junction"); }
      catch { t.skip("symlink/junction creation not permitted on this host"); return; }
      await refusesWith(render(env, "staging-observer"), "deployment-directory-not-exact");
    } finally { await rm(elsewhere, { recursive: true, force: true }); }
  });
});

test("CLI accepts exactly one closed mode and no path/account/key/cron arguments", () => withEnv(async (env) => {
  for (const args of [[], ["staging-mailbox", "--output", "x.jsonc"], ["staging-transport", "--account", account], ["staging-mailbox", "--cron", "* * * * *"],
    ["mailbox"], ["transport"], ["staging-mailbox", "staging-observer"], ["--config", "deployment/lifecycle-mailbox.staging.jsonc"]]) {
    const result = runCli(env, args);
    assert.equal(result.status, 2, `args ${JSON.stringify(args)} must be refused`);
    assert.match(result.stderr, /REFUSED \(explicit-staging-render-mode-required\)/u);
    assert.equal(result.stdout, "");
  }
  for (const mode of STAGING_RENDER_MODES) await outputAbsent(env, mode);
}));

test("CLI refuses a non-pinned account before key access and prints no account or key material", () => withEnv(async (env) => {
  for (const mode of STAGING_RENDER_MODES) {
    const result = runCli(env, [mode]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /REFUSED \(account-fingerprint-mismatch\)/u);
    assert.equal(result.stdout, "");
    assert.equal(`${result.stdout}${result.stderr}`.includes(account), false);
    assert.equal(`${result.stdout}${result.stderr}`.includes(env.publicKey), false);
    const missing = runCli(env, [mode], null);
    assert.match(missing.stderr, /REFUSED \(missing-or-malformed-account-pin\)/u);
    await outputAbsent(env, mode);
  }
}));

test("renderer and CLI sources have no process, network or provider path", async () => {
  for (const file of ["operator/staging-config-renderer.ts", "scripts/authority-staging-render.ts"]) {
    const source = await readFile(join(repoRoot, file), "utf8");
    for (const forbidden of [/child_process/u, /node:net\b/u, /node:https?\b/u, /node:dns\b/u, /node:tls\b/u, /\bfetch\s*\(/u, /undici/u,
      /wrangler/iu, /r2-transport/u, /generateKey/u, /\.production\./u])
      assert.doesNotMatch(source, forbidden, `${file} must not match ${forbidden}`);
  }
});
