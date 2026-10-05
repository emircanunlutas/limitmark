import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validateStagingLifecycleObserverConfig } from "../deployment/lifecycle-private-contract";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { generateStagingAttestationKey } from "../operator/staging-attestation-key";
import {
  R06PreflightError, REVIEWED_WRANGLER_VERSION, runR06ActivationPreflight, type GitRunner, type R06PreflightRequest,
} from "../operator/staging-r06-preflight";
import { renderR06Artifact } from "../operator/staging-r06-renderer";
import { createProtectedKeyDirectory, protectKeyDirectory } from "./support/r06-key-directory";

// R06 activation (T4): the composite local preflight. The whole fixture is a synthetic "repository" under mkdtemp(); git is an injected
// scripted runner (so no process is spawned and the real repository is never inspected); keys, accounts and configs are synthetic.
// The preflight authorizes nothing, and this file proves it contacts no provider and only ever asks git two read-only questions.

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const account = "0123456789abcdef0123456789abcdef";
const HEAD = "a".repeat(40);
const NOW = Date.now();
const sha256 = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest("hex");

type Fixture = { root: string; home: string; keys: string; operatorPublicKey: string; operatorFingerprint: string; calls: string[][];
  request: R06PreflightRequest; cleanup: () => Promise<void> };

async function makeFixture(): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "r06-preflight-root-"));
  const home = await mkdtemp(join(tmpdir(), "r06-preflight-home-"));
  const keys = await createProtectedKeyDirectory(home);
  await mkdir(join(root, "deployment"));
  await mkdir(join(root, "node_modules", "wrangler"), { recursive: true });
  await writeFile(join(root, "package.json"), JSON.stringify({ devDependencies: { wrangler: REVIEWED_WRANGLER_VERSION } }));
  await writeFile(join(root, "package-lock.json"), JSON.stringify({ packages: { "node_modules/wrangler": { version: REVIEWED_WRANGLER_VERSION } } }));
  await writeFile(join(root, "node_modules", "wrangler", "package.json"), JSON.stringify({ version: REVIEWED_WRANGLER_VERSION }));
  for (const name of ["admission-service.staging.template.jsonc", "authority-result-trust.template.json", "lifecycle-observer.staging.template.jsonc"])
    await copyFile(join(repoRoot, "deployment", name), join(root, "deployment", name));

  const raw = Buffer.from(generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x as string, "base64url");
  const operatorPublicKey = encodeBase64url(new Uint8Array(raw));
  const operatorFingerprint = sha256(raw);
  const pins = { accountFingerprint: sha256(account).slice(0, 16), keyFingerprint: operatorFingerprint.slice(0, 16) };
  const transportTemplate = JSON.parse(await readFile(join(repoRoot, "deployment", "lifecycle-transport.staging.template.json"), "utf8")) as Record<string, unknown>;
  await writeFile(join(root, "deployment", "lifecycle-transport.staging.json"), JSON.stringify({ ...transportTemplate, accountId: account, operatorPublicKey }));
  await renderR06Artifact({ mode: "staging-admission", root, keyDirectory: keys, nowMs: NOW, pins });

  const observerTemplate = JSON.parse(await readFile(join(repoRoot, "deployment", "lifecycle-observer.staging.template.jsonc"), "utf8")) as Record<string, unknown>;
  const observer = { ...observerTemplate, main: "../workers/staging-lifecycle-observer.ts", account_id: account, triggers: { crons: ["* * * * *"] } };
  validateStagingLifecycleObserverConfig(observer, false, "STAGING_SCHEDULE_ARMED");
  await writeFile(join(root, "deployment", "lifecycle-observer.staging.armed.jsonc"), JSON.stringify(observer));

  await generateStagingAttestationKey({ directory: keys, repositoryRoot: root, nowMs: NOW - 60_000, operatorFingerprint });
  await renderR06Artifact({ mode: "staging-trust", root, keyDirectory: keys, nowMs: NOW, pins });

  const calls: string[][] = [];
  const git: GitRunner = (args) => {
    calls.push([...args]);
    if (args[0] === "rev-parse") return { status: 0, stdout: `${HEAD}\n` };
    return { status: 0, stdout: "" };
  };
  return { root, home, keys, operatorPublicKey, operatorFingerprint, calls,
    request: { root, expectedHead: HEAD, env: { CLOUDFLARE_ACCOUNT_ID: account, PATH: "x" }, keyDirectory: keys, nowMs: NOW, git, pins, operatorFingerprint },
    cleanup: async () => { await rm(root, { recursive: true, force: true }); await rm(home, { recursive: true, force: true }); } };
}
async function withFixture(fn: (fixture: Fixture) => Promise<void>): Promise<void> {
  const fixture = await makeFixture();
  try { await fn(fixture); } finally { await fixture.cleanup(); }
}
async function refusesWith(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => error instanceof R06PreflightError && error.code === code, `expected refusal ${code}`);
}
const withRequest = (fixture: Fixture, over: Partial<R06PreflightRequest>) => ({ ...fixture.request, ...over });

test("a fully consistent synthetic activation set passes, authorizes nothing, contacts no provider and asks git exactly two read-only questions", () => withFixture(async (f) => {
  const result = await runR06ActivationPreflight(f.request);
  assert.equal(result.status, "PASS");
  assert.equal(result.authorization, "none");
  assert.equal(result.providerContact, "none");
  assert.equal(result.head, HEAD);
  assert.equal(result.wranglerVersion, REVIEWED_WRANGLER_VERSION);
  assert.deepEqual(result.scope, { included: ["admission", "attestation-secrets", "observer"], excludedByDesign: ["mailbox", "executor"] });
  assert.equal(result.plannedSequence.length, 4);
  assert.deepEqual(f.calls, [["rev-parse", "HEAD"], ["status", "--porcelain=v1", "--untracked-files=all"]]);
  const printed = JSON.stringify(result);
  for (const secret of [account, f.operatorPublicKey]) assert.equal(printed.includes(secret), false, "no raw account id or key value is printed");
}));

test("argument, environment and account preconditions", () => withFixture(async (f) => {
  for (const head of ["", "abc", "A".repeat(40), `${"a".repeat(39)}g`, `${HEAD}0`]) await refusesWith(runR06ActivationPreflight(withRequest(f, { expectedHead: head })), "expected-head-malformed");
  await refusesWith(runR06ActivationPreflight(withRequest(f, { nowMs: Number.NaN })), "clock-unavailable");
  for (const name of ["AUTHORITY_STAGING_OPERATOR_PRIVATE_KEY", "AUTHORITY_OPERATOR_PRIVATE_KEY", "AUTHORITY_STAGING_ATTESTATION_PRIVATE_KEY", "authority_x_private_key"])
    for (const value of ["synthetic", ""]) await refusesWith(runR06ActivationPreflight(withRequest(f, { env: { ...f.request.env, [name]: value } })), "private-key-in-environment");
  for (const bad of [undefined, "", "ABC", "0".repeat(32)]) await refusesWith(runR06ActivationPreflight(withRequest(f, { env: { PATH: "x", CLOUDFLARE_ACCOUNT_ID: bad } })), "account-pin-missing-or-malformed");
  await refusesWith(runR06ActivationPreflight(withRequest(f, { env: { PATH: "x", CLOUDFLARE_ACCOUNT_ID: "f".repeat(32) } })), "account-fingerprint-mismatch");
  assert.deepEqual(f.calls, [], "git is not consulted before the cheap local preconditions pass");
}));

test("git preconditions: unavailable, wrong commit, dirty tree, failing status", () => withFixture(async (f) => {
  const run = (git: GitRunner) => runR06ActivationPreflight(withRequest(f, { git }));
  await refusesWith(run(() => ({ status: 128, stdout: "" })), "git-head-unavailable");
  await refusesWith(run(() => ({ status: 0, stdout: "not-a-hash\n" })), "git-head-unavailable");
  await refusesWith(run((args) => args[0] === "rev-parse" ? { status: 0, stdout: `${"b".repeat(40)}\n` } : { status: 0, stdout: "" }), "git-head-not-the-reviewed-commit");
  await refusesWith(run((args) => args[0] === "rev-parse" ? { status: 0, stdout: `${HEAD}\n` } : { status: 0, stdout: " M workers/x.ts\n" }), "git-tree-not-clean");
  await refusesWith(run((args) => args[0] === "rev-parse" ? { status: 0, stdout: `${HEAD}\n` } : { status: 0, stdout: "?? stray.txt\n" }), "git-tree-not-clean");
  await refusesWith(run((args) => args[0] === "rev-parse" ? { status: 0, stdout: `${HEAD}\n` } : { status: 1, stdout: "" }), "git-status-unavailable");
}));

test("F1: an implicit Wrangler dotenv entry in the repository root refuses the preflight (git-ignored `.env*` files are invisible to the clean-tree check)", () => withFixture(async (f) => {
  await runR06ActivationPreflight(f.request);
  for (const name of [".env", ".env.local", ".env.staging", ".env.staging.local", ".env.", ".ENV"]) {
    await writeFile(join(f.root, name), "CLOUDFLARE_API_BASE_URL=https://attacker.invalid\nHTTPS_PROXY=http://attacker.invalid:3128\nWRANGLER_LOG=debug\n");
    await refusesWith(runR06ActivationPreflight(f.request), "dotenv-entry-in-working-directory");
    await rm(join(f.root, name));
  }
  await mkdir(join(f.root, ".env.local"));
  await refusesWith(runR06ActivationPreflight(f.request), "dotenv-entry-in-working-directory");
  await rm(join(f.root, ".env.local"), { recursive: true });
  await writeFile(join(f.root, ".env.example"), "CLOUDFLARE_API_TOKEN=\n");
  assert.equal((await runR06ActivationPreflight(f.request)).status, "PASS", "the tracked template is the one tolerated name");
}));

test("Wrangler must be the one reviewed version in package.json, the lockfile and the installed package", () => withFixture(async (f) => {
  const files = { "package.json": JSON.stringify({ devDependencies: { wrangler: "^4.143.1" } }), "package-lock.json": JSON.stringify({ packages: { "node_modules/wrangler": { version: "4.131.1" } } }) };
  const good = { "package.json": await readFile(join(f.root, "package.json"), "utf8"), "package-lock.json": await readFile(join(f.root, "package-lock.json"), "utf8") };
  for (const [name, bad] of Object.entries(files)) {
    await writeFile(join(f.root, name), bad);
    await refusesWith(runR06ActivationPreflight(f.request), "wrangler-version-not-the-reviewed-pin");
    await writeFile(join(f.root, name), good[name as keyof typeof good]);
  }
  await writeFile(join(f.root, "node_modules", "wrangler", "package.json"), JSON.stringify({ version: "4.131.1" }));
  await refusesWith(runR06ActivationPreflight(f.request), "wrangler-version-not-the-reviewed-pin");
  await rm(join(f.root, "node_modules", "wrangler", "package.json"));
  await refusesWith(runR06ActivationPreflight(f.request), "wrangler-not-installed");
}));

test("rendered artifacts: exact names, existing contract validators and mutual continuity", async (t) => {
  await withFixture(async (f) => {
    const dir = join(f.root, "deployment");
    const original = async (name: string) => readFile(join(dir, name), "utf8");
    const mutate = async (name: string, change: (text: string) => string, code: string) => {
      const before = await original(name);
      await writeFile(join(dir, name), change(before));
      try { await refusesWith(runR06ActivationPreflight(f.request), code); } finally { await writeFile(join(dir, name), before); }
    };
    await runR06ActivationPreflight(f.request);

    // transport manifest
    await mutate("lifecycle-transport.staging.json", (text) => text.replace('"staging"', '"production"'), "transport-manifest-contract-failed");
    await mutate("lifecycle-transport.staging.json", () => "{ not json", "transport-manifest-not-strict-json");
    await mutate("lifecycle-transport.staging.json", (text) => text.replace(account, "1".repeat(32)), "transport-account-mismatch");
    // admission config
    await mutate("admission-service.staging.jsonc", (text) => text.replace("limitmark-admission-service-staging", "limitmark-admission-service-production"), "admission-config-contract-failed");
    await mutate("admission-service.staging.jsonc", (text) => text.replace(f.operatorPublicKey, encodeBase64url(new Uint8Array(32).fill(7))), "admission-operator-key-differs-from-transport");
    // observer: inactive schedule, other account, extra vars, alternate content
    await mutate("lifecycle-observer.staging.armed.jsonc", (text) => text.replace('"* * * * *"', ""), "observer-armed-config-contract-failed");
    await mutate("lifecycle-observer.staging.armed.jsonc", (text) => text.replace(account, "2".repeat(32)), "observer-account-differs-from-pin");
    await mutate("lifecycle-observer.staging.armed.jsonc", (text) => text.replace('"workers_dev":false', '"workers_dev":true'), "observer-armed-config-contract-failed");
    // missing
    for (const [name, code] of [["lifecycle-transport.staging.json", "transport-manifest-missing"], ["admission-service.staging.jsonc", "admission-config-missing"],
      ["lifecycle-observer.staging.armed.jsonc", "observer-armed-config-missing"], ["authority-result-trust.json", "trust-manifest-missing"]] as const) {
      const before = await original(name);
      await rm(join(dir, name));
      try { await refusesWith(runR06ActivationPreflight(f.request), code); } finally { await writeFile(join(dir, name), before); }
    }
    // a symlink at an exact name pointing elsewhere is refused as not exact
    const before = await original("authority-result-trust.json");
    const elsewhere = join(f.home, "elsewhere.json");
    await writeFile(elsewhere, before);
    await rm(join(dir, "authority-result-trust.json"));
    try { await symlink(elsewhere, join(dir, "authority-result-trust.json"), "file"); }
    catch { t.diagnostic("symlink creation unavailable on this platform; symlink case skipped"); await writeFile(join(dir, "authority-result-trust.json"), before); return; }
    await refusesWith(runR06ActivationPreflight(f.request), "trust-manifest-not-exact");
  });
});

test("attestation key custody and the trust manifest that names it must agree", () => withFixture(async (f) => {
  const dir = join(f.root, "deployment");
  const trustPath = join(dir, "authority-result-trust.json");
  const trust = await readFile(trustPath, "utf8");
  type Trust = { environments: Array<{ currentKeyFingerprint: string; keys: Array<Record<string, unknown>> }> };
  const edit = async (change: (value: Trust) => void) => {
    const value = JSON.parse(trust) as Trust;
    change(value);
    await writeFile(trustPath, JSON.stringify(value));
  };

  // staging section naming another key (a perfectly valid manifest, but not this custody key)
  const other = await mkdtemp(join(tmpdir(), "r06-preflight-other-"));
  try {
    await mkdir(join(other, "staging"));
    await protectKeyDirectory(join(other, "staging"));
    await generateStagingAttestationKey({ directory: join(other, "staging"), repositoryRoot: f.root, nowMs: NOW - 60_000, operatorFingerprint: f.operatorFingerprint });
    await rm(trustPath);
    await renderR06Artifact({ mode: "staging-trust", root: f.root, keyDirectory: join(other, "staging"), nowMs: NOW, pins: f.request.pins });
    await refusesWith(runR06ActivationPreflight(f.request), "trust-manifest-staging-section-does-not-match-key");
  } finally { await rm(other, { recursive: true, force: true }); }

  await writeFile(trustPath, trust);
  await runR06ActivationPreflight(f.request);
  await edit((value) => { value.environments[1].keys[0].notBeforeMs = (value.environments[1].keys[0].notBeforeMs as number) + 1; });
  await refusesWith(runR06ActivationPreflight(f.request), "trust-manifest-staging-section-does-not-match-key");
  await writeFile(trustPath, trust);
  await edit((value) => { value.environments[1].keys[0].notAfterMs = NOW + 1_000_000; });
  await refusesWith(runR06ActivationPreflight(f.request), "trust-manifest-staging-section-does-not-match-key");
  await writeFile(trustPath, "{}");
  await refusesWith(runR06ActivationPreflight(f.request), "trust-manifest-contract-failed");
  await writeFile(trustPath, trust);

  // a custody key dated after "now" cannot be trusted yet
  await refusesWith(runR06ActivationPreflight(withRequest(f, { nowMs: NOW - 10 * 60_000 })), "attestation-key-meta-created-in-the-future");
  // a key whose fingerprint equals the pinned operator fingerprint is refused
  const fingerprint = (JSON.parse(trust) as { environments: Array<{ currentKeyFingerprint: string }> }).environments[1].currentKeyFingerprint;
  await refusesWith(runR06ActivationPreflight(withRequest(f, { operatorFingerprint: fingerprint })), "operator-key-continuity-failed");
  // missing custody
  await rm(join(f.keys, "staging-attestation-private-key.pkcs8.b64url"));
  await refusesWith(runR06ActivationPreflight(f.request), "attestation-key-custody-file-unavailable");
}));

test("the preflight CLI requires exactly --expected-head, and (real pins) refuses a non-pinned account before touching git, files or any provider", async () => {
  const cli = (args: string[], env: Record<string, string | undefined>) => {
    const childEnv: NodeJS.ProcessEnv = { ...process.env };
    for (const name of Object.keys(childEnv)) if (/^CLOUDFLARE_/iu.test(name)) delete childEnv[name];
    Object.assign(childEnv, env);
    for (const [name, value] of Object.entries(childEnv)) if (value === undefined) delete childEnv[name];
    return spawnSync(process.execPath, [join(repoRoot, "node_modules/tsx/dist/cli.mjs"), join(repoRoot, "scripts/authority-staging-r06-preflight.ts"), ...args],
      { cwd: repoRoot, encoding: "utf8", env: childEnv });
  };
  for (const args of [[], ["--expected-head"], ["--expected-head", HEAD, "extra"], ["--head", HEAD], [HEAD]]) {
    const result = cli(args, {});
    assert.equal(result.status, 2);
    assert.match(result.stderr, /REFUSED \(expected-head-argument-required\)/u);
    assert.equal(result.stdout, "");
  }
  const mismatch = cli(["--expected-head", HEAD], { CLOUDFLARE_ACCOUNT_ID: account });
  assert.equal(mismatch.status, 2);
  assert.match(mismatch.stderr, /REFUSED \(account-fingerprint-mismatch\)/u);
  const privateKey = cli(["--expected-head", HEAD], { CLOUDFLARE_ACCOUNT_ID: account, AUTHORITY_STAGING_ATTESTATION_PRIVATE_KEY: "x" });
  assert.match(privateKey.stderr, /REFUSED \(private-key-in-environment\)/u);
  assert.equal(`${mismatch.stdout}${mismatch.stderr}`.includes(account), false);
});

test("source: the preflight only ever spawns git, never Wrangler, and has no network path", async () => {
  const strip = (source: string) => source.split("\n").filter((line) => !line.trim().startsWith("//") && !line.trim().startsWith("*")).join("\n");
  const moduleSource = strip(await readFile(join(repoRoot, "operator/staging-r06-preflight.ts"), "utf8"));
  const script = strip(await readFile(join(repoRoot, "scripts/authority-staging-r06-preflight.ts"), "utf8"));
  assert.equal(moduleSource.match(/spawnSync\(/gu)?.length, 1);
  assert.match(moduleSource, /spawnSync\("git", \[\.\.\.args\]/u);
  assert.equal(/wrangler\.js|bin\/wrangler|secret put|deploy --config|node:(net|http|https|tls|dns)|\bfetch\s*\(|WebSocket/u.test(moduleSource), false);
  assert.equal(/child_process|spawn|node:(net|http|https|tls|dns)|\bfetch\s*\(|WebSocket/u.test(script), false);
});
