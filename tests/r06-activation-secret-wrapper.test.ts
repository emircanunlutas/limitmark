import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ATTESTATION_SIGNER_BINDINGS } from "../workers/admission-service/authority-attestation-config";
import { generateStagingAttestationKey, readStagingAttestationKeyForSecretPut } from "../operator/staging-attestation-key";
import * as productionModule from "../operator/staging-attestation-secret";
import {
  ATTESTATION_SECRET_ORDER, ATTESTATION_SECRET_WORKER, AttestationSecretError, assertNoWranglerConfigInAncestry, buildWranglerChildEnvironment,
  createAttestationSecretTooling, WORKER_CONFIRMATION_FILE, WORKER_CONFIRMATION_MAX_AGE_MS,
} from "../operator/staging-attestation-secret-engine";
import {
  DOTENV_TOLERATED_TEMPLATE, REVIEWED_WRANGLER_VERSION, WRANGLER_DOTENV_DEFAULT_FILES, WranglerPinError, assertNoImplicitWranglerDotenv, isDotenvEntryName,
} from "../operator/staging-wrangler-pin";
import { createProtectedKeyDirectory } from "./support/r06-key-directory";
import { FAKE_WRANGLER_RECORDING_SOURCE, FAKE_WRANGLER_SOURCE, selfTestWranglerSandbox, withWranglerSandbox } from "./support/wrangler-sandbox";

// R06 activation (remediation B1-B3 and hardening): the closed-set attestation-secret engine. No test here reaches the real Wrangler: the
// engine is built over a throwaway sandbox ROOT whose Wrangler is a RECORDING FAKE (tests/support/wrangler-sandbox.ts) that records argv,
// stdin, the working directory and the complete environment it received, then exits. The fail-closed sandbox self-test runs first. Keys,
// accounts and tokens are synthetic; the operator's real key directory, real home and real account are never touched.
//
// The PRODUCTION binding (operator/staging-attestation-secret.ts) is imported only to inspect its exports and to prove that caller-supplied
// root/pins/worker/order/executable are ignored: its account pin is first, so a synthetic account is refused before anything else happens.

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const account = "0123456789abcdef0123456789abcdef";
const pins = { accountFingerprint: createHash("sha256").update(account).digest("hex").slice(0, 16), keyFingerprint: "0".repeat(16) };
const names = ATTESTATION_SIGNER_BINDINGS.staging;
const OS_NAMES = ["PATH", "SystemRoot", "SYSTEMROOT", "windir", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"];

type Env = Record<string, string | undefined>;
type Invocation = { argv: string[]; stdin: string; cwd: string; env: Record<string, string> };
type Tooling = ReturnType<typeof createAttestationSecretTooling>;
type Rig = { root: string; keys: string; home: string; fakePath: string; env: Env; tooling: Tooling };

/** What an operator's shell reasonably looks like: the OS values, the pinned account, nothing hostile. */
function operatorShell(home: string, extra: Env = {}): Env {
  const env: Env = {};
  for (const name of OS_NAMES) if (process.env[name] !== undefined) env[name] = process.env[name];
  Object.assign(env, { HOME: home, USERPROFILE: home, CLOUDFLARE_ACCOUNT_ID: account }, extra);
  for (const [key, value] of Object.entries(env)) if (value === undefined) delete env[key];
  return env;
}

const toolingFor = (root: string, keys: string): Tooling => createAttestationSecretTooling({ root, pins, keyDirectory: () => keys, clock: () => Date.now() });

async function withRig(fn: (rig: Rig) => Promise<void>): Promise<void> {
  await withWranglerSandbox(async (sandbox) => {
    const home = await mkdtemp(join(tmpdir(), "r06-secret-home-"));
    const keys = await createProtectedKeyDirectory(home);
    try {
      await selfTestWranglerSandbox(sandbox.root, operatorShell(home), FAKE_WRANGLER_RECORDING_SOURCE);
      await fn({ root: sandbox.root, keys, home, fakePath: sandbox.fakeWranglerPath, env: operatorShell(home), tooling: toolingFor(sandbox.root, keys) });
    } finally { await rm(home, { recursive: true, force: true }); }
  }, { recording: true });
}

async function invocations(rig: Pick<Rig, "root">): Promise<Invocation[]> {
  let text = "";
  try { text = await readFile(join(rig.root, "fake-wrangler-record.jsonl"), "utf8"); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  return text.split("\n").filter(Boolean).map((line) => JSON.parse(line) as Invocation);
}

const seedKey = (rig: Rig) => generateStagingAttestationKey({ directory: rig.keys, repositoryRoot: rig.root, nowMs: Date.now() - 1_000 });
const confirmation = (overrides: Record<string, unknown> = {}) => ({
  version: 1, environment: "staging", worker: ATTESTATION_SECRET_WORKER, accountFingerprint: pins.accountFingerprint,
  confirmedAtMs: Date.now() - 60_000, evidence: "wrangler-versions-list", deployedVersionIdPrefix: "877ba1f2", ...overrides,
});
const writeConfirmation = (rig: Rig, value: unknown = confirmation()) => writeFile(join(rig.keys, WORKER_CONFIRMATION_FILE), typeof value === "string" ? value : JSON.stringify(value));
async function ready(rig: Rig) { const key = await seedKey(rig); await writeConfirmation(rig); return key; }

async function refusesWith(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => error instanceof AttestationSecretError && error.code === code, `expected refusal ${code}`);
}

test("the reviewed secret names are exactly the three staging signer bindings, private key last, never the Production names", () => {
  assert.deepEqual([...ATTESTATION_SECRET_ORDER], [names.writerKeyFingerprint, names.publicKey, names.privateKey]);
  assert.deepEqual([...ATTESTATION_SECRET_ORDER], ["AUTHORITY_STAGING_ATTESTATION_KEY_FINGERPRINT", "AUTHORITY_STAGING_ATTESTATION_PUBLIC_KEY", "AUTHORITY_STAGING_ATTESTATION_PRIVATE_KEY"]);
  assert.equal(ATTESTATION_SECRET_WORKER, "limitmark-admission-service-staging");
  assert.equal(ATTESTATION_SECRET_ORDER.some((name) => /^AUTHORITY_ATTESTATION_/u.test(name)), false);
  assert.equal(Object.isFrozen(ATTESTATION_SECRET_ORDER), true, "the order cannot be edited in place");
});

test("preflight performs every local check, spawns nothing, and describes the plan without any secret value", () => withRig(async (rig) => {
  const key = await ready(rig);
  const description = await rig.tooling.preflight({ env: { ...rig.env, CLOUDFLARE_API_TOKEN: "synthetic-token-value-0123456789" } });
  assert.equal(description.worker, ATTESTATION_SECRET_WORKER);
  assert.equal(description.accountFingerprint, pins.accountFingerprint);
  assert.equal(description.attestationKeyFingerprint, key.keyFingerprint);
  assert.equal(description.wranglerVersion, REVIEWED_WRANGLER_VERSION);
  assert.equal(description.workerConfirmation.evidence, "wrangler-versions-list");
  assert.equal(description.childEnvironment.authentication, "CLOUDFLARE_API_TOKEN");
  const text = JSON.stringify(description);
  const { privateKey } = await readStagingAttestationKeyForSecretPut({ directory: rig.keys, repositoryRoot: rig.root, nowMs: Date.now() });
  for (const secret of [privateKey, key.publicKey, account, "synthetic-token-value-0123456789", rig.root, rig.home]) assert.equal(text.includes(secret), false, "no secret value or local path in the description");
  assert.deepEqual(await invocations(rig), [], "preflight never spawns");
}));

test("submission spawns the pinned Wrangler exactly three times: closed argv, fixed order, value on stdin only, pinned working directory", () => withRig(async (rig) => {
  const key = await ready(rig);
  const { privateKey } = await readStagingAttestationKeyForSecretPut({ directory: rig.keys, repositoryRoot: rig.root, nowMs: Date.now() });
  const outcome = await rig.tooling.submit({ env: rig.env });
  assert.deepEqual(outcome, { submitted: [...ATTESTATION_SECRET_ORDER], stoppedAt: null });
  const calls = await invocations(rig);
  assert.deepEqual(calls.map((call) => call.argv), ATTESTATION_SECRET_ORDER.map((name) => ["secret", "put", name, "--name", "limitmark-admission-service-staging"]));
  assert.deepEqual(calls.map((call) => call.stdin), [key.keyFingerprint, key.publicKey, privateKey], "values travel on stdin only, private key last");
  for (const call of calls) for (const value of [privateKey, key.publicKey, key.keyFingerprint, account]) assert.equal(call.argv.some((arg) => arg.includes(value)), false, "no value in argv");
  for (const call of calls) assert.equal(call.argv.some((arg) => /^--(env|config|var|route|cron|name-override)/u.test(arg) || arg === "-e" || arg === "-c"), false);
  const realRoot = await realpath(rig.root);
  for (const call of calls) assert.equal(await realpath(call.cwd), realRoot, "the child's working directory is exactly the verified root");
}));

test("submission stops at the first failure and never attempts a later secret", () => withRig(async (rig) => {
  await ready(rig);
  await writeFile(join(rig.root, "fake-wrangler-fail-on"), names.publicKey);
  assert.deepEqual(await rig.tooling.submit({ env: rig.env }), { submitted: [names.writerKeyFingerprint], stoppedAt: names.publicKey });
  const calls = await invocations(rig);
  assert.equal(calls.length, 2, "the private key was never attempted");
  assert.equal(calls.some((call) => call.argv.includes(names.privateKey)), false);
}));

// ---------------------------------------------------------------------------------------------------------------------------------
// B1: the child environment is built, never inherited
// ---------------------------------------------------------------------------------------------------------------------------------

test("B1: the Wrangler child receives a minimal explicit environment; nothing is inherited", () => withRig(async (rig) => {
  await ready(rig);
  const parent = { ...rig.env, CLOUDFLARE_API_TOKEN: "synthetic-token-value-0123456789", WRANGLER_SEND_METRICS: "false",
    // present in many real shells and exported by npm itself: must neither be refused nor forwarded
    NODE: "C:\\node.exe", npm_config_noproxy: "", npm_config_cache: "x", INIT_CWD: rig.root, EDITOR: "vim", SECRET_UNRELATED: "do-not-forward", ANTHROPIC_API_KEY: "do-not-forward",
    AUTHORITY_STAGING_OPERATOR_PUBLIC_KEY: "public-but-not-forwarded", GITHUB_TOKEN: "do-not-forward" };
  await rig.tooling.submit({ env: parent });
  const [first] = await invocations(rig);
  const received = Object.keys(first.env);
  const allowed = new Set([...OS_NAMES, "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN", "WRANGLER_SEND_METRICS"].map((name) => name.toUpperCase()));
  const supplied = new Set(Object.keys(parent).map((name) => name.toUpperCase()));
  // Nothing the PARENT supplied beyond the reviewed list may reach the child. (The Windows loader itself adds a few session values --
  // HOMEDRIVE, USERNAME, ... -- to every process regardless of the env block; those were not in the parent and are not forwarded by us.)
  const inherited = received.filter((name) => !allowed.has(name.toUpperCase()) && supplied.has(name.toUpperCase()));
  assert.deepEqual(inherited, [], `variable(s) inherited from the parent: ${inherited.join(", ")}`);
  assert.deepEqual(received.filter((name) => allowed.has(name.toUpperCase())).map((name) => name.toUpperCase()).filter((name) => !supplied.has(name) && name !== "WRANGLER_SEND_METRICS"), [],
    "only variables the parent actually had are copied from the reviewed OS list");
  for (const name of ["SECRET_UNRELATED", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "INIT_CWD", "EDITOR", "NODE", "npm_config_noproxy", "AUTHORITY_STAGING_OPERATOR_PUBLIC_KEY"])
    assert.equal(received.some((entry) => entry.toUpperCase() === name.toUpperCase()), false, `${name} must not be forwarded`);
  assert.equal(first.env.CLOUDFLARE_ACCOUNT_ID, account);
  assert.equal(first.env.CLOUDFLARE_API_TOKEN, "synthetic-token-value-0123456789");
  assert.equal(first.env.WRANGLER_SEND_METRICS, "false");
  // the account value and the token are in the child environment ONLY: never argv, never stdin
  for (const call of await invocations(rig)) {
    assert.equal(call.argv.join(" ").includes("synthetic-token-value"), false);
    assert.equal(call.stdin.includes("synthetic-token-value"), false);
  }
}));

test("B1: hostile or unexpected variables are REFUSED before anything is read or spawned", () => withRig(async (rig) => {
  await ready(rig);
  const hostile: Array<[string, string, string]> = [
    ["CLOUDFLARE_API_BASE_URL", "https://attacker.example", "unexpected-cloudflare-variable"],
    ["cloudflare_api_base_url", "https://attacker.example", "unexpected-cloudflare-variable"],
    ["CLOUDFLARE_ENV", "production", "unexpected-cloudflare-variable"],
    ["CLOUDFLARE_API_KEY", "synthetic", "unexpected-cloudflare-variable"],
    ["CLOUDFLARE_EMAIL", "a@b.example", "unexpected-cloudflare-variable"],
    ["CLOUDFLARE_ACCOUNT_ID_OVERRIDE", "x", "unexpected-cloudflare-variable"],
    ["CF_ACCOUNT_ID", account, "unexpected-cloudflare-variable"],
    ["CF_API_TOKEN", "synthetic", "unexpected-cloudflare-variable"],
    ["WRANGLER_API_ENVIRONMENT", "staging", "unexpected-wrangler-variable"],
    ["WRANGLER_LOG", "debug", "unexpected-wrangler-variable"],
    ["WRANGLER_HOME", "x", "unexpected-wrangler-variable"],
    ["WRANGLER_SEND_METRICS", "true", "wrangler-metrics-must-be-disabled"],
    ["WRANGLER_SEND_METRICS", "", "wrangler-metrics-must-be-disabled"],
    ["NODE_OPTIONS", "--require ./evil.js", "runtime-injection-variable-in-environment"],
    ["NODE_EXTRA_CA_CERTS", "/tmp/evil.pem", "runtime-injection-variable-in-environment"],
    ["NODE_TLS_REJECT_UNAUTHORIZED", "0", "runtime-injection-variable-in-environment"],
    ["NODE_PATH", "/tmp", "runtime-injection-variable-in-environment"],
    ["LD_PRELOAD", "/tmp/evil.so", "runtime-injection-variable-in-environment"],
    ["DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib", "runtime-injection-variable-in-environment"],
    ["SSL_CERT_FILE", "/tmp/evil.pem", "runtime-injection-variable-in-environment"],
    ["OPENSSL_CONF", "/tmp/evil.cnf", "runtime-injection-variable-in-environment"],
    ["HTTP_PROXY", "http://127.0.0.1:8080", "proxy-variable-in-environment"],
    ["HTTPS_PROXY", "http://127.0.0.1:8080", "proxy-variable-in-environment"],
    ["https_proxy", "http://127.0.0.1:8080", "proxy-variable-in-environment"],
    ["ALL_PROXY", "socks5://127.0.0.1:1080", "proxy-variable-in-environment"],
    ["NO_PROXY", "*", "proxy-variable-in-environment"],
    ["npm_config_https_proxy", "http://127.0.0.1:8080", "proxy-variable-in-environment"],
    ["AUTHORITY_STAGING_ATTESTATION_PRIVATE_KEY", "synthetic", "private-key-in-environment"],
  ];
  for (const [name, value, code] of hostile) {
    await refusesWith(rig.tooling.submit({ env: { ...rig.env, [name]: value } }), code);
    // defined-but-empty counts as defined
    if (!name.startsWith("WRANGLER_SEND")) await refusesWith(rig.tooling.submit({ env: { ...rig.env, [name]: "" } }), code);
  }
  assert.deepEqual(await invocations(rig), [], "no hostile environment ever reached a spawn");
  // an explicitly undefined entry is absent, not defined
  await rig.tooling.preflight({ env: { ...rig.env, NODE_OPTIONS: undefined, HTTPS_PROXY: undefined } });
}));

test("B1: the API token is optional but must be well-formed; the account stays pinned", () => withRig(async (rig) => {
  await ready(rig);
  for (const bad of ["", "has space", "line\nbreak", "x".repeat(513), "ünïcode"]) await refusesWith(rig.tooling.submit({ env: { ...rig.env, CLOUDFLARE_API_TOKEN: bad } }), "api-token-malformed");
  await refusesWith(rig.tooling.submit({ env: { ...rig.env, HOME: "bad\0value" } }), "environment-value-invalid");
  assert.deepEqual(await invocations(rig), []);
  assert.equal((await rig.tooling.preflight({ env: rig.env })).childEnvironment.authentication, "wrangler-login-store");
  const direct = buildWranglerChildEnvironment({ ...rig.env, Path: process.env.PATH });
  assert.equal(Object.keys(direct.values).filter((name) => name.toUpperCase() === "PATH").length, 1, "one spelling per variable");
  assert.equal(direct.values.WRANGLER_SEND_METRICS, "false");
}));

test("B1: private-key material stays stdin-only: it is in no environment, no argv and no description", () => withRig(async (rig) => {
  await ready(rig);
  const { privateKey } = await readStagingAttestationKeyForSecretPut({ directory: rig.keys, repositoryRoot: rig.root, nowMs: Date.now() });
  await rig.tooling.submit({ env: rig.env });
  for (const call of await invocations(rig)) {
    assert.equal(Object.values(call.env).some((value) => value.includes(privateKey)), false, "not in the child environment");
    assert.equal(call.argv.some((arg) => arg.includes(privateKey)), false, "not in argv");
  }
  assert.equal((await invocations(rig)).filter((call) => call.stdin === privateKey).length, 1, "exactly one stdin carries it, and it is the last call");
  assert.equal((await invocations(rig)).at(-1)?.stdin, privateKey);
}));

// ---------------------------------------------------------------------------------------------------------------------------------
// B2: Wrangler searches UPWARD for wrangler.json / wrangler.jsonc / wrangler.toml and for .wrangler/deploy/config.json
// ---------------------------------------------------------------------------------------------------------------------------------

/** A repository-shaped sandbox NESTED three levels under a private parent, so hostile configs can be planted in real ancestors. */
async function withNestedRig(fn: (rig: Rig & { parent: string; levels: string[] }) => Promise<void>): Promise<void> {
  const parent = await realpath(await mkdtemp(join(tmpdir(), "r06-ancestry-")));
  const home = await mkdtemp(join(tmpdir(), "r06-ancestry-home-"));
  try {
    const levels = [join(parent, "one"), join(parent, "one", "two")];
    const root = join(levels[1], "repo");
    const keys = await createProtectedKeyDirectory(home);
    await mkdir(join(root, "node_modules", "wrangler", "bin"), { recursive: true });
    await writeFile(join(root, "node_modules", "wrangler", "bin", "wrangler.js"), FAKE_WRANGLER_RECORDING_SOURCE);
    await writeFile(join(root, "node_modules", "wrangler", "package.json"), JSON.stringify({ name: "wrangler", version: REVIEWED_WRANGLER_VERSION }));
    await writeFile(join(root, "package.json"), JSON.stringify({ name: "sandbox", devDependencies: { wrangler: REVIEWED_WRANGLER_VERSION } }));
    await writeFile(join(root, "package-lock.json"), JSON.stringify({ packages: { "node_modules/wrangler": { version: REVIEWED_WRANGLER_VERSION } } }));
    const rig = { root, keys, home, parent, levels, fakePath: join(root, "node_modules", "wrangler", "bin", "wrangler.js"), env: operatorShell(home), tooling: toolingFor(root, keys) };
    await fn(rig);
  } finally { await rm(parent, { recursive: true, force: true }); await rm(home, { recursive: true, force: true }); }
}

test("B2: a Wrangler configuration in the working directory or in ANY ancestor is refused; a clean ancestry is accepted", () => withNestedRig(async (rig) => {
  await ready(rig);
  await rig.tooling.preflight({ env: rig.env });
  const placements: Array<[string, string, string]> = [
    [rig.root, "wrangler.json", "wrangler-config-in-working-directory"],
    [rig.root, "wrangler.jsonc", "wrangler-config-in-working-directory"],
    [rig.root, "wrangler.toml", "wrangler-config-in-working-directory"],
    [rig.levels[1], "wrangler.toml", "wrangler-config-in-ancestor-directory"],
    [rig.levels[0], "wrangler.jsonc", "wrangler-config-in-ancestor-directory"],
    [rig.parent, "wrangler.json", "wrangler-config-in-ancestor-directory"],
  ];
  for (const [directory, name, code] of placements) {
    const path = join(directory, name);
    await writeFile(path, name.endsWith(".toml") ? "name = \"hostile\"\naccount_id = \"x\"\n" : "{\"name\":\"hostile\"}");
    await refusesWith(rig.tooling.preflight({ env: rig.env }), code);
    await refusesWith(rig.tooling.submit({ env: rig.env }), code);
    await rm(path);
    await rig.tooling.preflight({ env: rig.env });
  }
  // The deploy-config redirect Wrangler also honours, at the root and in an ancestor
  for (const directory of [rig.root, rig.levels[0]]) {
    await mkdir(join(directory, ".wrangler", "deploy"), { recursive: true });
    await writeFile(join(directory, ".wrangler", "deploy", "config.json"), JSON.stringify({ configPath: "../../elsewhere/wrangler.json" }));
    await refusesWith(rig.tooling.submit({ env: rig.env }), directory === rig.root ? "wrangler-config-in-working-directory" : "wrangler-config-in-ancestor-directory");
    await rm(join(directory, ".wrangler"), { recursive: true, force: true });
  }
  // A directory (or any entry) with a config name counts: Wrangler's search is by name, and an unreadable entry is treated as present.
  await mkdir(join(rig.levels[0], "wrangler.toml"));
  await refusesWith(rig.tooling.submit({ env: rig.env }), "wrangler-config-in-ancestor-directory");
  await rm(join(rig.levels[0], "wrangler.toml"), { recursive: true });
  try {
    await symlink(join(rig.parent, "does-not-exist"), join(rig.levels[0], "wrangler.json"));
    await refusesWith(rig.tooling.submit({ env: rig.env }), "wrangler-config-in-ancestor-directory");
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== "EPERM" && (error as NodeJS.ErrnoException).code !== "EACCES") throw error; /* no symlink privilege on this host */ }
  assert.deepEqual(await invocations(rig), [], "no hostile ancestry ever reached a spawn");
}));

test("B2: the ancestry scan is exhaustive up to the filesystem root and fails closed on an entry it cannot examine", async () => {
  const parent = await realpath(await mkdtemp(join(tmpdir(), "r06-scan-")));
  try {
    const deep = join(parent, "a", "b", "c", "d");
    await mkdir(deep, { recursive: true });
    await assertNoWranglerConfigInAncestry(deep);
    await writeFile(join(parent, "a", "wrangler.jsonc"), "{}");
    await assert.rejects(assertNoWranglerConfigInAncestry(deep), (error: unknown) => error instanceof AttestationSecretError && error.code === "wrangler-config-in-ancestor-directory");
    await assert.rejects(assertNoWranglerConfigInAncestry(join(parent, "a")), (error: unknown) => error instanceof AttestationSecretError && error.code === "wrangler-config-in-working-directory");
    // a path component that is a FILE makes lstat fail with ENOTDIR (absent) -- but any other error code refuses; here: a relative-looking segment
    await rm(join(parent, "a", "wrangler.jsonc"));
    await writeFile(join(parent, "a", "b", ".wrangler"), "i am a file, not a directory");
    await assertNoWranglerConfigInAncestry(deep);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test("B2: the check is repeated immediately before EVERY spawn: a config planted during the first put stops the second", () => withNestedRig(async (rig) => {
  await ready(rig);
  await writeFile(join(rig.root, "fake-wrangler-sabotage.json"), JSON.stringify({ path: join(rig.parent, "wrangler.toml"), content: "name = \"planted-mid-run\"\n" }));
  const outcome = await rig.tooling.submit({ env: rig.env });
  assert.deepEqual(outcome, { submitted: [names.writerKeyFingerprint], stoppedAt: names.publicKey });
  assert.equal((await invocations(rig)).length, 1, "the second secret was never attempted");
}));

// ---------------------------------------------------------------------------------------------------------------------------------
// F1: Wrangler loads dotenv files from its working directory by itself, whatever environment the wrapper builds
// ---------------------------------------------------------------------------------------------------------------------------------

/** What a hostile dotenv file would carry: every one of these is refused when it is in the SHELL (B1), and Wrangler would honour it from a file. */
const HOSTILE_DOTENV = [
  "CLOUDFLARE_API_BASE_URL=https://attacker.invalid/client/v4", "CLOUDFLARE_API_TOKEN=stolen-or-substituted-token-0123456789", "HTTPS_PROXY=http://attacker.invalid:3128",
  "WRANGLER_LOG=debug", "WRANGLER_OUTPUT_FILE_PATH=./exfil.ndjson", "NODE_OPTIONS=--require ./preload.js", "CLOUDFLARE_ACCOUNT_ID=ffffffffffffffffffffffffffffffff", "",
].join("\n");
const DOTENV_REFUSAL = "dotenv-entry-in-working-directory";

test("F1: any .env or .env.* entry in the verified root refuses preflight and submit before any spawn, whatever its content, and removing it restores the pass", () => withRig(async (rig) => {
  await ready(rig);
  await rig.tooling.preflight({ env: rig.env });
  const names = [".env", ".env.local", ".env.staging", ".env.staging.local", ".env.production", ".env.production.local", ".env.development", ".env.test.local",
    ".env.", ".env.x.y", ".env.example.local", ".env.example2", ".env.EXAMPLE", ".ENV", ".Env.Local", ".env.local.bak", ".env.cloudflare"];
  for (const name of names) {
    const path = join(rig.root, name);
    await writeFile(path, HOSTILE_DOTENV);
    await refusesWith(rig.tooling.preflight({ env: rig.env }), DOTENV_REFUSAL);
    await refusesWith(rig.tooling.submit({ env: rig.env }), DOTENV_REFUSAL);
    await rm(path);
    await rig.tooling.preflight({ env: rig.env });
  }
  assert.deepEqual(await invocations(rig), [], "no dotenv entry ever reached a spawn");
}));

test("F1: a directory, a symlink and a dangling symlink under a dotenv name are 'present' too; so is an empty file", () => withRig(async (rig) => {
  await ready(rig);
  for (const name of [".env", ".env.local", ".env.staging"]) {
    await mkdir(join(rig.root, name));
    await refusesWith(rig.tooling.submit({ env: rig.env }), DOTENV_REFUSAL);
    await rm(join(rig.root, name), { recursive: true });
  }
  await writeFile(join(rig.root, ".env"), "");
  await refusesWith(rig.tooling.submit({ env: rig.env }), DOTENV_REFUSAL);
  await rm(join(rig.root, ".env"));
  await writeFile(join(rig.root, "elsewhere.txt"), HOSTILE_DOTENV);
  for (const [target, name] of [["elsewhere.txt", ".env"], ["does-not-exist", ".env.local"], ["does-not-exist", ".env.production"]] as const) {
    try {
      await symlink(join(rig.root, target), join(rig.root, name));
      await refusesWith(rig.tooling.submit({ env: rig.env }), DOTENV_REFUSAL);
      await rm(join(rig.root, name), { force: true });
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "EPERM" && (error as NodeJS.ErrnoException).code !== "EACCES") throw error; /* no symlink privilege on this host */ }
  }
  assert.deepEqual(await invocations(rig), []);
}));

test("F1: hostile values in a dotenv file are refused by the file's presence, never by parsing it (and the same values are refused in the shell)", () => withRig(async (rig) => {
  await ready(rig);
  for (const line of HOSTILE_DOTENV.split("\n").filter(Boolean)) {
    await writeFile(join(rig.root, ".env"), `${line}\n`);
    await refusesWith(rig.tooling.submit({ env: rig.env }), DOTENV_REFUSAL);
    await rm(join(rig.root, ".env"));
    const [key, value] = [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)];
    // the same variable in the process environment is B1's refusal (the account pin and the token are the two values it may carry)
    if (key !== "CLOUDFLARE_ACCOUNT_ID" && key !== "CLOUDFLARE_API_TOKEN") await assert.rejects(rig.tooling.submit({ env: { ...rig.env, [key]: value } }), AttestationSecretError);
  }
  assert.deepEqual(await invocations(rig), []);
}));

test("F1: the one tolerated name is a REGULAR FILE called exactly .env.example; the tracked template cannot be loaded without --env example", () => withRig(async (rig) => {
  await ready(rig);
  await writeFile(join(rig.root, DOTENV_TOLERATED_TEMPLATE), "CLOUDFLARE_API_BASE_URL=https://attacker.invalid/client/v4\n");
  await rig.tooling.preflight({ env: rig.env });
  assert.deepEqual(await rig.tooling.submit({ env: rig.env }), { submitted: [...ATTESTATION_SECRET_ORDER], stoppedAt: null });
  for (const call of await invocations(rig)) assert.equal(call.argv.some((arg) => /^(?:-e|--env|--env-file)(?:=|$)/u.test(arg)), false, "the closed argv cannot select .env.example");
  await rm(join(rig.root, DOTENV_TOLERATED_TEMPLATE));
  await mkdir(join(rig.root, DOTENV_TOLERATED_TEMPLATE));
  await refusesWith(rig.tooling.preflight({ env: rig.env }), DOTENV_REFUSAL);
  await rm(join(rig.root, DOTENV_TOLERATED_TEMPLATE), { recursive: true });
  await writeFile(join(rig.root, "template-target"), "x");
  try {
    await symlink(join(rig.root, "template-target"), join(rig.root, DOTENV_TOLERATED_TEMPLATE));
    await refusesWith(rig.tooling.preflight({ env: rig.env }), DOTENV_REFUSAL);
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== "EPERM" && (error as NodeJS.ErrnoException).code !== "EACCES") throw error; }
}));

test("F1: the dotenv search fails closed when the directory cannot be examined", async () => {
  const parent = await realpath(await mkdtemp(join(tmpdir(), "r06-dotenv-")));
  try {
    await assertNoImplicitWranglerDotenv(parent);
    for (const target of [join(parent, "does-not-exist"), join(parent, "a-file")]) {
      await writeFile(join(parent, "a-file"), "x");
      await assert.rejects(assertNoImplicitWranglerDotenv(target), (error: unknown) => error instanceof WranglerPinError && error.code === "dotenv-search-unavailable");
    }
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test("F1: the check is repeated immediately before EVERY spawn: a dotenv entry created after the first put stops the second; one created after the second stops the private key", () => withRig(async (rig) => {
  await ready(rig);
  const sabotage = (path: string, onInvocation: number) => writeFile(join(rig.root, "fake-wrangler-sabotage.json"), JSON.stringify({ path, content: HOSTILE_DOTENV, onInvocation }));
  const reset = async (path: string) => { await rm(path, { force: true }); await rm(join(rig.root, "fake-wrangler-record.jsonl"), { force: true }); };

  await sabotage(join(rig.root, ".env"), 1);
  assert.deepEqual(await rig.tooling.submit({ env: rig.env }), { submitted: [names.writerKeyFingerprint], stoppedAt: names.publicKey });
  const first = await invocations(rig);
  assert.equal(first.length, 1, "the second secret was never attempted");
  assert.deepEqual(first.map((call) => call.argv[2]), [names.writerKeyFingerprint]);
  await reset(join(rig.root, ".env"));

  await sabotage(join(rig.root, ".env.local"), 2);
  assert.deepEqual(await rig.tooling.submit({ env: rig.env }), { submitted: [names.writerKeyFingerprint, names.publicKey], stoppedAt: names.privateKey });
  const second = await invocations(rig);
  assert.deepEqual(second.map((call) => call.argv[2]), [names.writerKeyFingerprint, names.publicKey]);
  const { privateKey } = await readStagingAttestationKeyForSecretPut({ directory: rig.keys, repositoryRoot: rig.root, nowMs: Date.now() });
  assert.equal(second.some((call) => call.argv.includes(names.privateKey) || call.stdin === privateKey), false, "the private key was never sent once a dotenv entry existed");
  await reset(join(rig.root, ".env.local"));

  // control: the same hook with a harmless file changes nothing, so the stops above are caused by the dotenv entry and not by the hook
  await sabotage(join(rig.root, "harmless.txt"), 2);
  assert.deepEqual(await rig.tooling.submit({ env: rig.env }), { submitted: [...ATTESTATION_SECRET_ORDER], stoppedAt: null });
}));

test("F1: the prohibited set is PINNED to Wrangler 4.143.1's own getDefaultEnvFiles and implicit-load call sites; a Wrangler change fails here, not silently", async () => {
  const installed = JSON.parse(await readFile(join(repoRoot, "node_modules", "wrangler", "package.json"), "utf8")) as { version: string };
  assert.equal(installed.version, REVIEWED_WRANGLER_VERSION, "this pin test describes the reviewed Wrangler");
  const dist = await readFile(join(repoRoot, "node_modules", "wrangler", "wrangler-dist", "cli.js"), "utf8");
  const count = (needle: string) => dist.split(needle).length - 1;
  const definition = dist.match(/function getDefaultEnvFiles\(env6\) \{[\s\S]*?\n\}/u);
  assert.ok(definition, "getDefaultEnvFiles is still defined with the reviewed signature");
  assert.equal(count("function getDefaultEnvFiles("), 1);
  // every place that asks for the default files, and every place that loads dotenv files: a new one is a review event
  assert.equal(count("getDefaultEnvFiles("), 3, "definition + the global CLI middleware + the dev-only getVarsForDev");
  assert.equal(count("loadDotEnv("), 3, "definition + the global CLI middleware + the dev-only getVarsForDev");
  assert.equal(count('(args["env-file"] ?? getDefaultEnvFiles(args.env)).map((p8) => path28.resolve(p8))'), 1, "the global middleware resolves default files against the working directory");
  assert.equal(count("process.env = loadDotEnv(resolvedEnvFilePaths, {"), 1, "the global middleware REPLACES process.env with the loaded result");
  assert.equal(count("function getVarsForDev("), 1, "the other loader is dev-only (`wrangler dev` vars), not reached by `secret put`");
  const getDefaultEnvFiles = new Function(`${definition![0]}\nreturn getDefaultEnvFiles;`)() as (environment?: string) => string[];
  assert.deepEqual(getDefaultEnvFiles(undefined), [".env", ".env.local"]);
  assert.deepEqual(getDefaultEnvFiles(undefined), [...WRANGLER_DOTENV_DEFAULT_FILES], "the engine's default probes are exactly Wrangler's default list");
  // For ANY selected environment, every path Wrangler could load is covered by the prohibited-name rule, and (but for the tracked template,
  // a regular file only) the filesystem check refuses it.
  const parent = await realpath(await mkdtemp(join(tmpdir(), "r06-dotenv-pin-")));
  try {
    for (const environment of [undefined, "", "staging", "production", "development", "test", "a.b", "example", "Example", "x y", "-"]) {
      for (const file of getDefaultEnvFiles(environment)) {
        assert.equal(isDotenvEntryName(file), true, `${file} (env ${JSON.stringify(environment)}) is covered by the prohibited-name rule`);
        await writeFile(join(parent, file), "CLOUDFLARE_API_BASE_URL=https://attacker.invalid\n");
        if (file === DOTENV_TOLERATED_TEMPLATE) await assertNoImplicitWranglerDotenv(parent);
        else await assert.rejects(assertNoImplicitWranglerDotenv(parent), (error: unknown) => error instanceof WranglerPinError && error.code === DOTENV_REFUSAL, file);
        await rm(join(parent, file));
      }
    }
    await assertNoImplicitWranglerDotenv(parent);
  } finally { await rm(parent, { recursive: true, force: true }); }
  // the names that are NOT dotenv entries stay usable
  for (const name of ["env", "dotenv", ".envrc", ".environment", "env.local", "x.env", ".git", ".github"]) assert.equal(isDotenvEntryName(name), false, name);
});

// ---------------------------------------------------------------------------------------------------------------------------------
// Hardening: the Worker must already exist; the Wrangler version is re-proven at the point of use
// ---------------------------------------------------------------------------------------------------------------------------------

test("`secret put` can never create a Worker: without a valid, fresh Worker-existence confirmation nothing is spawned", () => withRig(async (rig) => {
  await seedKey(rig);
  await refusesWith(rig.tooling.submit({ env: rig.env }), "worker-confirmation-missing");
  await refusesWith(rig.tooling.preflight({ env: rig.env }), "worker-confirmation-missing");
  const bad: Array<[unknown, string]> = [
    [confirmation({ worker: "limitmark-admission-service" }), "worker-confirmation-wrong-worker"],
    [confirmation({ worker: "limitmark-admission-service-staging-2" }), "worker-confirmation-wrong-worker"],
    [confirmation({ accountFingerprint: "0".repeat(16) }), "worker-confirmation-wrong-account"],
    [confirmation({ confirmedAtMs: Date.now() - WORKER_CONFIRMATION_MAX_AGE_MS - 60_000 }), "worker-confirmation-expired"],
    [confirmation({ confirmedAtMs: Date.now() + 10 * 60_000 }), "worker-confirmation-in-the-future"],
    [confirmation({ environment: "production" }), "worker-confirmation-shape"],
    [confirmation({ version: 2 }), "worker-confirmation-shape"],
    [confirmation({ evidence: "trust-me" }), "worker-confirmation-shape"],
    [confirmation({ deployedVersionIdPrefix: "877BA1F2" }), "worker-confirmation-shape"],
    [confirmation({ deployedVersionIdPrefix: "877ba1" }), "worker-confirmation-shape"],
    [confirmation({ confirmedAtMs: -1 }), "worker-confirmation-shape"],
    [confirmation({ confirmedAtMs: 1.5 }), "worker-confirmation-shape"],
    [{ ...confirmation(), extra: true }, "worker-confirmation-shape"],
    [Object.fromEntries(Object.entries(confirmation()).filter(([key]) => key !== "evidence")), "worker-confirmation-shape"],
    [[confirmation()], "worker-confirmation-shape"],
    ["null", "worker-confirmation-shape"],
    ["{not json", "worker-confirmation-unreadable"],
    [`\uFEFF${JSON.stringify(confirmation())}`, "worker-confirmation-bom"],
    [`${JSON.stringify(confirmation()).slice(0, -1)},"worker":"other"}`, "worker-confirmation-unreadable"],
    [" ".repeat(2_000), "worker-confirmation-unreadable"],
  ];
  for (const [value, code] of bad) {
    await writeConfirmation(rig, value);
    await refusesWith(rig.tooling.submit({ env: rig.env }), code);
  }
  assert.deepEqual(await invocations(rig), [], "Wrangler's create-a-draft-Worker fallback is unreachable: no spawn happens without confirmation");
  await writeConfirmation(rig);
  assert.deepEqual((await rig.tooling.submit({ env: rig.env })).stoppedAt, null);
}));

test("the Wrangler version is re-proven at the point of use, before every spawn", () => withRig(async (rig) => {
  await ready(rig);
  const installed = join(rig.root, "node_modules", "wrangler", "package.json");
  const write = (value: unknown) => writeFile(installed, JSON.stringify(value));
  for (const version of ["4.131.1", "4.143.0", "4.143.2", "4.143.1-beta.1", "5.0.0", ""]) {
    await write({ name: "wrangler", version });
    await refusesWith(rig.tooling.submit({ env: rig.env }), "wrangler-version-not-the-reviewed-pin");
  }
  await write({ name: "not-wrangler", version: REVIEWED_WRANGLER_VERSION });
  await refusesWith(rig.tooling.submit({ env: rig.env }), "pinned-wrangler-unavailable");
  await write({ name: "wrangler", version: REVIEWED_WRANGLER_VERSION });
  const manifest = join(rig.root, "package.json");
  await writeFile(manifest, JSON.stringify({ devDependencies: { wrangler: "^4.143.1" } }));
  await refusesWith(rig.tooling.submit({ env: rig.env }), "wrangler-version-not-the-reviewed-pin");
  await writeFile(manifest, JSON.stringify({ devDependencies: { wrangler: REVIEWED_WRANGLER_VERSION } }));
  await writeFile(join(rig.root, "package-lock.json"), JSON.stringify({ packages: { "node_modules/wrangler": { version: "4.131.1" } } }));
  await refusesWith(rig.tooling.submit({ env: rig.env }), "wrangler-version-not-the-reviewed-pin");
  await writeFile(join(rig.root, "package-lock.json"), JSON.stringify({ packages: { "node_modules/wrangler": { version: REVIEWED_WRANGLER_VERSION } } }));
  await rm(rig.fakePath);
  await refusesWith(rig.tooling.submit({ env: rig.env }), "pinned-wrangler-unavailable");
  assert.deepEqual(await invocations(rig), []);
}));

test("a Wrangler downgrade between two puts stops the sequence (the version is not trusted from an earlier check)", () => withRig(async (rig) => {
  await ready(rig);
  await writeFile(join(rig.root, "fake-wrangler-sabotage.json"), JSON.stringify({
    path: join(rig.root, "node_modules", "wrangler", "package.json"), content: JSON.stringify({ name: "wrangler", version: "4.131.1" }) }));
  assert.deepEqual(await rig.tooling.submit({ env: rig.env }), { submitted: [names.writerKeyFingerprint], stoppedAt: names.publicKey });
  assert.equal((await invocations(rig)).length, 1);
}));

// ---------------------------------------------------------------------------------------------------------------------------------
// B3: the closed-set API. Direct library-level bypass attempts, not merely CLI bypass.
// ---------------------------------------------------------------------------------------------------------------------------------

test("B3: the production module exports no plan type, no planner and no way to inject a root, worker, order, name or executable", () => {
  assert.deepEqual(Object.keys(productionModule).sort(), ["ATTESTATION_SECRET_ORDER", "ATTESTATION_SECRET_WORKER", "AttestationSecretError", "preflightAttestationSecrets", "submitAttestationSecrets"]);
  for (const gone of ["planAttestationSecrets", "describeAttestationSecretPlan", "createAttestationSecretTooling", "buildWranglerChildEnvironment"]) assert.equal(gone in productionModule, false, `${gone} is not part of the production surface`);
  assert.equal(productionModule.submitAttestationSecrets.length, 1);
  assert.equal(productionModule.preflightAttestationSecrets.length, 1);
});

test("B3: a caller-supplied plan, root, pins, Worker, order, secret names, executable, key directory or clock is ignored by the production API (refused at the account pin)", async () => {
  const sandboxRoot = await mkdtemp(join(tmpdir(), "r06-bypass-"));
  try {
    const hostile = {
      env: { CLOUDFLARE_ACCOUNT_ID: account },
      plan: { root: sandboxRoot, worker: "attacker-worker", order: ["ANYTHING"], values: { ANYTHING: "x" }, wranglerBin: join(sandboxRoot, "evil.js") },
      root: sandboxRoot, repositoryRoot: sandboxRoot, pins, accountFingerprint: pins.accountFingerprint, worker: "attacker-worker",
      order: ["ANYTHING"], secretNames: ["ANYTHING"], names: ["ANYTHING"], wranglerBin: join(sandboxRoot, "evil.js"), executable: process.execPath,
      keyDirectory: sandboxRoot, nowMs: 0, clock: () => 0, spawn: () => { throw new Error("must never be called"); }, argv: ["secret", "put", "ANYTHING"],
    };
    // The synthetic account does not match the REAL reviewed pin; the supplied `pins` cannot replace it. Nothing else is reached.
    await refusesWith(productionModule.submitAttestationSecrets(hostile as never), "account-fingerprint-mismatch");
    await refusesWith(productionModule.preflightAttestationSecrets(hostile as never), "account-fingerprint-mismatch");
    await refusesWith(productionModule.submitAttestationSecrets({ ...hostile, env: {} } as never), "missing-or-malformed-account-pin");
    await assert.rejects(productionModule.submitAttestationSecrets(undefined as never), TypeError);
  } finally { await rm(sandboxRoot, { recursive: true, force: true }); }
});

test("B3: the engine ignores every property except `env`: extra fields cannot change the Worker, names, order, argv, executable or root", () => withRig(async (rig) => {
  const key = await ready(rig);
  const decoy = await mkdtemp(join(tmpdir(), "r06-decoy-"));
  try {
    const outcome = await rig.tooling.submit({
      env: rig.env,
      plan: { root: decoy, worker: "attacker-worker", order: ["ATTACKER_SECRET"], wranglerBin: join(decoy, "evil.js"), values: { ATTACKER_SECRET: "x" } },
      root: decoy, worker: "attacker-worker", order: ["ATTACKER_SECRET"], names: ["ATTACKER_SECRET"], wranglerBin: join(decoy, "evil.js"), executable: join(decoy, "evil.exe"),
      argv: ["deploy", "--env", "production"], args: ["--config", join(decoy, "wrangler.toml")], cwd: decoy,
    } as never);
    assert.deepEqual(outcome, { submitted: [...ATTESTATION_SECRET_ORDER], stoppedAt: null });
    const calls = await invocations(rig);
    assert.deepEqual(calls.map((call) => call.argv), ATTESTATION_SECRET_ORDER.map((name) => ["secret", "put", name, "--name", ATTESTATION_SECRET_WORKER]));
    assert.deepEqual(calls.map((call) => call.stdin).slice(0, 2), [key.keyFingerprint, key.publicKey]);
    for (const call of calls) assert.equal(await realpath(call.cwd), await realpath(rig.root), "never the decoy directory");
  } finally { await rm(decoy, { recursive: true, force: true }); }
}));

test("B3: the engine's capability factory yields exactly preflight and submit; there is no plan to mutate and no internal derivation to call", () => withRig(async (rig) => {
  assert.deepEqual(Object.keys(rig.tooling).sort(), ["preflight", "submit"]);
  assert.equal(Object.isFrozen(ATTESTATION_SECRET_ORDER), true);
  assert.throws(() => { (ATTESTATION_SECRET_ORDER as unknown as string[]).push("ANOTHER"); }, TypeError, "the order cannot be extended");
  assert.throws(() => { (ATTESTATION_SECRET_ORDER as unknown as string[])[0] = "OTHER"; }, TypeError, "the order cannot be edited");
  await ready(rig);
  const description = await rig.tooling.preflight({ env: rig.env });
  // the returned description hands out the frozen constant itself: a caller cannot scribble on it to change what submit does
  assert.throws(() => { (description.plannedSecretNames as string[]).length = 0; }, TypeError);
  assert.deepEqual([...description.plannedSecretNames], [...ATTESTATION_SECRET_ORDER]);
  assert.equal((await rig.tooling.submit({ env: rig.env })).submitted.length, 3);
}));

// ---------------------------------------------------------------------------------------------------------------------------------
// Planning refusals (unchanged behaviour) and the CLI
// ---------------------------------------------------------------------------------------------------------------------------------

test("planning refuses: wrong, malformed or missing account pin; private key in the environment", () => withRig(async (rig) => {
  await ready(rig);
  for (const bad of [undefined, "", "ABC", "0".repeat(32), `${account}0`]) await refusesWith(rig.tooling.preflight({ env: { ...rig.env, CLOUDFLARE_ACCOUNT_ID: bad } }), "missing-or-malformed-account-pin");
  await refusesWith(rig.tooling.preflight({ env: { ...rig.env, CLOUDFLARE_ACCOUNT_ID: "f".repeat(32) } }), "account-fingerprint-mismatch");
  for (const name of ["AUTHORITY_STAGING_OPERATOR_PRIVATE_KEY", "AUTHORITY_OPERATOR_PRIVATE_KEY", "AUTHORITY_STAGING_ATTESTATION_PRIVATE_KEY", "authority_attestation_private_key"])
    for (const value of ["synthetic", ""]) await refusesWith(rig.tooling.preflight({ env: { ...rig.env, [name]: value } }), "private-key-in-environment");
  await rig.tooling.preflight({ env: { ...rig.env, AUTHORITY_STAGING_OPERATOR_PUBLIC_KEY: "x", UNRELATED_PRIVATE_KEY: "x" } });
  assert.deepEqual(await invocations(rig), []);
}));

test("planning refuses missing/invalid custody and a repository-contained key directory", () => withRig(async (rig) => {
  await refusesWith(rig.tooling.preflight({ env: rig.env }), "attestation-key-custody-file-unavailable");
  await ready(rig);
  const inside = join(rig.root, "inside");
  await mkdir(inside);
  await refusesWith(createAttestationSecretTooling({ root: rig.root, pins, keyDirectory: () => inside, clock: () => Date.now() }).preflight({ env: rig.env }), "attestation-key-key-directory-inside-repository");
  await refusesWith(createAttestationSecretTooling({ root: rig.root, pins, keyDirectory: () => join(rig.home, "absent"), clock: () => Date.now() }).preflight({ env: rig.env }), "attestation-key-key-directory-must-already-exist");
  await refusesWith(createAttestationSecretTooling({ root: join(rig.home, "no-such-root"), pins, keyDirectory: () => rig.keys, clock: () => Date.now() }).preflight({ env: rig.env }), "repository-root-unavailable");
  const keyFile = join(rig.keys, "staging-attestation-private-key.pkcs8.b64url");
  const good = await readFile(keyFile, "utf8");
  await writeFile(keyFile, "A".repeat(64));
  await refusesWith(rig.tooling.preflight({ env: rig.env }), "attestation-key-private-key-not-pkcs8");
  await writeFile(keyFile, good);
  await rig.tooling.preflight({ env: rig.env });
  assert.deepEqual(await invocations(rig), []);
}));

test("the CLI refuses an unknown or incomplete argument surface and a non-pinned account, never invoking Wrangler", () => withWranglerSandbox(async (sandbox) => {
  const home = await mkdtemp(join(tmpdir(), "r06-secret-cli-home-"));
  try {
    await mkdir(join(home, ".limitmark-keys", "staging"), { recursive: true });
    const overrides = { CLOUDFLARE_ACCOUNT_ID: account, HOME: home, USERPROFILE: home };
    const script = "scripts/authority-staging-attestation-secret.ts";
    for (const args of [[], ["put"], ["put", "--confirm-staging", "extra"], ["preflight", "--confirm-staging"], ["deploy"], ["put", "--name", "other"], ["put", "--confirm-production"]]) {
      const run = await sandbox.runWrapper(script, args, overrides);
      assert.equal(run.result.status, 2, `${args.join(" ")}: ${run.result.stderr}`);
      assert.match(run.result.stderr, /REFUSED \(explicit-mode-required\)/u);
      assert.deepEqual(run.invocations, []);
    }
    // The CLI binds the REAL reviewed pin and the REAL repository root; a synthetic account can never satisfy the pin, so this refuses first.
    for (const args of [["preflight"], ["put", "--confirm-staging"]]) {
      const run = await sandbox.runWrapper(script, args, overrides);
      assert.equal(run.result.status, 2);
      assert.match(run.result.stderr, /REFUSED \(account-fingerprint-mismatch\)/u);
      assert.equal(run.result.stdout, "");
      assert.deepEqual(run.invocations, []);
    }
    const missing = await sandbox.runWrapper(script, ["preflight"], { ...overrides, CLOUDFLARE_ACCOUNT_ID: undefined });
    assert.match(missing.result.stderr, /REFUSED \(missing-or-malformed-account-pin\)/u);
    assert.deepEqual(missing.invocations, []);
  } finally { await rm(home, { recursive: true, force: true }); }
}, { recording: true }));

test("the recording sandbox is fail-closed: an altered, missing or real Wrangler at the spawn path is refused before anything runs", async () => {
  await withWranglerSandbox(async (sandbox) => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    await selfTestWranglerSandbox(sandbox.root, env, FAKE_WRANGLER_RECORDING_SOURCE);
    const withDefaultRecord = { ...env, LIMITMARK_FAKE_WRANGLER_RECORD: join(sandbox.root, "default-record.json") };
    await assert.rejects(selfTestWranglerSandbox(sandbox.root, withDefaultRecord, FAKE_WRANGLER_SOURCE), /spawn target is not the fake wrangler/u, "the two fakes are not interchangeable");
    await writeFile(sandbox.fakeWranglerPath, `${FAKE_WRANGLER_RECORDING_SOURCE}\nrequire("node:child_process");\n`);
    await assert.rejects(selfTestWranglerSandbox(sandbox.root, env, FAKE_WRANGLER_RECORDING_SOURCE), /spawn target is not the fake wrangler/u);
    await rm(sandbox.fakeWranglerPath);
    await assert.rejects(selfTestWranglerSandbox(sandbox.root, env, FAKE_WRANGLER_RECORDING_SOURCE), /fake wrangler missing/u);
  }, { recording: true });
});

test("source: exactly one spawn site with the closed argv, in the engine; the CLI and the production binding spawn nothing", async () => {
  const strip = (source: string) => source.split("\n").filter((line) => !line.trim().startsWith("//") && !line.trim().startsWith("*") && !line.trim().startsWith("/*")).join("\n");
  const engine = strip(await readFile(join(repoRoot, "operator/staging-attestation-secret-engine.ts"), "utf8"));
  const binding = strip(await readFile(join(repoRoot, "operator/staging-attestation-secret.ts"), "utf8"));
  const script = strip(await readFile(join(repoRoot, "scripts/authority-staging-attestation-secret.ts"), "utf8"));
  assert.equal(engine.match(/spawnSync\(/gu)?.length, 1);
  assert.match(engine, /\[plan\.wranglerBin, "secret", "put", name, "--name", ATTESTATION_SECRET_WORKER\]/u);
  assert.match(engine, /spawnSync\(process\.execPath,/u);
  assert.match(engine, /env: plan\.child\.values/u, "the child environment is the built one, never process.env");
  assert.equal(/env:\s*(?:process\.env|input\.env|\.\.\.)/u.test(engine.replace(/env: plan\.child\.values[^,]*,/u, "")), false, "the engine never forwards an inherited environment");
  // No Wrangler flag other than the closed argv exists in the engine (path/evidence strings such as ".wrangler/deploy/config.json" are not flags).
  assert.equal(/shell\s*:\s*true|"--(?:env|config|var|route|cron|name-override|dry-run|minify|compatibility-date)\b/iu.test(engine.replace(/shell: false/u, "")), false);
  assert.equal(/child_process|spawn|exec\(|execFile|fork\(|node:(net|http|https|tls|dns)|\bfetch\s*\(|WebSocket/u.test(script), false);
  assert.equal(/child_process|spawn|exec\(|execFile|fork\(|node:(net|http|https|tls|dns)|\bfetch\s*\(|WebSocket/u.test(binding), false);
  assert.equal(/node:(net|http|https|tls|dns)|\bfetch\s*\(|WebSocket/u.test(engine), false);
});
