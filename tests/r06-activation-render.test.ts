import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { copyFile, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validateStagingAdmissionServiceConfig } from "../deployment/lifecycle-private-contract";
import {
  ATTESTATION_TRUST_EPOCH, attestationReceiptFromLifecycleReceipt, attestationReleaseRowFromAuthority, makeReconciliationStatement,
} from "../src/lib/authority-result-attestation";
import { parseAuthorityResultTrustManifest, selectAttestationTrustKey } from "../src/lib/authority-result-trust";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID, type LifecycleReceipt } from "../workers/admission-service/authority";
import { createAuthorityAttestationSigner } from "../workers/admission-service/authority-attestation-signer";
import { verifyStagingAuthorityResult } from "../operator/authority-result-verifier";
import { parseStrictJson } from "../operator/lifecycle-submitter";
import {
  STAGING_ATTESTATION_KEY_FILE, generateStagingAttestationKey, readStagingAttestationKeyForSecretPut,
} from "../operator/staging-attestation-key";
import { STAGING_GATE7_CONTINUITY } from "../operator/staging-gate7-continuity";
import { R06_RENDER_MODES, R06RenderError, renderR06Artifact } from "../operator/staging-r06-renderer";
import { protectKeyDirectory } from "./support/r06-key-directory";

// R06 activation (T2 trust manifest, T3 admission config). Every write happens inside a fresh mkdtemp() root plus a separate mkdtemp()
// key directory; the repository's own deployment/ is only READ (to copy the two committed templates) and never written, so real
// operator-rendered artifacts there are untouched. Keys and accounts are synthetic, generated per run.

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const NOW = Date.now();
const account = "0123456789abcdef0123456789abcdef";
const fp16 = (value: Uint8Array | string) => createHash("sha256").update(value).digest("hex").slice(0, 16);

type Env = { root: string; deployment: string; keys: string; home: string; operatorPublicKey: string; pins: { accountFingerprint: string; keyFingerprint: string }; cleanup: () => Promise<void> };

async function makeEnv(): Promise<Env> {
  const root = await mkdtemp(join(tmpdir(), "r06-render-root-"));
  const home = await mkdtemp(join(tmpdir(), "r06-render-home-"));
  const deployment = join(root, "deployment");
  const keys = join(home, ".limitmark-keys", "staging");
  await mkdir(deployment);
  await mkdir(keys, { recursive: true });
  await protectKeyDirectory(keys);
  for (const name of ["admission-service.staging.template.jsonc", "authority-result-trust.template.json"]) await copyFile(join(repoRoot, "deployment", name), join(deployment, name));
  const raw = Buffer.from(generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x as string, "base64url");
  const operatorPublicKey = encodeBase64url(new Uint8Array(raw));
  return { root, deployment, keys, home, operatorPublicKey, pins: { accountFingerprint: fp16(account), keyFingerprint: fp16(raw) },
    cleanup: async () => { await rm(root, { recursive: true, force: true }); await rm(home, { recursive: true, force: true }); } };
}
async function withEnv(fn: (env: Env) => Promise<void>): Promise<void> {
  const env = await makeEnv();
  try { await fn(env); } finally { await env.cleanup(); }
}
async function writeTransport(env: Env, overrides: Record<string, unknown> = {}): Promise<void> {
  const template = JSON.parse(await readFile(join(repoRoot, "deployment", "lifecycle-transport.staging.template.json"), "utf8")) as Record<string, unknown>;
  await writeFile(join(env.deployment, "lifecycle-transport.staging.json"), JSON.stringify({ ...template, accountId: account, operatorPublicKey: env.operatorPublicKey, ...overrides }));
}
const render = (env: Env, mode: string, extra: Record<string, unknown> = {}) =>
  renderR06Artifact({ mode, root: env.root, keyDirectory: env.keys, nowMs: NOW, pins: env.pins, ...extra });
async function refusesWith(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => error instanceof R06RenderError && error.code === code, `expected refusal ${code}`);
}
const absent = (path: string) => assert.rejects(lstat(path), /ENOENT/u, "no output may be written");

test("the closed mode table reaches only the two reviewed modes", async () => {
  assert.deepEqual([...R06_RENDER_MODES], ["staging-admission", "staging-trust"]);
  await withEnv(async (env) => {
    for (const mode of ["", "staging-mailbox", "staging-observer", "staging-transport", "production", "staging-admission ", "../staging-trust"])
      await refusesWith(render(env, mode), "unknown-r06-render-mode");
    assert.deepEqual((await readdir(env.deployment)).sort(), ["admission-service.staging.template.jsonc", "authority-result-trust.template.json"]);
  });
});

// ---------------------------------------------------------------- T3: staging-admission
test("staging-admission renders the exact contract config: only the operator public key is substituted, no account_id, no private key read", () => withEnv(async (env) => {
  await writeTransport(env);
  // The key directory is irrelevant to this mode: point it at something that does not exist to prove no key access is attempted.
  const result = await render(env, "staging-admission", { keyDirectory: join(env.home, "does-not-exist") });
  assert.deepEqual(result, { status: "PASS", mode: "staging-admission", output: "deployment/admission-service.staging.jsonc", keyFingerprint: env.pins.keyFingerprint,
    productionTrustAnchor: null, providerContact: "none" });
  const rendered = parseStrictJson(await readFile(join(env.deployment, "admission-service.staging.jsonc"), "utf8")) as Record<string, unknown>;
  validateStagingAdmissionServiceConfig(rendered, false);
  const template = parseStrictJson(await readFile(join(env.deployment, "admission-service.staging.template.jsonc"), "utf8")) as Record<string, unknown>;
  const plain = (value: unknown) => JSON.parse(JSON.stringify(value)) as unknown;
  assert.deepEqual(plain(rendered), plain({ ...template, vars: { AUTHORITY_OPERATOR_PUBLIC_KEY: env.operatorPublicKey } }));
  assert.equal(Object.hasOwn(rendered, "account_id"), false);
  assert.equal(JSON.stringify(rendered).includes("__REQUIRED_"), false);
}));

test("staging-admission: wrong operator key, wrong account, missing/invalid/Production-shaped transport and altered templates all refuse without writing", () => withEnv(async (env) => {
  const output = join(env.deployment, "admission-service.staging.jsonc");
  await refusesWith(render(env, "staging-admission"), "transport-manifest-unavailable");
  await writeTransport(env);
  await refusesWith(render(env, "staging-admission", { pins: { ...env.pins, keyFingerprint: "0".repeat(16) } }), "operator-key-fingerprint-mismatch");
  await refusesWith(render(env, "staging-admission", { pins: { ...env.pins, accountFingerprint: "0".repeat(16) } }), "account-fingerprint-mismatch");
  await writeTransport(env, { environment: "production" });
  await refusesWith(render(env, "staging-admission"), "transport-manifest-contract-failed");
  await writeTransport(env, { operatorPublicKey: "__REQUIRED_STAGING_OPERATOR_ED25519_PUBLIC_KEY__" });
  await refusesWith(render(env, "staging-admission"), "transport-manifest-contract-failed");
  await writeFile(join(env.deployment, "lifecycle-transport.staging.json"), "{ not json");
  await refusesWith(render(env, "staging-admission"), "transport-manifest-contract-failed");
  await writeTransport(env);

  const templatePath = join(env.deployment, "admission-service.staging.template.jsonc");
  const good = await readFile(templatePath, "utf8");
  const tamper = async (text: string, code: string) => { await writeFile(templatePath, text); await refusesWith(render(env, "staging-admission"), code); };
  await tamper(good.replace('"__REQUIRED_STAGING_OPERATOR_ED25519_PUBLIC_KEY__"', '"__REQUIRED_STAGING_OPERATOR_ED25519_PUBLIC_KEY__", "EXTRA": "__REQUIRED_OTHER__"'), "template-unexpected-placeholder");
  await tamper(good.replace('"AUTHORITY_OPERATOR_PUBLIC_KEY": "__REQUIRED_STAGING_OPERATOR_ED25519_PUBLIC_KEY__"', '"AUTHORITY_OPERATOR_PUBLIC_KEY": "abc"'), "template-placeholder-not-exactly-once");
  await tamper(good.replace('"limitmark-admission-service-staging"', '"limitmark-admission-service-production"'), "template-shape-not-reviewed");
  await tamper(good.replace('"workers_dev": false', '"workers_dev": true'), "template-shape-not-reviewed");
  await tamper("{ not json", "template-placeholder-not-exactly-once");
  await absent(output);
}));

test("staging-admission never overwrites an existing output", () => withEnv(async (env) => {
  await writeTransport(env);
  const output = join(env.deployment, "admission-service.staging.jsonc");
  await writeFile(output, "OPERATOR-RENDERED-CONTENT");
  await refusesWith(render(env, "staging-admission"), "output-already-exists");
  assert.equal(await readFile(output, "utf8"), "OPERATOR-RENDERED-CONTENT");
}));

// ---------------------------------------------------------------- T2: staging-trust (D1 Option A)
async function seedKey(env: Env) { return generateStagingAttestationKey({ directory: env.keys, repositoryRoot: env.root, nowMs: NOW - 120_000 }); }

test("staging-trust renders a manifest the frozen parser accepts: staging = the custody key, production = an inert throwaway anchor", () => withEnv(async (env) => {
  const key = await seedKey(env);
  const result = await render(env, "staging-trust");
  assert.deepEqual(result, { status: "PASS", mode: "staging-trust", output: "deployment/authority-result-trust.json", keyFingerprint: key.keyFingerprint,
    productionTrustAnchor: "inert-no-private-key", providerContact: "none" });
  const text = await readFile(join(env.deployment, "authority-result-trust.json"), "utf8");
  const manifest = await parseAuthorityResultTrustManifest(text);
  const [production, staging] = manifest.environments;
  assert.equal(staging.currentKeyFingerprint, key.keyFingerprint);
  assert.deepEqual(staging.keys.map((k) => [k.publicKey, k.status, k.notBeforeMs, k.notAfterMs]), [[key.publicKey, "active", NOW - 120_000, null]]);
  assert.equal(production.keys.length, 1);
  assert.notEqual(production.keys[0].keyFingerprint, key.keyFingerprint);
  assert.notEqual(production.keys[0].publicKey, key.publicKey);
  assert.deepEqual([production.keys[0].status, production.keys[0].notBeforeMs, production.keys[0].notAfterMs], ["active", NOW, null], "template literals are untouched; only placeholders were substituted");
  assert.equal(text.includes("__REQUIRED_"), false);
  assert.equal(text.includes((await readStagingAttestationKeyForSecretPut({ directory: env.keys, repositoryRoot: env.root, nowMs: NOW })).privateKey), false);
  // The rendered object equals the template with exactly the eight placeholder leaves replaced.
  const template = JSON.parse(await readFile(join(env.deployment, "authority-result-trust.template.json"), "utf8")) as { environments: Array<Record<string, unknown>> };
  const rendered = JSON.parse(text) as typeof template;
  assert.deepEqual(Object.keys(rendered), Object.keys(template));
  for (const index of [0, 1]) {
    assert.deepEqual(Object.keys(rendered.environments[index]), Object.keys(template.environments[index]));
    for (const field of ["environment", "authorityId", "policyEpoch"]) assert.equal(rendered.environments[index][field], template.environments[index][field]);
  }
}));

test("staging-trust: the Production anchor is fresh per render and nobody holds its private half (nothing but a public key was ever written)", async () => {
  const fingerprints: string[] = [];
  for (let run = 0; run < 2; run += 1) await withEnv(async (env) => {
    await seedKey(env);
    await render(env, "staging-trust");
    const manifest = await parseAuthorityResultTrustManifest(await readFile(join(env.deployment, "authority-result-trust.json"), "utf8"));
    fingerprints.push(manifest.environments[0].keys[0].keyFingerprint);
    // Everything written under the temp tree: the template, the output, and the two custody files. No second key file exists anywhere.
    assert.deepEqual((await readdir(env.deployment)).sort(), ["admission-service.staging.template.jsonc", "authority-result-trust.json", "authority-result-trust.template.json"]);
    assert.deepEqual((await readdir(env.keys)).sort(), ["staging-attestation-key.meta.json", STAGING_ATTESTATION_KEY_FILE].sort());
  });
  assert.notEqual(fingerprints[0], fingerprints[1]);
});

test("staging-trust end to end: a statement signed by the custody key verifies and is POSITIVE through the real staging reader with the Gate 7 pins; the Production section trusts nothing", () => withEnv(async (env) => {
  await seedKey(env);
  await render(env, "staging-trust");
  const manifest = await parseAuthorityResultTrustManifest(await readFile(join(env.deployment, "authority-result-trust.json"), "utf8"));
  const key = await readStagingAttestationKeyForSecretPut({ directory: env.keys, repositoryRoot: env.root, nowMs: NOW });
  const signer = createAuthorityAttestationSigner({ environment: "staging", writerKeyFingerprint: key.keyFingerprint, privateKey: key.privateKey, publicKey: key.publicKey });
  await signer.ready(NOW);
  const g = STAGING_GATE7_CONTINUITY;
  const nonce = "a".repeat(32);
  const statement = (environment: "staging", observedAtMs: number) => makeReconciliationStatement({
    trustEpoch: ATTESTATION_TRUST_EPOCH, environment, authorityId: STAGING_ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH as "phase5c-i1-epoch-1",
    digest: g.receipt.digest, nonce, initialized: true, coverage: "COMPLETE", status: "EXACT_RECEIPT",
    receipt: attestationReceiptFromLifecycleReceipt(g.receipt as unknown as LifecycleReceipt),
    releases: g.releases.map((row) => attestationReleaseRowFromAuthority(row)), observedAtMs, writerKeyFingerprint: key.keyFingerprint });
  const envelope = await signer.sign(statement("staging", NOW - 1_000));
  const expectations = { kind: "reconciliation" as const, environment: "staging" as const, authorityId: STAGING_ADMISSION_AUTHORITY_ID,
    policyEpoch: ADMISSION_POLICY_EPOCH, digest: g.receipt.digest, nonce };
  const outcome = await verifyStagingAuthorityResult({ bytes: envelope, expectations, trustManifest: manifest, nowMs: NOW });
  assert.equal(outcome.status, "POSITIVE", "the rendered manifest + custody key satisfy the real staging composer and the Gate 7 pins");

  // The Production section trusts nothing the staging key could sign: a PRODUCTION statement naming the staging writer key finds no key.
  const productionStatement = makeReconciliationStatement({
    trustEpoch: ATTESTATION_TRUST_EPOCH, environment: "production", authorityId: "production-public-inquiries-v1", policyEpoch: ADMISSION_POLICY_EPOCH as "phase5c-i1-epoch-1",
    digest: g.receipt.digest, nonce, initialized: false, coverage: "COMPLETE", status: "NOT_FOUND", receipt: null, releases: [],
    observedAtMs: NOW - 1_000, writerKeyFingerprint: key.keyFingerprint });
  assert.throws(() => selectAttestationTrustKey(manifest, productionStatement, NOW), /attestation-key/u);
  // ...and the very same statement shape for STAGING does find the key (the control).
  assert.equal(selectAttestationTrustKey(manifest, statement("staging", NOW - 1_000), NOW).keyFingerprint, key.keyFingerprint);
  // A statement from before the key existed is outside its validity window.
  const early = await signer.sign(statement("staging", NOW - 120_000 - 5_000));
  await assert.rejects(verifyStagingAuthorityResult({ bytes: early, expectations, trustManifest: manifest, nowMs: NOW }));
}));

test("staging-trust refuses missing, broken or repository-contained custody, existing outputs and altered templates without writing", () => withEnv(async (env) => {
  const output = join(env.deployment, "authority-result-trust.json");
  await refusesWith(render(env, "staging-trust"), "attestation-key-custody-file-unavailable");
  await seedKey(env);
  await refusesWith(render(env, "staging-trust", { nowMs: Number.NaN }), "clock-unavailable");
  await refusesWith(render(env, "staging-trust", { keyDirectory: join(env.root, "somewhere-inside") }), "attestation-key-key-directory-must-already-exist");
  await mkdir(join(env.root, "inside-repo"));
  await refusesWith(render(env, "staging-trust", { keyDirectory: join(env.root, "inside-repo") }), "attestation-key-key-directory-inside-repository");

  const templatePath = join(env.deployment, "authority-result-trust.template.json");
  const good = await readFile(templatePath, "utf8");
  const tamper = async (text: string, code: string) => { await writeFile(templatePath, text); await refusesWith(render(env, "staging-trust"), code); };
  await tamper(good.replace('"__REQUIRED_STAGING_WRITER_KEY_FINGERPRINT__"', '"abc"'), "template-placeholder-count-not-reviewed");
  await tamper(good.replace('"__REQUIRED_STAGING_NOT_BEFORE_MS__"', '1'), "template-placeholder-count-not-reviewed");
  await tamper(good.replace('"notAfterMs": null', '"notAfterMs": null, "__REQUIRED_EXTRA__": 1'), "template-unexpected-placeholder");
  await tamper("{ not json", "template-not-strict-json");
  await absent(output);

  await writeFile(templatePath, good);
  await writeFile(output, "OPERATOR-RENDERED-CONTENT");
  await refusesWith(render(env, "staging-trust"), "output-already-exists");
  assert.equal(await readFile(output, "utf8"), "OPERATOR-RENDERED-CONTENT");
}));

test("a symlinked deployment directory is refused", async (t) => {
  await withEnv(async (env) => {
    await seedKey(env);
    const real = join(env.home, "real-deployment");
    await mkdir(real);
    await rm(env.deployment, { recursive: true, force: true });
    try { await symlink(real, env.deployment, "junction"); } catch { t.diagnostic("symlink/junction creation unavailable; case skipped"); return; }
    await refusesWith(render(env, "staging-trust"), "deployment-directory-not-exact");
  });
});

// ---------------------------------------------------------------- CLI
function runCli(env: Env, args: string[]) {
  const childEnv: NodeJS.ProcessEnv = { ...process.env, HOME: env.home, USERPROFILE: env.home };
  for (const name of Object.keys(childEnv)) if (/^CLOUDFLARE_/iu.test(name)) delete childEnv[name];
  return spawnSync(process.execPath, [join(repoRoot, "node_modules/tsx/dist/cli.mjs"), join(repoRoot, "scripts/authority-staging-r06-render.ts"), ...args],
    { cwd: env.root, encoding: "utf8", env: childEnv });
}

test("the render CLI accepts exactly one closed mode and no path/key/account arguments", () => withEnv(async (env) => {
  for (const args of [[], ["staging-trust", "extra"], ["staging-mailbox"], ["--output", "x"], ["staging-trust", "--key", "x"]]) {
    const result = runCli(env, args);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /REFUSED \(explicit-r06-render-mode-required\)/u);
    assert.equal(result.stdout, "");
  }
  await absent(join(env.deployment, "authority-result-trust.json"));
}));

test("the render CLI writes staging-trust from the fixed key directory, prints no key material, and never overwrites", () => withEnv(async (env) => {
  const key = await generateStagingAttestationKey({ directory: env.keys, repositoryRoot: env.root, nowMs: Date.now() - 5_000 });
  const first = runCli(env, ["staging-trust"]);
  assert.equal(first.status, 0, first.stderr);
  const printed = JSON.parse(first.stdout) as Record<string, unknown>;
  assert.equal(printed.keyFingerprint, key.keyFingerprint);
  assert.equal(printed.providerContact, "none");
  const privateText = await readFile(join(env.keys, STAGING_ATTESTATION_KEY_FILE), "utf8");
  assert.equal(`${first.stdout}${first.stderr}`.includes(privateText), false);
  const written = await readFile(join(env.deployment, "authority-result-trust.json"), "utf8");
  const second = runCli(env, ["staging-trust"]);
  assert.equal(second.status, 2);
  assert.match(second.stderr, /REFUSED \(output-already-exists\)/u);
  assert.equal(await readFile(join(env.deployment, "authority-result-trust.json"), "utf8"), written);
}));

test("the admission CLI refuses a synthetic transport (real pins) before writing anything", () => withEnv(async (env) => {
  await writeTransport(env);
  const result = runCli(env, ["staging-admission"]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /REFUSED \((operator-key-fingerprint-mismatch|account-fingerprint-mismatch)\)/u);
  await absent(join(env.deployment, "admission-service.staging.jsonc"));
}));

test("renderer and CLI sources have no process, network or provider path", async () => {
  for (const file of ["operator/staging-r06-renderer.ts", "scripts/authority-staging-r06-render.ts"]) {
    const source = (await readFile(join(repoRoot, file), "utf8")).split("\n").filter((line) => !line.trim().startsWith("//") && !line.trim().startsWith("*")).join("\n");
    assert.equal(/child_process|node:(net|http|https|tls|dns)|\bfetch\s*\(|WebSocket|\bspawn|wrangler/iu.test(source), false, file);
    assert.equal(/exportKey|privateKey\.export|writeFile\([^)]*private/u.test(source.replace(/const \{ publicKey \} = generateKeyPairSync/u, "")), false, `${file}: the throwaway Production private half is never exported`);
  }
});
