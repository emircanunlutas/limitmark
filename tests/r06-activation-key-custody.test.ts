import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { decodeCanonicalBase64url, encodeBase64url } from "../src/lib/ingress-protocol";
import {
  AttestationKeyError, STAGING_ATTESTATION_KEY_FILE, STAGING_ATTESTATION_META_FILE, generateStagingAttestationKey,
  readStagingAttestationKeyForSecretPut, verifyStagingAttestationKey,
} from "../operator/staging-attestation-key";
import { STAGING_GATE7_KEY_FINGERPRINT } from "../operator/staging-gate7-continuity";
import { createProtectedKeyDirectory } from "./support/r06-key-directory";

// R06 activation (T1) key custody. Every write in this file happens inside a fresh mkdtemp() directory (a synthetic "repository root"
// plus a separate synthetic "key directory"); the operator's real key directory and the repository's deployment/ are never touched.
// Keys are generated per run. No process other than the CLI under test is spawned and nothing here contacts a provider.

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const NOW = 1_800_000_000_000;

type Env = { root: string; keys: string; home: string; cleanup: () => Promise<void> };
async function makeEnv(): Promise<Env> {
  const root = await mkdtemp(join(tmpdir(), "r06-custody-root-"));
  const home = await mkdtemp(join(tmpdir(), "r06-custody-home-"));
  const keys = await createProtectedKeyDirectory(home);
  return { root, keys, home, cleanup: async () => { await rm(root, { recursive: true, force: true }); await rm(home, { recursive: true, force: true }); } };
}
async function withEnv(fn: (env: Env) => Promise<void>): Promise<void> {
  const env = await makeEnv();
  try { await fn(env); } finally { await env.cleanup(); }
}
const request = (env: Env, extra: Record<string, unknown> = {}) => ({ directory: env.keys, repositoryRoot: env.root, nowMs: NOW, ...extra });

async function refusesWith(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => error instanceof AttestationKeyError && error.code === code, `expected refusal ${code}`);
}

test("generation writes exactly the two custody files, with canonical key material and exact public meta", () => withEnv(async (env) => {
  const result = await generateStagingAttestationKey(request(env));
  assert.deepEqual((await readdir(env.keys)).sort(), [STAGING_ATTESTATION_META_FILE, STAGING_ATTESTATION_KEY_FILE].sort());
  const privateText = await readFile(join(env.keys, STAGING_ATTESTATION_KEY_FILE), "utf8");
  assert.equal(decodeCanonicalBase64url(privateText, 48).length, 48, "canonical unpadded base64url RFC 8410 PKCS#8 (48 bytes)");
  assert.equal(privateText.endsWith("\n"), false, "no trailing newline");
  const meta = JSON.parse(await readFile(join(env.keys, STAGING_ATTESTATION_META_FILE), "utf8")) as Record<string, unknown>;
  assert.deepEqual(Object.keys(meta).sort(), ["createdAtMs", "environment", "keyFingerprint", "publicKey", "purpose", "version"]);
  assert.equal(meta.createdAtMs, NOW);
  assert.equal(meta.keyFingerprint, createHash("sha256").update(decodeCanonicalBase64url(meta.publicKey as string, 32)).digest("hex"));
  assert.deepEqual(result, { createdAtMs: NOW, publicKey: meta.publicKey, keyFingerprint: meta.keyFingerprint });
  assert.notEqual(result.keyFingerprint, STAGING_GATE7_KEY_FINGERPRINT);
  assert.equal(JSON.stringify(meta).includes(privateText), false, "the meta record never contains the private key");
}));

test("verification returns public facts only; only the secret-put reader returns the private key", () => withEnv(async (env) => {
  const generated = await generateStagingAttestationKey(request(env));
  const verified = await verifyStagingAttestationKey(request(env));
  assert.deepEqual(verified, generated);
  assert.equal(Object.keys(verified).includes("privateKey"), false);
  const forPut = await readStagingAttestationKeyForSecretPut(request(env));
  assert.equal(forPut.privateKey, await readFile(join(env.keys, STAGING_ATTESTATION_KEY_FILE), "utf8"));
  assert.equal(forPut.keyFingerprint, generated.keyFingerprint);
}));

test("custody files are never overwritten and a refused generation leaves no orphan key", () => withEnv(async (env) => {
  await generateStagingAttestationKey(request(env));
  const before = await Promise.all([STAGING_ATTESTATION_KEY_FILE, STAGING_ATTESTATION_META_FILE].map((name) => readFile(join(env.keys, name), "utf8")));
  await refusesWith(generateStagingAttestationKey(request(env)), "custody-file-already-exists");
  assert.deepEqual(await Promise.all([STAGING_ATTESTATION_KEY_FILE, STAGING_ATTESTATION_META_FILE].map((name) => readFile(join(env.keys, name), "utf8"))), before);

  // A pre-existing meta alone also blocks generation, and the key file that would have been created is not left behind.
  await rm(join(env.keys, STAGING_ATTESTATION_KEY_FILE));
  await refusesWith(generateStagingAttestationKey(request(env)), "custody-file-already-exists");
  assert.deepEqual(await readdir(env.keys), [STAGING_ATTESTATION_META_FILE]);
}));

test("a key whose fingerprint equals the operator key's is refused at every load (the pin is a parameter only so the refusal is provable)", () => withEnv(async (env) => {
  // A real operator-key collision cannot be generated, so pin the freshly generated key's own fingerprint as "the operator fingerprint".
  const { keyFingerprint } = await generateStagingAttestationKey(request(env));
  await refusesWith(verifyStagingAttestationKey(request(env, { operatorFingerprint: keyFingerprint })), "attestation-key-must-differ-from-operator-key");
  await refusesWith(readStagingAttestationKeyForSecretPut(request(env, { operatorFingerprint: keyFingerprint })), "attestation-key-must-differ-from-operator-key");
}));

test("the key directory must already exist and may not be inside the repository (including through a symlink)", async (t) => {
  await withEnv(async (env) => {
    await refusesWith(generateStagingAttestationKey({ directory: join(env.home, "absent"), repositoryRoot: env.root, nowMs: NOW }), "key-directory-must-already-exist");
    const inside = join(env.root, "keys");
    await mkdir(inside);
    await refusesWith(generateStagingAttestationKey({ directory: inside, repositoryRoot: env.root, nowMs: NOW }), "key-directory-inside-repository");
    await refusesWith(generateStagingAttestationKey({ directory: env.root, repositoryRoot: env.root, nowMs: NOW }), "key-directory-inside-repository");
    const link = join(env.home, "link-into-repository");
    try { await symlink(inside, link, "junction"); } catch { t.diagnostic("symlink/junction creation unavailable on this platform; symlink case skipped"); return; }
    await refusesWith(generateStagingAttestationKey({ directory: link, repositoryRoot: env.root, nowMs: NOW }), "key-directory-inside-repository");
    assert.deepEqual(await readdir(inside), [], "nothing was written into the repository");
  });
});

test("verification refuses tampered, malformed, mismatched and future-dated custody state", () => withEnv(async (env) => {
  await generateStagingAttestationKey(request(env));
  const keyPath = join(env.keys, STAGING_ATTESTATION_KEY_FILE);
  const metaPath = join(env.keys, STAGING_ATTESTATION_META_FILE);
  const goodKey = await readFile(keyPath, "utf8");
  const goodMeta = JSON.parse(await readFile(metaPath, "utf8")) as Record<string, unknown>;
  const writeMeta = (value: unknown) => writeFile(metaPath, typeof value === "string" ? value : JSON.stringify(value));
  const other = generateKeyPairSync("ed25519");
  const otherRaw = Buffer.from(other.publicKey.export({ format: "jwk" }).x as string, "base64url");

  await writeMeta({ ...goodMeta, publicKey: encodeBase64url(new Uint8Array(otherRaw)) });
  await refusesWith(verifyStagingAttestationKey(request(env)), "meta-does-not-match-private-key");
  await writeMeta({ ...goodMeta, keyFingerprint: "0".repeat(64) });
  await refusesWith(verifyStagingAttestationKey(request(env)), "meta-does-not-match-private-key");
  await writeMeta({ ...goodMeta, extra: 1 });
  await refusesWith(verifyStagingAttestationKey(request(env)), "meta-shape");
  const withoutPurpose = { ...goodMeta };
  delete withoutPurpose.purpose;
  await writeMeta(withoutPurpose);
  await refusesWith(verifyStagingAttestationKey(request(env)), "meta-shape");
  await writeMeta({ ...goodMeta, environment: "production" });
  await refusesWith(verifyStagingAttestationKey(request(env)), "meta-shape");
  await writeMeta("{ not json");
  await refusesWith(verifyStagingAttestationKey(request(env)), "meta-not-strict-json");
  await writeMeta(`{"version":1,"version":1}`);
  await refusesWith(verifyStagingAttestationKey(request(env)), "meta-not-strict-json");
  await writeMeta({ ...goodMeta, createdAtMs: NOW + 3_600_000 });
  await refusesWith(verifyStagingAttestationKey(request(env)), "meta-created-in-the-future");
  await writeMeta(goodMeta);
  assert.equal((await verifyStagingAttestationKey(request(env))).createdAtMs, NOW, "restored custody verifies again");

  await writeFile(keyPath, `${goodKey}\n`);
  await refusesWith(verifyStagingAttestationKey(request(env)), "private-key-not-canonical-pkcs8");
  await writeFile(keyPath, goodKey.slice(0, -4));
  await refusesWith(verifyStagingAttestationKey(request(env)), "private-key-not-canonical-pkcs8");
  const x25519 = generateKeyPairSync("x25519").privateKey;
  await writeFile(keyPath, encodeBase64url(new Uint8Array(x25519.export({ format: "der", type: "pkcs8" }))));
  await refusesWith(verifyStagingAttestationKey(request(env)), "private-key-not-ed25519");
  await writeFile(keyPath, encodeBase64url(new Uint8Array(other.privateKey.export({ format: "der", type: "pkcs8" }))));
  await refusesWith(verifyStagingAttestationKey(request(env)), "meta-does-not-match-private-key");
  await writeFile(keyPath, "A".repeat(500));
  await assert.rejects(verifyStagingAttestationKey(request(env)), (error: unknown) => error instanceof AttestationKeyError && error.code === "custody-file-size");
  await rm(keyPath);
  await refusesWith(verifyStagingAttestationKey(request(env)), "custody-file-unavailable");
}));

test("a custody file that is a symlink to a different place is refused as not exact", async (t) => {
  await withEnv(async (env) => {
    await generateStagingAttestationKey(request(env));
    const elsewhere = join(env.home, "elsewhere.b64url");
    await writeFile(elsewhere, await readFile(join(env.keys, STAGING_ATTESTATION_KEY_FILE), "utf8"));
    await rm(join(env.keys, STAGING_ATTESTATION_KEY_FILE));
    try { await symlink(elsewhere, join(env.keys, STAGING_ATTESTATION_KEY_FILE), "file"); } catch { t.diagnostic("symlink creation unavailable on this platform; case skipped"); return; }
    await refusesWith(verifyStagingAttestationKey(request(env)), "custody-file-not-exact");
  });
});

function runKeygen(env: Env, args: string[] = []) {
  const childEnv: NodeJS.ProcessEnv = { ...process.env, HOME: env.home, USERPROFILE: env.home };
  return spawnSync(process.execPath, [join(repoRoot, "node_modules/tsx/dist/cli.mjs"), join(repoRoot, "scripts/authority-staging-attestation-keygen.ts"), ...args],
    { cwd: env.root, encoding: "utf8", env: childEnv });
}

test("the keygen CLI generates once into the fixed key directory, prints public facts only, and refuses arguments and overwrite", () => withEnv(async (env) => {
  const first = runKeygen(env);
  assert.equal(first.status, 0, first.stderr);
  const printed = JSON.parse(first.stdout) as Record<string, unknown>;
  const privateText = await readFile(join(env.keys, STAGING_ATTESTATION_KEY_FILE), "utf8");
  assert.equal(printed.status, "GENERATED");
  assert.equal(printed.providerContact, "none");
  assert.deepEqual(Object.keys(printed).sort(), ["createdAtMs", "custodyFiles", "environment", "keyFingerprint", "providerContact", "publicKey", "status"]);
  assert.equal(`${first.stdout}${first.stderr}`.includes(privateText), false, "the private key is never printed");
  assert.equal(`${first.stdout}${first.stderr}`.includes(privateText.slice(0, 20)), false);
  const before = await readFile(join(env.keys, STAGING_ATTESTATION_KEY_FILE), "utf8");

  const again = runKeygen(env);
  assert.equal(again.status, 2);
  assert.match(again.stderr, /REFUSED \(custody-file-already-exists\)/u);
  assert.equal(again.stdout, "");
  assert.equal(await readFile(join(env.keys, STAGING_ATTESTATION_KEY_FILE), "utf8"), before);

  const withArgument = runKeygen(env, ["--output", join(env.home, "x")]);
  assert.equal(withArgument.status, 2);
  assert.match(withArgument.stderr, /REFUSED \(no-arguments-accepted\)/u);
}));

test("the keygen CLI refuses when the repository root contains the key directory", () => withEnv(async (env) => {
  // cwd is the "repository root": point HOME inside it so the fixed key directory resolves into the repository.
  const insideHome = join(env.root, "home");
  await mkdir(join(insideHome, ".limitmark-keys", "staging"), { recursive: true });
  const childEnv: NodeJS.ProcessEnv = { ...process.env, HOME: insideHome, USERPROFILE: insideHome };
  const result = spawnSync(process.execPath, [join(repoRoot, "node_modules/tsx/dist/cli.mjs"), join(repoRoot, "scripts/authority-staging-attestation-keygen.ts")],
    { cwd: env.root, encoding: "utf8", env: childEnv });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /REFUSED \(key-directory-inside-repository\)/u);
  assert.deepEqual(await readdir(join(insideHome, ".limitmark-keys", "staging")), []);
}));

test("custody sources have no process, network or provider path", async () => {
  for (const file of ["operator/staging-attestation-key.ts", "scripts/authority-staging-attestation-keygen.ts"]) {
    const source = (await readFile(join(repoRoot, file), "utf8")).split("\n").filter((line) => !line.trim().startsWith("//") && !line.trim().startsWith("*")).join("\n");
    assert.equal(/child_process|node:(net|http|https|tls|dns)|\bfetch\s*\(|WebSocket|\bspawn|wrangler/iu.test(source), false, file);
    assert.equal(/console\.|process\.stdout\.write\([^)]*privateKey/u.test(source), false, `${file} never prints key material`);
  }
});
