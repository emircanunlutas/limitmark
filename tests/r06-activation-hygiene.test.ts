import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

// R06 activation tooling hygiene (T8): scope, reachability and repository-hygiene invariants of the activation tooling as a whole. It
// reads source text and asks git read-only questions; it writes nothing and contacts nothing.

const root = fileURLToPath(new URL("../", import.meta.url));
const ignored = (path: string) => spawnSync("git", ["check-ignore", "-q", path], { cwd: root }).status === 0;
// SECONDARY TRIPWIRES ONLY. The text checks in this file (comment-stripped lines matched by regular expression) are NOT the security
// enforcement: a leading block comment, a namespace import or an alias walks past them. The enforcing guards are structural (syntax tree) in
// tests/r06-activation-capability-guard.test.ts: `childProcessViolations` pins the exact child-process imports and call sites,
// `networkCapabilityViolations` forbids network built-ins/clients/globals, and `protectedReferenceViolations` pins importers by canonical spelling.
const strip = (source: string) => source.split("\n").filter((line) => !line.trim().startsWith("//") && !line.trim().startsWith("*") && !line.trim().startsWith("/*")).join("\n");
const read = async (path: string) => strip(await readFile(join(root, path), "utf8"));

const toolingFiles = [
  "operator/staging-attestation-key.ts", "operator/staging-attestation-secret.ts", "operator/staging-attestation-secret-engine.ts", "operator/staging-key-protection.ts",
  "operator/staging-wrangler-pin.ts", "operator/staging-r06-renderer.ts", "operator/staging-r06-preflight.ts",
  "scripts/authority-staging-attestation-keygen.ts", "scripts/authority-staging-attestation-secret.ts", "scripts/authority-staging-r06-render.ts",
  "scripts/authority-staging-r06-preflight.ts",
] as const;

test("the rendered trust manifest is git-ignored by its exact name; its template (and the other templates) stay tracked", () => {
  assert.equal(ignored("deployment/authority-result-trust.json"), true);
  assert.equal(ignored("deployment/authority-result-trust.template.json"), false);
  assert.equal(ignored("deployment/admission-service.staging.jsonc"), true, "the existing admission rule is unchanged");
  assert.equal(ignored("deployment/admission-service.staging.template.jsonc"), false);
  // Exact filename only: nothing broader than the one rendered file is swallowed.
  assert.equal(ignored("deployment/authority-result-trust.json.bak"), false);
  assert.equal(ignored("deployment/authority-result-trust-notes.md"), false);
});

test("package scripts name exactly the reviewed tools, and the one provider-mutating command is explicit", async () => {
  const scripts = (JSON.parse(await readFile(join(root, "package.json"), "utf8")) as { scripts: Record<string, string> }).scripts;
  assert.deepEqual(Object.fromEntries(Object.entries(scripts).filter(([name]) => name.startsWith("authority:staging:r06:"))), {
    "authority:staging:r06:key:generate": "tsx scripts/authority-staging-attestation-keygen.ts",
    "authority:staging:r06:render:admission": "tsx scripts/authority-staging-r06-render.ts staging-admission",
    "authority:staging:r06:render:trust": "tsx scripts/authority-staging-r06-render.ts staging-trust",
    "authority:staging:r06:preflight": "tsx scripts/authority-staging-r06-preflight.ts",
    "authority:staging:r06:secrets:preflight": "tsx scripts/authority-staging-attestation-secret.ts preflight",
    "authority:staging:r06:secrets:put": "tsx scripts/authority-staging-attestation-secret.ts put",
  });
  assert.equal(scripts["test:workers:r06-upgrade"], "tsx tests/workers/r06-upgrade-rehearsal.integration.ts");
  assert.match(scripts["test:workers"], /tests\/workers\/r06-upgrade-rehearsal\.integration\.ts$/u, "the rehearsal is part of the standard worker suite");
  // No R06 script deploys, arms, rolls back or initializes: the deploy wrappers are the unchanged Gate 4B/7A ones.
  for (const [name, command] of Object.entries(scripts)) if (name.startsWith("authority:staging:r06:")) assert.equal(/deploy|rollback|init|rotate|arm/iu.test(name + command.replace(/secrets put/u, "")), false, name);
});

test("the activation tooling cannot initialize, rotate, reset, deploy, roll back or arm anything", async () => {
  for (const file of toolingFiles) {
    // ".wrangler/deploy/config.json" is the path of Wrangler's deploy-config REDIRECT that the secret engine REFUSES; it is not a deploy.
    const source = (await read(file)).replace(/\[".wrangler", "deploy", "config\.json"\]/gu, "[<redirect-path>]");
    assert.equal(/initializeAuthority|submitInitialize|authority-staging-initialize|staging-initialization-lock|rotate|Rotation|\bdeploy\b|rollback|versions deploy|--cron|crons/u.test(source), false, file);
    // secondary tripwire only; the structural network prohibition is networkCapabilityViolations in the capability guard
    assert.equal(/node:(net|http|https|tls|dns|dgram|http2)|\bfetch\s*\(|WebSocket|XMLHttpRequest/u.test(source), false, `${file}: no network path`);
  }
});

test("the tooling builds, signs and verifies nothing; WHICH names it imports is pinned structurally in tests/r06-activation-capability-guard.test.ts", async () => {
  // tests/authority-activation-guards.test.ts allowlists WHICH tooling files may import the frozen modules. The exact imported NAMES, the
  // namespace/dynamic/require/re-export bypasses and the signer usage shape are pinned by a syntax-tree analysis in the capability guard
  // (the regular expression that used to live here missed every one of those forms). What stays here is the plain-text belt: no tooling
  // file may even NAME a statement-building, signing or attested-RPC capability.
  for (const file of toolingFiles) {
    const source = await read(file);
    assert.equal(/\.sign\(|signResultAttestation|make(Lifecycle|Reconciliation)Statement|verifyAttestationSignature|verifyAuthoritySignedStatement|AuthorityAttestationCoordinator|attestReconciliation|attestAppliedLifecycle/u.test(source), false, `${file}: no signing, statement or attested-RPC use`);
  }
});

test("(secondary tripwire; structural pin: capability guard) exactly three spawn sites exist across the tooling: the pinned-Wrangler secret put, read-only git, and the two read-only Windows ACL tools", async () => {
  const spawning: Record<string, number> = {};
  for (const file of toolingFiles) {
    // a bare call only: `RegExp#exec(` and `.exec(` are method calls on a pattern, not processes
    const count = (await read(file)).match(/(?<![.\w])(?:spawnSync|spawn|execSync|execFileSync|execFile|exec|fork)\(/gu)?.length ?? 0;
    if (count) spawning[file] = count;
  }
  assert.deepEqual(spawning, { "operator/staging-attestation-secret-engine.ts": 1, "operator/staging-key-protection.ts": 1, "operator/staging-r06-preflight.ts": 1 });
  assert.match(await read("operator/staging-attestation-secret-engine.ts"), /\[plan\.wranglerBin, "secret", "put", name, "--name", ATTESTATION_SECRET_WORKER\]/u);
  assert.match(await read("operator/staging-r06-preflight.ts"), /spawnSync\("git", \[\.\.\.args\]/u);
  assert.match(await read("operator/staging-key-protection.ts"), /type WindowsTool = "icacls" \| "whoami";/u);
});

test("private key material is never printed, logged or placed in argv by any tool", async () => {
  for (const file of toolingFiles) {
    const source = await read(file);
    assert.equal(/console\.(log|error|warn|info)|process\.(stdout|stderr)\.write\([^;]*(privateKey|\.values\b|plan\.values)/u.test(source), false, file);
  }
  const engine = await read("operator/staging-attestation-secret-engine.ts");
  assert.equal(/argv|\[.*plan\.values/u.test(engine.replace(/plan\.wranglerBin, "secret"/u, "")), false, "values reach Wrangler on stdin only");
  assert.match(engine, /input: plan\.values\[name\]/u);
  assert.equal(engine.match(/plan\.values/gu)?.length, 1, "the secret values are referenced exactly once: as the stdin input of the one spawn (never the child environment)");
});

test("the tests of this tooling never write to the repository's own deployment/ or key locations", async () => {
  for (const file of ["tests/r06-activation-key-custody.test.ts", "tests/r06-activation-render.test.ts", "tests/r06-activation-secret-wrapper.test.ts",
    "tests/r06-activation-preflight.test.ts", "tests/r06-activation-key-protection.test.ts", "tests/r06-activation-capability-guard.test.ts",
    "tests/support/r06-key-directory.ts", "tests/support/r06-import-guard.ts",
    "tests/workers/r06-upgrade-rehearsal.integration.ts", "tests/workers/support/r06-upgrade-rig.ts"]) {
    const source = await read(file);
    assert.equal(/(writeFile|rm|mkdir|symlink|unlink)\(\s*join\(repoRoot/u.test(source), false, `${file}: repository paths are read-only here`);
    assert.equal(/copyFile\([^,]+,\s*join\(repoRoot/u.test(source), false, `${file}: a copy never targets the repository (it may only be a source)`);
    assert.equal(/homedir\(\)/u.test(source), false, `${file}: the operator's real home/key directory is never referenced`);
  }
});
