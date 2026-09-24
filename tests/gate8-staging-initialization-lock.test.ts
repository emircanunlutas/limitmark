// Gate 8 Phase 0: permanent staging initialization CLI lockout.
//
// Every CLI below is an esbuild bundle of the real script, executed with
// process.execPath in a throwaway working directory. The signer, artifact
// reader, manifest loader, credential reader and R2 transport are replaced by
// synthetic traps that only append to a trace file, so no test can read the
// real staging key, credential, manifest or artifact, or open a socket. Each
// lockout assertion has a matching control build in which ONLY the lock module
// is replaced by a no-op, proving the traps fire when the lock is absent and
// therefore that the lock itself is what stops them.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { build, type Plugin } from "esbuild";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, commandDigest, signAuthorityInitializationCommand,
  type AuthorityInitializationCommand } from "../workers/admission-service/operator-command";
import * as lockModule from "../operator/staging-initialization-lock";

const root = process.cwd();
const { STAGING_INITIALIZATION_LOCK, STAGING_INITIALIZATION_REFUSAL } = lockModule;
const posix = (path: string) => path.replace(/\\/gu, "/");

const traceHelper = `import { appendFileSync } from "node:fs";
const trace = (event) => appendFileSync(process.env.GATE8_TRACE, event + "\\n");`;
const traps = {
  credentialIo: `${traceHelper}
import { readFileSync } from "node:fs";
export async function boundedFile(path) { trace("artifact-read"); return new Uint8Array(readFileSync(path)); }
export async function loadStagingLifecycleTransportManifest() { trace("manifest-load"); return JSON.parse(process.env.GATE8_MANIFEST); }
export async function readStagingR2Credential() { trace("credential-read"); return { accessKeyId: "synthetic", secretAccessKey: "synthetic" }; }`,
  transport: `${traceHelper}
export async function oneR2Request(method, _target, _credential, key) {
  trace("transport " + method + " " + key);
  return { statusCode: Number(process.env.GATE8_STATUS || "200"), body: new Uint8Array(Buffer.from(process.env.GATE8_BODY || "", "base64")) };
}`,
  signer: `${traceHelper}
import { signAuthorityInitializationCommand as realSign } from ${JSON.stringify(posix(resolve(root, "workers/admission-service/operator-command.ts")))};
export * from ${JSON.stringify(posix(resolve(root, "workers/admission-service/operator-command.ts")))};
export async function signAuthorityInitializationCommand(command, key) { trace("sign"); return realSign(command, key); }`,
  noopLock: `${traceHelper}
export const STAGING_INITIALIZATION_LOCK = {};
export const STAGING_INITIALIZATION_REFUSAL = "";
export function refuseClosedStagingInitialization() { trace("control-lock-removed"); }`,
};

function plugin(substitutions: Array<[RegExp, string]>): Plugin {
  return { name: "gate8-cli", setup(api) {
    api.onResolve({ filter: /^node:/ }, (args) => ({ path: args.path, external: true }));
    for (const [index, [filter]] of substitutions.entries())
      api.onResolve({ filter }, () => ({ path: `trap-${index}`, namespace: "gate8-trap" }));
    api.onLoad({ filter: /.*/, namespace: "gate8-trap" }, (args) => ({ loader: "js", resolveDir: root,
      contents: substitutions[Number(args.path.slice("trap-".length))][1] }));
    api.onResolve({ filter: /.*/ }, async (args) => {
      const base = args.path.startsWith(".") || isAbsolute(args.path) ? resolve(args.resolveDir || root, args.path) :
        createRequire(args.importer && isAbsolute(args.importer) ? args.importer : join(root, "package.json")).resolve(args.path);
      for (const path of [base, `${base}.ts`, `${base}.js`, `${base}.json`, join(base, "index.ts")]) {
        try { await readFile(path); return { path, namespace: "workspace-file" }; } catch { /* next */ }
      }
      throw new Error(`Unresolved CLI module: ${args.path}`);
    });
    api.onLoad({ filter: /.*/, namespace: "workspace-file" }, async (args) => ({ contents: await readFile(args.path),
      resolveDir: dirname(args.path), loader: extname(args.path) === ".ts" ? "ts" : extname(args.path) === ".json" ? "json" : "js" }));
  } };
}

let directory: string;
async function bundle(name: string, entry: string, substitutions: Array<[RegExp, string]>): Promise<string> {
  const outfile = join(directory, `${name}.cjs`);
  const result = await build({ entryPoints: [resolve(root, entry)], bundle: true, write: false, platform: "node", format: "cjs",
    target: "node24", plugins: [plugin(substitutions)], logLevel: "silent" });
  await writeFile(outfile, result.outputFiles[0].contents);
  return outfile;
}

/** Inherited provider/operator variables never reach a child. */
function scrubbedEnvironment(extra: Record<string, string>): NodeJS.ProcessEnv {
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
    !/^(CLOUDFLARE_|CF_|WRANGLER_|AUTHORITY_|GATE8_)/iu.test(name)));
  return { ...inherited, ...extra } as NodeJS.ProcessEnv;
}

type Run = { status: number | null; stdout: string; stderr: string; trace: string[] };
async function run(cli: string, args: string[], extra: Record<string, string> = {}): Promise<Run> {
  const trace = join(directory, "trace.txt");
  await writeFile(trace, "");
  const result = spawnSync(process.execPath, [cli, ...args], { cwd: directory, encoding: "utf8", timeout: 20_000,
    env: scrubbedEnvironment({ GATE8_TRACE: trace, ...extra }) });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr,
    trace: (await readFile(trace, "utf8")).split("\n").filter(Boolean) };
}

let privateKey: string;
let publicKey: string;
let artifactPath: string;
let credentialPath: string;
let signature: string;
let artifactText: string;
let manifest: string;
let digest: string;
const prepareArgs = ["--authority-id", STAGING_ADMISSION_AUTHORITY_ID, "--policy-epoch", ADMISSION_POLICY_EPOCH,
  "--release-id", "synthetic-release", "--release-key-id", "synthetic-key", "--confirm-staging-authority-initialization"];
const cli: Record<string, string> = {};

before(async () => {
  directory = await mkdtemp(join(tmpdir(), "gate8-lock-"));
  assert.ok(!resolve(directory).startsWith(resolve(root)), "sandbox must be outside the repository");
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  privateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  publicKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  // A fresh, validly signed synthetic staging initialization: exactly the
  // artifact the lockout must refuse even though it would pass every check.
  const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging",
    STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "synthetic-release", "synthetic-key", Date.now(), false];
  signature = await signAuthorityInitializationCommand(command, privateKey);
  artifactText = JSON.stringify({ command, signature });
  digest = await commandDigest(command);
  artifactPath = join(directory, "synthetic-artifact.json");
  credentialPath = join(directory, "synthetic-credential.json");
  await writeFile(artifactPath, artifactText);
  await writeFile(credentialPath, JSON.stringify({ accessKeyId: "synthetic", secretAccessKey: "synthetic" }));
  manifest = JSON.stringify({ accountId: "a".repeat(32), requestBucket: "limitmark-lifecycle-requests-staging",
    resultBucket: "limitmark-lifecycle-results-staging", operatorPublicKey: publicKey,
    authorityId: STAGING_ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH });
  const submitTraps: Array<[RegExp, string]> = [[/staging-credential-io$/, traps.credentialIo], [/r2-transport$/, traps.transport]];
  const lockRemoved: [RegExp, string] = [/staging-initialization-lock$/, traps.noopLock];
  cli.prepare = await bundle("prepare", "scripts/authority-staging-initialize.ts", [[/operator-command$/, traps.signer]]);
  cli.prepareControl = await bundle("prepare-control", "scripts/authority-staging-initialize.ts", [[/operator-command$/, traps.signer], lockRemoved]);
  cli.submit = await bundle("submit", "scripts/authority-staging-submit.ts", submitTraps);
  cli.submitControl = await bundle("submit-control", "scripts/authority-staging-submit.ts", [...submitTraps, lockRemoved]);
  cli.production = await bundle("production-prepare", "scripts/authority-initialize.ts", []);
});
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });

function assertRefusal(result: Run): void {
  assert.equal(result.status, 2);
  assert.equal(result.stdout, "", "no stdout: the operator capture pattern sees zero lines");
  assert.equal(result.stderr, STAGING_INITIALIZATION_REFUSAL);
  assert.deepEqual(result.trace, [], "no key, signer, artifact, manifest, credential or transport access");
  for (const secret of [privateKey, signature, artifactText, publicKey])
    assert.equal(`${result.stdout}${result.stderr}`.includes(secret), false, "no key/artifact/signature leaks");
}

test("L1: the lock record is exactly the reviewed frozen Gate 7 evidence record", () => {
  assert.deepEqual({ ...STAGING_INITIALIZATION_LOCK }, {
    version: 1, state: "STAGING_INITIALIZED_PERMANENTLY_CLOSED", environment: "staging",
    authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1", gate: 7, recordedDate: "2026-09-24",
    evidenceCommit: "2216dcb", digest: "f14876a5367f3d5d97d562119203b346159117814b23232ff84958ee36d18bcf",
    releaseId: "staging-gate7-initial", releaseKeyId: "staging-gate7-key-1", receiptSequence: 1, settlement: "SETTLED",
    keyFingerprint: "74f6e266c7cbdced", accountFingerprint: "0df3a690b3154513",
  });
  assert.equal(Object.isFrozen(STAGING_INITIALIZATION_LOCK), true);
  assert.throws(() => { (STAGING_INITIALIZATION_LOCK as unknown as Record<string, unknown>).state = "OPEN"; }, TypeError);
  assert.equal(STAGING_INITIALIZATION_LOCK.state, "STAGING_INITIALIZED_PERMANENTLY_CLOSED");
});

test("L2: every evidence value matches the committed Gate 7 runbook record", async () => {
  const runbook = await readFile(join(root, "PHASE5C_I3_PROVISIONING_RUNBOOK.md"), "utf8");
  const start = runbook.indexOf("**Gate 7 live evidence — 2026-09-24 (environment: staging; PASS).**");
  // Bounded to the operator-recorded Gate 7 evidence only, so the Phase 0 note
  // (which repeats these values) cannot satisfy this check by itself.
  const end = runbook.indexOf("**Gate 8 Phase 0 note");
  assert.ok(start > 0 && end > start, "Gate 7 live evidence section present and precedes the Phase 0 note");
  const gate7 = runbook.slice(start, end);
  const lock = STAGING_INITIALIZATION_LOCK;
  for (const value of [lock.digest, lock.releaseId, lock.releaseKeyId, lock.keyFingerprint, lock.accountFingerprint,
    lock.authorityId, lock.policyEpoch, lock.recordedDate])
    assert.ok(gate7.includes(value), `Gate 7 evidence records ${value}`);
  assert.match(gate7, /sequence 1\b/u);
  assert.match(gate7, /`status: SETTLED`/u);
  assert.match(gate7, /Gate 7 is therefore recorded as PASS, dated 2026-09-24, for the staging environment only/u);
  const phase0 = runbook.slice(runbook.indexOf("**Gate 8 Phase 0 note"));
  assert.ok(phase0.includes(`revision \`${lock.evidenceCommit}\``), "Phase 0 note names the pre-lockout evidence revision");
  const commit = spawnSync("git", ["log", "-1", "--format=%s", `${lock.evidenceCommit}^{commit}`], { cwd: root, encoding: "utf8" });
  assert.equal(commit.status, 0, "evidence commit resolves in this repository");
  assert.equal(commit.stdout.trim(), "Record Gate 7 staging initialization evidence");
});

test("L3: the module exports no unlock, setter, rearm or predicate surface", async () => {
  assert.deepEqual(Object.keys(lockModule).sort(),
    ["STAGING_INITIALIZATION_LOCK", "STAGING_INITIALIZATION_REFUSAL", "refuseClosedStagingInitialization"]);
  assert.equal(typeof lockModule.refuseClosedStagingInitialization, "function");
  assert.equal(lockModule.refuseClosedStagingInitialization.length, 0, "takes no input that could select an outcome");
  const source = await readFile(join(root, "operator", "staging-initialization-lock.ts"), "utf8");
  assert.equal(/\bexport\s+(let|var|class)\b/u.test(source), false);
  assert.equal(/process\.(env|argv)/u.test(source), false, "enforcement reads no environment or arguments");
  assert.equal(/STAGING_INITIALIZATION_LOCK\./u.test(source), false, "enforcement never reads a record value");
  assert.equal(/\b(unlock|rearm|reopen|setLock|isLocked|enable|override|force)\w*\s*\(/iu.test(source), false);
  for (const refusal of STAGING_INITIALIZATION_REFUSAL.match(/[A-Za-z0-9_-]{40,}/gu) ?? [])
    assert.fail(`refusal message contains an opaque token: ${refusal}`);
});

test("L4: prepare refuses unconditionally before arguments, key access or signing", async () => {
  const env = { AUTHORITY_STAGING_OPERATOR_PRIVATE_KEY: privateKey };
  assertRefusal(await run(cli.prepare, prepareArgs, env));
  assertRefusal(await run(cli.prepare, [], env));
  assertRefusal(await run(cli.prepare, ["--authority-id", "wrong"], {}));
  const control = await run(cli.prepareControl, prepareArgs, env);
  assert.equal(control.status, 0, "control: without the lock the historical body still signs");
  assert.deepEqual(control.trace, ["control-lock-removed", "sign"]);
  assert.equal((JSON.parse(control.stdout) as { command: unknown[] }).command[2], "staging");
});

test("L5: submit initialize and initialize --inspect refuse a fresh valid artifact before any access", async () => {
  const extra = { GATE8_MANIFEST: manifest };
  assertRefusal(await run(cli.submit, ["initialize", "--command", artifactPath, "--request-credentials", credentialPath,
    "--confirm-staging"], extra));
  assertRefusal(await run(cli.submit, ["initialize", "--command", artifactPath, "--confirm-staging", "--inspect"], extra));
  assertRefusal(await run(cli.submit, ["initialize"], extra));
  assertRefusal(await run(cli.submit, ["initialize", "--force"], extra));
  const control = await run(cli.submitControl, ["initialize", "--command", artifactPath, "--request-credentials", credentialPath,
    "--confirm-staging"], extra);
  assert.deepEqual(control.trace, ["control-lock-removed", "artifact-read", "manifest-load", "credential-read", "transport PUT initialize.json"],
    "control: without the lock this fresh artifact would have been uploaded");
  assert.equal((JSON.parse(control.stdout) as { digest: string }).digest, digest);
});

test("L6: reconcile, settle and read-result remain reachable exactly as before", async () => {
  const nonce = "c".repeat(32);
  for (const operation of ["reconcile", "settle"] as const) {
    const result = await run(cli.submit, [operation, "--digest", digest, "--request-credentials", credentialPath, "--confirm-staging"],
      { GATE8_MANIFEST: manifest });
    assert.equal(result.status, 0, result.stderr);
    const printed = JSON.parse(result.stdout) as { status: string; operation: string; digest: string };
    assert.deepEqual([printed.status, printed.operation, printed.digest], ["REQUESTED", operation, digest]);
    assert.deepEqual(result.trace, ["manifest-load", "credential-read", `transport PUT ${operation}.json`]);
  }
  const base = { version: 1, digest, nonce, environment: "staging", authorityId: STAGING_ADMISSION_AUTHORITY_ID,
    policyEpoch: ADMISSION_POLICY_EPOCH, observedAtMs: Date.now() };
  const settlement = await run(cli.submit, ["read-result", "--kind", "settlement", "--digest", digest, "--nonce", nonce,
    "--result-credentials", credentialPath], { GATE8_MANIFEST: manifest,
    GATE8_BODY: Buffer.from(JSON.stringify({ ...base, settled: true })).toString("base64") });
  assert.equal(settlement.status, 0, settlement.stderr);
  assert.equal((JSON.parse(settlement.stdout) as { status: string }).status, "SETTLED");
  assert.deepEqual(settlement.trace, ["manifest-load", "credential-read", `transport GET settlement/${nonce}.json`]);
  const reconciliation = await run(cli.submit, ["read-result", "--kind", "reconciliation", "--digest", digest, "--nonce", nonce,
    "--result-credentials", credentialPath], { GATE8_MANIFEST: manifest, GATE8_BODY: Buffer.from(JSON.stringify({ ...base,
    initialized: true, coverage: "COMPLETE", status: "NOT_FOUND", receipt: null, releases: [] })).toString("base64") });
  assert.equal(reconciliation.status, 3, "negative observation stays UNCONFIRMED");
  assert.deepEqual(JSON.parse(reconciliation.stdout), { status: "UNCONFIRMED", environment: "staging", digest, observation: "NOT_FOUND" });
  assert.deepEqual(reconciliation.trace, ["manifest-load", "credential-read", `transport GET reconciliation/${nonce}.json`]);
});

function mainBody(source: string): string[] {
  const start = source.indexOf("async function main()");
  assert.ok(start >= 0);
  return source.slice(source.indexOf("{", start) + 1).split("\n").map((line) => line.trim())
    .filter((line) => line && !line.startsWith("//"));
}

test("L7: refusal is the first main() action and no override surface was added", async () => {
  const prepare = await readFile(join(root, "scripts", "authority-staging-initialize.ts"), "utf8");
  assert.deepEqual(mainBody(prepare).slice(0, 3), ["refuseClosedStagingInitialization();", "await historicalGate7Preparation();", "}"]);
  assert.equal(prepare.match(/historicalGate7Preparation\(\)/gu)?.length, 2, "one definition and one unreachable call site only");
  assert.equal(/\bexport\b/u.test(prepare), false, "the historical body is not exported as a callable library path");
  const submit = await readFile(join(root, "scripts", "authority-staging-submit.ts"), "utf8");
  const body = mainBody(submit);
  assert.equal(body[0], "const action = process.argv[2];");
  assert.equal(body[1], 'if (action === "initialize") { refuseClosedStagingInitialization(); await submitInitialize(); }');
  assert.equal(submit.match(/submitInitialize\(\)/gu)?.length, 2, "one definition and one unreachable call site only");
  // Existing comments legitimately name absent flags (e.g. "has no `--environment` flag"); scan code only.
  for (const source of [prepare, submit].map((text) => text.split("\n").filter((line) => !line.trim().startsWith("//")).join("\n"))) {
    assert.equal(/--(force|unlock|rearm|reopen|target|account|manifest|environment|worker|bucket|endpoint)\b/u.test(source), false);
    assert.equal(/process\.env\.\w*(LOCK|UNLOCK|FORCE|OVERRIDE|TARGET)\w*/u.test(source), false);
    assert.equal(/STAGING_INITIALIZATION_LOCK/u.test(source), false, "scripts never branch on record values");
  }
  const runtimeFiles = spawnSync("git", ["grep", "-l", "staging-initialization-lock", "--", "workers", "src", "deployment"],
    { cwd: root, encoding: "utf8" });
  assert.equal(runtimeFiles.stdout.trim(), "", "never imported by runtime code");
  const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8")) as { scripts: Record<string, string> };
  assert.equal(packageJson.scripts["authority:staging:init:prepare"], "tsx scripts/authority-staging-initialize.ts");
  assert.equal(packageJson.scripts["authority:staging:init:submit"], "tsx scripts/authority-staging-submit.ts initialize");
});

test("L8: the Production preparer cannot mint a staging artifact and its Production path is unchanged", async () => {
  const env = { AUTHORITY_OPERATOR_PRIVATE_KEY: privateKey };
  for (const authority of [STAGING_ADMISSION_AUTHORITY_ID, "production-public-inquiries-v1"]) {
    const result = await run(cli.production, ["--environment", "staging", "--authority-id", authority, "--policy-epoch",
      ADMISSION_POLICY_EPOCH, "--release-id", "synthetic-release", "--release-key-id", "synthetic-key"], env);
    assert.equal(result.status, 1, `staging via Production preparer (${authority}) is refused`);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "Authority initialization request was not created.\n");
  }
  const production = await run(cli.production, ["--environment", "production", "--authority-id", "production-public-inquiries-v1",
    "--policy-epoch", ADMISSION_POLICY_EPOCH, "--release-id", "synthetic-release", "--release-key-id", "synthetic-key",
    "--confirm-production-authority-initialization"], env);
  assert.equal(production.status, 0, production.stderr);
  const sealed = JSON.parse(production.stdout) as { command: unknown[] };
  assert.deepEqual(sealed.command.slice(1, 4), ["initialize", "production", "production-public-inquiries-v1"]);
  const diff = spawnSync("git", ["diff", "--quiet", "HEAD", "--", "scripts/authority-initialize.ts", "scripts/authority-submit.ts",
    "scripts/authority-rotate-release.ts"], { cwd: root });
  assert.equal(diff.status, 0, "Production scripts are byte-identical to HEAD");
});
