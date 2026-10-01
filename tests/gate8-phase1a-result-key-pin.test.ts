// Gate 8 Phase 1A (revised for R06 Slice 2C): staging result reading pins every positive to the exact Gate 7 canonical evidence
// (receipt, full operator public-key fingerprint, release row) AND, since 2C, to an Authority-signed staging statement. The CLI cases
// bundle the real scripts/authority-staging-submit.ts with the transport-manifest/credential loader and the R2 transport replaced by
// synthetic traps (the Phase 0 pattern); the trust manifest is read from a sandboxed deployment/ directory outside the repository.
// No real manifest, credential or socket is used.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { build, type Plugin } from "esbuild";
import { STAGING_GATE7_CONTINUITY, STAGING_GATE7_KEY_FINGERPRINT } from "../operator/staging-gate7-continuity";
import { NONCE, fixturesAt, text, trustManifestText } from "./support/authority-result-fixtures";

const root = process.cwd();
const pinned = STAGING_GATE7_KEY_FINGERPRINT;
const wrong = `${pinned.slice(0, 16)}${"0".repeat(48)}`;
const digest = STAGING_GATE7_CONTINUITY.receipt.digest;
const nonce = NONCE;

const traceHelper = `import { appendFileSync } from "node:fs";
const trace = (event) => appendFileSync(process.env.PHASE1A_TRACE, event + "\\n");`;
const traps: Array<[RegExp, string]> = [
  [/staging-credential-io$/, `${traceHelper}
export async function boundedFile() { trace("artifact-read"); throw new Error("trapped"); }
export async function loadStagingLifecycleTransportManifest() { trace("manifest-load"); return JSON.parse(process.env.PHASE1A_MANIFEST); }
export async function readStagingR2Credential() { trace("credential-read"); return { accessKeyId: "synthetic", secretAccessKey: "synthetic" }; }`],
  [/r2-transport$/, `${traceHelper}
export async function oneR2Request(method, _target, _credential, key) {
  trace("transport " + method + " " + key);
  return { statusCode: 200, body: new Uint8Array(Buffer.from(process.env.PHASE1A_BODY || "", "base64")) };
}`],
];
const plugin: Plugin = { name: "phase1a-result-cli", setup(api) {
  api.onResolve({ filter: /^node:/ }, (args) => ({ path: args.path, external: true }));
  for (const [index, [filter]] of traps.entries()) api.onResolve({ filter }, () => ({ path: `trap-${index}`, namespace: "phase1a-trap" }));
  api.onLoad({ filter: /.*/, namespace: "phase1a-trap" }, (args) => ({ loader: "js", resolveDir: root,
    contents: traps[Number(args.path.slice("trap-".length))][1] }));
  api.onResolve({ filter: /.*/ }, async (args) => {
    const target = args.path.startsWith(".") || isAbsolute(args.path) ? resolve(args.resolveDir || root, args.path) :
      createRequire(args.importer && isAbsolute(args.importer) ? args.importer : join(root, "package.json")).resolve(args.path);
    for (const path of [target, `${target}.ts`, `${target}.js`, `${target}.json`, join(target, "index.ts")]) {
      try { await readFile(path); return { path, namespace: "workspace-file" }; } catch { /* next */ }
    }
    throw new Error(`Unresolved CLI module: ${args.path}`);
  });
  api.onLoad({ filter: /.*/, namespace: "workspace-file" }, async (args) => ({ contents: await readFile(args.path),
    resolveDir: dirname(args.path), loader: extname(args.path) === ".ts" ? "ts" : extname(args.path) === ".json" ? "json" : "js" }));
} };

let directory: string;
let cli: string;
const manifest = JSON.stringify({ accountId: "a".repeat(32), requestBucket: "limitmark-lifecycle-requests-staging",
  resultBucket: "limitmark-lifecycle-results-staging", operatorPublicKey: "A".repeat(43),
  authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1" });
before(async () => {
  directory = await mkdtemp(join(tmpdir(), "gate8-phase1a-result-"));
  assert.ok(!resolve(directory).startsWith(resolve(root)), "sandbox must be outside the repository");
  await mkdir(join(directory, "deployment"));
  await writeFile(join(directory, "deployment", "authority-result-trust.json"), await trustManifestText());
  const result = await build({ entryPoints: [resolve(root, "scripts/authority-staging-submit.ts")], bundle: true, write: false,
    platform: "node", format: "cjs", target: "node24", plugins: [plugin], logLevel: "silent" });
  cli = join(directory, "staging-submit.cjs");
  await writeFile(cli, result.outputFiles[0].contents);
});
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });

/** Inherited provider/operator variables never reach a child. */
function scrubbedEnvironment(extra: Record<string, string>): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = { ...process.env };
  for (const name of Object.keys(environment))
    if (/^(CLOUDFLARE_|CF_|WRANGLER_|AUTHORITY_|GATE8_|PHASE1A_)/iu.test(name)) delete environment[name];
  return Object.assign(environment, extra);
}

async function readResult(kind: string, body: Uint8Array): Promise<{ status: number | null; stdout: string; stderr: string; trace: string[] }> {
  const trace = join(directory, "trace.txt");
  await writeFile(trace, "");
  const args = ["read-result", "--kind", kind, "--digest", digest, ...(kind === "lifecycle" ? [] : ["--nonce", nonce]),
    "--result-credentials", "synthetic-credential.json"];
  const result = spawnSync(process.execPath, [cli, ...args], { cwd: directory, encoding: "utf8", timeout: 20_000,
    env: scrubbedEnvironment({ PHASE1A_TRACE: trace, PHASE1A_MANIFEST: manifest, PHASE1A_BODY: Buffer.from(body).toString("base64") }) });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, trace: (await readFile(trace, "utf8")).split("\n").filter(Boolean) };
}
const printed = (stdout: string) => JSON.parse(stdout) as Record<string, unknown>;
const getTrace = (kind: string) => ["manifest-load", "credential-read", `transport GET ${kind === "lifecycle" ? `lifecycle/${digest}` : `${kind}/${nonce}`}.json`];

// Gate 7 canonical evidence is anchored in 2026-09; the sandbox CLI uses the real clock, so the signed statements are observed "now".
const fx = fixturesAt(Date.now());
const fresh = () => Date.now() - 1_000;
const gate7Lifecycle = (over = {}) => fx.lifecycle("staging", fx.gate7Receipt(over), fresh(), digest);
const gate7Reconciliation = (over = {}) => fx.reconciliation("staging", "EXACT_RECEIPT", digest, fx.gate7Receipt(over), { observedAtMs: fresh(), releases: [fx.gate7Release()] });

test("K6: staging CLI read-result prints POSITIVE only for signed evidence that carries the canonical Gate 7 receipt and the pinned fingerprint", async () => {
  for (const [kind, bytes] of [["lifecycle", await gate7Lifecycle()], ["reconciliation", await gate7Reconciliation()]] as const) {
    const result = await readResult(kind, bytes);
    assert.equal(result.status, 0, `${kind}: ${result.stderr}${result.stdout}`);
    const out = printed(result.stdout);
    assert.deepEqual([out.status, out.environment, out.kind, out.digest], ["POSITIVE", "staging", kind, digest]);
    assert.deepEqual(out.receipt, fx.gate7Receipt());
    assert.equal((out.receipt as { operatorKeyFingerprint: string }).operatorKeyFingerprint, pinned);
    assert.deepEqual(result.trace, getTrace(kind), "one read, no mutation, no retry");
  }
  // a signed statement carrying a wrong operator fingerprint is genuine Authority evidence that contradicts the pin
  for (const [kind, build] of [["lifecycle", () => gate7Lifecycle({ operatorKeyFingerprint: wrong })], ["reconciliation", () => gate7Reconciliation({ operatorKeyFingerprint: wrong })]] as const) {
    const result = await readResult(kind, await build());
    assert.equal(result.status, 3, `${kind}: ${result.stderr}`);
    assert.deepEqual(printed(result.stdout), { status: "UNCONFIRMED", environment: "staging", kind, digest, reason: "result-contract" }, "a wrong-key receipt is never displayed");
    assert.equal(result.stdout.includes(wrong), false);
    assert.deepEqual(result.trace, getTrace(kind));
  }
});

test("K6b: unsigned old staging positives (SUCCESS / ALREADY_APPLIED / EXACT_RECEIPT) are non-positive through the actual CLI", async () => {
  const base = { version: 1, digest, environment: "staging", authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1", observedAtMs: Date.now() };
  const receipt = STAGING_GATE7_CONTINUITY.receipt;
  for (const [kind, body] of [["lifecycle", { ...base, status: "SUCCESS", receipt }], ["lifecycle", { ...base, status: "ALREADY_APPLIED", receipt }],
    ["reconciliation", { ...base, nonce, status: "EXACT_RECEIPT", initialized: true, coverage: "COMPLETE", receipt, releases: STAGING_GATE7_CONTINUITY.releases }]] as const) {
    const result = await readResult(kind, text(body));
    assert.equal(result.status, 3, `${kind} ${body.status}`);
    assert.equal(printed(result.stdout).status, "UNCONFIRMED");
    assert.equal(result.stdout.includes("POSITIVE"), false);
  }
});

test("K7: staging CLI settlement reads remain valid without any receipt or trust-manifest dependence", async () => {
  const body = (settled: boolean) => text({ version: 1, digest, environment: "staging", authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1",
    observedAtMs: Date.now(), nonce, settled });
  const settled = await readResult("settlement", body(true));
  assert.equal(settled.status, 0, settled.stderr);
  assert.deepEqual(printed(settled.stdout), { status: "SETTLED", digest, nonce, environment: "staging" });
  const unsettled = await readResult("settlement", body(false));
  assert.equal(unsettled.status, 3);
  assert.deepEqual(printed(unsettled.stdout), { status: "UNCONFIRMED", environment: "staging", digest, nonce });
  assert.deepEqual(settled.trace, getTrace("settlement"));
});

test("K11: a genuinely signed staging result whose receipt deviates from the canonical Gate 7 receipt is refused and never displayed", async () => {
  const deviations: Record<string, unknown> = { sequence: 2, appliedMs: STAGING_GATE7_CONTINUITY.receipt.appliedMs + 1, currentReleaseId: "staging-gate7-other",
    nextKeyId: "staging-gate7-key-2", activatesMs: STAGING_GATE7_CONTINUITY.receipt.activatesMs + 1 };
  let refused = 0;
  for (const [field, value] of Object.entries(deviations)) {
    let bytes: Uint8Array;
    try { bytes = await gate7Lifecycle({ [field]: value }); } catch { continue; } // the frozen protocol itself will not sign an incoherent statement
    refused += 1;
    const result = await readResult("lifecycle", bytes);
    assert.equal(result.status, 3, `${field}: ${result.stderr}`);
    assert.deepEqual(printed(result.stdout), { status: "UNCONFIRMED", environment: "staging", kind: "lifecycle", digest, reason: "result-contract" });
    assert.equal(result.stderr, "");
  }
  assert.ok(refused >= 3, `exercised ${refused} deviating signed receipts`);
  // signed negatives remain reportable
  const negative = await fx.reconciliation("staging", "NOT_FOUND", digest, null, { observedAtMs: fresh(), releases: [fx.gate7Release()] });
  const reported = await readResult("reconciliation", negative);
  assert.equal(reported.status, 3);
  assert.deepEqual(printed(reported.stdout), { status: "VERIFIED_NON_POSITIVE", environment: "staging", kind: "reconciliation", digest, observation: "NOT_FOUND",
    observedAtMs: (printed(reported.stdout).observedAtMs as number), signingKeyFingerprint: printed(reported.stdout).signingKeyFingerprint });
});

test("K5: only the staging caller pins the Gate 7 evidence; Production reading is command-backed and staging-free; no unsigned verifier is reachable", async () => {
  const production = await readFile(join(root, "scripts", "authority-submit.ts"), "utf8");
  // Staging-only trust state never reaches Production.
  assert.equal(/staging-gate7-continuity|STAGING_GATE7|STAGING_ADMISSION|staging-public-inquiries|staging-credential-io|staging-initialization-lock/u.test(production), false);
  assert.equal(/expectedReceipt|STAGING_GATE7_CONTINUITY/u.test(production), false, "Production passes no staging canonical expected receipt");
  assert.equal(/\bverifyLifecycleResult\b|verifyProductionLifecycleResult/u.test(production), false, "no unsigned positive verifier in the Production CLI");
  assert.equal(production.match(/readProductionAuthorityResult\(/gu)?.length, 1, "exactly one Production positive call site");
  assert.match(production, /authenticatedCommand: command/u, "the only independent evidence passed is the authenticated command");
  const staging = await readFile(join(root, "scripts", "authority-staging-submit.ts"), "utf8");
  assert.equal(staging.match(/readStagingAuthorityResult\(/gu)?.length, 1, "exactly one staging positive call site");
  assert.equal(/verifyLifecycleResult|verifyProductionLifecycleResult|authenticateSealedLifecycleArtifact|readProductionAuthorityResult/u.test(staging), false,
    "staging uses neither the unsigned verifier nor the Production command-backed path");
});
