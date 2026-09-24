// Gate 8 Phase 1A: staging result verification pins every receipt to the exact
// full Gate 7 operator public-key fingerprint. Unit cases call the verifier
// directly; CLI cases bundle the real scripts/authority-staging-submit.ts with
// the manifest/credential loader and R2 transport replaced by synthetic traps
// (the Phase 0 pattern), so no real manifest, credential or socket is used.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { build, type Plugin } from "esbuild";
import { verifyLifecycleResult } from "../operator/lifecycle-result";
import { STAGING_GATE7_KEY_FINGERPRINT } from "../operator/staging-gate7-continuity";

const root = process.cwd();
const pinned = STAGING_GATE7_KEY_FINGERPRINT;
const wrong = `${pinned.slice(0, 16)}${"0".repeat(48)}`;
const digest = "f14876a5367f3d5d97d562119203b346159117814b23232ff84958ee36d18bcf";
const nonce = "e".repeat(32);
const now = 1_790_300_000_000;
const receipt = (keyFingerprint: string) => ({ digest, version: 1, operation: "initialize", environment: "staging",
  authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1", keyFingerprint, sequence: 1,
  appliedMs: 1790252041703, currentReleaseId: "staging-gate7-initial", nextReleaseId: "staging-gate7-initial",
  nextKeyId: "staging-gate7-key-1", activatesMs: 1790251978099, retiresMs: null });
const base = (observedAtMs = now) => ({ version: 1, digest, environment: "staging", authorityId: "staging-public-inquiries-v1",
  policyEpoch: "phase5c-i1-epoch-1", observedAtMs });
const lifecycle = (status: string, keyFingerprint: string, observedAtMs = now) => ({ ...base(observedAtMs), status, receipt: receipt(keyFingerprint) });
const reconciliation = (keyFingerprint: string, observedAtMs = now) => ({ ...base(observedAtMs), nonce, status: "EXACT_RECEIPT",
  initialized: true, coverage: "COMPLETE", receipt: receipt(keyFingerprint),
  releases: [{ release_id: "staging-gate7-initial", key_id: "staging-gate7-key-1", activated_ms: 1790251978099, retired_ms: null }] });
const bytes = (value: object) => new TextEncoder().encode(JSON.stringify(value));
const staged = (value: object, kind: "lifecycle" | "reconciliation" | "settlement", fingerprint?: string) =>
  verifyLifecycleResult(bytes(value), kind, kind === "lifecycle" ? { digest } : { digest, nonce }, now, "staging",
    "staging-public-inquiries-v1", fingerprint);
const contract = (error: unknown) => error instanceof Error && error.message === "result-contract";

test("K1: staging lifecycle SUCCESS/ALREADY_APPLIED pass only with the exact pinned fingerprint", () => {
  for (const status of ["SUCCESS", "ALREADY_APPLIED"]) {
    const verified = staged(lifecycle(status, pinned), "lifecycle", pinned);
    assert.equal(verified.status, status);
    assert.equal((verified as unknown as { receipt: { keyFingerprint: string } }).receipt.keyFingerprint, pinned);
    for (const bad of [wrong, "0".repeat(64), pinned.toUpperCase()])
      assert.throws(() => staged(lifecycle(status, bad), "lifecycle", pinned), contract);
  }
  // A non-positive lifecycle result that nevertheless carries a wrong-key receipt is refused too.
  assert.throws(() => staged(lifecycle("REFUSED", wrong), "lifecycle", pinned), contract);
});

test("K2: staging reconciliation EXACT_RECEIPT passes with the pinned fingerprint and refuses a wrong one", () => {
  assert.equal(staged(reconciliation(pinned), "reconciliation", pinned).status, "SUCCESS");
  assert.throws(() => staged(reconciliation(wrong), "reconciliation", pinned), contract);
});

test("K3: receipt-less results are unaffected by the pin", () => {
  const negative = { ...base(), nonce, initialized: true, coverage: "COMPLETE", receipt: null, releases: [] };
  assert.deepEqual(staged({ ...negative, status: "NOT_FOUND" }, "reconciliation", pinned),
    { status: "UNCONFIRMED", digest, observation: "NOT_FOUND" });
  assert.equal(staged({ ...negative, status: "HISTORY_INCOMPLETE", coverage: "INCOMPLETE" }, "reconciliation", pinned).status, "UNCONFIRMED");
  assert.deepEqual(staged({ ...base(), nonce, status: "UNAVAILABLE" }, "reconciliation", pinned),
    { status: "UNCONFIRMED", digest, observation: "UNAVAILABLE" });
  assert.deepEqual(staged({ ...base(), status: "UNCONFIRMED", reason: "dispatch-ambiguous" }, "lifecycle", pinned),
    { status: "UNCONFIRMED", digest, observation: "UNCONFIRMED" });
  assert.deepEqual(staged({ ...base(), nonce, settled: true }, "settlement", pinned), { status: "SETTLED", digest, nonce });
  assert.deepEqual(staged({ ...base(), nonce, settled: false }, "settlement", pinned), { status: "UNCONFIRMED", digest, nonce });
  // Settlement never gains a receipt member: one is still a schema violation.
  assert.throws(() => staged({ ...base(), nonce, settled: true, receipt: receipt(pinned) }, "settlement", pinned), contract);
});

test("K4: omitting the parameter preserves prior behavior exactly (any well-formed fingerprint)", () => {
  assert.equal(staged(lifecycle("SUCCESS", wrong), "lifecycle").status, "SUCCESS");
  assert.equal(staged(reconciliation(wrong), "reconciliation").status, "SUCCESS");
  const production = { ...lifecycle("SUCCESS", "c".repeat(64)), environment: "production", authorityId: "production-public-inquiries-v1",
    receipt: { ...receipt("c".repeat(64)), environment: "production", authorityId: "production-public-inquiries-v1" } };
  assert.equal(verifyLifecycleResult(bytes(production), "lifecycle", { digest }, now).status, "SUCCESS");
  assert.throws(() => staged(lifecycle("SUCCESS", "not-hex"), "lifecycle"), contract, "shape check unchanged");
  for (const malformed of ["", "74f6e266c7cbdced", pinned.toUpperCase()])
    assert.throws(() => staged(lifecycle("SUCCESS", pinned), "lifecycle", malformed), contract, "a malformed pin never widens acceptance");
});

test("K5: only the staging caller pins; Production scripts are untouched", async () => {
  const production = await readFile(join(root, "scripts", "authority-submit.ts"), "utf8");
  assert.equal(/staging-gate7-continuity|STAGING_GATE7_KEY_FINGERPRINT/u.test(production), false);
  const call = production.slice(production.indexOf("verified = verifyLifecycleResult("));
  assert.match(call.slice(0, call.indexOf(";")), /nonce: nonce as string \}\)$/u,
    "Production call still passes only bytes, kind and expected target: no identity or fingerprint argument");
  const staging = await readFile(join(root, "scripts", "authority-staging-submit.ts"), "utf8");
  assert.match(staging, /"staging", "staging-public-inquiries-v1", STAGING_GATE7_KEY_FINGERPRINT\);/u);
  assert.match(staging, /import \{ STAGING_GATE7_KEY_FINGERPRINT \} from "\.\.\/operator\/staging-gate7-continuity";/u);
});

// --- CLI boundary -----------------------------------------------------------

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

async function readResult(kind: string, body: object): Promise<{ status: number | null; stdout: string; stderr: string; trace: string[] }> {
  const trace = join(directory, "trace.txt");
  await writeFile(trace, "");
  const args = ["read-result", "--kind", kind, "--digest", digest, ...(kind === "lifecycle" ? [] : ["--nonce", nonce]),
    "--result-credentials", "synthetic-credential.json"];
  const result = spawnSync(process.execPath, [cli, ...args], { cwd: directory, encoding: "utf8", timeout: 20_000,
    env: scrubbedEnvironment({ PHASE1A_TRACE: trace, PHASE1A_MANIFEST: manifest,
      PHASE1A_BODY: Buffer.from(JSON.stringify(body)).toString("base64") }) });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr,
    trace: (await readFile(trace, "utf8")).split("\n").filter(Boolean) };
}

test("K6: staging CLI read-result prints SUCCESS for the pinned fingerprint and UNCONFIRMED for a wrong one", async () => {
  const fresh = Date.now();
  const cases: Array<[string, object, number, string]> = [
    ["lifecycle", lifecycle("SUCCESS", pinned, fresh), 0, "SUCCESS"],
    ["lifecycle", lifecycle("SUCCESS", wrong, fresh), 3, "UNCONFIRMED"],
    ["lifecycle", lifecycle("ALREADY_APPLIED", wrong, fresh), 3, "UNCONFIRMED"],
    ["reconciliation", reconciliation(pinned, fresh), 0, "SUCCESS"],
    ["reconciliation", reconciliation(wrong, fresh), 3, "UNCONFIRMED"],
  ];
  for (const [kind, body, exit, status] of cases) {
    const result = await readResult(kind, body);
    assert.equal(result.status, exit, `${kind}/${status}: ${result.stderr}`);
    const printed = JSON.parse(result.stdout) as Record<string, unknown>;
    assert.equal(printed.status, status);
    assert.equal(printed.environment, "staging");
    if (status === "UNCONFIRMED") {
      assert.deepEqual(printed, { status: "UNCONFIRMED", environment: "staging", kind }, "a wrong-key receipt is never displayed");
      assert.equal(result.stdout.includes(wrong), false);
    } else assert.equal((printed.receipt as { keyFingerprint: string }).keyFingerprint, pinned);
    assert.deepEqual(result.trace, ["manifest-load", "credential-read",
      `transport GET ${kind === "lifecycle" ? `lifecycle/${digest}` : `${kind}/${nonce}`}.json`], "one read, no mutation, no retry");
  }
});

test("K7: staging CLI settlement reads remain valid without any receipt", async () => {
  const fresh = Date.now();
  const settled = await readResult("settlement", { ...base(fresh), nonce, settled: true });
  assert.equal(settled.status, 0, settled.stderr);
  assert.deepEqual(JSON.parse(settled.stdout), { status: "SETTLED", digest, nonce, environment: "staging" });
  const unsettled = await readResult("settlement", { ...base(fresh), nonce, settled: false });
  assert.equal(unsettled.status, 3);
  assert.deepEqual(JSON.parse(unsettled.stdout), { status: "UNCONFIRMED", environment: "staging", digest, nonce });
  assert.deepEqual(settled.trace, ["manifest-load", "credential-read", `transport GET settlement/${nonce}.json`]);
});
