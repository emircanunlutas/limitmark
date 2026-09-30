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
import { STAGING_GATE7_CONTINUITY, STAGING_GATE7_KEY_FINGERPRINT } from "../operator/staging-gate7-continuity";

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
const stagingRow = { release_id: "staging-gate7-initial", key_id: "staging-gate7-key-1", activated_ms: 1790251978099, retired_ms: null };
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
  const negative = { ...base(), nonce, initialized: true, coverage: "COMPLETE", receipt: null, releases: [stagingRow] };
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

test("K4b: with the staging pin, an initialize expectation refuses a rotate-release receipt and an incoherent EXACT_RECEIPT", () => {
  const rotate = { ...receipt(pinned), operation: "rotate-release" };
  const call = (value: object, kind: "lifecycle" | "reconciliation") => verifyLifecycleResult(bytes(value), kind,
    kind === "lifecycle" ? { digest } : { digest, nonce }, now, "staging", "staging-public-inquiries-v1", pinned, "initialize");
  assert.equal(call(lifecycle("SUCCESS", pinned), "lifecycle").status, "SUCCESS");
  assert.equal(call(reconciliation(pinned), "reconciliation").status, "SUCCESS");
  assert.throws(() => call({ ...lifecycle("SUCCESS", pinned), receipt: rotate }, "lifecycle"), contract);
  assert.throws(() => call({ ...reconciliation(pinned), receipt: rotate }, "reconciliation"), contract);
  assert.throws(() => call({ ...reconciliation(pinned), initialized: false }, "reconciliation"), /result-integrity/u);
  assert.throws(() => call({ ...reconciliation(pinned), coverage: "INCOMPLETE" }, "reconciliation"), /result-integrity/u);
});

test("K5: only the staging caller pins; Production scripts are untouched", async () => {
  const production = await readFile(join(root, "scripts", "authority-submit.ts"), "utf8");
  assert.equal(/staging-gate7-continuity|STAGING_GATE7_KEY_FINGERPRINT/u.test(production), false);
  const call = production.slice(production.indexOf("verified = verifyLifecycleResult("));
  assert.match(call.slice(0, call.indexOf(";")), /nonce: nonce as string \}\)$/u,
    "Production call still passes only bytes, kind and expected target: no identity or fingerprint argument");
  const staging = await readFile(join(root, "scripts", "authority-staging-submit.ts"), "utf8");
  assert.match(staging, /"staging", "staging-public-inquiries-v1", STAGING_GATE7_KEY_FINGERPRINT, "initialize", STAGING_GATE7_CONTINUITY\.receipt\);/u,
    "the staging caller binds the initialize operation, the Gate 7 key fingerprint and the full canonical Gate 7 receipt");
  assert.match(staging, /import \{ STAGING_GATE7_CONTINUITY, STAGING_GATE7_KEY_FINGERPRINT \} from "\.\.\/operator\/staging-gate7-continuity";/u);
  assert.equal(/expectedReceipt|STAGING_GATE7_CONTINUITY/u.test(production), false, "Production passes no expected receipt");
});

// --- Canonical receipt binding (R07) ------------------------------------------------------------------

const canonical = STAGING_GATE7_CONTINUITY.receipt;
const boundWith = (value: object, kind: "lifecycle" | "reconciliation" | "settlement", expectedReceipt?: typeof canonical) =>
  verifyLifecycleResult(bytes(value), kind, kind === "lifecycle" ? { digest } : { digest, nonce }, now, "staging",
    "staging-public-inquiries-v1", pinned, "initialize", expectedReceipt);
const bound = (value: object, kind: "lifecycle" | "reconciliation" | "settlement") => boundWith(value, kind, canonical);
const deviations: Record<keyof typeof canonical, unknown> = { digest: "0".repeat(64), version: 2, operation: "rotate-release",
  environment: "production", authorityId: "production-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-2", keyFingerprint: wrong,
  sequence: 2, appliedMs: canonical.appliedMs + 1, currentReleaseId: "staging-gate7-other", nextReleaseId: "staging-gate7-other",
  nextKeyId: "staging-gate7-key-2", activatesMs: canonical.activatesMs + 1, retiresMs: canonical.appliedMs + 1000 };

test("K8: the test fixture is the committed canonical Gate 7 receipt, and canonical results pass with it bound", () => {
  assert.deepEqual(receipt(pinned), canonical);
  for (const status of ["SUCCESS", "ALREADY_APPLIED"])
    for (let replay = 0; replay < 2; replay++) assert.equal(bound(lifecycle(status, pinned), "lifecycle").status, status);
  assert.equal(bound(reconciliation(pinned), "reconciliation").status, "SUCCESS");
  // Reconciliation releases[] is current authority state: the binding never compares it with the receipt snapshot.
  const rotated = { ...reconciliation(pinned), releases: [{ release_id: "later", key_id: "later-key", activated_ms: now - 1, retired_ms: null }] };
  assert.equal(bound(rotated, "reconciliation").status, "SUCCESS");
});

test("K9: every altered canonical-receipt field is refused for lifecycle and reconciliation results", () => {
  assert.deepEqual(Object.keys(deviations).sort(), Object.keys(canonical).sort());
  // Fields an existing check (digest/version/environment/authority/epoch/fingerprint/operation) refuses even without expectedReceipt.
  const earlier = new Set(["digest", "version", "operation", "environment", "authorityId", "policyEpoch", "keyFingerprint"]);
  for (const field of Object.keys(canonical) as (keyof typeof canonical)[]) {
    const altered = { ...receipt(pinned), [field]: deviations[field] };
    for (const [kind, value] of [["lifecycle", { ...lifecycle("SUCCESS", pinned), receipt: altered }],
      ["lifecycle", { ...lifecycle("ALREADY_APPLIED", pinned), receipt: altered }],
      ["reconciliation", { ...reconciliation(pinned), receipt: altered }]] as const) {
      assert.throws(() => bound(value, kind), contract, `${kind} ${field}`);
      const withoutReceipt = () => boundWith(value, kind);
      if (earlier.has(field)) assert.throws(withoutReceipt, contract, `${field}: an earlier check also refuses`);
      else assert.doesNotThrow(withoutReceipt, `${field}: only the canonical receipt binding refuses`);
    }
  }
});

test("K10: receipt-less and settlement results keep their behavior with the canonical receipt bound", () => {
  const negative = { ...base(), nonce, initialized: true, coverage: "COMPLETE", receipt: null, releases: [stagingRow] };
  assert.equal(bound({ ...negative, status: "NOT_FOUND" }, "reconciliation").status, "UNCONFIRMED");
  assert.equal(bound({ ...negative, status: "HISTORY_INCOMPLETE", coverage: "INCOMPLETE" }, "reconciliation").status, "UNCONFIRMED");
  assert.equal(bound({ ...base(), nonce, status: "UNAVAILABLE" }, "reconciliation").status, "UNCONFIRMED");
  assert.equal(bound({ ...base(), status: "UNCONFIRMED", reason: "dispatch-ambiguous" }, "lifecycle").status, "UNCONFIRMED");
  assert.deepEqual(bound({ ...base(), nonce, settled: true }, "settlement"), { status: "SETTLED", digest, nonce });
  assert.throws(() => bound({ ...base(), status: "SUCCESS" }, "lifecycle"), /result-integrity/u, "a receipt-less positive result is still not a pass");
  // Fingerprint and operation pins stay active alongside the receipt.
  assert.throws(() => bound(lifecycle("SUCCESS", wrong), "lifecycle"), contract);
  assert.throws(() => bound({ ...lifecycle("SUCCESS", pinned), receipt: { ...receipt(pinned), operation: "rotate-release" } }, "lifecycle"), contract);
  // Omitting the expectation keeps the prior pinned behavior.
  assert.equal(boundWith({ ...lifecycle("SUCCESS", pinned), receipt: { ...receipt(pinned), sequence: 2 } }, "lifecycle").status, "SUCCESS");
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

test("K11: staging CLI read-result refuses a correctly keyed result whose receipt deviates from the canonical Gate 7 receipt", async () => {
  const fresh = Date.now();
  for (const field of ["sequence", "appliedMs", "currentReleaseId", "nextKeyId", "activatesMs", "retiresMs"] as const) {
    const altered = { ...receipt(pinned), [field]: deviations[field] };
    for (const [kind, body] of [["lifecycle", { ...lifecycle("SUCCESS", pinned, fresh), receipt: altered }],
      ["reconciliation", { ...reconciliation(pinned, fresh), receipt: altered }]] as const) {
      const result = await readResult(kind, body);
      assert.equal(result.status, 3, `${kind}/${field}: ${result.stderr}`);
      assert.deepEqual(JSON.parse(result.stdout), { status: "UNCONFIRMED", environment: "staging", kind },
        "the deviating receipt is never displayed and no new field is emitted");
      assert.equal(result.stderr, "");
      assert.deepEqual(result.trace, ["manifest-load", "credential-read",
        `transport GET ${kind === "lifecycle" ? `lifecycle/${digest}` : `${kind}/${nonce}`}.json`]);
    }
  }
  // The canonical receipt is printed exactly as before.
  const good = await readResult("lifecycle", lifecycle("SUCCESS", pinned, fresh));
  assert.equal(good.status, 0);
  assert.deepEqual((JSON.parse(good.stdout) as { receipt: unknown }).receipt, STAGING_GATE7_CONTINUITY.receipt);
});

test("K11: release snapshot coherence applies to staging reconciliation without touching the canonical receipt binding", () => {
  const impossible = { ...reconciliation(pinned), releases: [{ ...stagingRow, retired_ms: stagingRow.activated_ms }] };
  assert.throws(() => bound(impossible, "reconciliation"), /result-integrity/u);
  assert.throws(() => bound({ ...reconciliation(pinned), releases: [stagingRow, { ...stagingRow }] }, "reconciliation"), /result-integrity/u);
  assert.throws(() => bound({ ...reconciliation(pinned), releases: [{ ...stagingRow, extra: 1 }] }, "reconciliation"), /result-contract/u);
  const rotatedPair = [{ ...stagingRow, retired_ms: now - 1 }, { release_id: "later", key_id: "later-key", activated_ms: now - 2, retired_ms: null }];
  assert.equal(bound({ ...reconciliation(pinned), releases: rotatedPair }, "reconciliation").status, "SUCCESS");
  // A deviating receipt is still refused as a contract failure, before any snapshot judgement.
  assert.throws(() => bound({ ...reconciliation(pinned), receipt: { ...receipt(pinned), sequence: 2 } }, "reconciliation"), contract);
});
