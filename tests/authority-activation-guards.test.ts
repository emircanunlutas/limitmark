import assert from "node:assert/strict";
import { readFile, readdir, stat } from "node:fs/promises";
import test from "node:test";

// R06 Slice 2C ACTIVATION GUARDS. The 2A/2B guards said "nobody may use the producer/composer"; since 2C activated them, the rule is
// "ONLY these exact reviewed active callers may use them". An unreviewed new caller (or a regression that reaches an unsigned positive)
// fails here. Source-level only: the behavior is proven by the unit, CLI and real-workerd tests.

const root = new URL("../", import.meta.url);
const read = (path: string) => readFile(new URL(path, root), "utf8");
async function files(directory: string, accept: (name: string) => boolean): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(new URL(`${directory}/`, root), { recursive: true })) {
    const relative = `${directory}/${entry.replaceAll("\\", "/")}`;
    if (!accept(relative) || relative.includes("/fixtures/")) continue;
    if ((await stat(new URL(relative, root))).isFile()) out.push(relative);
  }
  return out.sort();
}
const imports = (text: string) => [...text.matchAll(/(?:from|import\()\s*"([^"]+)"/gu)].map((match) => match[1]);
const code = (text: string) => text.split(String.fromCharCode(10)).filter((line) => !line.trim().startsWith("//") && !line.trim().startsWith("*") && !line.trim().startsWith("/*")).join(String.fromCharCode(10));
const SOURCE = /\.(?:ts|tsx|mts|js|mjs|json|jsonc)$/u;
const activeDirectories = ["src", "workers", "operator", "scripts", "deployment"] as const;
async function activeSources(): Promise<string[]> {
  const all: string[] = [];
  for (const directory of activeDirectories) all.push(...await files(directory, (name) => SOURCE.test(name)));
  return all;
}
// Local-workerd-only harnesses (no route, no workers_dev, never deployed; named only by wrangler.*.local.jsonc configs).
const HARNESSES = new Set(["workers/attestation-rpc-transport-harness.ts", "workers/production-do-rpc-harness.ts", "workers/staging-do-rpc-harness.ts",
  "workers/staging-admission-live-readonly-harness.ts", "workers/local-do-harness.ts", "workers/r06-active-path-harness.ts"]);

test("the frozen R06 protocol and trust modules are imported ONLY by the reviewed Authority producer and the reviewed verifier side", async () => {
  const importers: string[] = [];
  for (const file of await activeSources()) {
    if (file.startsWith("src/lib/authority-result-")) continue;
    if (imports(await read(file)).some((specifier) => /authority-result-(?:attestation|trust)$/u.test(specifier))) importers.push(file);
  }
  assert.deepEqual(importers.filter((file) => !HARNESSES.has(file)).sort(), [
    // Authority side: the producer, its signer and the runtime signer-configuration boundary.
    "workers/admission-service/authority-attestation-config.ts",
    "workers/admission-service/authority-attestation-signer.ts",
    "workers/admission-service/authority-attestation.ts",
    // Operator side: the 2B composers, the single active reader over them, and the public trust-manifest loader.
    "operator/authority-result-reader.ts",
    "operator/authority-result-verifier.ts",
    "operator/authority-trust-loader.ts",
    // R06 ACTIVATION TOOLING (offline, local-only; tests/r06-activation-capability-guard.test.ts pins the exact symbols structurally): public-key fingerprinting and the
    // safe-time predicate (custody), and the frozen trust-manifest parser (renderer and preflight). None of them signs, builds or verifies a statement.
    "operator/staging-attestation-key.ts",
    "operator/staging-r06-preflight.ts",
    "operator/staging-r06-renderer.ts",
  ].sort());
  // No relay, mailbox, observer, executor, guard, R2 writer, CLI or public route may import it: a relay cannot verify, parse or mint signed semantics.
  for (const relay of ["operator/attested-relay.ts", "operator/lifecycle-submitter.ts", "operator/lifecycle-result.ts", "operator/r2-transport.ts",
    "workers/lifecycle-mailbox/dispatch-guard.ts", "workers/lifecycle-mailbox/staging-dispatch-guard.ts", "workers/lifecycle-mailbox/processor.ts",
    "workers/lifecycle-mailbox/staging-processor.ts", "workers/lifecycle-mailbox/wire.ts", "workers/lifecycle-mailbox/index.ts", "workers/lifecycle-mailbox/staging-index.ts",
    "workers/lifecycle-observer.ts", "workers/staging-lifecycle-observer.ts", "workers/operator-lifecycle-executor.ts", "workers/staging-operator-lifecycle-executor.ts",
    "scripts/authority-submit.ts", "scripts/authority-staging-submit.ts"])
    assert.equal(imports(await read(relay)).some((specifier) => /authority-result-(?:attestation|trust)$/u.test(specifier)), false, `${relay} must not import the frozen protocol`);
});

test("the attested Authority RPCs are invoked ONLY by the reviewed active callers (executor submitter, dispatch guards, reconciliation observers)", async () => {
  const names = /FromOperatorAttested|attestAppliedLifecycle|attestReconciliation|AuthorityAttestationCoordinator|authority-attestation(?:-signer|-config)?["']/u;
  const callers: string[] = [];
  for (const file of await activeSources()) if (names.test(code(await read(file)))) callers.push(file);
  assert.deepEqual(callers.filter((file) => !HARNESSES.has(file)).sort(), [
    "operator/lifecycle-submitter.ts", // executor-side relay: initialize / rotate attested RPCs
    "workers/admission-service/authority-attestation-config.ts",
    "workers/admission-service/authority-attestation.ts",
    "workers/admission-service/index.ts", // the Authority DO classes and the lifecycle-only / read-only entrypoints
    "workers/lifecycle-mailbox/dispatch-guard.ts", // pre-dispatch signed read: attestAppliedLifecycle
    "workers/lifecycle-mailbox/staging-dispatch-guard.ts",
    "workers/lifecycle-observer.ts", // signed reconciliation: attestReconciliation
    "workers/staging-lifecycle-observer.ts",
    // R06 ACTIVATION TOOLING (offline, local-only): custody uses the Authority signer ONLY for its readiness self-test; the closed-set secret
    // engine reads ONLY the binding NAMES (ATTESTATION_SIGNER_BINDINGS.staging). Neither calls an attested RPC, a coordinator or a signing method;
    // tests/r06-activation-capability-guard.test.ts proves both structurally (syntax tree), not by pattern.
    "operator/staging-attestation-key.ts",
    "operator/staging-attestation-secret-engine.ts",
  ].sort());
  // The Production and staging dispatch/observer relays call exactly their reviewed method and nothing else of the attested surface.
  for (const guard of ["workers/lifecycle-mailbox/dispatch-guard.ts", "workers/lifecycle-mailbox/staging-dispatch-guard.ts"]) {
    const text = code(await read(guard));
    assert.equal(text.match(/LIFECYCLE_READER\.attestAppliedLifecycle\(/gu)?.length, 1, guard);
    assert.equal(/attestReconciliation|FromOperatorAttested/u.test(text), false, guard);
  }
  for (const observer of ["workers/lifecycle-observer.ts", "workers/staging-lifecycle-observer.ts"]) {
    const text = code(await read(observer));
    assert.equal(text.match(/LIFECYCLE_READER\.attestReconciliation\(control\.digest, control\.nonce\)/gu)?.length, 1, `${observer}: exact digest and nonce are forwarded`);
    assert.equal(/attestAppliedLifecycle|inspectLifecycle|FromOperatorAttested/u.test(text), false, observer);
  }
});

test("the 2B composers are used ONLY by the single reviewed reader; the active CLIs reach them only through it, each with its own environment", async () => {
  const composerImporters: string[] = [];
  const readerImporters: string[] = [];
  for (const file of await activeSources()) {
    const specifiers = imports(await read(file));
    if (specifiers.some((specifier) => /authority-result-verifier$/u.test(specifier))) composerImporters.push(file);
    if (specifiers.some((specifier) => /authority-result-reader$/u.test(specifier))) readerImporters.push(file);
  }
  assert.deepEqual(composerImporters, ["operator/authority-result-reader.ts"]);
  assert.deepEqual(readerImporters, ["scripts/authority-staging-submit.ts", "scripts/authority-submit.ts"]);
  const production = code(await read("scripts/authority-submit.ts"));
  const staging = code(await read("scripts/authority-staging-submit.ts"));
  assert.match(production, /import \{ readProductionAuthorityResult \} from "\.\.\/operator\/authority-result-reader";/u);
  assert.match(staging, /import \{ readStagingAuthorityResult \} from "\.\.\/operator\/authority-result-reader";/u);
  assert.equal(/readStagingAuthorityResult/u.test(production), false, "the Production reader path cannot reach the staging composer");
  assert.equal(/readProductionAuthorityResult/u.test(staging), false, "the staging reader path cannot reach the Production composer");
  const reader = code(await read("operator/authority-result-reader.ts"));
  assert.equal(reader.match(/composeProductionAuthorityResult\(/gu)?.length, 1);
  assert.equal(reader.match(/composeStagingAuthorityResult\(/gu)?.length, 1);
  assert.equal(reader.match(/verifyAuthoritySignedStatement\(/gu)?.length, 2, "one frozen verification per environment, no other signature path");
  // Settlement never goes through Authority evidence; it has its own verifier and its CLI branch calls nothing of the R06 reader.
  for (const [name, script] of [["production", production], ["staging", staging]] as const) {
    const branch = script.slice(script.indexOf('if (kind === "settlement") {', script.indexOf("async function readResult")));
    assert.match(branch.slice(0, branch.indexOf("return;")), /verifySettlementResult\(/u, name);
    assert.equal(/ReadResult|AuthorityResult|authenticate/u.test(branch.slice(0, branch.indexOf("return;"))), false, `${name} settlement branch is independent`);
  }
});

test("downgrade closure: no unsigned lifecycle/reconciliation positive verifier, no unsigned mutation RPC, and no signed-then-unsigned fallback exists in active code", async () => {
  const forbidden: Array<[RegExp, string]> = [
    [/\bverifyLifecycleResult\b|\bverifyProductionLifecycleResult\b/u, "unsigned positive result verifier"],
    [/\binitializeFromOperator\b(?!Attested)|\bwithLifecycleRefusal\b/u, "unsigned Authority initialize"],
    [/\bsubmitSealedLifecycleArtifact\b[^;]*\binitializeAuthorityFromOperator\b(?!Attested)/u, "unsigned executor call"],
    [/\binitializeAuthorityFromOperator\b(?!Attested)/u, "unsigned entrypoint initialize"],
    [/\brotateAuthorityReleaseFromOperator\b(?!Attested)\s*\([^)]*[a-z]/u, "unsigned entrypoint rotate with arguments"],
    [/status:\s*"(?:SUCCESS|ALREADY_APPLIED)"[^\n]*receipt/u, "unsigned positive result literal carrying a receipt"],
    [/\bUNAVAILABLE_AUTHORITY_OBSERVATION\b/u, "observer-constructed unavailable observation"],
  ];
  const allowed: Record<string, string[]> = {
    "unsigned Authority initialize": [],
    "observer-constructed unavailable observation": ["operator/lifecycle-observation.ts", "workers/admission-service/authority.ts"],
  };
  const offences: string[] = [];
  for (const file of await activeSources()) {
    if (HARNESSES.has(file)) continue;
    const text = code(await read(file));
    for (const [pattern, label] of forbidden) if (pattern.test(text) && !(allowed[label] ?? []).includes(file)) offences.push(`${file}: ${label}`);
  }
  assert.deepEqual(offences, []);
  // The one try-signed-then-unsigned shape: no active reader catches a signed failure and re-verifies unsigned.
  const reader = await read("operator/authority-result-reader.ts");
  assert.equal(/catch[^}]*verify(?!AuthoritySigned)/u.test(reader), false);
  for (const script of ["scripts/authority-submit.ts", "scripts/authority-staging-submit.ts"]) {
    const text = code(await read(script));
    assert.equal(/lifecycle-result/u.test(text.replace(/verifySettlementResult/gu, "")) && /verifyLifecycleResult|verifyProductionLifecycleResult/u.test(text), false, script);
  }
  // The Authority classes expose no unsigned lifecycle mutation (the staging rotation stub is the permanently closed Gate 9 refusal).
  const index = code(await read("workers/admission-service/index.ts"));
  assert.equal(/async initializeFromOperator\(|async rotateReleaseFromOperator\([^)]/u.test(index), false);
  assert.equal(index.match(/async rotateReleaseFromOperator\(\)/gu)?.length, 1, "only the staging Gate 9 closed refusal remains");
  // Legacy-shaped result parsing survives only as the non-positive diagnostic classifier and settlement verification.
  const result = await read("operator/lifecycle-result.ts");
  assert.equal(/EXACT_RECEIPT|"SUCCESS"|"ALREADY_APPLIED"/u.test(code(result)), false, "operator/lifecycle-result.ts has no positive lifecycle vocabulary");
});

test("relay modules are opaque: they never parse, rebuild or re-serialize the envelope, and the observer builds no Authority semantics", async () => {
  const wire = code(await read("workers/lifecycle-mailbox/wire.ts"));
  const publish = wire.slice(wire.indexOf("export async function publishSignedEnvelope"));
  assert.equal(/JSON\.|TextDecoder|TextEncoder|atob|btoa|toString\(|parse/u.test(publish), false, "publishSignedEnvelope stores the bytes as given");
  assert.match(publish, /bucket\.put\(key, envelope, /u);
  for (const processor of ["workers/lifecycle-mailbox/processor.ts", "workers/lifecycle-mailbox/staging-processor.ts"]) {
    const text = code(await read(processor));
    const slot = text.slice(text.indexOf("export async function process"), text.indexOf("export async function processSettlement") > 0 ? text.indexOf("export async function processSettlement") : text.indexOf("export async function processStagingSettlement"));
    assert.equal(/observedAtMs|Date\.now|receipt|environment|authorityId|policyEpoch|releases|coverage|initialized/u.test(slot), false, `${processor}: the lifecycle result path adds no semantics`);
    assert.match(slot, /publishSignedEnvelope\(env\.RESULT_BUCKET, resultKey, outcome\.envelope\)/u, processor);
  }
  for (const observer of ["workers/lifecycle-observer.ts", "workers/staging-lifecycle-observer.ts"]) {
    const text = code(await read(observer));
    assert.equal(/observedAtMs|Date\.now|receipt|environment:|authorityId|policyEpoch|releases|coverage|initialized|EXACT_RECEIPT|NOT_FOUND|HISTORY_INCOMPLETE|inspectLifecycle|\.\.\.snapshot/u.test(text), false,
      `${observer} manufactures no Authority semantics`);
    assert.match(text, /publishSignedEnvelope\(env\.RESULT_BUCKET, key, answer\.envelope\)/u, observer);
  }
  for (const relay of ["operator/attested-relay.ts", "operator/lifecycle-submitter.ts", "workers/lifecycle-mailbox/dispatch-guard.ts", "workers/lifecycle-mailbox/staging-dispatch-guard.ts"]) {
    const text = code(await read(relay));
    assert.equal(/parseResultAttestationEnvelope|encodeResultAttestationEnvelope|canonicalStatementBytes|resultStatementTuple|\.envelope\.(?:slice|subarray|map)|envelope\s*=\s*new Uint8Array/u.test(text), false, relay);
  }
});

test("no test-only signer material, test import or golden fixture appears in active runtime source", async () => {
  const golden = JSON.parse(await read("tests/fixtures/authority-result-attestation-v2.golden.json")) as { keys: Record<string, Record<string, string>> };
  const material = Object.values(golden.keys).flatMap((key) => [key.seedHex, key.privateKeyPkcs8, key.publicKey, key.publicKeyHex, key.fingerprint]);
  assert.equal(material.length, 10);
  const offences: string[] = [];
  for (const file of await activeSources()) {
    if (HARNESSES.has(file)) continue;
    const text = await read(file);
    for (const value of material) if (text.includes(value)) offences.push(`${file}: contains RFC test key material`);
    if (/tests\/|authority-attestation-test-signers|authority-result-fixtures|golden\.json|trust-v1\.test\.json|\bRFC 8032\b/u.test(code(text).replace(/importAttestationTestPrivateKey/gu, ""))) offences.push(`${file}: references test support`);
  }
  assert.deepEqual(offences, []);
  // The active signer configuration has no default and no fallback: a missing or malformed value yields NO signer.
  const config = code(await read("workers/admission-service/authority-attestation-config.ts"));
  assert.equal(/\?\?|\|\||default/u.test(config.replace(/\|\|/gu, "||")) && /privateKey\s*(?:\?\?|\|\|)|publicKey\s*(?:\?\?|\|\|)|writerKeyFingerprint\s*(?:\?\?|\|\|)/u.test(config), false);
  assert.equal(/process\.env|globalThis|import\.meta/u.test(config), false, "the signer reads only its own Worker environment");
});

test("signer bindings are distinct per environment, tracked as secrets, and confined to the Authority runtime", async () => {
  const { ATTESTATION_SIGNER_BINDINGS } = await import("../workers/admission-service/authority-attestation-config");
  const matrix = JSON.parse(await read("deployment/secret-matrix.json")) as { collisionSensitive: string[]; runtimes: Record<string, { forbiddenSecrets: string[]; requiredSecrets: string[] }> };
  const production = Object.values(ATTESTATION_SIGNER_BINDINGS.production);
  const staging = Object.values(ATTESTATION_SIGNER_BINDINGS.staging);
  assert.equal(new Set([...production, ...staging]).size, 6, "six distinct binding names: nothing is shared between Production and staging");
  for (const name of [ATTESTATION_SIGNER_BINDINGS.production.privateKey, ATTESTATION_SIGNER_BINDINGS.staging.privateKey]) {
    assert.ok(matrix.collisionSensitive.includes(name), `${name} is collision-checked`);
    for (const [runtime, policy] of Object.entries(matrix.runtimes)) {
      if (runtime === "admissionService") assert.equal(policy.forbiddenSecrets.includes(name), false, "the Authority runtime may hold it");
      else assert.ok(policy.forbiddenSecrets.includes(name), `${runtime} must never hold ${name}`);
    }
  }
  // "Code expects the binding" is NOT "the secret is provisioned": no operational value, placeholder-as-value or key is tracked anywhere.
  for (const file of await files("deployment", (name) => SOURCE.test(name))) {
    const text = await read(file);
    for (const name of [...production, ...staging]) assert.equal(text.includes(`"${name}": "`) && !/__REQUIRED_/u.test(text.slice(text.indexOf(name), text.indexOf(name) + 200)), false, `${file} must not carry a value for ${name}`);
  }
  const trust = JSON.parse(await read("deployment/authority-result-trust.template.json")) as { environments: Array<{ keys: Array<{ publicKey: string }> }> };
  for (const environment of trust.environments) for (const key of environment.keys) assert.match(key.publicKey, /^__REQUIRED_/u, "the tracked trust template carries placeholders only");
});

test("local-only test harnesses are named by no deployment config, template or script", async () => {
  // The Gate 4B live-readonly harness is deliberately named by its own reviewed deployment contract; the R06/DO-RPC test harnesses never are.
  const harnessFiles = ["attestation-rpc-transport-harness", "r06-active-path-harness", "production-do-rpc-harness", "staging-do-rpc-harness"];
  const named: string[] = [];
  for (const file of [...await files("deployment", (name) => SOURCE.test(name)), ...await files("scripts", (name) => SOURCE.test(name))]) {
    const text = await read(file);
    for (const harness of harnessFiles) if (text.includes(harness)) named.push(`${file} -> ${harness}`);
  }
  assert.deepEqual(named, []);
  for (const entry of await readdir(root)) {
    if (!/^wrangler\..*\.jsonc$/u.test(entry)) continue;
    assert.match(entry, /\.local\.jsonc$/u, `${entry}: only local-only configs may exist at the repository root`);
    const config = JSON.parse(await read(entry)) as { workers_dev?: boolean; preview_urls?: boolean; routes?: unknown };
    assert.equal(config.workers_dev, false, entry);
    assert.equal(config.preview_urls, false, entry);
    assert.equal(config.routes, undefined, entry);
  }
});

test("the 2A/2B inert-only assumptions are replaced by the exact reviewed allowlists above (no blanket 'unused' assertion remains)", async () => {
  for (const guard of ["tests/authority-result-attestation.test.ts", "tests/authority-result-verifier.test.ts"]) {
    const text = await read(guard);
    assert.equal(/no active caller imports the composer|2B is inert|inert Slice 2A Authority producer/u.test(text), false, guard);
  }
});

test("every attested admission entrypoint (mutating AND read-only) passes the one shared runtime-secret gate before reaching the Authority", async () => {
  const source = code(await read("workers/admission-service/index.ts"));
  // One gate definition, no duplicated validation logic: the policy is evaluated in exactly one place.
  assert.equal(source.match(/validateRuntimeSecrets\(/gu)?.length, 1, "validateRuntimeSecrets is called from the shared helper only");
  const entrypoint = (name: string): string => {
    const start = source.indexOf(`export class ${name} `);
    assert.ok(start >= 0, name);
    const next = source.indexOf("\nexport class ", start + 1);
    return source.slice(start, next < 0 ? undefined : next);
  };
  const method = (body: string, name: string): string => {
    const start = body.indexOf(`async ${name}(`);
    assert.ok(start >= 0, name);
    const next = body.indexOf("\n  async ", start + 1);
    return body.slice(start, next < 0 ? undefined : next);
  };
  for (const [className, attested] of [
    ["AuthorityLifecycleOnly", ["initializeAuthorityFromOperatorAttested", "rotateAuthorityReleaseFromOperatorAttested"]],
    ["StagingAuthorityLifecycleOnly", ["initializeAuthorityFromOperatorAttested"]],
    ["AuthorityLifecycleReadOnly", ["attestAppliedLifecycle", "attestReconciliation"]],
    ["StagingAuthorityLifecycleReadOnly", ["attestAppliedLifecycle", "attestReconciliation"]],
  ] as const) {
    const body = entrypoint(className);
    for (const name of attested) {
      const text = method(body, name);
      const gate = text.indexOf("runtimeSecretsValid(this.env)");
      const authority = text.indexOf("this.env.AUTHORITY");
      assert.ok(gate >= 0 && authority > gate, `${className}.${name}: the runtime-secret gate precedes the Authority call`);
    }
  }
  // The read-only gate answers a non-positive UNAVAILABLE; it can never answer receipt-not-found (the one reason that lets the guard claim).
  assert.equal(/RUNTIME_CONFIG_UNAVAILABLE\s*=\s*\{ status: "UNAVAILABLE", reason: "runtime-config-invalid" \} as const/u.test(source), true);
  assert.equal(source.includes('reason: "receipt-not-found"'), false);
  // The unsigned supervisory read (guard settlement, Gate 4 continuity) is deliberately unchanged and ungated.
  for (const className of ["AuthorityLifecycleReadOnly", "StagingAuthorityLifecycleReadOnly"])
    assert.equal(method(entrypoint(className), "inspectLifecycle").includes("runtimeSecretsValid"), false, `${className}.inspectLifecycle stays unchanged`);
});
