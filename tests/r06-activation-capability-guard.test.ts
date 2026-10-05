import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { builtinModules } from "node:module";
import { fileURLToPath } from "node:url";
import * as ts from "typescript";
import {
  ScannerSyntaxError, aliasConfigFiles, aliasSurfaceViolations, classifySpecifierPath, escapingReferenceViolations, isAcceptedSpecifier, scriptKindFor, unknownPackageViolations,
  SCAN_EXCLUDED_DIRECTORIES, assertNoUnreviewedUnprovableReferences, childProcessViolations, collectModuleReferences, computedAccessSites, dynamicCodeViolations, filesImporting,
  filesReferencing, forbiddenNodeModuleViolations, indirectAccessViolations, listScriptFiles, moduleName, moduleReferenceViolations, networkCapabilityViolations,
  protectedReferenceViolations, referenceShapeViolations, repositoryProtectedReferenceViolations, resolveRepositorySpecifier, scanRepository, signerCapabilityViolations,
  unprovableReferences, type ChildProcessUse, type ModulePolicy, type ReferenceKind, type RepositoryReferences,
} from "./support/r06-import-guard";

// R06 activation tooling (remediation B4): a STRUCTURAL capability and import restriction. The previous guard matched
// `import { ... } from "..."` with a regular expression; a namespace import, a dynamic import(), require()/createRequire(), a re-export, or
// an aliased/destructured/computed-property access to the signer all bypassed it. This file replaces that with a syntax-tree analysis
// (tests/support/r06-import-guard.ts) and proves, attack by attack, that each bypass is DETECTED. It reads source text and writes nothing.

const root = fileURLToPath(new URL("../", import.meta.url));
const read = (path: string) => readFile(join(root, path), "utf8");

/** The frozen authority-attestation modules, plus the tooling modules whose capability is pinned. */
const GUARDED = ["authority-result-attestation", "authority-result-trust", "authority-attestation-signer", "authority-attestation-config",
  "staging-attestation-key", "staging-attestation-secret", "staging-attestation-secret-engine", "staging-key-protection", "staging-wrangler-pin"] as const;

/** EXACTLY what each tooling file may import from a guarded module (named imports only). Any addition, rename, namespace/default/side-effect
 * import, re-export, dynamic import, require or createRequire is a failure, so widening this table is a reviewed change. */
const PINNED_IMPORTS: Readonly<Record<string, Readonly<Record<string, readonly string[]>>>> = {
  "operator/staging-attestation-key.ts": {
    "authority-result-attestation": ["attestationKeyFingerprint", "isSafeTime"],
    "authority-attestation-signer": ["createAuthorityAttestationSigner"],
    "staging-key-protection": ["KeyProtectionError", "assertCustodyProtected"],
  },
  "operator/staging-attestation-secret-engine.ts": {
    "authority-attestation-config": ["ATTESTATION_SIGNER_BINDINGS"],
    "staging-attestation-key": ["AttestationKeyError", "readStagingAttestationKeyForSecretPut"],
    "staging-wrangler-pin": ["WranglerPinError", "assertNoImplicitWranglerDotenv", "resolveReviewedWrangler"],
  },
  "operator/staging-attestation-secret.ts": {
    "staging-attestation-key": ["STAGING_ATTESTATION_KEY_DIRECTORY_SEGMENTS"],
    "staging-attestation-secret-engine": ["ATTESTATION_SECRET_ORDER", "ATTESTATION_SECRET_WORKER", "AttestationSecretDescription", "AttestationSecretError",
      "AttestationSecretInput", "AttestationSecretSubmission", "createAttestationSecretTooling"],
  },
  "operator/staging-key-protection.ts": {},
  "operator/staging-wrangler-pin.ts": {},
  "operator/staging-r06-renderer.ts": {
    "authority-result-attestation": ["isSafeTime"],
    "authority-result-trust": ["parseAuthorityResultTrustManifest"],
    "staging-attestation-key": ["AttestationKeyError", "verifyStagingAttestationKey"],
  },
  "operator/staging-r06-preflight.ts": {
    "authority-result-attestation": ["isSafeTime"],
    "authority-result-trust": ["parseAuthorityResultTrustManifest"],
    "staging-attestation-key": ["AttestationKeyError", "verifyStagingAttestationKey"],
    "staging-wrangler-pin": ["REVIEWED_WRANGLER_VERSION", "WranglerPinError", "assertNoImplicitWranglerDotenv"],
  },
  "scripts/authority-staging-attestation-keygen.ts": {
    "staging-attestation-key": ["AttestationKeyError", "STAGING_ATTESTATION_KEY_DIRECTORY_SEGMENTS", "STAGING_ATTESTATION_KEY_FILE", "STAGING_ATTESTATION_META_FILE", "generateStagingAttestationKey"],
  },
  "scripts/authority-staging-attestation-secret.ts": {
    "staging-attestation-key": ["AttestationKeyError"],
    "staging-attestation-secret": ["AttestationSecretError", "preflightAttestationSecrets", "submitAttestationSecrets"],
  },
  "scripts/authority-staging-r06-render.ts": { "staging-attestation-key": ["STAGING_ATTESTATION_KEY_DIRECTORY_SEGMENTS"] },
  "scripts/authority-staging-r06-preflight.ts": { "staging-attestation-key": ["STAGING_ATTESTATION_KEY_DIRECTORY_SEGMENTS"] },
};
const TOOLING = Object.keys(PINNED_IMPORTS);

/** F2: EVERY element access in the security-sensitive tooling whose key is not a literal, pinned exactly (one entry per occurrence, sorted). Each
 * is a plain data-record lookup whose key is a constant, an own key of a validated record, or a loop index. A new one -- the shape through
 * which a computed name could become `constructor` or `__proto__` -- is a reviewed change to this table, not a silent addition. */
const PINNED_COMPUTED_ACCESS: Readonly<Record<string, readonly string[]>> = {
  // environment-variable name tables: `parent[key]` iterates the caller's own keys, `values[name]` the child's own table
  "operator/staging-attestation-secret-engine.ts": ["parent[candidate]", "parent[key]", "parent[key]", "parent[key]", "parent[wanted]", "plan.values[name]", "values[name]"],
  // SDDL alias lookup in a frozen table, keyed by a two-letter trustee token read from the ACL text
  "operator/staging-key-protection.ts": ["SDDL_ALIASES[trustee]"],
  // fixed leaf-path walk over the reviewed trust-template positions and substitution table
  "operator/staging-r06-renderer.ts": ["(current as Record<string | number, unknown>)[step]", "current[path[path.length - 1]]", "current[step]", "path[path.length - 1]", "values[position.placeholder]"],
  // environment-variable name iteration
  "operator/staging-r06-preflight.ts": ["env[name]", "request.env[name]"],
};

/** F2: the ONLY unprovable module references in the whole repository (kind per occurrence), each reviewed by reading the site. None is in the
 * security-sensitive tooling and none can reach a guarded module: they are a CommonJS entry-point test, an object-literal property, an esbuild
 * `onResolve` helper that only calls `.resolve()`, and an `import()` of an in-memory bundle by `data:` URL. Any other file, any other kind, or
 * one more occurrence than listed fails the scan (and so does a listed one that disappeared: keep this table exact). */
const REVIEWED_UNPROVABLE_REFERENCES: Readonly<Record<string, readonly ReferenceKind[]>> = {
  // `if (require.main === module)`: the CommonJS entry-point idiom; `require` is read, never called
  "lab/concurrency/harness.ts": ["require"], "lab/failure/cancel-selftest.ts": ["require"], "lab/linux/parity.ts": ["require"], "lab/load/k6-selftest.ts": ["require"],
  "lab/postgres/guard-selftest.ts": ["require"], "lab/postgres/lab-db.ts": ["require"], "lab/postgres/run-db-tests.ts": ["require"], "lab/run.ts": ["require"],
  // an object-literal property named `require` in a test double
  "tests/admin-inquiry-mutations.test.ts": ["require"],
  // `createRequire(<package.json>).resolve(<path>)` inside an esbuild onResolve plugin: path resolution only, nothing is loaded through it
  "tests/gate8-phase1a-result-key-pin.test.ts": ["create-require"], "tests/gate8-staging-initialization-lock.test.ts": ["create-require"],
  "tests/workers/lifecycle-mailbox.integration.ts": ["create-require"], "tests/workers/operator-executor-rpc.integration.ts": ["create-require"],
  "tests/workers/staging-lifecycle-mailbox-faults.integration.ts": ["create-require"], "tests/workers/staging-lifecycle-mailbox.integration.ts": ["create-require"],
  "tests/workers/support/gate6-capture-harness.ts": ["create-require"], "tests/workers/support/gate6-verify-harness.ts": ["create-require"],
  "tests/workers/support/i3b-cli-result-harness.ts": ["create-require"], "tests/workers/support/r06-active-rig.ts": ["create-require"],
  "tests/workers/support/r06-upgrade-rig.ts": ["create-require"],
  // `import(`data:text/javascript;base64,...`)` of an esbuild bundle held in memory
  "tests/i3b-authority.test.ts": ["dynamic-import"], "tests/i3b-dispatch-faults.test.ts": ["dynamic-import"], "tests/i3b-staging-dispatch-faults.test.ts": ["dynamic-import"],
  "tests/i3b-staging.test.ts": ["dynamic-import"],
};

/** Finding 1: every protected module (canonical, lower-case name) and the ONE repository file it must mean. A reference to one of these names
 * is refused unless it is spelled plainly and resolves, case-exactly, to that file. */
const PROTECTED_FILES: Readonly<Record<string, string>> = {
  "authority-result-attestation": "src/lib/authority-result-attestation.ts",
  "authority-result-trust": "src/lib/authority-result-trust.ts",
  "authority-attestation-signer": "workers/admission-service/authority-attestation-signer.ts",
  "authority-attestation-config": "workers/admission-service/authority-attestation-config.ts",
  "staging-attestation-key": "operator/staging-attestation-key.ts",
  "staging-attestation-secret": "operator/staging-attestation-secret.ts",
  "staging-attestation-secret-engine": "operator/staging-attestation-secret-engine.ts",
  "staging-key-protection": "operator/staging-key-protection.ts",
  "staging-wrangler-pin": "operator/staging-wrangler-pin.ts",
};

/** Finding 2: the ONLY child-process use anywhere in the R06 tooling (every other tooling file may not reference `node:child_process` at all).
 * Each is one named, un-aliased import called directly exactly once, with these exact first and second argument expressions. */
const PINNED_CHILD_PROCESS: Readonly<Record<string, ChildProcessUse>> = {
  // the closed-set `wrangler secret put`: the Node executable, the pinned local wrangler.js, the one argv shape
  "operator/staging-attestation-secret-engine.ts": { name: "spawnSync", calls: 1, firstArgument: "process.execPath",
    secondArgument: `[plan.wranglerBin, "secret", "put", name, "--name", ATTESTATION_SECRET_WORKER]` },
  // the two read-only Windows ACL tools, absolute path, no shell
  "operator/staging-key-protection.ts": { name: "execFileSync", calls: 1, firstArgument: "executable", secondArgument: "[...args]" },
  // read-only git queries
  "operator/staging-r06-preflight.ts": { name: "spawnSync", calls: 1, firstArgument: `"git"`, secondArgument: "[...args]" },
};

const policyFor = (file: string): ModulePolicy => Object.fromEntries(GUARDED.map((module) => [module, PINNED_IMPORTS[file]?.[module] ?? []]));

const SIGNER = { module: "authority-attestation-signer", factory: "createAuthorityAttestationSigner", allowedMethod: "ready", forbiddenName: "sign" } as const;

// ---------------------------------------------------------------------------------------------------------------------------------
// The real tooling satisfies the structural restriction
// ---------------------------------------------------------------------------------------------------------------------------------

test("every tooling file imports EXACTLY its pinned names from the guarded modules, as static named imports, with no computed or dynamic access", async () => {
  for (const file of TOOLING) {
    const source = await read(file);
    assert.deepEqual(moduleReferenceViolations(source, policyFor(file), file), [], `${file}: structural import violations`);
    assert.deepEqual(dynamicCodeViolations(source, file), [], `${file}: eval / Function / mainModule`);
    // F2: no indirect route to require / eval / Function / the global object / process.mainModule either
    assert.deepEqual(indirectAccessViolations(source, file), [], `${file}: indirect module or code access`);
    assert.deepEqual(forbiddenNodeModuleViolations(source, file), [], `${file}: a Node built-in that evaluates code or loads modules`);
    // finding 2: STRUCTURAL spawn and network enforcement (the syntax tree; comments and trivia cannot hide anything from it)
    assert.deepEqual(childProcessViolations(source, PINNED_CHILD_PROCESS[file] ?? null, file), [], `${file}: child_process use differs from the reviewed table`);
    assert.deepEqual(networkCapabilityViolations(source, file), [], `${file}: a network-capable module or global client`);
    // finding 1: every reference to a protected module is plainly spelled and resolves case-exactly to the intended file
    assert.deepEqual(protectedReferenceViolations(file, collectModuleReferences(source, file), new Set(Object.values(PROTECTED_FILES).concat(file, ...Object.keys(PINNED_IMPORTS))), PROTECTED_FILES), [], `${file}: protected-module spelling`);
    assert.deepEqual(computedAccessSites(source, file), PINNED_COMPUTED_ACCESS[file] ?? [], `${file}: computed property access differs from the pinned, reviewed table`);
    // exact equality, not just a subset: an unused or newly added import of a guarded module is a reviewed change too
    const actual: Record<string, string[]> = {};
    for (const reference of collectModuleReferences(source, file)) {
      if (reference.specifier === null || !(GUARDED as readonly string[]).includes(moduleName(reference.specifier))) continue;
      (actual[moduleName(reference.specifier)] ??= []).push(...reference.names);
    }
    const expected = Object.fromEntries(Object.entries(PINNED_IMPORTS[file]).map(([module, names]) => [module, [...names].sort()]));
    assert.deepEqual(Object.fromEntries(Object.entries(actual).map(([module, names]) => [module, names.sort()])), expected, `${file}: guarded imports differ from the pinned table`);
    // no module-access escape hatch of any kind in tooling code (a non-literal require/import cannot be proven not to reach a guarded module)
    assert.equal(collectModuleReferences(source, file).some((reference) => reference.kind !== "import" && reference.kind !== "export-from" || reference.specifier === null), false, `${file}: dynamic/require/computed module access`);
    assert.equal(collectModuleReferences(source, file).some((reference) => reference.kind === "export-from"), false, `${file}: re-exports from another module`);
  }
});

test("key custody can invoke ONLY the signer's readiness self-test: the signer is bound to a const and used solely as `.ready(...)`; `sign` is never named", async () => {
  const source = await read("operator/staging-attestation-key.ts");
  assert.deepEqual(signerCapabilityViolations(source, SIGNER, "operator/staging-attestation-key.ts"), []);
  assert.match(source, /const signer = createAuthorityAttestationSigner\(/u, "the guard is not vacuous: the factory really is used in custody");
  assert.match(source, /signer\.ready\(/u);
});

test("the secret engine reads ONLY ATTESTATION_SIGNER_BINDINGS.staging: never the Production names, never the object itself", async () => {
  const source = await read("operator/staging-attestation-secret-engine.ts");
  assert.deepEqual(referenceShapeViolations(source, "authority-attestation-config", "ATTESTATION_SIGNER_BINDINGS", { kind: "property", name: "staging" }, "engine.ts"), []);
  assert.match(source, /ATTESTATION_SIGNER_BINDINGS\.staging/u, "the guard is not vacuous");
});

// ---------------------------------------------------------------------------------------------------------------------------------
// Negative controls: every bypass is DETECTED
// ---------------------------------------------------------------------------------------------------------------------------------

const TOOLING_POLICY: ModulePolicy = {
  "authority-result-attestation": ["attestationKeyFingerprint", "isSafeTime"],
  "authority-attestation-signer": ["createAuthorityAttestationSigner"],
  "authority-attestation-config": ["ATTESTATION_SIGNER_BINDINGS"],
};
const ATT = '"../src/lib/authority-result-attestation"';
const SIG = '"../workers/admission-service/authority-attestation-signer"';
const CFG = '"../workers/admission-service/authority-attestation-config"';

test("negative controls: a legitimate named import passes; every module-reference bypass of a frozen module is detected", () => {
  const clean = `import { attestationKeyFingerprint, isSafeTime } from ${ATT};\nimport {\n  createAuthorityAttestationSigner,\n} from ${SIG};`;
  assert.deepEqual(moduleReferenceViolations(clean, TOOLING_POLICY), [], "control: the permitted form is clean (the detector is not simply rejecting everything)");
  const bypasses: Record<string, string> = {
    "namespace import": `import * as attestation from ${ATT};`,
    "namespace import of the signer": `import * as signer from ${SIG};`,
    "default import": `import attestation from ${ATT};`,
    "default plus named import": `import attestation, { isSafeTime } from ${ATT};`,
    "side-effect import": `import ${ATT};`,
    "a name outside the allowlist": `import { signResultAttestation } from ${ATT};`,
    "a name outside the allowlist, aliased to an allowed one": `import { signResultAttestation as isSafeTime } from ${ATT};`,
    "a name outside the allowlist, multi-line": `import {\n  isSafeTime,\n  makeLifecycleStatement,\n} from ${ATT};`,
    "a type-only import of a name outside the allowlist": `import type { ResultStatement } from ${ATT};`,
    "the secret-name object of the signer config under another name": `import { ATTESTATION_SIGNER_BINDINGS, ATTESTATION_PRODUCTION_BINDINGS } from ${CFG};`,
    "re-export of everything": `export * from ${ATT};`,
    "re-export as a namespace": `export * as attestation from ${ATT};`,
    "re-export of a named symbol": `export { isSafeTime } from ${ATT};`,
    "re-export of a name outside the allowlist": `export { signResultAttestation } from ${ATT};`,
    "type re-export": `export type { ResultStatement } from ${ATT};`,
    "import-equals require": `import attestation = require(${ATT});`,
    "dynamic import": `const attestation = await import(${ATT});`,
    "dynamic import in a function": `async function load() { return (await import(${SIG})).createAuthorityAttestationSigner; }`,
    "dynamic import with a template literal": "const m = await import(`../src/lib/authority-result-attestation`);",
    "require()": `const attestation = require(${ATT});`,
    "require() destructured": `const { signResultAttestation } = require(${ATT});`,
    "module.require": `const attestation = module.require(${ATT});`,
    "createRequire": `import { createRequire } from "node:module";\nconst require = createRequire(import.meta.url);\nconst attestation = require(${ATT});`,
    "createRequire member": `import * as nodeModule from "node:module";\nconst r = nodeModule.createRequire(import.meta.url);`,
    "import.meta.resolve": `const where = import.meta.resolve(${ATT});`,
    "computed dynamic import": `const name = "../src/lib/authority-" + "result-attestation";\nconst m = await import(name);`,
    "computed require": `const m = require("../src/lib/authority-" + "result-attestation");`,
    "template-substitution import": "const part = \"attestation\";\nconst m = await import(`../src/lib/authority-result-${part}`);",
    "module['require']": `const m = module["require"](${ATT});`,
  };
  for (const [label, source] of Object.entries(bypasses)) {
    const violations = moduleReferenceViolations(source, TOOLING_POLICY);
    const dynamic = dynamicCodeViolations(source);
    assert.ok(violations.length + dynamic.length > 0, `bypass NOT detected: ${label}`);
  }
  // code that builds module access out of strings is flagged on its own
  for (const source of ['const r = eval("require");', 'const f = new Function("return require")();', "const r = process.mainModule.require;"]) assert.ok(dynamicCodeViolations(source).length > 0, source);
  assert.deepEqual(dynamicCodeViolations("const x = JSON.parse('{}'); const y = [1].map((n) => n);"), [], "control: ordinary code is not flagged");
});

test("negative controls: the guard also covers files that import from a differently-spelled path to the same module", () => {
  for (const specifier of ['"../src/lib/authority-result-attestation"', '"@/lib/authority-result-attestation"', '"./authority-result-attestation.ts"', '"../src/lib/authority-result-attestation.js"'])
    assert.ok(moduleReferenceViolations(`import * as a from ${specifier};`, TOOLING_POLICY).length > 0, specifier);
});

test("negative controls: the signer cannot be used for anything but `.ready()`: direct, aliased, destructured, computed, spread, passed or chained access are all detected", () => {
  const header = `import { createAuthorityAttestationSigner } from ${SIG};\n`;
  const ok = `${header}const signer = createAuthorityAttestationSigner({ environment: "staging" });\nawait signer.ready(1);\n`;
  assert.deepEqual(signerCapabilityViolations(ok, SIGNER), [], "control: the readiness self-test form is clean");
  assert.deepEqual(signerCapabilityViolations(`${header}const probe = createAuthorityAttestationSigner({});\nawait probe.ready(now);`, SIGNER), [], "control: any variable name is fine");
  const bypasses: Record<string, string> = {
    "direct sign call": `${header}const signer = createAuthorityAttestationSigner({});\nawait signer.sign(statement);`,
    "computed property, string literal": `${header}const signer = createAuthorityAttestationSigner({});\nawait signer["sign"](statement);`,
    "computed property, variable": `${header}const signer = createAuthorityAttestationSigner({});\nconst key = "si" + "gn";\nawait signer[key](statement);`,
    "computed property, template": `${header}const signer = createAuthorityAttestationSigner({});\nawait signer[\`sig\${'n'}\`](statement);`,
    "optional chaining": `${header}const signer = createAuthorityAttestationSigner({});\nawait signer?.sign?.(statement);`,
    "destructured sign": `${header}const signer = createAuthorityAttestationSigner({});\nconst { sign } = signer;\nawait sign(statement);`,
    "destructured with rename": `${header}const signer = createAuthorityAttestationSigner({});\nconst { sign: makeEnvelope } = signer;`,
    "destructured ready alongside": `${header}const signer = createAuthorityAttestationSigner({});\nconst { ready } = signer;\nawait ready(1);`,
    "alias of the signer": `${header}const signer = createAuthorityAttestationSigner({});\nconst other = signer;\nawait other.sign(statement);`,
    "alias, then ready only": `${header}const signer = createAuthorityAttestationSigner({});\nconst other = signer;\nawait other.ready(1);`,
    "passed to a function": `${header}const signer = createAuthorityAttestationSigner({});\nawait use(signer);`,
    "returned": `${header}function make() { const signer = createAuthorityAttestationSigner({});\n return signer; }`,
    "stored in an object": `${header}const signer = createAuthorityAttestationSigner({});\nconst holder = { signer };`,
    "spread": `${header}const signer = createAuthorityAttestationSigner({});\nconst copy = { ...signer };`,
    "Reflect.get": `${header}const signer = createAuthorityAttestationSigner({});\nawait Reflect.get(signer, "sign")(statement);`,
    ".ready used as a value, then called through .call": `${header}const signer = createAuthorityAttestationSigner({});\nawait signer.ready.call(signer, 1);`,
    "chained directly off the factory": `${header}await createAuthorityAttestationSigner({}).sign(statement);`,
    "chained ready off the factory": `${header}await createAuthorityAttestationSigner({}).ready(1);`,
    "factory stored under another name": `${header}const make = createAuthorityAttestationSigner;\nconst signer = make({});`,
    "factory passed on": `${header}register(createAuthorityAttestationSigner);`,
    "factory aliased at import": `import { createAuthorityAttestationSigner as make } from ${SIG};\nconst signer = make({});\nawait signer.sign(statement);`,
    "factory aliased at import, stored": `import { createAuthorityAttestationSigner as make } from ${SIG};\nconst factories = [make];`,
    "var instead of const": `${header}var signer = createAuthorityAttestationSigner({});\nawait signer.ready(1);`,
    "let instead of const": `${header}let signer = createAuthorityAttestationSigner({});\nawait signer.ready(1);`,
    "bound inside a destructuring pattern": `${header}const [signer] = [createAuthorityAttestationSigner({})];`,
    "the capability named anywhere": `${header}const signer = createAuthorityAttestationSigner({});\nawait signer.ready(1);\nconst capability = "sign";`,
    "the capability as a property name": `${header}const signer = createAuthorityAttestationSigner({});\nawait signer.ready(1);\nconst table = { sign: 1 };`,
  };
  for (const [label, source] of Object.entries(bypasses)) assert.ok(signerCapabilityViolations(source, SIGNER).length > 0, `signer bypass NOT detected: ${label}`);
});

test("negative controls: the binding names can only be read as `.staging`", () => {
  const header = `import { ATTESTATION_SIGNER_BINDINGS } from ${CFG};\n`;
  const shape = { kind: "property", name: "staging" } as const;
  assert.deepEqual(referenceShapeViolations(`${header}const names = ATTESTATION_SIGNER_BINDINGS.staging;`, "authority-attestation-config", "ATTESTATION_SIGNER_BINDINGS", shape), []);
  const bypasses: Record<string, string> = {
    production: `${header}const names = ATTESTATION_SIGNER_BINDINGS.production;`,
    "computed literal": `${header}const names = ATTESTATION_SIGNER_BINDINGS["staging"];`,
    "computed variable": `${header}const key = "prod" + "uction";\nconst names = ATTESTATION_SIGNER_BINDINGS[key];`,
    "whole object": `${header}const all = ATTESTATION_SIGNER_BINDINGS;`,
    "destructured": `${header}const { production } = ATTESTATION_SIGNER_BINDINGS;`,
    "Object.values": `${header}const all = Object.values(ATTESTATION_SIGNER_BINDINGS);`,
    "spread": `${header}const all = { ...ATTESTATION_SIGNER_BINDINGS };`,
    "aliased import": `import { ATTESTATION_SIGNER_BINDINGS as B } from ${CFG};\nconst names = B.production;`,
  };
  for (const [label, source] of Object.entries(bypasses)) assert.ok(referenceShapeViolations(source, "authority-attestation-config", "ATTESTATION_SIGNER_BINDINGS", shape).length > 0, `bindings bypass NOT detected: ${label}`);
});

// ---------------------------------------------------------------------------------------------------------------------------------
// F2: indirect module / code access. Negative controls: every route the reviewer demonstrated, and its relatives, is DETECTED
// ---------------------------------------------------------------------------------------------------------------------------------

/** Everything the structural guard applies to a tooling file. */
const toolingViolations = (source: string): string[] => [...moduleReferenceViolations(source, TOOLING_POLICY), ...dynamicCodeViolations(source),
  ...indirectAccessViolations(source), ...forbiddenNodeModuleViolations(source)];

test("F2 negative controls: ordinary tooling code is clean (the detectors do not simply reject everything)", () => {
  const clean = [
    `import { join } from "node:path";`,
    `import { spawnSync } from "node:child_process";`,
    `const home = process.env.USERPROFILE ?? "";`,
    `process.stdout.write(\`\${join(home, "x")}\\n\`);`,
    `process.exitCode = process.argv.length > 2 ? 2 : 0;`,
    `const here = import.meta.url;`,
    `const run = spawnSync(process.execPath, ["a"], { cwd: process.cwd(), shell: false });`,
    `await Promise.all([1, 2].map(async (n) => n + 1));`,
    `class Failure extends Error { constructor(readonly code: string) { super(code); } }`,
    `const record: Record<string, string> = { a: "b" };`,
    `const value = record.a;`,
    `const loaded = await import("../src/lib/ingress-protocol");`,
  ].join("\n");
  assert.deepEqual(toolingViolations(clean), [], "a representative sample of the legitimate constructs in the tooling");
});

test("F2 negative controls: every indirect route to require, eval, the Function constructor, the global object or process.mainModule is detected", () => {
  const bypasses: Record<string, string> = {
    // ----- require, however it is reached
    "(0, require)(x)": `const m = (0, require)("../src/lib/authority-result-attestation");`,
    "(0, require) with a computed specifier": `const m = (0, require)(name);`,
    "(1, 2, require)(x)": `const m = (1, 2, require)("../src/lib/authority-result-attestation");`,
    "aliased require": `const r = require;\nconst m = r("../src/lib/authority-result-attestation");`,
    "aliased require, assigned later": `let r;\nr = require;\nr("../src/lib/authority-result-attestation");`,
    "require passed as a value": `register(require);`,
    "require stored in an object": `const table = { load: require };`,
    "require destructured": `const { require: load } = globalThis;`,
    "require shorthand-destructured": `const { require } = holder;`,
    "require as a property": `const m = holder.require("../src/lib/authority-result-attestation");`,
    "globalThis.require": `const m = globalThis.require("../src/lib/authority-result-attestation");`,
    "global.require": `const m = global.require("../src/lib/authority-result-attestation");`,
    "globalThis['require']": `const m = globalThis["require"]("../src/lib/authority-result-attestation");`,
    "globalThis[computed]": `const name = "req" + "uire";\nconst m = globalThis[name]("../src/lib/authority-result-attestation");`,
    "global[computed]": `const m = global[name]("x");`,
    "Reflect.apply(require, ...)": `const m = Reflect.apply(require, undefined, ["../src/lib/authority-result-attestation"]);`,
    "Reflect.apply(aliased require, ...)": `const r = require;\nReflect.apply(r, undefined, ["x"]);`,
    "Reflect.get(globalThis, 'require')": `const m = Reflect.get(globalThis, "require");`,
    "Reflect.construct": `Reflect.construct(Thing, []);`,
    "Proxy around the global object": `const p = new Proxy({}, {});`,
    "require.call": `const m = require.call(undefined, "x");`,
    "require.apply": `const m = require.apply(undefined, ["x"]);`,
    "require.bind": `const f = require.bind(undefined);`,
    "createRequire": `import { createRequire } from "node:module";\nconst r = createRequire(import.meta.url);`,
    "module.require": `const m = module.require("../src/lib/authority-result-attestation");`,
    "module['require']": `const m = module["require"]("x");`,
    "module as a value": `const m = module;`,
    // ----- eval, however it is reached
    "(0, eval)": `(0, eval)("require");`,
    "(0, eval) with a result used": `const r = (0, eval)("1 + 1");`,
    "eval(...)": `eval("require");`,
    "aliased eval": `const e = eval;\ne("require");`,
    "globalThis.eval": `globalThis.eval("require");`,
    "global.eval": `global.eval("require");`,
    "globalThis['eval']": `globalThis["eval"]("require");`,
    "(0, globalThis.eval)": `(0, globalThis.eval)("require");`,
    "Reflect.apply(eval, ...)": `Reflect.apply(eval, undefined, ["1"]);`,
    "eval named by a string": `const key = "eval";\nholder[key]("1");`,
    "eval named by a template": "const key = `eval`;",
    // ----- the Function constructor
    "Function(...)": `Function("return require")();`,
    "new Function(...)": `new Function("return require")();`,
    "Function aliased": `const F = Function;\nF("return 1")();`,
    "globalThis.Function": `globalThis.Function("return 1")();`,
    "constructor of an arrow function": `const make = (() => {}).constructor;\nmake("return process.mainModule.require")();`,
    "constructor of a function expression, called": `(function () {}).constructor("return require")();`,
    "constructor of an array's constructor": `[].constructor.constructor("return require")();`,
    "constructor of an object": `({}).constructor.constructor("return require")();`,
    "constructor of an async function's prototype": `Object.getPrototypeOf(async function () {}).constructor("return 1");`,
    "constructor by string key": `const F = (() => {})["constructor"];`,
    "constructor by template key": "const F = (() => {})[`constructor`];",
    "constructor destructured": `const { constructor: F } = () => {};`,
    "constructor destructured, shorthand": `const { constructor } = () => {};`,
    "__proto__ walk": `const F = (() => {}).__proto__.constructor;`,
    "__proto__ by string": `const p = holder["__proto__"];`,
    // ----- process.mainModule and the rest of `process`
    "process['mainModule']": `const m = process["mainModule"].require("x");`,
    "process.mainModule": `const m = process.mainModule.require("x");`,
    "process[computed]": `const k = "main" + "Module";\nconst m = process[k];`,
    "process[template]": "const m = process[`main${'Module'}`];",
    "destructured mainModule": `const { mainModule } = process;`,
    "destructured mainModule, renamed": `const { mainModule: main } = process;`,
    "destructured process members": `const { env, argv } = process;`,
    "process aliased": `const p = process;\nconst m = p.mainModule;`,
    "process aliased, harmless member": `const p = process;\nconst a = p.argv;`,
    "process passed on": `inspect(process);`,
    "process stored": `const table = { process };`,
    "Reflect.get(process, ...)": `const m = Reflect.get(process, "mainModule");`,
    "process.binding": `process.binding("fs");`,
    "process.dlopen": `process.dlopen(module, "x");`,
    "process.mainModule through optional chaining": `const m = process?.mainModule?.require;`,
    "process default import": `import process from "node:process";\nconst m = process.mainModule;`,
    "process namespace import": `import * as proc from "node:process";`,
    "import.meta as a value": `const meta = import.meta;`,
    "import.meta.resolve": `const where = import.meta.resolve("../src/lib/authority-result-attestation");`,
    "import.meta['resolve']": `const where = import.meta["resolve"]("x");`,
    // ----- indirect invocation
    "(0, f)(x)": `const r = (0, helper)(1);`,
    "(a, b)(x)": `const r = (first, second)(1);`,
    "conditional callee": `const r = (flag ? one : two)(1);`,
    "logical callee": `const r = (one || two)(1);`,
    "result invocation f()(x)": `const r = makeFunction()(1);`,
    "computed member call": `const r = table[key](1);`,
    "computed member call, literal key": `const r = table["go"](1);`,
    "new on an expression": `const r = new (getConstructor())();`,
    "tagged template with an indirect tag": "const r = (0, tag)`x`;",
    "await import of a parenthesized callee": `const r = (await load())(1);`,
    // ----- modules that evaluate code or load modules
    "node:vm": `import vm from "node:vm";`,
    "vm": `import { runInThisContext } from "vm";`,
    "node:module": `import { builtinModules } from "node:module";`,
    "node:worker_threads": `import { Worker } from "node:worker_threads";`,
    "node:inspector": `import * as inspector from "node:inspector";`,
    "node:v8": `import { Script } from "node:v8";`,
    "dynamic import of node:vm": `const vm = await import("node:vm");`,
    "dynamic import of a computed built-in": `const vm = await import(\`node:\${name}\`);`,
    "import-equals require of node:vm": `import vm = require("node:vm");`,
  };
  for (const [label, source] of Object.entries(bypasses)) assert.ok(toolingViolations(source).length > 0, `indirect access NOT detected: ${label}`);
  assert.ok(Object.keys(bypasses).length >= 90, "the control list is not silently shrunk");
});

test("F2 negative controls: indirect require forms are recorded as UNPROVABLE references by the repository scan, never skipped", () => {
  const unprovable = (source: string) => collectModuleReferences(source, "x.ts").filter((reference) => reference.specifier === null);
  const caught: Record<string, string> = {
    "(0, require)(x)": `const m = (0, require)("x");`,
    "aliased require": `const r = require;\nr("x");`,
    "require destructured from the global object": `const { require: r } = globalThis;`,
    "globalThis.require": `globalThis.require("x");`,
    "global.require": `global.require("x");`,
    "globalThis['require']": `globalThis["require"]("x");`,
    "globalThis[computed]": `globalThis[name]("x");`,
    "Reflect.apply(require, ...)": `Reflect.apply(require, undefined, ["x"]);`,
    "require passed on": `register(require);`,
    "require.call": `require.call(undefined, "x");`,
    "computed require": `require(name);`,
    "computed dynamic import": `await import(name);`,
    "template dynamic import": "await import(`a${name}`);",
    "createRequire": `import { createRequire } from "node:module";\ncreateRequire(import.meta.url);`,
    "module.require with a computed specifier": `module.require(name);`,
    "module['require']": `module["require"]("x");`,
    "process[computed]": `process[name];`,
  };
  for (const [label, source] of Object.entries(caught)) assert.ok(unprovable(source).length > 0, `not recorded as unprovable: ${label}`);
  // controls: provable references are NOT unprovable
  for (const source of [`require("./x");`, `await import("./x");`, `import { a } from "./x";`, `module.require("./x");`, `const t = import("./x");`])
    assert.deepEqual(unprovable(source), [], source);
  // and the fail-closed assertion reports them
  for (const [label, source] of Object.entries(caught)) {
    const references: RepositoryReferences = new Map([["unreviewed/file.ts", collectModuleReferences(source, "unreviewed/file.ts")]]);
    assert.throws(() => assertNoUnreviewedUnprovableReferences(references, {}), /cannot prove these module references/u, label);
  }
  // reviewed exceptions are exact: the listed kind passes once, a second occurrence or another kind in the same file fails
  const one: RepositoryReferences = new Map([["lab/x.ts", collectModuleReferences(`if (require.main === module) {}`, "lab/x.ts")]]);
  assertNoUnreviewedUnprovableReferences(one, { "lab/x.ts": ["require"] });
  const two: RepositoryReferences = new Map([["lab/x.ts", collectModuleReferences(`if (require.main === module) {}\nconst r = require;`, "lab/x.ts")]]);
  assert.throws(() => assertNoUnreviewedUnprovableReferences(two, { "lab/x.ts": ["require"] }));
  const other: RepositoryReferences = new Map([["lab/x.ts", collectModuleReferences(`await import(name);`, "lab/x.ts")]]);
  assert.throws(() => assertNoUnreviewedUnprovableReferences(other, { "lab/x.ts": ["require"] }));
});

test("F2 negative controls: a computed property access in the tooling is pinned; a new one is detected", () => {
  assert.deepEqual(computedAccessSites(`const a = record[key];\nconst b = record["literal"];\nconst c = list[0];`), ["record[key]"], "literal keys are not computed");
  assert.deepEqual(computedAccessSites("const a = record[`${x}y`];\nconst b = record[a + b];\nconst c = (value as Record<string, unknown>)[step];").length, 3);
  assert.deepEqual(computedAccessSites(`const f = holder[name];`), ["holder[name]"]);
  assert.notDeepEqual(computedAccessSites(`const f = holder[name];`), PINNED_COMPUTED_ACCESS["operator/staging-key-protection.ts"], "an unreviewed lookup differs from the pinned table");
});

test("F2: the real repository scan proves every module reference, apart from EXACTLY the reviewed table", async () => {
  const references = await repository();
  const actual: Record<string, string[]> = {};
  for (const entry of unprovableReferences(references)) (actual[entry.file] ??= []).push(entry.kind);
  assert.deepEqual(Object.fromEntries(Object.entries(actual).map(([file, kinds]) => [file, kinds.sort()])),
    Object.fromEntries(Object.entries(REVIEWED_UNPROVABLE_REFERENCES).map(([file, kinds]) => [file, [...kinds].sort()])),
    "the unprovable references differ from the reviewed table (a new one, or a stale entry)");
  for (const file of TOOLING) assert.equal(unprovableReferences(references).some((entry) => entry.file === file), false, `${file}: security-sensitive tooling has no unprovable reference`);
});

test("F2: the repository scan excludes ONLY the exact, justified generated/dependency directories; build, dist, out and dot-directories elsewhere ARE scanned", async () => {
  assert.deepEqual([...SCAN_EXCLUDED_DIRECTORIES].sort(), [".git", ".next", ".npm-cache", ".playwright", ".wrangler", "artifacts", "node_modules", "out", "playwright-report", "test-results"]);
  const parent = await mkdtemp(join(tmpdir(), "r06-scan-"));
  try {
    const files: Record<string, boolean> = {
      "a.ts": true, "b.d.ts": true, "c.json": false, "d.mjs": true, "e.cjs": true, "f.tsx": true, "Upper.TS": true, "Upper.MJS": true,
      // excluded: exactly these root-level directories
      "node_modules/pkg/index.ts": false, ".next/g.ts": false, ".wrangler/h.ts": false, ".npm-cache/i.ts": false, "artifacts/j.ts": false, "out/k.ts": false,
      ".git/hooks/l.js": false, ".playwright/m.ts": false, "test-results/n.ts": false, "playwright-report/o.js": false,
      // scanned: the same names anywhere else, and every other directory including dot-directories
      "dist/p.ts": true, "build/q.ts": true, "coverage/r.ts": true, ".claude/s.ts": true, ".github/t.js": true, ".hidden/u.ts": true,
      "workers/dist/v.ts": true, "workers/build/w.ts": true, "workers/out/x.ts": true, "workers/node_modules/y.ts": true, "workers/.next/z.ts": true,
      "scripts/.hidden/aa.ts": true, "lab/artifacts/bb.ts": true, "lab/.wrangler/cc.ts": true, "src/node_modules/dd.ts": true,
    };
    for (const path of Object.keys(files)) { await mkdir(join(parent, ...path.split("/").slice(0, -1)), { recursive: true }); await writeFile(join(parent, ...path.split("/")), "export {};"); }
    assert.deepEqual(await listScriptFiles(parent), Object.entries(files).filter(([, scanned]) => scanned).map(([path]) => path).sort());
    // the old basename-based skip would have hidden every one of these
    for (const hidden of ["dist/p.ts", "build/q.ts", ".claude/s.ts", ".hidden/u.ts", "workers/dist/v.ts", "workers/out/x.ts", "workers/node_modules/y.ts", "scripts/.hidden/aa.ts"])
      assert.ok((await listScriptFiles(parent)).includes(hidden), hidden);
    // a symlink is an error: the scan cannot prove where it leads
    try {
      await symlink(join(parent, "workers"), join(parent, "linked"), "dir");
      await assert.rejects(listScriptFiles(parent), /symlink linked/u);
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "EPERM" && (error as NodeJS.ErrnoException).code !== "EACCES") throw error; /* no symlink privilege on this host */ }
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test("F2: every excluded directory other than .git is git-ignored, so none of them can hold committed or reviewable source", () => {
  for (const directory of SCAN_EXCLUDED_DIRECTORIES.filter((entry) => entry !== ".git"))
    assert.equal(spawnSync("git", ["check-ignore", "-q", `${directory}/probe.ts`], { cwd: root }).status, 0, `${directory} must be ignored by .gitignore`);
  assert.equal(spawnSync("git", ["check-ignore", "-q", "workers/dist/probe.ts"], { cwd: root }).status, 1, "dist elsewhere is not ignored, and so is scanned");
});

test("F2: the real repository scan really does visit the directories the old basename skip hid (dot-directories and build-named ones)", async () => {
  const files = await listScriptFiles(root);
  assert.ok(files.length > 200, "the scan is not vacuous");
  assert.ok(files.includes("tests/support/r06-import-guard.ts"));
  assert.equal(files.some((file) => file.startsWith("node_modules/") || file.startsWith(".next/") || file.startsWith(".git/") || file.startsWith(".wrangler/")), false);
});

// ---------------------------------------------------------------------------------------------------------------------------------
// Repository-wide pins: who may reach the provider-capable functions, the private-key loader and the capability factory
// ---------------------------------------------------------------------------------------------------------------------------------

let scanned: Promise<RepositoryReferences> | undefined;
/** The scan FAILS CLOSED: a reference whose module cannot be proven is an error unless it is in the reviewed table above. */
const repository = () => (scanned ??= scanRepository(root).then((references) => { assertNoUnreviewedUnprovableReferences(references, REVIEWED_UNPROVABLE_REFERENCES); return references; }));
const nonTest = (files: string[]) => files.filter((file) => !file.startsWith("tests/"));

test("the private-key loader is imported ONLY by the closed-set secret engine (tests aside, which use synthetic keys)", async () => {
  const importers = filesImporting(await repository(), "staging-attestation-key", "readStagingAttestationKeyForSecretPut");
  assert.deepEqual(nonTest(importers), ["operator/staging-attestation-secret-engine.ts"]);
  assert.deepEqual(importers.filter((file) => file.startsWith("tests/")), [
    "tests/r06-activation-key-custody.test.ts", "tests/r06-activation-key-protection.test.ts", "tests/r06-activation-render.test.ts", "tests/r06-activation-secret-wrapper.test.ts",
  ]);
});

test("the provider-capable production functions are imported ONLY by the closed-set CLI; the capability factory only by the production binding", async () => {
  const references = await repository();
  // the production binding module: the CLI, and the wrapper test (which imports it only to inspect its exports and prove a hostile call is refused at the account pin)
  assert.deepEqual(filesReferencing(references, ["staging-attestation-secret"]), ["scripts/authority-staging-attestation-secret.ts", "tests/r06-activation-secret-wrapper.test.ts"]);
  assert.deepEqual(filesImporting(references, "staging-attestation-secret", "submitAttestationSecrets").filter((file) => file !== "tests/r06-activation-secret-wrapper.test.ts"), ["scripts/authority-staging-attestation-secret.ts"]);
  assert.deepEqual(filesImporting(references, "staging-attestation-secret", "preflightAttestationSecrets").filter((file) => file !== "tests/r06-activation-secret-wrapper.test.ts"), ["scripts/authority-staging-attestation-secret.ts"]);
  // the factory module: the binding that fixes its constants, and the wrapper test that builds a sandbox root with a recording fake Wrangler
  assert.deepEqual(filesReferencing(references, ["staging-attestation-secret-engine"]), ["operator/staging-attestation-secret.ts", "tests/r06-activation-secret-wrapper.test.ts"]);
  assert.deepEqual(filesImporting(references, "staging-attestation-secret-engine", "createAttestationSecretTooling"), ["operator/staging-attestation-secret.ts", "tests/r06-activation-secret-wrapper.test.ts"]);
  // and only the CLI script may call them (the CLI never constructs anything else)
  const cli = await read("scripts/authority-staging-attestation-secret.ts");
  assert.equal(collectModuleReferences(cli).filter((reference) => reference.specifier !== null && moduleName(reference.specifier) === "staging-attestation-secret-engine").length, 0);
});

test("the custody, protection and Wrangler-pin modules have exactly the reviewed importers", async () => {
  const references = await repository();
  assert.deepEqual(nonTest(filesReferencing(references, ["staging-attestation-key"])), [
    "operator/staging-attestation-secret-engine.ts", "operator/staging-attestation-secret.ts", "operator/staging-r06-preflight.ts", "operator/staging-r06-renderer.ts",
    "scripts/authority-staging-attestation-keygen.ts", "scripts/authority-staging-attestation-secret.ts", "scripts/authority-staging-r06-preflight.ts", "scripts/authority-staging-r06-render.ts",
  ]);
  assert.deepEqual(filesReferencing(references, ["staging-key-protection"]), ["operator/staging-attestation-key.ts", "tests/r06-activation-key-protection.test.ts"]);
  assert.deepEqual(filesReferencing(references, ["staging-wrangler-pin"]), [
    "operator/staging-attestation-secret-engine.ts", "operator/staging-r06-preflight.ts", "tests/r06-activation-secret-wrapper.test.ts", "tests/support/wrangler-sandbox.ts",
  ]);
  // every referencing file outside the pinned tooling is a test; none of them re-exports, requires or dynamically imports any of these modules
  for (const [file, list] of references) {
    if (TOOLING.includes(file) || !file.startsWith("tests/")) continue;
    for (const reference of list) {
      if (reference.specifier === null || !(GUARDED as readonly string[]).slice(4).includes(moduleName(reference.specifier))) continue;
      assert.ok(reference.kind === "import" || reference.kind === "import-type", `${file}: ${reference.kind} of ${reference.specifier}`);
    }
  }
});

test("the structural scan sees every reference to the frozen protocol modules that the older text-pattern guard sees, and no more", async () => {
  // Consistency of the new analyzer with tests/authority-activation-guards.test.ts: a reference form the old pattern could not see (require,
  // createRequire, a re-export, a namespace import) would appear here as an extra importer and fail this test.
  const references = await repository();
  const structural = filesReferencing(references, ["authority-result-attestation", "authority-result-trust"])
    .filter((file) => ["src", "workers", "operator", "scripts", "deployment"].some((directory) => file.startsWith(`${directory}/`)) && !file.startsWith("src/lib/authority-result-"));
  const textual: string[] = [];
  for (const file of structural) {
    const text = await read(file);
    if ([...text.matchAll(/(?:from|import\()\s*"([^"]+)"/gu)].some((match) => /authority-result-(?:attestation|trust)$/u.test(match[1]))) textual.push(file);
  }
  assert.deepEqual(structural, textual, "a frozen-module reference exists that the text-pattern guard cannot see");
  for (const file of structural) {
    const odd = references.get(file)?.filter((reference) => reference.specifier !== null && /authority-result-(?:attestation|trust)$/u.test(reference.specifier) && reference.kind !== "import");
    assert.deepEqual(odd, [], `${file}: non-static reference to a frozen module`);
  }
});

// ---------------------------------------------------------------------------------------------------------------------------------
// Third-audit finding 1: canonical module-specifier / importer enforcement
// ---------------------------------------------------------------------------------------------------------------------------------
//
// Premise (shown locally with tsx, no provider): `import ... from "./guarded.ts?x=1"` and, on a case-insensitive file system, `"./Guarded"` both
// LOAD the module, while the previous scanner keyed on the exact last path segment and so attributed them to no module at all. TypeScript
// rejects some of those spellings, but a `// @ts-ignore` silences it and `.mjs`/`.cjs`/`.js` files are never type-checked, so enforcement here
// must not (and does not) consult a compiler diagnostic: everything below is syntax-tree and exact-file-set reasoning.

const REPOSITORY_FILES: ReadonlySet<string> = new Set([...Object.values(PROTECTED_FILES), "scripts/importer.ts", "operator/helper.ts"]);
const KEY_LOADER = "readStagingAttestationKeyForSecretPut";
const check = (importer: string, source: string) => protectedReferenceViolations(importer, collectModuleReferences(source, importer), REPOSITORY_FILES, PROTECTED_FILES);

test("finding 1 controls: the plain, exact spellings of a protected module are clean (the detector does not simply reject everything)", () => {
  for (const specifier of ["../operator/staging-attestation-key", "../operator/staging-attestation-key.ts", "../operator/staging-attestation-key.js", "../operator/./staging-attestation-key"])
    assert.deepEqual(check("scripts/importer.ts", `import { ${KEY_LOADER} } from ${JSON.stringify(specifier)};`), [], specifier);
  assert.deepEqual(check("scripts/importer.mjs", `import { x } from "../operator/staging-attestation-key.js";`), []);
  assert.deepEqual(check("scripts/importer.cjs", `const { x } = require("../operator/staging-attestation-key.ts");`), []);
  assert.deepEqual(check("workers/admission-service/index.ts", `import { y } from "./authority-attestation-config";`), []);
  assert.deepEqual(check("tests/a.test.ts", `import { z } from "@/lib/authority-result-attestation";`), []);
  assert.deepEqual(check("scripts/importer.ts", `import { j } from "../operator/helper";`), [], "an unrelated module is not touched");
});

test("finding 1 negative controls: query, fragment, alternate-case, percent-encoded, backslash and wrong-file spellings of a protected module are all detected", () => {
  const spellings: Record<string, string> = {
    "protected.ts?x=1": "../operator/staging-attestation-key.ts?x=1",
    "query without extension": "../operator/staging-attestation-key?raw",
    "query, empty": "../operator/staging-attestation-key?",
    "protected.ts#x": "../operator/staging-attestation-key.ts#x",
    "fragment only": "../operator/staging-attestation-key#frag",
    "alternate-case file name (Windows/macOS resolve it)": "../operator/Staging-Attestation-Key",
    "alternate-case with extension": "../operator/STAGING-ATTESTATION-KEY.ts",
    "alternate-case directory": "../Operator/staging-attestation-key",
    "alternate-case extension": "../operator/staging-attestation-key.TS",
    "percent-encoded hyphen": "../operator/staging%2Dattestation-key",
    "percent-encoded dot": "../operator/staging-attestation-key%2Ets",
    "percent-encoded slash": "..%2Foperator/staging-attestation-key",
    "backslash separator": "../operator\\staging-attestation-key",
    "backslash only": "..\\operator\\staging-attestation-key",
    "a bare package of the same name": "staging-attestation-key",
    "a file: URL": "file:///C:/repo/operator/staging-attestation-key.ts",
    "an absolute path": "/repo/operator/staging-attestation-key.ts",
    "the same name in another directory": "../scripts/staging-attestation-key",
    "a path that leaves the repository": "../../../outside/staging-attestation-key.ts",
    "trailing space": "../operator/staging-attestation-key.ts ",
    "trailing newline": "../operator/staging-attestation-key.ts\n",
    "NUL": "../operator/staging-attestation-key.ts\u0000",
  };
  const forms = (specifier: string): Record<string, string> => {
    const q = JSON.stringify(specifier);
    return {
      "named import": `import { ${KEY_LOADER} } from ${q};`, "namespace import": `import * as k from ${q};`, "default import": `import k from ${q};`,
      "side-effect import": `import ${q};`, "type import": `import type { T } from ${q};`, "re-export": `export { ${KEY_LOADER} } from ${q};`, "star re-export": `export * from ${q};`,
      "dynamic import": `const k = await import(${q});`, "require": `const k = require(${q});`, "import-equals": `import k = require(${q});`, "module.require": `const k = module.require(${q});`,
      "import.meta.resolve": `const where = import.meta.resolve(${q});`,
    };
  };
  let cases = 0;
  for (const [label, specifier] of Object.entries(spellings)) {
    for (const [form, source] of Object.entries(forms(specifier))) {
      // every importer extension the scan covers: .ts .tsx .mts .cts .js .jsx .mjs .cjs
      for (const extension of ["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"]) {
        const importer = `scripts/importer.${extension}`;
        const references = collectModuleReferences(source, importer);
        // detected means: the protected-reference check refuses it, OR the collector reports it as an unprovable reference (the repository scan fails closed on those)
        const violations = [...protectedReferenceViolations(importer, references, REPOSITORY_FILES, PROTECTED_FILES), ...references.filter((reference) => reference.specifier === null).map(() => "unprovable")];
        assert.ok(violations.length > 0, `NOT detected: ${label} / ${form} / .${extension}`);
        cases += 1;
      }
    }
  }
  assert.ok(cases >= 22 * 12 * 8, "the control matrix is not silently shrunk");
});

test("finding 1: percent-encoded and backslash literals are UNPROVABLE references (specifier null), so the repository scan fails closed on them", () => {
  for (const specifier of ["../operator/staging%2Dattestation-key", "../operator\\staging-attestation-key", "../operator/a b", ""]) {
    const references = collectModuleReferences(`import { x } from ${JSON.stringify(specifier)};`, "scripts/importer.ts");
    assert.deepEqual(references.map((reference) => reference.specifier), [null], JSON.stringify(specifier));
    assert.throws(() => assertNoUnreviewedUnprovableReferences(new Map([["scripts/importer.ts", references]]), {}), /cannot prove these module references/u, JSON.stringify(specifier));
  }
  // ordinary specifiers are untouched
  assert.deepEqual(collectModuleReferences(`import { x } from "node:fs/promises";`, "a.ts").map((reference) => reference.specifier), ["node:fs/promises"]);
});

test("finding 1: the importer pins see through case and extension spellings; a query or fragment literal is never interpreted -- it is UNPROVABLE", () => {
  assert.equal(moduleName("../operator/Staging-Attestation-Key.MJS"), "staging-attestation-key");
  assert.equal(moduleName("../operator/staging-attestation-key"), "staging-attestation-key");
  for (const variant of ["../operator/Staging-Attestation-Key", "../operator/staging-attestation-key.js"]) {
    const references: RepositoryReferences = new Map([["scripts/importer.mjs", collectModuleReferences(`import { ${KEY_LOADER} } from ${JSON.stringify(variant)};`, "scripts/importer.mjs")]]);
    assert.deepEqual(filesImporting(references, "staging-attestation-key", KEY_LOADER), ["scripts/importer.mjs"], `the loader importer is attributed despite the spelling: ${variant}`);
    assert.deepEqual(filesReferencing(references, ["staging-attestation-key"]), ["scripts/importer.mjs"], variant);
  }
  // sixth-pass: a literal containing `?` or `#` is not split, canonicalized or attributed; it is refused outright (specifier null), so the repository scan fails
  for (const variant of ["../operator/staging-attestation-key.ts?x=1", "../operator/staging-attestation-key.ts#x", "../operator/staging-attestation-key.js?v=2", "../x#/../operator/staging-attestation-key.ts"]) {
    const references = collectModuleReferences(`import { ${KEY_LOADER} } from ${JSON.stringify(variant)};`, "scripts/importer.mjs");
    assert.deepEqual(references.map((reference) => reference.specifier), [null], variant);
    assert.throws(() => assertNoUnreviewedUnprovableReferences(new Map([["scripts/importer.mjs", references]]), {}), /cannot prove these module references/u, variant);
  }
  assert.ok(moduleReferenceViolations(`import { verifyStagingAttestationKey } from "./staging-attestation-key.ts?x=1";`, { "staging-attestation-key": ["verifyStagingAttestationKey"] }).some((violation) => /computed or malformed/u.test(violation)),
    "a tooling file that pins an allowed name still cannot use the odd spelling");
});

test("finding 1: a // @ts-ignore (or an untyped .mjs/.cjs file) changes nothing -- the scan never consults a compiler diagnostic", () => {
  const ignored = `// @ts-ignore\nimport { ${KEY_LOADER} } from "../operator/staging-attestation-key.ts?x=1";\n// @ts-expect-error\nimport * as k from "../operator/Staging-Attestation-Key";`;
  for (const importer of ["scripts/importer.ts", "scripts/importer.mjs", "scripts/importer.cjs", "scripts/importer.js"]) {
    const found = collectModuleReferences(ignored, importer);
    // the query spelling is unprovable (specifier null, the scan fails closed); the alternate-case one is a protected-reference violation
    const violations = [...protectedReferenceViolations(importer, found, REPOSITORY_FILES, PROTECTED_FILES), ...found.filter((reference) => reference.specifier === null).map(() => "unprovable")];
    assert.equal(violations.length >= 2, true, `${importer}: ${violations.join(" | ")}`);
    const references: RepositoryReferences = new Map([[importer, collectModuleReferences(ignored, importer)]]);
    assert.deepEqual(filesImporting(references, "staging-attestation-key", KEY_LOADER), [importer]);
  }
});

test("finding 1: exact-case resolution -- a name that matches only case-insensitively resolves to nothing", () => {
  assert.equal(resolveRepositorySpecifier("scripts/importer.ts", "../operator/staging-attestation-key", REPOSITORY_FILES), "operator/staging-attestation-key.ts");
  assert.equal(resolveRepositorySpecifier("scripts/importer.ts", "../operator/staging-attestation-key.js", REPOSITORY_FILES), "operator/staging-attestation-key.ts");
  assert.equal(resolveRepositorySpecifier("scripts/importer.ts", "../operator/Staging-Attestation-Key", REPOSITORY_FILES), null);
  assert.equal(resolveRepositorySpecifier("scripts/importer.ts", "../Operator/staging-attestation-key", REPOSITORY_FILES), null);
  assert.equal(resolveRepositorySpecifier("tests/a.test.ts", "@/lib/authority-result-trust", REPOSITORY_FILES), "src/lib/authority-result-trust.ts");
  assert.equal(resolveRepositorySpecifier("scripts/importer.ts", "node:fs", REPOSITORY_FILES), null);
  assert.equal(resolveRepositorySpecifier("scripts/importer.ts", "../../x", REPOSITORY_FILES), null);
});

test("finding 1: every reference in the whole repository to a protected module is plainly spelled and resolves case-exactly to the intended file", async () => {
  const references = await repository();
  assert.deepEqual(repositoryProtectedReferenceViolations(references, PROTECTED_FILES), []);
  // not vacuous: the table's modules really are referenced
  assert.ok(filesReferencing(references, Object.keys(PROTECTED_FILES)).length > 20);
});

// ---------------------------------------------------------------------------------------------------------------------------------
// Third-audit finding 2: STRUCTURAL child-process and network enforcement
// ---------------------------------------------------------------------------------------------------------------------------------

const ENGINE = PINNED_CHILD_PROCESS["operator/staging-attestation-secret-engine.ts"];
const REVIEWED_SPAWN = `import { spawnSync } from "node:child_process";\nconst result = spawnSync(process.execPath, [plan.wranglerBin, "secret", "put", name, "--name", ATTESTATION_SECRET_WORKER], { shell: false });`;

test("finding 2 controls: the reviewed child-process use passes (with any whitespace or comments); a file with no entry may not reference child_process at all", () => {
  assert.deepEqual(childProcessViolations(REVIEWED_SPAWN, ENGINE), []);
  assert.deepEqual(childProcessViolations(REVIEWED_SPAWN.replace("spawnSync(process.execPath,", "/* reviewed */ spawnSync(\n  process.execPath,\n  // argv\n"), ENGINE), []);
  assert.deepEqual(childProcessViolations(`const x = 1;`, null), []);
  assert.deepEqual(networkCapabilityViolations(`import { join } from "node:path";\nimport { readFile } from "node:fs/promises";\nconst x = await readFile(join("a", "b"));`), [], "ordinary code is not flagged");
  for (const [file, use] of Object.entries(PINNED_CHILD_PROCESS)) assert.ok(use.calls === 1 && use.name.length > 0, file);
});

test("finding 2 negative controls: every way of adding, widening or hiding a child process is detected", () => {
  const arg = `process.execPath, [plan.wranglerBin, "secret", "put", name, "--name", ATTESTATION_SECRET_WORKER]`;
  const bad: Record<string, string> = {
    "namespace import": `import * as cp from "node:child_process";\ncp.spawnSync(${arg});`,
    "namespace import, no node: prefix": `import * as cp from "child_process";\ncp.spawnSync(${arg});`,
    "default import": `import cp from "node:child_process";\ncp.spawnSync(${arg});`,
    "aliased spawnSync": `import { spawnSync as go } from "node:child_process";\ngo(${arg});`,
    "alias that shadows another name": `import { spawn as spawnSync } from "node:child_process";\nspawnSync(${arg});`,
    "spawnSync plus exec": `import { spawnSync, exec } from "node:child_process";\nspawnSync(${arg});\nexec("x");`,
    "execFile": `import { execFile } from "node:child_process";\nexecFile("x");`,
    "execFileSync instead": `import { execFileSync } from "node:child_process";\nexecFileSync(${arg});`,
    "execSync": `import { execSync } from "node:child_process";\nexecSync("wrangler secret put X");`,
    "fork": `import { fork } from "node:child_process";\nfork("x.js");`,
    "spawn (async)": `import { spawn } from "node:child_process";\nspawn(${arg});`,
    "a second call site": `${REVIEWED_SPAWN}\nspawnSync(${arg});`,
    "a second call site in a function": `${REVIEWED_SPAWN}\nfunction again() { return spawnSync(${arg}); }`,
    "no call at all": `import { spawnSync } from "node:child_process";`,
    "different executable": REVIEWED_SPAWN.replace("process.execPath", `"wrangler"`),
    "different argv": REVIEWED_SPAWN.replace(`"secret", "put"`, `"secret", "delete"`),
    "argv extended": REVIEWED_SPAWN.replace(`ATTESTATION_SECRET_WORKER]`, `ATTESTATION_SECRET_WORKER, "--env", "x"]`),
    "stored": `${REVIEWED_SPAWN}\nconst run = spawnSync;`,
    "passed on": `${REVIEWED_SPAWN}\nregister(spawnSync);`,
    "called through .call": `${REVIEWED_SPAWN}\nspawnSync.call(undefined, ${arg});`,
    "destructured use": `${REVIEWED_SPAWN}\nconst { spawnSync: again } = { spawnSync };`,
    "type-only import": `import type { spawnSync } from "node:child_process";`,
    "dynamic import": `const cp = await import("node:child_process");\ncp.spawnSync(${arg});`,
    "dynamic import, template literal": "const cp = await import(`node:child_process`);",
    "dynamic import, computed": `const cp = await import("node:child" + "_process");`,
    "require": `const cp = require("child_process");`,
    "import-equals": `import cp = require("node:child_process");`,
    "re-export": `export { spawnSync } from "node:child_process";`,
    "star re-export": `export * from "node:child_process";`,
    "side-effect import": `import "node:child_process";`,
    "query-suffix spelling": REVIEWED_SPAWN.replace(`"node:child_process"`, `"node:child_process?x=1"`),
    "second import statement": `${REVIEWED_SPAWN}\nimport { spawnSync as other } from "child_process";`,
    "comment-prefixed extra call": `${REVIEWED_SPAWN}\n/**/ spawnSync(${arg});`,
    "comment-prefixed extra import": `${REVIEWED_SPAWN}\n/* x */ import { exec } from "node:child_process";`,
  };
  for (const [label, source] of Object.entries(bad)) assert.ok(childProcessViolations(source, ENGINE).length > 0, `child_process bypass NOT detected: ${label}`);
  assert.ok(Object.keys(bad).length >= 30);
  // a file that may not reference child_process at all: every form that mentions it fails, including the reviewed one
  for (const [label, source] of [...Object.entries(bad), ["the reviewed form itself", REVIEWED_SPAWN] as [string, string]])
    if (/child_process|child"/u.test(source)) assert.ok(childProcessViolations(source, null).length > 0, `unlisted-file bypass NOT detected: ${label}`);
  // and the reviewed form is rejected for a DIFFERENT pinned use (the pin is exact, not "some spawn is fine")
  assert.ok(childProcessViolations(REVIEWED_SPAWN, PINNED_CHILD_PROCESS["operator/staging-key-protection.ts"]).length > 0);
});

test("finding 2 negative controls: every network-capable built-in, client package and global client is detected, in every import form", () => {
  const modules = ["net", "http", "https", "http2", "tls", "dns", "dgram", "dns/promises", "node:net", "node:http", "node:https", "node:http2", "node:tls", "node:dns", "node:dns/promises", "node:dgram",
    "undici", "ws", "axios", "node-fetch", "cross-fetch", "got", "superagent", "socket.io-client", "cloudflare", "@cloudflare/workers-types", "miniflare", "wrangler"];
  for (const name of modules) {
    const q = JSON.stringify(name);
    const forms = [`import x from ${q};`, `import * as x from ${q};`, `import { a } from ${q};`, `import ${q};`, `import type { T } from ${q};`, `export { a } from ${q};`, `export * from ${q};`,
      `const x = await import(${q});`, `const x = require(${q});`, `import x = require(${q});`, `type T = import(${q}).Foo;`];
    for (const source of forms) assert.ok(networkCapabilityViolations(source).length > 0, `network module NOT detected: ${source}`);
  }
  // a query/fragment spelling of a network module is not interpreted: it is an unprovable reference, which fails the repository scan
  for (const name of ["https?x=1", "node:https#x", "../x#/../undici"])
    assert.deepEqual(collectModuleReferences(`import x from ${JSON.stringify(name)};`, "scripts/a.ts").map((reference) => reference.specifier), [null], name);
  const globals: Record<string, string> = {
    "fetch call": `await fetch("https://api.cloudflare.com/client/v4/accounts");`,
    "fetch with comment prefix": `/**/ await fetch("https://api.cloudflare.com/x");`,
    "fetch after a block comment on the same line": `/* harmless */ await fetch(url);`,
    "fetch after a multi-line comment": `/*\n * note\n */ fetch(url);`,
    "fetch inside a template substitution": "const s = `${await fetch(u)}`;",
    "fetch stored": `const f = fetch;`,
    "fetch as a property": `service.fetch(request);`,
    "fetch by string": `holder["fetch"](u);`,
    "fetch by template": "holder[`fetch`](u);",
    "globalThis.fetch": `globalThis.fetch(u);`,
    "self.fetch": `self.fetch(u);`,
    "window.fetch": `window.fetch(u);`,
    "WebSocket": `new WebSocket("wss://x");`,
    "WebSocket with comment prefix": `/**/ new WebSocket("wss://x");`,
    "XMLHttpRequest": `new XMLHttpRequest();`,
    "EventSource": `new EventSource("https://x");`,
    "navigator.sendBeacon": `navigator.sendBeacon(u, d);`,
    "Deno": `Deno.connect({ port: 1 });`,
    "Bun": `Bun.connect({});`,
  };
  for (const [label, source] of Object.entries(globals)) assert.ok(networkCapabilityViolations(source).length > 0 || indirectAccessViolations(source).length > 0, `global client NOT detected: ${label}`);
  // comment/trivia tricks cannot HIDE a call from the syntax tree (the previous plain-text belt was blind to these)
  for (const hidden of [`/**/ await fetch(u);`, `/**/ import net from "node:net";`, `/* a */ /* b */ new WebSocket(u);`, `// x\n/**/ fetch(u);`])
    assert.ok(networkCapabilityViolations(hidden).length > 0, hidden);
  // a mention inside a comment or an unrelated string is NOT a call (no false positive)
  assert.deepEqual(networkCapabilityViolations(`// fetch(u) is never used\n/* import net from "node:net" */\nconst note = "no fetch here";`), []);
});

test("finding 2: the real R06 tooling has NO network capability and exactly the three reviewed child-process uses, structurally", async () => {
  const using: string[] = [];
  for (const file of TOOLING) {
    const source = await read(file);
    assert.deepEqual(networkCapabilityViolations(source, file), [], file);
    assert.deepEqual(childProcessViolations(source, PINNED_CHILD_PROCESS[file] ?? null, file), [], file);
    if (collectModuleReferences(source, file).some((reference) => reference.specifier !== null && /child_process/u.test(reference.specifier))) using.push(file);
  }
  assert.deepEqual(using.sort(), Object.keys(PINNED_CHILD_PROCESS).sort(), "the child-process users are exactly the pinned table");
});

// ---------------------------------------------------------------------------------------------------------------------------------
// Fifth-audit remediation (importer closure): accepted specifier grammar, parser-language agreement, alias surface, exact identity
// ---------------------------------------------------------------------------------------------------------------------------------
//
// The fourth audit loaded a protected module through spellings the earlier denylist never attributed to it (A1 NTFS stream, A2 8.3 short
// name, A3 JSX text hiding an import from a TypeScript-mode parse, A4 package.json "imports" / tsconfig "paths" aliases). The controls below
// are SAFE LOCAL reproductions: temporary directories, the repository's own tsx, no provider, no network, no credential.

const tsxCli = join(root, "node_modules", "tsx", "dist", "cli.mjs");
const STUB_KEY_MODULE = 'export const SECRET = "loaded-ok";\n';
const ALL_EXTENSIONS = ["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"] as const;
/** A reference is DETECTED when the repository scan would fail on it (unprovable) or the protected-module check refuses it. */
const detected = (importer: string, source: string): boolean => {
  const references = collectModuleReferences(source, importer);
  const unprovable = (() => { try { assertNoUnreviewedUnprovableReferences(new Map([[importer, references]]), {}); return false; } catch { return true; } })();
  return unprovable || protectedReferenceViolations(importer, references, REPOSITORY_FILES, PROTECTED_FILES).length > 0;
};
const loaderImport = (specifier: string) => `import { ${KEY_LOADER} } from ${JSON.stringify(specifier)};`;

/** Every spelling the audit used or a Windows loader could plausibly canonicalize to the protected file, each of which must be DETECTED. */
const HOSTILE_SPELLINGS: Record<string, string> = {
  "A1 NTFS alternate data stream": "../operator/staging-attestation-key.ts::$DATA",
  "ADS, lower-case stream name": "../operator/staging-attestation-key.ts::$data",
  "ADS, named stream": "../operator/staging-attestation-key.ts:stream",
  "ADS without extension": "../operator/staging-attestation-key::$DATA",
  "A2 8.3 short name": "../operator/STAGIN~1.TS",
  "8.3 short name, lower-case": "../operator/stagin~1.ts",
  "8.3 short name without extension": "../operator/STAGIN~1",
  "8.3 short directory": "../OPERAT~1/staging-attestation-key",
  "8.3 short directory, lower-case": "../operat~1/staging-attestation-key.ts",
  "dollar sign": "../operator/staging-attestation-key$",
  "trailing dot (Windows strips it)": "../operator/staging-attestation-key.ts.",
  "several trailing dots": "../operator/staging-attestation-key...",
  "trailing dot on the directory": "../operator./staging-attestation-key",
  "empty segment": "..//operator/staging-attestation-key",
  "trailing slash": "../operator/staging-attestation-key.ts/",
  "directory-dot final segment": "../operator/staging-attestation-key.ts/.",
  "directory-dotdot final segment": "../operator/staging-attestation-key.ts/..",
  "alternate case": "../operator/Staging-Attestation-Key",
  "alternate case with extension": "../operator/STAGING-ATTESTATION-KEY.TS",
  "alternate-case directory": "../Operator/staging-attestation-key",
  "query": "../operator/staging-attestation-key.ts?x=1",
  "fragment": "../operator/staging-attestation-key.ts#x",
  // sixth pass: the fragment is a path character to the CommonJS loader, so `x#/..` cancels out and the protected module loads (see the real-tsx test below)
  "sixth pass: fragment-directory traversal (loads under CJS tsx)": "../x#/../operator/staging-attestation-key.ts",
  "sixth pass: fragment-directory traversal, extensionless": "../x#/../operator/staging-attestation-key",
  "sixth pass: fragment-directory traversal with fragment text": "../x#a/../operator/staging-attestation-key",
  "sixth pass: fragment on a real directory": "../operator#/../operator/staging-attestation-key.ts",
  "sixth pass: query-directory traversal": "../x?/../operator/staging-attestation-key.ts",
  "sixth pass: query-directory traversal, extensionless": "../x?/../operator/staging-attestation-key",
  "sixth pass: traversal hidden in the query": "../operator/staging-attestation-key.ts?/../../x",
  "sixth pass: fragment on an unrelated name leading to another directory": "./a#/../../operator/staging-attestation-key.ts",
  "sixth pass: bare fragment path": "./#/../operator/staging-attestation-key.ts",
  "query after an alternate-case name": "../operator/Staging-Attestation-Key?x",
  "percent-encoded hyphen": "../operator/staging%2Dattestation-key",
  "percent-encoded slash": "..%2Foperator/staging-attestation-key",
  "backslash": "..\\operator\\staging-attestation-key",
  "mixed separators": "../operator\\staging-attestation-key",
  "non-ASCII look-alike hyphen": "../operator/staging\u2010attestation-key",
  "full-width letters": "../operator/\uff53taging-attestation-key",
  "an absolute path": "/repo/operator/staging-attestation-key.ts",
  "a drive-letter path": "C:/repo/operator/staging-attestation-key.ts",
  "a file: URL": "file:///C:/repo/operator/staging-attestation-key.ts",
  "a data: URL": "data:text/javascript;base64,ZXhwb3J0IHt9",
  "traversal out of the repository": "../../../outside/staging-attestation-key.ts",
  "the same name in another directory": "../scripts/staging-attestation-key",
  "a bare package of that name": "staging-attestation-key",
  "package.json imports alias": "#k",
  "package.json imports alias spelled with the name": "#internal/staging-attestation-key",
  "tsconfig alias without a slash": "@k",
  "empty": "",
};

const FORMS = (specifier: string): Record<string, string> => {
  const q = JSON.stringify(specifier);
  return {
    "named import": loaderImport(specifier), "namespace import": `import * as k from ${q};`, "default import": `import k from ${q};`, "side-effect import": `import ${q};`,
    "type import": `import type { T } from ${q};`, "re-export": `export { ${KEY_LOADER} } from ${q};`, "star re-export": `export * from ${q};`,
    "dynamic import": `const k = await import(${q});`, "require": `const k = require(${q});`, "import-equals": `import k = require(${q});`,
    "module.require": `const k = module.require(${q});`, "import.meta.resolve": `const where = import.meta.resolve(${q});`,
  };
};

test("fifth audit: the accepted specifier grammar admits the reviewed forms and nothing else (the denylist is gone)", () => {
  for (const ok of ["node:fs/promises", "node:test", "cloudflare:workers", "./a", "../operator/staging-attestation-key.ts", "../operator/./x", "@/lib/authority-result-trust",
    "next/server", "@playwright/test", "drizzle-orm/pg-core", "zod", ".", ".."]) assert.equal(isAcceptedSpecifier(ok), true, ok);
  for (const bad of ["node:", "node:Fs", "node:fs:x", "cloudflare:", "cloudflare:Workers", "cloudflare:a/b", "Next/server", "@scope", "@Scope/x", "a:b", "x::$DATA", "x~1", "x$", "x%2e", "x\\y", "a b", "a\u00e9",
    "../a//b", "../a/", "./a/.", "./a/..", "../a.", "a.", "@/", "@/../x", "@/a/./b", "#k", "#", "@k", "/abs", "C:/x", "file:///x", "data:text/javascript,1", "../a?b c", "../a?%41", "",
    // sixth-pass: `?` and `#` are refused anywhere, in any position, with any content around them
    "../x.ts?bust=1", "../x.ts#frag", "../x?", "../x#", "../x#/../operator/staging-attestation-key.ts", "../x#/../operator/staging-attestation-key", "../x?/../operator/staging-attestation-key.ts",
    "../x#a/../y", "./a#/../../b", "node:fs?x", "node:fs#x", "next/server?x", "@/lib/a#b", "@playwright/test#x", "./?", "./#"])
    assert.equal(isAcceptedSpecifier(bad), false, JSON.stringify(bad));
  assert.equal(classifySpecifierPath("node:fs"), "node-builtin");
  assert.equal(classifySpecifierPath("cloudflare:workers"), "worker-builtin");
  assert.equal(classifySpecifierPath("../x"), "relative");
  assert.equal(classifySpecifierPath("@/lib/x"), "alias");
  assert.equal(classifySpecifierPath("@playwright/test"), "package");
  assert.equal(classifySpecifierPath("next/server"), "package");
  // an unaccepted literal is an UNPROVABLE reference (specifier null), exactly like a computed one: the repository scan fails closed on it
  for (const bad of ["../operator/staging-attestation-key.ts::$DATA", "../operator/STAGIN~1.TS", "#k", "@k", "../a.", "file:///x"])
    assert.deepEqual(collectModuleReferences(`import { x } from ${JSON.stringify(bad)};`, "scripts/importer.ts").map((reference) => reference.specifier), [null], bad);
});

test("fifth audit A1/A2/A4 negative controls: every hostile spelling x every reference form x every importer extension is DETECTED", () => {
  assert.equal(detected("scripts/importer.ts", loaderImport("../operator/staging-attestation-key")), false, "control: the plain spelling is not a violation (the detector is not simply rejecting everything)");
  let cases = 0;
  for (const [label, specifier] of Object.entries(HOSTILE_SPELLINGS)) {
    for (const [form, source] of Object.entries(FORMS(specifier))) for (const extension of ALL_EXTENSIONS) {
      assert.ok(detected(`scripts/importer.${extension}`, source), `NOT detected: ${label} / ${form} / .${extension}`);
      cases += 1;
    }
  }
  assert.ok(cases >= Object.keys(HOSTILE_SPELLINGS).length * 12 * 8);
  assert.ok(Object.keys(HOSTILE_SPELLINGS).length >= 40, "the control list is not silently shrunk");
});

test("fifth audit: exact-file identity does not depend on name attribution -- a reference that resolves to a protected file under another name is itself a violation", () => {
  const table = { alpha: "operator/beta.ts" } as const;
  const files = new Set(["operator/beta.ts", "scripts/importer.ts"]);
  const violations = protectedReferenceViolations("scripts/importer.ts", collectModuleReferences('import { x } from "../operator/beta";', "scripts/importer.ts"), files, table);
  assert.equal(violations.length, 1);
  assert.match(violations[0], /resolves to protected file operator\/beta\.ts under a name that is not its own/u);
  assert.deepEqual(protectedReferenceViolations("scripts/importer.ts", collectModuleReferences('import { x } from "../operator/other";', "scripts/importer.ts"), new Set([...files, "operator/other.ts"]), table), []);
  // short-name / stream / alternate-case spellings never resolve case-exactly to anything
  for (const spelling of ["../operator/STAGIN~1.TS", "../operator/staging-attestation-key.ts::$DATA", "../operator/Staging-Attestation-Key", "../Operator/staging-attestation-key.ts"])
    assert.equal(resolveRepositorySpecifier("scripts/importer.ts", spelling, REPOSITORY_FILES), null, spelling);
  // traversal out of the repository is reported for ANY importer, protected name or not
  assert.equal(escapingReferenceViolations("scripts/a.ts", collectModuleReferences('import { x } from "../../../outside/anything";', "scripts/a.ts")).length, 1);
  assert.deepEqual(escapingReferenceViolations("scripts/a.ts", collectModuleReferences('import { x } from "../src/lib/ok";', "scripts/a.ts")), []);
});

test("fifth audit A3: the parser matches the language each extension really runs in; a syntax failure is a scanner failure, never zero references", async () => {
  assert.equal(scriptKindFor("a.ts"), ts.ScriptKind.TS);
  assert.equal(scriptKindFor("a.mts"), ts.ScriptKind.TS);
  assert.equal(scriptKindFor("a.cts"), ts.ScriptKind.TS);
  assert.equal(scriptKindFor("a.tsx"), ts.ScriptKind.TSX);
  assert.equal(scriptKindFor("a.jsx"), ts.ScriptKind.JSX);
  assert.equal(scriptKindFor("a.JSX"), ts.ScriptKind.JSX);
  // .js/.mjs/.cjs cannot contain JSX at run time (measured: "The JSX syntax extension is not currently enabled"), so they are not parsed as JSX
  for (const extension of ["js", "mjs", "cjs", "JS", "MJS"]) assert.equal(scriptKindFor(`a.${extension}`), ts.ScriptKind.TS, extension);
  // the exact audit control: JSX text containing a quote and a backtick, followed by a protected import
  const hostile = "/** @jsx h */\nconst h = () => null;\nconst x = <p>it's a 'quote and `tick</p>;\n" + loaderImport("../operator/staging-attestation-key") + "\nconsole.log(x);\n";
  for (const extension of ["jsx", "tsx"] as const) {
    const importer = `scripts/hostile.${extension}`;
    const references = collectModuleReferences(hostile, importer);
    assert.deepEqual(references.map((reference) => reference.specifier), ["../operator/staging-attestation-key"], `${extension}: the hidden import is FOUND`);
    assert.deepEqual(filesImporting(new Map([[importer, references]]), "staging-attestation-key", KEY_LOADER), [importer], extension);
  }
  // in a language where the same text is NOT valid syntax (it cannot run there either) the scan cannot yield "zero references": it throws
  for (const extension of ["ts", "mts", "cts", "js", "mjs", "cjs"]) assert.throws(() => collectModuleReferences(hostile, `scripts/hostile.${extension}`), ScannerSyntaxError, extension);
  // every analyzer entry point fails closed, not just the collector
  for (const analyzer of [dynamicCodeViolations, indirectAccessViolations, networkCapabilityViolations, forbiddenNodeModuleViolations, computedAccessSites])
    assert.throws(() => analyzer("const = ;", "scripts/broken.ts"), ScannerSyntaxError);
  assert.throws(() => childProcessViolations("import {", null, "scripts/broken.ts"), ScannerSyntaxError);
  assert.throws(() => moduleReferenceViolations("export {", {}, "scripts/broken.ts"), ScannerSyntaxError);
  // and so does the repository scan, naming the file
  const parent = await mkdtemp(join(tmpdir(), "r06-parse-"));
  try {
    await mkdir(join(parent, "scripts"), { recursive: true });
    await writeFile(join(parent, "scripts", "ok.ts"), "export const a = 1;\n");
    await writeFile(join(parent, "scripts", "hostile.jsx"), hostile);
    const found = await scanRepository(parent);
    assert.deepEqual(filesImporting(found, "staging-attestation-key", KEY_LOADER), ["scripts/hostile.jsx"], "the scan attributes the importer hidden behind JSX text");
    await writeFile(join(parent, "scripts", "broken.mjs"), 'const s = `never closed\nimport { a } from "./ok";\n');
    await assert.rejects(scanRepository(parent), /scanner cannot parse scripts\/broken\.mjs/u);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test("fifth audit: the repository alias surface is pinned -- no package.json imports/exports, tsconfig paths exactly @/*, no other alias-capable file", async () => {
  assert.deepEqual(aliasSurfaceViolations(await read("package.json"), await read("tsconfig.json")), []);
  assert.deepEqual(await aliasConfigFiles(root), ["package.json", "tsconfig.json"], "a nested package.json / tsconfig / jsconfig could define aliases for a subtree");
  const pkg = JSON.stringify({ name: "x", scripts: {} });
  const config = (extra: Record<string, unknown> = {}, paths: unknown = { "@/*": ["./src/*"] }) => JSON.stringify({ compilerOptions: { paths, ...extra } });
  assert.deepEqual(aliasSurfaceViolations(pkg, config()), [], "control: the reviewed shape is clean");
  assert.deepEqual(aliasSurfaceViolations(pkg, '{ /* comments are fine */ "compilerOptions": { "paths": { "@/*": ["./src/*"] } } }'), []);
  const bad: Record<string, [string, string]> = {
    "package.json imports (the #k alias)": [JSON.stringify({ imports: { "#k": "./operator/staging-attestation-key.ts" } }), config()],
    "package.json exports (self-reference)": [JSON.stringify({ exports: { "./k": "./operator/staging-attestation-key.ts" } }), config()],
    "an extra tsconfig path": [pkg, config({}, { "@/*": ["./src/*"], "@k": ["./operator/staging-attestation-key.ts"] })],
    "a replaced tsconfig path": [pkg, config({}, { "@/*": ["./operator/*"] })],
    "an additional target": [pkg, config({}, { "@/*": ["./src/*", "./operator/*"] })],
    "no paths at all": [pkg, JSON.stringify({ compilerOptions: {} })],
    "baseUrl (bare repository-relative specifiers)": [pkg, config({ baseUrl: "." })],
    "rootDirs": [pkg, config({ rootDirs: ["src", "operator"] })],
    "extends": [pkg, JSON.stringify({ extends: "./other.json", compilerOptions: { paths: { "@/*": ["./src/*"] } } })],
    "unparsable tsconfig": [pkg, "{ not json"],
    "unparsable package.json": ["{", config()],
  };
  for (const [label, [packageJson, tsconfig]] of Object.entries(bad)) assert.ok(aliasSurfaceViolations(packageJson, tsconfig).length > 0, `alias surface change NOT detected: ${label}`);
  // and an alias specifier can never silently become protected-module access: it is unprovable (#k, @k) or an undeclared package (@k/x, k)
  const references: RepositoryReferences = new Map([["scripts/importer.ts", collectModuleReferences('import "@k/x"; import "k"; import "operator/staging-attestation-key"; import "next/server";', "scripts/importer.ts")]]);
  const violations = unknownPackageViolations(references, new Set(["next"]), new Set(), new Set());
  assert.equal(violations.length, 3, violations.join(" | "));
  assert.deepEqual(unknownPackageViolations(references, new Set(["next", "@k/x", "k", "operator"]), new Set(), new Set()), [], "control: declared packages pass");
});

test("fifth audit: every package specifier in the repository is a declared dependency, a Node built-in, or a reviewed exception; none leaves the repository", async () => {
  const manifest = JSON.parse(await read("package.json")) as Record<string, Record<string, string> | undefined>;
  const declared = new Set(["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"].flatMap((field) => Object.keys(manifest[field] ?? {})));
  // k6 load scripts (lab/load) import the k6 runtime's own modules (k6/http, k6/metrics); k6 is a separate binary, not an npm dependency
  // miniflare is a transitive dependency of the declared wrangler; the local-workerd rigs under tests/workers import it directly
  const reviewed = new Set(["k6", "miniflare"]);
  const references = await repository();
  assert.deepEqual(unknownPackageViolations(references, declared, new Set(builtinModules), reviewed), []);
  const escaping: string[] = [];
  for (const [file, list] of references) escaping.push(...escapingReferenceViolations(file, list));
  assert.deepEqual(escaping, []);
});

test("fifth audit A1/A2/A3/A4: SAFE LOCAL PREMISE -- the repository's own tsx really loads these spellings; the guard flags every one that loads", async () => {
  const parent = await mkdtemp(join(tmpdir(), "r06-premise-"));
  try {
    for (const directory of ["operator", "scripts"]) await mkdir(join(parent, directory), { recursive: true });
    await writeFile(join(parent, "operator", "staging-attestation-key.ts"), STUB_KEY_MODULE);
    const load = async (name: string, source: string): Promise<boolean> => {
      await writeFile(join(parent, "scripts", name), source);
      const result = spawnSync(process.execPath, [tsxCli, join("scripts", name)], { cwd: parent, encoding: "utf8", timeout: 60_000 });
      return result.status === 0 && result.stdout.includes("RESULT loaded-ok");
    };
    const importer = (specifier: string) => `import { SECRET } from ${JSON.stringify(specifier)};\nconsole.log("RESULT", SECRET);\n`;
    assert.equal(await load("plain.ts", importer("../operator/staging-attestation-key")), true, "harness sanity: the plain spelling loads");
    const loaded: string[] = [];
    for (const [label, specifier] of Object.entries(HOSTILE_SPELLINGS)) {
      if (specifier === "") continue;
      if (await load("probe.ts", importer(specifier))) {
        loaded.push(label);
        assert.ok(detected("scripts/probe.ts", importer(specifier)), `LOADS but is NOT detected: ${label}`);
      }
    }
    // A3: the exact JSX shape loads (and runs) as .jsx and the guard finds it; as .js the loader itself rejects it and the guard fails closed
    {
      const extension = "jsx";
      const source = "/** @jsx h */\nconst h = () => null;\nconst x = <p>it's a 'quote and `tick</p>;\nimport { SECRET } from \"../operator/staging-attestation-key\";\nconsole.log(\"RESULT\", SECRET, x);\n";
      assert.equal(await load(`jsx-probe.${extension}`, source), true, `the hostile JSX file runs as .${extension}`);
      assert.deepEqual(collectModuleReferences(source, `scripts/jsx-probe.${extension}`).map((reference) => reference.specifier), ["../operator/staging-attestation-key"]);
      assert.equal(await load("jsx-probe.js", source), false, "premise: the same text does not run as .js");
      assert.throws(() => collectModuleReferences(source, "scripts/jsx-probe.js"), ScannerSyntaxError);
      assert.throws(() => collectModuleReferences(source, "scripts/jsx-probe.ts"), ScannerSyntaxError);
      await rm(join(parent, "scripts", "jsx-probe.js")); // deliberately unparsable here; the tree is scanned again below
    }
    // A4: package.json "imports" and tsconfig "paths" really do alias the protected module (in an isolated tree) and are exactly what the alias pins refuse
    await writeFile(join(parent, "package.json"), JSON.stringify({ imports: { "#k": "./operator/staging-attestation-key.ts" } }));
    const viaImports = await load("alias-imports.ts", importer("#k"));
    await rm(join(parent, "package.json"));
    await writeFile(join(parent, "tsconfig.json"), JSON.stringify({ compilerOptions: { paths: { "@k": ["./operator/staging-attestation-key.ts"] } } }));
    const viaPaths = await load("alias-paths.ts", importer("@k"));
    await rm(join(parent, "tsconfig.json"));
    assert.equal(viaImports && viaPaths, true, "premise: both alias mechanisms load the protected module under a non-attributed name");
    assert.ok(detected("scripts/alias-imports.ts", importer("#k")) && detected("scripts/alias-paths.ts", importer("@k")), "the specifier itself is unprovable");
    assert.ok(aliasSurfaceViolations(JSON.stringify({ imports: { "#k": "./x.ts" } }), JSON.stringify({ compilerOptions: { paths: { "@/*": ["./src/*"] } } })).length > 0);
    assert.ok(aliasSurfaceViolations("{}", JSON.stringify({ compilerOptions: { paths: { "@k": ["./x.ts"] } } })).length > 0);
    // a declaration file executes when imported: it must be scanned (a hidden importer would otherwise be invisible)
    await writeFile(join(parent, "operator", "hidden.d.ts"), 'import { SECRET } from "./staging-attestation-key";\nconsole.log("RESULT", SECRET);\nexport {};\n');
    await writeFile(join(parent, "scripts", "load-dts.ts"), 'import "../operator/hidden.d";\n');
    const dts = spawnSync(process.execPath, [tsxCli, join("scripts", "load-dts.ts")], { cwd: parent, encoding: "utf8", timeout: 60_000 });
    assert.equal(dts.stdout.includes("RESULT loaded-ok"), true, "premise: a .d.ts file executes");
    assert.deepEqual(filesImporting(await scanRepository(parent), "staging-attestation-key", "SECRET").filter((file) => file.endsWith(".d.ts")), ["operator/hidden.d.ts"], "the scan sees the importer inside the .d.ts");
    process.stderr.write(`[fifth audit premise] spellings that loaded on this host: ${loaded.join("; ") || "(none)"}\n`);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

// ---------------------------------------------------------------------------------------------------------------------------------
// Sixth pass (fifth audit's blocking finding): `?` and `#` are never interpreted -- a literal containing either is UNPROVABLE
// ---------------------------------------------------------------------------------------------------------------------------------
//
// The fifth audit loaded the protected module through `../x#/../operator/staging-attestation-key.ts`. The scanner then split the literal at the first `#`,
// attributed the reference to `x`, and reported nothing; the CommonJS loader tsx runs for this package (no `"type"`) treats `#` as an ordinary path
// character and normalizes `..` lexically, so the module loaded. The scanner now refuses the literal instead of interpreting it. Safe local reproduction:
// temporary directory, the repository's own tsx, a stub module, no provider, no network, no credential.

const FRAGMENT_TRAVERSAL_SPELLINGS: readonly string[] = [
  "../x#/../operator/staging-attestation-key.ts",
  "../x#/../operator/staging-attestation-key",
  "../x#a/../operator/staging-attestation-key",
  "../operator#/../operator/staging-attestation-key.ts",
];
/** The spellings the premise ASSERTS load (measured with this repository's tsx); the others are only required to be refused. */
const FRAGMENT_TRAVERSAL_PRIMARY = FRAGMENT_TRAVERSAL_SPELLINGS.slice(0, 2);

/** Importer sources per extension. `import()` is ESM resolution (a `#` starts a fragment there, so it does not load -- measured), but it is still a reference
 * that must be refused: it names a guarded module under a spelling the scanner cannot prove. */
const FRAGMENT_FORMS: Readonly<Record<"ts" | "js" | "cjs", Readonly<Record<string, (specifier: string) => string>>>> = (() => {
  const q = JSON.stringify;
  const staticForms = {
    "named import": (s: string) => `import { SECRET } from ${q(s)};\nconsole.log("RESULT", SECRET);\n`,
    "side-effect import": (s: string) => `import ${q(s)};\nconsole.log("RESULT loaded-ok");\n`,
    "commonjs require": (s: string) => `const { SECRET } = require(${q(s)});\nconsole.log("RESULT", SECRET);\n`,
    "dynamic import": (s: string) => `import(${q(s)}).then((m) => console.log("RESULT", m.SECRET), () => undefined);\n`,
  };
  return { ts: staticForms, js: staticForms, cjs: { "commonjs require": staticForms["commonjs require"], "dynamic import": staticForms["dynamic import"] } };
})();
const MUST_LOAD_FORMS: ReadonlySet<string> = new Set(["named import", "side-effect import", "commonjs require"]);

test("sixth pass: SAFE LOCAL PREMISE -- `x#/..` really loads the protected module under the repository's CJS tsx for .ts/.js/.cjs importers, and the scanner refuses every spelling and form", async () => {
  // the premise is only meaningful because this repository's package is CommonJS (no `"type"`), which is also what the temporary tree below is
  assert.equal(((JSON.parse(await read("package.json")) as { type?: unknown }).type), undefined, "package.json declares no module type");
  const parent = await mkdtemp(join(tmpdir(), "r06-fragment-"));
  try {
    for (const directory of ["operator", "scripts"]) await mkdir(join(parent, directory), { recursive: true });
    await writeFile(join(parent, "package.json"), JSON.stringify({ private: true }));
    await writeFile(join(parent, "operator", "staging-attestation-key.ts"), STUB_KEY_MODULE);
    const load = (name: string): boolean => {
      const result = spawnSync(process.execPath, [tsxCli, join("scripts", name)], { cwd: parent, encoding: "utf8", timeout: 60_000 });
      return result.status === 0 && result.stdout.includes("RESULT loaded-ok");
    };
    // harness sanity: the plain spelling loads, in every extension, and the scanner does NOT flag it (the detector is not simply rejecting everything)
    for (const extension of ["ts", "js", "cjs"] as const) {
      const source = FRAGMENT_FORMS[extension]["commonjs require"]("../operator/staging-attestation-key");
      await writeFile(join(parent, "scripts", `plain.${extension}`), source);
      assert.equal(load(`plain.${extension}`), true, `harness sanity: the plain spelling loads as .${extension}`);
      assert.equal(detected(`scripts/plain.${extension}`, source), false, `the plain spelling is not a violation (.${extension})`);
    }
    for (const extension of ["ts", "js", "cjs"] as const) await rm(join(parent, "scripts", `plain.${extension}`));
    const written: string[] = [];
    const loaded: string[] = [];
    let counter = 0;
    for (const specifier of FRAGMENT_TRAVERSAL_SPELLINGS) for (const extension of ["ts", "js", "cjs"] as const) for (const [form, build] of Object.entries(FRAGMENT_FORMS[extension])) {
      const name = `fragment-${counter++}.${extension}`;
      const source = build(specifier);
      await writeFile(join(parent, "scripts", name), source);
      written.push(`scripts/${name}`);
      const label = `${JSON.stringify(specifier)} / ${form} / .${extension}`;
      const loads = load(name);
      if (loads) loaded.push(label);
      if (FRAGMENT_TRAVERSAL_PRIMARY.includes(specifier) && MUST_LOAD_FORMS.has(form)) assert.equal(loads, true, `premise: the protected module loads through ${label}`);
      // the refusal does not depend on whether this particular combination loads: the literal itself is unprovable, never attributed to `x`
      assert.deepEqual(collectModuleReferences(source, `scripts/${name}`).map((reference) => reference.specifier), [null], `NOT refused: ${label}`);
      assert.ok(detected(`scripts/${name}`, source), `NOT detected: ${label}`);
    }
    assert.ok(loaded.length >= 2 * (3 + 3 + 1), `the premise loaded the protected module through the expected forms (.ts/.js static+require, .cjs require): ${loaded.length}`);
    // and the repository scan over this tree FAILS CLOSED, naming every one of those importers
    const references = await scanRepository(parent);
    let message = "";
    try { assertNoUnreviewedUnprovableReferences(references, {}); } catch (error) { message = (error as Error).message; }
    assert.match(message, /cannot prove these module references/u);
    for (const file of written) assert.ok(message.includes(`${file}:1 `), `the scan does not name ${file}`);
    assert.deepEqual(unprovableReferences(references).length, written.length);
    process.stderr.write(`[sixth pass premise] ${loaded.length} fragment-traversal combinations loaded on this host; all ${written.length} are refused\n`);
  } finally { await rm(parent, { recursive: true, force: true }); }
});
