// Gate 8 Phase 0: test-only fault machinery can never reach a deployed or
// operator path, and the new Phase 0 tests are isolated from real provider,
// key, credential and Wrangler access. Static and validator-level only; this
// file reads repository sources and never spawns anything but `git grep`.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { validateStagingLifecycleMailboxConfig, validateStagingLifecycleObserverConfig } from "../deployment/lifecycle-private-contract";
import { STAGING_ADMISSION_SERVICE_NAME, STAGING_EXECUTOR_MAIN, STAGING_EXECUTOR_NAME,
  validateRenderedStagingOperatorExecutorConfig } from "../deployment/operator-executor-contract";

const root = process.cwd();
const runtimeTrees = ["workers", "operator", "scripts", "deployment", "src"];
const faultTokens = /FAIL_BEFORE|DROP_ACK|CountingExecutor|CountingAdmission|OperatorAckLossProxy|tests\/workers\/support|LocalFaultHooks|afterClaimSync|beforeExecutorCall|localFaults/u;

function gitGrep(pattern: string): Array<{ file: string; line: string }> {
  const result = spawnSync("git", ["grep", "-nE", pattern, "--", ...runtimeTrees], { cwd: root, encoding: "utf8" });
  assert.ok(result.status === 0 || result.status === 1, result.stderr);
  return result.stdout.split("\n").filter(Boolean).map((entry) => {
    const [file, , ...rest] = entry.split(":");
    return { file, line: rest.join(":").trim() };
  });
}

test("runtime/operator trees reference test-only fault machinery only in reviewed, justified places", () => {
  const hits = gitGrep(faultTokens.source);
  const guardFiles = new Set(["workers/lifecycle-mailbox/dispatch-guard.ts", "workers/lifecycle-mailbox/staging-dispatch-guard.ts"]);
  // Reviewed, justified, non-reachable references:
  //  - the two guards' constructor-only LocalFaultHooks parameter (private field,
  //    default {}); workerd constructs Durable Objects with (state, env) only;
  //  - a comment in scripts/gate6-secure-input.ts naming a test harness.
  const guardShapes = [
    /^type LocalFaultHooks = \{ afterClaimSync\?\(\): Promise<void>; beforeExecutorCall\?\(\): Promise<void> \};$/u,
    /^readonly #localFaults: LocalFaultHooks;$/u,
    /^constructor\(state: DurableObjectState, env: \w+, localFaults: LocalFaultHooks = \{\}\) \{$/u,
    /^this\.#localFaults = localFaults;$/u,
    /^try \{ await this\.#localFaults\.afterClaimSync\?\.\(\); \}$/u,
    /^await this\.#localFaults\.beforeExecutorCall\?\.\(\);$/u,
  ];
  for (const { file, line } of hits) {
    if (guardFiles.has(file)) assert.ok(guardShapes.some((shape) => shape.test(line)), `unreviewed fault reference in ${file}: ${line}`);
    else if (file === "scripts/gate6-secure-input.ts") assert.ok(line.startsWith("//"), `non-comment reference in ${file}`);
    else assert.fail(`test-only fault machinery referenced from ${file}: ${line}`);
  }
  assert.ok(hits.some((hit) => hit.file === "workers/lifecycle-mailbox/staging-dispatch-guard.ts"), "scan actually covered the staging guard");
});

test("no runtime or operator code constructs a guard with a third (fault-hook) argument", () => {
  assert.deepEqual(gitGrep("new (Staging)?LifecycleDispatchGuard\\("), []);
});

test("fault hooks are private constructor state, never public methods (no RPC surface)", async () => {
  for (const file of ["workers/lifecycle-mailbox/dispatch-guard.ts", "workers/lifecycle-mailbox/staging-dispatch-guard.ts"]) {
    const source = await readFile(join(root, file), "utf8");
    assert.equal(/^\s*(?:public\s+|async\s+)?(afterClaimSync|beforeExecutorCall|localFaults)\s*\(/mu.test(source), false, file);
    assert.equal(/\bthis\.localFaults\b|\breadonly localFaults\b/u.test(source), false, `${file}: hooks must stay #private`);
  }
  const stagingIndex = await readFile(join(root, "workers/lifecycle-mailbox/staging-index.ts"), "utf8");
  assert.deepEqual(stagingIndex.match(/^export .*$/gmu), ["export default stagingLifecycleMailbox;",
    'export { StagingLifecycleDispatchGuard } from "./staging-dispatch-guard";']);
});

async function syntheticKey(): Promise<string> {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  return encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
}

test("staging lifecycle validators refuse a counting/proxy executor or reader wiring", async () => {
  const key = await syntheticKey();
  const account = "1".repeat(32);
  const mailbox = JSON.parse(await readFile(join(root, "deployment/lifecycle-mailbox.staging.template.jsonc"), "utf8")) as Record<string, unknown>;
  Object.assign(mailbox, { main: "../workers/lifecycle-mailbox/staging-index.ts", account_id: account,
    vars: { AUTHORITY_OPERATOR_PUBLIC_KEY: key, LIFECYCLE_ENVIRONMENT: "staging" } });
  validateStagingLifecycleMailboxConfig(mailbox, false, "STAGING_DEPLOYMENT_INACTIVE");
  const services = mailbox.services as Array<Record<string, string>>;
  for (const replacement of [
    { ...services[0], entrypoint: "CountingExecutor" },
    { ...services[0], service: "proxy", entrypoint: "CountingExecutor" },
    { ...services[0], entrypoint: "OperatorAckLossProxy" },
  ]) assert.throws(() => validateStagingLifecycleMailboxConfig({ ...mailbox, services: [replacement, services[1]] }, false), /unsafe-lifecycle-services/u);
  assert.throws(() => validateStagingLifecycleMailboxConfig({ ...mailbox, services: [services[0], { ...services[1], entrypoint: "CountingAdmission" }] }, false),
    /unsafe-lifecycle-services/u);
  assert.throws(() => validateStagingLifecycleMailboxConfig({ ...mailbox, services: [...services,
    { binding: "COUNTING_EXECUTOR", service: "proxy", entrypoint: "CountingExecutor" }] }, false), /unsafe-lifecycle-services/u);

  const observer = JSON.parse(await readFile(join(root, "deployment/lifecycle-observer.staging.template.jsonc"), "utf8")) as Record<string, unknown>;
  Object.assign(observer, { main: "../workers/staging-lifecycle-observer.ts", account_id: account });
  validateStagingLifecycleObserverConfig(observer, false, "STAGING_DEPLOYMENT_INACTIVE");
  const reader = (observer.services as Array<Record<string, string>>)[0];
  assert.throws(() => validateStagingLifecycleObserverConfig({ ...observer, services: [{ ...reader, entrypoint: "CountingAdmission" }] }, false),
    /unsafe-lifecycle-services/u);

  const executor = JSON.parse(await readFile(join(root, "deployment/operator-lifecycle-executor.staging.template.jsonc"), "utf8")) as Record<string, unknown>;
  Object.assign(executor, { name: STAGING_EXECUTOR_NAME, main: STAGING_EXECUTOR_MAIN, account_id: account,
    services: [{ binding: "ADMISSION_SERVICE", service: STAGING_ADMISSION_SERVICE_NAME, entrypoint: "StagingAuthorityLifecycleOnly" }],
    vars: { AUTHORITY_OPERATOR_PUBLIC_KEY: key, OPERATOR_EXECUTOR_ENVIRONMENT: "staging" } });
  validateRenderedStagingOperatorExecutorConfig(executor);
  for (const service of [
    { binding: "ADMISSION_SERVICE", service: STAGING_ADMISSION_SERVICE_NAME, entrypoint: "CountingAdmission" },
    { binding: "ADMISSION_SERVICE", service: "admissionProxy", entrypoint: "CountingAdmission" },
    { binding: "ADMISSION_SERVICE", service: STAGING_ADMISSION_SERVICE_NAME, entrypoint: "OperatorAckLossProxy" },
  ]) assert.throws(() => validateRenderedStagingOperatorExecutorConfig({ ...executor, services: [service] }));
});

const phase0Tests = {
  integration: "tests/workers/staging-lifecycle-mailbox-faults.integration.ts",
  unit: "tests/i3b-staging-dispatch-faults.test.ts",
  lock: "tests/gate8-staging-initialization-lock.test.ts",
};
const forbiddenAccess = [/limitmark-keys/u, /USERPROFILE/u, /staging-operator-private-key/u, /lifecycle-transport\.staging\.json/u,
  /\.staging\.(armed\.)?jsonc/u, /AUTHORITY_STAGING_OPERATOR_PRIVATE_KEY\s*[:=]\s*process\.env/u, /from "wrangler"/u,
  /node_modules\/wrangler/u, /wrangler\.js/u, /\bremote\s*:/u, /startRemoteProxySession|getPlatformProxy|unstable_dev/u];

test("Phase 0 tests never touch real keys, credentials, rendered configs, Wrangler or remote bindings", async () => {
  for (const file of Object.values(phase0Tests)) {
    const source = await readFile(join(root, file), "utf8");
    for (const pattern of forbiddenAccess) assert.equal(pattern.test(source), false, `${file} matches ${pattern}`);
    assert.match(source, /crypto\.subtle\.generateKey\("Ed25519"/u, `${file} uses a per-run synthetic key`);
  }
});

test("the staging fault integration harness is local-only and isolated", async () => {
  const source = await readFile(join(root, phase0Tests.integration), "utf8");
  assert.equal(/child_process|spawn|execFile/u.test(source), false, "spawns no process (no real Wrangler)");
  assert.match(source, /for \(const name of Object\.keys\(process\.env\)\) if \(\/\^\(CLOUDFLARE_\|CF_\)\/iu\.test\(name\)\) delete process\.env\[name\];/u,
    "inherited CLOUDFLARE_* variables are scrubbed");
  assert.match(source, /process\.env\.WRANGLER_SEND_METRICS = "false";/u);
  assert.match(source, /options\.telemetry = \{ enabled: false \};/u);
  assert.match(source, /assert\.equal\(\/"remote"\/u\.test\(JSON\.stringify\(workers\)\), false/u, "runtime assertion: no remote binding");
  assert.match(source, /const testsRoot = resolve\(root, "\.wrangler", "tests"\);/u);
  assert.match(source, /startsWith\(testsRoot \+ sep\)/u, "runtime root asserted under .wrangler/tests");
  assert.match(source, /startsWith\(resolve\(runtimeRoot\) \+ sep\)/u, "every persistence path asserted under the runtime root");
  // Only real staging runtime entries plus the pre-existing test-only proxies are bundled.
  const entries = [...source.matchAll(/^\s+\w+: "((?:workers|tests)\/[^"]+\.ts)",$/gmu)].map((match) => match[1]).sort();
  assert.deepEqual(entries, ["tests/workers/support/i3b-counting-admission.ts", "tests/workers/support/i3b-counting-executor.ts",
    "tests/workers/support/i3b-driver.ts", "workers/admission-service/index.ts", "workers/lifecycle-mailbox/staging-index.ts",
    "workers/staging-lifecycle-observer.ts", "workers/staging-operator-lifecycle-executor.ts"]);
  assert.equal(/className: "(LifecycleDispatchGuard|ProductionAdmissionAuthority)"/u.test(source), false, "no Production class stands in for staging");
});

test("the lockout test runs CLIs only as node bundles in a temp sandbox with scrubbed provider variables", async () => {
  const source = await readFile(join(root, phase0Tests.lock), "utf8");
  assert.match(source, /spawnSync\(process\.execPath, \[cli, \.\.\.args\], \{ cwd: directory,/u, "children run node in the temp directory");
  assert.match(source, /mkdtemp\(join\(tmpdir\(\), "gate8-lock-"\)\)/u);
  assert.match(source, /!\/\^\(CLOUDFLARE_\|CF_\|WRANGLER_\|AUTHORITY_\|GATE8_\)\/iu\.test\(name\)/u, "inherited provider/operator variables are dropped");
  assert.equal(/spawnSync\("(npm|npx|tsx|wrangler)/u.test(source), false);
  for (const trap of ["staging-credential-io", "r2-transport"])
    assert.ok(source.includes(`/${trap}$/`), `${trap} is replaced by a synthetic trap`);
});
