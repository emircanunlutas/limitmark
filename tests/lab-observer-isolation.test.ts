import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { validateLabLifecycleObserverConfig, validateLifecycleObserverConfig, validateStagingLifecycleObserverConfig } from "../deployment/lifecycle-private-contract";
import { LAB_OBSERVER_CONFIG, LAB_OBSERVER_MAIN, observerEntrypointConfigs, validateLabObserverDeployment } from "../scripts/lab-observer-deploy";
import labLifecycleObserver, { observeLabReconciliation, labObserverEnvironmentValid, type LabObserverEnvironment } from "../workers/lab-lifecycle-observer";

// Lab observer isolation: (1) the Worker refuses to touch storage or the Authority unless the lab marker is exact; (2) no production/staging configuration or entry module exposes the
// lab read-only entrypoint; (3) the deployment wrapper validates the one reviewed configuration and any alternative configuration naming the lab observer is refused.
// The marker is declarative and the wrapper is bypassable by a manual `wrangler deploy`; the decisive boundary is the Authority's own authorization (see the last test).

const root = path.join(__dirname, "..");
const strip = (text: string): string => text.split("\n").filter((line) => !line.trim().startsWith("//")).join("\n");
const jsonc = (file: string): Record<string, unknown> => JSON.parse(strip(readFileSync(path.join(root, file), "utf8"))) as Record<string, unknown>;
const clone = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

type Calls = { get: number; head: number; put: number; reader: number };
function environment(marker: unknown, present = true): { env: LabObserverEnvironment; calls: Calls } {
  const calls: Calls = { get: 0, head: 0, put: 0, reader: 0 };
  const control = new TextEncoder().encode(JSON.stringify({ version: 1, digest: "a".repeat(64), nonce: "b".repeat(32) }));
  const env = {
    REQUEST_BUCKET: { async get() { calls.get++; return present ? { size: control.length, body: new Blob([control]).stream(), arrayBuffer: async () => control.buffer } : null; } },
    RESULT_BUCKET: { async head() { calls.head++; return null; }, async put(key: string) { calls.put++; return { key }; } },
    LIFECYCLE_READER: { async attestReconciliation() { calls.reader++; return { status: "UNAVAILABLE", reason: "test" }; } },
    ...(marker === undefined ? {} : { LIFECYCLE_OBSERVER_ENVIRONMENT: marker }),
  } as unknown as LabObserverEnvironment;
  return { env, calls };
}

test("a missing or invalid marker is refused before ANY bucket or Authority access (direct call and scheduled handler)", async () => {
  for (const marker of [undefined, null, "", "production", "staging", "LAB", "Lab", "lab ", " lab", "lab\n", true, 1, ["lab"], { toString: () => "lab" }]) {
    const { env, calls } = environment(marker);
    assert.equal(labObserverEnvironmentValid(env), false, String(marker));
    await assert.rejects(observeLabReconciliation(env), /invalid-observer-environment/u, String(marker));
    await labLifecycleObserver.scheduled({} as never, env); // swallows by design: still no access
    assert.deepEqual(calls, { get: 0, head: 0, put: 0, reader: 0 }, `marker ${String(marker)} reached storage or the Authority`);
  }
});

test("the exact marker \"lab\" is the only value that proceeds (and only as far as the existing read-only flow goes)", async () => {
  const { env, calls } = environment("lab");
  assert.equal(labObserverEnvironmentValid(env), true);
  await observeLabReconciliation(env);
  assert.equal(calls.get, 1, "the request bucket was read once");
  assert.equal(calls.reader, 1, "the read-only reconciliation was relayed once");
  assert.equal(calls.put, 1, "one unsigned diagnostic result was stored (the stub reader reports UNAVAILABLE)");
  const absent = environment("lab", false);
  await observeLabReconciliation(absent.env);
  assert.deepEqual(absent.calls, { get: 1, head: 0, put: 0, reader: 0 }, "no request, no further access");
});

test("the marker check precedes the first storage access in the source, and the observer gained no capability", () => {
  const text = readFileSync(path.join(root, LAB_OBSERVER_MAIN), "utf8").replace(/\/\*[\s\S]*?\*\//gu, "").replace(/\/\/.*$/gmu, "");
  assert.ok(text.indexOf("labObserverEnvironmentValid(env)") < text.indexOf("REQUEST_BUCKET.get"), "marker is checked first");
  assert.equal(text.match(/labObserverEnvironmentValid\(env\)/gu)?.length, 2, "checked in the exported function and in the scheduled handler");
  assert.equal(/LIFECYCLE_EXECUTOR|DISPATCH_GUARD|attestAppliedLifecycle|inspectLifecycle|AUTHORITY_OPERATOR|PRIVATE_KEY|\.delete\(/u.test(text), false, "still read-only and relay-only");
  assert.equal(text.match(/RESULT_BUCKET\.(?:put|head)/gu)?.length, 2 - 0, "the same two result-bucket operations as before");
});

test("the lab validator requires the marker var exactly; staging and production validators reject the lab configuration", () => {
  const template = jsonc("deployment/lifecycle-observer.lab.template.jsonc");
  validateLabLifecycleObserverConfig(template, true);
  assert.deepEqual(template.vars, { LIFECYCLE_OBSERVER_ENVIRONMENT: "lab" });
  const without = clone(template); delete without.vars;
  assert.throws(() => validateLabLifecycleObserverConfig(without, true));
  for (const bad of ["production", "staging", "", "LAB", true, null]) {
    const mutated = clone(template); mutated.vars = { LIFECYCLE_OBSERVER_ENVIRONMENT: bad };
    assert.throws(() => validateLabLifecycleObserverConfig(mutated, true), String(bad));
  }
  const extra = clone(template); extra.vars = { LIFECYCLE_OBSERVER_ENVIRONMENT: "lab", EXTRA: "x" };
  assert.throws(() => validateLabLifecycleObserverConfig(extra, true), "no additional vars");
  assert.throws(() => validateStagingLifecycleObserverConfig(template, true));
  assert.throws(() => validateLifecycleObserverConfig(template, true));
});

test("no production or staging configuration binds a lab entrypoint, and the production entry module exposes no lab class", () => {
  const nonLab = readdirSync(path.join(root, "deployment")).filter((name) => /\.jsonc?$/u.test(name) && !/\.lab\./u.test(name));
  assert.ok(nonLab.length > 8);
  for (const name of nonLab) {
    let config: { main?: unknown; services?: { entrypoint?: string; service?: string }[] };
    try { config = JSON.parse(strip(readFileSync(path.join(root, "deployment", name), "utf8"))); } catch { continue; } // not a Wrangler config (for example a synthetic fixture)
    const bound = [config.main, ...(config.services ?? []).flatMap((service) => [service.entrypoint, service.service])].filter((value): value is string => typeof value === "string");
    assert.equal(bound.some((value) => /Lab[A-Z]|lab-index|lab-lifecycle|-lab$/u.test(value)), false, `${name} binds a lab entrypoint, service or module`);
  }
  const entry = readFileSync(path.join(root, "workers/admission-service/production-index.ts"), "utf8").replace(/\/\/.*$/gmu, "");
  assert.equal(/\bLab[A-Z]/u.test(entry), false, "the production admission entry exports no lab class");
  assert.equal(jsonc("deployment/admission-service.template.jsonc").main, "../workers/admission-service/production-index.ts");
  assert.equal(jsonc("deployment/admission-service.staging.template.jsonc").main !== "../workers/admission-service/lab-index.ts", true);
});

test("the lab read-only entrypoint addresses only the fixed lab Authority, so reaching it never reaches another Authority (the decisive boundary)", () => {
  const index = readFileSync(path.join(root, "workers/admission-service/index.ts"), "utf8");
  const start = index.indexOf("export class LabAuthorityLifecycleReadOnly");
  const section = index.slice(start, index.indexOf("export default", start));
  assert.ok(start > 0);
  assert.equal(section.match(/getByName\(([A-Z_]+)\)/gu)?.every((call) => call === "getByName(LAB_ADMISSION_AUTHORITY_ID)"), true);
  assert.equal(/getByName\((?!LAB_ADMISSION_AUTHORITY_ID)/u.test(section), false);
});

test("alternative lab observer entrypoint configurations are identified and refused; the real repository has none", () => {
  assert.deepEqual(observerEntrypointConfigs(root).filter((config) => config !== LAB_OBSERVER_CONFIG), []);
  const dir = mkdtempSync(path.join(os.tmpdir(), "lab-observer-"));
  try {
    mkdirSync(path.join(dir, "deployment"), { recursive: true });
    const rendered = clone(jsonc("deployment/lifecycle-observer.lab.template.jsonc"));
    rendered.main = "../workers/lab-lifecycle-observer.ts"; rendered.account_id = "1".repeat(32);
    writeFileSync(path.join(dir, LAB_OBSERVER_CONFIG), JSON.stringify(rendered));
    validateLabObserverDeployment(dir); // the one reviewed rendered configuration is accepted
    // any other config naming the lab module (renamed copy, production-named copy, relative spelling) is an alternative entrypoint
    for (const [name, main] of [["lifecycle-observer.copy.jsonc", "../workers/lab-lifecycle-observer.ts"], ["lifecycle-observer.production.jsonc", "../workers/./lab-lifecycle-observer.ts"], ["x.json", "../workers/../workers/lab-lifecycle-observer.ts"]] as const) {
      writeFileSync(path.join(dir, "deployment", name), JSON.stringify({ ...rendered, main }));
      assert.throws(() => validateLabObserverDeployment(dir), /alternative lab observer entrypoint/u, name);
      rmSync(path.join(dir, "deployment", name));
    }
    validateLabObserverDeployment(dir);
    // a rendered configuration that is not the reviewed shape is refused: wrong marker, wrong bucket, cron added
    for (const mutate of [(c: Record<string, unknown>) => { c.vars = { LIFECYCLE_OBSERVER_ENVIRONMENT: "x" }; }, (c: Record<string, unknown>) => { c.r2_buckets = []; },
      (c: Record<string, unknown>) => { c.triggers = { crons: ["* * * * *"] }; }, (c: Record<string, unknown>) => { c.triggers = { crons: ["0 0 * * *"] }; }, (c: Record<string, unknown>) => { delete c.vars; }]) {
      const bad = clone(rendered); mutate(bad);
      writeFileSync(path.join(dir, LAB_OBSERVER_CONFIG), JSON.stringify(bad));
      assert.throws(() => validateLabObserverDeployment(dir));
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("the deployment wrapper accepts no argument but --execute, defaults to validation only, and has no config-path option; manual deployment can still bypass it", () => {
  const text = readFileSync(path.join(root, "scripts/lab-observer-deploy.ts"), "utf8");
  assert.match(text, /argv\.length > 1 \|\| \(argv\.length === 1 && argv\[0\] !== "--execute"\)/u);
  assert.equal(/--config\W+(?:argv|process\.argv)|process\.env/u.test(text), false);
  assert.equal(text.match(/execFileSync\(/gu)?.length, 1);
  assert.match(text, /NOT a security boundary/u);
  assert.match(text, /nothing in the repository can stop a person from running/u);
});
