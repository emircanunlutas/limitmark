import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import {
  productionScheduleState, validateLifecycleMailboxConfig, validateLifecycleObserverConfig, validateStagingLifecycleMailboxConfig,
  validateStagingLifecycleObserverConfig,
} from "../deployment/lifecycle-private-contract";

// Production mailbox/observer schedules are INACTIVE by default; ARMED is an explicit, separately authorized state. Nothing here deploys or
// contacts a provider: every check is a local validator or a local-file transform in a temporary directory.

const root = process.cwd();
const tsx = join(root, "node_modules", "tsx", "dist", "cli.mjs");
const ACCOUNT = "a".repeat(32);
const OPERATOR_KEY = encodeBase64url(new Uint8Array(32).fill(7));
const INACTIVE = "PRODUCTION_DEPLOYMENT_INACTIVE" as const;
const ARMED = "PRODUCTION_SCHEDULE_ARMED" as const;

const template = async (name: string) => JSON.parse(await readFile(join(root, "deployment", name), "utf8")) as Record<string, unknown>;
async function rendered() {
  const mailbox = await template("lifecycle-mailbox.template.jsonc");
  const observer = await template("lifecycle-observer.template.jsonc");
  for (const worker of [mailbox, observer]) worker.account_id = ACCOUNT;
  mailbox.main = "../workers/lifecycle-mailbox/index.ts";
  observer.main = "../workers/lifecycle-observer.ts";
  (mailbox.vars as Record<string, unknown>).AUTHORITY_OPERATOR_PUBLIC_KEY = OPERATOR_KEY;
  return { mailbox, observer };
}
const withTriggers = (config: Record<string, unknown>, triggers: unknown) => ({ ...structuredClone(config), triggers });

test("tracked production templates ship with no active Cron and validate as INACTIVE by default", async () => {
  const mailbox = await template("lifecycle-mailbox.template.jsonc");
  const observer = await template("lifecycle-observer.template.jsonc");
  assert.deepEqual(mailbox.triggers, { crons: [] });
  assert.deepEqual(observer.triggers, { crons: [] });
  assert.equal(validateLifecycleMailboxConfig(mailbox), INACTIVE);
  assert.equal(validateLifecycleObserverConfig(observer), INACTIVE);
  assert.throws(() => validateLifecycleMailboxConfig(mailbox, true, ARMED));
  assert.throws(() => validateLifecycleObserverConfig(observer, true, ARMED));
});

test("rendered production configs: the default accepts only INACTIVE; ARMED needs the explicit state; the two never satisfy each other", async () => {
  const { mailbox, observer } = await rendered();
  assert.equal(validateLifecycleMailboxConfig(mailbox, false), INACTIVE);
  assert.equal(validateLifecycleObserverConfig(observer, false), INACTIVE);
  const armedMailbox = withTriggers(mailbox, { crons: ["* * * * *"] });
  const armedObserver = withTriggers(observer, { crons: ["* * * * *"] });
  assert.throws(() => validateLifecycleMailboxConfig(armedMailbox, false), "an armed rendered mailbox is refused by default");
  assert.throws(() => validateLifecycleObserverConfig(armedObserver, false), "an armed rendered observer is refused by default");
  assert.throws(() => validateLifecycleMailboxConfig(armedMailbox, false, INACTIVE));
  assert.equal(validateLifecycleMailboxConfig(armedMailbox, false, ARMED), ARMED);
  assert.equal(validateLifecycleObserverConfig(armedObserver, false, ARMED), ARMED);
  assert.throws(() => validateLifecycleMailboxConfig(mailbox, false, ARMED), "an inactive config does not satisfy the armed requirement");
});

test("only the two exact trigger shapes exist; any other schedule state fails closed in both modes", async () => {
  const { mailbox, observer } = await rendered();
  const garbled: unknown[] = [
    undefined, null, {}, { crons: ["*/5 * * * *"] }, { crons: ["* * * * *", "*/5 * * * *"] }, { crons: ["* * * * *", "* * * * *"] }, { crons: "* * * * *" },
    { crons: [] , extra: true }, { crons: [""] }, { crons: ["0 0 * * *"] }, [], "crons",
  ];
  for (const triggers of garbled) {
    for (const state of [INACTIVE, ARMED] as const) {
      assert.throws(() => validateLifecycleMailboxConfig(withTriggers(mailbox, triggers), false, state), JSON.stringify(triggers));
      assert.throws(() => validateLifecycleObserverConfig(withTriggers(observer, triggers), false, state), JSON.stringify(triggers));
    }
    assert.throws(() => productionScheduleState(triggers), JSON.stringify(triggers));
  }
  assert.equal(productionScheduleState({ crons: [] }), INACTIVE);
  assert.equal(productionScheduleState({ crons: ["* * * * *"] }), ARMED);
  const missing = structuredClone(mailbox); delete missing.triggers;
  assert.throws(() => validateLifecycleMailboxConfig(missing, false));
});

test("lab and staging schedules are unchanged: still inactive, still on their own validators", async () => {
  for (const file of ["lifecycle-mailbox.staging.template.jsonc", "lifecycle-observer.staging.template.jsonc", "lifecycle-mailbox.lab.template.jsonc", "lifecycle-observer.lab.template.jsonc"]) {
    assert.deepEqual((await template(file)).triggers, { crons: [] }, file);
  }
  // Production state names are not staging state names: a staging validator cannot be satisfied by the production type or vice versa.
  const staging = await template("lifecycle-mailbox.staging.template.jsonc");
  assert.doesNotThrow(() => validateStagingLifecycleMailboxConfig(staging, true, "STAGING_DEPLOYMENT_INACTIVE"));
  assert.throws(() => validateLifecycleMailboxConfig(staging, true));
  const stagingObserver = await template("lifecycle-observer.staging.template.jsonc");
  assert.doesNotThrow(() => validateStagingLifecycleObserverConfig(stagingObserver, true, "STAGING_DEPLOYMENT_INACTIVE"));
});

async function workspace() {
  const directory = await mkdtemp(join(tmpdir(), "limitmark-production-schedule-"));
  await mkdir(join(directory, "deployment"));
  const { mailbox, observer } = await rendered();
  await writeFile(join(directory, "deployment", "lifecycle-mailbox.production.jsonc"), JSON.stringify(mailbox));
  await writeFile(join(directory, "deployment", "lifecycle-observer.production.jsonc"), JSON.stringify(observer));
  return directory;
}
const run = (cwd: string, script: string, args: string[], env: Record<string, string> = {}) =>
  spawnSync(process.execPath, [tsx, join(root, script), ...args], { cwd, encoding: "utf8", env: { ...process.env, ...env } });

test("production preflight CLI: mailbox/observer modes require INACTIVE; the -arm modes require ARMED and an exact armed filename", async () => {
  const cwd = await workspace();
  try {
    const preflight = (mode: string, file: string) => run(cwd, "scripts/lifecycle-private-preflight.ts", [mode, "--config", join("deployment", file)]);
    for (const [mode, file] of [["mailbox", "lifecycle-mailbox.production.jsonc"], ["observer", "lifecycle-observer.production.jsonc"]]) {
      const ok = preflight(mode, file);
      assert.equal(ok.status, 0, ok.stderr);
      assert.match(ok.stdout, /Schedule state: PRODUCTION_DEPLOYMENT_INACTIVE/);
      assert.notEqual(preflight(`${mode}-arm`, file).status, 0, "an inactive config cannot pass the armed preflight (and has the wrong filename)");
    }
    // produce armed files by hand (the transform is tested below) to prove the armed modes and that default modes refuse them
    for (const [resource, mode] of [["mailbox", "mailbox"], ["observer", "observer"]] as const) {
      const inactive = JSON.parse(await readFile(join(cwd, "deployment", `lifecycle-${resource}.production.jsonc`), "utf8"));
      await writeFile(join(cwd, "deployment", `lifecycle-${resource}.production.armed.jsonc`), JSON.stringify({ ...inactive, triggers: { crons: ["* * * * *"] } }));
      const armed = preflight(`${mode}-arm`, `lifecycle-${resource}.production.armed.jsonc`);
      assert.equal(armed.status, 0, armed.stderr);
      assert.match(armed.stdout, /Schedule state: PRODUCTION_SCHEDULE_ARMED/);
      assert.notEqual(preflight(mode, `lifecycle-${resource}.production.armed.jsonc`).status, 0, "the default mode refuses an armed config");
      await writeFile(join(cwd, "deployment", "renamed.jsonc"), JSON.stringify({ ...inactive, triggers: { crons: ["* * * * *"] } }));
      assert.notEqual(preflight(`${mode}-arm`, "renamed.jsonc").status, 0, "the armed mode refuses any other filename");
    }
  } finally { await rm(cwd, { recursive: true, force: true }); }
});

test("schedule-arming transform: separate explicit step, local only, never overwrites, refuses wrong pins and already-armed sources", async () => {
  const cwd = await workspace();
  try {
    const arm = (args: string[], env: Record<string, string> = { CLOUDFLARE_ACCOUNT_ID: ACCOUNT }) =>
      run(cwd, "scripts/authority-production-schedule-arm.ts", args, env);
    const armedPath = join(cwd, "deployment", "lifecycle-mailbox.production.armed.jsonc");
    // not armed without the explicit confirmation flag, a known resource, or the account pin
    assert.notEqual(arm(["mailbox"]).status, 0);
    assert.notEqual(arm(["mailbox", "--confirm"]).status, 0);
    assert.notEqual(arm(["staging", "--confirm-production-arm"]).status, 0);
    assert.notEqual(arm(["mailbox", "--confirm-production-arm"], { CLOUDFLARE_ACCOUNT_ID: "b".repeat(32) }).status, 0, "account pin mismatch");
    assert.notEqual(arm(["mailbox", "--confirm-production-arm"], { CLOUDFLARE_ACCOUNT_ID: "" }).status, 0, "missing pin");
    assert.equal(existsSync(armedPath), false, "no file is written by any refusal");
    // the explicit step
    const before = await readFile(join(cwd, "deployment", "lifecycle-mailbox.production.jsonc"), "utf8");
    const done = arm(["mailbox", "--confirm-production-arm"]);
    assert.equal(done.status, 0, done.stderr);
    const report = JSON.parse(done.stdout);
    assert.equal(report.providerContact, "none");
    assert.equal(report.deployed, false);
    assert.equal(report.scheduleState, ARMED);
    assert.ok(!done.stdout.includes(ACCOUNT), "the account id is reported only as a fingerprint");
    assert.equal(await readFile(join(cwd, "deployment", "lifecycle-mailbox.production.jsonc"), "utf8"), before, "the inactive source is untouched");
    const armed = JSON.parse(await readFile(armedPath, "utf8"));
    assert.deepEqual(armed.triggers, { crons: ["* * * * *"] });
    assert.deepEqual({ ...armed, triggers: undefined }, { ...JSON.parse(before), triggers: undefined }, "only `triggers` differs");
    // never overwrites
    assert.notEqual(arm(["mailbox", "--confirm-production-arm"]).status, 0);
    // an already-armed source is refused (the inactive source must be INACTIVE)
    await writeFile(join(cwd, "deployment", "lifecycle-observer.production.jsonc"), JSON.stringify({ ...JSON.parse(await readFile(join(cwd, "deployment", "lifecycle-observer.production.jsonc"), "utf8")), triggers: { crons: ["* * * * *"] } }));
    assert.notEqual(arm(["observer", "--confirm-production-arm"]).status, 0);
    assert.equal(existsSync(join(cwd, "deployment", "lifecycle-observer.production.armed.jsonc")), false);
  } finally { await rm(cwd, { recursive: true, force: true }); }
});

test("rendered production schedule files are git-ignored and the arming script contains no provider-contact capability", async () => {
  const ignore = await readFile(join(root, "deployment", ".gitignore"), "utf8");
  for (const name of ["lifecycle-observer.production.jsonc", "lifecycle-mailbox.production.armed.jsonc", "lifecycle-observer.production.armed.jsonc"]) assert.match(ignore, new RegExp(name.replaceAll(".", "\\.")));
  const source = await readFile(join(root, "scripts", "authority-production-schedule-arm.ts"), "utf8");
  const code = source.replace(/\/\/.*$/gmu, "");
  assert.doesNotMatch(code, /wrangler|child_process|spawn|exec\(|fetch\(|https?:\/\/|XMLHttpRequest|net\b/u);
  const manifest = JSON.parse(await readFile(join(root, "package.json"), "utf8")) as { scripts: Record<string, string> };
  assert.equal(manifest.scripts["authority:production:schedule-arm"], "tsx scripts/authority-production-schedule-arm.ts");
  assert.ok(!Object.values(manifest.scripts).some((command) => /production.*schedule-arm.*wrangler|wrangler.*schedule-arm/u.test(command)));
});
