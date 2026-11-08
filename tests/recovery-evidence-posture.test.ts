import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { validateRecoveryEvidencePosture } from "../deployment/lifecycle-private-contract";

// Recovery-evidence posture: observer ARMED (read-only reconciliation relay), mailbox INACTIVE (no dispatch). Local validation only.

const root = process.cwd();
const ACCOUNT = "a".repeat(32);
const template = async (name: string) => JSON.parse(await readFile(join(root, "deployment", name), "utf8")) as Record<string, unknown>;
async function rendered() {
  const mailbox = await template("lifecycle-mailbox.template.jsonc");
  const observer = await template("lifecycle-observer.template.jsonc");
  for (const worker of [mailbox, observer]) worker.account_id = ACCOUNT;
  mailbox.main = "../workers/lifecycle-mailbox/index.ts";
  observer.main = "../workers/lifecycle-observer.ts";
  (mailbox.vars as Record<string, unknown>).AUTHORITY_OPERATOR_PUBLIC_KEY = encodeBase64url(new Uint8Array(32).fill(7));
  (mailbox.vars as Record<string, unknown>).CLOUDFLARE_ACCOUNT_ID = ACCOUNT;
  observer.triggers = { crons: ["* * * * *"] };
  return { mailbox, observer };
}
const read = (path: string) => readFile(join(root, path), "utf8");
const stripComments = (source: string) => source.replace(/\/\*[\s\S]*?\*\//gu, "").replace(/^\s*\/\/.*$/gmu, "");

test("posture: observer armed + mailbox inactive passes; every other schedule/shape combination is refused", async () => {
  const { mailbox, observer } = await rendered();
  assert.deepEqual(validateRecoveryEvidencePosture(observer, mailbox), { observer: "PRODUCTION_SCHEDULE_ARMED", mailbox: "PRODUCTION_DEPLOYMENT_INACTIVE" });
  const armedMailbox = { ...structuredClone(mailbox), triggers: { crons: ["* * * * *"] } };
  const inactiveObserver = { ...structuredClone(observer), triggers: { crons: [] } };
  assert.throws(() => validateRecoveryEvidencePosture(observer, armedMailbox), /unsafe-lifecycle-config/u, "an armed mailbox can dispatch");
  assert.throws(() => validateRecoveryEvidencePosture(inactiveObserver, mailbox), /unsafe-lifecycle-config/u, "an inactive observer produces no evidence");
  assert.throws(() => validateRecoveryEvidencePosture(observer, observer), "swapped/duplicated roles");
  assert.throws(() => validateRecoveryEvidencePosture(armedMailbox, armedMailbox));
  assert.throws(() => validateRecoveryEvidencePosture({ ...structuredClone(observer), triggers: { crons: ["* * * * *", "*/5 * * * *"] } }, mailbox), "extra cron");
  assert.throws(() => validateRecoveryEvidencePosture(observer, { ...structuredClone(mailbox), account_id: "b".repeat(32), vars: { ...(mailbox.vars as object), CLOUDFLARE_ACCOUNT_ID: "b".repeat(32) } }), /recovery-posture-account-mismatch/u);
  assert.throws(() => validateRecoveryEvidencePosture(observer, { ...structuredClone(mailbox), account_id: "b".repeat(32) }), /unsafe-lifecycle-guard/u, "the guard account var must equal the config account");
  assert.throws(() => validateRecoveryEvidencePosture(observer, null));
});

test("posture: the observer config cannot carry an executor, Durable Object, extra service, extra bucket, vars or any extra key", async () => {
  const { mailbox, observer } = await rendered();
  const mailboxServices = mailbox.services as unknown[];
  const variants: Record<string, unknown>[] = [
    { ...observer, services: mailboxServices },
    { ...observer, services: [...(observer.services as unknown[]), mailboxServices[0]] },
    { ...observer, durable_objects: { bindings: [{ name: "DISPATCH_GUARD", class_name: "LifecycleDispatchGuard" }] } },
    { ...observer, migrations: mailbox.migrations },
    { ...observer, vars: { AUTHORITY_OPERATOR_PUBLIC_KEY: (mailbox.vars as Record<string, unknown>).AUTHORITY_OPERATOR_PUBLIC_KEY } },
    { ...observer, r2_buckets: [...(observer.r2_buckets as unknown[]), { binding: "EXTRA", bucket_name: "x" }] },
    { ...observer, kv_namespaces: [{ binding: "KV", id: "x" }] },
    { ...observer, d1_databases: [{ binding: "DB", database_id: "x" }] },
    { ...observer, routes: [{ pattern: "example.test/*", zone_name: "example.test" }] },
    { ...observer, workers_dev: true },
    { ...observer, services: [{ ...(observer.services as Record<string, unknown>[])[0], entrypoint: "AuthorityLifecycleOnly" }] },
    { ...observer, main: "../workers/lifecycle-mailbox/index.ts" },
  ];
  for (const [index, variant] of variants.entries()) assert.throws(() => validateRecoveryEvidencePosture(variant, mailbox), `observer variant ${index}`);
});

test("observer runtime capability (static): R2 get/head/put and the signed reconciliation call only; no dispatch, executor, guard, delete or lifecycle verb", async () => {
  const observer = stripComments(await read("workers/lifecycle-observer.ts"));
  assert.deepEqual([...observer.matchAll(/env\.([A-Z_]+)\.([A-Za-z]+)\(/gu)].map((m) => `${m[1]}.${m[2]}`).sort(),
    ["GUARD_READER.exportLedger", "LIFECYCLE_READER.attestReconciliation", "REQUEST_BUCKET.get", "REQUEST_BUCKET.get", "RESULT_BUCKET.head", "RESULT_BUCKET.head", "RESULT_BUCKET.put", "RESULT_BUCKET.put"].sort());
  assert.doesNotMatch(observer, /LIFECYCLE_EXECUTOR|DISPATCH_GUARD|AUTHORITY\b|processInitialization|processRotation|\.delete\(|\.settle\(|initializeFromOperator|executeSigned|rotateRelease/u);
  assert.deepEqual([...observer.matchAll(/^import .*? from "([^"]+)";$/gmu)].map((m) => m[1]).sort(),
    ["../deployment/secret-policy", "../operator/attested-relay", "./lifecycle-mailbox/guard-export", "./lifecycle-mailbox/wire", "@cloudflare/workers-types"].sort());
  // The environment type declares exactly these four bindings (whitespace-normalised comparison of the member list, comments stripped above).
  const declaration = observer.slice(observer.indexOf("export type ObserverEnvironment = {"), observer.indexOf("};", observer.indexOf("GUARD_READER?")) + 2).replace(/\s+/gu, " ");
  assert.equal(declaration, "export type ObserverEnvironment = { REQUEST_BUCKET: R2Bucket; RESULT_BUCKET: R2Bucket; LIFECYCLE_READER: { attestReconciliation(digest: string, nonce: string): Promise<unknown> }; GUARD_READER?: { exportLedger(envelopeJson: string): Promise<GuardExportOutcome> };");
  assert.doesNotMatch(observer, /REQUEST_BUCKET\.(?:put|delete)/u);
});

test("the read-only service entrypoint reaches only SELECT-only Authority methods that never initialize, claim or rotate", async () => {
  const index = stripComments(await read("workers/admission-service/index.ts"));
  const start = index.indexOf("export class AuthorityLifecycleReadOnly");
  const body = index.slice(start, index.indexOf("\n}\n", start));
  assert.deepEqual([...body.matchAll(/^\s+async (\w+)\(/gmu)].map((m) => m[1]), ["inspectLifecycle", "attestAppliedLifecycle", "attestReconciliation"]);
  assert.doesNotMatch(body, /initialize|rotate|settle|claim|put\(|exec\(/u);
  const attestation = stripComments(await read("workers/admission-service/authority-attestation.ts"));
  for (const method of ["attestAppliedLifecycle", "attestReconciliation"]) {
    const from = attestation.indexOf(`async ${method}(`);
    const section = attestation.slice(from, attestation.indexOf("\n  }\n", from));
    assert.ok(section.length > 200, method);
    assert.doesNotMatch(section, /executeSigned|transactionSync|\.storage\.(?:put|delete|sql)|\.exec\(|INSERT|UPDATE|DELETE|CREATE/u, `${method} must stay read-only`);
  }
  const pinned = await read("tests/i3b-authority.test.ts");
  assert.match(pinned, /read-only inspection executes SELECTs only/u);
  assert.match(pinned, /read-only APPLIED recovery signs the durable receipt, executes SELECTs only and mutates nothing/u);
});

test("CLI: the posture script validates two rendered files locally and refuses the armed mailbox filename and misuse", async () => {
  const { mailbox, observer } = await rendered();
  const directory = await mkdtemp(join(tmpdir(), "limitmark-posture-"));
  try {
    const deployment = join(directory, "deployment");
    await mkdir(deployment);
    const write = (name: string, value: unknown) => writeFile(join(deployment, name), JSON.stringify(value));
    await write("lifecycle-observer.production.armed.jsonc", observer);
    await write("lifecycle-mailbox.production.jsonc", mailbox);
    await write("lifecycle-mailbox.production.armed.jsonc", { ...mailbox, triggers: { crons: ["* * * * *"] } });
    const run = (...args: string[]) => spawnSync(process.execPath, [join(root, "node_modules", "tsx", "dist", "cli.mjs"), join(root, "scripts", "lifecycle-recovery-posture.ts"), ...args], { cwd: directory, encoding: "utf8" });
    const good = run("--observer", "deployment/lifecycle-observer.production.armed.jsonc", "--mailbox", "deployment/lifecycle-mailbox.production.jsonc");
    assert.equal(good.status, 0, good.stderr);
    assert.match(good.stdout, /Recovery-evidence posture: PASS \(local validation only\)/u);
    const armed = run("--observer", "deployment/lifecycle-observer.production.armed.jsonc", "--mailbox", "deployment/lifecycle-mailbox.production.armed.jsonc");
    assert.equal(armed.status, 2);
    assert.match(armed.stderr, /REFUSED \(config-location\)\. Nothing was changed\./u);
    assert.equal(run("--observer", "deployment/lifecycle-mailbox.production.jsonc", "--mailbox", "deployment/lifecycle-mailbox.production.jsonc").status, 2);
    assert.equal(run("--observer", "x").status, 2);
    assert.equal(run().status, 2);
    assert.equal(run("--observer", "../x", "--mailbox", "deployment/lifecycle-mailbox.production.jsonc").status, 2);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
