import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { validateLifecycleMailboxConfig, validateLifecycleObserverConfig, validateLifecycleTransportManifest } from "../deployment/lifecycle-private-contract";

const root = process.cwd();
const config = async (name: string) => JSON.parse(await readFile(join(root, "deployment", name), "utf8")) as Record<string, unknown>;
const synthetic = async () => {
  const mailbox = await config("lifecycle-mailbox.template.jsonc");
  const observer = await config("lifecycle-observer.template.jsonc");
  const transport = await config("lifecycle-transport.production.template.json");
  for (const worker of [mailbox, observer]) worker.account_id = "a".repeat(32);
  mailbox.main = "../workers/lifecycle-mailbox/index.ts";
  observer.main = "../workers/lifecycle-observer.ts";
  (mailbox.vars as Record<string, unknown>).AUTHORITY_OPERATOR_PUBLIC_KEY = encodeBase64url(new Uint8Array(32).fill(7));
  transport.accountId = "a".repeat(32);
  transport.operatorPublicKey = (mailbox.vars as Record<string, unknown>).AUTHORITY_OPERATOR_PUBLIC_KEY;
  return { mailbox, observer, transport };
};

test("private mailbox, observer and target manifest have exact capability allowlists", async () => {
  const { mailbox, observer, transport } = await synthetic();
  assert.doesNotThrow(() => validateLifecycleMailboxConfig(mailbox, false));
  assert.doesNotThrow(() => validateLifecycleObserverConfig(observer, false));
  assert.doesNotThrow(() => validateLifecycleTransportManifest(transport, false));
  const mutations: Array<[Record<string, unknown>, (value: Record<string, unknown>) => void]> = [
    [mailbox, (x) => { x.routes = []; }], [observer, (x) => { x.route = "example.com/*"; }],
    [mailbox, (x) => { x.workers_dev = true; }], [observer, (x) => { x.preview_urls = true; }],
    [mailbox, (x) => { x.services = [(x.services as unknown[])[0]]; }],
    [observer, (x) => { x.services = [...x.services as unknown[], { binding: "LIFECYCLE_EXECUTOR", service: "other" }]; }],
    [observer, (x) => { x.durable_objects = { bindings: [] }; }],
    [mailbox, (x) => { x.queues = {}; }], [mailbox, (x) => { x.assets = {}; }],
    [observer, (x) => { x.browser = {}; }], [mailbox, (x) => { x.tail_consumers = []; }],
    [mailbox, (x) => { x.env = { production: { workers_dev: true } }; }],
  ];
  for (const [base, mutate] of mutations) {
    const copy = structuredClone(base);
    mutate(copy);
    assert.throws(() => base === observer ? validateLifecycleObserverConfig(copy, false) : validateLifecycleMailboxConfig(copy, false));
  }
  assert.throws(() => validateLifecycleTransportManifest({ ...transport, resultBucket: transport.requestBucket }, false));
});

test("unresolved raw templates fail mandatory rendered preflight", async () => {
  const mailbox = await config("lifecycle-mailbox.template.jsonc");
  const observer = await config("lifecycle-observer.template.jsonc");
  const transport = await config("lifecycle-transport.production.template.json");
  validateLifecycleMailboxConfig(mailbox);
  validateLifecycleObserverConfig(observer);
  validateLifecycleTransportManifest(transport);
  for (const [kind, file] of [["mailbox", "lifecycle-mailbox.template.jsonc"], ["observer", "lifecycle-observer.template.jsonc"],
    ["transport", "lifecycle-transport.production.template.json"]]) {
    const run = spawnSync(process.execPath, ["node_modules/tsx/dist/cli.mjs", "scripts/lifecycle-private-preflight.ts",
      kind, "--config", join(root, "deployment", file)], { cwd: root, encoding: "utf8" });
    assert.notEqual(run.status, 0, `${kind} raw template must fail`);
  }
});
