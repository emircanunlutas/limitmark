import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { validateOperatorExecutorTemplate, validateRenderedOperatorExecutorConfig } from "../deployment/operator-executor-contract";

const root = fileURLToPath(new URL("../", import.meta.url));
const templatePath = join(root, "deployment", "operator-lifecycle-executor.template.jsonc");
const template = async () => JSON.parse(await readFile(templatePath, "utf8")) as Record<string, unknown>;
const rendered = async () => {
  const config = await template();
  config.name = "limitmark-authority-operator-executor-production";
  config.main = "../workers/operator-lifecycle-executor.ts";
  config.account_id = "a".repeat(32); // synthetic only
  config.services = [{ binding: "ADMISSION_SERVICE", service: "limitmark-admission-service-production" }];
  config.vars = { AUTHORITY_OPERATOR_PUBLIC_KEY: encodeBase64url(new Uint8Array(32).fill(7)), OPERATOR_EXECUTOR_ENVIRONMENT: "production" };
  return config;
};

test("executor contract is a strict capability allowlist", async () => {
  const valid = await rendered();
  assert.doesNotThrow(() => validateRenderedOperatorExecutorConfig(valid));
  const mutations: Array<[string, (config: Record<string, unknown>) => void]> = [
    ["singular route/custom domain", (c) => { c.route = { pattern: "operator.example.com/*", custom_domain: true }; }],
    ["plural routes", (c) => { c.routes = [{ pattern: "operator.example.com/*" }]; }],
    ["workers.dev", (c) => { c.workers_dev = true; }],
    ["preview URLs", (c) => { c.preview_urls = true; }],
    ["environment override workers.dev", (c) => { c.env = { production: { workers_dev: true } }; }],
    ["environment override preview", (c) => { c.env = { production: { preview_urls: true } }; }],
    ["alternate service", (c) => { c.services = [{ binding: "ADMISSION_SERVICE", service: "different-service" }]; }],
    ["second service", (c) => { c.services = [...c.services as unknown[], { binding: "EXTRA", service: "other" }]; }],
    ["DO", (c) => { c.durable_objects = { bindings: [{ name: "AUTHORITY", class_name: "ProductionAdmissionAuthority" }] }; }],
    ["KV", (c) => { c.kv_namespaces = [{ binding: "KV", id: "synthetic" }]; }],
    ["R2", (c) => { c.r2_buckets = [{ binding: "BUCKET", bucket_name: "synthetic" }]; }],
    ["D1", (c) => { c.d1_databases = [{ binding: "DB", database_id: "synthetic" }]; }],
    ["Queue", (c) => { c.queues = { producers: [{ binding: "Q", queue: "synthetic" }] }; }],
    ["Analytics Engine", (c) => { c.analytics_engine_datasets = [{ binding: "ANALYTICS" }]; }],
    ["Vectorize", (c) => { c.vectorize = [{ binding: "INDEX", index_name: "synthetic" }]; }],
    ["Hyperdrive", (c) => { c.hyperdrive = [{ binding: "DB", id: "synthetic" }]; }],
    ["browser rendering", (c) => { c.browser = { binding: "BROWSER" }; }],
    ["assets", (c) => { c.assets = { directory: "./public" }; }],
    ["dispatch namespace", (c) => { c.dispatch_namespaces = [{ binding: "DISPATCH", namespace: "synthetic" }]; }],
    ["tail", (c) => { c.tail_consumers = [{ service: "other" }]; }],
    ["unknown future capability", (c) => { c.future_binding = { enabled: true }; }],
  ];
  for (const [name, mutate] of mutations) {
    const config = structuredClone(valid);
    mutate(config);
    assert.throws(() => validateRenderedOperatorExecutorConfig(config), { name: "Error" }, name);
  }
});

test("raw and incomplete executor templates fail mandatory preflight", async () => {
  const raw = await template();
  assert.doesNotThrow(() => validateOperatorExecutorTemplate(raw));
  assert.throws(() => validateRenderedOperatorExecutorConfig(raw));
  assert.equal(existsSync(join(root, "deployment", String(raw.main))), false);
  const variants: Array<[string, (config: Record<string, unknown>) => void]> = [
    ["unresolved worker target", (c) => { c.name = raw.name; }],
    ["unresolved account", (c) => { c.account_id = raw.account_id; }],
    ["empty account identity", (c) => { c.account_id = "0".repeat(32); }],
    ["unresolved entrypoint", (c) => { c.main = raw.main; }],
    ["unresolved binding", (c) => { c.services = raw.services; }],
    ["unresolved public key", (c) => { c.vars = { ...(c.vars as object), AUTHORITY_OPERATOR_PUBLIC_KEY: (raw.vars as Record<string, unknown>).AUTHORITY_OPERATOR_PUBLIC_KEY }; }],
    ["unresolved environment", (c) => { c.vars = { ...(c.vars as object), OPERATOR_EXECUTOR_ENVIRONMENT: (raw.vars as Record<string, unknown>).OPERATOR_EXECUTOR_ENVIRONMENT }; }],
  ];
  for (const [name, mutate] of variants) {
    const config = await rendered(); mutate(config);
    assert.throws(() => validateRenderedOperatorExecutorConfig(config), { name: "Error" }, name);
  }
});

test("preflight command refuses raw template and accepts synthetic rendered config", async () => {
  const run = (path: string) => spawnSync(process.execPath,
    ["node_modules/tsx/dist/cli.mjs", "scripts/authority-executor-preflight.ts", "--config", path],
    { cwd: root, encoding: "utf8" });
  assert.notEqual(run(templatePath).status, 0);
  const path = join(root, "deployment", `.i3a-synthetic-${process.pid}.jsonc`);
  try {
    const valid = JSON.stringify(await rendered());
    await writeFile(path, valid.replace('"workers_dev":false', '"workers_dev":true,"workers_dev":false'));
    assert.notEqual(run(path).status, 0, "duplicate exposure member must fail");
    await writeFile(path, valid);
    const result = run(path);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /PASS/u);
  } finally { await rm(path, { force: true }); }
});
