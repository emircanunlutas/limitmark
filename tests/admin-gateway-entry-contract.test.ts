import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

// The deployable admin-gateway entry (deployment/admin-gateway.template.jsonc "main") may expose ONLY its default handler: workerd rejects any module export that is
// not a handler or class ("Incorrect type for map entry"). Everything else is imported from ./gateway by tests. This pins that export contract.

const entry = path.join(__dirname, "..", "workers", "admin-gateway", "index.ts");

test("the module namespace of the entry has exactly one runtime export: default", async () => {
  const namespace = await import("../workers/admin-gateway/index");
  assert.deepEqual(Object.keys(namespace), ["default"]);
});

test("the default export is a plain handler object exposing only fetch", async () => {
  const { default: worker } = await import("../workers/admin-gateway/index");
  assert.deepEqual(Object.keys(worker), ["fetch"]);
  assert.equal(typeof worker.fetch, "function");
});

test("source: no runtime re-export or named export besides default (types only)", () => {
  const source = readFileSync(entry, "utf8");
  const exports = [...source.matchAll(/^export\s+(?!type\b)(?!default\b)(.*)$/gmu)].map((match) => match[0]);
  assert.deepEqual(exports, []);
  assert.equal((source.match(/^export default /gmu) ?? []).length, 1);
  assert.doesNotMatch(source, /^export\s*\*|^export\s*\{/mu);
});

test("an environment that fails the runtime-secret policy gets an empty 503 and never reaches the gateway", async () => {
  const { default: worker } = await import("../workers/admin-gateway/index");
  const response = await worker.fetch(new Request("https://admin.limitmark.com/"), {} as never);
  assert.equal(response.status, 503);
  assert.equal(await response.text(), "");
});
