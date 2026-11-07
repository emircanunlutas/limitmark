import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const directory = "deployment/terraform/cloud-lab/";
const read = (name: string) => readFileSync(`${directory}${name}`, "utf8").replace(/\r\n/gu, "\n");
const variables = read("variables.tf");
const versions = read("versions.tf");
const stages = read("STAGES.md");
const backend = read("backend.gcs.hcl.example");
const lifecycle = JSON.parse(read("state-bucket-lifecycle.json")) as {
  rule: Array<{ action: { type: string }; condition: Record<string, unknown> }>;
};

test("PostgreSQL machine type is dedicated-core and shared-core types are rejected", () => {
  const block = variables.split(/^variable /mu).find((entry) => entry.startsWith('"postgres_machine_type"'))!;
  const type = block.match(/default\s*=\s*"([^"]+)"/u)?.[1];
  assert.ok(type && !/^e2-(micro|small|medium)$/u.test(type), `default ${type}`);
  assert.match(block, /contains\(\["e2-micro", "e2-small", "e2-medium"\], var\.postgres_machine_type\)/u);
});

test("remote state config holds no credentials and the state backend is not enabled prematurely", () => {
  const settings = backend.split("\n").filter((line) => line.trim() && !line.trim().startsWith("#")).join("\n");
  assert.equal(/credentials|access_token|private_key|BEGIN [A-Z ]*PRIVATE KEY/iu.test(settings), false);
  assert.match(backend, /^bucket\s*=\s*"[a-z0-9-]+-tfstate"$/mu);
  const backendBlock = versions.match(/backend\s+"gcs"\s*\{([^}]*)\}/u);
  assert.ok(backendBlock, "remote GCS backend must be configured");
  assert.equal(backendBlock[1].trim(), "", "bucket and prefix come from -backend-config, never inline credentials");
  assert.equal(/credentials|access_token|impersonate/iu.test(versions), false);
});

test("state bucket lifecycle only deletes old noncurrent versions, never live objects", () => {
  assert.equal(lifecycle.rule.length, 1);
  const [rule] = lifecycle.rule;
  assert.equal(rule.action.type, "Delete");
  assert.equal(rule.condition.isLive, false);
  assert.ok(Number(rule.condition.daysSinceNoncurrentTime) >= 30);
});

test("staging document requires the protective bucket settings and a rollback", () => {
  for (const flag of ["--uniform-bucket-level-access", "--public-access-prevention", "--versioning", "--lifecycle-file"]) {
    assert.ok(stages.includes(flag), flag);
  }
  assert.match(stages, /Retention policy \| \*\*None, deliberately\*\*/u);
  assert.match(stages, /\*\*Rollback\*\*/u);
  assert.match(stages, /must report \*\*31\*\*/u);
  assert.equal(/ya29\.|PRIVATE KEY-----/u.test(stages), false);
});
