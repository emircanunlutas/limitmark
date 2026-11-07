import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const directory = "deployment/terraform/cloud-lab/";
const read = (name: string) => readFileSync(`${directory}${name}`, "utf8").replace(/\r\n/gu, "\n");
const variables = read("variables.tf");
const cloudRun = read("cloud-run.tf");
const postgres = read("postgres.tf");
const example = read("terraform.tfvars.example");
const runbook = read("STAGE4-CLOUD-RUN.md");

function imagePattern(variable: string): RegExp {
  const block = variables.split(/^variable /mu).find((entry) => entry.startsWith(`"${variable}"`));
  assert.ok(block, variable);
  const hcl = block.match(/regex\("((?:[^"\\]|\\.)*)"/u)?.[1];
  assert.ok(hcl, `${variable} must validate its value`);
  return new RegExp(hcl.replace(/\\\\/gu, "\\"), "u");
}

const digest = "a".repeat(64);
const good = `europe-west3-docker.pkg.dev/limitmark-field-qual/limitmark/limitmark-app@sha256:${digest}`;

for (const variable of ["cloud_run_image", "otel_collector_image"]) {
  test(`${variable} accepts only a digest-pinned image from the project's limitmark repository`, () => {
    const pattern = imagePattern(variable);
    assert.ok(pattern.test(good));
    assert.ok(pattern.test(`europe-west3-docker.pkg.dev/limitmark-field-qual/limitmark/otelcol-contrib@sha256:${digest}`));
    for (const bad of [
      good.replace(`@sha256:${digest}`, ":latest"),
      good.replace(`@sha256:${digest}`, ":build-abc123"),
      good.replace(`@sha256:${digest}`, `@sha256:${"a".repeat(63)}`),
      good.replace("/limitmark/", "/other-repository/"),
      `docker.io/otel/opentelemetry-collector-contrib@sha256:${digest}`,
      `gcr.io/limitmark-field-qual/limitmark/app@sha256:${digest}`,
      "",
    ]) assert.equal(pattern.test(bad), false, bad);
  });
}

test("the collector image comes from a variable, not a mutable Docker Hub tag", () => {
  assert.match(cloudRun, /image\s*=\s*var\.otel_collector_image/u);
  assert.equal(/opentelemetry-collector-contrib:\d/u.test(cloudRun), false);
  assert.match(example, /^otel_collector_image\s*=\s*".*@sha256:/mu);
  assert.match(example, /^cloud_run_image\s*=\s*".*@sha256:/mu);
});

test("the PostgreSQL VM cannot be replaced by a bootstrap edit", () => {
  const instance = postgres.split(/^resource /mu).find((block) => block.startsWith('"google_compute_instance"'))!;
  assert.match(instance, /lifecycle\s*\{[^}]*ignore_changes\s*=\s*\[metadata_startup_script\]/u);
  assert.equal(/prevent_destroy|replace_triggered_by/u.test(instance), false);
});

test("Cloud Run stays IAM-authenticated, private-egress-only to the database subnet, with secrets by reference", () => {
  assert.equal(/allUsers|allAuthenticatedUsers/u.test(cloudRun), false);
  assert.match(cloudRun, /service_account\s*=\s*google_service_account\.app\.email/u);
  assert.match(cloudRun, /egress\s*=\s*"PRIVATE_RANGES_ONLY"/u);
  assert.match(cloudRun, /LAB_DATABASE_CA_CERT\s*=\s*"limitmark-lab-database-ca-cert"/u);
  assert.equal(/postgres(ql)?:\/\/|PASSWORD|BEGIN [A-Z ]*PRIVATE KEY/u.test(cloudRun), false);
  assert.match(cloudRun, /name\s*=\s*"REQUEST_SUBMISSION_MODE"\s*\n\s*value\s*=\s*"postgres"/u);
  assert.match(cloudRun, /name\s*=\s*"PUBLIC_ORIGIN_PROTECTION"\s*\n\s*value\s*=\s*"required"/u);
  assert.equal(/startup_probe|liveness_probe/u.test(cloudRun), false, "probes must not be used to mask fail-closed configuration states");
});

test("runbook keeps the three validations separate and flags the long-lived signer key", () => {
  assert.match(runbook, /validated \*\*independently\*\*/u);
  for (const phrase of ["Cloud Run infrastructure", "Application to PostgreSQL", "Public traffic"]) assert.ok(runbook.includes(phrase), phrase);
  assert.match(runbook, /service-account JSON key/u);
  assert.match(runbook, /7 add, 0 change, 0 destroy/u);
  assert.equal(/ya29\.|BEGIN [A-Z ]*PRIVATE KEY/u.test(runbook), false);
});
