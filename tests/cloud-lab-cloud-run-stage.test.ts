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
  assert.match(runbook, /6 add, 0 change, 0 destroy/u);
  assert.equal(/ya29\.|BEGIN [A-Z ]*PRIVATE KEY/u.test(runbook), false);
});

test("no network or project-wide permission beyond the reviewed set is granted to Cloud Run", () => {
  const iam = read("iam.tf");
  assert.equal(/google_compute_subnetwork_iam_member|roles\/compute\.networkUser/u.test(iam.replace(/^\s*#.*$/gmu, "")), false);
  assert.equal(/google_compute_subnetwork_iam_member/u.test(cloudRun), false);
});

test("end-to-end runbook keeps key creation unapproved and gated", () => {
  const e2e = read("E2E-DEPLOYMENT.md");
  assert.match(e2e, /No service-account key has been created/u);
  for (const gate of ["| A |", "| B |", "| C |", "| D |", "| E |", "| F |", "| G |"]) assert.ok(e2e.includes(gate), gate);
  assert.equal(/ya29\.|BEGIN [A-Z ]*PRIVATE KEY/u.test(e2e), false);
});

test("the live-deployment runbook marks approvals, keeps the key uncreated and records the initialization blocker", () => {
  const runbook = read("RUNBOOK-FIRST-LIVE-DEPLOYMENT.md");
  for (const phrase of ["[OWNER]", "[CF]", "NOTHING here has been executed", "authority initialization", "Cryptographic binding is not replay prevention", "6 to add, 0 to change, 0 to destroy"]) {
    assert.ok(runbook.toLowerCase().includes(phrase.toLowerCase()), phrase);
  }
  assert.equal(/ya29\.|BEGIN [A-Z ]*PRIVATE KEY|"private_key"\s*:/u.test(runbook), false);
  assert.match(runbook, /Turnstile[\s\S]*none\*\* - the admission Worker/u);
});

test("authority bootstrap is a mandatory, ordered gate with approvals marked and no secret material", () => {
  const bootstrap = read("AUTHORITY-BOOTSTRAP.md");
  const runbook = read("RUNBOOK-FIRST-LIVE-DEPLOYMENT.md");
  for (const phrase of ["Mandatory vs optional", "no real LimitMark production Workers", "Negative test first", "POSITIVE", "Rollback boundaries", "NOTHING here has been executed"]) assert.ok(bootstrap.includes(phrase), phrase);
  for (const phrase of ["| E0 |", "| E1 |", "AUTHORITY-BOOTSTRAP.md", "Dedicated Cloudflare account decision"]) assert.ok(runbook.includes(phrase), phrase);
  assert.ok(runbook.indexOf("| E0 |") < runbook.indexOf("| E1 |"), "authority initialization precedes public traffic");
  assert.equal(/ya29\.|BEGIN [A-Z ]*PRIVATE KEY|"private_key"\s*:/u.test(bootstrap + runbook), false);
});
