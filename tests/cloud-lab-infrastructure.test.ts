import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const terraformDirectory = "deployment/terraform/cloud-lab/";
const read = (path: string) => readFileSync(path, "utf8").replace(/\r\n/gu, "\n");
const iam = read(`${terraformDirectory}iam.tf`);
const postgres = read(`${terraformDirectory}postgres.tf`);
const cloudRun = read(`${terraformDirectory}cloud-run.tf`);
const bootstrap = read(`${terraformDirectory}postgres-bootstrap.sh`);

function resourceBlocks(source: string, type: string): string[] {
  return source.split(/^resource /mu).filter((block) => block.startsWith(`"${type}"`));
}

test("invoker self-impersonation is the narrowest role, bound to the invoker account only", () => {
  const bindings = resourceBlocks(iam, "google_service_account_iam_member");
  assert.equal(bindings.length, 1);
  assert.match(bindings[0], /service_account_id\s*=\s*google_service_account\.invoker\.name/u);
  assert.match(bindings[0], /role\s*=\s*"roles\/iam\.serviceAccountOpenIdTokenCreator"/u);
  assert.match(bindings[0], /member\s*=\s*"serviceAccount:\$\{google_service_account\.invoker\.email\}"/u);
  assert.equal(/Token ?Creator"/u.test(iam.replace(/serviceAccountOpenIdTokenCreator/gu, "")), false);
});

test("no project-level or broad impersonation or public invocation grants exist", () => {
  const projectRoles = resourceBlocks(iam, "google_project_iam_member").map((block) => block.match(/role\s*=\s*"([^"]+)"/u)?.[1]);
  assert.deepEqual(projectRoles, ["roles/monitoring.metricWriter"]);
  for (const forbidden of ["google_project_iam_binding", "google_project_iam_policy", "google_service_account_iam_binding", "google_service_account_iam_policy"]) {
    assert.equal(iam.includes(forbidden), false, forbidden);
  }
  assert.equal(/allUsers|allAuthenticatedUsers/u.test(iam + cloudRun), false);
  const invokers = resourceBlocks(iam, "google_cloud_run_v2_service_iam_member");
  assert.equal(invokers.length, 1);
  assert.match(invokers[0], /role\s*=\s*"roles\/run\.invoker"/u);
  assert.match(invokers[0], /name\s*=\s*var\.cloud_run_service_name/u);
  assert.match(invokers[0], /google_service_account\.invoker\.email/u);
});

test("admission Worker audience equals the Cloud Run admission audience, not the origin audience", () => {
  const template = JSON.parse(read("deployment/admission-service.cloud-run-lab.template.jsonc")
    .split("\n").filter((line) => !line.trim().startsWith("//")).join("\n")) as {
    routes: Array<{ pattern: string }>; vars: Record<string, string>;
  };
  const audience = template.vars.GOOGLE_OIDC_AUDIENCE;
  assert.equal(audience, `https://${template.routes[0].pattern}`);
  assert.equal(audience.includes("ORIGIN"), false);

  const sample = "admission-lab.example.test";
  const workerAudience = audience.replace(template.routes[0].pattern, sample);
  const yamlAudience = read("deployment/cloud-run-lab.yaml").match(/LAB_ADMISSION_OIDC_AUDIENCE\n\s+value: (\S+)/u)?.[1];
  assert.equal(yamlAudience?.replace("ADMISSION_HOSTNAME", sample), workerAudience);
  assert.match(cloudRun, /name\s*=\s*"LAB_ADMISSION_OIDC_AUDIENCE"\s*\n\s*value\s*=\s*"https:\/\/\$\{var\.lab_admission_hostname\}"/u);
});

test("PostgreSQL stays private: no external address, subnet-only 5432, IAP-only 22", () => {
  assert.equal(/access_config/u.test(postgres), false);
  assert.equal(postgres.includes("0.0.0.0/0"), false);
  const firewalls = resourceBlocks(postgres, "google_compute_firewall");
  assert.equal(firewalls.length, 2);
  const database = firewalls.find((block) => block.includes('"5432"'))!;
  assert.match(database, /source_ranges\s*=\s*\[data\.google_compute_subnetwork\.lab\.ip_cidr_range\]/u);
  const ssh = firewalls.find((block) => block.includes('"22"'))!;
  assert.match(ssh, /source_ranges\s*=\s*\["35\.235\.240\.0\/20"\]/u);
  assert.match(postgres, /enable-oslogin\s*=\s*"TRUE"/u);
});

test("bootstrap authorizes both roles over TLS only, from the real subnet, with no embedded credentials", () => {
  assert.match(bootstrap, /^hostnossl all all 0\.0\.0\.0\/0 reject$/mu);
  assert.match(bootstrap, /^hostssl \$\{database_name\} \$\{database_user\} \$\{subnet_cidr\} scram-sha-256$/mu);
  assert.match(bootstrap, /^hostssl \$\{database_name\} \$\{migration_user\} \$\{subnet_cidr\} scram-sha-256$/mu);
  assert.equal(/10\.80\.0\.0/u.test(bootstrap), false);
  assert.equal(/\bPASSWORD\s+['"]|PGPASSWORD|BEGIN (RSA |EC )?PRIVATE KEY/iu.test(bootstrap), false);
  assert.equal(/^\s*(host|hostssl)\s+.*\btrust\b/mu.test(bootstrap), false);
  assert.match(bootstrap, /NOSUPERUSER NOCREATEDB NOCREATEROLE/u);
});

test("bootstrap exports only the public CA certificate and publishes nothing through metadata", () => {
  assert.equal(/guest-attributes|metadata\.google\.internal|curl/u.test(bootstrap), false);
  assert.equal(/guest-attributes/u.test(postgres), false);
  assert.match(bootstrap, /install -o root -g root -m 0644 "\$PG_CA_CERT" "\$PG_CA_PUBLIC_CERT"/u);
  assert.match(bootstrap, /chmod 0600 "\$PG_CA_KEY"/u);
  assert.match(bootstrap, /install -d -o postgres -g postgres -m 0700 "\$PG_TLS_DIR" "\$PG_CA_DIR"/u);
  // The CA key may be used by openssl for signing; it must never be echoed, copied or exposed.
  const keyUses = bootstrap.split("\n").filter((line) => line.includes("PG_CA_KEY") && !line.trim().startsWith("#"));
  for (const line of keyUses) {
    assert.equal(/\b(cat|cp|echo|curl|scp|base64|install)\b/u.test(line.replace(/^PG_CA_KEY=.*/u, "")), false, line);
  }
  assert.match(bootstrap, /LAB_CA_FINGERPRINT: \$\(openssl x509 -noout -fingerprint -sha256 -in "\$PG_CA_PUBLIC_CERT"\)/u);
});
