import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const directory = "deployment/terraform/cloud-lab/";
const read = (name: string) => readFileSync(`${directory}${name}`, "utf8").replace(/\r\n/gu, "\n");
const renew = read("postgres-renew-cert.sh");
const bootstrap = read("postgres-bootstrap.sh");
const postgres = read("postgres.tf");
const code = (source: string) => source.split("\n").filter((line) => !line.trim().startsWith("#")).join("\n");

test("renewal validates the new pair before swapping and proves it is served, with rollback", () => {
  const validate = renew.indexOf("openssl verify -CAfile");
  const sanCheck = renew.indexOf("new certificate SAN mismatch");
  const keyMatch = renew.indexOf("new key does not match");
  const swap = renew.indexOf('mv -f "${PG_SERVER_KEY}.new"');
  assert.ok(validate > 0 && sanCheck > validate && keyMatch > sanCheck && swap > keyMatch, "all validation precedes the swap");
  assert.match(renew, /-starttls postgres[\s\S]*-verify_ip "\$INTERNAL_IP" -verify_return_error/u);
  assert.match(renew, /rollback\(\)/u);
  assert.match(renew, /if ! bash -c "\$RELOAD_CMD"; then[^\n]*rollback; exit 1/u);
  assert.match(renew, /not being served with a verified chain"; rollback; exit 1/u);
});

test("renewal reloads instead of restarting, never rotates the CA, and takes a lock", () => {
  assert.match(renew, /systemctl reload postgresql@/u);
  assert.equal(/systemctl (restart|stop)|pg_ctl (restart|stop)/u.test(code(renew)), false);
  assert.match(renew, /flock -n 9/u);
  assert.equal(/-newkey rsa:4096|req -x509/u.test(code(renew)), false, "renewal must not create or replace the CA");
  assert.equal(/CAkey[^\n]*(>|>>)|(>|>>)[^\n]*PG_CA_CERT/u.test(code(renew)), false);
});

test("the CA private key is only read by openssl signing and never copied, printed or logged", () => {
  const uses = code(renew).split("\n").filter((line) => line.includes("PG_CA_KEY"));
  assert.ok(uses.length >= 2);
  for (const line of uses.filter((entry) => !entry.startsWith("PG_CA_KEY="))) {
    assert.equal(/\b(cat|cp|echo|curl|scp|base64|install|logger|shred|tee|mv)\b/u.test(line.replace(/^\s*\[\[.*\]\]\s*\|\|.*$/u, "")), false, line);
  }
  assert.equal(/cat\s+"?\$\{?(PG_SERVER_KEY|WORK)[^\n]*key/u.test(code(renew)), false);
  assert.equal(/BEGIN [A-Z ]*PRIVATE KEY|PASSWORD|PGPASSWORD/u.test(renew), false);
  assert.match(renew, /shred -u/u, "temporary key material is shredded");
});

test("renews only when needed with a threshold that leaves daily retries inside the certificate lifetime", () => {
  const threshold = Number(renew.match(/RENEW_BEFORE_SECONDS="\$\{RENEW_BEFORE_SECONDS:-(\d+)\}"/u)?.[1]);
  const days = Number(renew.match(/SERVER_DAYS="\$\{SERVER_DAYS:-(\d+)\}"/u)?.[1]);
  assert.ok(threshold >= 7 * 86400 && threshold <= (days - 7) * 86400, `threshold ${threshold}s vs ${days}-day certificates`);
  assert.match(renew, /not due:/u);
  assert.match(renew, /SAN does not contain/u);
  assert.match(renew, /not chained to the laboratory CA/u);
});

test("bootstrap installs the script and a daily persistent timer; Terraform feeds it from the tested file", () => {
  assert.match(bootstrap, /<<'RENEW_SCRIPT'\n\$\{renew_script\}\nRENEW_SCRIPT/u);
  assert.match(bootstrap, /OnCalendar=daily/u);
  assert.match(bootstrap, /Persistent=true/u);
  assert.match(bootstrap, /systemctl enable --now limitmark-lab-cert-renew\.timer/u);
  assert.match(postgres, /renew_script\s*=\s*file\("\$\{path\.module\}\/postgres-renew-cert\.sh"\)/u);
  assert.match(read("test-renew-cert.sh"), /expired CA must fail closed/u);
});
