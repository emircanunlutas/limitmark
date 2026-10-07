import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

const directory = path.join(__dirname, "..", "lab", "bootstrap");
const files = readdirSync(directory);
const scripts = files.filter((name) => name.endsWith(".sh"));
const text = (name: string) => readFileSync(path.join(directory, name), "utf8");
/** Comments and blank lines are documentation; the executable body is what must be clean. */
const code = (name: string) => text(name).split("\n").filter((line) => !/^\s*#/.test(line)).join("\n");

test("the bootstrap directory contains exactly the reviewed files", () => {
  assert.deepEqual([...files].sort(), ["README.md", "host-metrics.sh", "lib-net.sh", "pins.env", "sut-bootstrap.sh", "sut-teardown.sh"]);
});

test("bootstrap scripts contain no provider CLI, provider API call, metadata access or remote mutation", () => {
  const forbidden: [string, RegExp][] = [
    ["gcloud", /\bgcloud\b/], ["gsutil", /\bgsutil\b/], ["bq", /\bbq\s/], ["aws", /\baws\s/], ["az", /\baz\s/], ["wrangler", /\bwrangler\b/], ["vercel", /\bvercel\b/],
    ["terraform", /\bterraform\b/], ["kubectl", /\bkubectl\b/], ["cloudflare", /cloudflare/i], ["resend", /\bresend\b/i], ["googleapis", /googleapis/i],
    ["metadata server", /metadata\.google|169\.254\.169\.254|\/computeMetadata/i], ["ssh-keygen", /ssh-keygen/], ["authorized_keys", /authorized_keys/],
    ["curl mutation", /curl[^\n]*\s(-X|--request)\s*(POST|PUT|PATCH|DELETE)/i], ["curl data", /curl[^\n]*\s(-d|--data\S*|-F|--form|-T|--upload-file)\b/],
    ["pipe to shell", /\|\s*(sudo\s+)?(ba)?sh\b/], ["eval of downloads", /\beval\b.*\$\(curl/], ["world-writable", /chmod\s+(-R\s+)?[0-7]*7[0-7]{0,2}\b\s/],
    ["open firewall", /0\.0\.0\.0\/0|::\/0|ufw\s+allow\s+(in\s+)?(3000|22|80|443|5432|55416|55417)(\/|\s|$)/], ["postgres exposure", /ufw\s+allow[^\n]*(5432|55416|55417)/],
    ["disable firewall", /ufw\s+(--force\s+)?disable/], ["docker socket exposure", /tcp:\/\/0\.0\.0\.0:2375|DOCKER_HOST/],
  ];
  for (const name of scripts) {
    const body = code(name);
    for (const [label, pattern] of forbidden) assert.doesNotMatch(body, pattern, `${name}: ${label}`);
  }
});

test("bootstrap scripts embed no credential, key, token, password or address", () => {
  const secrets: [string, RegExp][] = [
    ["private key", /-----BEGIN [A-Z ]*PRIVATE KEY-----/], ["aws key", /AKIA[0-9A-Z]{16}/], ["jwt", /eyJ[A-Za-z0-9_-]{10,}\./], ["bearer", /Bearer\s+[A-Za-z0-9._-]{8,}/i],
    ["password assignment", /(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY)\s*=\s*['"]?[^'"\s$_]{6,}/i], ["url credentials", /:\/\/[^\s/:@$]+:[^\s/@$]+@/],
    ["literal IPv4", /(?<![\d.])(\d{1,3}\.){3}\d{1,3}(?![\d.])/], ["long hex literal", /\b[0-9a-f]{40,}\b/],
  ];
  for (const name of scripts.concat("pins.env")) {
    // `203.0.113.10` appears only in a documentation example inside an error message.
    // The two pinned Node tarball SHA-256 digests in pins.env are public integrity values, not secrets.
    const body = code(name).replace(/http:\/\/203\.0\.113\.10:3000/g, "<example>").replace(/--hostname 0\.0\.0\.0/g, "<bind>")
      .replace(/^(NODE_SHA256_LINUX_(?:X64|ARM64))=[0-9a-f]{64}$/gm, "$1=<pinned-digest>");
    for (const [label, pattern] of secrets) assert.doesNotMatch(body, pattern, `${name}: ${label}`);
  }
});

test("bootstrap is reviewable and fail-closed: strict mode, explicit disposable acknowledgement, dry run, validated inputs", () => {
  for (const name of ["sut-bootstrap.sh", "sut-teardown.sh", "host-metrics.sh"]) {
    assert.match(text(name), /^#!\/usr\/bin\/env bash\n/, name);
    assert.match(code(name), /set -euo pipefail/, name);
  }
  for (const name of ["sut-bootstrap.sh", "sut-teardown.sh"]) {
    const body = code(name);
    assert.match(body, /--i-am-a-disposable-lab-vm/, name);
    assert.match(body, /--dry-run/, name);
    assert.match(body, /DRY_RUN/, name);
  }
  const bootstrap = code("sut-bootstrap.sh");
  for (const required of ["LAB_REPO_URL", "LAB_REPO_COMMIT", "LAB_APP_ORIGIN", "LAB_SSH_ALLOW_CIDRS", "LAB_LOADGEN_CIDRS"]) assert.match(bootstrap, new RegExp(`:\\s*"\\$\\{${required}:\\?`), required);
  assert.match(bootstrap, /\{40\}/, "commit must be pinned to a full SHA");
  assert.match(bootstrap, /cidr_list_check "\$LAB_SSH_ALLOW_CIDRS" "LAB_SSH_ALLOW_CIDRS" \|\| die/, "SSH CIDRs go through the strict validator");
  assert.match(bootstrap, /cidr_list_check "\$LAB_LOADGEN_CIDRS" "LAB_LOADGEN_CIDRS" \|\| die/, "load-generator CIDRs go through the strict validator");
  assert.match(bootstrap, /Ubuntu only/);
  assert.match(bootstrap, /sha256sum --check/, "Node tarball must be digest-verified");
  assert.match(bootstrap, /--proto '=https'/);
  assert.match(bootstrap, /default deny incoming/);
  // The only hosts the script downloads from.
  const urls = [...bootstrap.matchAll(/https?:\/\/[^\s"'$)]+/g)].map((match) => match[0]);
  // The only other `http://` strings are a bash validation regex and a documentation example.
  for (const url of urls.filter((candidate) => !candidate.startsWith("http://(") && !candidate.startsWith("https://[") && !candidate.startsWith("http://203.0.113.10") && !candidate.startsWith("http://localhost:3000/"))) {
    assert.match(url, /^https:\/\/nodejs\.org\/dist\//, url);
  }
  assert.doesNotMatch(bootstrap, /git clone/, "fetches an exact commit instead of cloning a moving branch");
});

test("every state-changing command in bootstrap and teardown goes through run() so --dry-run is complete", () => {
  for (const name of ["sut-bootstrap.sh", "sut-teardown.sh"]) {
    const mutating = /^\s*(apt-get|systemctl|ufw|useradd|usermod|userdel|install|ln|rm|tar|curl|docker|chmod|chown|mkdir|cp|mv|npm|git|runuser|env)\b/;
    const lines = code(name).split("\n");
    let insideHeredoc = false;
    lines.forEach((line, index) => {
      if (/<<\s*'?UNIT'?$|<<UNIT$/.test(line)) insideHeredoc = true;
      else if (insideHeredoc && line.trim() === "UNIT") insideHeredoc = false;
      if (insideHeredoc) return;
      if (mutating.test(line) && !/^\s*(run|echo)\b/.test(line) && !/^\s*(local\s)/.test(line)) {
        // `rm -f "$tarball"` etc. are allowed only inside the non-dry-run branch of install_node.
        assert.match(lines.slice(Math.max(0, index - 4), index + 1).join("\n"), /DRY_RUN|dry-run|else\n/, `${name}:${index + 1} bypasses run(): ${line.trim()}`);
      }
    });
  }
});

test("pins.env digests are each a real SHA-256 or a refused placeholder, and the script refuses placeholders outside --dry-run", () => {
  const pins = text("pins.env");
  assert.match(pins, /^NODE_VERSION=\d+\.\d+\.\d+$/m);
  const digest = (name: string) => new RegExp(`^${name}=(__REQUIRED_[A-Z0-9_]+__|[0-9a-f]{64})$`, "m").exec(pins)?.[1];
  const x64 = digest("NODE_SHA256_LINUX_X64");
  const arm64 = digest("NODE_SHA256_LINUX_ARM64");
  assert.ok(x64 && arm64, "each digest is a 64-hex SHA-256 or an explicit __REQUIRED_ placeholder");
  assert.notEqual(x64, arm64, "the two architectures cannot share a digest");
  assert.match(code("sut-bootstrap.sh"), /placeholder in pins\.env/);
});

test("the lab PostgreSQL is never opened by the firewall and the app unit carries no secret", () => {
  const bootstrap = code("sut-bootstrap.sh");
  assert.doesNotMatch(bootstrap, /5432|55416|55417/);
  const unit = bootstrap.slice(bootstrap.indexOf("[Unit]"), bootstrap.indexOf("[Install]"));
  assert.doesNotMatch(unit, /DATABASE_URL|CRON_SECRET|SECRET|KEY|TOKEN|PASSWORD|RESEND|TURNSTILE|CLOUDFLARE|VERCEL/i);
  assert.match(unit, /REQUEST_SUBMISSION_MODE=demo/);
  assert.match(unit, /ENABLE_PERSISTENT_SUBMISSIONS=false/);
  assert.match(unit, /NoNewPrivileges=true/);
  assert.match(unit, /User=\$\{LAB_USER\}/);
});

test("the metrics collector is bounded and records no addresses", () => {
  const body = code("host-metrics.sh");
  assert.match(body, /-le 3600/);
  assert.match(body, /-le 60/);
  assert.doesNotMatch(body, /\bss\s+-[a-z]*[tn][a-z]*p?\b(?!\s*\|\s*awk)/, "only the summary form of ss is used");
  assert.doesNotMatch(body, /\bnetstat\b|\bip\s+addr\b|\bhostname\b|\/etc\/passwd/);
});

test("all scripts pass bash -n", { skip: process.platform === "win32" && !hasBash() ? "bash not available" : false }, () => {
  for (const name of scripts) assert.doesNotThrow(() => execFileSync("bash", ["-n", path.join(directory, name)]), name);
});

function hasBash(): boolean {
  try { execFileSync("bash", ["--version"], { stdio: "ignore" }); return true; } catch { return false; }
}

// ---------------------------------------------------------------------------------------------- Codex F6 regressions
import { spawnSync } from "node:child_process";

const toBashPath = (file: string) => file.replace(/\\/g, "/");
const lib = toBashPath(path.join(directory, "lib-net.sh"));
const bashAvailable = hasBash();
const bashSkip = bashAvailable ? false : "bash not available";

/** Runs a snippet with lib-net.sh sourced. Returns the exit status and what the snippet printed. */
function bash(snippet: string): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync("bash", ["-c", `set -u; . "${lib}"; ${snippet}`], { encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

test("F6 regression: invalid CIDRs are refused (999.999.999.999/32 was accepted)", { skip: bashSkip }, () => {
  const invalid = [
    "999.999.999.999/32", "256.0.0.0/16", "1.2.3.256/32", "1.2.3/24", "1.2.3.4.5/32", "01.2.3.4/32", "1.02.3.4/32", "203.0.113.0/33", "203.0.113.0/", "203.0.113.0", "/24", "203.0.113.0/-1", "203.0.113.0/24x",
    "203.0.113.0/024", "abc/24", "203.0.113.0/2e1", "1.2.3.4/ 32", " 1.2.3.4/32", "1.2.3.4/32 ", "::1/128", "2001:db8::/32", "203.0.113.0/0", "0.0.0.0/0",
  ];
  for (const cidr of invalid) assert.notEqual(bash(`cidr_check '${cidr}'`).status, 0, cidr);
});

test("F6 regression: complementary broad networks that together cover all of IPv4 are refused (a bare /0 ban was not enough)", { skip: bashSkip }, () => {
  assert.notEqual(bash(`cidr_list_check '0.0.0.0/1,128.0.0.0/1' X`).status, 0);
  assert.notEqual(bash(`cidr_list_check '0.0.0.0/2,64.0.0.0/2,128.0.0.0/2,192.0.0.0/2' X`).status, 0);
  for (const cidr of ["0.0.0.0/1", "128.0.0.0/1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/15", "203.0.0.0/8"]) assert.notEqual(bash(`cidr_check '${cidr}'`).status, 0, cidr);
  // Sixteen /16s is still not "the world", but the list is bounded as well.
  const nine = Array.from({ length: 9 }, (_, index) => `198.${index}.0.0/16`).join(",");
  assert.notEqual(bash(`cidr_list_check '${nine}' X`).status, 0, "more than 8 entries");
  const eight = Array.from({ length: 8 }, (_, index) => `198.${index}.0.0/16`).join(",");
  assert.equal(bash(`cidr_list_check '${eight}' X`).status, 0);
});

test("F6: host bits, reserved ranges, empty entries and whitespace are refused; ordinary operator ranges pass", { skip: bashSkip }, () => {
  for (const cidr of ["203.0.113.7/24", "203.0.113.1/31", "198.51.100.128/24"]) assert.notEqual(bash(`cidr_check '${cidr}'`).status, 0, `host bits ${cidr}`);
  for (const cidr of ["0.0.0.0/32", "0.1.0.0/16", "127.0.0.1/32", "127.255.0.0/16", "169.254.0.0/16", "169.254.169.0/24", "224.0.0.0/24", "240.0.0.0/16", "255.255.255.255/32"]) {
    assert.notEqual(bash(`cidr_check '${cidr}'`).status, 0, `reserved ${cidr}`);
  }
  for (const list of ["", ",", "203.0.113.0/24,", ",203.0.113.0/24", "203.0.113.0/24,,198.51.100.0/24", "203.0.113.0/24, 198.51.100.0/24", "203.0.113.0/24 198.51.100.0/24"]) {
    assert.notEqual(bash(`cidr_list_check '${list}' X`).status, 0, JSON.stringify(list));
  }
  for (const cidr of ["203.0.113.0/24", "198.51.100.7/32", "192.0.0.0/16", "100.64.0.0/16", "10.20.0.0/16", "172.17.0.0/16"]) assert.equal(bash(`cidr_check '${cidr}'`).status, 0, cidr);
  assert.equal(bash(`cidr_list_check '203.0.113.0/24,198.51.100.7/32' X`).status, 0);
  // The refusal names the problem and never silently normalises.
  assert.match(bash(`cidr_check '203.0.113.7/24'`).stderr, /host bits are set/);
});

const UFW_STATUS = [
  "Status: active", "", "     To                         Action      From", "     --                         ------      ----",
  "[ 1] 22/tcp                     ALLOW IN    198.51.100.7               # limitmark-lab ssh",
  "[ 2] 80/tcp                     ALLOW IN    Anywhere                   # something else",
  "[ 3] 3000/tcp                   ALLOW IN    203.0.113.0/24             # limitmark-lab app",
  "[ 4] 3000/tcp                   ALLOW IN    192.0.2.0/24               # limitmark-lab app",
  "[ 5] 22/tcp                     ALLOW IN    192.0.2.0/24",
  "[10] 3000/tcp                   ALLOW IN    100.64.0.0/16              # limitmark-lab app", "",
].join("\n");

test("F6 regression: ufw rule numbers are parsed for single-digit AND two-digit numbering (the old awk lost `[ 1]`)", { skip: bashSkip }, () => {
  const numbers = bash(`ufw_lab_rule_numbers <<'STATUS'\n${UFW_STATUS}\nSTATUS`);
  assert.equal(numbers.status, 0);
  assert.deepEqual(numbers.stdout.trim().split("\n"), ["10", "4", "3", "1"], "every lab rule, highest first, and no foreign rule");
  const records = bash(`ufw_lab_rules <<'STATUS'\n${UFW_STATUS}\nSTATUS`).stdout.trim().split("\n");
  assert.deepEqual(records, ["1|22|198.51.100.7", "3|3000|203.0.113.0/24", "4|3000|192.0.2.0/24", "10|3000|100.64.0.0/16"]);
  // The pre-fix teardown extraction, for the record: `[ 1]` splits into "[" and "1]", so single-digit rules vanish.
  const legacy = spawnSync("bash", ["-c", `awk '/limitmark-lab/ {gsub(/[\\[\\]]/,"",$1); print $1}' <<'STATUS'\n${UFW_STATUS}\nSTATUS`], { encoding: "utf8" });
  assert.ok(!legacy.stdout.split("\n").some((line) => line === "1"), "the legacy parser dropped rule 1 (this is what the regression pins)");
});

test("F6 regression: rules for CIDRs that are no longer supplied are identified as stale; supplied ones are kept (a /32 is printed bare by ufw)", { skip: bashSkip }, () => {
  const stale = bash(`ufw_stale_lab_rule_numbers '22|198.51.100.7' '3000|203.0.113.0/24' <<'STATUS'\n${UFW_STATUS}\nSTATUS`);
  assert.deepEqual(stale.stdout.trim().split("\n"), ["10", "4"]);
  assert.equal(bash(`ufw_stale_lab_rule_numbers '22|198.51.100.7' '3000|203.0.113.0/24' '3000|192.0.2.0/24' '3000|100.64.0.0/16' <<'STATUS'\n${UFW_STATUS}\nSTATUS`).stdout.trim(), "");
  // Everything lab-tagged is stale when nothing is desired; foreign rules are never touched.
  assert.deepEqual(bash(`ufw_stale_lab_rule_numbers 'none|none' <<'STATUS'\n${UFW_STATUS}\nSTATUS`).stdout.trim().split("\n"), ["10", "4", "3", "1"]);
  assert.equal(bash(`ufw_normalize_cidr 198.51.100.7/32`).stdout.trim(), "198.51.100.7");
  assert.equal(bash(`ufw_normalize_cidr 203.0.113.0/24`).stdout.trim(), "203.0.113.0/24");
  // Same port, different source: a rule whose PORT matches but whose source changed is stale.
  assert.deepEqual(bash(`ufw_stale_lab_rule_numbers '3000|203.0.113.0/24' '22|198.51.100.7' <<'STATUS'\n${UFW_STATUS}\nSTATUS`).stdout.trim().split("\n"), ["10", "4"]);
});

const runOrder = (source: string) => {
  const section = source.slice(source.indexOf("# ---------------------------------------------------------------- run"));
  return section.split("\n").map((line) => line.trim()).filter((line) => /^[a-z_]+$/.test(line) || /^install_node$/.test(line));
};

test("F6 regression: the firewall is configured BEFORE the application is built or started, and the recovery marker is written before anything else", () => {
  const order = runOrder(text("sut-bootstrap.sh"));
  assert.deepEqual(order, ["write_marker", "install_packages", "install_node", "prepare_host", "configure_firewall", "build_application", "install_app_service", "install_metrics"]);
  assert.ok(order.indexOf("configure_firewall") < order.indexOf("install_app_service"), "port 3000 must never listen before the firewall is up");
});

test("F6 regression: a rebuilt or reconfigured application is RESTARTED and proven ready (`enable --now` does not restart a running service)", () => {
  const body = code("sut-bootstrap.sh");
  assert.match(body, /run systemctl restart limitmark-lab-app\.service/);
  assert.doesNotMatch(body, /enable --now limitmark-lab-app/);
  assert.match(body, /run systemctl enable limitmark-lab-app\.service/);
  assert.match(body, /verify_app_ready \|\| die "the application did not become ready after the restart"/);
  assert.match(body, /systemctl is-active --quiet limitmark-lab-app\.service && curl --fail/);
  assert.ok(body.indexOf("systemctl restart") > body.indexOf("daemon-reload"), "restart follows the unit rewrite");
});

test("F6 regression: stale lab firewall rules are removed after the desired rules are added (add first, then delete: never a window without SSH)", () => {
  const body = code("sut-bootstrap.sh");
  const firewall = body.slice(body.indexOf("configure_firewall() {"), body.indexOf("build_application() {"));
  assert.match(firewall, /ufw_stale_lab_rule_numbers "\$\{desired\[@\]\}"/);
  assert.ok(firewall.indexOf("ufw allow from") < firewall.indexOf("ufw_stale_lab_rule_numbers"), "desired rules first");
  assert.ok(firewall.indexOf("ufw_stale_lab_rule_numbers") < firewall.indexOf("ufw --force enable"));
  assert.match(firewall, /run ufw --force delete "\$number"/);
  assert.match(firewall, /desired\+=\("22\|\$\(ufw_normalize_cidr "\$cidr"\)"\)/);
  assert.match(firewall, /desired\+=\("3000\|\$\(ufw_normalize_cidr "\$cidr"\)"\)/);
});

test("F6 regression: an existing Node install is re-verified against digests recorded at install time, and lives where the service user cannot replace it", () => {
  const body = code("sut-bootstrap.sh");
  assert.match(body, /NODE_ROOT=\/opt\/limitmark-node/);
  assert.ok(!"/opt/limitmark-node".startsWith("/opt/limitmark-lab"), "outside the lab user's tree");
  assert.match(body, /node_install_verified\(\)/);
  assert.match(body, /sha256sum --check --quiet --strict "\$sums"/);
  assert.match(body, /find \. -type f \| wc -l/, "files that are not in the recorded manifest are also refused");
  assert.match(body, /chown -R root:root "\$target"/);
  assert.match(body, /tar -xJf "\$tarball" -C "\$NODE_ROOT" --no-same-owner/);
  assert.match(body, /Node tarball digest mismatch/);
  assert.doesNotMatch(body, /\[ -x "\$target\/bin\/node" \] && \[ "\$\("\$target\/bin\/node" --version\)" = "v\$\{NODE_VERSION\}" \]; then/, "a version string alone is no longer accepted as integrity");
  assert.doesNotMatch(body, /\$LAB_ROOT\/node-v/);
});

test("F6 regression: teardown reports every failure, keeps the recovery marker when anything failed, and only removes lab-labelled resources", () => {
  const body = code("sut-teardown.sh");
  assert.doesNotMatch(body, /\|\| true/, "no failure is suppressed");
  assert.doesNotMatch(body, /\|\| \{ *:|2>\/dev\/null \|\| true/);
  assert.match(body, /FAILURES\+=\("\$\*"\)/);
  assert.match(body, /INCOMPLETE: %d step\(s\) failed; the recovery marker %s\/DISPOSABLE was KEPT/);
  const exitIncomplete = body.indexOf("exit 1");
  assert.ok(exitIncomplete > 0 && exitIncomplete < body.indexOf('run rm -rf "$STATE_DIR"'), "the state directory (and marker) is removed only after the failure check");
  const library = code("lib-net.sh");
  assert.match(library, /label_of()/);
  assert.match(library, /[ "$(label_of "$name")" = disposable ]/);
  assert.match(library, /network_label_of limitmark-lab_lab/);
  assert.match(body, /ufw_lab_rule_numbers/);
  assert.match(body, /\. "\$SCRIPT_DIR\/lib-net\.sh"/);
  assert.match(body, /limitmark-lab-disposable-v1/);
  // Only symlinks that point into the lab's own Node tree are removed.
  assert.match(body, /readlink "\$link"/);
});

test("F6: the recovery marker has content that teardown verifies, and is never created after other state", () => {
  assert.match(code("sut-bootstrap.sh"), /printf 'limitmark-lab-disposable-v1\\n' > "\$STATE_DIR\/DISPOSABLE"/);
  assert.doesNotMatch(code("sut-bootstrap.sh"), /install -m 0644 \/dev\/null "\$STATE_DIR\/DISPOSABLE"/);
});

test("F6: teardown --dry-run lists every step without executing and says the marker is conditional", { skip: bashSkip }, () => {
  const result = spawnSync("bash", [toBashPath(path.join(directory, "sut-teardown.sh")), "--i-am-a-disposable-lab-vm", "--dry-run"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /remove limitmark-lab-pg16 only if it carries the limitmark\.lab=disposable label/);
  assert.match(result.stdout, /delete every ufw rule carrying the limitmark-lab comment, highest number first/);
  assert.match(result.stdout, /only if every step above succeeded/);
  assert.doesNotMatch(result.stdout + result.stderr, /FAILED/);
});

test("F6: on Linux the bootstrap dry run validates CIDRs before any action and prints the new order, restart and stale-rule steps", { skip: process.platform === "linux" ? false : "the bootstrap refuses to run anywhere but Linux; exercised in the Linux parity container" }, () => {
  const environment = { PATH: process.env.PATH ?? "", LAB_REPO_URL: "https://example.invalid/repo", LAB_REPO_COMMIT: "a".repeat(40), LAB_APP_ORIGIN: "http://203.0.113.10:3000", LAB_SSH_ALLOW_CIDRS: "198.51.100.0/24", LAB_LOADGEN_CIDRS: "203.0.113.0/24" };
  const run = (override: Record<string, string>) => spawnSync("bash", [toBashPath(path.join(directory, "sut-bootstrap.sh")), "--i-am-a-disposable-lab-vm", "--dry-run"], { encoding: "utf8", env: { ...environment, ...override } as unknown as NodeJS.ProcessEnv });
  const ok = run({});
  assert.equal(ok.status, 0, ok.stderr);
  const lines = ok.stdout.split("\n");
  const at = (pattern: RegExp) => lines.findIndex((line) => pattern.test(line));
  assert.ok(at(/ufw allow from 203\.0\.113\.0\/24 to any port 3000/) > 0);
  assert.ok(at(/delete every limitmark-lab ufw rule whose port and source are not in/) > at(/ufw allow from 203\.0\.113\.0\/24/));
  assert.ok(at(/ufw --force enable/) < at(/npm ci --no-audit/), "firewall before the build");
  assert.ok(at(/systemctl restart limitmark-lab-app\.service/) > at(/write \/etc\/systemd\/system\/limitmark-lab-app\.service/));
  assert.ok(at(/write \/etc\/limitmark-lab\/DISPOSABLE/) < at(/apt-get update/), "marker first");
  for (const bad of ["999.999.999.999/32", "0.0.0.0/1,128.0.0.0/1", "203.0.113.7/24", "10.0.0.0/8", "203.0.113.0/24,"]) {
    for (const key of ["LAB_SSH_ALLOW_CIDRS", "LAB_LOADGEN_CIDRS"]) {
      const refused = run({ [key]: bad });
      assert.equal(refused.status, 2, `${key}=${bad}`);
      assert.doesNotMatch(refused.stdout, /\[dry-run\]/, "refusal precedes every action");
    }
  }
  const badOrigin = run({ LAB_APP_ORIGIN: "http://999.1.1.1:3000" });
  assert.equal(badOrigin.status, 2);
});

// ---------------------------------------------------------------------------------------------- F4: the build context is a confidentiality boundary
test("F4: the image restates the one non-secret git setting that the excluded .git/config contributed", () => {
  const dockerfile = readFileSync(path.join(__dirname, "..", "lab", "linux", "Dockerfile"), "utf8");
  assert.match(dockerfile, /git config --system core\.filemode false/);
  assert.doesNotMatch(dockerfile, /COPY[^\n]*\.git\/config|credential\.helper|http\.extraheader|url\.[^\n]*insteadOf/i);
});

test("F4: the parity image's build context excludes everything .gitignore lists AND every credential pattern (gitignore is not the boundary)", () => {
  const dockerignore = readFileSync(path.join(__dirname, "..", "lab", "linux", "Dockerfile.dockerignore"), "utf8").split("\n").map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
  const normalise = (entry: string) => entry.replace(/^\/+/, "").replace(/\/+$/, "");
  const ignored = new Set(dockerignore.map(normalise));
  const gitignore = readFileSync(path.join(__dirname, "..", ".gitignore"), "utf8").split("\n").map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
  for (const entry of gitignore) assert.ok(ignored.has(normalise(entry)), `.gitignore entry ${entry} is not excluded from the build context`);
  for (const pattern of [
    "**/.env*", "!**/.env.example", "**/.dev.vars*", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/id_rsa*", "**/id_ed25519*", "**/.ssh", "**/.aws", "**/.azure", "**/.gcloud", "**/.config/gcloud",
    "**/.docker", "**/.kube", "**/.netrc", "**/.pgpass", "**/.git-credentials", "**/*.tfstate", "**/*.tfvars", "**/service-account*.json", ".git/config", ".git/hooks", "artifacts", "node_modules",
  ]) assert.ok(ignored.has(pattern), `${pattern} missing from Dockerfile.dockerignore`);
  // Nothing tracked by git is excluded by the credential patterns (the image must still build and test).
  const tracked = execFileSync("git", ["ls-files"], { cwd: path.join(__dirname, ".."), encoding: "utf8" }).split("\n").filter(Boolean);
  const credentialLike = /\.(pem|key|p12|pfx|jks|keystore|kdbx|tfvars|tfstate)$|(^|\/)\.(ssh|gnupg|aws|azure|gcloud|docker|kube|netrc|pgpass|vercel|cloudflared)(\/|$)|(^|\/)id_(rsa|dsa|ecdsa|ed25519)|service-account|client_secret|(^|\/)credentials\.json$|\.dev\.vars/;
  assert.deepEqual(tracked.filter((file) => credentialLike.test(file)), []);
});

test("F6 (probe finding): only lines carrying the EXACT lab comment tags are treated as lab firewall rules", { skip: bashSkip }, () => {
  const status = [
    "[ 1] 22/tcp                     ALLOW IN    198.51.100.7               # limitmark-lab ssh",
    "[ 2] 22/tcp                     ALLOW IN    192.0.2.0/24               # limitmark-labx ssh",
    "[ 3] 3000/tcp                   ALLOW IN    192.0.2.0/24               # limitmark-lab-other app",
    "[ 4] 3000/tcp                   ALLOW IN    192.0.2.0/24               # not limitmark-lab app",
    "[ 5] 3000/tcp                   ALLOW IN    203.0.113.0/24             # limitmark-lab app",
  ].join("\n");
  assert.deepEqual(bash(`ufw_lab_rule_numbers <<'STATUS'\n${status}\nSTATUS`).stdout.trim().split("\n"), ["5", "1"]);
});

test("F6 (probe finding): dry-run lines are single readable lines (IFS is a newline in these scripts)", { skip: bashSkip }, () => {
  const result = spawnSync("bash", [toBashPath(path.join(directory, "sut-teardown.sh")), "--i-am-a-disposable-lab-vm", "--dry-run"], { encoding: "utf8" });
  assert.match(result.stdout, /^\[dry-run\] systemctl disable --now limitmark-lab-app\.service$/m);
  assert.match(result.stdout, /^\[dry-run\] rm -rf \/opt\/limitmark-lab$/m);
});

// ---------------------------------------------------------------------------------------------- round 2: UNKNOWN is never ABSENT
import { chmodSync, mkdtempSync, rmSync as removeTree, writeFileSync as writeText } from "node:fs";
import os from "node:os";

/** A fake `docker` on PATH. FAKE_DOCKER_MODE: down (every command fails) | flaky (info ok, listings fail) | empty | foreign | lab. */
function withFakeDocker<T>(mode: string, body: (environment: NodeJS.ProcessEnv, logFile: string) => T): T {
  const folder = mkdtempSync(path.join(os.tmpdir(), "fake-docker-"));
  const logFile = path.join(folder, "calls.log");
  const script = [
    "#!/usr/bin/env bash",
    `echo "$*" >> "${toBashPath(logFile)}"`,
    'case "$FAKE_DOCKER_MODE" in down) exit 1 ;; esac',
    'case "$1" in',
    "  info) exit 0 ;;",
    '  ps) case "$FAKE_DOCKER_MODE" in flaky) exit 1 ;; empty) exit 0 ;; *) echo limitmark-lab-pg16 ;; esac ;;',
    '  network) case "$2" in ls) [ "$FAKE_DOCKER_MODE" = flaky ] && exit 1; exit 0 ;; inspect) exit 1 ;; *) exit 0 ;; esac ;;',
    '  inspect) if [ "$FAKE_DOCKER_MODE" = lab ]; then echo disposable; else echo ""; fi ;;',
    "  rm) exit 0 ;;",
    "esac",
  ].join("\n");
  writeText(path.join(folder, "docker"), `${script}\n`);
  try { chmodSync(path.join(folder, "docker"), 0o755); } catch { /* best effort on Windows */ }
  try { return body({ ...process.env, PATH: `${toBashPath(folder)}:${process.env.PATH ?? ""}`, FAKE_DOCKER_MODE: mode } as NodeJS.ProcessEnv, logFile); }
  finally { removeTree(folder, { recursive: true, force: true }); }
}

function runTeardownFunction(environment: NodeJS.ProcessEnv): { status: number | null; stdout: string; stderr: string } {
  const snippet = `set -u; . "${lib}"; FAILURES=(); log() { :; }; run() { "$@" || FAILURES+=("$*"); }; teardown_lab_containers; echo "failures=\${#FAILURES[@]}"`;
  const result = spawnSync("bash", ["-c", snippet], { encoding: "utf8", env: environment });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

test("F6 round 2 regression: an unreachable Docker daemon is a FAILURE (recovery state kept), never 'there are no containers'", { skip: bashSkip }, () => {
  withFakeDocker("down", (environment, logFile) => {
    const result = runTeardownFunction(environment);
    assert.match(result.stdout, /failures=1/);
    assert.match(result.stderr, /daemon is unreachable.*unknown is not absent/);
    assert.doesNotMatch(readFileSync(logFile, "utf8"), /\brm\b/, "nothing is removed on a guess");
  });
  // docker_cli_state distinguishes the three worlds.
  withFakeDocker("down", (environment) => assert.equal(spawnSync("bash", ["-c", `. "${lib}"; docker_cli_state`], { encoding: "utf8", env: environment }).stdout.trim(), "down"));
  withFakeDocker("empty", (environment) => assert.equal(spawnSync("bash", ["-c", `. "${lib}"; docker_cli_state`], { encoding: "utf8", env: environment }).stdout.trim(), "up"));
  const bare = spawnSync("bash", ["-c", `PATH=/usr/bin:/bin; . "${lib}"; docker_cli_state`], { encoding: "utf8" });
  assert.equal(bare.stdout.trim(), "no-cli");
});

test("F6 round 2 regression: a daemon that dies mid-teardown (listing fails) is UNKNOWN per object and a failure, not absence", { skip: bashSkip }, () => {
  withFakeDocker("flaky", (environment, logFile) => {
    const result = runTeardownFunction(environment);
    const failures = Number(/failures=(\d+)/.exec(result.stdout)?.[1]);
    assert.equal(failures, 4, "three containers and the network could not be determined");
    assert.match(result.stderr, /could not determine whether container limitmark-lab-pg16 exists/);
    assert.match(result.stderr, /could not determine whether network limitmark-lab_lab exists/);
    assert.doesNotMatch(readFileSync(logFile, "utf8"), /\brm\b/);
  });
});

test("F6 round 2: with a healthy daemon, absence is absence, a foreign container is left alone as a failure, and a lab-labelled one is removed", { skip: bashSkip }, () => {
  withFakeDocker("empty", (environment) => assert.match(runTeardownFunction(environment).stdout, /failures=0/));
  withFakeDocker("foreign", (environment, logFile) => {
    const result = runTeardownFunction(environment);
    assert.match(result.stdout, /failures=3/);
    assert.match(result.stderr, /exists but its lab label could not be confirmed/);
    assert.doesNotMatch(readFileSync(logFile, "utf8"), /\brm -f/);
  });
  withFakeDocker("lab", (environment, logFile) => {
    assert.match(runTeardownFunction(environment).stdout, /failures=0/);
    assert.match(readFileSync(logFile, "utf8"), /rm -f -v limitmark-lab-pg16/);
  });
});

test("F6 round 2: teardown uses only the state-aware container path, and its dry run states the daemon rule", { skip: bashSkip }, () => {
  const body = code("sut-teardown.sh");
  assert.match(body, /teardown_lab_containers/);
  assert.doesNotMatch(body, /docker_available|docker inspect --type container "\$name" >\/dev\/null 2>&1/);
  assert.match(code("lib-net.sh"), /docker_object_state\(\)/);
  const dry = spawnSync("bash", [toBashPath(path.join(directory, "sut-teardown.sh")), "--i-am-a-disposable-lab-vm", "--dry-run"], { encoding: "utf8" });
  assert.match(dry.stdout, /unreachable docker daemon is a FAILURE/);
});

// ---------------------------------------------------------------------------------------------- --ba0-field (external L7 readiness)
//
// The field mode prepares the VM for ONE BA0 level: the old Next service is retired, port 3000 gets no rule (and an old one is removed), the
// firewall allows exactly one reviewed port from exactly one /32, and the lab user gets one read-only privilege. These tests run the REAL script in
// --dry-run (with `uname` answering Linux so a Windows Git Bash can parse it) and read what it would do.

const scriptPath = toBashPath(path.join(directory, "sut-bootstrap.sh"));
const FIELD_ENV = {
  LAB_REPO_URL: "https://example.test/lab/repo", LAB_REPO_COMMIT: "a".repeat(40), LAB_SSH_ALLOW_CIDRS: "198.51.100.0/24", LAB_LOADGEN_CIDRS: "203.0.113.9/32", LAB_BA0_PLANE_PORT: "8080",
};

function dryRun(args: string[], env: Record<string, string | undefined>): { status: number | null; out: string } {
  const wrapper = `uname() { if [ "$1" = "-s" ]; then echo Linux; else command uname "$@"; fi; }; export -f uname; bash "${scriptPath}" ${args.join(" ")}`;
  const clean = Object.fromEntries(Object.entries({ ...process.env, ...env }).filter(([, value]) => value !== undefined)) as Record<string, string>;
  for (const key of Object.keys(env)) if (env[key] === undefined) delete clean[key];
  const result = spawnSync("bash", ["-c", wrapper], { encoding: "utf8", env: clean as NodeJS.ProcessEnv, timeout: 30_000 });
  return { status: result.status, out: `${result.stdout}${result.stderr}` };
}

test("--ba0-field dry run: retires the old service, adds NO port-3000 rule, allows exactly the reviewed port from the single /32, installs the one read-only privilege, builds nothing for Next", { skip: bashSkip }, () => {
  const result = dryRun(["--i-am-a-disposable-lab-vm", "--dry-run", "--ba0-field"], FIELD_ENV);
  assert.equal(result.status, 0, result.out);
  assert.match(result.out, /\[dry-run\] ufw allow from 203\.0\.113\.9\/32 to any port 8080 proto tcp comment limitmark-lab ba0 plane/);
  assert.match(result.out, /\[dry-run\] ufw allow from 198\.51\.100\.0\/24 to any port 22 proto tcp comment limitmark-lab ssh/);
  assert.doesNotMatch(result.out, /port 3000|limitmark-lab app/, "no old-application firewall rule is added in field mode");
  assert.match(result.out, /\[dry-run\] systemctl disable --now limitmark-lab-app\.service/);
  assert.match(result.out, /\[dry-run\] rm -f \/etc\/systemd\/system\/limitmark-lab-app\.service/);
  assert.match(result.out, /prove the old application service is not active/);
  assert.match(result.out, /write \/etc\/sudoers\.d\/limitmark-lab-ba0 allowing only: \/usr\/sbin\/ufw status numbered/);
  assert.doesNotMatch(result.out, /npm run build/, "the BA0 runner runs from source; no Next build is made");
  assert.match(result.out, /npm ci --no-audit --no-fund/);
  assert.doesNotMatch(result.out, /systemctl (enable|restart) limitmark-lab-app/, "the old application is never started in field mode");
  assert.match(result.out, /delete every limitmark-lab ufw rule whose port and source are not in: 22\|198\.51\.100\.0\/24\s+8080\|203\.0\.113\.9/, "an old port-3000 rule is stale, so it is deleted");
});

test("without --ba0-field the dry run is unchanged: the port-3000 rule is added and the application unit is installed", { skip: bashSkip }, () => {
  const result = dryRun(["--i-am-a-disposable-lab-vm", "--dry-run"], { ...FIELD_ENV, LAB_APP_ORIGIN: "http://203.0.113.10:3000", LAB_LOADGEN_CIDRS: "203.0.113.0/24", LAB_BA0_PLANE_PORT: undefined });
  assert.equal(result.status, 0, result.out);
  assert.match(result.out, /ufw allow from 203\.0\.113\.0\/24 to any port 3000 proto tcp comment limitmark-lab app/);
  assert.doesNotMatch(result.out, /ba0 plane|sudoers/);
  assert.match(result.out, /npm run build/);
  assert.match(result.out, /systemctl restart limitmark-lab-app\.service/);
});

test("--ba0-field refuses anything but ONE reviewed port from ONE /32: a network, two hosts, the old application port, a database port, a standard port, a missing port", { skip: bashSkip }, () => {
  const refused = (overrides: Record<string, string | undefined>, pattern: RegExp) => {
    const result = dryRun(["--i-am-a-disposable-lab-vm", "--dry-run", "--ba0-field"], { ...FIELD_ENV, ...overrides });
    assert.notEqual(result.status, 0, JSON.stringify(overrides));
    assert.match(result.out, pattern, JSON.stringify(overrides));
  };
  refused({ LAB_LOADGEN_CIDRS: "203.0.113.0/24" }, /exactly one \/32/);
  refused({ LAB_LOADGEN_CIDRS: "203.0.113.9/32,203.0.113.10/32" }, /exactly one \/32/);
  refused({ LAB_LOADGEN_CIDRS: "203.0.113.9" }, /invalid LAB_LOADGEN_CIDRS/);
  for (const port of ["3000", "5432", "55416", "55417", "22", "80", "443", "7999", "9000", "08080", "80800", "abc", ""]) refused({ LAB_BA0_PLANE_PORT: port }, /LAB_BA0_PLANE_PORT/);
  refused({ LAB_BA0_PLANE_PORT: undefined }, /LAB_BA0_PLANE_PORT is required/);
  refused({ LAB_LOADGEN_CIDRS: "127.0.0.1/32" }, /invalid LAB_LOADGEN_CIDRS/);
});

test("--ba0-field in the script: no port-3000 rule in its branch, no database port anywhere, one read-only sudoers command validated by visudo, retired service proven inactive", () => {
  const body = code("sut-bootstrap.sh");
  const firewall = body.slice(body.indexOf("configure_firewall() {"), body.indexOf("build_application() {"));
  const fieldBranch = firewall.slice(firewall.indexOf('if [ "$BA0_FIELD" = 1 ]; then'), firewall.indexOf("else\n      run ufw allow from"));
  assert.match(fieldBranch, /port "\$LAB_BA0_PLANE_PORT" proto tcp comment 'limitmark-lab ba0 plane'/);
  assert.doesNotMatch(fieldBranch, /3000/);
  assert.match(body, /ALL=\(root\) NOPASSWD: \/usr\/sbin\/ufw status numbered\\n' "\$LAB_USER"/, "exactly one command");
  assert.doesNotMatch(body, /NOPASSWD: ALL|NOPASSWD:\s*\/usr\/sbin\/ufw\s*$|NOPASSWD:[^\n]*\*/m, "no wildcard, no blanket privilege");
  assert.match(body, /visudo -cf "\$tmp"/, "the fragment is validated before it is installed");
  assert.match(body, /install -m 0440 -o root -g root "\$tmp" "\$fragment"/);
  assert.match(body, /systemctl is-active --quiet limitmark-lab-app\.service\; then die "the old application service is still active"|systemctl is-active --quiet limitmark-lab-app\.service; then die "the old application service is still active"/);
  assert.match(body, /\^8\[0-9\]\{3\}\$/, "the plane port is confined to 8000..8999");
  assert.doesNotMatch(body, /5432|55416|55417/);
  const teardown = code("sut-teardown.sh");
  assert.match(teardown, /run rm -f \/etc\/sudoers\.d\/limitmark-lab-ba0/, "teardown removes the privilege this mode granted");
});

test("the ba0 plane firewall rule is a lab rule: teardown deletes it, and a changed source or port makes the old one stale", { skip: bashSkip }, () => {
  const status = [
    "Status: active", "",
    "[ 1] 22/tcp                     ALLOW IN    198.51.100.7               # limitmark-lab ssh",
    "[ 2] 8080/tcp                   ALLOW IN    203.0.113.9                # limitmark-lab ba0 plane",
    "[ 3] 3000/tcp                   ALLOW IN    203.0.113.0/24             # limitmark-lab app",
    "[ 4] 8080/tcp                   ALLOW IN    192.0.2.0/24               # not ours", "",
  ].join("\n");
  assert.deepEqual(bash(`ufw_lab_rules <<'STATUS'\n${status}\nSTATUS`).stdout.trim().split("\n"), ["1|22|198.51.100.7", "2|8080|203.0.113.9", "3|3000|203.0.113.0/24"]);
  assert.deepEqual(bash(`ufw_lab_rule_numbers <<'STATUS'\n${status}\nSTATUS`).stdout.trim().split("\n"), ["3", "2", "1"], "teardown removes every lab rule, highest first, and never the foreign one");
  assert.deepEqual(bash(`ufw_stale_lab_rule_numbers '22|198.51.100.7' '8080|203.0.113.9' <<'STATUS'\n${status}\nSTATUS`).stdout.trim().split("\n"), ["3"], "the old port-3000 rule is stale in field mode");
  assert.deepEqual(bash(`ufw_stale_lab_rule_numbers '22|198.51.100.7' '8080|203.0.113.77' <<'STATUS'\n${status}\nSTATUS`).stdout.trim().split("\n"), ["3", "2"], "a changed generator host makes the old plane rule stale");
});
