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
  assert.deepEqual([...files].sort(), ["README.md", "host-metrics.sh", "pins.env", "sut-bootstrap.sh", "sut-teardown.sh"]);
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
    const body = code(name).replace(/http:\/\/203\.0\.113\.10:3000/g, "<example>").replace(/--hostname 0\.0\.0\.0/g, "<bind>");
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
  assert.match(bootstrap, /\*\/0\) die/, "a /0 CIDR must be refused");
  assert.match(bootstrap, /Ubuntu only/);
  assert.match(bootstrap, /sha256sum --check/, "Node tarball must be digest-verified");
  assert.match(bootstrap, /--proto '=https'/);
  assert.match(bootstrap, /default deny incoming/);
  // The only hosts the script downloads from.
  const urls = [...bootstrap.matchAll(/https?:\/\/[^\s"'$)]+/g)].map((match) => match[0]);
  // The only other `http://` strings are a bash validation regex and a documentation example.
  for (const url of urls.filter((candidate) => !candidate.startsWith("http://(") && !candidate.startsWith("https://[") && !candidate.startsWith("http://203.0.113.10"))) {
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

test("pins.env holds only placeholders for digests, and the script refuses placeholders outside --dry-run", () => {
  const pins = text("pins.env");
  assert.match(pins, /^NODE_VERSION=\d+\.\d+\.\d+$/m);
  assert.match(pins, /NODE_SHA256_LINUX_X64=__REQUIRED_/);
  assert.match(pins, /NODE_SHA256_LINUX_ARM64=__REQUIRED_/);
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
