import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const manifestPath = "docs/architecture/m3-checkpoint.json";
const [mode = "--worktree", reviewedDigest, ...extra] = process.argv.slice(2);
const staged = mode === "--index";
const shaPattern = /^[a-f0-9]{64}$/u;
assert.ok((staged && shaPattern.test(reviewedDigest) || mode === "--worktree" && !reviewedDigest) && !extra.length,
  "Usage: node scripts/verify-m3-checkpoint.mjs [--worktree | --index <owner-reviewed manifest SHA-256>]");

const git = (...args) => execFileSync("git", args, { cwd: root });
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const normalize = (bytes) => Buffer.from(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes).replace(/\r\n/gu, "\n"));

function read(path) {
  if (staged) {
    assert.match(git("ls-files", "--stage", "--", path).toString(), /^100644 [a-f0-9]+ 0\t[^\n]+\n$/u, `Expected one regular index entry for ${path}`);
    const bytes = git("show", `:${path}`);
    assert.ok(bytes.equals(normalize(bytes)), `Expected LF bytes in index for ${path}`);
    return bytes;
  }
  const absolute = join(root, path);
  assert.ok(lstatSync(absolute).isFile(), `Expected a regular file at ${path}`);
  return normalize(readFileSync(absolute));
}

const manifestBytes = read(manifestPath);
const digest = hash(manifestBytes);
if (staged) assert.equal(digest, reviewedDigest, "Index manifest differs from the owner-reviewed manifest");
const manifest = JSON.parse(manifestBytes);
assert.equal(manifest.schemaVersion, 1);
assert.equal(manifest.status, "PENDING OWNER APPROVAL");
assert.equal(manifest.hashFormat, "sha256:utf8-lf");
assert.deepEqual(manifest.manifest, { path: manifestPath, change: "A", digest: "out-of-band" });
assert.match(manifest.baseCommit, /^[a-f0-9]{40}$/u);
assert.equal(git("rev-parse", "HEAD").toString().trim(), manifest.baseCommit, "Unexpected checkpoint base");

const expected = new Map([[manifestPath, "A"]]);
for (const { path, change, sha256 } of manifest.files) {
  assert.match(path, /^(?:[a-z0-9-]+\/)+[a-z0-9][a-z0-9.-]*$/u);
  assert.ok(!expected.has(path) && (change === "M" || change === "A"), `Invalid manifest entry for ${path}`);
  assert.match(sha256, shaPattern);
  assert.equal(hash(read(path)), sha256, `SHA-256 mismatch for ${path}`);
  expected.set(path, change);
}

const diff = staged ? ["--cached"] : [];
const entries = git("diff", ...diff, "--name-status", "--no-renames", "-z", manifest.baseCommit, "--").toString().split("\0");
assert.equal(entries.pop(), "");
const actual = new Map();
for (let i = 0; i < entries.length; i += 2) actual.set(entries[i + 1], entries[i]);
if (!staged) {
  assert.equal(git("diff", "--cached", "--name-only", "-z").length, 0, "Expected an empty index before owner approval");
  const untracked = new Set(git("ls-files", "--others", "--exclude-standard", "-z").toString().split("\0"));
  for (const [path, change] of expected) {
    if (change === "A" && untracked.has(path)) actual.set(path, "A");
  }
}
assert.deepEqual(actual, expected, "Checkpoint path set or change types differ from the manifest");
console.log(`${staged ? "Index" : "Working tree"}: ${expected.size} candidate paths verified against ${manifest.baseCommit}`);
console.log(`Manifest LF SHA-256: ${digest}`);
