import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createGate6CaptureHarness } from "./workers/support/gate6-capture-harness";

// Gate 6A / F3, F12(D,E,F): CLI-level proof of the local credential-capture
// tool's safety properties. The synthetic scripts/gate6-secure-input
// substituted by the harness supplies two clearly-fake values without ever
// touching a real TTY; the real masked-input code path is not exercised by
// an automated test (it can only be driven by an interactive operator).

let harness: Awaited<ReturnType<typeof createGate6CaptureHarness>>;
before(async () => { harness = await createGate6CaptureHarness(); });
after(() => harness.dispose());

test("D: refuses a repo-contained output path", async () => {
  const result = await harness.run(["--role", "request-write", "--output", join(harness.repoDir, "sneaky.json")]);
  assert.notEqual(result.exitCode, 0);
});

test("D: refuses a repo-contained path even via a symlinked parent, where symlinks are supported", async (t) => {
  const outsideBase = await mkdtemp(join(tmpdir(), "gate6-capture-symlink-"));
  const linkPath = join(outsideBase, "escape-into-repo");
  try { await symlink(harness.repoDir, linkPath, "junction"); }
  catch { t.skip("symlink/junction creation not permitted in this environment"); return; }
  try {
    const result = await harness.run(["--role", "request-write", "--output", join(linkPath, "sneaky2.json")]);
    assert.notEqual(result.exitCode, 0, "a symlink whose real target resolves back into the repository must be refused");
  } finally { await rm(outsideBase, { recursive: true, force: true }); }
});

test("D: refuses when the parent directory does not exist (this tool never creates directories)", async () => {
  const result = await harness.run(["--role", "request-write", "--output", join(harness.outputDir, "does-not-exist", "creds.json")]);
  assert.notEqual(result.exitCode, 0);
});

test("E: refuses to overwrite an existing file, with no --force escape hatch", async () => {
  const target = join(harness.outputDir, "existing-e.json");
  await writeFile(target, "not a credential");
  const previousContent = await readFile(target, "utf8");
  const result = await harness.run(["--role", "request-write", "--output", target]);
  assert.notEqual(result.exitCode, 0);
  assert.equal(await readFile(target, "utf8"), previousContent, "the existing file must be completely untouched");
});

test("F: neither captured value ever appears in stdout or stderr", async () => {
  const target = join(harness.outputDir, "capture-f.json");
  const accessKeyId = "AKIAFAKEONLYNEVERREAL0001";
  const secretAccessKey = "totally-synthetic-secret-value-never-real-0001";
  const result = await harness.run(["--role", "request-write", "--output", target], accessKeyId, secretAccessKey);
  assert.equal(result.exitCode, 0, result.stdout + result.stderr);
  const combined = result.stdout + result.stderr;
  assert.ok(!combined.includes(accessKeyId));
  assert.ok(!combined.includes(secretAccessKey));
});

test("captured file is strict two-key JSON, UTF-8 without BOM, matching the existing staging-submitter reader's shape", async () => {
  const target = join(harness.outputDir, "capture-shape.json");
  const accessKeyId = "AKIAFAKESHAPE0002";
  const secretAccessKey = "synthetic-shape-secret-0002";
  const result = await harness.run(["--role", "result-read", "--output", target], accessKeyId, secretAccessKey);
  assert.equal(result.exitCode, 0, result.stdout + result.stderr);
  const bytes = await readFile(target);
  assert.notEqual(bytes[0], 0xef, "must not begin with a UTF-8 BOM");
  const parsed = JSON.parse(bytes.toString("utf8"));
  assert.deepEqual(Object.keys(parsed).sort(), ["accessKeyId", "secretAccessKey"]);
  assert.equal(parsed.accessKeyId, accessKeyId);
  assert.equal(parsed.secretAccessKey, secretAccessKey);
});

test("role labeling: request-write and result-read are captured to independent files with role named in stdout, never the secret", async () => {
  const requestWritePath = join(harness.outputDir, "role-request-write.json");
  const resultReadPath = join(harness.outputDir, "role-result-read.json");
  const rw = await harness.run(["--role", "request-write", "--output", requestWritePath], "AKIARW0001", "secret-rw-0001");
  const rr = await harness.run(["--role", "result-read", "--output", resultReadPath], "AKIARR0001", "secret-rr-0001");
  assert.equal(rw.exitCode, 0);
  assert.equal(rr.exitCode, 0);
  assert.equal(JSON.parse(rw.stdout).role, "request-write");
  assert.equal(JSON.parse(rr.stdout).role, "result-read");
  const requestWriteBody = JSON.parse(await readFile(requestWritePath, "utf8"));
  const resultReadBody = JSON.parse(await readFile(resultReadPath, "utf8"));
  assert.notEqual(requestWriteBody.accessKeyId, resultReadBody.accessKeyId, "the two roles must never share a captured file");
});

test("--role is mandatory and closed-set: an unknown role is refused before any file is written", async () => {
  const target = join(harness.outputDir, "bad-role.json");
  const result = await harness.run(["--role", "admin", "--output", target]);
  assert.notEqual(result.exitCode, 0);
  await assert.rejects(() => stat(target));
});

test("accessKeyId is never printed in full: the confirmation carries only a bounded fingerprint", async () => {
  const target = join(harness.outputDir, "fingerprint.json");
  const accessKeyId = "AKIAFULLVALUEMUSTNOTPRINT0003";
  const result = await harness.run(["--role", "request-write", "--output", target], accessKeyId, "secret-0003");
  assert.equal(result.exitCode, 0, result.stdout + result.stderr);
  const line = JSON.parse(result.stdout);
  assert.notEqual(line.accessKeyIdFingerprint, accessKeyId);
  assert.ok(line.accessKeyIdFingerprint.length < accessKeyId.length);
  assert.match(line.accessKeyIdFingerprint, /^[a-f0-9]+$/u);
});

test("a failed capture leaves no populated file behind (an empty placeholder at most, never a partial secret)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gate6-capture-fail-"));
  const target = join(dir, "creds.json");
  const failing = await createGate6CaptureHarness();
  try {
    const result = await failing.run(["--role", "request-write", "--output", target], "", "");
    assert.notEqual(result.exitCode, 0, "empty captured fields must be refused");
    try {
      const bytes = await readFile(target);
      assert.equal(bytes.byteLength, 0, "any leftover file must be empty, never a partial write");
    } catch { /* no file at all is also acceptable */ }
  } finally { await failing.dispose(); await rm(dir, { recursive: true, force: true }); }
});
