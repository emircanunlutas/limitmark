import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { lstat, mkdir, mkdtemp, open, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { preexistingFixturePaths } from "./support/rendered-artifact-guard";
import { SHARED_STAGING_LOCK_TOKEN_ENV, withSharedStagingConfigLock } from "./support/shared-staging-config-lock";

// Gate 7B / F2 regression: the Gate 4-7 tests use the exact rendered staging
// filenames as synthetic fixtures. With a pre-existing artifact at every one
// of those paths, running all of those test files must leave each artifact's
// bytes unchanged (the affected tests skip instead of writing or deleting).
// The artifacts here are clearly synthetic sentinels created by this test
// only after proving each path absent; this test reads back only its own
// sentinels, and never runs if a real operator artifact is present.

const root = fileURLToPath(new URL("../", import.meta.url));

const exactRenderedPaths = [
  "admission-service.staging.jsonc",
  "operator-lifecycle-executor.staging.jsonc",
  "lifecycle-mailbox.staging.jsonc",
  "lifecycle-observer.staging.jsonc",
  "lifecycle-transport.staging.json",
  "lifecycle-mailbox.staging.armed.jsonc",
  "lifecycle-observer.staging.armed.jsonc",
].map((name) => join(root, "deployment", name));

const affectedTestFiles = [
  "tests/gate4-staging-admission-deploy.test.ts",
  "tests/gate5-deploy-wrapper.test.ts",
  "tests/gate5-staging-preflight.test.ts",
  "tests/gate6-staging-transport-preflight.test.ts",
  "tests/gate7-arm-render.test.ts",
  "tests/gate7-deploy-wrapper.test.ts",
  "tests/gate7-staging-preflight.test.ts",
];

test("pre-existing rendered staging artifacts survive every affected Gate 4-7 test file byte-for-byte", { timeout: 300_000 }, (t) =>
  withSharedStagingConfigLock(root, "shared-staging-render", async (token) => {
    const found = await preexistingFixturePaths(exactRenderedPaths);
    if (found.length) {
      t.skip(`real rendered artifact(s) present; regression not run: ${found.map((path) => basename(path)).join(", ")}`);
      return;
    }
    const sentinels = new Map<string, Buffer>();
    try {
      for (const path of exactRenderedPaths) {
        const bytes = Buffer.from(`gate7b-synthetic-sentinel-${randomBytes(16).toString("hex")}\n`);
        const handle = await open(path, "wx");
        try { await handle.writeFile(bytes); }
        finally { await handle.close(); }
        sentinels.set(path, bytes);
      }
      // The children run inside this test's lock hold (serially, so they never
      // race one another) instead of deadlocking on it. NODE_TEST_CONTEXT is
      // cleared so the nested runner reports normally rather than to this one.
      const env: NodeJS.ProcessEnv = { ...process.env, [SHARED_STAGING_LOCK_TOKEN_ENV]: token };
      delete env.NODE_TEST_CONTEXT;
      const child = spawnSync(process.execPath, ["node_modules/tsx/dist/cli.mjs", "--conditions=react-server", "--test",
        "--test-concurrency=1", "--test-reporter=tap", ...affectedTestFiles],
      { cwd: root, encoding: "utf8", env, timeout: 280_000 });
      assert.equal(child.status, 0, `${child.stdout.slice(-4_000)}\n${child.stderr.slice(-2_000)}`);
      assert.match(child.stdout, /^# fail 0$/mu);
      const skipped = Number(/^# skipped (\d+)$/mu.exec(child.stdout)?.[1] ?? 0);
      assert.ok(skipped > 0, "the affected fixture tests must have skipped");
      for (const path of exactRenderedPaths)
        assert.ok(child.stdout.includes(basename(path)), `a skip reason must name ${basename(path)}`);
      for (const [path, bytes] of sentinels)
        assert.deepEqual(await readFile(path), bytes, `${basename(path)} must survive unchanged`);
    } finally {
      for (const path of sentinels.keys()) await rm(path, { force: true });
    }
  }));

test("the fixture guard reports files, directories and dangling symlinks as present (lstat only)", async () => {
  const directory = await mkdtemp(join(tmpdir(), "gate7b-guard-"));
  try {
    const file = join(directory, "file.jsonc");
    const folder = join(directory, "folder.jsonc");
    const link = join(directory, "link.jsonc");
    const absent = join(directory, "absent.jsonc");
    await writeFile(file, "synthetic");
    await mkdir(folder);
    let linkCreated = true;
    try { await symlink(join(directory, "does-not-exist"), link); } catch { linkCreated = false; }
    const probe = [file, folder, absent, ...(linkCreated ? [link] : [])];
    assert.deepEqual(await preexistingFixturePaths(probe), [file, folder, ...(linkCreated ? [link] : [])]);
    // A dangling symlink is still reported present (lstat, not stat/open).
    if (linkCreated) assert.ok((await lstat(link)).isSymbolicLink());
  } finally { await rm(directory, { recursive: true, force: true }); }
});
