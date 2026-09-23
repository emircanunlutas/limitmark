import assert from "node:assert/strict";
import { access, copyFile, mkdtemp, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { isWithinPath, sameResolvedPath, selfTestWranglerSandbox, withWranglerSandbox, type WranglerSandbox } from "./support/wrangler-sandbox";

// Gate 7B regression: a broken Wrangler sandbox must never fall through to the
// wrapper under test or to the real provider CLI. Each sabotage case replaces
// the sandbox's fake Wrangler and then asks the sandbox to run a harmless
// probe script in place of a deploy wrapper: the self-test must refuse before
// the probe starts (probe marker absent) and before any substituted file runs
// (sabotage marker absent). Nothing here ever runs a deploy wrapper or the
// real Wrangler.

const root = fileURLToPath(new URL("../", import.meta.url));
const realWrangler = path.join(root, "node_modules", "wrangler", "bin", "wrangler.js");
const exists = (file: string) => access(file).then(() => true, () => false);

async function withProbe(fn: (probe: { script: string; marker: string; sabotageMarker: string }) => Promise<void>) {
  const directory = await mkdtemp(path.join(tmpdir(), "gate7b-probe-"));
  try {
    const script = path.join(directory, "probe.mjs");
    const marker = path.join(directory, "probe-ran");
    await writeFile(script, 'import { writeFileSync } from "node:fs"; writeFileSync(process.env.GATE7B_PROBE_MARKER, "ran");\n');
    await fn({ script, marker, sabotageMarker: path.join(directory, "sabotage-ran") });
  } finally { await rm(directory, { recursive: true, force: true }); }
}

async function assertRefusedBeforeAnythingRuns(sandbox: WranglerSandbox, probe: { script: string; marker: string; sabotageMarker: string }, reason: RegExp) {
  await assert.rejects(sandbox.runWrapper(probe.script, [], { GATE7B_PROBE_MARKER: probe.marker, GATE7B_SABOTAGE_MARKER: probe.sabotageMarker }), reason);
  assert.equal(await exists(probe.marker), false, "the wrapper under test must never start when the self-test fails");
  assert.equal(await exists(probe.sabotageMarker), false, "a substituted spawn target must never be executed");
}

test("healthy sandbox: the self-test passes and the probe runs with the sandbox as cwd", () =>
  withProbe((probe) => withWranglerSandbox(async (sandbox) => {
    const { result, wrangler } = await sandbox.runWrapper(probe.script, [], { GATE7B_PROBE_MARKER: probe.marker });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(await exists(probe.marker), true);
    assert.equal(wrangler, null, "the probe itself never invokes Wrangler");
  })));

test("broken sandbox: an altered fake Wrangler is refused before it or the wrapper runs", () =>
  withProbe((probe) => withWranglerSandbox(async (sandbox) => {
    await writeFile(sandbox.fakeWranglerPath, 'require("node:fs").writeFileSync(process.env.GATE7B_SABOTAGE_MARKER, "ran");\n');
    await assertRefusedBeforeAnythingRuns(sandbox, probe, /not the fake wrangler/u);
  })));

test("broken sandbox: a missing fake Wrangler is refused before the wrapper runs", () =>
  withProbe((probe) => withWranglerSandbox(async (sandbox) => {
    await rm(sandbox.fakeWranglerPath);
    await assertRefusedBeforeAnythingRuns(sandbox, probe, /fake wrangler missing/u);
  })));

test("broken sandbox: a byte copy of the real Wrangler at the pinned path is refused without being executed", () =>
  withProbe((probe) => withWranglerSandbox(async (sandbox) => {
    await copyFile(realWrangler, sandbox.fakeWranglerPath);
    await assertRefusedBeforeAnythingRuns(sandbox, probe, /not the fake wrangler/u);
  })));

test("broken sandbox: a junction/symlink making the pinned path resolve to the real Wrangler is refused", () =>
  withProbe((probe) => withWranglerSandbox(async (sandbox) => {
    // Replace <sandbox>/node_modules/wrangler with a directory junction (no
    // privilege needed on Windows; a directory symlink on POSIX) to the
    // repository's real node_modules/wrangler.
    const packageDir = path.dirname(path.dirname(sandbox.fakeWranglerPath));
    await rm(packageDir, { recursive: true, force: true });
    await symlink(path.dirname(path.dirname(realWrangler)), packageDir, "junction");
    try { await assertRefusedBeforeAnythingRuns(sandbox, probe, /resolves to the repository or its real Wrangler/u); }
    finally {
      // Remove only the link itself, before the sandbox's recursive cleanup,
      // so that cleanup can never traverse into the real package.
      await unlink(packageDir);
    }
    assert.equal(await exists(realWrangler), true, "the real Wrangler package must be untouched");
  })));

test("broken sandbox: a self-test without its record path refuses", () =>
  withWranglerSandbox(async (sandbox) => {
    await assert.rejects(selfTestWranglerSandbox(sandbox.root, {}), /no record path/u);
  }));

test("path comparison follows Windows semantics (case-insensitive, either separator, drive-rooted)", () => {
  const win = path.win32;
  assert.equal(sameResolvedPath("C:\\Repo\\node_modules\\wrangler\\bin\\wrangler.js", "c:/repo/NODE_MODULES/wrangler/bin/wrangler.js", win, true), true);
  assert.equal(sameResolvedPath("C:\\Repo\\a\\..\\wrangler.js", "C:\\Repo\\wrangler.js", win, true), true);
  assert.equal(sameResolvedPath("C:\\Repo\\wrangler.js", "D:\\Repo\\wrangler.js", win, true), false);
  assert.equal(isWithinPath("c:\\REPO\\node_modules\\x.js", "C:\\Repo", win, true), true);
  assert.equal(isWithinPath("C:\\Repo", "C:\\Repo", win, true), true);
  assert.equal(isWithinPath("C:\\Repo2\\x.js", "C:\\Repo", win, true), false);
  assert.equal(isWithinPath("C:\\Users\\x\\AppData\\Local\\Temp\\sbx\\wrangler.js", "C:\\Repo", win, true), false);
  assert.equal(isWithinPath("D:\\Repo\\x.js", "C:\\Repo", win, true), false);
});

test("path comparison follows POSIX semantics (case-sensitive, '/'-rooted)", () => {
  const posix = path.posix;
  assert.equal(sameResolvedPath("/repo/node_modules/wrangler/bin/wrangler.js", "/repo/x/../node_modules/wrangler/bin/wrangler.js", posix, false), true);
  assert.equal(sameResolvedPath("/repo/wrangler.js", "/Repo/wrangler.js", posix, false), false);
  assert.equal(isWithinPath("/repo/node_modules/x.js", "/repo", posix, false), true);
  assert.equal(isWithinPath("/repo/..hidden/x.js", "/repo", posix, false), true);
  assert.equal(isWithinPath("/repo-other/x.js", "/repo", posix, false), false);
  assert.equal(isWithinPath("/Repo/x.js", "/repo", posix, false), false);
  assert.equal(isWithinPath("/tmp/sbx/node_modules/wrangler/bin/wrangler.js", "/repo", posix, false), false);
});
