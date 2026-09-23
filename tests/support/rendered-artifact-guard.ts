import { lstat } from "node:fs/promises";
import { relative } from "node:path";
import type { TestContext } from "node:test";

// Gate 7B test-safety guard. Several Gate 4-7 tests use the exact,
// contractually fixed rendered staging filenames in deployment/ as synthetic
// fixtures (the tools under test accept no path override, by design). Those
// same filenames hold the operator's REAL rendered staging artifacts during a
// live gate. A test may therefore only write a fixture path it has first
// observed to be absent: if any listed path already exists (file, directory
// or symlink), the test is skipped without writing, moving, reading or
// deleting anything there. Existence is probed with lstat() only -- a
// pre-existing artifact's bytes are never opened, read, copied or printed;
// only its repository-relative path name (already public in this repository)
// appears in the skip reason. Any lstat() error other than ENOENT fails the
// test before it touches anything.
//
// Callers sharing a path with another test file must hold the shared lock
// (tests/support/shared-staging-config-lock.ts) around this call, so another
// test's in-progress synthetic fixture is never mistaken for an operator
// artifact and vice versa.

export async function preexistingFixturePaths(paths: readonly string[]): Promise<string[]> {
  const found: string[] = [];
  for (const path of paths) {
    try { await lstat(path); found.push(path); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
  return found;
}

export async function withAbsentFixturePaths(t: TestContext, root: string, paths: readonly string[], fn: () => Promise<void>): Promise<void> {
  const found = await preexistingFixturePaths(paths);
  if (found.length) {
    t.skip(`pre-existing rendered artifact(s) left untouched: ${found.map((path) => relative(root, path)).join(", ")}`);
    return;
  }
  await fn();
}
