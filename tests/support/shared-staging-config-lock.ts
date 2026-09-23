import { open, unlink } from "node:fs/promises";
import { join } from "node:path";

// Gate 7A test-reliability fix. scripts/authority-staging-gate7-arm.ts (and
// several existing Gate 5 tests) must read/write the exact, contractually
// fixed rendered filenames in deployment/ -- there is no path override, by
// design (see F2/F3: the operator never chooses these paths). node:test runs
// separate test *files* in parallel by default (one process per file, up to
// os.availableParallelism()), so any two files that legitimately share one of
// these exact literal paths as a fixture race on the real filesystem. This
// lock (a simple lockfile mutex, exclusive-create + retry) serializes exactly
// that shared-path access across files/processes; it does not change,
// weaken, or bypass anything the tools under test themselves validate.

const lockPath = (root: string, name: string) => join(root, "deployment", `.gate57-lock-${name}`);

export async function withSharedStagingConfigLock<T>(root: string, name: string, fn: () => Promise<T>): Promise<T> {
  const path = lockPath(root, name);
  for (;;) {
    try {
      const handle = await open(path, "wx");
      await handle.close();
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }
  try { return await fn(); }
  finally { await unlink(path).catch(() => {}); }
}
