import { randomUUID } from "node:crypto";
import { open, readFile, unlink } from "node:fs/promises";
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
//
// Gate 7B: the lockfile now carries a random token. A holder may hand that
// token to a child test process via SHARED_STAGING_LOCK_TOKEN_ENV (used only
// by tests/gate7b-rendered-artifact-guard.test.ts, which runs the affected
// test files serially under --test-concurrency=1 while it holds the lock);
// the child then runs inside the parent's hold instead of deadlocking on it.
// A child never acquires or releases the parent's lockfile.

export const SHARED_STAGING_LOCK_TOKEN_ENV = "LIMITMARK_SHARED_STAGING_LOCK_TOKEN";

const lockPath = (root: string, name: string) => join(root, "deployment", `.gate57-lock-${name}`);

// Retry classification for the lockfile's exclusive create ONLY. EEXIST is an
// ordinary collision: another holder owns the lock, and it stays retryable
// with no bound, exactly as before (a legitimate holder can hold it for the
// whole Gate 7B artifact-survival run). On Windows, the same contention can
// also surface as EPERM/EACCES -- e.g. the previous holder's unlink() leaves
// the file delete-pending until its last handle closes, and an exclusive
// create against it fails with EPERM rather than EEXIST. Those two codes are
// retryable only on win32, and only for a bounded window of consecutive
// occurrences (WINDOWS_TRANSIENT_WINDOW_MS); a persistent EPERM/EACCES (a
// real permission problem) is rethrown unchanged. Any other code, on any
// platform, is rethrown immediately. Errors from every other operation (the
// token write, close, unlink, the inherited-token read) keep their existing
// handling and are never classified here.
export const WINDOWS_TRANSIENT_WINDOW_MS = 5_000;
const RETRY_DELAY_MS = 20;

export type LockRetryClass = "collision" | "windows-transient" | "fatal";

export function classifyLockAcquisitionError(error: unknown, platform: NodeJS.Platform = process.platform): LockRetryClass {
  const code = error !== null && typeof error === "object" ? (error as NodeJS.ErrnoException).code : undefined;
  if (code === "EEXIST") return "collision";
  if (platform === "win32" && (code === "EPERM" || code === "EACCES")) return "windows-transient";
  return "fatal";
}

type LockHandle = { writeFile(data: string): Promise<void>; close(): Promise<void> };
export type LockAcquisitionDeps = {
  openExclusive(path: string): Promise<LockHandle>;
  removeLock(path: string): Promise<void>;
  platform: NodeJS.Platform;
  now(): number;
  sleep(ms: number): Promise<void>;
};
const defaultDeps: LockAcquisitionDeps = {
  openExclusive: (path) => open(path, "wx"),
  removeLock: (path) => unlink(path),
  platform: process.platform,
  now: Date.now,
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

/** Creates the lockfile exclusively and writes `token` into it; exported for
 * the retry-classification tests, which inject a fake filesystem/platform. */
export async function acquireLockFile(path: string, token: string, deps: LockAcquisitionDeps = defaultDeps): Promise<void> {
  let transientSince: number | null = null;
  for (;;) {
    let handle: LockHandle;
    try { handle = await deps.openExclusive(path); }
    catch (error) {
      const kind = classifyLockAcquisitionError(error, deps.platform);
      if (kind === "fatal") throw error;
      if (kind === "collision") transientSince = null;
      else {
        transientSince ??= deps.now();
        if (deps.now() - transientSince > WINDOWS_TRANSIENT_WINDOW_MS) throw error;
      }
      await deps.sleep(RETRY_DELAY_MS);
      continue;
    }
    try { await handle.writeFile(token); }
    catch (error) { await handle.close(); await deps.removeLock(path).catch(() => {}); throw error; }
    await handle.close();
    return;
  }
}

export async function withSharedStagingConfigLock<T>(root: string, name: string, fn: (token: string) => Promise<T>): Promise<T> {
  const path = lockPath(root, name);
  const inherited = process.env[SHARED_STAGING_LOCK_TOKEN_ENV];
  if (inherited && await readFile(path, "utf8").then((value) => value === inherited, () => false)) return fn(inherited);
  const token = randomUUID();
  await acquireLockFile(path, token);
  try { return await fn(token); }
  finally { await unlink(path).catch(() => {}); }
}
