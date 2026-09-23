import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  WINDOWS_TRANSIENT_WINDOW_MS, acquireLockFile, classifyLockAcquisitionError, withSharedStagingConfigLock,
  type LockAcquisitionDeps,
} from "./support/shared-staging-config-lock";

// Gate 7B: the shared-lock retry classification. Every case except the last
// runs against an injected fake filesystem, platform and clock, so it proves
// the win32 and POSIX behavior identically on any host.

const errno = (code: string) => Object.assign(new Error(code), { code });

function fakeDeps(platform: NodeJS.Platform, outcomes: Array<string | "ok">, stepMs = 0, writeFailure?: Error) {
  const state = { opens: 0, sleeps: 0, written: [] as string[], closed: 0, removed: 0, clock: 0 };
  const deps: LockAcquisitionDeps = {
    platform,
    now: () => state.clock,
    sleep: async () => { state.sleeps += 1; state.clock += stepMs; },
    removeLock: async () => { state.removed += 1; },
    openExclusive: async () => {
      const outcome = outcomes[Math.min(state.opens, outcomes.length - 1)];
      state.opens += 1;
      if (outcome !== "ok") throw errno(outcome);
      return {
        writeFile: async (data: string) => { if (writeFailure) throw writeFailure; state.written.push(data); },
        close: async () => { state.closed += 1; },
      };
    },
  };
  return { deps, state };
}

test("classification: EEXIST is a collision everywhere; EPERM/EACCES are transient only on win32", () => {
  for (const platform of ["win32", "linux", "darwin"] as const)
    assert.equal(classifyLockAcquisitionError(errno("EEXIST"), platform), "collision");
  for (const code of ["EPERM", "EACCES"]) {
    assert.equal(classifyLockAcquisitionError(errno(code), "win32"), "windows-transient");
    assert.equal(classifyLockAcquisitionError(errno(code), "linux"), "fatal");
    assert.equal(classifyLockAcquisitionError(errno(code), "darwin"), "fatal");
  }
  for (const value of [errno("ENOENT"), errno("EISDIR"), errno("EBUSY"), new Error("no code"), null, undefined, "EPERM"])
    assert.equal(classifyLockAcquisitionError(value, "win32"), "fatal");
});

test("win32: transient EPERM/EACCES on the exclusive create are retried until the lock is acquired", async () => {
  const { deps, state } = fakeDeps("win32", ["EPERM", "EACCES", "EPERM", "ok"], 20);
  await acquireLockFile("lock", "token-1", deps);
  assert.deepEqual([state.opens, state.sleeps, state.written, state.closed, state.removed], [4, 3, ["token-1"], 1, 0]);
});

test("POSIX: EPERM/EACCES on the exclusive create are rethrown immediately (never retried)", async () => {
  for (const code of ["EPERM", "EACCES"]) {
    const { deps, state } = fakeDeps("linux", [code, "ok"]);
    await assert.rejects(acquireLockFile("lock", "t", deps), { code });
    assert.deepEqual([state.opens, state.sleeps, state.written.length], [1, 0, 0]);
  }
});

test("win32: a persistent EPERM/EACCES is rethrown unchanged once the bounded window elapses", async () => {
  for (const code of ["EPERM", "EACCES"]) {
    const { deps, state } = fakeDeps("win32", [code], 1_000);
    await assert.rejects(acquireLockFile("lock", "t", deps), { code });
    assert.equal(state.opens, Math.floor(WINDOWS_TRANSIENT_WINDOW_MS / 1_000) + 2, "bounded, not an infinite loop");
    assert.equal(state.written.length, 0);
  }
});

test("win32: an EEXIST (lock legitimately held) resets the transient window", async () => {
  // Without the reset, the last EPERM (8s after the first) would exceed the 5s window.
  const { deps, state } = fakeDeps("win32", ["EPERM", "EPERM", "EEXIST", "EPERM", "EPERM", "ok"], 2_000);
  await acquireLockFile("lock", "t", deps);
  assert.deepEqual([state.opens, state.written], [6, ["t"]]);
  // Control: the same elapsed time with no intervening EEXIST is refused.
  const control = fakeDeps("win32", ["EPERM", "EPERM", "EPERM", "EPERM", "EPERM", "ok"], 2_000);
  await assert.rejects(acquireLockFile("lock", "t", control.deps), { code: "EPERM" });
});

test("EEXIST stays retryable without a time bound on every platform (a holder may legitimately hold the lock for minutes)", async () => {
  for (const platform of ["win32", "linux"] as const) {
    const { deps, state } = fakeDeps(platform, [...Array<string>(200).fill("EEXIST"), "ok"], 1_000);
    await acquireLockFile("lock", "t", deps);
    assert.equal(state.opens, 201);
  }
});

test("any other acquisition error is rethrown immediately on every platform", async () => {
  for (const platform of ["win32", "linux"] as const) {
    const { deps, state } = fakeDeps(platform, ["ENOENT", "ok"]);
    await assert.rejects(acquireLockFile("lock", "t", deps), { code: "ENOENT" });
    assert.equal(state.opens, 1);
  }
});

test("the retry is scoped to the exclusive create: an EPERM from the token write is not retried and cleans up", async () => {
  const { deps, state } = fakeDeps("win32", ["ok"], 0, errno("EPERM"));
  await assert.rejects(acquireLockFile("lock", "t", deps), { code: "EPERM" });
  assert.deepEqual([state.opens, state.sleeps, state.closed, state.removed], [1, 0, 1, 1]);
});

test("real filesystem: concurrent holders are serialized and the lockfile is removed afterwards", async () => {
  const root = await mkdtemp(join(tmpdir(), "gate7b-lock-"));
  try {
    await mkdir(join(root, "deployment"));
    const events: string[] = [];
    const holder = (id: string) => withSharedStagingConfigLock(root, "unit", async () => {
      events.push(`start-${id}`);
      await new Promise((resolve) => setTimeout(resolve, 30));
      events.push(`end-${id}`);
    });
    await Promise.all(["a", "b", "c", "d"].map(holder));
    for (let index = 0; index < events.length; index += 2)
      assert.equal(events[index].replace("start-", ""), events[index + 1].replace("end-", ""), "holders must never overlap");
    assert.equal(await access(join(root, "deployment", ".gate57-lock-unit")).then(() => true, () => false), false);
  } finally { await rm(root, { recursive: true, force: true }); }
});
