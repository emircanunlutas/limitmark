import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { probeWithCancellation, type CancellableProbe } from "../lab/failure/postgres-outage";
import { judgeK6Run, superviseContainer } from "../lab/load/k6";
import { buildModel } from "../lab/load/k6/plan.mjs";
import { EXPECTED_DB_TESTS, EXPECTED_NPM_TEST_SKIPPED, evaluateDbRun, evaluateNpmTestRun, nodeTestCounts } from "../lab/linux/results";
import { IMAGE_COMMIT_LABEL, IMAGE_TREE_LABEL, assertImageMatchesTree, treeDigest } from "../lab/linux/provenance";
import { applyKnownFaultVerdict, isPostgresJsNullSocketWrite } from "../lab/postgres/known-faults";

const read = (...parts: string[]) => readFileSync(path.join(__dirname, "..", ...parts), "utf8");
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

// ------------------------------------------------------------------------------------------------ F5: timeouts cancel the work
type Handle = { id: number; destroyed: boolean; reject?: (error: Error) => void };

function fakeProbe(): { probe: CancellableProbe<Handle>; handles: Handle[]; destroyed: number[] } {
  const handles: Handle[] = [];
  const destroyed: number[] = [];
  const open = (): Handle => { const handle = { id: handles.length, destroyed: false }; handles.push(handle); return handle; };
  const probe: CancellableProbe<Handle> = {
    current: open(), open, unsettled: 0, maxUnsettled: 0, abandoned: 0,
    destroy: async (handle) => { handle.destroyed = true; destroyed.push(handle.id); handle.reject?.(Object.assign(new Error("connection destroyed"), { code: "CONNECTION_DESTROYED" })); },
  };
  return { probe, handles, destroyed };
}

/** An operation that hangs (a paused database) until its handle is destroyed, which rejects it like a dead socket would. */
const hanging = (handle: Handle) => new Promise<string>((_, reject) => { handle.reject = reject; });

test("F5 regression: a timed-out probe's work is CANCELLED (its connection destroyed, a fresh one used), not left running behind later probes", async () => {
  const { probe, handles, destroyed } = fakeProbe();
  const first = await probeWithCancellation(probe, hanging, 30);
  assert.deepEqual(first.ok ? null : { timedOut: first.timedOut }, { timedOut: true });
  assert.deepEqual(destroyed, [0], "the stale connection is destroyed, so the server sees EOF and rolls the transaction back");
  assert.equal(handles[0].destroyed, true);
  assert.notEqual(probe.current, handles[0]);
  assert.equal(probe.abandoned, 1);
  assert.equal(probe.unsettled, 0, "the abandoned operation settled before the next probe may start");
  const second = await probeWithCancellation(probe, async (handle) => `used ${handle.id}`, 1_000);
  assert.deepEqual(second, { ok: true, value: "used 1" });
  assert.equal(probe.maxUnsettled, 1, "reported concurrency of one actually held");
});

test("F5: if the abandoned work does NOT settle after its connection is destroyed, the overlap is recorded instead of hidden", async () => {
  const { probe } = fakeProbe();
  // This operation ignores the destroy (a leak): the next probe finds it still unsettled.
  const stuck = () => new Promise<string>(() => undefined);
  await probeWithCancellation(probe, stuck, 20, 10);
  assert.equal(probe.unsettled, 1);
  await probeWithCancellation(probe, async () => "fine", 1_000);
  assert.equal(probe.maxUnsettled, 2);
});

test("F5: a successful probe and a fast failure do not tear the pool down", async () => {
  const { probe, destroyed } = fakeProbe();
  assert.equal((await probeWithCancellation(probe, async () => "ok", 1_000)).ok, true);
  const failed = await probeWithCancellation(probe, async () => { throw Object.assign(new Error("boom"), { code: "ECONNREFUSED" }); }, 1_000);
  assert.deepEqual(failed.ok ? null : failed.timedOut, false);
  assert.deepEqual(destroyed, []);
  assert.equal(probe.abandoned, 0);
});

test("F5: the outage runner uses the cancelling probe, bounds server-side work, and verifies no backend is left running", () => {
  const source = read("lab", "failure", "postgres-outage.ts");
  assert.match(source, /probeWithCancellation\(/);
  assert.match(source, /statement_timeout/);
  assert.match(source, /idle_in_transaction_session_timeout/);
  assert.match(source, /orphanedBackends/);
  assert.match(source, /pg_stat_activity/);
  assert.match(source, /controlLabContainer\([^)]*"postgres"\)/);
});

// ------------------------------------------------------------------------------------------------ F2/F7: supervision kills AND proves it
type Behaviour = { startDelayMs?: number; startFails?: boolean; killFailures?: number; killAlwaysFails?: boolean; rmFails?: boolean; inspectFails?: boolean; vanishes?: boolean };

/** An injected Docker that models the container's real life: it only exists as "running" after start returns, and kill fails against a container that is not running. */
function fakeDocker(behaviour: Behaviour = {}) {
  const calls: string[] = [];
  let running = false;
  let removed = false;
  let remainingKillFailures = behaviour.killFailures ?? 0;
  const waiters: (() => void)[] = [];
  const stop = () => { running = false; for (const release of waiters.splice(0)) release(); };
  const run = async (args: readonly string[]) => {
    calls.push(args[0]);
    switch (args[0]) {
      case "start":
        await sleep(behaviour.startDelayMs ?? 0);
        if (behaviour.startFails) throw new Error("cannot start");
        running = true;
        return { stdout: "" };
      case "wait":
        if (running) await new Promise<void>((resolve) => waiters.push(resolve));
        return { stdout: "137\n" };
      case "kill":
        if (!running) throw new Error("Error response from daemon: container is not running");
        if (behaviour.killAlwaysFails || remainingKillFailures-- > 0) throw new Error("Error response from daemon: cannot kill container");
        stop();
        return { stdout: "" };
      case "rm":
        if (behaviour.rmFails) throw new Error("cannot remove");
        removed = true; stop();
        return { stdout: "" };
      case "inspect":
        if (behaviour.inspectFails) throw new Error("Cannot connect to the Docker daemon");
        if (removed || behaviour.vanishes) throw new Error("Error: No such object: " + args[args.length - 1]);
        return { stdout: running ? "true\n" : "false\n" };
      default: return { stdout: "" };
    }
  };
  return { calls, run, isRunning: () => running };
}
const quick = { retryMs: 2 };

test("F7 regression: a run past its wall clock is KILLED and the stop is PROVEN by reading the container's state back", async () => {
  const fake = fakeDocker();
  const result = await superviseContainer("c".repeat(64), { timeoutMs: 40, untilMs: null }, fake.run, quick);
  assert.deepEqual(result, { exitCode: 137, stoppedBy: "wall-clock", terminationProven: true, killFailures: 0 });
  assert.equal(fake.isRunning(), false);
  assert.ok(fake.calls.includes("kill") && fake.calls.includes("inspect"));
});

test("F2 regression: a target authorization that lapses mid-run KILLS the k6 container and proves it", async () => {
  const fake = fakeDocker();
  const result = await superviseContainer("c".repeat(64), { timeoutMs: 60_000, untilMs: Date.now() + 40 }, fake.run, quick);
  assert.equal(result.stoppedBy, "authorization-expiry");
  assert.equal(result.terminationProven, true);
  assert.equal(fake.isRunning(), false);
});

test("F7 round 2 regression: expiry DURING a pending start is deferred until the start returns (a kill against a not-yet-running container fails), then the container is killed and proven stopped", async () => {
  // The reproduced race: the limit fires at 20 ms, start only completes at 150 ms. The old supervisor fired one kill at 20 ms (rejected: not running),
  // swallowed the error, and the container then came up running while the result claimed an expiry stop.
  const fake = fakeDocker({ startDelayMs: 150 });
  const result = await superviseContainer("c".repeat(64), { timeoutMs: 60_000, untilMs: Date.now() + 20 }, fake.run, quick);
  assert.equal(result.stoppedBy, "authorization-expiry");
  assert.equal(result.terminationProven, true);
  assert.equal(result.killFailures, 0, "no kill was attempted against a container that was not running yet");
  assert.equal(fake.isRunning(), false, "the container that came up after the limit is not left running");
  assert.ok(fake.calls.indexOf("kill") > fake.calls.indexOf("start"));
});

test("F7 round 2 regression: if every kill fails, the result NEVER claims a successful expiry stop (ERROR, termination unproven, failures counted)", async () => {
  const fake = fakeDocker({ startDelayMs: 30, killAlwaysFails: true, rmFails: true });
  const result = await superviseContainer("c".repeat(64), { timeoutMs: 60_000, untilMs: Date.now() + 10 }, fake.run, { retryMs: 2, killAttempts: 3 });
  assert.equal(result.stoppedBy, "authorization-expiry");
  assert.equal(result.terminationProven, false);
  assert.ok(result.killFailures >= 3, `kill failures ${result.killFailures}`);
  assert.equal(fake.isRunning(), true, "the fake really is still running: the claim would have been false");
  const verdict = judgeK6Run({ summary: null, model: buildModel(planForJudge()), maxTotalRequests: 300, exitCode: result.exitCode, stoppedBy: result.stoppedBy, terminationProven: result.terminationProven });
  assert.equal(verdict.result, "ERROR");
  assert.match(verdict.reasons[0], /could NOT be proven stopped/);
  assert.doesNotMatch(verdict.reasons.join(" "), /killed\b/);
});

test("F7 round 2: transient kill failures are retried, counted and then proven; a daemon that cannot answer is UNKNOWN, never 'stopped'", async () => {
  const flaky = fakeDocker({ startDelayMs: 5, killFailures: 2 });
  const result = await superviseContainer("c".repeat(64), { timeoutMs: 30, untilMs: null }, flaky.run, quick);
  assert.deepEqual([result.stoppedBy, result.terminationProven, result.killFailures], ["wall-clock", true, 2]);
  const blind = fakeDocker({ startDelayMs: 5, inspectFails: true });
  const unknown = await superviseContainer("c".repeat(64), { timeoutMs: 30, untilMs: null }, blind.run, { retryMs: 2, killAttempts: 2 });
  assert.equal(unknown.terminationProven, false, "if the state cannot be read back the stop is not proven");
  const gone = fakeDocker({ startDelayMs: 5, vanishes: true });
  assert.equal((await superviseContainer("c".repeat(64), { timeoutMs: 30, untilMs: null }, gone.run, quick)).terminationProven, true, "an explicit 'no such container' is absence");
});

test("F7: a container that exits on its own is not reported as stopped by the supervisor; a failed start is an error, not a result", async () => {
  const done = async (args: readonly string[]) => ({ stdout: args[0] === "wait" ? "0\n" : "" });
  assert.deepEqual(await superviseContainer("c".repeat(64), { timeoutMs: 60_000, untilMs: null }, done, quick), { exitCode: 0, stoppedBy: null, terminationProven: true, killFailures: 0 });
  await assert.rejects(superviseContainer("c".repeat(64), { timeoutMs: 60_000, untilMs: null }, fakeDocker({ startFails: true }).run, quick), /cannot start/);
});

function planForJudge() {
  return { schema: 2 as const, baseUrl: "http://127.0.0.1:3000", maxTotalRequests: 300, requests: [{ method: "GET" as const, path: "/" }], phases: [{ name: "latency", seconds: 60, rate: 5, vus: 2, timeoutMs: 5000, measured: true }], thresholds: { passErrorRate: 0.005, stopErrorRate: 0.05, passP95Ms: 250, passP99Ms: 800, stopP99Ms: 3000 } };
}

// ------------------------------------------------------------------------------------------------ F5: interruption cleanup (real processes)
function cleanupHelper(mode: "exit" | "sigterm"): Promise<{ childPid: number; parentExit: number | null }> {
  return new Promise((resolve, reject) => {
    const parent = spawn(process.execPath, [path.join(__dirname, "..", "node_modules", "tsx", "dist", "cli.mjs"), path.join(__dirname, "support", "local-app-cleanup-child.ts"), mode], { stdio: ["ignore", "pipe", "inherit"], windowsHide: true });
    let output = "";
    parent.stdout.on("data", (chunk) => { output += chunk; });
    parent.on("error", reject);
    parent.on("close", (code) => {
      const childPid = Number(/^child:(\d+)$/m.exec(output)?.[1]);
      if (!Number.isInteger(childPid)) reject(new Error(`helper printed no child pid: ${output}`)); else resolve({ childPid, parentExit: code });
    });
  });
}

async function eventuallyDead(pid: number, withinMs = 8_000): Promise<boolean> {
  const until = Date.now() + withinMs;
  while (Date.now() < until) {
    try { process.kill(pid, 0); } catch { return true; }
    await sleep(100);
  }
  return false;
}

test("F5 regression: a started process tree does not outlive a normal exit of the lab process", async () => {
  const { childPid } = await cleanupHelper("exit");
  const dead = await eventuallyDead(childPid);
  if (!dead) { try { process.kill(childPid, "SIGKILL"); } catch { /* ignore */ } }
  assert.equal(dead, true, "the child process tree survived the parent");
});

test("F5 regression: a DETACHED child (own process group) does not outlive SIGTERM of the lab process", { skip: process.platform === "win32" ? "POSIX signals and process groups" : false }, async () => {
  const { childPid, parentExit } = await cleanupHelper("sigterm");
  const dead = await eventuallyDead(childPid);
  if (!dead) { try { process.kill(-childPid, "SIGKILL"); } catch { /* ignore */ } }
  assert.equal(dead, true, "the detached child survived SIGTERM of the parent");
  assert.equal(parentExit, 143, "the handler re-raises the termination (128 + SIGTERM)");
});

test("F5: lab-managed app startup and readiness are inside the cleanup scope of the restart workload", () => {
  const source = read("lab", "failure", "app-restart.ts");
  const tryAt = source.indexOf("  try {");
  assert.ok(tryAt > 0);
  assert.ok(source.indexOf("await app.start()") > tryAt, "start() must be inside try");
  assert.ok(source.indexOf("await app.waitUntilListening()") > tryAt, "readiness must be inside try");
  assert.match(source, /finally \{\s*await app\.kill\(\);/);
});

test("F5 regression: labDbDown removes only its own labelled container; it never runs `compose down` (which removes the other PG version)", () => {
  const source = read("lab", "postgres", "lab-db.ts");
  const down = source.slice(source.indexOf("export async function labDbDown"), source.indexOf("async function removeSharedNetworkIfUnused"));
  assert.match(down, /removeLabContainer\(container, "postgres"\)/);
  assert.doesNotMatch(down, /"down"|--remove-orphans|compose/, "compose down would remove the sibling lab");
  assert.ok(down.indexOf("removeLabContainer") < down.indexOf("rmSync"), "the state file is deleted only after the container is verifiably gone");
  assert.doesNotMatch(source.slice(source.indexOf("async function removeSharedNetworkIfUnused")), /compose/);
});

test("F5/F7: parity removes a pre-existing app container only after its labels prove ownership, by verified removal, and never by bare name", () => {
  const source = read("lab", "linux", "parity.ts");
  assert.match(source, /await removeLabContainer\(APP_CONTAINER, "app"\)/);
  assert.doesNotMatch(source, /\["rm", "-f", APP_CONTAINER\]/);
  assert.doesNotMatch(source, /containerExists\(APP_CONTAINER\)\) await docker/);
  assert.match(source, /limitmark\.lab\.role=app/);
  // Containers it creates for steps are labelled and named so a timeout can kill and verify them.
  assert.match(source, /limitmark\.lab\.role=parity/);
  assert.match(source, /terminated = await containerExists\(options\.containerName\)/);
  assert.match(source, /teardownOnCrash\(versions, \{\s*extraCleanup/);
});

// ------------------------------------------------------------------------------------------------ F7: the known postgres.js defect is never a pass
test("F7 regression: observing the postgres.js null-socket write defect can never end in PASS", () => {
  const reasons: string[] = [];
  assert.deepEqual(applyKnownFaultVerdict("PASS", reasons, { postgresJsNullSocketWrite: 2 }), { result: "FAIL" });
  assert.match(reasons[0], /known postgres\.js defect observed 2 time/);
  assert.deepEqual(applyKnownFaultVerdict("ERROR", [], { postgresJsNullSocketWrite: 1 }), { result: "ERROR" });
  assert.deepEqual(applyKnownFaultVerdict("STOP", [], { postgresJsNullSocketWrite: 1 }), { result: "STOP" });
  assert.deepEqual(applyKnownFaultVerdict("FAIL", [], { postgresJsNullSocketWrite: 1 }), { result: "FAIL" });
  const clean: string[] = [];
  assert.deepEqual(applyKnownFaultVerdict("PASS", clean, { postgresJsNullSocketWrite: 0 }), { result: "PASS" });
  assert.deepEqual(clean, []);
  // The detector itself still recognises the reproduced exception (postgres.js 3.4.9: nextWrite() on a destroyed socket).
  const fault = new TypeError("Cannot read properties of null (reading 'write')");
  fault.stack = "TypeError: Cannot read properties of null (reading 'write')\n    at Immediate.nextWrite (C:\\x\\node_modules\\postgres\\cjs\\src\\connection.js:1:1)";
  assert.equal(isPostgresJsNullSocketWrite(fault), true);
  assert.equal(isPostgresJsNullSocketWrite(new TypeError("Cannot read properties of null (reading 'write')")), false, "a TypeError from elsewhere is not tolerated");
});

test("F7: every runner that can observe the defect routes its verdict through applyKnownFaultVerdict", () => {
  for (const file of [["lab", "run.ts"], ["lab", "concurrency", "harness.ts"]]) assert.match(read(...file), /applyKnownFaultVerdict\(/, file.join("/"));
  assert.match(read("lab", "linux", "results.ts"), /KNOWN_FAULT/);
});

// ------------------------------------------------------------------------------------------------ F7: parity results cannot be false-green
const spec = (lines: Record<string, number>) => Object.entries(lines).map(([label, value]) => `ℹ ${label} ${value}`).join("\n");
const dbOutput = (over: Record<string, number> = {}) => spec({ tests: 34, suites: 0, pass: 34, fail: 0, cancelled: 0, skipped: 0, todo: 0, ...over });

test("F7: node:test summaries are read from both reporters and a missing count is 'unknown', not zero", () => {
  assert.deepEqual(nodeTestCounts(dbOutput()), { tests: 34, pass: 34, fail: 0, skipped: 0, cancelled: 0 });
  assert.deepEqual(nodeTestCounts("# tests 3\n# pass 3\n# fail 0\n# cancelled 0\n# skipped 0\n"), { tests: 3, pass: 3, fail: 0, skipped: 0, cancelled: 0 });
  assert.equal(nodeTestCounts("ℹ tests 34\nℹ pass 34\nℹ fail 0\nℹ skipped 0\n"), undefined, "no `cancelled` line: the summary is incomplete");
  assert.equal(nodeTestCounts(""), undefined);
});

test("F7 regression: a DB-suite step is PASS only for exactly 34 passing, unskipped tests and a clean exit", () => {
  assert.deepEqual(evaluateDbRun(dbOutput(), 0), { counts: { tests: 34, pass: 34, fail: 0, skipped: 0, cancelled: 0 } });
  assert.equal(EXPECTED_DB_TESTS, 34);
  assert.match(evaluateDbRun(dbOutput(), 1).failure ?? "", /exit code 1/);
  assert.match(evaluateDbRun("", 0).failure ?? "", /no test summary/);
  assert.match(evaluateDbRun("some output without a summary", 0).failure ?? "", /no test summary/);
  const mismatches: Record<string, number>[] = [{ tests: 33, pass: 33 }, { tests: 35, pass: 35 }, { skipped: 1, pass: 33 }, { fail: 1, pass: 33 }, { cancelled: 1 }];
  for (const over of mismatches) {
    assert.match(evaluateDbRun(dbOutput(over), 0).failure ?? "", /expected exactly 34/, JSON.stringify(over));
  }
  // The known library fault hiding behind exit code 0 (it is thrown outside any test promise).
  const hidden = `${dbOutput()}\nTypeError: Cannot read properties of null (reading 'write')\n`;
  assert.match(evaluateDbRun(hidden, 0).failure ?? "", /known postgres\.js defect/);
});

test("F7 regression: an `npm test` step needs a summary, no failures, and exactly the database-gated tests skipped", () => {
  const output = (over: Record<string, number> = {}) => spec({ tests: 900, suites: 0, pass: 866, fail: 0, cancelled: 0, skipped: EXPECTED_NPM_TEST_SKIPPED, todo: 0, ...over });
  assert.equal(evaluateNpmTestRun(output(), 0).failure, undefined);
  assert.match(evaluateNpmTestRun(output(), 1).failure ?? "", /exit code/);
  assert.match(evaluateNpmTestRun("", 0).failure ?? "", /no test summary/);
  assert.match(evaluateNpmTestRun(output({ fail: 1 }), 0).failure ?? "", /failed or cancelled/);
  assert.match(evaluateNpmTestRun(output({ tests: 0, pass: 0, skipped: 0 }), 0).failure ?? "", /failed or cancelled|none ran/);
  assert.match(evaluateNpmTestRun(output({ skipped: 0 }), 0).failure ?? "", /skipped/);
  assert.match(evaluateNpmTestRun(output({ skipped: EXPECTED_NPM_TEST_SKIPPED + 3 }), 0).failure ?? "", /skipped/, "newly skipped tests are noticed, not hidden");
  assert.match(evaluateNpmTestRun(`${output()}\nCannot read properties of null (reading 'write')`, 0).failure ?? "", /known postgres\.js defect/);
});

// ------------------------------------------------------------------------------------------------ F7: provenance
test("F7: the tree digest changes with HEAD, any tracked change and any untracked file, and not with the order of untracked files", () => {
  const base = { head: "a".repeat(40), diff: "", untracked: [] as { path: string; sha256: string }[] };
  const clean = treeDigest(base);
  assert.match(clean, /^[0-9a-f]{64}$/);
  assert.equal(treeDigest(base), clean);
  assert.notEqual(treeDigest({ ...base, head: "b".repeat(40) }), clean);
  assert.notEqual(treeDigest({ ...base, diff: "diff --git a/x b/x\n" }), clean);
  assert.notEqual(treeDigest({ ...base, diff: Buffer.from([0, 1, 2]) }), clean);
  const one = { path: "a.txt", sha256: "1".repeat(64) }, two = { path: "b.txt", sha256: "2".repeat(64) };
  assert.notEqual(treeDigest({ ...base, untracked: [one] }), clean);
  assert.equal(treeDigest({ ...base, untracked: [one, two] }), treeDigest({ ...base, untracked: [two, one] }));
  assert.notEqual(treeDigest({ ...base, untracked: [{ ...one, sha256: "3".repeat(64) }, two] }), treeDigest({ ...base, untracked: [one, two] }));
});

test("F7 regression: a reused image (--skip-build) must carry labels equal to the tree being reported, otherwise it is refused", () => {
  const current = { gitSha: "a".repeat(40), treeSha256: "b".repeat(64), dirty: false };
  const labels = { [IMAGE_COMMIT_LABEL]: current.gitSha, [IMAGE_TREE_LABEL]: current.treeSha256 };
  assert.doesNotThrow(() => assertImageMatchesTree(labels, current));
  assert.throws(() => assertImageMatchesTree(null, current), /no provenance labels/);
  assert.throws(() => assertImageMatchesTree({}, current), /no provenance labels/);
  assert.throws(() => assertImageMatchesTree({ [IMAGE_COMMIT_LABEL]: current.gitSha }, current), /no provenance labels/);
  assert.throws(() => assertImageMatchesTree({ ...labels, [IMAGE_COMMIT_LABEL]: "c".repeat(40) }, current), /different commit/);
  // Same commit, different working tree: a stale image next to today's commit.
  assert.throws(() => assertImageMatchesTree({ ...labels, [IMAGE_TREE_LABEL]: "d".repeat(64) }, current), /different working tree/);
});

test("F7: parity checks provenance for built AND reused images, labels the build, records scope honestly, and runs its drivers as the host's", () => {
  const source = read("lab", "linux", "parity.ts");
  assert.match(source, /--label", `\$\{IMAGE_COMMIT_LABEL\}=/);
  assert.match(source, /--label", `\$\{IMAGE_TREE_LABEL\}=/);
  assert.match(source, /assertImageMatchesTree\(labels, identity\)/);
  assert.doesNotMatch(source.slice(source.indexOf("assertImageMatchesTree")- 400, source.indexOf("assertImageMatchesTree")), /if \(skipBuild\)/, "the gate must not be conditional on a fresh build");
  assert.match(source, /the working tree changed during the build/);
  assert.match(source, /httpDriverRuntime: `host-\$\{process\.platform\}`/);
  assert.match(source, /does not prove VM, kernel, network or field parity/);
  assert.match(source, /--app-container/);
  assert.match(source, /--k6-netns-container/);
});

test("F5 round 2 regression: when the Docker daemon cannot be reached labDbDown FAILS and keeps its state file (unknown is never 'no container')", async () => {
  const { existsSync, mkdirSync, rmSync, writeFileSync } = await import("node:fs");
  const { labDbDown } = await import("../lab/postgres/lab-db");
  const stateDirectory = path.join(__dirname, "..", "artifacts", "lab", "pg");
  const stateFile = path.join(stateDirectory, "pg16.json");
  if (existsSync(stateFile)) return; // a real lab is up on this machine; never touch it
  mkdirSync(stateDirectory, { recursive: true });
  writeFileSync(stateFile, "{}\n");
  const previous = process.env.DOCKER_HOST;
  process.env.DOCKER_HOST = "tcp://203.0.113.9:2375"; // makes every wrapper call fail before any network use, like an unreachable daemon
  try {
    await assert.rejects(labDbDown("16"));
    assert.equal(existsSync(stateFile), true, "the state file must survive a teardown that could not establish the container's fate");
  } finally {
    if (previous === undefined) delete process.env.DOCKER_HOST; else process.env.DOCKER_HOST = previous;
    rmSync(stateFile, { force: true });
  }
});

test("F7 round 2 (variants): both limits firing during a pending start, and a kill that 'succeeds' while the container still reports running, still end proven or ERROR, never a false stop", async () => {
  const both = fakeDocker({ startDelayMs: 80 });
  const result = await superviseContainer("c".repeat(64), { timeoutMs: 10, untilMs: Date.now() + 10 }, both.run, quick);
  assert.ok(result.stoppedBy === "wall-clock" || result.stoppedBy === "authorization-expiry");
  assert.equal(result.terminationProven, true);
  assert.equal(both.isRunning(), false);
  // The daemon accepts `kill` but the container keeps reporting running (a zombie / wrong container): the claim must not be made.
  const calls: string[] = [];
  const stubborn = async (args: readonly string[]) => {
    calls.push(args[0]);
    if (args[0] === "wait") return new Promise<{ stdout: string }>(() => undefined);
    if (args[0] === "inspect") return { stdout: "true\n" };
    return { stdout: "" };
  };
  const unproven = await superviseContainer("c".repeat(64), { timeoutMs: 20, untilMs: null }, stubborn, { retryMs: 2, killAttempts: 2 });
  assert.equal(unproven.terminationProven, false);
  assert.ok(calls.filter((call) => call === "kill").length >= 2 && calls.includes("rm"), "kill retried, then forced");
});
