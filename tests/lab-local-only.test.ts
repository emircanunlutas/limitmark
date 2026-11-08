import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { PolicyRefusal, authorizeRun } from "../lab/policy/target-policy";
import { LOCAL_ONLY_TARGET_IDS, checkLocalOnly, loadOperatorTargets, parseArguments, registryForRun } from "../lab/run";

// Explicit local-only target loading for the disposable Linux parity environment. The ordinary path is unchanged: an expired operator entry still fails the load.

const NOW = new Date("2026-11-08T12:00:00.000Z");
const expiredRemote = { id: "gcp-sut-1", class: "lab-remote", scheme: "http", host: "203.0.113.7", port: 3000, allowedPaths: ["/", "/gizlilik"], allowedMethods: ["GET"], expiresAt: "2026-10-04T20:49:36Z", disposable: true };
const refusal = (code: string) => (error: unknown) => error instanceof PolicyRefusal && error.code === code;
const base = { localOnly: true, manageApp: false, appContainer: "limitmark-lab-app", k6Netns: undefined as string | undefined };

test("(a) ordinary loading still rejects an expired remote operator entry, whole load fails, nothing is skipped", () => {
  assert.throws(() => registryForRun({ localOnly: false }, NOW, () => [expiredRemote]), refusal("target-expired"));
  // through the real file loader as well
  const directory = mkdtempSync(path.join(tmpdir(), "lm-local-only-"));
  try {
    const file = path.join(directory, "targets.json");
    writeFileSync(file, JSON.stringify([expiredRemote]));
    assert.throws(() => registryForRun({ localOnly: false }, NOW, () => loadOperatorTargets(file)), refusal("target-expired"));
    // and a valid entry next to the expired one does not rescue the load
    const valid = { ...expiredRemote, id: "sut-2", expiresAt: "2026-11-09T00:00:00Z" };
    assert.throws(() => registryForRun({ localOnly: false }, NOW, () => [valid, expiredRemote]), refusal("target-expired"));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("(b) local-only never opens the operator inventory and cannot select a remote target", () => {
  let opened = 0;
  const registry = registryForRun({ localOnly: true }, NOW, () => { opened++; return [expiredRemote]; });
  assert.equal(opened, 0, "the operator inventory is not read in local-only mode");
  assert.deepEqual([...registry.keys()].sort(), ["local-app", "local-app-alt"]);
  assert.throws(() => authorizeRun({ targetId: "gcp-sut-1", workloadId: "connectivity-baseline", registry, now: NOW, treeIsClean: true }), refusal("target-unknown"));
  for (const id of ["gcp-sut-1", "sut-test", "limitmark.com", "203.0.113.7", "http://203.0.113.7:3000", ""]) {
    assert.throws(() => authorizeRun({ targetId: id, workloadId: "connectivity-baseline", registry, now: NOW, treeIsClean: true }), (e: unknown) => e instanceof PolicyRefusal, id);
  }
  const run = authorizeRun({ targetId: "local-app-alt", workloadId: "connectivity-baseline", registry, now: NOW, treeIsClean: true });
  assert.equal(run.target.class, "lab-local");
  assert.equal(checkLocalOnly(base, run.target), null);
});

test("local-only refuses a non-fixture id, a non-lab-local class, a non-loopback host, and a missing destination proof, before any traffic", () => {
  const ok = { id: "local-app", class: "lab-local", host: "127.0.0.1" };
  assert.equal(checkLocalOnly(base, ok), null);
  assert.equal(checkLocalOnly({ ...base, localOnly: false }, { id: "anything", class: "lab-remote", host: "203.0.113.7" }), null, "the check is inert outside local-only mode (ordinary rules apply there)");
  for (const target of [{ ...ok, id: "sut-test" }, { ...ok, class: "lab-remote" }, { ...ok, host: "203.0.113.7" }, { ...ok, host: "localhost" }, { ...ok, host: "limitmark.com" }, { ...ok, host: "0.0.0.0" }]) {
    assert.ok(checkLocalOnly(base, target) instanceof PolicyRefusal, JSON.stringify(target));
  }
  assert.ok(checkLocalOnly({ ...base, appContainer: undefined }, ok) instanceof PolicyRefusal, "no lab-established destination");
  assert.equal(checkLocalOnly({ ...base, appContainer: undefined, k6Netns: "limitmark-lab-app" }, ok), null);
  assert.equal(checkLocalOnly({ ...base, appContainer: undefined, manageApp: true }, ok), null);
  assert.deepEqual([...LOCAL_ONLY_TARGET_IDS], ["local-app", "local-app-alt"]);
});

test("the flag is a strict boolean on the command line only: no value, no duplicate, default off, no environment switch", () => {
  assert.equal(parseArguments(["--target", "local-app"]).localOnly, false);
  assert.equal(parseArguments(["--local-only", "--target", "local-app"]).localOnly, true);
  assert.throws(() => parseArguments(["--local-only", "--local-only"]), (e: unknown) => e instanceof PolicyRefusal);
  assert.throws(() => parseArguments(["--local-only=1"]), (e: unknown) => e instanceof PolicyRefusal);
  const source = readFileSync(path.join(__dirname, "..", "lab", "run.ts"), "utf8");
  const region = source.slice(source.indexOf("export function registryForRun"), source.indexOf("export function checkLocalOnly"));
  assert.ok(!/process\.env/u.test(region), "no environment variable enables local-only mode");
});

test("the Linux parity HTTP workloads run in local-only mode (both the node workloads and k6)", () => {
  const source = readFileSync(path.join(__dirname, "..", "lab", "linux", "parity.ts"), "utf8");
  assert.equal((source.match(/"--local-only"/gu) ?? []).length, 2);
});
