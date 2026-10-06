import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { REPOSITORY_ROOT } from "../lab/evidence/manifest";
import { parseArguments } from "../lab/run";
import { PolicyRefusal, authorizeRun, buildRegistry } from "../lab/policy/target-policy";
import { WORKLOADS, validateWorkloadCatalogue, type WorkloadSpec } from "../lab/policy/workloads";

const NOW = new Date("2030-01-01T00:00:00Z");
const remoteTarget = (overrides: Record<string, unknown> = {}) => ({
  id: "sut-test", class: "lab-remote", scheme: "http", host: "203.0.113.10", port: 8080, allowedPaths: ["/", "/gizlilik", "/test-talep-et", "/test-talep-et/tesekkurler", "/api/public-inquiries"],
  allowedMethods: ["GET", "POST"], expiresAt: "2030-01-02T00:00:00Z", disposable: true, ...overrides,
});
const refusal = (code: string) => (error: unknown): boolean => error instanceof PolicyRefusal && error.code === code;

// ------------------------------------------------------------------------------------------------ the catalogue
test("the closed-loop level is a coherent reviewed workload: one phase, N workers equal to the concurrency ceiling, exact fixtures, remote only", () => {
  const level = WORKLOADS["ba0-l7-pressure-c1"];
  assert.deepEqual(validateWorkloadCatalogue(), []);
  assert.equal(level.engine, "http-closed-loop");
  assert.equal(level.remoteOnly, true);
  assert.equal(level.localOnly, false);
  assert.equal(level.phases.length, 1);
  assert.ok(Object.isFrozen(level) && Object.isFrozen(level.fixtures));
  assert.deepEqual(level.fixtures?.map((fixture) => fixture.id), ["get_home", "get_privacy", "get_form", "post_inquiry"]);
});

test("the catalogue validator catches a malformed closed-loop workload", () => {
  const clone = (change: (workload: { fixtures?: { id: string; method: string; path: string }[]; phases: { concurrency: number }[]; methods: string[]; paths: string[]; engine: string; localOnly: boolean; remoteOnly: boolean }) => void) => {
    const copy = structuredClone(WORKLOADS["ba0-l7-pressure-c1"]) as unknown as Parameters<typeof change>[0];
    change(copy);
    return { x: copy as unknown as WorkloadSpec };
  };
  assert.ok(validateWorkloadCatalogue(clone((w) => { delete w.fixtures; })).length > 0, "a closed-loop workload must name its fixtures");
  assert.ok(validateWorkloadCatalogue(clone((w) => { w.fixtures![3].path = "/gizlilik"; })).length > 0, "POST on an unreviewed path");
  assert.ok(validateWorkloadCatalogue(clone((w) => { w.fixtures![0].path = "/admin"; })).length > 0, "a fixture outside the workload's paths");
  assert.ok(validateWorkloadCatalogue(clone((w) => { w.fixtures![1].id = "get_home"; })).length > 0, "duplicate fixture ids");
  assert.ok(validateWorkloadCatalogue(clone((w) => { w.fixtures![0].id = "Get Home"; })).length > 0, "a non-label fixture id");
  assert.ok(validateWorkloadCatalogue(clone((w) => { w.phases[0].concurrency = 2; })).length > 0, "workers must equal the concurrency ceiling");
  assert.ok(validateWorkloadCatalogue(clone((w) => { w.localOnly = true; })).length > 0, "local-only and remote-only are contradictory");
  assert.ok(validateWorkloadCatalogue(clone((w) => { w.engine = "http"; })).length > 0, "only a closed-loop workload names fixtures");
});

// ------------------------------------------------------------------------------------------------ the policy
test("the closed-loop level runs only against a reviewed REMOTE target: a loopback target is refused before anything else", () => {
  for (const targetId of ["local-app", "local-app-alt"]) {
    assert.throws(() => authorizeRun({ targetId, workloadId: "ba0-l7-pressure-c1", registry: buildRegistry([], NOW), now: NOW, treeIsClean: true }), refusal("workload-remote-only"), targetId);
  }
});

test("against a reviewed remote target it authorizes EXACTLY the four fixtures: the product of methods and paths is not authorized", () => {
  const registry = buildRegistry([remoteTarget()], NOW);
  const run = authorizeRun({ targetId: "sut-test", workloadId: "ba0-l7-pressure-c1", registry, now: NOW, treeIsClean: true });
  for (const fixture of WORKLOADS["ba0-l7-pressure-c1"].fixtures!) assert.equal(run.authorizeRequest(fixture.method, fixture.path).url, `http://203.0.113.10:8080${fixture.path}`);
  assert.throws(() => run.authorizeRequest("POST", "/"), refusal("method-forbidden"));
  // Each of the method and the path is allowed by the workload, but the PAIR is not one of its four reviewed requests.
  assert.throws(() => run.authorizeRequest("GET", "/api/public-inquiries"), refusal("method-forbidden"));
  assert.throws(() => run.authorizeRequest("POST", "/gizlilik"), refusal("method-forbidden"));
});

test("the existing authorization still applies to the level: expiry, a dirty tree, live hosts and provider infrastructure are refused", () => {
  const registry = buildRegistry([remoteTarget()], NOW);
  assert.throws(() => authorizeRun({ targetId: "sut-test", workloadId: "ba0-l7-pressure-c1", registry, now: NOW }), refusal("clean-tree-required"));
  assert.throws(() => authorizeRun({ targetId: "sut-test", workloadId: "ba0-l7-pressure-c1", registry, now: NOW, treeIsClean: false }), refusal("clean-tree-required"));
  assert.throws(() => authorizeRun({ targetId: "sut-test", workloadId: "ba0-l7-pressure-c1", registry, now: new Date("2030-01-03T00:00:00Z"), treeIsClean: true }), refusal("target-expired"));
  assert.throws(() => buildRegistry([remoteTarget({ host: "limitmark.com" })], NOW), refusal("target-live-limitmark"));
  assert.throws(() => buildRegistry([remoteTarget({ host: "76.76.21.21" })], NOW), refusal("target-provider-infrastructure"));
  assert.throws(() => buildRegistry([remoteTarget({ host: "127.0.0.1" })], NOW), refusal("target-address-forbidden"));
  assert.throws(() => buildRegistry([remoteTarget({ disposable: false })], NOW), refusal("target-definition-invalid"));
  assert.throws(() => buildRegistry([remoteTarget({ expiresAt: "2030-01-09T00:00:00Z" })], NOW), refusal("target-definition-invalid"), "more than 72 hours");
});

test("the CLI can only LOWER an ordinary workload, and may not touch the closed-loop level at all (its verdict is scoped to the exact reviewed level)", () => {
  const registry = buildRegistry([remoteTarget()], NOW);
  const run = authorizeRun({ targetId: "sut-test", workloadId: "ba0-l7-pressure-c1", registry, now: NOW, treeIsClean: true });
  assert.equal(run.limits.phases[0].concurrency, 1);
  assert.throws(() => authorizeRun({ targetId: "sut-test", workloadId: "ba0-l7-pressure-c1", registry, now: NOW, treeIsClean: true, limits: { maxConcurrency: 2 } }), refusal("limit-above-reviewed-ceiling"));
  assert.throws(() => authorizeRun({ targetId: "sut-test", workloadId: "ba0-l7-pressure-c1", registry, now: NOW, treeIsClean: true, limits: { maxRate: 26 } }), refusal("limit-above-reviewed-ceiling"));
});

test("the generator command line accepts --campaign as a plain value and nothing that names a host, a URL or a port", () => {
  assert.equal(parseArguments(["--target", "sut-test", "--workload", "ba0-l7-pressure-c1", "--campaign", "first-campaign"]).campaign, "first-campaign");
  for (const argv of [["--url", "http://x"], ["--host", "10.0.0.1"], ["--port", "80"], ["--campaign=x"], ["--campaign", "a", "--campaign", "b"], ["first-campaign"]]) assert.throws(() => parseArguments(argv), PolicyRefusal, JSON.stringify(argv));
});

// ------------------------------------------------------------------------------------------------ the CLI, end to end up to the refusal
function cli(args: string[]): { status: number | null; out: string } {
  const result = spawnSync(process.execPath, ["--conditions=react-server", "--import", "tsx", "lab/run.ts", ...args], { cwd: REPOSITORY_ROOT, encoding: "utf8", timeout: 60_000 });
  const out = `${result.stdout}${result.stderr}`;
  const evidence = /evidence=(\S+)/.exec(out)?.[1];
  if (evidence) fs.rmSync(path.join(REPOSITORY_ROOT, "artifacts", "lab", "evidence", evidence), { recursive: true, force: true });
  return { status: result.status, out };
}

test("the generator CLI refuses the closed-loop level against a loopback target, with exit code 2 and before any network activity", () => {
  const result = cli(["--target", "local-app", "--workload", "ba0-l7-pressure-c1", "--campaign", "first-campaign"]);
  assert.equal(result.status, 2);
  assert.match(result.out, /REFUSED before any network activity/);
  // The refusal reason is the first policy failure: remote-only for a clean checkout, or an operator-file problem on a machine whose artifacts/lab/targets.json
  // holds an expired entry (a single invalid entry fails the whole load). Either way nothing was sent; the remote-only rule itself is pinned above.
  assert.match(result.out, /lab policy refused \(/);
});

test("the open-loop engine never runs the closed-loop level: the dispatch to the closed-loop engine precedes it, and the engine names no closed-loop workload", () => {
  const run = fs.readFileSync(path.join(REPOSITORY_ROOT, "lab", "run.ts"), "utf8");
  assert.ok(run.indexOf('run.workload.engine === "http-closed-loop"') < run.indexOf("executeHttpWorkload({"), "the closed-loop dispatch comes first");
  const engine = fs.readFileSync(path.join(REPOSITORY_ROOT, "lab", "load", "engine.ts"), "utf8");
  assert.doesNotMatch(engine, /closed-loop|fixtures|ba0-l7/, "the existing open-loop engine is untouched by the closed-loop level");
});
