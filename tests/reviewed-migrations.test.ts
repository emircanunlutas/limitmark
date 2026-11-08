import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  MIGRATION_BASELINES, MIGRATION_REGISTRY_VERSION, REVIEWED_MIGRATIONS, assertMigrationBoundary, classifyDrift, isEffective, withoutReviewedChanges, type ReviewedMigration,
} from "./support/reviewed-migrations";

/**
 * The migration registry is inert until a human sets a status to APPROVED. These tests (1) pin its shape and current state, (2) prove on the REAL repository that
 * there is no unreviewed drift, (3) prove on a throwaway git repository that it distinguishes authorized, pending, modified-after-review and unreviewed changes,
 * and (4) show the exact evidence that would close the historical byte-identity guards: which approvals make which guard's diff empty.
 */
const root = path.join(__dirname, "..");
const git = (cwd: string, args: string[]) => execFileSync("git", args, { cwd, encoding: "utf8", maxBuffer: 1 << 28 });
const sha256Lf = (text: string) => createHash("sha256").update(text.replace(/\r\n/gu, "\n")).digest("hex");

// The pathspec sets of the three historical byte-identity guards, copied verbatim (the guards themselves are untouched).
const PATHS_64CCC9D = ["defense", "src", "workers", "lab/policy", "lab/evidence", "lab/defense/canary.ts", "lab/defense/field-canary.ts", "lab/defense/field-verdict.ts", "lab/defense/field-state.ts",
  "lab/defense/field-thresholds.ts", "lab/defense/reconcile.ts", "lab/defense/salvo-spec.ts", "lab/defense/salvo-reconcile.ts", "lab/defense/salvo-diagnostics.ts", "lab/defense/salvo-diagnostic-check.ts",
  "lab/defense/salvo-measurement.ts", "lab/defense/n2-measurement.ts", "lab/defense/external-reducer.ts", "lab/defense/external-accounting.ts", "lab/defense/collector.ts", "lab/defense/generator-report.ts",
  "lab/defense/ba0-field-reconcile.ts"];
const PATHS_DCF10AF8 = ["defense", "src", "workers", "lab/policy", "lab/defense/salvo-spec.ts", "lab/defense/salvo-reconcile.ts", "lab/defense/reconcile.ts", "lab/defense/field-verdict.ts",
  "lab/defense/n2-measurement.ts", "lab/defense/external-reducer.ts", "lab/defense/external-accounting.ts", "lab/defense/canary.ts", "lab/defense/field-canary.ts", "lab/defense/collector.ts",
  "lab/defense/exposure-proof.ts", "lab/evidence"];
const PATHS_AFF793E = ["defense", "lab/defense/n2-measurement.ts"];
const GUARDS: Array<[string, string, string[], number]> = [["64ccc9d", MIGRATION_BASELINES[0], PATHS_64CCC9D, 40], ["dcf10af8", MIGRATION_BASELINES[1], PATHS_DCF10AF8, 40], ["aff793e", MIGRATION_BASELINES[2], PATHS_AFF793E, 0]];
const NEW_APPROVALS = ["workers/admin-gateway/index.ts", "workers/lab-operator-lifecycle-executor.ts"];
const INSTRUMENTATION = ["defense/core/outcome-counters.ts", "defense/plane/runtime.ts"];

const approve = (registry: readonly ReviewedMigration[], which: (entry: ReviewedMigration) => boolean): ReviewedMigration[] =>
  registry.map((entry) => (which(entry) ? { ...entry, status: "APPROVED" as const, authorization: "TEST-ONLY decision reference", scope: "TEST-ONLY scope" } : { ...entry }));

test("registry shape: a closed, versioned list of exact files, only the two instrumentation entries and the two owner-approved lab/entry entries (2026-11-09) approved, every entry current against the working tree", () => {
  assert.equal(MIGRATION_REGISTRY_VERSION, 1);
  assert.equal(REVIEWED_MIGRATIONS.length, 44);
  assert.equal(new Set(REVIEWED_MIGRATIONS.map((entry) => entry.path)).size, 44);
  for (const entry of REVIEWED_MIGRATIONS) {
    assert.match(entry.path, /^(?:src|workers|defense)\/[A-Za-z0-9_./-]+\.tsx?$/u, entry.path);
    assert.match(entry.reviewedSha256, /^[0-9a-f]{64}$/u, entry.path);
    assert.ok(entry.historicalBlob === null || /^[0-9a-f]{40}$/u.test(entry.historicalBlob), entry.path);
    assert.equal(entry.change === "added", entry.historicalBlob === null, entry.path);
    assert.equal(sha256Lf(readFileSync(path.join(root, entry.path), "utf8")), entry.reviewedSha256, `${entry.path}: the entry records the CURRENT file (re-review after any edit)`);
    assert.equal(git(root, ["hash-object", entry.path]).trim(), entry.reviewedBlob, `${entry.path}: reviewedBlob is the current committed blob`);
    assert.match(entry.reviewedBlob, /^[0-9a-f]{40}$/u, entry.path);
    if (entry.status === "PENDING") {
      assert.equal(entry.authorization, null, `${entry.path}: PENDING carries no authorization`);
      assert.equal(entry.scope, "", `${entry.path}: PENDING carries no scope`);
      assert.equal(isEffective(entry), false, `${entry.path}: PENDING never exempts`);
    } else {
      assert.equal(isEffective(entry), true, `${entry.path}: an APPROVED entry binds authorization, scope and reviewed blob`);
    }
    for (const baseline of MIGRATION_BASELINES) {
      let blob: string | null = null;
      try { blob = git(root, ["rev-parse", `${baseline}:${entry.path}`]).trim(); } catch { blob = null; }
      assert.equal(blob, entry.historicalBlob, `${entry.path}@${baseline.slice(0, 7)}: one historical blob for all three baselines`);
    }
  }
  // Approving any further entry is a reviewed edit of this assertion. Exactly the two instrumentation entries are approved (owner decision D1, 2026-11-08), with this exact authorization and scope.
  assert.deepEqual(REVIEWED_MIGRATIONS.filter((entry) => entry.status === "APPROVED" && entry.reviewId.startsWith("INSTRUMENTATION/")).map((entry) => [entry.path, entry.reviewId, entry.authorization, entry.scope]), [
    ["defense/core/outcome-counters.ts", "INSTRUMENTATION/D1", "Owner decision D1 (instrumentation wiring, conditional approval) + INSTRUMENTATION-MIGRATION-APPROVAL.md, 040292b", "observational outcome tally only: new module + runtime.ts wiring that tallies emitted events; no defense policy, threshold, status or event-order change"],
    ["defense/plane/runtime.ts", "INSTRUMENTATION/D1", "Owner decision D1 (instrumentation wiring, conditional approval) + INSTRUMENTATION-MIGRATION-APPROVAL.md, 040292b", "observational outcome tally only: new module + runtime.ts wiring that tallies emitted events; no defense policy, threshold, status or event-order change"],
  ]);
  // Owner decision of 2026-11-09: exactly these two further entries are approved, each at its reviewed blob, with this authorization; the lab observer and every other entry stay PENDING.
  const approvedNow = REVIEWED_MIGRATIONS.filter((entry) => entry.status === "APPROVED").map((entry) => entry.path).sort();
  assert.deepEqual(approvedNow, [...INSTRUMENTATION, ...NEW_APPROVALS].sort());
  assert.equal(REVIEWED_MIGRATIONS.filter((entry) => entry.status === "PENDING").length, 40);
  for (const entry of REVIEWED_MIGRATIONS.filter((candidate) => NEW_APPROVALS.includes(candidate.path))) {
    assert.match(entry.authorization ?? "", /^Owner decision 'Criterion 9 Closure, Two Migration Approvals, and Observer Isolation' \(2026-11-09\)/u, entry.path);
    assert.match(entry.scope, /no deployment or production enablement/u, entry.path);
  }
  assert.equal(REVIEWED_MIGRATIONS.find((entry) => entry.path === "workers/admin-gateway/index.ts")?.reviewedBlob, "9c159eaf416dffe751e2fa66cb262ab3acc4c8a4");
  assert.equal(REVIEWED_MIGRATIONS.find((entry) => entry.path === "workers/lab-operator-lifecycle-executor.ts")?.reviewedBlob, "dadcb9769e11e67eaf8c01711a9150a159aa51fc");
  assert.equal(REVIEWED_MIGRATIONS.find((entry) => entry.path === "workers/lab-lifecycle-observer.ts")?.status, "PENDING", "the lab lifecycle observer stays PENDING");
  const holds = (hold: string) => REVIEWED_MIGRATIONS.filter((entry) => entry.hold === hold).length;
  assert.deepEqual([holds("none"), holds("shared-production-module"), holds("guard-export")], [28, 11, 5]);
});

test("real repository: every file that differs from each baseline is registered and unmodified since review (no unreviewed drift), and everything except the four approved entries is still PENDING", () => {
  for (const [name, baseline, paths, expected] of GUARDS) {
    const result = classifyDrift(root, baseline, paths);
    assert.deepEqual(result.unreviewed, [], `${name}: unreviewed drift`);
    assert.deepEqual(result.modifiedAfterReview, [], `${name}: modified after review`);
    assert.deepEqual([...result.authorized].sort(), name === "aff793e" ? INSTRUMENTATION : [...INSTRUMENTATION, ...NEW_APPROVALS].sort(), `${name}: exactly the approved entries inside this guard's paths are authorized`);
    assert.equal(result.pending.length, expected, `${name}: pending drift`);
  }
});

test("the mechanism distinguishes authorized, pending, modified-after-review and unreviewed changes (throwaway git repository)", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "migration-"));
  try {
    const run = (...args: string[]) => git(dir, args);
    run("init", "-q"); run("config", "user.email", "t@example.invalid"); run("config", "user.name", "t"); run("config", "commit.gpgsign", "false");
    mkdirSync(path.join(dir, "defense"), { recursive: true }); mkdirSync(path.join(dir, "src"), { recursive: true });
    for (const name of ["defense/a.ts", "defense/b.ts", "defense/c.ts", "defense/d.ts", "src/untouched.ts"]) writeFileSync(path.join(dir, name), `export const ${path.basename(name, ".ts")} = 0;\n`);
    run("add", "-A"); run("commit", "-q", "-m", "baseline");
    const baseline = run("rev-parse", "HEAD").trim();
    const blob = (file: string) => run("rev-parse", `${baseline}:${file}`).trim();
    // authorized (a), pending (b), modified after review (c), unreviewed (d), added+approved (e)
    for (const name of ["a", "b", "c", "d"]) writeFileSync(path.join(dir, `defense/${name}.ts`), `export const ${name} = 1;\n`);
    writeFileSync(path.join(dir, "defense/e.ts"), "export const e = 1;\n");
    const reviewedHash = (file: string) => sha256Lf(readFileSync(path.join(dir, file), "utf8"));
    const reviewedBlob = (file: string) => run("hash-object", file).trim();
    const bind = { authorization: "T/decision", scope: "T/scope" };
    const registry: ReviewedMigration[] = [
      { path: "defense/a.ts", change: "modified", historicalBlob: blob("defense/a.ts"), reviewedSha256: reviewedHash("defense/a.ts"), reviewedBlob: reviewedBlob("defense/a.ts"), reviewId: "T/a", hold: "none", status: "APPROVED", ...(bind) },
      { path: "defense/b.ts", change: "modified", historicalBlob: blob("defense/b.ts"), reviewedSha256: reviewedHash("defense/b.ts"), reviewedBlob: reviewedBlob("defense/b.ts"), reviewId: "T/b", hold: "none", status: "PENDING", ...({ authorization: null, scope: "" }) },
      { path: "defense/c.ts", change: "modified", historicalBlob: blob("defense/c.ts"), reviewedSha256: reviewedHash("defense/c.ts"), reviewedBlob: reviewedBlob("defense/c.ts"), reviewId: "T/c", hold: "none", status: "APPROVED", ...(bind) },
      { path: "defense/e.ts", change: "added", historicalBlob: null, reviewedSha256: reviewedHash("defense/e.ts"), reviewedBlob: reviewedBlob("defense/e.ts"), reviewId: "T/e", hold: "none", status: "APPROVED", ...(bind) },
    ];
    writeFileSync(path.join(dir, "defense/c.ts"), "export const c = 'edited again after review';\n"); // c: changed after its review
    run("add", "-A"); // an added file must be known to git for `git diff <baseline>` to list it (in the real repository added files are committed)
    const result = classifyDrift(dir, baseline, ["defense", "src"], registry);
    assert.deepEqual(result, { authorized: ["defense/a.ts", "defense/e.ts"], pending: ["defense/b.ts"], modifiedAfterReview: ["defense/c.ts"], unreviewed: ["defense/d.ts"] });
    // the byte-identity diff reports what is neither approved nor registered-clean; an APPROVED-but-edited file is excluded from the diff by status and is caught by the boundary assertion below
    // (exactly the reviewed-patch registry's division of labour: every guard calls BOTH)
    const remaining = git(dir, ["diff", "--name-only", baseline, "--", ...withoutReviewedChanges(["defense", "src"], registry)]).split("\n").filter(Boolean);
    assert.deepEqual(remaining, ["defense/b.ts", "defense/d.ts"]);
    // an APPROVED entry whose file changed after review fails its reviewed half
    assert.throws(() => assertMigrationBoundary(dir, baseline, registry), /exactly the reviewed/u);
    // an APPROVED entry WITHOUT authorization or scope exempts nothing and fails the boundary assertion
    const unbound = registry.map((entry) => (entry.path === "defense/a.ts" ? { ...entry, authorization: null, scope: "" } : entry));
    assert.ok(classifyDrift(dir, baseline, ["defense", "src"], unbound).pending.includes("defense/a.ts"));
    assert.ok(git(dir, ["diff", "--name-only", baseline, "--", ...withoutReviewedChanges(["defense", "src"], unbound)]).includes("defense/a.ts"));
    assert.throws(() => assertMigrationBoundary(dir, baseline, unbound), /must bind reviewedBlob, authorization and scope/u);
    // a wrong reviewed blob (same sha256 claim, different committed content identity) is modified-after-review, never authorized
    const wrongBlob = registry.map((entry) => (entry.path === "defense/a.ts" ? { ...entry, reviewedBlob: "1".repeat(40) } : entry));
    assert.ok(classifyDrift(dir, baseline, ["defense", "src"], wrongBlob).modifiedAfterReview.includes("defense/a.ts"));
    // a wrong historical half classifies as unreviewed, never as authorized
    const wrongHistory = registry.map((entry) => (entry.path === "defense/a.ts" ? { ...entry, historicalBlob: "0".repeat(40) } : entry));
    assert.ok(classifyDrift(dir, baseline, ["defense", "src"], wrongHistory).unreviewed.includes("defense/a.ts"));
    // approving everything that is registered and clean leaves only the genuinely unreviewed file
    writeFileSync(path.join(dir, "defense/c.ts"), "export const c = 1;\n");
    run("add", "-A");
    const clean = registry.map((entry) => ({ ...entry, status: "APPROVED" as const, ...bind }));
    assert.deepEqual(git(dir, ["diff", "--name-only", baseline, "--", ...withoutReviewedChanges(["defense", "src"], clean)]).split("\n").filter(Boolean), ["defense/d.ts"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("closure evidence on the real repository: which approvals empty which historical byte-identity diff", () => {
  const diff = (baseline: string, paths: string[], registry: readonly ReviewedMigration[]) => git(root, ["diff", "--name-only", baseline, "--", ...withoutReviewedChanges(paths, registry)]).split("\n").filter(Boolean);
  const instrumentation = approve(REVIEWED_MIGRATIONS, (entry) => entry.reviewId.startsWith("INSTRUMENTATION/"));
  assert.deepEqual(diff(MIGRATION_BASELINES[2], PATHS_AFF793E, instrumentation), [], "approving ONLY the two instrumentation files closes the aff793e guard");
  const withoutHolds = approve(REVIEWED_MIGRATIONS, (entry) => entry.hold === "none");
  const heldPaths = REVIEWED_MIGRATIONS.filter((entry) => entry.hold !== "none").map((entry) => entry.path).sort();
  for (const [name, baseline, paths] of GUARDS.slice(0, 2)) assert.deepEqual(diff(baseline, paths, withoutHolds), heldPaths, `${name}: with the 28 non-held entries approved, exactly the 16 held files remain`);
  const everything = approve(REVIEWED_MIGRATIONS, () => true);
  for (const [name, baseline, paths] of GUARDS) {
    assert.deepEqual(diff(baseline, paths, everything), [], `${name}: with all 44 approved the guard's diff is empty`);
    assertMigrationBoundary(root, baseline, everything);
  }
});

test("the three historical guards are wired to the registry (and stay wired): they exclude through withoutReviewedChanges and assert the migration boundary", () => {
  for (const file of ["lab-ba0-canary-continuity.test.ts", "lab-ba0-salvo-diagnostics.test.ts", "lab-ba0-salvo.test.ts"]) {
    const source = readFileSync(path.join(__dirname, file), "utf8");
    assert.match(source, /withoutReviewedChanges\(/u, file);
    assert.match(source, /assertMigrationBoundary\(root, /u, file);
    assert.match(source, /assertReviewedPatchBoundary\(root, /u, `${file}: the reviewed-patch boundary is still asserted`);
    assert.doesNotMatch(source, /withoutReviewedPatches\(/u, `${file}: no direct use of the narrower helper`);
  }
});

test("exact-file approval is not dependency closure and not deployment authorization: the pending dependencies of the two approved entries stay pending, and no approval is inherited through imports", () => {
  const byPath = new Map(REVIEWED_MIGRATIONS.map((entry) => [entry.path, entry]));
  const dependencies: Record<string, string[]> = {
    "workers/admin-gateway/index.ts": ["src/lib/ingress-protocol.ts", "workers/shared/bounded-jwks.ts"],
    "workers/lab-operator-lifecycle-executor.ts": ["src/lib/ingress-protocol.ts", "workers/admission-service/authority.ts", "workers/admission-service/operator-command.ts"],
  };
  for (const [approved, pending] of Object.entries(dependencies)) {
    assert.equal(byPath.get(approved)?.status, "APPROVED", approved);
    for (const dependency of pending) {
      const entry = byPath.get(dependency);
      assert.ok(entry !== undefined, `${dependency} is registered`);
      assert.equal(entry.status, "PENDING", `${dependency}: approving ${approved} does not approve its import`);
      assert.equal(isEffective(entry), false, dependency);
    }
  }
  // the classification (used by every guard) is per file: the dependencies appear as pending drift in every guard that covers them
  for (const [name, baseline, paths] of GUARDS.slice(0, 2)) {
    const result = classifyDrift(root, baseline, paths);
    for (const dependency of new Set(Object.values(dependencies).flat())) assert.ok(result.pending.includes(dependency), `${name}: ${dependency} is still pending drift`);
  }
  // the registry carries no deployment authority: no field of any entry names deployment, and the approval scopes say so explicitly
  for (const entry of REVIEWED_MIGRATIONS.filter((candidate) => NEW_APPROVALS.includes(candidate.path))) assert.match(entry.scope, /no deployment or production enablement/u);
  assert.deepEqual(Object.keys(REVIEWED_MIGRATIONS[0]).sort(), ["authorization", "change", "historicalBlob", "hold", "path", "reviewId", "reviewedBlob", "reviewedSha256", "scope", "status"]);
});
