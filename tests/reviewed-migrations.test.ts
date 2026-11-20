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
const GUARDS: Array<[string, string, string[], number]> = [["64ccc9d", MIGRATION_BASELINES[0], PATHS_64CCC9D, 5], ["dcf10af8", MIGRATION_BASELINES[1], PATHS_DCF10AF8, 5], ["aff793e", MIGRATION_BASELINES[2], PATHS_AFF793E, 0]];
const NEW_APPROVALS = ["workers/admin-gateway/index.ts", "workers/lab-operator-lifecycle-executor.ts"];
// Owner decision of 2026-11-09 ('Unified Acceptance False-PASS Closure and Targeted Migration Review'): exactly this one further entry, at its reviewed blob.
const JWKS_APPROVAL = "workers/shared/bounded-jwks.ts";
// Owner decision of 2026-11-09 ('Campaign Acceptance Trust Closure and Ingress Protocol Approval'): exactly this one further entry, at its reviewed blob.
const INGRESS_APPROVAL = "src/lib/ingress-protocol.ts";
// Owner decision of 2026-11-09 ('Migration Batch Closure and M1 Environment Preparation'): exactly these 27 entries (batches B1-B3), each at its reviewed blob. Nothing else is approved.
export const BATCH_APPROVALS = [
  "workers/admission-service/authority.ts", "workers/admission-service/operator-command.ts", "workers/admission-service/authority-attestation.ts", "workers/admission-service/authority-attestation-config.ts",
  "workers/admission-service/authority-attestation-signer.ts", "src/lib/authority-result-attestation.ts", "src/lib/authority-result-trust.ts",
  "workers/admission-service/auth.ts", "workers/admission-service/service.ts", "workers/admission-service/index.ts", "workers/admission-service/production-index.ts", "workers/admission-service/lab-index.ts",
  "src/lib/ingress-verifier.server.ts", "src/lib/public-origin.ts", "src/proxy.ts", "src/lib/public-inquiry-handler.server.ts", "src/lib/admission-client.server.ts", "src/lib/db/database.server.ts",
  "src/lib/public-inquiry-runtime.server.ts", "src/app/test-talep-et/page.tsx", "src/lib/public-inquiry-otel.server.ts", "src/lib/public-inquiry-telemetry.server.ts",
  "workers/ingress-signer/google-id-token.ts", "workers/ingress-signer/signer.ts", "workers/ingress-signer/index.ts", "workers/ingress-signer/laboratory-index.ts", "workers/lab-lifecycle-observer.ts",
];
// Owner decision of 2026-11-10 ('Owner Authorization: Six Reviewed Migrations'): exactly these six entries, each at its reviewed blob (pinned below). File-scoped and blob-specific;
// the production-preparation three authorize no enablement, deployment or real-provider claim; the laboratory three are limited to the isolated laboratory runtime.
export const PRODUCTION_PREPARATION_APPROVALS: Array<[string, string]> = [
  ["src/app/api/public-inquiries/route.ts", "6e2ad42b582b3afe9eaa8a34ed7939098a69f612"],
  ["src/lib/production-launch-policy.ts", "c7c6efdbe7b35f305828fd39867684a3520a019d"],
  ["src/lib/public-inquiry-production-runtime.server.ts", "60feab9014d6bf091262fb390b2bd2688f893f64"],
];
export const LABORATORY_MAILBOX_APPROVALS: Array<[string, string]> = [
  ["workers/lifecycle-mailbox/lab-dispatch-guard.ts", "90785956c990ef9496bb8829a84dcb151d28c0c3"],
  ["workers/lifecycle-mailbox/lab-index.ts", "c0fa2d23fd4b07f404c326251b80b5c4a7b5053a"],
  ["workers/lifecycle-mailbox/lab-processor.ts", "0e702b3bdd60b3ce877839d858ab7e0e64b76017"],
];
const SIX_APPROVALS = [...PRODUCTION_PREPARATION_APPROVALS, ...LABORATORY_MAILBOX_APPROVALS].map(([file]) => file);
// Entries that must stay PENDING: the Gate 11A guard-export set (owner decision 2026-11-10: the legacy operator-key verifier is not approved as an interim design).
// Each is pinned with its historical blob, reviewed blob and hold, so neither its identity nor its hold can change unnoticed.
export const STILL_PENDING_PINS: Array<[string, string | null, string]> = [
  ["workers/lifecycle-mailbox/dispatch-guard.ts", "8080226f215ab351cca3560b49ecd7db66ce4302", "b73b00460913469ae642b70764724ff01f6c9b23"],
  ["workers/lifecycle-mailbox/guard-export.ts", null, "201335cf0bba26f6c003eeeeb00beae05c1c177f"],
  ["workers/lifecycle-mailbox/guard-reader.ts", null, "8714bd2e776fb92b0d12acb03f88c89c8636f80c"],
  ["workers/lifecycle-mailbox/index.ts", "3464a3e0bb00ff8192cb2fea1d81f613c3e30020", "c030292698f396cd4875e0851f0fa673e47fae2d"],
  ["workers/lifecycle-observer.ts", "04c47007be9f3df61f108b67c4f18d571bff7c2f", "cb2f9cc72ba944c10425eefd3aad8a232236b9c7"],
];
export const STILL_PENDING = STILL_PENDING_PINS.map(([file]) => file);
const INSTRUMENTATION = ["defense/core/outcome-counters.ts", "defense/plane/runtime.ts"];
const M2_APPROVALS = [
  "defense/core/capacity-boundary.ts", "defense/core/capacity-heap.ts", "defense/core/capacity-policy.ts",
  "defense/core/capacity-port.ts", "defense/core/origin-capacity.ts",
];
const APPROVED_PATHS = [...INSTRUMENTATION, ...NEW_APPROVALS, JWKS_APPROVAL, INGRESS_APPROVAL, ...BATCH_APPROVALS, ...SIX_APPROVALS, ...M2_APPROVALS].sort();

test("registry shape: 49 exact files, 44 owner-approved and five Gate 11A holds, all current against the working tree", () => {
  assert.equal(MIGRATION_REGISTRY_VERSION, 1);
  assert.equal(REVIEWED_MIGRATIONS.length, 49);
  assert.equal(new Set(REVIEWED_MIGRATIONS.map((entry) => entry.path)).size, 49);
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
  const approvedNow = REVIEWED_MIGRATIONS.filter((entry) => entry.status === "APPROVED").map((entry) => entry.path).sort();
  assert.equal(approvedNow.length, 44);
  assert.deepEqual(approvedNow, APPROVED_PATHS);
  const m2Entries = REVIEWED_MIGRATIONS.filter((entry) => entry.reviewId === "BASELINE-V2/M2_INVENTORY_ADDITIONS");
  assert.deepEqual(m2Entries.map((entry) => entry.path).sort(), [...M2_APPROVALS].sort());
  for (const entry of m2Entries) {
    assert.deepEqual([entry.change, entry.historicalBlob, entry.hold, entry.status], ["added", null, "none", "APPROVED"], entry.path);
    assert.equal(entry.authorization, `Owner decision 'LimitMark — Owner-Authorized M2 Migration Registry Approval' for ${entry.path} at blob ${entry.reviewedBlob} and LF-normalized SHA-256 ${entry.reviewedSha256}; independently reviewed tree fafd3e7324936a8174576c734a8be4a41b22cbad.`);
    assert.equal(entry.scope, `Only the exact added ${entry.path} in the historical byte-identity diffs against 64ccc9d, dcf10af8, and aff793e. File-specific and non-transitive. Grants no runtime, deployment, or production enablement authority.`);
  }
  assert.equal(REVIEWED_MIGRATIONS.filter((entry) => entry.status === "PENDING").length, 5);
  assert.deepEqual(REVIEWED_MIGRATIONS.filter((entry) => entry.status === "PENDING").map((entry) => entry.path).sort(), [...STILL_PENDING].sort());
  // The five Gate 11A entries: still PENDING, same historical and reviewed blobs, same hold, no authorization, no scope.
  for (const [file, historicalBlob, reviewedBlob] of STILL_PENDING_PINS) {
    const entry = REVIEWED_MIGRATIONS.find((candidate) => candidate.path === file)!;
    assert.deepEqual([entry.status, entry.historicalBlob, entry.reviewedBlob, entry.hold, entry.reviewId, entry.authorization, entry.scope],
      ["PENDING", historicalBlob, reviewedBlob, "guard-export", "BASELINE-V2/GATE_11A_GUARD_EXPORT", null, ""], file);
  }
  // The six approvals of 2026-11-10: blob-specific (the authorization names the exact reviewed blob), never a Gate 11A entry, and each group carries its own restriction in the authorization itself.
  for (const [group, restriction] of [[PRODUCTION_PREPARATION_APPROVALS, /as a production-preparation artifact; it does not authorize production enablement, deployment, or claims about untested external providers/u],
    [LABORATORY_MAILBOX_APPROVALS, /limited to the isolated laboratory runtime; it does not extend to the production lifecycle guard or to Gate 11A export functionality/u]] as const) {
    for (const [file, reviewedBlob] of group) {
      const entry = REVIEWED_MIGRATIONS.find((candidate) => candidate.path === file)!;
      assert.deepEqual([entry.status, entry.reviewedBlob, entry.hold], ["APPROVED", reviewedBlob, "none"], file);
      assert.match(entry.authorization ?? "", /^Owner decision 'Owner Authorization: Six Reviewed Migrations' \(2026-11-10\)/u, file);
      assert.ok((entry.authorization ?? "").includes(`recognizes only the reviewed current blob ${reviewedBlob} of this file`), `${file}: the authorization is blob-specific`);
      assert.match(entry.authorization ?? "", restriction, file);
      assert.match(entry.authorization ?? "", /is not inherited by other files or by any future blob version$/u, file);
      assert.match(entry.scope, /file-scoped and not transitive/u, file);
      assert.match(entry.scope, /authorizes no deployment or production enablement/u, file);
      assert.equal(/GATE_11A/u.test(entry.reviewId), false, file);
    }
  }
  for (const [file] of PRODUCTION_PREPARATION_APPROVALS) assert.match(REVIEWED_MIGRATIONS.find((candidate) => candidate.path === file)!.scope, /makes no claim about real-provider integration$/u, file);
  for (const [file] of LABORATORY_MAILBOX_APPROVALS) assert.match(REVIEWED_MIGRATIONS.find((candidate) => candidate.path === file)!.scope, /does not approve the production dispatch guard$/u, file);
  for (const entry of REVIEWED_MIGRATIONS.filter((candidate) => BATCH_APPROVALS.includes(candidate.path))) {
    assert.match(entry.authorization ?? "", /^Owner decision 'Migration Batch Closure and M1 Environment Preparation' \(2026-11-09\)/u, entry.path);
    assert.match(entry.scope, /file-scoped and not transitive/u, entry.path);
    assert.match(entry.scope, /authorizes no deployment or production enablement/u, entry.path);
    assert.equal(entry.hold === "guard-export", false, `${entry.path}: no Gate 11A guard-export entry is approved`);
    assert.equal(/GATE_11A/u.test(entry.reviewId), false, entry.path);
  }
  const ingress = REVIEWED_MIGRATIONS.find((entry) => entry.path === INGRESS_APPROVAL)!;
  assert.deepEqual([ingress.historicalBlob, ingress.reviewedBlob, ingress.reviewId, ingress.hold], ["04de4ef57d95ccbc7fe9b523f6e85da861f39851", "15e374c3604ddd6b7a236d40adde9d76f0391b69", "BASELINE-V2/LABORATORY", "shared-production-module"]);
  assert.match(ingress.authorization ?? "", /^Owner decision 'Campaign Acceptance Trust Closure and Ingress Protocol Approval' \(2026-11-09\)/u);
  assert.match(ingress.scope, /Production limitmark\.com host pin, audience, deployment, key and signature validation are unchanged/u);
  assert.match(ingress.scope, /separate PENDING entries and are not approved/u);
  const jwks = REVIEWED_MIGRATIONS.find((entry) => entry.path === JWKS_APPROVAL)!;
  assert.deepEqual([jwks.historicalBlob, jwks.reviewedBlob, jwks.reviewId, jwks.hold], ["00c28240f03c35f82fd08fd44e70cfaf9bb5fcc6", "7941034b7c1de456796a3cdd31fcb56de5eef699", "BASELINE-V2/SHARED_FIX", "none"]);
  assert.match(jwks.authorization ?? "", /^Owner decision 'Unified Acceptance False-PASS Closure and Targeted Migration Review' \(2026-11-09\)/u);
  assert.match(jwks.scope, /no deployment or production enablement/u);
  assert.match(jwks.scope, /separate PENDING entry and is not approved/u);
  for (const entry of REVIEWED_MIGRATIONS.filter((candidate) => NEW_APPROVALS.includes(candidate.path))) {
    assert.match(entry.authorization ?? "", /^Owner decision 'Criterion 9 Closure, Two Migration Approvals, and Observer Isolation' \(2026-11-09\)/u, entry.path);
    assert.match(entry.scope, /no deployment or production enablement/u, entry.path);
  }
  assert.equal(REVIEWED_MIGRATIONS.find((entry) => entry.path === "workers/admin-gateway/index.ts")?.reviewedBlob, "9c159eaf416dffe751e2fa66cb262ab3acc4c8a4");
  assert.equal(REVIEWED_MIGRATIONS.find((entry) => entry.path === "workers/lab-operator-lifecycle-executor.ts")?.reviewedBlob, "dadcb9769e11e67eaf8c01711a9150a159aa51fc");
  const holds = (hold: string) => REVIEWED_MIGRATIONS.filter((entry) => entry.hold === hold).length;
  assert.deepEqual([holds("none"), holds("shared-production-module"), holds("guard-export")], [33, 11, 5]);
});

test("real repository: each baseline has only exact approved drift and its applicable Gate 11A holds", () => {
  for (const [name, baseline, paths, expected] of GUARDS) {
    const result = classifyDrift(root, baseline, paths);
    assert.deepEqual(result.unreviewed, [], `${name}: unreviewed drift`);
    assert.deepEqual(result.modifiedAfterReview, [], `${name}: modified after review`);
    assert.deepEqual([...result.authorized].sort(), name === "aff793e" ? [...INSTRUMENTATION, ...M2_APPROVALS].sort() : APPROVED_PATHS, `${name}: exactly the approved entries inside this guard's paths are authorized`);
    assert.deepEqual([...result.pending].sort(), expected === 0 ? [] : [...STILL_PENDING].sort(), `${name}: pending drift`);
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
  const pendingM2 = REVIEWED_MIGRATIONS.map((entry): ReviewedMigration =>
    M2_APPROVALS.includes(entry.path) ? { ...entry, status: "PENDING", authorization: null, scope: "" } : entry);
  for (const [name, baseline, paths, expected] of GUARDS) {
    const held = expected === 0 ? [] : STILL_PENDING;
    assert.deepEqual(diff(baseline, paths, pendingM2).sort(), [...M2_APPROVALS, ...held].sort(), `${name}: pending M2 remains visible`);
    assert.deepEqual(diff(baseline, paths, REVIEWED_MIGRATIONS).sort(), [...held].sort(), `${name}: only applicable Gate 11A holds remain`);
    assertMigrationBoundary(root, baseline);
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
    // bounded-jwks is a dependency of the gateway but is approved ONLY by its own explicit owner decision (JWKS_APPROVAL, asserted in the registry-shape test), never by this entry
    "workers/admin-gateway/index.ts": [],
    // authority.ts and operator-command.ts are now approved, each ONLY by its own entry in BATCH_APPROVALS (never through this executor)
    "workers/lab-operator-lifecycle-executor.ts": [],
    // approved batch entries whose importers remain held: the held importer is not approved by its import being approved.
    // (Their former held importers -- the production runtime factory, the route, the laboratory dispatch guard and processor -- are approved since 2026-11-10,
    // each ONLY by its own entry in the six approvals asserted in the registry-shape test, never through these imports.)
    "src/lib/admission-client.server.ts": [],
    "workers/admission-service/authority.ts": ["workers/lifecycle-mailbox/dispatch-guard.ts"],
    "workers/admission-service/operator-command.ts": ["workers/lifecycle-mailbox/dispatch-guard.ts"],
    "src/lib/public-inquiry-handler.server.ts": [],
    // approving the laboratory mailbox files does not approve the production dispatch guard they name in a type-only import, nor anything else in the Gate 11A set
    "workers/lifecycle-mailbox/lab-dispatch-guard.ts": ["workers/lifecycle-mailbox/dispatch-guard.ts"],
    "workers/lifecycle-mailbox/lab-processor.ts": ["workers/lifecycle-mailbox/dispatch-guard.ts"],
    "workers/lifecycle-mailbox/lab-index.ts": [...STILL_PENDING],
  };
  for (const [approved, pending] of Object.entries(dependencies)) {
    assert.equal(byPath.get(approved)?.status, "APPROVED", approved);
    for (const dependency of pending) {
      const entry = byPath.get(dependency);
      assert.ok(entry !== undefined, `${dependency} is registered`);
      assert.equal(entry.status, "PENDING", `${dependency}: approving ${approved} does not approve its importer`);
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
