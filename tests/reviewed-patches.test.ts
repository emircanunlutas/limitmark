import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { REVIEWED_PATCHES, assertReviewedPatchBoundary, withoutReviewedPatches, workingSha256 } from "./support/reviewed-patches";

/**
 * The reviewed-patch registry is the only exemption from the historical byte-identity guards. These tests pin its own shape, so it cannot
 * quietly grow into a wildcard, and show that each exemption is exactly one file with both halves checked.
 */
const root = path.join(__dirname, "..");
const BASELINES = ["64ccc9dabdde81fbc844807f8c104d707151de5e", "dcf10af8229a5738b1852721fe12de86a488d07d", "aff793e4968cd5615e25665c5437e20d268d744f"];
const git = (args: string[]) => execFileSync("git", args, { cwd: root, encoding: "utf8" });

test("the registry is a closed list of single defense/ files with well-formed pins (no globs, no duplicates)", () => {
  assert.deepEqual(REVIEWED_PATCHES.map((patch) => patch.path).sort(), [
    "defense/boundary/boundary.ts", "defense/core/hop-admission.ts", "defense/core/replay-guard.ts", "defense/core/types.ts", "defense/origin/synthetic-origin.ts", "defense/plane/front.ts",
  ], "adding or removing an exemption is a reviewed change to THIS assertion");
  for (const patch of REVIEWED_PATCHES) {
    assert.match(patch.path, /^defense\/[A-Za-z0-9_\/-]+\.ts$/, patch.path);
    assert.match(patch.historicalBlob, /^[0-9a-f]{40}$/, patch.path);
    assert.match(patch.patchedSha256, /^[0-9a-f]{64}$/, patch.path);
    assert.ok(existsSync(path.join(root, patch.path)), patch.path);
  }
  assert.equal(new Set(REVIEWED_PATCHES.map((patch) => patch.path)).size, REVIEWED_PATCHES.length);
});

test("each baseline: every listed file IS the historical pre-patch blob there and IS the pinned reviewed version here", () => {
  for (const baseline of BASELINES) assertReviewedPatchBoundary(root, baseline);
});

test("the exemption removes exactly the listed files from the diff and nothing else: without it the listed files differ, with it the diff over them is empty", () => {
  const listed = REVIEWED_PATCHES.map((patch) => patch.path);
  for (const baseline of BASELINES) {
    const changed = git(["diff", "--name-only", baseline, "--", ...listed]).split("\n").filter(Boolean).sort();
    assert.deepEqual(changed, [...listed].sort(), "every listed file really differs from the baseline, so the exemption is not vacuous");
    assert.equal(git(["diff", baseline, "--", ...withoutReviewedPatches(listed)]), "");
  }
  assert.deepEqual(withoutReviewedPatches(["defense", "x"]).slice(0, 2), ["defense", "x"]);
  assert.ok(withoutReviewedPatches(["defense"]).slice(1).every((spec) => spec.startsWith(":(exclude)defense/") && !spec.includes("*")));
});

test("every listed file in the working tree is exactly its pinned reviewed content", () => {
  for (const patch of REVIEWED_PATCHES) assert.equal(workingSha256(root, patch.path), patch.patchedSha256, patch.path);
});
