import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

/**
 * The reviewed changes to files under defense/ made AFTER the historical baselines were fixed. The historical byte-identity guards keep
 * every baseline commit, every other path and every fingerprint exactly as they were; this registry is the ONLY exemption, and each entry
 * is one path with two explicit halves:
 *
 *   1. the HISTORICAL half: at each baseline commit the file is still the recorded pre-patch git blob (so the historical implementation
 *      is not re-labelled and no historical hash is replaced), and
 *   2. the PATCHED half: the working-tree file is exactly the reviewed implementation, pinned by content hash.
 *
 * Any other change to a listed file (including a later one) fails (2) until it is reviewed and pinned here on purpose; an unlisted file
 * stays under the original byte-identity rule. The patched behaviour itself is covered by the patch's own regression tests, not by these
 * guards. Adding an entry is a reviewed act, never a convenience.
 */
export type ReviewedPatch = {
  path: string;
  /** git blob id of the file at every baseline the guards compare against (64ccc9d, dcf10af, aff793e) and at 91d9e1a / 65a69a8's parent. */
  historicalBlob: string;
  /** sha256 of the reviewed working-tree file, line endings normalized to LF. */
  patchedSha256: string;
  reviewedIn: string;
};

export const FRONT_PATH = "defense/plane/front.ts";
export const REVIEWED_PATCHES: readonly ReviewedPatch[] = Object.freeze([
  // P0-01: rejected-body lifecycle at the Defense Plane front door.
  { path: FRONT_PATH, historicalBlob: "28287c782f2d51e9f1ca49ee22e2cc6119016ba5", patchedSha256: "4a3b7edae3c6ebb5b42856bfff890b7dda1e87af6bff94f9775a4fc5908f8046", reviewedIn: "P0-01" },
  // P0-02: expiry horizon (EH). tests/defense-expiry-horizon.test.ts covers the behaviour.
  { path: "defense/core/replay-guard.ts", historicalBlob: "63da012e54b30b3f5a413b1d1159d390c60feff4", patchedSha256: "1c6ed506e0930f48e9f9b46165b2a42ee47f5a3cbb534b595734ff9f4fb2c56f", reviewedIn: "P0-02" },
  { path: "defense/core/hop-admission.ts", historicalBlob: "a965443ce4f8567903b33331b75ec4c625d6fcf6", patchedSha256: "bbc45b0887008f54933cb058b05ad9d91aa8d4a6305840dfe36f2a8fb7d8cdbe", reviewedIn: "P0-02" },
  { path: "defense/core/types.ts", historicalBlob: "cde8b06dd6a8d27b94b792173b2fb1fcbf7a6150", patchedSha256: "a2eda89eeb077c8e7962cd770544b8552ceaccd77b91391c8a92e4a9a5d0aee4", reviewedIn: "P0-02" },
  { path: "defense/boundary/boundary.ts", historicalBlob: "28890df9650bc80aa2cf89a2db03b1656d1a0868", patchedSha256: "e0ed16569ef3821e31c7ae129feb199f9500ee826904e1cb5c45ae1e91d7b97b", reviewedIn: "P0-02" },
  { path: "defense/origin/synthetic-origin.ts", historicalBlob: "e0f405ae5ed2274ae2438faa58eb3b0afad9ee5b", patchedSha256: "81d79d367fa0d814de68f46af98298a3c09c4ca102cf922b27a8d239811ab081", reviewedIn: "P0-02" },
]);

const git = (root: string, args: string[]) => execFileSync("git", args, { cwd: root, encoding: "utf8" });
const sha256Lf = (text: string) => createHash("sha256").update(text.replace(/\r\n/g, "\n")).digest("hex");

export const reviewedPatchFor = (file: string): ReviewedPatch | undefined => REVIEWED_PATCHES.find((patch) => patch.path === file);

/** Pathspecs that cover `paths` except the reviewed files, so every other file under them stays byte-identical to the baseline. */
export const withoutReviewedPatches = (paths: readonly string[]): string[] => [...paths, ...REVIEWED_PATCHES.map((patch) => `:(exclude)${patch.path}`)];

/** Both halves of every exemption, for one historical baseline commit. */
export function assertReviewedPatchBoundary(root: string, baseline: string): void {
  for (const patch of REVIEWED_PATCHES) {
    assert.equal(git(root, ["rev-parse", `${baseline}:${patch.path}`]).trim(), patch.historicalBlob, `${patch.path}: the historical file at the baseline is the unmodified pre-patch blob`);
    assert.equal(sha256Lf(readFileSync(path.join(root, patch.path), "utf8")), patch.patchedSha256, `${patch.path}: exactly the reviewed ${patch.reviewedIn} implementation`);
  }
}

/** sha256 (LF-normalized) of a file as it was at a historical commit, read from git and never from the working tree. */
export const historicalSha256 = (root: string, commit: string, file: string): string => sha256Lf(git(root, ["show", `${commit}:${file}`]));
export const workingSha256 = (root: string, file: string): string => sha256Lf(readFileSync(path.join(root, file), "utf8"));
