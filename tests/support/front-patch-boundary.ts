import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

/**
 * P0-01 (rejected-body lifecycle) is the one reviewed change to the Defense Plane front door after the historical baselines were fixed.
 * The historical byte-identity guards keep every baseline commit, every other path and every fingerprint exactly as they were; this
 * module is the ONLY exemption, and it is a single path with two explicit halves:
 *
 *   1. the HISTORICAL half: at each baseline commit, front.ts is still the pre-patch blob (so the historical implementation is not
 *      re-labelled and no baseline hash is replaced), and
 *   2. the PATCHED half: the working-tree front.ts is exactly the reviewed P0-01 implementation, pinned by content hash.
 *
 * Any other change to front.ts (including a later one) fails (2) until it is reviewed and pinned here on purpose. The patched behaviour
 * itself is covered by tests/defense-front-rejected-body.test.ts, not by these guards.
 */
export const FRONT_PATH = "defense/plane/front.ts";
/** git blob id of front.ts at every historical baseline (64ccc9d, dcf10af, aff793e) and at 91d9e1a, the commit the patch was made on. */
export const FRONT_HISTORICAL_BLOB = "28287c782f2d51e9f1ca49ee22e2cc6119016ba5";
/** sha256 of the reviewed P0-01 front.ts (line endings normalized to LF). */
export const FRONT_PATCHED_SHA256 = "4a3b7edae3c6ebb5b42856bfff890b7dda1e87af6bff94f9775a4fc5908f8046";

const git = (root: string, args: string[]) => execFileSync("git", args, { cwd: root, encoding: "utf8" });

/** Pathspecs that cover `paths` except the one patched file, so every other file under them stays byte-identical to the baseline. */
export const withoutPatchedFront = (paths: readonly string[]): string[] => [...paths, `:(exclude)${FRONT_PATH}`];

/** The two halves of the exemption for one historical baseline commit. */
export function assertFrontPatchBoundary(root: string, baseline: string): void {
  assert.equal(git(root, ["rev-parse", `${baseline}:${FRONT_PATH}`]).trim(), FRONT_HISTORICAL_BLOB, "the historical front.ts at the baseline is the unmodified pre-patch blob");
  const current = createHash("sha256").update(readFileSync(path.join(root, FRONT_PATH), "utf8").replace(/\r\n/g, "\n")).digest("hex");
  assert.equal(current, FRONT_PATCHED_SHA256, "front.ts is exactly the reviewed P0-01 implementation");
}
