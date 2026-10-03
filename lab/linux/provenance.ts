/**
 * Provenance of the Linux parity image: which commit and which working tree it was built from, and whether a REUSED image
 * (`--skip-build`) still corresponds to the tree being reported. An image built from yesterday's tree must never be recorded
 * next to today's commit.
 *
 * The digest covers exactly what the build context contains from git's point of view: HEAD, every tracked change
 * (`git diff --binary HEAD`) and every untracked, non-ignored file (name and content hash). Everything gitignored is
 * excluded from the build context (Dockerfile.dockerignore is pinned to be a superset of .gitignore by tests), so the digest
 * describes the context completely.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { REPOSITORY_ROOT } from "../evidence/manifest";

export const IMAGE_COMMIT_LABEL = "limitmark.lab.commit";
export const IMAGE_TREE_LABEL = "limitmark.lab.tree";

export type TreeIdentity = { gitSha: string; treeSha256: string; dirty: boolean };

/** Pure: the digest over the three ingredients. Order-independent for untracked files. */
export function treeDigest(parts: { head: string; diff: Buffer | string; untracked: readonly { path: string; sha256: string }[] }): string {
  const hash = createHash("sha256");
  hash.update(`head:${parts.head}\n`);
  hash.update("diff:"); hash.update(parts.diff); hash.update("\n");
  for (const entry of [...parts.untracked].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) hash.update(`untracked:${entry.sha256}  ${entry.path}\n`);
  return hash.digest("hex");
}

function git(args: string[]): Buffer {
  return execFileSync("git", args, { cwd: REPOSITORY_ROOT, maxBuffer: 256 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] });
}

export function collectTreeIdentity(): TreeIdentity {
  const head = git(["rev-parse", "HEAD"]).toString("utf8").trim();
  if (!/^[0-9a-f]{40}$/.test(head)) throw new Error("cannot determine HEAD");
  const diff = git(["diff", "--binary", "HEAD"]);
  const untrackedPaths = git(["ls-files", "--others", "--exclude-standard", "-z"]).toString("utf8").split("\0").filter(Boolean);
  const untracked = untrackedPaths.map((relative) => ({ path: relative, sha256: createHash("sha256").update(readFileSync(path.join(REPOSITORY_ROOT, relative))).digest("hex") }));
  return { gitSha: head, treeSha256: treeDigest({ head, diff, untracked }), dirty: diff.length > 0 || untracked.length > 0 };
}

/** Pure: throws unless the image's recorded commit and tree equal the tree being reported. */
export function assertImageMatchesTree(labels: Readonly<Record<string, string>> | null, current: TreeIdentity): void {
  const commit = labels?.[IMAGE_COMMIT_LABEL];
  const tree = labels?.[IMAGE_TREE_LABEL];
  if (!commit || !tree) throw new Error("the parity image carries no provenance labels (it was not built by this tool); rebuild it without --skip-build");
  if (commit !== current.gitSha) throw new Error("the parity image was built from a different commit than HEAD; rebuild it without --skip-build");
  if (tree !== current.treeSha256) throw new Error("the parity image was built from a different working tree than the one being reported; rebuild it without --skip-build");
}
