import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";

export type ReviewedAddition = readonly [file: string, blob: string, sha256: string];
export type AdmissionReview = { ownerDecision?: string; isolationEvidence?: string };

export function normalizedSha256(bytes: Buffer): string {
  // Latin-1 round trips every byte, so only CRLF pairs change.
  return createHash("sha256").update(Buffer.from(bytes.toString("latin1").replace(/\r\n/g, "\n"), "latin1")).digest("hex");
}

export function verifyBa0Inventory(options: {
  root: string;
  scopes: readonly string[];
  historical: ReadonlyMap<string, string>;
  additions: readonly ReviewedAddition[];
  review: AdmissionReview;
  mode: "pre-commit" | "committed";
  candidateCommit?: string;
}): void {
  const { root, scopes, historical, additions, review, mode, candidateCommit } = options;
  const git = (...args: string[]) => execFileSync("git", ["--no-optional-locks", "--no-replace-objects", "--literal-pathspecs", ...args], { cwd: root, maxBuffer: 1 << 26 });
  assert.ok(mode === "pre-commit" || mode === "committed", "invalid inventory verification mode");
  const authorized = Boolean(review.ownerDecision?.trim() && review.isolationEvidence?.trim());
  if (mode === "committed") {
    assert.ok(candidateCommit && /^[a-f0-9]{40}$/u.test(candidateCommit), "committed acceptance requires a full candidate commit ID");
    assert.equal(git("cat-file", "-t", candidateCommit).toString().trim(), "commit", "candidate object is not a commit");
    assert.equal(candidateCommit, git("rev-parse", "--verify", "HEAD").toString().trim(), "candidate commit is not the checkout revision");
  } else {
    assert.equal(candidateCommit, undefined, "pre-commit review does not accept a candidate commit selector");
  }
  const records = (bytes: Buffer) => {
    const decoded = bytes.toString("utf8");
    assert.ok(Buffer.from(decoded).equals(bytes), "Git paths must be valid UTF-8");
    return decoded.split("\0").filter(Boolean);
  };
  const expected = new Map<string, readonly [string, string?]>();
  for (const [file, blob] of historical) expected.set(file, [blob]);
  for (const [file, blob, digest] of additions) {
    assert.match(file, /^[a-z0-9_-]+(?:\/[a-z0-9_-]+)*\.[a-z0-9]+$/u, "malformed admission path");
    assert.ok(scopes.some(scope => file === scope || file.startsWith(scope + "/")), "admission outside scope");
    assert.ok(!expected.has(file), "duplicate or overlapping admission");
    assert.match(blob, /^[a-f0-9]{40}$/u, "malformed admission blob");
    assert.match(digest, /^[a-f0-9]{64}$/u, "malformed admission digest");
    expected.set(file, [blob, digest]);
  }
  const index = new Map<string, string>();
  for (const record of records(git("ls-files", "--stage", "-z", "--", ...scopes))) {
    const match = /^(\d+) ([a-f0-9]+) (\d)\t([\s\S]+)$/u.exec(record);
    assert.ok(match, "malformed index entry");
    const [, mode, blob, stage, file] = match;
    assert.equal(stage, "0", `unmerged index entry: ${file}`);
    assert.equal(mode, "100644", `invalid index mode: ${file}`);
    assert.ok(!index.has(file), `duplicate index entry: ${file}`);
    index.set(file, blob);
  }
  // With no exclude options, Git reports ignored files too.
  const untracked = new Set(records(git("ls-files", "--others", "-z", "--", ...scopes)));
  for (const file of [...index.keys(), ...untracked]) assert.ok(expected.has(file), `unexpected protected path: ${file}`);
  for (const file of historical.keys()) assert.ok(index.has(file), `missing historical index path: ${file}`);
  assert.deepEqual(records(git("diff", "--cached", "--no-renames", "--diff-filter=D", "--name-only", "-z", "--", ...scopes)),
    [], "staged deletion in protected scope");

  const committed = new Map<string, string>();
  if (candidateCommit !== undefined) {
    assert.match(candidateCommit, /^[a-f0-9]{40}$/u, "candidate must be a full commit ID");
    assert.equal(git("cat-file", "-t", candidateCommit).toString().trim(), "commit");
    for (const record of records(git("ls-tree", "-r", "-z", candidateCommit, "--", ...scopes))) {
      const match = /^100644 blob ([a-f0-9]+)\t([\s\S]+)$/u.exec(record);
      assert.ok(match, "invalid committed mode or object type");
      const [, blob, file] = match;
      assert.ok(expected.has(file), `unexpected committed path: ${file}`);
      committed.set(file, blob);
    }
  }

  const presentAdditions = additions.filter(([file]) => index.has(file) || untracked.has(file) || committed.has(file));
  if (presentAdditions.length || review.ownerDecision || review.isolationEvidence) {
    assert.equal(presentAdditions.length, additions.length, "incomplete reviewed additions");
  }
  const trustFileMode = git("config", "--type=bool", "--default=false", "--get", "core.filemode").toString().trim() === "true";
  const canonicalRoot = realpathSync(root);
  for (const [file, [blob, digest]] of expected) {
    if (digest && !presentAdditions.some(([addition]) => addition === file)) continue;
    const absolute = path.join(root, file);
    const stat = lstatSync(absolute, { throwIfNoEntry: false });
    assert.ok(stat && stat.isFile(), `missing or non-regular worktree file: ${file}`);
    if (trustFileMode) assert.equal(stat.mode & 0o100, 0, `invalid worktree mode: ${file}`);
    assert.equal(realpathSync(absolute), path.join(canonicalRoot, file), `non-canonical worktree path: ${file}`);
    assert.equal(git("hash-object", "--", file).toString().trim(), blob, `wrong worktree blob: ${file}`);
    const indexedBlob = index.get(file);
    if (authorized || candidateCommit !== undefined) assert.ok(indexedBlob, `missing required index entry: ${file}`);
    if (indexedBlob !== undefined) assert.equal(indexedBlob, blob, `wrong index blob: ${file}`);
    const committedBlob = committed.get(file);
    if (candidateCommit !== undefined) assert.equal(committedBlob, blob, `wrong committed blob: ${file}`);
    if (digest) {
      assert.equal(normalizedSha256(readFileSync(absolute)), digest, `wrong normalized worktree digest: ${file}`);
      if (indexedBlob !== undefined) {
        assert.equal(normalizedSha256(git("cat-file", "blob", indexedBlob)), digest, `wrong normalized indexed digest: ${file}`);
      }
      if (committedBlob !== undefined) {
        assert.equal(normalizedSha256(git("cat-file", "blob", committedBlob)), digest, `wrong normalized committed digest: ${file}`);
      }
    }
  }
  if (presentAdditions.length) {
    assert.ok(authorized,
      "M2 BA0 admission PENDING: explicit owner authorization and reviewed isolation evidence are required");
  }
}
