import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test, type TestContext } from "node:test";
import { normalizedSha256, verifyBa0Inventory, type ReviewedAddition } from "./support/ba0-inventory";

const history = "protected/history.ts";
const candidate = "protected/candidate.ts";
const fixtureReview = { ownerDecision: "fixture decision", isolationEvidence: "fixture evidence" };

function fixture(t: TestContext) {
  const root = mkdtempSync(path.join(tmpdir(), "ba0-inventory-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const git = (...args: string[]) => execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
  const write = (name: string, data: string) => writeFileSync(path.join(root, name), data);
  git("init", "--quiet");
  mkdirSync(path.join(root, "protected"));
  write(".gitattributes", "* text=auto eol=lf\n");
  write(".gitignore", "*.ignored\n");
  write(history, "historical\n");
  write(candidate, "candidate\n");
  git("add", "--", history);
  const historical = new Map([[history, git("hash-object", "--", history)]]);
  const addition: ReviewedAddition = [candidate, git("hash-object", "--", candidate), normalizedSha256(Buffer.from("candidate\n"))];
  const options = { root, scopes: ["protected"], historical, additions: [addition], review: fixtureReview, mode: "pre-commit" as const };
  return { root, git, write, addition, options };
}

test("authorized pre-commit review requires a stage-0 entry for the addition", t => {
  const { git, options } = fixture(t);
  assert.throws(() => verifyBa0Inventory(options), /missing required index entry: protected\/candidate\.ts/u);
  git("add", "--", candidate);
  verifyBa0Inventory(options);
});

test("a clean filter cannot substitute different indexed bytes for the reviewed worktree digest", t => {
  const { git, write, addition, options } = fixture(t);
  write(".gitattributes", "* text=auto eol=lf\nprotected/candidate.ts filter=fixture\n");
  write("filter.cjs", 'process.stdout.write(require("node:fs").readFileSync(0, "utf8").toUpperCase());');
  git("config", "filter.fixture.clean", "node filter.cjs");
  git("config", "filter.fixture.required", "true");
  git("add", "--", candidate);
  const filteredBlob = git("rev-parse", ":" + candidate);
  assert.equal(git("hash-object", "--", candidate), filteredBlob);
  assert.notEqual(filteredBlob, addition[1]);
  assert.throws(() => verifyBa0Inventory({ ...options, additions: [[candidate, filteredBlob, addition[2]]] }),
    /wrong normalized indexed digest/u);
});

test("inventory accepts CRLF and ignores out-of-scope files but rejects protected extras", t => {
  const { write, git, options } = fixture(t);
  git("add", "--", candidate);
  write(candidate, "candidate\r\n");
  write("outside.ignored", "local output");
  verifyBa0Inventory(options);
  write("protected/sixth.ignored", "unexpected");
  assert.throws(() => verifyBa0Inventory(options), /unexpected protected path/u);
});

test("inventory rejects missing, altered and locally recreated historical paths", t => {
  const { root, git, write, options } = fixture(t);
  rmSync(path.join(root, history));
  assert.throws(() => verifyBa0Inventory(options), /missing or non-regular worktree file/u);
  write(history, "changed\n");
  assert.throws(() => verifyBa0Inventory(options), /wrong worktree blob/u);
  write(history, "historical\n");
  git("update-index", "--force-remove", "--", history);
  assert.throws(() => verifyBa0Inventory(options), /missing historical index path/u);
});

test("inventory rejects staged blob disagreement, invalid modes and unmerged stages", t => {
  const { root, git, write, addition, options } = fixture(t);
  write(candidate, "wrong staged bytes\n");
  git("add", "--", candidate);
  write(candidate, "candidate\n");
  assert.throws(() => verifyBa0Inventory(options), /wrong index blob/u);
  for (const mode of ["100755", "120000", "160000"]) {
    git("update-index", "--cacheinfo", `${mode},${addition[1]},${candidate}`);
    assert.throws(() => verifyBa0Inventory(options), /invalid index mode/u);
  }
  git("update-index", "--force-remove", "--", candidate);
  execFileSync("git", ["update-index", "--index-info"], { cwd: root, input: `100644 ${addition[1]} 2\t${candidate}\n` });
  assert.throws(() => verifyBa0Inventory(options), /unmerged index entry/u);
});

test("inventory rejects malformed policy, bad digests and incomplete authorization", t => {
  const { addition, git, options } = fixture(t);
  git("add", "--", candidate);
  const check = (...additions: ReviewedAddition[]) => verifyBa0Inventory({ ...options, additions });
  assert.throws(() => check(addition, addition), /duplicate or overlapping/u);
  assert.throws(() => check([history, addition[1], addition[2]]), /duplicate or overlapping/u);
  assert.throws(() => check(["protected/../protected/candidate.ts", addition[1], addition[2]]), /malformed admission path/u);
  assert.throws(() => check([candidate, "not-a-blob", addition[2]]), /malformed admission blob/u);
  assert.throws(() => check([candidate, addition[1], "0".repeat(64)]), /wrong normalized worktree digest/u);
  assert.throws(() => check(["workers/lifecycle-mailbox/guard-export.ts", addition[1], addition[2]]),
    /admission outside scope/u, "BA0 owner evidence cannot admit a Gate 11A path");
  for (const review of [{}, { ownerDecision: "fixture" }, { isolationEvidence: "fixture" }]) {
    assert.throws(() => verifyBa0Inventory({ ...options, review }), /admission PENDING/u);
  }
});

test("committed acceptance requires an explicit full commit for the checked-out revision", () => {
  const root = path.join(__dirname, "..");
  const git = (...args: string[]) => execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
  const file = "defense/plane/runtime.ts";
  // Existing commits only. D1 changed this path after the historical baseline.
  const current = git("rev-parse", "HEAD");
  const prior = "64ccc9dabdde81fbc844807f8c104d707151de5e";
  const blob = git("rev-parse", `${current}:${file}`);
  const digest = normalizedSha256(execFileSync("git", ["cat-file", "blob", blob], { cwd: root }));
  // Use one literal file scope to exercise worktree, index and committed blob
  // bytes with the existing checkout, without creating a commit.
  const options = { root, scopes: [file], historical: new Map<string, string>(),
    additions: [[file, blob, digest] as const], review: fixtureReview, mode: "committed" as const };
  verifyBa0Inventory({ ...options, candidateCommit: current });
  assert.throws(() => verifyBa0Inventory(options), /requires a full candidate commit ID/u);
  assert.throws(() => verifyBa0Inventory({ ...options, candidateCommit: "HEAD" }), /requires a full candidate commit ID/u);
  assert.throws(() => verifyBa0Inventory({ ...options, candidateCommit: blob }), /candidate object is not a commit/u);
  assert.throws(() => verifyBa0Inventory({ ...options, candidateCommit: prior }), /not the checkout revision/u);
  assert.throws(() => verifyBa0Inventory({ ...options, mode: "pre-commit", candidateCommit: current }),
    /does not accept a candidate commit selector/u);
});

test("committed acceptance rejects a differing committed blob even when index and worktree agree", t => {
  const root = mkdtempSync(path.join(tmpdir(), "ba0-committed-view-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const git = (...args: string[]) => execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
  git("clone", "--quiet", "--shared", "--no-tags", "--", path.join(__dirname, ".."), ".");
  const current = git("rev-parse", "HEAD");
  const file = "defense/plane/runtime.ts";
  git("checkout", "64ccc9dabdde81fbc844807f8c104d707151de5e", "--", file);
  verifyBa0Inventory({ root, scopes: [file], historical: new Map([[file, git("rev-parse", ":" + file)]]),
    additions: [], review: {}, mode: "pre-commit" });
  assert.throws(() => verifyBa0Inventory({
    root, scopes: [file], historical: new Map([[file, git("rev-parse", ":" + file)]]),
    additions: [], review: {}, mode: "committed", candidateCommit: current,
  }), /wrong committed blob/u);
});
