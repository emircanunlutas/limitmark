import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

// Gate 5A / F2: proves the three exact rendered Gate 5 staging filenames are
// git-ignored while their templates stay tracked, using git's own plumbing
// (read-only; performs no repository mutation). This is a hygiene backstop,
// not the primary safety boundary -- tests/gate5-deploy-wrapper.test.ts and
// tests/gate5-staging-preflight.test.ts prove the exact-filename invariant
// itself.

const root = fileURLToPath(new URL("../", import.meta.url));
const ignored = (path: string) => spawnSync("git", ["check-ignore", "-q", path], { cwd: root }).status === 0;

test("rendered Gate 5 staging configs are ignored; their templates are not", () => {
  const pairs: Array<[string, string]> = [
    ["deployment/operator-lifecycle-executor.staging.jsonc", "deployment/operator-lifecycle-executor.staging.template.jsonc"],
    ["deployment/lifecycle-mailbox.staging.jsonc", "deployment/lifecycle-mailbox.staging.template.jsonc"],
    ["deployment/lifecycle-observer.staging.jsonc", "deployment/lifecycle-observer.staging.template.jsonc"],
  ];
  for (const [rendered, template] of pairs) {
    assert.equal(ignored(rendered), true, `${rendered} must be gitignored`);
    assert.equal(ignored(template), false, `${template} must stay tracked`);
  }
});

test("alternate rendered filenames are not made safe by the ignore glob (no broad pattern exists)", () => {
  // These would be tracked by git if they existed -- the .gitignore rule is
  // exact-filename, not a glob, so an alternate name is never silently hidden.
  const alternates = ["deployment/operator-lifecycle-executor.staging.custom.jsonc",
    "deployment/lifecycle-mailbox.staging.custom.jsonc", "deployment/lifecycle-observer.staging.custom.jsonc"];
  for (const path of alternates) assert.equal(ignored(path), false, `${path} must not be silently ignored by a broad glob`);
});

test("Gate 7A rendered armed staging configs are ignored; no broad pattern hides an alternate name", () => {
  const armed = ["deployment/lifecycle-mailbox.staging.armed.jsonc", "deployment/lifecycle-observer.staging.armed.jsonc"];
  for (const path of armed) assert.equal(ignored(path), true, `${path} must be gitignored`);
  const alternates = ["deployment/lifecycle-mailbox.staging.custom.armed.jsonc", "deployment/lifecycle-observer.staging.custom.armed.jsonc"];
  for (const path of alternates) assert.equal(ignored(path), false, `${path} must not be silently ignored by a broad glob`);
});
