import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

// Gate 6A / F1: proves the exact rendered staging lifecycle-transport
// filename is git-ignored while its template stays tracked, using git's own
// plumbing (read-only; performs no repository mutation). This is a hygiene
// backstop, not the primary safety boundary -- tests/gate6-staging-transport-preflight.test.ts
// proves the exact-filename invariant in the tooling itself.

const root = fileURLToPath(new URL("../", import.meta.url));
const ignored = (path: string) => spawnSync("git", ["check-ignore", "-q", path], { cwd: root }).status === 0;

test("the rendered Gate 6A staging transport manifest is ignored; its template is not", () => {
  assert.equal(ignored("deployment/lifecycle-transport.staging.json"), true, "rendered manifest must be gitignored");
  assert.equal(ignored("deployment/lifecycle-transport.staging.template.json"), false, "template must stay tracked");
});

test("an alternate rendered filename is not made safe by the ignore glob (no broad pattern exists)", () => {
  const alternates = ["deployment/lifecycle-transport.staging.custom.json", "deployment/lifecycle-transport.staging.json.bak"];
  for (const path of alternates) assert.equal(ignored(path), false, `${path} must not be silently ignored by a broad glob`);
});

test("the Production transport manifest is unaffected by the Gate 6A staging ignore rule", () => {
  assert.equal(ignored("deployment/lifecycle-transport.production.json"), false,
    "Production's own rendered manifest has no ignore rule at all in this repository yet, and Gate 6A must not add one incidentally");
});
