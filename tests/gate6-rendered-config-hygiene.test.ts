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

test("the Production transport manifest is ignored only by its own exact filename (Phase 3P.4), never by the Gate 6A staging rule or a glob", () => {
  // Gate 6A itself added no production rule; Phase 3P.4 (1cf7b81) deliberately added the EXACT production filename because the rendered file carries a real account id.
  assert.equal(ignored("deployment/lifecycle-transport.production.json"), true, "rendered production manifest must be gitignored (exact filename)");
  assert.equal(ignored("deployment/lifecycle-transport.production.template.json"), false, "a production template, if any, must stay tracked");
  for (const path of ["deployment/lifecycle-transport.production.custom.json", "deployment/lifecycle-transport.production.json.bak"]) assert.equal(ignored(path), false, `${path} must not be ignored by a broad glob`);
});

test("the rendered production lifecycle configs are excluded from BOTH Docker build contexts by exact filename (root app image copies deployment/)", async () => {
  const { readFileSync } = await import("node:fs");
  for (const file of [".dockerignore", "lab/linux/Dockerfile.dockerignore"]) {
    const lines = new Set(readFileSync(new URL(`../${file}`, import.meta.url), "utf8").split(/\r?\n/u).map((line) => line.trim()));
    for (const name of ["deployment/lifecycle-transport.production.json", "deployment/lifecycle-mailbox.production.jsonc", "deployment/operator-lifecycle-executor.production.jsonc"]) assert.ok(lines.has(name), `${file} must exclude ${name}`);
  }
});
