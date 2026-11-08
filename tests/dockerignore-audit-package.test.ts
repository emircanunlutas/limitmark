import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

const root = path.join(__dirname, "..");
const entries = readFileSync(path.join(root, "lab", "linux", "Dockerfile.dockerignore"), "utf8").split("\n").map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));

test("the parity build context excludes the owner-held C1 audit package by its EXACT path, and nothing broader hides source", () => {
  assert.equal(entries.filter((entry) => entry === "LimitMark-C1-Audit-Package").length, 1, "exactly one exact-path entry");
  // No entry may be able to match a tracked source file by accident: every entry that is not a pre-existing pattern must match no tracked file.
  const tracked = execFileSync("git", ["ls-files"], { cwd: root, encoding: "utf8" }).split("\n").filter(Boolean);
  assert.equal(tracked.some((file) => file === "LimitMark-C1-Audit-Package" || file.startsWith("LimitMark-C1-Audit-Package/")), false, "the audit package is untracked");
  for (const entry of entries) assert.ok(!/^\*+\/?$/u.test(entry) && !/^L[^/]*\*/u.test(entry) && !/^\*{1,2}\/?\*?$/u.test(entry), `no catch-all pattern: ${entry}`);
});

test("the audit package is excluded from the working-tree digest inputs the same way the context is (the image provenance does not cover it)", () => {
  const provenance = readFileSync(path.join(root, "lab", "linux", "provenance.ts"), "utf8");
  assert.match(provenance, /Dockerfile\.dockerignore/u, "provenance documents that the build context is defined by the Dockerfile-specific ignore file");
});
