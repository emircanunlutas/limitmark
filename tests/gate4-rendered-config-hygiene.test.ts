import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

// Gate 4B / F3: proves the exact rendered staging admission filename is
// git-ignored while the template it is rendered from stays tracked/visible,
// using git's own plumbing (read-only; performs no repository mutation).

const root = fileURLToPath(new URL("../", import.meta.url));
const ignored = (path: string) => spawnSync("git", ["check-ignore", "-q", path], { cwd: root }).status === 0;

test("rendered staging admission config is ignored; its template is not", () => {
  assert.equal(ignored("deployment/admission-service.staging.jsonc"), true, "rendered config must be gitignored");
  assert.equal(ignored("deployment/admission-service.staging.template.jsonc"), false, "template must stay tracked");
});
