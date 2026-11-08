import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import test from "node:test";

// Explicit, exact expectation of the production (runtime) dependency set. tests/lab-isolation.test.ts still pins the older eight-package list and is
// red at the verified baseline (the three OpenTelemetry packages, commit 1409e7c); it is intentionally NOT edited here. This file states what the set
// is NOW, requires exact pins (no ranges), and confines the Vercel OIDC SDK to the one reviewed module.

const root = process.cwd();
const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { dependencies: Record<string, string>; devDependencies: Record<string, string> };
const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8")) as { packages: Record<string, { version?: string; resolved?: string; integrity?: string; dev?: boolean; dependencies?: Record<string, string> }> };

test("production dependencies are exactly the reviewed set, all pinned to exact versions", () => {
  assert.deepEqual(Object.keys(manifest.dependencies).sort(), [
    "@opentelemetry/api", "@opentelemetry/exporter-metrics-otlp-proto", "@opentelemetry/sdk-metrics", "@vercel/oidc",
    "drizzle-orm", "jose", "next", "postgres", "react", "react-dom", "server-only", "zod",
  ]);
  // zod is the single pre-existing range; every other runtime dependency (including all additions since the eight-package list) is an exact pin.
  const preExistingRanges: Record<string, string> = { zod: "^4.6.6" };
  for (const [name, version] of Object.entries(manifest.dependencies)) {
    if (name in preExistingRanges) assert.equal(version, preExistingRanges[name]);
    else assert.match(version, /^\d+\.\d+\.\d+$/u, `${name} must be an exact version`);
  }
  assert.equal(manifest.dependencies["@vercel/oidc"], "4.0.7");
});

test("the Vercel OIDC SDK resolves to the audited version and tarball integrity, with its audited transitive set", () => {
  const entry = lock.packages["node_modules/@vercel/oidc"];
  assert.equal(entry.version, "4.0.7");
  assert.match(entry.resolved ?? "", /^https:\/\/registry\.npmjs\.org\/@vercel\/oidc\/-\/oidc-4\.0\.7\.tgz$/u);
  assert.match(entry.integrity ?? "", /^sha512-/u);
  assert.equal(entry.dev, undefined, "a runtime dependency is not dev-only");
  assert.deepEqual(Object.keys(entry.dependencies ?? {}).sort(), ["@vercel/cli-config", "@vercel/cli-exec", "jose"]);
  // The SDK brings its own jose major; the application's jose stays the pinned 6.x.
  assert.equal(lock.packages["node_modules/@vercel/oidc/node_modules/jose"]?.version?.split(".")[0], "5");
  assert.equal(lock.packages["node_modules/jose"].version, manifest.dependencies.jose);
  for (const name of ["@vercel/cli-config", "@vercel/cli-exec"]) {
    const transitive = lock.packages[`node_modules/${name}`];
    assert.ok(transitive?.version && transitive.integrity && transitive.resolved?.startsWith("https://registry.npmjs.org/"), name);
  }
});

function sources(directory: string): string[] {
  return readdirSync(directory).flatMap((entry) => {
    const full = join(directory, entry);
    if (entry === "node_modules" || entry === ".next" || entry.startsWith(".")) return [];
    return statSync(full).isDirectory() ? sources(full) : /\.(ts|tsx|mjs|js)$/u.test(entry) ? [full] : [];
  });
}

test("only the reviewed provider module imports the Vercel OIDC SDK; no Worker bundle, operator tool or script can reach it", () => {
  const importers = [...sources(join(root, "src")), ...sources(join(root, "workers")), ...sources(join(root, "operator")), ...sources(join(root, "scripts")),
    ...sources(join(root, "deployment"))]
    .filter((file) => /from\s+["']@vercel\/oidc["']|require\(["']@vercel\/oidc["']\)|import\(["']@vercel\/oidc["']\)/u.test(readFileSync(file, "utf8")))
    .map((file) => relative(root, file).replaceAll("\\", "/"));
  assert.deepEqual(importers, ["src/lib/admission-client.server.ts"]);
});
