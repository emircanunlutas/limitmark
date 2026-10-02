import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

const root = path.join(__dirname, "..");
const SKIP = new Set(["node_modules", ".next", "artifacts", ".git", ".npm-cache", ".wrangler", ".playwright", "test-results", "playwright-report", "lab", "tests"]);

function walk(directory: string, extensions: readonly string[]): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory)) {
    if (SKIP.has(entry)) continue;
    const full = path.join(directory, entry);
    if (statSync(full).isDirectory()) found.push(...walk(full, extensions));
    else if (extensions.some((extension) => entry.endsWith(extension))) found.push(full);
  }
  return found;
}

// Everything that is application runtime, build, deploy or operator code: i.e. everything except lab/ and tests/.
const runtimeFiles = walk(root, [".ts", ".tsx", ".js", ".mjs", ".cjs", ".json", ".jsonc", ".css"]).filter((file) => !/package-lock\.json$|tsconfig\.tsbuildinfo$/.test(file));

const importsLab = /(?:from\s+|import\s*\(\s*|require\s*\(\s*|import\s+)["'`](?:[^"'`]*[/\\])?lab(?:[/\\][^"'`]*)?["'`]/;

test("no application, worker, operator, deployment or script file imports from lab/", () => {
  assert.ok(runtimeFiles.length > 100, "the scan must actually see the codebase");
  const offenders = runtimeFiles.filter((file) => importsLab.test(readFileSync(file, "utf8"))).map((file) => path.relative(root, file));
  assert.deepEqual(offenders, []);
});

test("no runtime file references lab-only identifiers (proof schema, lab paths, lab environment)", () => {
  const needles = ["limitmark_lab_proof", "disposable_database_marker", "TEST_DATABASE_PROOF", "artifacts/lab", "lab/policy", "lab/postgres", "lab/evidence", "limitmark-lab-"];
  const offenders: string[] = [];
  // package.json holds the sanctioned `lab:*` launch scripts; the next test pins what they may run.
  for (const file of runtimeFiles.filter((candidate) => path.basename(candidate) !== "package.json")) {
    const text = readFileSync(file, "utf8");
    for (const needle of needles) if (text.includes(needle)) offenders.push(`${path.relative(root, file)}: ${needle}`);
  }
  assert.deepEqual(offenders, []);
});

test("no runtime file imports test support code", () => {
  const offenders = runtimeFiles.filter((file) => /from\s+["'][^"']*(?:\/|^)tests\/support/.test(readFileSync(file, "utf8"))).map((file) => path.relative(root, file));
  assert.deepEqual(offenders, []);
});

test("the production dependency set is unchanged: lab tooling adds no runtime dependency", () => {
  const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")) as { dependencies: Record<string, string>; devDependencies: Record<string, string>; scripts: Record<string, string> };
  assert.deepEqual(Object.keys(manifest.dependencies).sort(), ["drizzle-orm", "jose", "next", "postgres", "react", "react-dom", "server-only", "zod"]);
  for (const name of Object.keys({ ...manifest.dependencies, ...manifest.devDependencies })) assert.doesNotMatch(name, /k6|artillery|autocannon|loadtest|locust|vegeta|wrk|testcontainers/i, name);
});

test("lab npm scripts only run lab files; no existing script runs lab code", () => {
  const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")) as { scripts: Record<string, string> };
  for (const [name, command] of Object.entries(manifest.scripts)) {
    if (name.startsWith("lab:")) assert.match(command, /\blab\/|tests\/lab-/, name);
    else if (!/^test(:|$)|^check$/.test(name)) assert.doesNotMatch(command, /\blab\//, `${name} must not run lab code`);
  }
  assert.doesNotMatch(manifest.scripts.build, /lab/);
  assert.doesNotMatch(manifest.scripts.start, /lab/);
  assert.doesNotMatch(manifest.scripts.dev, /lab/);
});

test("the TypeScript path alias cannot reach lab/ and Next config does not mention it", () => {
  const tsconfig = JSON.parse(readFileSync(path.join(root, "tsconfig.json"), "utf8")) as { compilerOptions: { paths: Record<string, string[]> } };
  assert.deepEqual(tsconfig.compilerOptions.paths, { "@/*": ["./src/*"] });
  assert.doesNotMatch(readFileSync(path.join(root, "next.config.ts"), "utf8"), /lab/);
});

test("ESLint forbids importing lab/ from runtime code", () => {
  const config = readFileSync(path.join(root, "eslint.config.mjs"), "utf8");
  assert.match(config, /no-restricted-imports/);
  assert.match(config, /\*\*\/lab\/\*\*/);
  for (const glob of ["src/**", "workers/**", "operator/**", "deployment/**", "scripts/**"]) assert.ok(config.includes(glob), glob);
});

test("the lab tree is self-describing and documents its trust boundary", () => {
  const readme = readFileSync(path.join(root, "lab", "README.md"), "utf8");
  for (const phrase of ["trust boundary", "never imported", "Not production", "fail closed"]) assert.match(readme, new RegExp(phrase, "i"), phrase);
});
