import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

const root = path.join(__dirname, "..");
const SKIP = new Set(["node_modules", ".next", "artifacts", ".git", ".npm-cache", ".wrangler", ".playwright", "test-results", "playwright-report", "lab", "tests"]);

// Other test files create and delete rendered deployment files while this suite runs; an entry that disappears between
// readdir and stat/read is not runtime code and must not fail the scan (it made the suite flaky under the parallel runner).
function walk(directory: string, extensions: readonly string[]): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory)) {
    if (SKIP.has(entry)) continue;
    const full = path.join(directory, entry);
    let isDirectory: boolean;
    try { isDirectory = statSync(full).isDirectory(); } catch { continue; }
    if (isDirectory) found.push(...walk(full, extensions));
    else if (extensions.some((extension) => entry.endsWith(extension))) found.push(full);
  }
  return found;
}

function readIfPresent(file: string): string {
  try { return readFileSync(file, "utf8"); } catch { return ""; }
}

// Everything that is application runtime, build, deploy or operator code: i.e. everything except lab/ and tests/.
const runtimeFiles = walk(root, [".ts", ".tsx", ".js", ".mjs", ".cjs", ".json", ".jsonc", ".css"]).filter((file) => !/package-lock\.json$|tsconfig\.tsbuildinfo$/.test(file));

const importsLab = /(?:from\s+|import\s*\(\s*|require\s*\(\s*|import\s+)["'`](?:[^"'`]*[/\\])?lab(?:[/\\][^"'`]*)?["'`]/;

test("no application, worker, operator, deployment or script file imports from lab/", () => {
  assert.ok(runtimeFiles.length > 100, "the scan must actually see the codebase");
  const offenders = runtimeFiles.filter((file) => importsLab.test(readIfPresent(file))).map((file) => path.relative(root, file));
  assert.deepEqual(offenders, []);
});

const importsDefense = /(?:from\s+|import\s*\(\s*|require\s*\(\s*|import\s+)["'`](?:[^"'`]*[/\\])?defense(?:[/\\][^"'`]*)?["'`]/;
const defenseDirectory = `defense${path.sep}`;

test("no application, worker, operator, deployment or script file imports from defense/", () => {
  const offenders = runtimeFiles.filter((file) => !path.relative(root, file).startsWith(defenseDirectory)).filter((file) => importsDefense.test(readIfPresent(file))).map((file) => path.relative(root, file));
  assert.deepEqual(offenders, []);
});

test("defense/ imports only its own files and node: built-ins (no src/, operator/, scripts/, deployment/, workers/, lab/ and no package)", () => {
  const files = runtimeFiles.filter((file) => path.relative(root, file).startsWith(defenseDirectory) && file.endsWith(".ts"));
  assert.ok(files.length >= 8, "the scan must see the defense tree");
  const offenders: string[] = [];
  for (const file of files) {
    for (const match of readIfPresent(file).matchAll(/(?:from\s+|import\s*\(\s*|require\s*\(\s*)["']([^"']+)["']/g)) {
      const specifier = match[1];
      const inside = specifier.startsWith(".") && path.resolve(path.dirname(file), specifier).startsWith(path.join(root, "defense") + path.sep);
      if (!inside && !specifier.startsWith("node:")) offenders.push(`${path.relative(root, file)}: ${specifier}`);
    }
  }
  assert.deepEqual(offenders, []);
});

test("ESLint forbids defense/ from importing outside itself and forbids runtime code from importing defense/", () => {
  const config = readFileSync(path.join(root, "eslint.config.mjs"), "utf8");
  assert.match(config, /\*\*\/defense\/\*\*/);
  assert.ok(config.includes('files: ["defense/**/*.ts"]'));
  for (const glob of ["@/*", "**/src/**", "**/operator/**", "**/scripts/**", "**/deployment/**", "**/workers/**", "**/lab/**"]) assert.ok(config.includes(glob), glob);
});

test("only the lab:ba0 script runs defense-plane code; no other non-test script does", () => {
  const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")) as { scripts: Record<string, string> };
  for (const [name, command] of Object.entries(manifest.scripts)) {
    if (name === "lab:ba0") assert.match(command, /lab\/defense\/ba0-run\.ts/);
    else if (!/^test(:|$)|^check$|^lab:/.test(name)) assert.doesNotMatch(command, /\bdefense\//, `${name} must not run defense code`);
  }
});

test("no runtime file references lab-only identifiers (proof schema, lab paths, lab environment)", () => {
  const needles = ["limitmark_lab_proof", "disposable_database_marker", "TEST_DATABASE_PROOF", "artifacts/lab", "lab/policy", "lab/postgres", "lab/evidence", "limitmark-lab-"];
  const offenders: string[] = [];
  // package.json holds the sanctioned `lab:*` launch scripts; the next test pins what they may run.
  for (const file of runtimeFiles.filter((candidate) => path.basename(candidate) !== "package.json")) {
    const text = readIfPresent(file);
    for (const needle of needles) if (text.includes(needle)) offenders.push(`${path.relative(root, file)}: ${needle}`);
  }
  assert.deepEqual(offenders, []);
});

test("no runtime file imports test support code", () => {
  const offenders = runtimeFiles.filter((file) => /from\s+["'][^"']*(?:\/|^)tests\/support/.test(readIfPresent(file))).map((file) => path.relative(root, file));
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
