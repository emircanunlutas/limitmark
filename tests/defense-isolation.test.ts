import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

const root = path.join(__dirname, "..");

function tsFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    return entry.isDirectory() ? tsFiles(full) : entry.name.endsWith(".ts") ? [full] : [];
  });
}
const code = (file: string): string => readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
const defenseFiles = tsFiles(path.join(root, "defense"));
const labDefenseFiles = tsFiles(path.join(root, "lab", "defense"));
const rel = (file: string) => path.relative(root, file).replace(/\\/g, "/");

test("the defense tree exists as specified", () => {
  for (const expected of ["core/types.ts", "core/composer.ts", "core/ledger.ts", "layers/a7-shape-gate.ts", "plane/front.ts", "origin/synthetic-origin.ts"]) {
    assert.ok(defenseFiles.some((file) => rel(file) === `defense/${expected}`), expected);
  }
  for (const expected of ["canary.ts", "hostile-corpus.ts", "accounting.ts", "thresholds.ts", "ba0-run.ts", "collector.ts"]) {
    assert.ok(labDefenseFiles.some((file) => rel(file) === `lab/defense/${expected}`), expected);
  }
});

test("layers and the composer never read the correlation nonce, a hop id, an outcome header or any traffic-class label", () => {
  const judged = defenseFiles.filter((file) => rel(file).startsWith("defense/layers/") || rel(file) === "defense/core/composer.ts");
  assert.ok(judged.length >= 2);
  for (const file of judged) {
    assert.doesNotMatch(code(file), /x-ba0|NONCE_HEADER|HOP_HEADER|OUTCOME_HEADER|nonce|hostile|legitimate|\bcorr\b|trafficClass|traffic_class/i, rel(file));
  }
});

test("layers depend only on the shared closed vocabulary, never on the plane, the ledger or the origin", () => {
  for (const file of defenseFiles.filter((candidate) => rel(candidate).startsWith("defense/layers/"))) {
    const specifiers = [...code(file).matchAll(/from\s+["']([^"']+)["']/g)].map((match) => match[1]);
    for (const specifier of specifiers) assert.match(specifier, /^\.\.\/core\/types$/, `${rel(file)}: ${specifier}`);
  }
});

test("there is no fail-open path: no fail_open / error_failopen identifier or degraded-as-pass mapping exists in code", () => {
  for (const file of [...defenseFiles, ...labDefenseFiles]) {
    assert.doesNotMatch(code(file), /fail[_-]?open|failopen|failOpen/i, rel(file));
  }
  const types = code(path.join(root, "defense", "core", "types.ts"));
  assert.match(types, /export type FailurePolicy = "fail_closed";/);
  assert.doesNotMatch(types, /LayerOutcome[^;]*degraded/);
});

test("the defense path performs no durable or synchronous file I/O (authoritative measurement lives outside it)", () => {
  for (const file of defenseFiles) {
    assert.doesNotMatch(code(file), /from\s+["']node:fs(?:\/promises)?["']|require\(["']node:fs|\bfsync|\bwriteFileSync|\bappendFileSync|\bwriteSync\b/, rel(file));
  }
});

test("the plane never spawns or reaches other processes and has no network control surface beyond its one listener", () => {
  for (const file of defenseFiles) assert.doesNotMatch(code(file), /node:child_process|node:cluster|node:worker_threads|node:dgram|node:dns/, rel(file));
  const main = code(path.join(root, "defense", "plane", "main.ts"));
  assert.match(main, /process\.send/);
  assert.doesNotMatch(main, /createServer|node:http|node:net/, "main.ts only wires IPC to the front; the front owns the single loopback listener");
});

test("every listener binds 127.0.0.1 only", () => {
  for (const file of defenseFiles) for (const match of code(file).matchAll(/\.listen\(([^)]+)\)/g)) assert.match(match[1], /127\.0\.0\.1/, `${rel(file)}: listen(${match[1]})`);
});

test("the front forwards only to a loopback upstream chosen at construction (no request-derived host)", () => {
  const front = code(path.join(root, "defense", "plane", "front.ts"));
  assert.match(front, /host: upstream\.host, port: upstream\.port/);
  assert.doesNotMatch(front, /req\.headers\.host|headers\["host"\]|new URL\(req/);
});
