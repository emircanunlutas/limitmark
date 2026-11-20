import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isBuiltin } from "node:module";
import { build } from "esbuild";
import { collectModuleReferences, dynamicCodeViolations, listScriptFiles, parseSource } from "./support/r06-import-guard";
import { normalizedSha256 } from "./support/ba0-inventory";
import path from "node:path";
import { test, type TestContext } from "node:test";
import ts from "typescript";

const root = path.join(__dirname, "..");
const core = "defense/core";
const dependencies = {
  "capacity-port.ts": [],
  "capacity-policy.ts": ["./capacity-port", "node:crypto"],
  "origin-capacity.ts": ["./capacity-heap", "./capacity-policy", "./capacity-port"],
  "capacity-heap.ts": [],
  "capacity-boundary.ts": ["./capacity-policy", "./capacity-port", "./origin-capacity", "node:util"],
} as const;
type ModuleName = keyof typeof dependencies;

function parse(file: string) {
  return ts.createSourceFile(file, readFileSync(path.join(root, file), "utf8"), ts.ScriptTarget.Latest, true);
}

const modules = new Map(Object.keys(dependencies).map((name) => [name as ModuleName, parse(core + "/" + name)]));

function visit(node: ts.Node, inspect: (node: ts.Node) => void) {
  inspect(node);
  ts.forEachChild(node, (child) => visit(child, inspect));
}

function loadTarget(node: ts.Node): ts.Node | undefined {
  if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) return node.moduleSpecifier;
  if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
    return node.moduleReference.expression;
  }
  if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument)) return node.argument.literal;
  if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
      /^(?:require|require\.resolve|module\.require)$/u.test(node.expression.getText()))) {
    return node.arguments[0];
  }
}

function typeFields(source: ts.SourceFile, type: string) {
  const declaration = source.statements.find((node): node is ts.TypeAliasDeclaration =>
    ts.isTypeAliasDeclaration(node) && node.name.text === type);
  assert.ok(declaration && ts.isTypeLiteralNode(declaration.type), type);
  return declaration.type.members.map((member) => member.name?.getText()).sort();
}

test("the port emits no runtime code and the request input contains only the three supported fields", () => {
  const port = modules.get("capacity-port.ts")!;
  const { outputText } = ts.transpileModule(port.text, { compilerOptions: { module: ts.ModuleKind.ESNext, removeComments: true } });
  assert.equal(outputText.trim(), "export {};");
  assert.deepEqual(typeFields(port, "CapacityRequestInput"), ["body", "callerDeadlineMonoMs", "candidate"]);
});

test("all five isolated M2 modules have a closed dependency graph", () => {
  for (const [name, source] of modules) {
    const imports: string[] = [];
    visit(source, (node) => {
      if (ts.isCallExpression(node)) {
        assert.notEqual(node.expression.kind, ts.SyntaxKind.ImportKeyword, name);
        assert.doesNotMatch(node.expression.getText(), /^(?:require|require\.resolve|module\.require|createRequire)$/u, name);
      }
      const target = loadTarget(node);
      if (target) {
        assert.ok(ts.isStringLiteral(target), name);
        imports.push(target.text);
      }
    });
    assert.deepEqual(imports.sort(), [...dependencies[name]].sort(), name);
  }
});

test("the M2 closure contains no request sealer, synthetic verifier or caller-digest compiler", () => {
  for (const [name, source] of modules) {
    visit(source, (node) => {
      if (ts.isIdentifier(node)) {
        assert.doesNotMatch(node.text, /sealVerified|compileCustomerOriginPolicy|decodeCustomerOriginPolicy|SyntheticTestVerifier|createSynthetic/u, name);
      }
    });
  }
});

test("controller records keep scalar decision fields and owned bytes, and queue operations use indexed removal", () => {
  const controller = modules.get("origin-capacity.ts")!;
  assert.deepEqual(typeFields(controller, "Request"), [
    "attempt", "body", "bytes", "callerCutoff", "callerIndex", "cls", "cost", "monoIndex",
    "next", "prev", "proofCutoff", "proofExpiry", "waitCutoff", "wallIndex",
  ]);
  assert.deepEqual(typeFields(controller, "AttemptRecord"), ["holdUntilFinish", "preparationInFlight", "request", "status"]);
  for (const name of ["origin-capacity.ts", "capacity-heap.ts"] as const) {
    visit(modules.get(name)!, (node) => {
      if (ts.isPropertyAccessExpression(node)) {
        assert.doesNotMatch(node.name.text, /^(?:indexOf|shift|splice|unshift)$/u, name);
        if (name === "origin-capacity.ts") {
          assert.notEqual(node.name.text, "floor");
          if (/^#?snapshot$/u.test(node.name.text)) {
            const member = node.parent.parent.parent;
            assert.ok(ts.isPropertyAssignment(member) && member.name.getText() === "snapshot", node.getText());
          }
        }
      }
    });
  }
});

test("controller observations call only the committed-state readers and never mutate state", () => {
  const controller = modules.get("origin-capacity.ts")!;
  const readers = new Set(["#snapshot", "#pending", "#scanEnd", "#wakeDue"]);
  const found = new Set<string>();
  visit(controller, (node) => {
    if (!ts.isMethodDeclaration(node)) return;
    const name = node.name.getText();
    if (!readers.has(name)) return;
    found.add(name);
    assert.ok(node.body, name);
    visit(node.body, (expression) => {
      if (ts.isCallExpression(expression)) {
        const call = expression.expression.getText();
        assert.ok(call === "this.#classes.map" || call === "this.#scanEnd" || call === "this.#wakeDue", call);
      }
      if (ts.isBinaryExpression(expression)) {
        assert.ok(expression.operatorToken.kind < ts.SyntaxKind.FirstAssignment ||
          expression.operatorToken.kind > ts.SyntaxKind.LastAssignment, expression.getText());
      }
      assert.equal(ts.isDeleteExpression(expression), false, name);
      if (ts.isPrefixUnaryExpression(expression) || ts.isPostfixUnaryExpression(expression)) {
        assert.ok(expression.operator !== ts.SyntaxKind.PlusPlusToken &&
          expression.operator !== ts.SyntaxKind.MinusMinusToken, expression.getText());
      }
    });
  });
  assert.deepEqual(found, readers);
});

test("M2 contains no ambient clocks, asynchronous scheduling, I/O, network, or plane and telemetry dependencies", () => {
  for (const [name, source] of modules) {
    visit(source, (node) => {
      if (ts.isIdentifier(node)) {
        assert.doesNotMatch(node.text,
          /^(?:Date|performance|setTimeout|setInterval|setImmediate|queueMicrotask|randomBytes|fetch|XMLHttpRequest|WebSocket|AbortSignal|AbortController|JourneyLanes|CreditFilter|UseLedger|TokenBucket|TickSource|ProcessSampler|BoundedEventChannel)$|fail_?open/iu, name);
      }
      if (ts.isPropertyAccessExpression(node)) {
        assert.doesNotMatch(node.getText(), /^(?:process\.(?:env|argv)|Math\.random)$|\.listen$/u, name);
      }
      if (ts.isStringLiteralLike(node)) {
        assert.doesNotMatch(node.text, /^(?:0\.0\.0\.0|255\.255\.255\.255)$/u, name);
      }
    });
  }
});

// Governed historical BA0 launchers and verdict-path runtime entry points.
const historicalEntries = [
  "defense/boundary/main.ts",
  "defense/boundary/main-field.ts",
  "defense/origin/app-main.ts",
  "defense/origin/app-main-field.ts",
  "defense/plane/main.ts",
  "defense/plane/main-l2.ts",
  "defense/plane/runtime.ts",
  "lab/defense/ba0-run.ts",
  "lab/defense/ba0-origin-run.ts",
  "lab/defense/ba0-collapse-run.ts",
  "lab/defense/ba0-field-run.ts",
  "lab/defense/ba0-field-reconcile.ts",
];
const boundedProcessMembers = new Set([
  "argv", "cpuUsage", "env", "execArgv", "execPath", "exit", "exitCode", "getuid", "kill",
  "listenerCount", "memoryUsage", "off", "on", "once", "pid", "platform", "send", "stdout", "version",
]);
const indirectLoaderModules = new Set(["module", "process", "vm", "repl", "worker_threads"]);

type LaunchPolicy = Readonly<Record<string, { digest: string; targets: readonly string[] }>>;

// Pin the reviewed implementations that bind destinations to each process site.
// Empty target sets are host-tool/Next CLI sites, not repository JS entry points.
const historicalLaunches: LaunchPolicy = {
  "lab/defense/field-processes.ts": {
    digest: "cabd6df7b430638f9b6b1e868c9c16aaf8c3bb067c2f101ca481f428e255c055",
    targets: ["defense/boundary/main-field.ts", "defense/origin/app-main-field.ts"],
  },
  "lab/defense/origin-processes.ts": {
    digest: "55a251f1c5a41813bf3373be0b740a5c52688931fedbf9c0a23fbda951760236",
    targets: ["defense/boundary/main.ts", "defense/origin/app-main.ts"],
  },
  "lab/defense/plane-process.ts": {
    digest: "c74c961851b1781d1e5216660fd703afcf57a5bd946c416f3e6a500d19e21a55",
    targets: ["defense/plane/main.ts", "defense/plane/main-l2.ts", "lab/defense/collapse/plane-collapse-main.ts"],
  },
  "lab/defense/field-preflight.ts": { digest: "063ec77da795e45ff97a886ba8fee6aaa97308002fde3fb4c7aeefed832d7499", targets: [] },
  "lab/evidence/manifest.ts": { digest: "231744bb66fa727316fda0e17bbbbc375b0582dffd1d2a9dc6cd9471e060e97a", targets: [] },
  "lab/host/docker.ts": { digest: "b94aa4641aea0444ff0695080d0c9342b49550cf102087ba172ec87c46b6a62b", targets: [] },
  "lab/host/local-app.ts": { digest: "de914eaf096403a15a13d083e9499a60abed335e824332adb32d310269185070", targets: [] },
};
// PlaneProcess.start takes its entry from callers. Bind those call sites too,
// including the local collapse arm table and the field runner's L2 choice.
const historicalPlaneCallers: Readonly<Record<string, string>> = {
  "lab/defense/ba0-run.ts": "b9e32ca9d3682bdc72fce893080b323d3fa048d323ae2bbd67dbd3d4b5c83762",
  "lab/defense/ba0-origin-run.ts": "b2ed7c9a2e0cdb1938673cdc8cd4f3f4b69a286f5581e5cae00b12b805a33205",
  "lab/defense/ba0-collapse-run.ts": "681630352d02e080fe8b36d6df47d7e86025a1b9cb620fe73c6404596a9effd7",
  "lab/defense/ba0-field-run.ts": "eb1c885a2261eab6f8fe1fa2127b703ab297ee1cf34ce5d4f51ede82ec1222ad",
};

async function assertRuntimeIsolation(directory: string, entries: string[], additions: string[],
  launches: LaunchPolicy = {}, planeCallers: Readonly<Record<string, string>> = {}) {
  const canonical = (file: string) => realpathSync(path.resolve(directory, file));
  const forbidden = new Set(additions.map(canonical));
  const childTargets = Object.values(launches).flatMap(launch => launch.targets);
  const canonicalRoot = canonical(".");
  for (const target of childTargets) {
    const resolved = canonical(target);
    const relative = path.relative(canonicalRoot, resolved);
    assert.ok(!forbidden.has(resolved), "historical child launch targets M2: " + target);
    assert.ok(!path.isAbsolute(relative) && !relative.startsWith(".." + path.sep), "child target escapes the repository: " + target);
    assert.equal(relative.split(path.sep).join("/"), target, "non-canonical child target: " + target);
  }
  const requireLaunchReview = (file: string) => {
    const launch = launches[file];
    assert.ok(launch, "unreviewed process-launch site: " + file);
    assert.equal(normalizedSha256(readFileSync(path.join(directory, file))), launch.digest,
      "changed process launcher or child target: " + file);
  };
  const configPath = path.join(directory, "tsconfig.json");
  const config = ts.readConfigFile(configPath, ts.sys.readFile);
  assert.equal(config.error, undefined);
  const { options } = ts.parseJsonConfigFileContent(config.config, ts.sys, directory);
  const result = await build({
    absWorkingDir: directory, entryPoints: [...new Set([...entries, ...childTargets])], outdir: "ba0-isolation-output",
    bundle: true, write: false, metafile: true, logLevel: "silent",
    platform: "node", conditions: ["react-server"], tsconfig: "tsconfig.json",
    plugins: [{ name: "ba0-bounded-runtime-loaders", setup(plugin) {
      plugin.onLoad({ filter: /\.[cm]?[jt]sx?$/ }, ({ path: file }) => {
        if (file.split(path.sep).includes("node_modules")) return;
        const source = readFileSync(file, "utf8");
        // Type-only edges are erased by the build and confer no runtime reachability.
        // This exact entry-point predicate compares identity and cannot load a module.
        const relative = path.relative(directory, file).split(path.sep).join("/");
        const loaderSource = ["lab/run.ts", "lab/postgres/lab-db.ts"].includes(relative)
          ? source.replace(/^if \(require\.main === module\) \{$/mu, "if (false) {")
          : source;
        const runtime = collectModuleReferences(loaderSource, file).filter(edge => !edge.typeOnly);
        for (const edge of runtime) {
          assert.ok(edge.specifier !== null, file + ":" + edge.line + " unbounded " + edge.kind);
          assert.notEqual(edge.kind, "import-meta-resolve", file + " indirect module resolution");
          const builtin = edge.specifier.replace(/^node:/u, "");
          assert.ok(!indirectLoaderModules.has(builtin), file + " indirect loader: " + edge.specifier);
          if (builtin === "child_process") requireLaunchReview(relative);
        }
        assert.deepEqual(dynamicCodeViolations(source, file), [], file + " dynamic code");
        visit(parseSource(loaderSource, file), node => {
          assert.ok(!ts.isMetaProperty(node) || node.keywordToken !== ts.SyntaxKind.ImportKeyword,
            file + " unbounded access to import.meta");
          const name = ts.isIdentifier(node) || ts.isStringLiteralLike(node) ? node.text : undefined;
          assert.ok(name === undefined || !["createRequire", "getBuiltinModule", "mainModule", "eval", "Function"].includes(name),
            file + " indirect loader: " + name);
          if (ts.isIdentifier(node)) {
            assert.ok(!["globalThis", "global", "Reflect", "module"].includes(node.text),
              file + " unbounded access to " + node.text);
            if (node.text === "process") {
              assert.ok(ts.isPropertyAccessExpression(node.parent) && node.parent.expression === node &&
                boundedProcessMembers.has(node.parent.name.text),
                file + " unbounded access to process");
            }
          }
        });
        return undefined;
      });
    } }],
  });
  const seen = new Set<string>();
  const walk = (file: string, chain: string[]): void => {
    const absolute = canonical(file);
    const next = [...chain, file];
    assert.ok(!forbidden.has(absolute), "historical runtime reaches M2: " + next.join(" -> "));
    if (seen.has(file)) return;
    seen.add(file);
    const input = result.metafile.inputs[file];
    assert.ok(input, "missing graph input: " + file);
    for (const edge of input.imports) {
      if (!edge.external) {
        if (edge.path === "lab/defense/plane-process.ts") {
          assert.ok(planeCallers[file], "unreviewed plane launcher caller: " + file);
          assert.equal(normalizedSha256(readFileSync(absolute)), planeCallers[file],
            "changed plane launcher caller or child target: " + file);
        }
        walk(edge.path, next);
      } else if (edge.path.replace(/^node:/u, "") === "child_process" && !file.startsWith("node_modules/")) {
        requireLaunchReview(file);
      } else if (!isBuiltin(edge.path)) {
        // esbuild can retain an inferred type-only import as an external
        // input edge. Verify it resolves locally and was erased from output.
        const resolved = ts.resolveModuleName(edge.path, absolute, options, ts.sys).resolvedModule;
        assert.ok(resolved && !resolved.isExternalLibraryImport, "unresolved runtime edge: " + edge.path);
        assert.ok(!forbidden.has(canonical(resolved.resolvedFileName)), "historical import names M2: " + next.join(" -> ") + " -> " + edge.path);
      }
    }
    for (const target of launches[file]?.targets ?? []) walk(target, next);
  };
  for (const output of Object.values(result.metafile.outputs)) {
    for (const edge of output.imports) {
      if (edge.external) {
        assert.ok(isBuiltin(edge.path) && !indirectLoaderModules.has(edge.path.replace(/^node:/u, "")),
          "unverified external runtime edge: " + edge.path);
      }
    }
  }
  for (const entry of entries) walk(entry, []);
}

function assertHistoricalBa0Scripts(scripts: Record<string, string>): void {
  const ba0Scripts = Object.fromEntries(Object.entries(scripts).filter(([name]) => name === "lab:ba0" || name.startsWith("lab:ba0:")));
  assert.deepEqual(ba0Scripts, {
    "lab:ba0": "tsx --conditions=react-server lab/defense/ba0-run.ts",
    "lab:ba0:origin": "tsx --conditions=react-server lab/defense/ba0-origin-run.ts",
    "lab:ba0:collapse": "tsx --conditions=react-server lab/defense/ba0-collapse-run.ts",
    "lab:ba0:field": "tsx --conditions=react-server lab/defense/ba0-field-run.ts",
    "lab:ba0:field:reconcile": "tsx --conditions=react-server lab/defense/ba0-field-reconcile.ts",
  }, "changed BA0 launch command");
  for (const name of Object.keys(ba0Scripts)) {
    for (const prefix of ["pre", "post"]) {
      const hook = prefix + name;
      assert.ok(!Object.hasOwn(scripts, hook), "unexpected BA0 lifecycle hook: " + hook);
    }
  }
}

const { scripts: packageScripts } = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));

test("BA0 npm lifecycle accepts the current package scripts", () => {
  assertHistoricalBa0Scripts(packageScripts);
});

test("BA0 npm lifecycle rejects a base pre-hook targeting M2", () => {
  assert.throws(() => assertHistoricalBa0Scripts({
    ...packageScripts, "prelab:ba0": "tsx defense/core/origin-capacity.ts",
  }), /unexpected BA0 lifecycle hook: prelab:ba0$/u);
});

test("BA0 npm lifecycle rejects an empty nested post-hook", () => {
  assert.throws(() => assertHistoricalBa0Scripts({
    ...packageScripts, "postlab:ba0:field:reconcile": "",
  }), /unexpected BA0 lifecycle hook: postlab:ba0:field:reconcile$/u);
});

test("historical BA0 runtime cannot transitively reach any candidate M2 module", async () => {
  assertHistoricalBa0Scripts(packageScripts);
  await assertRuntimeIsolation(root, historicalEntries, Object.keys(dependencies).map(file => core + "/" + file),
    historicalLaunches, historicalPlaneCallers);
});

test("other repository entry points cannot directly import or re-export M2", async () => {
  const forbidden = new Set(Object.keys(dependencies).map(file => realpathSync(path.join(root, core, file))));
  const config = ts.readConfigFile(path.join(root, "tsconfig.json"), ts.sys.readFile);
  assert.equal(config.error, undefined);
  const { options } = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
  const directories = new Set(["defense", "deployment", "lab", "operator", "scripts", "smoke", "src", "workers"]);
  for (const file of await listScriptFiles(root)) {
    if (file.includes("/") && !directories.has(file.split("/")[0])) continue;
    const absolute = path.join(root, file);
    if (forbidden.has(realpathSync(absolute))) continue;
    for (const edge of collectModuleReferences(readFileSync(absolute, "utf8"), file)) {
      if (edge.specifier === null || isBuiltin(edge.specifier)) continue;
      const resolved = ts.resolveModuleName(edge.specifier, absolute, options, ts.sys).resolvedModule;
      if (resolved && !resolved.isExternalLibraryImport) {
        assert.ok(!forbidden.has(realpathSync(resolved.resolvedFileName)), file + " imports " + edge.specifier);
      }
    }
  }
});

test("runtime traversal resolves aliases and barrels, and rejects unknown loaders", async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "ba0-isolation-"));
  try {
    mkdirSync(path.join(directory, "m2"));
    mkdirSync(path.join(directory, "other"));
    const write = (file: string, contents: string) => writeFileSync(path.join(directory, file), contents);
    write("tsconfig.json", JSON.stringify({ compilerOptions: { paths: { "@review/*": ["./m2/*"] } } }));
    write("m2/origin-capacity.ts", "export const capacity = 1;");
    write("other/origin-capacity.ts", "export const capacity = 2;");
    const check = () => assertRuntimeIsolation(directory, ["main.ts"], ["m2/origin-capacity.ts"]);
    write("main.ts", 'import "./other/origin-capacity"; import type { capacity } from "@review/origin-capacity";');
    await check();
    write("barrel.ts", 'export * from "@review/origin-capacity"; export * from "./main";');
    write("main.ts", 'export * from "./barrel";');
    await assert.rejects(check(), /main\.ts -> barrel\.ts -> m2\/origin-capacity\.ts/u);
    for (const source of [
      'import "./missing";', 'import("./missing");', 'require("./missing");',
      'export const load = (name: string) => import(name);', 'const load = require; load("./other/origin-capacity");',
    ]) {
      write("main.ts", source);
      await assert.rejects(check(), /Could not resolve|unbounded/u);
    }
    write("main.ts", 'const host = globalThis; export const load = host["requ" + "ire"];');
    await assert.rejects(check(), /unbounded access/u);
    write("main.ts", 'const meta = import.meta; export const resolve = meta.resolve;');
    await assert.rejects(check(), /unbounded access/u);
    for (const source of [
      'void import("@review/origin-capacity");', 'require("@review/origin-capacity");',
      'import value = require("@review/origin-capacity"); export { value };',
    ]) {
      write("main.ts", source);
      await assert.rejects(check(), /historical runtime reaches M2/u);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function childFixture(t: TestContext) {
  const directory = mkdtempSync(path.join(tmpdir(), "ba0-child-isolation-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const write = (file: string, contents: string) => writeFileSync(path.join(directory, file), contents);
  const launcher = (target: string) => `import { fork } from "node:child_process"; fork(${target});`;
  const review = (source: string, target: string) => ({ "main.ts": {
    digest: normalizedSha256(Buffer.from(source)), targets: [target],
  } });
  write("tsconfig.json", "{}");
  write("m2.ts", "export const candidate = true;");
  write("child.ts", 'import "./main";');
  const check = (policy?: LaunchPolicy) => assertRuntimeIsolation(directory, ["main.ts"], ["m2.ts"], policy);
  const known = launcher('"./child.ts"');
  write("main.ts", known);
  return { write, launcher, review, check, policy: review(known, "child.ts") };
}

test("a reviewed child edge preserves a benign cycle and extends runtime traversal", async t => {
  const { write, check, policy } = childFixture(t);
  await check(policy);
  write("child.ts", 'import "./m2";');
  await assert.rejects(check(policy), /historical runtime reaches M2: main\.ts -> child\.ts -> m2\.ts/u);
});

test("a child destination in M2 is rejected even when listed in launch policy", async t => {
  const { write, launcher, review, check } = childFixture(t);
  const forbidden = launcher('"./m2.ts"');
  write("main.ts", forbidden);
  await assert.rejects(check(review(forbidden, "m2.ts")), /historical child launch targets M2: m2\.ts/u);
});

test("unknown child destinations, computed targets and unreviewed launch sites are rejected", async t => {
  const { write, launcher, check, policy } = childFixture(t);
  await assert.rejects(check(), /unreviewed process-launch site: main\.ts/u);
  write("unknown.ts", "export const unexpected = true;");
  for (const target of ['"./unknown.ts"', '"./" + process.argv[2]']) {
    write("main.ts", launcher(target));
    await assert.rejects(check(policy), /changed process launcher or child target: main\.ts/u);
  }
});
