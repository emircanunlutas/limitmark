import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { build, type Plugin } from "esbuild";

// Gate 6A CLI-level test harness for scripts/gate6-credential-capture.ts.
// Mirrors tests/workers/support/i3b-cli-result-harness.ts's esbuild
// substitution pattern: the real scripts/gate6-secure-input module (the only
// place a real invocation ever reads terminal keystrokes) is replaced, only
// inside this test's own bundle, with a synthetic version that returns two
// fixed, clearly-synthetic values from environment variables and never
// touches a TTY -- so the CLI's argument parsing, path/overwrite refusal,
// file writing and confirmation output can all be exercised without a real
// interactive terminal, while the real masked-input code path in
// scripts/gate6-secure-input.ts itself stays untouched and untested here
// (it can only be exercised by an interactive operator).

const root = process.cwd();
const files: Plugin = { name: "gate6-capture-test", setup(api) {
  api.onResolve({ filter: /^node:/ }, (args) => ({ path: args.path, external: true }));
  api.onResolve({ filter: /gate6-secure-input$/ }, () => ({ path: "synthetic-gate6-secure-input", namespace: "synthetic" }));
  api.onLoad({ filter: /.*/, namespace: "synthetic" }, () => ({ loader: "js", contents: `
    export async function readMaskedField(label) {
      if (label.endsWith("accessKeyId")) return process.env.GATE6_TEST_ACCESS_KEY_ID;
      return process.env.GATE6_TEST_SECRET_ACCESS_KEY;
    }
  ` }));
  api.onResolve({ filter: /.*/ }, async (args) => {
    const base = args.path.startsWith(".") || isAbsolute(args.path) ? resolve(args.resolveDir || root, args.path) :
      createRequire(args.importer || join(root, "package.json")).resolve(args.path);
    for (const path of [base, `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.json`, join(base, "index.ts")]) {
      try { await readFile(path); return { path, namespace: "workspace-file" }; } catch { /* next */ }
    }
    throw new Error(`Unresolved CLI module: ${args.path}`);
  });
  api.onLoad({ filter: /.*/, namespace: "workspace-file" }, async (args) => ({ contents: await readFile(args.path),
    resolveDir: dirname(args.path), loader: extname(args.path) === ".ts" ? "ts" : extname(args.path) === ".json" ? "json" : "js" }));
} };

export async function createGate6CaptureHarness() {
  const directory = await mkdtemp(join(tmpdir(), "gate6-capture-"));
  // `repoDir` is spawned as the CLI's own cwd, standing in for the real
  // project repository this tool refuses to write inside; `outputDir` is a
  // sibling directory standing in for the operator's protected, genuinely
  // out-of-repo capture location. This mirrors real usage, where an operator
  // always runs the tool from the repository root.
  const repoDir = join(directory, "repo");
  const outputDir = join(directory, "outside");
  const cli = join(directory, "cli.cjs");
  try {
    await mkdir(repoDir, { recursive: true });
    await mkdir(outputDir, { recursive: true });
    const bundle = await build({ entryPoints: [resolve(root, "scripts/gate6-credential-capture.ts")], outfile: cli, bundle: true,
      write: false, platform: "node", format: "cjs", target: "node24", plugins: [files], logLevel: "silent" });
    await writeFile(cli, bundle.outputFiles[0].contents);
    return {
      directory, repoDir, outputDir,
      async run(args: string[], accessKeyId = "AKIASYNTHETICGATE6ONLY0000", secretAccessKey = "synthetic-gate6-secret-only-000000") {
        const result = spawnSync(process.execPath, [cli, ...args], { cwd: repoDir, encoding: "utf8", timeout: 5_000,
          env: { ...process.env, GATE6_TEST_ACCESS_KEY_ID: accessKeyId, GATE6_TEST_SECRET_ACCESS_KEY: secretAccessKey } });
        return { exitCode: result.status, stdout: result.stdout, stderr: result.stderr };
      },
      dispose: () => rm(directory, { recursive: true, force: true }),
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
