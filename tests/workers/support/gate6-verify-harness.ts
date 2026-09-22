import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { build, type Plugin } from "esbuild";
import { encodeBase64url } from "../../../src/lib/ingress-protocol";

// Gate 6A CLI-level test harness for scripts/gate6-credential-verify.ts.
// Mirrors the existing esbuild-substitution pattern in
// tests/workers/support/i3b-cli-result-harness.ts exactly: the real
// operator/r2-transport module is replaced, only inside this test's own
// bundle, with a synthetic version that never opens a socket. It answers
// from an env-var-supplied allow-list of "METHOD BUCKET" pairs (simulating
// an issued credential's *effective* IAM policy) and appends every
// (method, bucket, key) tuple it was actually asked to sign to a trace file,
// so a test can assert both the classification logic and that at most one
// bounded call happens per invocation -- never a hidden retry.

const root = process.cwd();
const files: Plugin = { name: "gate6-verify-test", setup(api) {
  api.onResolve({ filter: /^node:/ }, (args) => ({ path: args.path, external: true }));
  api.onResolve({ filter: /r2-transport$/ }, () => ({ path: "synthetic-gate6-r2-transport", namespace: "synthetic" }));
  api.onLoad({ filter: /.*/, namespace: "synthetic" }, () => ({ loader: "js", contents: `
    import { appendFileSync } from "node:fs";
    export async function oneR2Request(method, target, credential, key) {
      appendFileSync(process.env.GATE6_TEST_TRACE, method + " " + target.bucket + " " + key + "\\n");
      if (process.env.GATE6_TEST_FAIL === "1") throw new Error("synthetic-r2-transport-failure");
      if (process.env.GATE6_TEST_STATUS) return { statusCode: Number(process.env.GATE6_TEST_STATUS), body: new Uint8Array() };
      const allowed = new Set(JSON.parse(process.env.GATE6_TEST_ALLOWED || "[]"));
      const granted = allowed.has(method + " " + target.bucket);
      return { statusCode: granted ? 200 : 403, body: new Uint8Array() };
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

export async function createGate6VerifyHarness() {
  const directory = await mkdtemp(join(tmpdir(), "gate6-verify-"));
  const trace = join(directory, "trace.txt");
  const credentials = join(directory, "synthetic-credential.json");
  const cli = join(directory, "cli.cjs");
  try {
    await mkdir(join(directory, "deployment"));
    await writeFile(join(directory, "deployment", "lifecycle-transport.staging.json"), JSON.stringify({
      version: 1, environment: "staging", accountId: "a".repeat(32),
      requestBucket: "limitmark-lifecycle-requests-staging", resultBucket: "limitmark-lifecycle-results-staging",
      authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1",
      operatorPublicKey: encodeBase64url(new Uint8Array(32).fill(7)),
    }));
    await writeFile(credentials, JSON.stringify({ accessKeyId: "synthetic-gate6-access", secretAccessKey: "synthetic-gate6-secret" }));
    await writeFile(trace, "");
    const bundle = await build({ entryPoints: [resolve(root, "scripts/gate6-credential-verify.ts")], outfile: cli, bundle: true,
      write: false, platform: "node", format: "cjs", target: "node24", plugins: [files], logLevel: "silent" });
    await writeFile(cli, bundle.outputFiles[0].contents);
    return {
      trace,
      async run(args: string[], allowed: string[] = [], fault: { status?: number; fail?: boolean } = {}) {
        await writeFile(trace, "");
        const result = spawnSync(process.execPath, [cli, ...args], { cwd: directory, encoding: "utf8", timeout: 5_000,
          env: { ...process.env, GATE6_TEST_ALLOWED: JSON.stringify(allowed), GATE6_TEST_TRACE: trace,
            GATE6_TEST_STATUS: fault.status === undefined ? "" : String(fault.status), GATE6_TEST_FAIL: fault.fail ? "1" : "" } });
        const traceLines = (await readFile(trace, "utf8")).split("\n").filter(Boolean);
        return { exitCode: result.status, stdout: result.stdout, stderr: result.stderr, traceLines };
      },
      credentialsPath: credentials,
      dispose: () => rm(directory, { recursive: true, force: true }),
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
