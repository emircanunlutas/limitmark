import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { build, type Plugin } from "esbuild";
import { encodeBase64url } from "../../../src/lib/ingress-protocol";

const root = process.cwd();
const files: Plugin = { name: "local-cli-result", setup(api) {
  api.onResolve({ filter: /^node:/ }, (args) => ({ path: args.path, external: true }));
  api.onResolve({ filter: /r2-transport$/ }, () => ({ path: "synthetic-read-transport", namespace: "synthetic" }));
  api.onLoad({ filter: /.*/, namespace: "synthetic" }, () => ({ loader: "js", contents: `
    import { appendFileSync } from "node:fs";
    export async function oneR2Request(method) {
      appendFileSync(process.env.I3B_CLI_TRACE, method + "\\n");
      if (method !== "GET") throw new Error("unexpected-mutation-transport");
      return { statusCode: 200, body: Uint8Array.from(Buffer.from(process.env.I3B_CLI_BODY, "base64")) };
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

export async function createCliResultHarness() {
  const directory = await mkdtemp(join(tmpdir(), "i3b-cli-result-"));
  const trace = join(directory, "trace.txt");
  const credentials = join(directory, "synthetic-result-credential.json");
  const cli = join(directory, "cli.cjs");
  try {
    await mkdir(join(directory, "deployment"));
    await writeFile(join(directory, "deployment", "lifecycle-transport.production.json"), JSON.stringify({
      version: 1, environment: "production", accountId: "a".repeat(32),
      requestBucket: "limitmark-lifecycle-requests-production", resultBucket: "limitmark-lifecycle-results-production",
      authorityId: "production-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1",
      operatorPublicKey: encodeBase64url(new Uint8Array(32).fill(7)),
    }));
    await writeFile(credentials, JSON.stringify({ accessKeyId: "synthetic-read", secretAccessKey: "synthetic-only" }));
    const bundle = await build({ entryPoints: [resolve(root, "scripts/authority-submit.ts")], outfile: cli, bundle: true,
      write: false, platform: "node", format: "cjs", target: "node24", plugins: [files], logLevel: "silent" });
    await writeFile(cli, bundle.outputFiles[0].contents);
    return {
      async run(bytes: Uint8Array, kind: "lifecycle" | "reconciliation", digest: string, nonce?: string) {
        await writeFile(trace, "");
        const args = [cli, "read-result", "--kind", kind, "--digest", digest, "--result-credentials", credentials];
        if (nonce) args.push("--nonce", nonce);
        const result = spawnSync(process.execPath, args, { cwd: directory, encoding: "utf8", timeout: 5_000,
          env: { ...process.env, I3B_CLI_BODY: Buffer.from(bytes).toString("base64"), I3B_CLI_TRACE: trace } });
        return { exitCode: result.status, stdout: result.stdout, stderr: result.stderr, methods: (await readFile(trace, "utf8")).trim().split(/\s+/u) };
      },
      dispose: () => rm(directory, { recursive: true, force: true }),
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
