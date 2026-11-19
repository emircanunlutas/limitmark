import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { build, type Plugin } from "esbuild";
import type { LifecycleDispatchGuard } from "../../workers/lifecycle-mailbox/dispatch-guard";

// The ONLY place the guard-export tests use the two already-reviewed unprovable-reference idioms (see REVIEWED_UNPROVABLE_REFERENCES in
// tests/r06-activation-capability-guard.test.ts): (1) `createRequire(<package.json>).resolve(<path>)` inside an esbuild onResolve plugin -- path resolution only,
// nothing is loaded through it; (2) `import(`data:text/javascript;base64,...`)` of an esbuild bundle held in memory.
const root = process.cwd();

export const localFiles: Plugin = { name: "workspace-files", setup(api) {
  api.onResolve({ filter: /.*/ }, async (args) => {
    if (args.path === "cloudflare:workers") return { path: args.path, external: true };
    const base = args.path.startsWith(".") || isAbsolute(args.path) ? resolve(args.resolveDir || root, args.path) :
      createRequire(args.importer || join(root, "package.json")).resolve(args.path);
    for (const path of [base, `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.json`, join(base, "index.ts")]) {
      try { await readFile(path); return { path, namespace: "workspace-file" }; } catch { /* next */ }
    }
    throw new Error(`Unresolved local module: ${args.path}`);
  });
  api.onLoad({ filter: /.*/, namespace: "workspace-file" }, async (args) => ({ contents: await readFile(args.path),
    resolveDir: dirname(args.path), loader: extname(args.path) === ".ts" ? "ts" : extname(args.path) === ".json" ? "json" : "js" }));
} };

/** The real LifecycleDispatchGuard class, bundled for Node with a minimal stand-in for `cloudflare:workers`' DurableObject base (env only). */
export async function loadBundledGuard(): Promise<typeof LifecycleDispatchGuard> {
  const bundled = await build({ entryPoints: [resolve("workers/lifecycle-mailbox/dispatch-guard.ts")], bundle: true, write: false, platform: "node", format: "esm", target: "node24",
    plugins: [{ name: "local-do-base", setup(api) {
      api.onResolve({ filter: /^cloudflare:workers$/ }, () => ({ path: "local-do-base", namespace: "test" }));
      api.onLoad({ filter: /.*/, namespace: "test" }, () => ({ contents: "export class DurableObject { constructor(_state, env) { this.env = env; } }", loader: "js" }));
      api.onResolve({ filter: /.*/ }, async (args) => {
        const base = args.path.startsWith(".") || isAbsolute(args.path) ? resolve(args.resolveDir || process.cwd(), args.path) : args.path;
        for (const path of [base, `${base}.ts`, `${base}.js`, join(base, "index.ts")]) { try { await readFile(path); return { path, namespace: "workspace-file" }; } catch { /* next */ } }
        throw new Error(`unresolved: ${args.path}`);
      });
      api.onLoad({ filter: /.*/, namespace: "workspace-file" }, async (args) => ({ contents: await readFile(args.path), resolveDir: dirname(args.path), loader: extname(args.path) === ".ts" ? "ts" : "js" }));
    } }] });
  return (await import(`data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`) as { LifecycleDispatchGuard: typeof LifecycleDispatchGuard }).LifecycleDispatchGuard;
}
