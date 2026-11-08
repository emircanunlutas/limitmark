// JWKS concurrency regression (workerd). Drives the REAL admin gateway entry (workers/admin-gateway/index.ts), which uses the shared
// BoundedRs256JwksResolver, with overlapping requests while the first JWKS acquisition is still in flight. Synthetic keys, no network.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve, sep } from "node:path";
import { build, type Plugin } from "esbuild";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { convertV4MiniflareOptions, Log, LogLevel, Miniflare, type V4MiniflareOptions } from "miniflare";

const root = process.cwd();
const runtimeRoot = join(root, ".wrangler", "tests", `jwks-concurrency-${process.pid}-${randomUUID()}`);
const bundle = join(runtimeRoot, "gateway.mjs");
const ISSUER = "https://synthetic.cloudflareaccess.com", CERTS = `${ISSUER}/cdn-cgi/access/certs`, AUD = "synthetic_access_audience";
const EMAIL = "admin@synthetic.test", UPSTREAM = "https://synthetic-admin.vercel.app";

const localFiles: Plugin = { name: "workspace-files", setup(api) {
  api.onResolve({ filter: /.*/ }, async (args) => {
    if (args.path === "cloudflare:workers") return { path: args.path, external: true };
    if (!args.path.startsWith(".") && !isAbsolute(args.path)) return undefined;
    const base = resolve(args.resolveDir || root, args.path);
    for (const path of [base, `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.json`, join(base, "index.ts")]) {
      try { await readFile(path); return { path, namespace: "workspace-file" }; } catch { /* next */ }
    }
    throw new Error(`Unresolved local module: ${args.path}`);
  });
  api.onLoad({ filter: /.*/, namespace: "workspace-file" }, async (args) => ({ contents: await readFile(args.path),
    resolveDir: dirname(args.path), loader: extname(args.path) === ".ts" ? "ts" : extname(args.path) === ".json" ? "json" : "js" }));
} };

type Mode = "ok" | "slow" | "fail" | "hang";
let mode: Mode = "ok", jwksBody = "", certFetches = 0, upstreamHits = 0;
const slowMs = 400;

async function start(): Promise<Miniflare> {
  const interceptor = async (request: Request): Promise<Response> => {
    if (request.url.startsWith(UPSTREAM)) { upstreamHits += 1; return new Response("admin-ok"); }
    if (request.url !== CERTS) return new Response("blocked", { status: 599 });
    certFetches += 1;
    if (mode === "fail") throw new TypeError("synthetic network failure");
    if (mode === "hang") return new Promise<Response>(() => { /* the resolver's own timeout must fire */ });
    if (mode === "slow") await new Promise((done) => setTimeout(done, slowMs));
    return new Response(jwksBody, { status: 200, headers: { "content-type": "application/json" } });
  };
  const options = convertV4MiniflareOptions({ host: "127.0.0.1", port: 0, log: new Log(LogLevel.ERROR), resourcePersistencePath: join(runtimeRoot, "state"),
    workers: [{ name: "gateway", scriptPath: bundle, modules: true, compatibilityDate: "2026-09-13", unsafeRegisterWorker: false, routes: ["admin.limitmark.com/*"],
      outboundService: interceptor, bindings: { VERCEL_ADMIN_UPSTREAM_ORIGIN: UPSTREAM, CLOUDFLARE_ACCESS_TEAM_DOMAIN: ISSUER, CLOUDFLARE_ACCESS_AUD: AUD,
        ADMIN_ALLOWED_EMAIL: EMAIL, VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET: "b".repeat(43) } }] } as unknown as V4MiniflareOptions);
  options.telemetry = { enabled: false };
  const mf = new Miniflare(options);
  await mf.ready;
  return mf;
}

async function main(): Promise<void> {
  assert.ok(resolve(runtimeRoot).startsWith(resolve(root, ".wrangler", "tests") + sep));
  await mkdir(runtimeRoot, { recursive: true });
  process.env.WRANGLER_SEND_METRICS = "false";
  let mf: Miniflare | undefined;
  try {
    const built = await build({ entryPoints: [resolve(root, "workers/admin-gateway/index.ts")], outfile: bundle, bundle: true, write: false, plugins: [localFiles],
      platform: "browser", format: "esm", target: "es2022", conditions: ["workerd", "worker", "browser"], external: ["cloudflare:workers"], logLevel: "silent" });
    await writeFile(bundle, built.outputFiles[0].contents);
    const keys = await generateKeyPair("RS256", { extractable: true });
    const jwk: JWK = { ...(await exportJWK(keys.publicKey)), kid: "access-kid", alg: "RS256", use: "sig" };
    jwksBody = JSON.stringify({ keys: [jwk], public_certs: [] });
    const token = () => {
      const now = Math.floor(Date.now() / 1_000);
      return new SignJWT({ email: EMAIL, type: "app" }).setProtectedHeader({ alg: "RS256", kid: "access-kid", typ: "JWT" }).setIssuer(ISSUER).setAudience(AUD)
        .setSubject("synthetic-admin").setIssuedAt(now).setNotBefore(now - 1).setExpirationTime(now + 300).sign(keys.privateKey);
    };
    const admin = async (signal?: AbortSignal): Promise<number> =>
      (await mf!.dispatchFetch("https://admin.limitmark.com/admin", { headers: { "cf-access-jwt-assertion": await token() }, signal })).status;
    const fresh = async (next: Mode) => { if (mf) await mf.dispose(); mode = next; certFetches = 0; upstreamHits = 0; mf = await start(); };

    // 1. Overlapping requests during the initial acquisition share one network fetch and all succeed; later requests reuse the cache.
    await fresh("slow");
    const burst = await Promise.all(Array.from({ length: 6 }, () => admin()));
    assert.deepEqual(burst, [200, 200, 200, 200, 200, 200], "overlapping initial requests all succeed");
    assert.equal(certFetches, 1, "overlapping initial requests share a single in-flight JWKS fetch");
    assert.equal(await admin(), 200); assert.equal(await admin(), 200);
    assert.equal(certFetches, 1, "later requests reuse the cache with no extra network fetch");
    assert.equal(upstreamHits, 8);

    // 2. The request that started the acquisition is abandoned by its client; a concurrent request must still complete.
    await fresh("slow");
    const abort = new AbortController();
    const first = admin(abort.signal).then(() => "completed", () => "aborted");
    await new Promise((done) => setTimeout(done, 100));
    const second = admin();
    abort.abort();
    const [, secondStatus] = await Promise.all([first, second]);
    assert.equal(secondStatus, 200, "a concurrent request survives its peer being abandoned during acquisition");
    assert.equal(certFetches, 1);

    // 3. Unavailable JWKS: concurrent requests fail closed with one fetch and never reach the upstream.
    await fresh("fail");
    assert.deepEqual(await Promise.all([admin(), admin(), admin()]), [403, 403, 403], "failed acquisition fails closed for every overlapping request");
    assert.equal(certFetches, 1); assert.equal(upstreamHits, 0);
    mode = "ok";
    assert.equal(await admin(), 403, "inside the 30 s cooldown the resolver stays closed rather than refetching");
    assert.equal(certFetches, 1, "no refetch inside the cooldown");
    await new Promise((done) => setTimeout(done, 31_000));
    assert.equal(await admin(), 200, "recovers once the cooldown has elapsed");
    assert.equal(certFetches, 2);
    assert.equal(await admin(), 200);
    assert.equal(certFetches, 2, "recovered key is cached");

    // 4. A hanging endpoint hits the resolver timeout; every overlapping request fails closed shortly after it.
    await fresh("hang");
    const started = Date.now();
    assert.deepEqual(await Promise.all([admin(), admin(), admin()]), [403, 403, 403]);
    assert.ok(Date.now() - started < 8_000, "hang bounded by the 2 s JWKS timeout");
    assert.equal(certFetches, 1); assert.equal(upstreamHits, 0);
    console.log("jwks concurrency integration: all assertions passed");
  } finally {
    await mf?.dispose();
    await rm(runtimeRoot, { recursive: true, force: true });
  }
}
main().then(() => process.exit(0), (error) => { console.error(error); process.exit(1); });
