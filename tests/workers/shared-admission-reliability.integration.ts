// Shared reliability regression (workerd) for the two defects first found in the laboratory admission Worker:
//  1. BoundedRs256JwksResolver stored the native `fetch` on itself and invoked it as a method ("Illegal invocation" in Workers), so no JWKS
//     ever loaded and every token failed closed.
//  2. The cached admission handler retained a Durable Object stub created in its first request ("Cannot perform I/O on behalf of a different
//     request"), so every later request in the isolate answered 503 at claimPre/consumePost.
// This test drives the REAL Production admission Worker entry (workers/admission-service/index.ts, Vercel OIDC, ProductionAdmissionAuthority)
// and the REAL admin gateway entry (workers/admin-gateway/index.ts) in Miniflare/workerd, with synthetic keys and a synthetic JWKS served through an
// outbound interceptor (no network, no real token, no provisioned secret).
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve, sep } from "node:path";
import { build, type Plugin } from "esbuild";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { convertV4MiniflareOptions, Log, LogLevel, Miniflare, type V4MiniflareOptions } from "miniflare";
import {
  ADMISSION_KEY_ID_HEADER, ADMISSION_MAC_HEADER, ADMISSION_RPC_CONTENT_TYPE, ADMISSION_RPC_VERSION,
  encodeAdmissionRpcPayload, importAdmissionRpcKey, signAdmissionRpc, type AdmissionRpcPayload,
} from "../../src/lib/admission-protocol";
import { encodeBase64url, toArrayBuffer } from "../../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH } from "../../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, signAuthorityInitializationCommand, type AuthorityInitializationCommand } from "../../workers/admission-service/operator-command";

const root = process.cwd();
const runtimeRoot = join(root, ".wrangler", "tests", `shared-reliability-${process.pid}-${randomUUID()}`);
const paths = { admission: join(runtimeRoot, "admission.mjs"), gateway: join(runtimeRoot, "gateway.mjs") };
const RPC_KEY = encodeBase64url(new Uint8Array(32).fill(5));

const VERCEL_ISSUER = "https://oidc.vercel.com/synthetic-team";
const VERCEL_JWKS = `${VERCEL_ISSUER}/.well-known/jwks`;
const VERCEL_AUDIENCE = "https://vercel.com/synthetic-team";
const OWNER = "synthetic-owner", PROJECT = "synthetic-project", OWNER_ID = "team_synthetic", PROJECT_ID = "prj_synthetic";
const VERCEL_SUBJECT = `owner:${OWNER}:project:${PROJECT}:environment:production`;
const ACCESS_ISSUER = "https://synthetic.cloudflareaccess.com";
const ACCESS_CERTS = `${ACCESS_ISSUER}/cdn-cgi/access/certs`;
const ACCESS_AUD = "synthetic_access_audience";
const ADMIN_EMAIL = "admin@synthetic.test";
const UPSTREAM = "https://synthetic-admin.vercel.app";

type KeyMaterial = { privatePkcs8: string; publicKey: string; fingerprint: string };
async function keyPair(): Promise<KeyMaterial> {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { privatePkcs8: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))), publicKey: encodeBase64url(raw),
    fingerprint: createHash("sha256").update(raw).digest("hex") };
}

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

const DRIVER = `export default { async fetch(request, env) { const { command, signature } = await request.json(); try { return Response.json(await env.LIFECYCLE.initializeAuthorityFromOperatorAttested(command, signature)); } catch (e) { return Response.json({ error: "relay" }, { status: 500 }); } } };`;

type Mode = "jwks" | "network-failure" | "hang" | "bad-status";
let mode: Mode = "jwks";
let jwksBody = "";
let upstreamHits = 0;
const fetches = { vercel: 0, access: 0 };
let operator: KeyMaterial;
let attestation: KeyMaterial;

async function start(): Promise<Miniflare> {
  const date = "2026-09-13";
  const interceptor = async (request: Request): Promise<Response> => {
    const url = request.url;
    if (url.startsWith(UPSTREAM)) { upstreamHits += 1; return new Response("admin-ok", { status: 200 }); }
    if (url === VERCEL_JWKS) fetches.vercel += 1; else if (url === ACCESS_CERTS) fetches.access += 1; else return new Response("blocked", { status: 599 });
    if (mode === "network-failure") throw new TypeError("synthetic network failure");
    if (mode === "hang") return new Promise<Response>(() => { /* never resolves; the resolver's own 2 s timeout must fire */ });
    if (mode === "bad-status") return new Response("nope", { status: 503 });
    return new Response(jwksBody, { status: 200, headers: { "content-type": "application/json" } });
  };
  const productionBindings = {
    VERCEL_OIDC_ISSUER: VERCEL_ISSUER, VERCEL_OIDC_AUDIENCE: VERCEL_AUDIENCE, VERCEL_OIDC_SUBJECT: VERCEL_SUBJECT,
    VERCEL_OWNER_ID: OWNER_ID, VERCEL_PROJECT_ID: PROJECT_ID,
    AUTHORITY_OPERATOR_PUBLIC_KEY: operator.publicKey, AUTHORITY_ATTESTATION_PRIVATE_KEY: attestation.privatePkcs8,
    AUTHORITY_ATTESTATION_PUBLIC_KEY: attestation.publicKey, AUTHORITY_ATTESTATION_KEY_FINGERPRINT: attestation.fingerprint,
    ADMISSION_CURRENT_RPC_KEY: RPC_KEY, ADMISSION_CURRENT_RELEASE_ID: "dpl_current", ADMISSION_CURRENT_KEY_ID: "prod-key", ADMISSION_CURRENT_ACTIVATED_AT_MS: "1",
  };
  const workers = [
    { name: "admission", scriptPath: paths.admission, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      routes: ["admission.synthetic.test/*"], bindings: productionBindings,
      durableObjects: { AUTHORITY: { className: "ProductionAdmissionAuthority", useSQLite: true } }, outboundService: interceptor },
    { name: "driver", script: DRIVER, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      serviceBindings: { LIFECYCLE: { name: "admission", entrypoint: "AuthorityLifecycleOnly" } } },
    { name: "gateway", scriptPath: paths.gateway, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      routes: ["admin.limitmark.com/*"], outboundService: interceptor,
      bindings: { VERCEL_ADMIN_UPSTREAM_ORIGIN: UPSTREAM, CLOUDFLARE_ACCESS_TEAM_DOMAIN: ACCESS_ISSUER, CLOUDFLARE_ACCESS_AUD: ACCESS_AUD,
        ADMIN_ALLOWED_EMAIL: ADMIN_EMAIL, VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET: "b".repeat(43) } },
  ];
  const options = convertV4MiniflareOptions({ host: "127.0.0.1", port: 0, log: new Log(LogLevel.ERROR),
    resourcePersistencePath: join(runtimeRoot, "state"), workers } as unknown as V4MiniflareOptions);
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
    for (const [name, entry] of [["admission", "workers/admission-service/index.ts"], ["gateway", "workers/admin-gateway/index.ts"]] as const) {
      const built = await build({ entryPoints: [resolve(root, entry)], outfile: paths[name], bundle: true, write: false, plugins: [localFiles], platform: "browser",
        format: "esm", target: "es2022", conditions: ["workerd", "worker", "browser"], external: ["cloudflare:workers"], logLevel: "silent" });
      await writeFile(paths[name], built.outputFiles[0].contents);
    }
    operator = await keyPair(); attestation = await keyPair();
    const vercelKeys = await generateKeyPair("RS256", { extractable: true });
    const otherKeys = await generateKeyPair("RS256");
    const jwk: JWK = { ...(await exportJWK(vercelKeys.publicKey)), kid: "synthetic-kid", alg: "RS256", use: "sig" };
    jwksBody = JSON.stringify({ keys: [jwk] });
    mf = await start();

    // ---------------------------------------------------------------- Production admission Worker (Vercel OIDC)
    const rpcKey = await importAdmissionRpcKey(RPC_KEY);
    const PRE = "/v1/pre" as const, POST = "/v1/post" as const;
    const opaque = (length: number, fill: number) => encodeBase64url(new Uint8Array(length).fill(fill));
    type Rpc = { path: typeof PRE | typeof POST; nonce: number; permit?: string };
    async function send(token: string | undefined, rpc: Rpc): Promise<{ status: number; body: { decision?: string; permit?: string } }> {
      const now = Date.now();
      const payload: AdmissionRpcPayload = [ADMISSION_RPC_VERSION, "dpl_current", opaque(16, 9), now, opaque(32, rpc.nonce), opaque(32, rpc.nonce + 100), opaque(16, rpc.nonce),
        rpc.path === PRE ? "-" : rpc.permit!, rpc.path === PRE ? now : 0];
      const body = encodeAdmissionRpcPayload(payload);
      const headers: Record<string, string> = { "content-type": ADMISSION_RPC_CONTENT_TYPE, [ADMISSION_KEY_ID_HEADER]: "prod-key",
        [ADMISSION_MAC_HEADER]: await signAdmissionRpc(rpc.path, body, rpcKey) };
      if (token !== undefined) headers.authorization = `Bearer ${token}`;
      const response = await mf!.dispatchFetch(`https://admission.synthetic.test${rpc.path}`, { method: "POST", body: toArrayBuffer(body), headers });
      return { status: response.status, body: await response.json().catch(() => ({})) as { decision?: string; permit?: string } };
    }
    async function vercelToken(kid: string, signer: CryptoKey): Promise<string> {
      const now = Math.floor(Date.now() / 1_000);
      return new SignJWT({ owner: OWNER, owner_id: OWNER_ID, project: PROJECT, project_id: PROJECT_ID, environment: "production" })
        .setProtectedHeader({ alg: "RS256", kid, typ: "JWT" }).setIssuer(VERCEL_ISSUER).setAudience(VERCEL_AUDIENCE).setSubject(VERCEL_SUBJECT)
        .setIssuedAt(now).setNotBefore(now - 1).setExpirationTime(now + 600).sign(signer);
    }
    {
      const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID,
        ADMISSION_POLICY_EPOCH, "dpl_current", "prod-key", Date.now(), true];
      const signature = await signAuthorityInitializationCommand(command, operator.privatePkcs8);
      // The relay result carries a signed Uint8Array envelope that workerd RPC may surface as an "internal error" to this minimal driver even though
      // the receipt committed (the production relay treats a transport exception the same way); initialization is verified behaviourally below.
      await (await (await mf.getWorker("driver")).fetch("http://localhost/", { method: "POST", body: JSON.stringify({ command, signature }) })).text();
    }
    const good = await vercelToken("synthetic-kid", vercelKeys.privateKey);
    mode = "jwks"; fetches.vercel = 0;
    assert.equal((await send(await vercelToken("synthetic-kid", otherKeys.privateKey), { path: PRE, nonce: 1 })).status, 401, "production: invalid signature is rejected");
    assert.ok(fetches.vercel >= 1, "production: the Worker retrieves the Vercel JWKS through the shared resolver");
    assert.equal((await send(await vercelToken("unknown-kid", vercelKeys.privateKey), { path: PRE, nonce: 1 })).status, 401, "production: unknown key id is rejected");
    assert.equal((await send(undefined, { path: PRE, nonce: 1 })).status, 401, "production: missing bearer is rejected");
    for (const nonce of [11, 12, 13]) {
      const result = await send(good, { path: PRE, nonce });
      assert.equal(result.status, 200, `production: sequential valid PRE ${nonce}`);
      assert.equal(result.body.decision, "allowed");
    }
    const pre = await send(good, { path: PRE, nonce: 21 });
    assert.equal(pre.body.decision, "allowed"); assert.ok(pre.body.permit);
    const post = await send(good, { path: POST, nonce: 21, permit: pre.body.permit });
    assert.equal(post.status, 200); assert.equal(post.body.decision, "allowed", "production: POST consumes the permit issued by an earlier request");
    assert.notEqual((await send(good, { path: POST, nonce: 21, permit: pre.body.permit })).body.decision, "allowed", "production: replayed POST is not admitted");
    assert.notEqual((await send(good, { path: PRE, nonce: 21 })).body.decision, "allowed", "production: replayed PRE is not admitted");

    // ---------------------------------------------------------------- Admin gateway
    async function accessToken(kid: string, signer: CryptoKey, email = ADMIN_EMAIL): Promise<string> {
      const now = Math.floor(Date.now() / 1_000);
      return new SignJWT({ email, type: "app" }).setProtectedHeader({ alg: "RS256", kid, typ: "JWT" }).setIssuer(ACCESS_ISSUER).setAudience(ACCESS_AUD)
        .setSubject("synthetic-admin").setIssuedAt(now).setNotBefore(now - 1).setExpirationTime(now + 300).sign(signer);
    }
    const admin = async (token: string): Promise<number> =>
      (await mf!.dispatchFetch("https://admin.limitmark.com/admin", { headers: { "cf-access-jwt-assertion": token } })).status;
    const accessJwk: JWK = { ...(await exportJWK(vercelKeys.publicKey)), kid: "access-kid", alg: "RS256", use: "sig" };
    jwksBody = JSON.stringify({ keys: [accessJwk], public_certs: [] }); // both JWKS endpoints answer from the same synthetic body in this phase
    fetches.access = 0; upstreamHits = 0;
    assert.equal(await admin(await accessToken("access-kid", otherKeys.privateKey)), 403, "gateway: invalid signature is rejected");
    assert.ok(fetches.access >= 1, "gateway: the Worker retrieves the Access certs through the shared resolver");
    assert.equal(upstreamHits, 0, "gateway: a rejected assertion never reaches the upstream");
    assert.equal(await admin(await accessToken("unknown-kid", vercelKeys.privateKey)), 403, "gateway: unknown key id is rejected");
    assert.equal(await admin(await accessToken("access-kid", vercelKeys.privateKey, "other@synthetic.test")), 403, "gateway: another email is rejected");
    for (let index = 0; index < 3; index += 1) assert.equal(await admin(await accessToken("access-kid", vercelKeys.privateKey)), 200, `gateway: sequential valid request ${index + 1}`);
    assert.equal(upstreamHits, 3, "gateway: exactly the three valid requests reached the fixed upstream");

    // ---------------------------------------------------------------- JWKS failures fail closed (fresh runtime so no cached key masks the failure)
    for (const failing of ["network-failure", "bad-status", "hang"] as const) {
      await mf.dispose(); mf = await start();
      mode = failing; fetches.vercel = 0; fetches.access = 0; upstreamHits = 0;
      const started = Date.now();
      assert.equal(await admin(await accessToken("access-kid", vercelKeys.privateKey)), 403, `gateway: ${failing} fails closed`);
      assert.equal(upstreamHits, 0);
      assert.ok(fetches.access >= 1);
      if (failing === "hang") assert.ok(Date.now() - started < 8_000, "gateway: the 2 s JWKS timeout fires");
      jwksBody = JSON.stringify({ keys: [jwk] });
      assert.equal((await send(await vercelToken("synthetic-kid", vercelKeys.privateKey), { path: PRE, nonce: 41 })).status, 401, `production: ${failing} fails closed`);
      assert.ok(fetches.vercel >= 1);
    }
    console.log("shared admission reliability integration: all assertions passed");
  } finally {
    if (mf) await mf.dispose();
    await rm(runtimeRoot, { recursive: true, force: true });
  }
}

main().catch((error) => { console.error(error); process.exit(1); });
