// Lab admission Worker regression (workerd). Two defects made the deployed lab Worker unusable:
//  1. BoundedRs256JwksResolver stores the native `fetch` on itself and calls it as a method; Workers throws "Illegal invocation", so Google's
//     keys were never loaded and every token failed closed at the JWKS stage.
//  2. The cached handler held a Durable Object stub created during the first request; workerd forbids using it from another request
//     ("Cannot perform I/O on behalf of a different request"), so every request after the first in an isolate answered 503 at claimPre.
// This test drives the ACTUAL lab entry module (workers/admission-service/lab-index.ts) in Miniflare/workerd with synthetic OIDC keys, a
// synthetic JWKS served through an outbound interceptor (no network, no real Google token) and a synthetic RPC key. The lab authority is
// initialized through its real operator-signed lifecycle command so /v1/pre issues a genuine permit that /v1/post consumes.
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
import { ADMISSION_POLICY_EPOCH, LAB_ADMISSION_AUTHORITY_ID } from "../../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, signAuthorityInitializationCommand, type AuthorityInitializationCommand } from "../../workers/admission-service/operator-command";

const root = process.cwd();
const runtimeRoot = join(root, ".wrangler", "tests", `lab-jwks-${process.pid}-${randomUUID()}`);
const admissionPath = join(runtimeRoot, "admission.mjs");
const JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const ISSUER = "https://accounts.google.com";
const AUDIENCE = "https://lab-admission.synthetic.test";
const EMAIL = "synthetic-lab@synthetic-project.iam.gserviceaccount.com";
const SUBJECT = "123456789012345678901";
const RPC_KEY = encodeBase64url(new Uint8Array(32).fill(7));

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

// Defect 1 and its correction, side by side, inside workerd.
const PROBE = `export default { async fetch() {
  const out = {};
  const attempt = async (call) => { try { await call(); return "ok"; } catch (e) { return { name: e.name, message: String(e.message).slice(0, 80) }; } };
  const holder = { request: fetch };
  out.method = await attempt(() => holder.request("https://www.googleapis.com/oauth2/v3/certs"));
  const wrapped = { request: (input, init) => fetch(input, init) };
  out.wrapper = await attempt(() => wrapped.request("https://www.googleapis.com/oauth2/v3/certs"));
  return Response.json(out);
} };`;

const DRIVER = `export default { async fetch(request, env) { const { command, signature } = await request.json(); try { return Response.json(await env.LIFECYCLE.initializeAuthorityFromOperatorAttested(command, signature)); } catch (e) { return Response.json({ error: String(e && e.stack || e).slice(0, 600) }, { status: 500 }); } } };`;

type Mode = "jwks" | "network-failure" | "hang" | "bad-status";
let mode: Mode = "jwks";
let jwksFetches = 0;
let jwksBody = "";
let operator: KeyMaterial;
let attestation: KeyMaterial;

async function start(): Promise<Miniflare> {
  const date = "2026-09-13";
  const interceptor = async (request: Request): Promise<Response> => {
    if (request.url !== JWKS_URL) return new Response("blocked", { status: 599 });
    jwksFetches += 1;
    if (mode === "network-failure") throw new TypeError("synthetic network failure");
    if (mode === "hang") return new Promise<Response>(() => { /* never resolves; the resolver's own 2 s timeout must fire */ });
    if (mode === "bad-status") return new Response("nope", { status: 503 });
    return new Response(jwksBody, { status: 200, headers: { "content-type": "application/json" } });
  };
  const bindings = {
    ADMISSION_IDENTITY_MODE: "google-lab", GOOGLE_OIDC_ISSUER: ISSUER, GOOGLE_OIDC_AUDIENCE: AUDIENCE,
    GOOGLE_SERVICE_ACCOUNT_EMAIL: EMAIL, GOOGLE_SERVICE_ACCOUNT_SUBJECT: SUBJECT,
    AUTHORITY_OPERATOR_PUBLIC_KEY: operator.publicKey, AUTHORITY_LAB_ATTESTATION_PRIVATE_KEY: attestation.privatePkcs8,
    AUTHORITY_LAB_ATTESTATION_PUBLIC_KEY: attestation.publicKey, AUTHORITY_LAB_ATTESTATION_KEY_FINGERPRINT: attestation.fingerprint,
    ADMISSION_CURRENT_RPC_KEY: RPC_KEY, ADMISSION_CURRENT_RELEASE_ID: "lab-current", ADMISSION_CURRENT_KEY_ID: "lab-key",
    ADMISSION_CURRENT_ACTIVATED_AT_MS: "1",
  };
  const workers = [
    { name: "admission", scriptPath: admissionPath, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      bindings, durableObjects: { AUTHORITY: { className: "LabAdmissionAuthority", useSQLite: true } }, outboundService: interceptor },
    { name: "driver", script: DRIVER, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      serviceBindings: { LIFECYCLE: { name: "admission", entrypoint: "LabAuthorityLifecycleOnly" } } },
    { name: "probe", script: PROBE, modules: true, compatibilityDate: date, unsafeRegisterWorker: false },
  ];
  const options = convertV4MiniflareOptions({ host: "127.0.0.1", port: 0, log: new Log(LogLevel.ERROR),
    resourcePersistencePath: join(runtimeRoot, `state`), workers } as unknown as V4MiniflareOptions);
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
    const built = await build({ entryPoints: [resolve(root, "workers/admission-service/lab-index.ts")], outfile: admissionPath, bundle: true, write: false,
      plugins: [localFiles], platform: "browser", format: "esm", target: "es2022", conditions: ["workerd", "worker", "browser"],
      external: ["cloudflare:workers"], logLevel: "silent" });
    await writeFile(admissionPath, built.outputFiles[0].contents);

    operator = await keyPair(); attestation = await keyPair();
    const keys = await generateKeyPair("RS256", { extractable: true });
    const jwk: JWK = { ...(await exportJWK(keys.publicKey)), kid: "synthetic-kid", alg: "RS256", use: "sig" };
    jwksBody = JSON.stringify({ keys: [jwk] });
    const otherKeys = await generateKeyPair("RS256");
    mf = await start();

    // Original unbound-fetch invocation reproduces the failure; the wrapper resolves it.
    const probe = await (await (await mf.getWorker("probe")).fetch("http://localhost/")).json() as { method: unknown; wrapper: unknown };
    assert.match(JSON.stringify(probe.method), /Illegal invocation/u, "fetch stored on an object and called as a method throws in workerd");
    assert.doesNotMatch(JSON.stringify(probe.wrapper), /Illegal invocation/u, "the plain-function wrapper does not");

    const rpcKey = await importAdmissionRpcKey(RPC_KEY);
    const PRE = "/v1/pre" as const, POST = "/v1/post" as const;
    const opaque = (length: number, fill: number) => encodeBase64url(new Uint8Array(length).fill(fill));
    type Rpc = { path: typeof PRE | typeof POST; nonce: number; permit?: string; wrongPathMac?: boolean };
    async function send(token: string | undefined, rpc: Rpc): Promise<{ status: number; body: { decision?: string; permit?: string } }> {
      const now = Date.now();
      const payload: AdmissionRpcPayload = [ADMISSION_RPC_VERSION, "lab-current", opaque(16, 9), now, opaque(32, rpc.nonce), opaque(32, rpc.nonce + 100), opaque(16, rpc.nonce),
        rpc.path === PRE ? "-" : rpc.permit!, rpc.path === PRE ? now : 0];
      const body = encodeAdmissionRpcPayload(payload);
      const macPath = rpc.wrongPathMac ? (rpc.path === PRE ? POST : PRE) : rpc.path;
      const headers: Record<string, string> = { "content-type": ADMISSION_RPC_CONTENT_TYPE, [ADMISSION_KEY_ID_HEADER]: "lab-key",
        [ADMISSION_MAC_HEADER]: await signAdmissionRpc(macPath, body, rpcKey) };
      if (token !== undefined) headers.authorization = `Bearer ${token}`;
      const response = await mf!.dispatchFetch(`https://lab-admission.synthetic.test${rpc.path}`, { method: "POST", body: toArrayBuffer(body), headers });
      return { status: response.status, body: await response.json().catch(() => ({})) as { decision?: string; permit?: string } };
    }
    async function token(kid: string, signer: CryptoKey, audience = AUDIENCE): Promise<string> {
      const now = Math.floor(Date.now() / 1_000);
      return new SignJWT({ email: EMAIL, email_verified: true, iat: now, exp: now + 600 })
        .setProtectedHeader({ alg: "RS256", kid, typ: "JWT" }).setIssuer(ISSUER).setAudience(audience).setSubject(SUBJECT).sign(signer);
    }
    async function initializeAuthority(): Promise<void> {
      const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "lab", LAB_ADMISSION_AUTHORITY_ID,
        ADMISSION_POLICY_EPOCH, "lab-current", "lab-key", Date.now(), false];
      const signature = await signAuthorityInitializationCommand(command, operator.privatePkcs8);
      // The relay result carries a signed Uint8Array envelope that workerd's RPC surfaces as an "internal error" to this minimal driver even
      // though the lifecycle receipt has committed (the production relay treats a transport exception the same way, see
      // submitSealedLifecycleArtifact). The commit is therefore verified through behaviour below: PRE must be admitted only once initialized.
      await (await mf!.getWorker("driver")).fetch("http://localhost/", { method: "POST", body: JSON.stringify({ command, signature }) }).then((r) => r.text());
    }
    const good = await token("synthetic-kid", keys.privateKey);
    await initializeAuthority();

    // Authentication negatives. The first one also proves the Worker now loads the JWKS through its normal path.
    mode = "jwks"; jwksFetches = 0;
    assert.equal((await send(await token("synthetic-kid", otherKeys.privateKey), { path: PRE, nonce: 1 })).status, 401, "invalid signature is rejected");
    assert.ok(jwksFetches >= 1, "the lab Worker retrieves the JWKS through its normal path");
    assert.equal((await send(await token("unknown-kid", keys.privateKey), { path: PRE, nonce: 1 })).status, 401, "unknown key id is rejected");
    assert.equal((await send(await token("synthetic-kid", keys.privateKey, "https://other.example"), { path: PRE, nonce: 1 })).status, 401, "wrong audience is rejected");
    assert.equal((await send(undefined, { path: PRE, nonce: 1 })).status, 401, "missing bearer is rejected");
    assert.equal((await send(good, { path: PRE, nonce: 1, wrongPathMac: true })).status, 401, "a MAC computed over the other path is rejected");

    // Request-context isolation: sequential valid requests in one isolate with no cross-request I/O error.
    for (const nonce of [11, 12, 13]) {
      const result = await send(good, { path: PRE, nonce });
      assert.equal(result.status, 200, `sequential valid PRE ${nonce}`);
      assert.equal(result.body.decision, "allowed");
    }
    // A genuine PRE -> POST through the real authority (separate requests), then replays.
    const pre = await send(good, { path: PRE, nonce: 21 });
    assert.equal(pre.status, 200); assert.equal(pre.body.decision, "allowed"); assert.ok(pre.body.permit);
    const post = await send(good, { path: POST, nonce: 21, permit: pre.body.permit });
    assert.equal(post.status, 200); assert.equal(post.body.decision, "allowed", "POST consumes the permit issued by PRE in an earlier request");
    const replayPost = await send(good, { path: POST, nonce: 21, permit: pre.body.permit });
    assert.equal(replayPost.status, 200); assert.notEqual(replayPost.body.decision, "allowed", "a replayed POST is not admitted again");
    const replayPre = await send(good, { path: PRE, nonce: 21 });
    assert.notEqual(replayPre.body.decision, "allowed", "a replayed PRE is not admitted again (authority state persists across requests)");
    assert.equal((await send(await token("synthetic-kid", otherKeys.privateKey), { path: PRE, nonce: 31 })).status, 401, "authentication still fails closed afterwards");

    // JWKS network failure / non-success / timeout fail closed (fresh Miniflare so no cached key can mask the failure).
    for (const failing of ["network-failure", "bad-status", "hang"] as const) {
      await mf.dispose(); mf = await start();
      mode = failing; jwksFetches = 0;
      const started = Date.now();
      assert.equal((await send(good, { path: PRE, nonce: 41 })).status, 401, `${failing} fails closed`);
      assert.ok(jwksFetches >= 1);
      if (failing === "hang") assert.ok(Date.now() - started < 8_000, "the 2 s JWKS timeout fires");
    }
    console.log("lab JWKS fetch + request-context integration: all assertions passed");
  } finally {
    if (mf) await mf.dispose();
    await rm(runtimeRoot, { recursive: true, force: true });
  }
}

main().catch((error) => { console.error(error); process.exit(1); });
