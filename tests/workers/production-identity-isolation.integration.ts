// Production vs laboratory identity isolation, in workerd, against the REAL admission entry modules:
//  - workers/admission-service/index.ts   (production class: Vercel OIDC, ProductionAdmissionAuthority)
//  - workers/admission-service/lab-index.ts (laboratory class: Google OIDC, LabAdmissionAuthority)
// Synthetic keys, a synthetic JWKS served through an outbound interceptor, no network, no provisioned secret.
// Properties proven:
//  1. The production Worker accepts a Vercel token whose audience is the dedicated admission audience (custom-audience trust policy), through the
//     team-scoped issuer, and rejects a default-audience token, a wrong-project token and a preview token.
//  2. A production-class Worker REFUSES the Google laboratory identity mode and any stray Google identity binding (503, before authentication),
//     even with an otherwise valid Vercel configuration and a valid release MAC.
//  3. The laboratory Worker REFUSES the Vercel identity mode (503), and still serves its own Google mode (401 for an unauthenticated request).
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
const runtimeRoot = join(root, ".wrangler", "tests", `production-identity-${process.pid}-${randomUUID()}`);
const paths = { production: join(runtimeRoot, "production.mjs"), lab: join(runtimeRoot, "lab.mjs") };
const RPC_KEY = encodeBase64url(new Uint8Array(32).fill(5));

const ISSUER = "https://oidc.vercel.com/synthetic-team";
const JWKS = `${ISSUER}/.well-known/jwks`;
const ADMISSION_AUDIENCE = "https://admission-rpc.synthetic.test";
const DEFAULT_AUDIENCE = "https://vercel.com/synthetic-team";
const OWNER = "synthetic-owner", PROJECT = "synthetic-project", OWNER_ID = "team_synthetic", PROJECT_ID = "prj_synthetic";
const SUBJECT = `owner:${OWNER}:project:${PROJECT}:environment:production`;
const GOOGLE_ISSUER = "https://accounts.google.com";

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

let jwksBody = "";
let jwksFetches = 0;
let operator: KeyMaterial;
let attestation: KeyMaterial;

async function main(): Promise<void> {
  assert.ok(resolve(runtimeRoot).startsWith(resolve(root, ".wrangler", "tests") + sep));
  await mkdir(runtimeRoot, { recursive: true });
  process.env.WRANGLER_SEND_METRICS = "false";
  let mf: Miniflare | undefined;
  try {
    for (const [name, entry] of [["production", "workers/admission-service/index.ts"], ["lab", "workers/admission-service/lab-index.ts"]] as const) {
      const built = await build({ entryPoints: [resolve(root, entry)], outfile: paths[name], bundle: true, write: false, plugins: [localFiles], platform: "browser",
        format: "esm", target: "es2022", conditions: ["workerd", "worker", "browser"], external: ["cloudflare:workers"], logLevel: "silent" });
      await writeFile(paths[name], built.outputFiles[0].contents);
    }
    operator = await keyPair(); attestation = await keyPair();
    const vercelKeys = await generateKeyPair("RS256", { extractable: true });
    const otherKeys = await generateKeyPair("RS256");
    const jwk: JWK = { ...(await exportJWK(vercelKeys.publicKey)), kid: "synthetic-kid", alg: "RS256", use: "sig" };
    jwksBody = JSON.stringify({ keys: [jwk] });

    const date = "2026-09-13";
    const interceptor = async (request: Request): Promise<Response> => {
      if (request.url === JWKS) { jwksFetches += 1; return new Response(jwksBody, { status: 200, headers: { "content-type": "application/json" } }); }
      return new Response("blocked", { status: 599 });
    };
    const shared = { AUTHORITY_OPERATOR_PUBLIC_KEY: operator.publicKey, ADMISSION_CURRENT_RPC_KEY: RPC_KEY, ADMISSION_CURRENT_RELEASE_ID: "dpl_current",
      ADMISSION_CURRENT_KEY_ID: "prod-key", ADMISSION_CURRENT_ACTIVATED_AT_MS: "1" };
    const vercelVars = { VERCEL_OIDC_ISSUER: ISSUER, VERCEL_OIDC_AUDIENCE: ADMISSION_AUDIENCE, VERCEL_OIDC_SUBJECT: SUBJECT, VERCEL_OWNER_ID: OWNER_ID, VERCEL_PROJECT_ID: PROJECT_ID };
    const googleVars = { ADMISSION_IDENTITY_MODE: "google-lab", GOOGLE_OIDC_ISSUER: GOOGLE_ISSUER, GOOGLE_OIDC_AUDIENCE: "https://lab-admission.synthetic.test",
      GOOGLE_SERVICE_ACCOUNT_EMAIL: "lab@synthetic.iam.gserviceaccount.com", GOOGLE_SERVICE_ACCOUNT_SUBJECT: "1234567890" };
    const prodAttestation = { AUTHORITY_ATTESTATION_PRIVATE_KEY: attestation.privatePkcs8, AUTHORITY_ATTESTATION_PUBLIC_KEY: attestation.publicKey, AUTHORITY_ATTESTATION_KEY_FINGERPRINT: attestation.fingerprint };
    const production = (name: string, bindings: Record<string, string>) => ({ name, scriptPath: paths.production, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      routes: [`${name}.synthetic.test/*`], bindings: { ...shared, ...prodAttestation, ...bindings },
      durableObjects: { AUTHORITY: { className: "ProductionAdmissionAuthority", useSQLite: true } }, outboundService: interceptor });
    const lab = (name: string, bindings: Record<string, string>) => ({ name, scriptPath: paths.lab, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      routes: [`${name}.synthetic.test/*`], bindings: { ...shared, ...bindings },
      durableObjects: { AUTHORITY: { className: "LabAdmissionAuthority", useSQLite: true } }, outboundService: interceptor });
    const workers = [
      production("prod", vercelVars),
      production("prodgoogle", { ...vercelVars, ...googleVars }),
      production("prodstray", { ...vercelVars, GOOGLE_OIDC_AUDIENCE: "https://stray.synthetic.test" }),
      production("prodgoogleonly", googleVars),
      { name: "driver", script: DRIVER, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
        serviceBindings: { LIFECYCLE: { name: "prod", entrypoint: "AuthorityLifecycleOnly" } } },
      lab("labvercel", vercelVars),
      lab("labgoogle", googleVars),
    ];
    const options = convertV4MiniflareOptions({ host: "127.0.0.1", port: 0, log: new Log(LogLevel.ERROR),
      resourcePersistencePath: join(runtimeRoot, "state"), workers } as unknown as V4MiniflareOptions);
    options.telemetry = { enabled: false };
    mf = new Miniflare(options);
    await mf.ready;

    const rpcKey = await importAdmissionRpcKey(RPC_KEY);
    const opaque = (length: number, fill: number) => encodeBase64url(new Uint8Array(length).fill(fill));
    async function send(host: string, token: string | undefined, nonce: number): Promise<number> {
      const now = Date.now();
      const payload: AdmissionRpcPayload = [ADMISSION_RPC_VERSION, "dpl_current", opaque(16, 9), now, opaque(32, nonce), opaque(32, nonce + 100), opaque(16, nonce), "-", now];
      const body = encodeAdmissionRpcPayload(payload);
      const headers: Record<string, string> = { "content-type": ADMISSION_RPC_CONTENT_TYPE, [ADMISSION_KEY_ID_HEADER]: "prod-key",
        [ADMISSION_MAC_HEADER]: await signAdmissionRpc("/v1/pre", body, rpcKey) };
      if (token !== undefined) headers.authorization = `Bearer ${token}`;
      const response = await mf!.dispatchFetch(`https://${host}.synthetic.test/v1/pre`, { method: "POST", body: toArrayBuffer(body), headers });
      return response.status;
    }
    async function vercelToken(changes: { audience?: string; subject?: string; projectId?: string; environment?: string; signer?: CryptoKey; kid?: string } = {}): Promise<string> {
      const now = Math.floor(Date.now() / 1_000);
      return new SignJWT({ owner: OWNER, owner_id: OWNER_ID, project: PROJECT, project_id: changes.projectId ?? PROJECT_ID, environment: changes.environment ?? "production" })
        .setProtectedHeader({ alg: "RS256", kid: changes.kid ?? "synthetic-kid", typ: "JWT" }).setIssuer(ISSUER).setAudience(changes.audience ?? ADMISSION_AUDIENCE)
        .setSubject(changes.subject ?? SUBJECT).setIssuedAt(now).setNotBefore(now - 1).setExpirationTime(now + 600).sign(changes.signer ?? vercelKeys.privateKey);
    }

    // Initialize the production authority (the relay may surface the signed envelope as an RPC error to this minimal driver; verified behaviourally).
    {
      const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID,
        ADMISSION_POLICY_EPOCH, "dpl_current", "prod-key", Date.now(), true];
      const signature = await signAuthorityInitializationCommand(command, operator.privatePkcs8);
      await (await (await mf.getWorker("driver")).fetch("http://localhost/", { method: "POST", body: JSON.stringify({ command, signature }) })).text();
    }

    // 1. Custom-audience trust policy on the production Worker
    assert.equal(await send("prod", await vercelToken(), 1), 200, "production: dedicated-audience Vercel token is accepted");
    assert.equal(await send("prod", await vercelToken(), 2), 200, "production: a second request in the same isolate is accepted");
    assert.equal(await send("prod", await vercelToken({ audience: DEFAULT_AUDIENCE }), 3), 401, "production: default Vercel audience is NOT accepted");
    assert.equal(await send("prod", await vercelToken({ projectId: "prj_other" }), 4), 401, "production: another project is rejected");
    assert.equal(await send("prod", await vercelToken({ subject: "owner:synthetic-owner:project:synthetic-project:environment:preview", environment: "preview" }), 5), 401, "production: preview identity is rejected");
    assert.equal(await send("prod", await vercelToken({ signer: otherKeys.privateKey }), 6), 401, "production: token signed by another key is rejected");
    assert.equal(await send("prod", undefined, 7), 401, "production: missing bearer is rejected");
    assert.ok(jwksFetches >= 1, "production: the team-scoped JWKS endpoint was used");

    // 2. Production class refuses the Google laboratory identity (even with valid Vercel config, valid MAC and a valid Vercel token)
    jwksFetches = 0;
    const valid = await vercelToken();
    assert.equal(await send("prodgoogle", valid, 11), 503, "production class: google-lab mode is refused");
    assert.equal(await send("prodgoogleonly", undefined, 14), 503, "production class: a pure Google laboratory configuration is refused, not served (no 401 from a Google verifier)");
    assert.equal(await send("prodstray", valid, 12), 503, "production class: a stray GOOGLE_* binding is refused");
    assert.equal(await send("prodgoogle", undefined, 13), 503, "production class: refusal happens before authentication");
    assert.equal(jwksFetches, 0, "production class: no identity provider is contacted when the identity mode is refused");

    // 3. Laboratory class refuses Vercel identity, and still serves its own Google mode
    assert.equal(await send("labvercel", valid, 21), 503, "lab: Vercel identity configuration is refused");
    assert.equal(await send("labgoogle", undefined, 22), 401, "lab: its own Google mode is served (unauthenticated -> 401)");
    assert.equal(await send("labgoogle", valid, 23), 401, "lab: a Vercel token is not a Google identity");
    console.log("production identity isolation integration: all assertions passed");
  } finally {
    if (mf) await mf.dispose();
    await rm(runtimeRoot, { recursive: true, force: true });
  }
}

main().catch((error) => { console.error(error); process.exit(1); });
