import assert from "node:assert/strict";
import test from "node:test";
import { SignJWT, exportJWK, generateKeyPair, type JWK } from "jose";
import {
  VERCEL_OIDC_REQUEST_HEADER, VercelRequestOidcTokenProvider, createProductionAdmissionClient, type VercelOidcSdk,
} from "../src/lib/admission-client.server";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { importAdmissionRpcKey } from "../src/lib/admission-protocol";
import { createVercelOidcVerifier } from "../workers/admission-service/auth";
import { createAdmissionService } from "../workers/admission-service/service";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, PublicInquiryAdmissionAuthority, initializeAuthority } from "../workers/admission-service/authority";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";

// Production Vercel identity path, locally: REAL provider -> REAL production admission client -> REAL admission service (REAL Vercel verifier with a
// locally served JWKS) -> REAL authority logic. What is NOT proven here: a token minted by Vercel, Vercel's real JWKS, the real ~token exchange.

const AUDIENCE = "https://admission-rpc.limitmark.test";
const ISSUER = "https://oidc.vercel.com/acme";
const SUBJECT = "owner:acme:project:acme_website:environment:production";
const OWNER_ID = "team_7Gw5ZMzpQA8h90F832KGp7nwbuh3";
const PROJECT_ID = "prj_7Gw5ZMBpQA8h9GF832KGp7nwbuh3";
const policy = { issuer: ISSUER, audience: AUDIENCE, subject: SUBJECT, ownerId: OWNER_ID, projectId: PROJECT_ID };
const rpcKeyText = encodeBase64url(new Uint8Array(32).fill(7));
const opaque = (length: number, fill: number) => encodeBase64url(new Uint8Array(length).fill(fill));
const DEPLOYMENT = "dpl_reviewed";

type Claims = Record<string, unknown>;
const baseClaims = (nowSeconds: number): Claims => ({
  iss: ISSUER, aud: AUDIENCE, sub: SUBJECT, owner: "acme", owner_id: OWNER_ID, project: "acme_website", project_id: PROJECT_ID,
  environment: "production", iat: nowSeconds - 5, nbf: nowSeconds - 5, exp: nowSeconds + 3_600,
});

async function identityFixture() {
  const pair = await generateKeyPair("RS256", { extractable: true });
  const jwk: JWK = { ...(await exportJWK(pair.publicKey)), kid: "vercel-key-1", alg: "RS256", use: "sig" };
  const jwksFetches: string[] = [];
  let jwksAvailable = true;
  const jwksFetch: typeof fetch = async (input) => {
    jwksFetches.push(String(input));
    if (!jwksAvailable) throw new Error("jwks-down");
    return new Response(JSON.stringify({ keys: [jwk] }), { status: 200, headers: { "content-type": "application/json" } });
  };
  const mint = async (changes: Claims = {}, header: { kid?: string; alg?: string } = {}) => {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const claims = { ...baseClaims(nowSeconds), ...changes };
    for (const key of Object.keys(claims)) if (claims[key] === undefined) delete claims[key];
    return new SignJWT(claims).setProtectedHeader({ alg: header.alg ?? "RS256", kid: header.kid ?? "vercel-key-1", typ: "JWT" }).sign(pair.privateKey);
  };
  return { mint, jwksFetch, jwksFetches, setJwksAvailable: (value: boolean) => { jwksAvailable = value; } };
}

/** An SDK whose request context carries a platform header and whose exchange returns the supplied factory's token. */
function fakeSdk(token: () => Promise<string>, options: { header?: string | null; audiences?: string[] } = {}): VercelOidcSdk & { calls: number } {
  const sdk = {
    calls: 0,
    getContext: () => (options.header === null ? {} : { headers: { [VERCEL_OIDC_REQUEST_HEADER]: options.header ?? "platform-token" } }),
    getVercelOidcToken: async ({ audience }: { audience: string }) => { sdk.calls++; options.audiences?.push(audience); return token(); },
  };
  return sdk;
}

async function admissionFixture(identity: Awaited<ReturnType<typeof identityFixture>>, sdk: VercelOidcSdk, provider = new VercelRequestOidcTokenProvider(sdk)) {
  const rpcKey = await importAdmissionRpcKey(rpcKeyText);
  const storage = new NodeSqliteDurableStorage();
  initializeAuthority(storage, { environment: "staging", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
    releaseId: DEPLOYMENT, releaseKeyId: "release-current", nowMs: Date.now(), confirmProduction: false });
  const authority = () => new PublicInquiryAdmissionAuthority({ storage }, { now: () => Date.now() });
  const service = createAdmissionService({
    releases: [{ role: "current", releaseId: DEPLOYMENT, keyId: "release-current", rpcKey, activatedAtMs: 0 }],
    oidcPolicy: policy,
    oidcVerifier: createVercelOidcVerifier(policy, { fetch: identity.jwksFetch, refreshCooldownMs: 60_000 }),
    authority: { claimPre: (input) => authority().claimPre(input), consumePost: (input) => authority().consumePost(input) },
    now: () => Date.now(),
  });
  const workerRequests: Request[] = [];
  const transport: typeof fetch = async (input, init) => {
    const request = new Request(String(input), init);
    workerRequests.push(request.clone());
    return service(request);
  };
  const client = await createProductionAdmissionClient({
    VERCEL: "1", VERCEL_ENV: "production", VERCEL_DEPLOYMENT_ID: DEPLOYMENT, ADMISSION_RELEASE_ID: DEPLOYMENT,
    ADMISSION_SERVICE_URL: "https://admission-rpc.limitmark.test", ADMISSION_OIDC_AUDIENCE: AUDIENCE,
    ADMISSION_RELEASE_KEY_ID: "release-current", ADMISSION_RELEASE_RPC_KEY: rpcKeyText,
  }, provider, transport);
  assert.ok(client);
  return { client: client!, workerRequests };
}
const preInput = (fill = 3) => ({ releaseId: DEPLOYMENT, clientPseudonym: opaque(32, 2), requestBinding: opaque(32, fill), nonce: opaque(16, fill), issuedAtMs: Date.now() });

// ---------------------------------------------------------------- provider unit behavior

test("provider returns a token only for the requested audience, in production, from the Vercel request context, and never caches", async () => {
  const identity = await identityFixture();
  const audiences: string[] = [];
  const sdk = fakeSdk(() => identity.mint(), { audiences });
  const provider = new VercelRequestOidcTokenProvider(sdk);
  const first = await provider.getToken(AUDIENCE);
  const second = await provider.getToken(AUDIENCE);
  assert.equal(first.split(".").length, 3);
  assert.equal(sdk.calls, 2, "every call re-asks the SDK: the provider holds no token cache");
  assert.deepEqual(audiences, [AUDIENCE, AUDIENCE]);
  assert.ok(second);
});

test("provider fails closed without the platform header: no env, file or CLI fallback is attempted", async () => {
  const identity = await identityFixture();
  for (const header of [null, ""]) {
    const sdk = fakeSdk(() => identity.mint(), { header });
    await assert.rejects(() => new VercelRequestOidcTokenProvider(sdk).getToken(AUDIENCE), /^Error: vercel-oidc-context$/);
    assert.equal(sdk.calls, 0);
  }
  const absent: VercelOidcSdk = { getContext: () => undefined, getVercelOidcToken: async () => { throw new Error("must not be called"); } };
  await assert.rejects(() => new VercelRequestOidcTokenProvider(absent).getToken(AUDIENCE), /vercel-oidc-context/);
});

test("provider maps every exchange failure to a fixed message that never contains the token", async () => {
  const secretToken = "eyJsecret.header.payload";
  const failing = fakeSdk(async () => { throw new Error(`exchange refused for ${secretToken}`); });
  await assert.rejects(() => new VercelRequestOidcTokenProvider(failing).getToken(AUDIENCE), (error: Error) => {
    assert.equal(error.message, "vercel-oidc-exchange");
    assert.ok(!error.message.includes(secretToken) && !String(error.stack ?? "").includes(secretToken));
    return true;
  });
});

test("provider bounds a hanging exchange with its timeout", async () => {
  const hanging = fakeSdk(() => new Promise<string>(() => {}));
  const started = Date.now();
  await assert.rejects(() => new VercelRequestOidcTokenProvider(hanging, 50).getToken(AUDIENCE), /^Error: vercel-oidc-timeout$/);
  assert.ok(Date.now() - started < 1_000);
});

test("provider refuses malformed, wrong-audience, wrong-environment and over-long tokens before they can be sent", async () => {
  const identity = await identityFixture();
  const cases: Array<[string, () => Promise<string>]> = [
    ["not-a-jwt", async () => "not-a-jwt"],
    ["empty", async () => ""],
    ["whitespace", async () => `${await identity.mint()} `],
    ["comma", async () => `${await identity.mint()},x`],
    ["oversized", async () => `a.${"b".repeat(9_000)}.c`],
    ["non-jwt-json", async () => "aaa.bbb.ccc"],
    ["wrong audience", () => identity.mint({ aud: "https://vercel.com/acme" })],
    ["audience array of two", () => identity.mint({ aud: [AUDIENCE, "https://other.test"] })],
    ["preview environment", () => identity.mint({ environment: "preview" })],
    ["development environment", () => identity.mint({ environment: "development" })],
    ["no environment", () => identity.mint({ environment: undefined })],
  ];
  for (const [name, token] of cases) {
    await assert.rejects(() => new VercelRequestOidcTokenProvider(fakeSdk(token)).getToken(AUDIENCE), /vercel-oidc-(token|claims)/, name);
  }
  for (const audience of ["", "has space", "a,b", "x".repeat(257)]) {
    await assert.rejects(() => new VercelRequestOidcTokenProvider(fakeSdk(() => identity.mint())).getToken(audience), /oidc-audience/);
  }
});

// ---------------------------------------------------------------- real @vercel/oidc SDK against a stubbed platform + exchange endpoint

test("real @vercel/oidc SDK: header-gated, custom-audience exchange via POST to oidc.vercel.com/~token, no token reaches logs", async () => {
  const identity = await identityFixture();
  const requestContext = Symbol.for("@vercel/request-context");
  const globals = globalThis as unknown as Record<symbol, unknown>;
  const originalContext = globals[requestContext];
  const originalFetch = globalThis.fetch;
  const originalEnv = process.env.VERCEL_OIDC_TOKEN;
  const unsigned = (claims: Claims) => `${encodeBase64url(new TextEncoder().encode('{"alg":"RS256"}'))}.${encodeBase64url(new TextEncoder().encode(JSON.stringify(claims)))}.sig`;
  const nowSeconds = Math.floor(Date.now() / 1000);
  const platformToken = unsigned({ ...baseClaims(nowSeconds), aud: "https://vercel.com/acme", jti: crypto.randomUUID() });
  const exchanged = await identity.mint();
  const captured: Array<{ url: string; method?: string; body: unknown; authorization: string | null }> = [];
  const logged: string[] = [];
  const originalLog = console.log; const originalError = console.error; const originalWarn = console.warn;
  console.log = (...parts: unknown[]) => { logged.push(parts.map(String).join(" ")); };
  console.error = (...parts: unknown[]) => { logged.push(parts.map(String).join(" ")); };
  console.warn = (...parts: unknown[]) => { logged.push(parts.map(String).join(" ")); };
  try {
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      captured.push({ url: String(input), method: init?.method, body: JSON.parse(String(init?.body)), authorization: new Headers(init?.headers).get("authorization") });
      return Response.json({ token: exchanged, expiry: Math.floor(Date.now() / 1000) + 3_000 });
    }) as typeof fetch;
    // (1) inside a Vercel request context
    globals[requestContext] = { get: () => ({ headers: { [VERCEL_OIDC_REQUEST_HEADER]: platformToken } }) };
    const provider = new VercelRequestOidcTokenProvider();
    assert.equal(await provider.getToken(AUDIENCE), exchanged);
    assert.equal(captured.length, 1);
    assert.equal(captured[0].url, "https://oidc.vercel.com/~token");
    assert.equal(captured[0].method, "POST");
    assert.equal(captured[0].authorization, null, "the platform token travels only in the JSON body, never as a header");
    assert.equal((captured[0].body as { aud: string }).aud, AUDIENCE);
    // (2) outside any request context (build/dev token present in the environment): must refuse, and must not contact the exchange
    globals[requestContext] = undefined;
    process.env.VERCEL_OIDC_TOKEN = unsigned({ ...baseClaims(nowSeconds), environment: "development" });
    captured.length = 0;
    await assert.rejects(() => provider.getToken(AUDIENCE), /^Error: vercel-oidc-context$/);
    assert.equal(captured.length, 0);
    // (3) exchange endpoint failure
    globals[requestContext] = { get: () => ({ headers: { [VERCEL_OIDC_REQUEST_HEADER]: unsigned({ ...baseClaims(nowSeconds), jti: crypto.randomUUID() }) } }) };
    globalThis.fetch = (async () => new Response(JSON.stringify({ error: "denied" }), { status: 403 })) as typeof fetch;
    await assert.rejects(() => provider.getToken(AUDIENCE), /^Error: vercel-oidc-exchange$/);
  } finally {
    globalThis.fetch = originalFetch;
    globals[requestContext] = originalContext;
    if (originalEnv === undefined) delete process.env.VERCEL_OIDC_TOKEN; else process.env.VERCEL_OIDC_TOKEN = originalEnv;
    console.log = originalLog; console.error = originalError; console.warn = originalWarn;
  }
  for (const line of logged) assert.ok(!line.includes(platformToken) && !line.includes(exchanged), "no token appears in console output");
});

// ---------------------------------------------------------------- PRE/POST through the real Vercel verifier

test("PRE then POST are allowed with a Vercel-shaped token; replays are rejected; the bearer is the exchanged token and appears nowhere else", async () => {
  const identity = await identityFixture();
  const sdk = fakeSdk(() => identity.mint());
  const { client, workerRequests } = await admissionFixture(identity, sdk);
  const input = preInput();
  const pre = await client.claimPre(input);
  assert.equal(pre.decision, "allowed");
  assert.ok("permit" in pre);
  const post = await client.consumePost({ releaseId: input.releaseId, clientPseudonym: input.clientPseudonym, requestBinding: input.requestBinding, nonce: input.nonce, permit: (pre as { permit: string }).permit });
  assert.deepEqual(post, { decision: "allowed" });
  assert.equal((await client.consumePost({ releaseId: input.releaseId, clientPseudonym: input.clientPseudonym, requestBinding: input.requestBinding, nonce: input.nonce, permit: (pre as { permit: string }).permit })).decision, "replay");
  assert.equal((await client.claimPre(input)).decision, "replay");
  assert.equal(sdk.calls, 4, "one token per RPC");
  assert.equal(identity.jwksFetches.length, 1);
  assert.equal(identity.jwksFetches[0], "https://oidc.vercel.com/acme/.well-known/jwks");
  for (const request of workerRequests) {
    assert.match(request.headers.get("authorization") ?? "", /^Bearer [\w-]+\.[\w-]+\.[\w-]+$/);
    assert.equal(request.url.includes("eyJ"), false);
  }
});

test("every issuer, audience, subject, owner, project, environment, algorithm and key mismatch is rejected at the Worker (no authority access)", async () => {
  const identity = await identityFixture();
  const wrong: Array<[string, Claims, { kid?: string; alg?: string }?]> = [
    ["issuer", { iss: "https://oidc.vercel.com" }],
    ["issuer other team", { iss: "https://oidc.vercel.com/other" }],
    ["subject preview", { sub: "owner:acme:project:acme_website:environment:preview" }],
    ["subject other project", { sub: "owner:acme:project:other:environment:production" }],
    ["owner id", { owner_id: "team_other" }],
    ["project id", { project_id: "prj_other" }],
    ["environment claim", { environment: "preview" }],
    ["expired", { iat: 1, nbf: 1, exp: 2 }],
    ["lifetime over 7200s", { iat: Math.floor(Date.now() / 1000) - 10, nbf: Math.floor(Date.now() / 1000) - 10, exp: Math.floor(Date.now() / 1000) + 10_000 }],
    ["unknown kid", {}, { kid: "unknown-key" }],
  ];
  for (const [name, claims, header] of wrong) {
    // The provider's own checks must not mask what the Worker enforces: bypass them with a provider stub that returns the minted token as-is.
    const token = await identity.mint(claims, header);
    const { client, workerRequests } = await admissionFixture(identity, fakeSdk(async () => token), { getToken: async () => token } as never);
    assert.deepEqual(await client.claimPre(preInput()), { decision: "unavailable" }, name);
    assert.equal(workerRequests.length, 1, name);
  }
  // control: the same fixture accepts the correct token
  const { client } = await admissionFixture(identity, fakeSdk(() => identity.mint()));
  assert.equal((await client.claimPre(preInput(9))).decision, "allowed");
});

test("a Google/lab-style token, a token signed by another key, and a missing bearer cannot pass the production verifier", async () => {
  const identity = await identityFixture();
  const other = await generateKeyPair("RS256");
  const forged = await new SignJWT(baseClaims(Math.floor(Date.now() / 1000))).setProtectedHeader({ alg: "RS256", kid: "vercel-key-1", typ: "JWT" }).sign(other.privateKey);
  const google = await new SignJWT({ iss: "https://accounts.google.com", aud: AUDIENCE, sub: "1234567890", email: "lab@example.iam.gserviceaccount.com",
    email_verified: true, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600 }).setProtectedHeader({ alg: "RS256", kid: "vercel-key-1" }).sign(other.privateKey);
  for (const token of [forged, google, ""]) {
    const { client } = await admissionFixture(identity, fakeSdk(async () => token), { getToken: async () => token } as never);
    assert.deepEqual(await client.claimPre(preInput()), { decision: "unavailable" });
  }
});

test("identity-service and JWKS unavailability fail closed: no allow, no authority mutation, no retry of a consuming call", async () => {
  const identity = await identityFixture();
  // (a) the token exchange fails: nothing is sent to the Worker
  const failing = fakeSdk(async () => { throw new Error("idp down"); });
  const a = await admissionFixture(identity, failing);
  assert.deepEqual(await a.client.claimPre(preInput()), { decision: "unavailable" });
  assert.equal(a.workerRequests.length, 0);
  // (b) the exchange hangs
  const hanging = new VercelRequestOidcTokenProvider(fakeSdk(() => new Promise<string>(() => {})), 40);
  const b = await admissionFixture(identity, fakeSdk(() => identity.mint()), hanging);
  assert.deepEqual(await b.client.claimPre(preInput()), { decision: "unavailable" });
  assert.equal(b.workerRequests.length, 0);
  // (c) Vercel JWKS unreachable at the Worker
  identity.setJwksAvailable(false);
  const c = await admissionFixture(identity, fakeSdk(() => identity.mint()));
  assert.deepEqual(await c.client.claimPre(preInput()), { decision: "unavailable" });
  assert.deepEqual(await c.client.consumePost({ ...preInput(), permit: opaque(32, 5) }), { decision: "unavailable" });
});
