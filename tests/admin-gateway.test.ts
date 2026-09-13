import assert from "node:assert/strict";
import test, { before } from "node:test";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { createAdminGateway, type AdminGatewayConfiguration } from "../workers/admin-gateway/gateway";

const nowSeconds = 1_800_000_000;
let pair: Awaited<ReturnType<typeof generateKeyPair>>;
let jwk: JWK;
before(async () => {
  pair = await generateKeyPair("RS256", { extractable: true });
  jwk = { ...(await exportJWK(pair.publicKey)), kid: "access-current", alg: "RS256", use: "sig" };
});
const configuration: AdminGatewayConfiguration = {
  environment: "production", publicHost: "admin.limitmark.com", upstreamOrigin: "https://limitmark-production.vercel.app",
  accessIssuer: "https://limitmark.cloudflareaccess.com", accessAudience: "access_audience", allowedAdminEmail: "admin@example.test",
  vercelAutomationBypassSecret: "b".repeat(43),
};
async function accessToken(changes: { email?: string; issuer?: string; audience?: string; expiration?: number; issuedAt?: number; notBefore?: number; key?: CryptoKey } = {}) {
  return new SignJWT({ email: changes.email ?? configuration.allowedAdminEmail, type: "app" })
    .setProtectedHeader({ alg: "RS256", kid: "access-current", typ: "JWT" }).setIssuer(changes.issuer ?? configuration.accessIssuer)
    .setAudience(changes.audience ?? configuration.accessAudience).setSubject("synthetic-admin").setIssuedAt(changes.issuedAt ?? nowSeconds)
    .setNotBefore(changes.notBefore ?? nowSeconds - 1).setExpirationTime(changes.expiration ?? nowSeconds + 300).sign(changes.key ?? pair.privateKey);
}

function fixture(changes: Partial<AdminGatewayConfiguration> = {}, upstreamResponse: Response = new Response("admin", { status: 200 })) {
  const upstream: Array<{ url: string; init?: RequestInit }> = [];
  let jwksFetches = 0;
  const gateway = createAdminGateway({ ...configuration, ...changes }, { now: () => nowSeconds * 1_000, fetch: async (input, init) => {
    const url = String(input);
    if (url.endsWith("/cdn-cgi/access/certs")) { jwksFetches++; return new Response(JSON.stringify({ keys: [jwk], public_certs: [] }), { status: 200 }); }
    upstream.push({ url, init }); return upstreamResponse;
  } });
  return { gateway, upstream, jwksFetches: () => jwksFetches };
}

test("valid Access assertion permits one fixed upstream request with a server-only bypass", async () => {
  const { gateway, upstream } = fixture();
  const response = await gateway(new Request("https://admin.limitmark.com/admin", { headers: {
    "cf-access-jwt-assertion": await accessToken(), "x-vercel-protection-bypass": "caller", "x-vercel-set-bypass-cookie": "1",
    cookie: "theme=dark; _vercel_jwt=caller-cookie", "x-limitmark-origin-secret": "caller-origin",
  } }));
  assert.equal(response.status, 200);
  assert.equal(upstream.length, 1);
  assert.equal(upstream[0].url, "https://limitmark-production.vercel.app/admin");
  const headers = upstream[0].init!.headers as Headers;
  assert.equal(headers.get("x-vercel-protection-bypass"), configuration.vercelAutomationBypassSecret);
  assert.equal(headers.get("cookie"), "theme=dark");
  assert.equal(headers.has("x-limitmark-origin-secret"), false);
  assert.equal(headers.get("host"), "limitmark-production.vercel.app");
  assert.equal(upstream[0].init!.redirect, "manual");
  assert.equal(response.headers.has("x-vercel-protection-bypass"), false);
  assert.equal(response.headers.has("set-cookie"), false);
});

test("gateway reconstructs Fetch bodyless responses with a null body", async () => {
  for (const status of [204, 205, 304]) {
    const { gateway } = fixture({}, new Response(null, { status, headers: { "x-safe": "retained",
      "x-reflected-secret": configuration.vercelAutomationBypassSecret } }));
    const response = await gateway(new Request("https://admin.limitmark.com/admin", { headers: { "cf-access-jwt-assertion": await accessToken() } }));
    assert.equal(response.status, status);
    assert.equal(await response.text(), "");
    assert.equal(response.headers.get("x-safe"), "retained");
    assert.equal(response.headers.has("x-reflected-secret"), false);
  }

  const { gateway } = fixture({}, new Response("upstream incorrectly supplied HEAD bytes", { status: 200 }));
  const response = await gateway(new Request("https://admin.limitmark.com/admin", { method: "HEAD",
    headers: { "cf-access-jwt-assertion": await accessToken() } }));
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "");
});

test("ordinary upstream response bodies remain intact", async () => {
  const { gateway } = fixture({}, new Response("ordinary admin response", { status: 200, headers: { "content-type": "text/plain" } }));
  const response = await gateway(new Request("https://admin.limitmark.com/admin", { headers: { "cf-access-jwt-assertion": await accessToken() } }));
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "ordinary admin response");
});

test("invalid Access, missing bypass, wrong host and public host make no upstream request", async () => {
  const invalidCases: Array<{ changes?: Partial<AdminGatewayConfiguration>; request: Request }> = [
    { request: new Request("https://admin.limitmark.com/admin", { headers: { "cf-access-jwt-assertion": "malformed",
      "x-vercel-protection-bypass": "B-public", "x-vercel-admin-protection-bypass": "B-admin" } }) },
    { changes: { vercelAutomationBypassSecret: "" }, request: new Request("https://admin.limitmark.com/admin", { headers: { "cf-access-jwt-assertion": await accessToken() } }) },
    { request: new Request("https://other.limitmark.com/admin", { headers: { "cf-access-jwt-assertion": await accessToken() } }) },
    { request: new Request("https://limitmark.com/", { headers: { "cf-access-jwt-assertion": await accessToken() } }) },
    { changes: { upstreamOrigin: "https://attacker.test" }, request: new Request("https://admin.limitmark.com/admin", { headers: { "cf-access-jwt-assertion": await accessToken() } }) },
  ];
  for (const item of invalidCases) {
    const fixtureValue = fixture(item.changes);
    assert.notEqual((await fixtureValue.gateway(item.request)).status, 200);
    assert.equal(fixtureValue.upstream.length, 0);
  }
});

test("wrong identity, issuer, audience, expiry and signature deny before bypass attachment", async () => {
  const other = await generateKeyPair("RS256");
  for (const token of await Promise.all([
    accessToken({ email: "other@example.test" }), accessToken({ issuer: "https://other.cloudflareaccess.com" }),
    accessToken({ audience: "other" }), accessToken({ expiration: nowSeconds - 120 }), accessToken({ issuedAt: nowSeconds + 120 }),
    accessToken({ notBefore: nowSeconds + 120 }), accessToken({ key: other.privateKey }),
  ])) {
    const { gateway, upstream } = fixture();
    assert.equal((await gateway(new Request("https://admin.limitmark.com/admin", { headers: { "cf-access-jwt-assertion": token } }))).status, 403);
    assert.equal(upstream.length, 0);
  }
});

test("gateway rejects public routes and bypass query controls", async () => {
  for (const url of ["https://admin.limitmark.com/", "https://admin.limitmark.com/api/public-inquiries",
    "https://admin.limitmark.com/admin?x-vercel-protection-bypass=caller", "https://admin.limitmark.com/_next/image?url=https://example.test/a"]) {
    const { gateway, upstream } = fixture();
    assert.notEqual((await gateway(new Request(url, { headers: { "cf-access-jwt-assertion": await accessToken() } }))).status, 200);
    assert.equal(upstream.length, 0);
  }
});

test("unapproved upstream redirects cannot leak the bypass credential", async () => {
  const { gateway, upstream } = fixture({}, new Response(null, { status: 302, headers: { location: "https://attacker.test/capture",
    "x-vercel-protection-bypass": configuration.vercelAutomationBypassSecret, "set-cookie": `_vercel_jwt=${configuration.vercelAutomationBypassSecret}` } }));
  const response = await gateway(new Request("https://admin.limitmark.com/admin", { headers: { "cf-access-jwt-assertion": await accessToken() } }));
  assert.equal(upstream.length, 1);
  assert.equal(response.status, 502);
  assert.equal(response.headers.has("location"), false);
  assert.equal(response.headers.has("set-cookie"), false);
  assert.equal(await response.text(), "");
});

test("an upstream response that reflects the bypass value is replaced with a neutral failure", async () => {
  const reflected = new Response(configuration.vercelAutomationBypassSecret, { status: 200,
    headers: { "x-debug": configuration.vercelAutomationBypassSecret } });
  const { gateway } = fixture({}, reflected);
  const response = await gateway(new Request("https://admin.limitmark.com/admin", { headers: { "cf-access-jwt-assertion": await accessToken() } }));
  assert.equal(response.status, 502);
  assert.equal(response.headers.has("x-debug"), false);
  assert.equal(await response.text(), "");
});

test("gateway JWKS outage and upstream timeout fail closed", async () => {
  let upstreamCalls = 0;
  const unavailable = createAdminGateway(configuration, { now: () => nowSeconds * 1_000, fetch: async () => { throw new Error("jwks-outage"); } });
  assert.equal((await unavailable(new Request("https://admin.limitmark.com/admin", { headers: { "cf-access-jwt-assertion": await accessToken() } }))).status, 403);

  const timeout = createAdminGateway(configuration, { now: () => nowSeconds * 1_000, fetch: async (input) => {
    if (String(input).endsWith("/cdn-cgi/access/certs")) return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
    upstreamCalls++; throw new DOMException("timeout", "TimeoutError");
  } });
  assert.equal((await timeout(new Request("https://admin.limitmark.com/admin", { headers: { "cf-access-jwt-assertion": await accessToken() } }))).status, 504);
  assert.equal(upstreamCalls, 1);
});
