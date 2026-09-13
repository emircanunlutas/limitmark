import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test, { before } from "node:test";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JSONWebKeySet,
  type JWTVerifyGetKey,
} from "jose";
import {
  authorizeAdmin,
  extractCloudflareAccessToken,
  resolveAdminFromRequest,
} from "../src/lib/admin-auth-core";
import {
  getAdminAuthConfiguration,
  type AdminAuthEnvironment,
} from "../src/lib/admin-auth-config";
import {
  verifyCloudflareAccessToken,
  type VerifiedCloudflareAccessIdentity,
} from "../src/lib/cloudflare-access";

const environment: AdminAuthEnvironment = {
  CLOUDFLARE_ACCESS_TEAM_DOMAIN: "https://limitmark-test.cloudflareaccess.com",
  CLOUDFLARE_ACCESS_AUD: "synthetic_access_application_audience",
  ADMIN_ALLOWED_EMAILS: " Admin.One@Example.test ,second.admin@example.test",
};

const parsedConfiguration = getAdminAuthConfiguration(environment);
if (!parsedConfiguration.enabled) throw new Error("Synthetic admin configuration must be valid");
const configuration: Extract<typeof parsedConfiguration, { enabled: true }> = parsedConfiguration;

const now = Math.floor(Date.now() / 1_000);
let primaryPair: Awaited<ReturnType<typeof generateKeyPair>>;
let rotatedPair: Awaited<ReturnType<typeof generateKeyPair>>;
let primaryJwk: JSONWebKeySet["keys"][number];
let rotatedJwk: JSONWebKeySet["keys"][number];

before(async () => {
  primaryPair = await generateKeyPair("RS256", { extractable: true });
  rotatedPair = await generateKeyPair("RS256", { extractable: true });
  primaryJwk = { ...(await exportJWK(primaryPair.publicKey)), alg: "RS256", use: "sig", kid: "primary" };
  rotatedJwk = { ...(await exportJWK(rotatedPair.publicKey)), alg: "RS256", use: "sig", kid: "rotated" };
});

function localResolver(...keys: JSONWebKeySet["keys"]): JWTVerifyGetKey {
  return createLocalJWKSet({ keys });
}

type TokenOverrides = {
  audience?: string;
  issuer?: string;
  email?: string;
  subject?: string;
  expiration?: number;
  notBefore?: number;
  issuedAt?: number;
  type?: string;
  key?: CryptoKey;
  kid?: string;
};

async function signedToken(overrides: TokenOverrides = {}): Promise<string> {
  return new SignJWT({
    email: overrides.email ?? "admin.one@example.test",
    type: overrides.type ?? "app",
  })
    .setProtectedHeader({ alg: "RS256", kid: overrides.kid ?? "primary", typ: "JWT" })
    .setIssuer(overrides.issuer ?? configuration.teamDomain)
    .setAudience(overrides.audience ?? configuration.audience)
    .setSubject(overrides.subject ?? "synthetic-user-id")
    .setIssuedAt(overrides.issuedAt ?? now)
    .setNotBefore(overrides.notBefore ?? now - 1)
    .setExpirationTime(overrides.expiration ?? now + 300)
    .sign(overrides.key ?? primaryPair.privateKey);
}

test("admin auth configuration fails closed when required values are missing or malformed", () => {
  assert.deepEqual(getAdminAuthConfiguration({}), { enabled: false, reason: "team-domain" });
  assert.deepEqual(getAdminAuthConfiguration({
    ...environment,
    CLOUDFLARE_ACCESS_TEAM_DOMAIN: "http://limitmark-test.cloudflareaccess.com",
  }), { enabled: false, reason: "team-domain" });
  assert.deepEqual(getAdminAuthConfiguration({
    ...environment,
    CLOUDFLARE_ACCESS_TEAM_DOMAIN: "https://limitmark-test.cloudflareaccess.com/other",
  }), { enabled: false, reason: "team-domain" });
  assert.deepEqual(getAdminAuthConfiguration({ ...environment, CLOUDFLARE_ACCESS_AUD: "" }), {
    enabled: false,
    reason: "audience",
  });
  assert.deepEqual(getAdminAuthConfiguration({ ...environment, CLOUDFLARE_ACCESS_AUD: "not valid" }), {
    enabled: false,
    reason: "audience",
  });
  assert.deepEqual(getAdminAuthConfiguration({ ...environment, ADMIN_ALLOWED_EMAILS: "" }), {
    enabled: false,
    reason: "allowlist",
  });
  assert.deepEqual(getAdminAuthConfiguration({
    ...environment,
    ADMIN_ALLOWED_EMAILS: "admin@example.test, ADMIN@example.test",
  }), { enabled: false, reason: "allowlist" });
});

test("explicit admin identities normalize but similar domains do not authorize", async () => {
  assert.deepEqual([...configuration.allowedEmails], [
    "admin.one@example.test",
    "second.admin@example.test",
  ]);

  const impostorToken = await signedToken({ email: "admin.one@limitmark.com" });
  const impostor = await verifyCloudflareAccessToken(
    impostorToken,
    configuration,
    localResolver(primaryJwk),
  );
  assert.equal(authorizeAdmin(impostor, configuration.allowedEmails), null);
});

test("a valid synthetic Cloudflare Access application token verifies", async () => {
  const identity = await verifyCloudflareAccessToken(
    await signedToken(),
    configuration,
    localResolver(primaryJwk),
  );
  assert.equal(identity.email, "admin.one@example.test");
  assert.deepEqual(Object.keys(identity), ["email"]);
});

test("wrong signature, issuer, audience, expiry, and not-before all fail", async () => {
  const cases = [
    signedToken({ key: rotatedPair.privateKey }),
    signedToken({ issuer: "https://other-team.cloudflareaccess.com" }),
    signedToken({ audience: "another_application" }),
    signedToken({ expiration: now - 120 }),
    signedToken({ notBefore: now + 300 }),
  ];

  for (const token of await Promise.all(cases)) {
    await assert.rejects(() => verifyCloudflareAccessToken(
      token,
      configuration,
      localResolver(primaryJwk),
    ));
  }
});

test("iat allows small clock skew but rejects a materially future-issued token", async () => {
  const resolver = localResolver(primaryJwk);
  const withinTolerance = await verifyCloudflareAccessToken(
    await signedToken({ issuedAt: now + 30 }),
    configuration,
    resolver,
  );
  assert.equal(withinTolerance.email, "admin.one@example.test");

  await assert.rejects(async () => verifyCloudflareAccessToken(
    await signedToken({ issuedAt: now + 300 }),
    configuration,
    resolver,
  ));
});

test("malformed and alg-none tokens fail before any key lookup", async () => {
  let keyLookups = 0;
  const rejectingResolver: JWTVerifyGetKey = async () => {
    keyLookups += 1;
    throw new Error("Synthetic resolver must not run");
  };
  const unsigned = [
    Buffer.from(JSON.stringify({ alg: "none", kid: "none" })).toString("base64url"),
    Buffer.from(JSON.stringify({
      iss: configuration.teamDomain,
      aud: configuration.audience,
      exp: now + 300,
      email: "admin.one@example.test",
      sub: "synthetic-user-id",
      type: "app",
    })).toString("base64url"),
    Buffer.from("unsigned").toString("base64url"),
  ].join(".");

  await assert.rejects(() => verifyCloudflareAccessToken("not-a-jwt", configuration, rejectingResolver));
  await assert.rejects(() => verifyCloudflareAccessToken(unsigned, configuration, rejectingResolver));
  assert.equal(keyLookups, 0);
});

test("multiple JWKS keys support rotation and still select by kid", async () => {
  const resolver = localResolver(primaryJwk, rotatedJwk);
  const oldIdentity = await verifyCloudflareAccessToken(await signedToken(), configuration, resolver);
  const newIdentity = await verifyCloudflareAccessToken(await signedToken({
    key: rotatedPair.privateKey,
    kid: "rotated",
    email: "second.admin@example.test",
  }), configuration, resolver);

  assert.equal(oldIdentity.email, "admin.one@example.test");
  assert.equal(newIdentity.email, "second.admin@example.test");
});

test("authorization requires a verified, explicitly allowlisted identity", async () => {
  const resolver = localResolver(primaryJwk);
  const allowed = await verifyCloudflareAccessToken(await signedToken(), configuration, resolver);
  const denied = await verifyCloudflareAccessToken(
    await signedToken({ email: "other@example.test" }),
    configuration,
    resolver,
  );

  assert.equal(authorizeAdmin(allowed, configuration.allowedEmails)?.email, allowed.email);
  assert.equal(authorizeAdmin(denied, configuration.allowedEmails), null);
  assert.equal(authorizeAdmin(
    { email: "admin.one@example.test" } as VerifiedCloudflareAccessIdentity,
    configuration.allowedEmails,
  ), null);
});

test("missing JWT and spoofed identity headers cannot authorize", async () => {
  let verifierCalls = 0;
  const mustNotVerify = async () => {
    verifierCalls += 1;
    throw new Error("No assertion token should reach verification");
  };

  assert.equal(await resolveAdminFromRequest(new Headers(), environment, mustNotVerify), null);
  assert.equal(await resolveAdminFromRequest(new Headers({
    "x-user-email": "admin.one@example.test",
    "x-forwarded-email": "admin.one@example.test",
  }), environment, mustNotVerify), null);
  assert.equal(verifierCalls, 0);
});

test("public edge credentials and Host/forwarding headers do not authorize admin", async () => {
  for (const host of ["admin.limitmark.com", "limitmark.com", "deployment.vercel.app"]) {
    assert.equal(await resolveAdminFromRequest(new Headers({
      host, "x-forwarded-host": "admin.limitmark.com", "origin": "https://admin.limitmark.com",
      "cf-connecting-ip": "203.0.113.9", "x-vercel-forwarded-for": "203.0.113.9",
      "x-limitmark-origin-secret": "A".repeat(43), "x-vercel-protection-bypass": "B-public",
      "x-vercel-admin-protection-bypass": "B-admin",
    }), environment), null);
  }
});

test("the documented assertion header is extracted; cookies and query strings are ignored", () => {
  assert.equal(extractCloudflareAccessToken(new Headers({
    "Cf-Access-Jwt-Assertion": " header-token ",
  })), "header-token");
  assert.equal(extractCloudflareAccessToken(new Headers({
    cookie: "CF_Authorization=cookie-token",
    referer: "https://example.test/admin?token=query-token",
  })), null);
  assert.equal(extractCloudflareAccessToken(new Headers({
    "cf-access-jwt-assertion": "header-wins",
    cookie: "CF_Authorization=conflicting-cookie",
  })), "header-wins");
});

test("the request boundary authorizes only a verified allowlisted identity", async () => {
  const token = await signedToken();
  const requestHeaders = new Headers({ "cf-access-jwt-assertion": token });
  const resolver = localResolver(primaryJwk);
  const verify = (value: string, config: typeof configuration) =>
    verifyCloudflareAccessToken(value, config, resolver);

  assert.equal((await resolveAdminFromRequest(requestHeaders, environment, verify))?.email,
    "admin.one@example.test");
  assert.equal(await resolveAdminFromRequest(
    requestHeaders,
    { ...environment, ADMIN_ALLOWED_EMAILS: "other@example.test" },
    verify,
  ), null);
  assert.equal(await resolveAdminFromRequest(requestHeaders, {}, verify), null);
});

test("the admin list route retains the real application-side boundary", async () => {
  const pageSource = await readFile(new URL("../src/app/admin/page.tsx", import.meta.url), "utf8");
  const enforcementSource = await readFile(new URL("../src/lib/admin-auth.ts", import.meta.url), "utf8");
  assert.match(pageSource, /authorize: \(\) => Promise<AuthorizedAdminIdentity> = requireAdmin/);
  assert.match(pageSource, /return renderAdminInquiryList\(searchParams\)/);
  assert.match(pageSource, /await authorize\(\)/);
  assert.match(enforcementSource, /if \(!identity\) notFound\(\)/);
  assert.doesNotMatch(enforcementSource, /forbidden/);
  assert.match(pageSource, /Limitmark Admin/);
  assert.match(pageSource, /Controlled inquiry administration/);
  assert.doesNotMatch(pageSource, /submissionToken|payloadFingerprint|notificationOutbox/);
});
