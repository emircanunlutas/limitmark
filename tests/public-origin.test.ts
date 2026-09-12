import assert from "node:assert/strict";
import test from "node:test";
import { NextRequest } from "next/server";
import { proxy } from "../src/proxy";
import { isPublicOriginAllowed, publicOriginHeader } from "../src/lib/public-origin";
import { derivePrivateClientKey, type ClientIdentityConfiguration } from "../src/lib/client-identity";
import { getPublicSubmissionConfiguration } from "../src/lib/public-submission-config";

const secret = "A".repeat(43);
const environment = { PUBLIC_ORIGIN_PROTECTION: "required", PUBLIC_ORIGIN_SECRET: secret, VERCEL: "1", VERCEL_ENV: "production" };
const valid = () => new Headers({ host: "limitmark.com", "x-forwarded-host": "limitmark.com", [publicOriginHeader]: secret });

test("origin protection is opt-in; unknown, empty and incomplete settings fail closed", () => {
  assert.equal(isPublicOriginAllowed(new Headers(), {}), true);
  assert.equal(isPublicOriginAllowed(new Headers(), { PUBLIC_ORIGIN_PROTECTION: "disabled" }), true);
  assert.equal(isPublicOriginAllowed(valid(), environment), true);
  for (const change of [
    { PUBLIC_ORIGIN_PROTECTION: "cloudflare" }, { PUBLIC_ORIGIN_PROTECTION: "" },
    { PUBLIC_ORIGIN_SECRET: undefined }, { PUBLIC_ORIGIN_SECRET: "short" },
    { VERCEL: undefined }, { VERCEL_ENV: "preview" },
  ]) assert.equal(isPublicOriginAllowed(valid(), { ...environment, ...change }), false);
});

test("direct-origin spoofing, duplicate secrets and host manipulation cannot authenticate the public edge", () => {
  for (const change of [
    { [publicOriginHeader]: "" }, { [publicOriginHeader]: "B".repeat(43) },
    { [publicOriginHeader]: `${secret}, ${secret}` },
    { host: "deployment.vercel.app" }, { host: "limitmark.com.attacker.test" },
    { "x-forwarded-host": "limitmark.com, attacker.test" },
    { "x-forwarded-host": "www.limitmark.com" },
  ]) {
    const headers = valid();
    for (const [name, value] of Object.entries(change)) headers.set(name, value);
    assert.equal(isPublicOriginAllowed(headers, environment), false);
  }
  const spoof = new Headers({ host: "limitmark.com", "x-forwarded-host": "limitmark.com",
    "cf-connecting-ip": "203.0.113.9", "cf-ray": "synthetic", "x-vercel-forwarded-for": "203.0.113.9" });
  assert.equal(isPublicOriginAllowed(spoof, environment), false);
  const www = valid();
  www.set("host", "www.limitmark.com");
  www.set("x-forwarded-host", "www.limitmark.com");
  assert.equal(isPublicOriginAllowed(www, environment), true);
});

test("Cloudflare client identity stays unsupported even with a valid origin credential", () => {
  const headers = valid();
  headers.set("cf-connecting-ip", "203.0.113.9");
  headers.set("x-vercel-forwarded-for", "198.51.100.1");
  for (const source of ["cloudflare-via-vercel", "unknown", "vercel"]) {
    assert.equal(derivePrivateClientKey(headers, { source, hmacSecret: secret } as ClientIdentityConfiguration), null);
  }
  const complete = {
    ...environment, REQUEST_SUBMISSION_MODE: "postgres", ENABLE_PERSISTENT_SUBMISSIONS: "true",
    DATABASE_URL: "postgresql://runtime:synthetic@db.example.test/app", RATE_LIMIT_PROVIDER: "synthetic-shared",
    SUBMISSION_CLIENT_IP_SOURCE: "vercel", SUBMISSION_CLIENT_KEY_SECRET: secret,
    TURNSTILE_MODE: "enabled", TURNSTILE_SITE_KEY: "synthetic-key", TURNSTILE_SECRET_KEY: "synthetic-secret",
    TURNSTILE_EXPECTED_HOSTNAME: "limitmark.com",
  };
  for (const PUBLIC_ORIGIN_PROTECTION of ["required", "unknown", ""]) {
    assert.deepEqual(getPublicSubmissionConfiguration({ ...complete, PUBLIC_ORIGIN_PROTECTION }, ["synthetic-shared"]),
      { enabled: false, reason: "deployment-boundary" });
  }
  for (const SUBMISSION_CLIENT_IP_SOURCE of ["cloudflare-via-vercel", "unknown", ""]) {
    assert.deepEqual(getPublicSubmissionConfiguration({ ...complete, PUBLIC_ORIGIN_PROTECTION: "disabled", SUBMISSION_CLIENT_IP_SOURCE }, ["synthetic-shared"]),
      { enabled: false, reason: "deployment-boundary" });
  }
});

test("direct ingress rejects incompatible Cloudflare hints and malformed IP chains without fallback", () => {
  const identity = { source: "vercel", hmacSecret: secret } as const;
  const direct = new Headers({ "x-vercel-forwarded-for": "203.0.113.9" });
  const expected = derivePrivateClientKey(direct, identity);
  assert.match(expected!, /^[A-Za-z0-9_-]{43}$/);
  for (const name of ["x-forwarded-for", "x-real-ip", "true-client-ip", "forwarded"]) direct.set(name, "attacker-controlled, invalid");
  assert.equal(derivePrivateClientKey(direct, identity), expected);
  for (const name of ["cf-connecting-ip", "cf-connecting-ipv6", "cf-ray", publicOriginHeader]) {
    const headers = new Headers(direct);
    headers.set(name, "");
    assert.equal(derivePrivateClientKey(headers, identity), null);
  }
  for (const value of ["203.0.113.9, 198.51.100.1", "[2001:db8::1]", "203.0.113.9:443", "fe80::1%eth0", ""]) {
    direct.set("x-vercel-forwarded-for", value);
    assert.equal(derivePrivateClientKey(direct, identity), null);
  }
  direct.set("x-vercel-forwarded-for", "2001:0DB8:0:0:0:0:0:1");
  const expanded = derivePrivateClientKey(direct, identity);
  direct.set("x-vercel-forwarded-for", "2001:db8::1");
  assert.equal(derivePrivateClientKey(direct, identity), expanded);
});

test("proxy denial covers prefetch and actions; narrow exceptions preserve admin and verification", () => {
  const prior = process.env.PUBLIC_ORIGIN_PROTECTION;
  process.env.PUBLIC_ORIGIN_PROTECTION = "unknown";
  try {
    for (const path of ["/", "/test-talep-et", "/test-talep-et/tesekkurler", "/test-talep-et/fake.css", "/admin-other"]) {
      const response = proxy(new NextRequest(`https://limitmark.com${path}`, { headers: { "next-router-prefetch": "1", rsc: "1" } }));
      assert.equal(response.status, 404);
      assert.match(response.headers.get("cache-control")!, /private.*no-store/);
      assert.equal(response.headers.get("cdn-cache-control"), "no-store");
      assert.equal(response.headers.has(publicOriginHeader), false);
    }
    assert.equal(proxy(new NextRequest("https://admin.limitmark.com/_next/static/chunk.js")).headers.get("x-middleware-next"), "1");
    for (const path of ["/admin", "/admin/inquiries/123", "/.well-known/vercel/probe", "/.well-known/acme-challenge/probe"]) {
      const response = proxy(new NextRequest(`https://limitmark.com${path}`));
      assert.equal(response.headers.get("x-middleware-next"), "1");
      assert.equal(response.headers.get("cdn-cache-control"), "no-store");
    }
    for (const path of ["/test-talep-et", "/_next/static/chunk.js", "/.well-known/vercel/probe", "/.well-known/acme-challenge/probe"]) {
      assert.equal(proxy(new NextRequest(`https://limitmark.com${path}`, { method: "POST" })).status, 404);
    }
  } finally {
    if (prior === undefined) delete process.env.PUBLIC_ORIGIN_PROTECTION;
    else process.env.PUBLIC_ORIGIN_PROTECTION = prior;
  }
});
