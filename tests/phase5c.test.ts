import assert from "node:assert/strict";
import test from "node:test";
import { derivePrivateClientKey, type ClientIdentityConfiguration } from "../src/lib/client-identity";
import { isPublicOriginAllowed, publicOriginHeader } from "../src/lib/public-origin";
import { getPublicSubmissionConfiguration, getPublicIntakeState } from "../src/lib/public-submission-config";
import { availableProductionRateLimitProviders, createProductionRateLimitAdapter, type RateLimitAdapter } from "../src/lib/rate-limit";
import { enforceSubmissionAbuseControls } from "../src/lib/submission-abuse-control";
import { submitToAdapter } from "../src/lib/submission-adapter";
import { requestSchema } from "../src/lib/request-schema";
import type { TurnstileVerifier } from "../src/lib/turnstile";
import { InMemoryTestRateLimitAdapter } from "./support/in-memory-rate-limit-adapter";

const secret = "A".repeat(43);
const identity = { source: "vercel", hmacSecret: secret } as const;
const direct = (ip = "203.0.113.9") => new Headers({ "x-vercel-forwarded-for": ip });
const verified: TurnstileVerifier = { async verify() { return "verified"; } };
const rejected: TurnstileVerifier = { async verify() { return "rejected"; } };
const production = {
  VERCEL: "1", VERCEL_ENV: "production", REQUEST_SUBMISSION_MODE: "postgres",
  ENABLE_PERSISTENT_SUBMISSIONS: "true", DATABASE_URL: "postgresql://synthetic:unused@db.example.test/app",
  RATE_LIMIT_PROVIDER: "upstash", SUBMISSION_CLIENT_IP_SOURCE: "vercel",
  SUBMISSION_CLIENT_KEY_SECRET: secret, TURNSTILE_MODE: "enabled",
  TURNSTILE_SITE_KEY: "synthetic-site", TURNSTILE_SECRET_KEY: "synthetic-secret",
  TURNSTILE_EXPECTED_HOSTNAME: "limitmark.com",
  UPSTASH_REDIS_REST_URL: "https://synthetic-unused.upstash.io",
  UPSTASH_REDIS_REST_TOKEN: "synthetic-never-sent-token",
};

function attempt(rateLimiter: RateLimitAdapter, ip = "203.0.113.9", turnstile = verified) {
  return enforceSubmissionAbuseControls({
    headers: direct(ip), clientIdentity: identity, rateLimiter, turnstile,
    submissionToken: "s".repeat(43), turnstileToken: "synthetic-challenge",
  });
}

test("Phase 5C: Lite-shaped and spoofed Cloudflare inputs both remain unsupported, even with a leaked bearer", () => {
  for (const peer of ["198.51.100.1", "203.0.113.66"]) {
    for (const credential of [undefined, secret]) {
      const headers = direct(peer);
      headers.set("host", "limitmark.com");
      headers.set("x-forwarded-host", "limitmark.com");
      headers.set("cf-connecting-ip", "203.0.113.9");
      headers.set("cf-ray", "synthetic-ray");
      if (credential) headers.set(publicOriginHeader, credential);
      assert.equal(isPublicOriginAllowed(headers, {
        ...production, PUBLIC_ORIGIN_PROTECTION: "required", PUBLIC_ORIGIN_SECRET: secret,
      }), Boolean(credential));
      for (const source of ["vercel", "cloudflare-via-vercel", "cloudflare", "", "unknown"]) {
        assert.equal(derivePrivateClientKey(headers, { ...identity, source } as ClientIdentityConfiguration), null);
      }
    }
  }
});

test("Phase 5C: detectable Worker and Pseudo IPv4 hints deny direct-only identity", () => {
  for (const name of ["cf-worker", "cf-ew-via", "cf-pseudo-ipv4", "cf-connecting-o2o"]) {
    for (const value of ["", "synthetic"]) {
      const headers = direct();
      headers.set(name, value);
      assert.equal(derivePrivateClientKey(headers, identity), null);
    }
  }
});

test("Phase 5C: canonical IPv4 and equivalent IPv6/mapped forms cannot split buckets", () => {
  for (const equivalents of [
    ["203.0.113.9", "::ffff:203.0.113.9", "0:0:0:0:0:FFFF:CB00:7109", "::ffff:cb00:7109"],
    ["2001:db8::abcd:1", "2001:0DB8:0:0:0:0:ABCD:0001"],
  ]) {
    const expected = derivePrivateClientKey(direct(equivalents[0]), identity);
    assert.match(expected!, /^[A-Za-z0-9_-]{43}$/);
    for (const ip of equivalents) assert.equal(derivePrivateClientKey(direct(ip), identity), expected);
  }
  for (const value of ["203.000.113.9", "0xcb007109", "3405803785", "203.0.113", "203.0.113.9:443",
    "203.0.113.9,203.0.113.9", "::1,::2", "[::1]", "fe80::1%1", "invalid", ""]) {
    assert.equal(derivePrivateClientKey(direct(value), identity), null);
  }
});

test("Phase 5C: forwarding alternatives never supply or change the platform identity", () => {
  for (const source of ["cloudflare-via-vercel", "cloudflare", "unknown", ""]) {
    assert.equal(derivePrivateClientKey(direct(), { ...identity, source } as ClientIdentityConfiguration), null);
  }
  for (const name of ["x-forwarded-for", "x-real-ip", "true-client-ip", "forwarded"]) {
    const forged = new Headers({ [name]: "203.0.113.66" });
    assert.equal(derivePrivateClientKey(forged, identity), null);
    forged.set("x-vercel-forwarded-for", "203.0.113.9");
    assert.equal(derivePrivateClientKey(forged, identity), derivePrivateClientKey(direct(), identity));
  }
});

test("Phase 5C: no Upstash configuration, including plausible Production credentials, registers a provider", async () => {
  assert.deepEqual(availableProductionRateLimitProviders, []);
  for (const provider of ["upstash", "memory", "redis", "synthetic-shared", ""]) {
    assert.equal(createProductionRateLimitAdapter(provider), null);
  }
  const request = requestSchema.parse({ name: "Synthetic", email: "qa@example.test", service: "web",
    system: "Disposable", objective: "Admission test", environment: "staging", authority: "authorized" });
  for (const change of [
    {}, { UPSTASH_REDIS_REST_URL: undefined }, { UPSTASH_REDIS_REST_URL: "http://malformed/path" },
    { UPSTASH_REDIS_REST_TOKEN: undefined }, { VERCEL_ENV: "preview" }, { VERCEL_ENV: "development" },
    { VERCEL_ENV: undefined }, { VERCEL: undefined },
    { SUBMISSION_CLIENT_IP_SOURCE: "cloudflare-via-vercel", PUBLIC_ORIGIN_PROTECTION: "required", PUBLIC_ORIGIN_SECRET: secret },
  ]) {
    const environment = { ...production, ...change };
    assert.equal(getPublicSubmissionConfiguration(environment, availableProductionRateLimitProviders).enabled, false);
    assert.deepEqual(getPublicIntakeState(environment, availableProductionRateLimitProviders), { kind: "closed" });
    assert.deepEqual(await submitToAdapter(request, "s".repeat(43), {
      headers: direct(), turnstileToken: "synthetic",
    }, environment), { status: "unavailable" });
  }
});

test("Phase 5C: even a future provider registration cannot open unreviewed ingress", () => {
  for (const source of ["cloudflare-via-vercel", "cloudflare", "x-forwarded-for", "unknown", ""]) {
    for (const protection of ["disabled", "required"]) {
      assert.deepEqual(getPublicSubmissionConfiguration({ ...production, SUBMISSION_CLIENT_IP_SOURCE: source,
        PUBLIC_ORIGIN_PROTECTION: protection, PUBLIC_ORIGIN_SECRET: secret }, ["upstash"]),
      { enabled: false, reason: "deployment-boundary" });
    }
  }
});

test("Phase 5C: origin credentials and edge-looking bypass headers cannot skip admission", async () => {
  for (const withOrigin of [false, true]) {
    const headers = direct();
    headers.set("x-edge-enabled", "true");
    headers.set("x-skip-rate-limit", "true");
    if (withOrigin) headers.set(publicOriginHeader, secret);
    const calls: string[] = [];
    assert.equal(await enforceSubmissionAbuseControls({
      headers, clientIdentity: identity, submissionToken: "s".repeat(43), turnstileToken: "synthetic",
      rateLimiter: { async consume() { calls.push("pre"); return "unavailable"; } },
      turnstile: { async verify() { calls.push("turnstile"); return "verified"; } },
    }), "unavailable");
    assert.deepEqual(calls, withOrigin ? [] : ["pre"]);
  }
});

test("Phase 5C: invalid runtime adapter results normalize to unavailable at either stage", async () => {
  for (const stage of [1, 2]) {
    for (const result of [undefined, null, true, { allowed: true }, "timeout", "ALLOW"]) {
      let calls = 0;
      const limiter: RateLimitAdapter = { async consume() {
        calls++;
        return calls === stage ? result as never : "allowed";
      } };
      assert.equal(await attempt(limiter), "unavailable");
      assert.equal(calls, stage);
    }
  }
});

test("Phase 5C: a consumed attempt with lost response is not retried by admission", async () => {
  for (const stage of [1, 2]) {
    const model = new InMemoryTestRateLimitAdapter(() => 0);
    let calls = 0;
    let verifications = 0;
    const limiter: RateLimitAdapter = { async consume(rules) {
      calls++;
      assert.equal(await model.consume(rules), "allowed");
      if (calls === stage) throw new Error("synthetic lost response after consumption");
      return "allowed";
    } };
    assert.equal(await attempt(limiter, "203.0.113.9", { async verify() {
      verifications++; return "verified";
    } }), "unavailable");
    assert.equal(calls, stage);
    assert.equal(verifications, stage - 1);
  }
});

test("Phase 5C: rejected or unavailable verification never calls the post limiter", async () => {
  for (const outcome of ["rejected", "unavailable", "throw"] as const) {
    const stages: string[] = [];
    const limiter: RateLimitAdapter = { async consume(rules) {
      stages.push(rules[0].key.includes(":pre:") ? "pre" : "post");
      assert.equal(rules.length, 2);
      return "allowed";
    } };
    assert.equal(await attempt(limiter, "203.0.113.9", { async verify() {
      if (outcome === "throw") throw new Error("synthetic timeout");
      return outcome;
    } }), outcome === "rejected" ? "rejected" : "unavailable");
    assert.deepEqual(stages, ["pre"]);
  }
});

// These tests exercise only the existing deterministic contract model. They do
// not execute Redis and do not establish Upstash consistency, TTL or atomicity.
test("Phase 5C model: global denial consumes no client quota and client denial consumes no global quota", async () => {
  for (const deny of ["client", "global"]) {
    const limiter = new InMemoryTestRateLimitAdapter(() => 0);
    const client = { key: "model:client", limit: 1, windowMs: 1_000 };
    const global = { key: "model:global", limit: 1, windowMs: 1_000 };
    assert.equal(await limiter.consume([deny === "client" ? client : global]), "allowed");
    assert.equal(await limiter.consume([client, global]), "limited");
    assert.equal(await limiter.consume([deny === "client" ? global : client]), "allowed");
  }
});

test("Phase 5C model: concurrent callers share the global bound", async () => {
  const limiter = new InMemoryTestRateLimitAdapter(() => 0);
  const results = await Promise.all(Array.from({ length: 100 }, (_, index) => limiter.consume([
    { key: `model:client:${index}`, limit: 1, windowMs: 1_000 },
    { key: "model:global", limit: 7, windowMs: 1_000 },
  ])));
  assert.equal(results.filter((value) => value === "allowed").length, 7);
  assert.equal(results.filter((value) => value === "limited").length, 93);
});

test("Phase 5C model: exact lower rolling boundary expires and denials do not postpone recovery", async () => {
  let now = 999;
  const limiter = new InMemoryTestRateLimitAdapter(() => now);
  const rules = [{ key: "model:boundary", limit: 1, windowMs: 1_000 }];
  assert.equal(await limiter.consume(rules), "allowed");
  for (now of [1_000, 1_500, 1_998]) assert.equal(await limiter.consume(rules), "limited");
  now = 1_999;
  assert.equal(await limiter.consume(rules), "allowed");
});

test("Phase 5C model: ten rejecting clients starve new verification for 60 seconds, not the strict budget", async () => {
  let now = 0;
  const limiter = new InMemoryTestRateLimitAdapter(() => now);
  for (let client = 1; client <= 10; client++) {
    for (let count = 0; count < 30; count++) {
      assert.equal(await attempt(limiter, `198.51.100.${client}`, rejected), "rejected");
    }
  }
  let verifications = 0;
  const verifier: TurnstileVerifier = { async verify() { verifications++; return "verified"; } };
  for (now of [0, 59_999]) assert.equal(await attempt(limiter, "203.0.113.9", verifier), "limited");
  assert.equal(verifications, 0);
  now = 60_000;
  for (let count = 0; count < 5; count++) assert.equal(await attempt(limiter, "203.0.113.9", verifier), "allowed");
  assert.equal(await attempt(limiter, "203.0.113.9", verifier), "limited");
  assert.equal(await attempt(limiter, "198.51.100.1", rejected), "limited");
  now = 600_000;
  assert.equal(await attempt(limiter, "198.51.100.1", rejected), "rejected");
});

test("Phase 5C model: a request already admitted to Turnstile can finish during pre-global saturation", async () => {
  const limiter = new InMemoryTestRateLimitAdapter(() => 0);
  let release!: (value: "verified") => void;
  const challenge = new Promise<"verified">((resolve) => { release = resolve; });
  let started!: () => void;
  const ready = new Promise<void>((resolve) => { started = resolve; });
  const pending = attempt(limiter, "203.0.113.9", { verify() { started(); return challenge; } });
  await ready;
  try {
    for (let index = 0; index < 299; index++) {
      assert.equal(await attempt(limiter, `198.51.100.${1 + Math.floor(index / 30)}`, rejected), "rejected");
    }
    assert.equal(await attempt(limiter, "203.0.113.10"), "limited");
  } finally {
    release("verified");
  }
  assert.equal(await pending, "allowed");
});
