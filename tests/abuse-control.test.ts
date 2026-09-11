import assert from "node:assert/strict";
import test from "node:test";
import { derivePrivateClientKey } from "../src/lib/client-identity";
import { getPublicSubmissionConfiguration, getTurnstileClientConfiguration } from "../src/lib/public-submission-config";
import { enforceSubmissionAbuseControls } from "../src/lib/submission-abuse-control";
import {
  CloudflareTurnstileVerifier,
  createTurnstileIdempotencyKey,
  readTurnstileToken,
  turnstileResponseField,
  type TurnstileVerifier,
} from "../src/lib/turnstile";
import { InMemoryTestRateLimitAdapter } from "./support/in-memory-rate-limit-adapter";
import { createPayloadFingerprint } from "../src/lib/payload-fingerprint";
import { readRequestFormData, requestSchema } from "../src/lib/request-schema";

const secret = "A".repeat(43);
const identity = { source: "vercel", hmacSecret: secret } as const;
const token = "s".repeat(43);
const verified: TurnstileVerifier = { async verify() { return "verified"; } };
const headers = (ip: string, extras: Record<string, string> = {}) => new Headers({ "x-vercel-forwarded-for": ip, ...extras });
const limits = { client: { limit: 2, windowMs: 1_000 }, globalBurst: { limit: 3, windowMs: 1_000 } };

function protect(rateLimiter: InMemoryTestRateLimitAdapter, ip: string, verifier = verified) {
  return enforceSubmissionAbuseControls({
    headers: headers(ip), clientIdentity: identity, submissionToken: token,
    turnstileToken: "synthetic-turnstile-token", rateLimiter, turnstile: verifier, limits,
  });
}

test("per-client thresholds are bounded and reset at the next window", async () => {
  let now = 0;
  const limiter = new InMemoryTestRateLimitAdapter(() => now);
  assert.equal(await protect(limiter, "203.0.113.10"), "allowed");
  assert.equal(await protect(limiter, "203.0.113.10"), "allowed");
  assert.equal(await protect(limiter, "203.0.113.10"), "limited");
  now = 1_000;
  assert.equal(await protect(limiter, "203.0.113.10"), "allowed");
});

test("independent clients have separate limits while sharing a global burst bound", async () => {
  const limiter = new InMemoryTestRateLimitAdapter(() => 0);
  assert.equal(await protect(limiter, "203.0.113.1"), "allowed");
  assert.equal(await protect(limiter, "203.0.113.2"), "allowed");
  assert.equal(await protect(limiter, "203.0.113.3"), "allowed");
  assert.equal(await protect(limiter, "203.0.113.4"), "limited");
});

test("the global rolling window does not reopen at a fixed-window boundary", async () => {
  let now = 999;
  const limiter = new InMemoryTestRateLimitAdapter(() => now);
  for (const suffix of [1, 2, 3]) assert.equal(await protect(limiter, `198.51.100.${suffix}`), "allowed");
  now = 1_000;
  assert.equal(await protect(limiter, "198.51.100.4"), "limited");
  now = 1_999;
  assert.equal(await protect(limiter, "198.51.100.4"), "allowed");
});

test("client keys are deterministic keyed hashes and never contain the address", () => {
  const first = derivePrivateClientKey(headers("2001:db8::1"), identity);
  const same = derivePrivateClientKey(headers("2001:db8::1"), identity);
  const otherIp = derivePrivateClientKey(headers("2001:db8::2"), identity);
  const otherSecret = derivePrivateClientKey(headers("2001:db8::1"), { ...identity, hmacSecret: "B".repeat(43) });
  assert.match(first!, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(first, same);
  assert.notEqual(first, otherIp);
  assert.notEqual(first, otherSecret);
  assert.equal(first!.includes("2001"), false);
});

test("arbitrary forwarding headers are ignored and malformed platform values fail closed", () => {
  for (const forged of [
    new Headers({ "x-forwarded-for": "203.0.113.8" }),
    new Headers({ "x-real-ip": "203.0.113.8" }),
    new Headers({ "cf-connecting-ip": "203.0.113.8" }),
    headers("203.0.113.8, 198.51.100.2"),
    headers("not-an-ip"),
  ]) assert.equal(derivePrivateClientKey(forged, identity), null);
});

test("limiter backend failure and missing identity fail closed before Turnstile", async () => {
  let verifications = 0;
  const verifier: TurnstileVerifier = { async verify() { verifications++; return "verified"; } };
  const limiter = new InMemoryTestRateLimitAdapter();
  limiter.unavailable = true;
  assert.equal(await protect(limiter, "203.0.113.9", verifier), "unavailable");
  assert.equal(await enforceSubmissionAbuseControls({
    headers: new Headers({ "x-forwarded-for": "203.0.113.9" }), clientIdentity: identity,
    submissionToken: token, turnstileToken: "token", rateLimiter: limiter, turnstile: verifier, limits,
  }), "unavailable");
  assert.equal(verifications, 0);
  const throwingLimiter = { async consume(): Promise<never> { throw new Error("synthetic outage"); } };
  assert.equal(await enforceSubmissionAbuseControls({
    headers: headers("203.0.113.9"), clientIdentity: identity, submissionToken: token,
    turnstileToken: "token", rateLimiter: throwingLimiter, turnstile: verifier, limits,
  }), "unavailable");
  assert.equal(verifications, 0);
});

test("Turnstile rejection and outage remain neutral abuse-control failures", async () => {
  for (const [decision, expected] of [["rejected", "rejected"], ["unavailable", "unavailable"]] as const) {
    const verifier: TurnstileVerifier = { async verify() { return decision; } };
    assert.equal(await protect(new InMemoryTestRateLimitAdapter(), "203.0.113.9", verifier), expected);
  }
  const throwingVerifier: TurnstileVerifier = { async verify() { throw new Error("synthetic outage"); } };
  assert.equal(await protect(new InMemoryTestRateLimitAdapter(), "203.0.113.9", throwingVerifier), "unavailable");
});

test("valid replay and same-token conflict semantics survive the abuse boundary", async () => {
  const limiter = new InMemoryTestRateLimitAdapter();
  const replayLimits = { client: { limit: 5, windowMs: 60_000 }, globalBurst: { limit: 10, windowMs: 60_000 } };
  const stored = new Map<string, string>();
  const request = requestSchema.parse({
    name: "Synthetic", email: "qa@example.test", service: "web", system: "Staging",
    objective: "Measure resilience", environment: "staging", authority: "authorized",
  });
  async function submit(objective: string) {
    const changed = { ...request, objective };
    const decision = await enforceSubmissionAbuseControls({
      headers: headers("203.0.113.20"), clientIdentity: identity, submissionToken: token,
      turnstileToken: "synthetic-turnstile-token", rateLimiter: limiter, turnstile: verified, limits: replayLimits,
    });
    assert.equal(decision, "allowed");
    const fingerprint = createPayloadFingerprint(changed);
    const existing = stored.get(token);
    if (!existing) { stored.set(token, fingerprint); return "persisted"; }
    return existing === fingerprint ? "idempotent" : "idempotency-conflict";
  }
  assert.equal(await submit(request.objective), "persisted");
  assert.equal(await submit(request.objective), "idempotent");
  assert.equal(await submit("Different payload"), "idempotency-conflict");
});

test("malformed and oversized fields do no limiter or Turnstile work; correction can submit", async () => {
  let turnstileCalls = 0;
  const verifier: TurnstileVerifier = { async verify() { turnstileCalls++; return "verified"; } };
  const limiter = new InMemoryTestRateLimitAdapter();
  const form = new FormData();
  for (const [field, value] of Object.entries({
    name: "Synthetic", email: "not-an-email", service: "web", system: "x".repeat(1001),
    objective: "Measure resilience", environment: "staging", authority: "authorized",
  })) form.set(field, value);
  assert.equal(requestSchema.safeParse(readRequestFormData(form)).success, false);
  assert.equal(turnstileCalls, 0);

  form.set("email", "qa@example.test");
  form.set("system", "Staging");
  const corrected = requestSchema.safeParse(readRequestFormData(form));
  assert.equal(corrected.success, true);
  assert.equal(await protect(limiter, "203.0.113.21", verifier), "allowed");
  assert.equal(turnstileCalls, 1);
});

test("Turnstile Siteverify checks action and hostname, omits raw IP, and handles failures", async () => {
  let body = "";
  const successFetch: typeof fetch = async (_input, init) => {
    body = String(init?.body);
    return Response.json({ success: true, hostname: "www.example.test", action: "public-inquiry" });
  };
  const configuration = { secretKey: "synthetic-secret", expectedHostname: "www.example.test", expectedAction: "public-inquiry", timeoutMs: 10 } as const;
  assert.equal(await new CloudflareTurnstileVerifier(configuration, successFetch).verify("response", crypto.randomUUID()), "verified");
  assert.equal(new URLSearchParams(body).has("remoteip"), false);
  const rejectedFetch: typeof fetch = async () => Response.json({ success: false, hostname: "www.example.test", action: "public-inquiry" });
  assert.equal(await new CloudflareTurnstileVerifier(configuration, rejectedFetch).verify("response", crypto.randomUUID()), "rejected");
  const timeoutFetch: typeof fetch = async () => { throw new DOMException("timed out", "AbortError"); };
  assert.equal(await new CloudflareTurnstileVerifier(configuration, timeoutFetch).verify("response", crypto.randomUUID()), "unavailable");
  const outageFetch: typeof fetch = async () => new Response(null, { status: 503 });
  assert.equal(await new CloudflareTurnstileVerifier(configuration, outageFetch).verify("response", crypto.randomUUID()), "unavailable");
});

test("Turnstile token parsing is singular and bounded, and retry keys are stable without exposing tokens", () => {
  const form = new FormData();
  form.set(turnstileResponseField, "x".repeat(2048));
  assert.equal(readTurnstileToken(form), "x".repeat(2048));
  form.set(turnstileResponseField, "x".repeat(2049));
  assert.equal(readTurnstileToken(form), null);
  form.set(turnstileResponseField, "valid");
  form.append(turnstileResponseField, "duplicate");
  assert.equal(readTurnstileToken(form), null);
  const turnstileToken = "turnstile-response-a";
  const key = createTurnstileIdempotencyKey(token, turnstileToken);
  const sameResponseKey = createTurnstileIdempotencyKey(token, turnstileToken);
  const newResponseKey = createTurnstileIdempotencyKey(token, "turnstile-response-b");
  assert.match(key, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(sameResponseKey, key);
  assert.notEqual(newResponseKey, key);
  assert.equal(key.includes(token), false);
  assert.equal(key.includes(turnstileToken), false);
});

test("public persistence cannot enable without every abuse-control gate", () => {
  const complete = {
    REQUEST_SUBMISSION_MODE: "postgres", ENABLE_PERSISTENT_SUBMISSIONS: "true",
    DATABASE_URL: "postgresql://runtime:synthetic@db.example.test/app",
    VERCEL: "1", VERCEL_ENV: "production", RATE_LIMIT_PROVIDER: "synthetic-shared", SUBMISSION_CLIENT_IP_SOURCE: "vercel",
    SUBMISSION_CLIENT_KEY_SECRET: secret, TURNSTILE_MODE: "enabled",
    TURNSTILE_SITE_KEY: "real-looking-site-key", TURNSTILE_SECRET_KEY: "real-looking-secret-key",
    TURNSTILE_EXPECTED_HOSTNAME: "www.example.test",
  };
  assert.deepEqual(getPublicSubmissionConfiguration(complete, []), { enabled: false, reason: "rate-limit-provider" });
  const cases = [
    ["ENABLE_PERSISTENT_SUBMISSIONS", "false", "persistence"],
    ["VERCEL", "0", "deployment-boundary"],
    ["VERCEL_ENV", "preview", "deployment-boundary"],
    ["VERCEL_ENV", "development", "deployment-boundary"],
    ["VERCEL_ENV", undefined, "deployment-boundary"],
    ["SUBMISSION_CLIENT_IP_SOURCE", "x-forwarded-for", "deployment-boundary"],
    ["SUBMISSION_CLIENT_KEY_SECRET", "short", "client-key-secret"],
    ["TURNSTILE_MODE", "disabled", "turnstile"],
    ["TURNSTILE_SECRET_KEY", "", "turnstile"],
    ["TURNSTILE_EXPECTED_HOSTNAME", "https://www.example.test", "turnstile"],
  ] as const;
  for (const [field, value, reason] of cases) {
    assert.deepEqual(getPublicSubmissionConfiguration({ ...complete, [field]: value }, ["synthetic-shared"]), { enabled: false, reason });
  }
  assert.equal(getPublicSubmissionConfiguration(complete, ["synthetic-shared"]).enabled, true);
  assert.equal(getTurnstileClientConfiguration(complete, []), null);
});

test("every documented Cloudflare testing key is denied by the production gate", () => {
  const complete = {
    REQUEST_SUBMISSION_MODE: "postgres", ENABLE_PERSISTENT_SUBMISSIONS: "true",
    DATABASE_URL: "postgresql://runtime:synthetic@db.example.test/app",
    VERCEL: "1", VERCEL_ENV: "production", RATE_LIMIT_PROVIDER: "synthetic-shared",
    SUBMISSION_CLIENT_IP_SOURCE: "vercel", SUBMISSION_CLIENT_KEY_SECRET: secret,
    TURNSTILE_MODE: "enabled", TURNSTILE_SITE_KEY: "real-looking-site-key",
    TURNSTILE_SECRET_KEY: "real-looking-secret-key", TURNSTILE_EXPECTED_HOSTNAME: "www.example.test",
  };
  const documentedSiteKeys = [
    "1x00000000000000000000AA",
    "2x00000000000000000000AB",
    "1x00000000000000000000BB",
    "2x00000000000000000000BB",
    "3x00000000000000000000FF",
  ];
  const documentedSecretKeys = [
    "1x0000000000000000000000000000000AA",
    "2x0000000000000000000000000000000AA",
    "3x0000000000000000000000000000000AA",
  ];
  for (const TURNSTILE_SITE_KEY of documentedSiteKeys) {
    assert.deepEqual(
      getPublicSubmissionConfiguration({ ...complete, TURNSTILE_SITE_KEY }, ["synthetic-shared"]),
      { enabled: false, reason: "turnstile" },
    );
  }
  for (const TURNSTILE_SECRET_KEY of documentedSecretKeys) {
    assert.deepEqual(
      getPublicSubmissionConfiguration({ ...complete, TURNSTILE_SECRET_KEY }, ["synthetic-shared"]),
      { enabled: false, reason: "turnstile" },
    );
  }
  assert.equal(getPublicSubmissionConfiguration(complete, ["synthetic-shared"]).enabled, true);
});
