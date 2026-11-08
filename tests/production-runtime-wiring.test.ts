import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createProductionRuntimeDependencies, type ProductionRuntimeEnvironment } from "../src/lib/public-inquiry-production-runtime.server";
import { createLaboratoryRuntimeDependencies } from "../src/lib/public-inquiry-runtime.server";
import { handlePublicInquiry } from "../src/lib/public-inquiry-handler.server";
import { availableProductionRateLimitProviders } from "../src/lib/rate-limit";
import { getPublicIntakeState, getPublicSubmissionConfiguration } from "../src/lib/public-submission-config";
import {
  createIngressEnvelope, encodeBase64url, INGRESS_BODY_ENCODING, INGRESS_ENVIRONMENT, INGRESS_HEADER, INGRESS_IDENTITY_VERSION,
  INGRESS_MUTATION_CONTENT_TYPE, INGRESS_MUTATION_PATH, INGRESS_VERSION, sha256Base64url, type IngressPayload,
} from "../src/lib/ingress-protocol";
import type { ProductionOidcTokenProvider } from "../src/lib/admission-client.server";

// Production runtime wiring. The shipped launch registry (availableProductionRateLimitProviders) is EMPTY on purpose and stays empty here:
// the enabled path is exercised only by injecting a provider list into the factory, which the route never does.

const secret = (fill: number) => encodeBase64url(new Uint8Array(32).fill(fill));
const publicKeyBytes = new Uint8Array(32).fill(0x42);

async function validEnvironment(): Promise<ProductionRuntimeEnvironment> {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  void publicKeyBytes;
  return {
    NODE_ENV: "production", VERCEL: "1", VERCEL_ENV: "production", VERCEL_PROJECT_ID: "prj_limitmark", VERCEL_DEPLOYMENT_ID: "dpl_reviewed",
    REQUEST_SUBMISSION_MODE: "postgres", ENABLE_PERSISTENT_SUBMISSIONS: "true", DATABASE_URL: "postgresql://synthetic:unused@db.example.test/app?sslmode=verify-full",
    RATE_LIMIT_PROVIDER: "cloudflare-do", PUBLIC_ORIGIN_PROTECTION: "required", PUBLIC_ORIGIN_SECRET: secret(1),
    INGRESS_PROTOCOL: INGRESS_VERSION, INGRESS_AUDIENCE: "prj_limitmark",
    INGRESS_PUBLIC_KEYS: JSON.stringify([{ role: "current", keyId: "current", publicKey: encodeBase64url(raw), activatesAtMs: 0 }]),
    INGRESS_REQUEST_BINDING_KEY: secret(2), SUBMISSION_TOKEN_SECRET: secret(3),
    ADMISSION_SERVICE_URL: "https://admission-rpc.limitmark.test", ADMISSION_OIDC_AUDIENCE: "https://admission-rpc.limitmark.test",
    ADMISSION_RELEASE_ID: "dpl_reviewed", ADMISSION_RELEASE_KEY_ID: "release-current", ADMISSION_RELEASE_RPC_KEY: secret(4),
    TURNSTILE_MODE: "enabled", TURNSTILE_SITE_KEY: "0x4AAAAAAAsynthetic-site", TURNSTILE_SECRET_KEY: "0x4AAAAAAAsynthetic-secret-value", TURNSTILE_EXPECTED_HOSTNAME: "limitmark.com",
  };
}
const providers = ["cloudflare-do"] as const;
const oidc: ProductionOidcTokenProvider = { async getToken() { return "unused.token.value"; } };

test("the launch registry stays empty and the production factory is disabled for an otherwise complete production environment", async () => {
  assert.deepEqual(availableProductionRateLimitProviders, []);
  const environment = await validEnvironment();
  assert.deepEqual(await createProductionRuntimeDependencies(environment), { enabled: false, reason: "configuration" });
  assert.equal(getPublicSubmissionConfiguration(environment, availableProductionRateLimitProviders).enabled, false);
  assert.deepEqual(getPublicIntakeState(environment, availableProductionRateLimitProviders), { kind: "closed" });
});

test("with an injected provider registry a complete production environment builds Vercel-identity dependencies", async () => {
  const environment = await validEnvironment();
  assert.equal(getPublicSubmissionConfiguration(environment, providers).enabled, true, "fixture must be a valid production configuration");
  const result = await createProductionRuntimeDependencies(environment, { providers, oidc });
  assert.equal(result.enabled, true);
  if (!result.enabled) return;
  const { dependencies } = result;
  assert.ok(dependencies.admission && dependencies.turnstile && dependencies.repository && dependencies.ingressPolicy);
  assert.equal(dependencies.ingressPolicy!.environment, "production");
  assert.equal(dependencies.ingressPolicy!.audience, "prj_limitmark");
  assert.equal(dependencies.ingressPolicy!.deploymentId, "dpl_reviewed");
});

test("every missing or invalid production input disables the factory (fail closed), one input at a time", async () => {
  const base = await validEnvironment();
  const mutations: Array<Record<string, string | undefined>> = [
    { ENABLE_PERSISTENT_SUBMISSIONS: undefined }, { REQUEST_SUBMISSION_MODE: "demo" }, { DATABASE_URL: undefined }, { RATE_LIMIT_PROVIDER: "memory" },
    { VERCEL: undefined }, { VERCEL_ENV: "preview" }, { VERCEL_ENV: "development" }, { PUBLIC_ORIGIN_PROTECTION: "disabled" },
    { PUBLIC_ORIGIN_SECRET: "short" }, { INGRESS_PUBLIC_KEYS: undefined }, { INGRESS_PUBLIC_KEYS: "[]" }, { INGRESS_REQUEST_BINDING_KEY: undefined },
    { INGRESS_AUDIENCE: "other" }, { ADMISSION_SERVICE_URL: undefined }, { ADMISSION_SERVICE_URL: "http://admission.test" }, { ADMISSION_SERVICE_URL: "https://admission.test/path" },
    { ADMISSION_OIDC_AUDIENCE: undefined }, { ADMISSION_RELEASE_ID: "dpl_other" }, { ADMISSION_RELEASE_KEY_ID: undefined }, { ADMISSION_RELEASE_RPC_KEY: undefined },
    { TURNSTILE_MODE: "disabled" }, { TURNSTILE_SITE_KEY: "1x00000000000000000000AA" }, { TURNSTILE_SECRET_KEY: "1x0000000000000000000000000000000AA" }, { TURNSTILE_EXPECTED_HOSTNAME: undefined },
    { ADMISSION_CURRENT_RPC_KEY: secret(9) }, { TEST_DATABASE_URL: "postgresql://t@x/y" }, { DATABASE_MIGRATION_URL: "postgresql://m@x/y" },
    { ADMISSION_RELEASE_RPC_KEY: secret(1) }, // collides with PUBLIC_ORIGIN_SECRET
  ];
  for (const change of mutations) {
    const result = await createProductionRuntimeDependencies({ ...base, ...change }, { providers, oidc });
    assert.equal(result.enabled, false, JSON.stringify(Object.keys(change)));
  }
});

test("production/lab identity isolation in the app: any laboratory, Google or runtime-selector setting disables the production factory", async () => {
  const base = await validEnvironment();
  for (const change of [
    { LIMITMARK_RUNTIME: "cloud-run-lab" }, { LIMITMARK_RUNTIME: "production" }, { LAB_ADMISSION_SERVICE_URL: "https://lab-admission.limitmark.test" },
    { LAB_DATABASE_URL: "postgresql://lab@10.0.0.1/db" }, { GOOGLE_OIDC_AUDIENCE: "https://x" }, { GOOGLE_SERVICE_ACCOUNT_EMAIL: "sa@x.iam.gserviceaccount.com" },
    { ADMISSION_IDENTITY_MODE: "google-lab" }, { ADMISSION_IDENTITY_MODE: "vercel" },
  ]) {
    assert.deepEqual(await createProductionRuntimeDependencies({ ...base, ...change }, { providers, oidc }), { enabled: false, reason: "runtime" }, JSON.stringify(change));
  }
  // and the reverse: the laboratory factory rejects every production credential and the Vercel runtime markers
  const lab = { LIMITMARK_RUNTIME: "cloud-run-lab", REQUEST_SUBMISSION_MODE: "postgres", ENABLE_PERSISTENT_SUBMISSIONS: "true" };
  assert.equal((await createLaboratoryRuntimeDependencies({ ...lab, ADMISSION_RELEASE_RPC_KEY: secret(4) })).enabled, false);
  assert.equal((await createLaboratoryRuntimeDependencies({ ...lab, VERCEL: "1", VERCEL_ENV: "production" })).enabled, false);
});

test("the production factory contains no laboratory, Google, demo or development fallback (source guard)", async () => {
  const withComments = await readFile(new URL("../src/lib/public-inquiry-production-runtime.server.ts", import.meta.url), "utf8");
  const source = withComments.replace(/\/\*[\s\S]*?\*\//gu, "").replace(/^\s*\/\/.*$/gmu, "");
  assert.doesNotMatch(source, /GoogleMetadataOidcTokenProvider|createLaboratory|LAB_RUNTIME|demo|NODE_ENV|VERCEL_OIDC_TOKEN\b/);
  assert.match(source, /VercelRequestOidcTokenProvider/);
  const route = await readFile(new URL("../src/app/api/public-inquiries/route.ts", import.meta.url), "utf8");
  assert.match(route, /createProductionRuntimeDependencies\(process\.env\)/);
  assert.match(route, /production\.enabled \? production\.dependencies : \{ environment: process\.env \}/);
  assert.doesNotMatch(route, /availableProductionRateLimitProviders|providers:/);
});

test("route behavior: disabled production keeps the generic 503; the enabled production path keeps PRE -> Turnstile -> POST -> DB order", async () => {
  const environment = await validEnvironment();
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const keyed = { ...environment, INGRESS_PUBLIC_KEYS: JSON.stringify([{ role: "current", keyId: "current", publicKey: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))), activatesAtMs: 0 }]) };
  const token = "s".repeat(43);
  const bodyText = new URLSearchParams({ name: "Synthetic", email: "qa@example.test", service: "web", system: "Disposable", objective: "Review boundary",
    environment: "staging", authority: "authorized", protection: "unknown", provider: "", notes: "", submissionToken: token, "cf-turnstile-response": "synthetic-challenge" }).toString();
  const body = new TextEncoder().encode(bodyText);
  const payload: IngressPayload = [INGRESS_VERSION, "current", INGRESS_ENVIRONMENT, "prj_limitmark", "dpl_reviewed", Date.now(),
    "POST", "https", "limitmark.com", INGRESS_MUTATION_PATH, "", INGRESS_MUTATION_CONTENT_TYPE, INGRESS_BODY_ENCODING, body.length,
    await sha256Base64url(body), INGRESS_IDENTITY_VERSION, encodeBase64url(new Uint8Array(32).fill(1)), encodeBase64url(new Uint8Array(16).fill(2))];
  const envelope = await createIngressEnvelope(payload, pair.privateKey);
  const headers = { origin: "https://limitmark.com", host: "limitmark.com", "x-forwarded-host": "limitmark.com", "x-limitmark-origin-secret": secret(1),
    "content-type": INGRESS_MUTATION_CONTENT_TYPE, "content-encoding": INGRESS_BODY_ENCODING, [INGRESS_HEADER]: envelope };
  const post = () => new Request("https://limitmark.com/api/public-inquiries", { method: "POST", body: bodyText, headers });

  // Route logic as written: disabled factory -> environment-only handler call -> 503 in persistent mode, no side effects.
  const disabled = await createProductionRuntimeDependencies(keyed);
  assert.equal(disabled.enabled, false);
  const closed = await handlePublicInquiry(post(), { environment: keyed });
  assert.equal(closed.status, 503);

  // Enabled path with the real factory output, recording the order through a transport that plays the Worker and Turnstile.
  const calls: string[] = [];
  const transport: typeof fetch = async (input) => {
    const url = new URL(String(input));
    if (url.hostname === "challenges.cloudflare.com") { calls.push("turnstile"); return Response.json({ success: true, hostname: "limitmark.com", action: "public-inquiry" }); }
    calls.push(url.pathname === "/v1/pre" ? "pre" : "post");
    return url.pathname === "/v1/pre" ? Response.json({ decision: "allowed", permit: encodeBase64url(new Uint8Array(32).fill(5)), expiresAtMs: Date.now() + 60_000 }) : Response.json({ decision: "allowed" });
  };
  const enabled = await createProductionRuntimeDependencies(keyed, { providers, oidc, request: transport });
  assert.equal(enabled.enabled, true);
  if (!enabled.enabled) return;
  const dependencies = { ...enabled.dependencies, repository: { async create() { calls.push("db"); return { status: "created" as const }; } } };
  const response = await handlePublicInquiry(post(), dependencies);
  const result = await response.json();
  assert.deepEqual(result, { kind: "redirect", location: "/test-talep-et/tesekkurler" });
  assert.deepEqual(calls, ["pre", "turnstile", "post", "db"]);
});
