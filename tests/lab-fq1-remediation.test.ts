import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { rootCertificates } from "node:tls";
import test from "node:test";
import { NextRequest } from "next/server";
import { proxy } from "../src/proxy";
import { isPublicOriginAllowed, publicOriginHeader, resolveOriginProtectionEnvironment } from "../src/lib/public-origin";
import { getLaboratoryIntakeState, isLaboratoryRuntimeConfigurationValid, createLaboratoryRuntimeDependencies } from "../src/lib/public-inquiry-runtime.server";
import { getPublicIntakeState } from "../src/lib/public-submission-config";
import { handlePublicInquiry } from "../src/lib/public-inquiry-handler.server";
import { INGRESS_MUTATION_CONTENT_TYPE } from "../src/lib/ingress-protocol";

// FQ1 remediation regression tests: laboratory intake page, laboratory origin-protection resolution, and the browser Origin comparison.
// All values are synthetic. The CA is a public root certificate from the Node trust store (any CA certificate satisfies the shape check).

const secret = "A".repeat(43);
const b64 = (byte: number) => Buffer.alloc(32, byte).toString("base64url");
const PUBLIC_HOST = "lab.example.test";
const ORIGIN_HOST = "origin-lab.example.run.app";
const labEnvironment: Record<string, string | undefined> = {
  LIMITMARK_RUNTIME: "cloud-run-lab",
  REQUEST_SUBMISSION_MODE: "postgres",
  ENABLE_PERSISTENT_SUBMISSIONS: "true",
  PUBLIC_ORIGIN_PROTECTION: "required",
  LAB_PUBLIC_HOSTNAME: PUBLIC_HOST,
  LAB_ORIGIN_HOSTNAME: ORIGIN_HOST,
  LAB_PUBLIC_ORIGIN_SECRET: secret,
  LAB_DATABASE_URL: "postgresql://lab:pw@10.0.0.6:5432/limitmark_lab",
  LAB_DATABASE_CA_CERT: rootCertificates[0],
  LAB_DATABASE_POOL_MAX: "5",
  LAB_INGRESS_AUDIENCE: "lab-aud",
  LAB_DEPLOYMENT_ID: "lab-deployment-1",
  LAB_INGRESS_PUBLIC_KEYS: "[]",
  LAB_INGRESS_REQUEST_BINDING_KEY: b64(2),
  LAB_ADMISSION_SERVICE_URL: "https://lab-admission.example.test/",
  LAB_ADMISSION_OIDC_AUDIENCE: "https://lab-admission.example.test",
  LAB_ADMISSION_RELEASE_ID: "lab-deployment-1",
  LAB_ADMISSION_RELEASE_KEY_ID: "lab-release-key-1",
  LAB_ADMISSION_RELEASE_RPC_KEY: b64(3),
  LAB_TURNSTILE_SITE_KEY: "0x4AAAAAAAlabsitekey000",
  LAB_TURNSTILE_SECRET_KEY: "0x4AAAAAAAlabsecretkey0000000000000",
  LAB_TURNSTILE_EXPECTED_HOSTNAME: PUBLIC_HOST,
};

test("lab intake is enabled only for a valid laboratory configuration and uses the laboratory Turnstile site key", () => {
  assert.equal(isLaboratoryRuntimeConfigurationValid(labEnvironment), true);
  const intake = getLaboratoryIntakeState(labEnvironment);
  assert.equal(intake.kind, "real");
  assert.equal(intake.kind === "real" && intake.turnstile.siteKey, labEnvironment.LAB_TURNSTILE_SITE_KEY);
});

test("lab intake fails closed on missing, invalid, inconsistent or production-scoped configuration", () => {
  const mutations: Array<Record<string, string | undefined>> = [
    { LAB_TURNSTILE_SITE_KEY: undefined }, { LAB_TURNSTILE_SECRET_KEY: undefined },
    { LAB_TURNSTILE_SITE_KEY: "1x00000000000000000000AA" },            // Cloudflare published test key
    { LAB_TURNSTILE_SECRET_KEY: "1x0000000000000000000000000000000AA" },
    { LAB_TURNSTILE_EXPECTED_HOSTNAME: undefined }, { LAB_PUBLIC_HOSTNAME: "limitmark.com" },
    { LAB_PUBLIC_ORIGIN_SECRET: undefined }, { LAB_PUBLIC_ORIGIN_SECRET: "short" },
    { LAB_DATABASE_URL: undefined }, { LAB_DATABASE_CA_CERT: undefined },
    { LAB_ADMISSION_RELEASE_ID: "different-release" },                   // must equal LAB_DEPLOYMENT_ID
    { PUBLIC_ORIGIN_PROTECTION: "disabled" }, { REQUEST_SUBMISSION_MODE: "demo" },
    { LIMITMARK_RUNTIME: undefined }, { LIMITMARK_RUNTIME: "production" },
    // production credentials must be rejected in the laboratory runtime, including the raw PUBLIC_ORIGIN_SECRET
    { DATABASE_URL: "postgresql://prod.example/app" }, { PUBLIC_ORIGIN_SECRET: secret }, { TURNSTILE_SECRET_KEY: "x" },
    { VERCEL: "1" }, { VERCEL_ENV: "production" },
  ];
  for (const mutation of mutations) {
    const environment = { ...labEnvironment, ...mutation };
    assert.deepEqual(getLaboratoryIntakeState(environment), { kind: "closed" }, JSON.stringify(Object.keys(mutation)));
  }
});

test("the API runtime and the page share one configuration check and agree on every mutation", async () => {
  for (const mutation of [{}, { LAB_TURNSTILE_SITE_KEY: undefined }, { PUBLIC_ORIGIN_SECRET: secret }, { LAB_DATABASE_CA_CERT: undefined }]) {
    const environment = { ...labEnvironment, ...mutation };
    const valid = isLaboratoryRuntimeConfigurationValid(environment);
    const runtime = await createLaboratoryRuntimeDependencies(environment);
    if (!valid) assert.deepEqual(runtime, { enabled: false, reason: "invalid" });
  }
  // The raw PUBLIC_ORIGIN_SECRET (what the earlier Terraform workaround supplied) disables the runtime: it must stay forbidden.
  assert.equal(isLaboratoryRuntimeConfigurationValid({ ...labEnvironment, PUBLIC_ORIGIN_SECRET: secret }), false);
});

test("production intake behavior is unchanged: the page selects the production decision for any non-laboratory runtime", () => {
  // Without production deployment configuration the production decision is closed, regardless of any LAB_* values present.
  assert.deepEqual(getPublicIntakeState({ ...labEnvironment, LIMITMARK_RUNTIME: undefined }, []), { kind: "closed" });
  const page = readFileSync("src/app/test-talep-et/page.tsx", "utf8").replace(/\r\n/g, "\n");
  assert.match(page, /process\.env\.LIMITMARK_RUNTIME === "cloud-run-lab"\s*\?\s*getLaboratoryIntakeState\(process\.env\)\s*:\s*getPublicIntakeState\(process\.env, availableProductionRateLimitProviders\)/u);
});

test("origin-protection resolution: laboratory uses only LAB_* values, never raw PUBLIC_ORIGIN_*; other runtimes are returned unchanged", () => {
  const production = { PUBLIC_ORIGIN_PROTECTION: "required", PUBLIC_ORIGIN_SECRET: secret, VERCEL: "1", VERCEL_ENV: "production" };
  assert.equal(resolveOriginProtectionEnvironment(production), production);
  const resolved = resolveOriginProtectionEnvironment(labEnvironment);
  assert.equal(resolved.PUBLIC_ORIGIN_SECRET, secret);
  assert.equal(resolved.PUBLIC_ORIGIN_HOSTNAME, ORIGIN_HOST);
  assert.equal(resolved.PUBLIC_ORIGIN_PUBLIC_HOSTNAME, PUBLIC_HOST);
  // A raw PUBLIC_ORIGIN_SECRET cannot substitute for a missing LAB_ secret.
  const raw = resolveOriginProtectionEnvironment({ ...labEnvironment, LAB_PUBLIC_ORIGIN_SECRET: undefined, PUBLIC_ORIGIN_SECRET: secret });
  assert.equal(raw.PUBLIC_ORIGIN_SECRET, undefined);
});

function labHeaders(overrides: Record<string, string> = {}): Headers {
  return new Headers({ host: ORIGIN_HOST, "x-forwarded-host": PUBLIC_HOST, [publicOriginHeader]: secret, ...overrides });
}

test("laboratory origin gate: valid accepted; missing, invalid, short or mismatched credentials and hosts rejected", () => {
  const resolved = resolveOriginProtectionEnvironment(labEnvironment);
  assert.equal(isPublicOriginAllowed(labHeaders(), resolved), true);
  for (const change of [{ [publicOriginHeader]: "" }, { [publicOriginHeader]: "B".repeat(43) }, { [publicOriginHeader]: "short" },
    { host: PUBLIC_HOST }, { "x-forwarded-host": "attacker.example" }]) {
    assert.equal(isPublicOriginAllowed(labHeaders(change as unknown as Record<string, string>), resolved), false, JSON.stringify(change));
  }
  for (const mutation of [{ LAB_PUBLIC_ORIGIN_SECRET: undefined }, { LAB_PUBLIC_ORIGIN_SECRET: "short" }, { LAB_ORIGIN_HOSTNAME: undefined }, { LAB_PUBLIC_HOSTNAME: undefined },
    { PUBLIC_ORIGIN_PROTECTION: "cloudflare" }]) {
    assert.equal(isPublicOriginAllowed(labHeaders(), resolveOriginProtectionEnvironment({ ...labEnvironment, ...mutation })), false, JSON.stringify(mutation));
  }
});

test("proxy serves laboratory pages with a valid origin secret from LAB_* and denies without it (runtime selected by server env only)", () => {
  const saved = { ...process.env };
  try {
    for (const key of Object.keys(labEnvironment)) delete process.env[key];
    Object.assign(process.env, Object.fromEntries(Object.entries(labEnvironment).filter(([, value]) => value !== undefined)), { LAB_DATABASE_CA_CERT: "x" });
    const request = (headers: Headers, url = `https://${ORIGIN_HOST}/`) => new NextRequest(url, { method: "GET", headers });
    assert.equal(proxy(request(labHeaders())).status, 200);
    assert.equal(proxy(request(labHeaders({ [publicOriginHeader]: "B".repeat(43) }))).status, 404);
    assert.equal(proxy(request(new Headers({ host: ORIGIN_HOST, "x-forwarded-host": PUBLIC_HOST }))).status, 404);
    // Request input cannot select the laboratory resolution: a request header named like the runtime variable has no effect.
    process.env.LIMITMARK_RUNTIME = "production";
    assert.equal(proxy(request(labHeaders({ "limitmark-runtime": "cloud-run-lab" }))).status, 404);
    // Fail closed when the laboratory secret is missing.
    process.env.LIMITMARK_RUNTIME = "cloud-run-lab";
    delete process.env.LAB_PUBLIC_ORIGIN_SECRET;
    process.env.PUBLIC_ORIGIN_SECRET = secret;
    assert.equal(proxy(request(labHeaders())).status, 404);
  } finally {
    for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
    Object.assign(process.env, saved);
  }
});

function submissionRequest(origin: string | null, host: string, headers: Record<string, string> = {}): Request {
  const requestHeaders = new Headers({ "content-type": INGRESS_MUTATION_CONTENT_TYPE, host, ...headers });
  if (origin !== null) requestHeaders.set("origin", origin);
  return new Request(`https://${host}/api/public-inquiries`, { method: "POST", body: "name=Synthetic", headers: requestHeaders });
}
const stubDependencies = (environment: Record<string, string | undefined>) => ({
  environment: { ...environment, PUBLIC_ORIGIN_SECRET: environment.LAB_PUBLIC_ORIGIN_SECRET, PUBLIC_ORIGIN_HOSTNAME: environment.LAB_ORIGIN_HOSTNAME,
    PUBLIC_ORIGIN_PUBLIC_HOSTNAME: environment.LAB_PUBLIC_HOSTNAME },
  ingressPolicy: {} as never, admission: {} as never, turnstile: {} as never, repository: {} as never,
});

test("laboratory browser Origin: the configured public origin passes the Origin gate; run.app, attacker and missing Origin are refused generically", async () => {
  const dependencies = stubDependencies(labEnvironment);
  const common = { "x-forwarded-host": PUBLIC_HOST, [publicOriginHeader]: secret };
  // Past the Origin/origin-secret gates the stub dependencies fail at ingress verification: a generic 400, never the 503 "unavailable" gate.
  const accepted = await handlePublicInquiry(submissionRequest(`https://${PUBLIC_HOST}`, ORIGIN_HOST, common), dependencies);
  assert.equal(accepted.status, 400);
  for (const origin of [`https://${ORIGIN_HOST}`, "https://attacker.example", `http://${PUBLIC_HOST}`, `https://${PUBLIC_HOST}:444`, `https://${PUBLIC_HOST}.attacker.example`, "null", null]) {
    const response = await handlePublicInquiry(submissionRequest(origin, ORIGIN_HOST, common), dependencies);
    assert.equal(response.status, 503, String(origin));
    assert.doesNotMatch(await response.text(), /origin|secret|ingress|turnstile|hostname/iu);
  }
  // The trusted origin comes from configuration, not from a request header: forging x-forwarded-host/origin-adjacent headers does not help.
  const forged = await handlePublicInquiry(submissionRequest("https://attacker.example", ORIGIN_HOST, { ...common, "x-forwarded-host": "attacker.example" }), dependencies);
  assert.equal(forged.status, 503);
  // Origin validation is independent of the origin secret: a valid Origin with a bad secret is refused too.
  const badSecret = await handlePublicInquiry(submissionRequest(`https://${PUBLIC_HOST}`, ORIGIN_HOST, { ...common, [publicOriginHeader]: "B".repeat(43) }), dependencies);
  assert.equal(badSecret.status, 503);
  // And a missing configured public hostname refuses even an "https://undefined" Origin.
  const noHost = await handlePublicInquiry(submissionRequest("https://undefined", ORIGIN_HOST, common), stubDependencies({ ...labEnvironment, LAB_PUBLIC_HOSTNAME: undefined }));
  assert.equal(noHost.status, 503);
});

test("production browser Origin behavior is unchanged: https://limitmark.com only", async () => {
  const production = { ...labEnvironment, LIMITMARK_RUNTIME: undefined, VERCEL: "1", VERCEL_ENV: "production", PUBLIC_ORIGIN_SECRET: secret };
  const dependencies = { environment: production, ingressPolicy: {} as never, admission: {} as never, turnstile: {} as never, repository: {} as never };
  const headers = { "x-forwarded-host": "limitmark.com", [publicOriginHeader]: secret };
  assert.equal((await handlePublicInquiry(submissionRequest("https://limitmark.com", "limitmark.com", headers), dependencies)).status, 400);
  for (const origin of [`https://${PUBLIC_HOST}`, `https://${ORIGIN_HOST}`, "https://www.limitmark.com", null]) {
    assert.equal((await handlePublicInquiry(submissionRequest(origin, "limitmark.com", headers), dependencies)).status, 503, String(origin));
  }
});
