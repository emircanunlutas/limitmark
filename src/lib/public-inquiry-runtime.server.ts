import "server-only";

import { Buffer } from "node:buffer";
import { createLaboratoryAdmissionClient, GoogleMetadataOidcTokenProvider } from "./admission-client.server";
import { getDatabase } from "./db/database.server";
import { importRequestBindingKey, importIngressPublicKeys, type IngressVerificationPolicy } from "./ingress-verifier.server";
import { PostgresInquiryRepository } from "./inquiry-repository";
import { handlePublicInquiry, type PublicInquiryHandlerDependencies } from "./public-inquiry-handler.server";
import { CloudflareTurnstileVerifier, publicInquiryTurnstileAction } from "./turnstile";

const LAB_RUNTIME = "cloud-run-lab";
const secretPattern = /^[A-Za-z0-9_-]{43}$/u;
const identifierPattern = /^[A-Za-z0-9_.:-]{1,128}$/u;
const turnstileTestSiteKeys = new Set(["1x00000000000000000000AA", "2x00000000000000000000AB", "1x00000000000000000000BB", "2x00000000000000000000BB", "3x00000000000000000000FF"]);
const turnstileTestSecretKeys = new Set(["1x0000000000000000000000000000000AA", "2x0000000000000000000000000000000AA", "3x0000000000000000000000000000000AA"]);
const forbiddenProductionKeys = [
  "DATABASE_URL", "DATABASE_MIGRATION_URL", "ADMISSION_SERVICE_URL", "ADMISSION_OIDC_AUDIENCE",
  "ADMISSION_RELEASE_ID", "ADMISSION_RELEASE_KEY_ID", "ADMISSION_RELEASE_RPC_KEY",
  "ADMISSION_CURRENT_RPC_KEY", "ADMISSION_PREVIOUS_RPC_KEY", "TURNSTILE_SITE_KEY",
  "TURNSTILE_SECRET_KEY", "TURNSTILE_EXPECTED_HOSTNAME", "PUBLIC_ORIGIN_SECRET",
  "INGRESS_PUBLIC_KEYS", "INGRESS_REQUEST_BINDING_KEY", "VERCEL_AUTOMATION_BYPASS_SECRET",
  "INGRESS_SIGNING_PRIVATE_KEY", "INGRESS_IDENTITY_HMAC_KEY", "AUTHORITY", "TEST_DATABASE_URL",
] as const;

export type LaboratoryRuntimeEnvironment = Record<string, string | undefined> & {
  LIMITMARK_RUNTIME?: string;
  LAB_PUBLIC_HOSTNAME?: string;
  LAB_PUBLIC_ORIGIN_SECRET?: string;
  LAB_DATABASE_URL?: string;
  LAB_DATABASE_POOL_MAX?: string;
  LAB_INGRESS_AUDIENCE?: string;
  LAB_DEPLOYMENT_ID?: string;
  LAB_INGRESS_PUBLIC_KEYS?: string;
  LAB_INGRESS_REQUEST_BINDING_KEY?: string;
  LAB_ADMISSION_SERVICE_URL?: string;
  LAB_ADMISSION_OIDC_AUDIENCE?: string;
  LAB_ADMISSION_RELEASE_ID?: string;
  LAB_ADMISSION_RELEASE_KEY_ID?: string;
  LAB_ADMISSION_RELEASE_RPC_KEY?: string;
  LAB_TURNSTILE_SITE_KEY?: string;
  LAB_TURNSTILE_SECRET_KEY?: string;
  LAB_TURNSTILE_EXPECTED_HOSTNAME?: string;
};

function validHostname(value: string | undefined): value is string {
  if (!value || value === "limitmark.com" || value === "www.limitmark.com" || value.length > 253 || value.includes(":") || value.includes("/") || value.includes("*")) return false;
  try { return new URL(`https://${value}`).hostname === value && value.includes("."); } catch { return false; }
}

function validSecret(value: string | undefined): value is string {
  if (!value || !secretPattern.test(value)) return false;
  try { return Buffer.from(value, "base64url").length === 32; } catch { return false; }
}

function validHttpsRoot(value: string | undefined): value is string {
  try {
    const url = new URL(value ?? "");
    return url.protocol === "https:" && url.pathname === "/" && !url.search && !url.hash && !url.username && !url.password;
  } catch { return false; }
}

function validDatabase(value: string | undefined): value is string {
  try {
    const url = new URL(value ?? "");
    return (url.protocol === "postgres:" || url.protocol === "postgresql:") &&
      Boolean(url.hostname && url.username && url.password && url.pathname.length > 1);
  } catch { return false; }
}

function validPool(value: string | undefined): number | null {
  const pool = value === undefined ? 5 : Number(value);
  return Number.isSafeInteger(pool) && pool >= 1 && pool <= 10 ? pool : null;
}

function hasProductionCredentials(environment: LaboratoryRuntimeEnvironment): boolean {
  return forbiddenProductionKeys.some((key) => Boolean(environment[key]));
}

export type LaboratoryRuntimeResult =
  | { enabled: false; reason: "disabled" | "invalid" }
  | { enabled: true; dependencies: PublicInquiryHandlerDependencies };

export async function createLaboratoryRuntimeDependencies(
  environment: LaboratoryRuntimeEnvironment,
  request: typeof fetch = fetch,
): Promise<LaboratoryRuntimeResult> {
  if (environment.LIMITMARK_RUNTIME !== LAB_RUNTIME) return { enabled: false, reason: "disabled" };
  const poolMax = validPool(environment.LAB_DATABASE_POOL_MAX);
  if (hasProductionCredentials(environment) || environment.VERCEL === "1" || environment.VERCEL_ENV !== undefined ||
      environment.REQUEST_SUBMISSION_MODE !== "postgres" ||
      environment.ENABLE_PERSISTENT_SUBMISSIONS !== "true" ||
      environment.PUBLIC_ORIGIN_PROTECTION !== "required" ||
      !validHostname(environment.LAB_PUBLIC_HOSTNAME) ||
      !validDatabase(environment.LAB_DATABASE_URL) ||
      poolMax === null ||
      !validSecret(environment.LAB_PUBLIC_ORIGIN_SECRET) ||
      !validSecret(environment.LAB_INGRESS_REQUEST_BINDING_KEY) ||
      !environment.LAB_INGRESS_AUDIENCE || !identifierPattern.test(environment.LAB_INGRESS_AUDIENCE) ||
      !environment.LAB_DEPLOYMENT_ID || !identifierPattern.test(environment.LAB_DEPLOYMENT_ID) ||
      !environment.LAB_INGRESS_PUBLIC_KEYS || !validHttpsRoot(environment.LAB_ADMISSION_SERVICE_URL) ||
      !environment.LAB_ADMISSION_OIDC_AUDIENCE ||
      !environment.LAB_ADMISSION_RELEASE_ID || environment.LAB_ADMISSION_RELEASE_ID !== environment.LAB_DEPLOYMENT_ID ||
      !environment.LAB_ADMISSION_RELEASE_KEY_ID || !/^[A-Za-z0-9_-]{1,64}$/u.test(environment.LAB_ADMISSION_RELEASE_KEY_ID) ||
      !validSecret(environment.LAB_ADMISSION_RELEASE_RPC_KEY) ||
      !environment.LAB_TURNSTILE_SITE_KEY || !environment.LAB_TURNSTILE_SECRET_KEY ||
      turnstileTestSiteKeys.has(environment.LAB_TURNSTILE_SITE_KEY) || turnstileTestSecretKeys.has(environment.LAB_TURNSTILE_SECRET_KEY) ||
      !environment.LAB_TURNSTILE_EXPECTED_HOSTNAME || !validHostname(environment.LAB_TURNSTILE_EXPECTED_HOSTNAME)) {
    return { enabled: false, reason: "invalid" };
  }

  try {
    const ingressPolicy: IngressVerificationPolicy = {
      audience: environment.LAB_INGRESS_AUDIENCE,
      deploymentId: environment.LAB_DEPLOYMENT_ID,
      hostname: environment.LAB_PUBLIC_HOSTNAME,
      publicKeys: await importIngressPublicKeys(environment.LAB_INGRESS_PUBLIC_KEYS),
      requestBindingKey: await importRequestBindingKey(environment.LAB_INGRESS_REQUEST_BINDING_KEY),
    };
    const admission = await createLaboratoryAdmissionClient({
      ADMISSION_SERVICE_URL: environment.LAB_ADMISSION_SERVICE_URL,
      ADMISSION_OIDC_AUDIENCE: environment.LAB_ADMISSION_OIDC_AUDIENCE,
      ADMISSION_RELEASE_ID: environment.LAB_ADMISSION_RELEASE_ID,
      ADMISSION_RELEASE_KEY_ID: environment.LAB_ADMISSION_RELEASE_KEY_ID,
      ADMISSION_RELEASE_RPC_KEY: environment.LAB_ADMISSION_RELEASE_RPC_KEY,
      LAB_DEPLOYMENT_ID: environment.LAB_DEPLOYMENT_ID,
    }, new GoogleMetadataOidcTokenProvider(request), request);
    if (!admission) return { enabled: false, reason: "invalid" };
    const database = getDatabase(environment.LAB_DATABASE_URL, poolMax);
    const repository = new PostgresInquiryRepository(database);
    const turnstile = new CloudflareTurnstileVerifier({
      secretKey: environment.LAB_TURNSTILE_SECRET_KEY,
      expectedHostname: environment.LAB_TURNSTILE_EXPECTED_HOSTNAME,
      expectedAction: publicInquiryTurnstileAction,
      timeoutMs: 5_000,
    }, request);
    const laboratoryEnvironment = {
      ...environment,
      LIMITMARK_RUNTIME: LAB_RUNTIME,
      PUBLIC_ORIGIN_SECRET: environment.LAB_PUBLIC_ORIGIN_SECRET,
      PUBLIC_ORIGIN_HOSTNAME: environment.LAB_PUBLIC_HOSTNAME,
    };
    return {
      enabled: true,
      dependencies: {
        environment: laboratoryEnvironment,
        ingressPolicy,
        admission,
        turnstile,
        repository: {
          async create(input) {
            const result = await repository.create(input);
            return { status: result.status === "idempotent" ? "existing" : result.status };
          },
        },
      },
    };
  } catch {
    return { enabled: false, reason: "invalid" };
  }
}

export async function handleLaboratoryPublicInquiry(request: Request, environment: LaboratoryRuntimeEnvironment): Promise<Response> {
  const runtime = await createLaboratoryRuntimeDependencies(environment);
  if (!runtime.enabled) return Response.json({ kind: "state", state: { errors: {}, message: "Talep gönderimi şu anda kullanılamıyor." } }, { status: 503 });
  return handlePublicInquiry(request, runtime.dependencies);
}
