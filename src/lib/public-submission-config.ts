import { Buffer } from "node:buffer";
import { getPersistenceConfiguration, type PersistenceEnvironment } from "./persistence-config";
import { INGRESS_VERSION } from "./ingress-protocol";
import { parseIngressSigningKeyRollout } from "./ingress-key-rollout";
import { validateRuntimeSecrets } from "../../deployment/secret-policy";
import { publicInquiryTurnstileAction } from "./turnstile";
import { isDemoSubmissionAllowed } from "./submission-policy";

export type PublicSubmissionEnvironment = PersistenceEnvironment & {
  VERCEL?: string; VERCEL_ENV?: string; VERCEL_PROJECT_ID?: string; VERCEL_DEPLOYMENT_ID?: string;
  PUBLIC_ORIGIN_PROTECTION?: string; RATE_LIMIT_PROVIDER?: string;
  INGRESS_PROTOCOL?: string; INGRESS_AUDIENCE?: string; INGRESS_PUBLIC_KEYS?: string; INGRESS_REQUEST_BINDING_KEY?: string;
  ADMISSION_SERVICE_URL?: string; ADMISSION_OIDC_AUDIENCE?: string; ADMISSION_RELEASE_ID?: string; ADMISSION_RELEASE_KEY_ID?: string; ADMISSION_RELEASE_RPC_KEY?: string;
  TURNSTILE_MODE?: string; TURNSTILE_SITE_KEY?: string; TURNSTILE_SECRET_KEY?: string; TURNSTILE_EXPECTED_HOSTNAME?: string;
};

export type PublicSubmissionConfiguration =
  | { enabled: false; reason: "persistence" | "rate-limit-provider" | "deployment-boundary" | "ingress" | "admission" | "turnstile" }
  | { enabled: true; databaseUrl: string; poolMax: number; rateLimitProvider: "cloudflare-do"; turnstile: {
      siteKey: string; secretKey: string; expectedHostname: string; expectedAction: typeof publicInquiryTurnstileAction; timeoutMs: number;
    } };

function isSecret(value: string | undefined): value is string {
  if (!value || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  try { return Buffer.from(value, "base64url").length === 32; } catch { return false; }
}
function isCredential(value: string | undefined): value is string { return Boolean(value && value.length >= 8 && value.length <= 256); }
function isIdentifier(value: string | undefined, maximum: number): value is string { return Boolean(value && value.length <= maximum && /^[A-Za-z0-9_.:-]+$/.test(value)); }
function isAudience(value: string | undefined): value is string { return Boolean(value && value.length <= 256 && /^[\x21-\x7e]+$/.test(value)); }
function isHttpsServiceRoot(value: string | undefined): boolean {
  try { const url = new URL(value ?? ""); return url.protocol === "https:" && url.pathname === "/" && !url.search && !url.hash && !url.username && !url.password; } catch { return false; }
}
function isHostname(value: string | undefined): value is string {
  if (!value || value.length > 253 || value.includes(":") || value.includes("/") || value.includes("*")) return false;
  try { const url = new URL(`https://${value}`); return url.hostname === value && value.includes("."); } catch { return false; }
}

const turnstileTestSiteKeys = new Set(["1x00000000000000000000AA", "2x00000000000000000000AB", "1x00000000000000000000BB", "2x00000000000000000000BB", "3x00000000000000000000FF"]);
const turnstileTestSecretKeys = new Set(["1x0000000000000000000000000000000AA", "2x0000000000000000000000000000000AA", "3x0000000000000000000000000000000AA"]);

export function getPublicSubmissionConfiguration(environment: PublicSubmissionEnvironment, availableRateLimitProviders: readonly string[]): PublicSubmissionConfiguration {
  const persistence = getPersistenceConfiguration(environment);
  if (!persistence.enabled) return { enabled: false, reason: "persistence" };
  if (environment.RATE_LIMIT_PROVIDER !== "cloudflare-do" || !availableRateLimitProviders.includes("cloudflare-do")) return { enabled: false, reason: "rate-limit-provider" };
  if (environment.VERCEL !== "1" || environment.VERCEL_ENV !== "production" || environment.PUBLIC_ORIGIN_PROTECTION !== "required" ||
      !isSecret(environment.PUBLIC_ORIGIN_SECRET) || !isIdentifier(environment.VERCEL_PROJECT_ID, 96) || !isIdentifier(environment.VERCEL_DEPLOYMENT_ID, 128)) return { enabled: false, reason: "deployment-boundary" };
  if (environment.INGRESS_PROTOCOL !== INGRESS_VERSION || environment.INGRESS_AUDIENCE !== environment.VERCEL_PROJECT_ID ||
      !parseIngressSigningKeyRollout(environment.INGRESS_PUBLIC_KEYS) || !isSecret(environment.INGRESS_REQUEST_BINDING_KEY)) return { enabled: false, reason: "ingress" };
  if (!isHttpsServiceRoot(environment.ADMISSION_SERVICE_URL) || !isAudience(environment.ADMISSION_OIDC_AUDIENCE) ||
      environment.ADMISSION_RELEASE_ID !== environment.VERCEL_DEPLOYMENT_ID || !environment.ADMISSION_RELEASE_KEY_ID || !/^[A-Za-z0-9_-]{1,64}$/u.test(environment.ADMISSION_RELEASE_KEY_ID) ||
      !isSecret(environment.ADMISSION_RELEASE_RPC_KEY)) return { enabled: false, reason: "admission" };
  if (new Set([environment.PUBLIC_ORIGIN_SECRET, environment.INGRESS_REQUEST_BINDING_KEY, environment.ADMISSION_RELEASE_RPC_KEY, environment.TURNSTILE_SECRET_KEY]).size !== 4) return { enabled: false, reason: "admission" };
  if (!validateRuntimeSecrets("vercelApplication", environment as unknown as Record<string, unknown>, false)) return { enabled: false, reason: "admission" };
  if (environment.TURNSTILE_MODE !== "enabled" || !isCredential(environment.TURNSTILE_SITE_KEY) || !isCredential(environment.TURNSTILE_SECRET_KEY) ||
      turnstileTestSiteKeys.has(environment.TURNSTILE_SITE_KEY) || turnstileTestSecretKeys.has(environment.TURNSTILE_SECRET_KEY) || !isHostname(environment.TURNSTILE_EXPECTED_HOSTNAME)) return { enabled: false, reason: "turnstile" };
  return { enabled: true, databaseUrl: persistence.databaseUrl, poolMax: persistence.poolMax, rateLimitProvider: "cloudflare-do", turnstile: {
    siteKey: environment.TURNSTILE_SITE_KEY, secretKey: environment.TURNSTILE_SECRET_KEY, expectedHostname: environment.TURNSTILE_EXPECTED_HOSTNAME,
    expectedAction: publicInquiryTurnstileAction, timeoutMs: 5_000,
  } };
}

export function getTurnstileClientConfiguration(environment: PublicSubmissionEnvironment, providers: readonly string[]) {
  const configuration = getPublicSubmissionConfiguration(environment, providers);
  return configuration.enabled ? { siteKey: configuration.turnstile.siteKey, action: configuration.turnstile.expectedAction } : null;
}
export type PublicIntakeState = { kind: "closed" } | { kind: "demo" } | { kind: "real"; turnstile: { siteKey: string; action: typeof publicInquiryTurnstileAction } };
export function getPublicIntakeState(environment: PublicSubmissionEnvironment, providers: readonly string[]): PublicIntakeState {
  const configuration = getPublicSubmissionConfiguration(environment, providers);
  if (configuration.enabled) return { kind: "real", turnstile: { siteKey: configuration.turnstile.siteKey, action: configuration.turnstile.expectedAction } };
  return isDemoSubmissionAllowed(environment) ? { kind: "demo" } : { kind: "closed" };
}
