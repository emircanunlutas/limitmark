import { Buffer } from "node:buffer";
import { getPersistenceConfiguration, type PersistenceEnvironment } from "./persistence-config";
import { publicInquiryTurnstileAction } from "./turnstile";
import { isPublicOriginProtectionDisabled } from "./public-origin";

export type PublicSubmissionEnvironment = PersistenceEnvironment & {
  VERCEL?: string;
  VERCEL_ENV?: string;
  PUBLIC_ORIGIN_PROTECTION?: string;
  RATE_LIMIT_PROVIDER?: string;
  SUBMISSION_CLIENT_IP_SOURCE?: string;
  SUBMISSION_CLIENT_KEY_SECRET?: string;
  TURNSTILE_MODE?: string;
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
  TURNSTILE_EXPECTED_HOSTNAME?: string;
};

export type PublicSubmissionConfiguration =
  | { enabled: false; reason: "persistence" | "rate-limit-provider" | "deployment-boundary" | "client-key-secret" | "turnstile" }
  | {
      enabled: true;
      databaseUrl: string;
      poolMax: number;
      rateLimitProvider: string;
      clientIdentity: { source: "vercel"; hmacSecret: string };
      turnstile: {
        siteKey: string;
        secretKey: string;
        expectedHostname: string;
        expectedAction: typeof publicInquiryTurnstileAction;
        timeoutMs: number;
      };
    };

function isSecret(value: string | undefined): value is string {
  if (!value || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  try {
    return Buffer.from(value, "base64url").length === 32;
  } catch {
    return false;
  }
}

function isCredential(value: string | undefined): value is string {
  return Boolean(value && value.length >= 8 && value.length <= 256);
}

// Exact production-safety denylist from Cloudflare's documented testing keys.
// Do not infer production validity from a key prefix or shape.
const turnstileTestSiteKeys = new Set([
  "1x00000000000000000000AA",
  "2x00000000000000000000AB",
  "1x00000000000000000000BB",
  "2x00000000000000000000BB",
  "3x00000000000000000000FF",
]);
const turnstileTestSecretKeys = new Set([
  "1x0000000000000000000000000000000AA",
  "2x0000000000000000000000000000000AA",
  "3x0000000000000000000000000000000AA",
]);

function isHostname(value: string | undefined): value is string {
  if (!value || value.length > 253 || value.includes(":") || value.includes("/") || value.includes("*")) return false;
  try {
    const url = new URL(`https://${value}`);
    return url.hostname === value && value.includes(".");
  } catch {
    return false;
  }
}

export function getPublicSubmissionConfiguration(
  environment: PublicSubmissionEnvironment,
  availableRateLimitProviders: readonly string[],
): PublicSubmissionConfiguration {
  const persistence = getPersistenceConfiguration(environment);
  if (!persistence.enabled) return { enabled: false, reason: "persistence" };
  const rateLimitProvider = environment.RATE_LIMIT_PROVIDER?.trim() ?? "";
  if (!rateLimitProvider || !availableRateLimitProviders.includes(rateLimitProvider)) {
    return { enabled: false, reason: "rate-limit-provider" };
  }
  // Authenticating an origin bearer does not establish a visitor IP. Until a
  // Cloudflare identity policy is reviewed, proxied persistence stays closed.
  if (environment.VERCEL !== "1" ||
      environment.VERCEL_ENV !== "production" ||
      !isPublicOriginProtectionDisabled(environment) ||
      environment.SUBMISSION_CLIENT_IP_SOURCE !== "vercel") {
    return { enabled: false, reason: "deployment-boundary" };
  }
  if (!isSecret(environment.SUBMISSION_CLIENT_KEY_SECRET)) return { enabled: false, reason: "client-key-secret" };
  if (environment.TURNSTILE_MODE !== "enabled" ||
      !isCredential(environment.TURNSTILE_SITE_KEY) ||
      !isCredential(environment.TURNSTILE_SECRET_KEY) ||
      turnstileTestSiteKeys.has(environment.TURNSTILE_SITE_KEY) ||
      turnstileTestSecretKeys.has(environment.TURNSTILE_SECRET_KEY) ||
      !isHostname(environment.TURNSTILE_EXPECTED_HOSTNAME)) {
    return { enabled: false, reason: "turnstile" };
  }
  return {
    enabled: true,
    databaseUrl: persistence.databaseUrl,
    poolMax: persistence.poolMax,
    rateLimitProvider,
    clientIdentity: { source: "vercel", hmacSecret: environment.SUBMISSION_CLIENT_KEY_SECRET },
    turnstile: {
      siteKey: environment.TURNSTILE_SITE_KEY,
      secretKey: environment.TURNSTILE_SECRET_KEY,
      expectedHostname: environment.TURNSTILE_EXPECTED_HOSTNAME,
      expectedAction: publicInquiryTurnstileAction,
      timeoutMs: 5_000,
    },
  };
}

export function getTurnstileClientConfiguration(
  environment: PublicSubmissionEnvironment,
  availableRateLimitProviders: readonly string[],
): null | {
  siteKey: string;
  action: typeof publicInquiryTurnstileAction;
} {
  const configuration = getPublicSubmissionConfiguration(environment, availableRateLimitProviders);
  if (!configuration.enabled) return null;
  return { siteKey: configuration.turnstile.siteKey, action: configuration.turnstile.expectedAction };
}
