import { derivePrivateClientKey, type HeaderReader, type ClientIdentityConfiguration } from "./client-identity";
import type { RateLimitAdapter, RateLimitDecision, RateLimitRule } from "./rate-limit";
import { createTurnstileIdempotencyKey, type TurnstileDecision, type TurnstileVerifier } from "./turnstile";

export const publicInquiryRateLimits = {
  client: { limit: 5, windowMs: 10 * 60_000 },
  globalBurst: { limit: 100, windowMs: 60_000 },
} as const;

// A separate budget bounds verification cost. Failed challenges do not spend
// the stricter post-verification budget, but still consume this outer budget.
export const publicInquiryPreVerificationRateLimits = {
  client: { limit: 30, windowMs: 10 * 60_000 },
  globalBurst: { limit: 300, windowMs: 60_000 },
} as const;

export type AbuseControlDecision = "allowed" | "limited" | "unavailable" | "rejected";

export async function enforceSubmissionAbuseControls(input: {
  headers: HeaderReader;
  clientIdentity: ClientIdentityConfiguration;
  submissionToken: string;
  turnstileToken: string | null;
  rateLimiter: RateLimitAdapter;
  turnstile: TurnstileVerifier;
  limits?: { client: Omit<RateLimitRule, "key">; globalBurst: Omit<RateLimitRule, "key"> };
  preVerificationLimits?: { client: Omit<RateLimitRule, "key">; globalBurst: Omit<RateLimitRule, "key"> };
}): Promise<AbuseControlDecision> {
  const clientKey = derivePrivateClientKey(input.headers, input.clientIdentity);
  if (!clientKey || !input.turnstileToken) return "unavailable";
  const limits = input.limits ?? publicInquiryRateLimits;
  const preLimits = input.preVerificationLimits ?? publicInquiryPreVerificationRateLimits;
  let rateLimitDecision: RateLimitDecision;
  try {
    rateLimitDecision = await input.rateLimiter.consume([
      { key: `public-inquiry:pre:client:v1:${clientKey}`, ...preLimits.client },
      { key: "public-inquiry:pre:global:v1", ...preLimits.globalBurst },
    ]);
  } catch {
    return "unavailable";
  }
  if (rateLimitDecision !== "allowed") return rateLimitDecision;
  let turnstileDecision: TurnstileDecision;
  try {
    turnstileDecision = await input.turnstile.verify(
      input.turnstileToken,
      createTurnstileIdempotencyKey(input.submissionToken, input.turnstileToken),
    );
  } catch {
    return "unavailable";
  }
  if (turnstileDecision !== "verified") return turnstileDecision === "rejected" ? "rejected" : "unavailable";
  try {
    return await input.rateLimiter.consume([
      { key: `public-inquiry:client:v1:${clientKey}`, ...limits.client },
      { key: "public-inquiry:global:v1", ...limits.globalBurst },
    ]);
  } catch {
    return "unavailable";
  }
}
