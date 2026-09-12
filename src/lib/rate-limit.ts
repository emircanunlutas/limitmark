import "server-only";

export type RateLimitRule = {
  key: string;
  limit: number;
  windowMs: number;
};

export type RateLimitDecision = "allowed" | "limited" | "unavailable";

/**
 * Production implementations must apply every rule atomically in shared,
 * durable storage: every accepted rule records the same attempt, or a denial
 * consumes none. Concurrent callers cannot overspend any rule. At server time t,
 * the rolling window includes (t - windowMs, t]; the lower boundary is expired.
 * Validate bounded rules/keys before mutation and expire historical state with
 * bounded TTLs. Failures and ambiguous execution return unavailable. Never retry
 * a possibly consumed attempt without a proven idempotent operation. Atomic
 * execution alone is insufficient without consistency across provider failover.
 * A per-instance memory implementation or fixed-window edge burst is unsafe.
 */
export interface RateLimitAdapter {
  consume(rules: readonly RateLimitRule[]): Promise<RateLimitDecision>;
}

// I1 contains the selected Cloudflare DO implementation and local conformance
// tests, but this launch registry intentionally stays empty. A later authorized
// provider/configuration phase must not be inferred from emulator evidence.
export const availableProductionRateLimitProviders = [] as const;
export type ProductionRateLimitProvider = (typeof availableProductionRateLimitProviders)[number];

export function createProductionRateLimitAdapter(provider: string): RateLimitAdapter | null {
  void provider;
  return null;
}
