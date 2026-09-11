export type RateLimitRule = {
  key: string;
  limit: number;
  windowMs: number;
};

export type RateLimitDecision = "allowed" | "limited" | "unavailable";

/**
 * Production implementations must apply every rule atomically in shared,
 * durable storage and enforce each limit over a rolling window. A per-instance
 * serverless-memory implementation or fixed-window edge burst is unsafe.
 */
export interface RateLimitAdapter {
  consume(rules: readonly RateLimitRule[]): Promise<RateLimitDecision>;
}

// A provider is deliberately not selected in this phase. Keeping this registry
// empty makes accidental public persistence impossible until a shared Vercel-
// compatible implementation is added and reviewed.
export const availableProductionRateLimitProviders = [] as const;
export type ProductionRateLimitProvider = (typeof availableProductionRateLimitProviders)[number];

export function createProductionRateLimitAdapter(provider: string): RateLimitAdapter | null {
  void provider;
  return null;
}
