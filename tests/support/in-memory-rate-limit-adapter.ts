import type { RateLimitAdapter, RateLimitDecision, RateLimitRule } from "../../src/lib/rate-limit";

/** Deterministic test double. Never use this per-process store in production. */
export class InMemoryTestRateLimitAdapter implements RateLimitAdapter {
  private readonly attempts = new Map<string, number[]>();
  unavailable = false;

  constructor(private readonly now: () => number = () => Date.now()) {}

  async consume(rules: readonly RateLimitRule[]): Promise<RateLimitDecision> {
    if (this.unavailable) return "unavailable";
    const now = this.now();
    const current = rules.map((rule) => ({
      rule,
      attempts: (this.attempts.get(rule.key) ?? []).filter((attempt) => now - attempt < rule.windowMs),
    }));
    if (current.some(({ rule, attempts }) => attempts.length >= rule.limit)) return "limited";
    for (const { rule, attempts } of current) {
      attempts.push(now);
      this.attempts.set(rule.key, attempts);
    }
    return "allowed";
  }
}
