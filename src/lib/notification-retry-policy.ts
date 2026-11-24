export interface NotificationRetryPolicy {
  /** Total delivery attempts, including the first attempt. */
  readonly maxAttempts: number;
  delayAfterFailure(attempts: number, retryAfterMs?: number): number;
}

export type ExponentialRetryPolicyOptions = {
  maxAttempts?: number;
  initialDelayMs?: number;
  maximumDelayMs?: number;
};

export const defaultNotificationRetryPolicyOptions = {
  maxAttempts: 5,
  initialDelayMs: 60_000,
  maximumDelayMs: 60 * 60_000,
} as const;

function requirePositiveInteger(name: string, value: number) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive safe integer`);
  }
}

export function createExponentialRetryPolicy(
  options: ExponentialRetryPolicyOptions = {},
): NotificationRetryPolicy {
  const maxAttempts = options.maxAttempts ?? defaultNotificationRetryPolicyOptions.maxAttempts;
  const initialDelayMs = options.initialDelayMs ?? defaultNotificationRetryPolicyOptions.initialDelayMs;
  const maximumDelayMs = options.maximumDelayMs ?? defaultNotificationRetryPolicyOptions.maximumDelayMs;

  requirePositiveInteger("maxAttempts", maxAttempts);
  requirePositiveInteger("initialDelayMs", initialDelayMs);
  requirePositiveInteger("maximumDelayMs", maximumDelayMs);
  if (maximumDelayMs < initialDelayMs) {
    throw new RangeError("maximumDelayMs must be at least initialDelayMs");
  }

  return {
    maxAttempts,
    delayAfterFailure(attempts, retryAfterMs = 0) {
      requirePositiveInteger("attempts", attempts);
      const backoff = initialDelayMs * (2 ** Math.min(attempts - 1, 52));
      const providerDelay = Number.isSafeInteger(retryAfterMs) ? retryAfterMs : 0;
      return Math.min(Math.max(backoff, providerDelay), maximumDelayMs);
    },
  };
}
