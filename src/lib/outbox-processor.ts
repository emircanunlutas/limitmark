import {
  sanitizeNotificationErrorCode,
  type NotificationAdapter,
  type NotificationDeliveryResult,
} from "./notification-adapter";
import type {
  ClaimedNotification,
  NotificationOutboxRepository,
} from "./notification-outbox-repository";
import {
  createExponentialRetryPolicy,
  type NotificationRetryPolicy,
} from "./notification-retry-policy";

export const defaultOutboxBatchSize = 10;
export const maximumOutboxBatchSize = 100;
export const defaultOutboxLeaseDurationMs = 5 * 60_000;

export type ProcessOutboxBatchOptions = {
  repository: NotificationOutboxRepository;
  adapter: NotificationAdapter;
  now: Date;
  batchSize?: number;
  leaseDurationMs?: number;
  retryPolicy?: NotificationRetryPolicy;
};

export type OutboxBatchSummary = {
  claimed: number;
  sent: number;
  retryable: number;
  failed: number;
  /** A newer claim owns the row, so this worker's late result was discarded. */
  leaseLost: number;
};

function validateOptions(
  now: Date,
  batchSize: number,
  leaseDurationMs: number,
  retryPolicy: NotificationRetryPolicy,
) {
  if (!Number.isFinite(now.getTime())) throw new RangeError("now must be a valid Date");
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > maximumOutboxBatchSize) {
    throw new RangeError(`batchSize must be an integer from 1 through ${maximumOutboxBatchSize}`);
  }
  if (!Number.isSafeInteger(leaseDurationMs) || leaseDurationMs < 1) {
    throw new RangeError("leaseDurationMs must be a positive safe integer");
  }
  if (!Number.isSafeInteger(retryPolicy.maxAttempts) || retryPolicy.maxAttempts < 1) {
    throw new RangeError("retryPolicy.maxAttempts must be a positive safe integer");
  }
}

function thrownAdapterFailure(): NotificationDeliveryResult {
  return { outcome: "retryable_failure", errorCode: "unknown" };
}

async function deliver(
  adapter: NotificationAdapter,
  job: ClaimedNotification,
): Promise<NotificationDeliveryResult> {
  try {
    return await adapter.deliver({
      idempotencyKey: job.outboxId,
      inquiryId: job.inquiryId,
      eventType: job.eventType,
    });
  } catch {
    // Provider exceptions are deliberately neither logged nor persisted.
    return thrownAdapterFailure();
  }
}

export async function processOutboxBatch(
  options: ProcessOutboxBatchOptions,
): Promise<OutboxBatchSummary> {
  const batchSize = options.batchSize ?? defaultOutboxBatchSize;
  const leaseDurationMs = options.leaseDurationMs ?? defaultOutboxLeaseDurationMs;
  const retryPolicy = options.retryPolicy ?? createExponentialRetryPolicy();
  validateOptions(options.now, batchSize, leaseDurationMs, retryPolicy);

  const lockedUntil = new Date(options.now.getTime() + leaseDurationMs);
  const jobs = await options.repository.claimBatch({ now: options.now, lockedUntil, batchSize });
  const summary: OutboxBatchSummary = {
    claimed: jobs.length,
    sent: 0,
    retryable: 0,
    failed: 0,
    leaseLost: 0,
  };

  // Sequential delivery is intentional: it bounds provider pressure and memory.
  for (const job of jobs) {
    const result = await deliver(options.adapter, job);
    if (result.outcome === "delivered") {
      const recorded = await options.repository.markSent({ ...job, now: options.now });
      if (recorded) summary.sent++;
      else summary.leaseLost++;
      continue;
    }

    const hasAttemptsRemaining = result.outcome === "retryable_failure"
      && job.attempts < retryPolicy.maxAttempts;
    let retryAt: Date | null = null;
    if (hasAttemptsRemaining) {
      const delayMs = retryPolicy.delayAfterFailure(job.attempts);
      if (!Number.isSafeInteger(delayMs) || delayMs < 1) {
        throw new RangeError("retry policy returned an invalid delay");
      }
      retryAt = new Date(options.now.getTime() + delayMs);
    }

    const recorded = await options.repository.markFailure({
      ...job,
      now: options.now,
      retryAt,
      errorCode: sanitizeNotificationErrorCode(result.errorCode),
    });
    if (!recorded) summary.leaseLost++;
    else if (retryAt) summary.retryable++;
    else summary.failed++;
  }

  return summary;
}
