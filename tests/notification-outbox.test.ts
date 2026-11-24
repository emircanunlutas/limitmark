import assert from "node:assert/strict";
import test from "node:test";
import type {
  FailNotificationInput,
  NotificationOutboxRepository,
} from "../src/lib/notification-outbox-repository";
import { createExponentialRetryPolicy } from "../src/lib/notification-retry-policy";
import { maximumOutboxBatchSize, processOutboxBatch } from "../src/lib/outbox-processor";
import { SyntheticNotificationAdapter } from "./support/synthetic-notification-adapter";

test("bounded exponential retry delays are deterministic and capped", () => {
  const policy = createExponentialRetryPolicy({
    maxAttempts: 4,
    initialDelayMs: 1_000,
    maximumDelayMs: 2_500,
  });
  assert.equal(policy.maxAttempts, 4);
  assert.deepEqual([1, 2, 3, 4].map((attempt) => policy.delayAfterFailure(attempt)), [1_000, 2_000, 2_500, 2_500]);
  assert.equal(policy.delayAfterFailure(2, 200), 2_000);
  assert.equal(policy.delayAfterFailure(1, 2_250), 2_250);
  assert.equal(policy.delayAfterFailure(1, Number.MAX_SAFE_INTEGER), 2_500);
  for (const invalid of [NaN, Infinity, -10, 1.5]) {
    assert.equal(policy.delayAfterFailure(1, invalid), 1_000);
  }
});

test("a slow batch timestamps each outcome and waits after the failure before retrying", async () => {
  const start = Date.UTC(2030, 8, 11, 12);
  let time = start;
  const outcomeTimes: number[] = [];
  const summary = await processOutboxBatch({
    now: () => new Date(time),
    repository: {
      async claimBatch({ now, lockedUntil }) {
        assert.equal(now.getTime(), start);
        return ["first", "second", "exhausted"].map((id) => ({
          outboxId: id, inquiryId: id, attempts: id === "exhausted" ? 5 : 1,
          eventType: "inquiry_received", lockedUntil,
        }));
      },
      async markSent({ now }) { outcomeTimes.push(now.getTime()); return true; },
      async markFailure({ now, outboxId, retryAt }) {
        outcomeTimes.push(now.getTime());
        if (outboxId === "exhausted") assert.equal(retryAt, null);
        else assert.equal(retryAt?.getTime(), start + 140_000 + 180_000);
        return true;
      },
    },
    adapter: {
      async deliver({ idempotencyKey }) {
        time += 70_000;
        return idempotencyKey === "first" ? { outcome: "delivered" } :
          { outcome: "retryable_failure", errorCode: "rate_limited", retryAfterMs: 180_000 };
      },
    },
  });
  assert.deepEqual(outcomeTimes, [start + 70_000, start + 140_000, start + 210_000]);
  assert.deepEqual(summary, { claimed: 3, sent: 1, retryable: 1, failed: 1, leaseLost: 0 });
});

test("processor rejects unbounded batches before accessing the repository", async () => {
  let accessed = false;
  const repository: NotificationOutboxRepository = {
    async claimBatch() { accessed = true; return []; },
    async markSent() { return true; },
    async markFailure() { return true; },
  };
  await assert.rejects(processOutboxBatch({
    repository,
    adapter: new SyntheticNotificationAdapter(),
    now: new Date("2026-09-11T12:00:00.000Z"),
    batchSize: maximumOutboxBatchSize + 1,
  }), /batchSize/);
  assert.equal(accessed, false);
});

test("a thrown adapter becomes a sanitized deterministic retry without provider details", async () => {
  const failureWrites: FailNotificationInput[] = [];
  const repository: NotificationOutboxRepository = {
    async claimBatch() {
      return [{
        outboxId: "00000000-0000-4000-8000-000000000001",
        inquiryId: "00000000-0000-4000-8000-000000000002",
        eventType: "inquiry_received",
        attempts: 1,
        lockedUntil: new Date("2026-09-11T12:01:00.000Z"),
      }];
    },
    async markSent() { return true; },
    async markFailure(input) { failureWrites.push(input); return true; },
  };
  const summary = await processOutboxBatch({
    repository,
    adapter: new SyntheticNotificationAdapter("throw"),
    now: new Date("2026-09-11T12:00:00.000Z"),
    leaseDurationMs: 60_000,
    retryPolicy: createExponentialRetryPolicy({ maxAttempts: 3, initialDelayMs: 1_000 }),
  });
  assert.deepEqual(summary, { claimed: 1, sent: 0, retryable: 1, failed: 0, leaseLost: 0 });
  assert.equal(failureWrites.length, 1);
  assert.equal(failureWrites[0].errorCode, "unknown");
  assert.equal(failureWrites[0].retryAt?.toISOString(), "2026-09-11T12:00:01.000Z");
});
