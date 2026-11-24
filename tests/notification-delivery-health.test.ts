import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import {
  NOTIFICATION_DELIVERY_OVERDUE_MS,
  assessNotificationDeliveryHealth,
  deriveNotificationDeliveryState,
  isNotificationOverdue,
  normalizeNotificationDeliveryCounts,
  toInquiryNotificationDelivery,
  type NotificationDeliveryCounts,
  type NotificationDeliveryRecord,
} from "../src/lib/notification-delivery-health";

const now = new Date("2026-11-24T12:00:00.000Z");
const minutesAgo = (minutes: number) => new Date(now.getTime() - minutes * 60_000);
const minutesAhead = (minutes: number) => new Date(now.getTime() + minutes * 60_000);
const T = NOTIFICATION_DELIVERY_OVERDUE_MS;

function record(overrides: Partial<NotificationDeliveryRecord> = {}): NotificationDeliveryRecord {
  return {
    id: "00000000-0000-4000-8000-0000000000a1", eventType: "inquiry_received", status: "pending", attempts: 0,
    createdAt: minutesAgo(5), availableAt: minutesAgo(5), lockedUntil: null, sentAt: null, lastErrorCode: null,
    ...overrides,
  };
}

function counts(overrides: Partial<NotificationDeliveryCounts> = {}): NotificationDeliveryCounts {
  return { due: 0, scheduled: 0, inProgress: 0, leaseExpired: 0, leaseMissing: 0, failed: 0, overdue: 0, oldestDueAt: null, ...overrides };
}

test("the overdue threshold is the documented, inclusive 30-minute product default", async () => {
  assert.equal(T, 30 * 60_000);
  assert.equal(isNotificationOverdue(new Date(now.getTime() - T), now), true);
  assert.equal(isNotificationOverdue(new Date(now.getTime() - T + 1), now), false);
  const readme = await readFile(new URL("../README.md", import.meta.url), "utf8");
  const start = readme.indexOf("### Notification delivery health");
  assert.notEqual(start, -1);
  const section = readme.slice(start, readme.indexOf("\n### ", start + 1));
  assert.match(section, /product default: 30 minutes/);
  assert.match(section, /30 minutes or more/);
  assert.doesNotMatch(section, /more than 30 minutes|over 30 minutes|healthy/i);
});

test("states follow the processor's claim rule, including a missing lease that is never reclaimed", () => {
  assert.equal(deriveNotificationDeliveryState(record({ status: "sent" }), now), "delivered");
  assert.equal(deriveNotificationDeliveryState(record({ status: "failed" }), now), "failed");
  assert.equal(deriveNotificationDeliveryState(record({ status: "pending", availableAt: now }), now), "due");
  assert.equal(deriveNotificationDeliveryState(record({ status: "retryable", availableAt: minutesAhead(1) }), now), "scheduled");
  assert.equal(deriveNotificationDeliveryState(record({ status: "processing", lockedUntil: minutesAhead(1) }), now), "in_progress");
  assert.equal(deriveNotificationDeliveryState(record({ status: "processing", lockedUntil: now }), now), "lease_expired");
  assert.equal(deriveNotificationDeliveryState(record({ status: "processing", lockedUntil: null }), now), "lease_missing");
  assert.equal(deriveNotificationDeliveryState(record({ status: "queued-by-hand" }), now), "unrecognized");
  // The processor's claim SQL is the authority being mirrored: it requires lte(locked_until, now), which a NULL never satisfies.
  return readFile(new URL("../src/lib/notification-outbox-repository.ts", import.meta.url), "utf8").then((source) => {
    assert.match(source, /eq\(notificationOutbox\.status, "processing"\),\s*lte\(notificationOutbox\.lockedUntil, input\.now\)/);
    assert.match(source, /inArray\(notificationOutbox\.status, \["pending", "retryable"\]\),\s*lte\(notificationOutbox\.availableAt, input\.now\)/);
  });
});

test("a claimable notification becomes overdue at exactly 30 minutes after it became eligible", () => {
  const due = (availableAt: Date) => toInquiryNotificationDelivery(record({ availableAt, createdAt: minutesAgo(600) }), now);
  assert.equal(due(new Date(now.getTime() - T)).overdue, true);
  assert.equal(due(new Date(now.getTime() - T + 1)).overdue, false);
  const scheduled = toInquiryNotificationDelivery(record({ status: "retryable", attempts: 3, createdAt: minutesAgo(600), availableAt: minutesAhead(45) }), now);
  assert.equal(scheduled.state, "scheduled");
  assert.equal(scheduled.overdue, false);
  assert.deepEqual(scheduled.nextAttemptAt, minutesAhead(45));
  const processing = (lockedUntil: Date | null) =>
    toInquiryNotificationDelivery(record({ status: "processing", attempts: 1, availableAt: minutesAgo(600), lockedUntil }), now);
  assert.equal(processing(minutesAgo(29)).overdue, false);
  assert.equal(processing(minutesAgo(30)).overdue, true);
  // A missing lease is not claimable, so it is reported as stuck rather than overdue, however old.
  assert.equal(processing(null).state, "lease_missing");
  assert.equal(processing(null).overdue, false);
  assert.equal(processing(minutesAhead(1)).overdue, false);
  assert.equal(toInquiryNotificationDelivery(record({ status: "failed", availableAt: minutesAgo(600) }), now).overdue, false);
});

test("per-inquiry projections expose only sanitized error codes and state-appropriate timestamps", () => {
  const failed = toInquiryNotificationDelivery(record({ status: "failed", attempts: 5, lastErrorCode: "rejected" }), now);
  assert.deepEqual([failed.state, failed.lastErrorCode, failed.deliveredAt, failed.nextAttemptAt], ["failed", "rejected", null, null]);
  assert.equal(toInquiryNotificationDelivery(record({ status: "retryable", lastErrorCode: "550 mailbox user@example.test unavailable" }), now).lastErrorCode, "unknown");
  const delivered = toInquiryNotificationDelivery(record({ status: "sent", attempts: 2, sentAt: minutesAgo(1), lastErrorCode: "timeout" }), now);
  assert.deepEqual(delivered.deliveredAt, minutesAgo(1));
  assert.equal(delivered.lastErrorCode, null);
  assert.deepEqual(Object.keys(delivered).sort(), ["attempts", "deliveredAt", "eventType", "id", "lastErrorCode", "nextAttemptAt", "overdue", "queuedAt", "state"]);
});

test("malformed rows and clocks fail closed instead of producing a misleading state", () => {
  assert.throws(() => toInquiryNotificationDelivery(record(), new Date(Number.NaN)), RangeError);
  assert.throws(() => toInquiryNotificationDelivery(record({ availableAt: new Date("not a date") }), now), RangeError);
  assert.throws(() => toInquiryNotificationDelivery(record({ attempts: -1 }), now), RangeError);
  assert.throws(() => toInquiryNotificationDelivery(record({ attempts: 1.5 }), now), RangeError);
  assert.throws(() => toInquiryNotificationDelivery(record({ sentAt: "2026-11-24" as unknown as Date }), now), RangeError);
  const foreign = runInNewContext("new Date('2026-11-24T11:00:00.000Z')") as Date;
  assert.equal(toInquiryNotificationDelivery(record({ availableAt: foreign, createdAt: foreign }), now).overdue, true);
});

test("aggregate rows accept driver encodings and reject structurally inconsistent snapshots", () => {
  const oldest = minutesAgo(60);
  assert.deepEqual(
    normalizeNotificationDeliveryCounts({ due: "2", scheduled: 1n, inProgress: 0, leaseExpired: "1", leaseMissing: "4", failed: "0", overdue: 3, oldestDueAt: String(oldest.getTime()) }),
    { due: 2, scheduled: 1, inProgress: 0, leaseExpired: 1, leaseMissing: 4, failed: 0, overdue: 3, oldestDueAt: oldest },
  );
  assert.deepEqual(normalizeNotificationDeliveryCounts({ ...counts(), oldestDueAt: undefined }), counts());
  const invalid: Array<Record<string, unknown>> = [
    { ...counts(), due: -1 }, { ...counts(), failed: 1.5 }, { ...counts(), failed: "1e3" }, { ...counts(), failed: null },
    { ...counts(), leaseMissing: undefined },
    { ...counts(), due: 1, overdue: 2, oldestDueAt: now },
    { ...counts(), leaseMissing: 1, overdue: 1, oldestDueAt: now }, // a missing lease is never eligible, so never overdue
    { ...counts(), oldestDueAt: now },
    { ...counts({ leaseMissing: 2 }), oldestDueAt: now },
    counts({ due: 1 }),
    { ...counts({ due: 1 }), oldestDueAt: "yesterday-ish" },
  ];
  for (const row of invalid) assert.throws(() => normalizeNotificationDeliveryCounts(row), RangeError, JSON.stringify(row, (_, value) => typeof value === "bigint" ? String(value) : value));
});

test("snapshots that contradict their own snapshot time are rejected", () => {
  // overdue > 0 but the oldest eligible row is younger than the threshold
  assert.throws(() => assessNotificationDeliveryHealth(counts({ due: 1, overdue: 1, oldestDueAt: new Date(now.getTime() - T + 1) }), now), RangeError);
  // overdue = 0 but the oldest eligible row is exactly at the inclusive threshold
  assert.throws(() => assessNotificationDeliveryHealth(counts({ due: 1, overdue: 0, oldestDueAt: new Date(now.getTime() - T) }), now), RangeError);
  // an eligible row cannot have become eligible after the snapshot instant
  assert.throws(() => assessNotificationDeliveryHealth(counts({ due: 1, oldestDueAt: minutesAhead(1) }), now), RangeError);
  assert.equal(assessNotificationDeliveryHealth(counts({ due: 1, overdue: 1, oldestDueAt: new Date(now.getTime() - T) }), now).level, "stalled");
  assert.equal(assessNotificationDeliveryHealth(counts({ due: 1, oldestDueAt: new Date(now.getTime() - T + 1) }), now).level, "clear");
});

test("queue levels: stalled on overdue, attention on terminal or lease-less rows, otherwise clear", () => {
  assert.equal(assessNotificationDeliveryHealth(counts(), now).level, "clear");
  const fresh = assessNotificationDeliveryHealth(counts({ due: 3, scheduled: 4, inProgress: 1, leaseExpired: 1, oldestDueAt: minutesAgo(29) }), now);
  assert.equal(fresh.level, "clear");
  assert.equal(fresh.oldestDueAgeMs, 29 * 60_000);
  assert.equal(assessNotificationDeliveryHealth(counts({ failed: 1 }), now).level, "attention");
  assert.equal(assessNotificationDeliveryHealth(counts({ leaseMissing: 1 }), now).level, "attention");
  const stalled = assessNotificationDeliveryHealth(counts({ due: 1, failed: 1, leaseMissing: 1, overdue: 1, oldestDueAt: minutesAgo(31) }), now);
  assert.equal(stalled.level, "stalled");
  assert.equal(stalled.oldestDueAgeMs, 31 * 60_000);
  assert.throws(() => assessNotificationDeliveryHealth(counts(), new Date(Number.NaN)), RangeError);
});
