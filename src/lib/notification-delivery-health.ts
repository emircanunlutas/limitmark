import { sanitizeNotificationErrorCode, type NotificationErrorCode } from "./notification-adapter";

/**
 * Product default (documented in README, "Notification delivery health"): a notification that has
 * been eligible for a delivery attempt for 30 minutes OR MORE (inclusive) is OVERDUE, and any overdue
 * notification marks the queue as STALLED: the delivery processor (cron route) is not running or not
 * keeping up. Retry back-off moves `availableAt` into the future, so a correctly scheduled retry is
 * "scheduled", never "due", and never counts toward this threshold however long the back-off is.
 * The SQL aggregate, this model and the UI text all use the same inclusive comparison
 * (`now - eligibleSince >= threshold`). Changing this value changes what administrators are told;
 * update the README alongside it.
 */
export const NOTIFICATION_DELIVERY_OVERDUE_MS = 30 * 60_000;

/** Upper bound on the per-inquiry delivery rows read for the admin detail page. */
export const ADMIN_INQUIRY_DELIVERY_LIMIT = 20;

/**
 * States mirror the outbox processor's claim rule (src/lib/notification-outbox-repository.ts):
 * it claims pending/retryable rows with `available_at <= now` and processing rows with a NON-NULL
 * `locked_until <= now`. A processing row with no lease at all is therefore never reclaimed.
 */
export const notificationDeliveryStates = [
  "due", // pending/retryable, available_at <= now: the next processor run claims it
  "scheduled", // pending/retryable, available_at > now: waiting for its back-off
  "in_progress", // processing, lease held (locked_until > now)
  "lease_expired", // processing, lease ended (locked_until <= now): the next processor run reclaims it
  "lease_missing", // processing with NULL locked_until: never reclaimed automatically
  "delivered",
  "failed", // terminal: never retried automatically
  "unrecognized",
] as const;

export type NotificationDeliveryState = (typeof notificationDeliveryStates)[number];

/** PostgreSQL reads carry epoch microseconds. Date inputs have millisecond precision. */
type DeliveryTimestamp = Date | bigint;
const MICROS_PER_MS = 1_000n;
const OVERDUE_MICROS = BigInt(NOTIFICATION_DELIVERY_OVERDUE_MS) * MICROS_PER_MS;

/** The outbox columns an administrator may see. Recipient, provider and payload data are never read. */
export type NotificationDeliveryRecord = {
  id: string;
  eventType: string;
  status: string;
  attempts: number;
  createdAt: DeliveryTimestamp;
  availableAt: DeliveryTimestamp;
  lockedUntil: DeliveryTimestamp | null;
  sentAt: DeliveryTimestamp | null;
  lastErrorCode: string | null;
};

export type InquiryNotificationDelivery = {
  id: string;
  eventType: string;
  state: NotificationDeliveryState;
  attempts: number;
  queuedAt: Date;
  /** Set only while a retry is scheduled for the future. */
  nextAttemptAt: Date | null;
  /** Set only for delivered notifications. */
  deliveredAt: Date | null;
  /** Always one of the sanitized adapter codes; never provider text. */
  lastErrorCode: NotificationErrorCode | null;
  overdue: boolean;
};

export type NotificationDeliveryCounts = {
  /** pending/retryable rows whose `availableAt` has passed (inclusive). */
  due: number;
  /** pending/retryable rows whose `availableAt` is still in the future. */
  scheduled: number;
  /** processing rows whose lease is still held. */
  inProgress: number;
  /** processing rows whose recorded lease ended; the processor reclaims these. */
  leaseExpired: number;
  /** processing rows with no recorded lease; the processor never reclaims these. */
  leaseMissing: number;
  /** Terminal failures: these will never be retried automatically. */
  failed: number;
  /** due or lease-expired rows eligible for at least NOTIFICATION_DELIVERY_OVERDUE_MS (inclusive). */
  overdue: number;
  /** Earliest moment any due or lease-expired row became eligible. */
  oldestDueAt: DeliveryTimestamp | null;
};

/** Scoped to the observed queue only; none of these levels proves that notifications reach anyone. */
export type NotificationDeliveryQueueLevel = "stalled" | "attention" | "clear";

export type NotificationDeliveryHealth = {
  level: NotificationDeliveryQueueLevel;
  counts: Omit<NotificationDeliveryCounts, "oldestDueAt"> & { oldestDueAt: Date | null };
  oldestDueAgeMs: number | null;
};

const countFields = ["due", "scheduled", "inProgress", "leaseExpired", "leaseMissing", "failed", "overdue"] as const;

function isValidDate(value: unknown): value is Date {
  // Cross-realm safe: a Date built in another VM context fails `instanceof Date`.
  return Object.prototype.toString.call(value) === "[object Date]" && Number.isFinite((value as Date).getTime());
}

function requireDate(name: string, value: unknown): Date {
  if (!isValidDate(value)) throw new RangeError(`${name} must be a valid Date`);
  return value;
}

function requireTimestamp(name: string, value: unknown): DeliveryTimestamp {
  if (typeof value !== "bigint") return requireDate(name, value);
  if (value < -8_640_000_000_000_000_000n || value > 8_640_000_000_000_000_000n) {
    throw new RangeError(`${name} must be a representable timestamp`);
  }
  return value;
}

function asMicros(value: DeliveryTimestamp): bigint {
  return typeof value === "bigint" ? value : BigInt(value.getTime()) * MICROS_PER_MS;
}

function displayDate(value: DeliveryTimestamp): Date {
  return typeof value === "bigint" ? new Date(Number(value / MICROS_PER_MS)) : value;
}

function requireCount(name: string, value: unknown): number {
  let parsed: number;
  if (typeof value === "number") parsed = value;
  else if (typeof value === "bigint") parsed = Number(value);
  else if (typeof value === "string" && /^\d{1,15}$/.test(value)) parsed = Number(value);
  else throw new RangeError(`${name} must be a non-negative integer`);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new RangeError(`${name} must be a non-negative integer`);
  return parsed;
}

/** True when a row eligible since `since` is overdue at `now`. The single inclusive comparison. */
export function isNotificationOverdue(since: DeliveryTimestamp, now: Date): boolean {
  return asMicros(now) - asMicros(since) >= OVERDUE_MICROS;
}

export function deriveNotificationDeliveryState(
  record: Pick<NotificationDeliveryRecord, "status" | "availableAt" | "lockedUntil">,
  now: Date,
): NotificationDeliveryState {
  const at = asMicros(requireDate("now", now));
  switch (record.status) {
    case "sent": return "delivered";
    case "failed": return "failed";
    case "processing":
      if (record.lockedUntil === null) return "lease_missing";
      return asMicros(requireTimestamp("lockedUntil", record.lockedUntil)) > at ? "in_progress" : "lease_expired";
    case "pending":
    case "retryable":
      return asMicros(requireTimestamp("availableAt", record.availableAt)) > at ? "scheduled" : "due";
    default: return "unrecognized";
  }
}

/** When a row became eligible for a claim that has not happened yet, or null (not claimable). */
function eligibleSince(record: NotificationDeliveryRecord, state: NotificationDeliveryState): DeliveryTimestamp | null {
  if (state === "due") return record.availableAt;
  if (state === "lease_expired") return record.lockedUntil;
  return null;
}

export function toInquiryNotificationDelivery(record: NotificationDeliveryRecord, now: Date): InquiryNotificationDelivery {
  const queuedAt = displayDate(requireTimestamp("createdAt", record.createdAt));
  const availableAt = requireTimestamp("availableAt", record.availableAt);
  if (record.lockedUntil !== null) requireTimestamp("lockedUntil", record.lockedUntil);
  const sentAt = record.sentAt === null ? null : displayDate(requireTimestamp("sentAt", record.sentAt));
  const attempts = requireCount("attempts", record.attempts);
  const state = deriveNotificationDeliveryState(record, now);
  const since = eligibleSince(record, state);
  return {
    id: record.id,
    eventType: record.eventType,
    state,
    attempts,
    queuedAt,
    nextAttemptAt: state === "scheduled" ? displayDate(availableAt) : null,
    deliveredAt: state === "delivered" ? sentAt : null,
    lastErrorCode: state === "delivered" || record.lastErrorCode === null ? null : sanitizeNotificationErrorCode(record.lastErrorCode),
    overdue: since !== null && isNotificationOverdue(since, now),
  };
}

/**
 * Validate one aggregate row as read from the database. Drivers return COUNT as number, bigint or
 * decimal string. Database timestamps are decoded to bigint microseconds before validation. A
 * snapshot that contradicts itself, is rejected so the page reports "unavailable".
 */
export function normalizeNotificationDeliveryCounts(row: Record<string, unknown>): NotificationDeliveryCounts {
  const counts = Object.fromEntries(countFields.map((field) => [field, requireCount(field, row[field])])) as Omit<NotificationDeliveryCounts, "oldestDueAt">;
  const rawOldest = row.oldestDueAt;
  let oldestDueAt: DeliveryTimestamp | null;
  if (rawOldest === null || rawOldest === undefined) oldestDueAt = null;
  else if (typeof rawOldest === "string" && /^\d{1,15}$/.test(rawOldest)) oldestDueAt = requireDate("oldestDueAt", new Date(Number(rawOldest)));
  else if (typeof rawOldest === "string") oldestDueAt = requireDate("oldestDueAt", new Date(rawOldest));
  else if (typeof rawOldest === "number") oldestDueAt = requireDate("oldestDueAt", new Date(rawOldest));
  else oldestDueAt = requireTimestamp("oldestDueAt", rawOldest);
  const waiting = counts.due + counts.leaseExpired;
  if (counts.overdue > waiting) throw new RangeError("overdue cannot exceed due and lease-expired notifications");
  if ((oldestDueAt === null) !== (waiting === 0)) throw new RangeError("oldestDueAt must be present exactly when notifications are waiting");
  return { ...counts, oldestDueAt };
}

/**
 * Classify a snapshot taken at `now` (the same instant the query compared against). Besides the
 * structural checks above, the oldest eligible row must not lie in the future, and "some row is
 * overdue" must agree exactly with "the oldest eligible row is overdue"; otherwise it is rejected.
 */
export function assessNotificationDeliveryHealth(counts: NotificationDeliveryCounts, now: Date): NotificationDeliveryHealth {
  const at = asMicros(requireDate("now", now));
  const checked = normalizeNotificationDeliveryCounts(counts);
  if (checked.oldestDueAt !== null) {
    if (asMicros(checked.oldestDueAt) > at) throw new RangeError("oldestDueAt cannot be later than the snapshot time");
    if ((checked.overdue > 0) !== isNotificationOverdue(checked.oldestDueAt, now)) {
      throw new RangeError("overdue count contradicts the oldest eligible notification");
    }
  }
  const level: NotificationDeliveryQueueLevel = checked.overdue > 0
    ? "stalled"
    : checked.failed > 0 || checked.leaseMissing > 0 ? "attention" : "clear";
  return {
    level,
    counts: { ...checked, oldestDueAt: checked.oldestDueAt === null ? null : displayDate(checked.oldestDueAt) },
    oldestDueAgeMs: checked.oldestDueAt === null ? null : Number(at - asMicros(checked.oldestDueAt)) / Number(MICROS_PER_MS),
  };
}
