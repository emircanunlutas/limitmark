export const notificationErrorCodes = [
  "timeout",
  "rate_limited",
  "provider_unavailable",
  "rejected",
  "unknown",
] as const;

export type NotificationErrorCode = (typeof notificationErrorCodes)[number];

export type NotificationCommand = {
  /** Stable key that a future provider should use for idempotency. */
  idempotencyKey: string;
  inquiryId: string;
  eventType: string;
};

export type NotificationDeliveryResult =
  | { outcome: "delivered" }
  | { outcome: "retryable_failure"; errorCode: NotificationErrorCode }
  | { outcome: "permanent_failure"; errorCode: NotificationErrorCode };

/** Delivery-only boundary. Implementations must not persist outbox state. */
export interface NotificationAdapter {
  deliver(command: NotificationCommand): Promise<NotificationDeliveryResult>;
}

const allowedErrorCodes = new Set<string>(notificationErrorCodes);

/** Prevent arbitrary provider text from reaching durable operational metadata. */
export function sanitizeNotificationErrorCode(value: unknown): NotificationErrorCode {
  return typeof value === "string" && allowedErrorCodes.has(value)
    ? value as NotificationErrorCode
    : "unknown";
}
