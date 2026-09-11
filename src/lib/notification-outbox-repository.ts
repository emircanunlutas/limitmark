import { and, asc, eq, inArray, lte, or, sql } from "drizzle-orm";
import type { PostgresJsDatabase } from "drizzle-orm/postgres-js";
import type { NotificationErrorCode } from "./notification-adapter";
import { notificationOutbox } from "./db/schema";
import * as schema from "./db/schema";

export type ClaimedNotification = {
  outboxId: string;
  inquiryId: string;
  eventType: string;
  attempts: number;
  /** Optimistic ownership token used to reject a stale worker's outcome. */
  lockedUntil: Date;
};

export type ClaimNotificationsInput = {
  now: Date;
  lockedUntil: Date;
  batchSize: number;
};

export type CompleteNotificationInput = {
  outboxId: string;
  attempts: number;
  lockedUntil: Date;
  now: Date;
};

export type FailNotificationInput = CompleteNotificationInput & {
  errorCode: NotificationErrorCode;
  retryAt: Date | null;
};

export interface NotificationOutboxRepository {
  claimBatch(input: ClaimNotificationsInput): Promise<ClaimedNotification[]>;
  markSent(input: CompleteNotificationInput): Promise<boolean>;
  markFailure(input: FailNotificationInput): Promise<boolean>;
}

export class PostgresNotificationOutboxRepository implements NotificationOutboxRepository {
  constructor(private readonly database: PostgresJsDatabase<typeof schema>) {}

  async claimBatch(input: ClaimNotificationsInput): Promise<ClaimedNotification[]> {
    return this.database.transaction(async (transaction) => {
      const candidates = await transaction.select({ id: notificationOutbox.id })
        .from(notificationOutbox)
        .where(or(
          and(
            inArray(notificationOutbox.status, ["pending", "retryable"]),
            lte(notificationOutbox.availableAt, input.now),
          ),
          and(
            eq(notificationOutbox.status, "processing"),
            lte(notificationOutbox.lockedUntil, input.now),
          ),
        ))
        .orderBy(
          asc(notificationOutbox.availableAt),
          asc(notificationOutbox.createdAt),
          asc(notificationOutbox.id),
        )
        .limit(input.batchSize)
        .for("update", { skipLocked: true });

      if (candidates.length === 0) return [];

      return transaction.update(notificationOutbox).set({
        status: "processing",
        lockedUntil: input.lockedUntil,
        attempts: sql`${notificationOutbox.attempts} + 1`,
      }).where(inArray(notificationOutbox.id, candidates.map(({ id }) => id))).returning({
        outboxId: notificationOutbox.id,
        inquiryId: notificationOutbox.inquiryId,
        eventType: notificationOutbox.eventType,
        attempts: notificationOutbox.attempts,
        lockedUntil: notificationOutbox.lockedUntil,
      }).then((rows) => rows.map((row) => ({
        ...row,
        // The UPDATE always sets this non-null value in the same statement.
        lockedUntil: row.lockedUntil!,
      })));
    });
  }

  async markSent(input: CompleteNotificationInput): Promise<boolean> {
    const updated = await this.database.update(notificationOutbox).set({
      status: "sent",
      sentAt: input.now,
      lockedUntil: null,
      lastErrorCode: null,
    }).where(this.ownedLease(input)).returning({ id: notificationOutbox.id });
    return updated.length === 1;
  }

  async markFailure(input: FailNotificationInput): Promise<boolean> {
    const updated = await this.database.update(notificationOutbox).set({
      status: input.retryAt ? "retryable" : "failed",
      ...(input.retryAt ? { availableAt: input.retryAt } : {}),
      lockedUntil: null,
      sentAt: null,
      lastErrorCode: input.errorCode,
    }).where(this.ownedLease(input)).returning({ id: notificationOutbox.id });
    return updated.length === 1;
  }

  private ownedLease(input: CompleteNotificationInput) {
    return and(
      eq(notificationOutbox.id, input.outboxId),
      eq(notificationOutbox.status, "processing"),
      eq(notificationOutbox.attempts, input.attempts),
      eq(notificationOutbox.lockedUntil, input.lockedUntil),
    );
  }
}
