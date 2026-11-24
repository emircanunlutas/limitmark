import "server-only";

import { addAbortListener } from "node:events";
import type { Sql } from "postgres";
import type { NotificationDeliveryConnection } from "./admin-notification-delivery-connection";
import {
  ADMIN_NOTIFICATION_DELIVERY_DEADLINE_MS,
  type AdminNotificationDeliveryReadRepository,
} from "./admin-notification-delivery";
import {
  NOTIFICATION_DELIVERY_OVERDUE_MS,
  normalizeNotificationDeliveryCounts,
  type NotificationDeliveryCounts,
  type NotificationDeliveryRecord,
} from "./notification-delivery-health";

/**
 * Transaction-local limits for the read, lock waits and idle time after setup. The separate client
 * deadline covers connection startup, setup and transaction cleanup too.
 */
export const ADMIN_NOTIFICATION_DELIVERY_STATEMENT_TIMEOUT_MS = 2_500;
const MAX_INQUIRY_DELIVERY_ROWS = 100;
// Do not queue delivery work or multiply database connections under concurrent dashboard traffic.
const MAX_CONCURRENT_DELIVERY_READS = 2;
let activeDeliveryReads = 0;

if (ADMIN_NOTIFICATION_DELIVERY_STATEMENT_TIMEOUT_MS >= ADMIN_NOTIFICATION_DELIVERY_DEADLINE_MS) {
  throw new Error("the server-side statement timeout must be shorter than the client deadline");
}

/** postgres.js returns int8 as text by default. Keep all six fractional digits for comparisons. */
function epochMicros(name: string, value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "string" && /^-?\d{1,19}$/.test(value)) return BigInt(value);
  throw new RangeError(`${name} must be epoch microseconds`);
}

type CountsRow = Record<string, unknown>;
type DeliveryRow = {
  id: string; eventType: string; status: string; attempts: number; lastErrorCode: string | null;
  createdAt: unknown; availableAt: unknown; lockedUntil: unknown; sentAt: unknown;
};

/**
 * Read-only outbox projection for authorized administrators. Every statement runs in a READ ONLY
 * transaction, so PostgreSQL itself rejects any write; only state, attempt, timestamp and the
 * already-sanitized error-code columns are selected. It never claims, leases, retries or resets rows.
 */
export class PostgresAdminNotificationDeliveryReadRepository implements AdminNotificationDeliveryReadRepository {
  constructor(
    private readonly openConnection: (signal: AbortSignal) => NotificationDeliveryConnection,
    private readonly statementTimeoutMs = ADMIN_NOTIFICATION_DELIVERY_STATEMENT_TIMEOUT_MS,
  ) {
    if (!Number.isSafeInteger(statementTimeoutMs) || statementTimeoutMs < 1) throw new RangeError("statementTimeoutMs must be a positive safe integer");
  }

  private async readOnly<T>(signal: AbortSignal, read: (sql: Sql) => Promise<T>): Promise<T> {
    signal.throwIfAborted();
    if (activeDeliveryReads >= MAX_CONCURRENT_DELIVERY_READS) throw new Error("delivery read capacity exhausted");
    activeDeliveryReads += 1;
    try {
      const connection = this.openConnection(signal);
      // The driver can still have an outstanding promise during startup failures. Release the
      // delivery slot after closing the transport even if that promise never settles.
      let abortListener: ReturnType<typeof addAbortListener> | undefined;
      const aborted = new Promise<never>((_resolve, reject) => {
        abortListener = addAbortListener(signal, () => reject(signal.reason));
      });
      try {
        return await Promise.race([this.readTransaction(connection.client, signal, read), aborted]);
      } finally {
        abortListener?.[Symbol.dispose]();
        await connection.close();
      }
    } finally {
      activeDeliveryReads -= 1;
    }
  }

  private async readTransaction<T>(sql: Sql, signal: AbortSignal, read: (sql: Sql) => Promise<T>): Promise<T> {
    // The private max:1 client runs this sequence on one socket and cannot reconnect.
    // Disconnect ends the read-only transaction without waiting for COMMIT or ROLLBACK.
    signal.throwIfAborted();
    await sql`begin read only`;
    signal.throwIfAborted();
    const timeout = String(this.statementTimeoutMs);
    await sql`select set_config('statement_timeout', ${timeout}, true), set_config('lock_timeout', ${timeout}, true), set_config('idle_in_transaction_session_timeout', ${timeout}, true)`;
    signal.throwIfAborted();
    return read(sql);
  }

  async getDeliveryCounts(now: Date, signal: AbortSignal): Promise<NotificationDeliveryCounts> {
    if (!Number.isFinite(now.getTime())) throw new RangeError("now must be a valid Date");
    const at = now.toISOString();
    // Inclusive threshold: eligible_since <= now - 30 min  <=>  now - eligible_since >= 30 min.
    const overdueBefore = new Date(now.getTime() - NOTIFICATION_DELIVERY_OVERDUE_MS).toISOString();
    return this.readOnly(signal, async (sql) => {
      // Mirrors the processor's claim rule: pending/retryable with available_at <= now, and processing
      // with a NON-NULL locked_until <= now. A NULL lease is never claimable, so it is counted separately
      // and has no eligible_since. All comparisons use PostgreSQL's full timestamp precision.
      const rows = await sql<CountsRow[]>`
        with classified as (
          select
            case
              when status in ('pending', 'retryable') and available_at <= ${at}::timestamptz then 'due'
              when status in ('pending', 'retryable') then 'scheduled'
              when status = 'processing' and locked_until is null then 'lease_missing'
              when status = 'processing' and locked_until > ${at}::timestamptz then 'in_progress'
              when status = 'processing' then 'lease_expired'
              else 'failed'
            end as state,
            case
              when status in ('pending', 'retryable') and available_at <= ${at}::timestamptz then available_at
              when status = 'processing' and locked_until <= ${at}::timestamptz then locked_until
            end as eligible_since
          from notification_outbox
          where status in ('pending', 'retryable', 'processing', 'failed')
        )
        select
          (count(*) filter (where state = 'due'))::int as "due",
          (count(*) filter (where state = 'scheduled'))::int as "scheduled",
          (count(*) filter (where state = 'in_progress'))::int as "inProgress",
          (count(*) filter (where state = 'lease_expired'))::int as "leaseExpired",
          (count(*) filter (where state = 'lease_missing'))::int as "leaseMissing",
          (count(*) filter (where state = 'failed'))::int as "failed",
          (count(*) filter (where eligible_since <= ${overdueBefore}::timestamptz))::int as "overdue",
          (extract(epoch from min(eligible_since)) * 1000000)::bigint as "oldestDueAt"
        from classified`;
      if (rows.length !== 1) throw new Error("aggregate query must return exactly one row");
      const [row] = rows;
      return normalizeNotificationDeliveryCounts({
        ...row,
        oldestDueAt: row.oldestDueAt === null ? null : epochMicros("oldestDueAt", row.oldestDueAt),
      });
    });
  }

  async listInquiryDeliveries(inquiryId: string, limit: number, signal: AbortSignal): Promise<NotificationDeliveryRecord[]> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_INQUIRY_DELIVERY_ROWS) {
      throw new RangeError(`limit must be an integer from 1 through ${MAX_INQUIRY_DELIVERY_ROWS}`);
    }
    return this.readOnly(signal, async (sql) => {
      const rows = await sql<DeliveryRow[]>`
        select
          id::text as "id",
          event_type::text as "eventType",
          status::text as "status",
          attempts as "attempts",
          last_error_code as "lastErrorCode",
          (extract(epoch from created_at) * 1000000)::bigint as "createdAt",
          (extract(epoch from available_at) * 1000000)::bigint as "availableAt",
          (extract(epoch from locked_until) * 1000000)::bigint as "lockedUntil",
          (extract(epoch from sent_at) * 1000000)::bigint as "sentAt"
        from notification_outbox
        where inquiry_id = ${inquiryId}::uuid
        order by created_at asc, id asc
        limit ${String(limit)}::int`;
      return rows.map((row) => ({
        id: row.id,
        eventType: row.eventType,
        status: row.status,
        attempts: row.attempts,
        lastErrorCode: row.lastErrorCode,
        createdAt: epochMicros("createdAt", row.createdAt),
        availableAt: epochMicros("availableAt", row.availableAt),
        lockedUntil: row.lockedUntil === null ? null : epochMicros("lockedUntil", row.lockedUntil),
        sentAt: row.sentAt === null ? null : epochMicros("sentAt", row.sentAt),
      }));
    });
  }
}
