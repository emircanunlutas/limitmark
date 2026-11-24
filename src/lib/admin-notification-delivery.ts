import type { NotificationErrorCode } from "./notification-adapter";
import {
  ADMIN_INQUIRY_DELIVERY_LIMIT,
  NOTIFICATION_DELIVERY_OVERDUE_MS,
  assessNotificationDeliveryHealth,
  toInquiryNotificationDelivery,
  type InquiryNotificationDelivery,
  type NotificationDeliveryCounts,
  type NotificationDeliveryHealth,
  type NotificationDeliveryRecord,
  type NotificationDeliveryState,
} from "./notification-delivery-health";

/**
 * Client-side deadline for every admin delivery read. The repository also sets a shorter server-side
 * statement_timeout, so PostgreSQL normally cancels a slow statement first; this deadline is the
 * backstop for a connection that cannot be obtained or a server that does not answer. When it fires,
 * the repository closes the transport for that read, including during startup and transaction cleanup.
 */
export const ADMIN_NOTIFICATION_DELIVERY_DEADLINE_MS = 3_000;

/** Read-only view of the notification outbox for authorized administrators. */
export interface AdminNotificationDeliveryReadRepository {
  /** Aggregate delivery counts as of `now`. Must stop work and reject once `signal` aborts. */
  getDeliveryCounts(now: Date, signal: AbortSignal): Promise<NotificationDeliveryCounts>;
  /** Oldest first, at most `limit` rows for one inquiry. Must stop work and reject once `signal` aborts. */
  listInquiryDeliveries(inquiryId: string, limit: number, signal: AbortSignal): Promise<NotificationDeliveryRecord[]>;
}

export type AdminNotificationDeliveryRepositoryFactory = () => Promise<AdminNotificationDeliveryReadRepository | null>;

/**
 * What this runtime's own configuration says about delivery, from the same fail-closed parsers the
 * cron route uses. "configured" only means the settings are present: whether a scheduler actually
 * invokes the processor is not observable from here.
 */
export type NotificationDeliveryConfigurationEvidence =
  | { state: "configured" }
  | { state: "disabled"; reason: "provider" | "processor" }
  | { state: "unknown" };

/** "unconfigured" and "unavailable" are never presented as a clear queue. */
export type NotificationDeliveryHealthView =
  | { kind: "unconfigured" }
  | { kind: "unavailable" }
  | { kind: "ready"; health: NotificationDeliveryHealth };

export type InquiryNotificationDeliveryView =
  | { kind: "unconfigured" }
  | { kind: "unavailable" }
  | { kind: "ready"; deliveries: InquiryNotificationDelivery[]; truncated: boolean };

export class NotificationDeliveryDeadlineError extends Error {
  constructor() { super("notification delivery read exceeded its deadline"); this.name = "NotificationDeliveryDeadlineError"; }
}

const TIMED_OUT = Symbol("timed-out");

/**
 * Runs `read` with an AbortSignal that aborts after `deadlineMs`. Resolves TIMED_OUT at the deadline
 * even if `read` ignores the signal; a later rejection of `read` is already handled by the race.
 */
async function withDeadline<T>(deadlineMs: number, read: (signal: AbortSignal) => Promise<T>): Promise<T | typeof TIMED_OUT> {
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1) throw new RangeError("deadlineMs must be a positive safe integer");
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<typeof TIMED_OUT>((resolve) => {
    timer = setTimeout(() => { controller.abort(new NotificationDeliveryDeadlineError()); resolve(TIMED_OUT); }, deadlineMs);
  });
  try {
    return await Promise.race([read(controller.signal), deadline]);
  } finally {
    clearTimeout(timer);
  }
}

type LoadOptions = { deadlineMs?: number };

async function load<T, V>(
  getRepository: AdminNotificationDeliveryRepositoryFactory,
  options: LoadOptions,
  read: (repository: AdminNotificationDeliveryReadRepository, signal: AbortSignal) => Promise<T>,
  ready: (value: T) => V,
): Promise<V | { kind: "unconfigured" } | { kind: "unavailable" }> {
  try {
    // Repository construction and the read share one deadline.
    const result = await withDeadline(options.deadlineMs ?? ADMIN_NOTIFICATION_DELIVERY_DEADLINE_MS, async (signal) => {
      const repository = await getRepository();
      if (!repository) return null;
      signal.throwIfAborted();
      return { value: await read(repository, signal) };
    });
    if (result === TIMED_OUT) return { kind: "unavailable" };
    if (result === null) return { kind: "unconfigured" };
    return ready(result.value);
  } catch {
    // Construction, query, timeout and validation failures are deliberately indistinguishable and detail-free.
    return { kind: "unavailable" };
  }
}

/** Never rejects and never takes longer than the deadline; see ADMIN_NOTIFICATION_DELIVERY_DEADLINE_MS. */
export async function loadNotificationDeliveryHealth(
  getRepository: AdminNotificationDeliveryRepositoryFactory,
  now: Date,
  options: LoadOptions = {},
): Promise<NotificationDeliveryHealthView> {
  return load(getRepository, options, (repository, signal) => repository.getDeliveryCounts(now, signal),
    (counts) => ({ kind: "ready" as const, health: assessNotificationDeliveryHealth(counts, now) }));
}

/** Never rejects and never takes longer than the deadline; see ADMIN_NOTIFICATION_DELIVERY_DEADLINE_MS. */
export async function loadInquiryNotificationDeliveries(
  getRepository: AdminNotificationDeliveryRepositoryFactory,
  inquiryId: string,
  now: Date,
  options: LoadOptions = {},
): Promise<InquiryNotificationDeliveryView> {
  return load(getRepository, options, (repository, signal) => repository.listInquiryDeliveries(inquiryId, ADMIN_INQUIRY_DELIVERY_LIMIT + 1, signal),
    (rows) => {
      if (!Array.isArray(rows)) throw new TypeError("delivery rows must be an array");
      return {
        kind: "ready" as const,
        deliveries: rows.slice(0, ADMIN_INQUIRY_DELIVERY_LIMIT).map((row) => toInquiryNotificationDelivery(row, now)),
        truncated: rows.length > ADMIN_INQUIRY_DELIVERY_LIMIT,
      };
    });
}

export const NOTIFICATION_DELIVERY_OVERDUE_MINUTES = NOTIFICATION_DELIVERY_OVERDUE_MS / 60_000;

export const notificationDeliveryStateLabels: Record<NotificationDeliveryState, string> = {
  due: "Waiting for delivery",
  scheduled: "Retry scheduled",
  in_progress: "Delivery in progress",
  lease_expired: "Interrupted: next processor run reclaims it",
  lease_missing: "Stuck: in progress without a lease",
  delivered: "Delivered",
  failed: "Failed permanently",
  unrecognized: "Unrecognized state",
};

export const notificationErrorCodeLabels: Record<NotificationErrorCode, string> = {
  timeout: "Provider timed out",
  rate_limited: "Provider rate limited",
  provider_unavailable: "Provider unavailable",
  rejected: "Rejected by provider",
  unknown: "Unknown error",
};

const notificationEventLabels: Record<string, string> = { inquiry_received: "New inquiry alert" };

export function notificationEventLabel(eventType: string): string {
  return Object.hasOwn(notificationEventLabels, eventType) ? notificationEventLabels[eventType] : "Notification";
}

export type NotificationDeliveryHealthSummary = { tone: "warning" | "neutral"; title: string; messages: string[] };

function countOf(count: number, verb: "has" | "is"): string {
  const plural = verb === "has" ? "have" : "are";
  return count === 1 ? `1 notification ${verb}` : `${count} notifications ${plural}`;
}

const disabledMessages: Record<"provider" | "processor", string> = {
  provider: "Real notification delivery is not enabled or is incompletely configured in this deployment, so queued notifications are not being sent.",
  processor: "The delivery processor's cron secret is not configured in this deployment, so the processor cannot run and queued notifications are not being sent.",
};

const QUEUE_SCOPE = "This describes the queue only; it does not confirm that notifications reach their recipients.";

export function describeNotificationDeliveryHealth(
  view: NotificationDeliveryHealthView,
  configuration: NotificationDeliveryConfigurationEvidence = { state: "unknown" },
): NotificationDeliveryHealthSummary {
  const disabled = configuration.state === "disabled" ? [disabledMessages[configuration.reason]] : [];
  if (view.kind === "unconfigured") {
    return { tone: "warning", title: "Delivery status not configured", messages: [...disabled, "Notification delivery status is not available in this deployment. This is not a clear result."] };
  }
  if (view.kind === "unavailable") {
    return { tone: "warning", title: "Delivery status unavailable", messages: [...disabled, "Notification delivery status could not be read in time. This is not a clear result; try again later."] };
  }
  const { level, counts } = view.health;
  const problems: string[] = [];
  if (counts.overdue > 0) {
    problems.push(`${countOf(counts.overdue, "has")} been waiting ${NOTIFICATION_DELIVERY_OVERDUE_MINUTES} minutes or more for a delivery attempt.${disabled.length ? "" : " The delivery processor may not be running or keeping up."}`);
  }
  if (counts.leaseMissing > 0) {
    problems.push(`${countOf(counts.leaseMissing, "is")} marked in progress without a lease. The delivery processor only reclaims expired leases, so it will never retry them automatically; they need manual investigation.`);
  }
  if (counts.failed > 0) {
    problems.push(`${countOf(counts.failed, "has")} failed permanently and will not be retried. Follow up with the affected customers directly.`);
  }
  if (disabled.length) return { tone: "warning", title: "Notification delivery disabled", messages: [...disabled, ...problems] };
  if (level === "stalled") return { tone: "warning", title: "Notification delivery stalled", messages: problems };
  if (level === "attention") return { tone: "warning", title: "Notification delivery needs attention", messages: problems };
  const queued = counts.due + counts.scheduled + counts.inProgress + counts.leaseExpired;
  return {
    tone: "neutral",
    title: queued === 0 ? "Delivery queue empty" : "No delivery backlog detected",
    messages: [
      queued === 0
        ? "No notifications are waiting, in progress or failed."
        : `No notification has waited ${NOTIFICATION_DELIVERY_OVERDUE_MINUTES} minutes or more, none is stuck without a lease, and none has failed permanently.`,
      QUEUE_SCOPE,
      ...(configuration.state === "configured" ? ["Delivery settings are present; whether a scheduler invokes the delivery processor is not visible here."] : []),
    ],
  };
}

export function notificationDeliveryCountRows(counts: NotificationDeliveryCounts): Array<readonly [label: string, value: number]> {
  return [
    ["Waiting for delivery", counts.due],
    ["Retry scheduled", counts.scheduled],
    ["In progress", counts.inProgress],
    ["Interrupted (reclaimable)", counts.leaseExpired],
    ["Stuck without a lease", counts.leaseMissing],
    ["Failed permanently", counts.failed],
    [`Overdue (${NOTIFICATION_DELIVERY_OVERDUE_MINUTES}+ min)`, counts.overdue],
  ];
}

export function describeInquiryDeliveryUnavailable(view: Exclude<InquiryNotificationDeliveryView, { kind: "ready" }>): string {
  return view.kind === "unconfigured"
    ? "Delivery status is not configured in this deployment."
    : "Delivery status unavailable. It could not be read in time; this does not mean the notification was delivered.";
}

export function describeDeliveryConfigurationNote(configuration: NotificationDeliveryConfigurationEvidence): string | null {
  return configuration.state === "disabled" ? disabledMessages[configuration.reason] : null;
}
