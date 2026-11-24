import {
  NOTIFICATION_DELIVERY_OVERDUE_MINUTES,
  describeDeliveryConfigurationNote,
  describeInquiryDeliveryUnavailable,
  describeNotificationDeliveryHealth,
  notificationDeliveryCountRows,
  notificationDeliveryStateLabels,
  notificationErrorCodeLabels,
  notificationEventLabel,
  type InquiryNotificationDeliveryView,
  type NotificationDeliveryConfigurationEvidence,
  type NotificationDeliveryHealthView,
} from "../lib/admin-notification-delivery";
import { ADMIN_INQUIRY_DELIVERY_LIMIT } from "../lib/notification-delivery-health";

// Presentation only: no data access, no framework routing imports. Everything rendered is React text.
function formatAdminTimestamp(value: Date): string {
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Istanbul" }).format(value);
}

function Timestamp({ value }: { value: Date }) {
  return <time dateTime={value.toISOString()}>{formatAdminTimestamp(value)}</time>;
}

export function NotificationDeliveryHealthPanel({ view, configuration }: { view: NotificationDeliveryHealthView; configuration: NotificationDeliveryConfigurationEvidence }) {
  const summary = describeNotificationDeliveryHealth(view, configuration);
  const oldestDueAt = view.kind === "ready" ? view.health.counts.oldestDueAt : null;
  return <section className="admin-panel admin-delivery-health" aria-labelledby="delivery-health-heading">
    <h2 id="delivery-health-heading">Notification delivery</h2>
    <div className={`admin-notice admin-notice-${summary.tone}`} role="status"><strong>{summary.title}</strong>{summary.messages.map((message) => <p key={message}>{message}</p>)}</div>
    {view.kind === "ready" && <dl className="admin-delivery-counts">{notificationDeliveryCountRows(view.health.counts).map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>}
    {oldestDueAt && <p className="admin-section-intro">Oldest waiting notification became eligible for delivery <Timestamp value={oldestDueAt} />.</p>}
  </section>;
}

export function InquiryNotificationDeliverySection({ view, configuration }: { view: InquiryNotificationDeliveryView; configuration: NotificationDeliveryConfigurationEvidence }) {
  const note = describeDeliveryConfigurationNote(configuration);
  let body: React.ReactNode;
  if (view.kind !== "ready") body = <p className="admin-notice admin-notice-warning" role="status">{describeInquiryDeliveryUnavailable(view)}</p>;
  else if (!view.deliveries.length) body = <p className="admin-muted admin-neutral-empty">No notifications were queued for this inquiry.</p>;
  else body = <ol className="admin-delivery-list">{view.deliveries.map((delivery) => <li key={delivery.id}>
    <div><strong>{notificationEventLabel(delivery.eventType)}</strong><span className="admin-status">{notificationDeliveryStateLabels[delivery.state]}</span>{delivery.overdue && <span className="admin-status admin-delivery-overdue">Overdue</span>}</div>
    <dl className="admin-delivery-facts">
      <div><dt>Queued</dt><dd><Timestamp value={delivery.queuedAt} /></dd></div>
      <div><dt>Attempts</dt><dd>{delivery.attempts}</dd></div>
      {delivery.deliveredAt && <div><dt>Delivered</dt><dd><Timestamp value={delivery.deliveredAt} /></dd></div>}
      {delivery.nextAttemptAt && <div><dt>Next attempt</dt><dd><Timestamp value={delivery.nextAttemptAt} /></dd></div>}
      {delivery.lastErrorCode && <div><dt>Last error</dt><dd>{notificationErrorCodeLabels[delivery.lastErrorCode]}</dd></div>}
    </dl>
  </li>)}</ol>;
  return <section className="admin-panel" aria-labelledby="delivery-heading">
    <h2 id="delivery-heading">Notification delivery</h2>
    <p className="admin-section-intro">Internal alerts queued for this inquiry, oldest first. Read-only. Overdue means eligible for a delivery attempt for {NOTIFICATION_DELIVERY_OVERDUE_MINUTES} minutes or more.{view.kind === "ready" && view.truncated && ` Showing the first ${ADMIN_INQUIRY_DELIVERY_LIMIT} notifications.`}</p>
    {note && <p className="admin-notice admin-notice-warning" role="status">{note}</p>}
    {body}
  </section>;
}
