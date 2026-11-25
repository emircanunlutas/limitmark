import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import type { Sql } from "postgres";
import { InquiryNotificationDeliverySection, NotificationDeliveryHealthPanel } from "../src/components/admin-notification-delivery";
import {
  ADMIN_NOTIFICATION_DELIVERY_DEADLINE_MS,
  NotificationDeliveryDeadlineError,
  describeNotificationDeliveryHealth,
  loadInquiryNotificationDeliveries,
  loadNotificationDeliveryHealth,
  type AdminNotificationDeliveryReadRepository,
  type InquiryNotificationDeliveryView,
  type NotificationDeliveryConfigurationEvidence,
  type NotificationDeliveryHealthView,
} from "../src/lib/admin-notification-delivery";
import { getNotificationDeliveryConfigurationEvidence } from "../src/lib/admin-notification-delivery-config";
import {
  ADMIN_NOTIFICATION_DELIVERY_STATEMENT_TIMEOUT_MS,
  PostgresAdminNotificationDeliveryReadRepository,
} from "../src/lib/admin-notification-delivery-repository";
import {
  ADMIN_INQUIRY_DELIVERY_LIMIT,
  NOTIFICATION_DELIVERY_OVERDUE_MS,
  assessNotificationDeliveryHealth,
  toInquiryNotificationDelivery,
  type NotificationDeliveryCounts,
  type NotificationDeliveryRecord,
} from "../src/lib/notification-delivery-health";

const now = new Date("2026-11-24T12:00:00.000Z");
const minutesAgo = (minutes: number) => new Date(now.getTime() - minutes * 60_000);
const inquiryId = "00000000-0000-4000-8000-000000000042";
const flush = () => new Promise<void>((resolve) => setImmediate(resolve));
const never = <T>() => new Promise<T>(() => {});

function counts(overrides: Partial<NotificationDeliveryCounts> = {}): NotificationDeliveryCounts {
  return { due: 0, scheduled: 0, inProgress: 0, leaseExpired: 0, leaseMissing: 0, failed: 0, overdue: 0, oldestDueAt: null, ...overrides };
}

function outboxRecord(overrides: Partial<NotificationDeliveryRecord> = {}): NotificationDeliveryRecord {
  return {
    id: "00000000-0000-4000-8000-0000000000b1", eventType: "inquiry_received", status: "sent", attempts: 1,
    createdAt: minutesAgo(10), availableAt: minutesAgo(10), lockedUntil: null, sentAt: minutesAgo(9), lastErrorCode: null,
    ...overrides,
  };
}

function factoryOf(overrides: Partial<AdminNotificationDeliveryReadRepository> = {}) {
  const repository: AdminNotificationDeliveryReadRepository = {
    getDeliveryCounts: async () => counts(),
    listInquiryDeliveries: async () => [],
    ...overrides,
  };
  return async () => repository;
}

const failingFactory = async (): Promise<AdminNotificationDeliveryReadRepository> => { throw new Error("connect ECONNREFUSED 10.0.0.5:5432 private detail"); };

// ---------------------------------------------------------------- loaders and deadline

test("loaders distinguish unconfigured, unavailable and ready, and never reject", async () => {
  assert.deepEqual(await loadNotificationDeliveryHealth(async () => null, now), { kind: "unconfigured" });
  assert.deepEqual(await loadNotificationDeliveryHealth(failingFactory, now), { kind: "unavailable" });
  assert.deepEqual(await loadNotificationDeliveryHealth(() => { throw new Error("synchronous factory failure"); }, now), { kind: "unavailable" });
  assert.deepEqual(await loadNotificationDeliveryHealth(factoryOf({ getDeliveryCounts: async () => { throw new Error("permission denied"); } }), now), { kind: "unavailable" });
  assert.deepEqual(await loadNotificationDeliveryHealth(factoryOf({ getDeliveryCounts: async () => counts({ due: 2 }) }), now), { kind: "unavailable" });
  const view = await loadNotificationDeliveryHealth(factoryOf({ getDeliveryCounts: async () => counts({ failed: 1 }) }), now);
  assert.equal(view.kind === "ready" && view.health.level, "attention");

  assert.deepEqual(await loadInquiryNotificationDeliveries(async () => null, inquiryId, now), { kind: "unconfigured" });
  assert.deepEqual(await loadInquiryNotificationDeliveries(failingFactory, inquiryId, now), { kind: "unavailable" });
  assert.deepEqual(await loadInquiryNotificationDeliveries(factoryOf({ listInquiryDeliveries: async () => [outboxRecord({ createdAt: new Date("invalid") })] }), inquiryId, now), { kind: "unavailable" });
  assert.deepEqual(await loadInquiryNotificationDeliveries(factoryOf({ listInquiryDeliveries: async () => ({}) as unknown as NotificationDeliveryRecord[] }), inquiryId, now), { kind: "unavailable" });
});

test("a stalled delivery read is abandoned at exactly the deadline and its signal is aborted", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let observed: AbortSignal | undefined;
  const pending = loadNotificationDeliveryHealth(factoryOf({ getDeliveryCounts: (_at, signal) => { observed = signal; return never(); } }), now);
  let settled = false;
  void pending.then(() => { settled = true; });
  await flush();
  assert.ok(observed);
  t.mock.timers.tick(ADMIN_NOTIFICATION_DELIVERY_DEADLINE_MS - 1);
  await flush();
  assert.equal(settled, false);
  assert.equal(observed.aborted, false);
  t.mock.timers.tick(1);
  assert.deepEqual(await pending, { kind: "unavailable" });
  assert.equal(observed.aborted, true);
  assert.ok(observed.reason instanceof NotificationDeliveryDeadlineError);
});

test("the deadline also bounds repository construction and per-inquiry reads, and honours a custom value", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const construction = loadNotificationDeliveryHealth(() => never(), now);
  t.mock.timers.tick(ADMIN_NOTIFICATION_DELIVERY_DEADLINE_MS);
  assert.deepEqual(await construction, { kind: "unavailable" });

  let observed: AbortSignal | undefined;
  const detail = loadInquiryNotificationDeliveries(factoryOf({ listInquiryDeliveries: (_id, _limit, signal) => { observed = signal; return never(); } }), inquiryId, now, { deadlineMs: 50 });
  await flush();
  t.mock.timers.tick(50);
  assert.deepEqual(await detail, { kind: "unavailable" });
  assert.equal(observed?.aborted, true);
  await assert.doesNotReject(loadNotificationDeliveryHealth(factoryOf(), now, { deadlineMs: 0 }));
  assert.deepEqual(await loadNotificationDeliveryHealth(factoryOf(), now, { deadlineMs: 0 }), { kind: "unavailable" });
});

test("a read that finishes in time is not aborted and clears its deadline", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let observed: AbortSignal | undefined;
  const view = await loadNotificationDeliveryHealth(factoryOf({ getDeliveryCounts: async (_at, signal) => { observed = signal; return counts(); } }), now);
  assert.equal(view.kind, "ready");
  t.mock.timers.tick(ADMIN_NOTIFICATION_DELIVERY_DEADLINE_MS * 2);
  assert.equal(observed?.aborted, false);
});

test("per-inquiry reads are bounded and report truncation", async () => {
  const rows = Array.from({ length: ADMIN_INQUIRY_DELIVERY_LIMIT + 1 }, (_, index) => outboxRecord({ id: `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}` }));
  const requested: Array<[string, number]> = [];
  const view = await loadInquiryNotificationDeliveries(factoryOf({ listInquiryDeliveries: async (id, limit) => { requested.push([id, limit]); return rows.slice(0, limit); } }), inquiryId, now);
  assert.deepEqual(requested, [[inquiryId, ADMIN_INQUIRY_DELIVERY_LIMIT + 1]]);
  assert.equal(view.kind === "ready" && view.deliveries.length, ADMIN_INQUIRY_DELIVERY_LIMIT);
  assert.equal(view.kind === "ready" && view.truncated, true);
});

// ---------------------------------------------------------------- repository: read-only, server timeout, cancellation

type Issued = { text: string; values: unknown[] };
function fakeConnection(respond: (statement: Issued) => Promise<unknown[]>) {
  const issued: Issued[] = [];
  let closed = 0;
  const sql = (strings: TemplateStringsArray, ...values: unknown[]) => {
    const statement = { text: strings.join("$"), values };
    if (statement.text === "begin read only") {
      begins.push(statement.text);
      return Promise.resolve([]);
    }
    issued.push(statement);
    return respond(statement);
  };
  const begins: string[] = [];
  const open = () => ({ client: sql as unknown as Sql, close: async () => { closed += 1; } });
  return { open, issued, begins, get closed() { return closed; } };
}

const micros = (date: Date) => BigInt(date.getTime()) * 1_000n;
const aggregateRow = { due: 1, scheduled: 0, inProgress: 0, leaseExpired: 0, leaseMissing: 2, failed: 0, overdue: 1, oldestDueAt: String(micros(minutesAgo(45))) };

test("counts run in a READ ONLY transaction with transaction-local server timeouts set first", async () => {
  const fake = fakeConnection(async (statement) => statement.text.includes("set_config") ? [{}] : [aggregateRow]);
  const repository = new PostgresAdminNotificationDeliveryReadRepository(fake.open);
  const result = await repository.getDeliveryCounts(now, new AbortController().signal);
  assert.deepEqual(result, { ...aggregateRow, oldestDueAt: micros(minutesAgo(45)) });
  assert.equal(fake.closed, 1);
  assert.deepEqual(fake.begins, ["begin read only"]);
  assert.equal(fake.issued.length, 2);
  const timeout = String(ADMIN_NOTIFICATION_DELIVERY_STATEMENT_TIMEOUT_MS);
  assert.match(fake.issued[0].text, /set_config\('statement_timeout', \$, true\), set_config\('lock_timeout', \$, true\), set_config\('idle_in_transaction_session_timeout', \$, true\)/);
  assert.deepEqual(fake.issued[0].values, [timeout, timeout, timeout]);
  assert.ok(ADMIN_NOTIFICATION_DELIVERY_STATEMENT_TIMEOUT_MS < ADMIN_NOTIFICATION_DELIVERY_DEADLINE_MS);
  // The aggregate mirrors the claim rule and the inclusive threshold.
  const aggregate = fake.issued[1];
  assert.match(aggregate.text, /when status = 'processing' and locked_until is null then 'lease_missing'/);
  assert.match(aggregate.text, /when status = 'processing' and locked_until <= \$::timestamptz then locked_until/);
  assert.match(aggregate.text, /count\(\*\) filter \(where eligible_since <= \$::timestamptz\)\)::int as "overdue"/);
  assert.ok(aggregate.values.includes(now.toISOString()));
  assert.ok(aggregate.values.includes(new Date(now.getTime() - NOTIFICATION_DELIVERY_OVERDUE_MS).toISOString()));
});

test("counts and detail preserve eligibility and the overdue threshold at microsecond precision", async () => {
  const cutoff = micros(minutesAgo(30));
  const at = micros(now);
  const makeRow = (status: string, availableAt: bigint, lockedUntil: bigint | null = null) => ({
    ...outboxRecord({ status, sentAt: null }),
    createdAt: String(cutoff),
    availableAt: String(availableAt),
    lockedUntil: lockedUntil === null ? null : String(lockedUntil),
  });
  const fake = fakeConnection(async (statement) => {
    if (statement.text.includes("set_config")) return [{}];
    assert.doesNotMatch(statement.text, /date_trunc/);
    if (statement.text.includes("with classified")) {
      assert.match(statement.text, /extract\(epoch from min\(eligible_since\)\) \* 1000000/);
      return [{ ...aggregateRow, overdue: 0, oldestDueAt: String(cutoff + 1n) }];
    }
    return [
      makeRow("pending", at + 1n), makeRow("processing", cutoff, at + 1n),
      makeRow("pending", cutoff + 1n), makeRow("processing", cutoff, cutoff + 1n),
      makeRow("pending", cutoff), makeRow("processing", cutoff, cutoff),
    ];
  });
  const repository = new PostgresAdminNotificationDeliveryReadRepository(fake.open);
  const signal = new AbortController().signal;
  const aggregate = await repository.getDeliveryCounts(now, signal);
  assert.equal(aggregate.oldestDueAt, cutoff + 1n);
  assert.equal(assessNotificationDeliveryHealth(aggregate, now).level, "attention");
  assert.throws(() => assessNotificationDeliveryHealth({ ...aggregate, overdue: 1 }, now), /contradicts/);
  const detail = (await repository.listInquiryDeliveries(inquiryId, 6, signal))
    .map((row) => toInquiryNotificationDelivery(row, now));
  assert.deepEqual(detail.map(({ state, overdue }) => [state, overdue]), [
    ["scheduled", false], ["in_progress", false], ["due", false], ["lease_expired", false],
    ["due", true], ["lease_expired", true],
  ]);
});

test("per-inquiry rows are scoped, bounded and mapped from epoch microseconds", async () => {
  const fake = fakeConnection(async (statement) => statement.text.includes("set_config") ? [{}] : [{
    id: "00000000-0000-4000-8000-0000000000c1", eventType: "inquiry_received", status: "processing", attempts: 1, lastErrorCode: null,
    createdAt: String(micros(minutesAgo(50))), availableAt: String(micros(minutesAgo(50))), lockedUntil: null, sentAt: null,
  }]);
  const repository = new PostgresAdminNotificationDeliveryReadRepository(fake.open);
  const rows = await repository.listInquiryDeliveries(inquiryId, ADMIN_INQUIRY_DELIVERY_LIMIT + 1, new AbortController().signal);
  assert.deepEqual(rows, [{
    id: "00000000-0000-4000-8000-0000000000c1", eventType: "inquiry_received", status: "processing", attempts: 1, lastErrorCode: null,
    createdAt: micros(minutesAgo(50)), availableAt: micros(minutesAgo(50)), lockedUntil: null, sentAt: null,
  }]);
  assert.equal(toInquiryNotificationDelivery(rows[0], now).state, "lease_missing");
  assert.deepEqual(fake.issued[1].values, [inquiryId, String(ADMIN_INQUIRY_DELIVERY_LIMIT + 1)]);
  assert.match(fake.issued[1].text, /where inquiry_id = \$::uuid\s+order by created_at asc, id asc\s+limit \$::int/);
  for (const limit of [0, 101, 1.5]) await assert.rejects(repository.listInquiryDeliveries(inquiryId, limit, new AbortController().signal), RangeError);
  const bad = fakeConnection(async (statement) => statement.text.includes("set_config") ? [{}] : [{ ...outboxRecord(), createdAt: "2026-11-24 12:00:00+00" }]);
  await assert.rejects(new PostgresAdminNotificationDeliveryReadRepository(bad.open).listInquiryDeliveries(inquiryId, 1, new AbortController().signal), RangeError);
  assert.equal(bad.closed, 1);
});

test("the repository source is read-only, selects no customer or payload columns, and uses transaction-local limits", async () => {
  const source = await readFile(new URL("../src/lib/admin-notification-delivery-repository.ts", import.meta.url), "utf8");
  assert.match(source, /^import "server-only";/);
  const statements = [...source.matchAll(/sql(?:<[^>]+>)?\`([^\`]*)\`/g)].map((match) => match[1]);
  assert.equal(statements.length, 4);
  for (const statement of statements) {
    assert.match(statement.trim(), /^(select|with)\b|^begin read only$/);
    assert.doesNotMatch(statement, /\b(insert|update|delete|truncate|alter|grant|for update|for share)\b/i);
    assert.doesNotMatch(statement, /\b(name|email|company|submission_token|payload_fingerprint|metadata|inquiries)\b/);
  }
  assert.doesNotMatch(source, /\.unsafe\(|\.file\(|sql\.raw/);
  assert.equal(statements.filter((statement) => statement === "begin read only").length, 1);
  assert.equal((source.match(/this\.readOnly\(signal/g) ?? []).length, 2);
});

// ---------------------------------------------------------------- configuration evidence

const completeEnvironment = {
  VERCEL: "1", VERCEL_ENV: "production",
  ENABLE_REAL_NOTIFICATIONS: "true", RESEND_API_KEY: "re_synthetic_unit_test_key",
  NOTIFICATION_FROM_EMAIL: "notifications@example.test", NOTIFICATION_TO_EMAIL: "internal@example.test",
  CRON_SECRET: "S".repeat(40), DATABASE_URL: "postgresql://runtime:synthetic@db.example.test/app",
};

test("configuration evidence comes from the cron route's own parsers and exposes only an enum", () => {
  assert.deepEqual(getNotificationDeliveryConfigurationEvidence(completeEnvironment), { state: "configured" });
  assert.deepEqual(getNotificationDeliveryConfigurationEvidence({ ...completeEnvironment, ENABLE_REAL_NOTIFICATIONS: "false" }), { state: "disabled", reason: "provider" });
  assert.deepEqual(getNotificationDeliveryConfigurationEvidence({ ...completeEnvironment, RESEND_API_KEY: "not-a-key" }), { state: "disabled", reason: "provider" });
  assert.deepEqual(getNotificationDeliveryConfigurationEvidence({ ...completeEnvironment, CRON_SECRET: "short" }), { state: "disabled", reason: "processor" });
  const throwing = new Proxy({}, { get() { throw new Error("environment exploded"); } });
  assert.deepEqual(getNotificationDeliveryConfigurationEvidence(throwing), { state: "unknown" });
  assert.doesNotMatch(JSON.stringify(getNotificationDeliveryConfigurationEvidence(completeEnvironment)), /re_|example\.test|SSSS/);
});

// ---------------------------------------------------------------- wording and rendering (real React elements, no framework shim)

type ReactLike = { type: unknown; props: Record<string, unknown> };
const escapeText = (value: string) => value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
function render(node: unknown): string {
  if (node === null || node === undefined || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return escapeText(String(node));
  if (Array.isArray(node)) return node.map(render).join("");
  const { type, props } = node as ReactLike;
  if (typeof type === "function") return render((type as (input: unknown) => unknown)(props));
  const inner = render(props.children);
  if (typeof type !== "string") return inner; // Fragment
  const attributes = ["id", "className", "role", "dateTime"].filter((name) => typeof props[name] === "string").map((name) => ` ${name}="${props[name]}"`).join("");
  return `<${type}${attributes}>${inner}</${type}>`;
}

const configured: NotificationDeliveryConfigurationEvidence = { state: "configured" };
const ready = (value: NotificationDeliveryCounts): NotificationDeliveryHealthView => ({ kind: "ready", health: assessNotificationDeliveryHealth(value, now) });
const panel = (view: NotificationDeliveryHealthView, configuration: NotificationDeliveryConfigurationEvidence = configured) =>
  render(NotificationDeliveryHealthPanel({ view, configuration }));

test("a clear queue is scoped to the queue and never claims delivery works", () => {
  for (const [view, title] of [[ready(counts()), "Delivery queue empty"], [ready(counts({ due: 2, scheduled: 1, oldestDueAt: minutesAgo(5) })), "No delivery backlog detected"]] as const) {
    const summary = describeNotificationDeliveryHealth(view, configured);
    assert.equal(summary.tone, "neutral");
    assert.equal(summary.title, title);
    assert.match(summary.messages.join(" "), /describes the queue only; it does not confirm that notifications reach their recipients/);
    assert.match(summary.messages.join(" "), /whether a scheduler invokes the delivery processor is not visible here/);
    assert.doesNotMatch(JSON.stringify(summary), /healthy|operational|working/i);
  }
  const html = panel(ready(counts()));
  assert.match(html, /<div className="admin-notice admin-notice-neutral" role="status"><strong>Delivery queue empty<\/strong>/);
  assert.match(html, /<dt>Overdue \(30\+ min\)<\/dt><dd>0<\/dd>/);
  assert.match(html, /<dt>Stuck without a lease<\/dt><dd>0<\/dd>/);
});

test("stalled, lease-less, failed, disabled and unreadable states are warnings with accurate recovery text", () => {
  const stalled = panel(ready(counts({ due: 2, overdue: 1, failed: 1, leaseMissing: 1, oldestDueAt: minutesAgo(40) })));
  assert.match(stalled, /admin-notice-warning" role="status"><strong>Notification delivery stalled<\/strong>/);
  assert.match(stalled, /1 notification has been waiting 30 minutes or more for a delivery attempt\. The delivery processor may not be running or keeping up\./);
  assert.match(stalled, /1 notification is marked in progress without a lease\. The delivery processor only reclaims expired leases, so it will never retry them automatically/);
  assert.match(stalled, /1 notification has failed permanently/);
  assert.match(stalled, /Oldest waiting notification became eligible for delivery <time dateTime="2026-11-24T11:20:00.000Z">/);

  const missing = describeNotificationDeliveryHealth(ready(counts({ leaseMissing: 3 })), configured);
  assert.equal(missing.title, "Notification delivery needs attention");
  assert.match(missing.messages[0], /^3 notifications are marked in progress without a lease/);
  const interrupted = describeNotificationDeliveryHealth(ready(counts({ leaseExpired: 1, oldestDueAt: minutesAgo(1) })), configured);
  assert.equal(interrupted.title, "No delivery backlog detected");

  const disabled = describeNotificationDeliveryHealth(ready(counts({ due: 1, overdue: 1, oldestDueAt: minutesAgo(31) })), { state: "disabled", reason: "processor" });
  assert.equal(disabled.title, "Notification delivery disabled");
  assert.match(disabled.messages[0], /cron secret is not configured/);
  assert.doesNotMatch(disabled.messages.join(" "), /may not be running/);
  assert.equal(describeNotificationDeliveryHealth(ready(counts()), { state: "disabled", reason: "provider" }).title, "Notification delivery disabled");

  for (const view of [{ kind: "unavailable" }, { kind: "unconfigured" }] as const) {
    const summary = describeNotificationDeliveryHealth(view, configured);
    assert.equal(summary.tone, "warning");
    assert.match(summary.messages.join(" "), /This is not a clear result/);
    assert.match(panel(view), new RegExp(`<strong>${summary.title}</strong>`));
    assert.doesNotMatch(panel(view), /<dl/);
  }
});

test("the inquiry section shows lease-less and failed rows with sanitized facts and a disabled-delivery note", () => {
  const deliveries = [
    outboxRecord({ id: "00000000-0000-4000-8000-0000000000c1", status: "failed", attempts: 5, sentAt: null, lastErrorCode: "<b>provider said no</b>" }),
    outboxRecord({ id: "00000000-0000-4000-8000-0000000000c2", status: "processing", attempts: 1, sentAt: null, lockedUntil: null }),
    outboxRecord({ id: "00000000-0000-4000-8000-0000000000c3", status: "pending", attempts: 0, sentAt: null, availableAt: minutesAgo(30), createdAt: minutesAgo(30) }),
    outboxRecord({ id: "00000000-0000-4000-8000-0000000000c4" }),
  ].map((row) => toInquiryNotificationDelivery(row, now));
  const view: InquiryNotificationDeliveryView = { kind: "ready", deliveries, truncated: false };
  const html = render(InquiryNotificationDeliverySection({ view, configuration: { state: "disabled", reason: "provider" } }));
  assert.match(html, /Overdue means eligible for a delivery attempt for 30 minutes or more\./);
  assert.match(html, /<p className="admin-notice admin-notice-warning" role="status">Real notification delivery is not enabled/);
  assert.match(html, /Failed permanently<\/span>/);
  assert.match(html, /<dt>Last error<\/dt><dd>Unknown error<\/dd>/);
  assert.doesNotMatch(html, /provider said no/);
  assert.match(html, /Stuck: in progress without a lease<\/span><\/div>/);
  assert.match(html, /Waiting for delivery<\/span><span className="admin-status admin-delivery-overdue">Overdue<\/span>/);
  assert.match(html, /<dt>Delivered<\/dt>/);

  const unavailable = render(InquiryNotificationDeliverySection({ view: { kind: "unavailable" }, configuration: configured }));
  assert.match(unavailable, /Delivery status unavailable\. It could not be read in time; this does not mean the notification was delivered\./);
  assert.match(render(InquiryNotificationDeliverySection({ view: { kind: "ready", deliveries: [], truncated: false }, configuration: configured })), /No notifications were queued for this inquiry\./);
});

// ---------------------------------------------------------------- page wiring (source; the pages import next/link, which cannot load under react-server)

test("admin routes authorize first, read deliveries only through the bounded loaders, and stay presentation-only", async () => {
  const [listSource, detailSource, componentSource] = await Promise.all([
    readFile(new URL("../src/app/admin/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../src/app/admin/inquiries/[id]/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../src/components/admin-notification-delivery.tsx", import.meta.url), "utf8"),
  ]);
  const listLoad = listSource.indexOf("loadNotificationDeliveryHealth(getDeliveryRepository, now())");
  const inquiryLoad = listSource.indexOf("InquiryList({ query, repository })");
  assert.ok(listSource.indexOf("await authorize();") < listLoad);
  assert.ok(listSource.indexOf("if (!repository)") < listLoad);
  assert.ok(listLoad < inquiryLoad, "the delivery read runs concurrently with, not before, the list");
  assert.ok(inquiryLoad < listSource.indexOf("deliveryHealth = await deliveryHealthPromise;"));
  const detailLoad = detailSource.indexOf("await loadInquiryNotificationDeliveries(getDeliveryRepository, detail.inquiry.id, now())");
  assert.ok(detailSource.indexOf("await authorize();") < detailLoad);
  assert.ok(detailSource.indexOf("if (!detail) notFound();") < detailLoad);
  for (const source of [listSource, detailSource]) {
    assert.equal((source.match(/getDeliveryRepository/g) ?? []).length, 2, "declared once, passed only to the loader");
    assert.doesNotMatch(source, /notificationOutbox|notification_outbox|\$client|dangerouslySetInnerHTML/);
  }
  assert.doesNotMatch(componentSource, /from "(next\/|postgres|drizzle|server-only)|Repository|\$client|dangerouslySetInnerHTML/);
});
