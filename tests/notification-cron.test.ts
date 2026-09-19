import assert from "node:assert/strict";
import test from "node:test";
import {
  getNotificationCronConfiguration,
  isAuthorizedCronRequest,
  type NotificationCronEnvironment,
} from "../src/lib/notification-cron-config";
import { GET, HEAD } from "../src/app/api/cron/process-notifications/route";

const cronSecret = "A".repeat(43);
const baseEnvironment: NotificationCronEnvironment = {
  VERCEL: "1",
  VERCEL_ENV: "production",
  CRON_SECRET: cronSecret,
  DATABASE_URL: "postgresql://runtime:synthetic@db.example.test/app",
  DATABASE_POOL_MAX: "5",
};

test("notification cron configuration requires exact Production, a bearer-shaped secret and a valid database", () => {
  assert.deepEqual(getNotificationCronConfiguration(baseEnvironment), {
    enabled: true,
    databaseUrl: baseEnvironment.DATABASE_URL,
    poolMax: 5,
    cronSecret,
  });

  for (const change of [
    { VERCEL: undefined }, { VERCEL_ENV: "preview" }, { VERCEL_ENV: undefined },
  ]) {
    assert.deepEqual(getNotificationCronConfiguration({ ...baseEnvironment, ...change }), { enabled: false, reason: "deployment-boundary" });
  }

  for (const CRON_SECRET of [undefined, "", "short", "A".repeat(31), "A".repeat(257), `${cronSecret}\n`, "A B".repeat(20)]) {
    assert.deepEqual(getNotificationCronConfiguration({ ...baseEnvironment, CRON_SECRET }), { enabled: false, reason: "secret" });
  }

  assert.deepEqual(getNotificationCronConfiguration({ ...baseEnvironment, DATABASE_URL: undefined }), { enabled: false, reason: "database-url" });
  assert.deepEqual(getNotificationCronConfiguration({ ...baseEnvironment, DATABASE_POOL_MAX: "0" }), { enabled: false, reason: "pool-size" });
});

test("cron authorization is an exact, timing-safe bearer match independent of configuration parsing", () => {
  const headers = (value: string | null) => new Headers(value === null ? {} : { authorization: value });

  assert.equal(isAuthorizedCronRequest(headers(`Bearer ${cronSecret}`), cronSecret), true);
  assert.equal(isAuthorizedCronRequest(headers(null), cronSecret), false);
  assert.equal(isAuthorizedCronRequest(headers(""), cronSecret), false);
  assert.equal(isAuthorizedCronRequest(headers(`bearer ${cronSecret}`), cronSecret), false);
  assert.equal(isAuthorizedCronRequest(headers(cronSecret), cronSecret), false);
  assert.equal(isAuthorizedCronRequest(headers(`Bearer ${cronSecret}x`), cronSecret), false);
  assert.equal(isAuthorizedCronRequest(headers(`Bearer ${"B".repeat(43)}`), cronSecret), false);
  assert.equal(isAuthorizedCronRequest(headers(`Bearer ${cronSecret}, Bearer ${cronSecret}`), cronSecret), false);
});

test("the actual cron route denies unauthenticated and Preview requests before outbox access", async () => {
  const previous = Object.fromEntries(Object.keys(baseEnvironment).map((key) => [key, process.env[key]]));
  const previousGate = process.env.ENABLE_REAL_NOTIFICATIONS;
  try {
    Object.assign(process.env, baseEnvironment);
    process.env.ENABLE_REAL_NOTIFICATIONS = "false";
    const url = "https://limitmark.com/api/cron/process-notifications?job=arbitrary&provider=arbitrary";
    for (const authorization of [undefined, "", `Bearer ${"B".repeat(43)}`, `Bearer ${cronSecret}, Bearer ${cronSecret}`]) {
      const headers = authorization === undefined ? undefined : { authorization };
      const response = await GET(new Request(url, { headers }));
      assert.equal(response.status, 404);
      assert.equal(await response.text(), "");
    }
    process.env.VERCEL_ENV = "preview";
    assert.equal((await GET(new Request(url, { headers: { authorization: `Bearer ${cronSecret}` } }))).status, 404);
    process.env.VERCEL_ENV = "production";
    const response = await GET(new Request(url, { headers: { authorization: `Bearer ${cronSecret}` } }));
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      ok: true, claimed: 0, sent: 0, retryable: 0, failed: 0, leaseLost: 0, reason: "notifications-not-configured",
    });
    assert.match(response.headers.get("cache-control")!, /no-store/);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    if (previousGate === undefined) delete process.env.ENABLE_REAL_NOTIFICATIONS;
    else process.env.ENABLE_REAL_NOTIFICATIONS = previousGate;
  }
});

test("HEAD cannot use Next.js GET auto-implementation to process the outbox", async () => {
  const response = HEAD();
  assert.equal(response.status, 405);
  assert.equal(await response.text(), "");
  assert.match(response.headers.get("cache-control")!, /no-store/);
});
