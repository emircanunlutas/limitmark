import "server-only";

import { timingSafeEqual } from "node:crypto";
import { Buffer } from "node:buffer";
import { getDatabaseRuntimeConfiguration, type DatabaseRuntimeEnvironment } from "./database-runtime-config";
import { isVercelProduction, type VercelEnvironment } from "./deployment-environment";
import type { HeaderReader } from "./client-identity";

export type NotificationCronEnvironment = DatabaseRuntimeEnvironment & VercelEnvironment & {
  [key: string]: string | undefined;
  CRON_SECRET?: string;
};

export type NotificationCronConfiguration =
  | { enabled: false; reason: "deployment-boundary" | "secret" | "database-url" | "pool-size" }
  | { enabled: true; databaseUrl: string; poolMax: number; cronSecret: string };

/** Same bearer-token shape already used for the admin gateway's automation bypass secret. */
function isCronSecret(value: string | undefined): value is string {
  return typeof value === "string" && /^[\x21-\x7e]{32,256}$/u.test(value);
}

/** Pure fail-closed parser. Independent of the public submission and admin gates:
 * outbox delivery must keep working even while public intake or admin access is closed. */
export function getNotificationCronConfiguration(
  environment: NotificationCronEnvironment,
): NotificationCronConfiguration {
  if (!isVercelProduction(environment)) return { enabled: false, reason: "deployment-boundary" };
  if (!isCronSecret(environment.CRON_SECRET)) return { enabled: false, reason: "secret" };
  const database = getDatabaseRuntimeConfiguration(environment);
  if (!database.available) return { enabled: false, reason: database.reason };
  return { enabled: true, databaseUrl: database.databaseUrl, poolMax: database.poolMax, cronSecret: environment.CRON_SECRET! };
}

/**
 * Vercel Cron Jobs automatically send `Authorization: Bearer $CRON_SECRET` when a
 * `CRON_SECRET` environment variable is configured; this independently re-verifies
 * that header so the route never trusts invocation source or hostname alone.
 */
export function isAuthorizedCronRequest(headers: HeaderReader, cronSecret: string): boolean {
  const expected = Buffer.from(`Bearer ${cronSecret}`);
  const received = Buffer.from(headers.get("authorization") ?? "");
  if (received.length !== expected.length) return false;
  return timingSafeEqual(expected, received);
}
