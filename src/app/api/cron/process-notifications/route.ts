import "server-only";

import { getDatabase } from "@/lib/db/database.server";
import { getNotificationCronConfiguration, isAuthorizedCronRequest } from "@/lib/notification-cron-config";
import { getNotificationAdapter } from "@/lib/resend-notification-adapter";
import { PostgresNotificationOutboxRepository } from "@/lib/notification-outbox-repository";
import { processOutboxBatch } from "@/lib/outbox-processor";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const noStoreHeaders = {
  "cache-control": "private, no-store, max-age=0, must-revalidate",
  "cdn-cache-control": "no-store",
  "vercel-cdn-cache-control": "no-store",
} as const;

// Next.js otherwise auto-implements HEAD by invoking GET, which would process
// the outbox for a second HTTP method.
export function HEAD(): Response {
  return new Response(null, { status: 405, headers: noStoreHeaders });
}

/**
 * Delivery entry point for the Phase 2A/2B outbox: still provider- and
 * scheduler-neutral (`processOutboxBatch` itself takes no dependency on this
 * route), but this is now the one reviewed way to actually invoke it. Nothing
 * calls this on a schedule by itself; wiring an actual Vercel Cron Job (or an
 * equivalent external scheduler) against it, with `CRON_SECRET` configured, is
 * a separate deployment decision left to the operator.
 */
export async function GET(request: Request): Promise<Response> {
  try {
    const configuration = getNotificationCronConfiguration(process.env);
    if (!configuration.enabled || !isAuthorizedCronRequest(request.headers, configuration.cronSecret)) {
      return new Response(null, { status: 404 });
    }

    const notificationAdapter = getNotificationAdapter(process.env);
    if (!notificationAdapter.available) {
      // Nothing to attempt yet; leave every outbox row untouched rather than
      // burning a retry attempt against an unconfigured provider.
      return Response.json(
        { ok: true, claimed: 0, sent: 0, retryable: 0, failed: 0, leaseLost: 0, reason: "notifications-not-configured" },
        { headers: noStoreHeaders },
      );
    }

    const repository = new PostgresNotificationOutboxRepository(
      getDatabase(configuration.databaseUrl, configuration.poolMax),
    );
    const summary = await processOutboxBatch({
      repository,
      adapter: notificationAdapter.adapter,
      now: new Date(),
    });
    return Response.json({ ok: true, ...summary }, { headers: noStoreHeaders });
  } catch {
    // Database/adapter construction failures never expose connection or
    // provider detail; the next invocation retries naturally.
    return Response.json({ ok: false }, { status: 503, headers: noStoreHeaders });
  }
}
