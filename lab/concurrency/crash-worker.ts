/** Claims a bounded batch and then dies abruptly (SIGKILL) without completing it. Lab use only. */
import { writeSync } from "node:fs";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "../../src/lib/db/schema";
import { PostgresNotificationOutboxRepository } from "../../src/lib/notification-outbox-repository";

async function main(): Promise<void> {
  const url = process.env.LAB_RUNTIME_URL;
  const now = new Date(process.env.LAB_NOW ?? "");
  const lockedUntil = new Date(process.env.LAB_LOCKED_UNTIL ?? "");
  const batchSize = Number(process.env.LAB_BATCH);
  if (!url || !Number.isFinite(now.getTime()) || !Number.isFinite(lockedUntil.getTime()) || !Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 10) {
    throw new Error("invalid crash-worker configuration");
  }
  const client = postgres(url, { max: 1, prepare: false, connect_timeout: 5 });
  const repository = new PostgresNotificationOutboxRepository(drizzle(client, { schema }));
  const claimed = await repository.claimBatch({ now, lockedUntil, batchSize });
  writeSync(1, `${JSON.stringify(claimed.map((job) => job.outboxId))}\n`);
  process.kill(process.pid, "SIGKILL");
}

main().catch(() => process.exit(2));
