import "server-only";
import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import postgres, { type Sql } from "postgres";
import * as schema from "./schema";

type DatabaseState = {
  client: Sql;
  database: PostgresJsDatabase<typeof schema>;
  databaseUrl: string;
  poolMax: number;
  tlsKey?: string;
};

const globalDatabase = globalThis as typeof globalThis & { __inquiryDatabase?: DatabaseState };

export type DatabaseTlsConfiguration = {
  ca: string;
  servername: string;
};

export function getDatabaseClientOptions(poolMax: number, tls?: DatabaseTlsConfiguration) {
  return {
    max: poolMax,
    idle_timeout: 20,
    connect_timeout: 5,
    prepare: false,
    ...(tls ? {
      ssl: {
        ca: tls.ca,
        rejectUnauthorized: true,
        servername: tls.servername,
      },
    } : {}),
  };
}

export function getDatabase(
  databaseUrl: string,
  poolMax: number,
  tls?: DatabaseTlsConfiguration,
): PostgresJsDatabase<typeof schema> {
  const tlsKey = tls ? `${tls.servername}\u0000${tls.ca}` : undefined;
  const existing = globalDatabase.__inquiryDatabase;
  if (existing) {
    if (existing.databaseUrl !== databaseUrl || existing.poolMax !== poolMax || existing.tlsKey !== tlsKey) {
      throw new Error("Database configuration changed after initialization");
    }
    return existing.database;
  }

  const clientOptions = getDatabaseClientOptions(poolMax, tls);
  const client = postgres(databaseUrl, clientOptions);
  const database = drizzle(client, { schema });
  globalDatabase.__inquiryDatabase = { client, database, databaseUrl, poolMax, tlsKey };
  return database;
}
