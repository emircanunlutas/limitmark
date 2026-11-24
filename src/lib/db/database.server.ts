import "server-only";
import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import postgres, { type Sql } from "postgres";
import * as schema from "./schema";

type DatabaseState = {
  client: Sql;
  database: PostgresJsDatabase<typeof schema>;
  databaseUrl: string;
  poolMax: number;
};

const globalDatabase = globalThis as typeof globalThis & { __inquiryDatabase?: DatabaseState };

export function getDatabaseClientOptions(poolMax: number) {
  return {
    max: poolMax,
    idle_timeout: 20,
    connect_timeout: 5,
    prepare: false,
  };
}

export function getDatabase(databaseUrl: string, poolMax: number): PostgresJsDatabase<typeof schema> {
  const existing = globalDatabase.__inquiryDatabase;
  if (existing) {
    if (existing.databaseUrl !== databaseUrl || existing.poolMax !== poolMax) {
      throw new Error("Database configuration changed after initialization");
    }
    return existing.database;
  }

  const client = postgres(databaseUrl, getDatabaseClientOptions(poolMax));
  const database = drizzle(client, { schema });
  globalDatabase.__inquiryDatabase = { client, database, databaseUrl, poolMax };
  return database;
}
