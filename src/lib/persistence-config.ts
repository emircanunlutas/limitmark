import { getDatabaseRuntimeConfiguration, type DatabaseRuntimeEnvironment } from "./database-runtime-config";

export type PersistenceEnvironment = DatabaseRuntimeEnvironment & {
  REQUEST_SUBMISSION_MODE?: string;
  ENABLE_PERSISTENT_SUBMISSIONS?: string;
};

export type PersistenceConfiguration =
  | { enabled: false; reason: "mode" | "gate" | "database-url" | "pool-size" }
  | { enabled: true; databaseUrl: string; poolMax: number };

export function getPersistenceConfiguration(environment: PersistenceEnvironment): PersistenceConfiguration {
  if (environment.REQUEST_SUBMISSION_MODE !== "postgres") return { enabled: false, reason: "mode" };
  if (environment.ENABLE_PERSISTENT_SUBMISSIONS !== "true") return { enabled: false, reason: "gate" };
  const database = getDatabaseRuntimeConfiguration(environment);
  if (!database.available) return { enabled: false, reason: database.reason };
  return { enabled: true, databaseUrl: database.databaseUrl, poolMax: database.poolMax };
}
