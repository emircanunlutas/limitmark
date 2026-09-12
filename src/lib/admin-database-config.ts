import { getDatabaseRuntimeConfiguration, type DatabaseRuntimeEnvironment } from "./database-runtime-config";
import { isVercelProduction, type VercelEnvironment } from "./deployment-environment";

export type AdminDatabaseEnvironment = DatabaseRuntimeEnvironment & VercelEnvironment;

export type AdminDatabaseConfiguration =
  | { enabled: false; reason: "deployment-boundary" | "database-url" | "pool-size" }
  | { enabled: true; databaseUrl: string; poolMax: number };

export function getAdminDatabaseConfiguration(
  environment: AdminDatabaseEnvironment,
): AdminDatabaseConfiguration {
  // Check the platform boundary before returning or using any Production data credential.
  if (!isVercelProduction(environment)) return { enabled: false, reason: "deployment-boundary" };
  const database = getDatabaseRuntimeConfiguration(environment);
  if (!database.available) return { enabled: false, reason: database.reason };
  return { enabled: true, databaseUrl: database.databaseUrl, poolMax: database.poolMax };
}
