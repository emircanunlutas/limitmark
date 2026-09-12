export type DatabaseRuntimeEnvironment = {
  [key: string]: string | undefined;
  DATABASE_URL?: string;
  DATABASE_POOL_MAX?: string;
};

export type DatabaseRuntimeConfiguration =
  | { available: false; reason: "database-url" | "pool-size" }
  | { available: true; databaseUrl: string; poolMax: number };

function validDatabaseUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === "postgres:" || url.protocol === "postgresql:") &&
      Boolean(url.hostname && url.username && url.password && url.pathname.slice(1));
  } catch {
    return false;
  }
}

/** Server-only values describe database availability, independently of public intake. */
export function getDatabaseRuntimeConfiguration(
  environment: DatabaseRuntimeEnvironment,
): DatabaseRuntimeConfiguration {
  const databaseUrl = environment.DATABASE_URL?.trim() ?? "";
  if (!validDatabaseUrl(databaseUrl)) return { available: false, reason: "database-url" };
  const poolMax = environment.DATABASE_POOL_MAX === undefined ? 5 : Number(environment.DATABASE_POOL_MAX);
  if (!Number.isSafeInteger(poolMax) || poolMax < 1 || poolMax > 10) {
    return { available: false, reason: "pool-size" };
  }
  return { available: true, databaseUrl, poolMax };
}
