export type PersistenceEnvironment = {
  [key: string]: string | undefined;
  REQUEST_SUBMISSION_MODE?: string;
  ENABLE_PERSISTENT_SUBMISSIONS?: string;
  DATABASE_URL?: string;
  DATABASE_POOL_MAX?: string;
};

export type PersistenceConfiguration =
  | { enabled: false; reason: "mode" | "gate" | "database-url" | "pool-size" }
  | { enabled: true; databaseUrl: string; poolMax: number };

function validDatabaseUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === "postgres:" || url.protocol === "postgresql:") &&
      Boolean(url.hostname && url.username && url.password && url.pathname.slice(1));
  } catch {
    return false;
  }
}

export function getPersistenceConfiguration(environment: PersistenceEnvironment): PersistenceConfiguration {
  if (environment.REQUEST_SUBMISSION_MODE !== "postgres") return { enabled: false, reason: "mode" };
  if (environment.ENABLE_PERSISTENT_SUBMISSIONS !== "true") return { enabled: false, reason: "gate" };
  const databaseUrl = environment.DATABASE_URL?.trim() ?? "";
  if (!validDatabaseUrl(databaseUrl)) return { enabled: false, reason: "database-url" };
  const poolMax = environment.DATABASE_POOL_MAX === undefined ? 5 : Number(environment.DATABASE_POOL_MAX);
  if (!Number.isSafeInteger(poolMax) || poolMax < 1 || poolMax > 10) return { enabled: false, reason: "pool-size" };
  return { enabled: true, databaseUrl, poolMax };
}
