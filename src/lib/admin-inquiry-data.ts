import "server-only";
import type { AdminInquiryReadRepository } from "./admin-inquiry-repository";
import { getPersistenceConfiguration } from "./persistence-config";

export async function getAdminInquiryReadRepository(): Promise<AdminInquiryReadRepository | null> {
  const configuration = getPersistenceConfiguration(process.env);
  if (!configuration.enabled) return null;
  const [{ getDatabase }, { PostgresAdminInquiryReadRepository }] = await Promise.all([
    import("./db/database.server"), import("./admin-inquiry-repository"),
  ]);
  return new PostgresAdminInquiryReadRepository(getDatabase(configuration.databaseUrl, configuration.poolMax));
}
