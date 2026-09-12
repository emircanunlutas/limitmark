import "server-only";
import type { AdminInquiryReadRepository } from "./admin-inquiry-repository";
import type { AdminInquiryMutationRepository } from "./admin-inquiry-mutation-repository";
import { getPersistenceConfiguration } from "./persistence-config";

export async function getAdminInquiryReadRepository(): Promise<AdminInquiryReadRepository | null> {
  const configuration = getPersistenceConfiguration(process.env);
  if (!configuration.enabled) return null;
  const [{ getDatabase }, { PostgresAdminInquiryReadRepository }] = await Promise.all([
    import("./db/database.server"), import("./admin-inquiry-repository"),
  ]);
  return new PostgresAdminInquiryReadRepository(getDatabase(configuration.databaseUrl, configuration.poolMax));
}

export async function getAdminInquiryMutationRepository(): Promise<AdminInquiryMutationRepository | null> {
  const configuration = getPersistenceConfiguration(process.env);
  if (!configuration.enabled) return null;
  const [{ getDatabase }, { PostgresAdminInquiryMutationRepository }] = await Promise.all([
    import("./db/database.server"), import("./admin-inquiry-mutation-repository"),
  ]);
  return new PostgresAdminInquiryMutationRepository(getDatabase(configuration.databaseUrl, configuration.poolMax));
}
