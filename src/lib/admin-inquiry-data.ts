import "server-only";
import type { AdminInquiryReadRepository } from "./admin-inquiry-repository";
import type { AdminInquiryMutationRepository } from "./admin-inquiry-mutation-repository";
import type { AdminNotificationDeliveryReadRepository } from "./admin-notification-delivery";
import { getAdminDatabaseConfiguration, type AdminDatabaseEnvironment } from "./admin-database-config";

export async function resolveAdminDataRepository<T>(
  environment: AdminDatabaseEnvironment,
  construct: (configuration: { databaseUrl: string; poolMax: number }) => Promise<T>,
): Promise<T | null> {
  const configuration = getAdminDatabaseConfiguration(environment);
  if (!configuration.enabled) return null;
  return construct({ databaseUrl: configuration.databaseUrl, poolMax: configuration.poolMax });
}

export async function getAdminInquiryReadRepository(): Promise<AdminInquiryReadRepository | null> {
  return resolveAdminDataRepository(process.env, async (configuration) => {
    const [{ getDatabase }, { PostgresAdminInquiryReadRepository }] = await Promise.all([
      import("./db/database.server"), import("./admin-inquiry-repository"),
    ]);
    return new PostgresAdminInquiryReadRepository(getDatabase(configuration.databaseUrl, configuration.poolMax));
  });
}

export async function getAdminInquiryMutationRepository(): Promise<AdminInquiryMutationRepository | null> {
  return resolveAdminDataRepository(process.env, async (configuration) => {
    const [{ getDatabase }, { PostgresAdminInquiryMutationRepository }] = await Promise.all([
      import("./db/database.server"), import("./admin-inquiry-mutation-repository"),
    ]);
    return new PostgresAdminInquiryMutationRepository(getDatabase(configuration.databaseUrl, configuration.poolMax));
  });
}

export async function getAdminNotificationDeliveryRepository(): Promise<AdminNotificationDeliveryReadRepository | null> {
  return resolveAdminDataRepository(process.env, async (configuration) => {
    const [{ openNotificationDeliveryConnection }, { PostgresAdminNotificationDeliveryReadRepository }] = await Promise.all([
      import("./admin-notification-delivery-connection"), import("./admin-notification-delivery-repository"),
    ]);
    return new PostgresAdminNotificationDeliveryReadRepository((signal) => openNotificationDeliveryConnection(configuration.databaseUrl, signal));
  });
}
