import "server-only";

import type { NotificationDeliveryConfigurationEvidence } from "./admin-notification-delivery";
import { getNotificationConfiguration, type NotificationEnvironment } from "./notification-config";
import { getNotificationCronConfiguration, type NotificationCronEnvironment } from "./notification-cron-config";

/**
 * Reliable evidence only: the same pure parsers the cron route (/api/cron/process-notifications) runs
 * against the same runtime environment. Only an enum leaves this function; no secret, address or
 * parser reason is exposed. A parser failure is reported as "unknown", never as "configured".
 */
export function getNotificationDeliveryConfigurationEvidence(
  environment: NotificationEnvironment & NotificationCronEnvironment,
): NotificationDeliveryConfigurationEvidence {
  try {
    if (!getNotificationConfiguration(environment).enabled) return { state: "disabled", reason: "provider" };
    if (!getNotificationCronConfiguration(environment).enabled) return { state: "disabled", reason: "processor" };
    return { state: "configured" };
  } catch {
    return { state: "unknown" };
  }
}
