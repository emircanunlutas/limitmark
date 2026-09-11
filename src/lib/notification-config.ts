import { getContactEmail } from "./contact-email";

export type NotificationEnvironment = {
  [key: string]: string | undefined;
  ENABLE_REAL_NOTIFICATIONS?: string;
  RESEND_API_KEY?: string;
  NOTIFICATION_FROM_EMAIL?: string;
  NOTIFICATION_TO_EMAIL?: string;
};

export type NotificationConfiguration =
  | { enabled: false; reason: "gate" | "api-key" | "sender" | "recipient" }
  | { enabled: true; apiKey: string; fromEmail: string; toEmail: string };

function getApiKey(value: string | undefined): string | null {
  const key = value?.trim() ?? "";
  return /^re_[A-Za-z0-9_-]+$/.test(key) && key.length <= 512 ? key : null;
}

/** Pure fail-closed parser; safe to unit test without constructing a provider client. */
export function getNotificationConfiguration(
  environment: NotificationEnvironment,
): NotificationConfiguration {
  if (environment.ENABLE_REAL_NOTIFICATIONS !== "true") {
    return { enabled: false, reason: "gate" };
  }

  const apiKey = getApiKey(environment.RESEND_API_KEY);
  if (!apiKey) return { enabled: false, reason: "api-key" };

  const fromEmail = getContactEmail(environment.NOTIFICATION_FROM_EMAIL);
  if (!fromEmail) return { enabled: false, reason: "sender" };

  const toEmail = getContactEmail(environment.NOTIFICATION_TO_EMAIL);
  if (!toEmail) return { enabled: false, reason: "recipient" };

  return { enabled: true, apiKey, fromEmail, toEmail };
}
