import "server-only";
import { postResendEmail } from "./resend-transport";
import type {
  NotificationAdapter,
  NotificationCommand,
  NotificationDeliveryResult,
} from "./notification-adapter";
import {
  getNotificationConfiguration,
  type NotificationEnvironment,
} from "./notification-config";

export const resendRequestTimeoutMs = 10_000;

type ResendSendRequest = {
  from: string;
  to: string[];
  subject: string;
  text: string;
};

type ResendSendResult =
  | { accepted: true }
  | { accepted: false; statusCode: number | null; errorName: string | null; retryAfterMs?: number };

export interface ResendEmailClient {
  send(request: ResendSendRequest, idempotencyKey: string): Promise<ResendSendResult>;
}

function readErrorName(value: unknown): string | null {
  if (!value || typeof value !== "object") return null;
  const name = Reflect.get(value, "name");
  return typeof name === "string" ? name : null;
}

function readRetryAfterMs(value: string | null): number | undefined {
  if (!value) return undefined;
  if (/^\d+$/.test(value)) {
    // Saturate before passing the duration to the outbox's configured delay cap.
    const duration = Math.min(Number(value) * 1000, Number.MAX_SAFE_INTEGER);
    return duration > 0 ? duration : undefined;
  }

  // Date.parse alone also accepts values such as "-2" and comma-separated numbers.
  const date = new Date(value);
  if (date.toUTCString() !== value) return undefined;
  const remaining = date.getTime() - Date.now();
  return remaining > 0 ? remaining : undefined;
}

/** Minimal typed Resend HTTPS client. It never logs or returns response bodies/messages. */
export class ResendHttpClient implements ResendEmailClient {
  constructor(
    private readonly apiKey: string,
    private readonly timeoutMs = resendRequestTimeoutMs,
  ) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
      throw new RangeError("timeoutMs must be a positive safe integer");
    }
  }

  async send(request: ResendSendRequest, idempotencyKey: string): Promise<ResendSendResult> {
    const { response, retryAfter } = await postResendEmail({
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey,
        "User-Agent": "resilience-testing-website/notification-outbox",
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (response.ok) return { accepted: true };

    let errorName: string | null = null;
    try {
      errorName = readErrorName(await response.json());
    } catch {
      // A malformed provider body is deliberately discarded and classified by status only.
    }
    const retryAfterMs = readRetryAfterMs(retryAfter);
    return { accepted: false, statusCode: response.status, errorName, retryAfterMs };
  }
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function validCommand(command: NotificationCommand): boolean {
  return uuidPattern.test(command.idempotencyKey) &&
    uuidPattern.test(command.inquiryId) &&
    command.eventType === "inquiry_received";
}

function classifyProviderFailure(
  statusCode: number | null,
  errorName: string | null,
): NotificationDeliveryResult {
  if (statusCode === 429 || errorName === "rate_limit_exceeded" ||
      errorName === "monthly_quota_exceeded" || errorName === "daily_quota_exceeded") {
    return { outcome: "retryable_failure", errorCode: "rate_limited" };
  }

  if (statusCode === 408) {
    return { outcome: "retryable_failure", errorCode: "timeout" };
  }

  if ((statusCode !== null && statusCode >= 500) ||
      errorName === "application_error" || errorName === "internal_server_error" ||
      errorName === "concurrent_idempotent_requests") {
    return { outcome: "retryable_failure", errorCode: "provider_unavailable" };
  }

  const rejectedNames = new Set([
    "invalid_idempotency_key",
    "validation_error",
    "missing_api_key",
    "restricted_api_key",
    "invalid_api_key",
    "not_found",
    "method_not_allowed",
    "invalid_idempotent_request",
    "invalid_attachment",
    "invalid_from_address",
    "invalid_access",
    "invalid_parameter",
    "invalid_region",
    "missing_required_field",
    "security_error",
  ]);
  if (errorName !== null && rejectedNames.has(errorName)) {
    return { outcome: "permanent_failure", errorCode: "rejected" };
  }

  return { outcome: "retryable_failure", errorCode: "unknown" };
}

function classifyThrownFailure(error: unknown): NotificationDeliveryResult {
  const name = readErrorName(error);
  if (name === "AbortError" || name === "TimeoutError") {
    return { outcome: "retryable_failure", errorCode: "timeout" };
  }
  if (error instanceof TypeError) {
    return { outcome: "retryable_failure", errorCode: "provider_unavailable" };
  }
  return { outcome: "retryable_failure", errorCode: "unknown" };
}

export class ResendNotificationAdapter implements NotificationAdapter {
  constructor(
    private readonly client: ResendEmailClient,
    private readonly fromEmail: string,
    private readonly toEmail: string,
  ) {}

  async deliver(command: NotificationCommand): Promise<NotificationDeliveryResult> {
    if (!validCommand(command)) {
      return { outcome: "permanent_failure", errorCode: "rejected" };
    }

    const request: ResendSendRequest = {
      from: this.fromEmail,
      to: [this.toEmail],
      subject: `New inquiry received — ${command.inquiryId}`,
      text: `A new inquiry has been received.\n\nReference: ${command.inquiryId}`,
    };

    try {
      const result = await this.client.send(request, command.idempotencyKey);
      if (result.accepted) return { outcome: "delivered" };
      const failure = classifyProviderFailure(result.statusCode, result.errorName);
      if (failure.outcome === "retryable_failure" && result.retryAfterMs !== undefined) {
        return { ...failure, retryAfterMs: result.retryAfterMs };
      }
      return failure;
    } catch (error) {
      // Provider exception messages and stacks are deliberately neither logged nor returned.
      return classifyThrownFailure(error);
    }
  }
}

export type ConfiguredNotificationAdapter =
  | { available: false; reason: "deployment-boundary" | "gate" | "api-key" | "sender" | "recipient" }
  | { available: true; adapter: NotificationAdapter };

export function createConfiguredNotificationAdapter(
  environment: NotificationEnvironment,
  createClient: (apiKey: string) => ResendEmailClient,
): ConfiguredNotificationAdapter {
  const configuration = getNotificationConfiguration(environment);
  if (!configuration.enabled) {
    return { available: false, reason: configuration.reason };
  }

  return {
    available: true,
    adapter: new ResendNotificationAdapter(
      createClient(configuration.apiKey),
      configuration.fromEmail,
      configuration.toEmail,
    ),
  };
}

/** Server-only runtime factory. It does not fall back to a synthetic success adapter. */
export function getNotificationAdapter(
  environment: NotificationEnvironment = process.env,
): ConfiguredNotificationAdapter {
  return createConfiguredNotificationAdapter(
    environment,
    (apiKey) => new ResendHttpClient(apiKey),
  );
}
