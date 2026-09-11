import "server-only";
import type {
  NotificationAdapter,
  NotificationCommand,
  NotificationDeliveryResult,
} from "./notification-adapter";
import {
  getNotificationConfiguration,
  type NotificationEnvironment,
} from "./notification-config";

const resendEndpoint = "https://api.resend.com/emails";
export const resendRequestTimeoutMs = 10_000;

type ResendSendRequest = {
  from: string;
  to: string[];
  subject: string;
  text: string;
};

type ResendSendResult =
  | { accepted: true }
  | { accepted: false; statusCode: number | null; errorName: string | null };

export interface ResendEmailClient {
  send(request: ResendSendRequest, idempotencyKey: string): Promise<ResendSendResult>;
}

type FetchImplementation = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

function readErrorName(value: unknown): string | null {
  if (!value || typeof value !== "object") return null;
  const name = Reflect.get(value, "name");
  return typeof name === "string" ? name : null;
}

/** Minimal typed Resend HTTPS client. It never logs or returns response bodies/messages. */
export class ResendHttpClient implements ResendEmailClient {
  constructor(
    private readonly apiKey: string,
    private readonly fetchImplementation: FetchImplementation = fetch,
    private readonly timeoutMs = resendRequestTimeoutMs,
  ) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
      throw new RangeError("timeoutMs must be a positive safe integer");
    }
  }

  async send(request: ResendSendRequest, idempotencyKey: string): Promise<ResendSendResult> {
    const response = await this.fetchImplementation(resendEndpoint, {
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
    return { accepted: false, statusCode: response.status, errorName };
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
      return result.accepted
        ? { outcome: "delivered" }
        : classifyProviderFailure(result.statusCode, result.errorName);
    } catch (error) {
      // Provider exception messages and stacks are deliberately neither logged nor returned.
      return classifyThrownFailure(error);
    }
  }
}

export type ConfiguredNotificationAdapter =
  | { available: false; reason: "gate" | "api-key" | "sender" | "recipient" }
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
