import assert from "node:assert/strict";
import test from "node:test";
import type { NotificationCommand } from "../src/lib/notification-adapter";
import { getNotificationConfiguration } from "../src/lib/notification-config";
import type { FailNotificationInput } from "../src/lib/notification-outbox-repository";
import { processOutboxBatch } from "../src/lib/outbox-processor";
import {
  createConfiguredNotificationAdapter,
  ResendHttpClient,
  ResendNotificationAdapter,
  type ResendEmailClient,
} from "../src/lib/resend-notification-adapter";

const command: NotificationCommand = {
  idempotencyKey: "00000000-0000-4000-8000-000000000001",
  inquiryId: "00000000-0000-4000-8000-000000000002",
  eventType: "inquiry_received",
};

const completeEnvironment = {
  VERCEL: "1",
  VERCEL_ENV: "production",
  ENABLE_REAL_NOTIFICATIONS: "true",
  RESEND_API_KEY: "re_synthetic_unit_test_key",
  NOTIFICATION_FROM_EMAIL: "notifications@example.test",
  NOTIFICATION_TO_EMAIL: "internal@example.test",
};

test("notification configuration and construction fail closed", () => {
  assert.deepEqual(getNotificationConfiguration({}), { enabled: false, reason: "deployment-boundary" });
  assert.deepEqual(
    getNotificationConfiguration({ ...completeEnvironment, VERCEL_ENV: "preview" }),
    { enabled: false, reason: "deployment-boundary" },
  );
  assert.deepEqual(
    getNotificationConfiguration({ VERCEL: "1", VERCEL_ENV: "production" }),
    { enabled: false, reason: "gate" },
  );
  assert.deepEqual(
    getNotificationConfiguration({ ...completeEnvironment, ENABLE_REAL_NOTIFICATIONS: "TRUE" }),
    { enabled: false, reason: "gate" },
  );
  assert.deepEqual(
    getNotificationConfiguration({ ...completeEnvironment, RESEND_API_KEY: "" }),
    { enabled: false, reason: "api-key" },
  );
  assert.deepEqual(
    getNotificationConfiguration({ ...completeEnvironment, RESEND_API_KEY: "malformed" }),
    { enabled: false, reason: "api-key" },
  );
  assert.deepEqual(
    getNotificationConfiguration({ ...completeEnvironment, NOTIFICATION_FROM_EMAIL: "Sender <sender@example.test>" }),
    { enabled: false, reason: "sender" },
  );
  assert.deepEqual(
    getNotificationConfiguration({ ...completeEnvironment, NOTIFICATION_TO_EMAIL: "not-an-address" }),
    { enabled: false, reason: "recipient" },
  );

  let constructedWith: string | null = null;
  const configured = createConfiguredNotificationAdapter(completeEnvironment, (apiKey) => {
    constructedWith = apiKey;
    return { async send() { return { accepted: true }; } };
  });
  assert.equal(configured.available, true);
  assert.equal(constructedWith, completeEnvironment.RESEND_API_KEY);

  let disabledClientConstructed = false;
  const disabled = createConfiguredNotificationAdapter(
    { ...completeEnvironment, ENABLE_REAL_NOTIFICATIONS: "false" },
    () => {
      disabledClientConstructed = true;
      return { async send() { return { accepted: true }; } };
    },
  );
  assert.deepEqual(disabled, { available: false, reason: "gate" });
  assert.equal(disabledClientConstructed, false);
});

test("accepted Resend delivery uses minimal content and the stable outbox idempotency key", async () => {
  const sends: Array<{ request: unknown; idempotencyKey: string }> = [];
  const client: ResendEmailClient = {
    async send(request, idempotencyKey) {
      sends.push({ request, idempotencyKey });
      return { accepted: true };
    },
  };
  const adapter = new ResendNotificationAdapter(
    client,
    completeEnvironment.NOTIFICATION_FROM_EMAIL,
    completeEnvironment.NOTIFICATION_TO_EMAIL,
  );
  const commandWithForbiddenExtras = {
    ...command,
    name: "FORBIDDEN CUSTOMER NAME",
    email: "forbidden-customer@example.test",
    company: "FORBIDDEN COMPANY",
    system: "FORBIDDEN TARGET",
    objective: "FORBIDDEN OBJECTIVE",
    notes: "FORBIDDEN NOTES",
    provider: "FORBIDDEN PROVIDER",
    submissionToken: "FORBIDDEN TOKEN",
    payloadFingerprint: "FORBIDDEN FINGERPRINT",
  } as NotificationCommand;

  assert.deepEqual(await adapter.deliver(commandWithForbiddenExtras), { outcome: "delivered" });
  assert.deepEqual(await adapter.deliver(commandWithForbiddenExtras), { outcome: "delivered" });
  assert.deepEqual(sends.map(({ idempotencyKey }) => idempotencyKey), [
    command.idempotencyKey,
    command.idempotencyKey,
  ]);
  assert.deepEqual(sends[0].request, {
    from: "notifications@example.test",
    to: ["internal@example.test"],
    subject: `New inquiry received — ${command.inquiryId}`,
    text: `A new inquiry has been received.\n\nReference: ${command.inquiryId}`,
  });

  const serialized = JSON.stringify(sends[0].request);
  for (const forbidden of [
    "FORBIDDEN CUSTOMER NAME",
    "forbidden-customer@example.test",
    "FORBIDDEN COMPANY",
    "FORBIDDEN TARGET",
    "FORBIDDEN OBJECTIVE",
    "FORBIDDEN NOTES",
    "FORBIDDEN PROVIDER",
    "FORBIDDEN TOKEN",
    "FORBIDDEN FINGERPRINT",
    command.eventType,
  ]) {
    assert.equal(serialized.includes(forbidden), false);
  }
});

test("Resend rate limits, temporary failures, and permanent rejections are classified", async () => {
  async function deliver(result: Awaited<ReturnType<ResendEmailClient["send"]>>) {
    const client: ResendEmailClient = { async send() { return result; } };
    return new ResendNotificationAdapter(client, "from@example.test", "to@example.test")
      .deliver(command);
  }

  assert.deepEqual(await deliver({ accepted: false, statusCode: 429, errorName: "rate_limit_exceeded" }), {
    outcome: "retryable_failure", errorCode: "rate_limited",
  });
  assert.deepEqual(await deliver({ accepted: false, statusCode: 503, errorName: "internal_server_error" }), {
    outcome: "retryable_failure", errorCode: "provider_unavailable",
  });
  assert.deepEqual(await deliver({ accepted: false, statusCode: 409, errorName: "concurrent_idempotent_requests" }), {
    outcome: "retryable_failure", errorCode: "provider_unavailable",
  });
  assert.deepEqual(await deliver({ accepted: false, statusCode: 400, errorName: "invalid_from_address" }), {
    outcome: "permanent_failure", errorCode: "rejected",
  });
  assert.deepEqual(await deliver({ accepted: false, statusCode: 422, errorName: "future_unclassified_4xx" }), {
    outcome: "retryable_failure", errorCode: "unknown",
  });
  assert.deepEqual(await deliver({ accepted: false, statusCode: null, errorName: "future_unclassified_error" }), {
    outcome: "retryable_failure", errorCode: "unknown",
  });
});

test("timeouts and network failures remain retryable without exposing exception text", async () => {
  const timeoutClient: ResendEmailClient = {
    async send() {
      throw new DOMException("RAW TIMEOUT PROVIDER TEXT", "TimeoutError");
    },
  };
  const networkClient: ResendEmailClient = {
    async send() {
      throw new TypeError("RAW NETWORK PROVIDER TEXT");
    },
  };
  const unknownClient: ResendEmailClient = {
    async send() {
      throw new Error("RAW UNKNOWN PROVIDER TEXT");
    },
  };

  assert.deepEqual(await new ResendNotificationAdapter(timeoutClient, "from@example.test", "to@example.test").deliver(command), {
    outcome: "retryable_failure", errorCode: "timeout",
  });
  assert.deepEqual(await new ResendNotificationAdapter(networkClient, "from@example.test", "to@example.test").deliver(command), {
    outcome: "retryable_failure", errorCode: "provider_unavailable",
  });
  const unknown = await new ResendNotificationAdapter(unknownClient, "from@example.test", "to@example.test").deliver(command);
  assert.deepEqual(unknown, { outcome: "retryable_failure", errorCode: "unknown" });
  assert.equal(JSON.stringify(unknown).includes("RAW UNKNOWN PROVIDER TEXT"), false);
});

test("only throttled or unavailable responses carry a numeric retry delay", async (t) => {
  const now = Date.UTC(2030, 8, 11, 12);
  t.mock.timers.enable({ apis: ["Date"], now });
  const cases: Array<[number, string | null, number | undefined]> = [
    [429, "120", 120_000],
    [503, new Date(now + 90_000).toUTCString(), 90_000],
    [429, "0005", 5_000],
    [429, "99999999999999999999", Number.MAX_SAFE_INTEGER],
    [429, null, undefined],
    [429, "0", undefined],
    [429, new Date(now - 1_000).toUTCString(), undefined],
    [429, "1.5", undefined],
    [429, "-2", undefined],
    [429, "120, 240", undefined],
    [429, "2030-09-12", undefined],
    [429, "private provider text", undefined],
    [500, "120", undefined],
    [400, "120", undefined],
  ];
  const client = new ResendHttpClient("synthetic");
  const fetchMock = t.mock.method(globalThis, "fetch", () => { throw new Error("unexpected fetch"); });
  for (const [status, header, retryAfterMs] of cases) {
    fetchMock.mock.mockImplementationOnce(async (url) => {
      assert.equal(url, "https://api.resend.com/emails");
      return new Response("invalid JSON", { status, headers: header === null ? {} : { "retry-after": header } });
    });
    const result = await new ResendNotificationAdapter(client, "from@example.test", "to@example.test").deliver(command);
    const errorCode = status === 429 ? "rate_limited" : status >= 500 ? "provider_unavailable" : "unknown";
    assert.deepEqual(result, {
      outcome: "retryable_failure", errorCode, ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
    }, `status=${status} header=${header}`);
  }
});

test("the HTTPS client bounds calls, sends the official idempotency header, and discards raw errors", async (t) => {
  let capturedInit: RequestInit | undefined;
  const rawProviderText = "RAW PROVIDER RESPONSE MUST NOT ESCAPE";
  const rejectingFetch = async (_input: string | URL | Request, init?: RequestInit) => {
    capturedInit = init;
    return new Response(JSON.stringify({
      name: "validation_error",
      message: rawProviderText,
      unexpected: { sensitive: rawProviderText },
    }), { status: 400 });
  };
  const fetchMock = t.mock.method(globalThis, "fetch", rejectingFetch);
  const client = new ResendHttpClient("re_synthetic_unit_test_key", 50);
  const adapter = new ResendNotificationAdapter(client, "from@example.test", "to@example.test");
  const result = await adapter.deliver(command);

  assert.deepEqual(result, { outcome: "permanent_failure", errorCode: "rejected" });
  assert.equal(JSON.stringify(result).includes(rawProviderText), false);
  assert.equal(new Headers(capturedInit?.headers).get("Idempotency-Key"), command.idempotencyKey);
  assert.equal(capturedInit?.signal instanceof AbortSignal, true);
  assert.equal(JSON.stringify(capturedInit?.body).includes(rawProviderText), false);

  const failureWrites: FailNotificationInput[] = [];
  const summary = await processOutboxBatch({
    repository: {
      async claimBatch() {
        return [{
          outboxId: command.idempotencyKey,
          inquiryId: command.inquiryId,
          eventType: command.eventType,
          attempts: 1,
          lockedUntil: new Date("2026-09-11T12:01:00.000Z"),
        }];
      },
      async markSent() { return true; },
      async markFailure(input) { failureWrites.push(input); return true; },
    },
    adapter,
    now: new Date("2026-09-11T12:00:00.000Z"),
    leaseDurationMs: 60_000,
  });
  assert.equal(summary.failed, 1);
  assert.equal(failureWrites[0].errorCode, "rejected");
  assert.equal(JSON.stringify(failureWrites[0]).includes(rawProviderText), false);

  const hangingFetch = async (_input: string | URL | Request, init?: RequestInit): Promise<Response> =>
    new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
    });
  fetchMock.mock.mockImplementation(hangingFetch);
  const timedClient = new ResendHttpClient("re_synthetic_unit_test_key", 5);
  const timedResult = await new ResendNotificationAdapter(
    timedClient,
    "from@example.test",
    "to@example.test",
  ).deliver(command);
  assert.deepEqual(timedResult, { outcome: "retryable_failure", errorCode: "timeout" });
});
