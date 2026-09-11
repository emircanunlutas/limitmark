import { createHash } from "node:crypto";

export const turnstileResponseField = "cf-turnstile-response";
export const turnstileTokenMaxLength = 2048;
export const publicInquiryTurnstileAction = "public-inquiry";

export type TurnstileConfiguration = {
  secretKey: string;
  expectedHostname: string;
  expectedAction: typeof publicInquiryTurnstileAction;
  timeoutMs: number;
};

export type TurnstileDecision = "verified" | "rejected" | "unavailable";

export interface TurnstileVerifier {
  verify(token: string, idempotencyKey: string): Promise<TurnstileDecision>;
}

export function readTurnstileToken(formData: FormData): string | null {
  const values = formData.getAll(turnstileResponseField);
  const token = values.length === 1 ? values[0] : null;
  return typeof token === "string" && token.length > 0 && token.length <= turnstileTokenMaxLength ? token : null;
}

export function createTurnstileIdempotencyKey(submissionToken: string, turnstileToken: string): string {
  const bytes = createHash("sha256")
    .update(`turnstile-v2\0${submissionToken}\0${turnstileToken}`, "utf8")
    .digest()
    .subarray(0, 16);
  // RFC 4122-shaped deterministic UUID. It lets Siteverify safely recognize a
  // retry while keeping the public submission token out of that parameter.
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

type SiteverifyResponse = {
  success?: unknown;
  hostname?: unknown;
  action?: unknown;
};

export class CloudflareTurnstileVerifier implements TurnstileVerifier {
  constructor(
    private readonly configuration: TurnstileConfiguration,
    private readonly request: typeof fetch = fetch,
  ) {}

  async verify(token: string, idempotencyKey: string): Promise<TurnstileDecision> {
    if (!token || token.length > turnstileTokenMaxLength) return "rejected";
    const body = new URLSearchParams({
      secret: this.configuration.secretKey,
      response: token,
      idempotency_key: idempotencyKey,
    });
    try {
      const response = await this.request("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        body,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        cache: "no-store",
        signal: AbortSignal.timeout(this.configuration.timeoutMs),
      });
      if (!response.ok) return "unavailable";
      const result = await response.json() as SiteverifyResponse;
      return result.success === true &&
        result.hostname === this.configuration.expectedHostname &&
        result.action === this.configuration.expectedAction
        ? "verified"
        : "rejected";
    } catch {
      return "unavailable";
    }
  }
}
