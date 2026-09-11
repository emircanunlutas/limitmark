import "server-only";
import type { TestRequest } from "./request-schema";
import { isDemoSubmissionAllowed } from "./submission-policy";
import { createPayloadFingerprint } from "./payload-fingerprint";
import type { HeaderReader } from "./client-identity";
import { availableProductionRateLimitProviders, createProductionRateLimitAdapter } from "./rate-limit";
import { getPublicSubmissionConfiguration } from "./public-submission-config";
import { enforceSubmissionAbuseControls } from "./submission-abuse-control";
import { CloudflareTurnstileVerifier } from "./turnstile";

export type SubmissionResult =
  | { status: "demo-accepted" | "persisted" | "idempotent" }
  | { status: "idempotency-conflict" | "unavailable" };
export interface SubmissionAdapter {
  submit(request: TestRequest, submissionToken: string): Promise<SubmissionResult>;
}

// DEMO ONLY: validates the public journey; deliberately does not persist, log,
// email, schedule, authorize or execute anything.
const demoAdapter: SubmissionAdapter = {
  async submit() {
    return { status: "demo-accepted" };
  },
};

export async function submitToAdapter(
  request: TestRequest,
  submissionToken: string,
  security?: { headers: HeaderReader; turnstileToken: string | null },
): Promise<SubmissionResult> {
  if ((process.env.REQUEST_SUBMISSION_MODE ?? "demo") === "demo") {
    // Fail closed on a conventional production host unless explicitly previewing.
    if (!isDemoSubmissionAllowed(process.env)) return { status: "unavailable" };
    return demoAdapter.submit(request, submissionToken);
  }

  const configuration = getPublicSubmissionConfiguration(process.env, availableProductionRateLimitProviders);
  // Unknown modes, a closed go-live gate, and missing/malformed configuration
  // are deliberately indistinguishable to the public caller.
  if (!configuration.enabled) return { status: "unavailable" };

  const rateLimiter = createProductionRateLimitAdapter(configuration.rateLimitProvider);
  if (!security || !rateLimiter) return { status: "unavailable" };
  const abuseDecision = await enforceSubmissionAbuseControls({
    headers: security.headers,
    clientIdentity: configuration.clientIdentity,
    submissionToken,
    turnstileToken: security.turnstileToken,
    rateLimiter,
    turnstile: new CloudflareTurnstileVerifier(configuration.turnstile),
  });
  if (abuseDecision !== "allowed") return { status: "unavailable" };

  const [{ getDatabase }, { PostgresInquiryRepository }] = await Promise.all([
    import("./db/database.server"),
    import("./inquiry-repository"),
  ]);
  const repository = new PostgresInquiryRepository(getDatabase(configuration.databaseUrl, configuration.poolMax));
  const result = await repository.create({
    request,
    submissionToken,
    payloadFingerprint: createPayloadFingerprint(request),
  });
  if (result.status === "conflict") return { status: "idempotency-conflict" };
  return { status: result.status === "created" ? "persisted" : "idempotent" };
}
