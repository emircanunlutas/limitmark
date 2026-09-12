import "server-only";
import type { TestRequest } from "./request-schema";
import { getSubmissionRuntimeMode } from "./submission-policy";
import type { HeaderReader } from "./client-identity";
import type { PublicSubmissionEnvironment } from "./public-submission-config";

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
  environment: PublicSubmissionEnvironment = process.env,
): Promise<SubmissionResult> {
  const runtimeMode = getSubmissionRuntimeMode(environment);
  if (runtimeMode === "demo") {
    return demoAdapter.submit(request, submissionToken);
  }
  if (runtimeMode === "unavailable") return { status: "unavailable" };

  void request; void submissionToken; void security;
  // The legacy adapter has no persistent implementation. Production writes can
  // only be wired later behind the signed raw-body Route Handler and PRE/POST
  // admission coordinator; I1 deliberately leaves that runtime wiring absent.
  return { status: "unavailable" };
}
