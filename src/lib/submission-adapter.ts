import "server-only";
import type { TestRequest } from "./request-schema";
import { isDemoSubmissionAllowed } from "./submission-policy";

type SubmissionResult = { status: "demo-accepted" } | { status: "unavailable" };
export interface SubmissionAdapter {
  submit(request: TestRequest): Promise<SubmissionResult>;
}

// DEMO ONLY: validates the public journey; deliberately does not persist, log,
// email, schedule, authorize or execute anything. Replace this adapter with a
// durable server-side inbox integration before accepting real customer requests.
const demoAdapter: SubmissionAdapter = {
  async submit() {
    return { status: "demo-accepted" };
  },
};

export async function submitToAdapter(request: TestRequest): Promise<SubmissionResult> {
  // Fail closed on a conventional production host unless explicitly previewing.
  // An unknown mode must never fall back to a demo success.
  if (!isDemoSubmissionAllowed(process.env)) return { status: "unavailable" };
  return demoAdapter.submit(request);
}
