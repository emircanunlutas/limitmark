import { isVercelProduction, type VercelEnvironment } from "./deployment-environment";

// Kept pure so the production demo guard can be checked without a framework runtime.
export function isDemoSubmissionAllowed(environment: {
  NODE_ENV?: string; REQUEST_SUBMISSION_MODE?: string; ALLOW_DEMO_SUBMISSIONS?: string;
} & VercelEnvironment): boolean {
  if (isVercelProduction(environment)) return false;
  return environment.REQUEST_SUBMISSION_MODE === "demo" &&
    (environment.NODE_ENV === "development" || environment.NODE_ENV === "test" || environment.ALLOW_DEMO_SUBMISSIONS === "true");
}

export function getSubmissionRuntimeMode(environment: {
  NODE_ENV?: string; REQUEST_SUBMISSION_MODE?: string; ALLOW_DEMO_SUBMISSIONS?: string;
} & VercelEnvironment): "demo" | "persistent" | "unavailable" {
  if (isDemoSubmissionAllowed(environment)) return "demo";
  return environment.REQUEST_SUBMISSION_MODE === "postgres" ? "persistent" : "unavailable";
}
