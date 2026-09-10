// Kept pure so the production demo guard can be checked without a framework runtime.
export function isDemoSubmissionAllowed(environment: {
  NODE_ENV?: string; REQUEST_SUBMISSION_MODE?: string; ALLOW_DEMO_SUBMISSIONS?: string;
}): boolean {
  return (environment.REQUEST_SUBMISSION_MODE ?? "demo") === "demo" &&
    (environment.NODE_ENV === "development" || environment.NODE_ENV === "test" || environment.ALLOW_DEMO_SUBMISSIONS === "true");
}
