export type VercelEnvironment = {
  VERCEL?: string;
  VERCEL_ENV?: string;
};

/** Platform-provided values establish the deployment boundary; request input and Host do not. */
export function isVercelProduction(environment: VercelEnvironment): boolean {
  return environment.VERCEL === "1" && environment.VERCEL_ENV === "production";
}
