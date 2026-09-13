import { createAdminGateway } from "./gateway";
import { validateRuntimeSecrets } from "../../deployment/secret-policy";
export { ADMIN_GATEWAY_HOST, createAdminGateway, type AdminGatewayConfiguration } from "./gateway";

export type AdminGatewayEnvironment = {
  VERCEL_ADMIN_UPSTREAM_ORIGIN: string;
  CLOUDFLARE_ACCESS_TEAM_DOMAIN: string;
  CLOUDFLARE_ACCESS_AUD: string;
  ADMIN_ALLOWED_EMAIL: string;
  VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET: string;
};

let configuredHandler: ((request: Request) => Promise<Response>) | undefined;
const adminGatewayWorker = {
  async fetch(request: Request, environment: AdminGatewayEnvironment): Promise<Response> {
    if (!validateRuntimeSecrets("adminGateway", environment as unknown as Record<string, unknown>)) return new Response(null, { status: 503 });
    configuredHandler ??= createAdminGateway({ environment: "production", publicHost: "admin.limitmark.com",
      upstreamOrigin: environment.VERCEL_ADMIN_UPSTREAM_ORIGIN, accessIssuer: environment.CLOUDFLARE_ACCESS_TEAM_DOMAIN,
      accessAudience: environment.CLOUDFLARE_ACCESS_AUD, allowedAdminEmail: environment.ADMIN_ALLOWED_EMAIL,
      vercelAutomationBypassSecret: environment.VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET });
    return configuredHandler(request);
  },
};
export default adminGatewayWorker;
