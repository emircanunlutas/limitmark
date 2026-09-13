export { createIngressSigner } from "./signer";
export { deriveClientPseudonym, parseCloudflareClientAddress } from "./identity";

import { createIngressSigner } from "./signer";
import { validateRuntimeSecrets } from "../../deployment/secret-policy";

export type IngressSignerEnvironment = {
  INGRESS_AUDIENCE: string;
  VERCEL_DEPLOYMENT_ID: string;
  INGRESS_SIGNING_KEY_ID: string;
  INGRESS_SIGNING_PRIVATE_KEY: string;
  INGRESS_IDENTITY_HMAC_KEY: string;
  PUBLIC_ORIGIN_SECRET: string;
  VERCEL_AUTOMATION_BYPASS_SECRET: string;
};

let configuredHandler: ((request: Request) => Promise<Response>) | undefined;

const ingressSignerWorker = {
  async fetch(request: Request, environment: IngressSignerEnvironment): Promise<Response> {
    if (!validateRuntimeSecrets("publicSigner", environment as unknown as Record<string, unknown>)) return new Response(null, { status: 503 });
    configuredHandler ??= createIngressSigner({
      environment: "production", publicHosts: ["limitmark.com", "www.limitmark.com"], targetOrigin: "https://limitmark.com",
      audience: environment.INGRESS_AUDIENCE, deploymentId: environment.VERCEL_DEPLOYMENT_ID, keyId: environment.INGRESS_SIGNING_KEY_ID,
      signingPrivateKeyPkcs8: environment.INGRESS_SIGNING_PRIVATE_KEY, identityHmacKey: environment.INGRESS_IDENTITY_HMAC_KEY,
      originSecret: environment.PUBLIC_ORIGIN_SECRET, vercelBypassSecret: environment.VERCEL_AUTOMATION_BYPASS_SECRET,
    });
    return configuredHandler(request);
  },
};
export default ingressSignerWorker;
