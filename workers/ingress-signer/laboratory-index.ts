import { createIngressSigner } from "./signer";
import { createGoogleIdTokenProvider } from "./google-id-token";

export type LaboratoryIngressSignerEnvironment = {
  LAB_PUBLIC_HOSTNAME: string;
  LAB_ORIGIN_HOSTNAME: string;
  LAB_INGRESS_AUDIENCE: string;
  LAB_DEPLOYMENT_ID: string;
  LAB_INGRESS_SIGNING_KEY_ID: string;
  LAB_INGRESS_SIGNING_PRIVATE_KEY: string;
  LAB_INGRESS_IDENTITY_HMAC_KEY: string;
  LAB_PUBLIC_ORIGIN_SECRET: string;
  LAB_GOOGLE_SERVICE_ACCOUNT_CREDENTIALS?: string;
};

let configuredHandler: ((request: Request) => Promise<Response>) | undefined;

function validHostname(value: string): boolean {
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/u.test(value) || value.length > 253 || value.includes("..")) return false;
  try { return new URL(`https://${value}`).hostname === value && value.includes("."); } catch { return false; }
}

const laboratoryIngressSignerWorker = {
  async fetch(request: Request, environment: LaboratoryIngressSignerEnvironment): Promise<Response> {
    if (!environment.LAB_PUBLIC_HOSTNAME || !environment.LAB_ORIGIN_HOSTNAME ||
        !environment.LAB_INGRESS_AUDIENCE || !environment.LAB_DEPLOYMENT_ID ||
        !environment.LAB_INGRESS_SIGNING_KEY_ID || !environment.LAB_INGRESS_SIGNING_PRIVATE_KEY ||
        !environment.LAB_INGRESS_IDENTITY_HMAC_KEY || !environment.LAB_PUBLIC_ORIGIN_SECRET ||
        !environment.LAB_GOOGLE_SERVICE_ACCOUNT_CREDENTIALS ||
        !validHostname(environment.LAB_PUBLIC_HOSTNAME) || !validHostname(environment.LAB_ORIGIN_HOSTNAME) ||
        environment.LAB_PUBLIC_HOSTNAME === environment.LAB_ORIGIN_HOSTNAME ||
        !/^[A-Za-z0-9_.:-]{1,128}$/u.test(environment.LAB_INGRESS_AUDIENCE) ||
        !/^[A-Za-z0-9_.:-]{1,128}$/u.test(environment.LAB_DEPLOYMENT_ID) ||
        !/^[A-Za-z0-9_-]{1,64}$/u.test(environment.LAB_INGRESS_SIGNING_KEY_ID) ||
        !/^[A-Za-z0-9_-]{43}$/u.test(environment.LAB_INGRESS_IDENTITY_HMAC_KEY) ||
        !/^[A-Za-z0-9_-]{43}$/u.test(environment.LAB_PUBLIC_ORIGIN_SECRET)) {
      return new Response(null, { status: 503 });
    }
    configuredHandler ??= createIngressSigner({
      environment: "cloud-run-lab",
      publicHosts: [environment.LAB_PUBLIC_HOSTNAME],
      targetOrigin: `https://${environment.LAB_ORIGIN_HOSTNAME}`,
      originHostname: environment.LAB_ORIGIN_HOSTNAME,
      audience: environment.LAB_INGRESS_AUDIENCE,
      deploymentId: environment.LAB_DEPLOYMENT_ID,
      keyId: environment.LAB_INGRESS_SIGNING_KEY_ID,
      signingPrivateKeyPkcs8: environment.LAB_INGRESS_SIGNING_PRIVATE_KEY,
      identityHmacKey: environment.LAB_INGRESS_IDENTITY_HMAC_KEY,
      originSecret: environment.LAB_PUBLIC_ORIGIN_SECRET,
      cloudRunAuthorizationToken: createGoogleIdTokenProvider(
        environment.LAB_GOOGLE_SERVICE_ACCOUNT_CREDENTIALS,
        `https://${environment.LAB_ORIGIN_HOSTNAME}`,
      ),
    });
    return configuredHandler(request);
  },
};

export default laboratoryIngressSignerWorker;
