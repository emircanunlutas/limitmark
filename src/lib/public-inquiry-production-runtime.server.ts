import "server-only";

import { createProductionAdmissionClient, VercelRequestOidcTokenProvider, type ProductionOidcTokenProvider } from "./admission-client.server";
import { getDatabase } from "./db/database.server";
import { importIngressPublicKeys, importRequestBindingKey, type IngressVerificationPolicy } from "./ingress-verifier.server";
import { PostgresInquiryRepository } from "./inquiry-repository";
import type { PublicInquiryHandlerDependencies } from "./public-inquiry-handler.server";
import { getPublicSubmissionConfiguration, type PublicSubmissionEnvironment } from "./public-submission-config";
import { availableProductionRateLimitProviders } from "./rate-limit";
import { CloudflareTurnstileVerifier } from "./turnstile";

export type ProductionRuntimeEnvironment = PublicSubmissionEnvironment & { [key: string]: string | undefined };
export type ProductionRuntimeResult =
  | { enabled: false; reason: "runtime" | "configuration" | "invalid" }
  | { enabled: true; dependencies: PublicInquiryHandlerDependencies };

/** Any of these on the production runtime means a laboratory/Google identity configuration leaked into it. The production factory refuses to run. */
const forbiddenLaboratoryKeyPattern = /^(?:LAB_|GOOGLE_|ADMISSION_IDENTITY_MODE$)/u;

/**
 * Production counterpart of `createLaboratoryRuntimeDependencies`: builds the dependencies of the public inquiry handler for the Vercel
 * production runtime, or reports that it is disabled. It adds no policy of its own: the single production configuration decision remains
 * `getPublicSubmissionConfiguration` (persistence gate, rate-limit provider registry, deployment boundary, ingress, admission, Turnstile and the
 * `vercelApplication` secret policy), so the public page and this factory cannot disagree.
 *
 * Fail-closed: `availableProductionRateLimitProviders` is intentionally empty at launch, so with the shipped registry this returns disabled and the
 * handler keeps answering 503. `providers` and `oidc`/`request` exist only so tests can exercise the enabled path; the route never passes them.
 * It uses the Vercel OIDC token provider exclusively -- there is no laboratory, Google, demo or development fallback.
 */
export async function createProductionRuntimeDependencies(
  environment: ProductionRuntimeEnvironment,
  options: { providers?: readonly string[]; oidc?: ProductionOidcTokenProvider; request?: typeof fetch } = {},
): Promise<ProductionRuntimeResult> {
  if (environment.LIMITMARK_RUNTIME !== undefined || Object.keys(environment).some((key) => forbiddenLaboratoryKeyPattern.test(key) && environment[key] !== undefined && environment[key] !== "")) {
    return { enabled: false, reason: "runtime" };
  }
  const configuration = getPublicSubmissionConfiguration(environment, options.providers ?? availableProductionRateLimitProviders);
  if (!configuration.enabled) return { enabled: false, reason: "configuration" };
  const request = options.request ?? fetch;
  try {
    const ingressPolicy: IngressVerificationPolicy = {
      audience: environment.INGRESS_AUDIENCE!,
      deploymentId: environment.VERCEL_DEPLOYMENT_ID!,
      environment: "production",
      publicKeys: await importIngressPublicKeys(environment.INGRESS_PUBLIC_KEYS!),
      requestBindingKey: await importRequestBindingKey(environment.INGRESS_REQUEST_BINDING_KEY!),
    };
    const admission = await createProductionAdmissionClient(environment, options.oidc ?? new VercelRequestOidcTokenProvider(), request);
    if (!admission) return { enabled: false, reason: "invalid" };
    const turnstile = new CloudflareTurnstileVerifier({
      secretKey: configuration.turnstile.secretKey,
      expectedHostname: configuration.turnstile.expectedHostname,
      expectedAction: configuration.turnstile.expectedAction,
      timeoutMs: configuration.turnstile.timeoutMs,
    }, request);
    const repository = new PostgresInquiryRepository(getDatabase(configuration.databaseUrl, configuration.poolMax));
    return {
      enabled: true,
      dependencies: {
        environment,
        ingressPolicy,
        admission,
        turnstile,
        repository: {
          async create(input) {
            const result = await repository.create(input);
            return { status: result.status === "idempotent" ? "existing" : result.status };
          },
        },
      },
    };
  } catch {
    return { enabled: false, reason: "invalid" };
  }
}
