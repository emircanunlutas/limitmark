import "server-only";

import { getSubmissionRuntimeMode } from "./submission-policy";
import { readRequestFormData, requestSchema, getFieldErrors, getRequestValues, type RequestState } from "./request-schema";
import { readSubmissionToken } from "./submission-token";
import { submitToAdapter } from "./submission-adapter";
import { INGRESS_BODY_ENCODING, INGRESS_MUTATION_CONTENT_TYPE, INGRESS_MUTATION_PATH } from "./ingress-protocol";
import { verifyMutationIngress, type IngressVerificationPolicy } from "./ingress-verifier.server";
import { isPublicOriginAllowed, type PublicOriginEnvironment } from "./public-origin";
import { executeVerifiedPublicInquiry, type PublicInquiryFlowResult, type PublicInquiryRepository } from "./public-inquiry-flow.server";
import { parseStrictUrlEncodedForm, readBoundedPublicInquiryBody } from "./public-inquiry-body";
import type { AdmissionClient } from "./admission-client.server";
import type { TurnstileVerifier } from "./turnstile";

export type PublicInquiryHandlerDependencies = {
  environment: PublicOriginEnvironment & { NODE_ENV?: string; REQUEST_SUBMISSION_MODE?: string; ALLOW_DEMO_SUBMISSIONS?: string; PUBLIC_DEMO_ORIGIN?: string };
  ingressPolicy?: IngressVerificationPolicy; admission?: AdmissionClient; turnstile?: TurnstileVerifier; repository?: PublicInquiryRepository;
};
const noStoreHeaders = {
  "cache-control": "private, no-store, max-age=0, must-revalidate",
  "cdn-cache-control": "no-store",
  "vercel-cdn-cache-control": "no-store",
} as const;
function jsonState(state: RequestState, status = 400): Response {
  return Response.json({ kind: "state", state }, { status, headers: noStoreHeaders });
}
function responseFor(result: PublicInquiryFlowResult): Response {
  return result.kind === "redirect" ? Response.json(result, { headers: noStoreHeaders }) : jsonState(result.state);
}

export async function handlePublicInquiry(request: Request, dependencies: PublicInquiryHandlerDependencies): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== INGRESS_MUTATION_PATH || url.search || request.headers.get("content-type") !== INGRESS_MUTATION_CONTENT_TYPE ||
        request.headers.get("content-encoding") !== null && request.headers.get("content-encoding") !== INGRESS_BODY_ENCODING) return new Response(null, { status: 404 });
    const body = await readBoundedPublicInquiryBody(request);
    const mode = getSubmissionRuntimeMode(dependencies.environment);
    if (mode === "demo") {
      const origin = request.headers.get("origin");
      let expectedOrigin = url.origin;
      try {
        if (dependencies.environment.PUBLIC_DEMO_ORIGIN) {
          const configured = new URL(dependencies.environment.PUBLIC_DEMO_ORIGIN);
          if (configured.origin !== dependencies.environment.PUBLIC_DEMO_ORIGIN || configured.pathname !== "/" || configured.search || configured.hash) throw new Error("invalid demo origin");
          expectedOrigin = configured.origin;
        }
      } catch { return jsonState({ errors: {}, message: "Talep gönderimi şu anda kullanılamıyor." }, 503); }
      if (origin !== expectedOrigin) return jsonState({ errors: {}, message: "Talep gönderimi şu anda kullanılamıyor." }, 403);
      const form = parseStrictUrlEncodedForm(body);
      const raw = readRequestFormData(form); const values = getRequestValues(raw); const token = readSubmissionToken(form);
      const parsed = requestSchema.safeParse(raw);
      if (!parsed.success) return jsonState({ errors: getFieldErrors(parsed.error), values, submissionToken: token ?? undefined });
      if (!token) return jsonState({ errors: {}, values, message: "Talep gönderimi şu anda kullanılamıyor." });
      const result = await submitToAdapter(parsed.data, token, undefined, dependencies.environment);
      return result.status === "demo-accepted" ? responseFor({ kind: "redirect", location: "/test-talep-et/tesekkurler" }) : jsonState({ errors: {}, values, submissionToken: token, message: "Talep gönderimi şu anda kullanılamıyor." });
    }
    if (mode !== "persistent" || dependencies.environment.VERCEL !== "1" || dependencies.environment.VERCEL_ENV !== "production" ||
        dependencies.environment.PUBLIC_ORIGIN_PROTECTION !== "required" || request.headers.get("origin") !== "https://limitmark.com" ||
        url.protocol !== "https:" || url.hostname !== "limitmark.com" ||
        !isPublicOriginAllowed(request.headers, dependencies.environment) || !dependencies.ingressPolicy || !dependencies.admission || !dependencies.turnstile || !dependencies.repository) {
      return jsonState({ errors: {}, message: "Talep gönderimi şu anda kullanılamıyor." }, 503);
    }
    const ingress = await verifyMutationIngress(request, body, dependencies.ingressPolicy);
    const form = parseStrictUrlEncodedForm(body);
    return responseFor(await executeVerifiedPublicInquiry({ form, ingress, admission: dependencies.admission, turnstile: dependencies.turnstile, repository: dependencies.repository }));
  } catch (error) {
    if (error instanceof Error && error.message === "public-body-overflow") {
      return jsonState({ errors: {}, message: "Talep gönderimi şu anda kullanılamıyor." }, 413);
    }
    return jsonState({ errors: {}, message: "Talep gönderimi şu anda kullanılamıyor." }, 400);
  }
}
