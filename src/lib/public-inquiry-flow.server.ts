import "server-only";

import type { AdmissionClient } from "./admission-client.server";
import type { CreateInquiryInput, CreateInquiryResult } from "./inquiry-repository";
import { createPayloadFingerprint } from "./payload-fingerprint";
import { getFieldErrors, getRequestValues, readRequestFormData, requestSchema, type RequestState } from "./request-schema";
import { readSubmissionToken } from "./submission-token";
import { createTurnstileIdempotencyKey, readTurnstileToken, type TurnstileVerifier } from "./turnstile";
import type { VerifiedMutationIngress } from "./ingress-verifier.server";

export interface PublicInquiryRepository {
  create(input: CreateInquiryInput): Promise<Pick<CreateInquiryResult, "status">>;
}
export type PublicInquiryFlowResult =
  | { kind: "persisted" }
  | { kind: "unconfirmed" }
  | { kind: "state"; state: RequestState };
const unavailableMessage = "Talep gönderimi şu anda kullanılamıyor. Bilgileriniz iletilmedi. Lütfen daha sonra tekrar deneyin.";

export async function executeVerifiedPublicInquiry(input: {
  form: FormData; ingress: VerifiedMutationIngress; admission: AdmissionClient;
  turnstile: TurnstileVerifier; repository: PublicInquiryRepository;
}): Promise<PublicInquiryFlowResult> {
  const raw = readRequestFormData(input.form);
  const values = getRequestValues(raw);
  const submissionToken = readSubmissionToken(input.form);
  const parsed = requestSchema.safeParse(raw);
  if (!parsed.success) return { kind: "state", state: { errors: getFieldErrors(parsed.error), values, submissionToken: submissionToken ?? undefined } };
  const turnstileToken = readTurnstileToken(input.form);
  if (!submissionToken || !turnstileToken) return { kind: "state", state: { errors: {}, values, submissionToken: submissionToken ?? undefined, message: unavailableMessage } };
  const pre = await input.admission.claimPre({ releaseId: input.ingress.releaseId, clientPseudonym: input.ingress.clientPseudonym,
    requestBinding: input.ingress.requestBinding, nonce: input.ingress.nonce, issuedAtMs: input.ingress.issuedAtMs });
  if (pre.decision !== "allowed") return { kind: "state", state: { errors: {}, values, submissionToken, message: unavailableMessage } };
  let turnstile;
  try { turnstile = await input.turnstile.verify(turnstileToken, createTurnstileIdempotencyKey(submissionToken, turnstileToken)); }
  catch { turnstile = "unavailable" as const; }
  if (turnstile !== "verified") return { kind: "state", state: { errors: {}, values, submissionToken, message: unavailableMessage } };
  const post = await input.admission.consumePost({ releaseId: input.ingress.releaseId, clientPseudonym: input.ingress.clientPseudonym,
    requestBinding: input.ingress.requestBinding, nonce: input.ingress.nonce, permit: pre.permit });
  if (post.decision !== "allowed") return { kind: "state", state: { errors: {}, values, submissionToken, message: unavailableMessage } };
  try {
    const stored = await input.repository.create({ request: parsed.data, submissionToken, payloadFingerprint: createPayloadFingerprint(parsed.data) });
    if (stored.status === "conflict") return { kind: "state", state: { errors: {}, values, submissionToken, message: "Talebiniz iletilemedi. Lütfen sayfayı yenileyip bilgilerinizi yeniden gönderin." } };
    if (stored.status === "created" || stored.status === "idempotent") return { kind: "persisted" };
  } catch {
    // The database may have committed before the connection was interrupted.
    return { kind: "unconfirmed" };
  }
  return { kind: "unconfirmed" };
}
