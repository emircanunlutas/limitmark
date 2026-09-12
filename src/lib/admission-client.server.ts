import "server-only";

import {
  ADMISSION_MAC_HEADER,
  ADMISSION_POST_PATH,
  ADMISSION_PRE_PATH,
  ADMISSION_RPC_CONTENT_TYPE,
  ADMISSION_RPC_VERSION,
  encodeAdmissionRpcPayload,
  importAdmissionRpcKey,
  signAdmissionRpc,
  type AdmissionRpcPayload,
} from "./admission-protocol";
import { decodeCanonicalBase64url, encodeBase64url, toArrayBuffer } from "./ingress-protocol";
import type { ClaimPreInput, ConsumePostInput, PostDecision, PreDecision } from "../../workers/admission-service/authority";

export interface ProductionOidcTokenProvider { getToken(audience: string): Promise<string> }
export interface AdmissionClient {
  claimPre(input: ClaimPreInput): Promise<PreDecision>;
  consumePost(input: ConsumePostInput): Promise<PostDecision>;
}

export type AdmissionClientEnvironment = {
  VERCEL?: string; VERCEL_ENV?: string; VERCEL_DEPLOYMENT_ID?: string;
  ADMISSION_SERVICE_URL?: string; ADMISSION_OIDC_AUDIENCE?: string;
  ADMISSION_RELEASE_ID?: string; ADMISSION_RELEASE_RPC_KEY?: string;
};

export async function createProductionAdmissionClient(environment: AdmissionClientEnvironment, oidc: ProductionOidcTokenProvider, request: typeof fetch = fetch): Promise<AdmissionClient | null> {
  if (environment.VERCEL !== "1" || environment.VERCEL_ENV !== "production" || !environment.VERCEL_DEPLOYMENT_ID ||
      environment.ADMISSION_RELEASE_ID !== environment.VERCEL_DEPLOYMENT_ID || !environment.ADMISSION_OIDC_AUDIENCE) return null;
  let endpoint: URL;
  try { endpoint = new URL(environment.ADMISSION_SERVICE_URL ?? ""); } catch { return null; }
  if (endpoint.protocol !== "https:" || endpoint.pathname !== "/" || endpoint.search || endpoint.hash || endpoint.username || endpoint.password) return null;
  let key: CryptoKey;
  try { key = await importAdmissionRpcKey(environment.ADMISSION_RELEASE_RPC_KEY ?? ""); } catch { return null; }

  async function call(path: typeof ADMISSION_PRE_PATH | typeof ADMISSION_POST_PATH, input: ClaimPreInput | ConsumePostInput): Promise<PreDecision | PostDecision> {
    try {
      const issuedAtMs = Date.now();
      const payload: AdmissionRpcPayload = [ADMISSION_RPC_VERSION, input.releaseId,
        encodeBase64url(crypto.getRandomValues(new Uint8Array(16))), issuedAtMs,
        input.clientPseudonym, input.requestBinding, input.nonce, "permit" in input ? input.permit : "-",
        "issuedAtMs" in input ? input.issuedAtMs : 0];
      const body = encodeAdmissionRpcPayload(payload);
      const token = await oidc.getToken(environment.ADMISSION_OIDC_AUDIENCE!);
      const response = await request(new URL(path, endpoint), {
        method: "POST", body: toArrayBuffer(body), cache: "no-store", redirect: "manual", signal: AbortSignal.timeout(2_000),
        headers: { authorization: `Bearer ${token}`, "content-type": ADMISSION_RPC_CONTENT_TYPE, [ADMISSION_MAC_HEADER]: await signAdmissionRpc(path, body, key) },
      });
      if (!response.ok) return { decision: "unavailable" };
      const text = await response.text();
      if (text.length > 1_024) return { decision: "unavailable" };
      const value = JSON.parse(text) as Record<string, unknown>;
      const keys = Object.keys(value).sort();
      if (path === ADMISSION_PRE_PATH && value.decision === "allowed" && typeof value.permit === "string" && typeof value.expiresAtMs === "number" &&
          Number.isSafeInteger(value.expiresAtMs) && keys.join(",") === "decision,expiresAtMs,permit") {
        decodeCanonicalBase64url(value.permit, 32);
        return value as PreDecision;
      }
      if (["limited", "replay", "unavailable"].includes(String(value.decision)) && keys.join(",") === "decision") return { decision: value.decision as "limited" | "replay" | "unavailable" };
      if (path === ADMISSION_POST_PATH && value.decision === "allowed" && keys.join(",") === "decision") return { decision: "allowed" };
      return { decision: "unavailable" };
    } catch {
      // A consuming call is never retried. Lost response remains unavailable.
      return { decision: "unavailable" };
    }
  }
  return {
    claimPre: (input) => call(ADMISSION_PRE_PATH, input) as Promise<PreDecision>,
    consumePost: (input) => call(ADMISSION_POST_PATH, input) as Promise<PostDecision>,
  };
}
