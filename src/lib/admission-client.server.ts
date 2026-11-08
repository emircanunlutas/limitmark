import "server-only";

import {
  ADMISSION_MAC_HEADER,
  ADMISSION_KEY_ID_HEADER,
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
import { decodeJwt } from "jose";
import { getContext, getVercelOidcToken } from "@vercel/oidc";
import type { ClaimPreInput, ConsumePostInput, PostDecision, PreDecision } from "../../workers/admission-service/authority";

export interface ProductionOidcTokenProvider { getToken(audience: string): Promise<string> }

/** The platform header that carries a Vercel Function's own OIDC token (set by Vercel on the function Request; see https://vercel.com/docs/oidc). */
export const VERCEL_OIDC_REQUEST_HEADER = "x-vercel-oidc-token";
export const VERCEL_OIDC_EXCHANGE_TIMEOUT_MS = 1_500;
/** Upper bound on SDK exchanges that have been started and not yet settled. The SDK's exchange fetch has no AbortSignal, so a call abandoned by the
 * timeout below keeps running until the network gives up; this cap keeps a Vercel identity outage from accumulating unbounded pending requests.
 * Over the cap the provider fails closed immediately and never calls the SDK. */
export const VERCEL_OIDC_MAX_PENDING_EXCHANGES = 16;
export type VercelOidcExchangeLimiter = { pending: number; readonly maximum: number };
/** One per process: provider instances are created per request, the limiter must outlive them. */
const sharedExchangeLimiter: VercelOidcExchangeLimiter = { pending: 0, maximum: VERCEL_OIDC_MAX_PENDING_EXCHANGES };

/** The narrow part of `@vercel/oidc` this provider uses; injectable so the failure modes can be tested without a Vercel runtime. */
export type VercelOidcSdk = {
  getContext(): { headers?: Record<string, string | undefined> } | undefined;
  getVercelOidcToken(options: { audience: string }): Promise<string>;
};
const defaultVercelOidcSdk: VercelOidcSdk = { getContext, getVercelOidcToken: (options) => getVercelOidcToken(options) };

/**
 * Production token provider for admission: a Vercel-issued OIDC token whose `aud` is the dedicated admission audience.
 *
 * Request-scoped and uncached by design (Vercel: "Don't cache the returned token"): every call re-reads the request context and re-asks the SDK,
 * whose own exchange cache is keyed by token and audience. Fail-closed: it throws, with a fixed non-secret message, unless
 *  - the Vercel request context carries the platform header (so the build/dev fallbacks of the SDK -- `VERCEL_OIDC_TOKEN`, `VERCEL_OIDC_TOKEN_FILE`
 *    and the local CLI refresh path -- can never supply a token in production),
 *  - the SDK resolves within the timeout, and
 *  - the returned JWT is well formed, carries exactly the requested audience and `environment: "production"`.
 * The token is never logged, stored or included in an error. The Worker remains the authority on issuer/subject/project; the checks here only
 * stop this process from sending an obviously wrong token.
 */
export class VercelRequestOidcTokenProvider implements ProductionOidcTokenProvider {
  constructor(
    private readonly sdk: VercelOidcSdk = defaultVercelOidcSdk,
    private readonly timeoutMs: number = VERCEL_OIDC_EXCHANGE_TIMEOUT_MS,
    private readonly limiter: VercelOidcExchangeLimiter = sharedExchangeLimiter,
  ) {}

  async getToken(audience: string): Promise<string> {
    if (!audience || audience.length > 256 || /[\s,]/u.test(audience)) throw new Error("oidc-audience");
    const platformToken = this.sdk.getContext()?.headers?.[VERCEL_OIDC_REQUEST_HEADER];
    if (typeof platformToken !== "string" || platformToken === "") throw new Error("vercel-oidc-context");
    if (this.limiter.pending >= this.limiter.maximum) throw new Error("vercel-oidc-saturated");
    let timer: ReturnType<typeof setTimeout> | undefined;
    let token: unknown;
    try {
      const exchange = this.sdk.getVercelOidcToken({ audience });
      this.limiter.pending += 1;
      // Released when the SDK call itself settles (not when we stop waiting for it); the extra handler also keeps a late rejection from being unhandled.
      void Promise.resolve(exchange).then(() => undefined, () => undefined).finally(() => { this.limiter.pending -= 1; });
      token = await Promise.race([
        exchange,
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("vercel-oidc-timeout")), this.timeoutMs); }),
      ]);
    } catch (error) {
      throw new Error(error instanceof Error && error.message === "vercel-oidc-timeout" ? "vercel-oidc-timeout" : "vercel-oidc-exchange");
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
    if (typeof token !== "string" || !token || token.length > 8_192 || /[\s,]/u.test(token) || token.split(".").length !== 3) throw new Error("vercel-oidc-token");
    let claims;
    try { claims = decodeJwt(token); } catch { throw new Error("vercel-oidc-token"); }
    const claimedAudience = Array.isArray(claims.aud) ? (claims.aud.length === 1 ? claims.aud[0] : undefined) : claims.aud;
    if (claimedAudience !== audience || claims["environment"] !== "production") throw new Error("vercel-oidc-claims");
    return token;
  }
}

export class GoogleMetadataOidcTokenProvider implements ProductionOidcTokenProvider {
  private cached?: { audience: string; token: string; expiresAtMs: number };
  constructor(
    private readonly request: typeof fetch = fetch,
    private readonly now: () => number = Date.now,
    private readonly endpoint = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity",
  ) {}

  async getToken(audience: string): Promise<string> {
    if (!audience || audience.length > 256 || /[\s,]/u.test(audience)) throw new Error("oidc-audience");
    const now = this.now();
    if (this.cached && this.cached.audience === audience && this.cached.expiresAtMs - 60_000 > now) return this.cached.token;
    const url = new URL(this.endpoint);
    if (url.protocol !== "http:" || url.hostname !== "metadata.google.internal" ||
        url.pathname !== "/computeMetadata/v1/instance/service-accounts/default/identity" || url.username || url.password || url.port || url.search || url.hash) {
      throw new Error("metadata-endpoint");
    }
    url.searchParams.set("audience", audience);
    url.searchParams.set("format", "full");
    const response = await this.request(url, {
      method: "GET",
      headers: { "Metadata-Flavor": "Google" },
      signal: AbortSignal.timeout(2_000),
      redirect: "manual",
    });
    if (!response.ok) throw new Error("metadata-token");
    const token = (await response.text()).trim();
    if (!token || token.length > 8_192) throw new Error("metadata-token");
    const claims = decodeJwt(token);
    if (typeof claims.exp !== "number" || !Number.isSafeInteger(claims.exp) || claims.exp * 1_000 <= now) throw new Error("metadata-expiry");
    this.cached = { audience, token, expiresAtMs: claims.exp * 1_000 };
    return token;
  }
}
export interface AdmissionClient {
  claimPre(input: ClaimPreInput): Promise<PreDecision>;
  consumePost(input: ConsumePostInput): Promise<PostDecision>;
}

export type AdmissionClientEnvironment = {
  VERCEL?: string; VERCEL_ENV?: string; VERCEL_DEPLOYMENT_ID?: string;
  ADMISSION_SERVICE_URL?: string; ADMISSION_OIDC_AUDIENCE?: string;
  ADMISSION_RELEASE_ID?: string; ADMISSION_RELEASE_KEY_ID?: string; ADMISSION_RELEASE_RPC_KEY?: string;
};

async function createAdmissionClient(environment: AdmissionClientEnvironment, oidc: ProductionOidcTokenProvider, request: typeof fetch, expectedDeploymentId: string | undefined): Promise<AdmissionClient | null> {
  if (!expectedDeploymentId || environment.ADMISSION_RELEASE_ID !== expectedDeploymentId || !environment.ADMISSION_OIDC_AUDIENCE ||
      !environment.ADMISSION_RELEASE_KEY_ID || !/^[A-Za-z0-9_-]{1,64}$/u.test(environment.ADMISSION_RELEASE_KEY_ID)) return null;
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
        headers: { authorization: `Bearer ${token}`, "content-type": ADMISSION_RPC_CONTENT_TYPE,
          [ADMISSION_KEY_ID_HEADER]: environment.ADMISSION_RELEASE_KEY_ID!, [ADMISSION_MAC_HEADER]: await signAdmissionRpc(path, body, key) },
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

export async function createProductionAdmissionClient(environment: AdmissionClientEnvironment, oidc: ProductionOidcTokenProvider, request: typeof fetch = fetch): Promise<AdmissionClient | null> {
  if (environment.VERCEL !== "1" || environment.VERCEL_ENV !== "production" || !environment.VERCEL_DEPLOYMENT_ID) return null;
  return createAdmissionClient(environment, oidc, request, environment.VERCEL_DEPLOYMENT_ID);
}

export async function createLaboratoryAdmissionClient(environment: AdmissionClientEnvironment & { LAB_DEPLOYMENT_ID?: string }, oidc: ProductionOidcTokenProvider, request: typeof fetch = fetch): Promise<AdmissionClient | null> {
  return createAdmissionClient(environment, oidc, request, environment.LAB_DEPLOYMENT_ID);
}
