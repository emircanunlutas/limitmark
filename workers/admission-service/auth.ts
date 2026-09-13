import { jwtVerify } from "jose";
import { BoundedRs256JwksResolver, inspectCompactJwt, type BoundedJwksOptions } from "../shared/bounded-jwks";

export type VerifiedVercelOidcClaims = {
  issuer: string;
  audience: readonly string[];
  subject: string;
  ownerId: string;
  projectId: string;
  environment: string;
  issuedAtSeconds: number;
  notBeforeSeconds?: number;
  expiresAtSeconds: number;
};

/** The implementation behind this seam must verify signature and allowed alg
 * against a fixed Vercel issuer/JWKS configuration before returning claims. */
export interface VercelOidcSignatureVerifier {
  verify(token: string, nowMs: number): Promise<VerifiedVercelOidcClaims>;
}

export type VercelOidcPolicy = {
  issuer: string;
  audience: string;
  subject: string;
  ownerId: string;
  projectId: string;
};

export const VERCEL_OIDC_CLOCK_TOLERANCE_SECONDS = 5;
export const VERCEL_OIDC_MAX_LIFETIME_SECONDS = 7_200;

function exactString(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= maximum && value.trim() === value;
}

function exactNumericDate(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function exactAudience(value: unknown, expected: string): readonly [string] | null {
  if (value === expected) return [expected];
  if (Array.isArray(value) && value.length === 1 && value[0] === expected) return [expected];
  return null;
}

function timestampsAreValid(iat: number, nbf: number, exp: number, now: number): boolean {
  const lifetime = exp - iat;
  return lifetime >= 0 && lifetime <= VERCEL_OIDC_MAX_LIFETIME_SECONDS &&
    iat <= now + VERCEL_OIDC_CLOCK_TOLERANCE_SECONDS &&
    nbf <= now + VERCEL_OIDC_CLOCK_TOLERANCE_SECONDS &&
    exp > now - VERCEL_OIDC_CLOCK_TOLERANCE_SECONDS;
}

export function getVercelJwksEndpoint(issuer: string): URL {
  const url = new URL(issuer);
  if (url.protocol !== "https:" || url.hostname !== "oidc.vercel.com" || url.username || url.password || url.port || url.search || url.hash ||
      !/^\/[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/u.test(url.pathname)) throw new Error("vercel-issuer");
  return new URL(`${url.origin}${url.pathname}/.well-known/jwks`);
}

/** Concrete Production verifier. Its issuer and JWKS endpoint derive only from reviewed policy. */
export function createVercelOidcVerifier(policy: VercelOidcPolicy, options: Omit<BoundedJwksOptions, "endpoint"> = {}): VercelOidcSignatureVerifier {
  const subject = /^owner:([A-Za-z0-9_-]{1,128}):project:([A-Za-z0-9_.-]{1,128}):environment:production$/u.exec(policy.subject);
  if (!subject) throw new Error("vercel-subject-policy");
  const [, expectedOwner, expectedProject] = subject;
  const resolver = new BoundedRs256JwksResolver({ endpoint: getVercelJwksEndpoint(policy.issuer), ...options });
  return {
    async verify(token: string, nowMs: number): Promise<VerifiedVercelOidcClaims> {
      const inspected = inspectCompactJwt(token, 8_192);
      const audience = exactAudience(inspected.payload.aud, policy.audience);
      const now = Math.floor(nowMs / 1_000);
      if (inspected.header.alg !== "RS256" || !exactString(inspected.header.kid, 128)) throw new Error("oidc-header");
      if (inspected.header.typ !== undefined && inspected.header.typ !== "JWT" && inspected.header.typ !== "jwt") throw new Error("oidc-type");
      if (inspected.payload.iss !== policy.issuer || !audience || inspected.payload.sub !== policy.subject ||
          inspected.payload.owner_id !== policy.ownerId || inspected.payload.project_id !== policy.projectId || inspected.payload.environment !== "production" ||
          inspected.payload.owner !== expectedOwner || inspected.payload.project !== expectedProject ||
          !exactNumericDate(inspected.payload.iat) || !exactNumericDate(inspected.payload.nbf) || !exactNumericDate(inspected.payload.exp)) throw new Error("oidc-claims");
      if (!timestampsAreValid(inspected.payload.iat, inspected.payload.nbf, inspected.payload.exp, now)) throw new Error("oidc-lifetime");

      const { payload } = await jwtVerify(token, resolver.resolve, {
        algorithms: ["RS256"],
        issuer: policy.issuer,
        audience: policy.audience,
        subject: policy.subject,
        requiredClaims: ["iss", "aud", "sub", "owner", "owner_id", "project", "project_id", "environment", "iat", "nbf", "exp"],
        clockTolerance: VERCEL_OIDC_CLOCK_TOLERANCE_SECONDS,
        currentDate: new Date(nowMs),
      });
      const verifiedAudience = exactAudience(payload.aud, policy.audience);
      if (!verifiedAudience || payload.owner_id !== policy.ownerId || payload.project_id !== policy.projectId || payload.environment !== "production" ||
          !exactNumericDate(payload.iat) || !exactNumericDate(payload.nbf) || !exactNumericDate(payload.exp) ||
          !timestampsAreValid(payload.iat, payload.nbf, payload.exp, now)) throw new Error("oidc-verified-claims");
      return {
        issuer: payload.iss!, audience: verifiedAudience, subject: payload.sub!, ownerId: payload.owner_id,
        projectId: payload.project_id, environment: payload.environment,
        issuedAtSeconds: payload.iat, notBeforeSeconds: payload.nbf, expiresAtSeconds: payload.exp,
      };
    },
  };
}

export async function authenticateVercelOidc(token: string, verifier: VercelOidcSignatureVerifier, policy: VercelOidcPolicy, nowMs: number): Promise<boolean> {
  if (!token || token.length > 8_192 || token.includes(",")) return false;
  try {
    const claims = await verifier.verify(token, nowMs);
    const now = Math.floor(nowMs / 1_000);
    return claims.issuer === policy.issuer && claims.audience.length === 1 && claims.audience[0] === policy.audience &&
      claims.subject === policy.subject && claims.ownerId === policy.ownerId && claims.projectId === policy.projectId &&
      claims.environment === "production" && exactNumericDate(claims.issuedAtSeconds) &&
      exactNumericDate(claims.notBeforeSeconds) && exactNumericDate(claims.expiresAtSeconds) &&
      timestampsAreValid(claims.issuedAtSeconds, claims.notBeforeSeconds, claims.expiresAtSeconds, now);
  } catch {
    return false;
  }
}
