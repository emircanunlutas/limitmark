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
  verify(token: string): Promise<VerifiedVercelOidcClaims>;
}

export type VercelOidcPolicy = {
  issuer: string;
  audience: string;
  subject: string;
  ownerId: string;
  projectId: string;
};

export async function authenticateVercelOidc(token: string, verifier: VercelOidcSignatureVerifier, policy: VercelOidcPolicy, nowMs: number): Promise<boolean> {
  if (!token || token.length > 8_192 || token.includes(",")) return false;
  try {
    const claims = await verifier.verify(token);
    const now = Math.floor(nowMs / 1_000);
    return claims.issuer === policy.issuer && claims.audience.length === 1 && claims.audience[0] === policy.audience &&
      claims.subject === policy.subject && claims.ownerId === policy.ownerId && claims.projectId === policy.projectId &&
      claims.environment === "production" && Number.isSafeInteger(claims.issuedAtSeconds) &&
      Number.isSafeInteger(claims.expiresAtSeconds) && claims.issuedAtSeconds <= now + 5 && claims.expiresAtSeconds >= now &&
      (claims.notBeforeSeconds === undefined || Number.isSafeInteger(claims.notBeforeSeconds) && claims.notBeforeSeconds <= now);
  } catch {
    return false;
  }
}
