import "server-only";

import {
  createRemoteJWKSet,
  decodeProtectedHeader,
  jwtVerify,
  type JWTVerifyGetKey,
} from "jose";
import type { AdminAuthConfiguration } from "./admin-auth-config";
import { getContactEmail } from "./contact-email";

type EnabledAdminAuthConfiguration = Extract<AdminAuthConfiguration, { enabled: true }>;
const CLOCK_TOLERANCE_SECONDS = 60;

const verifiedIdentityBrand: unique symbol = Symbol("verified-cloudflare-access-identity");

export type VerifiedCloudflareAccessIdentity = Readonly<{
  email: string;
  [verifiedIdentityBrand]: true;
}>;

export class CloudflareAccessVerificationError extends Error {
  constructor() {
    super("Cloudflare Access token verification failed");
    this.name = "CloudflareAccessVerificationError";
  }
}

type RemoteKeyResolver = {
  teamDomain: string;
  resolve: JWTVerifyGetKey;
};

let remoteKeyResolver: RemoteKeyResolver | undefined;

function getRemoteKeyResolver(teamDomain: string): JWTVerifyGetKey {
  if (remoteKeyResolver?.teamDomain === teamDomain) return remoteKeyResolver.resolve;

  const resolve = createRemoteJWKSet(
    new URL(`${teamDomain}/cdn-cgi/access/certs`),
    {
      timeoutDuration: 5_000,
      cooldownDuration: 30_000,
      cacheMaxAge: 600_000,
    },
  );
  remoteKeyResolver = { teamDomain, resolve };
  return resolve;
}

function hasCompactJwtShape(token: string): boolean {
  if (token.length === 0 || token.length > 16_384) return false;
  return token.split(".").length === 3 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token);
}

/**
 * Verifies signature and registered claims before returning a deliberately
 * minimal, runtime-branded identity. The resolver parameter exists only for
 * synthetic-key tests and other trusted server composition.
 */
export async function verifyCloudflareAccessToken(
  token: string,
  configuration: EnabledAdminAuthConfiguration,
  resolveKey: JWTVerifyGetKey = getRemoteKeyResolver(configuration.teamDomain),
): Promise<VerifiedCloudflareAccessIdentity> {
  try {
    if (!hasCompactJwtShape(token)) throw new CloudflareAccessVerificationError();

    const protectedHeader = decodeProtectedHeader(token);
    if (
      protectedHeader.alg !== "RS256" ||
      typeof protectedHeader.kid !== "string" ||
      protectedHeader.kid.length === 0 ||
      protectedHeader.kid.length > 512
    ) {
      throw new CloudflareAccessVerificationError();
    }

    const { payload } = await jwtVerify(token, resolveKey, {
      algorithms: ["RS256"],
      issuer: configuration.teamDomain,
      audience: configuration.audience,
      requiredClaims: ["exp", "iat", "email", "sub", "type"],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    });

    const email = typeof payload.email === "string" ? getContactEmail(payload.email) : null;
    const currentEpochSeconds = Math.floor(Date.now() / 1_000);
    const issuedAtIsValid =
      Number.isSafeInteger(payload.iat) &&
      (payload.iat as number) <= currentEpochSeconds + CLOCK_TOLERANCE_SECONDS;
    const subjectIsValid =
      typeof payload.sub === "string" &&
      payload.sub.trim() === payload.sub &&
      payload.sub.length > 0 &&
      payload.sub.length <= 512;

    if (!email || !issuedAtIsValid || !subjectIsValid || payload.type !== "app") {
      throw new CloudflareAccessVerificationError();
    }

    return Object.freeze({
      email: email.toLowerCase(),
      [verifiedIdentityBrand]: true as const,
    });
  } catch {
    throw new CloudflareAccessVerificationError();
  }
}

export function isVerifiedCloudflareAccessIdentity(
  value: unknown,
): value is VerifiedCloudflareAccessIdentity {
  return typeof value === "object" && value !== null &&
    verifiedIdentityBrand in value &&
    value[verifiedIdentityBrand] === true;
}
