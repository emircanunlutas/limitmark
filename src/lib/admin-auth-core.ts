import "server-only";

import {
  getAdminAuthConfiguration,
  type AdminAuthEnvironment,
  type AdminAuthConfiguration,
} from "./admin-auth-config";
import {
  isVerifiedCloudflareAccessIdentity,
  verifyCloudflareAccessToken,
  type VerifiedCloudflareAccessIdentity,
} from "./cloudflare-access";

type EnabledAdminAuthConfiguration = Extract<AdminAuthConfiguration, { enabled: true }>;
type AccessTokenVerifier = (
  token: string,
  configuration: EnabledAdminAuthConfiguration,
) => Promise<VerifiedCloudflareAccessIdentity>;

const authorizedAdminBrand: unique symbol = Symbol("authorized-admin-identity");

export type AuthorizedAdminIdentity = Readonly<{
  email: string;
  [authorizedAdminBrand]: true;
}>;

export type HeaderReader = Pick<Headers, "get">;

/** Only Cloudflare's documented origin assertion header is accepted. */
export function extractCloudflareAccessToken(requestHeaders: HeaderReader): string | null {
  const token = requestHeaders.get("cf-access-jwt-assertion")?.trim() ?? "";
  return token.length > 0 ? token : null;
}

/** Authorization is an explicit exact-mailbox check after verification. */
export function authorizeAdmin(
  identity: VerifiedCloudflareAccessIdentity,
  allowedEmails: ReadonlySet<string>,
): AuthorizedAdminIdentity | null {
  if (!isVerifiedCloudflareAccessIdentity(identity) || !allowedEmails.has(identity.email)) {
    return null;
  }

  return Object.freeze({
    email: identity.email,
    [authorizedAdminBrand]: true as const,
  });
}

/** Testable request boundary; every failure is intentionally collapsed to denial. */
export async function resolveAdminFromRequest(
  requestHeaders: HeaderReader,
  environment: AdminAuthEnvironment,
  verifyToken: AccessTokenVerifier = verifyCloudflareAccessToken,
): Promise<AuthorizedAdminIdentity | null> {
  const configuration = getAdminAuthConfiguration(environment);
  if (!configuration.enabled) return null;

  const token = extractCloudflareAccessToken(requestHeaders);
  if (!token) return null;

  try {
    const identity = await verifyToken(token, configuration);
    return authorizeAdmin(identity, configuration.allowedEmails);
  } catch {
    return null;
  }
}
