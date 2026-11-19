import "server-only";

import { timingSafeEqual } from "node:crypto";
import type { HeaderReader } from "./client-identity";

export const publicOriginHeader = "x-limitmark-origin-secret";

export type PublicOriginEnvironment = {
  [key: string]: string | undefined;
  PUBLIC_ORIGIN_PROTECTION?: string;
  PUBLIC_ORIGIN_SECRET?: string;
  VERCEL?: string;
  VERCEL_ENV?: string;
  LIMITMARK_RUNTIME?: string;
  PUBLIC_ORIGIN_HOSTNAME?: string;
  PUBLIC_ORIGIN_PUBLIC_HOSTNAME?: string;
};

/** Returns the environment the origin gate must evaluate. In the explicit `cloud-run-lab` runtime (selected only by server configuration, never by
 * request input) the laboratory-scoped LAB_* values are the sole source of the origin secret and hostnames: any raw PUBLIC_ORIGIN_* value is
 * ignored, and a missing LAB_* value yields undefined, which isPublicOriginAllowed rejects (fail closed). Every other runtime is returned unchanged.
 * The laboratory runtime forbids production-named credentials such as PUBLIC_ORIGIN_SECRET in the raw environment, so the gate cannot read them there. */
export function resolveOriginProtectionEnvironment(environment: PublicOriginEnvironment): PublicOriginEnvironment {
  if (environment.LIMITMARK_RUNTIME !== "cloud-run-lab") return environment;
  return {
    ...environment,
    PUBLIC_ORIGIN_SECRET: environment.LAB_PUBLIC_ORIGIN_SECRET,
    PUBLIC_ORIGIN_HOSTNAME: environment.LAB_ORIGIN_HOSTNAME,
    PUBLIC_ORIGIN_PUBLIC_HOSTNAME: environment.LAB_PUBLIC_HOSTNAME,
  };
}

export function isPublicOriginProtectionDisabled(environment: PublicOriginEnvironment): boolean {
  return environment.PUBLIC_ORIGIN_PROTECTION === undefined ||
    environment.PUBLIC_ORIGIN_PROTECTION === "disabled";
}

/** Routing restrictions supplement secret authentication; Host is never identity. */
export function isPublicOriginAllowed(headers: HeaderReader, environment: PublicOriginEnvironment): boolean {
  if (isPublicOriginProtectionDisabled(environment)) return true;
  if (environment.PUBLIC_ORIGIN_PROTECTION !== "required") return false;

  const expected = environment.PUBLIC_ORIGIN_SECRET ?? "";
  const received = headers.get(publicOriginHeader) ?? "";
  // Fixed-size server-only bearer secret. No trimming, duplicate values or fallback.
  if (!/^[A-Za-z0-9_-]{43}$/.test(expected) || !/^[A-Za-z0-9_-]{43}$/.test(received)) return false;
  if (!timingSafeEqual(Buffer.from(expected), Buffer.from(received))) return false;

  const host = headers.get("host");
  if (environment.LIMITMARK_RUNTIME === "cloud-run-lab") {
    const expectedHost = environment.PUBLIC_ORIGIN_HOSTNAME;
    const publicHost = environment.PUBLIC_ORIGIN_PUBLIC_HOSTNAME;
    return Boolean(expectedHost && publicHost && host === expectedHost && headers.get("x-forwarded-host") === publicHost);
  }
  if (environment.VERCEL !== "1" || environment.VERCEL_ENV !== "production") return false;
  return (host === "limitmark.com" || host === "www.limitmark.com") && headers.get("x-forwarded-host") === host;
}
