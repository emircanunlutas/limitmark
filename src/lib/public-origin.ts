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
};

export function isPublicOriginProtectionDisabled(environment: PublicOriginEnvironment): boolean {
  return environment.PUBLIC_ORIGIN_PROTECTION === undefined ||
    environment.PUBLIC_ORIGIN_PROTECTION === "disabled";
}

/** Routing restrictions supplement secret authentication; Host is never identity. */
export function isPublicOriginAllowed(headers: HeaderReader, environment: PublicOriginEnvironment): boolean {
  if (isPublicOriginProtectionDisabled(environment)) return true;
  if (environment.PUBLIC_ORIGIN_PROTECTION !== "required" ||
      environment.VERCEL !== "1" || environment.VERCEL_ENV !== "production") return false;

  const expected = environment.PUBLIC_ORIGIN_SECRET ?? "";
  const received = headers.get(publicOriginHeader) ?? "";
  // Fixed-size server-only bearer secret. No trimming, duplicate values or fallback.
  if (!/^[A-Za-z0-9_-]{43}$/.test(expected) || !/^[A-Za-z0-9_-]{43}$/.test(received)) return false;
  if (!timingSafeEqual(Buffer.from(expected), Buffer.from(received))) return false;

  const host = headers.get("host");
  return (host === "limitmark.com" || host === "www.limitmark.com") &&
    headers.get("x-forwarded-host") === host;
}
