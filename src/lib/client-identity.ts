import { createHmac } from "node:crypto";
import { isIP } from "node:net";
import { Buffer } from "node:buffer";

export type HeaderReader = Pick<Headers, "get">;

export type ClientIdentityConfiguration = {
  source: "vercel";
  hmacSecret: string;
};

function readVercelClientIp(headers: HeaderReader): string | null {
  // Vercel documents x-vercel-forwarded-for as its platform copy of the
  // public client address. Trust it only when the deployment gate explicitly
  // establishes Vercel as the immediate boundary. Never fall back to arbitrary
  // X-Forwarded-For, X-Real-IP, CF-Connecting-IP, or similar client input.
  const value = headers.get("x-vercel-forwarded-for")?.trim() ?? "";
  if (!value || value.includes(",") || isIP(value) === 0) return null;
  return value;
}

export function derivePrivateClientKey(
  headers: HeaderReader,
  configuration: ClientIdentityConfiguration,
): string | null {
  const ip = configuration.source === "vercel" ? readVercelClientIp(headers) : null;
  if (!ip) return null;
  return createHmac("sha256", Buffer.from(configuration.hmacSecret, "base64url"))
    .update(`public-inquiry-client-v1\0${ip}`, "utf8")
    .digest("base64url");
}
