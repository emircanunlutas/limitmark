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
  // public client address for direct ingress. The deployment gate must
  // establish Vercel with no upstream proxy. Never fall back to arbitrary
  // X-Forwarded-For, X-Real-IP, CF-Connecting-IP, or similar client input.
  // An unexpected Cloudflare hop is incompatible with this direct-only policy.
  // Presence is grounds for denial, never proof of Cloudflare authentication.
  if (["cf-connecting-ip", "cf-connecting-ipv6", "cf-ray", "x-limitmark-origin-secret"]
    .some((name) => headers.get(name) !== null)) return null;
  const value = headers.get("x-vercel-forwarded-for")?.trim() ?? "";
  if (!value || value.includes(",") || value.includes("%") || isIP(value) === 0) return null;
  // Equivalent IPv6 spellings must share a limiter bucket.
  return isIP(value) === 6 ? new URL(`http://[${value}]/`).hostname.slice(1, -1) : value;
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
