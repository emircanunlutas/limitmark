import "server-only";

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
  if (["cf-connecting-ip", "cf-connecting-ipv6", "cf-ray", "cf-worker", "cf-ew-via",
    "cf-pseudo-ipv4", "cf-connecting-o2o", "x-limitmark-origin-secret"]
    .some((name) => headers.get(name) !== null)) return null;
  const value = headers.get("x-vercel-forwarded-for")?.trim() ?? "";
  if (!value || value.includes(",") || value.includes("%") || isIP(value) === 0) return null;
  if (isIP(value) === 4) return value;
  // Equivalent IPv6 spellings, including IPv4-mapped addresses, share a bucket.
  const normalized = new URL(`http://[${value}]/`).hostname.slice(1, -1);
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(normalized);
  if (!mapped) return normalized;
  const high = Number.parseInt(mapped[1], 16);
  const low = Number.parseInt(mapped[2], 16);
  return [high >>> 8, high & 255, low >>> 8, low & 255].join(".");
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
