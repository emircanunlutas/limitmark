import {
  INGRESS_IDENTITY_VERSION,
  decodeCanonicalBase64url,
  encodeBase64url,
  toArrayBuffer,
} from "../../src/lib/ingress-protocol";

export const CLOUDFLARE_CLIENT_IP_HEADER = "cf-connecting-ip";
export const CLOUDFLARE_CROSS_ZONE_SENTINEL = "2a06:98c0:3600::103";
const identityDomain = new TextEncoder().encode(`limitmark:client:${INGRESS_IDENTITY_VERSION}\0`);

export type CanonicalAddress = { family: 4 | 6; bytes: Uint8Array };

function parseIpv4(value: string): Uint8Array | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let index = 0; index < 4; index++) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(parts[index])) return null;
    const part = Number(parts[index]);
    if (part > 255) return null;
    bytes[index] = part;
  }
  // Cloudflare Pseudo IPv4 uses the reserved Class E range. Production policy
  // requires Pseudo IPv4 off, so such an identity is never signed.
  if (bytes[0] >= 240) return null;
  return bytes;
}

function parseIpv6(value: string): Uint8Array | null {
  if (!value.includes(":")) return null;
  let input = value.toLowerCase();
  const dotted = input.lastIndexOf(":") + 1;
  if (input.slice(dotted).includes(".")) {
    const ipv4 = parseIpv4(input.slice(dotted));
    if (!ipv4) return null;
    input = `${input.slice(0, dotted)}${((ipv4[0] << 8) | ipv4[1]).toString(16)}:${((ipv4[2] << 8) | ipv4[3]).toString(16)}`;
  }
  if ((input.match(/::/g) ?? []).length > 1) return null;
  const sides = input.split("::");
  if (sides.length > 2) return null;
  const left = sides[0] ? sides[0].split(":") : [];
  const right = sides.length === 2 && sides[1] ? sides[1].split(":") : [];
  if ([...left, ...right].some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  const missing = 8 - left.length - right.length;
  if (sides.length === 1 ? missing !== 0 : missing < 1) return null;
  const words = [...left, ...Array.from({ length: missing }, () => "0"), ...right].map((part) => Number.parseInt(part, 16));
  if (words.length !== 8) return null;
  const bytes = new Uint8Array(16);
  words.forEach((word, index) => { bytes[index * 2] = word >>> 8; bytes[index * 2 + 1] = word & 255; });
  return bytes;
}

export function parseCloudflareClientAddress(value: string | null): CanonicalAddress | null {
  if (!value || value !== value.trim() || value.includes(",") || value.includes("%") || value.includes("[") || value.includes("]")) return null;
  const v4 = parseIpv4(value);
  if (v4) return { family: 4, bytes: v4 };
  const v6 = parseIpv6(value);
  if (!v6) return null;
  if (v6.every((byte, index) => byte === Uint8Array.of(0x2a, 0x06, 0x98, 0xc0, 0x36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3)[index])) return null;
  const mapped = v6.subarray(0, 10).every((byte) => byte === 0) && v6[10] === 0xff && v6[11] === 0xff;
  return mapped ? { family: 4, bytes: v6.slice(12) } : { family: 6, bytes: v6 };
}

export async function deriveClientPseudonym(value: string | null, hmacKeyBase64url: string, subtle: SubtleCrypto = crypto.subtle): Promise<string | null> {
  const address = parseCloudflareClientAddress(value);
  if (!address) return null;
  let keyBytes: Uint8Array;
  try {
    keyBytes = decodeCanonicalBase64url(hmacKeyBase64url, 32);
  } catch {
    return null;
  }
  const message = new Uint8Array(identityDomain.length + 1 + address.bytes.length);
  message.set(identityDomain);
  message[identityDomain.length] = address.family;
  message.set(address.bytes, identityDomain.length + 1);
  const key = await subtle.importKey("raw", toArrayBuffer(keyBytes), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return encodeBase64url(new Uint8Array(await subtle.sign("HMAC", key, toArrayBuffer(message))));
}
