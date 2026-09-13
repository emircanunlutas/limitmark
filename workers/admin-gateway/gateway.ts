import { jwtVerify } from "jose";
import { BoundedRs256JwksResolver, inspectCompactJwt, type BoundedJwksOptions } from "../shared/bounded-jwks";

export const ADMIN_GATEWAY_HOST = "admin.limitmark.com";
export const ADMIN_GATEWAY_MAX_BODY_BYTES = 256 * 1024;
const ACCESS_CLOCK_TOLERANCE_SECONDS = 60;
const reconstructableNullBodyStatuses = new Set([204, 205, 304]);
const bypassQueryNames = new Set(["x-vercel-protection-bypass", "x-vercel-set-bypass-cookie", "__vercel_protection_bypass"]);
const strippedRequestHeaders = new Set([
  "authorization", "proxy-authorization", "host", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port",
  "x-vercel-protection-bypass", "x-vercel-set-bypass-cookie", "x-vercel-deployment-url", "x-vercel-id",
  "x-vercel-forwarded-for", "x-vercel-ip-country", "x-vercel-ip-city", "x-now-route-matches", "x-matched-path",
  "x-limitmark-origin-secret", "x-limitmark-ingress", "x-limitmark-admission-mac", "x-limitmark-admission-key-id",
]);

export type AdminGatewayConfiguration = {
  environment: "production";
  publicHost: typeof ADMIN_GATEWAY_HOST;
  upstreamOrigin: string;
  accessIssuer: string;
  accessAudience: string;
  allowedAdminEmail: string;
  vercelAutomationBypassSecret: string;
};

function fixedUpstream(value: string): URL {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.port || url.pathname !== "/" || url.search || url.hash ||
      !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.vercel\.app$/u.test(url.hostname)) throw new Error("admin-upstream");
  return url;
}

function fixedAccessIssuer(value: string): URL {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.port || url.pathname !== "/" || url.search || url.hash ||
      !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/u.test(url.hostname)) throw new Error("access-issuer");
  return url;
}

function authorizedPath(pathname: string, method: string): boolean {
  if (pathname.includes("\\") || /%(?:2f|5c|00)/iu.test(pathname) || pathname.includes("//")) return false;
  if (method === "GET" || method === "HEAD") return pathname === "/admin" || pathname === "/admin/" || pathname.startsWith("/admin/inquiries/") || pathname.startsWith("/_next/static/");
  return method === "POST" && (pathname === "/admin" || pathname === "/admin/" || pathname.startsWith("/admin/inquiries/"));
}

function sanitizeCookie(value: string | null): string | null {
  if (!value) return null;
  const retained = value.split(";").map((part) => part.trim()).filter((part) => {
    const name = part.split("=", 1)[0].toLowerCase();
    return name !== "_vercel_jwt" && !name.includes("vercel_protection_bypass") && name !== "cf_authorization";
  });
  return retained.length ? retained.join("; ") : null;
}

function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (!needle.length || needle.length > haystack.length) return false;
  outer: for (let start = 0; start <= haystack.length - needle.length; start++) {
    for (let index = 0; index < needle.length; index++) if (haystack[start + index] !== needle[index]) continue outer;
    return true;
  }
  return false;
}

async function boundedBody(request: Request): Promise<ArrayBuffer | undefined> {
  if (request.method === "GET" || request.method === "HEAD") return undefined;
  const claimed = request.headers.get("content-length");
  if (claimed !== null && (!/^(?:0|[1-9][0-9]*)$/u.test(claimed) || Number(claimed) > ADMIN_GATEWAY_MAX_BODY_BYTES)) throw new Error("admin-body-size");
  if (!request.body) return new ArrayBuffer(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      length += item.value.length;
      if (length > ADMIN_GATEWAY_MAX_BODY_BYTES) throw new Error("admin-body-size");
      chunks.push(item.value);
    }
  } finally { reader.releaseLock(); }
  const body = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
  return body.buffer;
}

export function createAdminGateway(configuration: AdminGatewayConfiguration, dependencies: Omit<BoundedJwksOptions, "endpoint"> & { fetch?: typeof fetch } = {}) {
  let upstream: URL;
  let accessIssuer: URL;
  try { upstream = fixedUpstream(configuration.upstreamOrigin); accessIssuer = fixedAccessIssuer(configuration.accessIssuer); } catch { upstream = new URL("https://invalid.vercel.app"); accessIssuer = new URL("https://invalid.cloudflareaccess.com"); }
  const requestFetch = dependencies.fetch ?? fetch;
  const resolver = new BoundedRs256JwksResolver({
    ...dependencies, fetch: requestFetch, endpoint: new URL("/cdn-cgi/access/certs", accessIssuer), maximumKeys: 4,
    allowAdditionalTopLevelMembers: true,
  });

  return async function handle(request: Request): Promise<Response> {
    try {
      if (configuration.environment !== "production" || configuration.publicHost !== ADMIN_GATEWAY_HOST || upstream.hostname === "invalid.vercel.app" ||
          accessIssuer.hostname === "invalid.cloudflareaccess.com" || !/^[\x21-\x7e]{32,256}$/u.test(configuration.vercelAutomationBypassSecret) ||
          !/^[A-Za-z0-9_-]{1,512}$/u.test(configuration.accessAudience) || configuration.allowedAdminEmail !== configuration.allowedAdminEmail.toLowerCase() ||
          !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(configuration.allowedAdminEmail) || configuration.allowedAdminEmail.length > 254) return new Response(null, { status: 503 });
      const url = new URL(request.url);
      if (url.protocol !== "https:" || url.hostname !== ADMIN_GATEWAY_HOST || url.port || url.username || url.password || !authorizedPath(url.pathname, request.method)) return new Response(null, { status: 404 });
      for (const name of url.searchParams.keys()) if (bypassQueryNames.has(name.toLowerCase())) return new Response(null, { status: 404 });

      const assertion = request.headers.get("cf-access-jwt-assertion") ?? "";
      const nowMs = (dependencies.now ?? Date.now)();
      try {
        const inspected = inspectCompactJwt(assertion);
        if (inspected.header.alg !== "RS256" || typeof inspected.header.kid !== "string" || !/^[A-Za-z0-9._-]{1,128}$/u.test(inspected.header.kid) ||
            inspected.payload.iss !== configuration.accessIssuer ||
            !(inspected.payload.aud === configuration.accessAudience || Array.isArray(inspected.payload.aud) && inspected.payload.aud.length === 1 && inspected.payload.aud[0] === configuration.accessAudience) ||
            inspected.payload.email !== configuration.allowedAdminEmail || inspected.payload.type !== "app" || typeof inspected.payload.sub !== "string" ||
            !Number.isSafeInteger(inspected.payload.iat) || !Number.isSafeInteger(inspected.payload.exp) ||
            inspected.payload.nbf !== undefined && !Number.isSafeInteger(inspected.payload.nbf)) return new Response(null, { status: 403 });
        await jwtVerify(assertion, resolver.resolve, {
          algorithms: ["RS256"], issuer: configuration.accessIssuer, audience: configuration.accessAudience,
          requiredClaims: ["iss", "aud", "sub", "email", "type", "iat", "exp"], clockTolerance: ACCESS_CLOCK_TOLERANCE_SECONDS, currentDate: new Date(nowMs),
        });
        if ((inspected.payload.iat as number) > Math.floor(nowMs / 1_000) + ACCESS_CLOCK_TOLERANCE_SECONDS) return new Response(null, { status: 403 });
      } catch { return new Response(null, { status: 403 }); }

      const headers = new Headers();
      request.headers.forEach((value, name) => {
        const lower = name.toLowerCase();
        if (!strippedRequestHeaders.has(lower) && !lower.startsWith("x-limitmark-internal-") && !lower.startsWith("x-vercel-")) headers.append(lower, value);
      });
      const cookie = sanitizeCookie(headers.get("cookie"));
      if (cookie) headers.set("cookie", cookie); else headers.delete("cookie");
      headers.set("host", upstream.hostname);
      headers.set("x-forwarded-host", ADMIN_GATEWAY_HOST);
      headers.set("x-vercel-protection-bypass", configuration.vercelAutomationBypassSecret);
      const target = new URL(upstream);
      target.pathname = url.pathname; target.search = url.search;
      const response = await requestFetch(target, { method: request.method, headers, body: await boundedBody(request), redirect: "manual", signal: AbortSignal.timeout(5_000) });
      const responseHeaders = new Headers(response.headers);
      responseHeaders.delete("set-cookie");
      responseHeaders.delete("x-vercel-protection-bypass");
      responseHeaders.delete("x-vercel-set-bypass-cookie");
      for (const name of [...responseHeaders.keys()]) if (name.startsWith("x-limitmark-internal-")) responseHeaders.delete(name);
      for (const [name, value] of [...responseHeaders.entries()]) if (value.includes(configuration.vercelAutomationBypassSecret)) responseHeaders.delete(name);
      if (response.status >= 300 && response.status < 400) {
        const location = responseHeaders.get("location");
        if (location) {
          const redirect = new URL(location, target);
          if (redirect.origin !== upstream.origin && redirect.origin !== `https://${ADMIN_GATEWAY_HOST}`) return new Response(null, { status: 502 });
          if (redirect.origin === upstream.origin) responseHeaders.set("location", `https://${ADMIN_GATEWAY_HOST}${redirect.pathname}${redirect.search}${redirect.hash}`);
        }
      }
      // A switching-protocols response requires the original WebSocket pair and
      // cannot be reconstructed as a normal Response. A final 103 is likewise
      // invalid, so fail closed instead of fabricating either response shape.
      if (response.status === 101 || response.status === 103) return new Response(null, { status: 502 });
      if (request.method === "HEAD" || reconstructableNullBodyStatuses.has(response.status)) {
        return new Response(null, { status: response.status, statusText: response.statusText, headers: responseHeaders });
      }
      const responseBody = new Uint8Array(await response.arrayBuffer());
      if (responseBody.length > 8 * 1024 * 1024 || containsBytes(responseBody, new TextEncoder().encode(configuration.vercelAutomationBypassSecret))) return new Response(null, { status: 502 });
      return new Response(responseBody, { status: response.status, statusText: response.statusText, headers: responseHeaders });
    } catch (error) {
      return new Response(null, { status: error instanceof DOMException && error.name === "TimeoutError" ? 504 : 503 });
    }
  };
}
