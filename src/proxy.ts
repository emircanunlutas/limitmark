import { NextResponse, type NextRequest } from "next/server";
import { isPublicOriginAllowed } from "./lib/public-origin";

/** Public origin resistance only. Every admin page/action still verifies Access. */
export function proxy(request: NextRequest) {
  const path = request.nextUrl.pathname;
  const admin = path === "/admin" || path.startsWith("/admin/");
  // Vercel certificate/deployment verification must remain reachable. These
  // namespaces contain no application routes. Never exempt POST/actions here.
  const verification = (request.method === "GET" || request.method === "HEAD") &&
    (path.startsWith("/.well-known/acme-challenge/") || path.startsWith("/.well-known/vercel/"));
  // Immutable bundles contain no customer data and are also needed by the
  // independently protected admin hostname, which never receives this secret.
  const staticAsset = (request.method === "GET" || request.method === "HEAD") && path.startsWith("/_next/static/");
  // Vercel invokes Cron Jobs directly, never through the Cloudflare edge that
  // injects this secret. Like /admin, it retains its own independent bearer
  // authorization (CRON_SECRET) checked inside the route; no public credential
  // is accepted here.
  const cron = request.method === "GET" && path === "/api/cron/process-notifications";
  const denied = !admin && !verification && !staticAsset && !cron && !isPublicOriginAllowed(request.headers, process.env);
  const response = denied
    ? new NextResponse(null, { status: 404 })
    : NextResponse.next();

  if (denied || admin || verification || cron || request.method !== "GET" && request.method !== "HEAD" ||
      path === "/test-talep-et" || path.startsWith("/test-talep-et/")) {
    response.headers.set("Cache-Control", "private, no-store, max-age=0, must-revalidate");
    response.headers.set("CDN-Cache-Control", "no-store");
    response.headers.set("Vercel-CDN-Cache-Control", "no-store");
  }
  return response;
}

// The exact raw-body inquiry boundary must not enter Next's Proxy body clone:
// an over-limit clone can discard the crossing chunk before the Route Handler
// can observe byte 32,769. The Route Handler independently enforces every
// origin, ingress, environment and body check. All other pathnames remain here.
export const config = { matcher: "/((?!api/public-inquiries$).*)" };
