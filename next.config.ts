import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  experimental: {
    serverActions: { bodySizeLimit: "32kb" },
    proxyClientMaxBodySize: "64kb",
  },
  async headers() {
    return [{
      source: "/api/public-inquiries",
      headers: [
        { key: "Cache-Control", value: "private, no-store, max-age=0, must-revalidate" },
        { key: "CDN-Cache-Control", value: "no-store" },
        { key: "Vercel-CDN-Cache-Control", value: "no-store" },
      ],
    }, {
      // The homepage renders at request time so its intake notice matches the runtime configuration,
      // but its output is identical for every visitor. This short window applies to Vercel's CDN only
      // (the header is not forwarded); browsers and Cloudflare still receive Next's private no-store.
      // The Proxy sets no-store on every origin-denied response, overriding this rule (see tests/edge-origin).
      source: "/",
      headers: [{ key: "Vercel-CDN-Cache-Control", value: "max-age=60, stale-while-revalidate=120" }],
    }, {
      source: "/:path*",
      headers: [
        // Limited CSP: nonce/hash and Access form-redirect review are deferred.
        { key: "Content-Security-Policy", value: "frame-ancestors 'none'; object-src 'none'; base-uri 'self'" },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "X-Frame-Options", value: "DENY" },
        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
        { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
      ],
    }];
  },
};

export default nextConfig;
