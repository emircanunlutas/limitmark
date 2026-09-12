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
