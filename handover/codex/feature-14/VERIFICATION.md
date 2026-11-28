# Feature 14 homepage CDN policy

Base commit: 2a8a175. The policy from 25ee1ac is already in master via b5a684e. The production configuration is unchanged by this candidate. The new regression runs against a production build with origin protection required.

On lm-base-codex (Node 24.22.3, Next.js 16.4.5), npm ci and npm run build passed. The following command passed its single targeted test:

    npm run test:edge-origin -- --grep 'homepage caching'

The loopback server returned 404 and all three no-store policies for a direct homepage request. The admitted homepage returned 200 with private/no-store browser caching, no generic CDN override, and the Vercel-only 60-second freshness and 120-second stale window. A synthetic cookie did not change that policy or produce a Set-Cookie response. The origin credential was absent from admitted response headers and content. The adjacent intake route retained all three no-store policies.

This verifies emitted headers and origin admission on a built server. Vercel edge cache hits and cache-key behavior were outside this local check.
