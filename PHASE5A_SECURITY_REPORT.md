# Phase 5A security review

Reviewed 2026-09-12; baseline `e706416 — Add controlled admin inquiry mutations`; installed Next.js 16.3.4. The working tree was clean at start. No account/DNS/WAF/Access changes, real provider setup, deployment, persistence enablement, purchase or commit was performed. The implementation and [manual runbook](PHASE5A_EDGE_RUNBOOK.md) are preparation, not evidence of a live protected deployment.

## 1. Current trust chain: baseline facts versus external facts

**Code facts:** there are no domain bindings, public-host enforcement, Cloudflare public-proxy requirement, `vercel.json`, custom route handlers or Proxy in the baseline. Public pages can be served on any hostname that the hosting platform routes to this app. The code neither establishes which domains are currently public nor proves DNS/proxy/deployment protection status. The task supplies intended public hosts `limitmark.com`, `www.limitmark.com` and the intended admin host `admin.limitmark.com`. Actual attached domains, reachable generated/branch URLs, edge rules, Access policy and environment values require a control-plane inventory. None was inferred from code or probed live.

Baseline route inventory, confirmed against page sources:

| Route | Rendering | Data / action behavior |
| --- | --- | --- |
| `/`, `/gizlilik`, `/test-yetkilendirmesi` | Static | Public marketing/legal content |
| `/test-talep-et` | Dynamic via `connection()` and awaited `searchParams` | New random submission token, optional gated Turnstile widget; native/hydrated POST Action |
| `/test-talep-et/tesekkurler` | Static at baseline; now force-dynamic | Generic confirmation copy, no customer data; direct navigation does not prove receipt |
| `/admin` | `force-dynamic` | JWT/allowlist before bounded repository list queries |
| `/admin/inquiries/[id]` | `force-dynamic` | JWT/allowlist before parameter handling and customer detail queries; controlled mutation forms |
| `/_not-found` / unknown routes | Generated 404 handling | No inquiry data |

Baseline public form path:

```text
Internet -> hosting/router (deployment facts unknown) -> Next.js Action parsing/Origin/body checks
 -> readRequestFormData + Zod normalization/validation + singular token shape check
 -> submitToAdapter
    demo: production demo policy -> synthetic success only, no providers/data
    postgres: persistence gate -> registered provider gate -> Vercel production/source/secret gate
       -> Turnstile configuration gate -> HMAC client key
       -> single shared-limiter operation (client + global)
       -> Turnstile Siteverify -> fingerprint
       -> Postgres transaction (inquiry + event + outbox, unique token/conflict checks)
```

No production rate-limit provider is registered: public persistence cannot open from environment settings alone. `REQUEST_SUBMISSION_MODE`, `ENABLE_PERSISTENT_SUBMISSIONS`, database URL and pool settings protect database configuration; `VERCEL=1` and `VERCEL_ENV=production` protect **public persistent client identity selection only**. Admin JWT authorization does not depend on Vercel system variables. Demo acceptance uses `NODE_ENV` and `ALLOW_DEMO_SUBMISSIONS`, not `VERCEL_ENV`.

Security header consumers:

- `src/lib/client-identity.ts`: only `x-vercel-forwarded-for` supplies the direct-ingress address; no fallback to XFF, X-Real-IP, True-Client-IP, CF-Connecting-IP or Forwarded. It returns only an HMAC key.
- `src/lib/admin-auth-core.ts`: only `cf-access-jwt-assertion` supplies the Access token. `cloudflare-access.ts` verifies RS256 signature, configured issuer/audience, required claims, validity/clock bounds, app token type and email. A branded verified identity then passes an exact mailbox allowlist. Cookies, email headers, hostnames and public-edge credentials cannot authorize.
- `src/lib/admin-auth.ts`: `headers()` feeds that boundary on each protected page/action through `requireAdmin()`. JWT failure becomes denial before repository work.
- `src/app/test-talep-et/actions.ts`: passes `headers()` to the persistent adapter after schema/token validation.
- Installed `next/dist/server/app-render/action-handler.js`: framework Action parsing consumes Origin and X-Forwarded-Host/Host. Actions can be invoked directly; action IDs are not authorization.

Direct `*.vercel.app` public-route access is permitted **by baseline application code if Vercel routes it**. Actual internet reachability is unknown. Admin without a valid assertion is denied even on a legitimate admin Host. Access assertions are bearer credentials: an already valid allowlisted JWT can be replayed directly until expiry; the code does not prove that every authenticated request traversed Cloudflare's network.

## 2. Future proxy/IP trust model, based on official documentation

| Evidence | Supported conclusion |
| --- | --- |
| [Vercel request headers](https://vercel.com/docs/headers/request-headers) | Vercel replaces X-Forwarded-For rather than accepting arbitrary external chains, documents X-Real-IP as equivalent and X-Vercel-Forwarded-For as its platform copy. X-Forwarded-Host is documented as identical to Host. The selected requested domain is retained, rather than necessarily exposing a deployment hostname. |
| [Vercel reverse-proxy documentation](https://vercel.com/docs/security/reverse-proxy) | Cloudflare is automatically recognized by Verified Proxy Lite on all plans, using CF-Connecting-IP. This is not proof of this particular Cloudflare zone or signed application identity. |
| [Detailed Verified Proxy guide](https://vercel.com/kb/guide/how-to-setup-verified-proxy) | The connecting peer is the proxy; Lite still exposes the proxy IP to the app. Known provider egress ranges qualify headers for platform proxy recognition. Advanced is needed to expose real client IP/geolocation throughout the app. Direct access is not blocked by Verified Proxy. |
| [Cloudflare HTTP headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/) | Ordinary proxy requests carry Cloudflare-set CF-Connecting-IP; existing XFF can be extended rather than sanitized into a trusted single value. Pseudo IPv4 overwrite mode replaces CF-Connecting-IP/XFF and preserves IPv6 separately. Same-zone Workers can alter the source behind CF-Connecting-IP; cross-zone Workers use a sentinel address. Cloudflare forwards ordinary request headers, with documented modifications including Accept-Encoding and X-Forwarded-Proto. |

**Inference from these documents:** in ordinary Lite topology, treating X-Vercel-Forwarded-For as a visitor key groups users under Cloudflare egress addresses. CF-Connecting-IP is intended to reach the origin, but the reviewed docs do not provide a universal unchanged pass-through or an application-verifiable signature over it across every Vercel/Worker/transform setup. A direct client can submit CF headers, arbitrary forwarding inputs, a plausible Host/Origin and the name of the custom secret header. Presence, syntax, matching headers or CF-Ray do not authenticate ingress. Vercel's trusted platform values are trusted only under the explicitly selected platform topology, not on a self-hosted listener with spoofable environment flags.

There is **no implemented cryptographically established real-client IP chain** for Cloudflare→Vercel. Verified Proxy Advanced, egress ACLs and private signed request attestations would need separate documentation, entitlement and topology reviews. No paid feature or hand-maintained Cloudflare CIDR list was added. Do not use the Vercel webhook `x-vercel-signature` as a generic ingress proof; its documented scope is other services.

## 3. Client identity decision

Retain the exact environment selector `SUBMISSION_CLIENT_IP_SOURCE=vercel` as **direct Vercel only**. No `cloudflare-via-vercel` identity mode exists. Unknown selectors deny. The production gate now also requires public origin protection absent/`disabled`; `required`, empty or unknown values cannot enable persistence even if a later limiter provider is registered.

The identity module rejects unexpected `cf-connecting-ip`, `cf-connecting-ipv6`, `cf-ray` or origin-secret header presence. That is a consistency denial, not header authentication. Direct clients can deny their own request by adding these headers, but cannot turn them into a trusted IP. Removing all CF hints cannot establish a proxied identity; the required deployment setting still closes persistence. There is no auto-detection or fallback.

Only a single IPv4/IPv6 platform address is parsed, scoped/ported/bracketed/multi-hop values deny, equivalent IPv6 spellings normalize, and the module emits only a domain-separated HMAC-SHA-256 base64url key. Limiter calls receive opaque client keys plus fixed global keys and rules, never IPs or origin credentials. No raw-IP storage/logging/provider call was added; Siteverify still omits `remoteip`. Provider infrastructure may have its own request telemetry; the runbook forbids exporting it unnecessarily.

## 4. Origin bypass decision

Prepare `PUBLIC_ORIGIN_PROTECTION=required` with `PUBLIC_ORIGIN_SECRET` and Cloudflare **Set static** `x-limitmark-origin-secret`. The transform can add/overwrite a private origin-request value without putting it in a browser response. [Supported transformation](https://developers.cloudflare.com/rules/transform/request-header-modification/).

This optional mechanism denies public route requests without the exact bearer secret and consistent public hosts, with a fixed-size timing-safe comparison. It is off by default for the existing local/preview/direct topology. Unknown/empty mode and incomplete required configuration deny. The only exceptions are JWT-protected admin paths and GET/HEAD immutable bundle/platform-verification namespaces. Admin assets stay usable without a public credential. Private RSC requests and misleading file suffixes are not exempt.

It is application-level defense in depth, **not complete origin isolation**, and is deliberately not used to authenticate CF-Connecting-IP. Secret disclosure or outer-proxy compromise can bypass it; later application/data checks remain. Platform requests/bandwidth can be consumed before denial. Old deployments may lack the guard. The runbook classifies Deployment Protection, Vercel firewall, IP restrictions, host enforcement, generated URLs, automation bypass and AOP/Tunnel individually, with a concrete manual implementation path and no purchases.

## 5. Code changes and independent layers

- Added public-origin configuration/authentication helper and Node-runtime `src/proxy.ts`; exact host checks supplement the secret. Vercel production flags apply only when this optional guard is required.
- Added pre-verification client/global limiter budgets with separate key namespaces. A verified challenge still must pass the retained strict post-verification limiter. Limiter exceptions at either point return unavailable; rejected challenges spend only the outer budget. These use the same future provider but separate counters: they are separate admission stages, **not independent provider availability domains**.
- Kept schema/token checks, fingerprinting, production registry closure, Turnstile verification and transactional repositories in place. No edge flag can skip these checks or open persistence. The origin-required setting explicitly disallows persistence until a supported identity design is reviewed.
- Added constrained CSP directives without a script/style wildcard policy. Made thank-you rendering dynamic. Proxy sets CDN-specific no-store on admin, form descendants, verification paths, denials and non-GET/HEAD responses.
- Added targeted identity/origin/limiter/admin tests, production HTTP/security/Action tests and an isolated enabled-origin production harness using only synthetic secrets.
- Added environment comments, updated README and produced the manual runbook. No DB migrations, admin auth implementation changes, new dependencies or provider implementations.

## 6–7. Edge policy runbook and initial layers

[PHASE5A_EDGE_RUNBOOK.md](PHASE5A_EDGE_RUNBOOK.md) provides exact host expressions, transform operation, safe cutover/rollback/rotation order, control-plane inventory, TLS/verification exceptions, cache bypass expression, method/path policy, origin-option classifications and acceptance checks.

Initial policy design: network DDoS → available managed WAF defaults → narrowly scoped suspicious HTML GET challenge → separate measured edge-rate policies → origin resistance → pre-verification limiter → Turnstile → strict limiter → authoritative validation/idempotency → database integrity. Cloudflare execution order can differ from this conceptual numbering; no Skip rule or automation bypass is proposed that silently disables another layer.

Measurement hypotheses: 600 general navigations/IP/minute, 120 form GETs/IP/minute, 30 form POSTs/IP/minute; short recovery, no challenge on POST/RSC. Plan-limited 10-second alternatives and rule-priority decisions are documented. These are not production-enabled settings. The retained application limit of five verified requests per key per ten minutes is explicitly a shared-office go-live review item, not asserted to satisfy CGNAT fairness.

## 8. Next.js 16.3.4 Server Action assessment

Read the installed `serverActions.md`, `proxy.md`, headers/CSP guides, `cdn-caching.md`, Server Actions guide and `action-handler.js`. Configuration remains `bodySizeLimit: "32kb"`, with **no allowedOrigins expansion**.

Installed source behavior: it parses `Origin` as a URL host, chooses the first X-Forwarded-Host value when present (otherwise Host), and rejects a supplied mismatched origin unless explicitly allowed. `Origin: null` is rejected in the normal host topology. A missing Origin produces a warning and may proceed: it is **not** a fail-closed authentication check. Some unrecognized/malformed requests terminate earlier. Native multipart and hydrated Action requests are both relevant.

With unmodified public Host/Origin and Vercel's documented corresponding X-Forwarded-Host, public forms stay same-host through Cloudflare. No new origin allowance is needed. A Host rewrite to a deployment URL would cause incompatibility; repair that proxy configuration instead of widening CSRF exceptions. Host/Origin matching cannot authorize admin, nor can it stop a scripted direct request with self-consistent headers. [Official configuration reference](https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions).

Production HTTP tests replay real rendered bound-action metadata (including useActionState fields), accept both simulated public hostnames, reject hostile/null Origin and reject an oversized body. Existing native/hydrated browser regressions exercise actual form submission. These establish local framework behavior, not unobserved deployed header transformations. Next.js can log untrusted Origin/Host diagnostics; no identity-module IP logging was introduced.

## 9. Security headers

Retain `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and camera/microphone/geolocation-disabled Permissions-Policy. Add:

```text
Content-Security-Policy: frame-ancestors 'none'; object-src 'none'; base-uri 'self'
```

This reinforces framing, plugin and base-URL restrictions; it does **not** claim script-injection/XSS protection. It does not restrict Next.js inline scripts/styles or the future Turnstile script/frame. A strict script CSP requires nonce/hash integration and careful caching/Turnstile review, so it is deferred rather than replaced with unsafe wildcards. A proposed `form-action 'self'` directive was removed during review: cross-origin Access reauthentication after a native admin form submission needs deployed browser validation, and no trusted login destination can be inferred from this checkout. Next.js Action origin protection stays in place. HSTS is not added: actual TLS coverage, subdomains and existing platform/Cloudflare HSTS ownership were not verified. Avoid `includeSubDomains`/preload until all hosts are assessed. Keep the app as the owner of these configured headers; do not append conflicting policies at Cloudflare/Vercel.

## 10. Cache safety

Both admin pages remain force-dynamic with authorization before DB work, no shared cached queries and no customer-specific metadata. The token-bearing form already used request-time rendering. Thank-you is now explicitly force-dynamic even though it has only generic content. Installed Action handling sets no-cache/no-store; Proxy also covers early error/non-GET responses with CDN-specific no-store. Public static pages remain prerendered.

Production HTTP tests check admin anonymous denials, form and thank-you no-store plus all security headers. Unit/source regressions preserve authenticated-route dynamic rendering and ordering; full authenticated HTML/cache behavior cannot be established without an authorized runtime/database and the later edge configuration. JWT verification uses synthetic local keys in tests and makes no real Access call.

The manual cache rule bypasses all HTML/RSC/forms/admin/verification and allows only public immutable bundles under normal origin cache policy. This prevents a Cloudflare cache hit from bypassing application checks or mixing variants. Cache-Control cannot defend against a misconfigured CDN that explicitly overrides it. Actual multi-identity cache isolation remains a manual acceptance check. The installed CDN guide's `_rsc`/Vary/header requirements are preserved; no query stripping, Cache Everything or credential-blind HTML cache was introduced.

## 11. Failure modes and residual risk

“Required” below means the later manually configured origin-required posture, not the untouched deployment. The empty provider registry currently denies all public persistence regardless of these scenarios.

| Failure / attack | Rejecting layer or behavior | Next useful layer | Residual risk |
| --- | --- | --- | --- |
| Cloudflare outage | Requests fail at edge; direct traffic lacks required origin secret | App gates, admin JWT, DB constraints | Public availability loss; no automatic DNS-only fail-open |
| Proxy disabled / DNS-only / Cloudflare config accidentally removed | Required origin guard denies public rendering | Persistence gate and admin JWT | Missing guard setting or old deployment may still serve public pages |
| Known vercel.app or custom-Host direct connection | Deployment Protection if covered, otherwise required application secret | Application gates, JWT | Vercel cost/volumetric load; static assets remain public |
| Spoofed CF headers / origin credential | Secret mismatch denies; direct identity rejects unexpected CF hints | Limiter, Turnstile, schema/config gate | A stolen static secret bypasses the origin check, not admin authorization |
| Spoofed forwarding chain | Direct-only identity rejects malformed platform values; unrelated headers never supply fallback | Global limiter, Turnstile, schema | Trusting self-hosted platform-lookalike headers would be unsafe; prohibited topology |
| WAF misconfiguration | Overblocking denies legitimate traffic; underblocking passes to origin | Origin check plus all application controls | Availability loss or increased origin load; adjust only offending rule |
| Edge limiter absent/unavailable | No edge rate rejection assumed | Pre-verification/global budgets, Turnstile, post budget | Provider/Next rendering cost before admission; edge counters are not exact |
| Application limiter unavailable/throws (either stage) | Abuse boundary returns unavailable, adapter does not open DB | Schema/config already checked; DB integrity | Legitimate inquiries unavailable; same provider can affect both stages |
| Turnstile unavailable/rejected | Five-second-bounded Siteverify returns unavailable/rejected | Strict limiter only on verification success, persistence never called on failure | Availability and verification spend; application never fails open |
| Direct Server Action | Origin mismatch may reject; missing/matching Origin still reaches action validation/auth | Token/schema/gates/limiter/Turnstile or admin JWT | Action identifiers are public; absence of Origin is not proof of safety |
| Malformed/oversized body | Hosting/parser 32 KB raw-body bound, duplicate/type/length schema and token checks | Admission gates and DB constraints | Some resources are spent reading/parsing; edge inspection may truncate |
| Replay | Turnstile single-use/time rules when enabled; same token+fingerprint resolves idempotently, changed payload conflicts | Unique token index and atomic transaction | Submission token is unsigned/unbound/unexpired; attacker can invent a fresh token and try fresh abuse checks |
| Distributed low-rate abuse | Turnstile, global budgets and authoritative schema | DB integrity and manual business review | Human-assisted/valid-looking spam can pass; no IP-only guarantee |
| High-rate volumetric attack | Cloudflare/Vercel network protections where traversed | Origin guard and admission reduce deeper work | Application code cannot absorb network floods or cap all Vercel costs |
| Cache poisoning/deception | Bypass rule, no-store, exact guarded hosts and maintained RSC variants | Per-request admin authorization when origin is reached | Forced shared caching/compromised CDN can serve previously obtained private data without reaching the app |
| Valid Access JWT stolen | Verification/allowlist may still accept an unexpired token | Bounded queries, controlled mutations, OCC and audit | This is bearer compromise; Access session policy/revocation belongs to existing admin control plane |

Layer-by-layer independence:

| Layer | Rejects / reduces | If bypassed, what remains? | What it cannot guarantee |
| --- | --- | --- | --- |
| 1 Network DDoS | Floods at provider infrastructure | WAF, origin/application admission | No complete protection of alternate origins |
| 2 Managed WAF | Known exploit patterns | Scoped custom policies and validation | Business validity or SQL constraints |
| 3 Bot/custom/challenge | Some automated/suspicious navigation | Edge rate and origin gates | Human identity, fair treatment from reputation alone |
| 4 Edge rate | Repeated edge traffic | App pre-budget/Turnstile/post-budget | Strict shared rolling limits; universal distributed-abuse rejection |
| 5 Origin/deployment | Missing secret, inconsistent public hosts, covered deployment auth failures | App gates and separate admin JWT | Signed real-client identity or network isolation |
| 6 Pre-verification budget | Excess challenge attempts/cost | Turnstile and strict budget | Provider independence, network cost coverage |
| 7 Turnstile | Failed/reused/invalid attestations | Strict budget, schema/idempotency | Replacing rate limits or authenticating an admin |
| 8 Strict budget | Excess verified writes, client/global | Repository/DB constraints | Validity, distributed fairness by IP alone |
| 9 Schema/token/fingerprint | Invalid data, malformed token, conflicting retries | Unique/check/FK/transaction constraints | Authentic form issuance or client identity |
| 10 Database | Duplicates, invalid constrained values, partial transactions, stale mutations | Restricted runtime role, audit and operational recovery | Preventing all valid-looking spam or compromised privileged roles |

Application validation occurs early to avoid unnecessary providers; the conceptual numbering does not require parsing bad forms only after paid verification. DB enum/check/unique/FK restrictions, append-only event protections and transactional writes remain independent of outer layers. Admin mutations retain authorization, constrained transitions, revision compare-and-swap, transactional note/event/audit behavior.

## 12. Validation results

No live Cloudflare/deployment request or production database call was performed. Tests use synthetic keys/addresses/tokens and the existing isolated adapters.

| Check | Exact result |
| --- | --- |
| `npm.cmd test` | Exit 0; 107 discovered, **73 passed, 34 DB-dependent skipped**, 0 failed. Final run 1.8s. |
| `npm.cmd run test:db` | Exit 0; **34 skipped**, 0 executed/passed/failed because `TEST_DATABASE_URL` is absent. This is not a PostgreSQL integration pass. |
| Focused admin auth/dashboard/mutation unit command below | Exit 0; **24 passed**, 0 skipped/failed, 1.1s. These overlap the unit suite. |
| Full Playwright, all three projects, command below | Exit 1; **122 passed, 4 failed**, all 126 executed, 5.4m. Chromium 42/42; Firefox 42/42; WebKit 38/42. No assertion was weakened or skipped. |
| Final security HTTP/Action checks across all three browsers | Exit 0; **9 passed**, 0 failed, 6.3s; rerun after removing `form-action` from CSP. |
| `npm.cmd run test:edge-origin -- --output=artifacts/phase5a-origin-results` | Exit 0; **3 passed**, 0 failed, 1.6s, final production build, required origin mode and synthetic credential. |
| `npm.cmd run test:persistence-guard -- --output=artifacts/phase5a-persistence-results` | Exit 0; **3 passed**, 0 failed, 3.1s, including JavaScript and native unavailable/preserved-form cases. |
| `npm.cmd run lint` | Exit 0; ESLint with `--max-warnings=0`. |
| `npm.cmd run typecheck` | Exit 0; Next type generation and strict TypeScript (`strict: true`). Standalone `tsc --noEmit` also verifies the restored generated type-reference file. |
| `npm.cmd run build` | Exit 0; optimized Next.js 16.3.4 build including Proxy; admin list/detail, form and thank-you dynamic; three informational pages and generated not-found static. |
| `npm.cmd audit --omit=dev` | Exit 0; **0 vulnerabilities**. No dependency/lockfile change. |
| `git diff --check` | Exit 0; no whitespace errors. |

Reproducible browser commands (PowerShell; local test servers only):

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = "$PWD/.playwright"
$env:QA_CROSS_BROWSER = 'true'
npm.cmd run test:e2e -- --global-timeout=600000
npm.cmd run test:e2e -- tests/e2e/edge-security.spec.ts --output=artifacts/phase5a-security-results
npm.cmd run test:edge-origin -- --output=artifacts/phase5a-origin-results
npm.cmd run test:persistence-guard -- --output=artifacts/phase5a-persistence-results
node node_modules/tsx/dist/cli.mjs --conditions=react-server --test tests/admin-auth.test.ts tests/admin-dashboard.test.ts tests/admin-inquiry-mutations.test.ts
```

The four complete-run failures are the existing Windows WebKit Tab-to-anchor limitation recorded in baseline [QA_REPORT.md](QA_REPORT.md):

- `polish.spec.ts:39`: optional disclosure keyboard traversal at 375px and 1280px (two cases; privacy link never receives Tab focus).
- `release-navigation.spec.ts:84`: skip-link/menu/error-link keyboard flow (skip link not focused).
- `site.spec.ts:54`: mobile menu keyboard navigation.

None concerns the new origin, CSP, cache, identity or Action tests. Native Safari/assistive-technology confirmation remains outstanding; the full suite is **not green**. Complete-run output is retained locally in ignored `artifacts/phase5a-e2e.log`; failures retain traces/screenshots under `test-results/`. The complete browser run used the initially stricter CSP including `form-action 'self'`; after review removed that restriction, the build/lint/type checks, nine cross-browser security cases, origin harness and persistence regression were rerun on the final policy. No application behavior changed after that review.

During implementation, two TypeScript shape issues and the new test's incorrect assumption about unbound native Action metadata were corrected. Initial browser attempts used the wrong browser-cache path, and a later complete-project attempt reached the existing 300-second aggregate deadline (109 passed, 3 failed, 14 not run). The final complete run used the repository-installed browsers and a 600-second **aggregate** deadline; individual test/assertion limits stayed unchanged. Sandboxed Playwright shutdown hung after successful assertions; only this task's two known Next test-server PIDs were stopped, and subsequent browser runs used approved unsandboxed process management. No existing development server was stopped.

## 13. Files changed

Application/configuration: `.env.example`, `next.config.ts`, `package.json`, `src/proxy.ts`, `src/lib/public-origin.ts`, `src/lib/client-identity.ts`, `src/lib/public-submission-config.ts`, `src/lib/submission-abuse-control.ts`, `src/app/test-talep-et/tesekkurler/page.tsx`.

Tests: `tests/abuse-control.test.ts`, `tests/admin-auth.test.ts`, `tests/public-origin.test.ts`, `tests/e2e/edge-security.spec.ts`, `tests/edge-origin/origin.spec.ts`, `playwright.edge-origin.config.ts`.

Documentation: `README.md`, `PHASE5A_EDGE_RUNBOOK.md`, `PHASE5A_SECURITY_REPORT.md`. Generated Next type-path churn is restored to baseline after build checks; no lockfile/dependency change is intended.

## 14–16. Manual work, remaining risks and readiness

The operator still must inventory actual bindings/settings; protect applicable alternate and old deployment URLs; prepare the private transform and production guard; verify strict TLS/ACME; install cache bypass; stage measured WAF/method/rate policies; coordinate a separately authorized release/proxy cutover; and verify the real routed headers and cache/Access behavior. Nothing in this report authorizes a deployment or account change.

The code is designed for proxying **with public persistence closed**. It is not ready to accept persistent public inquiries behind Cloudflare: no supported real-client identity mode, shared production limiter or real Turnstile configuration exists. No database integration results can be claimed without TEST_DATABASE_URL. Strict CSP, IP-sharing fairness, real assistive-technology testing and deployed control-plane verification remain distinct follow-up work. The origin secret and Host restrictions do not provide full isolation; valid stolen Access JWTs remain bearer credentials; old unprotected deployments and misconfigured edge caches remain material risks.

**Readiness decision:** ready for the manual edge-configuration preparation/cutover workflow in the runbook, provided public persistence stays closed and the operator completes its control-plane prerequisites. This is not production-persistence approval, an all-browser accessibility sign-off, proof of current domain protection, or authorization to toggle DNS now. The four baseline WebKit failures remain explicitly reported; no new reproduced security/application regression is left unresolved by this phase's tests.

## 17. Final git state

HEAD remains `e706416`. **18 changed files: 10 modified tracked files and 8 untracked new files; nothing staged or committed.** `git diff --stat` for tracked files: **110 insertions, 11 deletions in 10 files**. That command omits the eight new files; they are included in section 13's inventory. Generated `next-env.d.ts` churn was restored; `AGENTS.md`, dependencies/lockfile and migrations are unchanged. Ignored local browser artifacts are not part of the source diff.

```text
 M .env.example
 M README.md
 M next.config.ts
 M package.json
 M src/app/test-talep-et/tesekkurler/page.tsx
 M src/lib/client-identity.ts
 M src/lib/public-submission-config.ts
 M src/lib/submission-abuse-control.ts
 M tests/abuse-control.test.ts
 M tests/admin-auth.test.ts
?? PHASE5A_EDGE_RUNBOOK.md
?? PHASE5A_SECURITY_REPORT.md
?? playwright.edge-origin.config.ts
?? src/lib/public-origin.ts
?? src/proxy.ts
?? tests/e2e/edge-security.spec.ts
?? tests/edge-origin/origin.spec.ts
?? tests/public-origin.test.ts
```
