# Phase 5A manual Cloudflare / Vercel runbook

Prepared 2026-09-12 against baseline `e706416`, installed Next.js 16.3.4. **Nothing in this runbook has been applied.** No DNS, account, Access, WAF, deployment, production database, provider or secret configuration was changed. See [review and test results](PHASE5A_SECURITY_REPORT.md).

## Scope and stop conditions

This prepares public marketing pages and a **closed submission path** for proxying. It does not authorize public persistence. Cloudflare client identity remains unsupported. Keep `ENABLE_PERSISTENT_SUBMISSIONS=false`, `TURNSTILE_MODE=disabled`, real notifications off and the production limiter registry empty. Do not set `ALLOW_DEMO_SUBMISSIONS=true` on the public production site: demo success is not receipt of an inquiry.

The operator must record the actual project, production deployment, domain bindings, DNS targets, Cloudflare zone, TLS status, account entitlements and current rules before making changes. They cannot be determined from this checkout. Stop if the project is already receiving real submissions: the proposed origin-required posture deliberately closes them and needs a separately agreed migration. Stop if strict TLS, cache bypass, request-header transformation or production-origin enforcement cannot be established. Do not compensate with header fallbacks, WAF bypass tokens or an expanded Action origin allowlist.

## 1. Inventory and preserve independent controls

1. In Vercel Project Settings/Domains, inventory `limitmark.com`, `www.limitmark.com`, `admin.limitmark.com`, project production aliases, generated deployment URLs, preview/branch URLs, older production deployments and any other custom domains. Copy the exact DNS records Vercel currently requests; this document intentionally supplies no guessed A/CNAME target.
2. Record Deployment Protection scope, exceptions, shareable links, OPTIONS exceptions, existing WAF/rate-limit rules and existing proxy arrangements. Old deployments without Phase 5A code need platform protection or retirement through a separately authorized operation.
3. In Cloudflare, record DNS proxy status, SSL mode, redirects, Cache/Page/Origin/Transform Rules, Workers/Snippets, bot products and Managed Transforms. Verify that no Worker or rule rewrites public Host/Origin or forwards the origin secret to other services.
4. Keep `admin.limitmark.com` proxied through its existing Access application. Keep its audience, issuer/team domain, exact email allowlist and identity-provider/MFA policy unchanged. The public origin credential is never admin authentication. Review both `/admin` and `/admin/*` on every alias as denial cases without a valid assertion.
5. Keep Vercel platform protections enabled. Verified Proxy Lite recognizes supported proxy providers; it is not an origin access restriction. [Vercel proxy guide](https://vercel.com/kb/guide/how-to-setup-verified-proxy).

## 2. Origin resistance and exact environment posture

The implemented application mechanism is **DEFENSE-IN-DEPTH ONLY**: a secret checked in Next.js Proxy before public route rendering, plus exact public-host routing checks. A request still reaches Vercel infrastructure and may incur cost. The static bearer credential authenticates possession, not a signed visitor IP or a specific HTTP body. It is intentionally not used for IP identity.

For the future approved production release, the operator must configure:

| Setting | Value / constraint |
| --- | --- |
| `PUBLIC_ORIGIN_PROTECTION` | `required` |
| `PUBLIC_ORIGIN_SECRET` | New independent 32 random bytes encoded as 43-character unpadded base64url; server-only |
| `VERCEL`, `VERCEL_ENV` | Vercel-supplied `1`, `production`; inspect that system variables are exposed |
| `ENABLE_PERSISTENT_SUBMISSIONS` | `false` |
| `TURNSTILE_MODE` | `disabled` |
| `ALLOW_DEMO_SUBMISSIONS` | `false` or absent |
| `SUBMISSION_CLIENT_IP_SOURCE` | Leave unset while proxied; no Cloudflare mode is implemented |

Do not reuse `SUBMISSION_CLIENT_KEY_SECRET`, an Access credential, or a Vercel automation bypass token. Store the new secret in the team's secret manager, Vercel's server environment and the restricted Cloudflare rule configuration only. Rule readers/editors can see static values: restrict their access. No `NEXT_PUBLIC` variable, browser code, response header, cookie, query string, log field, trace dump, screenshot or support-ticket attachment may contain it.

In Cloudflare **Rules → Overview → Create rule → Request Header Transform Rule**, select this exact expression:

```text
http.host in {"limitmark.com" "www.limitmark.com"}
```

Under Modify request header, choose **Set static**, name `x-limitmark-origin-secret`, value the new secret. Set overwrites a visitor-supplied value; do not append. Apply to all paths/methods for these two hosts, with no later rule overwriting/removing it. This modifies the request to the origin, not the browser response. These operations are supported by [Cloudflare's request-header rules](https://developers.cloudflare.com/rules/transform/request-header-modification/) and [dashboard workflow](https://developers.cloudflare.com/rules/transform/request-header-modification/create-dashboard/). Initially save as a draft; activation belongs to the cutover below.

The application accepts only an exact secret, `Host` equal to one of the two public hostnames, and `X-Forwarded-Host` equal to that same host. Unknown/empty modes, missing secret, duplicate secret values or inconsistent hosts deny with an empty non-cacheable 404. Only absent/`disabled` preserves the pre-edge posture; that is an explicit rollback setting, never automatic failure recovery.

Narrow exceptions:

- `/admin` and `/admin/*` retain their own page/action JWT authorization; no public credential is needed.
- Use `https://admin.limitmark.com/admin` as the admin entry point. Public marketing/form paths on the admin hostname are outside the two-host origin allowlist when required; the shared marketing links may therefore lead to a denial on that hostname. Use the public hostname for those pages. Admin list/detail/action links stay within `/admin`.
- GET/HEAD under `/_next/static/` remain publicly accessible so both public and admin bundles work. They carry no customer data. Arbitrary `.css`/`.js` suffixes elsewhere are not exceptions.
- GET/HEAD under `/.well-known/acme-challenge/` and `/.well-known/vercel/` remain reachable and non-cacheable for platform verification. There are currently no application routes under these namespaces. Never put an Action, private route or rewrite there; review any future use. POST is not exempt.
- RSC/prefetch headers, alternate page paths and internal-looking request headers do not create an exemption. Actions enforce their own application gates; Proxy is not the sole authorization boundary.

Rotation uses a maintenance window: keep persistence closed, prepare a new secret, update the production environment/release and matching Cloudflare transform, validate, then retire the old value. This implementation accepts one secret, so a mismatch can cause brief denial; it never falls back. Do not temporarily expose credentials to preserve availability.

## 3. TLS, proxy and cutover order

Vercel requires HTTP certificate-validation reachability under `/.well-known/acme-challenge/*` and no caching under `/.well-known/vercel/*`. For certificate validation, exempt the exact GET/HEAD namespace from HTTP→HTTPS redirects and custom bot/challenge policies. Do not broadly disable zone protection. Preserve the original public Host and TLS SNI; do not route by replacing Host with `*.vercel.app`. [Vercel prerequisites](https://vercel.com/docs/security/reverse-proxy), [Cloudflare Origin Rules](https://developers.cloudflare.com/rules/origin-rules/).

1. Prepare drafts of the transform, cache bypass and security rules. Confirm valid Vercel certificates for both public names. Use **Full (strict)** edge-to-origin TLS; Flexible is not acceptable. [Cloudflare strict TLS](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/).
2. Arrange an approved release/maintenance window. The code here is uncommitted and undeployed; deployment requires a separate authorized workflow. Do not activate the required guard on an unproxied live public route expecting uninterrupted service.
3. In that window, activate cache bypass and header-transform rules, release the reviewed origin-required build/environment, then toggle proxy for the existing correct `limitmark.com` and `www.limitmark.com` DNS records. Coordinate these steps closely: while the guard and proxy disagree, requests fail closed. Accept brief denial instead of silently opening the origin. Keep admin DNS/Access settings unchanged.
4. Verify both hosts, then activate measured WAF/custom/rate-limit policies incrementally. Preserve any already validated canonical redirect. If adding a canonical redirect, use GET/HEAD only initially; never redirect submitted form bodies across apex/www. The current expected Turnstile hostname is singular; selecting a form hostname is a future persistence decision.
5. Complete the checks in section 8. If the transform is stripped by the actual Vercel route, remain closed and investigate; do not infer pass-through from a successful local test.

## 4. Cache safety before traffic

Use one Cloudflare Cache Rule scoped to all three hosts that bypasses everything except immutable public bundles:

```text
(http.host in {"limitmark.com" "www.limitmark.com" "admin.limitmark.com"})
and not (
  http.request.method in {"GET" "HEAD"}
  and starts_with(http.request.uri.path, "/_next/static/")
  and http.host in {"limitmark.com" "www.limitmark.com"}
)
```

Select **Bypass cache**. Leave the permitted bundles on default cache behavior honoring origin headers; do not force-cache errors. The admin hostname bypasses all Cloudflare caching. Remove conflicting earlier/later Cache Everything, Edge TTL, Page Rules, Workers cache API use and cache-key overrides. A later rule must not override the bypass. Clear any previously cached HTML/private route content during the approved cutover. [Cloudflare cache settings](https://developers.cloudflare.com/cache/how-to/cache-rules/settings/).

Do not strip `RSC`, `Next-Router-State-Tree`, `Next-Router-Prefetch`, `Next-Router-Segment-Prefetch`, `Next-Url`, `Next-Action`, `Origin`, cookies or `_rsc` query parameters. Do not normalize all cache keys to the pathname. The application uses `CDN-Cache-Control: no-store` plus framework/browser controls for sensitive responses; Cloudflare must respect them. [Cloudflare cache precedence](https://developers.cloudflare.com/cache/concepts/cache-responses/).

This keeps Vercel's existing public static-page caching useful while avoiding a second HTML/RSC cache. Any future Cloudflare HTML caching requires a separate Next.js variant/cache-key review, invalidation plan and credential-isolation tests. The generic thank-you page contains no personal data, but is now dynamic and bypassed alongside the token-bearing form.

## 5. WAF, methods, paths and challenge policy

The numbered security layers are a threat model, not a promise about Cloudflare's internal ruleset execution order.

- Keep network DDoS protection. Start with the **Free Managed Ruleset** where that is the available entitlement; use the Cloudflare Managed Ruleset with defaults if already entitled. Review OWASP sensitivity and false positives before enabling additional rules. Do not purchase features. Managed rules and their availability are described in [Cloudflare Managed Rules](https://developers.cloudflare.com/waf/managed-rules/).
- Avoid zone-wide challenges, blanket country/ASN blocks, VPN/relay blocks and decisions based only on IP reputation. No JavaScript, unusual user agents or missing browser fetch metadata are not enough to reject a customer.
- Apply **Managed Challenge** only to suspicious top-level HTML GET navigation where the browser can recover. Exclude RSC/prefetch/fetch, Server Action POST, static files, ACME/verification paths and Access/admin traffic. Interstitial HTML is incompatible with fetch/AJAX responses. Do not challenge a form POST after the customer has entered data. [Challenge limitations](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/).
- Allow verified search crawlers on public informational navigation through narrowly scoped challenge exceptions, not a global Skip of WAF/rate limits. A crawler-like User-Agent is not proof. Do not exempt automation from form abuse controls. Test screen readers, keyboard-only navigation, privacy browsers and ordinary monitoring; use an agreed narrowly scoped monitor identity if needed, never a public bypass token.
- Do not enable Bot Fight Mode blindly: establish whether its scope/exceptions can preserve these flows under the actual plan. Monitor first where available; leave an incompatible bot product off while retaining other layers.

Current legitimate application methods:

| Route | Legitimate usage | Safe proposed edge handling |
| --- | --- | --- |
| `/`, `/gizlilik`, `/test-yetkilendirmesi` | GET/HEAD, including RSC navigation | Block other methods on public hosts |
| `/test-talep-et` (and normalized trailing slash) | GET/HEAD and native/hydrated Server Action POST | Permit POST with or without `Next-Action`; native multipart has no such header |
| `/test-talep-et/tesekkurler` | GET/HEAD | Block other methods |
| `/admin`, `/admin/*` on public hosts | No public business use | Optional exact path/subtree block; app JWT remains required on every hostname |
| `/admin`, `/admin/*` on admin host | GET/HEAD, controlled mutation POST | Preserve Access and action origin semantics; no public rule exceptions authorize |
| `/_next/static/*` | GET/HEAD | No challenges; cache only immutable successful assets |
| `/_next/image` | No current image use; reserve framework path | GET/HEAD if later used; do not apply a broad `/_next/*` exemption |
| `/.well-known/acme-challenge/*`, `/.well-known/vercel/*` | GET/HEAD platform verification | Narrow verification exceptions, no cache |
| `/cdn-cgi/*` | Cloudflare-owned flows | Do not block/challenge with application method/path rules |

For public hosts, a custom method rule can block methods outside GET/HEAD/POST on the listed application paths, then block POST except the exact form path. For admin paths, only GET/HEAD/POST are legitimate today. Keep OPTIONS decisions scoped: there is no application CORS API, but do not break provider-owned endpoints. Unknown routes should initially use ordinary application 404; maintain no universal action-ID or `Next-Action`-absence rules. Reassess when adding routes/actions.

Optional high-confidence scanner rule: block exact `/wp-login.php`, `/xmlrpc.php`, `/wp-admin` and its subtree on public hosts after confirming no redirects/integrations use them. There is no CMS here. Do not block all `.php`, all dot paths or generic strings appearing in customer form text.

Concrete optional **Block** rule for unexpected methods on the current public application routes (not provider endpoints):

```text
(http.host in {"limitmark.com" "www.limitmark.com"})
and (
  (http.request.uri.path in {"/" "/gizlilik" "/gizlilik/" "/test-yetkilendirmesi" "/test-yetkilendirmesi/" "/test-talep-et/tesekkurler" "/test-talep-et/tesekkurler/"}
   and not http.request.method in {"GET" "HEAD"})
  or
  (http.request.uri.path in {"/test-talep-et" "/test-talep-et/"}
   and not http.request.method in {"GET" "HEAD" "POST"})
)
```

Optional public-host admin-path **Block** rule, which leaves the admin hostname unchanged:

```text
(http.host in {"limitmark.com" "www.limitmark.com"})
and (http.request.uri.path eq "/admin" or starts_with(http.request.uri.path, "/admin/"))
```

Review normalized-path behavior in Cloudflare Trace before saving either rule. These restrictions are intentionally independent of the `Next-Action` header and do not replace Action authorization.

## 6. Initial edge rate policies, measurement and request size

These are **starting measurement hypotheses for a small inquiry site**, not throughput guarantees or replacements for a shared application limiter. Count by Cloudflare's connection-derived IP, never a visitor-supplied header. Both public hosts should be within the same rule scope where supported. Keep windows short and recovery quick for CGNAT/offices/mobile networks. IPv6 address rotation and distributed callers require the global application budget and Turnstile.

| Traffic class | Initial hypothesis | Action after measurement | Reason |
| --- | --- | --- | --- |
| General public HTML GET/HEAD navigation, excluding form/static/verification | 600 requests/IP/60 seconds | Managed Challenge only for top-level HTML; initially observe | Room for shared offices and prefetch; ten page navigations/second sustained is a tuning signal |
| Expensive form GET/HEAD `/test-talep-et` | 120 requests/IP/60 seconds | Short 10–60 second block if confirmed; challenge only top-level navigation if supported | Accommodates reloads and many office users; bounds token-render churn |
| Public inquiry POST `/test-talep-et` | 30 requests/IP/60 seconds | Short block/429 if configurable; never interstitial challenge | Allows corrections and multiple office users while reducing rapid submission cost |

In **Security → WAF / Security rules → Rate limiting → Create rule**, use the following separate expressions with the corresponding count/period/action above, count all matching attempts rather than successes, and choose IP as the characteristic. UI names and selectable fields vary by entitlement; if the expression/action is unavailable, keep that policy in draft rather than approximating a broad challenge.

General known informational/confirmation navigation, **HTML document requests only**:

```text
(http.host in {"limitmark.com" "www.limitmark.com"})
and http.request.method eq "GET"
and http.request.uri.path in {"/" "/gizlilik" "/gizlilik/" "/test-yetkilendirmesi" "/test-yetkilendirmesi/" "/test-talep-et/tesekkurler" "/test-talep-et/tesekkurler/"}
and http.request.headers["sec-fetch-dest"][0] eq "document"
and not has_key(http.request.headers, "rsc")
and not has_key(http.request.headers, "next-router-prefetch")
and not has_key(http.request.headers, "next-router-segment-prefetch")
and not has_key(http.request.headers, "next-action")
and not cf.client.bot
```

Form GET/HEAD, for the **short Block** version (includes RSC/prefetch; no challenge HTML):

```text
(http.host in {"limitmark.com" "www.limitmark.com"})
and http.request.uri.path in {"/test-talep-et" "/test-talep-et/"}
and http.request.method in {"GET" "HEAD"}
```

Inquiry POST, **short Block only**:

```text
(http.host in {"limitmark.com" "www.limitmark.com"})
and http.request.uri.path in {"/test-talep-et" "/test-talep-et/"}
and http.request.method eq "POST"
```

Header-map indexing and `has_key` use the documented [Rules language values](https://developers.cloudflare.com/ruleset-engine/rules-language/values/) and [map functions](https://developers.cloudflare.com/changelog/post/2026-01-20-array-map-functions/). Fetch metadata only selects a compatible challenge flow; it never authenticates a caller. Missing metadata avoids the interstitial policy without bypassing origin or application controls. RSC/HEAD clients and unlisted future pages remain outside the general challenge rule and should be measured separately. Narrow WAF false-positive exceptions to the specific rule and route; never skip all managed rules on the form.

Where non-HTML GET/RSC traffic is counted, do not return a challenge page: use a separately scoped short block policy or leave it measured until a compatible rule is available. Do not combine an HTML challenge rule and broad RSC matching. Exclude verified public crawlers from the navigation challenge where available; the submission policy has no crawler exemption.

Before enforcement, measure aggregate counts for 3–7 representative days using available security analytics or Log mode if entitled. If the plan has no observation mode, keep rules in draft, use existing analytics and begin with a narrowly scoped short block only after review. Review the highest legitimate shared-IP bursts and correction success; raise windows/thresholds or narrow scopes when false positives appear. Avoid long IP bans.

Rule counts, periods, actions and mitigation timeouts depend on plan. If only one 10-second rule is available, prioritize public POST at **10 requests/IP/10 seconds, 10-second mitigation**, keeping the other two policies as documented drafts. This alternative permits higher sustained traffic than 30/minute; it is not an equivalent conversion. If multiple rules are available but only 10-second windows, initial separate hypotheses are 150 general navigations/10 seconds and 40 form GETs/10 seconds, each with the same compatibility restrictions. Reassess from measurements rather than dividing thresholds mechanically. Do not purchase an upgrade to fill the table. Edge counters can lag/distribute and are not strict globally atomic admission control. [Availability and semantics](https://developers.cloudflare.com/waf/rate-limiting-rules/), [rate parameters](https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/).

The application adds pre-verification budgets of 30/client/10 minutes and 300/global/minute, then retains post-verification budgets of 5/client/10 minutes and 100/global/minute. The pre-budget is six times the existing client budget and three times its global budget to tolerate failed challenges without unbounded Siteverify work. These are inactive preparation defaults. The retained five/client strict policy can block a shared office; **review it before any persistence launch**, with provider cost/capacity measurements and customer retry data. Do not make reputation decisive or weaken the global budget to solve shared-IP fairness.

Keep the installed 32 KB **raw** Server Action body cap and bounded schema fields. If the edge plan exposes reliable body size, reject form bodies above 32,768 bytes after confirming actual UTF-8/multipart overhead fits legitimate maximum fields. Do not mistake WAF body-inspection truncation for rejection or rely solely on spoofable/absent Content-Length. Vercel/framework still handle streamed/chunked excess and malformed bodies. Do not log raw multipart contents or decoded customer fields. Document any platform request-size limits separately from this smaller application cap.

## 7. Origin option assessment

| Option | Classification | Decision / limitation |
| --- | --- | --- |
| Deployment Protection authentication on all applicable URLs | STRONG | Platform-enforced access restriction when coverage is correct. Unauthenticated public visitors would also be blocked on protected custom production domains; do not enable indiscriminately. |
| Standard Protection on generated/preview/old deployment URLs | STRONG for covered URLs | Prefer this independent control. It does not protect public production domains from direct connections using the custom hostname. Audit production aliases separately. [Protection scope](https://vercel.com/docs/deployment-protection). |
| All Deployments plus Cloudflare automation bypass token | NOT APPLICABLE to this phase's chosen design | Technically supported but not selected: the token also skips some Vercel system/bot protections, coupling layers. Never inject it for all visitors. [Bypass behavior](https://vercel.com/docs/deployment-protection/methods-to-bypass-deployment-protection/protection-bypass-automation). |
| Vercel WAF custom request-header denial | STRONG for covered requests while secret stays private | Potential platform enforcement supplement with separately reviewed field semantics, deployment coverage, exemptions and secret handling. Do not assume entitlement or apply here. [Rule fields](https://vercel.com/docs/vercel-firewall/vercel-waf/rule-configuration). |
| Vercel Trusted IPs / Cloudflare egress ACL | DEFENSE-IN-DEPTH ONLY for this topology | May exclude direct non-Cloudflare traffic, but shared provider ranges do not identify this zone, require current lists/plan support, and proxy-aware IP matching needs verification. |
| Application origin secret + exact hosts | DEFENSE-IN-DEPTH ONLY | Implemented disabled. Reduces bypass value at application routing; leaked bearer, stale deployment or pre-application saturation remain risks. |
| Host allowlist alone | DEFENSE-IN-DEPTH ONLY | Narrows alternate-host routing; attacker can target Vercel with the real Host/SNI. |
| Hide/rename generated URL; remove links; robots exclusion | COSMETIC | Not access control. Generated URLs exist; no documented global deletion switch is assumed. [Generated URLs](https://vercel.com/docs/deployments/generated-urls). |
| Remove unnecessary custom aliases | DEFENSE-IN-DEPTH ONLY | Useful surface reduction after inventory; not complete origin isolation. Not performed. |
| Cloudflare AOP/mTLS or Tunnel to ordinary Vercel hosting | NOT APPLICABLE | This checkout does not control Vercel's inbound TLS listener/client-cert trust or run a private tunnel origin. AOP requires origin-side enforcement. [AOP setup](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/global/). |
| Verified Proxy Lite / Advanced | NOT APPLICABLE as origin authentication | Proxy recognition/address semantics do not deny direct access. Advanced is not purchased/enabled here. |

Vercel announced free All Deployments Vercel Authentication on every plan on 2026-09-09; older pricing statements can be stale. Verify the actual account's available controls and their visitor impact before choosing scope. [Current announcement](https://vercel.com/changelog/protect-production-deployments-for-free-on-every-plan).

## 8. Manual acceptance, observations and rollback

After the later approved release/cutover, record **booleans and status codes only**, never full request headers:

1. Both public HTTPS hosts render and load immutable bundles; apex/www redirects preserve form behavior. No mixed content, CSP violations, unwanted challenges or real Turnstile calls occur in the closed posture.
2. Local tests simulate pass-through, but only a controlled deployed check can confirm the custom origin header survives the actual route. Verify via successful guarded navigation and negative direct-origin requests; do not add a header echo endpoint. No secrets in browser responses, build output or log drains.
3. Direct generated/branch/old deployment URLs are blocked by their intended platform policy or application guard. Also test a direct Vercel connection using the **custom public Host/SNI**: origin-secret absence still denies even though the host is legitimate. Spoofed CF/XFF/origin-secret values and duplicate values never grant entry.
4. Admin without Access JWT is denied on public, admin and generated hosts; legitimate Access authentication and exact allowed email still work. An allowlisted bearer JWT replayed directly may remain valid until expiry; do not label that as network isolation. Verify admin list/detail and mutations only with synthetic data in an approved nonproduction setup.
5. The form renders a fresh token, preserves errors and remains unable to persist. Test native and hydrated flows. Same-host Action posts reach normal validation; hostile/mismatched Origin fails. No `allowedOrigins` expansion.
6. Form/admin/detail/thank-you/action responses show no shared-cache HIT across repeated anonymous and authenticated sessions. Test RSC navigation, query parameters, a fake static suffix on a private path and differing credentials. All admin-host content bypasses Cloudflare cache. Never put real customer data into a cache probe.
7. Certificate checks remain reachable without HTTP redirection and Vercel verification paths are never cached. Confirm renewal prerequisites from both providers' current dashboards.
8. Watch per-rule matches, blocks/challenges, challenge solve rates, response status, p95 latency, origin request volume, cache status, Worker/transform changes, Vercel proxy-detected warnings and deployment-protection exceptions. Compare edge request volume with origin invocations to find bypass/configuration regressions. Alert on sudden origin spikes, 403/404/429 increases, 5xx, challenge failures and private-route cache hits.

Use aggregate provider metrics with the shortest practical retention and restricted operator access. Do not introduce full-header/body logging, visitor fingerprints, raw-IP exports, query-string captures, Access assertions, Turnstile tokens or HMAC-key dashboards. Internal limiter metrics should be aggregate outcome counters; HMAC keys belong only to the future limiter store, with bounded retention. A targeted incident investigation needs a separate minimized-data decision.

If a WAF/rate rule overblocks, narrow or disable that specific rule while retaining origin authentication and all application gates. If Cloudflare is unavailable or DNS becomes DNS-only, required origin protection denies requests: availability is lost, data gates remain. Do not automatically disable it. A deliberate DNS-only rollback requires explicit operator acceptance of lost origin resistance and restored **direct-only** ingress assumptions, while persistence remains disabled. A safer outage posture is maintenance/denial until Cloudflare recovers. Keep configuration snapshots and ownership outside this repository; do not store secret-bearing exports here.
