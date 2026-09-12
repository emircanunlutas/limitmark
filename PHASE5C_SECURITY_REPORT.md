# Phase 5C: trusted proxied ingress and shared atomic admission

Review date: 2026-09-12. Baseline: `da0b43d7390b518e31ac4cb8048efaa5af1c57c9`, initially clean. No deployment, DNS/account change, real provider request, customer-data write, or commit was performed.

## Decision

B1 remains unresolved. Neither a supported proxied visitor identity nor a production limiter meeting the complete strict contract can be established from the reviewed guarantees. The changes harden and test the closed posture; they do not make persistence ready. `cloudflare-via-vercel` is not implemented. `upstash` is not registered, and its URL/token are not read by production code. No weaker adapter, global-only bypass, CIDR allowlist, signed-header approximation, or in-memory production fallback was added.

## 1. Cloudflare to Vercel trust chain

The following describes the documented ordinary path; Workers, managed transforms, origin rules and Enterprise proxy onboarding can change it. These are documentation findings, not observations of the user's deployment.

| Header | Cloudflare behavior | Application consequence under Vercel Lite |
| --- | --- | --- |
| `CF-Connecting-IP` | Sets connecting visitor address on ordinary proxy traffic. | Can arrive, but has no documented application-visible authenticity wrapper. |
| `CF-Connecting-IPv6` | Preserves real IPv6 when Pseudo IPv4 overwrites visitor headers. | No independently authenticated identity. |
| `True-Client-IP` | Enterprise managed transform supplies visitor IP; otherwise stacked-CDN spoofing is possible. | No stronger trust than the CF header. |
| `X-Forwarded-For` | Sets visitor IP when absent; appends to an existing chain. Pseudo overwrite changes it. | Vercel overwrites external XFF. |
| `X-Real-IP` | Stripped on ordinary non-Worker requests. | Vercel defines it as identical to its XFF. |
| `X-Vercel-Forwarded-For` | No Cloudflare platform guarantee for this name. | Vercel platform copy of XFF, subject to the reviewed ingress configuration. |
| `CF-Ray` | Cloudflare supplies a request/colo identifier. | Presence/syntax is not proof of traversal. |

Cloudflare's definitions support the Cloudflare column; the Vercel column relies on Vercel's distinct platform contract. Direct clients can send CF-looking headers without traversing Cloudflare. [Cloudflare HTTP headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/).

Vercel documents overwriting external XFF to prevent spoofing; `X-Real-IP` and `X-Vercel-Forwarded-For` correspond to that platform value. `Host` is the requested domain and `X-Forwarded-Host` is identical to it. Inference: with Lite, the platform IP represents the upstream proxy, not the visitor. Header equality cannot establish proxy provenance. A direct client can target an assigned public hostname and choose Origin; routing and CSRF checks are not identity proofs. An untrusted local/self-hosted server does not acquire Vercel header guarantees by setting `VERCEL=1`. [Vercel request headers](https://vercel.com/docs/headers/request-headers).

Vercel recognizes supported provider egress ranges plus specific headers internally. Cloudflare Lite is automatic. Its knowledge-base guidance says direct access remains possible and app-visible IP/geolocation normally represents the proxy. Advanced is the Enterprise option for restoring visitor IP/geolocation. The reviewed documentation exposes no signed traversal claim or protected boolean for application code, and does not promise that a CF header is removed from direct requests. Absence of such a documented signal is an evidence gap, not proof no private platform capability exists. [Verified Proxy guide](https://vercel.com/kb/guide/how-to-setup-verified-proxy).

Advanced materially changes the available platform capability. It requires onboarding and an exact review of trusted egress, visitor-header source, platform overwrite behavior, direct access, Workers and hostname scope. The general Enterprise feature description is insufficient to implement an application policy here. No Advanced configuration or account entitlement was assumed. [Vercel reverse-proxy requirements](https://vercel.com/docs/security/reverse-proxy).

`Host` normally follows routing, but Cloudflare Origin Rules can override both Host and SNI. Thus consistent `limitmark.com` or `www.limitmark.com` values are necessary routing restrictions, never authentication. [Cloudflare Origin Rules](https://developers.cloudflare.com/rules/origin-rules/).

### Transforms, Workers and Pseudo IPv4

Request-header Set rules overwrite a prior value, so the origin-secret transform must use Set. Request transforms cannot rewrite protected CF headers (CF-Connecting-IP can be removed) or arbitrarily change visitor-IP headers. Removing XFF may still lead to the backend proxy restoring it. Snippets/Workers introduce different processing. These restrictions on Cloudflare execution do not restrict an attacker calling Vercel directly. [Request-header transforms](https://developers.cloudflare.com/rules/transform/request-header-modification/).

Same-zone Worker subrequests derive CF-Connecting-IP from mutable X-Real-IP; cross-zone requests use `2a06:98c0:3600::103`. For non-Cloudflare destinations, the documented Worker behavior differs again. `CF-Worker` marks fetch subrequests. Pseudo IPv4 Add Header adds `CF-Pseudo-IPv4`; Overwrite Headers replaces CF-Connecting-IP/XFF and preserves IPv6 separately. These signals can justify denial, never acceptance. Their absence proves neither ordinary traversal nor absence of a Worker. [Cloudflare Worker/header semantics](https://developers.cloudflare.com/fundamentals/reference/http-headers/).

| Actual path | What application code can conclude here |
| --- | --- |
| Ordinary Cloudflare → Lite | Plausible CF header and proxy peer; cannot authenticate the visitor claim. Denied. |
| Direct Vercel | Platform peer is usable only in explicitly configured direct mode. |
| Direct Vercel with spoofed CF headers | CF values remain untrusted. Denied, including with a leaked origin bearer. |
| Worker-mediated | Detectable hints cause denial; no universal application distinction is established. |

A Cloudflare egress HMAC could be a coarse peer bucket if the platform peer contract were selected. It groups unrelated visitors and is not a stable visitor identity: shared egress, routing changes and Worker egress remain. Applying 5/10 minutes to a proxy could block many visitors. An IP-range match proves at most network origin, not this zone or its visitor-header semantics. No such mode was added. Global controls are preserved, but a new global-only acceptance mode would remove the current required-client gate and still lack a qualified shared provider.

## 2. Independent origin and admin authentication

The existing origin layer is unchanged: exact Vercel Production, `PUBLIC_ORIGIN_PROTECTION=required`, a singular fixed-size bearer matched with a timing-safe comparison, public Host allowlist, and exact forwarded-host equality. Missing/wrong/duplicate credentials deny. Public routes/Actions remain protected by the existing proxy; admin routes retain independent Access JWT verification and explicit identity allowlisting.

A static bearer authenticates possession, not a client address or a specific request. Assuming an unexposed secret and a correctly controlled transform, secret plus CF-Connecting-IP can provide operational assurance of ordinary routing. It supplies no cryptographic binding, freshness, or protection against a bearer holder inventing the visitor header on a direct request. Therefore it does not meet the requested leaked-secret threat model. Neither origin credentials nor edge-looking bypass headers authorize intake or admin access.

## 3. Ingress changes implemented

Direct mode remains the only type/configuration accepted. The identity module now explicitly imports `server-only`, rejects additional detectable Worker/Pseudo IPv4/O2O hints, and maps IPv4-mapped IPv6 to the canonical IPv4 bucket. Ordinary IPv6 spelling normalization remains. Noncanonical IPv4 forms, ports, brackets, zone IDs and comma-separated values fail closed. Arbitrary XFF/X-Real-IP/True-Client-IP alternatives cannot supply or replace identity.

Only the HMAC-SHA-256 base64url result exits derivation. No raw IP return, persistence, log, or network transmission was added. The existing secret must still be supplied through the production configuration gate. Mapping changes only the former mapped-address bucket; no production limiter state exists to migrate.

## 4. Upstash suitability

| Option | Verdict against this adapter contract |
| --- | --- |
| `@upstash/ratelimit` | Not a direct fit: approximate sliding windows, independent identifier decisions, timeout success, and multi-region overshoot. |
| REST pipeline | Not atomic; commands can interleave. |
| `MULTI/EXEC` alone | Serial batch execution does not condition all writes on dynamically read capacities. Runtime command errors do not roll back the batch. |
| Lua/EVAL | Supports one isolated read/decide/write step across declared keys in normal execution. Does not establish failover/partition consistency. |
| Sorted-set observation log | Suitable data structure for exact rolling windows, conditional on a provider satisfying the storage/consistency contract. Not implemented. |

The SDK's sliding window estimates earlier traffic using weighted fixed buckets. It is not an exact observation log. Calling two limiters cannot make one denial undo another successful consume. [SDK algorithms](https://upstash.com/docs/redis/sdks/ratelimit-ts/algorithms).

The SDK documents timeout success and asynchronous multi-region synchronization with possible overshoot. Disabling timeout success would fix only that behavior, not combined-rule atomicity or replication guarantees. MultiRegionRatelimit over multiple databases is also distinct from one globally replicated Upstash database. [SDK features](https://upstash.com/docs/redis/sdks/ratelimit-ts/features).

Upstash REST supports JSON command requests, EVAL and `/multi-exec`. A pipeline is not atomic. Transactions execute all valid queued commands even if an individual command encounters a runtime error. [REST semantics](https://upstash.com/docs/redis/features/restapi).

EVAL uses a global lock by default; optional declared-key locking covers the participating hash tags. This supports atomic check-and-consume decisions during normal execution. Locks are not a published consensus/fencing guarantee across split brain. Passing all keys explicitly and using one request would be necessary but insufficient. [EVAL](https://upstash.com/docs/redis/commands/scripting/eval), [key locking](https://upstash.com/docs/redis/features/key-locking).

Upstash explicitly documents asynchronous replication, eventual consistency, and last-writer-wins conflict convergence during partitions. Its former single-region strong-consistency mode is deprecated. Inference: the published contract does not rule out an acknowledged quota observation being absent at a later serving leader, or conflicting admissions during a partition. An application can receive a syntactically successful response and cannot detect this to fail closed. This is the decisive blocker; it is not an assertion that every ordinary EVAL races. [Consistency](https://upstash.com/docs/redis/features/consistency).

Single-region selection does not remove primary replica failover. The replication documentation describes multiple primary replicas, and Global replication routes writes to a primary with read replicas elsewhere. That can reduce ordinary stale-read exposure for a write script but does not supersede the explicit consistency contract. [Replication](https://upstash.com/docs/redis/features/replication), [Global replication](https://upstash.com/docs/common/concepts/global-replication).

Upstash also documents persistent memory-plus-disk writes. This is valuable durability but is not a promise that all later elected leaders preserve the entire admitted history. Read-your-writes sessions do not globally serialize independent Vercel instances. [Durability](https://upstash.com/docs/redis/features/durability), [read your writes](https://upstash.com/docs/redis/howto/readyourwrites).

## 5. Algorithm, boundaries and ambiguous execution

No Redis script or network adapter was added. The contract now explicitly states all-rule consumption, no consumption on quota denial, concurrent no-overspend, bounded validation/TTL, and the interval `(t - windowMs, t]`: an observation exactly one window old is expired. The existing test double models this with timestamp arrays and a controlled clock. Its single-process synchronous decision is not evidence of Redis atomicity or durable state; it does not test TTL cleanup.

A future sorted-set implementation would require one server-time sample, removal of observations at/before the lower boundary, checking every rule before any new observation, then recording one unique internal attempt in every accepted rule. Equal timestamps must not collapse distinct attempts. Limits, windows, rule count, key lengths, key types, storage capacity/errors, expiration and clock changes all require review. No arbitrary bounds or unused script were added for a rejected provider. `TIME` exposes server seconds/microseconds; this avoids trusting Vercel clocks but does not itself prove monotonic time across failover. [Upstash TIME](https://upstash.com/docs/redis/commands/server/time).

An HTTP timeout or lost response can follow successful execution. Admission must return `unavailable` without refunding or retrying an uncertain consume. Quota may remain spent even though no business write occurs. Repeated user attempts may spend more quota; that is a separate attempt, not evidence the earlier consume was rolled back. The existing admission function makes one call per stage, and a deterministic lost-response test verifies it does not retry. No HTTP transport/timeout implementation is claimed here. The Redis SDK retries network errors by default, so a future adapter must explicitly prevent unsafe retries or prove provider-side idempotency. [SDK retries](https://upstash.com/docs/redis/sdks/ts/retries).

## 6. Two-stage admission and starvation

Existing order remains: schema and submission-token validation → identity → atomic pre client/global call → Turnstile → atomic post client/global call → repository. Turnstile rejection/outage consumes no post quota. A pre outage stops Turnstile; a post failure stops persistence. Unknown runtime limiter responses now become `unavailable`, preserving the bounded decision vocabulary. Post and pre retain independent existing key namespaces; no edge/origin option skips either stage.

| Stage | Client | Global | Purpose |
| --- | --- | --- | --- |
| Pre | 30 / 10 minutes | 300 / minute | Bound admissions to expensive verification. |
| Post | 5 / 10 minutes | 100 / minute | Bound verified admissions to business writes. |

These remain conservative, inactive defaults, not measured capacity estimates. There is no supplied inquiry-volume, latency, cost or shared-office distribution to justify raising them. Five requests per shared IP can be unfair to offices/CGNAT. IPv6 rotation/distributed clients can evade client fairness buckets; those keys identify network addresses, not people. Raising client/global ceilings would buy capacity at additional cost, not eliminate starvation.

The audit attack reproduces deterministically: 10 clients × 30 rejected attempts at time zero exhaust all 300 pre admissions. New clients get no Siteverify call until observations begin expiring at 60,000 ms. Denied attempts do not refresh the window. Original attacking clients remain client-limited until 600,000 ms. With more clients, an attacker can compete for every reopened global slot indefinitely; recovery after attack cessation is bounded by the last accepted observations, not the last denial. Client exhaustion can last ten minutes.

Strict post capacity stays untouched by these rejected challenges. Requests already admitted through pre can finish Turnstile and consume available post quota even while pre is saturated; a dedicated test proves this. Fresh submissions, even carrying a valid browser challenge token, must still pass pre and cannot use the reserved post capacity. Read-only pages and independent authorized admin operations are outside these budgets.

No anonymous pre-verification partition can guarantee a reserved legitimate share when attackers can choose identities. Shards with a summed ceiling partition rather than create capacity; distributed attackers can reach them. A bypass for allegedly verified clients would require verifying before the cost budget, defeating its purpose. Accordingly the report preserves the safety ceiling and explicitly leaves fresh-intake availability under sustained abuse unresolved.

Cloudflare edge shaping can reject traffic before Vercel and reduce pressure, but distributed rate counting and attacker diversity cannot establish strict fair admission. Existing edge policies supplement the app. [Cloudflare rate-limit semantics](https://developers.cloudflare.com/waf/rate-limiting-rules/).

The global pre ceiling bounds admissions to Siteverify, not all Redis billing: schema-valid denied attempts would still need a provider decision. In-flight scheduling/retries also mean admission timestamps are not an exact measurement of HTTP arrival times. Verified pre-admitted requests cause a second limiter decision even when post denies. Redis commands inside scripts and replication/analytics affect cost; one HTTP request is not necessarily one billed command. No spending figure or safe traffic volume is invented. [Upstash cost accounting](https://upstash.com/docs/redis/sdks/ratelimit-ts/costs).

## 7. Environment isolation and privacy

The production registry is empty and factory returns null for every provider, including `upstash`. Missing, malformed or plausible URL/token settings all leave intake closed, in Production as well as Preview/development. Tests also inject a hypothetical registered name into the pure configuration function to prove unsupported ingress still fails separately. This is not a credential validator or a successful adapter-construction test.

All existing deployment, submission-mode, persistence, DB, HMAC, Turnstile and origin gates remain. Production cannot demo-accept. Admin DB configuration remains independent of public intake, with exact Production restrictions. No Preview Redis path exists.

Before a future adapter is registered, code must enforce exact Production configuration and a fixed environment namespace in every physical provider key, plus a strict HTTPS endpoint and credential policy. The current logical test keys are not production Redis keys. Only fixed namespace/environment/stage/global components and opaque client HMACs may appear in actual keys. Payloads, email, UUIDs, all submission/challenge tokens and both secrets must be excluded. Namespace checks alone cannot stop someone with a copied full-access Redis credential operating outside this code: separate resources and scoped credentials remain operator requirements.

No Redis SDK, analytics, telemetry, logging or metrics transport was added. The limiter SDK's identifier analytics is documented as disabled by default; when enabled it records identifier activity. Its dashboard Data Browser can inspect full keys, and REST MONITOR can expose commands. An HMAC is pseudonymous, not anonymous. A future adapter should explicitly keep identifier analytics off, disable optional SDK telemetry, avoid MONITOR, restrict dashboard access and establish retention. This does not establish that arbitrary service-side key retention is disabled. Only aggregate stage/allowed/limited/unavailable/latency metrics would fit this application's requested observability model. [Analytics defaults](https://upstash.com/docs/redis/sdks/ratelimit-ts/features), [Data Browser commands](https://upstash.com/docs/redis/troubleshooting/command_count_increases_unexpectedly), [SDK telemetry](https://upstash.com/docs/redis/sdks/ts/advanced).

## 8. Verification and coverage limits

Results are recorded below. No existing assertions are weakened. New tests distinguish application behavior and a deterministic model from provider behavior.

| Requested coverage | Evidence / limitation |
| --- | --- |
| 1–10 ingress | Direct-mode, spoof, origin-bearer, unknown mode, Worker/Pseudo hints, malformed chains, IPv4/IPv6 equivalence and opaque-output tests. Legitimate proxied success intentionally not implemented. |
| 11–15 provider config | All configurations stay closed, including plausible Production credentials. Successful Upstash construction is inapplicable because suitability failed. |
| 16–21 atomic/window | Existing model tests both-rule admission, symmetric no-partial denial, concurrent capacity and exact boundary. No provider claim. |
| 22–26 TTL/input/HTTP | No provider/script exists: TTL, provider mutation validation, HTTP error and transport timeout integration are not implemented/tested. Admission's unavailable/throw/invalid-response behavior and no retry after modeled consumption are tested. |
| 27–34 two-stage/replay | Ordering, pre-only rejected/unavailable challenges, stage failures and retry/correction covered by unit/browser tests. Successful real-provider-to-DB flow is unavailable; DB replay/concurrency tests require the dedicated test URL. |
| 35–40 defense in depth | Origin/edge-looking headers cannot bypass; Preview/intake/demo gates and independent admin auth/data remain covered. No live WAF/account state is claimed. |

No exact Redis script exists to integrate. Local Docker was confirmed available (29.7.2), but executing an invented demonstration script would not validate a production implementation or resolve Upstash's consistency gap; no Redis container/image/resource was created. `TEST_DATABASE_URL` was absent; the DB suite reports skips, not a database pass.

## 9. Remaining launch blockers and later smoke tests

The [manual provider smoke runbook](PHASE5C_PROVIDER_SMOKE_RUNBOOK.md) is conditional and was not executed. A successful happy-path smoke cannot prove partition/failover safety.

Before real Turnstile/DB intake, obtain a reviewed platform-supported client identity contract independent of origin-secret possession, and a provider contract ensuring combined-rule history survives failover without overspend. Advanced onboarding may resolve part of ingress; it must be verified precisely. A different strongly consistent admission store/architecture may be necessary. Preserve independent origin and admin authentication. Then implement/verify the selected adapter, resource isolation, retention and edge/cost policy, run required DB integration and the provider/ingress smoke, and address remaining browser regressions. Merely copying credentials cannot satisfy B1.

## 10. Final results and change inventory

| Check | Exact result |
| --- | --- |
| `npm.cmd test` | Exit 0: 127 discovered, 93 passed, 34 DB-dependent skipped, 0 failures. Includes 15 new Phase 5C tests. |
| Final focused `tests/phase5c.test.ts` | Exit 0: 15 passed, 0 failed/skipped; includes the final unsupported-source assertion. |
| `npm.cmd run test:db` | Exit 0: 34 skipped, 0 executed. `TEST_DATABASE_URL` absent, so the conditional required gate cannot run. Not a DB integration pass. |
| Admin auth/dashboard/mutation tests | 24 passed within the unit suite; DB-dependent admin integration cases are included in the skips above. |
| Full Playwright, all three projects | Exit 1: 126 executed, 122 passed, 4 failed, 0 skipped/flaky; 308.5 seconds. Chromium 42/42, Firefox 42/42, WebKit 38/42. |
| Cross-browser edge/security/Action regressions | All 9 passed within the full Playwright run. |
| `npm.cmd run test:edge-origin` | Exit 0: 3 passed. Required origin authentication, spoof denial and independent admin denial. |
| `npm.cmd run test:persistence-guard` | Exit 0: 2 passed. Built-server Production intake remains closed with invalid persistence configuration. |
| `npm.cmd run test:closed-intake` | Exit 0: 2 passed. Production demo remains disabled and intake presentation stays closed. |
| `npm.cmd run test:blockers` | Exit 1: 48 executed, 46 passed, 2 failed, no skips; 3.0 minutes. Chromium 14/16, Firefox 16/16, WebKit 16/16. |
| Redis/script integration | Not applicable: no provider/script implemented. Docker availability confirmed only; no Redis mutation performed. |
| `npm.cmd run lint` | Exit 0, no warnings. |
| `npm.cmd run typecheck` | Exit 0, strict TypeScript. |
| `npm.cmd run build` | Exit 0, final runtime source built with Next.js 16.3.4. |
| `npm.cmd audit --omit=dev` | Exit 0: 0 vulnerabilities. |
| `git diff --check` | Exit 0. |

The four complete-run failures match the Windows WebKit keyboard cases documented in `QA_REPORT.md` and `PHASE5A_SECURITY_REPORT.md`: `polish.spec.ts:39` at both 375px/1280px (privacy-link Tab focus), `release-navigation.spec.ts:84` (skip-link focus), and `site.spec.ts:55` (mobile-menu link focus). No UI/assertion changes were made. The suite is not fully green.

The additional blocker run failed Chromium's `hydration.spec.ts:5` observe case and `journey.spec.ts:138` third-party-and-tracking 375px case. Both reached the final audit after their demo-flow assertions, but the critical-request check recorded `net::ERR_ABORTED` on a first-party submission POST. These were not marked expected, filtered out, or retried into a green aggregate. Their root cause is not established by this phase; they are additional regression findings requiring investigation, not qualified as harmless or as known baseline failures. Evidence is retained in `artifacts/phase5c-blockers/report.json` and that directory's per-test audits/traces. The existing three-browser blocker command uses `QA_CROSS_BROWSER=true`, the same installed-browser path, and `QA_BLOCKER_RUN_DIRECTORY=artifacts/phase5c-blockers`.

The first sandboxed browser attempt reported 81 passed / 45 failed plus a teardown error. Firefox's `browserContext.newPage` failed before navigation; WebKit also saw font TLS errors and a navigation failure. The task-owned stalled Next server (PID 17368) was terminated after normal/PowerShell shutdown failed. The complete outside-sandbox rerun used a 600-second aggregate deadline, with every test/assertion timeout unchanged; Firefox and WebKit TLS/navigation errors cleared. Final JSON is `artifacts/phase5c-e2e.json`; traces/screenshots are in `artifacts/phase5c-e2e-results/`. Other harness artifacts use the `artifacts/phase5c-*` directories. All are ignored local artifacts.

Reproduce the complete run in PowerShell with the repository's installed browsers:

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = 'C:\Users\Emir\Desktop\pentest-website\.playwright'
$env:QA_CROSS_BROWSER = 'true'
$env:PLAYWRIGHT_JSON_OUTPUT_FILE = 'C:\Users\Emir\Desktop\pentest-website\artifacts\phase5c-e2e.json'
npm.cmd run test:e2e -- --global-timeout=600000 --output=artifacts/phase5c-e2e-results --reporter=list,json
```

Changed files (eight total, all uncommitted):

| File | Change |
| --- | --- |
| `src/lib/client-identity.ts` | Server-only boundary, additional incompatible-hop hints, IPv4-mapped normalization. |
| `src/lib/rate-limit.ts` | Server-only boundary and precise contract/rejection rationale; registry remains empty. |
| `src/lib/submission-abuse-control.ts` | Server-only boundary, bounded runtime failure decisions and starvation caveat. |
| `tests/phase5c.test.ts` | 15 adversarial application/model tests; no provider simulation presented as integration. |
| `.env.example` | Explicit Upstash/proxied persistence prohibition and report pointers; no credentials. |
| `README.md` | Phase 5C readiness limitation and report/runbook links. |
| `PHASE5C_SECURITY_REPORT.md` | Official evidence, decisions, coverage and residual blockers. |
| `PHASE5C_PROVIDER_SMOKE_RUNBOOK.md` | Conditional later qualification steps, never executed here. |

HEAD remains `da0b43d7390b518e31ac4cb8048efaa5af1c57c9`. Nothing staged or committed. Five tracked files changed, with 37 insertions and 10 deletions; three new untracked files are excluded from that tracked diff statistic. Build-generated `next-env.d.ts` changes were restored. No dependencies, lockfile, migrations, AGENTS instructions, accounts or real configuration changed.

```text
 M .env.example
 M README.md
 M src/lib/client-identity.ts
 M src/lib/rate-limit.ts
 M src/lib/submission-abuse-control.ts
?? PHASE5C_PROVIDER_SMOKE_RUNBOOK.md
?? PHASE5C_SECURITY_REPORT.md
?? tests/phase5c.test.ts
```

B1 is unresolved: trusted proxied identity and a qualified strict shared provider are both still missing. The safe code changes do not resolve either launch condition. Redesign or stronger verified platform/provider guarantees are required before provider smoke can qualify persistence.
