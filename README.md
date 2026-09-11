# Resilience testing website

Turkish B2B website for **manually scoped, manually executed** resilience testing. The neutral `Resilience Testing` label is not a finalized brand. No accounts, dashboard, automated tests, pricing, invented claims or external service integrations are included.

## Local development

Requirements: Node.js 22+ (Node 24 recommended) and npm. The repository is the application root.

```sh
npm ci
npm run dev
```

Open **http://127.0.0.1:3000**. On PowerShell, use `npm.cmd` if local policy prevents executing `npm.ps1`; no execution-policy changes are needed. npm's cache is kept in the ignored `.npm-cache/` directory inside the repository.

## Stack and structure

- Next.js App Router, React, strict TypeScript.
- Plain CSS with central design tokens and responsive grid rules in `src/app/globals.css`. No Tailwind, animation package or UI framework.
- Server Components by default; client components only for navigation and form interactions.
- Native `details` / `summary` disclosures, labelled controls, error associations, keyboard focus, a skip link and reduced-motion support.
- `src/components/`: shared header, footer, container, link button, disclosure, diagram, form fields and request form.
- `src/lib/services.ts`: service descriptions and editable URL selection.
- `src/lib/site-config.ts`: neutral brand and server-side contact configuration.
- `src/lib/request-schema.ts`: shared Zod validation, whitelisted field extraction and Turkish errors.
- `src/app/test-talep-et/actions.ts`: independently validated Server Action.
- `src/lib/submission-adapter.ts`: isolated demo/production submission boundary.
- `src/lib/inquiry-repository.ts`: idempotent transactional inquiry repository.
- `src/lib/notification-adapter.ts`: provider-neutral, minimal notification delivery contract.
- `src/lib/notification-config.ts` and `src/lib/resend-notification-adapter.ts`: fail-closed Resend configuration, minimal message construction, bounded HTTPS delivery, and provider-neutral result classification.
- `src/lib/notification-outbox-repository.ts` and `src/lib/outbox-processor.ts`: PostgreSQL claim/lease persistence and deployment-neutral batch processing.
- `src/lib/notification-retry-policy.ts`: deterministic, configurable retry timing and budget.
- `src/lib/db/schema.ts` and `drizzle/`: typed PostgreSQL schema and SQL migrations.
- `src/lib/submission-policy.ts` and `src/lib/persistence-config.ts`: explicit fail-closed gates.

## Routes

| Route | Purpose |
| --- | --- |
| `/` | Services, deliverables, process, methodology, FAQ and contact |
| `/test-talep-et` | Single-step request form |
| `/test-talep-et?hizmet=web` | Preselect web (also `network`, `protection`, `unsure`) |
| `/test-talep-et/tesekkurler` | Confirmation copy; excluded from indexing |
| `/gizlilik` | Preliminary privacy information |
| `/test-yetkilendirmesi` | Operational scope and authorization principles |
| `/admin` | Independently authorized, read-only inquiry list with bounded search, status filtering and pagination |
| `/admin/inquiries/<uuid>` | Independently authorized, read-only inquiry submission, event history and existing admin notes |

An unknown or repeated service query defaults to `unsure`. A custom Turkish 404 and recoverable error page are included.

## Submission behavior — read before launch

The default mode remains a local demo. In demo mode no email is sent, no request is stored, and no CRM or external recipient receives the form. The confirmation page demonstrates the approved future flow; it is not evidence of delivery.

In development, valid requests pass through a non-persistent demo adapter and redirect to confirmation. Both client and server validate the same schema; server validation is authoritative. Unknown fields are stripped, repeated known fields and file values are rejected, lengths and enum values are checked, and stale provider details are removed when protection is not in use. Form data is never put into a URL, local storage or application logs. React renders text safely without raw HTML injection.

In production, the demo adapter is **disabled by default**. A valid submission returns a clear unavailable message and retains the entered values. To preview the complete demo using a production build, explicitly set `ALLOW_DEMO_SUBMISSIONS=true` in the process environment or an ignored `.env.local`. This opt-in is for isolated preview only. Unknown `REQUEST_SUBMISSION_MODE` values always fail closed.

Phase 1 adds an explicitly gated PostgreSQL mode. It is selected only when all of the following are valid:

- `REQUEST_SUBMISSION_MODE=postgres`
- `ENABLE_PERSISTENT_SUBMISSIONS=true`
- `DATABASE_URL` is a credentialed `postgres://` or `postgresql://` runtime URL using the selected managed provider's pooled/serverless-safe endpoint where available
- optional `DATABASE_POOL_MAX` is an integer from 1 through 10 (default `5`)

Missing or malformed configuration never falls back to demo success. Database connection/query failures also produce the existing safe failure path, without exposing database details or submitted values. The runtime keeps one bounded Postgres.js pool per application process and disables prepared statements for compatibility with managed transaction poolers; it does not create a pool per request. This process-level bound does not replace provider-side pooling across multiple serverless instances. Use the selected managed provider's pooled/serverless-safe PostgreSQL endpoint where applicable. Provider-specific TLS/query parameters belong in the server-only URL.

**REAL NON-DEMO PUBLIC SUBMISSIONS MUST NOT BE ENABLED UNTIL LATER ABUSE-CONTROL AND SECURITY/PRODUCTION-READINESS PHASES ARE COMPLETE.** Phase 1 is a persistence foundation, not public launch authorization.

### Persistence transaction and idempotency

Each fresh server render creates a 256-bit opaque submission token and places it in a hidden native form control. The same token survives hydrated submission, native submission, validation responses, corrected resubmission and transport retry. The server hashes a fixed-order serialization of the authoritative normalized Zod output with SHA-256; raw form bodies, tokens and fingerprints are not logged.

The repository transaction attempts an inquiry insert using the database-unique token. A new row atomically creates exactly one `inquiry_received` event and one pending notification outbox row. A matching token and fingerprint is an idempotent success, including after a concurrent unique-constraint race. A matching token with a different fingerprint neither writes nor overwrites anything and returns a generic safe retry path. PostgreSQL is the source of truth; no external side effect occurs inside the transaction.

`inquiry_events` is append-only (updates/deletes are rejected), and inquiry, event, note and outbox foreign keys use restrictive deletion rather than cascading history loss. The inquiry workflow vocabulary is `received`, `in_review`, `awaiting_scope`, `proposal_sent`, `approved`, `declined`, `completed`, and `archived`; Phase 1 does not implement transitions.

Outbox states are explicit: `pending` has never been attempted, `processing` is actively leased, `retryable` may be claimed again after a failed attempt, `sent` is delivered, and `failed` is terminal retry exhaustion or permanent rejection requiring operational attention. `admin_notes` remains schema-only.

### Phase 2A notification outbox processor

Phase 2A adds a pure, deployment-neutral `processOutboxBatch()` service. A future cron handler, scheduled function, CLI, or always-on worker can construct the repository and adapter and invoke the same service; there is no cron Route Handler or deployment-provider binding in this phase. Batch delivery is sequential for initial rate control, defaults to 10 rows, and rejects sizes above the enforced maximum of 100.

The lifecycle is:

1. In one short PostgreSQL transaction, select eligible rows with `FOR UPDATE SKIP LOCKED`, update them to `processing`, set `locked_until`, and increment `attempts`.
2. Commit that claim transaction before calling the notification adapter.
3. Deliver only a minimal command containing the outbox ID/idempotency key, inquiry reference, and event type. Customer e-mail, system, objective, provider, and notes are not passed to the adapter.
4. Conditionally persist `sent`, `retryable`, or `failed` only if the exact lease and attempt are still owned by that worker.

Eligible rows are `pending` or `retryable` with `available_at <= now`, plus `processing` rows whose non-null lease has expired. A future `locked_until` cannot be stolen. `sent` and `failed` are terminal and are never automatically claimed. Expired `processing` rows need no administrative reset: a later claim starts a new attempt and replaces the lease. A late result from the expired worker is discarded through the lease/attempt ownership condition, so it cannot overwrite the newer worker's state. Notification processing never mutates or deletes the related inquiry.

`attempts` means the number of delivery attempts started. Atomically claiming a row for delivery starts one attempt and increments it exactly once; merely inspecting or skipping a row does not. Consequently, a process crash immediately after a committed claim may consume an attempt even if the adapter call did not begin. The lease still makes the row recoverable.

The default retry policy allows five total attempts. Its deterministic bounded exponential calculator starts at one minute, doubles per failed attempt, and caps at one hour; under the default budget, attempts one through four schedule one-, two-, four-, and eight-minute retries, while a fifth failure is terminal. Callers can supply another explicit attempt budget and timing policy. A retryable result with budget remaining moves to `retryable`, schedules `available_at`, clears the lease, and stores only an allowlisted non-sensitive error code. Exhaustion moves directly to `failed`. A permanent result also moves immediately to `failed`. An unexpected adapter throw is caught without retaining or logging its message and is treated as retryable `unknown`, subject to the same budget. A repository/process crash leaves a claimed row in `processing` until lease recovery rather than falsely recording success.

Success moves the row to `sent`, records `sent_at`, clears the lease, and clears `last_error_code`. Error metadata is limited to `timeout`, `rate_limited`, `provider_unavailable`, `rejected`, or `unknown`; raw exception text, response bodies, credentials, secret URLs, tokens, stack traces, and inquiry content are not stored or logged.

Delivery is intentionally **at least once**, not exactly once. If a provider delivers successfully and the process dies before `sent` is recorded, the expired lease permits another delivery. A future production adapter should pass the stable outbox row ID as the provider idempotency key where supported. Lease ownership prevents stale database updates, but it cannot retract an already completed external delivery.

Synthetic adapters cover successful, retryable, permanent, thrown, and delayed behavior without internet calls. Phase 2A itself remains provider-neutral and deployment-neutral.

### Phase 2B Resend notification provider

Phase 2B adds a server-only `ResendNotificationAdapter` that can be passed to the existing `processOutboxBatch()` service. It adds provider capability only: it does not add a scheduler, cron Route Handler, worker daemon, automatic invocation, admin dashboard, or public enablement. PostgreSQL and the existing durable outbox state transitions remain the source of truth.

Real delivery fails closed and is available only when all four values are valid:

- `ENABLE_REAL_NOTIFICATIONS=true` (the value is exact; missing, `false`, and unknown values keep delivery unavailable)
- `RESEND_API_KEY` is a non-empty, syntactically valid `re_...` key
- `NOTIFICATION_FROM_EMAIL` is a plain valid mailbox on a sender domain verified in the Resend account
- `NOTIFICATION_TO_EMAIL` is one plain valid internal recipient mailbox

Keep these values in the server environment or an ignored local environment file. They are not `NEXT_PUBLIC_` variables and must never be exposed to browser code or logs. Disabled or malformed configuration does not construct a Resend client and never falls back to synthetic success. `.env.example` contains names and empty placeholders only.

The adapter sends one plain-text e-mail with exactly this shape (where `<inquiry UUID>` is the existing opaque inquiry reference):

```text
From: <configured sender>
To: <configured internal recipient>
Subject: New inquiry received — <inquiry UUID>

A new inquiry has been received.

Reference: <inquiry UUID>
```

No customer name, customer e-mail, company, system, target, objective, notes, provider/protection details, submission token, payload fingerprint, or event payload is included. Phase 4A does not add an admin-dashboard link to this message; notification content remains intentionally minimal.

Every attempt passes the unchanged notification outbox row UUID as Resend's `Idempotency-Key` request header. Retries of the same outbox command therefore reuse the same key and payload. Resend currently retains idempotency keys for 24 hours, so this reduces duplicates only within that provider window; the durable end-to-end model remains **at least once**, never exactly once.

The HTTPS request is bounded to ten seconds. Abort timeouts become retryable `timeout`; network failures and Resend server/temporary errors become retryable `provider_unavailable`; provider and quota rate limits become retryable `rate_limited`; clear request, sender, recipient, credential, and idempotency rejections become permanent `rejected`. Unknown failures remain conservatively retryable `unknown`. Provider bodies, exception messages, headers, request payloads, addresses, and credentials are neither logged nor returned to the processor, and only the existing bounded error codes can reach `notification_outbox.last_error_code`.

The official Node SDK was evaluated before implementation. Its current client has no request-timeout option and logs parsed API error objects outside production, which conflicts with this project's timeout and error-privacy requirements. Phase 2B therefore uses one small typed `fetch` client against Resend's official HTTPS API rather than adding the SDK dependency.

No real e-mail is sent merely by building or starting the application. A verified Resend account/domain/API key must be configured and an operator must explicitly invoke a future deployment-specific batch entry point. Public persistent form submissions remain separately protected by the existing `REQUEST_SUBMISSION_MODE=postgres` and `ENABLE_PERSISTENT_SUBMISSIONS=true` go-live gates, which must stay closed until later abuse-control and production-readiness work is complete.

### Phase 3 Cloudflare Access admin authentication

Phase 3 established only the internal `/admin` authentication and authorization foundation; Phase 4A builds the read-only views described below on that boundary. Primary authentication and MFA remain the responsibility of Cloudflare Access and the configured external identity provider; the application stores no users, passwords, MFA secrets, sessions, or Access tokens.

The trust chain is Cloudflare Access policy, then application-side cryptographic JWT verification, then an independent exact-email allowlist. The server accepts the application token only from Cloudflare's documented `Cf-Access-Jwt-Assertion` origin header. It ignores the `CF_Authorization` cookie, query parameters, `X-User-Email`, `X-Forwarded-Email`, and other forwarded identity headers. The header takes deterministic precedence because it is the only accepted source.

Every `/admin` server render calls the reusable `requireAdmin()` boundary. Future admin Server Actions and Route Handlers must call the same boundary independently; middleware or Cloudflare policy must never become the sole authorization check. The original Phase 3 page was force-dynamic and exposed only a neutral authenticated state; Phase 4A preserves the dynamic and authorization guarantees while adding bounded inquiry reads.

Configure all three server-only values at runtime:

- `CLOUDFLARE_ACCESS_TEAM_DOMAIN`: exact HTTPS team origin, such as the documented `https://<team-name>.cloudflareaccess.com` shape, with no path, query, credentials, or port.
- `CLOUDFLARE_ACCESS_AUD`: non-empty Application Audience (AUD) tag copied from the Access application.
- `ADMIN_ALLOWED_EMAILS`: comma-separated, explicit individual mailboxes. Values are trimmed and lowercased. Invalid or duplicate entries invalidate the entire configuration; an empty list authorizes nobody. Domain suffixes and wildcard/domain-only authorization are not supported.

The server uses `jose` to require an RS256 signature selected by `kid`, the exact configured issuer and audience, expiration, `nbf` when present, an `iat` no more than 60 seconds in the future, an Access application-token type, and structurally valid email and subject claims. The same explicit 60-second clock tolerance applies to registered time-claim verification. The verified email is then matched exactly against the normalized allowlist. Missing or malformed configuration, a missing/malformed/unsigned token, the wrong key/issuer/audience, expired or future-invalid claims, a non-user/service token, an unavailable JWKS endpoint, or a non-allowlisted user all fail closed through the stable generic not-found route outcome. Tokens and broad claims are neither logged, persisted, nor returned to the browser.

Operational references: Cloudflare's current documentation for [validating Access JWTs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/), [application-token claims](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/), and [publishing a self-hosted application](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/).

Signing keys are obtained over HTTPS from `<team-domain>/cdn-cgi/access/certs`; no signing key or Cloudflare API credential is stored in the app. The library keeps an in-process JWKS cache for ten minutes, bounds retrieval to five seconds, observes a 30-second refresh cooldown, selects rotating keys by `kid`, and re-fetches when appropriate. A matching cached public key still performs a fresh cryptographic signature and claims verification on every request. If a required fetch or refresh fails and no usable verified key is available, access is denied. Instance restarts and newly scaled instances begin with an empty cache, so temporary Cloudflare/network failure can temporarily deny admin access by design.

There is deliberately no environment-controlled development bypass. A local browser cannot open `/admin` unless its request carries a valid token from the configured Access application and the identity is explicitly allowlisted. Unit tests use locally generated asymmetric keys and an injected in-memory JWKS resolver; they never contact a real Cloudflare account or endpoint.

### Phase 4A read-only inquiry administration

Phase 4A replaces the authenticated skeleton with a small Server Component dashboard. `/admin` reads a projection containing only the received timestamp, status, name, e-mail, company, requested service and environment. `/admin/inquiries/<uuid>` reads the bounded submitted fields plus chronological append-only events and existing admin notes. It does not read or expose submission tokens, payload fingerprints, event metadata, notification-outbox state or provider errors. Submitted and note content is rendered only as React text; it is not interpreted as HTML, Markdown or a URL.

Both routes call `requireAdmin()` independently before resolving repository access. No JSON admin API, mutation endpoint, Server Action, status control, note editor, retry control, assignment, bulk action or export is present. Both routes are force-dynamic and publish static customer-free metadata with `noindex,nofollow`. Inquiry detail links disable Next.js prefetch so the list does not speculatively fetch customer records.

List pagination is server-side, newest first by `created_at DESC, id DESC`, with 25 visible rows and one look-ahead row. Page input normalizes to `1..10000`; filters are preserved in previous/next links. Offset pagination is intentionally simple for the current scale and should be replaced by cursor pagination if the table becomes large. Search is trimmed to 254 characters, treats `%`, `_` and `\` literally, and checks only inquiry UUID prefix, name, e-mail and company. The status filter reuses the authoritative schema vocabulary: `received`, `in_review`, `awaiting_scope`, `proposal_sent`, `approved`, `completed`, `declined`, and `archived`. Unknown values, including `scheduled`, normalize to the unfiltered state and never influence SQL construction.

Event history and admin notes are deliberately oldest-first with timestamp-plus-ID tie-breakers, and each collection is capped at the 500 most recent records to prevent an unbounded response. The UI identifies a truncated history. Event metadata is not selected. Only admin actors expose their stored actor identifier; system events do not. A missing or invalid UUID receives the same generic not-found outcome.

Admin database reads reuse the existing fail-closed PostgreSQL configuration and therefore remain unavailable unless the existing persistence configuration is fully enabled. Configuration absence and connection/query failure render an explicit neutral “Inquiry data unavailable” state without error details; a successful empty query renders a different empty state. Phase 4A does not set `ENABLE_PERSISTENT_SUBMISSIONS`, add a database URL, migrate production, or otherwise enable public persistence.

The cosmetic redirect from `admin.limitmark.com/` to `/admin` is deferred. Hostname alone must not become an authorization signal, and no broad routing/proxy change was justified for this read-only phase.

Cloudflare control-plane work remains manual and must be completed before launch:

1. Create a Cloudflare Access self-hosted application for the intended admin hostname/path.
2. Add an explicit Allow policy for only the intended individual identity or identities, require MFA through the chosen IdP or Access policy, and deny everyone else.
3. Choose a bounded application/policy session duration.
4. Copy the application's Audience (AUD) tag and configure the three server environment values above.
5. Verify proxy/Tunnel and origin routing before launch. Ensure the origin cannot expose another hostname, direct route, or unprotected `/admin` path that bypasses Access.

Even when the origin is reachable only through Cloudflare, application-side JWT verification remains required. Conversely, JWT verification does not replace protecting and restricting the origin. No Cloudflare API keys or Access service-token credentials are needed or should be added for normal verification.

### Migrations and database roles

Use separate migration credentials; the application runtime role needs data access but must not require table/type/function creation privileges.

```powershell
$env:DATABASE_MIGRATION_URL = '<migration connection URL>'
npm.cmd run db:migrate
Remove-Item Env:DATABASE_MIGRATION_URL
```

Create future generated migrations with `npm run db:generate`, review the SQL, then apply them with `db:migrate`. Keep all URLs in the process environment or ignored local environment files, never tracked files.

For PostgreSQL integration tests, create a **dedicated disposable database**. The suite applies tracked migrations and truncates the four Phase 1 tables between cases; never point it at development, staging or production data.

```powershell
$env:TEST_DATABASE_URL = '<dedicated disposable database URL>'
npm.cmd run test:db
Remove-Item Env:TEST_DATABASE_URL
```

The database command runs both the Phase 1 persistence suite and Phase 2A outbox suite serially against the disposable database. Phase 2A coverage includes atomic claims, overlapping workers/processors, leases and expiry, retries and exhaustion, terminal states, batch bounds, attempts, thrown adapters, stale-worker outcome rejection, and inquiry immutability.

Before a future public launch, retain the Server Action validation and 32 KB body limit, add approved shared abuse controls at the trusted ingress, define retention/access/backup policy, and review infrastructure logging. Never trust arbitrary forwarded IP headers or log request contents.

Keep execution entirely separate: **a form submission never starts, schedules or authorizes a test**. Final targets, exclusions, limits, conditions, schedule, stop procedure and explicit authority must be documented manually before any testing.

There is deliberately no target-fetching, probing, task queue or test executor in the application.

## Branding, contact and fonts

Set the real mailbox through `CONTACT_EMAIL` in the server environment; see `.env.example`. Without a valid address, contact links, contextual copy and their spacing are omitted entirely. Rebuild after changing this setting so statically generated pages reflect it. Replace `siteConfig.name` and metadata when branding is approved. There are no invented corporate details.

Inter is requested from Google Fonts at browser runtime with `display=swap`; Arial/sans-serif is the fallback. No self-hosted assets or font downloads are required to build or run the site. Google Fonts is the only external browser resource; the preliminary privacy page describes it. Review the font provider/privacy approach before launch.

## Checks

```sh
npm run lint
npm run typecheck
npm test
npm run build
```

`npm run check` runs all four. Lint uses the ESLint CLI independently of the Next build. Unit tests cover the trust boundary, validation and the production demo guard.

`npm run test:db` runs the PostgreSQL-only migration, idempotency, concurrency and rollback suite described above. `npm run test:persistence-guard` starts the production build with persistence requested but deliberately malformed database configuration and verifies fail-closed behavior with and without JavaScript.

The browser regression suite covers form completion, service selection, associated errors, mobile keyboard navigation, independent disclosures, six viewport widths and automated accessibility rules. After a production build, install a test browser and run it:

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = "$PWD/.playwright"
npx.cmd playwright install chromium
npm.cmd run test:e2e
```

The test runner starts an isolated production preview on port 3100 with demo opt-in enabled. It does not connect to or test customer systems. Use synthetic data only. Browser binaries and reports are ignored by Git. Automated accessibility checks supplement manual keyboard, responsive and visual review; they are not an accessibility certification.

The deep QA findings, regression coverage, actual check results and remaining browser limitations are recorded in [QA_REPORT.md](QA_REPORT.md). Run the normal journey suite against a build with `CONTACT_EMAIL` unset. It now includes transport failure/retry, native submissions without JavaScript, server-returned validation state, multiline boundaries, malformed POSTs, routing/history, expanded layouts from 320 to 1920 px and runtime diagnostics. Screenshots are written to ignored `test-results/` output; resource timings are supplied as test-report attachments.

Optional cross-browser run (browser binaries remain local to this repository):

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = "$PWD/.playwright"
npx.cmd playwright install chromium firefox webkit
$env:QA_CROSS_BROWSER = 'true'
npm.cmd run test:e2e
Remove-Item Env:QA_CROSS_BROWSER
```

The Windows WebKit harness skips links on Tab even on plain HTML. Its original keyboard assertions remain enabled; see the QA report before interpreting those failures. No global keyboard preferences are changed.

### Privacy / content-blocker resilience

After a production build, run the dedicated suite using the already installed browsers:

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = "$PWD/.playwright"
$env:QA_CROSS_BROWSER = 'true'
npm.cmd run test:blockers
Remove-Item Env:QA_CROSS_BROWSER
```

Without `QA_CROSS_BROWSER`, the suite runs Chromium only. It starts its own demo-enabled production preview on port 3100; run it separately from the existing E2E suite. Fresh contexts simulate tracker-like blocking, all external requests blocked, and font-file blocking, with unblocked controls. Tests cover desktop/mobile navigation, disclosures, validation, optional values, submission, confirmation, transport retry, native submission without JavaScript and draft retention across delayed hydration. No extension detection or bypass is included.

Each run retains JSON request/console audits, screenshots and failure traces under `artifacts/blocker-runs/<timestamp>/`; `QA_BLOCKER_RUN_DIRECTORY` can set an explicit output directory. These artifacts are ignored by Git. The findings, diagnostic classifications, actual results and real-extension smoke checklist are in [PRIVACY_BLOCKER_AUDIT.md](PRIVACY_BLOCKER_AUDIT.md).

To check development-mode form behavior, set `QA_DEV=true` and run `npm.cmd run test:e2e -- release-form release-torture --project=chromium`, then remove `QA_DEV`. This uses the repository's development server on port 3000, reusing it if already running. The default suite always starts an isolated production server on port 3100.

Contact configuration and the production demo guard have a separate suite. For example, using a **synthetic test-only** mailbox:

```powershell
$env:CONTACT_EMAIL = 'qa-contact@example.test'
$env:QA_CONTACT_EXPECTED = 'qa-contact@example.test'
npm.cmd run build
npm.cmd run test:e2e -- --config=playwright.configuration.config.ts
Remove-Item Env:CONTACT_EMAIL, Env:QA_CONTACT_EXPECTED
npm.cmd run build
```

Omit `QA_CONTACT_EXPECTED` for unset, empty or malformed contact settings. Rebuild for each setting because the contact pages are static. This suite disables production demo acceptance and checks that failed requests preserve values with and without JavaScript. Never configure the synthetic test mailbox for a public deployment.

## Conventional Node deployment

```sh
npm ci
npm run build
npm run start
```

The server binds to loopback by default, suitable for a reverse proxy. For a container or host requiring another binding: `npm run start -- --hostname 0.0.0.0 --port 3000`. Use HTTPS at the proxy and configure the correct public origin/forwarded host handling for Next Server Actions. No provider-specific hosting manifest or cloud dependency is used.

Before public launch:

- Select a managed PostgreSQL provider, apply the migration with the migration role, grant the least runtime privileges, and run the real PostgreSQL integration suite against that engine.
- Approve the brand and configure a real contact address.
- **Have final privacy, personal-data disclosure and legal/authorization texts reviewed.** Current support pages are operational placeholders, not finalized legal documents. Supply actual operator details, applicable legal basis, retention and request procedures.
- Review third-party infrastructure permissions and the manual execution/stop procedure independently of this website.
- Configure invisible backend abuse prevention, operational error monitoring without form contents, and backups/retention for the selected backend.
- Review security updates, HTTPS and proxy policy on the actual host. Basic frame, content-type, referrer and permissions headers are included; tailor CSP and HSTS to the selected deployment.
