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

Outbox states are explicit: `pending` has never been attempted, `processing` is actively leased, `retryable` may be claimed again after a failed attempt, `sent` is delivered, and `failed` is terminal retry exhaustion requiring operational attention. Only `pending` and `retryable` rows are eligible through the future claim index. `admin_notes` and notification worker behavior are schema-only. **No email or other real notification delivery exists in Phase 1.**

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
