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
- `src/lib/submission-adapter.ts`: isolated submission boundary.
- `src/lib/submission-policy.ts`: explicit production demo guard.

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

**This version is a local/demo implementation. No email is sent, no request is stored, and no CRM or external recipient receives the form.** The confirmation page implements the approved future public copy; it is a demonstration of that flow, not evidence of delivery. Do not use this version to accept real inquiries.

In development, valid requests pass through a non-persistent demo adapter and redirect to confirmation. Both client and server validate the same schema; server validation is authoritative. Unknown fields are stripped, repeated known fields and file values are rejected, lengths and enum values are checked, and stale provider details are removed when protection is not in use. Form data is never put into a URL, local storage or application logs. React renders text safely without raw HTML injection.

In production, the demo adapter is **disabled by default**. A valid submission returns a clear unavailable message and retains the entered values. To preview the complete demo using a production build, explicitly set `ALLOW_DEMO_SUBMISSIONS=true` in the process environment or an ignored `.env.local`. This opt-in is for isolated preview only. Unknown `REQUEST_SUBMISSION_MODE` values always fail closed.

To connect a real backend:

1. Implement a server-only `SubmissionAdapter` with an approved email/inbox/CRM or durable database destination. Extend the result type for real receipt and select it explicitly in `submitToAdapter`.
2. Return success only after durable acceptance; map failures to the existing safe UI error. Add idempotency so retries cannot create duplicate inquiries.
3. Retain the Server Action validation and 32 KB body limit. Add invisible backend rate limiting and abuse checks at the trusted ingress/adapter boundary. Do not trust arbitrary forwarded IP headers. Use shared rate-limit storage across server instances; no permanent CAPTCHA is included.
4. Define retention, access controls and redacted operational logging. Never store credentials in source or log request bodies. Review host/proxy logging independently.
5. Keep execution entirely separate: **a form submission never starts, schedules or authorizes a test**. Final targets, exclusions, limits, conditions, schedule, stop procedure and explicit authority must be documented manually before any testing.

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

- Connect and verify a real durable submission backend; remove production demo opt-in.
- Approve the brand and configure a real contact address.
- **Have final privacy, personal-data disclosure and legal/authorization texts reviewed.** Current support pages are operational placeholders, not finalized legal documents. Supply actual operator details, applicable legal basis, retention and request procedures.
- Review third-party infrastructure permissions and the manual execution/stop procedure independently of this website.
- Configure invisible backend abuse prevention, operational error monitoring without form contents, and backups/retention for the selected backend.
- Review security updates, HTTPS and proxy policy on the actual host. Basic frame, content-type, referrer and permissions headers are included; tailor CSP and HSTS to the selected deployment.
