# Limitmark Copilot instructions

## Repository context
This repository is the Limitmark Next.js app for a Turkish resilience-testing consultancy. It includes a public landing page, a public inquiry flow, an admin inquiry workflow, and a fail-closed notification outbox. Current tracked source is intentionally conservative: configuration and deployment boundaries fail closed instead of silently falling back.

## Build, test, and lint commands
Run from the repo root.

- Install dependencies: `npm ci`
- Local app: `npm run dev`
- Lint: `npm run lint`
- Typecheck: `npm run typecheck`
- Production build: `npm run build`
- Full validation: `npm run check`
- Node tests: `npm test`
- Database integration tests: `npm run test:db`
- Required database tests: `npm run test:db:required`
- Production-style E2E: `npm run build && npx playwright test`
- Development-server E2E: `QA_DEV=true npm run test:e2e`

Important safety notes:
- `npm test` is not unit-only. It runs the repo’s Node test suite from `tests/*.test.ts` and includes runtime-gate assertions that can touch DB- and environment-sensitive code.
- `npm run test:db` may skip when `TEST_DATABASE_URL` is absent, but `npm run test:db:required` exits immediately if the variable is missing.
- `TEST_DATABASE_URL` must point only to a dedicated, disposable test database. Relevant tests may truncate tables and drop schemas; do not point them at a production or shared database.
- The default `playwright.config.ts` starts the app using `next start`, so production-style E2E requires a fresh build first: `npm run build && npx playwright test` (equivalently, `npm run build && npm run test:e2e` because `test:e2e` invokes the repository Playwright config).
- When intentionally using the development server, use `QA_DEV=true npm run test:e2e`; this selects `next dev` in the repository config.
- Do not run the default Playwright configuration as plain `npx playwright test` after application source changes without rebuilding: it can test stale `.next` output.
- Do not treat worker integrations under `tests/workers/*.integration.ts` as ordinary safe single tests. Several start a local Wrangler/workerd runtime and must only be run when explicitly authorized.

## Public inquiry flow: handler checks vs verified persistent flow
The current route at `src/app/api/public-inquiries/route.ts` intentionally wires no live ingress-policy/admission/Turnstile/repository constructors for persistent intake. This is current state: persistent intake is unavailable/503 through that route until live wiring is explicitly authorized.

Handler-level checks belong in `src/lib/public-inquiry-handler.server.ts`:
- method / path / content-type / content-encoding checks
- body-size enforcement
- demo flow checks for `REQUEST_SUBMISSION_MODE` and `ALLOW_DEMO_SUBMISSIONS`
- runtime mode and deployment-boundary checks
- origin protection and `PUBLIC_ORIGIN_PROTECTION` handling
- ingress verification call ordering
- 404/413/400/503 response behavior

The verified persistent flow is separate and ordered as:

`schema` → `tokens` → `PRE admission` → `Turnstile` → `POST admission` → `repository`

Current source flow:
- `readRequestFormData()` and `requestSchema.safeParse()` in `src/lib/request-schema.ts`
- `readSubmissionToken()` and `readTurnstileToken()` in `src/lib/submission-token.ts` and `src/lib/turnstile.ts`
- `handlePublicInquiry()` verifies the mutation ingress before calling `executeVerifiedPublicInquiry()`
- `executeVerifiedPublicInquiry()` in `src/lib/public-inquiry-flow.server.ts` performs in order:
  1. schema validation
  2. token presence checks
  3. `claimPre()` PRE admission using the verified ingress pseudonym and request binding
  4. Turnstile verification via `CloudflareTurnstileVerifier.verify()`
  5. `consumePost()` POST admission using the PRE permit and request binding
  6. repository creation via `repository.create()`

Source-confirmed invariants:
- ingress verification, origin protection, Vercel deployment-boundary checks, and `PUBLIC_ORIGIN_PROTECTION` handling belong to the handler layer; `executeVerifiedPublicInquiry()` receives already-verified ingress.
- Admission is pseudonym-based budgeting, not an identity allowlist. The pseudonym is an opaque client identifier used for PRE/POST rate limiting and must not be described as identifying a person.
- Failed verification does not refund a previously consumed PRE charge. The PRE budget is consumed on allocation; the later failure path fails closed rather than reversing the earlier budget consumption.
- Current PRE budget in `workers/admission-service/authority.ts` is:
  - per-pseudonym PRE burst: 3 accepted grants in 60 seconds
  - existing client PRE ceiling: 30 in 10 minutes
  - existing global PRE ceiling: 300 per minute

A future coding agent must not activate or wire the live persistent path without explicit authorization. The current repository state is intentionally not live.

## Worker / deployment / operator architecture
The repo includes runtime governance components under `workers/`, `deployment/`, and `operator/`.

- `workers/`: worker/service logic and the public admission authority
- `deployment/`: deployment contracts and runtime secret-policy enforcement
- `operator/`: lifecycle and operator-side control-plane artifacts

Important invariants from current source:
- `deployment/secret-policy.ts` validates runtime secrets using `deployment/secret-matrix.json` at runtime; secret-matrix changes are not static-only documentation.
- Changing runtime secret policy can change deployed behavior after deployment.
- `admissionPolicy` and `ADMISSION_POLICY_EPOCH` changes require architectural and release-governance review; they are not ordinary local edits.
- Repository configuration does not establish current provider state. The files describe allowed architecture and runtime boundaries, but they do not prove which provider resources are active right now.

## Admin authorization
The actual admin JWT verification implementation is `src/lib/cloudflare-access.ts`.

Source-confirmed fail-closed requirements:
- valid Cloudflare Access team-domain origin
- valid audience configuration
- required JWT verification and claim checks (`alg`, `kid`, `issuer`, `audience`, `exp`, `iat`, `email`, `sub`, `type`)
- exact normalized allowlisted mailbox/email authorization after verification
- malformed or duplicate allowlist configuration disables authorization

The behavior is enforced in `src/lib/admin-auth-config.ts` and `src/lib/admin-auth-core.ts`:
- `getAdminAuthConfiguration()` returns disabled on invalid team domain, invalid audience, or invalid allowlist config
- `resolveAdminFromRequest()` returns `null` on missing/invalid token or identity
- `requireAdmin()` calls `notFound()` on denial

Do not weaken these checks to repair login problems; the repo intentionally treats invalid or malformed admin configuration as denied.

## Notification / cron boundary
The repository does not configure an in-repository schedule for the notification cron route. The route exists at `src/app/api/cron/process-notifications/route.ts`, but the current source does not establish a scheduler or provider-side schedule binding for that route in-repo.

Current source confirms:
- the route checks the Vercel Production boundary and `CRON_SECRET` before invoking the outbox processor
- the outbox processor is intentionally separate from the route and can be invoked by a reviewed deployment entry point
- provider-side scheduling state is unknown unless independently established
- the real notification gate is `ENABLE_REAL_NOTIFICATIONS === "true"` as enforced by `src/lib/notification-config.ts`
- `src/lib/resend-notification-adapter.ts` does not fall back to success when configuration is invalid; it remains fail-closed

## Dangerous command boundary
Future coding agents must not run these commands without explicit authorization:

- `npm run authority:*`
- `npm run gate6:*`
- deploy/deployment scripts
- Wrangler commands
- provider-facing verification scripts
- `drizzle-kit migrate` / `db:migrate`
- commands that contact Cloudflare, Vercel, Turnstile, Resend, or GitHub

This includes `authority:staging:admission:live-verify`, which is a retired/closed entry point: it now refuses unconditionally before any Wrangler launch or provider transport, and must not be used for live verification or as a health check. The retained harness config `wrangler.staging-admission-live-readonly.local.jsonc` can still be run manually with `wrangler dev`, which uses a provider-contacting preview transport and falls under the Wrangler rule above; do not run it.

## Safe command examples
Use the supported repo scripts only when relevant and authorized:

- `npm run lint`
- `npm run typecheck`
- `npm run build`
- `npm test`
- `npm run test:db` / `npm run test:db:required`
- `npm run build && npx playwright test` for production-style E2E
- `QA_DEV=true npm run test:e2e` only when intentionally using the development server

Do not present a worker integration harness as a normal safe test. Several integrations under `tests/workers/` start a Wrangler/workerd runtime and must only be run under explicit authorization.

## Guidance to keep
- Prefer allowlists over permissive parsing. The public request schema strips unknown fields and rejects duplicate or file-valued inputs.
- Keep deployment and environment boundaries explicit. Runtime checks are intentional gates, not optional fallbacks.
- Prefer server-only validation and server-only configuration. Keep provider secrets and server-only values out of browser code and logs.
- Keep public intake, admin authorization, and notification processing isolated and independently gated.
- For schema, runtime-config, or boundary changes, review the corresponding tests and code paths that consume the same values.
- Preserve the Turkish site language and existing UX conventions when modifying forms or copy.

## Non-goals for this file
This file is not a runbook, provider-state report, or future-plan document. Keep it focused on current repository wiring, current fail-closed invariants, and the exact unsafe operations that must not be run casually.