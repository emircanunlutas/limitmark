# LimitMark — FQ1 Session Handoff

Written 2026-11-08 at the end of the "Shared Admission Reliability: Deployment Preflight" session.
Repo: `C:\Users\Emir\Desktop\pentest-website`, branch `feat/capacity-engineering`, HEAD `fbd512808a7d5194da0d79730ad05b68b85c201b`.
Lab domain: `lab.limitmark.com`. GCP project: `limitmark-field-qual`. Cloudflare account: `a779e0b2506f4ed0272e6eff7bc91449`.
Statements are labelled **[DIRECT]** (observed output/logs/DB/test result), **[INFERRED]** (control-flow reasoning), or **[UNVERIFIED]**.
Gaps in my knowledge are stated as gaps. Earlier-session details that I could not re-verify from this session's summary are marked as such.

---

## 0. Project identity and architecture

- **Objective:** LimitMark is a Customer Defense Plane: it keeps a customer's service available to legitimate users while the service is under attack or abusive load.
- **Layered defense.** Principle: **"Every layer assumes the layer before it may have failed."** No layer may trust that an upstream layer filtered anything. Fail-closed behavior is mandatory in security-critical layers.
- **Control plane vs customer defense/data plane.** The control plane is operator/admin tooling: the admin gateway, operator-signed lifecycle commands, authority initialization and rotation. The customer defense/data plane is the path that real customer traffic takes: ingress signer, admission service (PRE/POST), the app, the database. They are separate on purpose, so that a control-plane fault does not take down the data plane and a data-plane flood cannot reach control-plane authority.
- **Legitimate users must stay unaffected during attacks.** Every defense decision should be judged by what it does to legitimate-user availability. Rollback and deployment plans prioritize this.
- **Per-layer measurement.** Each layer needs its own traffic accounting, canary success metrics and recovery metrics. Without per-layer numbers you cannot say which layer failed or recovered. Most of this is not yet built/qualified for the lab flow (see Open Risks).

---

## 1. VERIFIED FACTS

### 1.1 FQ1 laboratory qualification (owner accepted functional, persistence and sequential replay as PASS)

| Item | Evidence | Class |
|---|---|---|
| Browser inquiry submission through `lab.limitmark.com` succeeded and redirected | Browser run in an earlier session, owner-observed; one submission after the final lab fix | [DIRECT] (earlier session) |
| Cloudflare signer → Cloud Run integration | Request reached Cloud Run revision `limitmark-public-inquiry-lab-00005-bz7`; submission completed | [DIRECT] (earlier session) |
| Admission PRE and POST | Lab admission Worker `limitmark-admission-service-lab` version `88b69c16-e9c0-4f54-a1c8-57b8309e599c`; `wrangler tail`-based and replay-Job evidence (PRE allowed + permit, POST allowed) | [DIRECT] |
| Turnstile verification | The inquiry flow order is: schema parse → Turnstile token required → `claimPre` → Turnstile verify (real `CloudflareTurnstileVerifier`, non-test keys) → `consumePost` → DB create. The submission succeeded, which can only happen if verify passed. There is **no direct Turnstile log line**. | [INFERRED] from control flow. Limitation: no direct evidence of the Turnstile verdict itself. |
| PostgreSQL persistence | One SELECT-only IAP-SSH session (window 2026-11-07T23:25:20Z–23:25:40Z) showed the `inquiries` row, `inquiry_events` `inquiry_received`, and `notification_outbox` row with status `pending` | [DIRECT] |
| Sequential live replay qualification | Temporary Cloud Run Job ran exactly 4 sequential requests with a fresh synthetic identity: PRE allowed → POST allowed → replayed POST = `replay` → replayed PRE = `replay`. Script: `C:\Users\Emir\AppData\Local\Temp\claude\ae48934e1bc5acfd\0bd4e6fd-b000-4312-8ede-33b45793da8c\scratchpad\replay-job.js` | [DIRECT] |
| Temporary Cloud Run Job cleanup | Job deleted after the run | [DIRECT] (earlier session) |

### 1.2 NOT tested — do not claim PASS
- Concurrency (live)
- Restart persistence (live)
- Permit expiry (live)
- Load testing
- Outbox delivery (no consumer is deployed; the outbox row stays `pending`)

### 1.3 Defects found and fixed locally (workerd-reproduced)
1. **Shared JWKS resolver "Illegal invocation".** `workers/shared/bounded-jwks.ts` stored native `fetch` as `this.request` and called it as a method, which throws in Workers. Every JWKS load failed, so every token failed closed. Fixed by calling it as a plain function (wrapper).
2. **Cached Durable Object stub.** `workers/admission-service/index.ts` kept a DO stub created in the first request inside the cached handler; later requests failed with "Cannot perform I/O on behalf of a different request" (503). Fixed by resolving the stub per call in `configure()`.
3. **Admin gateway real entrypoint.** `workers/admin-gateway/index.ts` re-exported `ADMIN_GATEWAY_HOST` and `createAdminGateway` next to the default handler. workerd rejects non-handler exports ("Incorrect type for map entry 'ADMIN_GATEWAY_HOST'"), so the real wrangler dry-run bundle could not load. My earlier test used a test-only wrapper that hid this. Fixed by exporting only the default handler.

---

## 2. COMPLETED WORK

### 2.1 Local Git history (verified with `git log` this session; all unpushed)

Branch `feat/capacity-engineering` has no `origin/feat/capacity-engineering` ref (the remote-tracking branch is unknown to this clone), so "unpushed" is established from the standing rule that nothing was pushed, not from a remote diff.

| SHA | Purpose |
|---|---|
| `4be1b10` | Lab admission Worker: plain-function `fetch` for the Google OIDC verifier; per-request DO stub in the lab handler. Adds `tests/workers/lab-jwks-fetch.integration.ts` and `tests/lab-jwks-fetch-wrapper.test.ts` |
| `653d522` | Shared fix: `BoundedRs256JwksResolver` wraps `fetch`; production/staging handler resolves the DO stub per request. Adds `tests/workers/shared-admission-reliability.integration.ts`, updates the wrapper test, `package.json` scripts |
| `e1a65ce` | Admin gateway entry exports only the default handler; integration test now runs the real `workers/admin-gateway/index.ts`; test-only wrapper `tests/workers/support/admin-gateway-entry.ts` deleted |
| `fbd5128` | Adds `tests/workers/jwks-concurrency.integration.ts` and the `test:workers:jwks-concurrency` script (also appended to `test:workers`) |

Earlier unpushed lab commits: `5cb11f3`, `7937bcc`, `573b807`, plus `a04e184` and a lab-environment commit `38fec4d` (noted in memory as unpushed; not re-checked this session).

Working tree at handoff: only `audit-report.json` and `ba0-c1-tag.bundle` are untracked. Both are preserved unchanged and must never be staged.
Commit trailer in use: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Stage by explicit path.

### 2.2 Preflight findings
- **Admin gateway:** see 1.3 item 3. After the fix, `wrangler deploy --dry-run` produces a bundle whose only export is `default`; the real entry passes the shared-reliability integration test in workerd.
- **Staging architecture** [DIRECT for deployed/observed, INFERRED for intent]: dormant (no routes, no custom domain, workers.dev off, previews off). Deployed bundle is older than the source: deployed handlers are `fetch, initializeAuthorityFromOperator, rotateAuthorityReleaseFromOperator`; source has the `...Attested` variants. `StagingAdmissionAuthority` has no `claimPre`/`consumePost`; the shared fix does not change staging behavior. Recommendation: do not deploy staging for this fix (it would ship unrelated drift).
- **JWKS concurrency (workerd, real gateway entry, `tests/workers/jwks-concurrency.integration.ts`):** all pass, no defect reproduced.
  - 6 overlapping initial requests → all 200, exactly 1 JWKS fetch; later requests reuse cache, no extra fetch.
  - Initiating client aborts mid-acquisition → concurrent request still succeeds.
  - Failed fetch → every overlapping request 403, 1 fetch; within the 30 s cooldown stays closed with no refetch; after cooldown (the test waits 31 s) recovers and caches.
  - Hanging endpoint → bounded by the 2 s timeout, all 403 in under 8 s, upstream never reached.
- **Dry-runs** (non-uploading `wrangler deploy --config <rendered> --dry-run --outdir <rel>`, synthetic values, temp files deleted):
  - Production admission: builds, 154.64 KiB; `AUTHORITY` → `ProductionAdmissionAuthority`; migration `production-v1`; route `admission-rpc.limitmark.com` custom domain; vars as in `deployment/admission-service.template.jsonc`.
  - Staging admission: builds; bindings `AUTHORITY` → `StagingAdmissionAuthority` and `AUTHORITY_OPERATOR_PUBLIC_KEY`, same as deployed `d8f0818b`. Deployed version additionally has the secret `ADMISSION_CURRENT_RPC_KEY` and older handlers.
  - Admin gateway: builds; vars `VERCEL_ADMIN_UPSTREAM_ORIGIN`, `CLOUDFLARE_ACCESS_TEAM_DOMAIN`, `CLOUDFLARE_ACCESS_AUD`, `ADMIN_ALLOWED_EMAIL`; the secret `VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET` is not part of the dry-run. Route `admin.limitmark.com/*` on zone `limitmark.com`.
  - Note: `deployment/admission-service.staging.jsonc` is a sentinel string, not a config; render from `admission-service.staging.template.jsonc`.
  - Note: the admission bundle also exports `createAdmissionService` / `createVercelOidcVerifier` (functions). These load in workerd (lab deploy and integration tests prove it); only non-function exports such as the gateway string constant broke loading.

### 2.3 Test results
- `npx tsc --noEmit`: clean.
- `npm test`: 1780 tests, 1670 pass, 15 fail, 0 cancelled.
- `npm run test:workers`: exit 0 (includes lab, shared-reliability, concurrency, R06, staging suites).
- **Baseline caveat:** the 15 failures match the earlier baseline *by count only*. Identical failing test identities have NOT been verified. Memory also notes one pre-existing cancelled/flaky resend test; the last run showed 0 cancelled.

---

## 3. CURRENT INFRASTRUCTURE STATE

### Lab (deployed)
- Admission Worker `limitmark-admission-service-lab`: version `88b69c16-e9c0-4f54-a1c8-57b8309e599c` at 100%; earlier versions `92820d04`, `4cacd0aa`. Entry: `LabAdmissionServiceWorker`; DO `LabAdmissionAuthority`.
- Cloud Run service `limitmark-public-inquiry-lab`, revision `limitmark-public-inquiry-lab-00005-bz7`, image `limitmark-app@sha256:dfaaa0cd03a5a048bd200b723dc79c89a2d81ff111a2b8868e94cc049ef3b606`.
- Database: GCE VM `limitmark-lab-postgres` (10.80.0.6, private, TLS), **not Cloud SQL**. Access: IAP SSH + OS Login.
- Lab configs: `deployment/admission-service.lab.jsonc`, `deployment/cloud-run-lab.yaml`, `deployment/public-signer.cloud-run-lab.jsonc`, Terraform in `deployment/terraform`.

### Staging (deployed, dormant)
- `limitmark-admission-service-staging`: `d8f0818b-be93-4bf1-acae-3cee943ad9f0` at 100% (source "Secret Change", 2026-09-23); previous `877ba1f2-a435-4ec7-95bc-dcf3f42d1501` (2026-09-21 upload). No routes.
- Staging mailbox `676c0935` and observer `4826b589` exist (from the Phase 1 baseline; I did not re-verify the full IDs).
- Which staging executor Worker name is the real one: **[UNVERIFIED]**.

### Production
- **Production admission Worker (`limitmark-admission-service-production`) is NOT deployed in the inspected Cloudflare account.**
- **Admin gateway Worker is NOT deployed in the inspected Cloudflare account.**
- Templates exist and are unrendered: `deployment/admission-service.template.jsonc`, `deployment/admin-gateway.template.jsonc`, plus lifecycle/executor/signer templates.

### Known configuration drift
- Staging deployed bundle vs source (handlers; secrets).
- Production/gateway: no deployed counterpart to compare.
- Templates contain `__REQUIRED_*__` placeholders that must be supplied at render time.

---

## 4. AUTHORIZATION BOUNDARIES

Source: `CLAUDE.md` plus the owner's per-phase authorizations.

**Permitted without further approval:** read-only investigation; local code inspection and corrections within explicitly authorized scope; local regression tests; non-uploading dry-runs (only with tools that cannot upload/activate); local commits; preparing deployment and rollback plans.

**Requires explicit owner approval:** live deployments or uploading Worker versions; creating/changing routes; IAM changes; provisioning/modifying secrets; creating production Durable Objects or migrations; modifying live infrastructure; production or staging synthetic traffic; load/attack tests; database mutations; git push (and any change to `master`); destructive cleanup (force push, reset, branch deletion, history rewrite); authentication/admission-protocol semantic changes; DO schema changes.

**Always:** never weaken tests or fail-closed behavior; never print secrets/tokens; never stage `audit-report.json` or `ba0-c1-tag.bundle`; preserve historical INVALID verdicts and evidence.

**Wrangler OAuth session:** the user logged in themselves (`npx wrangler login`). **Do not run `wrangler logout`.**

---

## 5. OPEN RISKS

1. **First-ever production admission deployment** — needs rendered config, operator + attestation keys, Vercel OIDC values (issuer, audience, subject, owner/project IDs), current release/key IDs, RPC key secret, DO initialization via an operator-signed command. The DO is created fresh with migration `production-v1`.
2. **First-ever admin gateway deployment** — needs Access team domain/AUD, allowed admin email, upstream origin, route on zone `limitmark.com`, and `VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET`.
3. **Rollback has no prior version** for production admission and the gateway. Rolling back must not destroy DO state: prefer detaching the route/custom domain over deleting the Worker. The owner has not yet chosen.
4. **Staging deploy drift** — a staging deploy would ship unrelated handler changes; secrets/vars required by the new bundle on staging are unchecked.
5. **Baseline test failures** — 15 failing tests; identities not diffed against the earlier baseline.
6. **Remaining FQ1 gaps** — concurrency, restart, expiry, load, outbox delivery (no consumer deployed), no direct Turnstile log.
7. **R2 least-privilege credentials** — scoped tokens still to be created; the `wrangler logout` decision rests with the owner.
8. **Invoker key rotation deadline: 2027-02-05.**
9. **Collector descriptor race** — noted in earlier sessions; not investigated this session.
10. **Cloud Run `cpu-throttling:false` cost observation** — noted, unresolved.
11. **Scratchpad logs** — one (`fix-signer.log`) may contain the user's IP; scratch dir is `C:\Users\Emir\AppData\Local\Temp\claude\ae48934e1bc5acfd\0bd4e6fd-b000-4312-8ede-33b45793da8c\scratchpad\`.
12. **First-init-command finding** from earlier sessions: details not recoverable from this session's summary.
13. **Shared in-flight JWKS `refresh` promise** — tested in workerd for overlap/abort/failure; still not exercised on a live deployment.

---

## 6. UNVERIFIED ASSUMPTIONS

- The 15 failing tests are the same tests as in the earlier baseline.
- Real staging executor Worker name.
- That the new bundle deploys to staging without extra attestation secrets/vars.
- That production Vercel OIDC values and operator keys exist anywhere outside the repo.
- That nothing else in the account (other zones/routes) conflicts with `admin.limitmark.com/*` or `admission-rpc.limitmark.com` — only inspected in Phase 1 of this session.
- Whether `origin` has the branch (no remote-tracking ref in the clone).
- Turnstile verdict (control-flow inference only).

---

## 7. NEXT RECOMMENDED ACTIONS

(Each live step needs fresh explicit owner approval.)

1. Run `npm test` and diff failing test names against the stored baseline; record the result.
2. Decide the rollback strategy for first-ever deploys (detach route/custom domain vs delete Worker) and write it into the plan.
3. Provision production inputs (owner action): operator/attestation keys, Vercel OIDC identifiers, RPC key, current release/key IDs. Render configs into a temp directory, never commit rendered values.
4. Re-run the non-uploading dry-run against the real rendered config for production admission, then the gateway.
5. With approval: deploy production admission first; verify with one PRE→POST pair and a replay; then deploy the admin gateway (expect 403 without an Access assertion).
6. Hold staging. Revisit only as a dedicated change with its own drift review.
7. Plan a controlled live test for concurrency, restart and permit expiry; design the outbox consumer before testing delivery.
8. Handle R2 least-privilege tokens, the invoker key rotation (by 2027-02-05), and the collector descriptor race.

### Useful commands
- Tests: `npx tsc --noEmit`; `npm test`; `npm run test:workers`; single suites `npm run test:workers:lab-jwks-fetch`, `…:shared-admission-reliability`, `…:jwks-concurrency`.
- Dry-run (no upload): `npx wrangler deploy --config <rendered-config> --dry-run --outdir <path-relative-to-config-dir>`.
- Read-only inspection: `npx wrangler deployments list --name <worker>`, `npx wrangler versions list --name <worker>`, `npx wrangler versions view <full-version-id> --name <worker>` (needs the full UUID).
- Scripting quirks on this machine: no `gh`, no python; heredocs with special characters break in the shell — use the Write tool or `.cjs` files; run Miniflare scripts with `timeout` and `process.exit`.
- Memory index: `C:\Users\Emir\.claude\projects\C--Users-Emir-Desktop-pentest-website\memory\MEMORY.md`.

## Update 2026-11-08 — production security corrections (local, unpushed)
Commits on feat/capacity-engineering: 1720e9f (F-1), 655d58a (production entry + Vercel contract), ba65541 (account pin / public-CA tests), 17d9218 then f91b277 (reader signed `initialized`/`coverage`, now OPT-IN via `includeSignedInitialization` because 17d9218 changed default outcomes and broke exact-shape tests), 6212ccf (tests/support/worker-bundle.ts + owner-approved exact REVIEWED_UNPROVABLE_REFERENCES entry), b3b52ab (export-signing design, Gate 9 plan, baseline v2 register refresh).
Clean-checkout `npm test` at f91b277: 1875 tests, 5 fail (pre-existing): gate6 production-ignore (639), gate8 fault-hook allowlist lab guard (721), historical-immutability (933), byte-identical baseline (1179), F4 dockerignore (1267). `npm run test:workers` exit 0.
Open owner decisions: (a) .gitignore line `deployment/lifecycle-transport.production.json` (from 1cf7b81) conflicts with gate6 test 639 and F4 1267 — satisfying both means removing the ignore line; (b) add lab-dispatch-guard.ts to the fault-hook `guardFiles` allowlist; (c) baseline v2 hash acceptance; (d) dedicated export-request key (design only).
Docs: EXPORT-REQUEST-SIGNING-DESIGN.md, GATE-9-STAGING-ROTATION-PLAN.md.

## Update 2026-11-08 (later) — regression closure and qualification-readiness
e4f8267: D1 (.gitignore line kept; exact production names added to .dockerignore and lab/linux/Dockerfile.dockerignore; Gate 6A test now asserts exact-name ignore) and D2 (lab-dispatch-guard.ts in fault-hook guardFiles). ed07dd3: BASELINE-V2-FILE-REVIEW.md (42 entries, 5 HOLD / 11 HOLD-light / 26 accept; hashes unapproved) and EXPORT-REQUEST-SIGNING-DESIGN.md v2 (design only). Next commit: INDEPENDENT-QUALIFICATION-READINESS.md.
Clean checkout at e4f8267: npm test 1876 tests, 1832 pass, 2 fail (934 historical-immutable, 1180 byte-identical baseline), exit 1; test:workers exit 0. Main tree: 10 fail = those 2 + 8 audit-package scans.

## Update 2026-11-08 (qualification-first phase)
Owner decisions: first milestone = existing independent L1/L2 only (not L1/L2/L3); Workers/Vercel admission is a separate track; P0 instrumentation approved (local, bounded); GCP europe-west3 preferred, private addresses preferred (planning only); export key: overlap <= 24 h, two keys in staging, legacy verifier stays in first commit; baseline v2 stays unapproved.
Done: outcome tally + cross-checks as NEW files under lab/defense (commits 82045e3, 3369f81); wiring into defense/plane/runtime.ts is HELD as PROPOSED-INSTRUMENTATION-WIRING.patch because defense/ trees are diffed against aff793e/baseline (any edit or new file under defense/core breaks 653 historical-immutability). Overhead: ~50-130 ns/event, end-to-end delta within noise. Docs: BASELINE-V2-ACCEPTANCE-PACKAGE.md (26/11/5), QUALIFICATION-M1-DESIGN.md, QUALIFICATION-CLOUD-PLAN.md, EXPORT-KEY-IMPLEMENTATION-PLAN.md.

## Update 2026-11-08 (M1 instrumentation + migration phase)
040292b: observational tally WIRED into defense/plane/runtime.ts (+ defense/core/outcome-counters.ts); equivalence on the real plane process (tests/defense-plane-instrumentation.test.ts), benchmark lab/defense/outcome-benchmark.ts (~48 ns/event, paired end-to-end delta ~ -0.001 ms). 7c43775: append-only versioned registry tests/support/reviewed-migrations.ts (44 entries, ALL PENDING) + classifier + tests. PROPOSED-BASELINE-MIGRATION-TEST-WIRING.patch (not applied) adds withoutReviewedChanges/assertMigrationBoundary to the three guards; measured: 44 approved => all 3 guards pass; only the 2 instrumentation entries => aff793e guard passes; 28 non-held => the 64ccc9d and dcf10af8 guards still fail on exactly the 16 held files. cc5b112/25e9649: private-target tests. 9b23a6b: M1-DECISIONS-PACKAGE.md (criteria 7-9 verbatim, N-1/N-2 analysis, revocation comparison, cloud BLOCKED status).
