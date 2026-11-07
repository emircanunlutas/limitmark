# Lab environment in the existing Cloudflare account (Phase 3P.6; prepared 2026-11-07; NOTHING here has been executed)

Owner decision: the laboratory runs in the **existing** Cloudflare account and the **existing `limitmark.com` zone**, as a strictly isolated third environment named `lab`.
No second account is created. This document is the single resource manifest, permission list, DNS/route requirement list and deployment sequence for that environment.
Legend: **[OWNER]** needs the project owner's explicit approval; **[CF]** needs Cloudflare access; **[LOCAL]** workstation only, no cloud call.

Authorized in this phase: local configuration, validators, tests and documentation. **Not** authorized and not done: deploying Workers, creating R2 buckets or Durable Object namespaces,
creating Turnstile widgets, creating or rotating credentials, touching staging resources, initializing any authority, applying Terraform, changing DNS or routes, opening any production gate.

## 1. Exact lab resource names (all pinned in code; there is no wildcard or pattern acceptance)

| Kind | Lab name | Pinned in |
| --- | --- | --- |
| Admission Worker (public admission fetch + lifecycle entrypoints) | `limitmark-admission-service-lab` | `LAB_RESOURCES`, `validateLabAdmissionServiceConfig` |
| Admission Durable Object class / binding / migration | `LabAdmissionAuthority` / `AUTHORITY` / `lab-admission-v1` | same |
| Authority object name and id | `lab-public-inquiries-v1` (epoch `phase5c-i1-epoch-1`) | `LAB_ADMISSION_AUTHORITY_ID` |
| Operator executor Worker | `limitmark-authority-operator-executor-lab` (entrypoint class `LabOperatorLifecycleExecutor`, calls `LabAuthorityLifecycleOnly`) | `validateLabOperatorExecutorTemplate`, `validateRenderedLabOperatorExecutorConfig` |
| Lifecycle mailbox Worker (cron, initially no active cron) | `limitmark-lifecycle-mailbox-lab` | `validateLabLifecycleMailboxConfig` |
| DispatchGuard Durable Object class / binding / migration / object name | `LabLifecycleDispatchGuard` / `DISPATCH_GUARD` / `lab-guard-v1` / `lab-lifecycle-dispatch-v1` | same |
| Lifecycle observer Worker (optional, read-only) | `limitmark-lifecycle-observer-lab` | `validateLabLifecycleObserverConfig` |
| R2 request bucket | `limitmark-lifecycle-requests-lab` (private, 24 h object retention) | `validateLabLifecycleMailboxConfig`, transport manifest |
| R2 result bucket | `limitmark-lifecycle-results-lab` (private, 30 d object retention) | same |
| Public signer Worker (the only public Worker) | `limitmark-public-ingress-cloud-run-lab` (route `lab.limitmark.com/*`) | `public-signer.cloud-run-lab.template.jsonc` |
| Public hostname / admission hostname | `lab.limitmark.com` / `lab-admission.limitmark.com` | `LAB_RESOURCES`, gates JSON |
| Transport manifest (operator-local, git-ignored) | `deployment/lifecycle-transport.lab.json` from `lifecycle-transport.lab.template.json` | `validateLabLifecycleTransportManifest` |
| Result trust manifest (operator-local, git-ignored, single `lab` section) | `deployment/authority-result-trust.lab.json` from `authority-result-trust.lab.template.json` | `parseLabAuthorityResultTrustManifest` |

Lab keys and credentials (all distinct from every staging/production value; the secret policy forbids them in every runtime that does not need them and rejects any value shared between two of them):

| Material | Name | Lives only in |
| --- | --- | --- |
| Lab operator signing key | private: `AUTHORITY_LAB_OPERATOR_PRIVATE_KEY` (operator process only); public: `AUTHORITY_OPERATOR_PUBLIC_KEY` var of the lab admission, executor and mailbox Workers | workstation / Worker vars |
| Lab attestation key | `AUTHORITY_LAB_ATTESTATION_PRIVATE_KEY`, `_PUBLIC_KEY`, `_KEY_FINGERPRINT` | lab admission Worker secrets only |
| Admission RPC key | `ADMISSION_CURRENT_RPC_KEY` (equals GCP `limitmark-lab-admission-release-rpc-key`) | lab admission Worker secret + GCP |
| Ingress signing / identity-HMAC / origin / request-binding keys | `LAB_INGRESS_SIGNING_PRIVATE_KEY`, `LAB_INGRESS_IDENTITY_HMAC_KEY`, `LAB_PUBLIC_ORIGIN_SECRET`, GCP request-binding secret | lab signer Worker secrets, GCP |
| R2 tokens | request token: Object Write on `limitmark-lifecycle-requests-lab` only; result token: Object Read on `limitmark-lifecycle-results-lab` only | operator workstation files (outside the repo) |
| Turnstile | a new lab widget (real keys; test keys are rejected) | GCP Secret Manager (site and secret key) |

## 2. Isolation guarantees and where they are proven

| Property | Mechanism | Evidence |
| --- | --- | --- |
| Distinct identities in every layer | lab-only classes, entrypoints, Worker names, buckets, guard object, authority id; lab entry module `workers/admission-service/lab-index.ts` exports **only** lab classes | `tests/lab-environment-isolation.test.ts`, `tests/workers/lab-lifecycle-mailbox.integration.ts` |
| Validators are exact allowlists | every lab validator pins literals; Production/staging validators reject lab configs and the reverse; `lab2`, `*`, look-alike hostnames, extra bindings are rejected | isolation tests 1-4 |
| Production provisioning not implied | `lifecycle-environment-gates.json`: `production.provisioningOpen`, `staging.provisioningOpen` and `lab.provisioningOpen` all `false`; `lab.productionProvisioningImplied: false`; resource identities disjoint across environments | isolation test 4, `authority-activation-guards` |
| Lab cannot impersonate Production/staging | statements are bound to `environment: lab` and `lab-public-inquiries-v1`; separate single-section trust manifest and parser; lab key listed as the Production key is still refused | isolation tests 5-6 |
| Lab initialization cannot initialize another authority | lab command carries `confirmProduction=false` (a lab command with `true` cannot even be signed); lab id is bound both ways in the core; other authorities refuse lab commands | isolation test 7 and workerd integration |
| Lab credentials not reusable | per-environment signer bindings (a stray binding of another environment leaves an Authority without a signer); secret matrix forbids lab keys elsewhere and detects shared values | isolation tests 9-11 |
| Replay protection and initialization immutability | nonce primary key in the single lab authority DO; initialize is one-shot and permanent; guard claims are single-use | isolation tests 8, 12, 13; workerd integration |
| Control-plane failure does not disable admission | claim/consume touch only the core authority (pinned to the lab id); with the signer removed, attested reads answer `UNAVAILABLE` and admission still serves | isolation test 15; workerd integration |
| Lab rotation | not implemented (refused at the guard, executor and entrypoint), like staging | isolation test 17 |

Two defects were found and fixed while building the lab tests: (1) the data-plane core defaulted to the Production authority id, so a lab authority built without options would have
answered `unavailable` forever (fixed: the lab DO passes `expectedAuthorityId`/`expectedPolicyEpoch`; a test proves the Production-default core cannot serve lab state); (2) the previous
cloud-lab admission template bound the **Production** Durable Object class and id and was deleted in favour of `admission-service.lab.template.jsonc`.

## 3. DNS and route requirements (nothing is created or changed by this phase)

| Hostname | Cloudflare construct | Needs |
| --- | --- | --- |
| `lab.limitmark.com` | Worker **route** `lab.limitmark.com/*`, zone `limitmark.com`, on `limitmark-public-ingress-cloud-run-lab` | a proxied (orange-cloud) DNS record for `lab` that does not already exist for another purpose (a placeholder `AAAA 100::` proxied record is the usual pattern for a route-only host), `Workers Routes: Edit` on the zone |
| `lab-admission.limitmark.com` | Worker **custom domain** on `limitmark-admission-service-lab` (declared in its config as `custom_domain: true`) | Cloudflare creates the DNS record itself; **no record may already exist** for that name; `Workers Scripts: Edit` + `DNS: Edit` on the zone |

Both names are one label below the apex, so a Universal SSL certificate (`limitmark.com` plus `*.limitmark.com`), if the zone uses one, would cover them; this is unverified (see the status below). Neither name may be a wildcard route; no route is created for the
executor, mailbox or observer (they are service-binding-only, `workers_dev: false`, `preview_urls: false`).

**Status: UNVERIFIED.** The token available in this session could read Workers/R2 but was not permitted to read DNS records, so collisions with existing records for `lab` or `lab-admission`,
and the zone's Universal SSL coverage, were not checked. Before deployment run (read-only, [CF]): list DNS records for the two names in the zone and the zone's SSL/TLS certificate packs; abort if either name is in use.
The existing production Vercel/apex records and any existing Worker routes are not to be modified; confirm the planned route patterns do not overlap an existing route (a route list read is allowed).

## 4. Minimum Cloudflare permissions

Create **one dedicated, expiring API token** for the lab deployment instead of using the broad OAuth token from `wrangler login` (log out of that session when finished: `npx wrangler logout`). Permission names follow the current dashboard wording; confirm them when creating the token.

| Need | Permission | Scope |
| --- | --- | --- |
| Deploy the five lab Workers, apply DO migrations, set Worker secrets | Account: Workers Scripts - Edit | account |
| Create the two R2 buckets and set their lifecycle rules | Account: Workers R2 Storage - Edit | account (bucket-name scoped where the API allows) |
| Route `lab.limitmark.com/*` | Zone: Workers Routes - Edit | zone `limitmark.com` only |
| Custom domain for the admission Worker (creates its DNS record) | Zone: DNS - Edit | zone `limitmark.com` only |
| Read-only checks (DNS/SSL collision, resource inventory) | Zone: DNS - Read, Zone: Zone - Read, Account: Account Settings - Read | zone / account |
| Turnstile widget | Account: Turnstile - Edit (dashboard operation is also acceptable) | account |
| Operator transport credentials | two **R2 API tokens** (S3 compatible): request = Object Write on the requests bucket only; result = Object Read on the results bucket only | per bucket |

Not required, and not to be granted: any permission on existing staging or production Workers, buckets, KV, queues, Workflows, billing, members, or zone settings.

## 5. Turnstile hostname change

The earlier plan used a different public lab hostname. The lab widget must now list **exactly `lab.limitmark.com`** (no wildcard, no `localhost`, no `run.app` host), and the Cloud Run variable
`LAB_TURNSTILE_EXPECTED_HOSTNAME` must equal `lab.limitmark.com` (Terraform variable `lab_public_hostname`). Terraform variables for the lab hostnames stay unset until the owner approves apply:
`lab_public_hostname = "lab.limitmark.com"`, `lab_admission_hostname = "lab-admission.limitmark.com"`. The Turnstile secret key remains **out** of every Cloudflare Worker (policy-forbidden); it lives in GCP Secret Manager only.

## 6. Updated deployment sequence (each step is a separate approval; stop on any failure)

| # | Gate | Depends on | Public traffic? | Rollback |
| --- | --- | --- | --- | --- |
| P0 | Owner approval of this manifest; dedicated lab API token; DNS/SSL read-only checks (section 3); Turnstile widget for `lab.limitmark.com`; operator keygen | owner | no | delete token/widget/keys |
| A | GCP secrets; invoker key **not yet created** | P0 | no | disable versions |
| B | Images pushed (digests) | none | no | delete images |
| C | Terraform apply (6 resources), fails closed without Workers | A, B | no | destroy 6 resources |
| D | PostgreSQL connectivity from the Cloud Run network | C | no | delete job |
| E0 | Lab control plane: R2 buckets, `limitmark-admission-service-lab` (custom domain), executor, mailbox (cron off) -> **negative test** -> arm cron -> signed `initialize` -> **POSITIVE** result (`AUTHORITY-BOOTSTRAP.md`) | P0, A | admission custom domain only (Google-OIDC + MAC protected) | `AUTHORITY-BOOTSTRAP.md` section 4 |
| E1 | Signer Worker, invoker key creation **[OWNER]**, route `lab.limitmark.com/*` last | C, E0 | **yes, starts here** | detach route |
| F | Legitimate-user validation and failure drills | E1 | yes | detach route, revoke key |
| G | Baseline frozen for defensive testing | F | yes | n/a |

Steps that touch production resources do not exist in this sequence. Production and staging gates stay closed regardless of lab progress.

## 7. First-deployment decision

See the phase report: **GO for owner review of this manifest and the P0 read-only checks; NO-GO for any create/deploy action until P0 is approved and the section 3 DNS/SSL checks are done.**
