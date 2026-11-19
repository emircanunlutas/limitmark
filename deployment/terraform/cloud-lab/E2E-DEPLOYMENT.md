# End-to-end deployment (prepared 2026-11-07, Phase 3P.2; NOTHING here has been executed)

Path: legitimate client -> Cloudflare admission (signer Worker, Turnstile, admission Worker) -> IAM-authenticated Cloud Run -> PostgreSQL (`10.80.0.6:5432`, strict TLS).
Every layer assumes the previous one failed: Cloud Run refuses callers without a Google ID token (IAM), the app independently verifies the signed ingress
envelope, origin secret and request binding, and PostgreSQL accepts only TLS from the lab subnet with an INSERT-only role.

> **Correction (3P.3):** the gate table below omits the admission authority initialization (operator-signed command; the Durable Object answers `unavailable` until initialized). It is gate E0, specified in `AUTHORITY-BOOTSTRAP.md` and ordered in `RUNBOOK-FIRST-LIVE-DEPLOYMENT.md` section 0.3. Replay protection itself is verified there.

## 1. Cloudflare-to-Google authentication decision

| Option | Verified? | Verdict |
| --- | --- | --- |
| A. SA JSON key for `limitmark-lab-invoker` (as implemented in `workers/ingress-signer/google-id-token.ts`) | Code reviewed and unit-tested (`google-id-token-provider.test.ts`): RS256 assertion -> `oauth2.googleapis.com/token` -> IAM Credentials `generateIdToken`; token claims (aud/exp/iat) checked, cached, single-flight. | **Use for the laboratory, under the controls below.** Works today with no extra Google resources. |
| B. Workload Identity Federation with a self-issued OIDC JWT | Partially: WIF accepts external OIDC providers with an uploaded JWKS (RS256/ES256, `aud` = provider URL, `exp-iat` <= 24 h, `google.subject` mapping, `roles/iam.workloadIdentityUser`, 1 h access token). **Not verified:** that a federated token may call `generateIdToken` (the docs fetched are silent), the contents of `workloadIdentityUser`, and there is no native Cloudflare Worker OIDC issuer, so the Worker would hold its own long-lived signing key anyway. | **Do not rely on it.** It only moves the long-lived secret from a Google key to a self-issued signing key, and the ID-token step is unproven. Revisit after a throwaway test in a scratch project proves the full chain. |
| C. Eliminate the Google credential (unauthenticated Cloud Run + origin secret only) | n/a | Rejected: removes the IAM layer and violates layer independence. |

No service-account key has been created. Creating it requires explicit approval (CLAUDE.md: credentials).

### Controls if the key is created (Option A)

- **Minimum permissions:** the invoker SA holds only `roles/run.invoker` on the single Cloud Run service and `roles/iam.serviceAccountOpenIdTokenCreator` on itself.
  It cannot mint access tokens, sign blobs, impersonate others, or read Secret Manager, and has no project role (enforced by `tests/cloud-lab-infrastructure.test.ts`).
- **Creation/storage:** create once with `gcloud iam service-accounts keys create` into a transient `0600` file, pipe it straight into `wrangler secret put
  LAB_GOOGLE_SERVICE_ACCOUNT_CREDENTIALS`, then securely delete the file. Never commit, print, or put it in Terraform/state/CI logs. The only copy lives in the Worker secret store.
- **Rotation:** at most every 90 days (and on any suspected exposure): create key 2, `wrangler secret put`, verify the E2E signer path (gate F), then delete key 1. Limit to 2 keys per SA.
- **Revocation / exposure consequence:** `gcloud iam service-accounts keys delete <id>` (or disable the SA) takes effect within minutes. An attacker holding the key can obtain ID tokens
  that pass Cloud Run IAM but still **cannot** pass the application: they lack the Ed25519 ingress signing key, the origin secret and the request-binding key, so IAM bypass alone yields
  only 4xx ingress rejections (check 1 in `STAGE4-CLOUD-RUN.md`). Impact is bounded to invoking the one service.
- **Detection/recovery:** Cloud Audit Logs record `GenerateIdToken` and key use per SA; alert on invoker-SA activity from outside Cloudflare expectations. Recovery: delete the key, create a new one, redeploy the Worker secret.
- Organisation policy `iam.disableServiceAccountKeyCreation` may block this; if so, report it, do not disable the policy without approval.

## 2. Secrets: the nine missing versions

| Secret | Class | How |
| --- | --- | --- |
| `limitmark-lab-public-origin-secret` | Independently generable | 32 random bytes, base64url; same value set as Worker `LAB_PUBLIC_ORIGIN_SECRET` |
| `limitmark-lab-ingress-request-binding-key` | Independently generable | 32 random bytes, base64url; app only |
| `limitmark-lab-admission-release-rpc-key` | Independently generable | 32 random bytes, base64url; also Worker `ADMISSION_CURRENT_RPC_KEY` |
| `limitmark-lab-admission-release-key-id` | Independently generable | choose `[A-Za-z0-9_-]{1,64}`; also Worker `ADMISSION_CURRENT_KEY_ID` |
| `limitmark-lab-ingress-audience` | Independently generable | choose `[A-Za-z0-9_.:-]{1,128}`; also Worker `LAB_INGRESS_AUDIENCE` |
| `limitmark-lab-otel-collector-config` | From repository | `deployment/otel-collector.cloud-run-lab.yaml` |
| `limitmark-lab-ingress-public-keys` | Needs Ed25519 signer key pair | generate pair locally, private half -> Worker `signing key` secret, public half -> rollout JSON (`deployment/ingress-signing-key-rollout.template.json`), time-windowed |
| `limitmark-lab-turnstile-site-key`, `-secret-key` | **Needs real Cloudflare configuration** | create a Turnstile widget in the Cloudflare dashboard (runtime rejects test keys); cannot be fabricated |

Plus Worker-only values: `LAB_GOOGLE_SERVICE_ACCOUNT_CREDENTIALS` (Google identity, section 1), identity HMAC key (independent random, must differ from the other two secrets - the signer enforces distinctness).
Replaceable/eliminable: none safely. Nothing here may be substituted with a placeholder; the app and Workers fail closed (503) on any missing or malformed value.
Verification per secret: `gcloud secrets versions list` shows an enabled version; length/format checked at generation time without printing; the real proof is gate C/F.

## 3. Review findings (local, read-only)

- **Signer Worker** (`signer.ts`): strips inbound auth/forwarding/Vercel headers; rejects non-HTTPS, unknown hosts, `cf-worker` loops, wrong content-type/encoding, length mismatch; binds method, host, path, query,
  body SHA-256, client pseudonym and a 16-byte random nonce into an Ed25519 envelope; sets origin secret and `x-serverless-authorization`; hard-pins the target origin; scrubs secrets from responses; returns 503 on any error.
- **App verification** (`ingress-verifier.server.ts`): checks signature against the active-window public keys, environment/audience/deployment id, freshness, method, scheme, host/forwarded-host, path, query, content headers, body length and digest, then derives the request binding HMAC.
- **Replay/admission:** replay protection is the nonce + admission Worker (release-keyed, `google-lab` identity mode validating the Google OIDC token of the app SA, `GOOGLE_SERVICE_ACCOUNT_SUBJECT` = unique ID `112648989669419541876`).
- **Local tests passing:** 83 tests (cloud-lab suites, Google ID-token provider, laboratory identity, ingress protocol/verifier, signer Worker, admission auth, front ingress).
- **Origin bypass:** the `run.app` URL is public DNS but requires a Google ID token; with a leaked token the origin secret, signed envelope and request binding still block it. Ingress `all` is therefore acceptable; tighten to `internal-and-cloud-load-balancing` only if a load balancer is introduced.
- **Upstream failure:** Cloud Run down -> signer fetch error -> 503; admission Worker down -> app returns the generic unavailable state and does not persist; DB down -> generic failure, no partial success. Not yet exercised live (gate F).
- **Not run locally:** a live Cloudflare/Google round trip (needs real credentials), `wrangler` dry-run of Worker bundles (not part of this phase).

## 4. Deployment sequence with gates and rollbacks

| Gate | Action | Verify | Rollback |
| --- | --- | --- | --- |
| A | Provision genuine secrets: generate section 2 values; Turnstile widget; signer key pair; (approved) invoker key | each Secret Manager secret has one enabled version; Worker secrets listed by name only | disable secret versions; delete invoker key; delete widget |
| B | Build and push app and collector images (digest-pinned, see `STAGE4-CLOUD-RUN.md`) | `gcloud artifacts docker images describe` returns digests; fill `cloud_run_image`, `otel_collector_image` | delete image tags/digests |
| C | `terraform apply` the 6-resource plan against remote state (needs approval); service agent exists first | revision Ready; unauthenticated request -> 403; IAM-authenticated POST without envelope -> ingress 4xx (not 503) | `terraform destroy -target` the 6 resources, or set ingress/invoker off by removing the invoker binding |
| D | One-off Cloud Run job from same image/SA/VPC (needs approval) or first real submission | strict-TLS connect to `10.80.0.6:5432`; INSERT works, UPDATE/DELETE denied | delete job; DB unchanged |
| E | Deploy the lab admission Worker (`deployment/admission-service.lab.template.jsonc`) and signer Worker (`deployment/public-signer.cloud-run-lab.template.jsonc`) with Gate-A values (needs approval) | `wrangler deploy --dry-run` clean; admission health; signer returns 503 only when a secret is missing | `wrangler rollback`/delete Workers; route detach |
| F | Legitimate-user E2E (section 5) | all checks pass, counters reconcile (section 6) | revert Worker route; Cloud Run to 0 instances |
| G | Baseline for controlled defense testing: record latency/success under legitimate load, freeze versions and digests | baseline stored with commit SHA, digests, key ids | none (read-only) |

A healthy revision alone is not sufficient for F or G.

## 5. E2E validation

A synthetic legitimate-user monitor (separate from Cloud Run's own readiness) runs through the public hostname: (1) GET page, (2) GET static assets (200, content-type, cache headers),
(3) valid submission with a real Turnstile token -> 2xx and exactly one `inquiries` row (read via migrator role, never the runtime role), (4) invalid submission (bad payload) -> 4xx and no row,
(5) duplicate submission with the same token/fingerprint -> idempotent single row, (6) injected failures: missing Turnstile token, replayed envelope, stale timestamp, DB unreachable -> generic fail-closed responses without leakage,
(7) direct `run.app` request without ID token -> 403; with a token but no envelope -> 4xx.

## 6. Observability (bounded cardinality)

Counters with only low-cardinality labels (`outcome` enum, `stage` enum, status class; no IP, nonce, token, path or per-user labels):
`cf_requests` (Cloudflare analytics / Worker logs), `admission_rejected{reason}`, `forwarded_to_run` (signer), `run_requests{status_class}` (Cloud Run metrics), `app_accepted`, `db_insert{ok|fail}`.
Reconciliation: `received = admission_rejected + forwarded + signer_errors`; `forwarded = run_received (+ transport losses)`; `app_accepted = db_insert_ok`; any nonzero residual is an *unexplained discrepancy* and is investigated before baseline (gate G).
Cloud Run uses request-based CPU, so collector export may lag between requests; do not read a short gap as loss.

## 7. Cost (lab, approximate; confirm in billing)

Cloud Run min 0: ~0 idle, pay per request/CPU-second while active; PostgreSQL VM `e2-standard-2` + 20 GB pd-balanced runs continuously (largest line item, roughly USD 55-65/month); Artifact Registry and Secret Manager are cents; Cloud NAT already exists;
Cloudflare Workers free/paid tier per plan. Budget alert (TRY 3,000) notifies but does not cap. Stop the VM or destroy the stack when idle.
