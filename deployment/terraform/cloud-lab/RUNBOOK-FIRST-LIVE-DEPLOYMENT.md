# First live laboratory deployment - execution runbook (prepared 2026-11-07, Phase 3P.3; NOTHING here has been executed)

Legend: **[OWNER]** needs the project owner's explicit approval (cloud mutation, credential, billing); **[CF]** needs Cloudflare account access; **[LOCAL]** local/read-only.
Companion: `E2E-DEPLOYMENT.md` (architecture, secret classes, gates), `STAGE4-CLOUD-RUN.md` (Cloud Run plan and image commands).
Placeholders in angle brackets are supplied at run time. Never paste secret values into this repository, a chat, a ticket or a shell history; every secret is generated into a variable or a
transient file with restricted permissions and written straight to its destination.

## 0. Findings that gate the deployment

### 0.1 Replay protection (verified from code and tests)

| Question | Finding |
| --- | --- |
| Nonce generation | Signer Worker: 16 random bytes (`crypto.getRandomValues`) per POST, inside the Ed25519-signed envelope together with method, host, path, query, body SHA-256, client pseudonym and issue time. GET/HEAD carry no nonce and cannot mutate. |
| Where replay state lives | One named Durable Object (`ADMISSION_AUTHORITY_ID`), SQLite table `nonces` (nonce is PRIMARY KEY). Claims run in `transactionSync`. |
| Nonce reuse | Rejected at PRE (`replay`). The permit is bound to nonce, release, client pseudonym and request binding and is one-use at POST (`post_consumed`). |
| Across Worker instances | Yes: every isolate reaches the same single Durable Object, whose storage is the only state. `tests/replay-protection-chain.test.ts` models this with a fresh authority object per call over shared storage. |
| Expiry / skew | Envelope accepted for 30 s after issue and 5 s into the future (`INGRESS_MAX_AGE_MS`, `INGRESS_FUTURE_SKEW_MS`); nonces are retained 120 s, longer than the freshness window, so a pruned nonce is always already stale. The authority also refuses a clock that moves backwards (`last_now_ms`). |
| Reuse across route/origin/body | Not possible: path, query, host, forwarded host, method, content type/length and body digest are all verified against the signed payload. |
| Replay-state failure | Admission client maps every error, timeout (2 s), non-2xx or malformed answer to `unavailable`; the flow stops before Turnstile credit, POST and the repository. Consuming calls are never retried. A lost PRE response burns that nonce (fail closed); the visitor's retry gets a fresh envelope. |

**Cryptographic binding is not replay prevention.** The verifier is stateless: an identical copy of a valid request verifies every time (asserted in the test). One-time use is provided only by the
authority's nonce table. No defect was found; no code change was needed. Claim limit: this is proven for the code paths and a simulated Durable Object (Node SQLite) - not yet against a deployed
Cloudflare Durable Object, which gate F exercises.

### 0.2 Admission authority initialization - resolved by the existing reviewed chain (3P.4)

The authority answers `unavailable` until an operator-signed `initialize` is applied. The reviewed path (R2 request bucket -> cron mailbox with one-shot DispatchGuard -> operator executor -> admission Worker, with an
Authority attestation signer) is **mandatory** and is specified, with its dependency graph, trust-chain test results, key generation, delivery, verification and partial-failure recovery, in `AUTHORITY-BOOTSTRAP.md`.
Since 3P.6 the lab is an isolated `lab` environment inside the **existing** Cloudflare account and `limitmark.com` zone (owner decision; no second account): every Worker, Durable Object class, bucket, key and authority id has a lab-only name pinned by lab validators, and Production and staging stay closed. The exact manifest, permissions, DNS/route requirements and sequence are in `LAB-ENVIRONMENT.md`. Decisions that remain with the project owner: approval of that manifest and of each Cloudflare creation step.

### 0.3 Ordered gate overview (no circular dependencies)

| # | Gate | Depends on | Public traffic possible? | Rollback boundary |
| --- | --- | --- | --- | --- |
| P0 | Lab environment manifest approval (`LAB-ENVIRONMENT.md`), dedicated lab API token, DNS/SSL read-only checks, Turnstile widget for `lab.limitmark.com`, operator workstation + keygen | owner | no | delete token/widget/keys |
| A | GCP secrets (11) | P0 | no | disable versions, delete key |
| B | Images pushed (digests) | none | no | delete images |
| C | Cloud Run applied (6 resources); fails closed (404/503/ingress 4xx) without Workers | A, B | no (IAM-protected) | destroy 6 resources |
| D | PostgreSQL connectivity from the Cloud Run network | C | no | delete job |
| E0 | **Control plane + authority initialization** (R2, admission, executor, mailbox; POSITIVE signed result) | P0, A (RPC key shared) | no (no public route) | AUTHORITY-BOOTSTRAP section 4 |
| E1 | Invoker key created (just before use), signer Worker deployed, route attached last | C, E0 | **yes, starts here** | detach route |
| F | Legitimate-user validation + failure drills | E1 | yes | detach route, revoke key |
| G | Baseline frozen for defensive testing | F | yes | n/a |

Infrastructure prerequisites (gates A-D) need no Cloudflare Workers. Prerequisites for accepting public traffic: C, D, E0 (POSITIVE), E1, and a real Turnstile widget. Cloud Run does not need the admission Worker to become Ready, so there is no cycle.

## 1. Pre-flight [LOCAL], repeatable and read-only

```powershell
git rev-parse --short HEAD                           # expect this runbook's commit descendant of 0a7e854
git status --short                                   # only audit-report.json and ba0-c1-tag.bundle untracked
npx tsx --conditions=react-server --test tests/cloud-lab-*.test.ts tests/replay-protection-chain.test.ts tests/lab-e2e-baseline.test.ts
terraform fmt -check -recursive ; terraform validate
gcloud projects get-iam-policy limitmark-field-qual --format=json   # no run.invoker / token-creator / allUsers bindings
```

Observed on 2026-11-07 (read-only): no project-level `roles/run.invoker`, `serviceAccountUser`, token-creator or `allUsers` binding; the invoker SA has **no user-managed keys**; its only IAM binding is the self
`roles/iam.serviceAccountOpenIdTokenCreator`; effective `iam.disableServiceAccountKeyCreation` is not enforced (`booleanPolicy: {}`), so key creation would be allowed; 2 of 11 secrets have a version
(`database-url`, `database-ca-cert`).

## 2. Step 1 - Real Turnstile widget [CF] [OWNER for account access]

1. Cloudflare dashboard -> **Turnstile** -> **Add widget** (account-level, not tied to a Worker).
2. Name `limitmark-lab`. **Hostname management:** add exactly `lab.limitmark.com` (the value of `lab_public_hostname`; no wildcard, no `localhost`, no `run.app` host, not any earlier lab hostname). The app additionally checks the
   `hostname` field of the verification response against `LAB_TURNSTILE_EXPECTED_HOSTNAME`.
3. Widget mode: Managed (default). Pre-clearance off.
4. Copy the **site key** (public) and **secret key** (shown once). Never use Cloudflare's published dummy test keys: `createLaboratoryRuntimeDependencies` rejects the known ones.
5. Destinations:
   | Value | Google Secret Manager | Cloudflare Worker secret |
   | --- | --- | --- |
   | Site key | `limitmark-lab-turnstile-site-key` (rendered into the page by the app) | none |
   | Secret key | `limitmark-lab-turnstile-secret-key` (the app calls Siteverify) | **none** - the admission Worker's secret policy forbids `TURNSTILE_SECRET_KEY`, and the signer never verifies Turnstile |
6. Write straight from the clipboard/prompt, no echo, no file:
   ```powershell
   $s = Read-Host -AsSecureString "Turnstile secret"            # paste; nothing is echoed
   $plain = [System.Net.NetworkCredential]::new("", $s).Password
   $plain | gcloud secrets versions add limitmark-lab-turnstile-secret-key --data-file=- ; Remove-Variable plain, s
   ```
   Repeat for the site key. (Needs **[OWNER]** approval: creates Secret Manager versions.)
7. Validation without exposing the value: (a) `gcloud secrets versions list` shows one enabled version per secret; (b) after Cloud Run exists, a legitimate browser load of `/test-talep-et` shows the widget and a real
   solve results in `verified` (gate F); (c) optional Siteverify probe with an invalid response must answer `invalid-input-response` (secret accepted) not `invalid-input-secret`.
8. Leak hygiene: no key in Git (`git grep` for the first 8 characters before every commit), in shell history (use `Read-Host`), in logs or in screenshots (log redaction of these values was not audited).

## 3. Step 2 - Generate remaining secrets [LOCAL generate, OWNER approval to write]

Values are created in memory and piped to Secret Manager; formats from `STAGE4-CLOUD-RUN.md`. For secrets shared with a Worker, write the **same variable** to both destinations in one session, then clear it.

```powershell
function New-B64Url32 { $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Fill($b); [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') }
$origin = New-B64Url32; $origin | gcloud secrets versions add limitmark-lab-public-origin-secret --data-file=-
$origin | npx wrangler secret put LAB_PUBLIC_ORIGIN_SECRET --name limitmark-public-ingress-cloud-run-lab ; Remove-Variable origin
# Same pattern: limitmark-lab-ingress-request-binding-key (app only); limitmark-lab-admission-release-rpc-key <-> admission Worker ADMISSION_CURRENT_RPC_KEY.
# LAB_INGRESS_IDENTITY_HMAC_KEY (signer Worker only) is an independent value; the signer refuses equal signing/HMAC/origin secrets.
# Choose and record (not secret): admission release key id [A-Za-z0-9_-]{1,64}; ingress audience [A-Za-z0-9_.:-]{1,128}. Release id = lab_deployment_id.
gcloud secrets versions add limitmark-lab-otel-collector-config --data-file=deployment/otel-collector.cloud-run-lab.yaml
```

Signer key pair (Ed25519): generate with WebCrypto/Node into memory, write PKCS#8 base64url to `LAB_INGRESS_SIGNING_PRIVATE_KEY` (Worker secret only), and put the public key in the rollout JSON stored as
`limitmark-lab-ingress-public-keys` (`deployment/ingress-signing-key-rollout.template.json` shape; `activatesAtMs` in the past, validated both at instance start and per request).
Verification: each secret shows exactly one enabled version; `wrangler secret list` shows names only.

## 4. Step 3 - Laboratory invoker credential [OWNER]

Preconditions verified read-only (section 1). Create the key only at gate E1, after E0 is POSITIVE and Cloud Run is applied, in one uninterrupted sitting with the signer Worker deployment that receives it.

1. Create into a dedicated directory only the current user can read, on an encrypted volume (BitLocker/DPAPI-protected profile):
   ```powershell
   $dir = Join-Path $env:LOCALAPPDATA "limitmark-keytmp"; New-Item -ItemType Directory $dir | Out-Null; icacls $dir /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
   gcloud iam service-accounts keys create "$dir\k.json" --iam-account=limitmark-lab-invoker@limitmark-field-qual.iam.gserviceaccount.com
   ```
2. Transfer directly into the Worker secret store; never into Secret Manager, Terraform, a variable that is printed, or Git:
   ```powershell
   Get-Content -Raw "$dir\k.json" | npx wrangler secret put LAB_GOOGLE_SERVICE_ACCOUNT_CREDENTIALS --name limitmark-public-ingress-cloud-run-lab
   ```
3. Remove the copy at once: overwrite then delete (`Set-Content "$dir\k.json" ([string]::new('0', 4096))`, `Remove-Item -Recurse -Force $dir`). SSD wear-levelling means overwrite is best-effort; the encrypted
   volume and the short lifetime are the real controls. Record only the **key ID** (`gcloud iam service-accounts keys list --iam-account=... --managed-by=user`).
4. Verify: `keys list` shows exactly one user-managed key; `git status` is clean of `*.json`; the signer returns 503 (not 200) until this secret exists (already unit-tested).

**This key is not harmless.** Anyone holding it can mint Google ID tokens for the invoker and so pass Cloud Run IAM; the signed-envelope, origin-secret and request-binding layers are what stop them from
submitting, and those layers are separate secrets in different stores. Treat a leaked key as an IAM-layer compromise: a loss of defence in depth, with the remaining layers still required to hold.

Rotation (every 90 days, or at once on suspicion): create key 2 -> `wrangler secret put` -> run the signer-path check (`E2E` homepage + one submission) -> `gcloud iam service-accounts keys delete <key1-id>` ->
confirm `keys list` shows one key.
Revocation: `gcloud iam service-accounts keys delete <id>` (immediate for new token exchanges; already-issued ID tokens live up to 1 h) and, if needed, `gcloud iam service-accounts disable <sa>` or remove the service-scoped
`run.invoker` binding (Terraform). Detect: Cloud Audit Logs `GenerateIdToken` / `ServiceAccountKey` events for the invoker.
Recovery drill (run once after gate F, as part of acceptance): perform the rotation above end to end and measure the interval during which legitimate submissions fail (expected: zero or one failed request); then
assert the disabled-SA behaviour (`disable` -> signer returns 503 on the next token refresh, no unauthenticated forwarding -> `enable`).

## 5. Step 4 - Immutable images [OWNER: pushes to Artifact Registry]

Commands in `STAGE4-CLOUD-RUN.md` ("Images"). Gate: both digests recorded; `terraform plan` accepts them (variable validation requires `@sha256:<64 hex>` from the project's `limitmark` repository).

## 6. Step 5 - Cloud Run [OWNER: apply]

Fresh plan (2026-11-07, current remote state, placeholder digests only for planning): **6 to add, 0 to change, 0 to destroy** - `google_cloud_run_v2_service.lab`, `..._service_iam_member.invoker`,
`google_project_iam_member.app_metric_writer`, and the services `run`, `monitoring`, `logging`. No existing resource is touched. Recheck with real digests immediately before apply and abort on any other count.

Verified in configuration and tests: digest-pinned images only; dedicated `limitmark-lab-app` identity (no `allUsers`); IAM-protected origin (`run.invoker` only for the invoker SA, service scope); Direct VPC egress
`PRIVATE_RANGES_ONLY` to `limitmark-lab-subnet`; PostgreSQL pinned CA + `rejectUnauthorized` + server name = URL host; collector config from Secret Manager; app requires `PUBLIC_ORIGIN_PROTECTION=required` and
returns 404/503 for missing runtime configuration; no health probe masks fail-closed states. Residual note: `ingress = ALL` is needed because Cloudflare reaches the `run.app` URL; bypass resistance rests on IAM plus
the application gates, not on network reachability.

Cold start (expected, measure at gate D): the ~1.1 GB application image is pulled on every new instance; Direct VPC egress attaches on the first request; the collector is NOT a startup dependency (no `depends_on`/probe: the loopback-only OTLP receiver cannot be reached by a platform startup probe, and application availability must not depend on telemetry; decision 2026-11-07), the app's TCP startup
probe passes as soon as Next listens (~150 ms after process start), and the first PostgreSQL connection pays TLS and a 5 s `connect_timeout` ceiling. Min instances is 0, so the first request after idle may take several seconds and
the signer may see a slow origin; the request timeout is 30 s and per-instance concurrency 2 (max 2 instances = at most 4 in-flight requests). Risk: 512 Mi for the Next server plus pool of 5 connections is untested under load -
watch container memory in the baseline and raise limits before defensive testing if utilisation exceeds ~70 %. Request-based CPU lets the collector stall between requests; metric gaps are not loss.

Apply order: secrets exist (section 3) -> `terraform apply` -> `gcloud run services describe` (Ready, digest, SA, ingress, VPC) -> unauthenticated request must be 403. An authenticated check from the operator workstation is deliberately not provided (it would need token-creator rights on the invoker that are intentionally not granted), so the IAM-authenticated path is first proven by the signer at Step 8.
Rollback: `terraform destroy -target` the six resources, or remove the service-scoped invoker binding to cut off all callers immediately.

## 7. Step 6 - Private PostgreSQL connectivity [OWNER: a Cloud Run job is a new resource]

Preferred: a one-off Cloud Run **job** from the same image, SA and VPC running a read of `select 1` over the pinned-CA client, then deleted. Alternative: the first real submission at gate F with the application's
`db_insert` outcome as evidence. Pass: TLS verified connection to `10.80.0.6:5432`, INSERT succeeds, UPDATE/DELETE denied. Rollback: delete the job.

## 8. Step 7 - Cloudflare control plane (E0) then signer (E1) [CF] [OWNER]

**E0** - follow `AUTHORITY-BOOTSTRAP.md` sections 3.1-3.8 end to end. Gate: `authority:result --kind lifecycle` returns **POSITIVE**, and the negative (unauthorized-command) test was run first. Do not continue otherwise.

**E1** - signer Worker (the only public Worker):
1. Render `public-signer.cloud-run-lab.template.jsonc` (public hostname `lab.limitmark.com`, audience, deployment id, signing key id; Worker **custom domain** `lab.limitmark.com`: the available OAuth token cannot create DNS records or read zones, so a zone route cannot be used). Secrets via `wrangler secret put`: `LAB_INGRESS_SIGNING_PRIVATE_KEY`, `LAB_INGRESS_IDENTITY_HMAC_KEY`, `LAB_PUBLIC_ORIGIN_SECRET`, `LAB_GOOGLE_SERVICE_ACCOUNT_CREDENTIALS` (the key from Step 3, piped directly).
2. `wrangler deploy --dry-run`, deploy, then attach the route `LAB_PUBLIC_HOSTNAME/*` last. Before the route exists the hostname must return the Cloudflare default response, never the origin.
Rollback: `wrangler rollback` or detach the route.

## 9. Step 8 - End-to-end functional validation

Automated baseline: `deployment/lab-e2e/legitimate-user-baseline.mjs` (homepage, assets, navigation, invalid and valid submission, duplicate) with success rate, p50/p95/p99, status histogram and
unexpected challenge/block detection; unit-tested in `tests/lab-e2e-baseline.test.ts`. Valid submissions need one **real, single-use Turnstile response token** per submission (supplied via
`LAB_E2E_TURNSTILE_TOKENS_FILE`; real tokens come from the widget in a browser - they cannot be fabricated, and a script cannot solve the challenge). Reconcile created submission tokens against PostgreSQL as the migration role.

Failure and recovery scenarios are performed by the operator, each followed by `--expect degraded` then `--expect healthy`:
| Scenario | Induce [OWNER] | Expected | Recover |
| --- | --- | --- | --- |
| Cloud Run failure | set max instances 0 or revoke the service-scoped invoker binding | signer 5xx/503, no row, no bypass | restore binding/scale |
| PostgreSQL failure | stop the VM (`gcloud compute instances stop limitmark-lab-postgres`) | valid submission answers "iletilemedi", no partial state; static pages still 200 | start VM; confirm the certificate/IP unchanged; re-run |
| Admission failure | `wrangler rollback`/disable the admission route | PRE `unavailable` -> generic unavailable, no row | redeploy |
Acceptance: all healthy runs 100 % success for static and valid scenarios, zero unexpected challenge/blocks, discrepancy counters (`E2E-DEPLOYMENT.md` section 6) reconcile; degraded runs fail closed with no row.

## 10. Step 9 - Rollback and credential revocation, in this order

1. Cut ingress: remove the signer route (public traffic stops).
2. Revoke the invoker key (`keys delete`), then remove the service-scoped `run.invoker` binding.
3. `terraform destroy -target` the Cloud Run service and its IAM; leave PostgreSQL and state intact.
4. Disable Secret Manager versions of the shared secrets; delete Worker secrets; delete the Turnstile widget if abandoning the lab.
5. Stop the PostgreSQL VM if idle (cost). Evidence under `docs`/audit artifacts is never modified.

## 11. Approval index

| Action | Owner approval | Cloudflare access |
| --- | --- | --- |
| Secret Manager versions (11 secrets) | yes | no |
| Invoker SA key creation and rotation | yes | no |
| Image push to Artifact Registry | yes | no |
| `terraform apply` (6 resources) and Cloud Run job | yes | no |
| Lab environment manifest approval and dedicated lab API token; Turnstile widget | yes | yes |
| R2 buckets and two scoped R2 tokens; admission, executor, mailbox Workers and their secrets (E0) | yes | yes |
| Operator keygen, signed initialization command and its submission | yes (operator key custody) | R2 write token |
| Signer Worker, its secrets and public route (E1) | yes | yes |
| Stop/start PostgreSQL, scale/revoke for failure drills | yes | no |
