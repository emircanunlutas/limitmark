# Admission authority bootstrap (Phase 3P.4; prepared 2026-11-07, NOTHING here has been executed)

Uses the existing reviewed operator-signed chain. There is no lab-only bypass and no code change to any protected mechanism.
Legend: **[OWNER]** approval needed; **[CF]** Cloudflare account access; **[LOCAL]** workstation only.

## 1. Why this is needed, and the exact dependency graph

The Durable Object `AUTHORITY` answers `unavailable` until an operator-signed `initialize` command has been applied. The only reviewed way to apply it:

```
operator workstation                                   Cloudflare account (dedicated to the lab)
 [LOCAL] lab-authority-keygen  -> operator private key (never leaves the workstation)
 [LOCAL] authority:init:prepare -> sealed {command, signature} (<= 4096 bytes, valid 5 minutes)
 [LOCAL] authority-submit initialize -- S3 PUT, request-bucket credential -->  R2 REQUEST_BUCKET  initialize.json
                                                                                  | polled by cron (every minute)
                                                                      lifecycle MAILBOX Worker  (+ DispatchGuard Durable Object: one-shot claim ledger)
                                                                                  | service binding (private RPC, no public route)
                                                                      OPERATOR EXECUTOR Worker  (pins operator public key, env "production")
                                                                                  | service binding, entrypoint AuthorityLifecycleOnly
                                                                      ADMISSION Worker  -> AUTHORITY Durable Object
                                                                         verifies Ed25519 operator signature + freshness + environment/authority pins,
                                                                         applies initialization in one transaction, signs a receipt with the ATTESTATION key
 [LOCAL] authority-submit read-result  <-- S3 GET, result-bucket credential --  R2 RESULT_BUCKET   lifecycle/<digest>.json (Authority-signed, verified against authority-result-trust.json)
```

### Mandatory vs optional

| Component | Needed to initialize? | Why |
| --- | --- | --- |
| Admission Worker + `AUTHORITY` DO, `ADMISSION_CURRENT_RPC_KEY`, `AUTHORITY_OPERATOR_PUBLIC_KEY` | **yes** | it is the authority |
| Attestation signer: `AUTHORITY_ATTESTATION_PRIVATE_KEY`, `_PUBLIC_KEY`, `_KEY_FINGERPRINT` (Worker secrets) | **yes** | a signer-less authority answers `UNAVAILABLE` before touching storage (tested); no initialization can commit without producing signed evidence |
| Operator executor Worker | **yes** | only holder of the `AuthorityLifecycleOnly` binding; no public route |
| Lifecycle mailbox Worker + DispatchGuard DO (cron) | **yes** | the only reviewed caller of the executor; the guard makes each command digest single-use |
| R2 `REQUEST_BUCKET` and `RESULT_BUCKET` | **yes** | the operator-to-mailbox transport |
| Two scoped R2 API tokens (request: write; result: read) | **yes** | operator-side transport credentials |
| `deployment/lifecycle-transport.production.json` (account id, buckets, operator public key) | **yes** | `authority-submit` target; contains no secret |
| `deployment/authority-result-trust.json` (public attestation key + fingerprint) | for verifying the result | needed to accept a POSITIVE result; does not affect the authority |
| Lifecycle observer Worker | **no** | optional read-only monitoring |
| Queues, Workflows, browser, staging variants | **no** | forbidden by `secret-matrix.json` or unused |

Pinned names (validators in `deployment/operator-executor-contract.ts`, `lifecycle-private-contract.ts` accept only these): Workers `limitmark-admission-service-production`,
`limitmark-authority-operator-executor-production`, `limitmark-lifecycle-mailbox-production`; buckets `limitmark-lifecycle-requests-production`, `limitmark-lifecycle-results-production`;
guard name `production-lifecycle-dispatch-v1`; authority `production-public-inquiries-v1`, epoch `phase5c-i1-epoch-1`.
**Consequence [OWNER decision]:** the laboratory must use these "production" names, so it **must run in a Cloudflare account that has no real LimitMark production Workers or buckets** (otherwise deploying
would overwrite them). The lab admission Worker is rendered from `admission-service.cloud-run-lab.template.jsonc` with only `name` changed to `limitmark-admission-service-production`. Relaxing the validators
to accept lab names would be a protected-mechanism change and is not proposed here.

## 2. Trust-chain verification results (automated: `tests/authority-bootstrap-trust.test.ts`, 10 tests, plus the existing `i3b-authority`, `authority-activation-guards` and the workerd integrations)

| Property | Result |
| --- | --- |
| Only an operator signature initializes | Wrong-key signature and a tampered command are `REFUSED` with no rows written; a malformed signature throws before any storage access. |
| Bound to environment and authority | Staging command or staging authority id against the production authority is refused; the authority id/epoch are pinned in the signed command. |
| Replay | Exact replay of the signed command returns the stored receipt (`ALREADY_APPLIED`), no second mutation. A different, validly signed command against an initialized authority is `REFUSED`; release state is unchanged (cannot reset). The guard additionally makes each digest single-use. |
| Freshness | Commands issued more than 5 minutes in the past or future are refused. |
| Invalid signature | Refused (above). |
| Cannot disable enforcement | After initialization: nonce replay -> `replay`, burst cap -> `limited`, unknown release -> `unavailable`, unchanged policy table. Initialization only inserts `authority_meta` and one `active_releases` row. |
| Credential separation | No policy requires `AUTHORITY_OPERATOR_PRIVATE_KEY`; the admission, executor, mailbox and application policies forbid it; Cloud Run and the signer Worker reference no operator/attestation material. The attestation key must differ from the operator key (generated distinct; the runtime pins its fingerprint). |
| Control-plane failure vs data plane | `authority.ts` and the `claimPre`/`consumePost` entrypoints import and call nothing from the operator, attestation, executor or mailbox. If the mailbox, executor, R2 or the signer secret disappear after initialization, admission keeps working; only lifecycle operations (rotation, evidence) become unavailable. |
| Initialization without a signer | `UNAVAILABLE` before any storage statement (not even the schema is created). |
| Local multi-Worker proof | `tests/workers/lifecycle-mailbox.integration.ts`, `operator-executor-rpc`, `production-admission-do-rpc`, `attestation-rpc-transport` (real workerd) all PASS in this environment. |

Not proven: behaviour on deployed Cloudflare (R2 event timing, cron cadence, S3-compatible endpoint behaviour); the first live run is the proof.

## 3. Procedure

### 3.1 Generate keys [LOCAL]
```powershell
$keys = Join-Path $env:USERPROFILE "limitmark-lab-keys"     # must be OUTSIDE the repository; the tool refuses repo paths and existing directories
npx tsx scripts/lab-authority-keygen.ts $keys               # prints PUBLIC keys and fingerprints only
icacls $keys /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F"
```
Outputs: `operator.private.b64url`, `attestation.private.b64url` (mode 0600 files, never printed), plus printed operator public key, attestation public key/fingerprint, and a staging-slot public key
(private half discarded; it only fills the second slot the trust manifest format requires). Keep the operator key offline from every Cloud/Cloudflare secret store. Back up both private files
to encrypted offline storage; losing the operator key means no future rotation (the authority stays functional).

### 3.2 Register the trusted public keys [LOCAL, no secrets]
Render, with exact ignored filenames in `deployment/` (`.gitignore` now covers them):
- `lifecycle-transport.production.json` from the `.template.json`: `accountId`, `operatorPublicKey`.
- `operator-lifecycle-executor.production.jsonc` from `operator-lifecycle-executor.template.jsonc`: name `limitmark-authority-operator-executor-production`, `main` `../workers/operator-lifecycle-executor.ts`,
  account id, service `limitmark-admission-service-production`, `AUTHORITY_OPERATOR_PUBLIC_KEY`, `OPERATOR_EXECUTOR_ENVIRONMENT` `production`.
- `lifecycle-mailbox.production.jsonc` from `lifecycle-mailbox.template.jsonc`: `main` `../workers/lifecycle-mailbox/index.ts`, account id, `AUTHORITY_OPERATOR_PUBLIC_KEY`.
- `authority-result-trust.json` from the template: production slot = attestation public key/fingerprint with `notBeforeMs` set to the generation time; staging slot = the staging-slot public key/fingerprint.
- Admission Worker config (lab template rendered, name `limitmark-admission-service-production`): `AUTHORITY_OPERATOR_PUBLIC_KEY`, `GOOGLE_SERVICE_ACCOUNT_EMAIL` `limitmark-lab-app@limitmark-field-qual.iam.gserviceaccount.com`,
  `GOOGLE_SERVICE_ACCOUNT_SUBJECT` `112648989669419541876`, `ADMISSION_CURRENT_RELEASE_ID` = `lab_deployment_id`, `ADMISSION_CURRENT_KEY_ID` = the `limitmark-lab-admission-release-key-id` value, `ADMISSION_CURRENT_ACTIVATED_AT_MS` = a time not later than deployment.
Preflight (local, read-only): `npm run authority:executor:preflight -- --config deployment/operator-lifecycle-executor.production.jsonc`; `npm run authority:lifecycle:preflight -- mailbox --config deployment/lifecycle-mailbox.production.jsonc`;
`... -- transport --config deployment/lifecycle-transport.production.json`. Any placeholder left or wrong name fails these.

### 3.3 Provision the minimum Cloudflare dependencies [CF] [OWNER]
1. Dedicated account decision (section 1). 2. Create R2 buckets `limitmark-lifecycle-requests-production` and `limitmark-lifecycle-results-production` (private, no public access, no custom domain).
3. Create two R2 API tokens: **request** token = Object Write on the requests bucket only; **result** token = Object Read on the results bucket only. Save each as a JSON file
`{"accessKeyId":"...","secretAccessKey":"..."}` outside the repository (the tooling reads exactly these two keys), mode restricted, never in Git.
4. Deploy in this order (each `wrangler deploy --dry-run` first): admission Worker -> set its Worker secrets (`ADMISSION_CURRENT_RPC_KEY` = the same value as GCP `limitmark-lab-admission-release-rpc-key`;
`AUTHORITY_ATTESTATION_PRIVATE_KEY`, `AUTHORITY_ATTESTATION_PUBLIC_KEY`, `AUTHORITY_ATTESTATION_KEY_FINGERPRINT`) via `wrangler secret put` reading the file/values directly -> executor -> mailbox.
Set no `AUTHORITY_STAGING_ATTESTATION_*` (the presence of the other environment's material disables the signer by design).
5. Do **not** route any public hostname to these Workers; the executor and mailbox have no routes, and the admission Worker is reachable only at its custom domain by Google-authenticated, MAC-signed RPC.

### 3.4 Pre-checks before sending the command [LOCAL + read-only]
- Both secret sets exist: `wrangler secret list --name limitmark-admission-service-production` shows the four names.
- **Negative test first (unauthorized command):** create a throwaway key pair in memory, sign a valid-shape command with it, `PUT` it as `initialize.json`, wait two cron periods. Expected: no `lifecycle/...` result, the guard consumed
  nothing (rejected before any claim), authority still uninitialized (no ATTESTED evidence; a read via `read-result` is `UNCONFIRMED`). Then replace `initialize.json` with the real command. Never reuse a throwaway-signed artifact.

### 3.5 Deliver the signed initialization command [LOCAL + OWNER]
```powershell
$env:AUTHORITY_OPERATOR_PRIVATE_KEY = (Get-Content -Raw "$keys\operator.private.b64url").Trim()
npm run authority:init:prepare -- --environment production --release-id <lab_deployment_id> --release-key-id <release key id> --authority-id production-public-inquiries-v1 --policy-epoch phase5c-i1-epoch-1 --confirm-production-authority-initialization > "$env:TEMP\init.json"
Remove-Item Env:AUTHORITY_OPERATOR_PRIVATE_KEY
npm run authority:init:submit -- --command "$env:TEMP\init.json" --confirm-production --inspect                       # prints environment/authority only
npm run authority:init:submit -- --command "$env:TEMP\init.json" --confirm-production --request-credentials <request-token.json>   # PUT; must finish within 5 minutes of signing
```
(`authority:init:prepare` signs with the key from the process environment and emits only the command and signature; delete `init.json` after use.)
Expected: submit prints `UNCONFIRMED` with `transport: ACCEPTED` - that is normal; confirmation comes from the signed result.

### 3.6 Verify initialization [LOCAL]
After 1-3 minutes: `npm run authority:result -- --kind lifecycle --digest <digest printed by submit> --command "$env:TEMP\init.json" --result-credentials <result-token.json>` -> **POSITIVE** only if an
Authority-signed envelope verifies against `authority-result-trust.json` and the authenticated command. Any other status is non-positive; do not proceed to public traffic.

### 3.7 Confirm normal admission enforcement remains active
- Automated proof already covers replay, burst limit and unknown release (section 2). Live confirmation happens at gate F: a duplicate-token submission and the unauthenticated/forged-envelope probes from the E2E runbook produce no
  second row; counters reconcile. Do not weaken or bypass any check to "prove" initialization.

### 3.8 Recover from partial initialization
| Symptom | Meaning | Action |
| --- | --- | --- |
| Result absent, authority uninitialized, guard unclaimed | command never consumed (signer/secret problem is caught *before* a claim) | fix configuration, sign a **new** command (new digest, new 5-minute window), resubmit |
| Result `UNCONFIRMED consumed` / `attestation-ambiguous` / `dispatch-ambiguous` | claim consumed; initialization may have committed | use `authority:reconcile` then `authority:result --kind reconciliation`; if the signed reconciliation reports the receipt, you are done; `authority:settle` releases the supervisor latch after an exact receipt |
| Claim consumed, reconciliation proves the command was **not** applied | the guard stays latched (by design, no reset) | the guard holds no authority state: delete the mailbox Worker and its DO namespace, redeploy the mailbox with a new migration tag, sign a new command. The authority DO is untouched |
| Authority initialized with the wrong release/key id | initialization cannot be overwritten (`authority-already-initialized`) | in the lab, delete the admission Worker's Durable Object namespace (data is only nonce/permit state), redeploy, re-initialize with new command. Never edit SQLite by hand |
| Operator key suspected exposed | an attacker could sign lifecycle commands (rotation) | replace `AUTHORITY_OPERATOR_PUBLIC_KEY` in admission, executor, mailbox, transport manifest and redeploy; the authority's enforcement is unaffected |

The recovery rows above are derived from the code paths and tests; none has been exercised on Cloudflare. Rehearse the negative test (3.4) and one deliberate failed-then-new-command run in the dedicated lab account before relying on them.

## 4. Rollback boundaries
- Boundary 1 (control plane only): delete mailbox, executor, R2 tokens/buckets, `init.json`. Data plane unaffected.
- Boundary 2 (authority): delete the admission Worker (and its DO namespace) - lab admission stops (fail closed); the application keeps rejecting submissions with the generic state.
- Boundary 3 (keys): delete private key files, delete Worker secrets. Public keys in config may remain.
