# Lab admission authority bootstrap (Phase 3P.4, reconciled for the isolated `lab` environment in 3P.6; NOTHING here has been executed)

Uses the existing reviewed operator-signed chain, instantiated as the strictly isolated third environment `lab` in the existing Cloudflare account. There is no lab-only bypass: lab has its own
classes, names, keys and validators (`LAB-ENVIRONMENT.md`), and no Production or staging identity is reused. Legend: **[OWNER]** approval needed; **[CF]** Cloudflare access; **[LOCAL]** workstation only.

## 1. Why this is needed, and the exact dependency graph

The Durable Object `AUTHORITY` (class `LabAdmissionAuthority`) answers `unavailable` until an operator-signed `initialize` command has been applied. The only reviewed way to apply it:

```
operator workstation                                   existing Cloudflare account, environment "lab"
 [LOCAL] lab-authority-keygen  -> lab operator private key (never leaves the workstation)
 [LOCAL] authority:lab:init:prepare -> sealed {command, signature} (<= 4096 bytes, valid 5 minutes, environment "lab", confirmProduction=false)
 [LOCAL] authority:lab:init:submit -- S3 PUT, request-bucket credential -->  R2 limitmark-lifecycle-requests-lab  initialize.json
                                                                                  | polled by cron (every minute)
                                                                      limitmark-lifecycle-mailbox-lab  (+ LabLifecycleDispatchGuard DO: one-shot claim ledger)
                                                                                  | service binding (private RPC, no public route)
                                                                      limitmark-authority-operator-executor-lab  (pins the lab operator public key, env "lab")
                                                                                  | service binding, entrypoint LabAuthorityLifecycleOnly
                                                                      limitmark-admission-service-lab  -> LabAdmissionAuthority Durable Object ("lab-public-inquiries-v1")
                                                                         verifies Ed25519 operator signature + freshness + environment/authority pins,
                                                                         applies initialization in one transaction, signs a receipt with the LAB attestation key
 [LOCAL] authority:lab:result  <-- S3 GET, result-bucket credential --  R2 limitmark-lifecycle-results-lab  lifecycle/<digest>.json (Authority-signed, verified against authority-result-trust.lab.json)
```

### Mandatory vs optional

| Component | Needed to initialize? | Why |
| --- | --- | --- |
| Lab admission Worker + `LabAdmissionAuthority` DO, `ADMISSION_CURRENT_RPC_KEY`, `AUTHORITY_OPERATOR_PUBLIC_KEY` | **yes** | it is the authority |
| Attestation signer: `AUTHORITY_LAB_ATTESTATION_PRIVATE_KEY`, `_PUBLIC_KEY`, `_KEY_FINGERPRINT` (Worker secrets) | **yes** | a signer-less authority answers `UNAVAILABLE` before touching storage (tested); no initialization can commit without producing signed evidence |
| Operator executor Worker | **yes** | only holder of the `LabAuthorityLifecycleOnly` binding; no public route |
| Lifecycle mailbox Worker + DispatchGuard DO (cron) | **yes** | the only reviewed caller of the executor; the guard makes each command digest single-use |
| R2 `limitmark-lifecycle-requests-lab` and `limitmark-lifecycle-results-lab` | **yes** | the operator-to-mailbox transport |
| Two scoped R2 API tokens (request: write; result: read) | **yes** | operator-side transport credentials |
| `deployment/lifecycle-transport.lab.json` (account id, lab buckets, lab operator public key) | **yes** | `authority:lab:*` target; contains no secret |
| `deployment/authority-result-trust.lab.json` (public lab attestation key + fingerprint) | for verifying the result | needed to accept a POSITIVE result; does not affect the authority |
| Lifecycle observer Worker | **no** | optional read-only monitoring |
| Queues, Workflows, browser, any Production/staging resource | **no** | forbidden by `secret-matrix.json` or unused |

Pinned lab names (the validators accept only these; Production and staging validators reject them and the lab validators reject Production and staging names): see `LAB-ENVIRONMENT.md` section 1.
**Isolation [OWNER-approved]:** the lab shares the Cloudflare account and zone with staging resources but no name, namespace, key, credential or authority identity; deploying lab cannot overwrite a staging or Production
resource (different Worker names, different DO classes), and no Production Worker or bucket exists or is created by this procedure. The Production gates remain closed.

## 2. Trust-chain verification results (automated: `tests/lab-environment-isolation.test.ts`, `tests/authority-bootstrap-trust.test.ts`, `tests/workers/lab-lifecycle-mailbox.integration.ts` on real workerd, plus the existing `i3b-authority`, `authority-activation-guards` and staging/Production integrations)

| Property | Result |
| --- | --- |
| Only a lab operator signature initializes | Wrong-key signature and a tampered command are `REFUSED` with no rows written; a malformed signature throws before any storage access. |
| Bound to environment and authority | A Production or staging command, a mixed environment/authority command, or a lab command carrying a production confirmation is refused by the lab authority; a lab command (even signed with the right key) is refused by the Production and staging authorities. |
| Replay | Exact replay of the signed command returns the stored receipt (`ALREADY_APPLIED`), no second mutation. A different, validly signed command against an initialized authority is `REFUSED`; release state is unchanged (cannot reset). The guard additionally makes each digest single-use. |
| Freshness | Commands issued more than 5 minutes in the past or future are refused. |
| Cannot disable enforcement | After initialization: nonce replay -> `replay`, burst cap -> `limited`, unknown release -> `unavailable`; replay history survives a full workerd restart. |
| Credential separation | The secret policy forbids the lab operator private key in every runtime and the lab attestation private key in every runtime but the admission Worker; shared values across environments are rejected; another environment's signer binding leaves an Authority without a signer. |
| Control-plane failure vs data plane | The lab claim/consume path imports and calls nothing from the operator, attestation, executor or mailbox. With the signer removed, attested reads answer `UNAVAILABLE` and admission keeps serving. |
| Initialization without a signer | `UNAVAILABLE` before any storage statement (not even the schema is created). |

Not proven: behaviour on deployed Cloudflare (R2 event timing, cron cadence, S3-compatible endpoint behaviour); the first live run is the proof.

## 3. Procedure

### 3.1 Generate keys [LOCAL]
```powershell
$keys = Join-Path $env:USERPROFILE "limitmark-lab-keys"     # must be OUTSIDE the repository; the tool refuses repo paths and existing directories
npx tsx scripts/lab-authority-keygen.ts $keys               # prints PUBLIC keys and fingerprints only
icacls $keys /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F"
```
Outputs: `operator.private.b64url` (the lab operator key) and `attestation.private.b64url` (the lab attestation key) - mode 0600 files, never printed - plus the printed public keys and fingerprints. The printed
"staging slot" key belongs to the earlier two-section trust format and is **unused** by the lab trust manifest (single `lab` section); discard it. These keys are used for lab only and must never be reused anywhere else.
Keep the operator key offline from every Cloud/Cloudflare secret store. Back up both private files to encrypted offline storage; losing the operator key means no future rotation (the authority stays functional).

### 3.2 Register the trusted public keys [LOCAL, no secrets]
Render, with exact ignored filenames in `deployment/` (`.gitignore` covers them), from the lab templates:
- `lifecycle-transport.lab.json` from `lifecycle-transport.lab.template.json`: `accountId`, `operatorPublicKey`.
- `operator-lifecycle-executor.lab.jsonc` from `operator-lifecycle-executor.lab.template.jsonc`: `main` `../workers/lab-operator-lifecycle-executor.ts`, account id, `AUTHORITY_OPERATOR_PUBLIC_KEY`, `OPERATOR_EXECUTOR_ENVIRONMENT` `lab`.
- `lifecycle-mailbox.lab.jsonc` from `lifecycle-mailbox.lab.template.jsonc`: `main` `../workers/lifecycle-mailbox/lab-index.ts`, account id, `AUTHORITY_OPERATOR_PUBLIC_KEY` (cron stays `[]` until step 3.4 passes).
- `authority-result-trust.lab.json` from `authority-result-trust.lab.template.json`: the lab attestation public key/fingerprint, `notBeforeMs` set to the generation time.
- Lab admission Worker config from `admission-service.lab.template.jsonc`: `AUTHORITY_OPERATOR_PUBLIC_KEY`, `GOOGLE_SERVICE_ACCOUNT_EMAIL` `limitmark-lab-app@limitmark-field-qual.iam.gserviceaccount.com`,
  `GOOGLE_SERVICE_ACCOUNT_SUBJECT` `112648989669419541876`, `ADMISSION_CURRENT_RELEASE_ID` = `lab_deployment_id`, `ADMISSION_CURRENT_KEY_ID` = the `limitmark-lab-admission-release-key-id` value, `ADMISSION_CURRENT_ACTIVATED_AT_MS` = a time not later than deployment. The name, route, audience and Durable Object class are fixed by the template and by `validateLabAdmissionServiceConfig`.
The lab validators (`validateLab*` in `deployment/lifecycle-private-contract.ts` and `deployment/operator-executor-contract.ts`) are the local gate for these rendered files; any placeholder left or a Production/staging name fails them. Lab-specific preflight/render wrappers are not provided; run the validators through a short local script or test before any deploy.

### 3.3 Provision the minimum Cloudflare dependencies [CF] [OWNER]
1. Owner approves `LAB-ENVIRONMENT.md`; create the dedicated lab API token (permissions in section 4 there); complete the read-only DNS/SSL checks (section 3 there).
2. Create R2 buckets `limitmark-lifecycle-requests-lab` and `limitmark-lifecycle-results-lab` (private, no public access, no custom domain; 24 h / 30 d object lifecycle rules).
3. Create two R2 API tokens: **request** token = Object Write on the lab requests bucket only; **result** token = Object Read on the lab results bucket only. Save each as a JSON file
`{"accessKeyId":"...","secretAccessKey":"..."}` outside the repository (the tooling reads exactly these two keys), mode restricted, never in Git.
4. Deploy in this order (each `wrangler deploy --dry-run` first): lab admission Worker -> set its Worker secrets (`ADMISSION_CURRENT_RPC_KEY` = the same value as GCP `limitmark-lab-admission-release-rpc-key`;
`AUTHORITY_LAB_ATTESTATION_PRIVATE_KEY`, `AUTHORITY_LAB_ATTESTATION_PUBLIC_KEY`, `AUTHORITY_LAB_ATTESTATION_KEY_FINGERPRINT`) via `wrangler secret put` reading the file/values directly -> executor -> mailbox (cron `[]`).
Set no `AUTHORITY_ATTESTATION_*` or `AUTHORITY_STAGING_ATTESTATION_*` (the presence of another environment's material disables the signer by design).
5. The executor and mailbox have no routes and no workers.dev; the admission Worker is reachable only at its custom domain `lab-admission.limitmark.com` by Google-authenticated, MAC-signed RPC. Do not route `lab.limitmark.com` yet (that is gate E1).

### 3.4 Pre-checks before sending the command [LOCAL + read-only]
- Both secret sets exist: `wrangler secret list --name limitmark-admission-service-lab` shows the four names.
- **Negative test first (unauthorized command):** create a throwaway key pair in memory, sign a valid-shape lab command with it, `PUT` it as `initialize.json`, arm the cron (`* * * * *`) and wait two periods. Expected: no `lifecycle/...` result, the guard consumed
  nothing (rejected before any claim), authority still uninitialized (no ATTESTED evidence; a read via `authority:lab:result` is `UNCONFIRMED`). Then replace `initialize.json` with the real command. Never reuse a throwaway-signed artifact.

### 3.5 Deliver the signed initialization command [LOCAL + OWNER]
```powershell
$env:AUTHORITY_LAB_OPERATOR_PRIVATE_KEY = (Get-Content -Raw "$keys\operator.private.b64url").Trim()
npm run authority:lab:init:prepare -- --release-id <lab_deployment_id> --release-key-id <release key id> --authority-id lab-public-inquiries-v1 --policy-epoch phase5c-i1-epoch-1 --confirm-lab-authority-initialization > "$env:TEMP\init.json"
Remove-Item Env:AUTHORITY_LAB_OPERATOR_PRIVATE_KEY
npm run authority:lab:init:submit -- --command "$env:TEMP\init.json" --confirm-lab --inspect                       # prints environment/authority only
npm run authority:lab:init:submit -- --command "$env:TEMP\init.json" --confirm-lab --request-credentials <request-token.json>   # PUT; must finish within 5 minutes of signing
```
(`authority:lab:init:prepare` signs with the key from the process environment and emits only the command and signature; delete `init.json` after use. It has no `--environment` flag and cannot prepare a Production or staging command.)
Expected: submit prints `UNCONFIRMED` with `transport: ACCEPTED` - that is normal; confirmation comes from the signed result.

### 3.6 Verify initialization [LOCAL]
After 1-3 minutes: `npm run authority:lab:result -- --kind lifecycle --digest <digest printed by submit> --command "$env:TEMP\init.json" --result-credentials <result-token.json>` -> **POSITIVE** only if a
lab Authority-signed envelope verifies against `authority-result-trust.lab.json` and the authenticated lab command. Any other status is non-positive; do not proceed to public traffic.

### 3.7 Confirm normal admission enforcement remains active
- Automated proof already covers replay, burst limit and unknown release (section 2). Live confirmation happens at gate F: a duplicate-token submission and the unauthenticated/forged-envelope probes from the E2E runbook produce no
  second row; counters reconcile. Do not weaken or bypass any check to "prove" initialization.

### 3.8 Recover from partial initialization
| Symptom | Meaning | Action |
| --- | --- | --- |
| Result absent, authority uninitialized, guard unclaimed | command never consumed (signer/secret problem is caught *before* a claim) | fix configuration, sign a **new** command (new digest, new 5-minute window), resubmit |
| Result `UNCONFIRMED consumed` / `attestation-ambiguous` / `dispatch-ambiguous` | claim consumed; initialization may have committed | use `authority:lab:reconcile` then `authority:lab:result --kind reconciliation`; if the signed reconciliation reports the receipt, you are done; `authority:lab:settle` releases the supervisor latch after an exact receipt |
| Claim consumed, reconciliation proves the command was **not** applied | the guard stays latched (by design, no reset) | the guard holds no authority state: delete the lab mailbox Worker and its DO namespace, redeploy it with a new migration tag, sign a new command. The authority DO is untouched |
| Authority initialized with the wrong release/key id | initialization cannot be overwritten (`authority-already-initialized`) | delete the **lab** admission Worker's Durable Object namespace (data is only lab nonce/permit state), redeploy, re-initialize with a new command. Never edit SQLite by hand. Never delete a staging or Production object |
| Operator key suspected exposed | an attacker could sign lab lifecycle commands | replace `AUTHORITY_OPERATOR_PUBLIC_KEY` in the lab admission, executor, mailbox, transport manifest and redeploy; the authority's enforcement is unaffected |

The recovery rows above are derived from the code paths and tests; none has been exercised on Cloudflare. Rehearse the negative test (3.4) and one deliberate failed-then-new-command run in the lab environment before relying on them.

## 4. Rollback boundaries
- Boundary 1 (control plane only): delete the lab mailbox, executor, R2 tokens/buckets, `init.json`. Data plane unaffected.
- Boundary 2 (authority): delete the lab admission Worker (and its DO namespace) - lab admission stops (fail closed); the application keeps rejecting submissions with the generic state.
- Boundary 3 (keys): delete private key files, delete lab Worker secrets. Public keys in config may remain.
- Every rollback targets lab-named resources only; none touches a staging or Production resource.
