# M1 cloud pilot readiness (2026-11-09, from baseline 7ae95b3)

Local only. Nothing was provisioned, planned against an account, applied, deployed or sent over a network; no credential was requested or stored; no attack traffic exists; public ingress is not enabled. The migration registry (44 / 33 approved / 11 pending), the two historical guards and the acceptance and campaign evaluators are untouched. `QUALIFIED` stays unreachable. Builds on `M1-EXECUTION-READINESS.md`.

## 1. Preflight (`npm run lab:m1 -- preflight`)
```
npm run lab:m1 -- preflight --mode pilot|campaign --authorization FILE --tfvars FILE --cost FILE [--thresholds FILE] [--terraform-dir DIR] [--commit SHA]
```
Read-only (`lab/m1/preflight.ts`): reads the named JSON files and `infra/m1/*.tf`, runs `git` for the state, prints ONE canonical-JSON line, writes nothing, contacts nothing, `details.provisioned` is always `false`. Exit: **0 PASS, 20 INCOMPLETE, 30 ERROR**, 64 usage. INCOMPLETE = something missing, unset, a placeholder, unverified or stale. ERROR = malformed, contradictory, over a limit or unreadable. PASS = complete and consistent; it authorizes nothing and does not prove a spending cap.

| Check | What decides it |
|---|---|
| `git` | tracked changes: ERROR; untracked files: INCOMPLETE (use a clean worktree); HEAD must equal the commit pinned in the authorization (and `--commit` if given) |
| `level_parameters` | authorization pins `ba0-field-v1` and the digest of the code's `BA0_FIELD_V1`; a different id or digest is ERROR, absence INCOMPLETE |
| `terraform_structure` | the constructs the isolation/cost story relies on must exist in the file that holds them: `max_run_duration` + `termination_action = "DELETE"`, the 5-minute reaper schedule, run and campaign budgets, retention policy, versioning, `prevent_destroy`, the quota override; no `access_config` (external IP); `lock_retention` default false |
| `terraform_variables` | every variable WITHOUT a default in `variables.tf` is set (parsed from the file, so it cannot drift); budget, lifetime, currency, retention, lock and `create_vms` must be STATED (a default may not decide them silently); unknown keys, forbidden plane ports, addresses outside their ranges are ERROR |
| `network_scope` | the four /32 addresses, campaign id and run id in tfvars equal the authorization; addresses distinct; pilot run ids start `pilot-`, campaign ids must not |
| `authorization` | owner, reference, window (not future, not expired, at most 72 h), the owner's acknowledgement that spending is NOT hard-capped, and digests binding the approval to the exact tfvars, cost inputs and (campaign) thresholds: a file changed after approval is ERROR |
| `cost` | prices and exchange rate must be named, verified and at most 24 h old (stale/unverified: INCOMPLETE; future/malformed: ERROR); fleet = four VMs; hours must cover the provider-enforced lifetime; `maxRunCostWithRate` must stay within the run budget and (runs x cost) within the campaign budget |
| `budget_ttl` | owner budget stated and within the 750 / 3,000 TRY planning ceilings; tfvars agree; currency TRY; lifetime 30 min to 4 h and longer than the run plus the target minimum |
| `canary_journey` | the six-step journey and the 100 percent completion requirement are unchanged; campaign: thresholds record FIXED |
| `heartbeat_limit` | campaign: the verifier-side limit comes from the FIXED thresholds record; pilot: not applicable |
| `evidence_custody` | three distinct groups, retention at least 30 days, retention lock never in a pilot and only with explicit owner approval in a campaign |
| `identities` | folder, billing account, three principal groups (group principals only), three DISTINCT pinned image resources (`projects/P/global/images/NAME`, never a family) |
| `ingress_lane` | `PRIVATE-LANE` and `publicIngress:false` only; a campaign also needs the owner's decision on whether a private-peering generator counts as external |

Templates (placeholders, never PASS): `infra/m1/templates/{authorization,tfvars,cost-inputs,pilot-results}.template.json`. Remove the `_comment` key from a real copy and keep the real copy OUTSIDE the repository. Tests: `tests/m1-preflight.test.ts` (16 tests: PASS in both modes, every INCOMPLETE and ERROR path, CLI exit codes, determinism, no file written). Test data there is consistent data that exists only in the test; it proves the gate, not a real plan.

## 2. Terraform stages (nothing below the first row has been run)
| Stage | Command | State |
|---|---|---|
| 1 Structural validation | on a COPY: `terraform fmt -check -recursive`, `terraform init -backend=false`, `terraform validate` | passes (Terraform 1.9.8; re-run at final HEAD) |
| 2 Preflight | `npm run lab:m1 -- preflight --mode pilot ...` | exits 20 until the owner inputs exist |
| 3 Credentialed plan | `terraform -chdir=infra/m1 plan -var-file=<REAL tfvars, outside the repo> -out=<outside the repo>`, then `terraform show -json` and review | NOT run: needs folder, billing account, groups, built images, a plan-only identity and a state-location decision |
| 4 Apply | `create_vms=false` first (campaign-level resources), later `create_vms=true`; separate owner GO per apply | NOT run |
| 5 Connectivity verification | the pilot (section 4) | NOT run |
| 6 Qualification authorization | `preflight --mode campaign` PASS + `PILOT_PASS` + written GO for the exact campaign | not reachable yet |

A dummy-valued plan is not readiness evidence: the provider validates folder, billing account and groups against the real account. What a real plan needs from the owner is listed in section 7. Applier permissions (a requirement of the person or identity that runs apply, never granted to the stack): project creation on the folder, billing-user on the billing account, and **billing-account scoped rights to create budgets** (see blockers). No billing detachment is implemented and none is requested.

## 3. Off-host observer launch package
`npm run lab:m1:observer -- <collector|canary> ...` (`lab/m1/observation/launch.ts`; recording code shared with the local harness in `collector-core.ts` / `canary.ts`).
```
collector --run-id ID --campaign-id ID --listen-host IP --listen-port N --upstream-host IP --upstream-port N --output-dir DIR [--heartbeat-ms N] [--stop-file FILE] [--allow-private-network]
canary    --run-id ID --campaign-id ID --target-host IP --target-port N --output-dir DIR [--plan B,W,R] [--timeout-ms N] [--journey-gap-ms N] [--process NAME=PID ...] [--allow-private-network]
```
- Identity, network and output destination are explicit; an invalid run or campaign id, a missing flag or an unknown flag is exit 64 and writes nothing.
- Address policy: loopback always; RFC 1918 literals only with `--allow-private-network`; public addresses, names, `0.0.0.0`, link-local, CGNAT, multicast are refused. The launcher cannot target a public endpoint.
- Heartbeats: every `--heartbeat-ms` the collector records its own clock (also appended to `collector-heartbeats.ndjson` for monitoring). Finalization: the stop file (or SIGINT/SIGTERM) triggers ONE closing declaration (run/campaign binding, receipt count, last sequence, covered window, heartbeats), written atomically; exit 0 only after it is on disk. A collector that dies leaves no declaration and the evidence cannot pass (tested).
- The canary writes `canary-results.json` and `observation-meta.json` (run window, truthful `loopbackOnly`/`topology`) and never a heartbeat-gap limit: that number is the verifier's.
- Evidence export: `npm run lab:m1 -- seal ...` (byte consistency only) to storage the producer cannot rewrite, then `verify-seal`, as in `M1-EXECUTION-READINESS.md` section 4.
- Run on a VM (checkout of the pinned commit, `npm ci`, the launcher script). A container image was NOT built or tested (no pinned base-image digest could be obtained offline): the image build is an INFRASTRUCTURE item. Tests (`tests/m1-observer-launch.test.ts`, 6): address policy; usage errors; in-process finalization; four separate local processes (origin fixture, front stand-in, collector launcher, canary launcher) producing evidence the UNCHANGED observation evaluator accepts; a killed collector; a private-lane meta.
- **Found CODE blocker:** `evaluateObservation` requires `meta.loopbackOnly === true` and at least five distinct process ids. Evidence from a genuinely off-host canary and collector is therefore rejected fail-closed (`m1.obs.meta_identity_mismatch`, `m1.obs.processes_not_separate`), as the test demonstrates. Accepting a truthful private-lane topology is a change to verifier acceptance logic; it was not made and needs explicit approval.

## 4. Minimal GCP pilot (infrastructure only; do not run without a separate owner GO)
Contract and evaluator: `lab/m1/pilot.ts` (`PILOT_CONTRACT`, `evaluatePilotResults`), CLI `npm run lab:m1 -- pilot --results FILE` (exit 0 `PILOT_PASS`, 20 incomplete, 10 reject), template `infra/m1/templates/pilot-results.template.json`. Tests: `tests/m1-pilot-contract.test.ts` (8).
Rules: disposable sandbox folder and projects only (never the campaign's); `trafficProfile: smoke` (single connects, DNS lookups, marker objects); no attack traffic, no `BA0_FIELD_V1` workload, no public ingress; lifetime at the validated minimum of 1,800 s for the expiry check; the evaluator rejects a record that claims otherwise.
1. `preflight --mode pilot` PASS (owner authorization bound by digest to this exact tfvars and cost). 2. Apply with `create_vms=false`, then `create_vms=true`. 3. Run the ten probes (each is defined with its pass condition and required evidence kinds in `PILOT_CONTRACT`): VM creation and expiry; private DNS; generator to target; canary to target; target to collector; evidence bucket permissions; IAP access; TTL reaper; budget stop (synthetic Pub/Sub message at 80 percent and a malformed one; a REAL budget notification is recorded as `verified` or `not-verified`, billing data lags); complete cleanup. 4. Record results, run `pilot --results`. 5. Teardown last (`create_vms=false`, then delete the sandbox projects); the cleanup record must list no remaining resource.
Abort at the first FAIL, tear down, and record it; a failed pilot is a result, not a retry loop. Known friction: campaign-level resources carry `prevent_destroy`, so a sandbox pilot is torn down by deleting its sandbox projects (owner decision), not by `terraform destroy`.

## 5. Pilot cost estimate and enforcement limits (`infra/m1/pilot-cost-ledger.json`)
Assumed, unverified prices (e2-standard-2 0.10, e2-small 0.04 USD/h, 45 TRY/USD high case): compute 2 h 0.56 USD, a second short fleet for the expiry check 0.28, disks 0.10, logs 0.20, bucket 0.01, function/scheduler 0.05, smoke traffic 0.01: **about 1.21 USD, about 54 TRY**. Proposed owner maximum for the pilot: **150 TRY** (owner decision; the planning ceilings of 750 TRY per run and 3,000 TRY per campaign are unchanged and separate).
Enforcement is exactly as unverified as before: the vCPU quota, `max_run_duration`, the reaper and the budget stop are all `verified:false`; budget alerts notify only and lag; logs, bucket, function and scheduler have no enforcement; orphaned disks are not covered by the reaper. `assessCostBound` returns `strictlyBounded:false` (tested). **No guaranteed spending cap is claimed**; the pilot's purpose is to turn those rows into verified or failed. Only project-scoped controls are used; billing detachment (a billing-account-wide role) is not implemented or requested.

## 6. Two distinct test categories
| | PRIVATE-LANE | PUBLIC-INGRESS |
|---|---|---|
| Path | generator and target over private peering | authorized external generators to a disposable PUBLIC endpoint |
| Suitable for | data-plane, accounting and observer validation, pilot connectivity | claims about real internet-facing behavior |
| Does NOT establish | public-internet ingress resilience, real ingress routing, real source diversity, provider edge behavior | n/a |
| Needs | this cycle's work plus owner decisions | separate scope, provider acceptable-use/compliance confirmation, authorized external generators, a public endpoint design, and separate owner approval |
| State | the only category the preflight accepts (`lane: PRIVATE-LANE`, `publicIngress:false`); the observer launcher refuses public addresses | NOT enabled, NOT designed in Terraform, refused by the gate |
Private-lane results must never be quoted as public-ingress results.

## 7. Exact owner inputs
**For a credentialed plan:** folder id (sandbox for the pilot); billing account id; project prefix; campaign id; run id (`pilot-...` for the pilot); plane port; the four /32 addresses; three pinned image resources (target, generator, observer: built from the pinned commit, DISTINCT); three distinct principal groups; a plan-only identity and its credentials (kept by the owner, never stored here); the state location; the lifetime, budgets, currency, retention days and lock decision stated explicitly.
**For the pilot:** a maximum pilot budget (proposal 150 TRY); confirmed current prices and exchange rate (within 24 h); the signed authorization bound to the three digests; the acknowledgement that spending is not hard-capped; who creates the budgets and with which billing-account role (below); a written GO to execute the pilot.
**For a campaign (later):** everything above plus: canary thresholds and named operational actions after the baseline measurements; baseline sample size N; maximum heartbeat gap; whether a private-peering generator counts as external; retention-lock decision; D-1/D-3/Gate 11A for the 11 pending migrations; written GO for the exact campaign.

## 8. Blockers found or confirmed
| Class | Item |
|---|---|
| CODE (needs approval) | verifier rejects truthful off-host observer metadata (`loopbackOnly`, five distinct pids) |
| CODE | seals and provenance have no producer authentication; the end-to-end dry run uses a synthetic server package |
| INFRASTRUCTURE | images not built (observer image especially); `plan`/`apply` never run; peering, IAP, DNS, Private Google Access, `max_run_duration`, reaper and budget stop unexercised |
| PROVIDER | whether budget notifications can publish to the topic; Cloud Scheduler prerequisites; quota override acceptance; folder organisation-policy rights; prices and exchange rate |
| OWNER DECISION | creating budgets needs billing-account scoped rights for the applier: either grant a narrow billing-account role to the applying identity for the apply, or have a billing admin create the two budgets out-of-band (needs a reviewed Terraform change, not made here); pilot teardown by project deletion because of `prevent_destroy`; everything in section 7 |
