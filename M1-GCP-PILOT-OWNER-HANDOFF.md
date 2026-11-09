# M1 GCP pilot: owner handoff (plan-only)

Documentation only. Local development is frozen. Nothing in this document has been executed against any cloud account: no credential was requested or used, no Terraform `plan` or `apply` ran, no billing or production change was made. **Status: NO-GO for any apply, any pilot, any qualification traffic and Production.** The next permitted step is Gate A (a credentialed plan that creates nothing), and it is blocked only on the owner inputs in section 3.

## 1. Frozen baseline
| | |
|---|---|
| Frozen commit | `b81b05f9ed91dc6a7fc0f84c130a26ec591076c7` (branch `feat/capacity-engineering`, local only, never pushed). This handoff adds one documentation file in a later commit; no code, Terraform, registry, guard, evaluator or contract file changes after `b81b05f` (check: `git diff --stat b81b05f HEAD` lists only this file). |
| Working tree | tracked files clean at `b81b05f`; the pre-existing untracked files are unrelated to M1 and are the reason to run from a clean worktree |
| TypeScript / lint | `tsc --noEmit` exit 0; `eslint . --max-warnings=0` no warnings |
| Terraform | 1.9.8: `fmt -check` exit 0, `init -backend=false` exit 0, `validate` valid. `plan` has NEVER run |
| Clean-checkout `npm test` | 2180 tests: 2136 pass, 2 fail, 0 cancelled, 42 skipped, exit 1. The 2 failures are the historical guards (historical qualification immutable; admission-deciding files byte-identical to baseline), which stay red until the 11 pending migration approvals are decided. Registry: 44 total, 33 approved, 11 pending |
| Not run | workerd suites (no worker code changed) |

Detail documents: `M1-PILOT-FINAL-READINESS.md`, `M1-CLOUD-PILOT-READINESS.md`, `M1-EXECUTION-READINESS.md`.

## 2. Plan-only command sequence
Run by the owner (or a person the owner designates) on their own machine. Angle brackets are placeholders, not values. Keep every real file OUTSIDE the repository. Never paste credentials, tfvars or plan output containing identifiers into chat.

**Step 0: clean checkout at the frozen commit**
```
git worktree add <CLEAN_DIR> <COMMIT_YOU_PIN>      # b81b05f, or the handoff commit that adds only this file
cd <CLEAN_DIR> && npm ci
```
**Step 1: credential setup (the only step that touches an account)**
Use a dedicated sandbox, PLAN-ONLY identity: a user or a service account the owner controls, with read-only access to the sandbox folder and billing account. Prefer short-lived credentials: `gcloud auth application-default login` as that identity, or `GOOGLE_IMPERSONATE_SERVICE_ACCOUNT=<plan-only-sa>` from the owner's own login. No service-account key file (the stack itself forbids keys). Confirm with `gcloud auth list` and `gcloud config list` that the active identity is the sandbox identity and that no production project or identity is selected. If the plan fails on a permission, report the error text; do not broaden the identity to make it pass.

**Step 2: Terraform state initialization**
A plan of resources that do not exist needs no state and writes none. Work on a COPY of the validated configuration so the repository stays clean:
```
mkdir <WORK_DIR> && cp <CLEAN_DIR>/infra/m1/*.tf <WORK_DIR>/
terraform -chdir=<WORK_DIR> init -input=false         # local backend; downloads the pinned providers
```
Do not configure a remote state backend yet. Choosing the state location (and who can read it) is a Gate B decision; the pilot state is discarded at teardown.

**Step 3: variable-file preparation**
```
cp <CLEAN_DIR>/infra/m1/templates/tfvars.template.json         <SECRETS_DIR>/pilot.tfvars.json
cp <CLEAN_DIR>/infra/m1/templates/cost-inputs.template.json    <SECRETS_DIR>/pilot-cost.json
cp <CLEAN_DIR>/infra/m1/templates/authorization.template.json  <SECRETS_DIR>/pilot-authorization.json
```
Delete the `_comment` key from each, fill the values from section 3, set `"mode": "pilot"`, `"create_vms": false` for the FIRST plan, `"lock_retention": false`, `"observationProfile": "REMOTE_PRIVATE"`, `"lane": "PRIVATE-LANE"`, `"publicIngress": false`. Pilot rules the gate enforces: project prefix starts with `pilot`, run id starts with `pilot-`, budgets at most 150, retention at least 30 days.

**Step 4: preflight (read-only, offline)**
```
cd <CLEAN_DIR>
npm run lab:m1 -- preflight --mode pilot --authorization <SECRETS_DIR>/pilot-authorization.json --tfvars <SECRETS_DIR>/pilot.tfvars.json --cost <SECRETS_DIR>/pilot-cost.json --commit <COMMIT_YOU_PIN>
```
The first runs will exit 20 or 30 and list the reasons. Copy `details.digests.tfvars` and `details.digests.costInputs` from the output into the authorization's `tfvarsSha256` and `costInputsSha256`, and put the commit into `commit` and the parameters digest into `parametersDigest`. Repeat until the exit code is **0 (PASS)**. A PASS authorizes nothing and proves no spending cap. If you change a value afterwards the digest check fails by design; re-approve.

**Step 5: Terraform plan (credentialed, creates nothing)**
```
terraform -chdir=<WORK_DIR> plan -input=false -var-file=<SECRETS_DIR>/pilot.tfvars.json -out=<OUT_DIR>/m1-pilot.plan
terraform -chdir=<WORK_DIR> show -no-color <OUT_DIR>/m1-pilot.plan > <OUT_DIR>/m1-pilot.plan.txt
sha256sum <OUT_DIR>/m1-pilot.plan                      # record the digest
```
**Step 6: plan inspection (the owner reads `m1-pilot.plan.txt`)**
Accept only if ALL hold: plan summary has only `to add`, with 0 to change and 0 to destroy; with `create_vms=false` no `google_compute_instance`; exactly four projects, all ids starting with the pilot prefix, all in the sandbox folder; no resource in any project not in that list; no `access_config` or external address anywhere; no ALLOW firewall rule with a `0.0.0.0/0` source or destination (the default-deny rules legitimately use it; the only external source allowed is the IAP range on port 22); peerings only target-generator and target-observer; the evidence bucket has `is_locked = false`; the two budgets and the reaper schedule (`*/5 * * * *`) are present; every VM resource (second plan) has `max_run_duration` with `DELETE`; labels `purpose` and `campaign` present; nothing references a production identity. Then run a SECOND plan with `create_vms = true` the same way (re-run preflight, new digests) and inspect the VM resources. Any surprise: stop and report.

**Step 7: apply authorization**
Stop here. Applying is not part of this document and is not authorized by a PASS, a clean plan, or this handoff. It requires Gate B (section 5): a separate written owner GO that names the exact saved plan by its sha256 from step 5.

## 3. Owner input checklist
Formats only; every value is the owner's to supply. Do not reuse the examples.

**Required before a PLAN can run**
| Input | Format |
|---|---|
| Sandbox folder id (a folder that holds nothing else) | digits, e.g. `<12-digit folder number>` |
| Billing account id | `XXXXXX-XXXXXX-XXXXXX` (hex groups) |
| Project prefix | `pilot` + letters/digits, 4 to 12 characters in total; projects become `m1<prefix>-target`, `-gen`, `-obs`, `-evid` |
| Campaign id / run id | `[a-z0-9-]` up to 31 characters / `pilot-<text>` |
| Plane port | integer above 1023, not 3000, 5432, 55416, 55417 |
| Four addresses | `10.10.0.<2-253>/32` target; `10.20.0.<2-253>/32` generator; `10.30.0.<2-253>/32` canary; `10.30.0.<2-253>/32` collector (different from the canary) |
| Three principal groups, pairwise different | `group:<name>@<your-domain>` for operators, observers, custodian |
| Three image resource names, pairwise different (never a family) | `projects/<image-project>/global/images/<image-name>`; for the FIRST plan (`create_vms=false`) they must be well formed but need not exist yet |
| Plan-only credentials | owner's own setup (step 1); never sent to anyone |
| Cost inputs | current provider prices and exchange rate with source and time (at most 24 h old), logging, storage and cleanup amounts, runtime hours, worst-case hours |
| Signed authorization record | the template, including: acknowledgement that spending is not hard-capped, acknowledgement of residual charges, budgets (at most 150 TRY for the pilot) |

**Required only before APPLY (Gate B)**
Built and pinned images (they must exist); provider quota confirmation for the regional vCPU override; acceptable-use confirmation for single-connect smoke traffic; Terraform state location and its access; the budget-creation route (decision 7.1); the named teardown owner (7.2); an explicit maximum runtime (for example the lifetime in `run_max_seconds`, 1,800 s to 14,400 s); written GO naming the plan digest.

**Required only for later qualification (Gate C or beyond)**
Observer deployment identities committed before a run; canary baseline measurements and the owner's latency thresholds and named operational actions; baseline sample size; maximum heartbeat gap; authorized target and expiry; retention-lock decision; D-1, D-3 and Gate 11A for the 11 pending migrations; whether a private-peering generator counts as external; written GO for the exact campaign.

## 4. Budget and cleanup decision record
- Normal estimated pilot cost: approximately **61 TRY**, UNVERIFIED (assumed prices and exchange rate).
- Provisional planning threshold: **150 TRY**. It is a planning figure the preflight uses to say NO-GO. It is NOT protection: nothing enforces it.
- Uncontrolled exposure if the provider lifetime and the reaper both fail and the fleet runs 48 hours: approximately **641 TRY**, UNVERIFIED, and above the threshold.
- **Spending is not strictly bounded.** Budget alerts are notifications that lag billing data; they are not hard spending caps. The vCPU quota, `max_run_duration`, the reaper and the budget stop are defined but have never been exercised; their enforcement is unverified.
- **Resource deletion and project teardown have not been tested.** `terraform destroy` cannot run by design (`prevent_destroy` on the projects and the evidence bucket, which is kept). Intended sequence (owner-run, unexecuted): apply with `create_vms=false`; inventory instances, disks and addresses; delete the two billing budgets FIRST (they live on the billing account and would be orphaned by project deletion); delete the four sandbox projects; discard the sandbox state; record the 15-category cleanup inventory (`M1-PILOT-FINAL-READINESS.md` section 4).
- Unverified provider facts that cleanup depends on: project deletion with unexpired unlocked retention; active peerings; whether projects pending deletion are billed; whether a targeted destroy of the budgets is accepted despite `prevent_destroy` elsewhere.

## 5. Stage gates
Each gate is a separate owner decision; passing one authorizes nothing in the next.

**GATE A: PLAN.** Requires: verified sandbox identity (step 1 confirmation); owner inputs of section 3 (plan); valid Terraform configuration (frozen, validated); preflight exit 0; credentialed plan reviewed against step 6. Permitted: reading and planning. **No infrastructure is created.** Output: plan file digest and the owner's written review.

**GATE B: INFRASTRUCTURE PILOT.** Requires: a separate written owner GO naming the plan digest; verified current cost inputs (fresh preflight PASS); accepted residual exposure (section 4, in writing); provider and quota confirmation; a named teardown owner; a validated plan; an explicit maximum runtime. Permitted: disposable sandbox infrastructure only, smoke probes only (`PILOT_CONTRACT`: ten checks, single connects, DNS lookups, marker objects). **No qualification traffic, no attack traffic, no `BA0_FIELD_V1` workload, no public ingress.** Exit: `npm run lab:m1 -- pilot --results <file>` returns `PILOT_PASS` (exit 0) including the full cleanup inventory.

**GATE C: PRIVATE-LANE M1.** Requires: Gate B passed and cleanup completed; operational independent observers (launcher run off-host under the observers' principal); verified evidence custody; baseline measurements, latency thresholds and heartbeat threshold fixed; authorized target and campaign; a separate written GO. Known CODE blocker to approve first: observer and producer authentication do not exist, so identities remain self-reported. Results are private-lane results and must never be quoted as public-internet qualification. `QUALIFIED` remains unreachable in code.

**GATE D: PUBLIC-INGRESS M1.** Requires an independently authorized public-ingress design and scope, provider compliance and separate owner approval. **No public-ingress work is authorized now**; the preflight and the launcher refuse it.

## 6. Teardown ownership
Not assigned. The owner must name one person or group who (a) runs the section 4 sequence, (b) holds the project-delete right on the sandbox folder (a project-level right, no billing-account-wide role), and (c) confirms the final inventory in writing. Until named, Gate B cannot be passed.

## 7. Remaining owner decisions
1. **Budget creation route.** Creating the two budgets needs billing-account scoped rights for whoever applies. Choose: (a) grant a narrow billing-account role to the applying identity for the duration of the apply only, or (b) a billing administrator creates the budgets outside Terraform (this needs a reviewed Terraform change, which this freeze does not allow; it would be a new cycle). No billing-account-wide role is requested by this work, and billing detachment is not implemented.
2. **Teardown owner** (section 6) and acceptance of the unverified teardown path.
3. **Pilot maximum.** Confirm 150 TRY as a planning threshold, or set another, understanding it protects nothing by itself.
4. **Residual exposure.** Accept in writing that the uncontrolled exposure (about 641 TRY, unverified) exceeds the threshold and that spending is not bounded.
5. **Sandbox and identities:** folder, billing account, groups, plan-only identity, state location, images, addresses.
6. **Provider confirmations:** quota, acceptable use, current prices and exchange rate.
7. **Later (not needed for Gate A or B):** thresholds and baseline N, heartbeat gap, retention lock, D-1/D-3/Gate 11A, authorized target, private-lane-as-external-generator question, producer-authentication work, written campaign GO.

## 8. Current NO-GO status
| Item | Status |
|---|---|
| Production | NO-GO (unchanged; Gates 9, 10, 11A closed) |
| Gate A (plan) | not started; blocked only on owner inputs |
| Gate B (pilot) | NO-GO: no plan, no GO, no teardown owner, cost unverified, enforcement and cleanup untested |
| Gate C (private-lane M1) | NO-GO |
| Gate D (public ingress) | not authorized |
| Spending | not strictly bounded; no cap claimed |
| Historical guards | 2 red by design until the 11 pending migrations are decided |
