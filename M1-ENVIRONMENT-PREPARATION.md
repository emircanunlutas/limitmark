# M1 disposable environment preparation (2026-11-09, from HEAD 956fc65)

Local definitions only. Nothing is provisioned, planned, applied or deployed; no traffic, no production endpoint, no bucket, no retention lock. **`terraform` is not installed on this machine, so `infra/m1/*.tf` is unvalidated** (no `fmt`, `validate` or `plan` was possible); the JavaScript and TypeScript parts are tested. Builds on `M1-REMOTE-QUALIFICATION-RUNBOOK.md` and does not change it. `QUALIFIED` stays unreachable.

## 1. What now exists
| Path | Role | Verified |
|---|---|---|
| `infra/m1/versions.tf`, `variables.tf` | provider, inputs; owner decisions have NO default (`plane_port`, the four /32 addresses, image, three groups, folder, billing account), `lock_retention=false` | not validated |
| `infra/m1/projects.tf` | 4 projects (target, generator, observer, evidence) in one dedicated folder, no default network; folder policies (no SA keys, OS Login, no external IP, shielded VM); regional vCPU quota override | not validated |
| `infra/m1/network.tf` | one VPC per project, default-deny both directions, IAP-only SSH (22), plane port only from the generator and canary /32, target egress only to the collector, generator egress only to the target /32, peering only target-generator and target-observer | not validated |
| `infra/m1/iam.tf` | per-VM service accounts, three principal groups, create-only evidence prefixes, kill-switch service account with a custom delete role | not validated |
| `infra/m1/compute.tf` | 2 x e2-standard-2 (target, generator), 2 x e2-small (canary, collector); private only, shielded, OS Login, provider-enforced `max_run_duration` with DELETE, disks auto-delete, outputs the instance facts for the commitment | not validated |
| `infra/m1/evidence.tf` | evidence bucket: versioning, uniform access, public access prevented, 30 day retention policy, lock OFF; data-access audit logs | not validated |
| `infra/m1/killswitch.tf`, `killswitch/` | custodian-owned TTL reaper (every 5 minutes) and budget-triggered stop, campaign budget with 50/80/100 percent alerts | logic tested; Terraform not validated |
| `lab/m1/commitment.ts` | pre-run commitment builder and cross-run fresh-instance check | 3 tests |
| `lab/m1/canary-contract.ts` | legitimate-user acceptance contract | 4 tests |
| `lab/m1/observation-completeness.ts` | explicit observation completeness check | 3 tests |

## 2. Budget and hard stops
Provisional maximums (not targets): 750 TRY per run, 3,000 TRY per campaign. A budget alert is not a stop, and billing data lags, so cost is bounded in three independent layers.
1. **By construction.** A fixed fleet of four small VMs; a regional vCPU quota (8) per disposable project, so an erroneous apply cannot create more; provider-enforced `max_run_duration` (default 2 h, maximum 4 h by validation) with DELETE on expiry, which depends on none of our code; no external IPs and no load balancer. The level itself is bounded: 60 s, at most 25 requests per second, at most 1,500 requests, responses at most 1 MiB (`BA0_FIELD_V1`), so at most about 1.5 GB of traffic.
2. **TTL reaper.** Cloud Scheduler every 5 minutes; deletes any instance labeled with the campaign and purpose that is older than the maximum lifetime plus 5 minutes. Never selects an unlabeled or other-campaign instance (tested).
3. **Budget stop.** The campaign budget publishes to Pub/Sub; at or above 80 percent of the campaign budget the function deletes every labeled instance in the three disposable projects. It does not touch the evidence project. Billing detachment is deliberately not implemented because it needs a billing-account-wide role (owner decision O-9).

Estimate with ASSUMED, unverified inputs (no current price list or exchange rate was available offline): e2-standard-2 0.10 USD/h, e2-small 0.04 USD/h, 40 TRY per USD, egress 0.12 USD/GB, 2 h lifetime, 1.5 GB traffic, 0.5 USD storage and logs.
| | USD | TRY |
|---|---|---|
| 2 x e2-standard-2 + 2 x e2-small, 2 h | 0.56 | 22 |
| egress 1.5 GB | 0.18 | 7 |
| storage, flow logs, scheduler, function (generous) | 0.50 | 20 |
| **Per run, structural maximum** | **1.24** | **about 50** |
| Three-run campaign | 3.72 | about 150 |
That is about 7 percent of the per-run cap and 5 percent of the campaign cap. `maxRunCost()` (tested) recomputes this from confirmed prices and returns "not bounded" for any missing or non-finite input; it must be run with the day's confirmed prices and exchange rate as a pre-run gate. **Verdict on cost: bounded by construction (not NO-GO on cost); the dollar figures need price and FX confirmation before provisioning.** Residual cost risks: the reaper and budget stop are unverified against a real project; provider billing delay; projects left behind after the campaign (custodian teardown).

## 3. Independent canary and legitimate-user acceptance (`lab/m1/canary-contract.ts`)
Initial target: 100 percent of journeys in every phase (baseline, attack window, recovery) complete every required step: homepage, assets, navigation and FAQ, form, valid form submission, thanks, plus the operational actions the owner names. Any unexpected 429, challenge, timeout, transport failure, HTTP error status (4xx/5xx) or false rejection (403/429/503) fails the run (REJECT, named reason). A missing or duplicated required step fails it. A phase that was not observed, or operational actions that are not named, leave it INCOMPLETE (never PASS). Baseline, window and recovery p50/p95/p99 are recorded separately. **No numerical latency threshold is set here.** The pinned `BA0_FIELD_V1` window rule (p95 at most 4 x baseline p95 plus 150 ms, `jcrMinimum` 1) already applies elsewhere and is unchanged.

Measurements needed before the owner can fix latency thresholds (`LATENCY_MEASUREMENTS_REQUIRED`): baseline percentiles per step on three fresh instances; the run-to-run spread; rehearsal attack-window percentiles (not qualification evidence); the canary-to-target round trip with no application work; recovery percentiles and time back to the baseline spread; canary scheduling lag and clock error.

## 4. Observer completeness and evidence custody
**Separation.** The defense telemetry gap tolerance (`telemetry.gapToleranceMs = 2500` in `BA0_FIELD_V1`, and the event-kind ledger gap ranges) concerns the defense plane's own event stream and is neither read nor widened. `evaluateObservationCompleteness` is independent and tolerates nothing silently: the collector receipts must have a gapless sequence 1..n that equals its own closing declaration (count and last sequence); its declared coverage window must contain the whole run; heartbeats must leave no gap larger than a limit the OWNER sets before the run (unset means INCOMPLETE, never PASS); the canary must return exactly the steps it planned; every successful canary step must have an origin receipt. A step that never reached the origin needs no receipt only when it did not succeed. Missing receipts, missing heartbeats and missing canary steps cannot produce a PASS.

**Custody contract.**
| Principal | Group | Controls | Evidence permission |
|---|---|---|---|
| A controller | operators | target, generator | create-only under `a/` (commitment, finalized package digest) |
| B observers | observers | canary, collector | create-only under `b/` (canary results, receipts, heartbeats, declaration, provenance) |
| C custodian | custodian | evidence project, kill switch | read all; create under `c/` (seal, export manifests); bucket administration |
No principal holds a role in another's compute project; no service-account keys. Sequence: A writes the commitment (`buildCommitment`), B countersigns its digest, run, B writes observations, A writes the package digest, C writes the seal, and the verifier recomputes acceptance from the exported evidence. Before the retention lock is activated, C can still alter objects (custody of C is trusted, not enforced); the lock removes that for the retention period.

**Fresh instance.** The commitment binds the cloud instance id, creation time, image id and boot id and requires all counters at zero; `evaluateFreshness` requires distinct instance, boot, run id and digest per run, one commit and campaign, non-overlapping windows, creation after the previous run ended and a recorded teardown. Machine freshness beyond these facts remains unproven.

## 5. Retention (30 days, provisional)
The policy is defined with `lock_retention=false`: it blocks deletion or replacement by anyone for 30 days but a custodian can still shorten or remove it. **Locking is irreversible**: the period cannot be shortened or removed, the bucket cannot be deleted until every object has aged out, and (to be confirmed with the provider before locking) the project that holds it cannot be cleanly removed early. Storage is tiny (tens of MB per run, well below 0.01 USD/month); versioning and 7 day soft delete add a small multiple. Costs of the lock itself: none, the cost is the commitment. Recommendation: lock only for the real campaign, never for rehearsals; not activated here.

## 6. Open items before provisioning (owner)
O-1 authorized target, addresses and expiry; O-2 budget cap (provisional values accepted for planning); O-5 latency thresholds (after the measurements above) and the named operational actions; O-6 maximum heartbeat gap; O-7 lock decision (30 day period provisional); O-8 provider, projects, folder, billing account, group identities; O-9 whether billing detachment (billing-account-wide role) is wanted; confirmed prices and exchange rate; Terraform installed and `fmt`/`validate`/`plan` run against an empty sandbox folder (not the real one) before any apply.
