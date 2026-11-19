# M1 off-host observation compatibility and pilot final readiness (2026-11-09, from baseline 98a773b)

Local only: nothing provisioned, planned against an account, applied, deleted or sent over a network; no credential, billing permission, key or Wrangler change. Registry (44 / 33 / 11), the two historical guards, Criterion 7 and 9 thresholds untouched. `QUALIFIED` stays unreachable. Builds on `M1-CLOUD-PILOT-READINESS.md`.

## 1. The correction (observation profiles)
`evaluateObservation` used to require `meta.loopbackOnly === true` and at least five distinct process ids, which rejects truthful off-host evidence. It now judges the evidence under one explicit profile (`lab/m1/observation-profile.ts`, `observation-check.ts`):

| | LOCAL_LOOPBACK | REMOTE_PRIVATE |
|---|---|---|
| Requirements | UNCHANGED: `loopbackOnly: true`, at least five distinct positive process ids, pinned timeout, all existing checks | metadata must state `loopbackOnly: false`, `topology: private-lane`; process ids are ignored and are NOT proof; canary and collector must each report a deployment identity and a PRIVATE address; canary results, metadata and collector declaration must agree; both must equal the identities in the environment commitment; the two must differ; neither may equal the target address |
| Common to both | run and campaign binding, journey steps, origin attribution of every successful canary step, receipt sequence and completeness, heartbeats with the verifier's limit, finalization (declaration), the pinned latency rule | same |
| Selected by | the verifier: absent commitment means local | the verifier: a verified pre-run commitment with `observation.profile = REMOTE_PRIVATE` |

**The file never selects its profile.** The profile and the committed identities come from `expectedObservationFrom(commitment)`, and the CLI builds the commitment with the same builder and compares its digest, run, campaign and commit with the server package (`checkCommitment`). A file claiming REMOTE_PRIVATE without a verified commitment is ERROR (`m1.obs.remote_profile_without_environment_commitment`); any disagreement between the claimed profile and the expected one is REJECT (`m1.obs.profile_mismatch`); an unknown profile is ERROR. Missing identity evidence is ERROR, contradictions are REJECT. A file that claims authenticated or independent custody is REJECT: this check cannot establish it. The commitment itself (`observation` block, optional so existing digests do not change) refuses duplicate identities, a public address, an observer address equal to the target, an observer identity equal to the target instance, a remote profile with a non-private target, and a local profile that declares remote observers.

**Binding through the chain.** `observe` and `completeness` take `--commitment`; `accept` derives the profile from `--commitment` (also used for the seal); `campaign` derives it per run from each run's `commitmentFile` and refuses mixed profiles (`m1.cli.observation_profile_mixed_across_runs`, `m1.fresh.observation_profile_changed`); `VerifierSettings.expectedObservation` carries it into `evaluateRunFromEvidence` (a function form selects per run) so acceptance and campaign recompute with the SAME function. The stored observation result records the profile only through its limitations (a closed-key schema is deliberately untouched), so a result recorded under one profile disagrees under another and is not accepted. Preflight requires the owner's authorization to state `observationProfile: REMOTE_PRIVATE` (`LOCAL_LOOPBACK` is ERROR for a cloud topology); the pilot record must declare `REMOTE_PRIVATE`; the launcher takes `--profile` with `--observer-id` and `--observer-address` (private addresses only, `--allow-private-network`, the collector must listen on its own observer address).

**Limitations that remain (stated in every remote result).** `observer_identities_self_reported_not_authenticated`, `independent_custody_not_established_by_this_check`, `producer_authenticity_not_established`, and that simulated evidence does not prove a real off-host deployment. Agreement of three self-reports with a commitment is consistency; it does not prove who ran the observers or who wrote the bytes. Independent custody needs separate principals, credentials and storage (`M1-EXECUTION-READINESS.md` section 3) and authenticated producers (CODE, not built). A commitment file is likewise only byte-consistent: its digest is recomputed, not signed. The seal remains byte consistency only.

## 2. Pilot cost gate (preflight, pilot mode)
The owner's provisional pilot planning ceiling is **150 TRY**: a planning figure, not a provider-enforced cap and not authorization to incur charges. Preflight now requires, before any GO: named and verified prices and exchange rate, at most 24 h old; every material component stated (compute vms x hours, egress quantity and price, storage, logging, cleanup; an unknown one is INCOMPLETE); a documented worst-case exposure (`worstCaseHours`: the provider lifetime AND the reaper both fail; computed and reported in `details.exposure`); the owner's acknowledgements of unverified spend cap and of residual charges; budgets at most 150 TRY; an estimated run above 150 TRY is **NO-GO (ERROR)**. `details.exposure` always carries `strictlyBounded:false` and `lifetimeAndCleanupVerified:false`: those become true only through a recorded pilot, and nothing here marks spending bounded. Pilot project ids must start with `pilot` and the campaign's must not (a pilot is torn down by deleting its projects).
Assumed-price estimate: about 61 TRY for the planned run in the test data (compute 0.56 USD for 2 h, storage 0.5, logging 0.2, cleanup 0.1, egress 0.0012, at 45 TRY/USD); the documented worst case with 48 h of runaway VMs is about 641 TRY. **Unresolved exposure:** the worst case exceeds 150 TRY by design of the failure it models, and no enforcement that would prevent it (provider lifetime, quota, reaper, budget stop) has been verified. Billing data lags. The figures are inputs the owner must replace with verified ones.

## 3. Prerequisites checklist
Credentialed PLAN (read-only intent; `terraform plan` creates nothing but needs real inputs and credentials) versus APPLY (creates and bills; separate owner GO per apply). A plan is not authorization to apply it; the preflight PASS is not either.

| # | Needed for | Item | Owner / provider |
|---|---|---|---|
| 1 | plan | Sandbox folder id (pilot) | owner |
| 2 | plan | Billing account id | owner |
| 3 | plan | Four disposable project identities: `m1<prefix>-target/-gen/-obs/-evid`, prefix starting `pilot` | owner chooses prefix |
| 4 | plan | Three distinct IAM groups (operators, observers, custodian) | owner |
| 5 | plan | Plan-only identity and credentials, kept by the owner, never stored here | owner |
| 6 | plan | State storage location for the sandbox state; discarded after pilot teardown | owner |
| 7 | plan | Fixed private addresses: target, generator, canary, collector `/32` inside the documented ranges; plane port | owner |
| 8 | plan | Three pinned, DISTINCT VM images built from the pinned commit | INFRASTRUCTURE |
| 9 | plan | Confirmed prices and exchange rate, worst case documented, signed authorization with the three digests | owner |
| 10 | plan | Commitment-side: observer deployment identities decided (they are committed before a run) | owner |
| 11 | apply | Provider quota for the regional vCPU override | PROVIDER |
| 12 | apply | Acceptable-use confirmation for the pilot traffic (single connects only) | PROVIDER |
| 13 | apply | Budget creation permission: billing-account scoped for whoever applies, or a billing admin creates the budgets out of band | owner decision |
| 14 | apply | Written GO for the exact apply | owner |
| 15 | apply | Teardown owner named (who runs section 4) | owner |

## 4. Cleanup review (`prevent_destroy` and project deletion)
`prevent_destroy` is NOT removed. Facts from `infra/m1/*.tf`: the four projects (`projects.tf`, `deletion_policy = "DELETE"`) and the evidence bucket (`evidence.tf`, `force_destroy=false`, 30 d unlocked retention, 7 d soft delete, versioning) carry `prevent_destroy`; VMs sit behind `create_vms`; the ops bucket has `force_destroy = true`; the Scheduler job, function, Eventarc trigger, topic and the two billing budgets are not behind a switch. Consequence: **`terraform destroy` cannot run** (a plan that includes a protected resource is refused), and it is not meant to.

Intended sequence (nothing executed; owner-run):
1. `apply -var create_vms=false`: deletes the four VMs; boot disks auto-delete.
2. Inventory instances, disks and addresses in the three disposable projects: expect zero.
3. **Delete the two billing budgets first** (`terraform destroy -target=google_billing_budget.run -target=google_billing_budget.campaign`, or a billing admin deletes them). Budgets live on the BILLING ACCOUNT, so deleting projects does not remove them. Expected to be allowed despite `prevent_destroy` elsewhere because the plan contains only the targets; verify in the plan output.
4. Owner deletes the four sandbox projects (project-level right; no billing-account right). Inside them this removes VPCs, peerings, firewall rules, DNS zones, routers, Scheduler job, function, Eventarc trigger, topic, service accounts and both buckets (retention is unlocked; confirm the provider does not block it with unexpired objects, and that a locked retention WOULD block it).
5. Discard the sandbox Terraform state (it refers to deleted projects).
6. Record `cleanup.inventory` in the pilot result (fifteen categories; only buckets and projects may remain, with a stated reason, e.g. pending provider deletion). The evaluator enforces this (tests).

**Exact gaps found:** (a) no teardown script or runbook existed (now this section); (b) budgets are outside project scope and would be orphaned by step 4 unless step 3 happens first; (c) the targeted destroy of budgets needs the budget-capable permission again; (d) the claim that project deletion succeeds with an unlocked, unexpired retention, that peerings do not block it, and that projects pending deletion are not billed are all PROVIDER facts not verified; (e) logs and soft-deleted objects persist until the provider purges the project (residual charges: acknowledged by the owner, size unknown). With these, the design CAN show a reliable path; it cannot yet DEMONSTRATE one, because no step has run. The real campaign's evidence project must never be deleted this way until the custodian has exported the evidence and the lock decision (O-7) is made.

## 5. Blockers
| Class | Item |
|---|---|
| CODE | observer and producer authentication (identities remain self-reported); signed commitments; the dry run still uses a synthetic server package; no real off-host run of the launcher |
| INFRASTRUCTURE | images not built; `plan`/`apply` never run; peering, IAP, DNS, Private Google Access, `max_run_duration`, reaper, budget stop and every cleanup step unexercised |
| PROVIDER | quota override, acceptable use, budget publishing, Scheduler prerequisites, project deletion behavior, billing of projects pending deletion, current prices and exchange rate |
| OWNER DECISION | everything in section 3 marked owner; the pilot maximum (150 TRY proposal accepted as planning ceiling); budget permission route; who tears down; plus the campaign items already listed (thresholds, N, heartbeat limit, retention lock, D-1/D-3/Gate 11A, written campaign GO) |
