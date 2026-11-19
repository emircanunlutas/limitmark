# Existing LimitMark GCP infrastructure and historical test evidence: read-only discovery (2026-11-09, baseline 0a58105)

Method: local files read in place; GCP queried with read-only `list`/`describe` calls using the owner's already-present gcloud login (the Cloud SDK needed `CLOUDSDK_PYTHON` pointed at its own bundled Python; no `auth`, `config`, `set` or any mutating command was run; an access-token cache refresh is the only incidental local state change possible). No VM was started, no disk attached/mounted/snapshotted, no API enabled, no resource created, no secret value read (secret NAMES only), no traffic. Tarball backups were extracted to a scratch copy; originals untouched. Only the project `limitmark-field-qual` was inspected; two other projects on the account (`gen-lang-client-0960644259`, `rclone-drive-510412`) are not LimitMark and were not touched.

## 0. Recovery of the "~86.5%" three-layer result: NOT RECOVERED
Searched: all 277 commits on all branches and tags (`git log -S` for 86.5, 86,5, 0.865, 86.50, 8650: no hit), the working tree, `artifacts/lab` (203 local evidence directories), docs, the Oct 7 SUT and generator backup tarballs, the Oct 29 C1 SUT evidence copy in Downloads, the audit-experiment folders (copies of that C1 evidence), and a numeric sweep of every counter ratio in the recovered runs. The only textual "86.5" is a timestamp (`tMonoMs: 174286.54`). **No artifact states or implies 86.5 %, and no ratio of recorded counters equals it.** The figure is therefore unconfirmed and must not be quoted.
What the recovered runs DO show (measured, identical in three completed field runs): 1,500 requests; layer 1 entered 1,500, rejected 0; layer 2 (credit lane) entered 1,500, shed 313 (all `mutation.unverified.lane_budget`), i.e. **layer 2 produced 100 % of the rejections**; 1,187 proxied to the origin (79.13 %), the origin executed 1,187 and mutated 62 (of 375 mutation requests: 313 shed = 83.47 %); origin kept answering; legitimate-user journeys 12/12 baseline, 17/17 window, 6/6 recovery, 3/3 residual, 0 legitimate refusals; recovery proof ok. Ratios derivable and checked: 79.13 %, 20.87 %, 83.47 % (shed of mutations), 95.87 % (not mutated), none 86.5 %. This pattern (L2 doing the rejecting, traffic reaching a still-healthy origin) matches the memory, but the number does not.
Where an earlier or different result could still be: the raw evidence of the Oct 8 salvo runs R1/R2 (my own notes say it lives only on the SUT disk `instance-20261007-124437`, plus possibly the 54 MB snapshot `limitmark-sut-ssh-recovery-20261008`). Reading either needs separate authorization (section 7). The Oct 5-6 loopback "layer diversity" runs (arms C0/C0r/C1/C2/C2p, `artifacts/lab/evidence/*ba0-collapse*`) give 15-97 % depending on arm and also contain no 86.5.

## 1. Historical test summary (local evidence)
| Run | Date | Commit | Roles | Load | Result | Where |
|---|---|---|---|---|---|---|
| loopback layer diversity (arms C0..C2p) | Oct 5-6 | 23c4c2c | one host, loopback, fixed counts | 283-3,553 req per arm | LAYER-DIVERSITY-VALID, 119 gates; no volumetric, network or transport measurement | `artifacts/lab/evidence/*ba0-collapse*` |
| first-gcp-n1 (C1) | Oct 7 13:45Z | c250fd4 | SUT + loadgen on default network | none | ABORTED (generator not started), operational | Oct 7 SUT backup |
| first-gcp-n1b (C1) | Oct 7 13:48Z | c250fd4 | same | 60 s, 25 rps, 1,500 req | server complete; reconcile **EXTERNAL-L7-QUALIFICATION-VALID** (scoped) | SUT + loadgen backup |
| first-gcp-n2 (C2) | Oct 7 17:19Z | aff793e | same | 2 workers, 1,500 req | server complete, same 1,187/313 histogram; reconcile **INVALID** (`n2_completion`, `n2_exercise`, `n2_measurement_phase`) | SUT + loadgen backup |
| salvo R1/R2 | Oct 8 | dcf10af | same | 750 pairs | R2 INVALID (727/750); raw evidence not in repo | NOT RECOVERED (SUT disk) |
| gcp-field-002 (C1) | Oct 29 22:51Z | 2f25e4d | SUT (host unverified) + separate authorized generator, lab VPC | 60 s, 25 rps, 1,500 req | EXTERNAL-L7-QUALIFICATION-VALID, 15/15; tag `ba0-l7-c1-valid-20261029` | `Downloads/20261029T225041Z-ba0-l7-c1-ee077d` (SUT only; generator and reconcile evidence not found locally) |
Measured: counters, histograms, canary journeys, listener-state exposure proof, recovery bucket state, processes list, telemetry (1.2 MB with CPU/event-loop ticks). **Claims or not measured:** every record states it is provisional/uncalibrated, plain HTTP, one source, synthetic stand-in origin, L1/L2 in one process, no network/transport/TLS/cloud-firewall measurement, no DDoS claim, no production readiness. Memory and network utilization of the VMs are NOT recorded (only event-loop delay and process CPU in telemetry). Evidence completeness: the Oct 29 SUT directory has its `SHA256SUMS`; the generator report, client evidence (`20261029T225128Z-ba0-l7-pressure-c1-6d4d58`) and reconcile evidence (`20261029T230140Z-reconcile-8b55d8`) were not found on this machine. Historical tests are not M1 evidence and are not retroactively M1-qualified.

## 2. GCP inventory (`limitmark-field-qual`, created 2026-10-04, no organization/folder parent, billing account `0142D1-D02FFF-B41F27`, TRY, open; existing budget "limitmark-field-qual monthly TRY 3000")
| Resource | State | Detail |
|---|---|---|
| `instance-20261007-124437` | TERMINATED | e2-standard-2, europe-west3-a, 20 GB pd-balanced, **default network**, external IP when running, deletionProtection on, stopped 2026-10-08 |
| `limitmark-loadgen` | TERMINATED | e2-standard-2, 20 GB, default network, deletionProtection on, stopped 2026-10-08 |
| `limitmark-primary` | TERMINATED | c3-standard-4, 50 GB hyperdisk, lab VPC, labels project/environment/role, stopped 2026-11-01 |
| `limitmark-observer` | TERMINATED | c4d-standard-4, 50 GB hyperdisk, lab VPC, stopped 2026-10-29 |
| `limitmark-client` | TERMINATED | c4d-highcpu-8, 30 GB hyperdisk, lab VPC, default compute service account, stopped 2026-10-29 |
| `limitmark-sut` | TERMINATED | e2-standard-8, 50 GB pd-balanced, lab VPC, default compute service account, stopped 2026-10-29 |
| **`limitmark-lab-postgres`** | **RUNNING since 2026-11-07** | e2-standard-2, 20 GB, Terraform-provisioned (label), lab VPC |
| Snapshot `limitmark-sut-ssh-recovery-20261008` | READY | 54 MB, source = the Oct 7 SUT disk |
| Networks | | `default` (auto; firewall allows SSH, RDP, ICMP from 0.0.0.0/0 and internal), `limitmark-lab-vpc` (custom) with subnet, router `limitmark-lab-router`, Cloud NAT `limitmark-lab-nat` on a static external IP (in use) |
| Firewall | | 14 rules: default-allow-icmp/internal/rdp/ssh; `limitmark-ba0-plane` (10.156.0.3/32 to SUT tcp 8443); lab-VPC rules for IAP SSH (35.235.240.0/20), client to primary 8443, client to SUT 8444, Postgres 5432 from 10.80.0.0/24, `limitmark-lab-allow-client` and `limitmark-lab-allow-postgres` with NO source range recorded in the listing (confirm) |
| Peerings / routes | | none / defaults |
| Service accounts | | compute default (**project Editor**), lab-app, lab-postgres, lab-invoker; IAM: owner = the owner's user |
| Other | | Cloud Run `limitmark-public-inquiry-lab` (min 0 / max 2), 11 Secret Manager secrets (names only), a Terraform state bucket (`limitmark-field-qual-1045646810362-tfstate`, created 2026-11-07), 35 APIs enabled incl. billingbudgets, iap, pubsub, run |
| Quotas (europe-west3) | | CPUS 2/200, E2_CPUS 0/24, C3 0/24, INSTANCES 7/24, in-use addresses 0/8, SSD 110/500 GB |
**Not queried:** the contents of any disk, bucket object, secret value or log; folder/organization structure (there is none: `gcloud organizations list` returns nothing).

## 3. Historical VM evidence
Disk metadata only (no start, no mount, no snapshot, no copy). Disk names, sizes, images and creation dates are above. Instance metadata keys: SUT/loadgen carry only `ssh-keys`; others `enable-oslogin`; descriptions mostly empty (`limitmark-primary`: "LimitMark primary defense server - isolated Google Cloud validation lab - October 2026"). Nothing in the metadata says what files the disks hold. **Likely** content, from the repository's own notes and the tarball paths: raw R1/R2 salvo evidence and later field-run evidence under `/opt/limitmark-lab/...` on the Oct 7 SUT disk. **Unverified.** Reading it needs a started VM or an attached disk: stop, separate authorization.

## 4. Comparison with the four-project M1 design
Classes: R-AS-IS = REUSABLE_AS_IS, R-CHG = REUSABLE_WITH_CHANGES, HIST = HISTORICAL_EVIDENCE_ONLY, UNS = UNSUITABLE, UNK = UNKNOWN.
| Existing | M1 role | Class | Why |
|---|---|---|---|
| Oct 7 SUT disk, loadgen disk, snapshot | evidence | HIST | irreplaceable (R1/R2 raw data probably); protected by deletionProtection; contents UNK |
| `limitmark-primary`, `-observer`, `-client`, `-sut` | target / observer / generator | HIST (+UNS for M1 runs) | M1 needs a FRESH instance per run (new id, boot, image, zero counters, pinned image); these are used, differently sized (c3/c4d/e2-standard-8), same project and the default compute service account (Editor), so no independent custody or principal separation |
| `limitmark-lab-postgres`, Cloud Run, secrets, state bucket | none (lab application) | UNS for M1; UNK (state) | belongs to the lab application, running and billing; must not be touched by M1 |
| `default` network and its 0.0.0.0/0 SSH/RDP/ICMP rules | any | UNS | violates the isolation the M1 firewall design assumes |
| `limitmark-lab-vpc`, NAT, static IP | network | UNS | M1 uses per-project default-deny VPCs, no external IPs, no NAT |
| Service accounts / IAM | identities | UNS | Editor-level default SA; M1 needs per-VM service accounts and three disjoint principal groups |
| Project budget TRY 3000 monthly | cost alert | R-AS-IS as an alert only | a notification, not an M1 control (M1 budgets are run/campaign scoped) |
| Billing account `0142D1-D02FFF-B41F27` (TRY, open) | billing | R-AS-IS candidate | owner decision; the other three accounts are closed |
| Quotas | capacity | R-AS-IS | ample; M1 needs 8 vCPU per project |

## 5. Value of the historical tests as baseline
Usable as INFORMATION for the new campaign (not as M1 evidence): the three completed C1/C2 runs reproduce the same server-side histogram (1,187/313), which suggests a stable layer-2 shed rate for this workload; the canary journey numbers (latency baselines p50 about 10 ms, p95 about 21 ms over the private network) and the recovery-bucket behaviour; the reconcile pipeline works end to end. Must be collected again under M1: fresh-instance commitments, observer-measured baselines on three fresh instances, owner thresholds, independent observation, CPU/memory/network utilization (not recorded historically), cleanup and cost facts.

## 6. Findings that change the plan
1. **There is no Google Cloud Organization**, hence no folders. `infra/m1` takes `folder_id` (no default), places the four projects in it and sets folder-level policies. As written, Gate A cannot run on this account. Choices (owner): create an organization (for example a free Cloud Identity domain), or approve a reviewed Terraform change that makes the folder and its policies optional (the current freeze forbids it; without an organization the no-SA-key / OS Login / no-external-IP policies are not enforceable at folder level and would have to be per-project).
2. A **VM is running and billing now** (`limitmark-lab-postgres`), plus Cloud NAT with a static IP and three hyperdisk volumes (130 GB) while their VMs are stopped. Not part of M1; not touched.
3. The historical network holds permissive default firewall rules open to the internet; do not run any M1 workload there.
4. Compute default service account has project Editor.

## 7. Gate A recommendation and next authorization
- **Use NEW disposable projects, not this project.** Reasons: it is a single mixed project (historical evidence, a live lab application, secrets, Terraform state, a running database); the M1 teardown is "delete the sandbox projects", which must never be possible here; freshness, custody separation and default-deny networking cannot be retrofitted; and deleting or reconfiguring anything here risks the historical evidence.
- **Blocking for Gate A as designed:** the missing organization/folder (finding 1).
- **Exact next owner authorizations:**
  A. *Gate A route:* choose (i) create an organization and a sandbox folder, or (ii) authorize a reviewed Terraform change to make `folder_id` optional (new cycle, per-project policies).
  B. *Evidence retrieval (optional, separate):* "I authorize creating one temporary disk from snapshot `limitmark-sut-ssh-recovery-20261008` (and, if I name it, a new snapshot of `instance-20261007-124437`), attaching it READ-ONLY to one temporary e2-micro VM in europe-west3-a, copying the evidence directories to my machine, verifying SHA256SUMS, and deleting the temporary disk and VM, with a maximum of N TRY and M hours." The original disks and VMs stay untouched and stopped. This is the safest way to look for the R1/R2 evidence and any "86.5" source.
  C. *Cost hygiene (separate, not M1):* the owner decides whether the running Postgres VM, NAT address and idle hyperdisks should continue.
- **Missing information:** which VM hosted the Oct 29 run; the C1 generator/reconcile evidence; contents of the Oct 7 disks; firewall source ranges of two rules; the Terraform that manages the lab resources and its state; whether the owner has any organization elsewhere.
