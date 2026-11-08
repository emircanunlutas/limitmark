# Cloud plan for M1 — Google Cloud, europe-west3, private addressing (PLANNING ONLY, 2026-11-08)

Nothing was created. No account, project, quota or billing page was accessed: I have no access to your project, so **quotas, credit balance and coverage are UNVERIFIED and listed as pre-provisioning checks**. Facts below that came from the web are marked [W] with their reliability; most pricing came from third-party aggregators, not Google's pricing page.

## 1. What must be verified before provisioning (checklist, in order)
| # | Check | How | Status |
|---|---|---|---|
| 1 | Acceptable-use / security-testing rules for the exact traffic | Read Google Cloud's Acceptable Use Policy and "security testing" pages; secondary sources say own-project testing needs no notice, but that **DoS / resource-exhaustion / stress tests and load above quotas are prohibited** [W: third-party blogs, wording unconfirmed] | OPEN. M1 is 25 req/s from one VM to one VM in the same project (a functional/low-rate test, not a flood), but it is *designed to provoke shed behavior*. Record the clause, and if in doubt ask Google support in writing before the first run |
| 2 | Credit coverage | Billing console: credit balance, expiry, eligible products. Public free-trial terms: $300 credit, 90-day expiry, covers products included in the trial [W: Google free-trial page, reliable] | OPEN: your actual credit, program and expiry are unknown to me |
| 3 | Quotas in europe-west3 | IAM & Admin > Quotas: CPUs (per region and all regions), in-use external IPs (should be 0), persistent disk GB, firewall rules, `Compute Engine API` rate | OPEN |
| 4 | Machine family availability in europe-west3 | `gcloud compute machine-types list --zones=europe-west3-{a,b,c}` | OPEN. Candidate: general-purpose E2 (e2-medium or e2-standard-2); the plane is single-threaded Node plus harness processes, so 2 vCPU per VM is the intent [I] |
| 5 | Network/LB limits | None required: no load balancer is part of the topology (an L7 balancer would change client-address semantics and add a second defense layer; Cloud NAT is not needed after bootstrap) | Design decision, confirm |
| 6 | Budget alerts and an *actual* stop | Budgets only notify, they do not stop spend [W]. A hard stop needs a Pub/Sub-triggered action that disables billing or stops VMs [W: 2018 Google blog, confirm current docs] | OPEN: build and test the stop in an empty project first |
| 7 | Independent management and observation access | See section 4 | Design |
| 8 | Teardown | Existing `sut-teardown.sh` marker logic [R] plus project-level deletion procedure | Design |

## 2. Proposed resources (not created)
- **Project:** a new dedicated project (or folder) with its own billing budget; nothing else in it. Region europe-west3, one zone.
- **Network:** one custom VPC, one subnet, **no external IPs on either VM** (private addresses only, per your preference). Firewall rules: (a) ingress to the plane port from the generator's internal /32 only; (b) SSH only via IAP range (35.235.240.0/20) [I: confirm]; (c) default-deny otherwise; (d) egress deny-all after bootstrap except the package/Node mirrors needed during the one-time bootstrap (use a short-lived Cloud NAT or a prebuilt image to avoid even that).
- **VMs:** `sut` and `generator`, Ubuntu LTS, shielded VM, default service account **disabled**, no scopes, OS Login on, metadata SSH keys off. Generator may be Spot (stateless); SUT standard (a preemption mid-run would INVALIDATE the level).
- **Image:** one prebuilt image of the pinned Node and the exact commit so a run does not re-bootstrap (saves time and egress).
- **Storage:** boot disks only (balanced, ~20 GB). Evidence is pulled to the operator workstation over IAP after each level; no bucket needed.

## 3. Expected cost (formula; numbers are third-party and unverified)
Spend per level = Σ(VM hourly rate × hours) + disks + egress.
Aggregator list prices for europe-west3 [W, unverified]: e2-small ≈ $0.0216/h, e2-medium ≈ $0.0432/h on demand; Spot ≈ 42% of that. For two e2-medium VMs for 2 hours per level: 2 × 0.0432 × 2 ≈ **$0.17** compute, plus disks (a few cents per day) and negligible internal egress. Even 20 levels would be on the order of single-digit to low-tens of dollars. So **the credits are not the constraint; discipline is**: the real cost risks are forgetting running VMs, external IPs/NAT left on, and larger machine families.
Controls: budget at a small fixed amount per milestone with 50/90/100% alerts; a VM max-run-duration/termination schedule so nothing outlives a day [I: confirm the exact Compute Engine feature name]; the stop automation from check 6; a written per-tier spend ceiling (tier is not started until the previous tier's actual billed cost is recorded); reserve = twice the cost of the most expensive tier.

## 4. Management plane and observation (independent of the data path)
- Operator reaches both VMs through IAP TCP forwarding (no public SSH), with OS Login; the plane's public listener is never the management path.
- Observation does not depend on the plane: host `/proc` sampler and the existing 1 s ticks run on the VM; Cloud Monitoring agent optional but **not** relied on for verdicts; evidence is hash-listed (`SHA256SUMS`) and pulled to the workstation.
- No SUT credential can mint cloud credentials (service account disabled), so a compromised SUT cannot touch the project.

## 5. Stop conditions and teardown
Automatic: existing harness STOP reasons (tick gap, exposure violation, unexplained request, ceiling, SIGINT, target expiry ≤ 72 h) [R]; VM TTL; billing-stop automation; dead-man firewall flip on missed operator heartbeats [I]. Manual: operator abort. Teardown order: pull evidence → verify hashes → run `sut-teardown.sh` (verifies its marker) → delete VMs and disks → delete firewall rules and VPC → delete project (or leave empty with zero billing). Never leave the project holding evidence.

## 6. Blockers specific to private addressing
`lab/policy/target-policy.ts` accepts remote targets as IPv4 literals with `disposable: true` and an expiry ≤ 72 h [R]; `forbiddenRemoteAddress` refuses loopback, link-local/metadata, multicast, reserved and CGNAT ranges and does not list RFC1918, so private literals look accepted [R, to be confirmed by a test]; whether the exposure proof's "only non-loopback LISTEN is the reviewed plane IPv4:port" works with an internal address, are unverified (blocker B6 in `QUALIFICATION-M1-DESIGN.md`). A code change there is a verdict-path-adjacent change and needs its own approval.

Sources: [Google Cloud free tier and trial](https://docs.cloud.google.com/free), [programmatic budget notifications (2018)](https://cloud.google.com/blog/products/gcp/better-cost-control-with-google-cloud-billing-programmatic-notifications), [GCP pentesting requirements summary (third party)](https://0xcriminal.gitbook.io/fdmyvkhtguuyb/pentesting-requirements-for-the-cloud/pentesting-requirements-google-cloud), [europe-west3 machine pricing aggregator](https://gcloud-compute.com/europe-west3.html), [e2-medium aggregator](https://gcloud-compute.com/e2-medium.html). The AUP text itself was not retrieved.
