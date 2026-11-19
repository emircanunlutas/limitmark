# M1 remote qualification runbook (2026-11-09, from HEAD 1fff395)

Plan only. Nothing is provisioned, no traffic is sent, no production endpoint is used. It builds on the existing remote M1 design (`M1-ACCEPTANCE-SECURITY-REVIEW-AND-REMOTE-DESIGN.md`, `M1-CAMPAIGN-TRUST-CLOSURE.md`) and does not redesign it. Every threshold not already pinned in code is an owner decision (section 9), not invented here.

## 1. Topology and principals
Three principals with separate credentials; no credential of one is readable by another.
| Principal | Holds | Must not hold |
|---|---|---|
| A: controller and target | disposable target VM(s), the load generator, run commitment, target-side counters | observer keys, evidence-store write-admin |
| B: observers | independent legitimate-user canary, independent origin receipt collector, provenance signing keys | target admin, generator control |
| C: evidence custody | append-only evidence bucket, retention lock, export | any write path from A or B beyond create-only objects |
Components: (1) disposable target running the defense stack at the reviewed commit; (2) external generator in a separate project and network from the target (`BA0_FIELD_V1`, code-pinned, calibration "provisional-uncalibrated"); (3) legitimate-user canary in a third location, never sharing an address range with the generator; (4) origin receipt collector receiving per-request receipts from the origin side only; (5) evidence bucket (principal C). The control plane (Cloudflare, this repository tooling) is not a runtime dependency of the data plane: the target must keep serving, and counting, if the control plane is unreachable. Cloudflare is not foundational.

## 2. Resources and permissions (GCP, europe-west3, as in the existing plan)
- Project P-target (target VM, private addressing; ingress only from generator and canary ranges; IAP/OS Login for operators, no public SSH), project P-gen (generator VMs), project P-obs (canary and receipt collector), project P-evid (bucket). Separate projects give separate IAM and billing scope.
- Target policy: remote disposable IPv4 literal only, explicit owner authorization recorded in `artifacts/lab/targets.json` by the owner, expiry at most 72 h (`MAX_REMOTE_TARGET_LIFETIME_HOURS`). The existing `gcp-sut-1` entry is not renewed or modified by this plan.
- IAM: operators get OS Login on P-target and P-gen only; observers' service accounts get create-only on the bucket; custodian holds retention lock and export; nobody holds delete on locked objects. No service-account keys; short-lived tokens only.
- No load balancer, no public IP on the target beyond what the target policy literal requires (B6 uncertainty: confirm private-address reachability from generator before the first run).

## 3. Network isolation
Default-deny VPC firewall. Allowed: generator and canary to target service ports; target to the receipt collector (origin side) only; observers to the bucket via private access; operators via IAP. Denied: target egress to the internet (patches baked into the image, none fetched at run time), generator access to the bucket, any route from the generator to observers. Production endpoints and Cloudflare production zones are unreachable by construction (no routes, no credentials in these projects).

## 4. Evidence custody and finalization
1. Pre-run commitment: before traffic, principal A publishes a signed commitment (commit SHA, clean-tree proof, parameters digest `BA0_FIELD_V1`, fixture digest, campaign id, run id, window, target literal) to the bucket; B countersigns receipt of it.
2. During the run, observers write only their own records (canary observations, origin receipts, provenance beacons) as create-only objects.
3. Finalization: A writes the finalized package digest; C seals the run prefix (retention lock). Nothing is edited after sealing; corrections are new runs.
4. Retention and export: evidence retained for the period the owner sets (decision O-7); export is a copy by C, and the verifier recomputes acceptance from the exported evidence, never from stored acceptance (`evaluateRunFromEvidence`).
5. Independent observer custody: observer keys and logs stay with B; A may not read B's raw records before sealing.

## 5. Fresh-state proof (per run)
New target instance from the pinned image per run (no reuse of a VM or process). Evidence: process counters reconciling from zero (the only freshness evidence the code accepts today), instance creation record, image digest, boot id inside the commitment. Machine freshness beyond counters is a stated unproven blocker (M1-CAMPAIGN-TRUST-CLOSURE.md section 2) and is listed in GO/NO-GO.

## 6. Per-run sequence (three runs, each identical)
1. Verify clean source tree at the commit; build; record SHA and tree state.
2. Create the target from the pinned image; confirm zero counters; seal the pre-run commitment.
3. Start observers (canary and receipt collector) and confirm each independently reaches the target.
4. Dry-run self-test: `npm run lab:ba0:field -- --selftest` locally (no traffic), then `--dry-run` against the target configuration (no traffic).
5. Run: `npm run lab:ba0:field -- --target <authorized literal> --level <level> --campaign <id>`; the campaign id must be at most 31 characters and unique per campaign.
6. Legitimate-user journey on the canary throughout: homepage, static assets, navigation and FAQ, valid form submission, supported operational actions, then recovery and residual restrictions after the load stops.
7. Stop generator; wait for the post-run recovery window; collect target counters.
8. Finalize and seal evidence (section 4); destroy the target; record teardown.
9. Verify: base verdict VALID; overlay accepted; Criterion 9 PASS; receipt reconciliation PASS; provenance consistency; complete per-layer traffic accounting; no unexplained origin traffic; per-run acceptance recomputed from evidence.
After three accepted runs: Criterion 7 (shed-reason sets, +/-5 percentage points of the median, distinct ids, non-overlapping windows) through the unchanged repeatability rules. Result at best `LOCAL_REPEATABILITY_PASS` in the current code; `QUALIFIED` is unreachable until the owner enables it (O-4). Local fixtures are never external qualification evidence.

## 7. Reported measurements
Per run, from the canary and receipts: success rate, p50/p95/p99 latency, HTTP errors, timeouts, false rejects, rate limits, challenges, origin exposure (requests reaching the origin), target resource pressure (CPU, memory, connections). Pass/fail limits for the legitimate-user metrics are not defined in code and are owner decisions (O-5).

## 8. Hard stops (abort and destroy, run recorded INVALID, never retried silently)
Any traffic to an address not on the authorized literal; any production endpoint or credential reachable; target lifetime within 2 h of expiry; budget at 80 percent of the cap (stop automation, since budgets only notify); evidence store write failure or retention lock missing; observer lost for more than the owner-set gap (O-6); counters not zero at start; commit or tree not matching the commitment; provider quota or acceptable-use notice; operator abort. Aborted runs stay in evidence and keep their INVALID verdict; no run is deleted or replaced.

## 9. Cost, quota and provider prerequisites
- Budget: owner-set cap per run and per campaign (O-2); budget alerts plus an automated stop (scheduled teardown job and a budget-triggered shutdown), because GCP budgets alone do not stop spend.
- Provider: written confirmation that the planned traffic volume and source count are within the provider acceptable-use policy and quota for the three projects; quota increase requests filed ahead; pre-notification to the provider if required.
- Teardown: destroy target, generators, canary and collector VMs after each run; bucket persists under retention; delete service accounts and firewall rules after the campaign; confirm zero residual billable resources.
- Ownership: the target and the address space are owned or explicitly authorized in writing by the owner (O-1).

## 10. Not yet existing (build before the first run, not part of this cycle)
CLI wrappers for observation, provenance, acceptance and campaign evaluation (`lab/m1/*` has none); non-loopback observer processes (currently loopback prototypes); the project/IAM/network provisioning code; the commitment and sealing implementation; the stop automation. Each is a separate authorized change.
