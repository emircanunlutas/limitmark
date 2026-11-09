# M1 qualification GO / NO-GO (2026-11-09, from HEAD 1fff395)

**Current status: NO-GO for any remote qualification run. Production remains NO-GO. Gates 9, 10 and 11A remain closed.**

## 1. Readiness
| Area | State |
|---|---|
| Local acceptance and campaign evaluation | implemented, recomputes from evidence, adversarially tested; QUALIFIED unreachable |
| Migration registry (updated at 956fc65) | 44 entries, 33 APPROVED, 11 PENDING; 3 lab mailbox files dependency-blocked, 8 need boundary decisions (M1-MIGRATION-BLOCKER-CLOSURE.md section 7) |
| Historical guards | 2 fail, both only because of the 11 pending entries; unchanged and enforced; close only when all 11 are approved |
| Remote infrastructure | Terraform definitions, kill switch, commitment, canary and completeness contracts written and (except Terraform, unvalidated) tested; nothing provisioned (M1-ENVIRONMENT-PREPARATION.md) |
| Budget | provisional 750 TRY per run, 3,000 TRY per campaign; structural maximum about 50 TRY per run under ASSUMED unverified prices; prices and FX must be confirmed |
| Authorized target | none; `gcp-sut-1` expired and not renewed |

## 2. Hard blockers (each must be cleared; items 4 to 9 partly addressed locally, see M1-ENVIRONMENT-PREPARATION.md)
1. 11 pending migrations (guards red; the qualification baseline cannot be declared). Needs the owner decisions on D-1, D-3 and Gate 11A, then batches B4 and B5.
2. Owner decisions D-1 (baseline v2), D-3 (export key), and the Gate 11A boundary.
3. No authorized remote target and no expiry-bound policy entry.
4. Observer processes are loopback prototypes; no independent canary or receipt collector exists off-host.
5. No CLI wrappers for observation, provenance, acceptance and campaign evaluation.
6. No pre-run commitment, sealing or retention-locked evidence storage.
7. Machine freshness is unproven beyond zero-reconciling counters.
8. No budget stop automation; provider quota and acceptable-use prerequisites unconfirmed.
9. Legitimate-user pass/fail thresholds are undefined.
10. The BA0_FIELD_V1 calibration is "provisional-uncalibrated"; a calibrated run is a different claim.

## 3. Owner decisions required
| Id | Decision |
|---|---|
| O-1 | Authorize a target and address space in writing; set its expiry (at most 72 h) |
| O-2 | Budget cap per run and per campaign |
| O-3 | Approve migration batches B1 to B3 now, and decide D-1, D-3 and Gate 11A for B4/B5 |
| O-4 | Whether `QUALIFIED` may ever be reachable, and under what conditions |
| O-5 | Legitimate-user pass/fail thresholds (success, p95/p99, false rejects, challenges, origin exposure) |
| O-6 | Maximum permitted observer gap |
| O-7 | Evidence retention period and custodian |
| O-8 | Provider and projects to use; confirm acceptable-use compliance |

## 4. GO conditions (all required)
- Registry fully approved by the owner, both historical guards green with no test or guard edited.
- Clean source tree at a recorded commit; clean-checkout suite green.
- Target authorized and unexpired; budget and stop automation in place; provider prerequisites confirmed.
- Independent canary, origin receipt collector and append-only, retention-locked evidence storage operating under separate principals.
- Commitment and sealing implemented; per-run fresh instance with zero counters.
- Thresholds in O-5 recorded before the first run.
- Written owner GO for the specific campaign.

## 5. NO-GO conditions (any one stops the run)
Any item in section 2 open; traffic or credentials able to reach a production endpoint; target outside the authorized literal or past expiry; dirty tree or commit mismatch; observers not independent or evidence write path shared with the target; missing retention lock; any hard stop in the runbook section 8; a response to silence treated as approval; any attempt to weaken a guard, test or threshold to pass.

## 6. Shortest safe path
1. Owner decides B1 to B3 (27 files group by group), then D-1, D-3, Gate 11A, then B4/B5: guards green.
2. Owner decisions O-1, O-2, O-5 to O-8.
3. Build, each as a separate authorized change: acceptance and campaign CLI wrappers; off-host observers; commitment and sealing; provisioning and stop automation.
4. Local rehearsal of the whole pipeline against disposable fixtures (not qualification evidence).
5. Owner GO for one authorized campaign; three runs; recompute acceptance from sealed evidence; report.

## 7. Status after the preparation cycle (2026-11-09, from 956fc65)
Still **NO-GO**. Written locally and tested: commitment and fresh-instance check, canary acceptance contract (100 percent journeys; unexpected 429, challenge, timeout or false rejection fails; latency thresholds deliberately unset), explicit observation completeness check, kill-switch decision logic and cost-bound check. Written but unvalidated (Terraform not installed): `infra/m1/*.tf`. Remaining GO conditions, in addition to section 4:
- Target and address space explicitly authorized (O-1); provider requirements confirmed (O-8).
- Prices and exchange rate confirmed and `maxRunCost` run as a pre-run gate; reaper and budget stop verified in a sandbox project (not the real one).
- Independent observer processes running off-host with the custody contract (they are loopback prototypes today); no CLI wrappers for the new contracts yet.
- Canary latency thresholds fixed from the measurements listed in M1-ENVIRONMENT-PREPARATION.md section 3; operational actions named; heartbeat gap limit set (O-6).
- A clean code-pinned run configuration (recorded commit, clean tree, `BA0_FIELD_V1` digest) in the pre-run commitment.
- Retention lock decision (O-7) and billing-detachment decision (O-9).
- The owner's written GO for the exact campaign.
