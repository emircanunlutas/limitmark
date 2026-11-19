# M1 campaign trust closure, unknown-authority classification and concurrency review (2026-11-09, from HEAD 6d49a71)

Local and additive. No historical verdict, byte-pinned file or production module changed. `QUALIFIED` stays unreachable; `LOCAL_REPEATABILITY_PASS` is not a qualified campaign. Production remains NO-GO.

## 1. The campaign defect, reproduced and closed
**Reproduced (against 6d49a71, disposable fixture, real writers):** three runs in one root, run 2's observer evidence really failing (a dropped form submission). A stored `m1-acceptance.json` written for run 2 with the correct identity, `outcome: LOCALLY_CONSISTENT` and all components PASS made `m1LocalCampaign` report `LOCAL_REPEATABILITY_PASS`. The genuine acceptance record of the same run gave REJECT. `loadAcceptance` trusted the stored artifact after an inventory check and an identity match.

**Closed:** `lab/m1/campaign.ts` no longer reads a stored acceptance for its decision. For each run the IO wrapper calls `evaluateRunFromEvidence` (the complete per-run evaluation of `lab/m1/acceptance.ts`, the same function `m1AcceptRun` now uses): authoritative package, generator report, observer records and retained provenance records, every component recomputed. Only that recomputed result enters `evaluateLocalCampaign`. The stored artifact is then compared with it (`auditStoredAcceptance`: identity and identity digest, run id, outcome, reasons, component statuses, provenance levels, input digests, qualification). A missing record is INCOMPLETE, a disagreeing or unverifiable one is ERROR, and neither can pass. The repeatability facts still come from the unchanged `extractRun` over the same finalized package, are bound to the recomputed identity, and the unchanged `evaluateRepeatability` decides Criterion 7 (exactly three runs, distinct run/campaign/finalization identities, non-overlapping windows, same commit/parameters/fixture/level, shed-reason sets, +/-5 points of the median).

The pure `evaluateLocalCampaign` now requires `audit: "agrees"` on every run; an absent value is ERROR, so a caller cannot skip the audit.

## 2. Adversarial results (`tests/m1-campaign-adversarial.test.ts`, 10 tests; every invalid case prevents the pass)
| Case | Result |
|---|---|
| genuine three runs, all inputs present | LOCAL_REPEATABILITY_PASS, qualification unreachable |
| forged acceptance artifact (correct identity) for a run with failing observer evidence | ERROR `stored_acceptance_not_verified` (the recomputed acceptance is REJECT) |
| genuine record with outcome upgraded or downgraded; components or input digests edited | ERROR |
| copied identity hash plus a re-sealed forged observation result | ERROR (disagrees with the recomputation) |
| observer record modified after acceptance; retained beacons modified | ERROR |
| Criterion 9 rejects now / receipt reconciliation rejects now / canary observation rejects now | REJECT, failing component named, repeatability not consulted |
| substituted finalization digest; another run's record; the same package submitted twice | ERROR / ERROR / REJECT |
| process counters not reconciling from zero (a reused process) | REJECT through the receipt reconciliation |
| retained or observer evidence not supplied; stored record absent; no result ids | INCOMPLETE; a missing generator report is ERROR |
| campaign id reused across runs; overlapping windows (each run individually consistent) | REJECT via the unchanged `m1.repeat.*` rules |
| two or four runs | INCOMPLETE / ERROR |

Fresh state: distinct ids are not read as fresh machines or fresh processes. The only freshness evidence is process counters reconciling from zero per run; machine freshness stays an unproven blocker.

## 3. Unknown authority classification (`inspectLifecycleAuthority`)
1. Why: the label is `staging` for the staging id, `lab` for the lab id, and `production` for EVERY other value (default branch), including unknown, empty or look-alike ids. The not-found answer echoes the supplied id.
2. Presentation only? Yes for the answer itself: `status` is NOT_FOUND, `initialized` is false, `authorityId` echoes the input.
3. Callers: `authority-attestation.ts` (two calls) pass the coordinator's frozen identity; `index.ts` passes the fixed production default, the staging id or the lab id. No caller derives authorization from the label.
4. The one security-relevant path: `attestReconciliation` copies `observation.environment` and `observation.authorityId` into the statement it signs. It is reachable only after the signer is checked against the coordinator identity (`signer-mismatch`), signers exist only for the three environments, and the statement validator requires `authorityId === ATTESTATION_AUTHORITY_IDS[environment]`. A production label on an unknown id cannot be signed or verified.
5. Probe (`tests/authority-unknown-classification.test.ts`, 4 tests): the label table; a coordinator with an unknown id and a production signer returns `UNAVAILABLE signer-mismatch`; `makeReconciliationStatement` rejects the production label with an unknown or lab id; the default (no id) is the production authority by design.

Severity: informational (default-label hygiene), not a vulnerability on any current call path. Possible hardening, not applied: return an explicit unknown environment (or throw) for unrecognized ids.

## 4. Concurrency-only failures
Observed once, during a full `npm test` run while workerd suites ran concurrently: `defense-front-rejected-body` ("duplicate conflicting Content-Length") and `lab-ba0-collapse-run` (layer diversity). Both passed in isolation twice and in a quiet full run.
- Shared mutable state: none found. Both use ephemeral ports (`listen()` with no fixed number) and no shared temporary paths.
- `lab-ba0-collapse-run`: reproducible under CPU oversubscription. With 24 to 36 busy node processes on a 12-core machine it failed in 2 of 7 runs, each time on a measured-latency gate (`C2p.latency_calm: added p95 14.98 ms, p99 163.33 ms` and `C0.f4_filter_poisoned_by_renders`). It compares real wall-clock latency of a control against a protected path, so it is contention-sensitive by construction (resource contention, not a logic defect). It was not weakened.
- `defense-front-rejected-body`: not reproduced in 7 loaded runs. Its assertions depend on fixed wall-clock waits (2 s for the response head, 1.5 s for the server to close), which is consistent with contention; this remains a hypothesis. `npm test` runs `tests/*.test.ts` with node's default file concurrency (about one file per core), so any additional parallel load oversubscribes the machine.

Recommendation (not applied; needs authorization): run these two latency/deadline-sensitive files serially or in an uncontended step; do not loosen the thresholds.
