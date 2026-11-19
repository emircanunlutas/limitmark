# M1 unified evidence binding and local acceptance prototype (2026-11-09, from HEAD 046dba8)

Local prototype only. Nothing here changes a historical verdict, approves a migration, contacts anything outside this machine, or makes `QUALIFIED` reachable. Production remains NO-GO.

## Correction to the previous document
`M1-RECEIPT-RECONCILIATION-PROVENANCE-AND-ACCEPTANCE-COMPOSITION.md` section 5 says campaign acceptance needs three runs "in one campaign". That is wrong. The existing Criterion 7 rule (`lab/defense/m1-repeatability.ts`, unchanged) requires DISTINCT server run ids, campaign ids and generator run ids per run. The campaign wrapper preserves that rule.

## 1. Canonical evidence identity (`lab/m1/identity.ts`)
Nine fields, derived only from the finalized package's checksum-verified bytes (`lab/m1/inventory.ts`). The directory name is checked for equality with the manifest run id and is never a source.
| Field | Source | Status |
|---|---|---|
| runId | `manifest.json` | authoritative |
| campaignId, levelId, gitSha, paramsSha256 | `server-level.json` | authoritative |
| paramsId, paramsVersion | `core.json` parameters | authoritative |
| workloadSha256 (fixture identity) | `server-level.json` workload fingerprint | authoritative |
| finalizationSha256 | sha256 of `SHA256SUMS` bytes | derived |
| identitySha256 | digest of the nine fields | derived, convenience only |
Cross-artifact disagreement (core vs server-level vs manifest), tampered bytes, unlisted artifacts or a renamed directory give no identity (`identity: null` plus dotted `identityProblems`).
Producer-contract gap that existed: tally, receipt and verdict outputs carried only the server run id. They now carry additive `identity`, `identitySha256`, `identityProblems`; historical fields and verdict semantics are unchanged.

## 2. Local independent observation (`lab/m1/observation/*`, `lab/m1/observation-check.ts`)
Four loopback child processes (canary, SUT stand-in front, origin receipt collector proxy, origin fixture site) plus the parent. Requests carry `x-m1-run-id`, `x-m1-campaign-id`, `x-m1-request-id`. The collector records requests at arrival, not App counters. Observer files live outside the SUT evidence directory. Pinned `BA0_FIELD_V1.canary` thresholds are used; only journey counts are scaled.
Evaluator rejects: canary success without origin receipt, duplicate, foreign-campaign, foreign-run, unattributed and identity-less receipts, replayed request ids, missing canary results, non-separate processes, journey success below minimum, incomplete recovery, window latency over rule, timeouts. Missing or malformed observer evidence is ERROR.
Covered actions: homepage, static assets, FAQ/navigation, valid form submission. Operational actions are not covered and are reported as not covered.
Limitation: separate local processes are not independent organizational custody.

## 3. Provenance lifecycle (`lab/m1/provenance-session.ts`, seam in `ba0-field-run.ts`)
Commitment is written before the run; beacons (journal-prefix digests, hash-chained from the commitment seal) are emitted during the run; finalization records the `SHA256SUMS` and journal digests; all retained outside the evidence directory. Verification reports byte integrity, completeness, run binding, producer identity (CLAIMED_UNVERIFIED), corroboration and authenticity (UNVERIFIED) separately, with fixed claims `authenticated:false`, `independent:false`. Beacons are self-reported by the server process. Tested on a real run: substitution (consistently re-hashed artifact), replay (other run id), truncation, mismatched campaign/parameters.

## 4. Unified acceptance (`lab/m1/acceptance.ts`, artifact `m1-acceptance.json`)
Consumes overlay, tally, receipts, observation and provenance results; each is loaded through the strict inventory and must carry the same identity as the package. Precedence: ERROR (untrusted, unreadable, no identity, provenance overclaim) > REJECT (component not passed, identity mismatch) > INCOMPLETE (component absent) > LOCALLY_CONSISTENT. `QUALIFIED` exists only in the type; no code path returns it, there is no flag, and an exhaustive test over all 5^5 component states confirms it.

## 5. Criterion 7 integration (`lab/m1/campaign.ts`, artifact `m1-campaign.json`)
Exactly three runs (fewer INCOMPLETE, more ERROR), each LOCALLY_CONSISTENT with receipts PASS, repeatability facts bound to the accepted identity, distinct finalization digests, then the unchanged `evaluateRepeatability`. Best outcome is `LOCAL_REPEATABILITY_PASS`, explicitly not a qualified campaign.

## 6. Why QUALIFIED is unreachable
independent_custody_not_established; authenticity_unverified; authorized_external_lane_qualification_absent; real_remote_target_run_absent; machine_freshness_not_provable_from_evidence (receipt PASS shows counters reconcile from zero, which a reused process would fail, but fresh hardware is not provable); canary_and_origin_collector_are_local_processes; for campaigns, three_local_runs_are_not_a_remote_qualification_campaign.
