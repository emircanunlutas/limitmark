# M1 decisions package (2026-11-08) — for approval; nothing here is approved or implemented

Production NO-GO; Gates 9, 10, 11A closed. No external traffic, no cloud resources, no guard-boundary change.

## A. M1 criteria 7–9 — verbatim from `QUALIFICATION-M1-DESIGN.md` (lines 42–44), for approval
> 7. **NEW, repeatability:** three independent runs on fresh state (same commit, parameters, fixture cycle) all VALID, with identical shed reason sets and per-run shed share within ±5 percentage points of the median. A single VALID run is a smoke result, not M1.
>
> 8. **NEW, status allow-list (finding N-1):** every client-visible status must be in the predeclared set {200, 302/303 per fixture, 503 attributed to the allowed shed, 403/404 only where the fixture expects them}; any other status is INVALID. This needs a verdict-path change (migration event) and is a prerequisite, not part of the run.
>
> 9. **NEW, unexplained differences:** plane outcome tally (82045e3) vs collector ledger equal per event kind, once wiring is approved (`PROPOSED-INSTRUMENTATION-WIRING.patch`). Until then this criterion is reported `not_measured`, and M1 cannot claim it.

Notes for the reviewer (not part of the quoted criteria):
- Criterion 9 refers to commit `82045e3`, where the tally was first committed; it is now wired in by `040292b` and the cross-check is covered by `tests/defense-plane-instrumentation.test.ts` (tally == events delivered over IPC on the real plane process). The condition "once wiring is approved" is therefore satisfied locally; the run-time check against the collector ledger on a real field run is still unexercised.
- Criterion 8 as quoted allows {200, 302/303 per fixture, attributed 503, 403/404 where the fixture expects them}. My analysis in B1 finds the synthetic origin answers only 200 and 503 for the reviewed cycle, so the tighter set {200, attributed 503} is proposed for the new level; if you approve criterion 8, please say which wording governs.
- Criterion 8 depends on the N-1 change analysed in section B. Criterion 7 needs no code.

## B. N-1 and campaign-ID limit: behavior and compatibility analysis (NOT implemented)
### B1. N-1 — client-visible status allow-list
**What the code does today.** `lab/defense/reconcile.ts` rejects unreviewed statuses only inside the N=2 branch (identity `g2.n2_no_unexplained_status`: 429, and 5xx other than an attributed 503). `lab/defense/external-accounting.ts` E8 (`e8.no_other_5xx`) covers 5xx for every level. Nothing bounds 2xx/3xx/4xx for the N=1 level `ba0-l7-c1`: a plane answering 404 on every route would be VALID unless the canary catches it at baseline (documented in the C1 audit).
**Why M1 needs it.** M1 is built on the N=1 level, and its goal is "legitimate users keep working"; a level that cannot say "only 200 and attributed 503 occurred" cannot support that claim for the generator's own traffic.
**Proposed narrow behavior.** A new identity evaluated only when the level is a NEW level id (working name `ba0-l7-c1-m1`, same fixture cycle, rate, duration and thresholds as `ba0-l7-c1`): every status in the generator report and in the server `statusHistogram` must be in `{200, 503}` and every 503 must be an attributed `mutation/unverified/lane_budget` shed. The set is derived from the fixture cycle (GET routes return 200 from the synthetic origin; the POST returns 200 "state" or is shed 503), and must be confirmed empirically in a local run before it is pinned.
**Contracts affected if done as a modification of existing levels (rejected option).** `lab/defense/reconcile.ts` is byte-pinned to all three baselines; the aff793e guard asserts `finalFrom(...)` equals the historical implementation for C1/C2 fixtures, and the baseline-diagnostics guard asserts the full ORDERED identity-name list of the baseline commit. Adding an identity to C1/C2 would break both and would rewrite historical verdict semantics. **So the change must be additive: a new level id, new thresholds object with its own fingerprint, identity added only for that id.** Existing fingerprints (`5f7fbb86…`, `cf56f4e3…`) and the reviewed workloads stay untouched.
**Files touched (all migration-registry events):** `lab/defense/field-thresholds.ts` (new level in `FIELD_LEVELS`), `lab/defense/reconcile.ts` (conditional identity), `lab/policy/workloads.ts` (new workload entry referencing the same cycle), `lab/defense/ba0-field-run.ts` / `lab/run.ts` (level registry; not pinned today).
**Tests:** (1) historical fixtures: C1, C2, salvo `finalFrom` outputs unchanged (the existing aff793e guard); (2) new level: statuses {200, attributed 503} → VALID; each of 404, 403, 302, 429, 500, an unattributed 503, in either the generator report or the server histogram → INVALID with a named reason; (3) fingerprint pin of the new thresholds; (4) real-plane local run with an injected all-404 origin proves detection (this is the case that was VALID before).
**Risk:** the allow-list could be too tight for a legitimate origin response (e.g. a redirect); the empirical confirmation in step "Proposed" is mandatory and the set is part of the pinned fingerprint.

### B2. Campaign-ID limit
**What happens today.** `campaignIdPattern = /^[a-z0-9][a-z0-9-]{5,40}$/` (6–41 chars) is accepted at argument parsing (`lab/run.ts`, `lab/defense/ba0-field-run.ts`), but `lab/evidence/redact.ts` refuses any 32+ character `[A-Za-z0-9_+/=-]` string as a "long token-like string". Verified locally: a campaign id of 31 characters is accepted by the evidence scanner, 32, 33 and 41 are refused (`$.campaignId: long token-like string`), so a 32–41 character id passes parsing and then fails late, after the level ran.
**Why M1 needs it.** M1 requires three runs, each with its own campaign id; losing a run's evidence to a late scanner refusal costs a repeat and, worse, a possible INVALID on a run that was fine.
**Proposed narrow behavior.** Refuse a campaign id longer than 31 characters at argument parsing, with the existing refusal message class. Do NOT change the shared pattern constant or the scanner.
**Compatibility.** The constant `campaignIdPattern` lives in `generator-report.ts`, which is byte-pinned; the two parse sites (`lab/run.ts:256`, `lab/defense/ba0-field-run.ts:686`) are not covered by any pathspec, so the change can be made there without a baseline migration (add `&& id.length <= 31`). Historical campaign ids are shorter (e.g. `first-gcp-n2-salvo-r2`, 21 chars); no test fixture uses 32+ characters (searched `tests/` and `lab/`). Report builders, fingerprints and evidence keys are unaffected (the id is not part of any fingerprint).
**Tests:** boundary 31 accepted, 32 refused at parse time for both entry points; scanner behavior unchanged (a 32-char id still refused by `assertEvidenceSafe`); a full dry run with a 31-char id reaches evidence writing.

## C. Export-key emergency revocation — design comparison (design only)
Scope note: the export guard belongs to the Cloudflare lifecycle path, not to the L1/L2 defense plane; "control-plane dependency for the defense data plane" is read as "revocation must not add a runtime dependency to the guard's request path that can make exports or lifecycle operations unavailable".

| | 1. Deployment-based | 2. Durable Object-backed state | 3. Short-lived keys + deployment revocation (recommended) |
|---|---|---|---|
| Mechanism | remove/mark the key in `GUARD_EXPORT_KEYS`, redeploy guard Worker | guard stores revoked fingerprints in its SQLite, a signed revoke method writes them | keys carry a finite `notAfterMs` of **≤ 24 h hard cap (default ≤ 8 h, issued per export session)**; emergency = deployment; expiry is the backstop |
| Latency | operator detection + deploy time (typically seconds to a minute [I, not measured]); unbounded if deploy is impossible | next request (milliseconds) | min(time to deploy, remaining validity ≤ 24 h) — a **bounded** worst case even if the deploy path itself is down |
| Failure behavior | failed deploy ⇒ old key stays valid (revocation fails open until deploy succeeds) | revoke-write failure ⇒ key stays valid; storage read failure ⇒ export refused (fail closed) | same as 1, but the exposure is capped by expiry |
| Availability | none on the data path | adds a write path and a table to the guard | none |
| Persistent-state / boundary impact | none | **adds a table: guard DDL changes**, which the R06 rehearsal pins ("identical old/HEAD Authority and guard DDL"); new write authority (lifecycle key, or a third key to custody); a compromised revoker can deny exports (fail closed) | none beyond the key-set validator already planned |
| Custody | public keys only in config | revoke-signing key to custody and rotate | pre-generated, sealed **standby** export key so revocation never leaves forensics blocked |
| Tests | T7 (removed key refuses same bytes), T9 config matrix | new: revoke idempotence, replay, DDL parity, storage-failure matrix | T4/T6/T7/T9 plus: validity cap enforced (> 24 h rejected by the validator), expired key refused at the boundary instant, standby activation rehearsal, **measured deploy-to-effect time in staging** recorded as evidence |

**Recommendation:** option 3. It gives a *bounded* revocation latency without touching the guard's persistent schema, without a new write authority and without any runtime dependency; option 2's only advantage (instant) is bought with a DDL change that the existing pinned rehearsal exists to forbid and with a second secret to protect. Emergency revocation removes the affected key at once and does not wait for the 24 h planned-overlap window. A deployment is described everywhere as **"effective when the new guard version is serving"**, never as instantaneous.
**Open for you:** the validity cap (24 h proposed as hard cap, 8 h default) and whether staging two-key rehearsal must also rehearse a failed deploy.

## D. Cloud planning status (D7)
**Primary-source check performed 2026-11-08.**
- Google Cloud support page *Penetration testing / security testing* (support.google.com/cloud/answer/6262505, fetched): "you are not required to contact us"; testers must "abide by the Cloud Platform Acceptable Use Policy and Terms of Service, and ensure that your tests only affect your projects (and not other customers' applications)". The page does not itself list denial of service, load testing or quotas.
- The Acceptable Use Policy text itself (cloud.google.com/terms/aup) **could not be retrieved** by my tooling (the page returns title only). Secondary sources claim DoS/stress tests are prohibited; that is unverified.
**Status of external stress testing: BLOCKED** until a human reads the current AUP and Terms of Service, records the clause numbers that govern a 25 requests/second functional test whose purpose is to provoke bounded shed behavior, and, if there is doubt, obtains Google's written answer. M1's load (≤ 25 req/s, one source, one project, no third party) is far from a flood, but "stress test" language is the reason for the block, not the rate.
**Still unverified (need your account):** quotas in europe-west3, credit eligibility and expiry, current machine-type availability, actual prices (the figures in `QUALIFICATION-CLOUD-PLAN.md` are third-party aggregator numbers).
**Budget alerts are not spending limits** (confirmed by Google's own documentation of budgets as notifications; hard stops need automation). Independently enforceable stop and teardown, four layers that do not share a failure mode:
1. **On the VM, harness-independent:** every lab service runs under systemd with `RuntimeMaxSec` (plane and generator ≤ the level's hard cap) and a `shutdown -P +N` timer armed at bootstrap before any listener starts; a hung harness cannot extend life.
2. **Cloud-side lifetime:** a Compute Engine maximum run duration / termination action on each instance, so a VM deletes or stops itself even if the guest is unreachable [I: confirm the exact current feature and its console/CLI name in primary docs].
3. **Billing:** a budget → Pub/Sub → small automation that stops or deletes the lab VMs (and, as last resort, detaches billing from the lab project). Must be exercised in an empty throwaway project and its trigger-to-effect time recorded **before** any real run; alert delay is a documented property of budgets, so the VM-level limits (1, 2) are the primary bound and billing is the backstop.
4. **Operator kill switch:** a pre-written `gcloud` firewall-rule or instance-stop command pair, tested from the workstation, that does not use the harness.
**Teardown:** evidence pulled and hash-verified first; `sut-teardown.sh` marker logic; then deletion of VMs, disks, firewall rules, VPC; project left empty.

## E. Remaining blockers before the first isolated qualification
1. Approval of criteria 7–9 (section A).
2. Approval and implementation of N-1 (new level id) and N-2 (parse-time limit), each with its tests.
3. Baseline migration decisions: wiring patch for the registry into the three guards (`PROPOSED-BASELINE-MIGRATION-TEST-WIRING.patch`), then entry reviews (28 candidates; 11 independent reviews; 5 pending the export-key decision).
4. AUP/Terms review by a human; quotas, credit, prices from the account (D7).
5. The independent stop/teardown mechanism built and rehearsed in an empty project.
6. A local dress rehearsal (`lab:ba0:field -- --selftest`, `lab:parity`) re-run with the new instrumentation.
