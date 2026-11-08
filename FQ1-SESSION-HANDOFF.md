# LimitMark — Session Handoff (canonical)

**Reading order:** Part A (below) is the CURRENT state as of 2026-11-08 and supersedes everything after it. Part B (from "HISTORICAL" onward) is the preserved FQ1-era handoff written at HEAD `fbd5128`; its statements about HEAD, test counts and "next actions" are historical and are NOT current. Labels: **[VERIFIED]** = checked against Git/files while writing this handoff; **[RECORDED]** = taken from earlier session evidence, not re-run now; **[DECISION]** = owner decision; **[PROPOSAL]** = designed, not authorized; **[BLOCKER]**.

# PART A — CURRENT STATE (2026-11-08, end of the "M1 Baseline Migration and Qualification Preparation" session)

## A1. Repository and Git state [VERIFIED]
- Path `C:\Users\Emir\Desktop\pentest-website`, branch `feat/capacity-engineering`, remote `origin` = github.com/emircanunlutas/limitmark. HEAD when this handoff was written: `3192163160de767a970dbeee6f19843618e8c9e2`; the canonical rewrite commit `87b553c93e203a987144312f25926810cf9328b6` followed it and was the verified HEAD at the start of the next session (`git log -1` is authoritative). Nothing was pushed: there is no `origin/feat/capacity-engineering` ref, and the branch is 99 commits ahead of local `master` and 101 ahead of `origin/master` (`git log <ref>..HEAD`). `master` is untouched.
- Working tree: only untracked files. Tracked changes: none.
- Untracked files: `GATE-11A-LOCAL-HARDENING-REPORT.md`, `GUARD-GENERATION-MARGIN-REVIEW.md`, `GUARD-GENERATION-RECOVERY-DESIGN.md`, `PRODUCTION-DESIGN-REPORT.md`, `PRODUCTION-READINESS-REPORT.md` (owner-facing reports, intentionally not committed), `audit-report.json`, `ba0-c1-tag.bundle`. The audit package directory `LimitMark-C1-Audit-Package/` exists on disk and is hidden from `git status` by `.git/info/exclude` (line 9) [VERIFIED]; it is untracked and protected.
- **Protected, never stage/modify/delete/clean/reset:** `audit-report.json`, `ba0-c1-tag.bundle`, `LimitMark-C1-Audit-Package/`, the untracked reports above, the Wrangler OAuth session (**never run `wrangler logout`**). No push. No force operations.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Stage by explicit path.
- Recent commits (newest first; all local): `3192163` handoff update; `be90516` two-entry instrumentation approval package, N-1 design, M1 criteria status, export-key lifetimes/revocation design; `507ea6b` campaign ID max 31 (N-2) with tests; `531862e` origin-delivery-count tests on/off; `9929d65` migration registry wired into the three historical guards; `c3db7b5` handoff; `25e9649`/`cc5b112` private-target (RFC1918) tests; `9b23a6b` M1 decisions package; `2511a8a` proposed wiring patch; `7c43775` migration registry (44 PENDING); `040292b` outcome tally wired into plane runtime; `3156a68` readiness note; `b9cb337`/`3369f81`/`82045e3` tally module and cross-checks; `bc32500` baseline v2 acceptance package, M1 design, cloud plan, export-key plan; `3ae37bd` independent readiness; `ed07dd3` baseline v2 file review + export signing design v2; `e4f8267` hygiene fixes (dockerignore, fault-hook guard allowlist); `b3b52ab`, `f91b277`, `17d9218`, `6212ccf`, `ba65541`, `655d58a`, `1720e9f` production security corrections.

## A2. Product intent (unchanged) [DECISION]
LimitMark is intended to become an **independent Customer Defense Plane**, not a Cloudflare-dependent add-on. Principle: **"Every layer assumes the layer before it may have failed."** Cloudflare is optional and additive; Cloudflare security decisions are never credited to LimitMark. The defense/data plane must keep working when the control plane is unavailable. Onboarding should stay simple. Primary qualification objective: legitimate-user continuity under adverse traffic.
Four separate workstreams, never to be conflated:
1. **Independent L1/L2 defense qualification (M1)** — the existing application-plane defense.
2. **Future L3/network isolation and volumetric (n3/t4) capabilities** — NOT implemented.
3. **Cloudflare Workers / Vercel inquiry-admission qualification** — separate track.
4. **Production provisioning and lifecycle gates (9, 10, 11A, 12, 17)** — all closed.

## A3. What the code actually implements [VERIFIED from earlier code inspection; absences confirmed]
- **L1 `a7.shape-gate`** (`defense/`): stateless shape/grammar gate; 22 reject reasons plus 3 semantic and 2 lane reasons; fail-closed.
- **L2 `a7.journey-lanes`**: global credited/unverified token buckets, Bloom-filter token provenance; no per-sender input, no spill, no refunds. The only reviewed shed is `mutation/unverified/lane_budget`.
- **Origin boundary**: Slice 2 Boundary/App hop proofs; claims application non-bypass only.
- **Field-run infrastructure**: level `ba0-l7-c1` (60 s, ≤25 req/s, 1 worker, cycle GET `/`, `/gizlilik`, `/test-talep-et`, POST `/api/public-inquiries`), correlated lifecycle ledger/collector, per-layer accounting and reconciliation (identities E1..E11), legitimate-user canary (JCR 100%, window p95 ≤ 4×baseline + 150 ms), resource ceilings (CPU 80%, memory 15% available, ELD p99 250 ms, RSS 512 MB, fds 70%), recovery quiet period 135 s, 1 s ticks.
- **NOT implemented (confirmed absent):** L3 network isolation; n3/t4 volumetric layers; TLS handling in the plane; per-source limiting; adaptive control; quarantine. Do not claim them.

## A4. Instrumentation [VERIFIED present; results RECORDED]
- Files: `lab/defense/outcome-counters.ts` (source of truth for tests), identical in-tree copy `defense/core/outcome-counters.ts` (a test pins equality after import-path normalization), `lab/defense/plane-outcome-check.ts` (identities I1–I12, `compareToLedger`), `lab/defense/outcome-benchmark.ts`, wiring in `defense/plane/runtime.ts` (commit `040292b`). Tests: `tests/defense-outcome-counters.test.ts`, `tests/defense-plane-instrumentation.test.ts`.
- Behavior: counters exist only when plane telemetry ticks run (tickMs integer 100..10000); `countingEmit` observes each event and returns the same sequence number; `observe` swallows exceptions and counts faults; ticks gain an `outcomes` snapshot (null when disabled). Closed key spaces (hostile values land in `unknown`), positional reject-reason keys (`r00…`), dot-joined L2 keys, snapshot < 8 000 bytes, no nonce/address/header/path content (evidence-scanner compatible).
- Evidence: instrumentation on/off equivalence on a real plane process (identical statuses, identical ordered event stream); origin receipts = plane egress attempts − failures, on and off; mutation check (a wrapper returning `seq+1` fails 7 field-run tests); `lab:ba0` and `lab:ba0:origin` outputs identical before/after wiring (0 differing lines after normalizing run ids/timings, 27 and 67 lines); overhead ≈ 49 ns/event, paired end-to-end delta ≈ −0.0023 ms (noise). **Limits:** equivalence shown on a 15-request workload and the existing field-run suite, not on a Linux field host; tally does not see pre-parser traffic or kernel drops (`not_measured`); a fault inside `observe` is counted but not surfaced to a verdict.
- **Proposed only (not implemented):** the N-1 status overlay (A8), the export-key v2 verifier (A9).

## A5. Baseline migration — CRITICAL [VERIFIED]
- Historical baselines: `64ccc9d` (canary continuity), `dcf10af8` (salvo diagnostics), `aff793e` (salvo). Three byte-identity guards diff whole trees (`defense`, `src`, `workers`, `lab/policy`, `lab/evidence`, listed lab/defense files) against those commits: `tests/lab-ba0-canary-continuity.test.ts`, `tests/lab-ba0-salvo-diagnostics.test.ts`, `tests/lab-ba0-salvo.test.ts`. Any edit OR new file in those trees is drift. Untracked files are invisible to git-diff tests — always re-run in a clean checkout after committing.
- Original mechanism: `tests/support/reviewed-patches.ts` (6 defense files). New mechanism: append-only versioned `tests/support/reviewed-migrations.ts` (+ `tests/reviewed-migrations.test.ts`) with 44 entries and `withoutReviewedChanges` / `classifyDrift` / `assertMigrationBoundary`, wired into the three guards in `9929d65` (`PROPOSED-BASELINE-MIGRATION-TEST-WIRING.patch` retained as record).
- **Counts [VERIFIED by grep now]: 44 entries, 44 `PENDING`, 0 `APPROVED`. By hold: 28 `none`, 11 `shared-production-module`, 5 `guard-export`.** Composition: 2 instrumentation entries (need an independent second review), 26 other acceptance candidates (two conditions open: OIDC claim-check confirmation, telemetry label-set re-check), 11 shared-production-module entries (independent review required), 5 guard-export entries (hold pending the export-key decision and implementation; they will change again).
- Classification: **authorized** (APPROVED and effective), **pending** (PENDING — exempts nothing), **modifiedAfterReview** (working blob differs from the reviewed blob), **unreviewed** (changed path in no entry). An entry is effective only if APPROVED **and** carries `authorization` **and** `scope` **and** a valid `reviewedBlob`; it must bind the historical blob (same at all three baselines, or null for added files) and the reviewed replacement blob (git hash-object) plus LF-normalized `reviewedSha256`. Unbound approval, wrong reviewed blob, wrong historical blob, edit after review, and unregistered changes all keep failing (tested on throwaway repos).
- Measured closure matrix: approving only the 2 instrumentation entries closes the `aff793e` guard; the 28 non-held entries leave the 16 held files failing in the other two guards; all 44 close all three.
- **Expected current failures (clean checkout):** `historical qualification is immutable` (test 947), `files that decide admission… byte-identical to the baseline commit` (1193), `exact aff793e historical C1/C2 parameters… immutable` (1236). They are red because no entry is APPROVED. This is by design; do NOT approve hashes, edit historical evidence, or weaken the guards to make them green.
- Review sequence (no bulk approval): (1) the 2 instrumentation entries — package in `INSTRUMENTATION-MIGRATION-APPROVAL.md` with recommended authorization/scope strings and a reviewer-independence caveat (the author is also the reviewer there, so a second reader is advisable); (2) the 26 accept candidates by `reviewId` group (`BASELINE-V2-ACCEPTANCE-PACKAGE.md`, `BASELINE-V2-FILE-REVIEW.md`); (3) the 11 shared-production-module entries with independent review; (4) the 5 guard-export entries after the export-key decision. Approval is made by the owner editing the registry.

## A6. M1 decisions [DECISION unless noted]
- M1 = independent **L1/L2 application-plane** qualification at `ba0-l7-c1`. Never claim L1/L2/L3.
- **N-1:** overlay approach selected (Option B); **implementation NOT yet authorized**.
- **N-2:** campaign ID max length **31**, implemented (`507ea6b`, `lab/defense/campaign-id.ts`; boundary tests 30/31/32 + malformed).
- Historical level identities, ordering and verdicts stay unchanged.
- The synthetic origin's existing responses govern the first M1 fixture: 200 and attributed 503 only; 302/303 and 403/404 are NOT claimed as covered.
- Criteria 7–9 remain **PENDING final approval**. Linux parity is outstanding. No external qualification traffic has been authorized.

### Exact M1 criteria (from `M1-CRITERIA.md`)
**1–6 are IN FORCE (numbers from the reviewed `ba0-field-v1`; wording is a restatement in `QUALIFICATION-M1-DESIGN.md`):**
1. Legitimate users: JCR = 100% in every required group (baseline, window, residual, recovery); window p95 ≤ 4 × baseline p95 + 150 ms; no canary 5xx; every step 200 with expected content.
2. Accounting: identities E1..E11 hold; ingress = sum of terminal outcomes; zero unresolved; no unexplained request; no unattributed 503; the only shed is `mutation/unverified/lane_budget`; zero bypass.
3. Exposure: continuous proof holds in every tick; no external accept before ARMED.
4. Resources never exceed ceilings: host CPU ≤ 80% (3 ticks), available memory ≥ 15%, plane ELD p99 ≤ 250 ms (3 ticks), RSS ≤ 512 MB, fds ≤ 70%; generator schedule-lag p99 ≤ 50 ms and ELD p99 ≤ 100 ms (otherwise INVALID, not a defense failure).
5. Recovery: after load stops, quiet period 135 s, then recovery journeys all succeed; residual journeys all succeed.
6. Telemetry: gapless 1 s ticks (gap tolerance 2.5 s). [Restored 2026-11-08 by owner decision D1: it is criterion 6 of `QUALIFICATION-M1-DESIGN.md` §3 and matches `telemetry.gapToleranceMs: 2_500` in `lab/defense/field-thresholds.ts`; it had been omitted when `M1-CRITERIA.md` was written. The earlier "no printed criterion 6" discrepancy is resolved; nothing was invented.]

**7–9 as currently written (PENDING; verbatim from `QUALIFICATION-M1-DESIGN.md`):**
7. NEW, repeatability: three independent runs on fresh state (same commit, parameters, fixture cycle) all VALID, with identical shed reason sets and per-run shed share within ±5 percentage points of the median. A single VALID run is a smoke result, not M1.
8. NEW, status allow-list (finding N-1): every client-visible status must be in the predeclared set {200, 302/303 per fixture, 503 attributed to the allowed shed, 403/404 only where the fixture expects them}; any other status is INVALID. This needs a verdict-path change (migration event) and is a prerequisite, not part of the run.
9. NEW, unexplained differences: plane outcome tally (82045e3) vs collector ledger equal per event kind, once wiring is approved (`PROPOSED-INSTRUMENTATION-WIRING.patch`). Until then this criterion is reported `not_measured`, and M1 cannot claim it.

**Proposed revisions (PENDING, not approved):** 7 unchanged in substance. 8 changed to follow the response-contract decision: every client-visible status in both the generator view and the server view ∈ {200, 503}, every 503 attributed to `mutation/unverified/lane_budget`, any other status → M1-INVALID, implemented as an overlay verdict that never alters the existing qualification verdict; coverage of 302/303 and 403/404 not claimed. 9 changed because instrumentation now exists: tally and ledger agree per event kind (`compareToLedger` empty), tally satisfies its identities; absent tally or non-zero `faults`/`unknown` → **failed**, not skipped (wiring applied in `040292b`; its migration entries are PENDING). Approval of 7–9 fixes an acceptance rule only; it authorizes no run, resource or traffic.

## A7. (reserved — see A5 for migration)

## A8. N-1 overlay [PROPOSAL; design in `N1-STATUS-CONTRACT-DESIGN.md`]
Reason for the overlay: a new level id would require edits to four byte-pinned files (`field-thresholds.ts`, `workloads.ts`, `reconcile.ts`, `ba0-field-reconcile.ts`), and `reconcile.ts` must not be modified. The overlay lives in NEW files (`lab/defense/m1-status-contract.ts`, `lab/defense/ba0-m1-reconcile.ts`), first calls the unchanged final-verdict path, writes a separate `m1-verdict.json` (`M1-STATUS-CONTRACT-VALID|INVALID`, scope-labelled). Required properties: never upgrade INVALID; never remove existing reasons; evaluation failure never becomes acceptance; record explicitly whether evaluation occurred; historical reconciliation semantics preserved; independently testable. Checks: generator and server status keys ⊆ {200, 503}; `status503.unexplained == 0`; only cause `mutation.unverified.lane_budget`; base verdict VALID. **Six acceptance criteria (A–F):** A clean fixture → VALID; B each of 302/303/400/403/404/413/429/500/502/504/unknown injected in either view → INVALID (11×2); C unattributed or differently-caused 503 → INVALID; D non-VALID base verdict never upgraded, base reason stays visible; E all-404 origin → INVALID; F historical guards/`finalFrom` outputs unchanged, no pinned file changed. **Open before implementation:** explicit authorization; empirical local-chain histogram confirming {200, 503} before pinning; the "evaluation occurred" marker field name; whether the evaluation-failure state is a distinct verdict label (the design says failure never accepts, but the exact label is unspecified).

## A9. Export-key and lifecycle security [PROPOSAL unless noted]
Docs: `EXPORT-REQUEST-SIGNING-DESIGN.md` (v2), `EXPORT-KEY-IMPLEMENTATION-PLAN.md`, `EXPORT-KEY-REVOCATION-DESIGN.md`. **Approved architectural principles [DECISION]:** dedicated export-request key (not the lifecycle operator key); planned rotation overlap ≤ 24 h; two staging keys; legacy v1 verifier retained in the first commit; fail closed. **Not authorized:** any implementation; any guard-boundary change. Design: Ed25519, domain-separated v2 tuple binding key fingerprint, environment and `expiresAtMs`; individual request expiry exactly 120 s (+ ±120 s freshness); key validity cap 24 h hard / 8 h default — **the cap is a proposal awaiting owner decision**; at most 2 keys; config-selected verifier. Revocation: deployment-based, "effective when the updated verifier is serving" (never "instantaneous"); DO-backed revocation rejected (changes guard DDL pinned by the R06 rehearsal); short-lived keys + deployment recommended. Four quantities kept distinct: key validity, planned overlap, request expiry, emergency revocation latency. Open owner decisions: validity cap; whether staging must rehearse a failed deployment; two-person record per export vs per key issuance.
**Gates:** Production **NO-GO**. Gates 9, 10 and 11A **closed**. Gate 12 (production initialization) **not executed and closed**: a first initialization consumed without a receipt can latch the production guard, so the design correction is unauthorized (see `PRODUCTION-READINESS-REPORT.md`, untracked). Gate 17/launch **closed**: `availableProductionRateLimitProviders` empty, production DB must present a publicly verifiable certificate with `sslmode=verify-full`, Vercel OIDC exchange unverified against real infrastructure, initialization/key provisioning/rollback rehearsal not done (`GATE-11A-LOCAL-HARDENING-REPORT.md`, untracked). Production admission Worker and admin gateway are not deployed (RECORDED from the FQ1-era inspection; not re-checked now).

## A10. Test evidence
Latest actual results (RECORDED from the end of the last session; HEAD has changed since only by documentation — `git diff --stat be90516 HEAD` = FQ1-SESSION-HANDOFF.md only, +3 lines [VERIFIED] — so code-level results are unchanged but were NOT re-run for this handoff):
- `npx tsc --noEmit`: exit 0.
- `npm run test:workers`: exit 0.
- Focused (counters, plane instrumentation, reviewed-migrations, reviewed-patches, private-target, campaign-id, lab-ba0-field-run): 46/46 pass.
- Clean-checkout `npm test` at `be90516`: **1903 tests, 1858 pass, 3 fail, exit 1** — exactly the three historical-immutability guards (947, 1193, 1236). Still accurate for the code at HEAD.
- Main working tree additionally shows 8 repository-scan failures caused by the untracked `LimitMark-C1-Audit-Package/` (RECORDED earlier; not re-measured in the last segment). They are NOT clean-checkout regressions.
- `lab:ba0:field -- --selftest`: SELFTEST-OK (13 artifacts, 0 refused). `lab:ba0`: BASELINE-VALID (JCR 20/20). `lab:ba0:origin`: APP-NON-BYPASS-VALID. These are simulated/local runs, not Linux field qualification.
- **Linux parity (`lab:parity`) has NOT run successfully.** The Docker daemon was not running; nothing was started or pulled. The field runner refuses non-Linux hosts, so no real field run exists. No simulated result may be described as real Linux qualification. Journey thresholds, resource sampling and recovery are verified only through simulated runs.
- Known quirk: one pre-existing cancelled/flaky resend test in `npm test`; do not edit it. Tooling: no `gh`, no python; heredocs with quotes/backticks break — use the Write tool; git worktrees need a `node_modules` junction (PowerShell `New-Item -ItemType Junction`; remove via `(Get-Item).Delete()` before `git worktree remove`).

## A11. Cloud qualification preparation [PROPOSAL; docs: `INDEPENDENT-QUALIFICATION-READINESS.md`, `QUALIFICATION-M1-DESIGN.md`, `QUALIFICATION-CLOUD-PLAN.md`, `M1-CRITERIA.md`, `M1-DECISIONS-PACKAGE.md`]
- Preferred candidate: Google Cloud `europe-west3`; two-VM private-address isolated topology (RFC1918 accepted by the target policy and plane ingress bind — tested); separate origin and defense roles; independent canary and monitoring.
- **Unverified/blocked:** quotas and credit eligibility not verified; provider acceptable-use text was not retrievable → **external stress testing is BLOCKED** until a human confirms the policy; budget alerts are not hard spending limits.
- **Four-layer independent stop** (systemd RuntimeMaxSec/shutdown timer; cloud max-run-duration [to verify]; billing-automation backstop; operator kill switch): designed, **not implemented or rehearsed**.
- **No provisioning is authorized.** Smallest trustworthy M1 = three repeatable VALID runs of the existing `ba0-l7-c1` cycle on an isolated private pair with criteria 1–9; larger-scale or volumetric qualification is a later, separate milestone. No traffic-generation or bypass procedure is designed here.

## A12. Restrictions carried forward
Production NO-GO; Gates 9, 10, 11A closed; no live deployment; no cloud provisioning; no external attack/load traffic; no production activation; no key rotation or initialization; no remote push; no unauthorized security-boundary change; protected files preserved; Wrangler session preserved (no logout). Allowed: local read-only inspection, documentation, tests, local commits. CLAUDE.md requires owner approval for security boundaries, historical evidence/baselines, force-push, credentials, broad refactors.

## A13. Next-session plan (ordered)
1. Verify state: `git status`, `git log -5`, confirm 44 PENDING / 0 APPROVED, read this file, `M1-CRITERIA.md`, `INSTRUMENTATION-MIGRATION-APPROVAL.md`.
2. Obtain an independent review of the two instrumentation entries (this author cannot be the independent reviewer); owner decides on approval and edits the registry (`status`, `authorization`, `scope`). Re-run the three guards in a clean checkout.
3. Prepare the smallest acceptable migration batch: the 26 accept candidates by `reviewId` group, with the two open conditions (OIDC claim-check, telemetry label-set) resolved first.
4. Present criteria 7–9 (A6) for final owner approval; (criteria 1–6 numbering: resolved, criterion 6 restored, see A6.)
5. Review the N-1 overlay contract (A8); implement only after explicit authorization and the empirical histogram.
6. Establish Linux parity prerequisites (Docker/Linux host availability; `lab:parity`); do not start Docker without a decision.
7. Prepare M1 execution readiness (stop mechanism build/rehearsal, AUP human review, quotas/prices) without provisioning or generating traffic.
8. Preserve every production and security restriction; avoid broad feature development before the first isolated qualification milestone is ready.

## A14. Unresolved items and unverified claims
- Criteria 1–6 numbering: RESOLVED (criterion 6, telemetry, restored from `QUALIFICATION-M1-DESIGN.md`; see A6). Gate 12/17 status is taken from untracked reports and the runbook, not re-derived. The 8 audit-package failures and production/gateway non-deployment were not re-measured. Docker state not re-checked. The owner's N-1 "overlay selected" is recorded from the owner's handoff instruction; the prior session had presented it as a recommendation. Remote state of the branch is unknown (no remote-tracking ref).
- Reviewer independence for the two instrumentation entries is not satisfied by the author.
- A7 above is intentionally empty (numbering retained to avoid renumbering references).

## A15. Update (owner decisions 2026-11-08, later session) [VERIFIED by tests in this repo]
- Migration registry: the two instrumentation entries are APPROVED (`defense/core/outcome-counters.ts`, `defense/plane/runtime.ts`; the owner named the lab copy, but the registered entry is the in-tree one); 42 remain PENDING. The `aff793e` guard passes; the `64ccc9d` and `dcf10af8` guards stay red for the 42. `tests/reviewed-migrations.test.ts` now pins exactly those two approvals. No other approval is authorized; the first baseline batch is under review (joint reviews: ingress-signer index+signer, test-talep-et page+launch policy; large lab modules need a full review).
- M1 criteria 7 to 9 are APPROVED (see `M1-CRITERIA.md`). N-1 overlay implemented locally in new files only (`lab/defense/m1-status-contract.ts`, `lab/defense/ba0-m1-reconcile.ts`, `tests/m1-status-contract.test.ts`); outcomes PASS | REJECT | ERROR; empirical real-chain histogram {200, 503}. Not yet run on a field run. Criterion 9 tooling and criterion 7 aggregation are not implemented.
- Export-key: fail-closed migration design in `EXPORT-KEY-FAILCLOSED-MIGRATION-DESIGN.md` (design only; validity cap undecided).

---

# PART B — HISTORICAL: FQ1-era handoff (written at HEAD `fbd5128`; superseded by Part A)

Written 2026-11-08 at the end of the "Shared Admission Reliability: Deployment Preflight" session.
Repo: `C:\Users\Emir\Desktop\pentest-website`, branch `feat/capacity-engineering`, HEAD at that time `fbd512808a7d5194da0d79730ad05b68b85c201b`.
Lab domain: `lab.limitmark.com`. GCP project: `limitmark-field-qual`. Cloudflare account: `a779e0b2506f4ed0272e6eff7bc91449`.
Statements are labelled **[DIRECT]** (observed output/logs/DB/test result), **[INFERRED]** (control-flow reasoning), or **[UNVERIFIED]**.
Gaps in my knowledge are stated as gaps. Earlier-session details that I could not re-verify from this session's summary are marked as such.

---

## 0. Project identity and architecture

- **Objective:** LimitMark is a Customer Defense Plane: it keeps a customer's service available to legitimate users while the service is under attack or abusive load.
- **Layered defense.** Principle: **"Every layer assumes the layer before it may have failed."** No layer may trust that an upstream layer filtered anything. Fail-closed behavior is mandatory in security-critical layers.
- **Control plane vs customer defense/data plane.** The control plane is operator/admin tooling: the admin gateway, operator-signed lifecycle commands, authority initialization and rotation. The customer defense/data plane is the path that real customer traffic takes: ingress signer, admission service (PRE/POST), the app, the database. They are separate on purpose, so that a control-plane fault does not take down the data plane and a data-plane flood cannot reach control-plane authority.
- **Legitimate users must stay unaffected during attacks.** Every defense decision should be judged by what it does to legitimate-user availability. Rollback and deployment plans prioritize this.
- **Per-layer measurement.** Each layer needs its own traffic accounting, canary success metrics and recovery metrics. Without per-layer numbers you cannot say which layer failed or recovered. Most of this is not yet built/qualified for the lab flow (see Open Risks).

---

## 1. VERIFIED FACTS

### 1.1 FQ1 laboratory qualification (owner accepted functional, persistence and sequential replay as PASS)

| Item | Evidence | Class |
|---|---|---|
| Browser inquiry submission through `lab.limitmark.com` succeeded and redirected | Browser run in an earlier session, owner-observed; one submission after the final lab fix | [DIRECT] (earlier session) |
| Cloudflare signer → Cloud Run integration | Request reached Cloud Run revision `limitmark-public-inquiry-lab-00005-bz7`; submission completed | [DIRECT] (earlier session) |
| Admission PRE and POST | Lab admission Worker `limitmark-admission-service-lab` version `88b69c16-e9c0-4f54-a1c8-57b8309e599c`; `wrangler tail`-based and replay-Job evidence (PRE allowed + permit, POST allowed) | [DIRECT] |
| Turnstile verification | The inquiry flow order is: schema parse → Turnstile token required → `claimPre` → Turnstile verify (real `CloudflareTurnstileVerifier`, non-test keys) → `consumePost` → DB create. The submission succeeded, which can only happen if verify passed. There is **no direct Turnstile log line**. | [INFERRED] from control flow. Limitation: no direct evidence of the Turnstile verdict itself. |
| PostgreSQL persistence | One SELECT-only IAP-SSH session (window 2026-11-07T23:25:20Z–23:25:40Z) showed the `inquiries` row, `inquiry_events` `inquiry_received`, and `notification_outbox` row with status `pending` | [DIRECT] |
| Sequential live replay qualification | Temporary Cloud Run Job ran exactly 4 sequential requests with a fresh synthetic identity: PRE allowed → POST allowed → replayed POST = `replay` → replayed PRE = `replay`. Script: `C:\Users\Emir\AppData\Local\Temp\claude\ae48934e1bc5acfd\0bd4e6fd-b000-4312-8ede-33b45793da8c\scratchpad\replay-job.js` | [DIRECT] |
| Temporary Cloud Run Job cleanup | Job deleted after the run | [DIRECT] (earlier session) |

### 1.2 NOT tested — do not claim PASS
- Concurrency (live)
- Restart persistence (live)
- Permit expiry (live)
- Load testing
- Outbox delivery (no consumer is deployed; the outbox row stays `pending`)

### 1.3 Defects found and fixed locally (workerd-reproduced)
1. **Shared JWKS resolver "Illegal invocation".** `workers/shared/bounded-jwks.ts` stored native `fetch` as `this.request` and called it as a method, which throws in Workers. Every JWKS load failed, so every token failed closed. Fixed by calling it as a plain function (wrapper).
2. **Cached Durable Object stub.** `workers/admission-service/index.ts` kept a DO stub created in the first request inside the cached handler; later requests failed with "Cannot perform I/O on behalf of a different request" (503). Fixed by resolving the stub per call in `configure()`.
3. **Admin gateway real entrypoint.** `workers/admin-gateway/index.ts` re-exported `ADMIN_GATEWAY_HOST` and `createAdminGateway` next to the default handler. workerd rejects non-handler exports ("Incorrect type for map entry 'ADMIN_GATEWAY_HOST'"), so the real wrangler dry-run bundle could not load. My earlier test used a test-only wrapper that hid this. Fixed by exporting only the default handler.

---

## 2. COMPLETED WORK

### 2.1 Local Git history (verified with `git log` this session; all unpushed)

Branch `feat/capacity-engineering` has no `origin/feat/capacity-engineering` ref (the remote-tracking branch is unknown to this clone), so "unpushed" is established from the standing rule that nothing was pushed, not from a remote diff.

| SHA | Purpose |
|---|---|
| `4be1b10` | Lab admission Worker: plain-function `fetch` for the Google OIDC verifier; per-request DO stub in the lab handler. Adds `tests/workers/lab-jwks-fetch.integration.ts` and `tests/lab-jwks-fetch-wrapper.test.ts` |
| `653d522` | Shared fix: `BoundedRs256JwksResolver` wraps `fetch`; production/staging handler resolves the DO stub per request. Adds `tests/workers/shared-admission-reliability.integration.ts`, updates the wrapper test, `package.json` scripts |
| `e1a65ce` | Admin gateway entry exports only the default handler; integration test now runs the real `workers/admin-gateway/index.ts`; test-only wrapper `tests/workers/support/admin-gateway-entry.ts` deleted |
| `fbd5128` | Adds `tests/workers/jwks-concurrency.integration.ts` and the `test:workers:jwks-concurrency` script (also appended to `test:workers`) |

Earlier unpushed lab commits: `5cb11f3`, `7937bcc`, `573b807`, plus `a04e184` and a lab-environment commit `38fec4d` (noted in memory as unpushed; not re-checked this session).

Working tree at handoff: only `audit-report.json` and `ba0-c1-tag.bundle` are untracked. Both are preserved unchanged and must never be staged.
Commit trailer in use: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Stage by explicit path.

### 2.2 Preflight findings
- **Admin gateway:** see 1.3 item 3. After the fix, `wrangler deploy --dry-run` produces a bundle whose only export is `default`; the real entry passes the shared-reliability integration test in workerd.
- **Staging architecture** [DIRECT for deployed/observed, INFERRED for intent]: dormant (no routes, no custom domain, workers.dev off, previews off). Deployed bundle is older than the source: deployed handlers are `fetch, initializeAuthorityFromOperator, rotateAuthorityReleaseFromOperator`; source has the `...Attested` variants. `StagingAdmissionAuthority` has no `claimPre`/`consumePost`; the shared fix does not change staging behavior. Recommendation: do not deploy staging for this fix (it would ship unrelated drift).
- **JWKS concurrency (workerd, real gateway entry, `tests/workers/jwks-concurrency.integration.ts`):** all pass, no defect reproduced.
  - 6 overlapping initial requests → all 200, exactly 1 JWKS fetch; later requests reuse cache, no extra fetch.
  - Initiating client aborts mid-acquisition → concurrent request still succeeds.
  - Failed fetch → every overlapping request 403, 1 fetch; within the 30 s cooldown stays closed with no refetch; after cooldown (the test waits 31 s) recovers and caches.
  - Hanging endpoint → bounded by the 2 s timeout, all 403 in under 8 s, upstream never reached.
- **Dry-runs** (non-uploading `wrangler deploy --config <rendered> --dry-run --outdir <rel>`, synthetic values, temp files deleted):
  - Production admission: builds, 154.64 KiB; `AUTHORITY` → `ProductionAdmissionAuthority`; migration `production-v1`; route `admission-rpc.limitmark.com` custom domain; vars as in `deployment/admission-service.template.jsonc`.
  - Staging admission: builds; bindings `AUTHORITY` → `StagingAdmissionAuthority` and `AUTHORITY_OPERATOR_PUBLIC_KEY`, same as deployed `d8f0818b`. Deployed version additionally has the secret `ADMISSION_CURRENT_RPC_KEY` and older handlers.
  - Admin gateway: builds; vars `VERCEL_ADMIN_UPSTREAM_ORIGIN`, `CLOUDFLARE_ACCESS_TEAM_DOMAIN`, `CLOUDFLARE_ACCESS_AUD`, `ADMIN_ALLOWED_EMAIL`; the secret `VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET` is not part of the dry-run. Route `admin.limitmark.com/*` on zone `limitmark.com`.
  - Note: `deployment/admission-service.staging.jsonc` is a sentinel string, not a config; render from `admission-service.staging.template.jsonc`.
  - Note: the admission bundle also exports `createAdmissionService` / `createVercelOidcVerifier` (functions). These load in workerd (lab deploy and integration tests prove it); only non-function exports such as the gateway string constant broke loading.

### 2.3 Test results
- `npx tsc --noEmit`: clean.
- `npm test`: 1780 tests, 1670 pass, 15 fail, 0 cancelled.
- `npm run test:workers`: exit 0 (includes lab, shared-reliability, concurrency, R06, staging suites).
- **Baseline caveat:** the 15 failures match the earlier baseline *by count only*. Identical failing test identities have NOT been verified. Memory also notes one pre-existing cancelled/flaky resend test; the last run showed 0 cancelled.

---

## 3. CURRENT INFRASTRUCTURE STATE

### Lab (deployed)
- Admission Worker `limitmark-admission-service-lab`: version `88b69c16-e9c0-4f54-a1c8-57b8309e599c` at 100%; earlier versions `92820d04`, `4cacd0aa`. Entry: `LabAdmissionServiceWorker`; DO `LabAdmissionAuthority`.
- Cloud Run service `limitmark-public-inquiry-lab`, revision `limitmark-public-inquiry-lab-00005-bz7`, image `limitmark-app@sha256:dfaaa0cd03a5a048bd200b723dc79c89a2d81ff111a2b8868e94cc049ef3b606`.
- Database: GCE VM `limitmark-lab-postgres` (10.80.0.6, private, TLS), **not Cloud SQL**. Access: IAP SSH + OS Login.
- Lab configs: `deployment/admission-service.lab.jsonc`, `deployment/cloud-run-lab.yaml`, `deployment/public-signer.cloud-run-lab.jsonc`, Terraform in `deployment/terraform`.

### Staging (deployed, dormant)
- `limitmark-admission-service-staging`: `d8f0818b-be93-4bf1-acae-3cee943ad9f0` at 100% (source "Secret Change", 2026-09-23); previous `877ba1f2-a435-4ec7-95bc-dcf3f42d1501` (2026-09-21 upload). No routes.
- Staging mailbox `676c0935` and observer `4826b589` exist (from the Phase 1 baseline; I did not re-verify the full IDs).
- Which staging executor Worker name is the real one: **[UNVERIFIED]**.

### Production
- **Production admission Worker (`limitmark-admission-service-production`) is NOT deployed in the inspected Cloudflare account.**
- **Admin gateway Worker is NOT deployed in the inspected Cloudflare account.**
- Templates exist and are unrendered: `deployment/admission-service.template.jsonc`, `deployment/admin-gateway.template.jsonc`, plus lifecycle/executor/signer templates.

### Known configuration drift
- Staging deployed bundle vs source (handlers; secrets).
- Production/gateway: no deployed counterpart to compare.
- Templates contain `__REQUIRED_*__` placeholders that must be supplied at render time.

---

## 4. AUTHORIZATION BOUNDARIES

Source: `CLAUDE.md` plus the owner's per-phase authorizations.

**Permitted without further approval:** read-only investigation; local code inspection and corrections within explicitly authorized scope; local regression tests; non-uploading dry-runs (only with tools that cannot upload/activate); local commits; preparing deployment and rollback plans.

**Requires explicit owner approval:** live deployments or uploading Worker versions; creating/changing routes; IAM changes; provisioning/modifying secrets; creating production Durable Objects or migrations; modifying live infrastructure; production or staging synthetic traffic; load/attack tests; database mutations; git push (and any change to `master`); destructive cleanup (force push, reset, branch deletion, history rewrite); authentication/admission-protocol semantic changes; DO schema changes.

**Always:** never weaken tests or fail-closed behavior; never print secrets/tokens; never stage `audit-report.json` or `ba0-c1-tag.bundle`; preserve historical INVALID verdicts and evidence.

**Wrangler OAuth session:** the user logged in themselves (`npx wrangler login`). **Do not run `wrangler logout`.**

---

## 5. OPEN RISKS

1. **First-ever production admission deployment** — needs rendered config, operator + attestation keys, Vercel OIDC values (issuer, audience, subject, owner/project IDs), current release/key IDs, RPC key secret, DO initialization via an operator-signed command. The DO is created fresh with migration `production-v1`.
2. **First-ever admin gateway deployment** — needs Access team domain/AUD, allowed admin email, upstream origin, route on zone `limitmark.com`, and `VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET`.
3. **Rollback has no prior version** for production admission and the gateway. Rolling back must not destroy DO state: prefer detaching the route/custom domain over deleting the Worker. The owner has not yet chosen.
4. **Staging deploy drift** — a staging deploy would ship unrelated handler changes; secrets/vars required by the new bundle on staging are unchecked.
5. **Baseline test failures** — 15 failing tests; identities not diffed against the earlier baseline.
6. **Remaining FQ1 gaps** — concurrency, restart, expiry, load, outbox delivery (no consumer deployed), no direct Turnstile log.
7. **R2 least-privilege credentials** — scoped tokens still to be created; the `wrangler logout` decision rests with the owner.
8. **Invoker key rotation deadline: 2027-02-05.**
9. **Collector descriptor race** — noted in earlier sessions; not investigated this session.
10. **Cloud Run `cpu-throttling:false` cost observation** — noted, unresolved.
11. **Scratchpad logs** — one (`fix-signer.log`) may contain the user's IP; scratch dir is `C:\Users\Emir\AppData\Local\Temp\claude\ae48934e1bc5acfd\0bd4e6fd-b000-4312-8ede-33b45793da8c\scratchpad\`.
12. **First-init-command finding** from earlier sessions: details not recoverable from this session's summary.
13. **Shared in-flight JWKS `refresh` promise** — tested in workerd for overlap/abort/failure; still not exercised on a live deployment.

---

## 6. UNVERIFIED ASSUMPTIONS

- The 15 failing tests are the same tests as in the earlier baseline.
- Real staging executor Worker name.
- That the new bundle deploys to staging without extra attestation secrets/vars.
- That production Vercel OIDC values and operator keys exist anywhere outside the repo.
- That nothing else in the account (other zones/routes) conflicts with `admin.limitmark.com/*` or `admission-rpc.limitmark.com` — only inspected in Phase 1 of this session.
- Whether `origin` has the branch (no remote-tracking ref in the clone).
- Turnstile verdict (control-flow inference only).

---

## 7. NEXT RECOMMENDED ACTIONS

(Each live step needs fresh explicit owner approval.)

1. Run `npm test` and diff failing test names against the stored baseline; record the result.
2. Decide the rollback strategy for first-ever deploys (detach route/custom domain vs delete Worker) and write it into the plan.
3. Provision production inputs (owner action): operator/attestation keys, Vercel OIDC identifiers, RPC key, current release/key IDs. Render configs into a temp directory, never commit rendered values.
4. Re-run the non-uploading dry-run against the real rendered config for production admission, then the gateway.
5. With approval: deploy production admission first; verify with one PRE→POST pair and a replay; then deploy the admin gateway (expect 403 without an Access assertion).
6. Hold staging. Revisit only as a dedicated change with its own drift review.
7. Plan a controlled live test for concurrency, restart and permit expiry; design the outbox consumer before testing delivery.
8. Handle R2 least-privilege tokens, the invoker key rotation (by 2027-02-05), and the collector descriptor race.

### Useful commands
- Tests: `npx tsc --noEmit`; `npm test`; `npm run test:workers`; single suites `npm run test:workers:lab-jwks-fetch`, `…:shared-admission-reliability`, `…:jwks-concurrency`.
- Dry-run (no upload): `npx wrangler deploy --config <rendered-config> --dry-run --outdir <path-relative-to-config-dir>`.
- Read-only inspection: `npx wrangler deployments list --name <worker>`, `npx wrangler versions list --name <worker>`, `npx wrangler versions view <full-version-id> --name <worker>` (needs the full UUID).
- Scripting quirks on this machine: no `gh`, no python; heredocs with special characters break in the shell — use the Write tool or `.cjs` files; run Miniflare scripts with `timeout` and `process.exit`.
- Memory index: `C:\Users\Emir\.claude\projects\C--Users-Emir-Desktop-pentest-website\memory\MEMORY.md`.

## Update 2026-11-08 — production security corrections (local, unpushed)
Commits on feat/capacity-engineering: 1720e9f (F-1), 655d58a (production entry + Vercel contract), ba65541 (account pin / public-CA tests), 17d9218 then f91b277 (reader signed `initialized`/`coverage`, now OPT-IN via `includeSignedInitialization` because 17d9218 changed default outcomes and broke exact-shape tests), 6212ccf (tests/support/worker-bundle.ts + owner-approved exact REVIEWED_UNPROVABLE_REFERENCES entry), b3b52ab (export-signing design, Gate 9 plan, baseline v2 register refresh).
Clean-checkout `npm test` at f91b277: 1875 tests, 5 fail (pre-existing): gate6 production-ignore (639), gate8 fault-hook allowlist lab guard (721), historical-immutability (933), byte-identical baseline (1179), F4 dockerignore (1267). `npm run test:workers` exit 0.
Open owner decisions: (a) .gitignore line `deployment/lifecycle-transport.production.json` (from 1cf7b81) conflicts with gate6 test 639 and F4 1267 — satisfying both means removing the ignore line; (b) add lab-dispatch-guard.ts to the fault-hook `guardFiles` allowlist; (c) baseline v2 hash acceptance; (d) dedicated export-request key (design only).
Docs: EXPORT-REQUEST-SIGNING-DESIGN.md, GATE-9-STAGING-ROTATION-PLAN.md.

## Update 2026-11-08 (later) — regression closure and qualification-readiness
e4f8267: D1 (.gitignore line kept; exact production names added to .dockerignore and lab/linux/Dockerfile.dockerignore; Gate 6A test now asserts exact-name ignore) and D2 (lab-dispatch-guard.ts in fault-hook guardFiles). ed07dd3: BASELINE-V2-FILE-REVIEW.md (42 entries, 5 HOLD / 11 HOLD-light / 26 accept; hashes unapproved) and EXPORT-REQUEST-SIGNING-DESIGN.md v2 (design only). Next commit: INDEPENDENT-QUALIFICATION-READINESS.md.
Clean checkout at e4f8267: npm test 1876 tests, 1832 pass, 2 fail (934 historical-immutable, 1180 byte-identical baseline), exit 1; test:workers exit 0. Main tree: 10 fail = those 2 + 8 audit-package scans.

## Update 2026-11-08 (qualification-first phase)
Owner decisions: first milestone = existing independent L1/L2 only (not L1/L2/L3); Workers/Vercel admission is a separate track; P0 instrumentation approved (local, bounded); GCP europe-west3 preferred, private addresses preferred (planning only); export key: overlap <= 24 h, two keys in staging, legacy verifier stays in first commit; baseline v2 stays unapproved.
Done: outcome tally + cross-checks as NEW files under lab/defense (commits 82045e3, 3369f81); wiring into defense/plane/runtime.ts is HELD as PROPOSED-INSTRUMENTATION-WIRING.patch because defense/ trees are diffed against aff793e/baseline (any edit or new file under defense/core breaks 653 historical-immutability). Overhead: ~50-130 ns/event, end-to-end delta within noise. Docs: BASELINE-V2-ACCEPTANCE-PACKAGE.md (26/11/5), QUALIFICATION-M1-DESIGN.md, QUALIFICATION-CLOUD-PLAN.md, EXPORT-KEY-IMPLEMENTATION-PLAN.md.

## Update 2026-11-08 (M1 instrumentation + migration phase)
040292b: observational tally WIRED into defense/plane/runtime.ts (+ defense/core/outcome-counters.ts); equivalence on the real plane process (tests/defense-plane-instrumentation.test.ts), benchmark lab/defense/outcome-benchmark.ts (~48 ns/event, paired end-to-end delta ~ -0.001 ms). 7c43775: append-only versioned registry tests/support/reviewed-migrations.ts (44 entries, ALL PENDING) + classifier + tests. PROPOSED-BASELINE-MIGRATION-TEST-WIRING.patch (not applied) adds withoutReviewedChanges/assertMigrationBoundary to the three guards; measured: 44 approved => all 3 guards pass; only the 2 instrumentation entries => aff793e guard passes; 28 non-held => the 64ccc9d and dcf10af8 guards still fail on exactly the 16 held files. cc5b112/25e9649: private-target tests. 9b23a6b: M1-DECISIONS-PACKAGE.md (criteria 7-9 verbatim, N-1/N-2 analysis, revocation comparison, cloud BLOCKED status).

## Update 2026-11-08 (migration wiring + N-2)
9929d65: migration registry wired into the 3 historical guards (all 44 PENDING; APPROVED must bind historical blob, reviewed blob, authorization, scope). 507ea6b: campaign id <= 31 chars at both parse sites (lab/defense/campaign-id.ts). be90516: INSTRUMENTATION-MIGRATION-APPROVAL.md (2 entries), N1-STATUS-CONTRACT-DESIGN.md (overlay Option B, zero pinned files), M1-CRITERIA.md, EXPORT-KEY-REVOCATION-DESIGN.md. Selftest `lab:ba0:field -- --selftest` OK; `lab:ba0` and `lab:ba0:origin` outputs byte-identical before/after wiring; Docker daemon down so `lab:parity` was NOT run. Clean checkout: 3 failures (the 3 historical immutability guards).
