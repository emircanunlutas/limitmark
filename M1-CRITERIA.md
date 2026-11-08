# M1 criteria — exact wording, with approval status (2026-11-08)

Scope: the existing independent L1/L2 application-plane defense at the reviewed N=1 level (`ba0-l7-c1`). Not L3, not network isolation, not volumetric defense; none of those exist.
Status legend: **IN FORCE** = value already in reviewed code and not in question; **DECIDED (D4)** = decided by the owner; **APPROVED (2026-11-08)** = approved by the owner in the decision recorded below; **PENDING** = requires approval; nothing PENDING is treated as approved.

## Criteria 1–6 (IN FORCE: numbers taken from the reviewed `ba0-field-v1` in `lab/defense/field-thresholds.ts`; wording copied from `QUALIFICATION-M1-DESIGN.md`, which is my restatement, not the code)
**VALID requires all of:**
1. Legitimate users: JCR = 100% in every required group (baseline, window, residual, recovery); window p95 ≤ 4 × baseline p95 + 150 ms; no canary 5xx; every step 200 with expected content.
2. Accounting: identities E1..E11 hold; ingress = sum of terminal outcomes; zero unresolved; no unexplained request; no unattributed 503; the only shed is `mutation/unverified/lane_budget`; zero bypass (origin receipt without plane pass).
3. Exposure: continuous proof holds in every tick (only the reviewed plane IPv4:port listens non-loopback); no external accept before ARMED.
4. Resources never exceed ceilings: host CPU ≤ 80% (3 ticks), available memory ≥ 15%, plane ELD p99 ≤ 250 ms (3 ticks), RSS ≤ 512 MB, fds ≤ 70%; generator schedule-lag p99 ≤ 50 ms and ELD p99 ≤ 100 ms (otherwise the run is INVALID, not a defense failure).
5. Recovery: after the load stops, quiet period 135 s, then recovery journeys all succeed; residual journeys (restriction after load) all succeed.
6. Telemetry: gapless 1 s ticks (gap tolerance 2.5 s).

## Response contract for this fixture — DECIDED (D4)
The synthetic origin's reviewed implementation governs: the reviewed cycle produces **200** (GET routes, POST states) and **503** (attributed `mutation/unverified/lane_budget` shed). 302/303 and 403/404 are **not** claimed as covered, because no fixture or assertion exercises them. The broader response contract (other statuses exist in the origin's malformed-input paths) is preserved and unaffected.

## Criteria 7–9 as originally written (SUPERSEDED by the approved wording below; kept verbatim as history; from `QUALIFICATION-M1-DESIGN.md`)
> 7. **NEW, repeatability:** three independent runs on fresh state (same commit, parameters, fixture cycle) all VALID, with identical shed reason sets and per-run shed share within ±5 percentage points of the median. A single VALID run is a smoke result, not M1.
>
> 8. **NEW, status allow-list (finding N-1):** every client-visible status must be in the predeclared set {200, 302/303 per fixture, 503 attributed to the allowed shed, 403/404 only where the fixture expects them}; any other status is INVALID. This needs a verdict-path change (migration event) and is a prerequisite, not part of the run.
>
> 9. **NEW, unexplained differences:** plane outcome tally (82045e3) vs collector ledger equal per event kind, once wiring is approved (`PROPOSED-INSTRUMENTATION-WIRING.patch`). Until then this criterion is reported `not_measured`, and M1 cannot claim it.

## Proposal text that preceded the approval (kept as history; the APPROVED section below governs)
7. **Repeatability** (unchanged in substance): three independent runs on fresh state (same commit, parameters, fixture cycle) all VALID, with identical shed reason sets and per-run shed share within ±5 percentage points of the median. A single VALID run is a smoke result, not M1.
8. **Status contract** (CHANGED to follow D4): every client-visible status, in both the generator view and the server view, must be in **{200, 503}**, and every 503 must be attributed to `mutation/unverified/lane_budget`; any other status makes the run M1-INVALID. Implemented as an overlay verdict that never alters the existing qualification verdict (see `N1-STATUS-CONTRACT-DESIGN.md`). Not claimed: coverage of 302/303 or 403/404.
9. **Unexplained differences** (CHANGED: instrumentation now exists): the plane's own outcome tally and the collector ledger must agree per event kind (`compareToLedger` empty) and the tally must satisfy its accounting identities; if the tally is absent or its `faults`/`unknown` counters are non-zero the criterion is reported **failed**, not skipped. Status of the wiring: applied in `040292b`; its baseline-migration entries are PENDING (see `INSTRUMENTATION-MIGRATION-APPROVAL.md`).

## Criteria 7–9 — APPROVED (owner decision, 2026-11-08)
7. **Repeatability:** three independent runs on fresh state, with the same commit, parameters and fixture cycle, must all have a base verdict of EXTERNAL-L7-QUALIFICATION-VALID, identical shed-reason sets, and shed shares within ±5 percentage points of the median. A single VALID run is a smoke result, not M1.
8. **Status contract (existing synthetic-origin fixture):** every client-visible status, in both the generator view and the server view, must belong to {200, 503}, and every 503 must be attributed to an allowed `mutation`/`unverified`/`lane_budget` shed. Any other status or any unexplained 503 produces overlay outcome **REJECT**. No `M1-INVALID` historical verdict category exists or is introduced. Coverage of 302/303 and 403/404 is not claimed. Evidence: `statusOverlay: { evaluated, outcome, reasons }` with outcomes PASS | REJECT | ERROR, written to a separate `m1-verdict.json`; M1 acceptance requires base VALID **and** overlay PASS; unreadable or malformed evidence is ERROR (fail closed, never PASS). Implemented locally in `lab/defense/m1-status-contract.ts` and `lab/defense/ba0-m1-reconcile.ts` (new files only); design in `N1-STATUS-CONTRACT-DESIGN.md`.
9. **Unexplained differences:** the plane outcome tally and the collector ledger must agree per event kind; every tally identity must hold; an absent tally, a non-zero `faults` count or a non-zero `unknown` count fails M1 acceptance. The tally wiring (`040292b`) has its two migration entries APPROVED; the acceptance check that consumes the tally for an M1 verdict is NOT yet implemented (criterion 9 is therefore still `not_measured` by the tooling until it is).

Implementation status of the approved criteria: 8 implemented and tested locally (overlay, not yet run on a real field run). 7 and 9 have no tooling yet; no run has been authorized.

## What approval of 7–9 does and does not authorize
It fixes the acceptance rule for a future run. It authorizes no run, no cloud resource and no external traffic. The cloud acceptable-use question remains BLOCKED (see `M1-DECISIONS-PACKAGE.md` section D).
