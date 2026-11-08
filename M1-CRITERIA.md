# M1 criteria — exact wording, with approval status (2026-11-08)

Scope: the existing independent L1/L2 application-plane defense at the reviewed N=1 level (`ba0-l7-c1`). Not L3, not network isolation, not volumetric defense; none of those exist.
Status legend: **IN FORCE** = value already in reviewed code and not in question; **DECIDED (D4)** = decided by the owner in the latest message; **PENDING** = requires approval; nothing PENDING is treated as approved.

## Criteria 1–6 (IN FORCE: numbers taken from the reviewed `ba0-field-v1` in `lab/defense/field-thresholds.ts`; wording copied from `QUALIFICATION-M1-DESIGN.md`, which is my restatement, not the code)
**VALID requires all of:**
1. Legitimate users: JCR = 100% in every required group (baseline, window, residual, recovery); window p95 ≤ 4 × baseline p95 + 150 ms; no canary 5xx; every step 200 with expected content.
2. Accounting: identities E1..E11 hold; ingress = sum of terminal outcomes; zero unresolved; no unexplained request; no unattributed 503; the only shed is `mutation/unverified/lane_budget`; zero bypass (origin receipt without plane pass).
3. Exposure: continuous proof holds in every tick (only the reviewed plane IPv4:port listens non-loopback); no external accept before ARMED.
4. Resources never exceed ceilings: host CPU ≤ 80% (3 ticks), available memory ≥ 15%, plane ELD p99 ≤ 250 ms (3 ticks), RSS ≤ 512 MB, fds ≤ 70%; generator schedule-lag p99 ≤ 50 ms and ELD p99 ≤ 100 ms (otherwise the run is INVALID, not a defense failure).
5. Recovery: after the load stops, quiet period 135 s, then recovery journeys all succeed; residual journeys (restriction after load) all succeed.

## Response contract for this fixture — DECIDED (D4)
The synthetic origin's reviewed implementation governs: the reviewed cycle produces **200** (GET routes, POST states) and **503** (attributed `mutation/unverified/lane_budget` shed). 302/303 and 403/404 are **not** claimed as covered, because no fixture or assertion exercises them. The broader response contract (other statuses exist in the origin's malformed-input paths) is preserved and unaffected.

## Criteria 7–9 as currently written (PENDING approval; verbatim from `QUALIFICATION-M1-DESIGN.md`)
> 7. **NEW, repeatability:** three independent runs on fresh state (same commit, parameters, fixture cycle) all VALID, with identical shed reason sets and per-run shed share within ±5 percentage points of the median. A single VALID run is a smoke result, not M1.
>
> 8. **NEW, status allow-list (finding N-1):** every client-visible status must be in the predeclared set {200, 302/303 per fixture, 503 attributed to the allowed shed, 403/404 only where the fixture expects them}; any other status is INVALID. This needs a verdict-path change (migration event) and is a prerequisite, not part of the run.
>
> 9. **NEW, unexplained differences:** plane outcome tally (82045e3) vs collector ledger equal per event kind, once wiring is approved (`PROPOSED-INSTRUMENTATION-WIRING.patch`). Until then this criterion is reported `not_measured`, and M1 cannot claim it.

## Proposed wording for the pending criteria (PENDING; changes marked)
7. **Repeatability** (unchanged in substance): three independent runs on fresh state (same commit, parameters, fixture cycle) all VALID, with identical shed reason sets and per-run shed share within ±5 percentage points of the median. A single VALID run is a smoke result, not M1.
8. **Status contract** (CHANGED to follow D4): every client-visible status, in both the generator view and the server view, must be in **{200, 503}**, and every 503 must be attributed to `mutation/unverified/lane_budget`; any other status makes the run M1-INVALID. Implemented as an overlay verdict that never alters the existing qualification verdict (see `N1-STATUS-CONTRACT-DESIGN.md`). Not claimed: coverage of 302/303 or 403/404.
9. **Unexplained differences** (CHANGED: instrumentation now exists): the plane's own outcome tally and the collector ledger must agree per event kind (`compareToLedger` empty) and the tally must satisfy its accounting identities; if the tally is absent or its `faults`/`unknown` counters are non-zero the criterion is reported **failed**, not skipped. Status of the wiring: applied in `040292b`; its baseline-migration entries are PENDING (see `INSTRUMENTATION-MIGRATION-APPROVAL.md`).

## What approval of 7–9 does and does not authorize
It fixes the acceptance rule for a future run. It authorizes no run, no cloud resource and no external traffic. The cloud acceptable-use question remains BLOCKED (see `M1-DECISIONS-PACKAGE.md` section D).
