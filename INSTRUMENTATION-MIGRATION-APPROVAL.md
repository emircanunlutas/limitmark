# Two-entry approval package: the observational outcome tally (`040292b`) — RECOMMENDATION ONLY, nothing is approved

Registry: `tests/support/reviewed-migrations.ts` (version 1). Both entries are PENDING and exempt nothing. This package does not touch the other 42 entries.
**Reviewer independence:** I wrote this change and I am also its reviewer here. Everything below is evidence you can re-run; the recommendation should be read as "the evidence is complete and consistent", not as an independent second opinion. A second reader is advisable before approval.

## 1. The two entries (exact bindings)
| Field | `defense/core/outcome-counters.ts` | `defense/plane/runtime.ts` |
|---|---|---|
| change | added | modified |
| historical blob (identical at `64ccc9d`, `dcf10af8`, `aff793e`) | absent at all three | `5a909606d168e65d39f006d41cc5c2a798ad7e22` |
| reviewed replacement blob | `07255f152ae578e22a4a5d9f49721aa9afbdcc82` | `2306b1718d4e4d07db6bea2b6e94a619bf63ac9f` |
| reviewedSha256 (LF-normalized) | `6169f8e5aacc78870345c60936bc2b3d58a02bfa954ac9ecf1c62fedaa0c6be8` | `d46cd98632bab52df42ce993b3862f4ee26cae4b889b02e9899ed798d205203c` |
| introducing commit | `040292b` (module first written in `82045e3`, moved/refined since) | `040292b` |
Verified by the registry's own test: blobs equal at all three baselines, working file equals the recorded hashes.

## 2. Full runtime diff (`runtime.ts`, 12 changed lines against the historical blob)
```
+ import { OutcomeCounters, countingEmit, type WithOutcomes } from "../core/outcome-counters";
- let ticks: TickSource<PlaneTickData> | null = null;
+ let ticks: TickSource<WithOutcomes<PlaneTickData>> | null = null;
+ const telemetryTickMs = raw.telemetry?.tickMs;
+ const outcomeCounters = (valid tick interval: safe integer, 100..10000) ? new OutcomeCounters() : undefined;
- emit: (event) => ch.emit(event),
+ emit: outcomeCounters === undefined ? (event) => ch.emit(event) : countingEmit(outcomeCounters, (event) => ch.emit(event)),
- ticks = new TickSource<PlaneTickData>(...
+ ticks = new TickSource<WithOutcomes<PlaneTickData>>(...
+ ... channel: owned.channel.stats(), outcomes: outcomeCounters === undefined ? null : outcomeCounters.snapshot(),
```
Nothing else changes: no layer, composer, lane, bucket, deadline, status, header or policy value is touched. `countingEmit` is `(event) => { counters.observe(event); return emit(event); }`; `observe` swallows every exception.

## 3. Checks requested, each with its evidence
| Check | Evidence (re-runnable) | Result |
|---|---|---|
| Defense-policy and HTTP-response equivalence | `tests/defense-plane-instrumentation.test.ts` #1: real plane process (`main-l2.ts`) with instrumentation off vs on, 15-request mixed workload | identical statuses; identical (kind, reason, status, class, lane, outcome, egressError) event stream |
| Event ordering | same test: compares the ordered streams | identical order |
| Accounting correctness | #3 (tally equals IPC-delivered events; identities I1–I10 hold; `unknown` = `faults` = 0) and `lab/defense/plane-outcome-check.ts` | pass |
| Origin delivery | #2: origin receipts = plane egress attempts − failures, on and off | pass |
| Hop correlation through the wrapper | mutation check: a wrapper returning `seq + 1` makes 7 tests in `tests/lab-ba0-field-run.test.ts` fail (real plane + Boundary + App); restored | detected; with the real code all pass |
| Disabled-mode behavior | `OutcomeCounters` is only constructed when ticks run; otherwise the original emit closure is passed and no tick exists (test: `off.ticks.length === 0`); `lab:ba0` and `lab:ba0:origin` (instrumentation off) produce byte-identical accounting output before (`3156a68`) and after (`HEAD`) once run ids/timings are normalized (0 differing lines, 27 and 67 lines) | pass |
| Failure isolation | unit: a tally throwing on every event changes no response/event/status and counts faults; plane: `observe` try/catch; a throwing snapshot would be caught by the existing tick `try/catch` and costs only a tick | pass |
| Boundedness and content | closed key spaces (hostile values land in `unknown`), keys positional (`r00…`) to satisfy the evidence scanner, snapshot < 8 000 bytes, no nonce/address/header/path in the payload (tests) | pass |
| Overhead | `npx tsx lab/defense/outcome-benchmark.ts` (alternating off/on, 7 rounds × 600 requests, one warm-up each): off median 0.5699 ms, on median 0.5599 ms, paired delta median −0.0023 ms (range −0.0252…+0.0048); tally 49 ns/event, ≈ 4 events/request | within noise |
| Lab copy = in-tree copy | `tests/defense-plane-instrumentation.test.ts` #5 compares the two files after import-path normalization | identical |

## 4. Residual risks and limits
- The tally counts events the plane emits; it does not observe pre-parser traffic or kernel-level drops (those remain `not_measured`).
- A fault inside `observe` is counted but not surfaced to a verdict; criterion 9 uses the counts as an advisory cross-check only.
- Equivalence was demonstrated on a 15-request workload and by the existing field-run suite, not on a Linux field host.
- The hop-correlation protection depends on `tests/lab-ba0-field-run.test.ts` staying in the suite.

## 5. Recommended approval (two entries only; to be made by you, by editing the registry)
Set, for exactly these two entries: `status: "APPROVED"`, and
```
authorization: "Owner decision D1 (instrumentation wiring, conditional approval) + INSTRUMENTATION-MIGRATION-APPROVAL.md, 040292b"
scope: "observational outcome tally only: new module + runtime.ts wiring that tallies emitted events; no defense policy, threshold, status or event-order change"
```
Effect (measured with the wiring applied): the `aff793e` guard closes; the `64ccc9d` and `dcf10af8` guards remain red because of the other 42 entries. After approval, any later edit to either file fails the reviewed half until it is reviewed again.

## 6. Review sequence for the whole registry (no bulk approval)
1. These two entries (above).
2. The 26 accept-candidates, in groups by `reviewId` (production preparation, observability, shared fix, lab files), each group with its diff and test evidence from `BASELINE-V2-ACCEPTANCE-PACKAGE.md`; two conditions pending (OIDC claim-check confirmation; telemetry label-set re-check).
3. The 11 shared-production-module entries, each needing an independent reader.
4. The 5 guard-export entries, after the export-key decision and its implementation (they will change again).
At every step the guards must show the remaining failures as exactly the not-yet-approved set.
