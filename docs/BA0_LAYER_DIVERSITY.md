# BA0 layer-diversity defense: technical reference

Status: **research and validation tooling, not production-qualified.** This page is an index into code and tests that already exist; the authoritative
mechanism description is [Slice 3 in `defense/README.md`](../defense/README.md#ba0-slice-3-layer-diversity-and-predecessor-collapse-application-plane-only). Nothing here has
been audited or certified by a third party, and no field validation of this mechanism is claimed.

Original implementation: commit `d50aaf36247b2587146c6b872459e37f9ce930a9` (`feat: add BA0 layer-diversity defense`), merged as PR #25
(`23c4c2c`). Both are ancestors of `ba0-n2-progression` (verified with `git merge-base --is-ancestor`). Later commits on that line add N2/Salvo field instrumentation and
do not redefine this mechanism.

## Problem

BA0's first layer (L1, `a7.shape-gate`) is a stateless judgement of one request's shape. Any single layer can be wrong, and a defense whose only second line is a copy of
the first fails with it. Slice 3 asks a narrow, measurable question: **if L1 passes a request it should not have, does a different mechanism using a different signal
still bound what reaches the application?**

## Threat model (as scoped by the implementation)

In scope, application plane only (`a7.*`), loopback, fixed counts:

* **F1** well-formed, valid-looking mutation whose submission token was never issued by the plane (L1 passes it by design).
* **F2** a genuinely issued token replayed beyond K uses.
* **F3** a stateful "journey farmer" that renders the form, then POSTs the real token, repeatedly.
* **F4** render flood aimed at the credit filter (to raise false positives and erase attenuation).
* **Predecessor collapse**: L1 (and in one arm L2) wrongly passing; modelled by a harness-only forced verdict, always labelled `basis: "simulated"`.

Out of scope and not measured: DDoS / volumetric load, network and transport layers (`n3.*`, `t4.*`), bot detection, read-flood protection, per-user fairness, a
sender identity of any kind (the mechanism never uses IP or connection identity), and L1/L2 process independence (both run in one plane process).

## Mechanism (L2 `a7.journey-lanes`)

Requests are classed `open` / `mutation` / `unknown`. Mutations are placed in a `credited` or `unverified` lane by **journey provenance**: whether the submission token was
delivered by this plane's own flushed form response (a keyed, fixed-memory, two-generation Bloom filter). Each lane has its own token bucket; the buckets are the bound,
provenance only selects the lane. Invariants: no spill between lanes, use records purged only after the credit window, no refunds. L2 errors on mutation/unknown requests
fail closed (503). See `defense/README.md` for the full table.

## Where things live

| Concern | File |
| --- | --- |
| Lanes, token buckets, use ledger, decision vocabulary | `defense/core/lanes.ts` |
| Credit-provenance filter | `defense/core/credit-filter.ts` |
| Enrollment contract (what response may enroll a token) | `defense/core/enrollment.ts` |
| L2 as a composer `Layer` | `defense/layers/a7-journey-lanes.ts` |
| L2 stage (deadline, bulkhead, failure policy) | `defense/plane/l2-stage.ts`, `defense/plane/l2-protocol.ts`, `defense/core/l2-port.ts` |
| Plane composition; **production Slice-3 entry** (no override code in graph) | `defense/plane/runtime.ts`, `defense/plane/main-l2.ts` |
| Per-request penetration depth / terminal explanation | `defense/core/penetration.ts` |
| L2 lifecycle rules | `defense/core/l2-lifecycle.ts` |
| Harness-only collapse override (must not exist outside `lab/`) | `defense/core/override-port.ts` (interface only), `lab/defense/collapse/` |
| Runner, fixtures, thresholds (`ba0-collapse-local-v1`) | `lab/defense/ba0-collapse-run.ts`, `collapse-corpus.ts`, `collapse-thresholds.ts` |
| Accounting derived from lifecycle records | `lab/defense/lane-accounting.ts` |

## Implementation-to-test map

| Area | Tests (`tests/`) |
| --- | --- |
| Lanes / buckets / ledger | `defense-lanes.test.ts` |
| Credit filter | `defense-credit-filter.test.ts` |
| Enrollment | `defense-enrollment.test.ts`, `built-form-enrollment.integration.ts` (real build; not in `npm test`) |
| Front + L2 behaviour | `defense-front-l2.test.ts` |
| Penetration records | `defense-penetration.test.ts` |
| Static rules (module graphs, override placement, unchanged files) | `defense-slice3-static.test.ts`, `defense-isolation.test.ts` |
| Collapse harness | `lab-ba0-collapse-contract.test.ts`, `lab-ba0-collapse-override.test.ts`, `lab-ba0-collapse-run.test.ts`, `lab-ba0-lane-accounting.test.ts` |

## Reproducing the checks

Node.js 22+, after `npm ci`. Commands below were run on Node.js v22.22.0 (Windows) against the commit that adds this page.

```sh
# Slice-3 unit and contract tests only (11 files; 106 tests passed, 0 failed)
npx tsx --conditions=react-server --test tests/defense-lanes.test.ts tests/defense-credit-filter.test.ts tests/defense-enrollment.test.ts tests/defense-front-l2.test.ts tests/defense-penetration.test.ts tests/defense-slice3-static.test.ts tests/defense-isolation.test.ts tests/lab-ba0-collapse-contract.test.ts tests/lab-ba0-collapse-override.test.ts tests/lab-ba0-collapse-run.test.ts tests/lab-ba0-lane-accounting.test.ts

# Local loopback collapse experiment (no arguments; writes to the gitignored artifacts/lab/evidence/)
npm run lab:ba0:collapse

# Repository-wide checks that CI runs
npm run lint
npm run typecheck
npm test

# G1 against the real build (separate prerequisites; not run by CI)
npm run build && npx tsx --conditions=react-server tests/built-form-enrollment.integration.ts
```

`npm run lab:ba0:collapse` printed per-arm check lines and ended with an `evidence=<run id>` line; its `collapse.json` recorded the verdict `LAYER-DIVERSITY-VALID`.
In one such run the cross-arm line read "fabricated valid mutations reaching APP_MUTATED per 200 sent: reference 200, with L2 3". Treat that as an illustration of what the
check reports, not a benchmark: counts are fixed and every threshold is provisional.

## Known limitations and unverified assumptions

* The verdict means only what the claim boundary in `defense/README.md` says: local, fixed-count, reviewed fixtures. It is not a defense-qualification PASS.
* The Bloom filter is scaled down (2^13 bits) and epochs compressed (seconds) in the lab; the production-sized parameters are untested at scale. Semantics are unit-tested on an injected clock only.
* Thresholds (`ba0-collapse-local-v1`) are uncalibrated.
* L1 and L2 share one process, so a plane-process fault takes out both.
* Cross-process and full-length field behaviour is not established; the historical BA0 N2 R2 result remains INVALID (see the repository README).
* Evidence under `artifacts/lab/evidence/` is gitignored and regenerated by each run; it is not reproducible byte-for-byte and the committed repository holds no such artifacts for this mechanism.
* The G1 build integration test was not run for this documentation pass.
