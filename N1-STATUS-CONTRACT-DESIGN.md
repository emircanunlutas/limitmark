# N-1 — M1 client-visible status contract: design for approval (NOT implemented; `reconcile.ts` untouched)

## 1. Problem (verified in code)
`lab/defense/reconcile.ts` rejects unreviewed statuses only in the N=2 branch (`g2.n2_no_unexplained_status`: 429 and 5xx other than an attributed 503). `external-accounting.ts` E8 covers 5xx for every level. For the N=1 level `ba0-l7-c1` nothing bounds 2xx/3xx/4xx, so a plane answering 404 on every route could still be VALID unless the canary notices at baseline journey 1 (the C1 audit's finding N-1). M1 claims "legitimate users keep working", so its own generator traffic must have a closed response contract.

## 2. Two ways to be additive — and a conflict between them and your constraints
Pinned files (byte-identity guards) that a "new level id" implementation would have to touch: `lab/defense/field-thresholds.ts` (level registry and type unions), `lab/policy/workloads.ts` (new workload), `lab/defense/reconcile.ts` (the conditional identity), and the CLI `lab/defense/ba0-field-reconcile.ts`. Your D6 forbids modifying `reconcile.ts`, and each of the others would be a registry migration event.

**Option A (the approach you accepted): a new level id** `ba0-l7-c1-m1`. Touches the four pinned files above. Cannot be done under D6 as written.
**Option B (recommended, zero pinned files): an M1 verdict overlay.** The reviewed level `ba0-l7-c1`, its workload, thresholds, fingerprints (`5f7fbb86…` params) and `finalFrom` stay exactly as they are. A NEW file pair evaluates an additional contract over the same evidence and writes a separate artifact:
- `lab/defense/m1-status-contract.ts` (pure function) and `lab/defense/ba0-m1-reconcile.ts` (CLI). Neither is in any pinned pathspec.
- The overlay first calls the existing final-verdict path unchanged. It can only add reasons; it can never turn an INVALID into anything else.
Both options give the same property you asked for (existing identities, ordering and historical verdicts unchanged). B achieves it without any registry entry. If you prefer A for identity-of-level reasons (the evidence then names a distinct level id), A needs separate authorization for the four pinned-file edits.

## 3. Exact intended behavior (Option B)
Inputs: the existing final decision (from the unchanged reconcile), `server-level.json` (`statusHistogram`, `status503 {total, expectedShed, unexplained, byCause}`), `generator-report.json` (`statuses`).
Contract for `ba0-l7-c1` traffic (reviewed fixture cycle: GET `/`, GET `/gizlilik`, GET `/test-talep-et`, POST `/api/public-inquiries`):
1. `m1.status_allowlist_generator`: every status key in the generator view ∈ {200, 503}.
2. `m1.status_allowlist_server`: every status key in the server view ∈ {200, 503}.
3. `m1.shed_attributed`: server `status503.unexplained == 0`.
4. `m1.shed_cause_closed`: `status503.byCause` has only the cause `mutation.unverified.lane_budget` (the only reviewed shed, `allowedShed`).
5. `m1.base_verdict_valid`: the unchanged reconcile verdict is `EXTERNAL-L7-QUALIFICATION-VALID`.
Output `m1-verdict.json`: `M1-STATUS-CONTRACT-VALID` only if 1–5 hold, else `M1-STATUS-CONTRACT-INVALID` with the failing identity names. The label is deliberately different from the qualification verdict and states its scope (L1/L2 application plane; nothing about network or transport).
**Why {200, 503} and not more:** the synthetic origin's reviewed implementation answers 200 for GET routes and 200 or 503 for POST states in this cycle (it also has 400/403/404/413 paths for malformed input that this cycle never produces). Per D4, 302/303 and 403/404 are not claimed as covered because no fixture and assertion exercises them.
**Empirical confirmation required before pinning:** run the unchanged cycle through the local real chain (plane + Boundary + App, loopback) and record the observed histogram; the allow-list is pinned only if it equals {200, 503}. The pinned list is hashed into the overlay artifact.

## 4. Acceptance criteria
A. Clean fixture (generator + server views only 200 and attributed `lane_budget` 503) → `M1-STATUS-CONTRACT-VALID`.
B. Each of 302, 303, 400, 403, 404, 413, 429, 500, 502, 504, and an unknown status, injected in either view → INVALID naming the identity (11 statuses × 2 views).
C. An unattributed 503, or a 503 with a different cause → INVALID.
D. A base verdict that is not VALID → overlay INVALID (never upgraded); a base reason stays visible.
E. The all-404 origin (the audit's N-1 case) → INVALID.
F. Historical: the three guards and `finalFrom` outputs unchanged; no pinned file changed (verified by the registry classifier: zero new drift).

## 5. Compatibility
- Contracts affected: none of the pinned ones. New files only; no `package.json` script needed (run with `tsx`). The overlay reads artifacts the existing level already writes.
- The M1 criteria text (criterion 8) is the only contract this implements; wording is in `M1-CRITERIA.md`.
- Evidence scanner: the overlay's artifact uses only closed keys (`m1.status_allowlist_*`), no `/` or `:`, no forbidden words.

## 6. Required tests
Unit (pure function, table-driven for acceptance A–E); fixture round-trip from real `server-level.json`/`generator-report.json` shapes produced by the existing builders (so the overlay breaks if the report shape changes); the empirical local-chain run recording the histogram; a source-scan test that the overlay imports no pinned module for writing and that the CLI refuses to run without an existing final verdict; evidence-scanner test on `m1-verdict.json`; regression: all existing reconcile/final tests unchanged.
