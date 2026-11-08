# Export-request verification: fail-closed migration from the legacy verifier — DESIGN ONLY (2026-11-08)

Companion to `EXPORT-REQUEST-SIGNING-DESIGN.md` (v2), `EXPORT-KEY-IMPLEMENTATION-PLAN.md` and `EXPORT-KEY-REVOCATION-DESIGN.md`. Nothing here is implemented; the guard verification boundary is NOT modified; no live rotation, no configuration update. The key-validity cap is **not decided** (see section 7).

## 1. The defect this closes
`EXPORT-KEY-IMPLEMENTATION-PLAN.md` section 1 selects the verifier by configuration: *key set configured => v2 only; key variable absent => legacy lifecycle-key verifier*. That makes the **absence** of one variable select the weaker verifier. Once v2 is enabled, any of these silently downgrades exports to the lifecycle-key verifier: the variable deleted by a configuration edit, a template rendering bug, a partial deployment, or a code rollback that ignores the variable. This contradicts the plan's own header ("missing or inconsistent configuration fails closed"). It is not acceptable once the new mode is enabled.

## 2. Rule
**Absence never selects a verifier.** The verifier is selected only by an explicit, exact, mandatory mode value; any other state refuses.

| Variable | Allowed values | Meaning |
|---|---|---|
| `GUARD_EXPORT_MODE` (mandatory in the new code) | exactly `legacy-v1` or `v2-only` | `legacy-v1`: only the existing lifecycle-key verifier, behaviour byte-for-byte as today, selected EXPLICITLY. `v2-only`: only the export-key verifier. |
| `GUARD_EXPORT_KEYS` | required and valid iff mode is `v2-only`; must be absent under `legacy-v1` | the 1 to 2 key entries of the revocation design |

Runtime decision table (the first matching row wins; every refusal is `REFUSED(configuration)` with a fixed string, **before any storage read**):

| Mode | Keys | Envelope | Result |
|---|---|---|---|
| absent / empty / unknown / wrong case / whitespace | any | any | REFUSED(configuration) |
| `legacy-v1` | present (any content) | any | REFUSED(configuration) — a half-migrated configuration is not interpreted |
| `legacy-v1` | absent | v1 | existing legacy path |
| `legacy-v1` | absent | v2 or malformed | REFUSED |
| `v2-only` | absent / empty / malformed / over cap / inconsistent | any | REFUSED(configuration) — never falls back to v1 |
| `v2-only` | valid | v1 | REFUSED (a request cannot select a weaker verifier) |
| `v2-only` | valid | v2 | v2 verification (bindings, window, fingerprint in set) |
| `v2-only` | valid | malformed | REFUSED |

The cost of fail-closed is only export availability, which is on no critical path (revocation design section 3); lifecycle dispatch, settlement and the L1/L2 plane share no code path with it.

## 3. Migration sequence (each step independently reviewable and revertible; none is authorized)
0. **Today (unchanged):** deployed guards have no mode variable and the legacy verifier. Nothing changes until step 1 ships.
1. **Code + explicit config together (the first commit that knows about the mode):** the guard requires `GUARD_EXPORT_MODE`; every environment's rendered configuration sets `legacy-v1` explicitly, and the deployment-contract validator (`deployment/lifecycle-private-contract.ts`) rejects a configuration without the variable. Behaviour for existing exports is identical, but the downgrade surface is already closed: from this step on, deleting the variable refuses.
2. **v2 code path behind `v2-only`**, tests first (T1 to T13 of the implementation plan plus section 5 below). Staging only: `v2-only` with two staging keys. Evidence: the staging rotation rehearsal.
3. **Cut-over per environment** (staging, then production): the owner changes the environment's mode to `v2-only` and supplies the key set. The contract pins, per environment, the **expected** mode. After cut-over the pinned expectation for that environment is `v2-only`, and the contract test fails if the rendered configuration says `legacy-v1`: a reversion is a reviewed edit of a test, never a silent revert.
4. **Remove the legacy verifier** (separate reviewed commit, only after a staging qualification record exists). Afterwards `legacy-v1` is an unknown value and refuses.

## 4. Residual downgrade routes and how each is closed
| Route | Closure |
|---|---|
| Variable deleted or renamed | mode absent => REFUSED (section 2) |
| Keys deleted under `v2-only` | REFUSED(configuration), no fallback |
| Mode edited back to `legacy-v1` | contract pin per environment fails in CI and in the pre-deploy check; the change needs an owner-signed decision record (same two-person record as key issuance) |
| **Code rollback to a build that predates the mode** (it ignores the variable and runs the legacy verifier) | not closed by configuration. Proposed: the export result carries a non-secret `verifier` marker (`"v1"` or `"v2"`) in the existing write-once result object, and the deployment runbook requires a post-deploy probe export that must report `"v2"`; a build without the marker is detectable as a downgrade. Needs a separate review because it touches the result format. |
| Request tries to choose the verifier | the request carries a version but the configuration decides; a mismatch is REFUSED |
| Partial rollout (some guard instances old, some new) | Durable Object guards are single-instance per object; the post-deploy probe covers the serving version |

## 5. Tests to write before implementation
1. The full section 2 matrix as a table-driven test with the recording harness proving **no storage read** for every refusal row.
2. Mode value fuzz: case variants, trailing whitespace, unicode lookalikes, `"null"`, `"undefined"`, JSON, numbers, arrays: all REFUSED.
3. Deletion tests: start from a valid `v2-only` configuration, remove each variable in turn: REFUSED, never a v1 acceptance. Same bytes that were valid with the keys present are refused once the keys are removed (revocation test T7).
4. Contract tests: rendered configuration without the mode is rejected for every environment (production, staging, lab); `legacy-v1` plus keys is rejected; per-environment pinned expected mode.
5. Downgrade regression: with `v2-only`, a correctly signed v1 envelope (valid lifecycle-key signature) is REFUSED.
6. Legacy preservation under `legacy-v1`: the complete existing `guard-export-method` and `guard-ledger-export` suites pass unchanged.
7. If the `verifier` marker is accepted: a probe test that the marker equals the configured mode and cannot be influenced by the request.

## 6. What this design does not do
It does not change the guard's persistent-state schema (the R06 DDL parity stays), does not add a revocation store, does not select key custody, does not touch the lifecycle operator key or the recovery approver keys, and does not authorize any deployment.

## 7. Open owner decisions
- The key-validity cap. The earlier proposal (24 h hard, 8 h default) is **not adopted by this document**; the validator takes the cap as a single named constant, all validity tests are parameterized on it, and the worst-case exposure of a stolen key after a failed revocation deployment equals the cap, so the value is a risk decision.
- Whether the `verifier` marker in the export result is acceptable (changes the result format, not the verification boundary).
- Whether step 1 (explicit `legacy-v1` plus the mandatory variable) may ship ahead of the v2 code, to close the downgrade surface early.
- Whether the staging rehearsal must include a failed deployment and a code rollback.
