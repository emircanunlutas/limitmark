# Criterion 9 acceptance-path audit (after R-1..R-4) and lab observer isolation proposal (2026-11-09, from HEAD 0cfbd1e + b4da778 + fabe5ab)

Nothing here approves deployment, production enablement, or an observer change. The observer stays PENDING and unmodified.

## Part A. Criterion 9 PASS path: every artifact that can influence a PASS

`SHA256SUMS` covers the registered artifacts and `manifest.json`. `verifyEvidenceDirectory` checks only listed files. Rows marked **unlisted** are read by criterion 9 but are not checksummed (see R-5).

| Artifact (field) | Producer | Consumer | Validation | Cross-artifact identity | Missing / malformed | Can a contradiction still PASS? |
|---|---|---|---|---|---|---|
| `telemetry.json` final-tick `outcomes` (tally) | plane `OutcomeCounters` at emit | `gatherTallyInput` → `evaluateTallyAgainstLedger` | final tick required; closed key set (F-1); tally self-identities | tally vs kind ledger per kind; tally INGRESS_ACCEPTED ≥ external.accepted | missing → REJECT; malformed → ERROR | No (a self-consistent forged set is the residual below) |
| `kind-ledger.json` (counts, unsupported/dup/malformed) | collector `observePlaneEvents` hook | same | mandatory (F-2); closed shape; C1 identity | counts vs tally; collector.received vs processes plane | missing → REJECT `kind_ledger_absent` | **Yes if unlisted and replaced consistently (R-5)** |
| `processes.json` plane channel + `drained` | plane process | same | S1-S4 identities; C2-C4 vs collector | emitted == collector.received + dropped etc. | missing/malformed → ERROR | Only by forging all anchors together |
| `processes.json` boundary / app `stats` | boundary / app processes | receipt check (R-1) | inequality only | reducer boundary/app ≤ process stats; boundary.arrived ≤ egress.attempted | missing → ERROR | Inequality, not equality (canary adds to process counters); inflated process stats pass |
| `external.json` counters | external reducer | lane reader | `accepted` > 0 (R-1); terminal sum == accepted, unresolved 0; per-kind counts vs ledger − journal | `== server-level.reconcileInput.externalAccepted`; ≤ `connections.final.acceptedRemote` condition | missing/malformed → ERROR; zero → REJECT `external_lane_inactive` | Only with consistent forgery of reducer + copy |
| `server-level.json` (levelId, campaignId, gitSha, fingerprints, window, serverSide, reconcileInput) | `ba0-field-run` | `readLevel` (R-4) | HEX40/HEX64, non-null window, `serverSide.status === complete`, `failureClass` present, reasons | vs `core.json` (level, campaign, fingerprints, status); vs `manifest.git.gitSha`, `manifest.result` | missing → `level_evidence_missing` | See residual 3-5 |
| `core.json` (level, parameters, sequence, firstReason, phasesCompleted) | `ba0-field-run` | `readLevel` | steps close_ingress, drain, final_telemetry, snapshot all ok; `firstReason` present and null; phasesCompleted true | as above | as above | See residual 3-5 |
| `manifest.json` (result, git) | `EvidenceRun` | `readLevel` | result SERVER-COMPLETE; gitSha HEX40 | == server-level.gitSha | missing → ERROR | `git.dirty` is not consulted (residual 4) |
| `connections.json` final | plane listener | R-1 | acceptedRemote ≥ 1; no equality (keep-alive) | acceptedRemote ≥ 1 when external.accepted > 0 | missing → ERROR | Counter semantics differ, only existence is checked |
| `accounting.json` journal digest/lines/overflow | collector | journal verification | digest, line count, overflow false; duplicate keys (R-3) | digest of unlisted `ledger-journal-field.ndjson` | missing → ERROR | `anomalyTotal` not required zero (residual 6) |
| `ledger-journal-field.ndjson` (**unlisted**) | collector | per-kind journal counts | per-line parse, duplicate keys, digest | via `accounting.json` digest | mismatch → ERROR | Detected by digest, but `accounting.json` itself is the anchor |
| `SHA256SUMS` | `EvidenceRun.finalize` | `verifyEvidenceDirectory` | listed files only | n/a | n/a | **Unlisted files are never verified** |

Negative tests exist for missing, substituted, truncated, contradictory and duplicate-key evidence (`tests/m1-criterion9-closure.test.ts` 13 tests, `m1-tally-check.test.ts`, `m1-kind-ledger.test.ts`).

### Residual false-PASS paths (reported, not implemented)

1. **R-5 (confirmed by probe): unlisted artifact consumption.** A forged `kind-ledger.json` that is absent from `SHA256SUMS` is read and yields PASS (exit 0). Proposed fix: criterion 9 requires every artifact it reads to be listed in `SHA256SUMS`, and fails closed otherwise.
2. A fully self-consistent forged evidence set passes. Criterion 9 is internal consistency, not authenticity; authenticity needs the checksum plus an external anchor (campaign manifest committed before the run).
3. The parameter fingerprint is checked for shape and cross-artifact equality, not against the code-pinned `BA0_FIELD_V1` fingerprint.
4. `manifest.git.dirty` is ignored; a dirty tree can PASS.
5. `window.elapsedMs` versus `closedAt − openedAt` is not checked.
6. `accounting.anomalyTotal` is not required to be zero.
7. Receipts are inequality-checked only.
8. No real external-lane run exists: the loopback rig has no remote peer, so a real run currently yields REJECT with only `m1.tally.external_lane_inactive` (asserted in `lab-ba0-field-run.test.ts`).

None of 1 to 7 is implemented. Item 1 is the one I recommend authorizing first.

## Part B. Lab lifecycle observer isolation (`workers/lab-lifecycle-observer.ts`, HOLD)

Facts: the observer binds `REQUEST_BUCKET`, `RESULT_BUCKET` and `LIFECYCLE_READER` (read-only entrypoint) and has no signing or write path to the Authority. `fetch` returns 404, `scheduled` runs only if the secret policy passes. Its lab-ness is today defined only by `deployment/lifecycle-observer.lab.jsonc` (bucket and service names), enforced by `validateLabLifecycleObserverConfig`, which only tests call. The repository has no deploy script, so a human running `wrangler deploy --config <any file>` bypasses every validator. In contrast the lab executor checks `OPERATOR_EXECUTOR_ENVIRONMENT === "lab"` at runtime.

| | (1) Mandatory fail-closed deploy-time validation | (2) Runtime environment/authority validation |
|---|---|---|
| What | A single deploy wrapper script (`scripts/deploy-lab-observer.ts`) that calls `validateLabLifecycleObserverConfig` on the exact file, then runs wrangler | A required var `LIFECYCLE_OBSERVER_ENVIRONMENT = "lab"` checked in `scheduled`/`observeLabReconciliation` before any bucket read; fail closed otherwise |
| Strength | Validates the real bucket and service names | Travels with the deployed worker, applies to every deploy path |
| Bypass | Direct `wrangler deploy`; nothing in the repository forces the wrapper | A config can set the marker and bind production buckets: the Worker cannot read its bucket names at runtime, so the marker is declarative only |
| Verdict | Necessary, not sufficient | Necessary, not sufficient |

Neither alone is enforceable. Bindings cannot be introspected at runtime, and wrangler cannot be forced through a repository script.

### Minimal proposal (not implemented)

1. **Runtime marker (code, small).** Add `LIFECYCLE_OBSERVER_ENVIRONMENT: "lab"` to the lab config vars and to `validateLabLifecycleObserverConfig`; in `scheduled`, return before any read unless `env.LIFECYCLE_OBSERVER_ENVIRONMENT === "lab"` (same pattern as `OPERATOR_EXECUTOR_ENVIRONMENT`). The production observer must not accept `"lab"`, and the lab observer must not accept the production value. This stops a lab bundle from running in production config by accident, and a production config from running the lab bundle.
2. **Authority-side enforcement (the real invariant).** The lab observer holds only `LabAuthorityLifecycleReadOnly`. The Authority entrypoint for production should reject callers that are not the production observer; the lab entrypoint is already a separate class bound to `limitmark-admission-service-lab`. The invariant "a lab observer cannot reach a production Authority" is therefore carried by the service binding name plus the separate entrypoint, and a test should assert that the production Authority exposes no `LabAuthorityLifecycleReadOnly`.
3. **Deploy path (policy, not code).** Provide `scripts/deploy-lab-observer.ts` that validates then deploys, and add a test that fails if any other file under `deployment/` binds `workers/lab-lifecycle-observer.ts` as `main`. This narrows but cannot prevent manual `wrangler deploy`; the residual stays documented.

Proposed tests: lab marker missing, `"production"`, `"staging"`, `"LAB"`, wrong type each leave both buckets untouched (counting stub, workerd); validator rejects a config without the marker; no `deployment/` config other than the lab file references the lab observer.

Observer decision: remains PENDING until items 1 and 2 are authorized, implemented and reviewed.
