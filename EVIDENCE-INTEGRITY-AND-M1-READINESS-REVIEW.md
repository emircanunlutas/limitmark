# Evidence integrity review, recovery-assertion review, baseline acceptance batch and M1 readiness (2026-11-08, HEAD 45a83fb)

Review only. No source, test, registry, threshold or historical file was changed by this review. Scratch probes were run from temporary files that were deleted; nothing is committed except this document.

## 1. Criterion 9 — false-PASS assessment

**What criterion 9 can and cannot show.** The tally is counted inside the plane process at emit time (`countingEmit`). The kind ledger is counted in the collector at receipt (`observePlaneEvents`). So criterion 9 is **internal accounting consistency of the plane-to-collector event path**. It is not independently observed end-to-end delivery: an event the plane never emitted is invisible to both records. End-to-end delivery is the job of criterion 2 (generator report, external accounting, origin receipts).

**Shared failure modes.** Tally and ledger share the same source events (an unemitted event is missed by both). They do not share the transport: channel loss, reorder, duplication, and transit truncation affect only the ledger, and are detected as shown below.

### Mutation and fault-injection results (deterministic probes against the committed evaluator)

| # | Fault | Result |
|---|---|---|
| 3 | one event lost in transit (seq gap) | REJECT (`sequence_gap`, `anchor_mismatch`, per-kind differences) |
| 3 | duplicate / reordered event | REJECT (`duplicates_or_reordered`); event not double counted |
| 4 | trailing events lost, plane anchor says 18, ledger saw 17 | REJECT (`anchor_mismatch`) |
| 4 | trailing loss and anchor absent | REJECT (`completeness_unanchored`) |
| 4 | zero tally and zero ledger while plane `lastSeq` = 18 | REJECT (`anchor_mismatch`) |
| 5 | dropped events (queue full): they consume seq numbers and are counted in the tally at emit | REJECT (gap and tally/ledger difference) |
| 8 | unsupported kind | REJECT |
| 9 | counts of 2^60 or NaN, negative, fractional | ERROR (not safe integers) |
| earlier tick as tally | REJECT (differences) |
| 7 | journal incomplete / reducer counters malformed | ERROR |
| 12 | ledger absent (older runs), no remote traffic | PASS by the old rule (see F-2) |

### False-PASS paths found (all confirmed by probe)

- **F-1 (tally key set is not closed).** `readSnapshot` accepts any key set and `compareToLedger` iterates only the tally's keys. A tally with a kind key deleted passes when that kind is not in any identity: `PROOF_ISSUED`, `L2_ENROLLED`, `L2_ENROLL_SKIPPED`, `PARSER_REJECTED`, with ledger counts of 2 or 1, returned **PASS**. A foreign extra zero key also passes. Real `OutcomeCounters.snapshot()` always zero-fills every kind, so this needs a truncated or foreign tally, but the evaluator does not require it.
- **F-2 (silent fallback).** If `kind-ledger.json` is absent (for instance the runner's isolated write failed and was swallowed, or it is a pre-ledger run), the evaluator silently uses the weaker journal-and-reducer rule. That rule cannot see the two enrollment kinds for remote traffic and passes when the tally has none. A new run should not be allowed to degrade this way.
- **F-3 (anchors partly unused).** Only `plane.lastSeq` and `plane.dropped` are compared. Contradictory channel stats pass: `emitted` ≠ `lastSeq`, `unacknowledged` > 0, `queued` > 0 with equal `lastSeq`, and `collector.received` ≠ ledger total (the artifact records `collector.received/lastSeq/droppedReported` but nothing compares them).
- **F-4 (empty level).** A level with zero events everywhere (total 0, `lastSeq` 0, tally all zero) passes criterion 9. Other criteria would fail it, but criterion 9 alone does not say "no traffic".

### Not false-PASS (checked)
- `>=` for the two enrollment kinds only relates ledger to **journal** (remote enrollments are legitimately absent from the journal). Tally-to-ledger equality still applies to them. So `>=` cannot hide a tally/ledger discrepancy; it can only fail to catch an inflated ledger count that the tally equally shows (shared failure, see above).
- Missing initial events: the first gap is counted from sequence 0, and `firstSeq` must be 1.
- Counter overflow and malformed numerics: rejected as ERROR.
- Completeness can be established only up to the anchors: ledger `lastSeq` = plane final `lastSeq`, `missingSeqs` = plane `dropped`. It cannot be established for events never numbered.

### Proposed minimal additive corrections (NOT implemented; authorization requested)
Evaluator-only, in `lab/defense/m1-tally-check.ts` and the CLI reader; no pinned file, no emission change:
1. F-1: require the tally `events` key set to equal `KIND_LEDGER_KINDS` exactly, and compare over the union of tally and ledger keys.
2. F-2: when `kind-ledger.json` is absent, add reason `m1.tally.kind_ledger_absent` (REJECT) unless the run predates the ledger commit (a recorded `ledgerRequired` flag derived from the run's git commit, or an explicit legacy argument that is reported in the artifact).
3. F-3: require `emitted === lastSeq`, `queued === 0`, `unacknowledged === 0`, `sent === received` when those fields exist (missing fields become `completeness_unanchored`), and require `collector.received === total + unsupported + duplicatesOrReordered` and `collector.lastSeq === ledger.lastSeq`.
4. F-4: require `INGRESS_ACCEPTED > 0` and `total > 0` for a level.
Each gets a mutation test. Estimated size: about 40 lines plus tests.

## 2. Recovery-evidence assertion (commit 45a83fb)

- Original assertion (`tests/recovery-evidence.test.ts`, "the judge is pure"): the import specifiers of `tests/support/recovery-evidence.ts` equal exactly `[authority-result-reader, recovery-decision-record, workers/admission-service/authority]`; the source contains none of `node:fs|node:child_process|fetch(|sign(|submit|claim|settle|replace|writeFile|initializeAuthority`; and its only export is `assessRecoveryEvidence`.
- Change: the third specifier removed from the expected list, and the unused import removed from the support file (commit `218ccef`). The other two assertions are untouched.
- Evidence of equivalence: in `218ccef^` the names `ADMISSION_AUTHORITY_ID` and `ADMISSION_POLICY_EPOCH` appear only in the import line (zero uses). `workers/admission-service/authority.ts` exports two string constants (`production-public-inquiries-v1`, `phase5c-i1-epoch-1`) and a pure module graph; nothing the judge could call. The six behavior tests in that file pass; the judge's decisions do not read those constants. Module-load side effects: none relevant (constants only).
- Assessment: the allowlist is still exact (a deliberate subset), so any new import still fails the test, including a re-added authority import. **No weakening of a security-relevant dependency or evidence invariant.** One note: the old list could be read as "the judge is anchored to the production authority identifiers", but because it never used them it gave no such guarantee. The test file itself still uses the constants for its fixtures. If the owner wants that anchoring, the judge would need to actually compare against them (a feature change, not proposed here).

## 3. Smallest dependency-safe baseline acceptance batch

Independent verification (not from previous summaries), for all 44 entries: working-tree sha256 (LF-normalized) equals `reviewedSha256`, `HEAD` blob equals `reviewedBlob`, and the historical blob equals the recorded value at all three baselines (or the file is absent at all three for added files). 44 of 44 match. Entry count: 2 APPROVED, 42 PENDING.

Dependency method: static relative imports resolved against the registry; a candidate is "dependency-safe" only if every registered file it imports is approved, in the same batch, or absent.

**Recommended batch (3 entries, no registered dependency):**

| Path | Change | Historical blob | Replacement blob | ReviewId | Production reachability | Security impact | Existing tests | Missing | Recommendation |
|---|---|---|---|---|---|---|---|---|---|
| `workers/admin-gateway/index.ts` | modified | `98ea23e` (prefix) | registry `reviewedBlob` | BASELINE-V2/PRODUCTION_PREPARATION | yes (production admin gateway entry) | removes non-handler re-exports (workerd rejects them); handler unchanged; no behavior or auth change | `admin-gateway.test.ts` (imports `./gateway`, not the entry), workerd suites | an assertion that the entry's only export is the default handler | approve after the missing assertion is added |
| `workers/lab-lifecycle-observer.ts` | added | absent | registry | BASELINE-V2/LABORATORY | lab only | read-only relay of signed envelopes; no unsigned read; fixed 404 fetch | `authority-activation-guards`, `lab-environment-isolation` | negative test for the 404 and unsigned-diagnostic path | approve (lab-only, leaf) |
| `workers/lab-operator-lifecycle-executor.ts` | added | absent | registry | BASELINE-V2/LABORATORY | lab only | initialization submitter; no rotation method (Gate 9 closed), environment check `lab` | same two files | test that no rotation method is exposed | approve only after a full read by the owner (it submits lifecycle artifacts) |

Exact blob ids are in `tests/support/reviewed-migrations.ts` and were verified equal to `git rev-parse HEAD:<path>`; I list them by reference rather than retype 40-hex strings.

**Next candidate, not in the minimal batch:** `src/lib/db/database.server.ts` (leaf, production-reachable; adds optional verified TLS: `rejectUnauthorized: true`, CA, servername; the TLS-key change check). Existing tests: `database-tls`, `production-database-tls`, `production-launch-policy`. Recommend approving it **together with** its consumers in the launch-policy group, not alone.

**Dependency groups kept together (all stay PENDING):**
- Ingress signer: `workers/ingress-signer/index.ts` + `signer.ts` (signer depends on `src/lib/ingress-protocol.ts`, shared-production hold, so the group also waits on that file).
- Public inquiry page and launch policy: `src/app/test-talep-et/page.tsx` + `src/lib/production-launch-policy.ts` (+ leaf `database.server.ts`).
- Public inquiry route, runtime, launch policy: `route.ts`, `public-inquiry-production-runtime.server.ts`, `public-inquiry-runtime.server.ts`, `production-launch-policy.ts`, handler, verifier, admission client.
- Lab attestation: `authority-attestation-config.ts`, `-signer.ts`, `authority-attestation.ts`, verifier `src/lib/authority-result-attestation.ts` and `-trust.ts` (shared holds).
- Five guard-export entries on hold: `dispatch-guard.ts`, `guard-export.ts`, `guard-reader.ts`, `lifecycle-mailbox/index.ts`, `lifecycle-observer.ts` (and `lab-dispatch-guard`, `lab-processor`, `lab-index` depend on `dispatch-guard`, so they wait too).
- `workers/shared/bounded-jwks.ts` (4-line behavior-preserving fetch wrapper) imports pending `ingress-protocol.ts`, so it waits with the shared group.
- Pending by earlier owner instruction: OIDC claim-check (`google-id-token.ts`) and telemetry label-set (`public-inquiry-telemetry.server.ts`, `-otel.server.ts`).

Effect on the guards: approving this batch removes at most three entries from the historical diff. Guards 958 and 1204 will still fail until all verdict-path entries are approved. Do not expect them to turn green from this batch.

## 4. Local M1 readiness

Finding that governs everything: the M1 level workloads (`ba0-l7-pressure-c1` and siblings) are `remoteOnly: true`; `authorizeRun` refuses them for any `lab-local` target (`workload-remote-only`). A complete M1 level therefore needs a reviewed disposable remote target and an external generator. `--local-only` correctly cannot run them. With cloud provisioning and external traffic not authorized, **a full M1 dry run cannot be performed with the current policy.** The loopback test rig runs the same runner code with a fake `/proc`, which demonstrates mechanics only.

| Requirement | Status | Basis |
|---|---|---|
| L1/L2 field level (runner, states, finalization, teardown) | Implemented, demonstrated in rig only | `lab-ba0-field-run.test.ts` (15 tests); no real level has been run |
| Independent canary | Implemented, demonstrated in rig | JCR 1 in all six phases in rig |
| Baseline latency measurement | Implemented, demonstrated in rig | baseline phase in rig; no real-network baseline |
| Journey completion | Implemented, demonstrated in rig | complete journeys, zero unresolved in rig |
| Origin receipt accounting | Implemented, demonstrated in rig | identities hold in rig; real remote-lane traffic untested |
| Resource sampling | Implemented, not demonstrated on a real host | `/proc` sampler faked in rig; Linux kernel sampling not exercised in a level |
| Recovery measurement | Implemented, demonstrated in rig with shortened quiet period | real quiet period is 135 s |
| Criterion 7 repeatability | Implemented, tested on synthetic evidence; not demonstrated | needs three real runs |
| Criterion 8 status overlay | Implemented, tested; not demonstrated | needs a real server and report pair |
| Criterion 9 tally reconciliation | Implemented; kind ledger demonstrated in rig; four weaknesses (F-1..F-4) open | section 1 |
| Evidence provenance and run identity | Implemented and demonstrated | manifest, git state, SHA256SUMS, campaign id, server/report pairing |
| Fresh-state requirements | Implemented in preflight (no stale listener, lock); target-side freshness **Blocked** | needs the remote target |
| Real L1/L2 qualification run | **Blocked** | remote-only workload; no authorized target; stale `gcp-sut-1` not renewed |

The four loopback HTTP workloads are infrastructure parity evidence and are not counted toward any row above.

## 5. Remaining engineering blockers
1. Two historical migration guards (958, 1204) stay red until the 42 PENDING entries are decided.
2. Criterion 9 corrections F-1..F-4 (authorization requested).
3. No authorized remote disposable target for an M1 level (policy: `remoteOnly`).
4. No real run of criteria 7, 8, 9.
5. Production remains NO-GO; Gates 9, 10, 11A closed.

## 6. Recommended approval sequence
1. Authorize criterion 9 corrections F-1..F-4 (evaluator-only).
2. Approve the 3-entry batch after the two missing tests are added (admin-gateway entry export, lab executor no-rotation surface); owner to read the lab executor.
3. Review the launch-policy group including `database.server.ts` and the ingress signer group.
4. Decide the shared-production-module group (`ingress-protocol.ts` first), then lab attestation, then guard-export.
5. Separately decide how an M1 level may be run (reviewed remote target and provisioning authorization); until then no three-run campaign.
