# Criterion 9 evidence trust: R-5 closure, receipt-accounting review, provenance design, observer isolation (2026-11-09, from HEAD 83b1aba)

Design and review only where marked. Nothing here deploys, signs, rotates keys or approves a migration.

## 1. R-5 closure and mandatory-artifact coverage (implemented, 366ba23)
Finalization order was already correct: `kind-ledger.json` is added by `evidence.addJsonArtifact` before `evidence.finalize` (`lab/defense/ba0-field-run.ts`), so a real run lists it in `manifest.json.artifacts` and in `SHA256SUMS`. The gap was in the consumer: `gatherTallyInput` read files by name, and `verifyEvidenceDirectory` checked only the files `SHA256SUMS` listed, so an extra or replacement file was read unchecked. No producer change was needed and no historical evidence was touched.

`verifyMandatoryInventory` (`lab/defense/ba0-m1-tally-check.ts`) now covers `telemetry`, `kind-ledger`, `processes`, `external`, `server-level`, `core`, `accounting`, `connections` and `manifest.json`:
- Strict `SHA256SUMS` grammar (`<64 hex>␣␣<lowercase plain .json name>`). Anything else, duplicates, case aliases, `..`, `/`, `\` or absolute paths are refused (exit 2) before any file is hashed.
- `manifest.json.artifacts` must equal the `SHA256SUMS` set (names and hashes). A disagreement is an inventory conflict (ERROR).
- Any `.json` file on disk that is not listed is an ERROR (the unlisted replacement case).
- A mandatory artifact that is present but unlisted, not a regular file, or whose bytes do not match is an ERROR, and its bytes are never returned.
- The verified buffer is the buffer that is parsed and duplicate-key scanned (no second read).
- The journal `ledger-journal-field.ndjson` is deliberately not in the inventory; it is bound by the digest recorded in the listed `accounting.json`.
- A mandatory artifact absent from both disk and inventory keeps its specific reason (for example `kind_ledger_absent`, REJECT).

Regression: `tests/m1-evidence-trust.test.ts` reproduces the original R-5 probe (unlisted forged `kind-ledger.json`, previously exit 0) and now gets ERROR `m1.tally.evidence_inventory_invalid`. It also removes each mandatory artifact from `SHA256SUMS`, replaces and re-hashes a ledger (caught by the manifest conflict), and covers duplicate, alias, traversal, malformed and sums-only lines. The real field-run evidence (`lab-ba0-field-run.test.ts`) passes the inventory check.

## 2. Additional consistency checks (implemented, 366ba23)
| Check | Authoritative producer / semantics | Rule | Conflict found |
|---|---|---|---|
| Parameter fingerprint | `ba0FieldFingerprint(FIELD_LEVELS[levelId].thresholds)`: sha256 of canonical JSON of the level's code-pinned set, with `id` and `version`; recorded in `server-level.paramsFingerprintSha256` and `core.parameters.{id,version,sha256}` | all three must equal the pinned value for the evidence's own level; an unknown level cannot be accepted (`m1.tally.params_not_code_pinned`) | The field-run test rig uses a time-scaled `fast()` set, so real rig evidence now also carries this reason. Correct behavior; its test assertion lists both reasons. |
| Clean source | `manifest.git.dirty` from `collectGitState()` (`git status --porcelain -uall`, any line = dirty, git failure = dirty) | must be the boolean `false`; non-boolean or absent is ERROR (`m1.tally.source_tree_dirty`) | This working tree is dirty (untracked reports), so a real M1 run from it cannot be accepted until the tree is clean. |
| Window | `openedAt` and `closedAt` are two `Date` reads; `elapsedMs` is one rounded monotonic span, taken in adjacent statements (`ba0-field-run.ts` ~597 and ~620) | `|(closedAt - openedAt) - elapsedMs| <= 1000 ms` (`m1.tally.level_window_elapsed_inconsistent`) | Different clocks, so exact equality is not valid. The 1 s allowance is a documented constant for rounding and jitter, not a traffic threshold. |
| Anomalies | `accounting.json.anomalyTotal` = `collector.finalize().anomalyTotal` (same source as `manifest.metrics.anomalyTotal`) | non-negative integer, exactly 0; absent or non-count is ERROR | none |

## 3. Receipt accounting (review only; nothing implemented)
Today (`lab/defense/m1-tally-check.ts`): reducer `boundary`/`app` counters must be less than or equal to the matching process `stats`, and `boundary.arrived <= egress.attempted`. The reducer's `origin` stream is never compared. Concrete probes (evaluator level, all against otherwise valid evidence), **every one PASS**:

| Concern | Probe | Result |
|---|---|---|
| Missing origin receipts | reducer `app` and process app counters all zero although `egress.attempted > 0` | PASS |
| Duplicate receipts | boundary/app process counters inflated by 5000 each | PASS |
| Another campaign / bypass | app executes 99999 while boundary relayed 5 | PASS |
| Generator vs boundary | reducer `boundary` all zero although `egress.attempted > 0` | PASS |
| Boundary-to-app attribution | reducer `app.admitted > boundary.relayed` | PASS |

Why they hide: inequalities are one-sided (an upper bound is never checked), the origin stream is unused, and no relation links boundary and app counters. Receipts carry only a nonce; `processes.json` and the events contain no campaign or run identifier, so a receipt from another campaign cannot be recognised by content. Binding to the run comes only from the evidence directory.

Exactly comparable (proposal, needs authorization):
- reducer boundary/app/origin counters versus the collector's journal (`src: "b"|"a"|"o"` lines, anonymous refusals and orphans included) plus the process `stats`: process stats = canary share (journal) + reducer external share, when the boundary/app channels report `dropped == 0` and drained.
- reducer `egress.attempted` = `boundary.arrived` + attempts refused before the boundary (a stated, finite set), per request nonce.
- `app.executed` relation to `boundary.relayed` (each relayed request is admitted at most once), per nonce.
Not exactly comparable: `connections.acceptedRemote` versus accepted requests (keep-alive reuses connections); pre-parser and kernel drops (outside every counter); generator-side counts (a separate package, belongs to the repeatability/reconcile criteria).

## 4. Evidence authenticity and provenance (design only)
Seven properties, and what exists:
1. **Internal consistency:** criterion 9 (identities, cross-artifact equalities). Present.
2. **Byte integrity:** `SHA256SUMS` plus manifest, now enforced for the consumed set. Present, but it only detects accidental change.
3. **Artifact completeness:** inventory of mandatory artifacts (R-5). Present.
4. **Producer identity:** none. Nothing says which process or code wrote an artifact; `manifest.git` records what the verifier-side checkout looks like, not what ran.
5. **Run identity:** run id and campaign id are plain strings written by the same process; nothing is committed before the run.
6. **Independent observations:** the reducer, collector and processes all belong to one harness; the generator report is a separate package, not cross-bound.
7. **Authenticity against deliberate substitution:** absent.

**Can a process that controls all evidence files and `SHA256SUMS` forge the package? Yes.** `SHA256SUMS` and `manifest.json` carry no secret and are in the same directory. Such a process can generate any self-consistent set (identities, level binding and pinned fingerprints all verify) and checksum it. Criterion 9 cannot detect this and does not claim to.

Smallest architecture without self-attestation (no new keys needed):
1. **Pre-run commitment held by someone else.** Before a run, the owner's workstation records a campaign commitment (campaign id, level id, code-pinned fingerprint, git SHA, a random run secret held by the generator, planned start) in an append-only place the server process cannot write (a local signed commit or tag on the owner's machine is enough for the lab).
2. **Rolling digest beacons to the independent party.** During the run the external generator, which is a different process, host and credential, receives from the server a hash chain (digest of cumulative journal and the telemetry tick, every N seconds) and stores it itself. The server cannot rewrite what the generator already holds.
3. **Finalization digest delivered out of band.** At close, the server sends the digest of `SHA256SUMS` to the generator, which countersigns or simply records it in its own package next to its client-side counts. A verifier run by a third party accepts a package only if (a) the pre-run commitment exists, (b) the beacon chain held by the generator is a prefix-consistent chain ending in the finalization digest, (c) the generator's client-side counts agree with the reducer's external counters, and (d) the target's own request log (cloud provider, read-only) agrees on the request count.
A signature alone does not establish independence: a key held by the same process attests only that the same process said it. A signed finalization manifest adds value only when the key is held by, and the signing is done by, the independent collector. Independence criteria: different principal, different host or account, write path the server cannot reach, and a verifier that is not run by the SUT. Remaining trust: the owner and generator operator are one party in the lab; collusion between them is outside this design. The target provider's log is the only observation not controlled by the lab operator.

## 5. Observer isolation (implemented, bb3f9ab)
- `workers/lab-lifecycle-observer.ts`: `LIFECYCLE_OBSERVER_ENVIRONMENT` must be exactly `"lab"`; checked at the top of `observeLabReconciliation` and in `scheduled` before `validateRuntimeSecrets`. Missing, non-string, case/whitespace variants, `production`, `staging` all refuse before any bucket or Authority access (counting-stub tests: zero calls). No capability added; same single reader method and two result-bucket operations.
- `deployment/lifecycle-private-contract.ts`: the lab observer validator requires `vars` to be exactly `{LIFECYCLE_OBSERVER_ENVIRONMENT:"lab"}`. Template, local rendered config and the workerd integration test updated. Staging and production validators still reject the lab configuration.
- `scripts/lab-observer-deploy.ts`: validation by default; `--execute` runs one fixed `wrangler deploy --config deployment/lifecycle-observer.lab.jsonc`; no other argument or config path; refuses the armed cron state; refuses any other config under `deployment/` whose `main` names the lab observer. I ran only the validation mode.
- Tests `tests/lab-observer-isolation.test.ts` (8): marker matrix, no production/staging config binds a lab entrypoint or service, the production entry exports no `Lab*` class, the lab read-only entrypoint only addresses `LAB_ADMISSION_AUTHORITY_ID`, alternative entrypoint configs refused.
- Production Authority review: `production-index.ts` exports only production classes and every non-lab config binds only non-lab entrypoints. **No production capability violates the boundary; no production code was changed.**
- Limitations: the marker is declarative (a Worker cannot read its bucket names). The wrapper is bypassable by a manual `wrangler deploy` or a different config file. The decisive boundary is the Authority: the lab entrypoint is a different class of a different Worker bound to the lab Authority id, so a mis-deployed lab observer can reach nothing in production.
- Registry: the observer is still PENDING. Its blob changed (`b0c2eb42…` to `d6d45079…`), so `reviewedBlob` and `reviewedSha256` were updated to the new reviewed identity; reviewId and PENDING status are unchanged. Older identities stay in the acceptance package and git history.

## 6. Migration semantics
Registry: 44 entries, 4 APPROVED (two instrumentation, `admin-gateway/index.ts`, `lab-operator-lifecycle-executor.ts`), 40 PENDING. A test now asserts that the approved files' imports (`ingress-protocol`, `bounded-jwks`, `authority`, `operator-command`) remain PENDING and non-effective, still appear as pending drift in the two open guards, and that the registry has no deployment field. Approval is per file; dependency closure and deployment are separate decisions. The `fabe5ab` approvals are unchanged.
