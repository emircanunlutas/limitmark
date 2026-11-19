# M1 unified acceptance: false-PASS closure (2026-11-09, from HEAD 885c403)

Local, additive. No historical verdict, byte-pinned file or protected evidence was changed. `QUALIFIED` remains unreachable. Production remains NO-GO.

## 1. The five confirmed paths and their corrections
| # | Confirmed path | Correction | Where |
|---|---|---|---|
| 1 | Forged PASS with the (public) package identity or a copied identity hash | A PASS is no longer read from the supplied result. Acceptance re-runs the deterministic evaluator over authoritative bytes and accepts a component only when the RECOMPUTED result passes AND the supplied result agrees in outcome, reasons and material claims. Disagreement is ERROR (`supplied_result_disagrees_with_recomputation`) | `lab/m1/acceptance.ts` `gatherAuthority`, `evaluateAcceptance` |
| 2 | Outcome/reasons changed after evaluation | The result's `outputSha256` (canonical JSON of the artifact without its own provenance block) must match; and, if the forger re-seals it, the edit disagrees with the recomputation | `lab/m1/result-provenance.ts`, `outputDigest` |
| 3 | One forged component among genuine ones | Every component is checked independently against its own recomputation; any ERROR makes the set ERROR; there is no averaging | `evaluateAcceptance` |
| 4 | Observer or retained records modified after evaluation | The result declares the sha256 of every input it read; acceptance recomputes those digests from the bytes it reads now (`inputs_not_the_bytes_read`) and recomputes the verdict from them | `observedInputs` |
| 5 | Contradictory or missing metadata (`runId`, `inputs`, `claims`) | Closed result schemas per component (exact key set, fixed contract string, `runId` equals the package identity, closed `claims`, closed provenance block); empty or partial input declarations are refused | `schemaProblems`, `provenanceProblems` |
The previous pin tests (`CONFIRMED_FALSE_PASS`) are replaced by `tests/m1-acceptance-adversarial.test.ts`, which now asserts ERROR, REJECT or INCOMPLETE for all five and for the additional probes (12 tests).

## 2. What is recomputed and what is only consumed
| Component | Recomputed by acceptance from | Same evaluator as the writer | Missing input |
|---|---|---|---|
| Criterion 9 tally | the finalized package (`gatherTallyInput` + `evaluateTallyAgainstLedger`) | yes (imported) | n/a |
| Receipt reconciliation | the package and, when the level carried remote traffic, the generator report bytes (`gatherReceiptInput` + `evaluateReceipts`) | yes (imported) | generator report absent and external traffic present: INCOMPLETE |
| Independent canary + origin receipts | the observer records (`readObservation` + `evaluateObservation`) | yes (imported) | observer directory absent: INCOMPLETE |
| Provenance | the package and the retained records (`verifyProvenance`) | yes (imported) | retained directory absent: INCOMPLETE |
| Status overlay | `server-level.json` of the package and the generator report bytes, with the UNCHANGED `finalFrom`, `evaluateStatusOverlay`, `overlayIsWellFormed`, `m1Accepted` and thresholds | the orchestration of `ba0-m1-reconcile.ts` is repeated in acceptance (the original is not modified); a test proves the two agree on genuine and failing inputs | generator report absent: INCOMPLETE |
Overlay inputs identified: exactly `server-level.json` (in the package, covered by `SHA256SUMS`) and `generator-report.json` (a separate party's file, not in the package; its sha256 is recorded in the overlay result and verified). The optional `--final` cross-check needs `final.json` of another evidence run: acceptance does not take it, so an overlay written with `finalCrossChecked: true` cannot be reproduced and is ERROR rather than accepted.
Consumed, not recomputed: nothing decides a verdict. The supplied artifact is an audit record that must agree with the recomputation.
Not recomputable here (and therefore not claimed): the authenticity or custody of any input. Anyone who can write the package, the observer records, the retained records AND the generator report consistently still obtains `LOCALLY_CONSISTENT` (the same-actor limit, unchanged).

## 3. Result-provenance contract (`resultProvenance`, written by every result writer)
| Field | Producer | Verified by acceptance against |
|---|---|---|
| `contract` | writer | fixed string `m1-result-provenance-v1` |
| `component` | writer | the slot it is presented in |
| `evaluator.contract` | writer | fixed per component |
| `evaluator.sources[]` `{path, gitBlobId}` | writer reads the evaluator source files and computes git blob ids (`git.blob.` prefix: the evidence scanner admits a bare 40-hex value only in a gitSha field) | the same files read now |
| `inputs[]` `{role, sha256}` | writer hashes the exact bytes it read | the bytes acceptance reads now; role set fixed per component, never empty |
| `evaluatedAt` | writer clock | well-formed ISO time only; never a freshness proof, no threshold |
| `producerClaim` `{claimed, verified:false}` | writer | exact value; `verified` is always false |
| `outputSha256` | writer: sha256 of the canonical artifact without this block (no circular dependency) | recomputed from the artifact |
Roles: all components `package.finalization`; tally `package.journal`; receipts `package.journal` (+ `generator.report`); overlay `package.server.level`, `generator.report`; observation `observer.canary`, `observer.receipts`, `observer.meta`; provenance `retained.commitment`, `retained.beacons`, `retained.final`.
A forged block cannot substitute for recomputation: a complete, re-sealed block over a false result still disagrees with the recomputed verdict (tested). The block is not authentication; no key or signature is involved.

## 4. Mandatory fields by component (closed key sets)
All: `contract`, `scope`, the identity trio (`identity`, `identitySha256`, `identityProblems`), `claims`, `resultProvenance`.
tally (`ba0-m1-tally-check.ts`): `runId`, `tallyCheck`, `differences`, `ledgerSource`. receipts (`ba0-m1-receipt-check.ts`): `runId`, `generatorReportSha256`, `receiptCheck`, `identities`, `limitations`, `campaignAttribution`. overlay (`ba0-m1-reconcile.ts`): `baseVerdict`, `statusOverlay`, `m1StatusContract`, `allowedStatuses`, `inputs` (run id lives in `inputs.server.runId`). observation (`results.ts`): `runId`, `observation`, `summary`, `limitations`, `inputs`. provenance (`results.ts`): `runId`, `provenance`, `claimedProducer`, `problems`, `announcementSource`, `notClaimed`.
Claims are fixed: `defenseQualification: not_claimed` everywhere; receipts `authenticity: not_claimed`; observation `independentCustody: not_established`; provenance `authenticated: false`, `independent: false`.

## 5. Outcome rules (unchanged precedence)
ERROR (untrusted, malformed, unbound, disagreement) > REJECT (identity mismatch, a recomputed component not passed) > INCOMPLETE (component or authoritative input absent) > LOCALLY_CONSISTENT. Order of checks per component: identity, closed schema, authoritative input availability, result provenance against bytes read now, agreement with the recomputation, pass.

## 6. Fixtures
The previous acceptance world used same-shape synthetic overlay and receipts results. They are now REAL: `tests/support/m1-receipt-fixture.ts` builds one package that satisfies Criterion 9, the receipt reconciliation and the status overlay at once, plus a matching generator report, so all five components are produced by their real writers and recomputed.

## 7. New findings
1. `lab/m1/campaign.ts` `loadAcceptance` trusts a stored `m1-acceptance.json` after an identity match (by inspection; not probed). The same defect class one level up: a forged `LOCALLY_CONSISTENT` acceptance artifact would be consumed by the Criterion 7 wrapper. Smallest correction: the campaign wrapper re-runs `m1AcceptRun`'s evaluation per run from authoritative inputs. Not corrected (outside this authorization).
2. The overlay recomputation repeats the orchestration of `ba0-m1-reconcile.ts`. Drift is possible if the original changes; the evaluator-source blob ids make a changed original invalidate old results, and the agreement tests would fail.
3. Evaluator source blob ids are computed from working-tree bytes. A checkout with different line endings yields different ids, so results from it are ERROR (fail-closed, not a false pass).
4. `inspectLifecycleAuthority` labels an UNKNOWN authority id as `environment: "production"` in its not-found answer (it echoes the unknown id). Pinned as an observation in `tests/lab-authority-binding.test.ts`.
5. Authenticity and custody are unchanged: same-actor forgery of every authoritative input is not detectable by this software.
