# M1 unified acceptance: security review, result provenance, freshness, and remote architecture (2026-11-09, from HEAD 303ec0a)

Review and design only. The evaluator (`lab/m1/acceptance.ts`) and result writers are NOT modified. Probes live in `tests/m1-acceptance-adversarial.test.ts` (9 tests; tests named CONFIRMED_FALSE_PASS pin today's defective behavior so a correction flips them on purpose). Nothing here authorizes a remote target, key, or production change. Production remains NO-GO; `QUALIFIED` stays unreachable in every probe.

## 1. Are independently produced results revalidated? No.
`evaluateAcceptance` re-derives only the identity of the SERVER PACKAGE (from checksum-verified bytes). Every other component is a JSON file loaded through the strict inventory, which proves only that the file matches its own `SHA256SUMS` (self-consistency, not origin). The evaluator then checks (a) the identity block parses, (b) `identitySha256` equals the digest of the identity fields, (c) the identity equals the package identity, (d) a shallow shape (`outcome === "PASS"` and `reasons` empty, or the provenance level strings). The recorded `inputs.*Sha256` digests, `runId`, `claims` and `summary` are never consulted, and no evaluator is re-run. The identity is public (readable from the package) and its digest is an unkeyed hash of public fields, so (b)/(c) bind a result to a run, not to the truth of the result.

## 2. Probe results
| # | Probe | Result | Status |
|---|---|---|---|
| 1 | Forged PASS (observation, provenance, tally, receipts) with correct package identity, written as a normal finalized evidence run, over a package whose REAL observer evidence failed and whose journal was rewritten | `LOCALLY_CONSISTENT` | **CONFIRMED false-PASS** |
| 2 | Same with a copied identity hash | identical; digest is a pure function of public fields | **CONFIRMED** |
| 3 | Genuine result, payload fields substituted (outcome flipped, reasons cleared, summary replaced), identity untouched | `LOCALLY_CONSISTENT` | **CONFIRMED** |
| 4 | Stale results replayed against a re-finalized package (same run id, different `SHA256SUMS` bytes) | REJECT by `finalizationSha256` (or ERROR if the package no longer verifies) | holds |
| 5 | One forged result among genuine ones; components contradicting each other | `LOCALLY_CONSISTENT`; no cross-component check | **CONFIRMED** |
| 6a | Package bytes modified after evaluation | no identity, every result ERROR | holds |
| 6b | Observer / retained records modified after their result was written | still `LOCALLY_CONSISTENT`; recorded input digests never compared | **CONFIRMED** |
| 7 | Contradictory producer metadata: top-level `runId` of another run, empty `inputs`, missing `claims` and `announcementSource` | accepted; ignored | **CONFIRMED (minor)** |
| 8 | No identity block, malformed block, wrong digest, wrong shape; missing result | ERROR; INCOMPLETE | holds |
Nothing reaches `QUALIFIED`. The false-PASS impact is bounded: the outcome is only ever `LOCALLY_CONSISTENT`, which already carries the "authenticity unverified, no custody" disclaimers. But the label is meant to mean "locally demonstrable checks passed", and a local producer who can write an evidence run can currently assert that without the checks passing.

## 3. Smallest safe corrections (not applied)
1. Recompute, do not consume. Tally, observation and provenance evaluation are deterministic functions of bytes the acceptance run can read (the package, the observer directory, the retained store). Acceptance should call those pure evaluators itself and require the supplied result to equal the recomputed outcome and reasons; the supplied artifact becomes an audit record. This closes probes 1, 2, 3, 5.
2. Compare recorded `inputs.*Sha256` with the digests of the bytes re-read now (observer directory, retained store, package `SHA256SUMS`). Closes 6b even before (1).
3. Strict closed-key schemas per component; require `inputs`, `claims`, `announcementSource` and a top-level `runId` equal to `identity.runId`. Closes 7.
4. Overlay and receipts depend on the generator report and byte-pinned reconcilers; until their inputs are bound (item 2 of section 4), acceptance should record them as `CONSUMED_NOT_RECOMPUTED` and the outcome label should say so rather than `LOCALLY_CONSISTENT` alone. A forged overlay or receipts PASS stays possible until then.
5. Cross-component consistency (for example receipt totals vs tally totals vs observation journey counts) so that two forged-independently results cannot both be internally plausible.

## 4. Result provenance and producer binding (design only)
**Evaluation record** (one per component, additive, in the result artifact):
| Field | Meaning |
|---|---|
| `evaluator` | `{ contract, sourceBlobSha1s[] }`: contract string plus the git blob ids of the evaluator modules that ran (read from the running tree, not asserted by the caller) |
| `inputs[]` | `{ role, sha256 }` of the exact bytes read: package `SHA256SUMS`, each package artifact digest used, generator report, observer files, retained commitment/beacons/final |
| `packageIdentity` | the nine-field identity; `finalizationSha256` binds the package bytes |
| `runId`, `campaignId` | copies, required equal to the identity |
| `evaluatedAt` | wall clock of the evaluator host; informational, never a freshness proof |
| `producerClaim` | free text, labelled `CLAIMED_UNVERIFIED` |
| `outputSha256` | digest of the canonical result body |
**Reproducible evaluation vs authentication.** Anyone holding the inputs can re-run the evaluator and compare `outputSha256`; that detects substitution of results and is the property to build first. It says nothing about who produced the inputs. Cryptographic producer authentication (a key held by the evaluator operator, signing the record) would add attribution, and is deliberately not designed here: no production key, no signing infrastructure.
**Should acceptance re-run checks?** Yes, for every check that is a pure function of retained bytes (tally, observation, provenance, receipts once the generator report is an input). The unified evaluator then has two roles only: recompute, and compare to the supplied record. Overlay is the exception until the byte-pinned reconciler's inputs are all named in `inputs[]`.

## 5. Fresh-state and three-run review
What the evidence proves today, by property:
| Property | Status | Basis |
|---|---|---|
| Distinct run ids | directly observed | manifests; Criterion 7 and the campaign wrapper require distinct |
| Distinct campaign ids | directly observed, weak | operator-chosen labels in `server-level.json`; distinctness proves naming, not independence |
| Distinct generator run ids | directly observed | generator report |
| Distinct finalization digests | directly observed | `SHA256SUMS` bytes; the campaign wrapper requires distinct |
| Non-overlapping windows | observed but self-reported | window times come from the server process clock; no external time source |
| Reset process counters | indirectly inferred | receipt PASS shows counters reconcile exactly from zero to the run's ledger; a process carrying counters from an earlier run would fail |
| Fresh process instances | inferred only | follows from reset counters if the process was reused with a restart; no instance id / start time is bound |
| Fresh target state | unproven | storage (authority, ledger, rate state) emptiness is not attested |
| Machine / VM reuse | unproven | no host identity, boot id or image digest in the evidence |
| Configuration consistency | partly observed | git SHA, code-pinned parameter fingerprint and workload fingerprint are equal across runs; the effective runtime configuration and environment of a remote target are not attested |
The existing ±5 percentage-point shed rule and shed-reason-set rule are preserved unchanged and are not freshness evidence.

**Minimal freshness attestation contract (future authorized disposable remote environment; not implemented).** Written by the environment controller, not the SUT, and listed in the pre-run commitment:
- pre-run: `environmentId` (unique per run), `instanceId`, `bootId`, `imageDigest`, `configDigest`, `createdAt`, `emptyStateDigest` (digest of a canonical snapshot of the SUT's durable state, equal to a published constant for "empty"), `firstProbeCounters` (all zero, read by an independent probe before any traffic), `predecessors` (empty).
- post-run: `destroyedAt` and a teardown receipt naming the same `environmentId`.
- cross-run rules for a three-run campaign: `environmentId`, `instanceId`, `bootId` all pairwise distinct; `createdAt` later than the previous run's `destroyedAt`; `imageDigest` and `configDigest` equal across runs (configuration consistency); attestation `createdAt` earlier than the run window open time.
- custody: the attestation's strength is the controller's custody. A controller run by the same actor as the SUT yields consistency, not authenticity.

## 6. Real M1 evidence architecture (design only)
Assumes external protections (CDN, WAF, platform rate limits) are absent or bypassed: the application-plane defenses are the only protection, and the measurement must not rely on any other layer.
**Components and ownership**
| # | Component | Owner / principal | Independent of SUT? |
|---|---|---|---|
| 1 | Disposable remote target (SUT + its storage) | environment controller account A | n/a (subject) |
| 2 | External traffic generator (attack load) | generator operator, separate host | independent measurement of what it sent and received; its report is self-reported by the generator |
| 3 | Legitimate-user canary | observer account B, separate host and network path from the generator | independent of SUT and of generator, if B is a different principal |
| 4 | Origin receipt collector | observer account B (or C), at the origin boundary, records requests at arrival, never SUT counters | independent only if not operated by A |
| 5 | Evidence storage | account C, append-only, write path distinct from A | custody point; A cannot rewrite |
| 6 | Pre-run commitment | written to C before any traffic: campaign, level, params fingerprint, git SHA, nonce, freshness pre-run attestation, canary seed/journey plan | independent timestamp from C |
| 7 | Finalization and verification | verifier run by a reviewer, reading only C | reproducible; authenticity depends on C |
| 8 | Fresh-state attestation | controller account A (pre/post) plus an independent probe by B | controller claim = self-reported; first-probe zero counters = observed by B |
| 9 | Three-run campaign evaluation | reviewer, over three distinct environments, windows, campaigns | existing Criterion 7 rules + freshness cross-run rules |
**Independent vs self-reported.** Independent (if the custody separation is real): canary outcomes and latency, origin receipts, generator send/receive counts, commitment time. Self-reported by the SUT: its ledger, counters, journal, beacons, `server-level` verdict inputs, window times. Self-reported by the controller: environment creation and teardown. The verifier's role is to find contradictions between the two groups; it cannot make the self-reported group true.
**Legitimate-user journey** (canary, identical plan committed pre-run): homepage; static assets; navigation/FAQ; valid form submission; operational actions (only those the deployed system actually offers; any unsupported action listed as not covered, never invented); recovery (journey repeated after the load stops until success is restored or a bound expires) and residual restrictions (any challenge, rate limit or block still applied to the canary identity after recovery, and any applied to a fresh identity).
**Measurements.** Journey success rate = complete journeys / attempted journeys, per phase (baseline, attack window, recovery). Latency p50/p95/p99 per step and per journey, measured by the canary clock. Timeouts = requests without a response before the pinned timeout. False rejects = canary requests that the origin never received or that were answered with a deny for a legitimate identity (distinguished by the origin collector: a deny with no origin receipt is a rejection by the SUT; an unanswered request with no receipt is a timeout). Challenges and rate limits counted separately. Unexplained traffic = origin receipts with no attributable canary or generator request id; any nonzero count is a reject.
**Assumed absent protections.** The design adds no reliance on edge filtering, so origin receipts must include everything that reaches the origin, and the generator must be able to reach the SUT on the same path as the canary.
**Preconditions before any of this can run**: owner authorization of a specific disposable target and lane, separate principals for A/B/C, the acceptance corrections of section 3, the freshness contract of section 5. None are present.

## 7. Remaining blockers
Authorized external-lane qualification; separate custody principals; authenticity (producer keys, out of scope); the acceptance corrections (recompute, input-digest comparison, closed schemas); freshness attestation; three real remote runs; 40 PENDING migrations (see the migration review).
