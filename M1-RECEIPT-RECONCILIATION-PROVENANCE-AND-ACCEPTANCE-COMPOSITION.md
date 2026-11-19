# M1 receipt reconciliation, receipt identity, provenance prototype and acceptance composition (2026-11-09, from HEAD 216ff81)

Nothing here adds an overall PASS gate, changes a historical verdict, approves a migration, or contacts anything outside this machine.

## 1. Receipt reconciliation contract (implemented: `lab/defense/m1-receipt-check.ts`, CLI `lab/defense/ba0-m1-receipt-check.ts`, 79e9d81)
Separate from criterion 9. Criterion 9 accounts for the plane-to-collector event path; this evaluator checks that what the downstream observers say they received equals what the ledger attributes to them.

### Counter semantics (written in the evaluator header; every comparison rests on these)
| Term | Meaning | Compared with |
|---|---|---|
| request | one `INGRESS_ACCEPTED` at the plane, keyed by a plane-minted nonce | never with connections |
| connection | a TCP connection; keep-alive makes connections <= requests | never compared with requests |
| attempt | plane `EGRESS_ATTEMPTED`; failure before the Boundary is `EGRESS_FAILED` (E3 requires none) | Boundary `arrived` (exact) |
| Boundary counters | `processes.json` boundary.stats; each increments with exactly one event of the same name | ledger attribution (exact), per kind |
| App counters | `counters.{admitted,refused,executed,stateMutations}` | ledger attribution (exact), per kind |
| origin receipt | the App's `served.{received,completed,aborted,overloaded}`: the only origin-side observation in the field level (the harness "control" origin is a bypass probe, not a delivery observation) | App admissions, completions (exact) |
| ledger attribution | every event belongs to exactly one of: the external reducer, a collector-registered record (journaled with a request id), or the anonymous set (journaled without one) | process counters = reducer + registered + anonymous |
| canary client | `canary.json.clientObservedMutations`, what the canary client saw succeed | journal `APP_MUTATED` of registered records (exact) |
| generator | a separate process with its own report (campaign, level, git SHA, counts) | reducer `accepted` and status table (exact), identity fields (equal) |

### Identities (exact; 36+ on real evidence)
- Per kind, Boundary (9 kinds) and App (6 kinds): process counter = reducer + registered journal + anonymous journal.
- Channel completeness: `emitted` of each process = number of events the ledger attributes, with no drop, queue, unacknowledged or gap; processes drained; `anomalyTotal` = 0.
- Pipeline chain (documented E5 relations): `arrived = admitted + rejected`, `admitted = appProofsIssued`, `relayed = admitted`, `relayed = forwardResponded + forwardFailed`, `App.admitted = Boundary.forwardResponded`, `executed = admitted`, `served.received = admitted`, `completed + aborted = received`.
- No alternative path in this workload (E3/E5): rejections, parser/protocol refusals, forward failures, App refusals, origin overload and egress failures must all be zero. They are not "explained away"; a nonzero value is a REJECT.
- Plane link: ledger `EGRESS_ATTEMPTED` = Boundary `arrived`; external lane alone: attempts = reducer boundary arrivals, reducer admitted = proofs, reducer App admissions = reducer `forwardResponded`.
- Independent canary client mutations = registered `APP_MUTATED`.
- Generator, required whenever the level carried remote traffic: identity fields equal the server level, zero transport failures (a failure the server never saw would need attribution and none exists), responses = `accepted`, status table = server status table.
Exact equality is used only where a counter and an event are the same increment point. Real-evidence check: on the rig's run (55 canary requests) every one of these holds exactly (`lab-ba0-field-run.test.ts` asserts PASS on that evidence), including boundary channel `emitted` 330 = 6 x 55 and app 176 = 3 x 55 + 11.

## 2. The five original false-PASS probes
Criterion 9 returned PASS for all five. `tests/m1-receipt-check.test.ts` (10 tests) reproduces each and the evaluator now rejects them.
| # | Probe | Rejected by |
|---|---|---|
| 1 | no app/origin receipts although egress attempted | `app_executed_equals_admitted`, `app_admitted_equals_boundary_forward_responded`, ledger attribution |
| 2 | process counters inflated by 5000 | `boundary_arrived_equals_ledger`, `app_admitted_equals_ledger`, `plane_egress_attempts_equal_boundary_arrivals` |
| 3 | App executes 99999 vs boundary relayed | `app_admitted_equals_boundary_forward_responded`, `app_executed_equals_ledger` |
| 4 | reducer boundary counters all zero | `boundary_arrived_equals_ledger`, `external_egress_attempts_equal_boundary_arrivals` |
| 5 | App admissions exceed attributable deliveries | `external_app_admitted_equals_forward_responded` |
A mutation test also moves each process counter and each attribution by +1 and -1: none passes.

## 3. Receipt identity (D2) and its limitations
Inspected: events carry `nonce` (unique, opaque, minted by the front for remote peers, documented as "a measurement key, never a security signal"), a per-channel `seq` and a kind. `campaignId` and `runId` appear nowhere in the `defense/` code (only in its README). `processes.json` counters carry no run or campaign field.
| Identity | Can a receipt be bound to it? |
|---|---|
| request | yes, by nonce, within one run only |
| observation source | yes, by channel (stream), not by an event field |
| run / campaign / level | **no.** Only the evidence directory, its manifest and the generator report (which carries its own campaign, level, run, git) name them |
| origin instance | **no** event field; only the aggregate `served` counters |
Consequences: the evaluator always reports `campaignAttribution: "not_established"` and the limitations `receipts_nonce_only`, `no_run_campaign_binding`, `origin_is_app_served_only`; it never infers campaign identity from directory placement; the generator report's identity fields are checked against the server level, and a missing report fails when remote traffic exists. A claim that a receipt belongs to this campaign needs the provenance layer. Process counters start at process creation, so cross-campaign reuse requires a reused process; nothing in the evidence rules that out.

Proposal (no production protocol or receipt format changed): an additive evidence-side `receipt-binding.json` written by the run, naming run id, campaign id, level id and the per-stream attributed totals, and sealed into the beacon chain of section 4. It would still be self-attested by the server process until the beacon/commitment layer is in place.

## 4. Provenance prototype (`lab/provenance/prototype.ts`, 54c2148; tests `tests/m1-provenance-prototype.test.ts`, 8)
Records are held outside the evidence directory by a separate party (modelled by a separate directory): `commitment.json` (campaign, level, code-pinned parameter fingerprint, git SHA, commit time, nonce, seal), `beacons.ndjson` (hash chain `link_n = sha256(link_{n-1}:n:runId:bytes:digest)` seeded by the commitment seal, each beacon a journal prefix digest), `final.json` (run id, last beacon, chain head, digest of `SHA256SUMS`, journal digest). No keys, no signatures, no network.
The verifier reports separate levels: byteIntegrity, artifactCompleteness, runBinding, producerIdentity (always `CLAIMED_UNVERIFIED`), independentCorroboration, authenticity (always `UNVERIFIED`), plus the fixed claims `authenticated: false`, `independent: false`. Its strongest overall statement is `CONSISTENT_WITH_RECORDS`.

Substitution, replay and tamper results (all in the test file):
| Case | Result |
|---|---|
| honest package + store | CONSISTENT; authenticity UNVERIFIED |
| artifact replaced and consistently re-hashed in manifest and SHA256SUMS | byteIntegrity VERIFIED, corroboration FAILED (`finalization_digest_mismatch`) |
| SHA256SUMS line removed / manifest edited / artifact edited / unlisted artifact / artifact removed | FAILED at byteIntegrity |
| retained records of another run | FAILED (`beacon_run_id_mismatch`) |
| commitment dated after run start | FAILED (`commitment_not_before_run`) |
| campaign / level / parameters / git differ from commitment | FAILED (named) |
| commitment edited after the fact | FAILED (`commitment_seal_mismatch`) |
| beacon chain truncated / altered / reordered | FAILED (`final_beacon_count`, `chain_broken`, `beacon_sequence`) |
| journal rewritten after the beacons, package re-hashed consistently | FAILED (`journal_prefix_mismatch`) |
| journal extended after the last beacon | FAILED |
| retained store missing | INCOMPLETE (corroboration ABSENT), never consistent |
| **same actor forges the package AND the retained store** | **CONSISTENT_WITH_RECORDS, authenticity UNVERIFIED, authenticated false, independent false.** The honest store exposes the same forgery (FAILED). |
This prototype shows what a separately held record can detect. It does not show independence: independence is custody (different principal, host and write path) and cannot be read from file content.

## 5. Proposed M1 acceptance composition (design only; no gate implemented)
Per run, ACCEPT-RUN requires all of the following bound to the same identity tuple (run id, campaign id, level id, git SHA, parameter fingerprint, workload fingerprint). Any missing, malformed, unbound or conflicting input is not accepted.
| # | Input | Producer today | Required result | Fail-closed on |
|---|---|---|---|---|
| 1 | Base field verdict | `ba0-field-reconcile` (byte-pinned) via `decideFinal` | VALID, from a complete, non-INVALID level | anything else, absent, INVALID preserved |
| 2 | M1 status overlay | `ba0-m1-reconcile` | accepted (`m1Accepted`) | absent/malformed overlay |
| 3 | Criterion 9 tally | `ba0-m1-tally-check` | PASS | REJECT/ERROR/REFUSED |
| 4 | Receipt reconciliation | `ba0-m1-receipt-check` | PASS with generator report present | REJECT/ERROR, missing report |
| 5 | Legitimate-user canary | base verdict (JCR 100%, p95 window latency) plus receipt link `canary_client_mutations_equal_ledger` | both hold | either missing |
| 6 | Provenance | prototype only | `CONSISTENT_WITH_RECORDS`, reported as `unauthenticated` | absent store, any FAILED level |
Per campaign, ACCEPT-CAMPAIGN additionally requires criterion 7 (3-run repeatability, `ba0-m1-repeatability`) over three ACCEPT-RUN results with distinct run ids, campaign ids and generator run ids (corrected in M1-UNIFIED-EVIDENCE-BINDING-AND-LOCAL-ACCEPTANCE.md). The composed label must carry the provenance level: with authenticity UNVERIFIED the strongest honest label is "ACCEPTED, LOCALLY CONSISTENT, AUTHENTICITY UNVERIFIED"; it must never read "qualified" or "authenticated".

### Missing dependencies (why no gate yet)
1. **A common identity record.** `m1-tally-check.json` and `m1-receipt-check.json` carry only the server run id; there is no binding to campaign, git SHA and fingerprints in their outputs, and the overlay/repeatability tools do not consume them. A composer needs each result to carry the digest of the exact input it evaluated.
2. **Provenance is not wired to the field run.** The server does not announce journal prefixes or a final digest, and there is no separate retained store or commitment step.
3. **Independent canary.** The canary client runs in the same harness as the server under test. Only a canary on the generator's host (separate principal) would be independent; today it is corroborated by receipts, not independent.
4. **Real remote lane.** No run exists with external traffic and a generator report, so receipt identities involving the generator were exercised only with fixtures.
5. **Source state and parameters.** A run needs a clean tree and the code-pinned `BA0_FIELD_V1`.
6. **Authenticity.** Not available: it requires custody separation that this repository cannot create.
7. **Repeatability composition.** `ba0-m1-repeatability` does not yet require tally/receipt PASS per run.

## 6. Additional false-PASS paths found while implementing this
1. **Criterion 9's receipt inequalities remain** (it still passes the five probes). They are superseded, not changed, because criterion 9's contract is unchanged; a composer must require both results.
2. **A reducer `accepted` count with no generator report passes criterion 9** if the other evidence is consistent; only the receipt check requires the report. Composition must require item 4.
3. **`kind-ledger.json` plane counts are collector-observed**; if a forger controls the collector they control both sides of every identity (same-actor limit, section 4).
4. **`ledger-journal-field.ndjson` is not in the inventory**; it is bound only by the digest in `accounting.json`. A forger who edits both and re-hashes the package is caught only by the retained prefix digests.
5. **Beacon content is self-reported by the server** in a real deployment; the chain proves ordering and non-rewriting after the fact, not that the server told the truth at each tick.
