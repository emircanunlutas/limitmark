# Gate 9 — staging key/release rotation: implementation plan (NOT implemented, NOT executed)

Gate 9 stays CLOSED. Production remains NO-GO. This plan changes nothing.

## 1. Current state (read from code)
- Production rotation exists end to end: `rotateAuthorityRelease` (`workers/admission-service/authority.ts`) in one `transactionSync`; command tuple of 12 fields, production-only (`operator-command.ts`); script `scripts/authority-rotate-release.ts` (operator key from env, prints signed command); mailbox slot `rotate-release.json`; production guard, executor, attestation (`rotate-release` receipts, sequence >= 2).
- Staging has **no** rotation: `StagingAdmissionAuthority.rotateReleaseFromOperator` and `StagingAuthorityLifecycleOnly.rotateAuthorityReleaseFromOperator` return `{status:"refused"}` without parsing; staging mailbox/guard/processor have no `rotate-release.json` handling; `canonicalOperatorCommandBytes` rejects non-production rotation; the attestation validator rejects a staging `rotate-release` and assumes exactly one staging release row; `deployment/lifecycle-environment-gates.json` has `rotationImplemented:false`; `operator/guard-ledger-export.ts` allows only `initialize` for staging.
- Pinned bounds: overlap `previousRetiresAtMs - activatesAtMs` in (0, 300 000] ms; retired row kept `AUTHORITY_RELEASE_RETENTION_AFTER_RETIRE_MS` = 12 min before it can be deleted by the next rotation; at most two release rows; command freshness +/- 300 s.
- Related key sets that also rotate (separate mechanisms, not Gate 9 scope unless stated): attestation signer keys via trust manifest (`active`/`retired`, `notBeforeMs`/`notAfterMs`, `currentKeyFingerprint`); ingress public keys (`current`/other roles with `activatesAtMs`); release RPC key.

## 2. Missing implementation and tooling
1. Staging command grammar: allow `command[2]==="staging"` with `STAGING_ADMISSION_AUTHORITY_ID` in `canonicalOperatorCommandBytes` (new, separately reviewed branch; production branch byte-for-byte unchanged).
2. `StagingAdmissionAuthority.rotateReleaseFromOperatorAttested` + `StagingAuthorityLifecycleOnly` method calling the shared `rotateAuthorityRelease` pinned to the staging identity; remove the "refused" stubs only in that step.
3. Attestation: staging `rotate-release` receipts and two-row snapshots (revise the validator on purpose, with golden-fixture additions; keep v2 production goldens unchanged); update the "exactly one staging row" invariant to "one, or two during overlap".
4. Staging mailbox slot `rotate-release.json`, staging guard `processRotation`, staging executor method, settlement/reconcile coverage mirroring production; ledger export allow `rotate-release` for staging.
5. Staging CLI: `scripts/authority-staging-rotate.ts` (signing only, offline, no network), staging submit action, result reader path for staging rotation.
6. `rotationImplemented` flips to true only in the commit that completes items 1-5 and its tests, and only after approval.

## 3. Rotation authority and signing
- Signed by the staging operator key (the key pinned as the staging `AUTHORITY_OPERATOR_PUBLIC_KEY`), never the production operator key (`crossEnvironmentKeyReuseAllowed:false`). Private key offline; fresh `issuedAtMs`; command bound to environment, authority id, policy epoch, current and next release ids, next key id, activation and retirement times.
- Recommend a two-person authorization record (existing decision-record format) for staging rotation so the production procedure is rehearsed as it will be used.

## 4. Overlap and revocation behavior (to be proven in staging)
- Activation at T; previous release retired at T+d, 0 < d <= 300 s: both verify during overlap; after T+d only the new key verifies; replays of old-release permits after retirement fail.
- Emergency revocation is a separate, not-yet-designed path (immediate retirement). Plan: a distinct command, explicitly out of Gate 9 scope, to be decided before Gate 10.
- Retention: the retired row cannot be pruned for 12 min; a second rotation inside that window must fail with `release-retention`.

## 5. Failure and rollback
- Single-transaction rotation: any failure leaves the prior single-row state. Idempotent re-submit returns `already-rotated`.
- "Rollback" is a forward rotation back to the prior key as a new release id (ids may not be reused); never a state edit. Guard claim is single-use: a lost or UNCONFIRMED result is resolved by the signed reconciliation read, as for initialization, never by re-dispatch.
- No persistent DO state edits, no guard replacement as part of rotation.

## 6. Required staging qualification evidence (when later authorized)
Local first: workerd integration (rotate, overlap, retire, retention refusal, replay, wrong-environment and wrong-authority refusals, tampered signature, expired command, crash between claim and settle); golden attestation vectors for staging; chaos-ordering tests. Then staging live (separate authorization): signed APPLIED envelope for the rotation, pre/post signed reconciliation snapshots (one row -> two rows -> one row), reads verified through the reader with the staging trust manifest, guard-ledger export showing the claim, and a record that production state was untouched. Evidence is appended; historical INVALID verdicts are not edited.

## 7. Dependencies before Gate 10 unlocks
1. Items 2.1-2.6 implemented, reviewed and tested locally.
2. Staging rotation qualification evidence (section 6) accepted.
3. Export-request signing key decision (see `EXPORT-REQUEST-SIGNING-DESIGN.md`) and Gate 11A boundary decisions D-1..D-8.
4. Baseline v2 reviewed and the 13 baseline failures dispositioned.
5. Emergency-revocation design decided.

## 8. Blockers now
Gate 9 closed by owner decision; any change to staging authority, operator command grammar, attestation validator or guard is security-boundary work needing explicit approval.
