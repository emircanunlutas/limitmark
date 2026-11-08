# Dedicated export-request key — implementation diff plan and test matrix (FOR REVIEW; nothing implemented, 2026-11-08)

Companion to `EXPORT-REQUEST-SIGNING-DESIGN.md` (v2). Decisions applied: planned rotation overlap ≤ 24 h; emergency revocation invalidates the affected key at once; staging carries two key identities during rotation tests; the legacy (lifecycle-key) verifier is **not removed** in the first implementation commit (removal is a separate, reviewed step); missing or inconsistent configuration fails closed. The guard verification boundary is NOT modified yet.

## 1. Design adjustments caused by the decisions
- **Key set, not a single key.** Configuration holds 1–2 export keys, each with `keyId`, raw Ed25519 public key, `fingerprint` (= SHA-256 of the raw key, hex), `notBeforeMs`, `notAfterMs`. Two entries are permitted in every environment, but a validator requires their validity windows to overlap by **at most 24 h** and to have finite `notAfterMs` (so a stale key can never be forever-valid). Staging rotation tests use exactly this two-entry form.
- **Emergency revocation.** Revocation is removing (or `status:"revoked"`-marking) the entry in the guard's configuration and redeploying the guard Worker. It takes effect when the new version is live, not instantaneously; until then a stolen key is bounded by the 120 s request window and by write-once result objects. Making revocation instantaneous would need a mutable revocation list in Durable Object storage, which is persistent-state modification and a new attack surface; I do not propose it. Please confirm that "immediately" means "next config deploy".
- **Version selection is by configuration, never by the request.** If the key set is configured, only v2 requests are accepted and v1 is refused; if the key variable is absent, only the legacy path runs exactly as today. A request cannot select a weaker verifier. Both code paths coexist after commit 2; legacy deletion is commit N (separate review) once a staging qualification record exists.

## 2. File-level diff plan
| File | Change | Baseline register effect |
|---|---|---|
| `workers/lifecycle-mailbox/guard-export.ts` | add `GUARD_EXPORT_DOMAIN_V2 = "limitmark-guard-export-request-domain-v2\n"`, v2 tuple type (10 elements: version 2, operation, environment, authorityId, guardObject, accountId, **exportKeyFingerprint**, nonce, issuedAtMs, expiresAtMs), `canonicalGuardExportRequestBytesV2`, `parseGuardExportKeySet`, `verifyGuardExportRequestV2(request, signature, keySet, nowMs)`; `parseGuardExportEnvelope` dispatches on `request[0]` (1 or 2). v1 functions untouched | HOLD set; re-pinned after review |
| `workers/lifecycle-mailbox/dispatch-guard.ts` (`exportLedger`) | env gains optional `GUARD_EXPORT_KEYS`; if present → v2 path (bindings: environment, authority, guard, account, fingerprint ∈ configured set and inside its window; `expiresAtMs - issuedAtMs === 120000`; freshness ±120 s; `now < expiresAtMs`) else legacy path; any config inconsistency → `REFUSED(configuration)` before any storage read. No change to SELECT-only reads, row cap, claim/latch/settle | HOLD set; re-pinned after review |
| `deployment/lifecycle-private-contract.ts` | mailbox var allow-lists (production and staging, lines ~50 and ~118) accept optional `GUARD_EXPORT_KEYS`; new `validateGuardExportKeys(value, {environment, lifecycleKey, approverKeys})`: ≤ 2 entries, unique ids/fingerprints, fingerprint matches key, `notAfterMs` finite, overlap ≤ 24 h, none equals the lifecycle key or any hash-pinned recovery approver key, environment-specific (a production fingerprint in staging/lab config is rejected) | contract file (not in the 42; has own tests) |
| `scripts/guard-export-sign.ts` (new, offline) | reads key from a path argument, builds/ signs a v2 request using the guard module's canonicalizer, prints request JSON; refuses missing flags (`--environment --authority-id --guard-object --account-id --confirm-guard-export`), refuses nonce reuse via an append-only local log, fixed error strings, no network imports | new file; script-importer boundary tests need the new file listed |
| `scripts/guard-export-verify.ts` (new) | public-key-only verification of an envelope | new |
| `operator/guard-ledger-export.ts` | unchanged except accepting a v2 envelope file when producing the request file (no signing code in `operator/`) | review needed |
| `workers/lifecycle-observer.ts`, `workers/lifecycle-mailbox/guard-reader.ts`, `index.ts` | **no change** (they pass the envelope string through) | none |
| docs | `GATE-11A-LOCAL-HARDENING-REPORT.md` update after implementation | none |

## 3. Commit sequence (each independently reviewable and revertible)
1. Tests first (all expected-failing are marked `todo` or kept in a branch only) + contract validator and its tests (configuration validation only; no guard change).
2. `guard-export.ts` v2 primitives + unit tests (no guard wiring).
3. `dispatch-guard.ts` v2 path behind the configuration switch + guard unit tests with the real guard class (existing `loadBundledGuard` helper).
4. Workerd integration (real DO, both a legacy-config guard and a v2-config guard).
5. Offline sign/verify scripts + source-scan tests.
6. Baseline register regeneration for the touched HOLD entries (reviewed, not auto-accepted).
Later, separately reviewed: remove the legacy verifier; remove `v1` fixtures.

## 4. Test matrix (written before implementation)
| # | Property | Where |
|---|---|---|
| T1 | Distinctness: export key ≠ lifecycle key ≠ each approver key, enforced by validator and by the signing script | contract + scripts tests |
| T2 | Cross-domain, both directions: lifecycle-key signatures, recovery-record signatures and v1 export signatures are refused by the v2 verifier; v2 signatures are refused by the lifecycle verifier and the recovery verifier | guard unit |
| T3 | Binding: each of environment, authority, guard object, account, key fingerprint mismatched → `REFUSED`, with the recording harness proving **no storage read** | guard unit (statement/transaction recorder as in `guard-export-method.test.ts`) |
| T4 | Window: exact 120 000 ms span required; ±120 s freshness edges; `now ≥ expiresAtMs`; future-dated; non-integer; negative | guard unit |
| T5 | Nonce: shape; replay returns the existing write-once object; observer never overwrites; script refuses local reuse | guard unit + observer integration + scripts |
| T6 | Two keys: a request naming either configured fingerprint verifies inside that key's window; a request naming a removed/expired/not-yet-valid key is refused; overlap > 24 h is rejected at validation | guard unit + contract |
| T7 | Revocation: config with the key removed refuses its previously valid signatures (same bytes, same nonce) | guard unit |
| T8 | Selection: with `GUARD_EXPORT_KEYS` set, a v1 envelope is refused; with it absent, a v2 envelope is refused and v1 behaves byte-for-byte as before; the request cannot choose | guard unit |
| T9 | Fail closed matrix: missing, empty, malformed JSON, > 2 entries, duplicate id/fingerprint, wrong key length, fingerprint mismatch, `notAfterMs` null/absent, `notBeforeMs ≥ notAfterMs`, unknown extra fields, environment mismatch → `REFUSED(configuration)` | guard unit + contract |
| T10 | Source scans: no private-key material or key loading in `workers/`, `operator/`, `src/`; signing scripts import no network module and no `tests/support`; allowed-importer tables updated by exact entry only (reviewed act) | scan tests |
| T11 | Legacy preserved: the complete existing `guard-export-method` / `guard-ledger-export` suites pass unchanged in a legacy-config guard | existing suites |
| T12 | Workerd end to end (real DO class): v2 authenticated export returns the ledger; ledger tables unchanged afterwards; legacy-config guard still answers v1 | workerd integration |
| T13 | Staging rotation rehearsal (local): key A only → overlap A+B → B only; every transition verified including revocation of A inside the overlap | workerd integration |

## 5. Risks and open questions
- Deploying a changed guard class is a live-infrastructure change and is outside this authorization; everything above is local.
- Rotation of the *guard's* `AUTHORITY_OPERATOR_PUBLIC_KEY` is a different matter and is not touched.
- The existing `GUARD_EXPORT_FRESHNESS_MS` (120 s) is reused as the exact window.
- Confirm: (a) "immediate revocation" = next config deploy; (b) production may also hold two entries for ≤ 24 h; (c) T10 allowed-importer table additions are acceptable as exact entries.
