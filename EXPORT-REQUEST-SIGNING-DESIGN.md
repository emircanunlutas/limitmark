# Dedicated export-request key — security design (v2, 2026-11-08)

Status: **architecture approved, implementation NOT authorized.** No code, key, variable, deployment or signing capability is created by this document. The guard verification boundary is unchanged. Production stays NO-GO; Gates 9, 10, 11A closed.

## 0. Problem
`workers/lifecycle-mailbox/guard-export.ts` verifies export requests with the guard's pinned `AUTHORITY_OPERATOR_PUBLIC_KEY`, the **lifecycle operator** key. A private key that can initialize/rotate the Authority therefore also reads the dispatch ledger. Read-only evidence access should not require the key that can change state, and the two should be revocable independently. Domain separation by byte prefix already prevents cross-use of signatures, but not compromise coupling.

## 1. Keys and signing domains
Three Ed25519 keys, pairwise distinct (by public-key fingerprint), none reused across environments:
| Key | Signs | Domain prefix (first bytes of the signed message) |
|---|---|---|
| lifecycle operator | initialize / rotate-release commands | none (JSON array, existing) |
| recovery approver(s) | two-person decision records | existing recovery-record domain |
| **export-request (new)** | guard ledger export requests | `limitmark-guard-export-request-domain-v2\n` |

v2 differs from today's `…-v1\n` so a v1-era signature (made by the lifecycle key) cannot be accepted by a v2 verifier and vice versa. Signed bytes = `DOMAIN_V2 || JSON.stringify(tuple)`.

Tuple (fixed order, no extras): `[2, "export-guard-ledger", environment, authorityId, guardObject, accountId, exportKeyFingerprint, nonce, issuedAtMs, expiresAtMs]`. Binding: `environment` in {production, staging, lab} must equal the guard's own environment; `authorityId` and `guardObject` must equal the guard's pinned identities; `accountId` must equal the guard's `CLOUDFLARE_ACCOUNT_ID`; `exportKeyFingerprint` must equal the fingerprint of the key the guard has pinned (stops a request signed for one key generation being replayed against another). `expiresAtMs - issuedAtMs` must equal exactly 120 000.

## 2. Provisioning and custody
- Generated on an offline host or hardware token by a dedicated ceremony (two witnesses for production). Private key never in Workers, R2, source, env files, CI, shell history or logs; the tool takes a key path/token slot, holds it in memory, and uses fixed error strings.
- Only the public key is deployed, as a new pinned guard variable `GUARD_EXPORT_PUBLIC_KEY` (plus `GUARD_EXPORT_KEY_FINGERPRINT`), listed in the lifecycle private contract and checked by `validate*Mailbox*` validators.
- Registry of export keys: a hash-pinned, reviewed file (same pattern as the recovery approver registry) records fingerprint, environment, status, `notBeforeMs`, `notAfterMs`. A production export key is never valid for staging or lab.
- Production export requires a second person's countersigned authorization record naming the request digest (reuse the decision-record format). Staging/lab may use single-signer.

## 3. Replay and expiry
- Freshness: guard accepts only `|clock - issuedAtMs| <= 120 000`, and `now < expiresAtMs`.
- Nonce: 128 random bits (hex). Result written to `ledger-export/<nonce>.json` write-once; a replay returns the existing object (never a new read at a later time). The signing tool keeps an append-only local log of used nonces and refuses reuse.
- Any refusal for an unauthenticated request carries no nonce or digest (unchanged).

## 4. Rotation and emergency revocation
- **Planned rotation:** deploy the new public key and fingerprint **alongside** the old one for an overlap of at most 24 h (guard variable holds up to two keys, each with its fingerprint; the request names which one). After the overlap the old entry is removed by a reviewed redeploy of guard vars. Because export is read-only, an overlap has no state-change risk.
- **Emergency revocation:** a reviewed guard-variable change that removes the key (one config redeploy, no DO state edit). Until redeployed, requests are bounded by the 120 s window and write-once results. Revocation does not touch the lifecycle operator key. Both actions are operator-local procedures with no live step authorized here.
- Compromise of the export key: ledger contents are bookkeeping, not Authority evidence (recovery decisions need signed Authority reads), so impact is confidentiality of ledger digests/timing and load (bounded: 24 rows/table cap, write-once result per nonce, request budget per window).

## 5. Migration from the lifecycle-key verifier
1. Add v2 verification beside v1 in the guard behind a variable: guard accepts v1 only while `GUARD_EXPORT_PUBLIC_KEY` is absent (compatibility), and **only v2** once it is present. No state in which both are accepted for the same guard.
2. Deploy order: key ceremony -> register -> guard variable -> contract validator update -> tests -> redeploy. v1 removal is a later reviewed commit.
3. The v1 path remains until v2 has an accepted staging qualification record; then v1 is deleted from source (not left dormant).

## 6. Fail-closed behavior
Missing/empty/malformed `GUARD_EXPORT_PUBLIC_KEY` or fingerprint after v2 is enabled; fingerprint mismatch with the public key; equal fingerprint to the lifecycle key or any recovery approver; environment/account/authority/guard mismatch; unknown version; expired, future-dated or wrong-width window; bad signature; nonce shape — all return REFUSED without reading storage. Contract validators reject a deployment where the export key equals the lifecycle key, where v2 is enabled without a fingerprint, or where a production fingerprint appears in a staging/lab config.

## 7. Tests required before implementation (written first)
1. Distinctness: export key vs lifecycle vs each approver — equality refused at tool, validator and guard.
2. Cross-domain: lifecycle-key signatures, recovery-record signatures and v1 export signatures refused by the v2 verifier; v2 signatures refused by lifecycle and recovery verifiers.
3. Every binding field (environment, authority, guard, account, fingerprint) mismatch refused with no storage read (statement/transaction recorder as in existing tests).
4. Window: exact 120 000 span, ±120 s skew edges, expired, future.
5. Nonce: replay returns the stored object; shape violations; tool refuses reuse.
6. Overlap: two pinned keys accepted only by fingerprint named in the request; removed key refused.
7. Migration: v1 accepted only when no v2 variable; v2 present => v1 refused.
8. Config fail-closed matrix (section 6) incl. contract validators.
9. Source scans: no private key material or key-loading code in `workers/`, `operator/`, `src/`; signing tool is offline (no network imports), prints no key material; allowed-importer lists unchanged.
10. Workerd integration: authenticated v2 export end to end on the real guard class; ledger unchanged afterwards.

## 8. Tool shape (offline, not built)
`export-sign` (reads key path/slot, prints request JSON only), `export-verify` (public key only). Same canonicalization function imported from the guard module, never re-implemented. Reason string and countersignature digest recorded in the local log.

## 9. Open decisions for approval before implementation
(a) overlap window length (proposed 24 h); (b) staging single-signer vs two-person; (c) whether v1 removal is bundled with the first v2 commit.
