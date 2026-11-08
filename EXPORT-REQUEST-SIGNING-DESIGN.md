# Guard-ledger export request: offline signing tool DESIGN (not implemented)

Status: design only. No signing capability, key, or provisioning exists or is created by this document. Production remains NO-GO.

## 1. Finding that shapes the design
`workers/lifecycle-mailbox/guard-export.ts` currently verifies export requests against the guard's pinned `AUTHORITY_OPERATOR_PUBLIC_KEY`, i.e. the **lifecycle** operator key. The export is domain-separated by prefix (`limitmark-guard-export-request-domain-v1\n`), so a request signature cannot be replayed as a lifecycle command, but the **same private key** would sign both. The authorization asks for a dedicated key. Achieving that is a **security-boundary change** (new pinned variable on the guard, contract validation, tests) and needs separate approval; it is specified here, not made.

## 2. Key custody
- New key `EXPORT_REQUEST_SIGNING_KEY` (Ed25519), generated on an offline, air-gapped signing host or hardware token; **distinct** from the lifecycle operator key and from every recovery-approval (two-person decision) key. Pairwise distinctness is checked by public-key fingerprint in the tool and by a contract validator on the Worker side (reject equal fingerprints).
- Private key never in Workers, R2, source, env files, CI, shell history or logs. The tool reads it from a hardware token / OS-protected file path given by flag, loads it into memory only, and never prints it or any error containing key material (fixed error strings, as in `scripts/authority-rotate-release.ts`).
- Only the public key is deployed, as a new guard var `GUARD_EXPORT_PUBLIC_KEY` (pinned, hash-listed in the lifecycle private contract). One custodian signs; the operator who runs the export is not the key holder's sole authority (see 6).

## 3. Request and canonicalization
Existing tuple, unchanged: `[version, "export-guard-ledger", environment, authorityId, guardObject, accountId, nonce, issuedAtMs]`. Signed bytes = `DOMAIN || JSON.stringify(tuple)` (fixed element order, no whitespace, integers only, lowercase 32-hex nonce, no unknown elements). The tool and guard use the same `canonicalExportRequestBytes`; the tool imports it, never re-implements it.

## 4. Domain separation
Keep the text prefix. Add a **key-level** separation: the verifying key is a different pinned key, so a lifecycle or recovery signature cannot verify even if bytes collided. Tests: a lifecycle command signature and a decision-record signature are refused by the export verifier, and an export signature is refused by the lifecycle verifier.

## 5. Expiry and nonce
- `issuedAtMs` taken from the signing host clock at signing; guard accepts `|clock - issuedAtMs| <= 120 000 ms`. The tool refuses a stale host clock check input (operator confirms time source) and prints the expiry instant.
- Nonce: 128 random bits from the OS CSPRNG, hex. Result object `ledger-export/<nonce>.json` is write-once, so a replayed request cannot overwrite; a replay returns the existing object. The tool records `(nonce, requestDigest)` in an append-only local log (no key material) and refuses nonce reuse.

## 6. Authorization
Signing requires: (a) explicit `--environment`, `--authority-id`, `--guard-object`, `--account-id` (must equal the pinned `CLOUDFLARE_ACCOUNT_ID`; no default), and a `--confirm-guard-export` flag; (b) a written reason string recorded in the local log; (c) for production, a second operator's countersigned authorization record (reusing the two-person decision-record format) naming the request digest before the token is used. Export is SELECT-only and cannot change state, so a single-signer path may be approved for staging/lab only.

## 7. Verification
Offline `verify` subcommand: recomputes canonical bytes and digest, checks signature against the public key, freshness, and field pins. Guard-side: unchanged order (shape, pinned account, freshness, signature, then SELECT-only read); unauthenticated requests carry no nonce/digest in refusals. The export result is checked by `operator/guard-ledger-export.ts` against the request digest.

## 8. Out of scope / not done
No key generation, no signing, no deployment var, no guard change. Tests to write when approved: distinct-key enforcement, cross-domain rejection both ways, nonce reuse refusal, expiry bounds, no-secret-in-output.
