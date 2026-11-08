# Export-request key: lifetimes and emergency revocation — design only (2026-11-08)

Companion to `EXPORT-REQUEST-SIGNING-DESIGN.md` and `EXPORT-KEY-IMPLEMENTATION-PLAN.md`. The guard verification boundary is NOT modified; nothing here is implemented, deployed or provisioned.

## 1. Four different time quantities (never equated)
| Quantity | Meaning | Bound | Who enforces |
|---|---|---|---|
| **Key validity lifetime** | `[notBeforeMs, notAfterMs]` of one export public key in the guard's configuration | finite; hard cap 24 h (default 8 h), per key | guard (reject outside the window) and the configuration validator (reject > cap, null, or open-ended) |
| **Planned rotation overlap** | time during which two keys are both valid while the successor is brought in | ≤ 24 h, only for planned rotation | validator (overlap of the two windows ≤ 24 h) |
| **Individual request expiry** | validity of ONE signed export request | exactly 120 000 ms (`expiresAtMs − issuedAtMs`), plus ±120 s clock freshness | guard, per request |
| **Emergency revocation latency** | time from the decision "this key is compromised" to "the serving verifier refuses it" | see section 3: bounded by min(time to get the updated verifier serving, remaining key validity) | operator procedure + the key-validity cap as backstop |
A request's lifetime is never derived from, or limited by, the key's lifetime, and vice versa: a key valid for 8 h signs many requests of 120 s each; revoking the key does not need to wait for outstanding requests to expire, and an outstanding request does not extend a revoked key. Request expiry is checked against the guard's own clock at verification; key validity is checked against the same clock using the configuration the guard is currently serving.

## 2. Mechanisms compared
| | Deployment-based revocation | Durable-Object-backed revocation state | Short-lived keys + deployment revocation (recommended) |
|---|---|---|---|
| How | remove or mark the key in `GUARD_EXPORT_KEYS` and redeploy the guard Worker | guard keeps revoked fingerprints in its SQLite; a signed method writes them | key validity capped at ≤ 24 h; emergency = deployment; expiry is the backstop |
| Effective when | **only when the updated verifier is serving** (never described as instantaneous) | on the next request after the revoke write commits | deployment: when the updated verifier is serving; otherwise at the key's `notAfterMs` |
| Latency guarantee | none by itself (depends on operator and platform) | near-immediate, but only after a successful write | **bounded**: ≤ min(deploy time, remaining validity ≤ 24 h) |
| Failure behavior | deploy fails ⇒ revoked key stays valid until a deploy succeeds (fails open for revocation) | write fails ⇒ stays valid; storage read failure ⇒ refuse (fail closed) | as deployment, with the cap limiting exposure |
| Availability | no new runtime dependency | new write path and table in the guard | no new runtime dependency |
| Persistent-state impact | none | **changes the guard's schema** (pinned by the R06 upgrade rehearsal: "identical old/HEAD Authority and guard DDL"); modifies Durable Object state | none |
| Custody | public keys in config | a revocation-signing key must be custodied and rotated | pre-generated sealed **standby** export key |
| Residual exposure of a stolen export key | until the verifier update is serving | until the write | until update or `notAfterMs`, ≤ 24 h |
**What a stolen export key can do:** request SELECT-only guard-ledger exports (≤ 24 rows per table, write-once result per nonce, 120 s window per request). It cannot initialize, rotate, settle or alter any state, and ledger contents are bookkeeping that recovery decisions do not rely on (signed Authority reads are the evidence). The impact is confidentiality of ledger digests and timing plus bounded read load.

## 3. Recommended design
- Export keys are **short-lived by construction**: validity ≤ 24 h hard cap (validator-enforced), default 8 h, issued per export session; planned rotation overlaps two keys for ≤ 24 h.
- **Emergency revocation procedure** (operator-local, documented, not yet authorized to run): (1) mark/remove the affected key in the guard configuration, keeping the other key if present; (2) deploy the updated guard version; (3) confirm it is serving (a probe export signed with the revoked key must return `REFUSED`, with a freshly signed request so freshness is not the reason); (4) record the time. Emergency revocation **does not wait for the overlap window**; it removes the affected key even if its successor is not yet active, which makes exports unavailable until the standby key is activated — an acceptable outage because exports are not on any critical path.
- **Failure behavior:** if the new configuration is missing, malformed, inconsistent or exceeds the validity cap, the guard answers `REFUSED(configuration)` before any storage read (fail closed). A failed deployment leaves the previous configuration serving; the runbook then escalates to the key's expiry as the bound, and may add a deploy of a configuration with an empty key set (which refuses all v2 requests).
- **Availability implications:** revocation can only reduce availability of exports, never of lifecycle dispatch, settlement or the L1/L2 defense plane (separate code paths and components; no shared runtime dependency).
- **Custody:** private keys offline (hardware token or air-gapped host); only public keys and fingerprints in configuration; the standby key sealed separately; two-person authorization record for production exports (existing decision-record format).
- **Measured latency evidence required before any live use:** time from "deploy started" to "revoked key refused" in a staging environment, recorded as evidence; the claim in documentation stays "effective when the updated verifier is serving".

## 4. Tests required before implementation
1. Validator: validity > 24 h, null/absent `notAfterMs`, `notBeforeMs ≥ notAfterMs`, overlap > 24 h, > 2 keys, duplicate ids/fingerprints, fingerprint/key mismatch, equality with the lifecycle key or any recovery approver key — all rejected.
2. Boundary instants: `now = notBeforeMs − 1`, `notBeforeMs`, `notAfterMs − 1`, `notAfterMs` (valid set is half-open, pinned by test).
3. Request expiry is independent: a request is refused at `expiresAtMs` even though the key is valid; a request signed before key expiry but verified after is refused; exact 120 000 ms span required.
4. Revocation: configuration with the key removed refuses the same bytes that were valid before (same nonce, same signature); the remaining key keeps working; the empty key set refuses all v2 requests.
5. Fail closed: every malformed/missing configuration returns `REFUSED(configuration)` with no storage read (recorder harness).
6. Emergency path rehearsal (local, workerd): key A+B overlap → revoke A inside the overlap → A refused, B accepted → revoke B → everything refused → standby C activated.
7. No schema change: the guard DDL parity check from the R06 rehearsal still passes.
8. Source scans: no private key material or key loading in `workers/`, `operator/`, `src/`.
9. Documentation test: no document or code comment calls deployment-based revocation instantaneous (grep guard on the revocation docs and the runbook).

## 5. Open for your decision
Validity cap (24 h hard, 8 h default); whether the staging rotation test must also rehearse a failed deployment; whether the production export requires the two-person record for every export or only for the key issuance.
