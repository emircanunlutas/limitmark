# Qualification baseline migration — PROPOSAL (not accepted, not wired into any test)

Status: **PROPOSED**. Nothing here changes a test, a pin, a verdict or any historical evidence. Generated from `HEAD 7eb0404` against the historical baseline `dcf10af8229a5738b1852721fe12de86a488d07d` by `npm run qualification:baseline-proposal` (read-only; fails closed on any unclassified path). Machine-readable form: `QUALIFICATION-BASELINE-V2-PROPOSED.json` (untracked; sha256 of the version this document was written against: `957752d280da463aa4e4e8011afac7e5b725c7f91a8674095392cf658115c563`).

## 1. What the failing test actually asserts, and why it fails
`tests/lab-ba0-salvo-diagnostics.test.ts` ("files that decide admission, rejection, L1/L2, forwarding, canary behavior and every G1-G6 identity are byte-identical to the baseline commit") requires `git diff dcf10af8 -- defense src workers lab/policy … lab/evidence` to be empty after excluding the six files of the reviewed-patch registry (P0-01 `defense/plane/front.ts`; P0-02 `defense/core/{replay-guard,hop-admission,types}.ts`, `defense/boundary/boundary.ts`, `defense/origin/synthetic-origin.ts`).
The premise "only `route.ts` differs" is false: **41 files** differ (15 of them added after the baseline) over 70 commits since the baseline. The six registry files are already exempt and correct. The 35 files the previous report counted have grown to 41 because the Gate 11A work (guard export, observer relay, launch policy) added six more.

## 2. Principle: evidence is never rewritten
- `dcf10af8` and its two sibling baselines stay the immutable historical reference. Their blobs, fingerprints, verdict-path files and the `historical qualification is immutable` test are untouched and remain a separate (currently failing, untouched) subject.
- "Baseline v2" is a **second, additive layer**: a versioned register of reviewed drift, each entry pinning (a) the historical blob at `dcf10af8` (or `null` = file did not exist), which must still resolve to exactly that blob, and (b) the sha256 (LF-normalised) of the reviewed working-tree file. This is the existing reviewed-patch mechanism extended from "defense/ only, six files" to the explicitly reviewed set below. A file that is not in either register stays under the original byte-identity rule; a registered file that changes again fails until it is re-reviewed and re-pinned on purpose.
- The register is append-only and versioned (`…-v2`); a future v3 adds entries, never edits v2 entries, and the older register remains checkable.

## 3. Classification of the 41 files
Authorized production-preparation changes are those delivered under the accepted instruction series (commits `ab49021`, `08cc375`, `7cabf1a`, `9f45010`, `0de1536`, `0073ca9`, `e1a65ce`). Laboratory and observability changes are earlier, separately reviewed work (FQ1/3P lab environment, Cloud Run lab, OTel) that this proposal only *records*, it does not re-approve them.

### PRODUCTION_PREPARATION (6)

| File | Change | Commits since baseline | Security review note |
|---|---|---|---|
| `src/app/api/public-inquiries/route.ts` | modified | 6f1c36f, ab49021 | none: production branch delegates to the factory; disabled => generic 503 |
| `src/lib/admission-client.server.ts` | modified | 6f1c36f, eb4a7fb, ab49021, 9f45010 | none: additive Vercel OIDC provider (request-scoped, timeout, pending cap, claim checks); lab Google provider is a separate class |
| `src/lib/production-launch-policy.ts` | added | 0de1536 | none: new, fail-closed |
| `src/lib/public-inquiry-production-runtime.server.ts` | added | ab49021, 0de1536 | none: refuses LAB_/GOOGLE_/LIMITMARK_RUNTIME, verified-TLS and telemetry-off launch policy |
| `workers/admin-gateway/index.ts` | modified | e1a65ce | none: removes non-handler re-exports so the bundle loads in workerd |
| `workers/admission-service/index.ts` | modified | eb4a7fb, 38fec4d, 4be1b10, 653d522, 08cc375 | OBSERVATION O-2: the production bundle's main module also exports the lab classes (as it already exports the staging classes); see proposal |

### GATE_11A_GUARD_EXPORT (5)

| File | Change | Commits since baseline | Security review note |
|---|---|---|---|
| `workers/lifecycle-mailbox/dispatch-guard.ts` | modified | 0073ca9 | none: one SELECT-only, operator-authenticated method added; dispatch/settle code untouched |
| `workers/lifecycle-mailbox/guard-export.ts` | added | 0073ca9 | none: new request/response format |
| `workers/lifecycle-mailbox/guard-reader.ts` | added | 0073ca9 | none: single-method read-only entrypoint |
| `workers/lifecycle-mailbox/index.ts` | modified | 0073ca9 | none: one additional entrypoint export |
| `workers/lifecycle-observer.ts` | modified | 0073ca9 | none: optional relay of an authenticated read-only export; no new write path to the request bucket |

### SHARED_FIX (1)

| File | Change | Commits since baseline | Security review note |
|---|---|---|---|
| `workers/shared/bounded-jwks.ts` | modified | 653d522 | none: wraps native fetch as a plain function; no verification change |

### OBSERVABILITY (2)

| File | Change | Commits since baseline | Security review note |
|---|---|---|---|
| `src/lib/public-inquiry-otel.server.ts` | added | 1409e7c | none: inert unless PUBLIC_INQUIRY_OTEL_METRICS=true; production launch policy forbids it |
| `src/lib/public-inquiry-telemetry.server.ts` | added | 7fcc117, 1409e7c | none: bounded counters; never affects the response path |

### LABORATORY (27)

| File | Change | Commits since baseline | Security review note |
|---|---|---|---|
| `src/app/test-talep-et/page.tsx` | modified | a04e184 | none |
| `src/lib/authority-result-attestation.ts` | modified | 38fec4d | none: adds the lab environment tag |
| `src/lib/authority-result-trust.ts` | modified | 38fec4d | none: adds the lab environment section handling |
| `src/lib/db/database.server.ts` | modified | b6ba401 | none: optional verified-TLS object for the lab; production client options unchanged (see production-launch-policy) |
| `src/lib/ingress-protocol.ts` | modified | caa2f70 | none for production: parser also accepts the lab environment tag; the production verifier still requires the production tag |
| `src/lib/ingress-verifier.server.ts` | modified | 6f1c36f, caa2f70, 5cb11f3 | none for production: URL-authority comparison preserved unless policy.environment is the lab; policy is server configuration |
| `src/lib/public-inquiry-handler.server.ts` | modified | 7fcc117, 1409e7c, 6f1c36f, a04e184, 7937bcc | none for production: production hostname/Origin/VERCEL checks preserved; OBSERVATION O-3; also carries telemetry wrapper (OBSERVABILITY) |
| `src/lib/public-inquiry-runtime.server.ts` | added | 6f1c36f, eb4a7fb, caa2f70, b6ba401, a04e184 | none: new lab runtime factory |
| `src/lib/public-origin.ts` | modified | 6f1c36f, caa2f70, a04e184 | none: lab branch selected only by LIMITMARK_RUNTIME; production VERCEL checks preserved (order of two failing checks changed, same outcome). OBSERVATION O-3 |
| `src/proxy.ts` | modified | a04e184 | none |
| `workers/admission-service/auth.ts` | modified | eb4a7fb | none: additive Google OIDC verifier; Vercel verifier untouched |
| `workers/admission-service/authority-attestation-config.ts` | modified | 38fec4d | none |
| `workers/admission-service/authority-attestation-signer.ts` | modified | 38fec4d | none |
| `workers/admission-service/authority-attestation.ts` | modified | 38fec4d | none |
| `workers/admission-service/authority.ts` | modified | 38fec4d | none: lab identity bound both ways |
| `workers/admission-service/lab-index.ts` | added | 38fec4d | none |
| `workers/admission-service/operator-command.ts` | modified | 38fec4d | none: lab environment/authority pairing added; production pairing unchanged |
| `workers/admission-service/service.ts` | modified | eb4a7fb | none: authentication step parameterized; same checks and order for the Vercel path |
| `workers/ingress-signer/google-id-token.ts` | added | f61f517 | none |
| `workers/ingress-signer/index.ts` | modified | caa2f70 | none: adds originHostname |
| `workers/ingress-signer/laboratory-index.ts` | added | caa2f70, f61f517, 1295172 | none |
| `workers/ingress-signer/signer.ts` | modified | caa2f70 | FINDING F-1 (low): production no longer checks that vercelBypassSecret differs from the other three secrets inside createIngressSigner; compensated by validateRuntimeSecrets('publicSigner') collisionSensitive check in index.ts |
| `workers/lab-lifecycle-observer.ts` | added | 38fec4d | none |
| `workers/lab-operator-lifecycle-executor.ts` | added | 38fec4d | none |
| `workers/lifecycle-mailbox/lab-dispatch-guard.ts` | added | 38fec4d | none |
| `workers/lifecycle-mailbox/lab-index.ts` | added | 38fec4d | none |
| `workers/lifecycle-mailbox/lab-processor.ts` | added | 38fec4d | none |

## 4. Security review of the drift (diffs read for the files with security meaning)
No change was found that weakens admission, rejection, L1/L2, forwarding, canary behavior or a G1–G6 identity for the **production** path. Findings:

- **F-1 (low, genuine weakening of a defense-in-depth check) — `workers/ingress-signer/signer.ts`.** `createIngressSigner` used to refuse unless all FOUR secrets (signing key, identity HMAC, origin secret, Vercel bypass secret) were pairwise distinct; for production it now checks only three (the bypass secret was dropped from the distinctness set when the lab variant made it optional). Compensation: `workers/ingress-signer/index.ts` calls `validateRuntimeSecrets("publicSigner")`, whose `collisionSensitive` list contains `VERCEL_AUTOMATION_BYPASS_SECRET`, so the deployed Worker still refuses collisions. Direct callers of `createIngressSigner` lose the check. **Not corrected** (security-boundary change: needs your approval). Suggested fix: include `vercelBypassSecret` in the set when `environment === "production"` and add the missing test.
- **O-2 (observation) — `workers/admission-service/index.ts`.** The production bundle's `main` module also exports the lab classes (`LabAdmissionAuthority`, `LabAdmissionServiceWorker`, `LabAuthorityLifecycleOnly`, `LabAuthorityLifecycleReadOnly`), exactly as it already exports the staging classes. They are reachable only if some other Worker declares a service/DO binding to them by name; the production deployment config binds none. Cleaner: a production entry module that re-exports only production classes (the lab already has `lab-index.ts`). Not changed.
- **O-3 (observation) — `src/lib/public-origin.ts`, `src/lib/public-inquiry-handler.server.ts`.** The laboratory branch is selected by server configuration (`LIMITMARK_RUNTIME === "cloud-run-lab"`), never by request input; production hostname, Origin and `VERCEL`/`VERCEL_ENV` checks are preserved. The production runtime factory refuses to build any dependency when `LIMITMARK_RUNTIME` is set (so the lab branch could not become reachable with real admission dependencies). `deployment/vercel-project-contract.json` does not itself forbid `LIMITMARK_RUNTIME`/`LAB_*` on the production project; adding that is a recommended hardening, not done.
- Ingress verifier/protocol: the parser now accepts the lab environment tag, but the production verifier still requires the production tag and the URL-authority comparison is skipped only when `policy.environment === "cloud-run-lab"` (server configuration).
- Database client: the only production-relevant change is the optional verified-TLS object; production client options are unchanged (the TLS enforcement is the new launch policy, `src/lib/production-launch-policy.ts`).
- Everything else (Google OIDC verifier, lab authority, lab mailbox/executor/observer, attestation environment tag) is additive and isolated from production identities by pairing checks; the production-identity isolation tests added in `08cc375` pin that.

## 5. Proposed mechanism (NOT implemented)
1. Add `tests/support/qualification-baseline-v2.ts` (data only) holding the 41 entries above (`path`, `historicalBlob`, `reviewedSha256`, `category`, `commits`, `reviewedIn`).
2. Extend `withoutReviewedPatches` with a *second* exclusion list sourced from that file, and extend `assertReviewedPatchBoundary` with a v2 boundary check: for every entry, `git rev-parse dcf10af8:<path>` equals `historicalBlob` (or the path is absent at the baseline for `added`), and the working-tree file hashes to `reviewedSha256`. No change to the `diff(...) === ""` assertion itself beyond the exclusion, to the fingerprints, or to the identity-list assertions.
3. Add a test that the v2 register is exactly the set of drifted paths (no more, no fewer) so that new drift cannot hide inside the register and removed drift cannot linger.
4. Re-run the generator after review and pin the reviewed hashes; any later edit to a registered file (this includes every Gate 11A follow-up commit) requires regenerating and re-reviewing its entry.

## 6. What acceptance requires (a separate review)
- A reviewer reads each `PRODUCTION_PREPARATION`, `GATE_11A_GUARD_EXPORT` and `SHARED_FIX` diff against the table and the findings above, and decides F-1.
- The owner decides whether LABORATORY and OBSERVABILITY drift is recorded as-is (this proposal) or first re-reviewed.
- Pins are generated at the final reviewed commit, not at this one.
- Decide whether `historical qualification is immutable` (currently failing, untouched, a different subject) is addressed in the same step.

I did **not** declare the new baseline accepted and did **not** modify the byte-identical test, the reviewed-patch registry, or any fingerprint.

## 7. Update 2026-11-08 (status of findings; hashes still NOT approved)
- **F-1 CORRECTED** in `1720e9f`: `createIngressSigner` again refuses any collision among the four secrets (production includes `vercelBypassSecret`); the Worker-level check is retained; regression tests for every prohibited collision through direct factory calls. `workers/ingress-signer/signer.ts` remains in the drift register (lab environment tag), with the F-1 note changed to "corrected".
- **O-2 addressed** in `655d58a`: production builds from `workers/admission-service/production-index.ts` (no lab/staging exports).
- **O-3 hardened** in `655d58a`: the Vercel production contract pins `LIMITMARK_RUNTIME`, `ADMISSION_IDENTITY_MODE`, `LAB_*`, `GOOGLE_*` as forbidden.
- New drifted files since the first proposal (all classified in the generator, none fail-open): `workers/admission-service/production-index.ts`, `operator/authority-result-reader.ts`, and the `deployment/*`, `tests/*` changes of 1720e9f..f91b277. The JSON register `QUALIFICATION-BASELINE-V2-PROPOSED.json` was regenerated from the working tree at `f91b277`. The generator still fails closed on any unclassified path.
- The byte-identical test, reviewed-patch registry and fingerprints are untouched. No hash is accepted; pins still require a separate review at the final reviewed commit.
