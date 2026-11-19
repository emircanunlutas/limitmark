# M1 migration blocker closure (2026-11-09, from HEAD 1fff395)

Registry: 44 entries, 6 APPROVED, 38 PENDING. This document approves nothing. Evidence used: the pinned historical and reviewed blobs (all equal HEAD), `QUALIFICATION-BASELINE-MIGRATION-PROPOSAL.md` / `tests/support/qualification-baseline-proposal.ts` (per-file category and security note), `BASELINE-V2-FILE-REVIEW.md`, the reviews of earlier cycles, and the import graph between the 44 entries. The clean-checkout suite passes everything except the two historical guards, so every existing test that covers these files passes.

## 1. Result
| Class | Count | Meaning |
|---|---|---|
| APPROVE-READY | 27 | file-level approval is supportable now; the three authority tests (below) are written and pass |
| DEPENDENCY-BLOCKED | 3 | ready in themselves, but import `dispatch-guard.ts`, which is in the Gate 11A set |
| DEPLOYMENT-BOUNDARY-BLOCKED | 8 | approval needs an owner boundary decision, not a missing test |
| TEST-BLOCKED | 0 | the three previously missing tests were added this cycle (`tests/lab-attestation-negatives.test.ts`, 3 tests, pass) |
| SECURITY-BLOCKED | 0 | no unsafe behavior found; the only shared-production observations are O-2 and O-3 below |
File-level approval, dependency closure, deployment authorization and production qualification are four separate decisions. Approving a file never deploys it and never qualifies anything.

## 2. All 38 entries
Dependencies are imports between registry entries (A = already approved).
### G1. Authority and attestation core (7): APPROVE-READY as one set
| Path | Review id | Historical blob | Reviewed blob | Depends on |
|---|---|---|---|---|
| `workers/admission-service/authority.ts` | BASELINE-V2/LABORATORY | e937425e | 4f3bb59c | A: ingress-protocol |
| `workers/admission-service/operator-command.ts` | BASELINE-V2/LABORATORY | 5d2dfbcd | d1755057 | authority, A: ingress-protocol |
| `workers/admission-service/authority-attestation.ts` | BASELINE-V2/LABORATORY | 7cf8447c | a0b2e153 | authority, operator-command, signer, result-attestation |
| `workers/admission-service/authority-attestation-config.ts` | BASELINE-V2/LABORATORY | 7d2e7cdb | f3f959f9 | attestation, signer, result-attestation |
| `workers/admission-service/authority-attestation-signer.ts` | BASELINE-V2/LABORATORY | 44f343d7 | 3ac6096c | result-attestation |
| `src/lib/authority-result-attestation.ts` | BASELINE-V2/LABORATORY (hold shared-production-module) | d4aac6a6 | bfa81faf | authority |
| `src/lib/authority-result-trust.ts` | BASELINE-V2/LABORATORY (hold shared-production-module) | 8f784ee5 | 949c5045 | result-attestation |
Evidence: AUTHORITY-ATTESTATION-GROUP-REVIEW.md; direct negatives `tests/lab-authority-binding.test.ts` (6), `tests/lab-environment-isolation.test.ts`, `tests/authority-unknown-classification.test.ts` (4) and now `tests/lab-attestation-negatives.test.ts` (3: lab release cap is exactly one and Production keeps its two-row window; a lab statement cannot bind to a Production or staging authority id and no other environment can carry the lab id; a lab coordinator refuses a staging signer and a staging coordinator a lab signer). Changes are additive for `lab` and tighten unknown environments. Unknown-authority label: informational (M1-CAMPAIGN-TRUST-CLOSURE.md section 3).
### G2. Admission service authentication and entries (5): APPROVE-READY (closure: G1 + `bounded-jwks` A)
| Path | Review id | Note |
|---|---|---|
| `workers/admission-service/auth.ts` | LABORATORY | additive Google OIDC verifier; Vercel verifier untouched; tests admission-service-auth, google-laboratory-identity, lab-jwks-fetch-wrapper |
| `workers/admission-service/service.ts` | LABORATORY | authentication step parameterized; same checks and order for the Vercel path; tests admission-service-auth, production-vercel-oidc |
| `workers/admission-service/index.ts` | PRODUCTION_PREPARATION | shared module; O-2: still exports lab and staging classes, so the production bundle is built from `production-index.ts`, pinned by `production-identity-contract.test.ts` |
| `workers/admission-service/production-index.ts` | PRODUCTION_PREPARATION | 6-line re-export of production names only; pinned by the same test |
| `workers/admission-service/lab-index.ts` | LABORATORY | 5-line re-export of lab names only; `lab-environment-isolation` |
### G3. Public inquiry web path (11): APPROVE-READY except as noted in section 3 (closure: `ingress-protocol` A, G1 for `admission-client`)
`src/lib/ingress-verifier.server.ts` (production URL-authority comparison preserved unless server configuration selects the lab; 38 tests including the new isolation suite), `src/lib/public-origin.ts` and `src/proxy.ts` (lab branch selected only by `LIMITMARK_RUNTIME`; O-3: the order of two failing checks changed, same outcome; `public-origin.test`, `lab-fq1-remediation`), `src/lib/public-inquiry-handler.server.ts` (O-3; carries the telemetry wrapper), `src/lib/admission-client.server.ts` (additive Vercel OIDC provider, inert until the production factory is enabled; 8 test files), `src/lib/db/database.server.ts` (optional verified-TLS object; production client options unchanged; `database-tls`, `production-database-tls`), `src/lib/public-inquiry-runtime.server.ts` (lab runtime factory; `public-inquiry-runtime.test`), `src/app/test-talep-et/page.tsx` (lab intake selected only by `LIMITMARK_RUNTIME`; uses the tested `getLaboratoryIntakeState`), `src/lib/public-inquiry-otel.server.ts` and `src/lib/public-inquiry-telemetry.server.ts` (inert unless enabled; the production launch policy forbids it).
The three production enablement files of this group are classified in section 3.
### G4. Ingress signer (4): APPROVE-READY
`workers/ingress-signer/google-id-token.ts` (2 test files), `signer.ts` (F-1 corrected in 1720e9f; `worker-ingress-signer`, `replay-protection-chain`), `index.ts` (adds `originHostname`; `production-identity-contract`), `laboratory-index.ts` (referenced by `authority-bootstrap-trust` and the rendered lab configuration).
### G5. Lab lifecycle observer (1): APPROVE-READY
`workers/lab-lifecycle-observer.ts` (`lab-observer-isolation`; stays out of any production bundle).
### G6. Lab lifecycle mailbox (3): DEPENDENCY-BLOCKED
`workers/lifecycle-mailbox/lab-dispatch-guard.ts` (imports `dispatch-guard`, `operator-command`, `authority`), `lab-processor.ts` (imports `dispatch-guard`), `lab-index.ts` (imports `lab-processor`, `lab-dispatch-guard`). Concrete blocker: `dispatch-guard.ts` is in G7. Covered by `lab-environment-isolation`, `authority-activation-guards`, `guard-export-method`, and the workerd lab suites (PASS at 1fff395).

## 3. Entries needing an owner boundary decision (8): DEPLOYMENT-BOUNDARY-BLOCKED
| Path | Review id | Concrete boundary |
|---|---|---|
| `src/app/api/public-inquiries/route.ts` | PRODUCTION_PREPARATION | the production branch now calls `createProductionRuntimeDependencies`; stays disabled (generic 503) while `availableProductionRateLimitProviders = []` (pinned by `phase5c.test.ts`). Approval admits production route wiring: needs the baseline-v2 acceptance decision (D-1) |
| `src/lib/public-inquiry-production-runtime.server.ts` | PRODUCTION_PREPARATION | production dependency factory (Vercel OIDC); refuses lab variables and non-verify-full TLS; same decision |
| `src/lib/production-launch-policy.ts` | PRODUCTION_PREPARATION | the fail-closed launch gate itself; same decision |
| `workers/lifecycle-mailbox/guard-export.ts` | GATE_11A_GUARD_EXPORT | request/response format of the guard ledger export |
| `workers/lifecycle-mailbox/guard-reader.ts` | GATE_11A_GUARD_EXPORT | single-method read-only entrypoint |
| `workers/lifecycle-mailbox/dispatch-guard.ts` | GATE_11A_GUARD_EXPORT | adds one SELECT-only, operator-authenticated export method to the production guard surface (the pinned surface test was updated with approval); depends on G1 and `guard-export` |
| `workers/lifecycle-mailbox/index.ts` | GATE_11A_GUARD_EXPORT | exports the reader entrypoint |
| `workers/lifecycle-observer.ts` | GATE_11A_GUARD_EXPORT | optional relay of the authenticated export; a production-adjacent Worker |
Why not APPROVE-READY: Gate 11A is closed by owner decision; the export key (D-3) is architecture-approved but its implementation is not authorized; the baseline-v2 acceptance (D-1) is open. No test is missing; these are decisions. File-level approval would still deploy nothing.
Observations carried forward: O-2 (shared admission `index.ts` exports lab and staging classes; mitigated by `production-index.ts`), O-3 (public-origin/handler check order).

## 4. Batch approval proposal (owner decision required; nothing here is applied)
| Batch | Entries | Closure it needs | Result on the guards |
|---|---|---|---|
| B1 | G1 (7) | `ingress-protocol` A | 31 pending remain on each guard |
| B2 | G2 (5) + G4 (4) + G5 (1) | B1, `bounded-jwks` A | 21 remain |
| B3 | G3 minus the production enablement files (8 of 11) | B1 for `admission-client`, B2 not required | 13 remain |
| B4 | the 3 DEPENDENCY-BLOCKED (G6) | the Gate 11A set approved first, or approved together with it | |
| B5 | Gate 11A set (5) and production enablement set (3) | owner decisions D-1, D-3 and the Gate 11A boundary decision | 0 remain |
Each batch is a registry edit of `status`, `authorization` and `scope` only, at the existing reviewed blob, with the dependency note "not implied for its imports", exactly as the six existing approvals.

## 5. Historical guard closure sequence
The two failing guards ("historical qualification is immutable", baseline 64ccc9d; "files that decide admission", baseline dcf10af8) diff `defense`, `src` and `workers`. Measured by simulating approvals against the real repository (no registry change made):
| Approvals added to the current six | 64ccc9d remaining | dcf10af8 remaining |
|---|---|---|
| none | 38 | 38 |
| B1 (7) | 31 | 31 |
| all 27 APPROVE-READY | 11 | 11 |
| 27 + the 3 dependency-blocked (30) | 8 (the eight boundary entries) | 8 |
| all 38 | 0 | 0 |
So both guards pass only when ALL 38 are approved; no subset closes them, and the pending counts in `tests/reviewed-migrations.test.ts` must change only with each legitimate approval (never to obtain green). Sequence: B1, B2, B3, then the owner's boundary decisions, then B4 and B5. The guards remain enforced and unchanged throughout.

## 6. Owner decisions that release the blockers
1. Approve batches B1 to B3 (20 files group by group, or all 27 at once).
2. D-1: accept baseline v2 for the production-preparation files (`route.ts`, production runtime, launch policy).
3. Gate 11A: authorize file-level approval of the five guard-export files (not deployment), and decide D-3 (export key implementation).
4. Then B4/B5, which closes both guards.

## 7. Update after owner approval of B1 to B3 (2026-11-09, commit 956fc65)
- **Corrected counts.** Section 2 mislabels the public inquiry group: it lists 10 approve-ready files (plus the 3 production enablement files of section 3), so the 27 are G1 7 + G2 5 + G3 10 + G4 4 + G5 1. The batch table's B3 is therefore 10 files, not "8 of 11".
- **Verified before the change (all 27, by script):** each historical blob exists and equals the pinned blob at all three baselines; each reviewed blob equals the HEAD blob, the working-tree blob and the recorded sha256; no entry imports any of the 11 held entries (the lab observer imports only `lifecycle-mailbox/wire`, which is not registered); none has hold `guard-export` or a Gate 11A review id; unit suite and workerd suites (admission, lab executor, lab JWKS, lab lifecycle mailbox, production identity) pass.
- **Applied:** exactly those 27 entries are APPROVED, file-scoped and non-transitive, with a per-file scope and the phrase "authorizes no deployment or production enablement". Registry: 44 total, 33 APPROVED, 11 PENDING. `tests/reviewed-migrations.test.ts` was updated for the approval only (pending count 11, the exact list of 27 approvals and of the 11 that must remain pending, authorization and scope assertions, and the dependency test now also pins that approving an import does not approve its held importer).
- **Still PENDING (11):** `src/app/api/public-inquiries/route.ts`, `src/lib/public-inquiry-production-runtime.server.ts`, `src/lib/production-launch-policy.ts` (D-1 and production enablement); `workers/lifecycle-mailbox/guard-export.ts`, `guard-reader.ts`, `dispatch-guard.ts`, `index.ts`, `workers/lifecycle-observer.ts` (Gate 11A, D-3); `workers/lifecycle-mailbox/lab-dispatch-guard.ts`, `lab-processor.ts`, `lab-index.ts` (import the held `dispatch-guard.ts`; B4).
- **Guards:** both historical guards are still red and now fail on exactly these 11 files (`pending` = 11 for each baseline, no unreviewed drift, no file modified after review). They close only when all 11 are approved.
- Not deployable: approved files whose dependencies remain PENDING are not deployable by that fact; approving `admission-client.server.ts` does not enable the production factory, route or launch policy.
