# Baseline v2 acceptance package (2026-11-08) — NOTHING IS ACCEPTED

Register: `QUALIFICATION-BASELINE-V2-PROPOSED.json` (status PROPOSED-NOT-ACCEPTED). Historical baseline commit `dcf10af8229a…`; register generated at `f91b277`.
All SHA-256 values below were re-verified against the git blob at HEAD (0 mismatches). "Hist blob" is the git blob id at the historical baseline (`-` = file absent there). "Current blob" is the git blob id at HEAD.
Recommendation vocabulary: **ACCEPT-CANDIDATE** (not approved), **HOLD-light** (second reader required), **HOLD** (blocked on the export-key decision D3).

Instrumentation note: the P0 counters (82045e3) add only NEW files; the runtime wiring is a held patch (PROPOSED-INSTRUMENTATION-WIRING.patch) and would be a further migration entry for `defense/plane/runtime.ts` (pinned to aff793e and the baseline).

| # | File | Δ | Hist blob | Current blob | reviewedSha256 (first 16) | Commits | Behavioral / security impact | Test evidence | Recommendation |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `src/app/api/public-inquiries/route.ts` | modified | fb10855a51 | 6e2ad42b58 | d19fc52d41db601c | 6f1c36f, ab49021 | No (R) | T,S | ACCEPT-CANDIDATE |
| 2 | `src/app/test-talep-et/page.tsx` | modified | 7dd22aa776 | 13371695d5 | 80e3a1d0d433143b | a04e184 | Lab only | - | ACCEPT-CANDIDATE |
| 3 | `src/lib/admission-client.server.ts` | modified | f8ea5e3797 | bbc7125393 | 43582e2e9cb8be50 | 6f1c36f, eb4a7fb, ab49021, 9f45010 | Adds an auth path (R) | T | ACCEPT-CANDIDATE (condition: owner confirms OIDC claim checks) |
| 4 | `src/lib/authority-result-attestation.ts` | modified | d4aac6a690 | bfa81fafdc | a5858c34d11f8f3a | 38fec4d | Production statements unchanged; golden v2 fixtures unchanged (R) | T | HOLD-light |
| 5 | `src/lib/authority-result-trust.ts` | modified | 8f784ee5b3 | 949c504560 | e232f0f130599976 | 38fec4d | Manifest grammar extended (R) | T | HOLD-light |
| 6 | `src/lib/db/database.server.ts` | modified | f7b508c3cb | 8d87826196 | 919202e113d8d437 | b6ba401 | Production client options unchanged; enforcement is launch policy | T | ACCEPT-CANDIDATE |
| 7 | `src/lib/ingress-protocol.ts` | modified | 04de4ef57d | 15e374c360 | 6a7c17ef9e5b7f43 | caa2f70 | Production verifier still requires production tag (R) | T | HOLD-light |
| 8 | `src/lib/ingress-verifier.server.ts` | modified | cdd68bfa75 | 11c36fa038 | 3244951c85937ee8 | 6f1c36f, caa2f70, 5cb11f3 | Server config only (R) | T | HOLD-light |
| 9 | `src/lib/production-launch-policy.ts` | added | - | c7c6efdbe7 | 2b08e98a866ac13c | 0de1536 | Tightens (R) | T,S | ACCEPT-CANDIDATE |
| 10 | `src/lib/public-inquiry-handler.server.ts` | modified | d15207ff70 | 65aebccd07 | 9d06d12dcd80aba6 | 7fcc117, 1409e7c, 6f1c36f, a04e184, 7937bcc | Same selector rule (R) | T | HOLD-light |
| 11 | `src/lib/public-inquiry-otel.server.ts` | added | - | c49895a22b | 8c38cbb0244ead4b | 1409e7c | Forced off in production by launch policy | T | ACCEPT-CANDIDATE |
| 12 | `src/lib/public-inquiry-production-runtime.server.ts` | added | - | 60feab9014 | 8b6680cfaf8bb614 | ab49021, 0de1536, 655d58a | Tightens (R) | T | ACCEPT-CANDIDATE |
| 13 | `src/lib/public-inquiry-runtime.server.ts` | added | - | 886c4fc558 | ed92d46c3c146f95 | 6f1c36f, eb4a7fb, caa2f70, b6ba401, a04e184 | Unreachable from production factory | T | ACCEPT-CANDIDATE |
| 14 | `src/lib/public-inquiry-telemetry.server.ts` | added | - | a53bb83ece | 3dcc5c8b286b3e0c | 7fcc117, 1409e7c | Bounded labels (re-verify label set) | T | ACCEPT-CANDIDATE (condition: label-set re-check) |
| 15 | `src/lib/public-origin.ts` | modified | 3ca900726f | 910a0ee1da | 19673ef8351cea00 | 6f1c36f, caa2f70, a04e184 | Selected by `LIMITMARK_RUNTIME`; production checks preserved (R) | T | HOLD-light |
| 16 | `src/proxy.ts` | modified | dd18b5a024 | 40ab5fe32e | 3f77a95ac96cd04d | a04e184 | Same selector rule | T | HOLD-light |
| 17 | `workers/admin-gateway/index.ts` | modified | 98ea23e176 | 9c159eaf41 | a1c9e3061e46d25b | e1a65ce | No | W | ACCEPT-CANDIDATE |
| 18 | `workers/admission-service/auth.ts` | modified | b2dbf6509a | 0989a55b84 | c6339e4cf974086a | eb4a7fb | New verifier; production uses its own provider | T | HOLD-light |
| 19 | `workers/admission-service/authority-attestation-config.ts` | modified | 7d2e7cdb75 | f3f959f91d | 8d829524c6074b45 | 38fec4d | Selected by environment | T | ACCEPT-CANDIDATE |
| 20 | `workers/admission-service/authority-attestation-signer.ts` | modified | 44f343d7b4 | 3ac6096c21 | 227339082094a176 | 38fec4d | Selected by environment | T | ACCEPT-CANDIDATE |
| 21 | `workers/admission-service/authority-attestation.ts` | modified | 7cf8447c69 | a0b2e15376 | 61d80c64409bb154 | 38fec4d | Selected by environment | T | ACCEPT-CANDIDATE |
| 22 | `workers/admission-service/authority.ts` | modified | e937425eaf | 4f3bb59ce5 | 978af3510671a4d9 | 38fec4d | Production identity pins preserved (R) | T,W | HOLD-light |
| 23 | `workers/admission-service/index.ts` | modified | 5d5354596d | f52f91d2f8 | 06be74ef1342e278 | eb4a7fb, 38fec4d, 4be1b10, 653d522, 08cc375 | Production path unchanged (R); shared module still exports lab/staging classes (O-2, mitigated by production-index.ts) | W,S | ACCEPT-CANDIDATE |
| 24 | `workers/admission-service/lab-index.ts` | added | - | 9289602654 | 0ac4a527a73371b5 | 38fec4d | No | S | ACCEPT-CANDIDATE |
| 25 | `workers/admission-service/operator-command.ts` | modified | 5d2dfbcdb6 | d175505731 | aa0322cd6e0186e7 | 38fec4d | Production rotate branch unchanged (R) | T | HOLD-light |
| 26 | `workers/admission-service/production-index.ts` | added | - | 46289a1059 | 924cd788d3e20394 | 655d58a | Tightens | S,W | ACCEPT-CANDIDATE |
| 27 | `workers/admission-service/service.ts` | modified | 22da37a95e | 83e3af7d9f | 6c61bfa108d3f85f | eb4a7fb | Server config only, never request input (R) | T | HOLD-light |
| 28 | `workers/ingress-signer/google-id-token.ts` | added | - | e3d0272468 | 78bf1b131a159654 | f61f517 | Lab only | T,W | ACCEPT-CANDIDATE |
| 29 | `workers/ingress-signer/index.ts` | modified | bd531caa3f | 383c884d05 | d69da46abc2369a1 | caa2f70 | Lab only | T,W | ACCEPT-CANDIDATE |
| 30 | `workers/ingress-signer/laboratory-index.ts` | added | - | 283d01e41f | 9ecbab1409dd69fb | caa2f70, f61f517, 1295172 | Lab only | T,W | ACCEPT-CANDIDATE |
| 31 | `workers/ingress-signer/signer.ts` | modified | 18f977033f | 6949104882 | 3c26770514d19fc4 | caa2f70, 1720e9f | Equal or stronger than baseline | T | ACCEPT-CANDIDATE |
| 32 | `workers/lab-lifecycle-observer.ts` | added | - | b0c2eb4201 | 14e57f8d4a52e554 | 38fec4d | Separate classes and namespaces; lab guard now in fault-hook coverage (D2) | W,S | ACCEPT-CANDIDATE |
| 33 | `workers/lab-operator-lifecycle-executor.ts` | added | - | dadcb9769e | f6c98d7f01e6e1a9 | 38fec4d | Separate classes and namespaces; lab guard now in fault-hook coverage (D2) | W,S | ACCEPT-CANDIDATE |
| 34 | `workers/lifecycle-mailbox/dispatch-guard.ts` | modified | 8080226f21 | b73b004609 | b24783bebd9754a2 | 0073ca9 | Production guard gains a read method | T,W | HOLD |
| 35 | `workers/lifecycle-mailbox/guard-export.ts` | added | - | 201335cf0b | ad807439d7790807 | 0073ca9 | New authenticated read surface (R) | T,W | HOLD |
| 36 | `workers/lifecycle-mailbox/guard-reader.ts` | added | - | 8714bd2e77 | f7cfc64e0f71753e | 0073ca9 | New surface | W | HOLD |
| 37 | `workers/lifecycle-mailbox/index.ts` | modified | 3464a3e0bb | c030292698 | 449a58917de85c1d | 0073ca9 | New binding target | W | HOLD |
| 38 | `workers/lifecycle-mailbox/lab-dispatch-guard.ts` | added | - | 90785956c9 | 8675191e9920366b | 38fec4d | Separate classes and namespaces; lab guard now in fault-hook coverage (D2) | W,S | ACCEPT-CANDIDATE |
| 39 | `workers/lifecycle-mailbox/lab-index.ts` | added | - | c0fa2d23fd | 81d151db986eeedf | 38fec4d | No | S | ACCEPT-CANDIDATE |
| 40 | `workers/lifecycle-mailbox/lab-processor.ts` | added | - | 0e702b3bdd | 24515ffc1fc5e3fb | 38fec4d | Separate classes and namespaces; lab guard now in fault-hook coverage (D2) | W,S | ACCEPT-CANDIDATE |
| 41 | `workers/lifecycle-observer.ts` | modified | 04c47007be | cb2f9cc72b | c40e4c00243beca4 | 0073ca9 | New write path, authenticated requests only | W | HOLD |
| 42 | `workers/shared/bounded-jwks.ts` | modified | 00c28240f0 | 7941034b7c | 9edcf0fb3760ca42 | 653d522 | No | W,T | ACCEPT-CANDIDATE |

Totals: ACCEPT-CANDIDATE 26, HOLD-light 11, HOLD 5 (=42).

## What approval would mean (not done)
1. An append-only v2 boundary check is added (second exclusion list sourced from the approved subset; the `diff(...) === ""` assertions, fingerprints and identity-list assertions unchanged).
2. Pins are generated at the final reviewed commit; any later edit to a registered file requires regeneration and re-review.
3. Held entries stay out of the v2 exclusion list, so the two byte-identical tests keep failing for them until their review completes — they are never silently absorbed.
4. Full-file column detail (why/authorization) is in `BASELINE-V2-FILE-REVIEW.md`; diffs: `git diff dcf10af822 HEAD -- <file>`.
