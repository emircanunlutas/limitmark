# Baseline v2 — file-by-file review of the 42 proposed entries (2026-11-08)

Status: REVIEW ONLY. Every hash remains **UNAPPROVED**. Nothing was regenerated-and-accepted. The byte-identical test (1179), the historical-immutability test (933), the reviewed-patch registry and all fingerprints are untouched. Register: `QUALIFICATION-BASELINE-V2-PROPOSED.json` (baseline `dcf10af8…`; entries keyed by path + historicalBlob + reviewedSha256).

Columns: **Why / authorization** = the introducing commit and the recorded engineering decision (owner-authorized phases: 3P.6/3P.7 lab environment, FQ1 remediation, production preparation, Gate 11A hardening). **Sec** = does it change security behavior of the *production* path. **Cov** = T direct unit tests, W workerd integration, S static/contract/scan tests. **Accept** = reviewer recommendation for the append-only register. HOLD-light = no weakening found, but the file sits on a security boundary and needs a second reader. HOLD = do not accept yet.

Method limit: I read the full diffs of the security-relevant files (marked R) when the first proposal was written and re-read the production-relevant ones after F-1. The rest were assessed from commit subject, diff size and tests. This is one reviewer's assessment, not independent review.

## A. Production preparation (7)
| File | Why / authorization | Sec | Cov | Accept |
|---|---|---|---|---|
| `src/app/api/public-inquiries/route.ts` | 6f1c36f lab runtime contract, ab49021 production factory delegation; disabled => generic 503 | No (R) | T,S | Yes |
| `src/lib/admission-client.server.ts` | 6f1c36f/eb4a7fb lab Google provider (separate class); ab49021, 9f45010 Vercel OIDC provider (request-scoped, 1.5 s timeout, pending cap 16) | Adds an auth path (R) | T | Yes, once owner confirms the OIDC claim checks |
| `src/lib/production-launch-policy.ts` | new, 0de1536: verify-full TLS, OTel off, empty launch registry | Tightens (R) | T,S | Yes |
| `src/lib/public-inquiry-production-runtime.server.ts` | new, ab49021/0de1536/655d58a: refuses LAB_/GOOGLE_/LIMITMARK_RUNTIME | Tightens (R) | T | Yes |
| `workers/admin-gateway/index.ts` | e1a65ce: only default handler exported so the bundle loads in workerd | No | W | Yes |
| `workers/admission-service/index.ts` | eb4a7fb, 38fec4d, 4be1b10, 653d522, 08cc375: lab/Google classes added to the shared module, plain-fetch fixes | Production path unchanged (R); shared module still exports lab/staging classes (O-2, mitigated by production-index.ts) | W,S | Yes |
| `workers/admission-service/production-index.ts` | new, 655d58a: production-only exports | Tightens | S,W | Yes |

## B. Gate 11A guard export (5)
| File | Why / authorization | Sec | Cov | Accept |
|---|---|---|---|---|
| `workers/lifecycle-mailbox/guard-export.ts` | new, 0073ca9 (owner-authorized SELECT-only operator-authenticated export) | New authenticated read surface (R) | T,W | HOLD until D3 (verifier will change from the lifecycle key) |
| `workers/lifecycle-mailbox/guard-reader.ts` | new, 0073ca9: read-only WorkerEntrypoint | New surface | W | HOLD with guard-export.ts |
| `workers/lifecycle-mailbox/dispatch-guard.ts` | 0073ca9: adds `exportLedger`; claim/latch/settle logic unchanged (R) | Production guard gains a read method | T,W | HOLD with guard-export.ts |
| `workers/lifecycle-mailbox/index.ts` | 0073ca9: exports the reader entrypoint | New binding target | W | HOLD |
| `workers/lifecycle-observer.ts` | 0073ca9: slot `export-ledger.json` -> write-once `ledger-export/<nonce>.json` | New write path, authenticated requests only | W | HOLD |

## C. Observability (2)
| File | Why | Sec | Cov | Accept |
|---|---|---|---|---|
| `src/lib/public-inquiry-telemetry.server.ts` | new, 7fcc117/1409e7c: bounded request telemetry | Bounded labels (re-verify label set) | T | Yes, after label-set re-check |
| `src/lib/public-inquiry-otel.server.ts` | new, 1409e7c: optional OTel export | Forced off in production by launch policy | T | Yes |

## D. Shared fix (1)
| File | Why | Sec | Cov | Accept |
|---|---|---|---|---|
| `workers/shared/bounded-jwks.ts` | 653d522: call native `fetch` as a plain function (workerd illegal invocation) | No | W,T | Yes |

## E. Laboratory (27)
Lab changes are additive, but several edit shared production modules; those carry a production-path question.

| File | Why / authorization | Sec on production path | Cov | Accept |
|---|---|---|---|---|
| `src/lib/authority-result-attestation.ts` | 38fec4d lab environment tag | Production statements unchanged; golden v2 fixtures unchanged (R) | T | HOLD-light |
| `src/lib/authority-result-trust.ts` | 38fec4d lab trust section | Manifest grammar extended (R) | T | HOLD-light |
| `workers/admission-service/authority.ts` | 38fec4d lab authority id | Production identity pins preserved (R) | T,W | HOLD-light |
| `workers/admission-service/operator-command.ts` | 38fec4d lab `initialize` branch | Production rotate branch unchanged (R) | T | HOLD-light |
| `workers/admission-service/auth.ts` | eb4a7fb Google Cloud Run OIDC verifier | New verifier; production uses its own provider | T | HOLD-light |
| `workers/admission-service/service.ts` | eb4a7fb identity-mode selection | Server config only, never request input (R) | T | HOLD-light |
| `src/lib/ingress-protocol.ts` | caa2f70 parser accepts lab environment tag | Production verifier still requires production tag (R) | T | HOLD-light |
| `src/lib/ingress-verifier.server.ts` | 6f1c36f/caa2f70/5cb11f3 URL-authority comparison skipped only for `cloud-run-lab` | Server config only (R) | T | HOLD-light |
| `src/lib/public-origin.ts` | 6f1c36f/caa2f70/a04e184 LAB_* origin resolution | Selected by `LIMITMARK_RUNTIME`; production checks preserved (R) | T | HOLD-light |
| `src/lib/public-inquiry-handler.server.ts` | 7fcc117…7937bcc telemetry, lab Origin gate | Same selector rule (R) | T | HOLD-light |
| `src/proxy.ts` | a04e184 lab-aware origin gate | Same selector rule | T | HOLD-light |
| `src/app/test-talep-et/page.tsx` | a04e184 lab intake page | Lab only | - | Yes |
| `src/lib/public-inquiry-runtime.server.ts` | new, lab runtime factory | Unreachable from production factory | T | Yes |
| `src/lib/db/database.server.ts` | b6ba401 verified TLS object | Production client options unchanged; enforcement is launch policy | T | Yes |
| `workers/admission-service/authority-attestation-config.ts`, `-signer.ts`, `authority-attestation.ts` | 38fec4d lab signer/config | Selected by environment | T | Yes |
| `workers/admission-service/lab-index.ts` | 38fec4d lab entry | No | S | Yes |
| `workers/ingress-signer/signer.ts` | caa2f70 lab tag; 1720e9f **F-1 corrected** | Equal or stronger than baseline | T | Yes |
| `workers/ingress-signer/index.ts`, `laboratory-index.ts`, `google-id-token.ts` | caa2f70, f61f517, 1295172 lab signer entry, Google invoker token | Lab only | T,W | Yes |
| `workers/lab-lifecycle-observer.ts`, `workers/lab-operator-lifecycle-executor.ts`, `workers/lifecycle-mailbox/lab-dispatch-guard.ts`, `lab-index.ts`, `lab-processor.ts` | 38fec4d lab lifecycle workers; rotation absent | Separate classes and namespaces; lab guard now in fault-hook coverage (D2) | W,S | Yes |

## Counts and remaining approval decisions
- Entries: 42 = A 7 + B 5 + C 2 + D 1 + E 27.
- **HOLD (5):** the Gate 11A export set (section B), until D3 is decided, because the verifier will change and the hashes would need re-pinning at once.
- **HOLD-light (11):** the shared production modules edited for the lab (rows marked in section E). No production weakening found; a second reader must sign off.
- **Accept (26):** everything else, with the three conditions noted in the table (OIDC claim-check confirmation, telemetry label re-check, final-commit pinning).
- Pins are produced only at the final reviewed commit. Any later edit to a registered file needs regeneration and re-review. The register is append-only; 933 and 1179 keep reporting drift for historical files until a v2 boundary check is separately approved and added.
