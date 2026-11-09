# Authority and attestation dependency group: review (2026-11-09, from HEAD 6d49a71)

Review only. No entry approved, no production file modified. All blobs below equal the registry `reviewedBlob` at HEAD, and every historical blob exists in the object store.

| Entry | Historical blob | Reviewed blob | Diff |
|---|---|---|---|
| `workers/admission-service/authority.ts` | e937425e | 4f3bb59c | 25 lines |
| `workers/admission-service/operator-command.ts` | 5d2dfbcd | d1755057 | 26 lines |
| `workers/admission-service/authority-attestation.ts` | 7cf8447c | a0b2e153 | 5 lines |
| `workers/admission-service/authority-attestation-config.ts` | 7d2e7cdb | f3f959f9 | 15 lines |
| `workers/admission-service/authority-attestation-signer.ts` | 44f343d7 | 3ac6096c | 4 lines |
| `src/lib/authority-result-attestation.ts` | d4aac6a6 | bfa81faf | 10 lines |
| `src/lib/authority-result-trust.ts` | 8f784ee5 | 949c5045 | 28 lines |

## Per entry
- **authority / operator-command** (reviewed earlier, MIGRATION-REVIEW-BATCH-3.md): two-way lab binding (`environment === "lab"` iff the lab authority id), lab requires `confirmProduction === false`, rotation stays Production-only, defaults unchanged. Direct negative tests exist (`tests/lab-authority-binding.test.ts`).
- **authority-attestation**: adds `LAB_ATTESTATION_IDENTITY` only. The signer-to-identity check (environment, authorityId, policyEpoch; `signer-mismatch`) is unchanged and runs before any storage access. The production-only refusal of the rotation entry point is unchanged.
- **authority-attestation-config**: adds the three lab binding names. The cross-environment check is GENERALIZED: previously a production or staging Authority was left without a signer if the single other environment's variables were present; now any binding of any other environment (three-way) yields no signer. This is a tightening, covered by `lab-environment-isolation` ("signer bindings are per environment": every pair and every stray binding).
- **authority-attestation-signer**: one condition: the pinned environment may also be `lab`. The fingerprint, key and other checks are unchanged.
- **authority-result-attestation**: the id table gains `lab`; the release-row cap changes from `staging ? 1 : 2` to `production ? 2 : 1` (identical for production and staging, tighter for anything else, so lab allows one row); statement environment validation accepts `lab` with `authorityId` pinned to the table.
- **authority-result-trust**: a separate lab manifest parser (exactly one `lab` section). The two-section parser rejects it and this parser rejects a two-section manifest, so evidence cannot be verified against another environment's keys (test: "trust manifests are environment-exact"). Environment validation accepts `lab` with the pinned authority id.

## Authorization boundaries and validation chain
Operator command (Ed25519 over canonical bytes, 5 minute freshness, environment pinned to one authority id) leads to the authority core (two-way identity binding), then the attestation signer (per-environment key, pinned fingerprint, other environments' bindings forbidden), then the result statement (authority id pinned to environment), then the reader/verifier (per-environment trust manifest). Each hop fails closed and each hop's change is additive for `lab`.

## Callers and dependencies
Config: `admission-service/index.ts`, `r06-active-path-harness.ts`, `operator/staging-attestation-secret-engine.ts`. Signer: config, attestation, one transport harness, `operator/staging-attestation-key.ts`. Result attestation: trust, config, signer, attestation, and the operator reader, verifier, lab and staging tooling. Trust: operator reader, verifier, trust loader, lab IO, staging preflight and renderer. None of these callers is approved by approving the group.

## Missing negative tests
1. A direct statement-level test that `lab` is capped at one release row (the cap rule changed; existing row-cap tests use staging and production).
2. A direct statement/validator test pairing `environment: lab` with the production or staging authority id and the reverse (covered only through the coordinator and manifests today).
3. A direct test that a coordinator with the lab identity refuses a staging signer (the production-signer case is covered by `tests/lab-authority-binding.test.ts`).
None indicates a defect; the rules are correct by inspection.

## Can the group be approved together?
Yes, as one set of seven (the two reviewed earlier plus these five). The changes are additive for `lab`, tightening for unknown environments, and no entry weakens another's check. Recommendation: APPROVE the set after items 1 and 2 are added as tests (test-only). Approving fewer than all seven leaves the approved lab executor depending on unreviewed attestation code. `src/lib/ingress-verifier.server.ts`, `public-inquiry-*` and the other PENDING consumers remain separate decisions.
