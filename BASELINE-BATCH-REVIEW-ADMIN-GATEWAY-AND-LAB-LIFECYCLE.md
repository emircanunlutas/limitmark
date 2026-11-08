# Baseline batch review: admin-gateway entry, lab lifecycle observer, lab lifecycle executor (2026-11-08) — REVIEW ONLY, NOTHING APPROVED

Registry state is unchanged (44 entries, 2 APPROVED, 42 PENDING). Each blob below was read with `git rev-parse` and compared with `tests/support/reviewed-migrations.ts`; they match.

| Path | Change | Historical blob (64ccc9d = dcf10af8 = aff793e) | Replacement blob (HEAD) | reviewed sha256 (LF) |
|---|---|---|---|---|
| `workers/admin-gateway/index.ts` | modified | `98ea23e1764d2c504e7844bf5d300f6b2e4fee36` | `9c159eaf416dffe751e2fa66cb262ab3acc4c8a4` | `a1c9e306…292f76e` |
| `workers/lab-lifecycle-observer.ts` | added | absent at all three | `b0c2eb42011285e1ce031bb89ecd715fece9a21c` | `14e57f8d…fe13227` |
| `workers/lab-operator-lifecycle-executor.ts` | added | absent at all three | `dadcb9769e11e67eaf8c01711a9150a159aa51fc` | `f6c98d7f…459a5` |

## 1. `workers/admin-gateway/index.ts`
- Diff: one re-export line replaced by a comment (`export { ADMIN_GATEWAY_HOST, createAdminGateway, type AdminGatewayConfiguration } from "./gateway"` removed). The handler, the secret-policy gate and the configuration mapping are byte-identical.
- Reason and effect: workerd refuses a module export that is not a handler or class, so the deployable entry must expose only the default handler. No behavior change for requests.
- New test: `tests/admin-gateway-entry-contract.test.ts` (4 tests, pass): the namespace has exactly `default`; the default object has exactly `fetch`; the source has no runtime re-export or named export; an environment that fails the secret policy gets an empty 503 and the gateway is not reached. The baseline file fails the source assertion (it re-exports a runtime value), so the test discriminates.
- Existing: `admin-gateway.test.ts` imports `./gateway` directly and never imported these names from the entry.
- Observation (pre-existing, not in this diff): `configuredHandler ??=` caches the first environment's configuration for the isolate's lifetime.

## 2. `workers/lab-lifecycle-observer.ts`
- A copy of the production observer's reconciliation relay only. The production observer's guard-export relay (`observeGuardExport`, `GUARD_READER`, the import of `lifecycle-mailbox/guard-export`) is absent, so this file does not depend on any guard-export hold entry.
- Behavior: reads `reconcile.json` (bounded to 1 024 bytes), parses it as a control, forwards the exact digest and nonce to the Authority's `attestReconciliation`, and stores the returned signed envelope bytes unchanged. Without signed evidence it stores only an explicit unsigned, non-positive diagnostic. Never overwrites an existing key. `fetch` answers an empty 404. Errors are swallowed so a later request with a new nonce can retry.
- Boundaries: it holds no signing key, builds no Authority semantics, and gates its scheduled work on `validateRuntimeSecrets("lifecycleObserver", env)`.
- Observation: unlike the executor it carries no runtime environment marker; its lab isolation comes from the deployment contract (`validateLabLifecycleObserverConfig`: lab buckets and service binding), not from a check in the code.
- Imports are outside the registry (`lifecycle-mailbox/wire`, `operator/attested-relay`, `deployment/secret-policy`) and unchanged from the baselines, except `deployment/secret-policy.ts`: its 11 added lines (production Vercel project forbidden-variable contract) do not touch `validateRuntimeSecrets`.
- Reachability: lab only (`deployment/lifecycle-observer.lab.jsonc`).

## 3. `workers/lab-operator-lifecycle-executor.ts`
Compared line by line with the production `workers/operator-lifecycle-executor.ts` (itself unchanged from the baselines):
- Removed: `submitRotationArtifact`. The lab class has no rotation method at all (Gate 9 closed), so a misconfigured caller gets "no such method" before any lifecycle code runs. The lab binding type is `Pick<…, "initializeAuthorityFromOperatorAttested">`.
- Changed: the environment guard requires `OPERATOR_EXECUTOR_ENVIRONMENT === "lab"` (production requires `"production"`), and the submitter is called with `expectedEnvironment = "lab"`.
- **Artifact construction:** a sealed JSON string, at most 4 096 characters, encoded UTF-8. The shared submitter parses it with a strict parser (duplicate object keys, BOM, invalid UTF-8 and trailing data refused) and requires an exact two-member envelope `{command, signature}`.
- **Signing and verification boundary:** the command version, operation (`initialize`), environment (`lab`), authority id (the lab id) and policy epoch are pinned; the command schema is validated; the signature must be canonical base64url of 64 bytes; `verifyOperatorCommand` verifies it against `AUTHORITY_OPERATOR_PUBLIC_KEY` (a deployed public value) before anything is relayed; a submission is refused unless `issuedAt` is within 5 minutes of now. The Authority then verifies again (`…Attested`).
- **Environment binding / target identity:** the deployment binds only the service `limitmark-admission-service-lab` entrypoint `LabAuthorityLifecycleOnly`. A production or staging artifact is refused by the pinned environment and authority id. The cross-environment behavior is exercised by `lab-environment-isolation.test.ts` with real rigs.
- **Authorization:** no public route (`fetch` is 404, `workers_dev` false); only a holder of the private service binding can call it; the call still needs an operator-signed command.
- **Error handling:** invalid environment or oversize input throws a fixed error; a transport exception becomes `UNCONFIRMED` and is never retried (a commit may have happened). A signature failure throws from the shared verifier, before the relay try block (same as production).
- **Relation to production:** strictly a subset of the production executor's capability, parameterized to the lab environment. It adds no new signing, key or network path.
- Tests today: structural (`authority-activation-guards` file lists, `lab-environment-isolation` config rendering and source scans, `operator-executor-contract`). **Superseded by FINAL-C9-VERIFICATION-AND-MIGRATION-DECISION-PACKAGE.md: the executor-level runtime test now exists (and lab-lifecycle-mailbox.integration.ts already covered it end to end).** Originally missing: a runtime test of the class itself (wrong `OPERATOR_EXECUTOR_ENVIRONMENT` throws, no `submitRotationArtifact` property, oversize input refused). It imports `cloudflare:workers`, so it needs the workerd harness (`tests/workers/*.integration.ts`) or a module stub; not added in this cycle.

## 4. Findings and recommendation
- No defect found. Observations only: the lab observer's missing in-code environment marker, the executor's missing runtime test, and the pre-existing handler cache in the admin gateway.
- Approval recommendation (not an approval): admin-gateway entry is ready (its missing test now exists). The lab observer is ready (lab-only, relay only). The lab executor is ready on the code, with the runtime test recommended before approval because it submits lifecycle artifacts.
