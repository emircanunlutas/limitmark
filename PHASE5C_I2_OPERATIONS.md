# Phase 5C-I2 provider integration operations

Status: preparation only. Nothing in this document authorizes deployment, DNS/account changes, provider resource creation, secret installation, Deployment Protection, Turnstile, PostgreSQL, notifications, or public persistence.

## Deployment and route contract

The reviewed Production intent is defined by the three files in `deployment/`. They are templates rather than deployable configurations: every template contains `__REQUIRED_` placeholders and uses a `.template` suffix. `npm run validate:worker-config` validates that the three named Production Workers disable `workers_dev` and `preview_urls`, retain the reviewed compatibility date, have disjoint routes, and remain blocked. A later operator must render a separate reviewed configuration; `npm run validate:worker-config -- --production` deliberately refuses the unresolved templates.

Route ownership is exclusive:

- `limitmark.com/*` and `www.limitmark.com/*` belong to the public ingress signer.
- `admin.limitmark.com/*` belongs to the admin gateway.
- `admission-rpc.limitmark.com` is an authenticated service API. It has no browser UI and accepts only exact POST RPC paths after Vercel OIDC and release MAC verification.

Only the admission Worker has the `AUTHORITY` Durable Object binding. The public signer and admin gateway configurations have no DO binding. Preview must use a separate Vercel project, Workers, namespace, keys, and secrets; it must not be added as another route or environment in these Production templates.

Secrets named in `deployment/secret-matrix.json` are installed later through provider secret storage, never rendered into these files. The matrix is enforced by runtime loaders where one runtime can observe the relevant values. The public signer has four purpose-separated secrets, including B-public. The admin gateway has only B-admin. The admission service has only current and optionally previous release RPC keys; its operator key is public. Production Vercel project P may receive platform-injected B-public and may observe B-admin on an authorized proxied request, but it never receives the Workers' signing/HMAC keys, the offline operator private key, or the `AUTHORITY` binding.

`deployment/admission-release-lifecycle.template.json` and `deployment/ingress-signing-key-rollout.template.json` record the reviewed current/previous and current/next rollout shapes. Their placeholders are metadata, public keys, and secret names only; they contain no credential value.

## OIDC and JWKS behavior

The admission verifier fixes a team-scoped `https://oidc.vercel.com/<team>` issuer and derives only `https://oidc.vercel.com/<team>/.well-known/jwks`. It accepts only RS256 with a bounded `kid`, an exact audience encoded either as a string or as a singleton array containing only that string, exact subject, immutable owner ID, immutable project ID, and Production environment. Empty, multiple, duplicate, mixed, or wrong audiences deny.

`iat`, `nbf`, and `exp` are required nonnegative safe integers. The claim-to-claim ceiling has no clock tolerance: `0 <= exp - iat <= 7200`. Independently, `iat <= now + 5`, `nbf <= now + 5`, and `exp > now - 5`. There is no `nbf`-to-`iat` ordering rule because a custom-audience exchange replaces `iat` while preserving the original `nbf` and `exp`. Vercel OIDC authenticates the Production team/project workload; it does not identify one deployment. The release-specific MAC remains the deployment authorization layer.

The JWKS resolver allows HTTPS only, manual redirects, 64 KiB, eight public RSA signing keys, and a two-second timeout. A successful set is fresh for ten minutes. After freshness expires, a known cached key may be used for at most five additional minutes only when refresh fails. No key is usable after that 15-minute absolute age. Unknown `kid` values trigger at most one refresh per 30-second cooldown, and concurrent refreshes coalesce. Unknown keys, malformed sets, private key members, oversized responses, redirects, timeouts, and network failures deny. There is no indefinite stale acceptance.

## Authority initialization

The I3A sealed-artifact validator, private executor contract, local workerd proof, and remaining provider invocation gate are documented in `PHASE5C_I3A_OPERATOR_SUBMITTER.md`.

Initialization is absent from public HTTP routing. `ProductionAdmissionAuthority` extends Cloudflare's official `DurableObject` base and composes the reviewed SQLite authority core. `AdmissionServiceWorker` extends `WorkerEntrypoint`; its lifecycle methods call the fixed-name DO through the `AUTHORITY` binding. Public `fetch` dispatches only the authenticated PRE/POST service API and never dispatches lifecycle operations. The signing private key remains in the operator process; the admission Worker/DO receives only the operator public key.

Prepare a request only after provisioning has been separately authorized:

```powershell
$env:AUTHORITY_OPERATOR_PRIVATE_KEY = '<operator-only Ed25519 PKCS8 base64url>'
npm run authority:init:prepare -- --environment production --authority-id production-public-inquiries-v1 --policy-epoch phase5c-i1-epoch-1 --release-id <exact-release> --release-key-id <exact-key-id> --confirm-production-authority-initialization
```

The output contains metadata and a signature, no private key or runtime secret. Submit it from an operator-only Worker/service-binding runner to `AdmissionServiceWorker.initializeAuthorityFromOperator(command, signature)`; do not add an HTTP route. The Worker resolves only `production-public-inquiries-v1` and invokes `ProductionAdmissionAuthority.initializeFromOperator` over DO RPC. The DO verifies signature and five-minute freshness, confirms the exact environment/authority/epoch/release, and refuses Production without the explicit flag. An identical request can report `already-initialized`. Any changed metadata refuses. There is no reset operation.

Release rotation keeps the authority ID and policy epoch stable. Prepare the signed command only with the offline operator key:

```powershell
$env:AUTHORITY_OPERATOR_PRIVATE_KEY = '<operator-only Ed25519 PKCS8 base64url>'
npm run authority:rotate:prepare -- --environment production --authority-id production-public-inquiries-v1 --policy-epoch phase5c-i1-epoch-1 --current-release-id <exact-current-release> --next-release-id <exact-next-release> --next-release-key-id <exact-next-key-id> --activates-at-ms <exact-ms> --previous-retires-at-ms <exact-ms-within-5-minutes> --confirm-production-authority-rotation
```

Submit the sealed output from the same operator-only service-binding runner to `AdmissionServiceWorker.rotateAuthorityReleaseFromOperator(command, signature)`, which invokes the fixed DO's `rotateReleaseFromOperator` RPC method. The command includes only exact authority/epoch/release/key identifiers and timestamps; it cannot carry history or a reset request. Signature, Production confirmation, five-minute command/activation freshness, and overlap of at most five minutes are enforced. An identical operation is safely idempotent; a conflicting operation refuses.

Exactly one current release is configured, with at most one previous release during the reviewed overlap. Release IDs and key IDs are unique. The service rejects a retired key before MAC verification and the DO rejects a retired release. Rotation changes no observation, nonce, permit, or quota history. The operator runner must never log the signing key, release RPC keys, bypass credentials, signed request body beyond its sealed handoff, or RPC response internals.

## Vercel system-variable and bypass-secret contract

Vercel documents one project-level **Enable access to System Environment Variables** control. Enabling it makes `VERCEL_DEPLOYMENT_ID` and other deployment metadata available; if Protection Bypass for Automation is configured, Vercel also exposes one selected bypass secret as `VERCEL_AUTOMATION_BYPASS_SECRET` at build and runtime. No documented per-variable selector can retain deployment ID while suppressing only the bypass value.

`deployment/vercel-project-contract.json` records one shared Production application project P and one separate Preview project Q:

- P serves both public and admin application routes, keeps All Deployments protection, and enables system variables so `VERCEL_DEPLOYMENT_ID`, `VERCEL_PROJECT_ID`, `VERCEL_ENV`, and the exact `VERCEL=1` Production boundary remain available. Both Cloudflare gateways target P; the admin gateway's rendered upstream is one fixed reviewed P `.vercel.app` origin, never request-selected.
- P owns two independently generated, project-wide, independently revocable automation credentials. B-public is copied only to the public signer and selected for Vercel system-environment exposure, so it may exist in P at build/runtime. B-admin is copied only to the admin gateway and is not deliberately configured as an application environment variable, although P may observe it on a credential-bearing authorized request. The two values must differ.
- Q is a genuinely separate Vercel project and resource boundary. It receives no Production database, admission, origin, signing/HMAC, bypass, Turnstile, notification, operator, or `AUTHORITY` resource.

Both bypass credentials cross the Vercel platform gate for every deployment in P; neither is route-scoped or application authorization. Possession satisfies none of signed ingress, the origin bearer, admission OIDC/MAC, Turnstile, persistence authorization, Cloudflare Access, or application `requireAdmin()`. Neither value nor a derived bypass cookie may be deliberately exposed through browser code, `NEXT_PUBLIC_` variables, responses, redirects, logs, screenshots, or artifacts. Static checks catch accidental source/configuration regressions; they do not prove runtime secrecy. P is a trusted application runtime, and arbitrary code execution inside P is a broader compromise outside these application-level gates.

Ingress Ed25519 rollout similarly contains one current and optionally one next public key. The next key has an activation time; the current key has a retirement time; overlap is at most five minutes. Add and verify the next public key before switching the signer. After retirement, the old key is absent from the verifier map. Algorithms are fixed to Ed25519 and never token-selected. The private key remains only in the signer Worker.

## State loss and recovery boundaries

The response to a missing sentinel, wrong epoch, suspected PITR rollback, corruption, lost namespace, or accidental new authority is always to close intake. Do not initialize a replacement while requests or permits may still be relevant.

1. Keep `ENABLE_PERSISTENT_SUBMISSIONS=false`, leave the Production provider registry closed, and revoke the affected release RPC keys.
2. Expire or revoke in-flight permits and stop new pre admissions.
3. Preserve the suspect authority read-only for investigation. Record only authority ID, epoch, release IDs, timestamps, and aggregate counts.
4. Wait at least the maximum quota/history and replay drain interval required by `PHASE5C_R_ARCHITECTURE.md` (currently 12 minutes). A provider rollback or ambiguous loss restarts this wait.
5. Decide whether provider-supported recovery preserves the same authority history. If that cannot be verified, create a replacement only after the drain, with an explicitly reviewed namespace/object identity and the same policy epoch unless a separately reviewed migration changes it.
6. Prepare and submit one signed initialization command. Verify sentinel, authority ID, epoch, release state, empty post-drain history, alarms, and restart retention while intake remains closed.
7. Reopen only after the full synthetic provider smoke and a separate persistence launch authorization.

Never create fresh quota immediately after suspected state loss. Never automate a reset, flush, failover to an empty authority, or dual-write to two independent authorities.

For release migration, close or use the bounded previous-release overlap while preserving the namespace. For signer-key rotation, close intake for emergency compromise; ordinary rollout uses the bounded public-key overlap. Pseudonym-key rotation changes client identities and therefore quota continuity: close intake and drain the maximum history window before activation, unless a future reviewed dual-identity design proves continuity.

## Historical deployment and Preview gate

Before public persistence can ever open, an operator must inventory every P production, generated, branch, custom, and historical URL; identify pre-I1 builds; and remove their effective Production DB and admission access. All Deployments is intended to cover all those URLs, but compromise of either B-public or B-admin can cross that project-wide platform gate. Unsafe historical deployments retaining usable Production resources must therefore be retired or stripped of effective access. Latest application code cannot protect an older implementation. Retirement may be protection, credential revocation, resource-level access removal, or deletion. Deletion is not the sole acceptable control, and origin URL secrecy is never a control.

Verify the Preview application is a separate Vercel project and cannot access the Production database, authority namespace, admission endpoint credentials, Worker bypass credentials, ingress private/HMAC keys, origin bearer, request-binding key, Turnstile secret, or notification credentials. Probe old deployments with no credential, then one synthetic credential class at a time. A stale deployment must not combine a current release ID with its retired key, and project/environment OIDC claims must remain wrong for Preview.

## Later provider smoke

`smoke/provider-smoke-plan.json` is the machine-readable 16-check harness definition. Execute it only after explicit provider-test authorization, using disposable resources and synthetic data. Never dump all headers. The runner must redact assertion/OIDC tokens, bypass and MAC credentials, cookies, raw IP, pseudonyms, bodies, and inquiry data before console output, traces, screenshots, or artifacts.

For each check record only pass/fail, bounded category, timestamp, provider region/version, and aggregate latency/counts. Confirm denial occurred at the intended platform or application layer rather than inferring it from one status code. Provider smoke still must establish real IP provenance, same/cross-zone Worker behavior, Host/SNI and bytes, All Deployments behavior, both gateways, actual OIDC rotation, DO concurrency/restart/failure semantics, historical URLs, Preview isolation, and infrastructure logging privacy.

Public persistence remains blocked after I2 by the empty provider registry, the unwired Production route, `ENABLE_PERSISTENT_SUBMISSIONS=false`, and missing real Turnstile/PostgreSQL/provider configuration. Only a separate launch review may change those controls.

## Provider references reviewed

- Vercel OIDC custom API validation: <https://vercel.com/docs/oidc/api>
- Vercel OIDC claims and team-scoped discovery: <https://vercel.com/docs/oidc/reference>
- Vercel Deployment Protection automation bypass: <https://vercel.com/docs/deployment-protection/methods-to-bypass-deployment-protection/protection-bypass-automation>
- Vercel system environment variables: <https://vercel.com/docs/environment-variables/system-environment-variables>
- Cloudflare Access JWT validation and signing-key rotation: <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/>
- Cloudflare Durable Object base class and RPC: <https://developers.cloudflare.com/durable-objects/api/base/> and <https://developers.cloudflare.com/workers/runtime-apis/rpc/>
