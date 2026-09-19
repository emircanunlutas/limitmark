# Phase 5C-I3A: private operator lifecycle submission

Status: local implementation and workerd proof only. This document does not authorize provisioning, deployment, secret installation, provider access, or public persistence.

## Existing lifecycle contract

The sealed artifact is the existing `{ "command": [...], "signature": "..." }` JSON emitted by `authority:init:prepare` or `authority:rotate:prepare`. It uses `limitmark-authority-operator-v1`, the fixed Production authority `production-public-inquiries-v1`, policy epoch `phase5c-i1-epoch-1`, and an offline Ed25519 signature. No new lifecycle command or reset exists. The offline private key stays only with the preparer. The submitter and executor receive the signed artifact and the matching public key; the Durable Object verifies the signature again before mutation.

`AdmissionServiceWorker.initializeAuthorityFromOperator` and `rotateAuthorityReleaseFromOperator` are service-binding RPC methods. Each resolves only the fixed `AUTHORITY` object name and calls `ProductionAdmissionAuthority`. The public admission `fetch` serves only authenticated PRE/POST. Known policy failures return the bounded result `refused`; an unexpected exception remains ambiguous.

## Operator boundary

Prepare the artifact using the I2 commands and save their output to an operator-controlled UTF-8 file. The preparation commands print the signed artifact to stdout, so redirect stdout to a protected file and avoid recording it in terminal logs. Submission requires an explicit path and flag:

```powershell
npm run authority:init:submit -- --command .\sealed-init.json --confirm-production --inspect
npm run authority:rotate:submit -- --command .\sealed-rotate.json --confirm-production --inspect
```

`--inspect` reads at most 4096 bytes, rejects invalid UTF-8, duplicate JSON members, extra fields, wrong command/version/environment/authority/epoch, malformed signature encoding, invalid release transition, and commands beyond the five-minute freshness window. It prints only operation, environment, authority ID, epoch, and issuance time. It never calls RPC. The parser does not accept stdin, target URLs, Worker names, DO names, RPC method names, or private keys.

Without `--inspect`, the CLI performs the same validation and currently exits `UNAVAILABLE` without invoking RPC. A local terminal does not possess a deployed Cloudflare service-binding stub. There is no direct shell transport in this design, and an HTTPS lifecycle endpoint must not be substituted. The CLI's unavailable status is intentional until a separately authorized provider-private invocation channel exists. The private executor returns success, already-applied, refused, or unconfirmed; its invoker must translate every non-success result to a nonzero job exit.

## Private executor contract

`OperatorLifecycleExecutor` is an RPC-only `WorkerEntrypoint` with exactly two methods: `submitInitializationArtifact` and `submitRotationArtifact`. Its `fetch` always returns 404. Its Production methods also require the exact `production` executor environment. The deployment template leaves the Worker name, account ID, entry file, admission service identity, operator public key, and environment unresolved. The raw template's `main` names a nonexistent render-required file. Wrangler can parse the JSON shape; parsing alone is not a deployment safety check. Direct `wrangler deploy` against the raw template is prohibited.

There is no repository deployment wrapper for this executor. Before any separately authorized deployment, render a config in `deployment/` and run:

```powershell
npm run authority:executor:preflight -- --config deployment/<reviewed-rendered-config>.jsonc
```

This local preflight rejects the raw template, unresolved or malformed account ID/public key, wrong Worker/service/environment identity, duplicate JSON members, and any field beyond the exact reviewed schema. The only permitted capabilities are one service binding to `limitmark-admission-service-production` and the two reviewed public configuration values. It rejects `route`, `routes`, `env`, assets, storage, queues, observability/tail bindings, and every unknown future top-level capability. It verifies the entry file resolves to the reviewed executor source. A fully specified synthetic config passes local validation; no actual account ID or key is stored in this repository. This preflight is a required operator step for a future reviewed deployment command path; direct Wrangler use bypassing it is outside the reviewed procedure. The public key must also be independently checked against the key installed on the admission Worker.

A later provider-authenticated operator job must have a service binding to this executor, receive the existing sealed file through its private input channel, and invoke only the matching executor RPC method. That job must have no public route, `workers.dev`, preview URL, browser access, or reusable HTTP bearer endpoint. The exact provider job and its private invocation mechanism require separate design review and provider provisioning. The job must not receive the operator private key. The executor's submitter validates and verifies the artifact against its pinned public key, calls the admission service binding once, and accepts only the two expected result sets. It never selects a Worker, namespace, object, or method from artifact content.

If the RPC call throws or returns an unexpected result after dispatch, the result is `unconfirmed`: **inspect authoritative state before any retry; the mutation may have committed**. The submitter never retries or creates another command. A definite `refused` is distinct from this case. An identical fresh command can report `already-initialized` or `already-rotated`; a conflicting one is refused by the authority.

## Local proof and remaining gates

**PROVEN LOCALLY:** the focused parser, validator, preflight, and ambiguity tests; the earlier Production DO RPC integration; and a separate official Miniflare/workerd multi-Worker regression that invokes the actual `OperatorLifecycleExecutor` over a configured service binding. That executor invokes the actual `AdmissionServiceWorker` binding, which resolves the fixed-name `ProductionAdmissionAuthority` DO and persists SQLite. The new regression verifies initialization, rotation, idempotency, conflicts, state/history preservation, executor HTTP 404 closure, and restart. A test-only service-binding proxy drops one acknowledgement after a real DO commit: the executor returns `unconfirmed`, exactly one dispatch occurred, authoritative SQLite contains the mutation, and a controlled identical later submission returns `already-initialized`. Test-only HTTP drivers and the older local harness are absent from Production deployment templates.

**REQUIRES CLOUDFLARE PROVISIONING:** render and review the exact service binding, executor Worker, offline-key public-key match, private operator job, and provider access boundary. Do not expose a lifecycle route on the admission service or executor. Existing admission deployment and secret contracts remain in force.

**REQUIRES OPERATOR AUTHORIZATION:** offline preparation of a fresh signed artifact, controlled handoff to the private job, explicit Production confirmation, and separate authorization for any real mutation.

**REQUIRES LIVE SMOKE:** verify the provider's actual service-binding path, lifecycle acknowledgement and timeout behavior, authority sentinel and release state, historical state continuity, no public lifecycle exposure, and the later I2 smoke gates. Local workerd does not prove account identity, provider access policy, or deployed routing.

**UNRESOLVED PROVIDER INVOCATION ARCHITECTURE:** local operator CLI → **missing reviewed provider-authenticated trigger/input/result channel** → provider-side `OperatorLifecycleExecutor` → `AdmissionServiceWorker` → `ProductionAdmissionAuthority`. This correction does not select or implement that channel. It must never be replaced with a public bearer lifecycle endpoint, arbitrary RPC endpoint, generic admin API, or signing-key upload. **I3 control-plane provisioning MUST NOT begin** until the invocation architecture is selected, implemented and reviewed as necessary, and its ambiguous-result reconciliation procedure is defined.

**ENVIRONMENT QUALIFICATION:** the shared initialization protocol can validate correctly signed staging commands, but the I3A Production executor accepts and submits Production lifecycle artifacts only. The local regression rejects a signed staging artifact at that executor. Operator keys and resources must be separated by environment before provisioning unless a later reviewed design deliberately proves safe sharing. No staging command may target the Production executor.

Public persistence remains closed by the existing Production gates. This tooling performs no inquiry PRE/POST, database access, provider mutation, deployment, or persistence enablement.
