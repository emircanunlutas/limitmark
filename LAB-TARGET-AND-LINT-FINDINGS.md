# Parity blockers: expired lab target authorization, and the 18 lint errors — investigation only (2026-11-08)

Nothing here changes an expiry, a signature, a rule or a lint configuration. Proposals are proposals.

## A. The "expired target" that blocks the parity HTTP workloads

### What is refused, exactly
`lab/linux/parity.ts` runs `lab/run.ts --target local-app-alt` (and `--target local-app` for k6). Both are **built-in `lab-local` loopback fixtures** (`BUILTIN_TARGETS`, `lab/policy/target-policy.ts`): host `127.0.0.1`, ports 3100 and 3000, GET/POST on the reviewed path catalogue, **no expiry** (`expiresAt` is forbidden on `lab-local`). They are not what expired.

`lab/run.ts:151` builds the registry as `buildRegistry(loadOperatorTargets(), now)`. `loadOperatorTargets()` reads the operator file `artifacts/lab/targets.json` (gitignored, local, created 2026-10-04 15:51 +03:00). `buildRegistry` validates every operator entry and, by design ("a single invalid entry fails the whole load"), throws on the first invalid one. The file holds one entry:

| field | value |
|---|---|
| id | `gcp-sut-1` |
| class | `lab-remote` (expiring, disposable IPv4-literal target) |
| scheme / port | http / 3000, GET and POST, 4 catalogue paths |
| host | an IPv4 literal (a former Google Cloud lab VM address; not reproduced here) |
| `disposable` | true |
| `expiresAt` | `2026-10-04T20:49:36Z` (already past) |

### The expiry rule (code)
`validateTargetDefinition`: a `lab-remote` target must carry `disposable: true` and an ISO-8601 UTC `expiresAt`; `expiresAt <= now` -> `target-expired` ("target definition has expired"); `expiresAt` more than `MAX_REMOTE_TARGET_LIFETIME_HOURS = 72` ahead of load time -> `target-definition-invalid`. At run time the whole run is also bound to that instant (`authorizedUntilMs`; `target-expired` again if it lapses mid-run, and k6 refuses a run that cannot finish before it).

### Authorization mechanism
Loopback targets are the built-in fixtures only; the operator file may define `lab-remote` targets only (`loadOperatorTargets` refuses anything else). The operator file is the owner's local statement "this IPv4 literal is a disposable lab system until time T". Nothing signs it; the control is the owner-held, gitignored file plus the expiry and 72-hour cap.

### Verified facts (read-only checks run for this report)
- `buildRegistry([], now)` yields exactly `local-app`, `local-app-alt`: **the built-ins load fine on their own.**
- `buildRegistry(loadOperatorTargets(), now)` throws `target-expired`: **the stale operator entry alone blocks the load**, hence all four parity workloads were refused before any network activity.
- `run.ts` has no environment or flag override for the operator file path.

### Would renewal affect an external target?
Yes. Renewing `gcp-sut-1` (a new `expiresAt`) would re-authorize generating traffic to that remote IPv4 literal. That address belonged to a lab VM that was disposable and, as far as this repository shows, torn down; whether it is reachable or now belongs to someone else is unknown. **Renewal is not proposed and was not done.**

### Already-authorized local-only alternative
The parity workloads need only the built-in loopback fixtures, which carry no expiry. They would run today if the stale `gcp-sut-1` entry were not in the file the loader reads.

### Minimal proposals (owner choice; none applied)
1. **Owner action, no code:** move the stale file aside, e.g. rename `artifacts/lab/targets.json` to `artifacts/lab/targets.expired-2026-10-04.json` (a gitignored local file; the content is preserved, nothing is renewed, nothing is authorized). The parity HTTP workloads would then target loopback only.
2. **Code (not recommended):** make the loader skip expired entries. That weakens a deliberate fail-closed rule in a policy file; it would be a security-boundary change needing separate approval and tests.
3. If a remote lab target is ever wanted again: a new, explicitly scoped entry with a fresh id, an expiry no more than 72 h out, created by the owner at the time of use. Not requested.

## B. The 18 `no-explicit-any` errors (and 18 warnings): classification
`npm run lint` is `eslint . --max-warnings=0`, so warnings also fail it. Measured on the Windows host and in the Linux container: **18 errors and 18 warnings in both** — the same set, so **not an environment difference**. They are in 11 files, **all test files, all created on this branch (none exists on `master`)**:

| file | errors | warnings | introduced |
|---|---|---|---|
| `tests/lab-environment-isolation.test.ts` | 13 (`any`) | 0 | `38fec4d` (2026-11-07) |
| `tests/guard-export-account-pin.test.ts` | 2 (`any`) | 0 | `ba65541` (2026-11-08) |
| `tests/production-identity-contract.test.ts` | 2 (`any`) | 0 | `655d58a` (2026-11-08) |
| `tests/guard-ledger-export.test.ts` | 1 (`any`) | 4 (unused) | `2c7fe2d` (2026-11-08) |
| `tests/guard-export-method.test.ts` | 0 | 4 (unused) | this branch |
| `tests/workers/guard-export.integration.ts` | 0 | 4 (unused) | this branch |
| `tests/support/recovery-evidence.ts` | 0 | 2 (unused) | this branch |
| `tests/defense-plane-instrumentation.test.ts` | 0 | 1 (unused) | earlier session (instrumentation tests) |
| `tests/lab-hostname-gate.test.ts` | 0 | 1 (unused) | this branch |
| `tests/workers/support/guard-export-driver.ts`, `guard-export-stub.ts` | 0 | 1 each (`import/no-anonymous-default-export`) | this branch |

Classification: **pre-existing relative to this session's work** (introduced by earlier sessions on this branch), **not newly exposed** by anything done here (a lint run on the three new test files and the new tooling of this session is clean), **not caused by the environment**. They were simply never gated: no earlier report listed the lint step as run.

### Minimal correction proposal (separate; not started)
- `any` (18): replace each with `unknown` plus a narrowing cast at the use, or the concrete type the code already uses at that call; no rule disabled. `lab-environment-isolation.test.ts` accounts for 13 and probably shares one helper signature.
- unused names (14 warnings): delete the unused imports/bindings or prefix intentional ones with `_`.
- anonymous default exports (2): assign to a named constant before `export default`.
Test-only edits; expected to touch 11 test files and no production or lab source. Each change must keep the tests' assertions identical.
