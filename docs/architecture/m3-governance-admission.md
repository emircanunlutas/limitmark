# LimitMark M3 governance admission proposal

**PENDING OWNER APPROVAL**

The proposed admission is for the exact local M3 origin-execution-fencing checkpoint over `58bfe18aa8d5b34d08cb819cdc572a92349a819d`. The owner decision covers the five reviewed source identities, the named lab and test implementation, and the checkpoint documents and verifier. The proposal leaves the historical verdicts and existing authorizations intact. It carries no production, deployment, external testing, or Gate 11A authorization.

## Dependency changes proposed for admission

Paths in this table identify exact repository module edges. The checkpoint manifest pins the candidate files that introduce them.

| Importer or entry | Candidate dependency change |
| --- | --- |
| `defense/boundary/boundary.ts` | Adds runtime imports of `createOriginCapacityBoundary` from `defense/core/capacity-boundary.ts` and `createBoundaryExecution`, `EXECUTION_HEADER`, and `TERMINAL_HEADER` from `defense/origin/execution-fence.ts`. Adds a type-only import of `CapacityExecutionEvidence`, `CapacitySnapshot`, `CompiledCustomerOriginPolicy`, and `HttpScheme` from `defense/core/capacity-port.ts`. Extends the existing `hop-admission.ts` import with the type `Admitted`. |
| Historical Boundary entry points `defense/boundary/main.ts` and `defense/boundary/main-field.ts` | Their existing import of `boundary.ts` now reaches `capacity-boundary.ts`, which already imports `capacity-policy.ts` and `origin-capacity.ts`. `origin-capacity.ts` already imports `capacity-heap.ts` and `capacity-policy.ts`. These are runtime edges even when the historical callers omit the optional capacity configuration. `capacity-port.ts` remains type-only. The historical launchers do not provision or activate fencing. |
| `defense/origin/synthetic-origin.ts` | Adds the runtime `TERMINAL_HEADER` and type `ExecutionFence` import from `defense/origin/execution-fence.ts`. Historical `app-main.ts` and `app-main-field.ts`, in-process BA0 runners, and other existing synthetic-origin callers therefore reach the fence module. |
| `defense/origin/execution-fence.ts` | New runtime dependencies are the Node built-ins `node:crypto` and `node:http`. It has no M2 import. |
| `defense/core/capacity-boundary.ts` and `defense/core/origin-capacity.ts` | Existing import graph. The first uses the controller's new `canDispatch` capability. The second retains the proof and caller cutoffs in active leases and checks them before dispatch. |
| `lab/defense/fenced-supervisor.ts` | Adds direct lab runtime edges to `capacity-policy.ts` and `execution-fence.ts`. Forks `fenced-process-main.ts`. Bootstrap, protocol, lifetime, capacity-port and hop-trust imports are type-only. |
| `lab/defense/fenced-process-main.ts` | Adds direct lab runtime edges to `boundary.ts`, `capacity-policy.ts`, `hop-proof.ts`, `app-guard.ts`, `execution-fence.ts`, `synthetic-origin.ts`, and `fenced-lifetime.ts`. Boundary protocol, App protocol, and capacity-port imports are type-only. |
| `lab/defense/fenced-witness.ts`, `fenced-witness-main.ts`, and `fenced-lifetime.ts` | The launcher uses `fenced-lifetime.ts` and forks `fenced-witness-main.ts`. That entry imports `hop-proof.ts`, `fenced-supervisor.ts`, and `fenced-witness.ts`, and reuses its own fork entry for owner sessions. The lifetime helper depends on Node built-ins. |
| `tests/defense-boundary-capacity.test.ts` | Adds test runtime edges to `boundary.ts`, `capacity-policy.ts`, `hop-proof.ts`, `lanes.ts`, `semantic-request.ts`, `a7-shape-gate.ts`, `app-guard.ts`, `execution-fence.ts`, `synthetic-origin.ts`, `front.ts`, `l2-stage.ts`, `semantic-gate.ts`, `hop-keys.ts`, and `tests/fixtures/customer-origin-v1/ba0.json`. `capacity-port.ts` and `ledger.ts` imports are type-only. |
| `tests/defense-fenced-supervisor.test.ts` | Adds test runtime edges to `hop-proof.ts`, `semantic-request.ts`, `execution-fence.ts`, `fenced-supervisor.ts`, `fenced-witness.ts`, `hop-keys.ts`, `fenced-lifetime.ts`, and the same BA0 policy fixture. The `fenced-process-main.ts` import is type-only. The test also forks that entry and `tests/support/fenced-owner-process.ts`, and preloads `tests/support/fenced-reply-failure.cjs` in a child. The owner fixture imports `fenced-supervisor.ts` and `hop-keys.ts`. |

No package manifest, lockfile, legacy entry-point or worker file belongs to the proposed checkpoint. The historical M2 isolation assertions still reject the new reachability. The owner decision must address that reachability explicitly.

## Stage 6 scope

Stage 6 provides witness-hosted owner-session rotation. The surviving witness hosts the supervisor, retains ownership, and verifies the old session and origin exits before rotating the epoch and requiring signed readiness for a fresh origin. Full supervisor recovery is outside this scope. Witness loss also loses the supervisor and its original process handles. The existing local data path can persist while the lifetime channel remains open, and the marker continues to block acquisition when termination evidence is unavailable. See [Local origin execution fencing](origin-execution-fence.md).

## Gate 11A holds

The existing `guard-export` migration holds remain pending for these exact files. Historical pins, baselines, and migration approvals remain unchanged. See [the migration registry](../../tests/support/reviewed-migrations.ts).

- `workers/lifecycle-mailbox/dispatch-guard.ts`
- `workers/lifecycle-mailbox/guard-export.ts`
- `workers/lifecycle-mailbox/guard-reader.ts`
- `workers/lifecycle-mailbox/index.ts`
- `workers/lifecycle-observer.ts`

## Historical governance results

The same 134 checks ran against the M3 working candidate and a detached checkout of the checkpoint base. The base passed **132** and failed **2**. The candidate passed **122** and failed **12**. Ten checks fail only with M3. Two fail in both runs, and one of those stops at a different assertion in the candidate. All 12 candidate failures remain failures.

| Historical check | Only candidate | Both runs | Observed evidence |
| --- | ---: | ---: | --- |
| `defense-origin-capacity-static.test.ts` | 2 | 0 | Historical runtime closure reaches `capacity-boundary.ts` and then fails its bounded-loader check on `process`. The direct importer guard rejects the Boundary import of `capacity-boundary.ts`. |
| `defense-slice3-static.test.ts` | 1 | 0 | Slice-1/2 pinned Boundary SHA-256 differs. |
| `lab-ba0-canary-continuity.test.ts` | 0 | 1 | The historical qualification diff fails on Gate 11A worker changes in both runs. That assertion precedes the reviewed-patch and migration checks. |
| `lab-ba0-salvo-diagnostics.test.ts` | 0 | 1 | The base fails on the historical Gate 11A worker diff. Candidate stops earlier at the P0-02 Boundary hash mismatch. |
| `lab-ba0-salvo.test.ts` | 1 | 0 | Historical C1/C2 immutability check rejects the P0-02 Boundary hash mismatch. |
| `m1-historical-pins.test.ts` | 1 | 0 | Closed verdict-path set rejects the added `defense/origin/execution-fence.ts`. |
| `reviewed-migrations.test.ts` | 3 | 0 | Registry current-file identity, baseline drift, and closure-evidence checks reject post-review M2 capacity changes. |
| `reviewed-patches.test.ts` | 2 | 0 | Historical reviewed-patch checks reject the changed P0-02 Boundary identity. |

Reproduce the comparison with Node 22 and installed repository dependencies. Run the following from the candidate root and again from a detached checkout of the manifest's base commit. Create the ignored `artifacts/lab` directory in both checkouts for test fixtures.

```powershell
New-Item -ItemType Directory -Path artifacts/lab -Force | Out-Null
node --import tsx --conditions=react-server --test `
  tests/m1-historical-pins.test.ts tests/reviewed-patches.test.ts `
  tests/reviewed-migrations.test.ts tests/defense-origin-capacity-static.test.ts `
  tests/defense-field-static.test.ts tests/defense-slice3-static.test.ts `
  tests/lab-ba0-salvo.test.ts tests/lab-ba0-salvo-diagnostics.test.ts `
  tests/lab-ba0-canary-continuity.test.ts
```

## Checkpoint verification and authorization

The exact authorization scope is every path in [m3-checkpoint.json](m3-checkpoint.json), plus `docs/architecture/m3-checkpoint.json` itself. `M` denotes a modified base file and `A` denotes an addition. Existing dependencies are anchored to the base commit. Root-level review drafts, local tool settings and Gate 11A files are outside the checkpoint. Hashes are SHA-256 over UTF-8 bytes with CRLF converted to LF. Only the manifest's own digest is supplied separately, so the manifest can be pinned without a recursive hash.

The Windows remediation run passed all 14 real-process tests, the relevant runtime and contract tests, TypeScript, repository-wide ESLint, and whitespace checks. Preparation verified the five protected LF-normalized identities, all 18 checkpoint paths, and the candidate diff's whitespace. The verifier confirmed the index was empty and rejected index mode on the unstaged candidate. The separate verifier has no effect on the historical checks.

Before approval, run `node scripts/verify-m3-checkpoint.mjs --worktree`. It checks the current base, all manifest hashes, listed additions, tracked changes, and that the index is empty. Record the printed manifest digest in the owner decision.

After the owner authorizes staging, stage only the authorized path list. Before using the verifier, confirm its bytes against the verifier hash in the approved manifest. Run `node scripts/verify-m3-checkpoint.mjs --index <owner-reviewed-manifest-sha256>` against the same base. It checks the index manifest against that digest and verifies the index bytes, paths, change types, and regular-file modes. Use `git diff --cached --check` for staged whitespace. Index verification is pending staging authorization.

The owner decision on the exact checkpoint and the historical M2 reachability is still required. Historical check failures remain open under their own criteria. Gate 11A holds require a separate owner decision.
