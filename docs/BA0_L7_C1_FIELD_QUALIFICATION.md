# BA0-L7-C1 external field qualification

Status: **valid for the reviewed qualification scope below.** This report records the completed external field qualification; it does not change the
qualification tag, implementation, thresholds, or historical evidence.

## Qualification record

| Field | Recorded result |
| --- | --- |
| Campaign | `gcp-field-002` |
| Level | `ba0-l7-c1` |
| Repository commit | [`2f25e4d1c0fd5b22c5f8bcbbee76f530fb6792f9`](https://github.com/emircanunlutas/limitmark/commit/2f25e4d1c0fd5b22c5f8bcbbee76f530fb6792f9) |
| Git tag | [`ba0-l7-c1-valid-20261029`](https://github.com/emircanunlutas/limitmark/releases/tag/ba0-l7-c1-valid-20261029) |
| Final verdict | `EXTERNAL-L7-QUALIFICATION-VALID` |
| Reconciliation | 15/15 checks passed |

## Test topology

The qualification used an isolated Google Cloud field setup with a disposable Linux system under test (SUT) and a separate, authorized generator
host. The reviewed field runner executes on the SUT and does not drive a second remote target. The generator was bounded to the authorized test
path; no production traffic, credentials, or provider configuration is recorded here.

The topology and evidence boundary follow the repository's BA0 field-run documentation in
[`defense/README.md`](../defense/README.md), including its separation of the field runner, closed-loop generator, and reconciliation step.

## Bounded C1 workload

`ba0-l7-c1` is the first reviewed external L7 level. Its workload was `ba0-l7-pressure-c1` with:

- one worker;
- a 60-second run;
- a ceiling of 25 requests per second and 1,500 total requests;
- a 5-second request timeout and 1 MiB maximum response size; and
- the reviewed round-robin fixture cycle: `GET /`, `GET /gizlilik`, `GET /test-talep-et`, and `POST /api/public-inquiries`.

These are reviewed qualification bounds, not production defaults or a general capacity claim. The parameter definitions and their provisional,
uncalibrated status are maintained in [`lab/defense/field-thresholds.ts`](../lab/defense/field-thresholds.ts).

## Evidence identifiers

The qualification record identifies the evidence artifacts as follows:

| Evidence | Identifier |
| --- | --- |
| SUT evidence | `20261029T225041Z-ba0-l7-c1-ee077d` |
| Client evidence | `20261029T225128Z-ba0-l7-pressure-c1-6d4d58` |
| Reconciliation evidence | `20261029T230140Z-reconcile-8b55d8` |

The evidence files themselves are not claimed to be present in this repository. This report records the supplied identifiers only.

## Scope and limitations

The verdict applies only to the named commit, tag, campaign, level, workload, reviewed parameters, isolated topology, and reconciled evidence
identified above. It does not establish production readiness, general DDoS resistance, behavior at higher qualification levels, multi-source traffic
coverage, per-user fairness, or resilience outside the tested application-plane boundary.

The C1 parameter set is explicitly provisional and uncalibrated. A valid C1 result does not automatically qualify a later level or transfer its
thresholds to production. Historical limitations and non-claims in [`defense/README.md`](../defense/README.md) remain in force.

## Next planned level

`ba0-l7-c2` is the next planned qualification level. It has **not** been executed and is not included in this verdict.

## Repository impact

This is a documentation-only record. No application code, tests, generator workloads, thresholds, security policies, configuration, qualification tag,
or qualified commit was modified.
