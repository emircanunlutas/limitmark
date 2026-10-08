# lab/ — local-only field-lab tooling

Purpose: prepare the repository for real external field testing (a disposable Linux system under
test, later driven from authorised load generators) **without** provisioning or contacting any
provider. Nothing here deploys, mutates remote state, or needs a real credential.

## Trust boundary

| Zone | Contents | May import `lab/`? |
| --- | --- | --- |
| Application runtime | `src/`, `workers/`, `operator/`, `deployment/`, `scripts/`, `next.config.ts` | **No — never imported** |
| Lab tooling | `lab/` | — (imports `src/` repositories and `tests/support/` guards read-only) |
| Tests | `tests/` (`tests/lab-*.test.ts`) | Yes |

Enforced three ways: ESLint `no-restricted-imports` on the runtime globs, `tests/lab-isolation.test.ts`
(scans every runtime file for lab imports and identifiers, pins the production dependency set, forbids
non-`lab:*` npm scripts from running lab code) and the fact that `lab/` is not reachable through the
`@/*` alias. Lab output lives only in `artifacts/lab/` (gitignored).

Not production: nothing in `lab/` is part of a build, deployment or runtime path. Operators run it by
hand, and every tool here must fail closed.

## What a lab run may touch

* **Targets** are chosen by ID from an allowlist (`lab/policy/target-policy.ts`): built-in loopback
  fixtures (`local-app` 127.0.0.1:3000, `local-app-alt` 127.0.0.1:3100) plus `lab-remote` operator definitions in
  the gitignored `artifacts/lab/targets.json`. The CLI never accepts a URL, host, port, path, method
  or header. Remote targets must be IPv4 literals with `disposable: true`, an `expiresAt` at most 72 h
  ahead and an explicit scheme and port. Live LimitMark hosts, Cloudflare/Vercel/Google/Resend
  infrastructure, `admission-rpc`, cron and admin paths are refused before any network activity.
* **Workloads** are a reviewed catalogue with finite ceilings (`lab/policy/workloads.ts`); the CLI can
  only lower them.
* **Failure injection and namespace donors** act only on a process the lab started, or on a container whose
  daemon-recorded LABELS say the lab created it (`limitmark.lab=disposable` plus the expected `limitmark.lab.role`); a name prefix
  alone is never ownership.
* **The Docker daemon** is chosen by the lab, not by the environment: `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_TLS_VERIFY` and
  `DOCKER_CERT_PATH` make the wrapper refuse; the CLI's active context must point at a local socket or named pipe from a short allowlist.
  EVERY Docker process the lab starts (wrapper, evidence version probe, parity build/run steps) goes through one confinement
  (`confinedDockerInvocation`), which binds it to the verified ENDPOINT (`--host`, also pinned in `DOCKER_HOST` for compose/buildx; builds name the local `default`
  builder; `BUILDX_*`/`BUILDKIT_*`/`COMPOSE_*` and proxy variables are not inherited), never to a context name that could be switched afterwards. (A unix socket forwarded to a remote daemon cannot be distinguished from a local one: operator assumption.)
* **A local port is not a destination.** A connection to 127.0.0.1:3000/3100 proves nothing about WHAT answers (an ssh/socat
  forwarder would silently redirect authorized traffic). Local HTTP runs therefore need `--manage-app` (a process the lab started and
  keeps alive), `--app-container <name>` (a lab-labelled app container that publishes exactly 127.0.0.1:<port>, re-checked before every
  phase) or, for k6, `--k6-netns-container <name>`. Without one the run is REFUSED (`target-listener-unproven`).
  For `--app-container` ownership is a **lease** held for the whole run: re-verified before the first request and every 250 ms (same container id, running, publishing exactly
  127.0.0.1:<port>); a request is dispatched only while the last successful check is younger than 750 ms, and a failed or hung check stops the run and cancels in-flight requests.
  This bounds traffic to a replacement listener to roughly one staleness window; it is not a proof of TCP peer identity, which plain TCP cannot give.
* **Remote targets are operator assertions.** `disposable: true` plus an expiry is what the operator states; the lab cannot prove ownership of
  an arbitrary IP. The evidence records `ownership: operator-asserted` (other values: `lab-process`, `lab-container-port`, `lab-container-netns`, `unproven`). Authorization is re-checked for the whole run:
  before every request, and a k6 container is killed when the target definition expires (a run that could not finish inside the window is refused).
* **Databases** are only disposable Docker PostgreSQL 16/17 on 127.0.0.1 with a proof marker.

## Commands

```text
npm run lab:test                                  # focused lab tests (also part of `npm test`)
npm run lab:db:test -- 16|17|both                 # the 34 TEST_DATABASE_URL-gated tests against a fresh lab DB
npm run lab:db:guard-selftest -- 16               # hostile TEST_DATABASE_URL configurations against a real DB
npm run lab:concurrency -- 16                     # idempotency / outbox concurrency harness
npm run lab:db:up -- 16   /   npm run lab:db:down -- 16   # manual lifecycle (random credentials, 0600 state file)
npm run build && npm run lab:run -- --target local-app --workload latency-measurement --manage-app
npm run lab:run -- --workload postgres-outage --pg 16 [--outage-mode stop|pause]
npm run lab:run -- --target local-app --workload app-restart
npm run lab:parity                                # Linux container parity checks (add -- --skip-build to reuse an image that matches the tree)
npm run lab:k6:selftest                           # real-k6 envelope probes and the mid-phase destination-replacement reproduction against a fixture container
npm run lab:cancel:selftest -- 16|17 [pause|stop] # a paused/stopped PostgreSQL: timed-out transactional work must not commit after recovery
```

`lab:run` flags: `--target`, `--workload`, `--thresholds`, `--max-rate`, `--max-concurrency`,
`--max-duration` (lower-only; plain decimal integers; an above-ceiling value is refused, not clamped),
`--manage-app` (lab-local only), `--app-container` (node engine, lab-local), `--dry-run`, `--engine node|k6`,
`--k6-netns-container`, `--pg`, `--outage-mode`. Anything else is refused. Exit codes: 0 PASS, 1 FAIL, 2 REFUSED, 3 STOP, 4 ERROR.

## Workloads and exact ceilings

| Workload | Shape | Rate | Concurrency | Duration | Max requests |
| --- | --- | --- | --- | --- | --- |
| `connectivity-baseline` | 1 phase | 2/s | 1 | 30 s | 60 |
| `latency-measurement` | 1 phase | 5/s | 2 | 60 s | 300 |
| `controlled-concurrency` | steps 1,2,4,8,16 × 20 s | 40/s | 16 | 100 s | 4 000 |
| `burst` | 5 s @5/s, 10 s @100/s, 15 s @5/s | 100/s | 50 | 30 s | 1 200 |
| `sustained-soak` | 1 phase | 20/s | 20 | 900 s | 18 000 |
| `timeout-behaviour` | client timeouts 1/2/5/10/50 ms + health probe | 2/s | 1 | 55 s | 110 |
| `demo-submission-post` | synthetic demo POST (lab targets only) | 5/s | 4 | 30 s | 150 |
| `app-restart` (local only) | steady, kill, restart, steady | 4/s | 1 | 80 s | 340 |
| `postgres-outage` (local only) | healthy, stop or pause, start, healthy | 2/s | 1 | 85 s | 170 |

Hard ceilings above every workload: 100 req/s, 50 connections, 900 s, 20 000 requests, 10 s request
timeout, 1 MiB response read, 3 warm-up requests. A reduced duration clips a single-phase workload;
multi-phase workloads run whole (lower the rate or concurrency instead).

### What the ceilings bound: ONE process

Every ceiling is **per lab process**, not per campaign or fleet. Two valid `lab:run` processes (or a runner on each of two load
generators) may together reach 200 req/s and 100 connections; nothing here counts across processes or machines. A campaign needs an
explicit budget (sum the per-process ceilings of every concurrently running generator, and keep that sum under what the system under
test may receive); evidence manifests state `ceilings.scope: "per-process; not campaign- or fleet-wide"`.

Within one process the ceilings are **upper bounds**, enforced where requests are emitted:

* *Node engine*: per-phase rate (token bucket), per-phase request cap of rate × duration, per-phase in-flight cap (excess is dropped and
  counted, never queued), global request cap, a dispatch deadline of the duration ceiling plus a 2 s set-up allowance (nothing is sent after it; requests still in flight
  2 s later are cancelled; what is emitted is bounded independently and strictly by the per-phase and total caps), per-request timeout, a response cap that cancels at 1 MiB, authorization checked before every request. Warm-up GETs
  (at most 3) are separately accounted; reviewed totals plus warm-up are pinned to stay under the hard total.
* *k6 engine*: the script and the Node wrapper validate the plan with one shared module (`lab/load/k6/plan.mjs`), re-deriving every ceiling
  from the phases (a self-hashed plan scheduling 90 000 requests is refused when the hard total is 20 000). Phases run strictly one after
  another, each followed by a graceful stop long enough for its own requests to finish, so concurrency is the largest phase, never a sum
  (the wall clock is therefore the dispatch window plus those graces, and is recorded). Every phase has an iteration cap of rate × seconds, so
  the total is an upper bound (the old script emitted 3 requests for 1 s at 2 req/s). The process aborts itself past its wall clock, and the
  wrapper kills the container at the wall-clock bound or when the target authorization lapses, then verifies it is removed.
* *Response size in k6 is detect-and-abort, not a hard read cap.* k6 cannot truncate a body mid-transfer: the first response larger than
  1 MiB is read in full (bounded by the 512 MiB container limit and the request timeout) and then aborts the whole run (STOP). The old script
  read every oversized response. Use the Node engine when a per-read cap matters.
* *k6 container*: created, then its configuration is read back from the daemon and checked (labels, network namespace of the verified
  donor, and no proxy variable, whether passed explicitly or injected by the docker CLI's `proxies` config) before it is started.
  `npm run lab:k6:selftest` exercises all of this against real k6 and a fixture container, and replays the previous script to show each problem was real.

PASS/STOP thresholds are named sets (`local-loopback-v1`, `field-remote-v1`; a remote target must name
one). STOP aborts a run immediately; PASS is evaluated at the end; the set id, version and content hash
are recorded in the manifest. The numbers are initial and need calibration against the first baselines.

## Evidence

`artifacts/lab/evidence/<runId>/manifest.json` + artifacts + `SHA256SUMS`. It records git SHA and dirty
state, OS/kernel, Node, Docker and PostgreSQL versions, the target ID (never an address), workload
phases, ceilings, the threshold fingerprint, timestamps, the result and aggregate metrics. The writer
**refuses** credentials, authorization headers, cookies (any name), IPv4 and IPv6 addresses (also next to a timestamp), URLs and query
strings, e-mail addresses, stack traces and filesystem paths, request bodies and user data, in values **and in object keys**
(`lab/evidence/redact.ts`). Free text that must be kept is transformed first: errors go through `evidenceSafeError` (class, code and a
message only if the message is itself safe) and raw child-process or container output goes through `sanitizeLog` (offending lines are
replaced by a marker, home directories rewritten; stack-shaped lines are scanned like any other, and the exact bytes about to be written are re-verified by `verifyLogText` before the file is created); nothing raw is persisted. `.gitignore` is not the confidentiality boundary: the parity
image's build context excludes every credential pattern in `lab/linux/Dockerfile.dockerignore` (pinned by tests to be a superset of
`.gitignore`). The per-run state files under `artifacts/lab/pg/` hold generated passwords by design (mode 0600, removed at teardown).

## k6

`lab/load/k6/lab-load.js` runs only an integrity-hashed plan produced from an *authorized* run and
re-validates it with independent rules (`lab/load/k6/plan.mjs`: IP-literal base URL, fixed path catalogue, GET or the one demo
POST, hard ceilings, total request cap derived from the phases; the plan's own hash only proves it was not altered). It runs in Docker (`grafana/k6`); to reach a lab container it joins that
container's network namespace (`--k6-netns-container limitmark-lab-app`). For the host's own app use the
Node engine: k6 in Docker Desktop cannot reach the host loopback.

## PostgreSQL lab and the TEST_DATABASE_URL guard

See `lab/postgres/` and `tests/support/test-database-guard.ts`. A destructive DB test refuses unless the
URL is loopback + `limitmark_lab_*` database + `lab_*` role, `TEST_DATABASE_PROOF` is set, and the database
holds a marker (written by the lab, never by tests) bound to that database and cluster, in a cluster
containing no other non-template database.

**The connection that executes destructive SQL is the connection that was proven.** The URL is parsed once, under a strict canonical
grammar with no ambiguous delimiter (a raw `@` or `,` in userinfo, escapes, other IPv6 spellings and short IPv4 forms are refused: WHATWG URL
and postgres.js read `u:a@h1:P1,b@h2:P2/db` as different hosts). No other component sees the string: `testDatabase.connect()` builds the postgres.js
client from the parsed fields, and every TRUNCATE, trigger/schema DDL and DROP in the suites runs through `testDatabase.destructive(client, ...)`, which
re-reads and re-judges the proof inside the transaction, on the same connection, immediately before the statement. Nothing is memoized: when the cluster
stops being dedicated the next destructive step refuses. A client the guard did not create is refused. **Migrations are inside the proving transaction too**
(`testDatabase.migrate(client, "drizzle")`: schema/table bookkeeping, migration SQL and history rows all run on the connection that read the proof, in one transaction, and the backend
session is asserted unchanged), so a pool that reconnects to a replaced server cannot move migration SQL onto an unproven connection. Residual: a pool still opens several connections to the same fixed loopback endpoint.
`npm run lab:db:guard-selftest -- 16` runs the hostile cases (including the reproduced wrong-endpoint URL, against a second cluster holding an unproven canary).

## Known library defect (not fixed here)

postgres.js 3.4.9 throws an uncaught `TypeError: Cannot read properties of null (reading 'write')` from a `setImmediate` callback after a backend
was terminated during an in-flight transaction (the transaction promise has already rejected). It is a library defect that also affects the application's
`begin()` paths and is **not** worked around here (a separate reviewed task). The lab counts every occurrence and any run that observes it ends **FAIL**, never PASS.

## Failure lifetime

* A PostgreSQL probe that times out has its pool destroyed (so the server rolls the transaction back) and replaced, the abandoned operation must settle
  before the next probe, server-side `statement_timeout`/`idle_in_transaction_session_timeout` bound what remains, and after the run no runtime backend may
  still be active or in a transaction (verified, recorded as `orphanedBackends`).
* k6 supervision: a stop requested while the container is still starting is deferred until the start returns; kills are retried, then forced, and the container's state is READ BACK:
  a stop is reported only when the daemon confirms it (otherwise the run is ERROR, never "stopped by expiry"). A k6 summary missing any required numeric metric is ERROR, not zero-valued success.
* Teardown (`sut-teardown.sh`, `labDbDown`): an unreachable Docker daemon or a failing listing is UNKNOWN, never "no containers": it is a failure, recovery state (marker, state files) is kept and the teardown is reported incomplete.
* The lab-started app tree is killed on normal exit, SIGINT, SIGTERM and SIGHUP (the detached POSIX group included); start-up and readiness are inside the restart workload's cleanup scope.
* `lab:db:down 16` removes only the pg16 container (after its labels prove ownership) and its state file; `compose down` is never used, so the pg17 lab and its state file are untouched.
* Parity removes a pre-existing `limitmark-lab-app` only after its labels prove the lab created it, kills and verifies removal of step containers on timeout, and sanitizes its logs.

## Linux parity provenance

The parity image is labelled with the commit and a digest of the working tree it was built from; `--skip-build` reuses an image only if both match the tree being
reported (otherwise it refuses). A step passes only on positive evidence (a complete test summary, exactly 34 DB tests with no skips, exactly the 34 DB-gated tests
skipped in `npm test`, no known-defect trace). The result is **container parity only**: it does not prove VM, kernel, network or field parity, and the Node HTTP load
drivers run on the host (recorded as `httpDriverRuntime`).

## Google VM bootstrap

`lab/bootstrap/` is reviewable, idempotent and provider-free, and has **not** been run. See
`lab/bootstrap/README.md`.

## BA0 field level (first external L7 qualification, N = 1)

`lab/load/closed-loop.ts` is a SEPARATE closed-loop engine (the open-loop engine above is untouched): N workers, each sending its next request only after the previous one settled, at most N logical requests in flight,
no automatic retries, no pipelining, exact `inFlight` / `maxInFlightObserved`, connection reuse counted separately, and the first transport failure stops an N = 1 generator. A response status is an HTTP observation,
never a failure and never proof of what the server did. The reviewed workload `ba0-l7-pressure-c1` is remote-only and takes no limit override (its verdict is scoped to the exact reviewed level).
It writes `generator-report.json` (evidence about the generator only; nothing in it feeds any enforcement decision). The server side is `npm run lab:ba0:field` on the disposable Linux host, and the final verdict
comes only from `npm run lab:ba0:field:reconcile`. See `defense/README.md` (BA0 field qualification readiness) for the claim vocabulary and the continuous exposure proof, and `lab/bootstrap/README.md` for `--ba0-field`.

### Reviewed BA0 N=2 progression

The user-reported two-host N=1 qualification at `c250fd440018641f67120a36786975b857341555` concluded `EXTERNAL-L7-QUALIFICATION-VALID`;
master `f6a7ab6399984849ef39fcdb9b28c3247a0f0e23` retains its exact parameter/workload definitions. N=2 is a separate reviewed code entry.
This progression changes no defense decision, lane capacity, credit behavior, Boundary/App admission, canary acceptance threshold, or evidence capacity.
One invocation still runs one level. These commands document a future separately authorized campaign; adding the level does not authorize running it.

| Parameter | N=1 | N=2 |
| --- | --- | --- |
| Level | `ba0-l7-c1` | `ba0-l7-c2` |
| Workload | `ba0-l7-pressure-c1` | `ba0-l7-pressure-c2` |
| Parameter set / version | `ba0-field-v1` / 1 | `ba0-field-c2-v1` / 1 |
| Planned workers / logical in-flight ceiling | 1 | 2 |
| Aggregate pacing ceiling | 25 req/s | 25 req/s |
| Duration / total request ceiling | 60 s / 1,500 | 60 s / 1,500 |
| Request timeout / response byte ceiling | 5,000 ms / 1,048,576 | 5,000 ms / 1,048,576 |
| Request cycle | GET home, privacy, form; POST inquiry | identical |
| Retries / pipelining | 0 / false | 0 / false |
| Recovery quiet period | 135,000 ms | 135,000 ms |
| JCR minimum, every required group | 100% | 100% |
| Generator schedule lag p99 / ELD p99 ceilings | 50 ms / 100 ms | 50 ms / 100 ms |

Canonical SHA-256 fingerprints, pinned in tests:

| Level | Parameters | Workload |
| --- | --- | --- |
| N=1 | `5f7fbb865fcc8f44219a01af4cb02a48113a20fb75436a7f42f5ddd772b3e625` | `a91b1014db56a16b808703b3616a73ab2b8f19492e61de81727737a33a2f5cec` |
| N=2 remediated | `cf56f4e3272c9a4cd8257deacf153eaaf154501ceb3749e31179d756134917ab` | `0fa05c0ca19bfa898d7784e75d4ae1d403fe7d5ea1324be2ddc9f7d724182239` |

The read-only implementation survey found the accidental single-level restrictions in `field-thresholds.ts` (literal level/worker types and N=1 gate),
`ba0-field-run.ts` (registry and hardcoded workload hash), `lab/run.ts` (hardcoded generator set), `ba0-field-reconcile.ts` (hardcoded limits and manifest fingerprint),
`policy/workloads.ts` (catalogue/type), and `policy/thresholds.ts` (exclusion from open-loop thresholds). The exact `BA0_FIELD_V1` object, c1 workload,
default fingerprint, N=1 selftest, and existing N=1 fixtures in field thresholds/workload/run/evidence/preflight, closed-loop, reducer/accounting/reconcile,
and telemetry tests intentionally describe N=1 and remain valid. Only `lab-workloads.test.ts` and `lab-ba0-field-run.test.ts` asserted a one-entry catalogue.
The historical field sections in both READMEs describe N=1; this section records the new progression. No worker/rate/level tuning lives in `defense/`.

The existing closed-loop engine already supports N workers with one shared pacing schedule. Starts reserve aggregate 40 ms slots;
each worker awaits its preceding request's settlement before sending again. Increasing concurrency independently of the offered-rate ceiling is supported.
Overdue sleepers can dispatch together after an event-loop stall; the instantaneous burst is bounded by the two workers.
Holding 25 req/s, duration, request mix and total fixed isolates the concurrency progression. A different or doubled rate would change both factors.
Closed-loop backpressure can change achieved throughput, so report observed latency, achieved rate, generator and server maximum in-flight together.
If responses complete below 40 ms, N=2 may still observe a maximum of one; that result does not demonstrate sustained concurrency-two pressure.
With the reported N=1 maximum latency of 25.85 ms, ordinary pacing is expected to serialize requests. Such an N=2 run is unexercised and INVALID.
No artificial latency or burst synchronization is introduced. Low achieved rate alone is not generator saturation: the pinned schedule-lag and ELD checks decide that.

N=2 qualification now requires direct exposure in **every one-second interval** of the 60-second campaign, independently on generator and server:
at least four starts while another external request is active, and at least 160 ms of residency at exactly two active requests.
Four is the length of the reviewed fixture cycle; 160 ms is four aggregate pacing slots (`4 * 1000 / 25`).
Sixty intervals therefore require at least 240 overlapping starts and 9.6 seconds of dual-request residency, spread across the campaign.
This is a provisional, repeatable exercise criterion derived from the existing cycle, scheduler and telemetry period; it is not a capacity or statistical-power claim,
nor does it require that the four overlapping starts belong to four different fixtures. One incidental jitter overlap, many tiny overlaps,
or exposure concentrated in part of the campaign cannot qualify. Each side stores just two fixed arrays of 60 counters, not a new request history.
Generator bins use its monotonic campaign start; server bins use the first authorized ingress's source timestamp.

Only generator stop `completed` with null detail qualifies, after at least 60,000 ms of monotonic execution and at most 64,000 ms including the existing
2,000 ms setup and 2,000 ms drain allowances. Dispatch must finish before 60,000 ms and every attempt must settle.
`operator_abort`, `authorization_expired`, `transport_failure`, `deadline`, `total_ceiling`, `in_flight_exceeded`, missing measurements and short durations all fail,
even with matching totals. A ceiling stop does not prove duration completion; no completed state may be inferred from counts.

The server requests two observation-only IPC barriers from the Plane: after baseline, immediately before announcing ARMED, and at WINDOW closure after canaries drain.
Each carries the emitting process's monotonic time, wall time, event sequence watermark, cumulative external accepts and current external occupancy.
The source ARMED barrier defines the authorized traffic transition; all preceding external accepts invalidate the campaign and trigger STOP, including events still queued in IPC.
The first ingress must arrive within the existing 20-second start slack. Source closure must be within the existing 90-second ARMED deadline and have zero external requests active.
Every accept and terminal must belong to this phase; post-close ingress and requests crossing closure invalidate qualification.
Generator dispatch/settlement bounds and server first/last ingress/settlement timestamps must agree within the reviewed 2,000 ms clock tolerance,
and their window/duration evidence must agree. This makes timing consequential for N=2; it assumes host clocks within that tolerance and does not measure skew.
The server may write COMPLETE when its own phases finish; only the offline reconcile can qualify both views, including their exposure.
Evidence from pre-remediation N=2 cannot qualify under these rules: its old parameter hash was `e5173d8dcc1c5c04757ae3e479d5d8410a9ee13d1145e3ddb66efed94f5d658d`.

The same unverified budget (capacity 3, refill 1/s) and credited budget (10, 2/s) apply; increased shedding is an observation.
The window mutation bound remains `3 + floor(windowMs / 1000) + 1`, checked with exact bucket replay.
Credit state spans two 60-second epochs, so recovery remains `2 * 60,000 + 15,000 = 135,000 ms`.
Two concurrent requests settle in parallel; the margin still covers the 5,000 ms PB lifetime plus 5,000 ms Plane egress timeout.

All evidence capacities remain unchanged. Preflight evaluates the existing gates plus eight N=2 proofs:

| Budget | Conservative N=2 requirement | Existing capacity |
| --- | --- | --- |
| Canary collector records | 320: (46 protected + 18 control journeys) * 5 steps | 4,000 |
| Per-request events, per stream | Plane 12 / Boundary 7 / App 5 | 32, external and collector |
| Active reducer records | 2 + ceil(25 * (10 s stall + 5 s grace + 1 s sweep)) = 402 | 1,024 |
| Orphan reducer records | 2 + ceil(25 * (10 s stall + 10 s grace + 1 s sweep)) = 527 | 1,024 |
| Decisions including conservative canary allowance | 1,500 + 320 = 1,820 | 20,000 |
| Full external traces, even if every request is selected | 1,500 | 2,000 |
| Recently reduced external nonces | 1,500 | 4,096 |
| Modeled journal including harness and derived origin events | 320 * (24 + 2 + 2) * 512 = 4,587,520 bytes | half of 48 MiB budget |
| Event queue: 10 s hostile arrivals, burst and ALL canary events | (250 + 2 + 320) * 24 = 13,728 | 16,384; window 8,192 <= queue |
| Hop replay: existing rate/lifetime safety factor, all canaries and burst | 25 * 5 * 4 + 320 + 2 = 822 | 4,096 |
| L2 ledger, two epochs of credited admissions | 10 + ceil(2 * 120) + 1 = 251 | 512 |
| Bloom inserts, treating every external request as a render | 1,500 + 46 + 18 = 1,564; 0.1305% fill; FPR bound 6.45e-21 | 2^23 bits, 7 hashes |
| External reducer plus channel modeled accounting | 235.8 MiB | 256 MiB accounting budget |

The state/channel stall bounds assume healthy bounded evidence delivery; they do not promise lossless collection under arbitrary stalls or malformed traffic.
Longer stalls, overflow, unresolved requests, missing events, telemetry gaps and journal loss still invalidate the measurement explicitly.
235.8 MiB is modeled accounting using 512 bytes per retained event, not a runtime heap/RSS maximum or an enforced event-size maximum.
JavaScript object/string overhead and transient allocations are outside that arithmetic; runtime RSS/resource ceilings still apply.
The historical 256-byte journal-line value is also an estimate, despite its legacy `Max` name: a legitimate credited line measured 264 bytes.
N=1 arithmetic and gate output remain unchanged. N=2 models journal lines at 512 bytes, still an estimate, with the enforced 48 MiB journal cap and loss invalidation.
The 90-second window still covers 20-second start slack + 60-second generator + 4-second allowances (84 seconds).
Stop steps still total 40 seconds within the 45-second cap, and the target still needs at least 900 seconds remaining.

The shared registry selects the server by level and generator by workload, independently before either starts. Parameter and workload hashes bind both views.
The v1 generator/server schemas already carry string level ids, numeric workers and both hashes, so no schema version or historical reinterpretation is needed.
G1–G6 cross-level equality remains mandatory. N=2 additionally verifies both inputs against the exact reviewed set, planned workers, zero remaining in-flight,
aggregate rate ceiling, total ceiling, and conservation of generator response/outcome/fixture fates. The offline manifest uses the selected level's fingerprint.
It additionally requires completion, repeated exposure and measurement-phase identities described above; missing or inconsistent evidence is INVALID.
Historical N=1 parameters, fingerprints, gate ids/output and reconciliation criteria are unchanged. Cross-level inputs are INVALID.
Every required journey group must complete at 100%; any legitimate false reject, L2 non-admit, refusal, parity mismatch, unexplained status,
accounting anomaly, evidence loss or required recovery failure still prevents VALID.

Regression risks are wrong-level selection/hashing, mutation of canonical N=1 JSON, altered historical reconcile semantics,
accidental per-worker rate multiplication, and weakened legitimate-user/recovery criteria. Tests pin both hashes, both exact parameter sets,
capacity failures, cross-level refusal, in-flight 2 versus 3, explicit transport failures, saturation boundaries, and unchanged acceptance parameters.
Local field-runner tests use a deliberately scaled test-only epoch/window and a fake `/proc`; they do not qualify the real N=2 external level.
The N=1 evidence selftest remains unchanged. The only defense runtime addition is the IPC observation barrier; it changes no admission, budgets or request behavior.

```text
npm run lab:ba0:field -- --target <id> --level ba0-l7-c2 --campaign <id> --dry-run
# A later separately authorized campaign would select ba0-l7-c2 on the server and ba0-l7-pressure-c2 on the generator.
# Final reconciliation uses the same offline command as N=1.
```

Historical validation of the initial progression at `e538cde` on Windows / Node 22.22.0 used local fixtures and loopback only:

| Check | Result |
| --- | --- |
| Focused thresholds, workload, reconcile, accounting, external-chain, closed-loop and catalogue suites | 89 passed; no failures, cancellations or skips |
| Field runner, field evidence/selftest, static field safeguards and reconcile suites | 51 passed; no failures, cancellations or skips |
| Final reconcile suite including matching-aggregate unexplained 429/5xx rejection | 22 passed |
| Docker confinement suite with ambient context unset | 27 passed |
| Existing `lab:ba0:field -- --selftest` | SELFTEST-OK; 13 artifacts written, zero refused |
| N=2 field dry-run | All 30 applicable gates pass; no network activity; target-lifetime gate also passes with 3,600 seconds remaining |
| `npm.cmd run typecheck`, `npm.cmd run lint`, `git diff --check` | Pass |
| Full suite, serialized | 1,477 tests: 1,417 passed, zero failed, one cancelled, 59 skipped; exit 1 |

The full command was `node --import tsx --conditions=react-server --test --test-concurrency=1 tests/*.test.ts`, with `TEST_DATABASE_URL` unset,
`NEXT_TELEMETRY_DISABLED=1`, and no ambient `DOCKER_CONTEXT`. Skips are the existing database and platform-dependent cases, not passes.
All Slice-1/2/3 and field regressions pass. The sole cancellation is the unchanged `tests/resend-notification.test.ts` case
"the HTTPS client bounds calls, sends the official idempotency header, and discards raw errors": "Promise resolution is still pending but the event loop has already resolved".
It reproduced on a clean local checkout of master `f6a7ab6399984849ef39fcdb9b28c3247a0f0e23` (four passed, one cancelled, no tracked changes);
another clean-master probe passed, establishing timing dependence. No notification code or test was modified.
An initial full invocation also failed a confinement test because validation had set an artificial `DOCKER_CONTEXT`; correcting the invocation resolved it.
Local TAP logs are retained under `artifacts/lab/n2-validation-*.tap`, including the clean-master reproduction. No commit, push, deployment,
external traffic, real GCP campaign, or cloud/firewall configuration change occurred. N=2 remains prepared for review, not externally qualified.

Remediation validation against that exact commit, using synthetic observations and loopback only:

| Check | Result |
| --- | --- |
| Focused N=2 measurement, reconcile, thresholds, field runner/writer, scheduler and defense static suites | 92 passed; zero failed, cancelled or skipped |
| N=1 immutability comparisons | Parameter object, fingerprint and gate output match both `e538cde` and base master; workload, report construction, all 13 writer artifacts and 10 reconcile scenarios match `e538cde` exactly |
| Typecheck, repository lint, diff check | Pass |
| Full suite, serialized | 1,489 tests: 1,429 passed, zero failed, one cancelled, 59 skipped; exit 1 |

The full suite's cancellation is the same unchanged notification HTTPS test described above, with the same pending-promise/event-loop message.
Database URLs and Next telemetry were disabled; no ambient Docker context was set. Logs are `artifacts/lab/n2-remediation-focused.tap`
and `artifacts/lab/n2-remediation-full.tap`. The sandbox's TSX user lookup failed with `uv_os_get_passwd ENOMEM`; local tests were rerun outside that sandbox.
No external campaign was run, and no commit, push, deployment or cloud/firewall change was performed. Under fast N=1-like latency,
the unchanged offered workload is expected to remain unexercised; the remediation makes that result fail qualification instead of manufacturing overlap.

### Separately reviewed N=2 salvo

The field specimen lineage is `aff793e4968cd5615e25665c5437e20d268d744f`. Historical `ba0-l7-c1` and `ba0-l7-c2` retain their parameters,
workloads, report shapes and reconciliation interpretation. The real `first-gcp-n2` result remains INVALID: completion, exercise and the
completion-dependent historical phase identity fail. The new level does not reinterpret that evidence.

| Identity | Value |
| --- | --- |
| Level | `ba0-l7-c2-salvo` |
| Workload | `ba0-l7-pressure-c2-salvo` |
| Parameters | `ba0-field-c2-salvo-v1` |
| Parameter SHA-256 | `eda312909c18c7a7cd9c4525f2071b474f10b1b27c3b181e9e1a12ea27208f46` (remediated; the pre-review value `231a5ccd8574f3bb21d61ff160e424636076090bb451c7b43ef5651700ac400f` was never run in the field) |
| Workload SHA-256 | `43ee3f7c0aaacea44384cc7e614eb58fe126bb042698417cf6c65f8f138d4264` |

The isolated scheduler releases 750 pairs at `80 * index` ms, indices 0 through 749, over a full 60-second monotonic phase. The final release is
59,920 ms. Even pairs send home + privacy; odd pairs send form + inquiry. Both sends begin before either response is awaited. Counts remain
375 per fixture, 1,125 reads, 375 mutations and a hard maximum of 1,500 requests. No HTTP warm-up is added.

This is 25 requests/second **campaign average**, with burst two and nominal one-second bins alternating 26/24. It changes temporal clustering
as well as actual concurrency compared with historical C1/C2. A claim isolating concurrency causally needs a fresh separately identified N=1
control with the same paired release opportunities; historical N=1 is a reference observation. No defense, lane, credit or canary value changes.

Timer wakes always recheck the monotonic not-before time. Every dispatch must be less than 40 ms late. An active pair at the next release,
excessive lateness, expiry, transport failure or operator abort stops dispatch and latches a non-completion reason. Missed pairs never catch up.
Only finite schedule exhaustion, all clean fates, full phase duration and bounded drain qualify as `completed`. A hard watchdog acts at 64,000 ms;
elapsed above 64,000 ms cannot qualify. `total_ceiling` is a safety stop, never normal completion. No request 1501 slot is reserved.
Authorization is checked at each dispatch and again after the full-duration wait and final drain; expiry after the last response still cannot qualify.

Generator `salvo` evidence records monotonic stop-latch time, per-pair starts/settlements and fixture latency summaries derived from those records.
Salvo latency summaries measure logical dispatch-to-settlement lifetimes; historical C1/C2 sender latency summaries are unchanged.
Server `salvo` evidence records the existing source ARMED/CLOSED phase counters/barriers and 750 bounded pair records. Pair association uses
consecutive external-ingress ordinals; generator waiting for both responses before the next release and zero-ambiguity accounting support that
association. Arrival order within a pair can reverse. Existing source events are observed; no new defense events or client identity headers are added.
Only two active nonce associations are retained. Missing, duplicate, malformed, overflowing or temporally inconsistent records cannot qualify.

For each source and pair, opportunity is `P = min(endA-startA, endB-startB)` and actual overlap is
`O = max(0, min(endA,endB)-max(startA,startB))`. A material pair has positive opportunity and `O >= 0.75 * P`. Normalized overlap is the primary
physical-exercise evidence on both sources. The generator additionally bounds its own dispatch skew `s = |startA-startB|`; exact observed timestamps are
retained and never rounded. Source lifetimes are independent measurements, not counterfactual service-time estimates.

Dispatch skew rule (replaces the pre-review absolute 0.5 ms gate): `s <= min(10 ms, 0.25 * P)`. The normalized term is derived, not chosen: for equal
lifetimes `d`, `O = d - s`, so `O >= 0.75 d` is exactly `s <= 0.25 d`; using the pair's own `P` generalizes that to unequal lifetimes and rejects a short
request nested inside a long one (overlap ratio 1, but not a salvo). Serial dispatch needs `s >= d`, hence zero overlap, and is already excluded by the
overlap rule. The 10 ms absolute cap is an engineering bound, not a derived one: both sends are issued in one synchronous scheduler turn, so skew only
measures setup cost (or a stall inside that turn); 10 ms is one eighth of the 80 ms period and a quarter of the 40 ms lateness allowance, 4.6 times the
2.163 ms cold first pair measured on loopback, and bounds staggered dispatch regardless of how long lifetimes are. The old 0.5 ms value was an
implementation-timing proxy: steady-state loopback skew is 0.10 to 0.34 ms but the cold first pair measured 2.163 ms, and the server has no equivalent
measurement. The server rule has no skew term; overlap alone applies.

Qualification requires each source to pass independently and a **joint** set of at least 743 pairs. A pair is jointly material only when both
independently valid sources prove it material (the intersection of the two material index sets). The two sources may miss different pairs. Every
planned one-second bin admits at most one jointly missed pair: 12/13 or 11/12 jointly material. On both sources, the opportunity-weighted ratio including **all** pairs in every planned bin is at least 0.75;
every actual source-clock second has at least 11 material overlap starts. Planned bins group whole pairs by reviewed release index; actual bins
use the later start on each emitting source clock. Residency includes each pair's bounded settlement, including any final drain.
All summaries are derived offline from the bounded records; claimed aggregates cannot override them. Boundaries are evaluated without rounding
up. The 743 threshold is a preregistered seven-opportunity loss budget, not a statistical confidence level.

The pre-review rule required the two material index sets to be identical. That made one pair seen as non-material by only one source (for example a
cold first pair, or a few milliseconds of arrival skew on the server) fatal even with 749 jointly material pairs, so it was replaced by the joint
intersection above. `final.json` persists the joint material indices, the missing indices and the joint planned-bin counts. Requests are never
held to manufacture overlap. Fast requests can qualify with much less than the old 9.6-second absolute residency requirement.

The new completion and phase-only predicates are independent diagnostics and both are mandatory. `final.json` persists their failed subconditions
and both derived exposure summaries. Phase binding verifies source barriers, zero pre-arm/post-close ingress, complete ingress/settlement counts,
clean close, every pair's clock bounds and the runner window. The existing 2,000 ms clock agreement is assumed, not measured. Transport ambiguity,
unexplained 429/5xx, unaccounted 503, retries, pipelining, saturation, server evidence failures and existing legitimate-user/recovery failures remain fatal.

No capacity is resized. Source ingress allows network jitter using `2 * (1 + ceil(intervalMs / 80))` arrivals: consecutive pairs can bunch even
though the generator releases remain spaced. Normal pairs must settle before the next release; the final pair can only arrive later. Bounds are
402 active / 528 orphan records, 1,820 decisions, 1,500 traces/recent nonces, 320 canary records,
12/7/5 events per request per stream, 13,728 queued events for a 10-second stall plus all canaries, and 832 hop replay entries. Existing capacities
are respectively 1,024 / 1,024, 20,000, 2,000 / 4,096, 4,000, 32 per stream, 16,384 queue entries and 4,096 replay entries. Collector window remains
8,192. L2 use ledger remains 251 required / 512 available; worst Bloom inserts remain 1,564, with 0.1305% fill and FPR estimate 6.45e-21.

Pair memory conservatively charges both participants and three representations at 512 bytes per pair: `2 * 3 * 750 * 512 = 2,304,000` bytes.
Modeled external/channel/pair accounting becomes **238.0 MiB / 256 MiB**. Modeled journal including origin events plus both pair JSON artifacts
is `4,587,520 + 2 * 750 * 512 = 5,355,520` bytes, within half of the enforced 48 MiB journal budget. Pair records are separate JSON evidence,
not journal lines; this additional charge is conservative. Neither 512 bytes per record/event nor the legacy 256-byte journal value is a runtime
maximum. Runtime resource ceilings and evidence-loss invalidation remain mandatory. Recovery remains `2 * 60,000 + 15,000 = 135,000` ms.

The synthetic scheduler tests run the exact full schedule on a deterministic clock. The short real HTTP test uses loopback only and intentionally
aborts after eight responses to verify two keep-alive connections and no pipelining. Neither test qualifies an external field campaign.

Validation against the working tree based on `aff793e4968cd5615e25665c5437e20d268d744f`:

| Check | Result |
| --- | --- |
| Focused salvo scheduler, qualification, historical, field, workload and defense static suites | 138 passed; zero failed, cancelled or skipped |
| Exact historical comparisons | C1/C2 parameters, fingerprints, workload objects, budget gates, reports, all 13 writer artifacts and reconcile scenarios match the field specimen; historical scheduler body is unchanged |
| Real `first-gcp-n2` evidence reproduction | Exactly the original three failed identities and INVALID result |
| Typecheck, repository lint, diff check | Pass |
| Full suite, serialized | 1,524 tests: 1,464 passed, zero failed, one cancelled, 59 skipped; exit 1 |

The full suite includes the final authorization-expiry and delayed-watchdog regressions. Its cancellation is the unchanged notification HTTPS
test described above, with the same pending-promise/event-loop message. Database and platform skips remain skips. Logs are
`artifacts/lab/salvo-focused-final.tap`, `artifacts/lab/salvo-full-final.tap`, `artifacts/lab/salvo-typecheck.log` and `artifacts/lab/salvo-lint.log`.
All 34 applicable capacity gates pass with 3,600 seconds of target lifetime, recorded in `artifacts/lab/salvo-capacity.json`.
No commit, push, deployment, external host contact, external traffic or cloud/firewall configuration change was performed.

#### Salvo review remediation

An independent review found that exact generator/server material-set equality could return INVALID with 749 of 750 jointly material pairs: a cold
first pair measured 2.163 ms of generator dispatch skew against a 0.5 ms gate, and the server has no equivalent measurement. The remediation replaces
set equality with the joint intersection and replaces the absolute 0.5 ms gate with the normalized-plus-cap skew rule above. Only
`lab/defense/salvo-spec.ts`, `lab/defense/salvo-reconcile.ts`, their tests and this document changed. The `ba0-field-c2-salvo-v1` parameter
fingerprint changed because the reviewed salvo specification changed; the salvo workload fingerprint and every C1/C2 parameter and workload
fingerprint are unchanged. Defense, lane, credit, canary, recovery, exposure and accounting parameters are untouched and still asserted equal.

| Check | Result |
| --- | --- |
| Salvo, scheduler, workload, field-run and field-threshold suites | 74 passed; zero failed, cancelled or skipped |
| All `tests/lab-*.test.ts` | 512 passed, 0 failed, 8 skipped (one earlier run immediately after a local `git stash` round trip reported 2 failures that did not reproduce in three later runs) |
| Typecheck, repository lint, `git diff --check` | Pass |
| Full suite, `npm test` | 1,529 tests: 1,487 passed, 0 failed, 0 cancelled, 42 skipped |
| Historical C1/C2 and `first-gcp-n2` | Immutability and original three failed identities and INVALID result tests pass unchanged |
