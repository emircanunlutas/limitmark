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
