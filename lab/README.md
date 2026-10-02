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
* **Failure injection** acts only on a process the lab started, or on a container carrying the
  `limitmark-lab-` name prefix and the `limitmark.lab=disposable` label.
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
npm run lab:parity                                # Linux container parity checks
```

`lab:run` flags: `--target`, `--workload`, `--thresholds`, `--max-rate`, `--max-concurrency`,
`--max-duration` (lower-only; plain decimal integers; an above-ceiling value is refused, not clamped),
`--manage-app` (lab-local only), `--dry-run`, `--engine node|k6`, `--k6-netns-container`, `--pg`,
`--outage-mode`. Anything else is refused. Exit codes: 0 PASS, 1 FAIL, 2 REFUSED, 3 STOP, 4 ERROR.

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

PASS/STOP thresholds are named sets (`local-loopback-v1`, `field-remote-v1`; a remote target must name
one). STOP aborts a run immediately; PASS is evaluated at the end; the set id, version and content hash
are recorded in the manifest. The numbers are initial and need calibration against the first baselines.

## Evidence

`artifacts/lab/evidence/<runId>/manifest.json` + artifacts + `SHA256SUMS`. It records git SHA and dirty
state, OS/kernel, Node, Docker and PostgreSQL versions, the target ID (never an address), workload
phases, ceilings, the threshold fingerprint, timestamps, the result and aggregate metrics. The writer
**refuses** credentials, authorization headers, cookies, raw IPs, request bodies and user data
(`lab/evidence/redact.ts`).

## k6

`lab/load/k6/lab-load.js` runs only an integrity-hashed plan produced from an *authorized* run and
re-validates it with independent rules (IP-literal base URL, fixed path catalogue, GET or the one demo
POST, hard ceilings). It runs in Docker (`grafana/k6`); to reach a lab container it joins that
container's network namespace (`--k6-netns-container limitmark-lab-app`). For the host's own app use the
Node engine: k6 in Docker Desktop cannot reach the host loopback.

## PostgreSQL lab and the TEST_DATABASE_URL guard

See `lab/postgres/` and `tests/support/test-database-guard.ts`. A destructive DB test refuses unless the
URL is loopback + `limitmark_lab_*` database + `lab_*` role, `TEST_DATABASE_PROOF` is set, and the database
holds a marker (written by the lab, never by tests) bound to that database and cluster, in a cluster
containing no other non-template database.

## Google VM bootstrap

`lab/bootstrap/` is reviewable, idempotent and provider-free, and has **not** been run. See
`lab/bootstrap/README.md`.
