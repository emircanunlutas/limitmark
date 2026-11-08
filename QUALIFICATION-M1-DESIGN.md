# First independent L1/L2 qualification milestone (M1) — responsibilities, architecture, acceptance criteria (2026-11-08)

LOCAL design. Nothing provisioned, no traffic sent, nothing deployed. Production NO-GO; Gates 9, 10, 11A closed. This milestone is **L1/L2 application-plane qualification only**. It is NOT L1/L2/L3 qualification: L3 network isolation and the `n3.*` / `t4.*` volumetric layers are not implemented (reported `not_measured`). The Cloudflare Workers / Vercel inquiry-admission path is outside M1 and keeps its own end-to-end track.

Correction to `INDEPENDENT-QUALIFICATION-READINESS.md`: it listed "no legitimate-user latency threshold" as missing. That was wrong. The reviewed field level already predeclares `canary.jcrMinimum = 1` and `canary.windowLatency = { p95Factor 4, p95AddedMs 150 }`, plus ceilings and an `allowedShed` list (read in `lab/defense/field-thresholds.ts`). The gaps that remain are listed in section 4.

## 1. Exact responsibilities of the existing layers (read from source, not inferred from names)
### L1 `a7.shape-gate` (`defense/layers/a7-shape-gate.ts`)
- **Does:** a pure, stateless verdict on the *shape* of one request, in a fixed order that bounds cost before anything expensive: (1) method; (2) target length, alphabet, structure (no decoding); (3) header count, bytes, name/value alphabets, Host; (4) framing (Content-Length only, never Transfer-Encoding, no body on GET); (5) POST content type and body size/state; (6) form grammar, only over a body already bounded to 32 768 bytes.
- **Fixed policy:** five exact routes (`/`, `/gizlilik`, `/test-talep-et`, `/test-talep-et/tesekkurler`: GET; `/api/public-inquiries`: POST); an allow-listed form field set (13 names, max 16 fields, 32-byte names, 12 000 encoded bytes per field); 43-char submission token shape; target ≤ 2048, query ≤ 64 bytes, ≤ 48 headers, ≤ 8192 header bytes.
- **Output:** pass, or exactly one of 22 closed reject reasons (+3 semantic, +2 lane). A layer exception, missed deadline or malformed verdict is an explicit error answered 503 (fail closed); saturation of its 64-slot bulkhead is an explicit shed.
- **Does NOT:** rate-limit, remember, score, identify senders, check token *validity* (only shape), terminate TLS, or see the harness traffic-class label.
### L2 `a7.journey-lanes` (`defense/core/lanes.ts`, `defense/plane/l2-stage.ts`)
- **Does:** classifies every L1-passed request (`open` = the four GET routes; `mutation` = POST `/api/public-inquiries`; `unknown` = anything else, treated as unverified work) and bounds mutation work with two **global** token buckets: `credited` (a submission token this plane itself delivered recently, proven by a rotating Bloom filter, ≤ `maxUses` uses per token, ledger of 512) and `unverified` (everything else). No spill between lanes; no refunds; a failed evaluation of mutation/unknown work is a shed or error, never an admit; only `open` requests may become `degraded`.
- **Reviewed field parameters (provisional, uncalibrated):** credited bucket 10 + 2/s, unverified 3 + 1/s, epoch 60 s, 2^23-bit filter with 7 hashes, 3 uses, L2 deadline 50 ms, bulkhead 64.
- **Does NOT:** consider the sender at all (no per-client or per-IP fairness; sender is never an input), do flow provenance beyond submission-token enrollment, adapt thresholds, or run a quarantine lane (reserved, unimplemented). A credited-lane flood by someone holding genuine tokens is bounded only by the global credited bucket.
### Around them (Slice 2, application non-bypass only)
Semantic request canonicalization, signed single-use hop proofs Plane→Boundary→App, replay guard, and origin accounting that makes any origin receipt without a plane pass an INVALID bypass. This is *application* non-bypass; a 403 after `accept()` is not network isolation.
### Missing relative to what the names might suggest
No L3 (`n3`/`t4`), no TLS, no per-source limiting, no reputation/behavioural scoring, no CAPTCHA, no adaptive control, no quarantine, thresholds uncalibrated, and the 2026-10 fairness research verdict RETAIN_V1 recorded open issues [M]. M1 must say "L1/L2 as implemented", never more.

## 2. Architecture under test
```
 Generator VM (one /32, closed-loop, no retries/pipelining)                SUT VM (disposable, own VPC subnet)
   cycle: GET /, GET /gizlilik, GET /test-talep-et, POST inquiry  ---->   Defense Plane (own process): front -> L1 -> L2 -> egress
   canary journeys (legit, 5-step incl. valid POST, real token)  ---->        |  bounded IPC events + 1 s ticks        |
                                                                              v                                       v
                                                                 Collector/ledger (harness process)         Origin Boundary -> App (+ synthetic backend)
 Operator workstation: preflight, monitor, reconcile, evidence pull; no credentials on SUT.
```
Adverse condition in M1 = the reviewed cycle's POSTs arrive **unverified** (no genuine token) at 25 req/s total, saturating the 3+1/s unverified bucket (expected shed: mutation/unverified/lane_budget only), while legitimate canary journeys use genuine tokens through the credited lane. No new traffic type is needed.

## 3. Predeclared acceptance criteria (fixed before any run; values are the reviewed ones unless marked NEW)
M1 = the reviewed N=1 external level `ba0-l7-c1` (60 s, ≤ 25 req/s, ≤ 1 500 requests, 1 worker) plus the repeat rule.
**VALID requires all of:**
1. Legitimate users: JCR = 100% in every required group (baseline, window, residual, recovery); window p95 ≤ 4 × baseline p95 + 150 ms; no canary 5xx; every step 200 with expected content.
2. Accounting: identities E1..E11 hold; ingress = sum of terminal outcomes; zero unresolved; no unexplained request; no unattributed 503; the only shed is `mutation/unverified/lane_budget`; zero bypass (origin receipt without plane pass).
3. Exposure: continuous proof holds in every tick (only the reviewed plane IPv4:port listens non-loopback); no external accept before ARMED.
4. Resources never exceed ceilings: host CPU ≤ 80% (3 ticks), available memory ≥ 15%, plane ELD p99 ≤ 250 ms (3 ticks), RSS ≤ 512 MB, fds ≤ 70%; generator schedule-lag p99 ≤ 50 ms and ELD p99 ≤ 100 ms (otherwise the run is INVALID, not a defense failure).
5. Recovery: after the load stops, quiet period 135 s, then recovery journeys all succeed; residual journeys (restriction after load) all succeed.
6. Telemetry: gapless 1 s ticks (gap tolerance 2.5 s).
7. **NEW, repeatability:** three independent runs on fresh state (same commit, parameters, fixture cycle) all VALID, with identical shed reason sets and per-run shed share within ±5 percentage points of the median. A single VALID run is a smoke result, not M1.
8. **NEW, status allow-list (finding N-1):** every client-visible status must be in the predeclared set {200, 302/303 per fixture, 503 attributed to the allowed shed, 403/404 only where the fixture expects them}; any other status is INVALID. This needs a verdict-path change (migration event) and is a prerequisite, not part of the run.
9. **NEW, unexplained differences:** plane outcome tally (82045e3) vs collector ledger equal per event kind, once wiring is approved (`PROPOSED-INSTRUMENTATION-WIRING.patch`). Until then this criterion is reported `not_measured`, and M1 cannot claim it.
**Not claimed even on VALID:** network/transport health, capacity, behavior at higher N, any production readiness, any property of Cloudflare/Vercel/admission.

## 4. Remaining blockers to the first isolated test
| # | Blocker | Type |
|---|---|---|
| B1 | Status allow-list (N-1) not implemented | verdict-path change, migration event |
| B2 | Campaign id ≤ 31 chars (N-2) trap documented but not enforced at argument parsing | verdict-path-adjacent |
| B3 | Plane tally wiring not applied (needs `runtime.ts`, pinned to aff793e) | migration event, patch ready |
| B4 | Server pair records lack method/status/decision (per-request attribution) | verdict-path change |
| B5 | Two baseline failures (historical immutability, byte-identical) unresolved | reviewed baseline migration |
| B6 | Private-address target support: `forbiddenRemoteAddress` does not refuse RFC1918, so it looks accepted; confirm with a test and confirm the exposure proof works with an internal address | local test |
| B7 | Cloud project, quotas, budget cap, firewall, TTL, evidence pull automation | infrastructure (not authorized) |
| B8 | Local dress rehearsal on Linux container parity (`lab:parity`, `lab:ba0:field -- --selftest`) not re-run in this phase | local, doable |
| B9 | Acceptance criteria 7–9 need owner sign-off before the first run | decision |

## 5. Local-only preparation that needs no approval
`npm run lab:ba0:field -- --selftest` and `npm run lab:parity` (Docker required) to rehearse the exact evidence path; unit tests already run in `npm test`. No external traffic.
