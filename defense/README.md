# defense/ — BA0 Defense Plane (application plane only)

Status: **BA0 Slice 1** = skeleton + L1 (`a7.shape-gate`) + the complete measurement path. Local, loopback-only, fixed counts. Nothing
here is deployed, wired into the application, or reachable from a build. Slice 1 may conclude **BASELINE-VALID** or **INVALID**; it never
claims a defense-qualification PASS.

## Trust boundary

| Zone | May import `defense/`? | `defense/` may import |
| --- | --- | --- |
| `src/`, `workers/`, `operator/`, `deployment/`, `scripts/` | **No — never** | — |
| `lab/` (the harness: `lab/defense/`) | Yes | — |
| `defense/` itself | — | its own files and `node:` built-ins only (no package, no `src/`, `operator/`, `scripts/`, `deployment/`, `workers/`, `lab/`) |

Enforced by ESLint `no-restricted-imports` (both directions), `tests/lab-isolation.test.ts` and `tests/defense-isolation.test.ts`.

## Scope: application plane only

Layer ids are namespaced `n3.*` (network volumetric), `t4.*` (transport) and `a7.*` (application). BA0 populates **only `a7.*`**; `n3.*`
and `t4.*` are reserved and reported `not_measured`. **An L7 success says nothing about network or transport health**, and loss before the
socket (SYN floods, backlog drops, link saturation) is invisible to an L7 ledger. Every evidence file states this.

## Request path

```
client -> front (127.0.0.1, bounded read) -> composer(L1) -> fixed loopback synthetic origin
```

* The upstream is one fixed `127.0.0.1:<port>` given at construction. A request cannot choose or influence it.
* Spoofable internal/forwarding headers (`x-ba0-*`, `x-forwarded-*`, `forwarded`, `x-real-ip`, `cf-connecting-ip`, `x-limitmark-*`, `x-vercel-*`, …)
  are removed **before any layer sees the request** and are never forwarded. Only an allow-listed set of request headers reaches the origin.
* L1 is a pure, stateless decision on shape and grammar: method, target, headers, framing, content type, body bounds, then the form grammar.
  No rate limiting, bans, CAPTCHA, reputation or behavioural scoring. Layers cannot see the traffic-class label or the correlation nonce
  (a test proves it).

## Correlated lifecycle accounting

Every harness request carries a unique opaque nonce and an explicit lifecycle (`core/ledger.ts`):

```
SENT -> INGRESS_ACCEPTED -> L1_ENTERED -> exactly one of L1_PASSED | L1_REJECTED | L1_SHED | L1_ERROR
     -> (when L1_PASSED) EGRESS_ATTEMPTED -> EGRESS_RESPONDED | EGRESS_FAILED
     -> ORIGIN_RECEIVED -> ORIGIN_COMPLETED | ORIGIN_ABORTED          (observed independently by the origin)
     -> INGRESS_RESPONDED | INGRESS_ABORTED -> CLIENT_COMPLETED
```

Counters are **derived** from these records (`lab/defense/accounting.ts`); they are never the source of truth. The validator flags duplicate
terminal processing, missing transitions, impossible order, a request disappearing after ingress, duplicate origin processing, work
completing after the ledger froze, and unresolved in-flight work at finalization. Any one of them makes the run INVALID. The aggregate
identities (ingress = terminal outcomes; per layer in = pass + reject + shed + error; egress attempts = L1 passes; …) remain as secondary
reconciliation checks.

Cross-process ordering never relies on clocks: the origin records the plane's `EGRESS_ATTEMPTED` sequence number (`x-ba0-hop`, set by the
front) and the collector requires it to match.

## Failure policy: no raw fail-open

Slice 1 has exactly one failure policy, **fail closed**. An unexpected layer exception, a missed verdict deadline, or a malformed verdict is an
explicit `L1_ERROR` and the request is refused with a 503. It is never an ordinary pass, there is no `error_failopen`, and the composer
refuses to be constructed with any other policy. A distinct degraded/quarantine outcome is **reserved** for a later slice (`RESERVED_OUTCOMES`);
it is not implemented and must never be equivalent to PASS. Saturation is an explicit `L1_SHED` (503), also fail closed.

## Origin/egress reconciliation

A layer PASS is not delivery. `EGRESS_ATTEMPTED`, `ORIGIN_RECEIVED`, `ORIGIN_COMPLETED` are separate events, and L1 passes are reconciled against
what the origin independently observed (`delivery.l1PassedNotReceivedByOrigin`). Egress `refused` / `reset` / `timeout` / `error` are separately
attributed (`EGRESS_FAILED` with a kind, answered 502 or 504). An origin receipt with no plane pass behind it is a bypass and is INVALID.

## Ledger crash survivability (property: measurement outside the plane's failure domain)

Design chosen (smallest that satisfies the property, no shared memory): the plane is its **own process**; the authoritative collector
(`lab/defense/collector.ts`) lives in the harness process and the plane only emits events over a bounded, flow-controlled IPC channel
(`BoundedEventChannel`). The collector keeps a bounded in-memory ledger and a bounded append-only NDJSON journal, flushed in batches off the
request path. There is no synchronous per-request durable I/O anywhere in the defense path.

* **Survives a Defense Plane crash:** every harness event, every origin observation (collected in the harness, not via the plane), and every
  plane event the collector had already received; they are in the ledger and the journal.
* **May be lost:** plane events still in the plane's queue or in flight on the pipe when it died (bounded by `queueCap` + `windowCap`).
* **Lost or unacknowledged events make the run INVALID, never falsely successful:** the child's unexpected exit is recorded
  (`plane_crashed`); the plane's FIN is missing (`plane_not_finalized`); the event stream has a sequence gap or the plane reports dropped
  events (`event_channel_loss`); and independently of the plane, each request the harness SENT but whose lifecycle is incomplete is flagged
  (`ingress_loss`, `disappeared_after_ingress`, `unresolved_at_finalization`, `sent_without_completion`).
* **Memory stays bounded:** the plane queue is capped (overflow drops the event and counts it, which is INVALID, instead of blocking or
  growing); the collector caps records, events per record, anomalies and journal bytes (journal overflow is itself INVALID).
* Plane self-reported statistics (RSS, event-loop delay, composer counters) are labelled **advisory**; the ledger is authoritative.
* Not covered in Slice 1 (stated, not hidden): a crash of the harness/collector process itself; the journal is not yet part of `SHA256SUMS`
  (its SHA-256 is recorded in the manifest instead).

## Event-loop safety (what the layer timeout does and does not do)

The composer's per-layer timeout is a deadline on the **verdict**, not preemption. JavaScript cannot interrupt synchronous CPU work, so a
layer that spins synchronously blocks the whole process and its timer cannot fire until it returns. What the composer guarantees is that a
verdict that arrives after its deadline (a hung promise, or a synchronous overrun) is **discarded** and recorded as `L1_ERROR (timeout)`.

The protection against expensive synchronous work is therefore the **strict bounds applied before any expensive parsing**: Node's header size
limit; L1's target, header-count, header-byte and framing checks; the front reading a body only when `Content-Length` is declared at or below
32 KiB (a larger declaration is rejected without reading a byte); a body read deadline. The form grammar parser runs only on a body that
passed all of them, and the run proves it: the plane's parser-invocation counter must equal the number of requests the ledger says reached
the grammar stage.

## Bulkhead

The composer gives each layer its own concurrency cap. Beyond it, work is `shed` (explicit, 503). A timed-out evaluation that has not settled keeps
counting against the bulkhead (bounded by a reclaim timer), so a hung layer cannot be fed unbounded new work.

## Not implemented in Slice 1 (later milestones)

L2 flow provenance / replay and token-farming protection; L3 origin-local admission and kernel/network isolation; L3/L4 telemetry;
predecessor-collapse tests; parser differential fuzzing; hardware/VPC-separated A/B; external attack traffic; any quarantine lane.

## Running

```text
npm run lab:ba0        # loopback only; takes no arguments; evidence under the gitignored artifacts/lab/evidence/
```

# BA0 Slice 2: independent origin boundary (application non-bypass only)

Status: **local, loopback-only, fixed counts.** Slice 2 may conclude **APP-NON-BYPASS-VALID** or **INVALID**; it never claims a defense-qualification PASS.

**What it measures, and what it does not.** Slice 2 measures *application non-bypass*: a request without a valid, request-bound, fresh,
single-use proof chain cannot enter application semantics or state, even when the sender knows the origin boundary's exact address and
port (and, as a stricter extra, the application's own port). It does **not** measure *network non-bypass*. A 403 returned after
`accept()` is an application-layer refusal on an open socket, not L3/L4 isolation. Nothing here speaks to bandwidth, PPS, SYN,
TLS-handshake or connection-state exhaustion; `networkNonBypass` and `originNetworkIsolation` are `not_measured` in every artifact.

## Topology: three processes, two cryptographically distinct hops

```
canary / corpora -> Defense Plane (L1 + semantic gate + PB issuer) -> Origin Boundary (PB verifier, BA issuer) -> Protected App (BA + lineage verifier)
known-address direct tests -> Origin Boundary, and the Protected App's own port
```

| Process | Private keys | Public keys | Replay state |
| --- | --- | --- | --- |
| Defense Plane | `K_P` | none | none |
| Origin Boundary | `K_B` | `K_P` | `pb` |
| Protected App | **none** | `K_B`, `K_P` | `ba`, `lineage` |
| Harness (lab trust root) | both, for labelled misuse and positive-control cases only | all | none |

Keys, audiences and kids are generated per run by the harness and delivered **only over IPC**: never env, argv, a file, a log or evidence.
Process separation gives failure-domain separation (crash, event loop, memory) only; compromise independence comes from the distinct keys
plus the lineage check.

## Proof formats

Both are `b64url(payload) "." b64url(sig64)` over a canonical JSON array, Ed25519 over `domain || payload`, strict canonical encoding.

```
PB (Plane -> Boundary)  x-ba0-hop-pb  ["ba0-pb-v2", kid, boundaryId, iat, exp<=5s, jti, hop, corr, method, target, pairs, bodyLen, bodySha256]
BA (Boundary -> App)    x-ba0-hop-ba  ["ba0-ba-v2", kid, appId,      iat, exp<=2s, jti, hop, corr, method, target, pairs, bodyLen, bodySha256, pbJti, pbSha256]
```

Role string, signing domain, key pair, kid prefix, audience, header name, replay set, lifetime and tag namespace all differ; each is
independently sufficient to reject cross-hop use. A BA carries the Plane's PB (verbatim) as **lineage**: the App admits only when both
verify, the PB's request fields equal the BA's, and the BA commits to that exact PB by jti and hash. A PB alone, or a BA alone, admits
nothing at the App; a BA never admits at the Boundary. A compromised Boundary holding only `K_B` can drop, delay or replay-once what the
Plane approved, but cannot make the App execute anything the Plane did not approve.

Issuing is capability-shaped: `issuePb` accepts only an `ApprovedRequest`, `issueBa` only a `VerifiedPb`. There is no function in `defense/`
that signs caller-chosen facts; test-only minting lives under `lab/defense/hop-keys.ts` (an independent encoder) and is pinned by a static test.

## The canonical semantic request

What every hop authenticates is the exact representation the Plane approved, never raw client headers (`core/semantic-request.ts`):

| Class | Headers |
| --- | --- |
| bound (signed, forwarded) | `host` (required), `origin` (optional), `content-type` (POST only) |
| derived | `content-length` (re-emitted from the body length) |
| transport | `connection` (only exactly `close` or `keep-alive`) |
| refused | `content-encoding`, `transfer-encoding`, `expect`, `upgrade`, `te`, `trailer`, `range`, `if-range`, `proxy-authorization`, `authorization` |
| spoofable / ingress indicators | stripped and counted at the plane; any presence downstream is rejected |
| everything else | dropped at the plane, never forwarded; any presence downstream is rejected |

Normalisation is exactly lowercase names and trimmed ASCII whitespace; values are byte-exact otherwise. A duplicated bound header is
refused, never merged. The plane **rebuilds** the outbound request from the approved representation; the Boundary and App scan the raw
header list against the same closed set, compare the observed pairs with the signed ones, and the App interprets the verified claims, not
its own header view. `tests/lab-ba0-semantic-contract.test.ts` pins this table to every header `src/` actually reads.

## Replay state machine

`UNSEEN -> RESERVED -> COMMITTED | BURNED`. `reserve` is synchronous and runs before any asynchronous body work; a timeout, abort, digest
mismatch or exception after reservation leaves the id BURNED until expiry; no unexpired entry is ever evicted; at capacity the request
fails closed (`ob.replay_cache_full`, 503, only reachable after authentication). Verifier-start fencing (`iat >= verifier start`) and
wall/monotonic clock-step detection are preserved.

## Lifecycle and accounting

A clean protected request reconciles across three independent processes:
`L1 PASS -> EGRESS_ATTEMPTED(hop) -> PROOF_ISSUED -> BOUNDARY_ADMITTED -> APP_PROOF_ISSUED -> APP_ADMITTED -> APP_EXECUTED -> [APP_MUTATED] -> APP_COMPLETED`,
with `hop` and two proof tags agreeing at every stage. Any app admission, execution or mutation without that lineage, and any direct
rejected lane that reaches the application, is an anomaly and makes the run INVALID. Positive controls are separate lanes
(`positive_control_boundary`, `positive_control_app`) in a disjoint hop range and can never satisfy a protected identity. Mutation reconciles
three ways: client-observed success = ledger-correlated mutation = the application's own counter.

A crash can lose the dying process's last events (bounded flush window); a request that completed just before the kill then cannot have its
lineage proven and the run is INVALID: the loss is detected, never silent.

## Not implemented in Slice 2 (later milestones)

Tunnels, WireGuard, mTLS, nftables/eBPF, public cloud, L3/L4 handling, external traffic, L2 flow provenance, key rotation/revocation/KMS.
Limits: the Boundary and App share one verifier implementation (common-mode); the harness holds both private keys; responses are not
authenticated; headers outside the closed set are not bound (they are dropped by policy); replay protection across a restart rests on the
start fence alone.

## Running

```text
npm run lab:ba0:origin   # loopback only; takes no arguments; evidence under the gitignored artifacts/lab/evidence/
```

# BA0 Slice 3: layer diversity and predecessor-collapse (application plane only)

Status: **local, loopback-only, fixed counts.** Slice 3 may conclude **LAYER-DIVERSITY-VALID** or **INVALID**; it never claims a defense-qualification PASS.

**What it measures.** If L1 is wrong, is there a genuinely different layer behind it that still protects the application? L1 judges the *shape of one
request* (stateless). L2 `a7.journey-lanes` judges two things L1 cannot: whether a mutation request carries a submission token that this plane itself
delivered to a client recently (journey provenance, a cross-request signal), and how much mutation work each lane has already been admitted for (a
budget). Provenance only *selects* the lane; the budgets are the bound. The sender is never an input: no IP, no connection identity, no ban.

```
L1 (shape gate + semantic gate) -> L2 journey-lanes -> canonicalization -> PB -> Boundary -> BA -> App        (PB/BA architecture unchanged)
```

## The mechanism

| Part | What it is |
| --- | --- |
| Operation class | `open` (the four exact GET routes, no budget) · `mutation` (`POST /api/public-inquiries`) · `unknown` (anything else L1 might wrongly pass: handled as unverified work, never rejected by a second route list) |
| Lanes | `credited` and `unverified`, each with its own token bucket; `open` for GETs. Lane, outcome (`admitted`/`shed`/`error`/`degraded`) and basis are separate facts |
| Credit provenance | `core/credit-filter.ts`: a fixed-memory, two-generation, **keyed Bloom filter**. A render never allocates, nothing is evicted, an insertion cannot fail. Untrusted render volume can only raise the false-positive rate (less attenuation), never remove a genuine credit. A credit lives at least one and at most two epochs |
| Use ledger | K uses per genuinely enrolled token, retained until the epoch window that could hold its genuine enrollment is over; sized from the credited-admission bound; full fails closed |
| Enrollment | Only from the plane's own forwarded response, only if it satisfies the strict contract in `core/enrollment.ts` (exact route, status 200, exact content type, one token in the reviewed form structure, the response completely flushed to the client). Pinned to the form component by a contract test and to the real built application by the G1 script |

Locked invariants: **P1** no spill (a credited request whose bucket is empty is shed with `lane_budget`/503 and never touches the unverified bucket, nor the reverse) ·
**P2** a use record is purged only when `epoch >= firstCreditedEpoch + 2` · **P3** no refunds: a mutation decision is one synchronous function with no `await`; a bucket
token and a use, once taken, are never returned, whatever happens downstream.

**Failure policy.** An L2 error, timeout or saturation on a mutation or unknown request is a 503 (`l2_error`/`l2_shed`), never an admit. Only an `open` GET may become
`degraded` (healthy L2 would admit it unconditionally); a degraded decision is never `admitted` and never enrolls credit.

## Collapse control: harness-only, unreachable from a request

The force-pass implementation exists **only under `lab/defense/collapse/`** and is constructed only by the harness's own plane entry. `defense/plane/main.ts` (the unchanged
Slice-1/2 entry) has no L2 code in its module graph; `defense/plane/main-l2.ts` (the Slice-3 entry) has L2 always present and passes no injected dependency. `core/override-port.ts`
is interface-only. An arm is one-shot, created only over IPC with a CSPRNG id, and matches only the harness's own nonce, the exact fixture bytes (digest) and the kernel-assigned
connection port. Every simulated verdict is permanently labelled `basis: "simulated"` with the real verdict as its shadow.

## Arms

`C0r` the unchanged Slice-2 composition (L2 absent) · `C0` the normal Slice-3 composition, with repeated pressure → recovery → pressure → recovery · `C1` real L1 evaluation delivered as a simulated
false negative, real L2 · `C2` both layers' verdicts simulated (canonicalization, PB, Boundary, BA, replay guards and the App guard stay real; characterization only) · `C2'` real L1/L2 faults, no forced verdict.

## Claim boundary

LAYER-DIVERSITY-VALID means only that, under these local fixed-count conditions and for the reviewed fixture set, a second application-plane mechanism using a different signal bounded
residual mutation while preserving the declared legitimate journeys. It does **not** imply DDoS resistance, bot detection, read-flood protection, per-user fairness, L1/L2 process
independence (both run in one plane process), network or transport protection, or production readiness. Every number is provisional; the filter is scaled down and the generations compressed
for the lab, with identical semantics unit-tested on an injected clock.

## Running

```text
npm run lab:ba0:collapse          # loopback only; takes no arguments; evidence under the gitignored artifacts/lab/evidence/
npm run build && npx tsx --conditions=react-server tests/built-form-enrollment.integration.ts    # G1 against the real build
```

# BA0 field qualification readiness (external L7, first level N = 1)

The historical readiness description below is retained for the N=1 implementation. The reviewed N=2 progression is documented in
[lab/README.md](../lab/README.md#reviewed-ba0-n2-progression): two workers with the same aggregate 25 req/s, 60 s, 1,500-request ceiling,
defense parameters, evidence capacities, legitimate-user criteria and derived recovery. N=2 adds completion, repeated concurrency exposure and measurement-phase
qualification evidence. Its IPC-only Plane observation barrier reports source timestamps, event watermarks and external counters; it changes no defense decision.

Status: **readiness patch only.** It adds NO defense layer and changes no Slice-1/2/3 decision. It makes the existing system measurable and safely
operable for the future first authorized external HTTP qualification. Nothing here has been run against an external generator, and the field runner
itself runs only on a disposable Linux host. The 29 Slice-1/2 files the Slice-3 acceptance pins are still byte-identical; the field entries are NEW files.

## What changed in `defense/`

| Area | Change |
| --- | --- |
| Plane ingress (`plane/front.ts`, `core/ingress-class.ts`) | One optional reviewed bind (`ingress`: a canonical IPv4 literal and a fixed port, validated; wildcard, hostname, IPv6, reserved and port 0 are refused). Absent, the plane binds 127.0.0.1 on an ephemeral port exactly as before. Boundary and App are unchanged and loopback-only. |
| Peer class | A request's peer is `local` (this host: loopback, or remote address equal to local address) or `remote`, from the kernel's view of the connection. A **remote** peer cannot choose the correlation nonce (the header is stripped and counted, the plane mints the id, the request is marked `ingress: "external"`) and is **never told an internal decision** (no `x-ba0-outcome`). |
| Exact pre-ingress counters | Connections accepted (by peer class), closed (clean/error), dropped (listener cap), `clientError` by **every** code, split into raised with no request in flight vs during one, socket errors, CONNECT and non-100-continue `Expect` refusals, active and its high-water. Node 22 behaviour is pinned by raw-socket tests (`tests/defense-front-ingress.test.ts`); what Node does not distinguish (header vs request timeout: both `ERR_HTTP_REQUEST_TIMEOUT`; a server keep-alive timeout vs a polite close) is stated as ambiguous, not invented. |
| `close_ingress` | One IPC-only control message that stops the listener accepting (the STOP path). Existing connections finish. |
| Ticks (`core/telemetry.ts`, field entries) | One small observation-only tick per second from the Plane, Boundary and App, outside the bounded event channel, with a gapless sequence. Nothing that decides ever reads telemetry (pinned by a test, with a state-neutrality test for the L2 snapshot). A tick that fails or is lost is a measurement gap, never a verdict. |
| Field entries | `boundary/main-field.ts` and `origin/app-main-field.ts`: the Slice-2 entries plus the tick, and **without** the lab fault control for the App. The Slice-2 entries are untouched. |

## What changed in `lab/defense/`

`ba0-field-run.ts` (one reviewed level per invocation: PREFLIGHT, TOPOLOGY_UP, BASELINE, ARMED, WINDOW, RESIDUAL, QUIET, RECOVERY, FINALIZING, DONE),
`field-preflight.ts`, `exposure-proof.ts`, `external-reducer.ts` (the bounded external lane), `external-accounting.ts` (E1-E11), `field-state.ts` (state machine, first-STOP latch,
bounded ordered finalization), `field-monitor.ts`, `proc-net.ts`/`proc-sampler.ts` (Linux /proc, read-only), `field-thresholds.ts` (`ba0-field-v1` and the budget gates),
`field-evidence.ts`/`field-selftest.ts`, `generator-report.ts`/`reconcile.ts`/`ba0-field-reconcile.ts` (G1-G6, the only producer of a final verdict) and the closed-loop generator `lab/load/closed-loop.ts`.

## Continuous exposure proof (what it proves and does not)

Before the plane binds, on every 1-second tick and again at finalization, the runner proves: the only non-loopback LISTEN socket owned by the topology (inode held by the runner or one of its
three children, same network namespace) is the exact reviewed Plane IPv4:port; the Boundary, the App and the control origin are on loopback; no wildcard (IPv4 or IPv6, including the IPv4-mapped one)
and no non-loopback IPv6 socket exists in the topology; no process outside the topology holds a topology listening inode; no stale listener sits on the plane's port; and nothing non-loopback listens on the old Field Lab port 3000.
It proves **host listener state only**: nothing about the cloud firewall, NAT, forwarders on the host, or network isolation, and a process whose fds /proc forbids reading is counted, not assumed clean.

## Claim vocabulary

The server side concludes only `complete | invalid | aborted` (and `refused` at preflight). The final verdict `EXTERNAL-L7-QUALIFICATION-VALID | INVALID | ABORTED` exists only after the offline reconcile of the
server evidence and the generator report, and VALID is scoped to the exact `{commit, campaignId, levelId, N, parameter fingerprint, workload fingerprint}`. A failure is classed **measurement** (the evidence cannot support a claim),
**defense** (a sound measurement of a failure) or **operational** (the operator or environment ended the level). It does **not** claim DDoS resistance, capacity, bot detection, read-flood resistance (the open lane has no budget by design),
per-user fairness, network/transport/TLS/origin isolation, protection of the real application (the protected app is the synthetic stand-in), multi-source traffic, any level above the tested one, or production readiness.

```text
npm run lab:ba0:field -- --target <id> --level ba0-l7-c1 --campaign <id> [--dry-run]    # on the disposable Linux host; takes no URL, host, port or path
npm run lab:ba0:field -- --selftest                                                      # the evidence writer on a synthetic level, no network
npm run lab:run -- --target <id> --workload ba0-l7-pressure-c1 --campaign <id>          # the closed-loop generator (the other host); writes generator-report.json
npm run lab:ba0:field:reconcile -- --server <server evidence id> --report <generator-report.json>
```
