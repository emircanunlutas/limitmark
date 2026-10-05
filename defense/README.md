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
