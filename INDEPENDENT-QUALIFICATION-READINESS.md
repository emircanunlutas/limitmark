# Independent defense qualification — readiness assessment and plan (2026-11-08)

LOCAL analysis only. No infrastructure was provisioned, no traffic was sent, nothing was deployed. Production stays NO-GO; Gates 9, 10, 11A stay closed.

**Evidence labels.** [R] = read in source/README this session. [M] = from earlier-session project notes (not re-verified now). [I] = my inference, to be confirmed. Where the facts and the plan disagree with your terms (L1/L2/L3), the definitions in section 1 are mine and need your confirmation.

## 0. Principle applied
LimitMark is judged as an independent customer-defense platform. Any upstream (Cloudflare or other) filtering is **not credited** to LimitMark: an upstream "Allowed" counter is never equated with requests delivered to the plane or the origin. Success = legitimate users complete their journey during adverse traffic; "the process stayed up" is not success.

## 1. Can the complete L1/L2/L3 path run independently?
Terminology as I read it from `defense/README.md` [R]:
- **L1** = `a7.shape-gate`: stateless request-shape/grammar decision. Implemented in the Defense Plane. [R]
- **L2** = journey/flow-level control (`a7-journey-lanes`, `l2-stage`, `semantic-gate`, lane budgets, 503 shed). Present in the plane [R]; the README still lists *flow provenance / replay / token-farming protection* as later work, and earlier research concluded RETAIN_V1 with open fairness issues [M].
- **L3** = origin-local admission and kernel/network isolation. Application-level non-bypass (signed proof chain Boundary -> App) is implemented in Slice 2 [R]; **network non-bypass, kernel/network isolation (nftables/eBPF), and layers `n3.*`/`t4.*` are NOT implemented and are reported `not_measured`** [R].

Independence: `defense/` imports only its own files and `node:` built-ins [R], and the field level runs the plane on a disposable Linux VM reached directly by a /32 generator at a fixed IPv4:port [R]. No Cloudflare component is in that path. So **L1+L2 and L3-application can already be qualified without any Cloudflare filtering; L3 network isolation and L3/L4 volumetric defense cannot yet, because they do not exist** [R].
Not to be conflated: the Cloudflare Workers/Durable-Object admission Authority and the Vercel app are the *production inquiry-admission* system [R]. They need Cloudflare by construction and are outside this independent-defense qualification [I]. Please confirm that this is the intended scope split.

## 2. Smallest isolated, disposable origin environment
Two disposable Linux VMs in one provider project/VPC, plus the operator's workstation:
1. **SUT VM** (existing bootstrap [R]): Defense Plane (L1, L2) + Boundary + App + synthetic/demo submission backend; bootstrap writes the `DISPOSABLE` marker, installs a pinned Node, sets ufw (second layer) behind a VPC firewall (primary): SSH from operator CIDR only, plane port from generator /32 only, nothing for PostgreSQL.
2. **Generator VM**: one /32, reviewed closed-loop engine; no other role.
3. **Operator workstation**: runs preflight/reconcile, holds no SUT credentials on the SUT.
No load balancer, no CDN, no managed database, no NAT egress from the SUT (egress denied except package pins during bootstrap, then closed) [I].

## 3. Independent legitimate-user canary flows
Existing canary [R]: homepage (FAQ+nav) -> privacy -> form page (well-formed submission token) -> valid POST (redirect to thank-you) -> (five-step journey, byte-pinned), where a step is ok only for a 200 with expected content; **JCR (journey completion rate) must be 100% in every required group** for a qualifying level [R]. Gaps: the canary measures completion, not experience under load; see section 6.

## 4. Per-layer ingress/pass/reject/reason accounting
Existing [R]: correlated lifecycle ledger (SENT -> INGRESS_ACCEPTED -> L1_* -> EGRESS_* -> ORIGIN_* -> CLIENT_*), counters derived from records, field identities E1..E11 (ingress = terminal outcomes; L1 in = outcomes; L2 in = L1 passes; ...), reconciliation of L1 passes against origin receipts, bypass = INVALID, unexplained request / unattributed 503 = measurement STOP. Verdict classes: measurement / defense / operational.
Missing [R/M]: (a) no status allow-list per level (finding N-1: an all-route 404/503 mix was VALID in pipeline tests [M]); (b) server pair records carry no method/status/decision, so per-request attribution of shed vs pass relies on a bounded trace sample [M]; (c) campaign id limit 31 characters (N-2) [M].

## 5. Origin exposure and unexplained traffic differences
Existing [R]: continuous exposure proof (pre_bind, every tick, final): the only non-loopback LISTEN socket of the topology is the reviewed plane IPv4:port; any violation is fatal. Source ARMED barrier: any external accept before ARMED invalidates the campaign.
Add [I]: for any optional edge integration, a three-way reconciliation **edge-reported allowed = plane ingress + (named, counted) dropped-between**; a non-zero unexplained remainder makes the run INVALID. Without an edge, the generator-sent count must equal plane ingress + client-visible connection failures; the remainder is reported, never absorbed.

## 6. Resource observability
Existing [R]: 1 s /proc sampler of owned processes and host: CPU, RSS, fds vs limit, threads; host CPU, available memory, network bytes, TCP socket counts; kernel listen-overflow, listen-drop, retransmit, reset counters (labelled advisory); event-loop delay (ELD) and generator schedule-lag p99 gates.
Missing [I]: (1) bulkhead/queue occupancy time series per layer (the cap and shed counts exist; occupancy over time is not a persisted series as far as I read); (2) NIC-level packets/s and drops, conntrack usage; (3) GC pause data; (4) per-journey-step latency percentiles of the canary **during** the pressure window with a legitimate-user threshold (today's pass rule is completion); (5) provider-side quota/egress metering for cost.

## 7. Recovery and residual restriction
Existing [R]: recovery quiet period 135 000 ms in the level definition. Missing [I]: a measured *return-to-baseline curve* (canary success and p95 latency each second after load stops until two consecutive baseline-equivalent windows), and a *residual-restriction* test (a clean legitimate client previously co-located with attacker behavior, e.g. same /24 or same token pool, is still served after the quiet period). Pass criteria must be set before the run.

## 8. Cloud limits, provider policy, cost control
- Before any traffic: read the provider's acceptable-use/penetration-testing policy for the exact product and region and record the clause; keep generator and SUT in one VPC on private addresses if the policy requires traffic not to leave the provider network [I]. The existing lab policy accepts remote targets only as IPv4 literals with `disposable: true` and an expiry of at most 72 h [R]; private-range support must be checked before relying on it.
- Quotas: confirm vCPU, external-IP and egress quotas; preferred shapes are the smallest that expose the first resource limit (so the limit is reachable cheaply) [I].
- Cost controls [I]: budget alert and hard billing cap at project level; a VM-level TTL (scheduled shutdown) independent of the harness; spot/preemptible generator (stateless, restartable); stop SUT between runs but keep disk; one prebuilt image (pinned Node, pinned commit) to avoid repeat bootstrap time; teardown script verified by the existing marker logic.

## 9. Management-plane isolation and automatic stop
Existing [R]: STOP reasons (tick gaps, exposure violation, unexplained request, ceiling hit, SIGINT, target expiry, generator never started); k6/generator killed at target expiry. Add [I]: (1) management SSH reachable only from the operator /32, key-only, no agent forwarding; (2) no cloud credentials, service-account keys or metadata access on SUT or generator beyond the minimum (default service account disabled); (3) a dead-man switch: if the operator control channel misses N heartbeats the SUT stops accepting external traffic (firewall flip) and the VM shuts down at TTL; (4) cost stop: billing alert triggers a documented shutdown, not an automatic delete of evidence; (5) evidence copied off the SUT after each level before teardown (raw evidence loss made the R2 forensics inconclusive [M]).

## 10. Progressive qualification process
| Tier | What | Exit rule |
|---|---|---|
| T0 | Local loopback replay (existing, Windows/Node) | Deterministic fixtures green |
| T1 | Linux container parity (`lab:parity`) [R] | Same results as T0 |
| T2 | Two-VM N=1 plain pressure (reported VALID in the past [M]) re-run on fresh VMs with fixes P0 below | JCR 100%, all E-identities hold |
| T3 | N=2 salvo (CONDITIONAL GO earlier, one measurement [M]) | Only after P0 and a pre-registered per-pair predicate |
| T4 | **Mixed load**: legitimate canaries concurrent with the hostile corpus at fixed rates | Legit JCR + latency thresholds met while hostile rejects are attributed per layer |
| T5 | Variable load: ramps, bursts, step-downs, seeded randomization (seed recorded; reproducible replay of the schedule) | Same pass rule across 3 seeds |
| T6 | Recovery/residual-restriction tests | Section 7 criteria |
| T7 | L3/L4 volumetric — blocked until `n3.*`/`t4.*` instrumentation and isolation exist and provider policy allows | Separate approval |
| T8 | Optional edge integration, evaluated separately, credited separately | Three-way reconciliation holds |

## 11. Prioritized missing work
P0 (before any new field run): status allow-list per level (N-1); campaign id/redaction mismatch (N-2); server-side per-request method/status/decision in pair records; evidence capture off-host automation; pre-registered thresholds for legit-user latency.
P1: mixed legit+hostile level definition; queue/bulkhead occupancy series; recovery curve and residual-restriction scenarios; budget/TTL/dead-man tooling; private-address target support check.
P2: NIC/conntrack/GC metrics; seeded variable-load scheduler; edge reconciliation module.
P3: n3/t4 layers and kernel/network isolation (design first; real security-boundary work needing approval).
Each P0/P1 item that touches verdict-path files must go through the same append-only baseline migration (verdict-path files are pinned byte-identical; tests 933/1179).

## 12. First trustworthy milestone (M1)
**Re-run the N=1 external level on fresh disposable VMs after P0, with a legit-user latency threshold and a mixed hostile background at a fixed small rate, producing a VALID/INVALID verdict whose every identity is accounted.** It is the smallest step that (a) removes known evidence weaknesses, (b) tests "legitimate users succeed under adverse traffic" rather than "defense stays online", (c) needs one SUT + one generator for under an hour of load, and (d) is repeatable with the same seed. No claim of qualification follows from M1; it establishes that the measurement can be trusted.

## 13. Cost-aware budgeting (no figures invented)
Spend = (VM hours x hourly rate x 2 hosts) + external egress + disk. Plan repeated measurements as many short levels (60-120 s load, minutes of quiet) against one warm, prebuilt image; cap total load hours per milestone before starting; track actual billed cost after each tier before starting the next; keep a reserve of at least the cost of re-running the most expensive tier twice. Concrete numbers need the provider's current price list and your credit balance, which I do not have.

## 14. Decisions needed from you
1. Confirm the L1/L2/L3 definitions and that the Workers/Vercel admission path is out of this scope.
2. Approve P0 work on verdict-path-adjacent files (each is a baseline-migration event).
3. Provider and region for T2+, and whether private-address targets are acceptable.
4. Whether Cloudflare is evaluated at T8 only.

## Appendix — proposed topology (not provisioned)
```
 operator workstation (/32)  --ssh key-only-->  SUT VM            <--- plane port, generator /32 only --- Generator VM (spot, stateless)
   preflight / reconcile                         Defense Plane (L1,L2) -> Boundary -> App -> synthetic backend
   evidence pull after each level                ufw + VPC firewall; no egress after bootstrap; no service-account creds
                                                 exposure proof: only the reviewed plane IPv4:port listens non-loopback
 billing alert + hard cap (project)   VM TTL shutdown (independent of harness)   dead-man firewall flip on missed heartbeats
```

## Correction (2026-11-08, later)
Section 6 item (4) and the P0 list claimed a legitimate-user latency threshold was missing. The reviewed field level already predeclares `canary.jcrMinimum = 1` and `canary.windowLatency = { p95Factor 4, p95AddedMs 150 }`. Remaining gaps are in `QUALIFICATION-M1-DESIGN.md` section 4.
