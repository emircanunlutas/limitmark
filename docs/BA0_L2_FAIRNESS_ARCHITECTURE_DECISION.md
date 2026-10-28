# BA0 L2 fairness: architecture decision study

Status: **design study only.** No production code, threshold, fingerprint, evidence or verdict was changed. Base: `ba0-n2-progression` (`8b45d05`).
Input: `docs/BA0_L2_CREDITED_LANE_CHARACTERIZATION.md` and `tests/defense-l2-credited-lane-characterization.test.ts` (V1 behavior, pinned, and it must stay pinned).

**Reading guide.** Statements marked *(measured)* come from that characterization. Statements marked *(code)* come from reading `defense/`. Everything else is analysis or a
hypothesis, and says so. Nothing in this document is evidence that a proposed mechanism works; Section 8 defines the experiment that would be.

## 0. The result in five lines

1. The starvation *(measured)* is caused by **attempted** credited requests draining one global bucket (V1: 10 at 2/s) that has no allocation rule, while credit is **free to mint**.
2. A small shared budget cannot be protected by a per-credit *cost* alone: the attacker only needs to sustain the refill rate (2/s), so even an expensive credit is cheap in aggregate.
3. Without a trusted identity or a signal that is costly to multiply, **no allocation rule can promise per-actor fairness.** What can be promised is conditional and cost-denominated (Section 1).
4. The only candidate that attacks the measured mechanism directly and needs no external service is **per-class admission ceilings keyed by a hint the attacker pays to multiply** (Approach A). It reverses the
   rule "the sender is never an input", so it is an owner decision, not an engineering one.
5. Recommendation: do not implement anything yet. Start with a shadow (non-enforcing) measurement stage that costs nothing in behavior, then decide (Section 6).

## 1. A guarantee we could realistically make

Three layers of statement, strongest last, each strictly weaker in who it covers and stronger in what it promises:

- **G0 exposure (exists, V1, unchanged).** For every lane and window T, admitted mutations are at most capacity plus refill times T. Nothing below may weaken it; an approach that cannot prove it keeps G0 is rejected.
- **G1 attacker-cost denial (proposed, needs no trusted identity).** *Denying service to a legitimate journey requires the adversary to hold, at the moment of denial, a resource whose acquisition rate it controls and
  we can state in units (distinct network classes, or attested credits).* The guarantee is the **price list**, not an availability promise: "to take fraction f of credited capacity you need at least m(f) classes / a(f) attestations".
- **G2 conditional continuity (proposed, calibrated by experiment only).** *If the adversary occupies at most m of the classes (or attested credits at most a per second), then a legitimate journey outside them completes with
  probability at least 1 - epsilon, provided aggregate legitimate demand stays below a stated fraction of the remaining capacity.* Outside that condition it degrades to V1 behavior, never below the G0 exposure bound.

What is **not** promised in any layer: that legitimate users never perceive an attack; protection against volumetric load; a guarantee for users who share a network class with the attacker; any guarantee against an adversary
that can mint network classes or attestations faster than the stated price. The desired product outcome ("users do not perceive an ongoing attack") is a **hypothesis (H*)** to be tested, not a claim.

### What cannot be guaranteed without a trusted identity or a meaningful per-actor cost

Let S be the requests the allocator cannot tell apart with the signals it has. If an adversary can emit members of S faster than the budget refills, legitimate members get at most about d/(d + lambda) of the budget
(d legitimate demand, lambda attacker rate), whatever the policy. Per-token fairness, fair queueing across tokens, lotteries and dwell times all fail the same way *(analysis)*: the attacker mints tokens in proportion to what
it wants, and a poll-rate race merely becomes a ticket-count race. Our budget is also small (2/s), so the **aggregate** cost of monopolising it is small even when each credit is expensive: at one CPU-second per credit the
attacker needs about two cores. Fairness therefore needs a *partition the attacker cannot multiply for free* (identity, attestation, or a network class), or *abundance* (capacity far above anything an attacker will pay for).

## 2. Signals: what can distinguish independent journeys from a farmer

| Signal | Spoofable by the stated adversaries | Privacy | Shared-network false rejects | Operational cost | External dependency |
| --- | --- | --- | --- | --- | --- |
| Network class of the TCP peer (keyed /24, /48 hash) | Cost-bearing, not forgeable past the handshake; **rotatable** (proxies, IPv6) | Personal data (IP), but processable as an in-memory keyed hash that is never logged | **Yes** (CGNAT, offices, mobile carriers) | Low: fixed memory | None; **wrong behind a proxy/CDN** unless a trusted forwarding chain exists |
| Cookies / session continuity | Free (retain cookies) | Medium; **blocking cookies must not be penalised** (see PRIVACY_BLOCKER_AUDIT) | Low | Low | None |
| Dwell time between render and POST | Free (pre-mint in parallel) | Low | Low | Low | None |
| Header or TLS fingerprint (UA, JA3/JA4) | Trivial | Medium (fingerprinting) | Medium | Medium | None |
| Credit mint rate and concentration | Observable only; attacker shapes it | Low | Low | Low | None |
| Proof of work per credit | Paid in CPU, parallelisable | Low | Low (slow devices) | Medium (client JS) | None |
| Interactive or invisible challenge | Solver farms exist (not measured here) | Medium | Low | Medium | Usually yes |
| Attestation token (Privacy Pass style, Turnstile-like, platform attestation) | Cost per token, issuer-dependent | Low to medium | Low | Medium | **An issuer is required** |
| Behavioral signals (pointer, timing in browser) | Replayable; bot frameworks emulate | **High** | Medium | High | Often |
| Out-of-band confirmation (email link before the mutation executes) | Needs real mailboxes | Low | None | Application change, not L2 | Mail delivery |

Two facts from the repository constrain this table. L2 is today deliberately sender-blind (*code*, `defense/README.md`: "no IP, no connection identity, no ban"). The form already carries a `cf-turnstile-response` field that L1
permits (`a7-shape-gate.ts` `ALLOWED_FORM_FIELDS`), but L2 never reads it. The repository also commits to **not penalising privacy tools** (`PRIVACY_BLOCKER_AUDIT.md`: "no privacy-tool detection or bypass"),
which rules out any mandatory signal that depends on cookies, scripting or fingerprint availability.

## 3. Reserved legitimate capacity: is it feasible?

A reserved pool is claimable by whoever satisfies its eligibility predicate, so feasibility reduces to whether the predicate is costly to satisfy at the attacker's needed rate. Candidate predicates:

- **Cookie/continuity/dwell/returning-visitor credentials**: satisfiable at no cost, and a returning-user credential is minted by an admitted mutation, which the attacker also obtains at up to the refill rate. **Not feasible.**
- **A fixed fraction per network class** (a floor): feasible, but with a pool this small it dilutes burst tolerance. Worked example, *rough Poisson/loss-system estimate, not validated*: 8 classes, floor 0.125/s and capacity 1 each,
  legitimate demand 0.25/s spread evenly: about one arrival in five finds its class bucket empty. Floors therefore force the budget **up**, which loosens G0.
- **Attested credits**: feasible, and the attacker's claim rate equals its attestation rate (Approach B).
- **A ceiling on any one class** (rather than a floor for each): feasible, adds only restriction, and leaves the unclaimed remainder as a shared pool. This is the form recommended in Approach A.

## 4. Approaches

All four are **additive restrictions or additional pools around the unchanged V1 bucket**: a request needs the existing credited token as before, and the new element can only shed more or add a separate pool. Where this
document says "check, then take", the check is non-mutating and the takes are one synchronous step, so P1 (no spill between credited and unverified) and P3 (no refunds) keep their current meaning. Anything that cannot be
stated that way is called out as a semantic change and needs its own review; none is introduced silently.

### Approach A: per-class admission ceilings on a fixed keyed array (contention-gated)

*Mechanism.* Hash a **non-authoritative** network class (peer address truncated to /24 for IPv4, /48 for IPv6; a per-epoch random key; never logged or persisted) into one of S fixed class buckets (for example S = 1024; fixed
memory, no allocation per request, no table to exhaust). Each class bucket has a ceiling (for example phi times the credited refill, phi = 1/8, so 0.25/s). **Under contention only** (global credited level below a threshold),
a credited request must find a token in its class bucket *and* in the global bucket (check both, then take both). A class-ceiling shed is a new shed reason; it does **not** consume a global token.

*Why it addresses the measured mechanism.* V1 starvation comes from the farmer's *attempted* credited takes draining the global bucket. With a ceiling, the farmer's attempts beyond its class ceiling are shed **before** they
touch the global bucket, so global consumption by one class is at most phi times the refill. *(Measured anchor: at a farmer admission rate below the refill, V1 already serves every legitimate journey: farmer at 1.0/s and 1.9/s
gave 30/30.)* Prediction **H1** (falsifiable): a 4/s farmer in one class leaves legitimate success in other classes within noise of the no-attacker control.

*Adversarial analysis.*
- Single host, cookies, challenge-free (the characterized farmer): attempts capped at phi x refill; **defeated** if H1 holds.
- Address rotation across P classes: attacker's credited throughput is min(P x phi, 1) x refill. It needs **1/phi classes (8)** to take everything. For IPv4 /24s via residential-proxy pools that is cheap; for IPv6 a single
  allocation often contains thousands of /48s. Result: **degrades to V1**, never below it, at a price in classes that we can publish (G1).
- Challenge solving: irrelevant to this approach (it uses no challenge).
- Collision attack on a victim: the key is secret and rotates each epoch, so the attacker cannot choose to share a bucket with a given victim; it can only occupy m of S buckets, harming a fraction of about m/S of legitimate classes
  while contention lasts.
- State exhaustion: none (fixed array). Key leakage: only reveals which of the attacker's own addresses share a bucket.

*Trade-offs.* Security: strictly additive restriction, G0 can only improve. Availability: legitimate users **sharing a class with a heavy sender** are capped at phi x refill while contention lasts (CGNAT, large offices,
mobile carriers). **Behind a proxy or CDN the peer address is the proxy's**, so every user would share one class and the ceiling would throttle all of them: the mechanism must be off, or driven only by a trusted forwarding
configuration, in that topology. Do **not** adapt automatically ("if traffic concentrates, switch it off"): that gives the attacker a switch. Complexity: moderate (new shed reason, new accounting identity, one new input to the
decision function: the only change that reverses the sender-blind design rule).

### Approach B: attested reserved pool (issuer pluggable, default off)

*Mechanism.* Reserve a fraction R of the credited refill (for example 1/s of 2/s) for credits enrolled with a **single-use attestation** (one attestation, one credit, bound to the journey token). The verifier is an
interface with three implementations: `none` (pool disabled, V1 behavior), a **deterministic local issuer** (HMAC-signed, used only by the laboratory, so the allocation logic is testable without any provider), and optional
real issuers chosen by the operator. No provider is assumed available; if the issuer is down, the pool simply cannot be claimed and the lane behaves as V1.

*Adversarial analysis.*
- Single host: cannot claim the pool without attestations; the open pool (the other half) is still farmable, so **continuity is guaranteed only for attested journeys**.
- Address rotation: irrelevant (attestation is the scarce resource).
- Attestation solving: the attacker can exhaust R at the rate it can obtain attestations; the price is the issuer's, not ours (G1 in units of attestations). Commercial solving services exist; I have **not** measured
  current prices, so no cost figure is claimed.
- Replay of an attestation across journeys: prevented by single-use binding to the token (a new state: a used-attestation set that must be bounded and fail closed, like the use ledger).

*Trade-offs.* Security: a real, issuer-denominated price on the pool; leaves the open pool unprotected. Availability: legitimate users must obtain an attestation (usually invisible in good issuers, but the product
promises not to penalise privacy tools: an attestation scheme that fails for them is unacceptable). Complexity: medium to high; client integration (the form already has a Turnstile field, so a widget exists in production,
but the BA0 stand-in does not), and a dependency story for the real issuer. Deployment cost for customers: low when an issuer exists, otherwise unavailable.

### Approach C: priced mint with adaptive proof of work, plus higher credited capacity ("abundance")

*Mechanism.* Bound credit enrollment (a mint bucket; new state sized like the use ledger) and make each credit require a small client puzzle whose difficulty rises with the mint rate; raise credited capacity so that the
attacker's required mint rate is high.

*Adversarial analysis.*
- Single host: pays CPU. At the current budget the cost to monopolise is rate x puzzle cost = roughly 2 x c; a puzzle a mid-range phone can finish unnoticed is cheap for a server-class attacker. **Not defeated; priced low.**
- A bounded mint bucket **moves the starvation to the render side** (the farmer exhausts the mint bucket, legitimate renders get no credit and fall to the unverified lane).
- Adaptive difficulty makes legitimate users pay *during* an attack, which contradicts H*.
- Address rotation and cookies: irrelevant. Solving: the intended attacker input.

*Trade-offs.* Weakest security-per-complexity; real client cost; raising capacity raises the exposure bound G0 (a new threshold set). Useful only as a **supplement** (headroom plus telemetry), not as the primary mechanism.

### Approach D: decouple admission from execution (admit, then defer or quarantine)

*Mechanism.* Raise the admission bound and execute mutations from a bounded, rate-limited deferred queue with triage (the repository already lists "any quarantine lane" as not implemented). The scarce budget becomes
*execution capacity*, which is large and cheap relative to a form submission, so the scarce shared admission budget disappears for ordinary load.

*Adversarial analysis.* It does not change who wins a contest; it removes the contest at today's scales. A well-funded attacker simply moves the contest to the queue (a **new shared budget**), and a deferred queue adds
a delivery-latency hazard for legitimate inquiries and a new place to lose or duplicate work. Single host and rotation: defeated *at current rates*, not in principle. Solving: not relevant.

*Trade-offs.* Changes what "mutation executed" means, therefore the origin's accounting (the O2 identities), P3's meaning for deferred work, and every historical claim about exposure. Highest redesign cost; not recommended as
the first step.

### Not viable as the *basis* of a guarantee (usable only as telemetry or UX)

- **Cookie/session continuity and dwell time**: free for any adversary that "renders pages and retains cookies"; they also penalise cookie-blocking users.
- **Header/TLS fingerprinting and behavioral signals**: spoofable and privacy-invasive.
- **Out-of-band email confirmation**: a genuine per-actor cost, but an application-level product change, not an L2 allocation rule.

## 5. Comparison against the adversary model (all rows are analysis, not measurement)

| Adversary | Approach A (ceilings) | Approach B (attested pool) | Approach C (priced mint) | Approach D (defer) |
| --- | --- | --- | --- | --- |
| T1 renders, keeps cookies, one address (the characterized farmer) | Defeated if H1 holds | Open pool still farmable; attested journeys protected | Cost small; not defeated | Defeated at current rates |
| T2 as T1 plus address rotation (P classes) | Needs 1/phi classes to reach V1; below that, partial | Unaffected | Unaffected | Unaffected |
| T3 as T1 plus challenge/attestation solving (rate s) | Unaffected | Pool lost when s reaches R | Pays puzzle cost | Unaffected |
| T4 all of the above | V1 behavior | Pool lost at cost s x price | V1 behavior at higher cost | Contest moves to the queue |
| Legit user behind the attacker's network class | **Collateral false rejects** (capped at phi x refill) | None | None | None |
| Legit user with privacy tools | Unaffected | Depends on issuer | Needs script support | Unaffected |
| Needs an external provider | No | Optional, pluggable | No | No |
| Weakens G0 | Never (strictly additive) | No (separate pool, budgeted inside the bound) | Raises it if capacity rises | Redefines it |

## 6. Recommendation

**Primary: Approach A, enforced only after a measurement stage, conditional on an owner decision to allow an *untrusted* network-class hint** (explicit non-claim: the hint is never assumed trustworthy, and in the worst case
the behavior is V1). It is the only candidate that attacks the measured mechanism, is deterministic, needs no external service or customer installation, uses fixed memory, and can only restrict.

**Optional upgrade: Approach B**, off by default, added later where an operator accepts an issuer, because it is the only way to raise the price beyond "number of network classes".

**If the owner declines any sender-derived input:** use B where an issuer is acceptable; otherwise **do not claim continuity** and keep V1 with documented non-claims. The cost-free measures that still help are:
a mint-concentration alert, `Retry-After` with jitter on the credited-lane 503 *(the characterization shows retry helps against slow pollers but not fast ones: 29/30 vs 0/30)*, and capacity re-sizing as a new, versioned threshold set.

**Rejected as primary:** C (cheap for the attacker at this budget, makes legitimate users pay during attacks), D (changes the meaning of exposure), and every signal in the "not viable" list.

## 7. Staged implementation and test plan (nothing here is started)

| Stage | What | Gate to continue |
| --- | --- | --- |
| S0 | Owner decisions in Section 9 (sender hint, topology, issuer, legitimate demand data) | Written decision; **no code before it** |
| S1 | **Shadow mode**: compute class assignment and the *counterfactual* ceiling decision for every credited request, record counters only, enforce nothing. Observe-only telemetry: mint rate, mint concentration, counterfactual sheds | V1 byte-identical behavior proven by the existing guards plus a new "shadow changes nothing" differential test |
| S2 | Pure state-machine model and exhaustive/property tests outside `defense/` (invariants: G0 holds, ceiling never raises admissions, P1 and P3 unchanged, exact accounting, state fixed) | Model checked; no counterexample |
| S3 | Deterministic virtual-time evaluation (Section 8, layer 1) with pre-registered thresholds | All pre-registered criteria met, including H1; otherwise stop |
| S4 | Implementation behind a **new versioned threshold set (V2)**, feature off by default, reviewed-patch registry entry; V1 arms re-run unchanged | V1 fingerprints and INVALID verdict tests unchanged; reviewed change recorded |
| S5 | Loopback laboratory arms (layer 2) with real plane processes and the attacker matrix | Evidence passes the existing accountant and scanner; no unexplained traffic |
| S6 | Optional Approach B behind the interface using the deterministic local issuer | Same criteria; no external service |
| S7 | Authorized disposable-host level (the existing BA0 field process) | Separate authorization |

Any stage can be the last one: stopping after S1 still yields the data needed to document the limitation honestly.

## 8. Deterministic laboratory evaluation

**Layer 1: virtual time.** Extend the existing harness (real `JourneyLanes`, injected clock; the new mechanism as a model outside `defense/` until approved). Seeded arrivals only; no `Math.random`.
Matrix: attacker rate in {1, 2, 4, 8, 20, 100}/s; attacker classes P in {1, 4, 8, 16, 64, 1024}; solving rate s in {0, 0.5, 1, 4}/s; attacker jitter in {0, 5, 50} ms; legitimate demand in {0.1, 0.25, 1}/s; shared-class
fraction (legitimate users in the attacker's class) in {0, 10, 50} %; legitimate client retry in {none, 1 s, 20 ms}. Record per cell: legitimate first-attempt and eventual success, time to complete, **attacker credited
admissions (exposure)**, attacker cost units (renders, classes, attestations), false rejects by cause (class ceiling, global bucket, unverified), memory high-water, **quiescent-state digest equality after recovery**
(the existing digest), and residual state (must be none; there are no bans).

**Layer 2: loopback, real processes** (the existing collapse-run infrastructure): the F3 farmer profile concurrent with canary journeys *and* page browsing, with the existing per-layer accounting identities plus two new ones
(sum of class counters equals lane counters; class admissions never exceed their ceiling). Report p50/p95/p99 of legitimate latency, 429/503 and shed counts by reason, challenges shown (zero unless Approach B is on),
attacker admissions and origin exposure, resource pressure (event-loop delay, RSS), recovery time, and any unclassified traffic (must be zero).
Evidence-writing must follow the redaction scanner rules (no `token`, `ip`, `url`, `host` keys; use `credits`, `class`, `prefixClass`).

**Pre-registered criteria (proposals for the owner to fix before running).** (1) Exposure: attacker credited admissions never exceed V1's bound. (2) H1: legitimate first-attempt completion in the 4/s single-class cell
is within 2 percentage points of the no-attacker control. (3) Graceful degradation: completion never falls below the V1 value in the same cell. (4) False rejects for users in other classes at or below 1 %. (5) Recovery to the quiescent digest within two epochs.
(6) Reads: browsing latency under attack within a stated margin of baseline. **H*** ("users do not perceive the attack") is claimed only if all hold with the matrix above; otherwise the report states which cells fail.

## 9. Unresolved questions and non-claims

**Questions that block S0**
1. Are you willing to add an *untrusted* network-class hint to L2, knowingly reversing "the sender is never an input", given that the hint is never trusted and the worst case is V1?
2. What is the deployment topology: direct to the plane, or behind a proxy/CDN? Is any forwarding header from a trusted hop available? Without it Approach A must stay off.
3. Is any attestation issuer acceptable, and which? (The form already has a Turnstile field; the repository's own production path depends on a third party, which this study does not assume.)
4. What is the real legitimate mutation demand? The 2/s credited refill and the 0.25/s legitimate rate used here are lab parameters ("provisional-uncalibrated"), not data.
5. May V2 raise capacity (a looser G0), and by how much?
6. **Browsing and assets.** L1's route list is a closed five-route set (`a7-shape-gate.ts` `ROUTES`), so the plane today does not pass static assets. I did not run an asset request through it. The acceptance criterion "asset loading"
   cannot be evaluated until the product scope of the plane is decided; reads are `open` and unbudgeted at L2 by construction, so L2 credit farming cannot starve them, but read-flood resistance is explicitly not claimed.
7. IPv6 granularity (/48 versus /32) trades attacker cost against collateral and needs data.
8. Privacy and legal review of transient keyed class hashing. This study gives no legal conclusion; the design stores nothing persistent, but it does process an address.
9. Does the real form retry on 503? Not inspected; it determines how much `Retry-After` helps.
10. Is a new shed reason acceptable under the closed `SHED_REASONS` vocabulary and every accounting identity that enumerates it? It is a reviewed change, not a rename.

**Non-claims.** No claim that any approach works, that legitimate users will not perceive an attack, or that G2's epsilon can be met: that requires the Section 8 evidence. No per-user fairness, DDoS resistance, bot detection,
read-flood resistance or protection of the real application. No protection against an adversary that can mint classes or attestations at the stated rates. The BA0 V1 documented non-claims, its thresholds, fingerprints
and the INVALID verdicts remain exactly as they are, and the V1 characterization test must keep passing unchanged.


## Errata and qualifications (appended after the V2 shadow evaluation; the results above are unchanged)

See `docs/BA0_L2_V2_SHADOW_EVALUATION.md` section 1.

1. The NOT_CLAIMED list in `lab/defense/ba0-collapse-run.ts` is not individually pinned for the string "protection against a stateful automation that renders and then posts, beyond the stated credited-lane bound". The contract test pins the phrase list containing "per-user fairness", and the collapse-run tests only require that evidence `notClaimed` equals the exported list. "Pinned by a test" above should be read with that limit.
2. "(measured)" means output of a deterministic virtual-time simulation, not a live-plane measurement.
3. The V1 characterization used one legitimate client at a fixed phase; the V2 matrix uses Poisson and periodic arrivals over several seeds.
4. The contention-gate threshold was unspecified in the decision study, and its H1 prediction applied to an ungated per-class ceiling. The shadow evaluation shows ungated ceilings fail the shared-network hypothesis (H2).
