# BA0 L2 — V2 Architecture Alternatives: Fair Share vs Attested Pool

Status: **research only. No production change is proposed or authorized.** Version label of every model here: `l2-alt-research-experimental-1`.
Base: `ba0-n2-progression` @ `8b45d05` (working branch `fix/p0-02-expiry-horizon`, identical tree). Nothing under `defense/`, `artifacts/`, `lab/` or `src/` was modified; nothing is committed.
Code: `tests/support/l2-alt-model.ts`, `l2-alt-matrix.ts`, `l2-alt-scenarios.ts`; pinned results: `tests/defense-l2-alt-architectures.test.ts`.
Earlier work, unchanged: `docs/BA0_L2_CREDITED_LANE_CHARACTERIZATION.md`, `docs/BA0_L2_FAIRNESS_ARCHITECTURE_DECISION.md`, `docs/BA0_L2_V2_SHADOW_EVALUATION.md` and their tests.

## Decision: FURTHER RESEARCH REQUIRED

Neither candidate can be recommended for design on the evidence available, and the two fail for different reasons:

- **Max-min fair share (A) cannot be called fairness.** Its share goes to an *identity key*, and every key an L2 arbiter can see is cheap or free for an attacker to multiply. Keyed by credit token it is identical to V1; keyed by session it collapses with 64 sessions (4% legitimate success at 100/s); keyed by network class it degrades smoothly with the number of classes (57% at 16, 33% at 64) and gives nothing to users who share the attacker's class. It also never restores the no-attacker control (80%) and costs a shared network near saturation up to 8 points (class 6, hierarchical 8, session 3).
- **The attested pool (B) is the only evaluated approach whose benefit does not depend on identity multiplication** (88% at 64 classes, 86% at 100/s with 64 sessions, 91% for users inside the attacker's class), and it never raises exposure above V1. But its guarantee is conditional on a number this simulation cannot supply — how fast an attacker can obtain attestations relative to the reserved refill (0.2 / 0.4 / 0.8 per second for a 10 / 20 / 40% reserve) — and on accessibility (the benefit is capped by the share of users who can attest). It also fails two pre-registered criteria for every variant: it does not restore the control within 5 points, and with the issuer unavailable the idle reserve makes legitimate users worse off than V1 (97% → 86% for a 20% reserve, 66% for 40%, at demand 1.9).
- **RETAIN V1** remains the correct posture until the open questions below are answered. It is not the recommendation because the starvation is real and one approach (B) is plausibly addressable, but the documented non-claim ("per-user fairness") stays exactly as it is.

What would change the decision: (1) a measured acquisition-cost curve for a concrete attestation source (sustained rate an attacker can reach vs 0.2 to 0.8 per second); (2) measured accessibility (the result needs it near 100% to restore the control); (3) an evaluation of the pool *combined* with a class ceiling (not evaluated here); (4) a design for a shared spent store or instance-bound attestations (without it a double spend halves the attacker's price per reserved admission). If (1) or (2) is unfavourable the recommendation becomes RETAIN V1 AND DOCUMENT LIMITATION.

All numbers are the output of a deterministic simulation (virtual clock, seeded arrivals). "Measured" never means measured on a live plane.

---

## 1. Phase 1 — Threat model

Everything below is an input the arbiter receives. None of them identifies a human, and none is assumed to.

| # | Attacker capability | Modeled as | Scenarios |
|---|---|---|---|
| T1 | Unlimited ordinary credits | Every farmer POST carries a fresh genuine credit (a free render mints one), rate 1 to 100/s | D1 (all) |
| T2 | Shares an address or network class with legitimate clients | Legitimate clients placed in the farmer's class; or 8 clients behind one NAT with the farmer elsewhere | D3 |
| T3 | Rotates across network classes | 4 / 16 / 64 classes; an adaptive attacker that gains a class per shed, no faster than 0.5 classes/s | D2, D4 |
| T4 | Maintains many independent sessions | 8 / 64 session labels (free); adaptive spreader up to 256 | D2, D3, D4 |
| T5 | Acquires or solves attestations at a configurable rate | 0.1, 0.5, 2, 10, 100 per second; single-use, valid 60 s; optional replay to several verifiers | D5, D5b |
| T6 | Adapts timing to the policy | 2.1/s (just over the refill), 4/s with ±50 ms jitter, 20/s on/off, retrying legitimate clients | D4, D7 |

Not assumed: that a class, a session or a credit is a unique person; that any hint is authentic; that the plane sits behind a CDN or trusted proxy; that an external issuer exists. Not modeled: an attacker that tunes its attestation spend to legitimate demand, an attacker that compromises the issuer, human behaviour, L1, real clocks and networks.

## 2. Phase 2 — What can receive a fair share?

A fair share needs a *key*; the share is only as fair as the key is expensive to multiply. The arbiter sees four candidates:

| Key | Cost to create another | What a sample attacker gets | Measured (4/s farmer unless stated; V1 = 5%) | Verdict |
|---|---|---|---|---|
| Credit token | Zero: each render mints one, and fresh keys always start with a full bucket | Every POST is a new entity | **5%** (= V1); 0% at 100/s | No fairness at all |
| Session label | Zero; L2 takes no session input today, so this would be a new client-supplied input | N sessions = N shares | 80% with 1 session, 69% with 8, **35%** with 64; **4%** with 64 at 100/s | Fairness claim fails |
| Network class (peer-derived) | Unknown: IPv6 prefix rotation, proxies, botnets | C classes = C shares | 80% (1), 74% (4), 57% (16), **33%** (64); at 100/s, 30% with 16 classes | Graceful loss, no guarantee; nothing for users inside the attacker's class (3%) |
| Hierarchy: class → session | Classes cost something; sessions inside a class are free | C shares, then free sessions inside | 61% at 16 classes; users inside the attacker's class: 63% against 1 session, **24%** against 64 | Protects between classes only |
| No identity (probabilistic thinning ∝ attempts) | Attempts are free | Share ∝ attempt rate | 46% at 4/s, **3%** at 100/s | Helps only against slow farmers (breaks phase lock); cannot scale |

Rule applied: where an attacker can obtain more shares cheaply, **no fairness is claimed**. That is every row. Max-min fair share is therefore an *allocation rule*, not a fairness guarantee; what it can honestly promise is "no single key takes more than the water level while demand exceeds the refill".

## 3. Phase 3 — Attested pool feasibility

**Model.** The V1 credited capacity (10 at 2/s) is *partitioned*, never raised: a 10 / 20 / 40% reserve is a general bucket plus a reserved bucket whose capacities and refills sum to V1's (9+1, 8+2, 6+4; 1.8+0.2, 1.6+0.4, 1.2+0.8 per second). A request that carries a valid, unspent, unexpired attestation takes from the reserved bucket; if that is empty it falls back to the general bucket and the attestation stays unspent. Any other request uses the general bucket. A refusal consumes no token and no ledger use (P1/P3). Attestations are HMAC-signed, expire after 60 s, and the verifier keeps a bounded (512) spent set that fails closed to the ordinary path when full. Forged, tampered, expired and replayed attestations are pinned in the test as never reaching the reserved bucket.

**Two issuers, evaluated separately.**

| | Local deterministic issuer (LDI) | External provider |
|---|---|---|
| Signal available | Only rules computable by the server: a rate rule keyed by the (rotatable) class (here: 1 per class per 10 s, plus the reserved refill as a global cap) | A cost or a proof the server cannot produce itself |
| What it proves | Nothing about the requester: it is Approach A's per-class rate limit moved earlier | Whatever the provider's price or challenge costs the attacker |
| Measured | 81% single class; **25%** with 16 classes (the attacker exhausts the global issuance); NAT near saturation 91% (−7 points vs V1); NAT with attacker elsewhere 18% | 84% (20% reserve) and 88% (40%) at 4/s; independent of class and session counts |
| Verdict | Adds nothing over a class ceiling and fails shared networks; inherits the class-rotation weakness | The only configuration whose benefit survives identity multiplication; its value is entirely the provider's cost curve and accessibility |

The external provider is modeled only by parameters (acquisition rate, accessibility, latency, availability); no real provider was evaluated or contacted, and none is assumed to exist.

**Costs and limits measured** (details in §5):

- *Attacker acquisition rate.* A 20% reserve (0.4/s) holds at 0.1 attestations/s (76%) and is exhausted at 0.5/s (22%); a 40% reserve (0.8/s) holds at 0.5/s (91%) and is exhausted at 2/s (32%). Beyond that legitimate users sit at 12 to 13% (above V1's 5%, because the smaller general lane breaks the phase lock) and the attacker is back at 245 admissions (V1: 248). Exposure never exceeds V1.
- *Accessibility.* If half the users can attest: 48 to 54%. If none can: the reserve is wasted and service is V1-like or worse (5 to 19%).
- *Latency.* 0.8 s default, 5 s tested: 5 s costs a 20% pool almost nothing in success (82%) but every attested journey pays the full delay.
- *Missing issuer.* The reserve idles. No attacker, demand 1.9: V1 97%; 20% reserve 86%; 40% reserve 66%; the overflow variant (a non-attested request may borrow a reserved token only while the reserved bucket is full) recovers part of it (91%), is still about 6 points below V1, and gives the attacker part of the reserve back (81% vs 84% at 4/s).
- *Multiple verifiers.* With per-instance spent sets an attestation spent at both of 2 instances is admitted twice: 49 double spends against 98 reserved admissions in the replay scenario; a shared spent set: 0. The reserved bucket still bounds exposure (98 reserved attacker admissions either way), so a double spend halves the attacker's price per reserved admission rather than raising capacity.
- *Reserve cost under attack.* With nobody attested, a 40% reserve leaves total credited admissions at 172 against V1's 249: lower exposure, but unused capacity.

## 4. Method and disclosures

**Variants (fixed grid; every point reported):** V1 (the real `JourneyLanes`); Approach A (`always`, `gated`, and the post-hoc `gated-low`, marked `*`, reference only, not approved); fair share keyed by token, session, class, class→session; probabilistic thinning; pool 10 / 20 / 40% with an external issuer; pool 20% with overflow; pool 20% with the local issuer; plus two 2-instance pool variants used only in D5b. All constants were fixed before the evaluation and not tuned: 1024 slots, demand window τ = 10 s, water level recomputed every 250 ms, per-entity bucket capacity 2 (fresh keys start full), attestation TTL 60 s, spent set 512, external issuer defaults accessibility 0.9 / latency 0.8 s / timeout 2 s.

**Scenarios:** 47 cells (blocks D1 to D7) × 14 variants × 3 evaluation seeds (211, 223, 227) × 120 s of virtual time; legitimate clients are Poisson, 64 independent clients unless a NAT is stated; credit is one free render per POST. Each variant is the sole decider of a closed-loop run over the same generated stream (no shadow world, so no open-loop bias).

**Pre-registered criteria** (`ALT_CRITERIA`, written before the first evaluation run):
K1 continuity — where V1 ≤ 0.80, improve ≥ +0.20 *and* come within 0.05 of the no-attacker control (single identity, rates 2/4/100, slow 2.1/s, 50 ms jitter); K2 shared networks — no attacker, success ≥ V1 − 0.02 (NAT demand 1 and 1.9, NAT with attacker elsewhere, demand 1.9 and 3); K3 exposure — capacity identities exact in every cell and attacker admissions ≤ V1 + 5; K4 free identities — with 8 and 64 free sessions still ≥ V1 + 0.20; K6 optional issuer — issuer down: success ≥ V1 − 0.02. K5 (class multiplication) and the attestation economics are report-only curves, not pass/fail.

**Disclosures.**
- Dev seeds (1, 2, 3) were used only to check that the harness runs and its identities hold; that found a reason-code mapping error (`class_ceiling` counted as a global shed) and a legitimate-population default (one client putting every journey into one class), both fixed before the evaluation.
- After the first evaluation run, while reading its results, I found two harness errors: attacker attestations were minted on the wrong clock base (they were expired on arrival, so the whole attacker-acquisition sweep was invalid), and a class-rotating attacker reused one session label (flattering per-session fairness in the class-rotation cells). An evaluator also crashed on the 2-instance cells. All three were fixed with **no parameter change** and the evaluation was re-run once. A diff of the two runs shows changes only in the 20 cells that use attacker attestations or class rotation; no pass/fail verdict moved. The first run's attacker-acquisition rows are discarded.
- Two post-hoc diagnostics were run on the dev seeds only and are **not** part of the decision: raising the fair-share burst cap (cap 10 restores NAT demand 1.9 to 98% but halves single-identity continuity to 50%; cap 4 gives 69% and 96%) and raising accessibility (a 20% pool reaches 87% and a 40% pool 100% only at 100% accessibility). They show the fair-share NAT penalty is a burst-cap trade-off rather than a bug, and that restoring the control needs near-total accessibility.
- `A gated-low*` is the post-hoc candidate from the previous study; here it is a reference column, evaluated on seeds and criteria it was not chosen on.
- The K1 restore tolerance (0.05) is new to this study (0.02 previously); for the pools the default accessibility (0.9) caps the result near 0.9 by construction, so K1 restore failing for a pool is partly a property of the setting, and is reported as such, not as a defect.
- Differences of one or two points across 3 seeds are noise.

## 5. Results

### 5.1 Pre-registered criteria (pass / fail)

| Variant | K1 continuity | K2 shared networks | K3 exposure | K4 free identities | K6 optional issuer |
|---|---|---|---|---|---|
| V1 | fail (baseline) | pass | pass | fail (baseline) | pass |
| A always | pass | **fail** (26%, 14%) | pass | pass | pass |
| A gated | pass | **fail** (95.1% vs 97.2%, −2.1, narrow) | pass | pass | pass |
| A gated-low* | pass | pass | pass | pass | pass |
| FS token | fail (= V1) | pass | pass | fail (= V1) | pass |
| FS session | fail | **fail** (94% vs 97%) | pass | **fail** | pass |
| FS class | fail (80%) | **fail** (91% vs 97%) | pass | pass | pass |
| FS hier | fail (80%) | **fail** (90% vs 97%) | pass | pass | pass |
| thin | fail | **fail** (65% vs 68% at demand 3) | pass | fail | **fail** |
| pool 10% | fail | pass | pass | pass | **fail** |
| pool 20% | fail | pass | pass | pass | **fail** (86% vs 97%) |
| pool 40% | fail | pass (95.4% vs 97.2%, −1.8, narrow) | pass | pass | **fail** (66% vs 97%) |
| pool 20% overflow | fail | pass | pass | pass | **fail** (91% vs 97%) |
| pool 20% local issuer | fail | **fail** (91% vs 97%) | pass | pass | pass |

K3 holds for every variant: credited admissions never exceed 250 and no variant admits more than 5 extra attacker requests over V1 in any cell. No variant passes everything except the post-hoc `gated-low*`, which is a class-keyed ceiling and is defeated by class rotation (below).

### 5.2 Comparative results (legitimate journey success, mean of 3 seeds)

| scenario | V1 | A always | A gated | A gated-low* | FS token | FS session | FS class | FS hier | thin | pool 10% | pool 20% | pool 40% | pool 20% ovf | pool 20% local |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| no attacker (control) | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| farmer 2/s, 1 identity | 34% | 100% | 100% | 100% | 34% | 98% | 98% | 97% | 89% | 82% | 87% | 89% | 84% | 92% |
| farmer 4/s, 1 identity | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 63% | 84% | 88% | 81% | 81% |
| farmer 100/s, 1 identity | 0% | 100% | 100% | 99% | 0% | 76% | 76% | 76% | 3% | 46% | 82% | 86% | 76% | 80% |
| 4/s, 8 free sessions | 5% | 100% | 100% | 99% | 5% | 69% | 80% | 83% | 46% | 63% | 84% | 88% | 81% | 81% |
| 100/s, 64 free sessions | 0% | 100% | 100% | 99% | 0% | 4% | 76% | 73% | 3% | 46% | 82% | 86% | 76% | 80% |
| 4/s over 4 classes | 5% | 100% | 100% | 85% | 5% | 74% | 74% | 75% | 46% | 63% | 84% | 88% | 81% | 28% |
| 4/s over 16 classes | 5% | 5% | 5% | 5% | 5% | 57% | 57% | 61% | 46% | 63% | 84% | 88% | 81% | 25% |
| 4/s over 64 classes | 5% | 5% | 5% | 5% | 5% | 38% | 33% | 33% | 46% | 63% | 84% | 88% | 81% | 25% |
| 100/s over 16 classes | 0% | 0% | 0% | 0% | 0% | 29% | 30% | 44% | 3% | 46% | 82% | 86% | 76% | 0% |
| 8 clients behind one NAT, demand 1, no attacker | 100% | 26% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| same, demand 1.9 | 97% | 14% | 95% | 97% | 97% | 94% | 91% | 90% | 96% | 97% | 97% | 95% | 97% | 91% |
| NAT demand 1 + farmer 4/s elsewhere | 2% | 26% | 26% | 27% | 2% | 88% | 71% | 71% | 34% | 32% | 46% | 76% | 43% | 18% |
| NAT shares the farmer's class, 1 session | 3% | 0% | 2% | 2% | 3% | 85% | 3% | 63% | 34% | 48% | 71% | 91% | 67% | 10% |
| NAT shares the farmer's class, 64 sessions | 3% | 0% | 2% | 2% | 3% | 25% | 3% | 24% | 34% | 48% | 71% | 91% | 67% | 10% |
| 8 independent clients, demand 1 + farmer 4/s | 2% | 92% | 92% | 83% | 2% | 88% | 88% | 88% | 34% | 32% | 46% | 76% | 43% | 35% |
| adaptive spreader 4/s | 5% | 22% | 14% | 10% | 5% | 89% | 84% | 88% | 46% | 63% | 84% | 88% | 81% | 14% |
| adaptive spreader 100/s | 0% | 14% | 11% | 7% | 0% | 0% | 5% | 4% | 3% | 46% | 82% | 86% | 76% | 3% |
| on/off 20/s | 47% | 100% | 100% | 99% | 47% | 92% | 92% | 89% | 23% | 78% | 90% | 90% | 89% | 89% |
| slow 2.1/s | 65% | 100% | 100% | 100% | 65% | 95% | 95% | 95% | 90% | 74% | 87% | 92% | 86% | 90% |
| 4/s with 50 ms jitter | 42% | 100% | 100% | 100% | 42% | 85% | 85% | 85% | 48% | 66% | 84% | 86% | 78% | 87% |
| attacker acquires 0.1 attestations/s | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 51% | 76% | 88% | 70% | 81% |
| 0.5/s | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 32% | 22% | 91% | 22% | 81% |
| 2/s | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 28% | 12% | 32% | 12% | 81% |
| 100/s | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 28% | 12% | 13% | 12% | 81% |
| only 50% of clients can attest | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 48% | 49% | 54% | 49% | 81% |
| nobody can attest | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 19% | 5% | 14% | 6% | 81% |
| issuer down, farmer 4/s | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 20% | 11% | 12% | 12% | 81% |
| issuer down, no attacker, demand 1.9 | 97% | 97% | 97% | 97% | 97% | 97% | 97% | 97% | 96% | 94% | 86% | 66% | 91% | 96% |
| issuer down, no attacker, demand 3 | 68% | 68% | 68% | 68% | 68% | 68% | 68% | 68% | 65% | 61% | 55% | 41% | 64% | 67% |
| farmer 4/s + demand 1.9 | 2% | 92% | 85% | 69% | 2% | 84% | 84% | 84% | 28% | 26% | 31% | 49% | 31% | 26% |
| farmer 4/s + demand 3 | 1% | 60% | 59% | 52% | 1% | 62% | 62% | 62% | 25% | 22% | 23% | 33% | 23% | 20% |
| no attacker, demand 3 | 68% | 68% | 68% | 68% | 68% | 68% | 68% | 68% | 65% | 67% | 68% | 67% | 68% | 67% |
| 4/s, retry 1 s x5 | 5% | 100% | 100% | 100% | 5% | 96% | 96% | 96% | 89% | 93% | 94% | 91% | 94% | 96% |
| 100/s, retry 20 ms x250 | 0% | 100% | 100% | 100% | 1% | 100% | 100% | 100% | 99% | 91% | 96% | 91% | 96% | 97% |


### 5.3 What the numbers say

- **Single identity.** Every alternative improves V1 (5% at 4/s). Static ceilings reach 100%; fair share 80% (work-conserving max-min hands the attacker the whole residual, so legitimate bursts have no slack); pools 20% and 40%: 84% and 88% (accessibility 0.9 and burst), pool 10%: 63%; thinning 46%.
- **Identity multiplication.** Static ceilings (A) collapse to V1 at 16 classes. Per-token fairness is V1. Per-session fairness collapses at 64 sessions. Class fair share degrades smoothly. Pools do not move (84 to 88% at 64 classes). The adaptive spreader (a class per shed, at most 0.5 classes/s) takes A to 7 to 22% and per-session fairness to 0% at 100/s; the 20% and 40% pools stay at 82 to 88%.
- **Shared networks.** A *always* is unusable (26%, 14% for a harmless NAT). Fair-share variants lose 3 to 8 points at NAT demand 1.9 because per-entity buckets are smaller than the global bucket. Pools do not change shared-network behaviour while the issuer is up. Nobody helps users who share the attacker's class except the pools (71 to 91%) and, for a single session, hierarchical and per-session fair share (63 to 85%).
- **Exposure and capacity.** All variants stay within the 250 bound. Pools and A reduce the attacker's admissions (pool 40%: 149 of 248); the cost is unused capacity when nobody attests (172 credited admissions vs 249).
- **Fairness among independent clients (8 clients, farmer 4/s).** Jain index: V1 0.32 (worst client 0%); A gated 1.00; fair share 0.99; pool 40% 0.98 (worst client 57%); thinning 0.91 (19%).
- **Starvation.** Longest run of consecutive failed legitimate journeys at 4/s: V1 115 s; A gated 0 s; fair share 16 to 17 s; pools 17 s; thinning 58 s.

## 6. Adversarial counterexamples

1. **Free identities defeat per-token and per-session fairness** (35% / 4% with 64 sessions; token = V1). Any claim of "fair share per user" is false for these keys.
2. **Class rotation** takes static ceilings to V1 at 16 classes and fair share to 33% at 64; the class cost is unknown.
3. **Users inside the attacker's class** are indistinguishable from it: 3% under class fair share and 2% under A; only attestation separates them (91%).
4. **Attestation flooding.** At 0.5/s (20% reserve) and 2/s (40% reserve) the pool is exhausted and legitimate users fall back to a smaller general lane (12 to 22%). The attacker's total admissions stay at V1 level (245).
5. **Idle reserve.** An unavailable issuer, or users who cannot attest, turns the reserve into dead capacity: 97% → 66% (40%) at demand 1.9.
6. **Local deterministic issuer** is just a class rate limit: 16 classes drive it to 25%.
7. **Double spend across uncoordinated verifiers** (49 per 98 reserved admissions with 2 instances).
8. **Adaptive attackers** (class-per-shed spreader) beat A and per-session fair share; the pools are indifferent to class and session counts but not to attestation supply.
9. **Work-conserving max-min gives away the slack.** With the attacker holding the residual, legitimate Poisson bursts meet an empty bucket; no static choice of the burst cap fixes both NATs and continuity (dev-seed diagnostic).

## 7. What each approach can and cannot guarantee

| | Can guarantee | Cannot guarantee |
|---|---|---|
| **V1** | Credited admissions ≤ 10 + 2/s × t, exactly (capacity bound, test-pinned) | Any access for a legitimate client while a farmer polls; unchanged documented non-claim |
| **Max-min fair share** | No effect while total demand fits the refill; a single key cannot exceed the water level while demand exceeds it | Fairness to people (keys are cheap); restoration of the no-attacker control; shared-network parity near saturation; protection for users sharing the attacker's key |
| **Attested pool** | Exposure ≤ V1; attested users' access limited only by attestation supply (attacker acquisition < reserved refill), independent of classes and sessions; unattested users keep V1-like service on a smaller general lane | Anything once attacker attestations reach the reserved refill; benefit for users who cannot attest; no capacity cost when the issuer is down or demand exceeds the reserve; no double spend without coordination |
| **Pool + local issuer** | Nothing beyond a class rate limit | Anything under class rotation |

## 8. Limits

Single-process virtual time; no L1, composer or HTTP; 3 seeds × 120 s; synthetic legitimate population (one journey = one mutation); class and session are opaque harness labels; the attestation source is a parameter set, not a measured service; accessibility, latency and availability are assumed constants; the attacker strategies are those listed in the threat model. Privacy: non-attesting users are not treated as suspicious in any model and no privacy-tool detection or bypass is assumed; the optional-issuer property here means only that the plane keeps working without one.

## 9. Reproduction

`npx tsx --conditions=react-server --test tests/defense-l2-alt-architectures.test.ts` (about 55 s). The post-hoc dev-seed diagnostics and the table generators were run from a scratch directory and are not in the repository.

---

## Appendix — full per-cell accounting (3 evaluation seeds)

Column order: V1, A always, A gated, A gated-low\*, FS token, FS session, FS class, FS hier, thin, pool 10%, pool 20%, pool 40%, pool 20% overflow, pool 20% local issuer. "Entity-ceiling" sheds are class ceilings (A), per-entity fair-share ceilings or thinning. False rejects are the refused legitimate attempts in A2 in the no-attacker cells (V1 sheds there only from global demand above the refill).


### A1. Legitimate journey success (mean of 3 seeds)

| cell | v1 | A_always | A_gated | A_gated_low | fs_token | fs_session | fs_class | fs_hier | thin | pool10_ext | pool20_ext | pool40_ext | pool20_overflow_ext | pool20_ldi |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| D1-rate/rate-0 | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| D1-rate/rate-1 | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| D1-rate/rate-2 | 34% | 100% | 100% | 100% | 34% | 98% | 98% | 97% | 89% | 82% | 87% | 89% | 84% | 92% |
| D1-rate/rate-4 | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 63% | 84% | 88% | 81% | 81% |
| D1-rate/rate-100 | 0% | 100% | 100% | 99% | 0% | 76% | 76% | 76% | 3% | 46% | 82% | 86% | 76% | 80% |
| D2-identities/sessions-8-rate-4 | 5% | 100% | 100% | 99% | 5% | 69% | 80% | 83% | 46% | 63% | 84% | 88% | 81% | 81% |
| D2-identities/sessions-64-rate-4 | 5% | 100% | 100% | 99% | 5% | 35% | 80% | 80% | 46% | 63% | 84% | 88% | 81% | 81% |
| D2-identities/sessions-64-rate-100 | 0% | 100% | 100% | 99% | 0% | 4% | 76% | 73% | 3% | 46% | 82% | 86% | 76% | 80% |
| D2-identities/classes-4-rate-4 | 5% | 100% | 100% | 85% | 5% | 74% | 74% | 75% | 46% | 63% | 84% | 88% | 81% | 28% |
| D2-identities/classes-16-rate-4 | 5% | 5% | 5% | 5% | 5% | 57% | 57% | 61% | 46% | 63% | 84% | 88% | 81% | 25% |
| D2-identities/classes-64-rate-4 | 5% | 5% | 5% | 5% | 5% | 38% | 33% | 33% | 46% | 63% | 84% | 88% | 81% | 25% |
| D2-identities/classes-16-rate-100 | 0% | 0% | 0% | 0% | 0% | 29% | 30% | 44% | 3% | 46% | 82% | 86% | 76% | 0% |
| D2-identities/classes-4-sessions-16-rate-100 | 0% | 100% | 99% | 67% | 0% | 2% | 70% | 57% | 3% | 46% | 82% | 86% | 76% | 4% |
| D3-shared/nat8-demand-1-no-attacker | 100% | 26% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| D3-shared/nat8-demand-1.9-no-attacker | 97% | 14% | 95% | 97% | 97% | 94% | 91% | 90% | 96% | 97% | 97% | 95% | 97% | 91% |
| D3-shared/nat8-demand-1-attacker-elsewhere | 2% | 26% | 26% | 27% | 2% | 88% | 71% | 71% | 34% | 32% | 46% | 76% | 43% | 18% |
| D3-shared/nat8-demand-0.5-in-attacker-class-sessions-1 | 3% | 0% | 2% | 2% | 3% | 85% | 3% | 63% | 34% | 48% | 71% | 91% | 67% | 10% |
| D3-shared/nat8-demand-0.5-in-attacker-class-sessions-64 | 3% | 0% | 2% | 2% | 3% | 25% | 3% | 24% | 34% | 48% | 71% | 91% | 67% | 10% |
| D3-shared/own8-demand-1-attacker | 2% | 92% | 92% | 83% | 2% | 88% | 88% | 88% | 34% | 32% | 46% | 76% | 43% | 35% |
| D4-adaptive/spread-rate-4 | 5% | 22% | 14% | 10% | 5% | 89% | 84% | 88% | 46% | 63% | 84% | 88% | 81% | 14% |
| D4-adaptive/spread-rate-100 | 0% | 14% | 11% | 7% | 0% | 0% | 5% | 4% | 3% | 46% | 82% | 86% | 76% | 3% |
| D4-adaptive/on-off-20-per-s | 47% | 100% | 100% | 99% | 47% | 92% | 92% | 89% | 23% | 78% | 90% | 90% | 89% | 89% |
| D4-adaptive/slow-2.1 | 65% | 100% | 100% | 100% | 65% | 95% | 95% | 95% | 90% | 74% | 87% | 92% | 86% | 90% |
| D4-adaptive/jitter-50-rate-4 | 42% | 100% | 100% | 100% | 42% | 85% | 85% | 85% | 48% | 66% | 84% | 86% | 78% | 87% |
| D5-attest/attacker-acquires-0.1-per-s-rate-4 | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 51% | 76% | 88% | 70% | 81% |
| D5-attest/attacker-acquires-0.5-per-s-rate-4 | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 32% | 22% | 91% | 22% | 81% |
| D5-attest/attacker-acquires-2-per-s-rate-4 | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 28% | 12% | 32% | 12% | 81% |
| D5-attest/attacker-acquires-10-per-s-rate-4 | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 28% | 12% | 13% | 12% | 81% |
| D5-attest/attacker-acquires-100-per-s-rate-4 | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 28% | 12% | 13% | 12% | 81% |
| D5-attest/attacker-acquires-0.5-per-s-rate-100 | 0% | 100% | 100% | 99% | 0% | 76% | 76% | 76% | 3% | 1% | 5% | 86% | 2% | 80% |
| D5-attest/accessible-0.5-rate-4 | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 48% | 49% | 54% | 49% | 81% |
| D5-attest/accessible-0.0-rate-4 | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 19% | 5% | 14% | 6% | 81% |
| D5-attest/latency-5000-rate-4 | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 57% | 82% | 88% | 70% | 81% |
| D5-attest/issuer-down-all-rate-4 | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 20% | 11% | 12% | 12% | 81% |
| D5-attest/issuer-down-second-half-rate-4 | 5% | 100% | 100% | 99% | 5% | 80% | 80% | 80% | 46% | 39% | 49% | 46% | 46% | 81% |
| D5-attest/issuer-down-all-no-attacker-demand-1.9 | 97% | 97% | 97% | 97% | 97% | 97% | 97% | 97% | 96% | 94% | 86% | 66% | 91% | 96% |
| D5-attest/issuer-down-all-no-attacker-demand-3 | 68% | 68% | 68% | 68% | 68% | 68% | 68% | 68% | 65% | 61% | 55% | 41% | 64% | 67% |
| D5-attest/attacker-classes-16-rate-4-ldi-acquisition | 5% | 5% | 5% | 5% | 5% | 57% | 57% | 61% | 46% | 63% | 84% | 88% | 81% | 25% |
| D6-demand/attacker-4-demand-1 | 2% | 100% | 99% | 86% | 2% | 85% | 85% | 85% | 34% | 32% | 46% | 76% | 43% | 38% |
| D6-demand/attacker-4-demand-1.9 | 2% | 92% | 85% | 69% | 2% | 84% | 84% | 84% | 28% | 26% | 31% | 49% | 31% | 26% |
| D6-demand/attacker-4-demand-3 | 1% | 60% | 59% | 52% | 1% | 62% | 62% | 62% | 25% | 22% | 23% | 33% | 23% | 20% |
| D6-demand/no-attacker-demand-1.9 | 97% | 97% | 97% | 97% | 97% | 97% | 97% | 97% | 96% | 97% | 97% | 95% | 97% | 96% |
| D6-demand/no-attacker-demand-3 | 68% | 68% | 68% | 68% | 68% | 68% | 68% | 68% | 65% | 67% | 68% | 67% | 68% | 67% |
| D7-retry/rate-4-retry-1s-x5 | 5% | 100% | 100% | 100% | 5% | 96% | 96% | 96% | 89% | 93% | 94% | 91% | 94% | 96% |
| D7-retry/rate-100-retry-20ms-x250 | 0% | 100% | 100% | 100% | 1% | 100% | 100% | 100% | 99% | 91% | 96% | 91% | 96% | 97% |

### A2. Legitimate attempts admitted / refused (mean per seed)

| cell | v1 | A_always | A_gated | A_gated_low | fs_token | fs_session | fs_class | fs_hier | thin | pool10_ext | pool20_ext | pool40_ext | pool20_overflow_ext | pool20_ldi |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| D1-rate/rate-0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 |
| D1-rate/rate-1 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 | 27/0 |
| D1-rate/rate-2 | 9/18 | 27/0 | 27/0 | 27/0 | 9/18 | 26/1 | 26/1 | 26/1 | 24/3 | 22/5 | 23/4 | 24/3 | 23/4 | 25/2 |
| D1-rate/rate-4 | 1/26 | 27/0 | 27/0 | 27/0 | 1/26 | 22/5 | 22/5 | 22/5 | 12/15 | 17/10 | 23/4 | 24/3 | 22/5 | 22/5 |
| D1-rate/rate-100 | 0/27 | 27/0 | 27/0 | 27/0 | 0/27 | 21/6 | 21/6 | 21/6 | 1/26 | 12/15 | 22/5 | 23/4 | 20/7 | 21/6 |
| D2-identities/sessions-8-rate-4 | 1/26 | 27/0 | 27/0 | 27/0 | 1/26 | 19/8 | 22/5 | 22/5 | 12/15 | 17/10 | 23/4 | 24/3 | 22/5 | 22/5 |
| D2-identities/sessions-64-rate-4 | 1/26 | 27/0 | 27/0 | 27/0 | 1/26 | 9/18 | 22/5 | 22/5 | 12/15 | 17/10 | 23/4 | 24/3 | 22/5 | 22/5 |
| D2-identities/sessions-64-rate-100 | 0/27 | 27/0 | 27/0 | 27/0 | 0/27 | 1/26 | 21/6 | 20/7 | 1/26 | 12/15 | 22/5 | 23/4 | 20/7 | 21/6 |
| D2-identities/classes-4-rate-4 | 1/26 | 27/0 | 27/0 | 23/4 | 1/26 | 20/7 | 20/7 | 20/7 | 12/15 | 17/10 | 23/4 | 24/3 | 22/5 | 8/19 |
| D2-identities/classes-16-rate-4 | 1/26 | 1/26 | 1/26 | 1/26 | 1/26 | 15/12 | 15/12 | 16/11 | 12/15 | 17/10 | 23/4 | 24/3 | 22/5 | 7/20 |
| D2-identities/classes-64-rate-4 | 1/26 | 1/26 | 1/26 | 1/26 | 1/26 | 10/17 | 9/18 | 9/18 | 12/15 | 17/10 | 23/4 | 24/3 | 22/5 | 7/20 |
| D2-identities/classes-16-rate-100 | 0/27 | 0/27 | 0/27 | 0/27 | 0/27 | 8/19 | 8/19 | 12/15 | 1/26 | 12/15 | 22/5 | 23/4 | 20/7 | 0/27 |
| D2-identities/classes-4-sessions-16-rate-100 | 0/27 | 27/0 | 27/0 | 18/9 | 0/27 | 1/26 | 19/8 | 15/12 | 1/26 | 12/15 | 22/5 | 23/4 | 20/7 | 1/26 |
| D3-shared/nat8-demand-1-no-attacker | 119/0 | 31/88 | 119/0 | 119/0 | 119/0 | 119/0 | 119/0 | 119/0 | 119/0 | 119/0 | 119/0 | 119/0 | 119/0 | 119/0 |
| D3-shared/nat8-demand-1.9-no-attacker | 219/7 | 31/195 | 214/12 | 218/8 | 219/7 | 212/14 | 204/22 | 201/25 | 216/10 | 218/8 | 218/8 | 215/11 | 218/8 | 204/22 |
| D3-shared/nat8-demand-1-attacker-elsewhere | 3/116 | 31/88 | 31/88 | 32/87 | 3/116 | 105/14 | 84/35 | 84/35 | 40/79 | 38/81 | 55/64 | 91/28 | 51/68 | 22/97 |
| D3-shared/nat8-demand-0.5-in-attacker-class-sessions-1 | 2/52 | 0/53 | 1/52 | 1/52 | 2/52 | 46/8 | 2/52 | 34/20 | 18/35 | 26/28 | 38/16 | 49/5 | 36/18 | 5/48 |
| D3-shared/nat8-demand-0.5-in-attacker-class-sessions-64 | 2/52 | 0/53 | 1/52 | 1/52 | 2/52 | 13/40 | 2/52 | 13/41 | 18/35 | 26/28 | 38/16 | 49/5 | 36/18 | 5/48 |
| D3-shared/own8-demand-1-attacker | 3/116 | 109/10 | 109/10 | 98/21 | 3/116 | 105/14 | 105/14 | 105/14 | 40/79 | 38/81 | 55/64 | 91/28 | 51/68 | 41/78 |
| D4-adaptive/spread-rate-4 | 1/26 | 6/21 | 4/23 | 3/24 | 1/26 | 24/3 | 23/4 | 24/3 | 12/15 | 17/10 | 23/4 | 24/3 | 22/5 | 4/23 |
| D4-adaptive/spread-rate-100 | 0/27 | 4/23 | 3/24 | 2/25 | 0/27 | 0/27 | 1/26 | 1/26 | 1/26 | 12/15 | 22/5 | 23/4 | 20/7 | 1/26 |
| D4-adaptive/on-off-20-per-s | 13/14 | 27/0 | 27/0 | 27/0 | 13/14 | 25/2 | 25/2 | 24/3 | 6/21 | 21/6 | 24/3 | 24/3 | 24/3 | 24/3 |
| D4-adaptive/slow-2.1 | 17/10 | 27/0 | 27/0 | 27/0 | 17/10 | 26/1 | 26/1 | 26/1 | 24/3 | 20/7 | 23/4 | 25/2 | 23/4 | 24/3 |
| D4-adaptive/jitter-50-rate-4 | 11/16 | 27/0 | 27/0 | 27/0 | 11/16 | 23/4 | 23/4 | 23/4 | 13/14 | 18/9 | 23/4 | 23/4 | 21/6 | 23/4 |
| D5-attest/attacker-acquires-0.1-per-s-rate-4 | 1/26 | 27/0 | 27/0 | 27/0 | 1/26 | 22/5 | 22/5 | 22/5 | 12/15 | 14/13 | 20/7 | 24/3 | 19/8 | 22/5 |
| D5-attest/attacker-acquires-0.5-per-s-rate-4 | 1/26 | 27/0 | 27/0 | 27/0 | 1/26 | 22/5 | 22/5 | 22/5 | 12/15 | 9/18 | 6/21 | 25/2 | 6/21 | 22/5 |
| D5-attest/attacker-acquires-2-per-s-rate-4 | 1/26 | 27/0 | 27/0 | 27/0 | 1/26 | 22/5 | 22/5 | 22/5 | 12/15 | 8/19 | 3/24 | 9/18 | 3/24 | 22/5 |
| D5-attest/attacker-acquires-10-per-s-rate-4 | 1/26 | 27/0 | 27/0 | 27/0 | 1/26 | 22/5 | 22/5 | 22/5 | 12/15 | 8/19 | 3/24 | 3/24 | 3/24 | 22/5 |
| D5-attest/attacker-acquires-100-per-s-rate-4 | 1/26 | 27/0 | 27/0 | 27/0 | 1/26 | 22/5 | 22/5 | 22/5 | 12/15 | 8/19 | 3/24 | 3/24 | 3/24 | 22/5 |
| D5-attest/attacker-acquires-0.5-per-s-rate-100 | 0/27 | 27/0 | 27/0 | 27/0 | 0/27 | 21/6 | 21/6 | 21/6 | 1/26 | 0/27 | 1/26 | 23/4 | 1/26 | 21/6 |
| D5-attest/accessible-0.5-rate-4 | 1/26 | 27/0 | 27/0 | 27/0 | 1/26 | 22/5 | 22/5 | 22/5 | 12/15 | 13/14 | 13/14 | 15/12 | 13/14 | 22/5 |
| D5-attest/accessible-0.0-rate-4 | 1/26 | 27/0 | 27/0 | 27/0 | 1/26 | 22/5 | 22/5 | 22/5 | 12/15 | 5/22 | 1/26 | 4/23 | 2/25 | 22/5 |
| D5-attest/latency-5000-rate-4 | 1/26 | 27/0 | 27/0 | 27/0 | 1/26 | 22/5 | 22/5 | 22/5 | 12/15 | 15/12 | 22/5 | 24/3 | 19/8 | 22/5 |
| D5-attest/issuer-down-all-rate-4 | 1/26 | 27/0 | 27/0 | 27/0 | 1/26 | 22/5 | 22/5 | 22/5 | 12/15 | 5/22 | 3/24 | 3/24 | 3/24 | 22/5 |
| D5-attest/issuer-down-second-half-rate-4 | 1/26 | 27/0 | 27/0 | 27/0 | 1/26 | 22/5 | 22/5 | 22/5 | 12/15 | 11/16 | 13/14 | 13/14 | 12/15 | 22/5 |
| D5-attest/issuer-down-all-no-attacker-demand-1.9 | 219/7 | 218/8 | 219/7 | 219/7 | 219/7 | 219/7 | 219/7 | 219/7 | 216/10 | 211/15 | 193/33 | 148/78 | 204/22 | 217/9 |
| D5-attest/issuer-down-all-no-attacker-demand-3 | 247/117 | 247/117 | 247/117 | 247/117 | 247/117 | 247/117 | 247/117 | 247/117 | 237/127 | 223/141 | 199/165 | 149/215 | 231/133 | 245/119 |
| D5-attest/attacker-classes-16-rate-4-ldi-acquisition | 1/26 | 1/26 | 1/26 | 1/26 | 1/26 | 15/12 | 15/12 | 16/11 | 12/15 | 17/10 | 23/4 | 24/3 | 22/5 | 7/20 |
| D6-demand/attacker-4-demand-1 | 3/116 | 119/0 | 118/1 | 103/16 | 3/116 | 101/18 | 101/18 | 101/18 | 40/79 | 38/81 | 55/64 | 91/28 | 51/68 | 45/74 |
| D6-demand/attacker-4-demand-1.9 | 4/222 | 208/18 | 193/33 | 156/70 | 4/222 | 189/37 | 190/36 | 190/36 | 63/163 | 59/167 | 70/156 | 111/115 | 70/156 | 59/167 |
| D6-demand/attacker-4-demand-3 | 5/359 | 217/147 | 214/151 | 190/174 | 5/359 | 224/141 | 224/141 | 225/139 | 91/274 | 81/283 | 84/280 | 121/243 | 84/280 | 73/291 |
| D6-demand/no-attacker-demand-1.9 | 219/7 | 218/8 | 219/7 | 219/7 | 219/7 | 219/7 | 219/7 | 219/7 | 216/10 | 218/8 | 218/8 | 215/11 | 218/8 | 217/9 |
| D6-demand/no-attacker-demand-3 | 247/117 | 247/117 | 247/117 | 247/117 | 247/117 | 247/117 | 247/117 | 247/117 | 237/127 | 245/120 | 246/119 | 244/120 | 246/119 | 245/119 |
| D7-retry/rate-4-retry-1s-x5 | 1/128 | 27/0 | 27/0 | 27/0 | 1/128 | 26/7 | 26/7 | 26/8 | 24/35 | 25/24 | 25/14 | 25/14 | 25/16 | 26/14 |
| D7-retry/rate-100-retry-20ms-x250 | 0/6732 | 27/0 | 27/0 | 27/2 | 0/6680 | 27/90 | 27/90 | 27/86 | 27/1318 | 25/1575 | 26/513 | 25/685 | 26/610 | 26/469 |

### A3. Attacker admissions, credited + unverified (mean per seed)

| cell | v1 | A_always | A_gated | A_gated_low | fs_token | fs_session | fs_class | fs_hier | thin | pool10_ext | pool20_ext | pool40_ext | pool20_overflow_ext | pool20_ldi |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| D1-rate/rate-0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D1-rate/rate-1 | 120 | 31 | 120 | 120 | 120 | 120 | 120 | 120 | 120 | 120 | 120 | 120 | 120 | 120 |
| D1-rate/rate-2 | 240 | 31 | 218 | 220 | 240 | 220 | 220 | 220 | 217 | 214 | 198 | 148 | 221 | 207 |
| D1-rate/rate-4 | 248 | 31 | 218 | 221 | 248 | 225 | 225 | 225 | 229 | 219 | 198 | 149 | 225 | 211 |
| D1-rate/rate-100 | 249 | 31 | 218 | 221 | 249 | 227 | 227 | 226 | 236 | 224 | 199 | 149 | 227 | 211 |
| D2-identities/sessions-8-rate-4 | 248 | 31 | 218 | 221 | 248 | 228 | 225 | 223 | 229 | 219 | 198 | 149 | 225 | 211 |
| D2-identities/sessions-64-rate-4 | 248 | 31 | 218 | 221 | 248 | 240 | 225 | 225 | 229 | 219 | 198 | 149 | 225 | 211 |
| D2-identities/sessions-64-rate-100 | 249 | 31 | 218 | 221 | 249 | 248 | 227 | 227 | 236 | 224 | 199 | 149 | 227 | 211 |
| D2-identities/classes-4-rate-4 | 248 | 124 | 218 | 225 | 248 | 226 | 226 | 226 | 229 | 219 | 198 | 149 | 225 | 239 |
| D2-identities/classes-16-rate-4 | 248 | 248 | 248 | 248 | 248 | 231 | 230 | 229 | 229 | 219 | 198 | 149 | 225 | 240 |
| D2-identities/classes-64-rate-4 | 248 | 248 | 248 | 248 | 248 | 239 | 240 | 238 | 229 | 219 | 198 | 149 | 225 | 240 |
| D2-identities/classes-16-rate-100 | 249 | 249 | 249 | 249 | 249 | 240 | 240 | 234 | 236 | 224 | 199 | 149 | 227 | 248 |
| D2-identities/classes-4-sessions-16-rate-100 | 249 | 124 | 218 | 230 | 249 | 248 | 227 | 232 | 236 | 224 | 199 | 149 | 227 | 247 |
| D3-shared/nat8-demand-1-no-attacker | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D3-shared/nat8-demand-1.9-no-attacker | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D3-shared/nat8-demand-1-attacker-elsewhere | 246 | 31 | 214 | 216 | 246 | 141 | 148 | 148 | 199 | 207 | 192 | 147 | 197 | 201 |
| D3-shared/nat8-demand-0.5-in-attacker-class-sessions-1 | 247 | 31 | 244 | 247 | 247 | 202 | 247 | 201 | 225 | 215 | 197 | 149 | 212 | 206 |
| D3-shared/nat8-demand-0.5-in-attacker-class-sessions-64 | 247 | 31 | 244 | 247 | 247 | 236 | 247 | 236 | 225 | 215 | 197 | 149 | 212 | 206 |
| D3-shared/own8-demand-1-attacker | 246 | 31 | 137 | 150 | 246 | 141 | 141 | 141 | 199 | 207 | 192 | 147 | 197 | 204 |
| D4-adaptive/spread-rate-4 | 248 | 238 | 245 | 246 | 248 | 198 | 200 | 193 | 229 | 219 | 198 | 149 | 225 | 244 |
| D4-adaptive/spread-rate-100 | 249 | 241 | 246 | 247 | 249 | 249 | 248 | 248 | 236 | 224 | 199 | 149 | 227 | 247 |
| D4-adaptive/on-off-20-per-s | 174 | 24 | 137 | 154 | 174 | 125 | 125 | 125 | 166 | 155 | 138 | 102 | 153 | 144 |
| D4-adaptive/slow-2.1 | 232 | 31 | 218 | 220 | 232 | 221 | 221 | 221 | 217 | 216 | 198 | 147 | 213 | 207 |
| D4-adaptive/jitter-50-rate-4 | 238 | 31 | 218 | 221 | 238 | 224 | 224 | 224 | 228 | 218 | 198 | 149 | 223 | 209 |
| D5-attest/attacker-acquires-0.1-per-s-rate-4 | 248 | 31 | 218 | 221 | 248 | 225 | 225 | 225 | 229 | 228 | 209 | 160 | 228 | 211 |
| D5-attest/attacker-acquires-0.5-per-s-rate-4 | 248 | 31 | 218 | 221 | 248 | 225 | 225 | 225 | 229 | 239 | 242 | 207 | 242 | 211 |
| D5-attest/attacker-acquires-2-per-s-rate-4 | 248 | 31 | 218 | 221 | 248 | 225 | 225 | 225 | 229 | 240 | 245 | 239 | 245 | 211 |
| D5-attest/attacker-acquires-10-per-s-rate-4 | 248 | 31 | 218 | 221 | 248 | 225 | 225 | 225 | 229 | 240 | 245 | 245 | 245 | 211 |
| D5-attest/attacker-acquires-100-per-s-rate-4 | 248 | 31 | 218 | 221 | 248 | 225 | 225 | 225 | 229 | 240 | 245 | 245 | 245 | 211 |
| D5-attest/attacker-acquires-0.5-per-s-rate-100 | 249 | 31 | 218 | 221 | 249 | 227 | 227 | 226 | 236 | 248 | 247 | 208 | 247 | 211 |
| D5-attest/accessible-0.5-rate-4 | 248 | 31 | 218 | 221 | 248 | 225 | 225 | 225 | 229 | 220 | 198 | 147 | 233 | 211 |
| D5-attest/accessible-0.0-rate-4 | 248 | 31 | 218 | 221 | 248 | 225 | 225 | 225 | 229 | 219 | 198 | 145 | 244 | 211 |
| D5-attest/latency-5000-rate-4 | 248 | 31 | 218 | 221 | 248 | 225 | 225 | 225 | 229 | 221 | 199 | 149 | 227 | 211 |
| D5-attest/issuer-down-all-rate-4 | 248 | 31 | 218 | 221 | 248 | 225 | 225 | 225 | 229 | 219 | 196 | 146 | 243 | 211 |
| D5-attest/issuer-down-second-half-rate-4 | 248 | 31 | 218 | 221 | 248 | 225 | 225 | 225 | 229 | 220 | 197 | 149 | 234 | 211 |
| D5-attest/issuer-down-all-no-attacker-demand-1.9 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D5-attest/issuer-down-all-no-attacker-demand-3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D5-attest/attacker-classes-16-rate-4-ldi-acquisition | 248 | 248 | 248 | 248 | 248 | 231 | 230 | 229 | 229 | 219 | 198 | 149 | 225 | 240 |
| D6-demand/attacker-4-demand-1 | 246 | 31 | 128 | 146 | 246 | 145 | 145 | 146 | 199 | 207 | 192 | 147 | 197 | 202 |
| D6-demand/attacker-4-demand-1.9 | 245 | 31 | 54 | 93 | 245 | 57 | 57 | 56 | 171 | 188 | 179 | 137 | 179 | 189 |
| D6-demand/attacker-4-demand-3 | 244 | 31 | 35 | 58 | 244 | 24 | 24 | 22 | 145 | 167 | 165 | 127 | 165 | 175 |
| D6-demand/no-attacker-demand-1.9 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D6-demand/no-attacker-demand-3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D7-retry/rate-4-retry-1s-x5 | 248 | 31 | 218 | 221 | 248 | 219 | 219 | 218 | 218 | 213 | 196 | 148 | 221 | 209 |
| D7-retry/rate-100-retry-20ms-x250 | 249 | 31 | 218 | 221 | 249 | 194 | 194 | 192 | 213 | 215 | 196 | 148 | 221 | 208 |

### A4. Total credited exposure (credited admissions, all actors; V1 bound 250)

| cell | v1 | A_always | A_gated | A_gated_low | fs_token | fs_session | fs_class | fs_hier | thin | pool10_ext | pool20_ext | pool40_ext | pool20_overflow_ext | pool20_ldi |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| D1-rate/rate-0 | 27 | 27 | 27 | 27 | 27 | 27 | 27 | 27 | 27 | 27 | 27 | 27 | 27 | 27 |
| D1-rate/rate-1 | 147 | 58 | 147 | 147 | 147 | 147 | 147 | 147 | 147 | 147 | 147 | 147 | 147 | 147 |
| D1-rate/rate-2 | 249 | 58 | 245 | 247 | 249 | 246 | 246 | 246 | 241 | 236 | 221 | 172 | 244 | 231 |
| D1-rate/rate-4 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 241 | 236 | 221 | 172 | 246 | 232 |
| D1-rate/rate-100 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 237 | 236 | 221 | 172 | 247 | 232 |
| D2-identities/sessions-8-rate-4 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 246 | 241 | 236 | 221 | 172 | 246 | 232 |
| D2-identities/sessions-64-rate-4 | 249 | 58 | 245 | 248 | 249 | 249 | 247 | 247 | 241 | 236 | 221 | 172 | 246 | 232 |
| D2-identities/sessions-64-rate-100 | 249 | 58 | 245 | 248 | 249 | 249 | 247 | 247 | 237 | 236 | 221 | 172 | 247 | 232 |
| D2-identities/classes-4-rate-4 | 249 | 151 | 245 | 248 | 249 | 246 | 246 | 246 | 241 | 236 | 221 | 172 | 246 | 247 |
| D2-identities/classes-16-rate-4 | 249 | 249 | 249 | 249 | 249 | 246 | 245 | 246 | 241 | 236 | 221 | 172 | 246 | 247 |
| D2-identities/classes-64-rate-4 | 249 | 249 | 249 | 249 | 249 | 249 | 249 | 247 | 241 | 236 | 221 | 172 | 246 | 247 |
| D2-identities/classes-16-rate-100 | 249 | 249 | 249 | 249 | 249 | 248 | 248 | 246 | 237 | 236 | 221 | 172 | 247 | 248 |
| D2-identities/classes-4-sessions-16-rate-100 | 249 | 151 | 245 | 248 | 249 | 249 | 246 | 247 | 237 | 236 | 221 | 172 | 247 | 248 |
| D3-shared/nat8-demand-1-no-attacker | 119 | 31 | 119 | 119 | 119 | 119 | 119 | 119 | 119 | 119 | 119 | 119 | 119 | 119 |
| D3-shared/nat8-demand-1.9-no-attacker | 219 | 31 | 214 | 218 | 219 | 212 | 204 | 201 | 216 | 218 | 218 | 215 | 218 | 204 |
| D3-shared/nat8-demand-1-attacker-elsewhere | 249 | 62 | 245 | 248 | 249 | 245 | 233 | 232 | 239 | 245 | 247 | 237 | 248 | 222 |
| D3-shared/nat8-demand-0.5-in-attacker-class-sessions-1 | 249 | 31 | 245 | 248 | 249 | 247 | 249 | 235 | 243 | 241 | 235 | 197 | 248 | 211 |
| D3-shared/nat8-demand-0.5-in-attacker-class-sessions-64 | 249 | 31 | 245 | 248 | 249 | 249 | 249 | 248 | 243 | 241 | 235 | 197 | 248 | 211 |
| D3-shared/own8-demand-1-attacker | 249 | 140 | 245 | 248 | 249 | 245 | 245 | 245 | 239 | 245 | 247 | 237 | 248 | 245 |
| D4-adaptive/spread-rate-4 | 249 | 244 | 249 | 249 | 249 | 222 | 223 | 217 | 241 | 236 | 221 | 172 | 246 | 248 |
| D4-adaptive/spread-rate-100 | 249 | 245 | 249 | 249 | 249 | 249 | 249 | 249 | 237 | 236 | 221 | 172 | 247 | 248 |
| D4-adaptive/on-off-20-per-s | 186 | 51 | 164 | 181 | 186 | 150 | 150 | 149 | 173 | 176 | 162 | 126 | 177 | 168 |
| D4-adaptive/slow-2.1 | 249 | 58 | 245 | 247 | 249 | 247 | 247 | 246 | 241 | 236 | 221 | 172 | 236 | 231 |
| D4-adaptive/jitter-50-rate-4 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 241 | 236 | 221 | 172 | 244 | 232 |
| D5-attest/attacker-acquires-0.1-per-s-rate-4 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 241 | 242 | 229 | 183 | 246 | 232 |
| D5-attest/attacker-acquires-0.5-per-s-rate-4 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 241 | 248 | 248 | 231 | 248 | 232 |
| D5-attest/attacker-acquires-2-per-s-rate-4 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 241 | 248 | 248 | 248 | 248 | 232 |
| D5-attest/attacker-acquires-10-per-s-rate-4 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 241 | 248 | 248 | 248 | 248 | 232 |
| D5-attest/attacker-acquires-100-per-s-rate-4 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 241 | 248 | 248 | 248 | 248 | 232 |
| D5-attest/attacker-acquires-0.5-per-s-rate-100 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 237 | 248 | 248 | 231 | 248 | 232 |
| D5-attest/accessible-0.5-rate-4 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 241 | 233 | 212 | 162 | 246 | 232 |
| D5-attest/accessible-0.0-rate-4 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 241 | 224 | 199 | 149 | 246 | 232 |
| D5-attest/latency-5000-rate-4 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 241 | 236 | 221 | 172 | 246 | 232 |
| D5-attest/issuer-down-all-rate-4 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 241 | 224 | 199 | 149 | 246 | 232 |
| D5-attest/issuer-down-second-half-rate-4 | 249 | 58 | 245 | 248 | 249 | 247 | 247 | 247 | 241 | 230 | 211 | 161 | 246 | 232 |
| D5-attest/issuer-down-all-no-attacker-demand-1.9 | 219 | 218 | 219 | 219 | 219 | 219 | 219 | 219 | 216 | 211 | 193 | 148 | 204 | 217 |
| D5-attest/issuer-down-all-no-attacker-demand-3 | 247 | 247 | 247 | 247 | 247 | 247 | 247 | 247 | 237 | 223 | 199 | 149 | 231 | 245 |
| D5-attest/attacker-classes-16-rate-4-ldi-acquisition | 249 | 249 | 249 | 249 | 249 | 246 | 245 | 246 | 241 | 236 | 221 | 172 | 246 | 247 |
| D6-demand/attacker-4-demand-1 | 249 | 150 | 246 | 248 | 249 | 246 | 246 | 247 | 239 | 245 | 247 | 237 | 248 | 248 |
| D6-demand/attacker-4-demand-1.9 | 249 | 239 | 247 | 249 | 249 | 246 | 246 | 246 | 234 | 247 | 249 | 248 | 249 | 248 |
| D6-demand/attacker-4-demand-3 | 249 | 248 | 248 | 249 | 249 | 247 | 248 | 247 | 235 | 248 | 249 | 249 | 249 | 248 |
| D6-demand/no-attacker-demand-1.9 | 219 | 218 | 219 | 219 | 219 | 219 | 219 | 219 | 216 | 218 | 218 | 215 | 218 | 217 |
| D6-demand/no-attacker-demand-3 | 247 | 247 | 247 | 247 | 247 | 247 | 247 | 247 | 237 | 245 | 246 | 244 | 246 | 245 |
| D7-retry/rate-4-retry-1s-x5 | 249 | 58 | 245 | 248 | 249 | 245 | 245 | 244 | 242 | 238 | 221 | 172 | 246 | 235 |
| D7-retry/rate-100-retry-20ms-x250 | 249 | 58 | 245 | 248 | 249 | 221 | 221 | 219 | 239 | 239 | 222 | 172 | 247 | 235 |

### A5. Credited sheds: entity-ceiling / global bucket (mean per seed)

| cell | v1 | A_always | A_gated | A_gated_low | fs_token | fs_session | fs_class | fs_hier | thin | pool10_ext | pool20_ext | pool40_ext | pool20_overflow_ext | pool20_ldi |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| D1-rate/rate-0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| D1-rate/rate-1 | 0/0 | 89/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| D1-rate/rate-2 | 0/18 | 209/0 | 22/0 | 20/0 | 0/18 | 20/1 | 20/1 | 21/0 | 26/0 | 0/31 | 0/46 | 0/95 | 0/23 | 0/36 |
| D1-rate/rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 240/20 | 240/20 | 241/19 | 229/36 | 0/271 | 0/286 | 0/335 | 0/261 | 0/275 |
| D1-rate/rate-100 | 0/11778 | 11969/0 | 11782/0 | 11779/0 | 94/11684 | 10878/901 | 10885/894 | 10888/892 | 11687/104 | 0/11791 | 0/11806 | 0/11855 | 0/11780 | 0/11795 |
| D2-identities/sessions-8-rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 212/49 | 240/20 | 245/16 | 229/36 | 0/271 | 0/286 | 0/335 | 0/261 | 0/275 |
| D2-identities/sessions-64-rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 111/147 | 240/20 | 240/20 | 229/36 | 0/271 | 0/286 | 0/335 | 0/261 | 0/275 |
| D2-identities/sessions-64-rate-100 | 0/11778 | 11969/0 | 11782/0 | 11779/0 | 94/11684 | 3977/7801 | 10885/894 | 10923/857 | 11687/104 | 0/11791 | 0/11806 | 0/11855 | 0/11780 | 0/11795 |
| D2-identities/classes-4-rate-4 | 0/258 | 356/0 | 262/0 | 221/38 | 1/257 | 221/40 | 222/39 | 228/32 | 229/36 | 0/271 | 0/286 | 0/335 | 0/261 | 0/260 |
| D2-identities/classes-16-rate-4 | 0/258 | 0/258 | 0/258 | 0/258 | 1/257 | 189/72 | 191/71 | 204/57 | 229/36 | 0/271 | 0/286 | 0/335 | 0/261 | 0/260 |
| D2-identities/classes-64-rate-4 | 0/258 | 0/258 | 0/258 | 0/258 | 1/257 | 109/149 | 112/146 | 124/137 | 229/36 | 0/271 | 0/286 | 0/335 | 0/261 | 0/260 |
| D2-identities/classes-16-rate-100 | 0/11778 | 1980/9798 | 1980/9798 | 1980/9798 | 94/11684 | 8351/3428 | 8337/3442 | 9825/1956 | 11687/104 | 0/11791 | 0/11806 | 0/11855 | 0/11780 | 0/11779 |
| D2-identities/classes-4-sessions-16-rate-100 | 0/11778 | 11876/0 | 11782/0 | 10598/1181 | 94/11684 | 5585/6193 | 10978/803 | 10992/788 | 11687/104 | 0/11791 | 0/11806 | 0/11855 | 0/11780 | 0/11779 |
| D3-shared/nat8-demand-1-no-attacker | 0/0 | 88/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| D3-shared/nat8-demand-1.9-no-attacker | 0/7 | 195/0 | 12/0 | 8/0 | 0/7 | 14/0 | 22/0 | 25/0 | 8/2 | 0/8 | 0/8 | 0/11 | 0/8 | 0/22 |
| D3-shared/nat8-demand-1-attacker-elsewhere | 0/350 | 537/0 | 354/0 | 351/0 | 2/348 | 329/24 | 349/17 | 350/17 | 318/41 | 0/354 | 0/352 | 0/362 | 0/351 | 0/377 |
| D3-shared/nat8-demand-0.5-in-attacker-class-sessions-1 | 0/284 | 502/0 | 288/0 | 285/0 | 1/283 | 267/19 | 0/284 | 286/13 | 250/40 | 0/292 | 0/298 | 0/336 | 0/286 | 0/322 |
| D3-shared/nat8-demand-0.5-in-attacker-class-sessions-64 | 0/284 | 502/0 | 288/0 | 285/0 | 1/283 | 107/177 | 0/284 | 186/99 | 250/40 | 0/292 | 0/298 | 0/336 | 0/286 | 0/322 |
| D3-shared/own8-demand-1-attacker | 0/350 | 459/0 | 354/0 | 338/13 | 2/348 | 329/24 | 329/24 | 330/23 | 318/41 | 0/354 | 0/352 | 0/362 | 0/351 | 0/354 |
| D4-adaptive/spread-rate-4 | 0/258 | 70/193 | 47/211 | 35/223 | 1/257 | 260/26 | 241/43 | 263/27 | 229/36 | 0/271 | 0/286 | 0/335 | 0/261 | 0/259 |
| D4-adaptive/spread-rate-100 | 0/11778 | 2620/9162 | 2259/9519 | 1990/9788 | 94/11684 | 451/11327 | 5552/6226 | 5800/5978 | 11687/104 | 0/11791 | 0/11806 | 0/11855 | 0/11780 | 0/11779 |
| D4-adaptive/on-off-20-per-s | 0/1041 | 1176/0 | 1063/0 | 1046/0 | 3/1038 | 950/127 | 950/127 | 951/127 | 948/106 | 0/1051 | 0/1065 | 0/1101 | 0/1050 | 0/1059 |
| D4-adaptive/slow-2.1 | 0/30 | 221/0 | 34/0 | 32/0 | 0/30 | 29/3 | 29/3 | 31/2 | 36/2 | 0/43 | 0/58 | 0/107 | 0/43 | 0/48 |
| D4-adaptive/jitter-50-rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 218/42 | 219/41 | 219/41 | 230/36 | 0/271 | 0/286 | 0/335 | 0/263 | 0/275 |
| D5-attest/attacker-acquires-0.1-per-s-rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 240/20 | 240/20 | 241/19 | 229/36 | 0/265 | 0/278 | 0/324 | 0/261 | 0/275 |
| D5-attest/attacker-acquires-0.5-per-s-rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 240/20 | 240/20 | 241/19 | 229/36 | 0/259 | 0/259 | 0/276 | 0/259 | 0/275 |
| D5-attest/attacker-acquires-2-per-s-rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 240/20 | 240/20 | 241/19 | 229/36 | 0/259 | 0/259 | 0/259 | 0/259 | 0/275 |
| D5-attest/attacker-acquires-10-per-s-rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 240/20 | 240/20 | 241/19 | 229/36 | 0/259 | 0/259 | 0/259 | 0/259 | 0/275 |
| D5-attest/attacker-acquires-100-per-s-rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 240/20 | 240/20 | 241/19 | 229/36 | 0/259 | 0/259 | 0/259 | 0/259 | 0/275 |
| D5-attest/attacker-acquires-0.5-per-s-rate-100 | 0/11778 | 11969/0 | 11782/0 | 11779/0 | 94/11684 | 10878/901 | 10885/894 | 10888/892 | 11687/104 | 0/11779 | 0/11779 | 0/11796 | 0/11779 | 0/11795 |
| D5-attest/accessible-0.5-rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 240/20 | 240/20 | 241/19 | 229/36 | 0/274 | 0/295 | 0/345 | 0/261 | 0/275 |
| D5-attest/accessible-0.0-rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 240/20 | 240/20 | 241/19 | 229/36 | 0/283 | 0/308 | 0/358 | 0/261 | 0/275 |
| D5-attest/latency-5000-rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 240/20 | 240/20 | 241/19 | 229/36 | 0/271 | 0/286 | 0/335 | 0/261 | 0/275 |
| D5-attest/issuer-down-all-rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 240/20 | 240/20 | 241/19 | 229/36 | 0/283 | 0/308 | 0/358 | 0/261 | 0/275 |
| D5-attest/issuer-down-second-half-rate-4 | 0/258 | 449/0 | 262/0 | 259/0 | 1/257 | 240/20 | 240/20 | 241/19 | 229/36 | 0/277 | 0/296 | 0/346 | 0/261 | 0/275 |
| D5-attest/issuer-down-all-no-attacker-demand-1.9 | 0/7 | 2/6 | 0/6 | 0/6 | 0/7 | 2/5 | 3/4 | 2/5 | 8/2 | 0/15 | 0/33 | 0/78 | 0/22 | 0/9 |
| D5-attest/issuer-down-all-no-attacker-demand-3 | 0/117 | 5/113 | 4/113 | 3/114 | 0/117 | 36/82 | 40/77 | 43/74 | 107/20 | 0/141 | 0/165 | 0/215 | 0/133 | 0/119 |
| D5-attest/attacker-classes-16-rate-4-ldi-acquisition | 0/258 | 0/258 | 0/258 | 0/258 | 1/257 | 189/72 | 191/71 | 204/57 | 229/36 | 0/271 | 0/286 | 0/335 | 0/261 | 0/260 |
| D6-demand/attacker-4-demand-1 | 0/350 | 449/0 | 352/1 | 334/16 | 2/348 | 324/28 | 324/29 | 326/27 | 318/41 | 0/354 | 0/352 | 0/362 | 0/351 | 0/351 |
| D6-demand/attacker-4-demand-1.9 | 0/457 | 451/16 | 427/32 | 388/69 | 5/452 | 419/41 | 420/40 | 423/37 | 429/44 | 0/459 | 0/457 | 0/458 | 0/457 | 0/458 |
| D6-demand/attacker-4-demand-3 | 0/595 | 453/143 | 449/147 | 425/171 | 5/590 | 490/107 | 490/106 | 499/98 | 560/49 | 0/596 | 0/595 | 0/596 | 0/595 | 0/596 |
| D6-demand/no-attacker-demand-1.9 | 0/7 | 2/6 | 0/6 | 0/6 | 0/7 | 2/5 | 3/4 | 2/5 | 8/2 | 0/8 | 0/8 | 0/11 | 0/8 | 0/9 |
| D6-demand/no-attacker-demand-3 | 0/117 | 5/113 | 4/113 | 3/114 | 0/117 | 36/82 | 40/77 | 43/74 | 107/20 | 0/120 | 0/119 | 0/120 | 0/119 | 0/119 |
| D7-retry/rate-4-retry-1s-x5 | 0/360 | 449/0 | 262/0 | 259/0 | 1/359 | 247/20 | 247/20 | 250/20 | 260/36 | 0/290 | 0/298 | 0/347 | 0/275 | 0/285 |
| D7-retry/rate-100-retry-20ms-x250 | 0/18483 | 11969/0 | 11782/0 | 11779/2 | 177/18254 | 11437/459 | 11438/459 | 11433/461 | 13002/104 | 0/13361 | 0/12317 | 0/12537 | 0/12389 | 0/12260 |

### A6. Longest run of consecutive failed legitimate journeys, in seconds (max over seeds)

| cell | v1 | A_always | A_gated | A_gated_low | fs_token | fs_session | fs_class | fs_hier | thin | pool10_ext | pool20_ext | pool40_ext | pool20_overflow_ext | pool20_ldi |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| D1-rate/rate-0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D1-rate/rate-1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D1-rate/rate-2 | 86 | 0 | 0 | 0 | 86 | 2 | 2 | 10 | 21 | 12 | 17 | 12 | 17 | 15 |
| D1-rate/rate-4 | 115 | 0 | 0 | 2 | 115 | 16 | 16 | 17 | 58 | 17 | 17 | 17 | 17 | 15 |
| D1-rate/rate-100 | 119 | 0 | 0 | 2 | 119 | 22 | 22 | 22 | 119 | 18 | 18 | 17 | 18 | 21 |
| D2-identities/sessions-8-rate-4 | 115 | 0 | 0 | 2 | 115 | 29 | 16 | 17 | 58 | 17 | 17 | 17 | 17 | 15 |
| D2-identities/sessions-64-rate-4 | 115 | 0 | 0 | 2 | 115 | 75 | 16 | 17 | 58 | 17 | 17 | 17 | 17 | 15 |
| D2-identities/sessions-64-rate-100 | 119 | 0 | 0 | 2 | 119 | 116 | 22 | 22 | 119 | 18 | 18 | 17 | 18 | 21 |
| D2-identities/classes-4-rate-4 | 115 | 0 | 0 | 21 | 115 | 16 | 16 | 18 | 58 | 17 | 17 | 17 | 17 | 42 |
| D2-identities/classes-16-rate-4 | 115 | 115 | 115 | 115 | 115 | 36 | 36 | 20 | 58 | 17 | 17 | 17 | 17 | 42 |
| D2-identities/classes-64-rate-4 | 115 | 115 | 115 | 115 | 115 | 34 | 50 | 52 | 58 | 17 | 17 | 17 | 17 | 42 |
| D2-identities/classes-16-rate-100 | 119 | 119 | 119 | 119 | 119 | 82 | 82 | 58 | 119 | 18 | 18 | 17 | 18 | 119 |
| D2-identities/classes-4-sessions-16-rate-100 | 119 | 0 | 6 | 28 | 119 | 116 | 28 | 28 | 119 | 18 | 18 | 17 | 18 | 109 |
| D3-shared/nat8-demand-1-no-attacker | 0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D3-shared/nat8-demand-1.9-no-attacker | 2 | 6 | 2 | 2 | 2 | 2 | 3 | 3 | 3 | 2 | 2 | 2 | 2 | 3 |
| D3-shared/nat8-demand-1-attacker-elsewhere | 118 | 7 | 7 | 7 | 118 | 6 | 6 | 6 | 13 | 8 | 6 | 5 | 6 | 12 |
| D3-shared/nat8-demand-0.5-in-attacker-class-sessions-1 | 117 | 120 | 117 | 117 | 117 | 12 | 117 | 11 | 40 | 10 | 9 | 6 | 9 | 80 |
| D3-shared/nat8-demand-0.5-in-attacker-class-sessions-64 | 117 | 120 | 117 | 117 | 117 | 37 | 117 | 37 | 40 | 10 | 9 | 6 | 9 | 80 |
| D3-shared/own8-demand-1-attacker | 118 | 2 | 2 | 5 | 118 | 6 | 6 | 6 | 13 | 8 | 6 | 5 | 6 | 9 |
| D4-adaptive/spread-rate-4 | 115 | 91 | 98 | 110 | 115 | 19 | 24 | 19 | 58 | 17 | 17 | 17 | 17 | 91 |
| D4-adaptive/spread-rate-100 | 119 | 98 | 109 | 109 | 119 | 119 | 82 | 116 | 119 | 18 | 18 | 17 | 18 | 117 |
| D4-adaptive/on-off-20-per-s | 30 | 0 | 0 | 2 | 30 | 18 | 18 | 18 | 33 | 15 | 7 | 7 | 7 | 21 |
| D4-adaptive/slow-2.1 | 15 | 0 | 0 | 0 | 15 | 9 | 9 | 9 | 12 | 12 | 17 | 6 | 17 | 15 |
| D4-adaptive/jitter-50-rate-4 | 34 | 0 | 0 | 0 | 34 | 12 | 12 | 12 | 58 | 17 | 17 | 17 | 17 | 21 |
| D5-attest/attacker-acquires-0.1-per-s-rate-4 | 115 | 0 | 0 | 2 | 115 | 16 | 16 | 17 | 58 | 19 | 21 | 17 | 21 | 15 |
| D5-attest/attacker-acquires-0.5-per-s-rate-4 | 115 | 0 | 0 | 2 | 115 | 16 | 16 | 17 | 58 | 29 | 60 | 6 | 60 | 15 |
| D5-attest/attacker-acquires-2-per-s-rate-4 | 115 | 0 | 0 | 2 | 115 | 16 | 16 | 17 | 58 | 50 | 87 | 29 | 87 | 15 |
| D5-attest/attacker-acquires-10-per-s-rate-4 | 115 | 0 | 0 | 2 | 115 | 16 | 16 | 17 | 58 | 50 | 52 | 72 | 52 | 15 |
| D5-attest/attacker-acquires-100-per-s-rate-4 | 115 | 0 | 0 | 2 | 115 | 16 | 16 | 17 | 58 | 50 | 52 | 72 | 52 | 15 |
| D5-attest/attacker-acquires-0.5-per-s-rate-100 | 119 | 0 | 0 | 2 | 119 | 22 | 22 | 22 | 119 | 117 | 117 | 17 | 117 | 21 |
| D5-attest/accessible-0.5-rate-4 | 115 | 0 | 0 | 2 | 115 | 16 | 16 | 17 | 58 | 34 | 30 | 17 | 30 | 15 |
| D5-attest/accessible-0.0-rate-4 | 115 | 0 | 0 | 2 | 115 | 16 | 16 | 17 | 58 | 87 | 94 | 91 | 92 | 15 |
| D5-attest/latency-5000-rate-4 | 115 | 0 | 0 | 2 | 115 | 16 | 16 | 17 | 58 | 18 | 18 | 17 | 18 | 15 |
| D5-attest/issuer-down-all-rate-4 | 115 | 0 | 0 | 2 | 115 | 16 | 16 | 17 | 58 | 58 | 71 | 83 | 71 | 15 |
| D5-attest/issuer-down-second-half-rate-4 | 115 | 0 | 0 | 2 | 115 | 16 | 16 | 17 | 58 | 45 | 48 | 58 | 48 | 15 |
| D5-attest/issuer-down-all-no-attacker-demand-1.9 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 3 | 2 | 2 | 3 | 2 | 2 |
| D5-attest/issuer-down-all-no-attacker-demand-3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 2 |
| D5-attest/attacker-classes-16-rate-4-ldi-acquisition | 115 | 115 | 115 | 115 | 115 | 36 | 36 | 20 | 58 | 17 | 17 | 17 | 17 | 42 |
| D6-demand/attacker-4-demand-1 | 118 | 0 | 1 | 5 | 118 | 6 | 6 | 6 | 13 | 8 | 6 | 5 | 6 | 7 |
| D6-demand/attacker-4-demand-1.9 | 117 | 3 | 3 | 3 | 117 | 5 | 5 | 5 | 14 | 6 | 4 | 3 | 4 | 6 |
| D6-demand/attacker-4-demand-3 | 118 | 3 | 3 | 3 | 118 | 3 | 3 | 3 | 9 | 6 | 3 | 3 | 3 | 5 |
| D6-demand/no-attacker-demand-1.9 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 3 | 2 | 2 | 2 | 2 | 2 |
| D6-demand/no-attacker-demand-3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 2 | 2 | 2 | 2 |
| D7-retry/rate-4-retry-1s-x5 | 115 | 0 | 0 | 0 | 115 | 12 | 12 | 12 | 12 | 12 | 17 | 12 | 17 | 15 |
| D7-retry/rate-100-retry-20ms-x250 | 119 | 0 | 0 | 0 | 119 | 0 | 0 | 0 | 2 | 5 | 12 | 10 | 12 | 8 |

### A7. Allocation fairness among independent legitimate clients (Jain index / worst client success)

| cell | v1 | A_always | A_gated | A_gated_low | fs_token | fs_session | fs_class | fs_hier | thin | pool10_ext | pool20_ext | pool40_ext | pool20_overflow_ext | pool20_ldi |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| D3-shared/nat8-demand-1-attacker-elsewhere | 0.32 / 0% | 0.85 / 8% | 0.85 / 8% | 0.86 / 8% | 0.32 / 0% | 0.99 / 76% | 0.98 / 49% | 0.98 / 51% | 0.91 / 19% | 0.86 / 10% | 0.93 / 21% | 0.98 / 57% | 0.92 / 16% | 0.84 / 6% |
| D3-shared/own8-demand-1-attacker | 0.32 / 0% | 1.00 / 84% | 1.00 / 84% | 0.99 / 71% | 0.32 / 0% | 0.99 / 76% | 0.99 / 76% | 0.99 / 76% | 0.91 / 19% | 0.86 / 10% | 0.93 / 21% | 0.98 / 57% | 0.92 / 16% | 0.93 / 22% |

### A8. Verifier instances and double spends (D5b; 3-seed means)

| cell | variant | success | attacker admissions | attacker reserved admissions | attestations acquired | double spends | credited exposure |
|---|---|---|---|---|---|---|---|
| D5b-verifiers/replay-4-acquires-2-per-s-rate-4 | v1 | 5% | 248 | 0 | 0 | 0 | 249 |
| D5b-verifiers/replay-4-acquires-2-per-s-rate-4 | pool40_ext_n2_local | 16% | 243 | 98 | 239 | 49 | 247 |
| D5b-verifiers/replay-4-acquires-2-per-s-rate-4 | pool40_ext_n2_shared | 16% | 243 | 98 | 239 | 0 | 247 |
| D5b-verifiers/replay-4-acquires-2-per-s-rate-4 | pool40_ext | 16% | 244 | 99 | 239 | 0 | 248 |
| D5b-verifiers/no-replay-acquires-2-per-s-rate-4 | v1 | 5% | 248 | 0 | 0 | 0 | 249 |
| D5b-verifiers/no-replay-acquires-2-per-s-rate-4 | pool40_ext_n2_local | 32% | 238 | 98 | 239 | 0 | 247 |
| D5b-verifiers/no-replay-acquires-2-per-s-rate-4 | pool40_ext_n2_shared | 32% | 238 | 98 | 239 | 0 | 247 |
| D5b-verifiers/no-replay-acquires-2-per-s-rate-4 | pool40_ext | 32% | 239 | 99 | 239 | 0 | 248 |

### A9. Legitimate added latency (mean ms per journey) and attested admissions (pool variants, D5 latency/accessibility cells)

| cell | variant | added latency | legit admitted via reserved |
|---|---|---|---|
| D5-attest/latency-5000-rate-4 | pool20_ext | 4313 | 22 |
| D5-attest/latency-5000-rate-4 | pool40_ext | 4313 | 23 |
| D5-attest/latency-5000-rate-4 | pool20_ldi | 0 | 21 |
| D5-attest/accessible-0.5-rate-4 | pool20_ext | 381 | 13 |
| D5-attest/accessible-0.5-rate-4 | pool40_ext | 381 | 13 |
| D5-attest/accessible-0.5-rate-4 | pool20_ldi | 0 | 21 |
| D1-rate/rate-4 | pool20_ext | 690 | 22 |
| D1-rate/rate-4 | pool40_ext | 690 | 23 |
| D1-rate/rate-4 | pool20_ldi | 0 | 21 |

