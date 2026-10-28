# BA0 L2 — V2 Fairness: Shadow-Mode Evaluation

Status: **experimental characterization, not a design approval and not an implementation.** Version label of every model in this document: `l2-v2-shadow-experimental-1`.
Base: `ba0-n2-progression` @ `8b45d05` (working branch `fix/p0-02-expiry-horizon`, identical tree). Nothing under `defense/`, `artifacts/`, `lab/` or `src/` was modified; nothing is committed.
Code: `tests/support/l2-v2-shadow.ts`, `l2-v2-matrix.ts`, `l2-v2-scenarios.ts`; pinned results: `tests/defense-l2-v2-shadow.test.ts`.
Input documents: `docs/BA0_L2_CREDITED_LANE_CHARACTERIZATION.md` (V1 behaviour), `docs/BA0_L2_FAIRNESS_ARCHITECTURE_DECISION.md` (Approach A, per-class ceilings).

**Recommendation: REVISE ARCHITECTURE.** Approach A as pre-registered is **unsuitable as a general default** (H1 passes, H2 fails). A contention-gated variant removes most of the harm, but the evidence does not yet support PROCEED TO V2 DESIGN. Section 9.

All numbers below are the output of a deterministic simulation (virtual clock, seeded arrivals). "Measured" means measured in that simulation, never on a live plane.

---

## 1. Phase 1 — review of the existing untracked material

Preserved unchanged: the V1 characterization test (9 tests, all pass) and its numbers; the decision study's guarantee tiers, signal table and four approaches. Historical BA0 evidence, INVALID verdicts, V1 thresholds and fingerprints are untouched.

Assumptions that needed correction or qualification (recorded as errata appended to the two earlier documents; their results were not rewritten):

1. **"NOT_CLAIMED (pinned by a test)."** The contract test pins the phrase list containing "per-user fairness", but it does not individually pin the string "protection against a stateful automation that renders and then posts, beyond the stated credited-lane bound". The collapse-run tests only check that evidence `notClaimed` equals the exported list. The non-claim is real and documented (`lab/defense/ba0-collapse-run.ts`, `defense/README.md` Claim boundary); "pinned by a test" was too strong for that string.
2. **"(measured)" in the decision study** means deterministic simulation output, not a live-plane measurement.
3. **One legitimate client at one fixed phase** was used in the V1 characterization; the 12-journey shape is a single arrival pattern. This matrix uses Poisson and periodic arrivals over three seeds.
4. **The gate threshold θ was unspecified** in the decision study, and its H1 prediction applied to an *ungated* ceiling. This study evaluates both.
5. **The decision study treated the class key as a single concept.** Here the hint source is explicit: `peer` (only enforced source), `forwarded` (untrusted), `declared_shared` (exempt), `missing` (exempt).

---

## 2. Exact model assumptions

**What is real:** every V1 decision comes from the actual `JourneyLanes` (`defense/core/lanes.ts`) on an injected clock, with the BA0 field parameters (`BA0_FIELD_V1.l2`: credited 10 @ 2/s, unverified 3 @ 1/s, K = 3, epoch 60 s, filter 2^23 bits, 7 hashes, ledger 512).

**What is modeled (V2, `V2Model`):** a full independent mirror of V1 state (own Bloom filter, use ledger, two token buckets) plus one extra step in the credited lane:

| Item | Value |
|---|---|
| Class table | S = 1024 class buckets, fixed memory, keyed hash of the class id (no rotating key) |
| Class bucket | capacity 2, refill φ × 2/s with φ = 1/8, i.e. 0.25/s |
| Metering | the class bucket is charged on **every** credited admission; it only **sheds** when enforcement applies |
| Enforcement | `always`: shed whenever the class bucket is empty. `gated θ`: shed only while the V2 global credited level is below θ × capacity (θ = 0.5 pre-registered; 0.25 = the post-hoc candidate `gated_low`) |
| Order | check class bucket and global bucket, then take both, in one synchronous step. A class-ceiling shed consumes **no** global token and **no** ledger use |
| Hint sources | `peer` enforced; `forwarded` ignored unless the UNSAFE `trustForwarded` switch is on (used only for the counterexample); `declared_shared` and `missing` exempt (behave like V1) |
| New shed reason | `class_ceiling` exists only in the model; V1's closed `SHED_REASONS` is untouched |

**Why V2 carries its own state:** judging a counterfactual against V1's already-drained bucket would hide any benefit. The V2 model sees the same request stream and makes its own decisions.

**Two worlds.** *World A (shadow)*: V1 decides, V2 observes the V1-driven stream. *World B (enforced)*: V2 is the sole decider on the same generated stream, closed-loop. They agree exactly in all 47 no-retry cells; they differ in the 8 retry cells because the shadow stream is produced by V1 outcomes (the open-loop bias: e.g. 136 shadow legitimate attempts vs 29 enforced in one cell). Success rates in retry cells are taken from World B.

**Workload.** 120 s virtual time (two filter generations). Legitimate clients: 1 journey = render + one mutation, Poisson (or periodic) arrivals; demand is expressed against the credited refill (2/s). Farmer: mints free credit by rendering, then posts at rate r. Seeds 11/23/37 (held-out: 101/103/107/109/113). Jitter is in ms, arrival-order variants put legitimate or farmer first on ties.

**Not modeled:** L1 and the composer, HTTP, real clock behaviour, multi-process, memory pressure, real NAT/CGNAT populations, IPv6 prefix choice, real attacker adaptation, human behaviour. The class key is an opaque string supplied by the harness.

**Capacity preservation** is demonstrated only in this sense: in every cell, credited admissions never exceed capacity + refill × time (= 250 over 120 s), and every V2 credited decision is exactly `admitted + global shed + class shed`. V2 adds no token, no refund and no second bucket the attacker can draw from. It is *not* demonstrated that legitimate users keep V1's access (that is H2, and it fails).

---

## 3. Pre-registration and disclosures

Criteria were fixed in `CRITERIA` before the first full run: H1 improve ≥ +0.20 over V1 where V1 ≤ 0.80; H1 restore within 0.02 of the no-attacker control; H2 no more than 0.02 worse than V1; H3 attacker admissions ≤ V1 + 5 and credited admissions ≤ bound; H4 enforcement only on `peer`, exempt traffic within 0.02 of V1, degenerate-topology flag (top class share ≥ 0.90) raised.

Disclosed deviations and flaws:

- **B8 jittered-farmer cells** (4/s jitter 50 ms, 100/s jitter 3 ms) were added after the first run, before their results were seen, and the H1 cell selector was extended to their no-retry cells. This can only make H1 stricter.
- **Criterion flaw (H4 spoof).** "Spoofed hint harmed the victim" is confounded for `always`: the 76% victim success in `B6-hints/spoof-victim-class-farmer-1.5` is the ungated ceiling clipping a single heavy class (the same effect as the NAT cells), not the spoof. A no-farmer control shows the same 76%. It is reported, not used to rescue the variant.
- **`gated_low` was chosen post hoc** from an 18-variant exploratory sweep (φ ∈ {1/8, 1/4, 1/2} × θ ∈ {0.25, 0.5, 0.75} × class capacity ∈ {2, 4}, 2 seeds) after `gated` failed H2. It is therefore not a pre-registered result. It was then validated on a held-out matrix (new seeds and new scenarios). The held-out scenario *structure* was written after the sweep, so it is held out on seeds and exact cells, not on the idea.
- The held-out matrix was run once and is reported as it came out.

---

## 4. Headline comparison (journey success; mean of seeds)

V1 is the real code. "Always", "Gated" (θ 0.5), "Gated-low" (θ 0.25, post hoc) are the counterfactual V2 under enforcement (World B). Full accounting per cell is in the appendix.

| Scenario | V1 | V2 always | V2 gated | V2 gated-low |
|---|---|---|---|---|
| No attacker (control) | 100% | 100% | 100% | 100% |
| Farmer 1/s | 100% | 100% | 100% | 100% |
| Farmer 2/s | 31% | 100% | 100% | 100% |
| Farmer 3/s | 22% | 100% | 100% | 100% |
| Farmer 4/s, 1 class | 5% | 100% | 100% | 98% |
| Farmer 100/s, 1 class | 0% | 100% | 100% | 98% |
| Farmer 4/s over 2 / 4 classes | 5% | 100 / 100% | 100 / 100% | 87 / 69% |
| Farmer 4/s over 8 / 16 classes | 5% | 23 / 5% | 23 / 5% | 23 / 5% |
| Farmer 100/s over 4 / 8 / 16 classes | 0% | 100 / 3 / 0% | 98 / 3 / 0% | 57 / 3 / 0% |
| Legit shares the attacker's class (ρ = 0.5) | 3% | 56% | 57% | 55% |
| Legit entirely in the attacker's class (ρ = 1) | 5% | **0%** | **1%** | 3% |
| NAT, no attacker, demand 0.25 / 0.5 / 1 | 100% | **76 / 51 / 26%** | 100% | 100% |
| NAT, no attacker, demand 1.9 | 97% | **14%** | **94%** (29 V2-only refusals vs 5 V1-only, 687 journeys) | 96% |
| NAT, no attacker, demand 3 | 66% | 8% | 65% | 66% |
| Undeclared single proxy, no attacker, demand 1 | 100% | **26%** | 100% | 100% |
| Undeclared single proxy + farmer 4/s | 5% | **0%** | **2%** | 5% |
| NAT/proxy declared shared, farmer 4/s | 5% | 5% | 5% | 5% |
| Missing hints, farmer 4/s | 5% | 5% | 5% | 5% |
| Farmer 4/s + legit demand 0.25 / 1 / 1.9 / 3 | 5 / 3 / 2 / 2% | 100 / 100 / 88 / 59% | 100 / 99 / 81 / 58% | 98 / 83 / 68 / 51% |
| No attacker, demand 1.9 / 3 (reference ceiling) | 95 / 67% | 95 / 67% | 95 / 67% | 95 / 67% |

Attacker admissions (credited + unverified, 120 s): V1 248 for a single-class 4/s farmer; V2 `gated` 216, `gated_low` 220, `always` 31. With 8+ classes V2 equals V1 (242–248). No cell has V2 attacker admissions above V1 + 5 in any variant.

---

## 5. Hypotheses

Pre-registered variants `always` and `gated` on the 55-cell matrix; `gated_low` flagged post hoc; held-out in section 6.

| | always | gated (θ 0.5) | gated-low (θ 0.25, post hoc) |
|---|---|---|---|
| **H1** single-class farmer constrained enough to improve legitimate continuity | **PASS** (improve and restore) | **PASS** (improve and restore) | improve PASS, restore **FAIL** (0.977 vs 1.000 control, a 2.3-point miss against a 2-point tolerance, 8 cells) |
| **H2** shared-network users not materially worse than V1 | **FAIL** (8 cells; NAT demand 0.25 → 76%, 1 → 26%, 1.9 → 14%) | **FAIL** (3 cells: ρ=1 5→1%, undeclared proxy + farmer 5→2%, both a handful of journeys; NAT demand 1.9 97→94%, a mechanism-explained false-reject increase) | **PASS** |
| **H3** rotation does not raise attacker exposure above V1 | **PASS** | **PASS** | **PASS** |
| **H4** missing / proxy-derived hints cannot silently produce unsafe enforcement | FAIL on one confounded criterion (section 3); enforcement only on `peer` | **PASS** | **PASS** |
| **H5** shadow has no side effects on V1 | **PASS** (below) | | |

**The rule applies:** H1 passes and H2 fails for both pre-registered configurations, so **Approach A, as pre-registered, is unsuitable as a general default.** The failure is large and structural for `always` (a harmless NAT or an undeclared single proxy loses 74–86% of its legitimate journeys with no attacker present) and small but real for `gated`.

**H5 evidence** (tests in `tests/defense-l2-v2-shadow.test.ts`): (a) `V2Model(enforce: off)` makes the same decision as the real `JourneyLanes` for 127k+ mixed decisions including 5k+ credited sheds, K exhaustion and epoch rotations: zero mismatches; (b) running the shadow beside V1 leaves V1's decision-stream fingerprint, snapshot (buckets, ledger, filter) and outcome accounting byte-identical, over 8 scenarios × 2 seeds; (c) the wrapper touches V1 only through `decide()` and `enroll()` and imports only V1 code and the pinned V1 constants. This shows no side effects *in the harness*; it says nothing about a production integration.

---

## 6. Held-out validation (5 unseen seeds, 24 new cells, criteria unchanged)

| | always | gated | gated-low |
|---|---|---|---|
| H1 improve | PASS | PASS | PASS |
| H1 restore | PASS | **FAIL** (1 cell: farmer 4/s + legit demand 1.5, 93% vs 100%) | **FAIL** (4 cells: 97.5%, 96.5%, 89.6%, 73.6%) |
| H2 | **FAIL** (5 cells, e.g. NAT demand 0.75 → 32%, 1.5 → 17%, three NATs 1.5 → 46%) | **PASS** | **PASS** |
| H3 | PASS | PASS | PASS |

Cells worth reading: farmer 2.5/s 41% → 98–100%; 6/s and 25/s 1% → 97–100%; periodic legitimate arrivals 3% → 100%; 5 ms-jittered farmer with retries 52% → 100%. Rotation: 3 / 5 / 6 / 7 classes at 4/s, `gated` 99 / 98 / 94 / 77%, `gated_low` 78 / 70 / 65 / 44%; 100/s over 12 classes 1% for all (V1: 0%). Legit in a NAT with an attacker elsewhere: 46% at demand 0.5 and 13% at 1.9 for every variant (V1: 1–2%).

Reading: `gated` and `gated_low` both survive the shared-network cells that sink `always`. `gated_low` is more conservative for NATs and proxies but gives up more continuity for a single-class farmer under high legitimate demand (74% vs 93% at demand 1.5) and is **less** rotation-resistant at 2–7 classes. There is no setting of θ in this sweep that is best on every axis.

---

## 7. Adversarial counterexamples

1. **Trusted forwarded hints enable targeted denial (H4).** With the UNSAFE `trustForwarded` switch on and `always`, a farmer at 1.5/s that claims the victim's class (`VICTIM`) drops that class's legitimate success from 100% (V1) to about 1% (85 V2-only refusals across seeds). V1 does not starve anyone at 1.5/s. With forwarded hints untrusted the same spoof does nothing (0 forwarded class sheds). `gated_trustfwd` stays at 100% at 1.5/s only because there is no contention; at 4/s everyone is starved anyway. Conclusion: a forwarded header must never be an enforcement key.
2. **Class-count rotation (H3 limit).** The ceiling costs the attacker `1/φ ≈ 8` classes to neutralize: at 4/s total, legitimate success is 100% with 1–4 classes, 23% with 8, 5% (= V1) with 16; at 100/s (`always`/`gated`), 98–100% with 1–4, 3% with 8, 0% with 16. If a class costs the attacker nothing (IPv6 /64 rotation, a botnet), A buys nothing. This study has no data on the real cost of a class.
3. **Legitimate users in the attacker's class (H1/H2 limit).** With ρ = 1, class and attacker are indistinguishable by construction. V2 cannot help and cannot do better than V1; under `always` it is strictly worse (5% → 0%).
4. **Undeclared single proxy / CGNAT.** Everyone shares one `peer` class. No attacker needed: `always` loses 74% of journeys at demand 1; `gated` only marginally. The degenerate-topology flag (top class share ≥ 0.90) is raised in these cells, but a flag is a measurement, not a remedy.
5. **NAT near saturation.** At demand 1.9 (≈ the 2/s refill) a gated ceiling still turns some journeys into class sheds: 29 V2-only refusals vs 5 V1-only. This is the cost of the mechanism, not noise.
6. **Evasion by hint absence.** `missing` and `declared_shared` traffic is exempt, so it behaves exactly like V1 (all-missing farmer at 4/s: 5%, same as V1). If an attacker can influence whether the hint exists, ceilings are bypassed. Safe only if the hint is derived from the connection peer address, never from a request field.
7. **Open-loop bias.** Shadow mode feeds V2 a stream shaped by V1 outcomes, so retry clients look worse to V2 than they would be. This is why World B exists, and why a production shadow deployment alone could not answer H1 for retrying clients.
8. **Demand near or above the global refill.** With a farmer at 4/s and legitimate demand 1.9 or 3 (≥ capacity), V2 restores 58–88% but cannot reach the no-attacker reference (95 / 67%): the bucket is simply too small for the total demand.

---

## 8. Limits of this evaluation

Single-process virtual time; no L1, composer or HTTP; three seeds (five held-out) of 120 s; the legitimate population is synthetic and one journey is one mutation; class identity is an opaque harness label; attacker is non-adaptive apart from class rotation; the demand matrix is parameterized because real demand is unknown (decision 4). Differences of one or two journeys (ρ = 1, undeclared proxy + farmer) are at noise level. `gated_low` and all parameter choices come from a small grid and must not be read as tuned optima. Nothing here measures what a real attacker or real network would do.

---

## 9. Recommendation: REVISE ARCHITECTURE

- **Not RETAIN V1:** the V1 starvation is real and H1 shows the mechanism is addressable: single-class farmers can be constrained with no increase in credited capacity, and legitimate journey success rises from 0–5% to 98–100% in the single-class cells.
- **Not PROCEED TO V2 DESIGN:** the pre-registered ceilings fail H2; the only variant that passed H2 on both matrices (`gated_low`) is post hoc, misses the pre-registered restore tier on both matrices, loses rotation resistance at 2–7 classes, and its benefit evaporates against any attacker that can cheaply obtain ~8 classes. Whether classes are expensive is unknown and decides the value of the whole approach.
- **Revise before design:** (1) make the contention gate θ a first-class, owner-visible parameter with a stated purpose (it creates a reserve for non-heavy classes); (2) require the hint to be derived only from the peer address and make "declared shared network" an explicit, owner-supplied deployment fact rather than something inferred; (3) decide the acceptable G-tier in the decision study and set the restore tolerance from the product's tolerance for false rejects, not from the simulation; (4) evaluate an alternative that does not depend on class cost, such as max-min fair-share across active classes (V1 behaviour when one class is active) or the attested reserved pool (Approach B), against the same matrix and the same held-out discipline; (5) obtain a real estimate of class cost and legitimate shared-network share before choosing parameters.

No production implementation is proposed or authorized by this document.

---

## 10. Reproduction

`npx tsx --conditions=react-server --test tests/defense-l2-v2-shadow.test.ts` (about 50 s). Models and scenarios are in `tests/support/l2-v2-*.ts`; the post-hoc variant is registered only inside the test via `EXPLORATORY`. The exploratory sweep script is not in the repository (it was run from a scratch directory); its conclusions are summarized in section 3 and are not pinned.

---

## Appendix — per-cell accounting

Columns: journey success (legitimate admitted / refused attempts, mean per seed); `atk` attacker admissions (credited + unverified); `cls` class-ceiling sheds; `glob` global credited-bucket sheds; `FR` false rejects as journeys V1 completed that V2 would refuse / journeys V2 completes that V1 refused (summed over seeds, shadow stream); `V1 global-shed` the V1 credited-bucket sheds; last column maximum starvation duration V1 → V2 variants. V1/V2 accounting differences: V2 credited decisions always equal admitted + global + class sheds, and credited admissions never exceed the bound of 250.

### Pre-registered matrix (3 seeds, 120 s)

| cell | V1 journeys ok (legit adm/ref) | V1 atk adm | always ok (adm/ref) · atk · class-shed · global-shed · false-rejects V2only/V1only | gated ok (adm/ref) · atk · class-shed · global-shed · false-rejects V2only/V1only | gated_low ok (adm/ref) · atk · class-shed · global-shed · false-rejects V2only/V1only | V1 global-shed | max starvation V1→V2s |
|---|---|---|---|---|---|---|---|
| B1-farm-rate/rate-0 | 100% (29/0) | 0 | 100% (29/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 100% (29/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 100% (29/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 0 | 0s→0s/0s/0s |
| B1-farm-rate/rate-1 | 100% (29/0) | 120 | 100% (29/0) · atk 31 · cls 89 · glob 0 · FR 0/0 | 100% (29/0) · atk 120 · cls 0 · glob 0 · FR 0/0 | 100% (29/0) · atk 120 · cls 0 · glob 0 · FR 0/0 | 0 | 0s→0s/0s/0s |
| B1-farm-rate/rate-2 | 31% (9/20) | 240 | 100% (29/0) · atk 31 · cls 209 · glob 0 · FR 0/60 | 100% (29/0) · atk 216 · cls 24 · glob 0 · FR 0/60 | 100% (29/0) · atk 218 · cls 22 · glob 0 · FR 0/60 | 20 | 90s→0s/0s/0s |
| B1-farm-rate/rate-3 | 22% (6/23) | 243 | 100% (29/0) · atk 31 · cls 329 · glob 0 · FR 0/68 | 100% (29/0) · atk 216 · cls 144 · glob 0 · FR 0/68 | 100% (29/0) · atk 218 · cls 142 · glob 0 · FR 0/68 | 140 | 53s→0s/0s/0s |
| B1-farm-rate/rate-4 | 5% (1/28) | 248 | 100% (29/0) · atk 31 · cls 449 · glob 0 · FR 0/83 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/83 | 98% (28/1) · atk 220 · cls 260 · glob 1 · FR 0/81 | 260 | 116s→0s/0s/19s |
| B1-farm-rate/rate-100 | 0% (0/29) | 249 | 100% (29/0) · atk 31 · cls 11969 · glob 0 · FR 0/87 | 100% (29/0) · atk 216 · cls 11784 · glob 0 · FR 0/87 | 98% (28/1) · atk 220 · cls 11780 · glob 1 · FR 0/85 | 11780 | 120s→0s/0s/19s |
| B2-spread/rate-4-classes-1 | 5% (1/28) | 248 | 100% (29/0) · atk 31 · cls 449 · glob 0 · FR 0/83 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/83 | 98% (28/1) · atk 220 · cls 260 · glob 1 · FR 0/81 | 260 | 116s→0s/0s/19s |
| B2-spread/rate-4-classes-2 | 5% (1/28) | 248 | 100% (29/0) · atk 62 · cls 418 · glob 0 · FR 0/83 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/83 | 87% (25/4) · atk 223 · cls 253 · glob 8 · FR 0/72 | 260 | 116s→0s/0s/19s |
| B2-spread/rate-4-classes-4 | 5% (1/28) | 248 | 100% (29/0) · atk 124 · cls 356 · glob 0 · FR 0/83 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/83 | 69% (20/9) · atk 228 · cls 219 · glob 42 · FR 0/57 | 260 | 116s→0s/0s/19s |
| B2-spread/rate-4-classes-8 | 5% (1/28) | 248 | 23% (7/22) · atk 242 · cls 116 · glob 144 · FR 0/17 | 23% (7/22) · atk 242 · cls 116 · glob 144 · FR 0/17 | 23% (7/22) · atk 242 · cls 116 · glob 144 · FR 0/17 | 260 | 116s→58s/58s/58s |
| B2-spread/rate-4-classes-16 | 5% (1/28) | 248 | 5% (1/28) · atk 248 · cls 0 · glob 260 · FR 0/0 | 5% (1/28) · atk 248 · cls 0 · glob 260 · FR 0/0 | 5% (1/28) · atk 248 · cls 0 · glob 260 · FR 0/0 | 260 | 116s→116s/116s/116s |
| B2-spread/rate-100-classes-1 | 0% (0/29) | 249 | 100% (29/0) · atk 31 · cls 11969 · glob 0 · FR 0/87 | 100% (29/0) · atk 216 · cls 11784 · glob 0 · FR 0/87 | 98% (28/1) · atk 220 · cls 11780 · glob 1 · FR 0/85 | 11780 | 120s→0s/0s/19s |
| B2-spread/rate-100-classes-2 | 0% (0/29) | 249 | 100% (29/0) · atk 62 · cls 11938 · glob 0 · FR 0/87 | 100% (29/0) · atk 216 · cls 11784 · glob 0 · FR 0/87 | 83% (24/5) · atk 224 · cls 11701 · glob 80 · FR 0/73 | 11780 | 120s→0s/0s/19s |
| B2-spread/rate-100-classes-4 | 0% (0/29) | 249 | 100% (29/0) · atk 124 · cls 11876 · glob 0 · FR 0/87 | 98% (28/1) · atk 217 · cls 11783 · glob 1 · FR 0/85 | 57% (17/12) · atk 231 · cls 10576 · glob 1204 · FR 0/51 | 11780 | 120s→0s/19s/25s |
| B2-spread/rate-100-classes-8 | 0% (0/29) | 249 | 3% (1/28) · atk 248 · cls 6768 · glob 5012 · FR 0/3 | 3% (1/28) · atk 248 · cls 6768 · glob 5012 · FR 0/3 | 3% (1/28) · atk 248 · cls 6768 · glob 5012 · FR 0/3 | 11780 | 120s→116s/116s/116s |
| B2-spread/rate-100-classes-16 | 0% (0/29) | 249 | 0% (0/29) · atk 249 · cls 1980 · glob 9800 · FR 0/0 | 0% (0/29) · atk 249 · cls 1980 · glob 9800 · FR 0/0 | 0% (0/29) · atk 249 · cls 1980 · glob 9800 · FR 0/0 | 11780 | 120s→120s/120s/120s |
| B3-attacker-class/rho-0.1 | 4% (1/29) | 248 | 91% (27/3) · atk 31 · cls 452 · glob 0 · FR 1/79 | 92% (27/2) · atk 218 · cls 264 · glob 0 · FR 0/79 | 91% (27/3) · atk 221 · cls 261 · glob 0 · FR 0/78 | 261 | 116s→6s/6s/6s |
| B3-attacker-class/rho-0.5 | 3% (1/34) | 248 | 56% (20/15) · atk 31 · cls 464 · glob 0 · FR 1/58 | 57% (20/15) · atk 225 · cls 270 · glob 0 · FR 0/58 | 55% (19/16) · atk 229 · cls 266 · glob 1 · FR 0/55 | 266 | 116s→24s/24s/24s |
| B3-attacker-class/rho-1 | 5% (1/28) | 248 | 0% (0/29) · atk 31 · cls 478 · glob 0 · FR 4/0 | 1% (0/29) · atk 245 · cls 264 · glob 0 · FR 3/0 | 3% (1/28) · atk 247 · cls 261 · glob 0 · FR 1/0 | 260 | 116s→120s/117s/117s |
| B4-nat/no-attacker-demand-0.25 | 100% (29/0) | 0 | 76% (22/7) · atk 0 · cls 7 · glob 0 · FR 21/0 | 100% (29/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 100% (29/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 0 | 0s→17s/0s/0s |
| B4-nat/no-attacker-demand-0.5 | 100% (57/0) | 0 | 51% (29/28) · atk 0 · cls 28 · glob 0 · FR 85/0 | 100% (57/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 100% (57/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 0 | 0s→11s/0s/0s |
| B4-nat/no-attacker-demand-1 | 100% (122/0) | 0 | 26% (31/91) · atk 0 · cls 91 · glob 0 · FR 272/0 | 100% (122/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 100% (122/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 0 | 0s→7s/0s/0s |
| B4-nat/no-attacker-demand-1.9 | 97% (223/7) | 0 | 14% (31/198) · atk 0 · cls 198 · glob 0 · FR 575/0 | 94% (215/15) · atk 0 · cls 15 · glob 0 · FR 29/5 | 96% (220/9) · atk 0 · cls 9 · glob 0 · FR 15/7 | 7 | 1s→6s/3s/2s |
| B4-nat/no-attacker-demand-3 | 66% (248/128) | 0 | 8% (31/345) · atk 0 · cls 345 · glob 0 · FR 653/2 | 65% (244/132) · atk 0 · cls 132 · glob 0 · FR 28/15 | 66% (246/130) · atk 0 · cls 130 · glob 0 · FR 160/154 | 128 | 2s→5s/2s/2s |
| B4-nat/attacker-elsewhere-demand-0.25 | 5% (1/27) | 248 | 76% (22/7) · atk 31 · cls 456 · glob 0 · FR 0/61 | 76% (22/7) · atk 224 · cls 263 · glob 0 · FR 0/61 | 76% (22/7) · atk 227 · cls 259 · glob 1 · FR 0/61 | 260 | 115s→17s/17s/17s |
| B4-nat/attacker-elsewhere-demand-1 | 3% (3/119) | 246 | 26% (31/91) · atk 31 · cls 540 · glob 0 · FR 4/88 | 26% (31/90) · atk 214 · cls 357 · glob 0 · FR 3/88 | 26% (32/90) · atk 216 · cls 354 · glob 0 · FR 1/88 | 353 | 118s→7s/7s/7s |
| B5-proxy/undeclared-farmer-4 | 5% (1/27) | 248 | 0% (0/29) · atk 31 · cls 478 · glob 0 · FR 4/0 | 2% (1/28) · atk 244 · cls 264 · glob 0 · FR 2/0 | 5% (1/27) · atk 247 · cls 261 · glob 0 · FR 0/0 | 260 | 115s→120s/117s/115s |
| B5-proxy/undeclared-no-attacker-demand-1 | 100% (122/0) | 0 | 26% (31/91) · atk 0 · cls 91 · glob 0 · FR 272/0 | 100% (122/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 100% (122/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 0 | 0s→7s/0s/0s |
| B5-proxy/declared-farmer-4 | 5% (1/27) | 248 | 5% (1/27) · atk 248 · cls 0 · glob 260 · FR 0/0 | 5% (1/27) · atk 248 · cls 0 · glob 260 · FR 0/0 | 5% (1/27) · atk 248 · cls 0 · glob 260 · FR 0/0 | 260 | 115s→115s/115s/115s |
| B6-hints/all-missing-farmer-4 | 5% (1/27) | 248 | 5% (1/27) · atk 248 · cls 0 · glob 260 · FR 0/0 | 5% (1/27) · atk 248 · cls 0 · glob 260 · FR 0/0 | 5% (1/27) · atk 248 · cls 0 · glob 260 · FR 0/0 | 260 | 115s→115s/115s/115s |
| B6-hints/farmer-missing-only | 5% (1/28) | 248 | 5% (1/28) · atk 248 · cls 0 · glob 260 · FR 0/0 | 5% (1/28) · atk 248 · cls 0 · glob 260 · FR 0/0 | 5% (1/28) · atk 248 · cls 0 · glob 260 · FR 0/0 | 260 | 116s→116s/116s/116s |
| B6-hints/spoof-victim-class-farmer-1.5 | 100% (29/0) | 180 | 76% (22/7) · atk 180 · cls 7 · glob 0 · FR 21/0 | 100% (29/0) · atk 180 · cls 0 · glob 0 · FR 0/0 | 100% (29/0) · atk 180 · cls 0 · glob 0 · FR 0/0 | 0 | 0s→17s/0s/0s |
| B6-hints/spoof-victim-class-farmer-4 | 5% (1/27) | 248 | 5% (1/27) · atk 248 · cls 0 · glob 260 · FR 0/0 | 5% (1/27) · atk 248 · cls 0 · glob 260 · FR 0/0 | 5% (1/27) · atk 248 · cls 0 · glob 260 · FR 0/0 | 260 | 115s→115s/115s/115s |
| B7-demand/farmer-4-demand-0.25 | 5% (1/28) | 248 | 100% (29/0) · atk 31 · cls 449 · glob 0 · FR 0/83 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/83 | 98% (28/1) · atk 220 · cls 260 · glob 1 · FR 0/81 | 260 | 116s→0s/0s/19s |
| B7-demand/farmer-4-demand-1 | 3% (4/120) | 245 | 100% (124/0) · atk 31 · cls 449 · glob 0 · FR 0/360 | 99% (122/2) · atk 123 · cls 357 · glob 2 · FR 0/355 | 83% (102/21) · atk 146 · cls 334 · glob 21 · FR 0/296 | 355 | 117s→0s/4s/6s |
| B7-demand/farmer-4-demand-1.9 | 2% (5/235) | 244 | 88% (209/30) · atk 31 · cls 445 · glob 34 · FR 0/613 | 81% (194/45) · atk 54 · cls 426 · glob 45 · FR 0/568 | 68% (162/78) · atk 87 · cls 393 · glob 78 · FR 0/470 | 471 | 118s→2s/3s/3s |
| B7-demand/farmer-4-demand-3 | 2% (6/365) | 243 | 59% (217/155) · atk 31 · cls 449 · glob 155 · FR 0/631 | 58% (214/158) · atk 34 · cls 446 · glob 158 · FR 0/623 | 51% (187/184) · atk 61 · cls 419 · glob 184 · FR 0/543 | 603 | 118s→3s/3s/3s |
| B7-demand/no-attacker-demand-1.9 | 95% (226/13) | 0 | 95% (226/13) · atk 0 · cls 0 · glob 13 · FR 0/0 | 95% (226/13) · atk 0 · cls 0 · glob 13 · FR 0/0 | 95% (226/13) · atk 0 · cls 0 · glob 13 · FR 0/0 | 13 | 1s→1s/1s/1s |
| B7-demand/no-attacker-demand-3 | 67% (247/125) | 0 | 67% (247/125) · atk 0 · cls 0 · glob 125 · FR 0/0 | 67% (247/125) · atk 0 · cls 0 · glob 125 · FR 0/0 | 67% (247/125) · atk 0 · cls 0 · glob 125 · FR 0/0 | 125 | 2s→2s/2s/2s |
| B8-retry/farmer-4-retry-none | 5% (1/28) | 248 | 100% (29/0) · atk 31 · cls 449 · glob 0 · FR 0/83 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/83 | 98% (28/1) · atk 220 · cls 260 · glob 1 · FR 0/81 | 260 | 116s→0s/0s/19s |
| B8-retry/farmer-4-retry-1s-x5 | 5% (1/134) | 248 | 100% (29/0) · atk 31 · cls 449 · glob 0 · FR 0/83 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/83 | 100% (29/1) · atk 219 · cls 261 · glob 1 · FR 0/83 | 367 | 116s→0s/0s/0s |
| B8-retry/farmer-4-retry-20ms-x250 | 5% (1/6664) | 248 | 100% (29/0) · atk 31 · cls 449 · glob 0 · FR 0/83 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/83 | 100% (29/9) · atk 219 · cls 261 · glob 9 · FR 0/83 | 6896 | 116s→0s/0s/0s |
| B8-retry/farmer-100-retry-none | 0% (0/29) | 249 | 100% (29/0) · atk 31 · cls 11969 · glob 0 · FR 0/87 | 100% (29/0) · atk 216 · cls 11784 · glob 0 · FR 0/87 | 98% (28/1) · atk 220 · cls 11780 · glob 1 · FR 0/85 | 11780 | 120s→0s/0s/19s |
| B8-retry/farmer-100-retry-1s-x5 | 0% (0/141) | 249 | 100% (29/0) · atk 31 · cls 11969 · glob 0 · FR 0/87 | 100% (29/0) · atk 216 · cls 11784 · glob 0 · FR 0/87 | 100% (29/1) · atk 219 · cls 11781 · glob 1 · FR 0/87 | 11892 | 120s→0s/0s/0s |
| B8-retry/farmer-100-retry-20ms-x250 | 0% (0/6997) | 249 | 100% (29/0) · atk 31 · cls 11969 · glob 0 · FR 0/87 | 100% (29/0) · atk 216 · cls 11784 · glob 0 · FR 0/87 | 100% (29/9) · atk 219 · cls 11781 · glob 9 · FR 0/87 | 18748 | 120s→0s/0s/0s |
| B8-retry/jittered-farmer-4-retry-none | 35% (10/19) | 239 | 100% (29/0) · atk 31 · cls 449 · glob 0 · FR 0/57 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/57 | 100% (29/0) · atk 218 · cls 262 · glob 0 · FR 0/57 | 260 | 32s→0s/0s/0s |
| B8-retry/jittered-farmer-4-retry-1s-x5 | 46% (13/82) | 236 | 100% (29/0) · atk 31 · cls 449 · glob 0 · FR 0/47 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/47 | 100% (29/0) · atk 218 · cls 262 · glob 0 · FR 0/47 | 327 | 29s→0s/0s/0s |
| B8-retry/jittered-farmer-4-retry-20ms-x250 | 99% (29/231) | 220 | 100% (29/0) · atk 31 · cls 449 · glob 0 · FR 0/1 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/1 | 100% (29/0) · atk 218 · cls 262 · glob 0 · FR 0/1 | 491 | 0s→0s/0s/0s |
| B8-retry/jittered-farmer-100-retry-none | 0% (0/29) | 249 | 100% (29/0) · atk 31 · cls 11969 · glob 0 · FR 0/87 | 100% (29/0) · atk 216 · cls 11784 · glob 0 · FR 0/87 | 98% (28/1) · atk 220 · cls 11780 · glob 1 · FR 0/85 | 11780 | 120s→0s/0s/19s |
| B8-retry/jittered-farmer-100-retry-1s-x5 | 2% (1/139) | 248 | 100% (29/0) · atk 31 · cls 11969 · glob 0 · FR 0/85 | 100% (29/0) · atk 216 · cls 11784 · glob 0 · FR 0/85 | 100% (29/1) · atk 219 · cls 11781 · glob 1 · FR 0/85 | 11891 | 117s→0s/0s/0s |
| B8-retry/jittered-farmer-100-retry-20ms-x250 | 56% (16/3696) | 233 | 100% (29/0) · atk 31 · cls 11969 · glob 0 · FR 0/38 | 100% (29/0) · atk 216 · cls 11784 · glob 0 · FR 0/38 | 100% (29/9) · atk 219 · cls 11781 · glob 9 · FR 0/38 | 15463 | 23s→0s/0s/0s |
| B9-jitter-order/jitter-0-legit-first-false | 5% (1/28) | 248 | 100% (29/0) · atk 31 · cls 449 · glob 0 · FR 0/83 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/83 | 98% (28/1) · atk 220 · cls 260 · glob 1 · FR 0/81 | 260 | 116s→0s/0s/19s |
| B9-jitter-order/jitter-0-legit-first-true | 5% (1/28) | 248 | 100% (29/0) · atk 31 · cls 449 · glob 0 · FR 0/83 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/83 | 98% (28/1) · atk 220 · cls 260 · glob 1 · FR 0/81 | 260 | 116s→0s/0s/19s |
| B9-jitter-order/jitter-50-legit-first-false | 35% (10/19) | 239 | 100% (29/0) · atk 31 · cls 449 · glob 0 · FR 0/57 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/57 | 100% (29/0) · atk 218 · cls 262 · glob 0 · FR 0/57 | 260 | 32s→0s/0s/0s |
| B9-jitter-order/jitter-50-legit-first-true | 35% (10/19) | 239 | 100% (29/0) · atk 31 · cls 449 · glob 0 · FR 0/57 | 100% (29/0) · atk 216 · cls 264 · glob 0 · FR 0/57 | 100% (29/0) · atk 218 · cls 262 · glob 0 · FR 0/57 | 260 | 32s→0s/0s/0s |

### Held-out matrix (5 unseen seeds)

| cell | V1 journeys ok (legit adm/ref) | V1 atk adm | always ok (adm/ref) · atk · class-shed · global-shed · false-rejects V2only/V1only | gated ok (adm/ref) · atk · class-shed · global-shed · false-rejects V2only/V1only | gated_low ok (adm/ref) · atk · class-shed · global-shed · false-rejects V2only/V1only | V1 global-shed | max starvation V1→V2s |
|---|---|---|---|---|---|---|---|
| HO1-single-class/control | 100% (32/0) | 0 | 100% (32/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 100% (32/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 100% (32/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 0 | 0s→0s/0s/0s |
| HO1-single-class/rate-2.5 | 41% (13/19) | 236 | 100% (32/0) · atk 31 · cls 269 · glob 0 · FR 0/93 | 100% (32/0) · atk 213 · cls 87 · glob 0 · FR 0/93 | 98% (31/1) · atk 216 · cls 84 · glob 1 · FR 0/90 | 83 | 46s→0s/0s/8s |
| HO1-single-class/rate-6 | 1% (0/31) | 249 | 100% (32/0) · atk 31 · cls 689 · glob 0 · FR 0/157 | 100% (32/0) · atk 214 · cls 506 · glob 0 · FR 0/157 | 98% (31/1) · atk 217 · cls 503 · glob 1 · FR 0/153 | 503 | 118s→0s/0s/9s |
| HO1-single-class/rate-25 | 1% (0/31) | 249 | 100% (32/0) · atk 31 · cls 2969 · glob 0 · FR 0/157 | 100% (32/0) · atk 214 · cls 2786 · glob 0 · FR 0/157 | 97% (31/1) · atk 217 · cls 2783 · glob 1 · FR 0/151 | 2783 | 119s→0s/0s/9s |
| HO1-single-class/rate-4-demand-0.5 | 2% (1/61) | 248 | 100% (63/0) · atk 31 · cls 449 · glob 0 · FR 0/307 | 100% (63/0) · atk 183 · cls 297 · glob 0 · FR 0/307 | 90% (56/6) · atk 192 · cls 288 · glob 6 · FR 0/275 | 294 | 117s→0s/0s/7s |
| HO1-single-class/rate-4-demand-1.5 | 2% (4/187) | 245 | 100% (190/1) · atk 31 · cls 449 · glob 1 · FR 0/930 | 93% (178/13) · atk 69 · cls 411 · glob 13 · FR 0/869 | 74% (140/50) · atk 108 · cls 372 · glob 50 · FR 0/682 | 422 | 118s→2s/4s/4s |
| HO1-single-class/rate-4-periodic-legit | 3% (1/29) | 248 | 100% (30/0) · atk 31 · cls 449 · glob 0 · FR 0/145 | 100% (30/0) · atk 215 · cls 265 · glob 0 · FR 0/145 | 100% (30/0) · atk 218 · cls 262 · glob 0 · FR 0/145 | 261 | 116s→0s/0s/0s |
| HO1-single-class/jittered-5ms-rate-4-retry-1s-x5 | 52% (17/89) | 232 | 100% (32/0) · atk 31 · cls 449 · glob 0 · FR 1/76 | 100% (32/0) · atk 213 · cls 267 · glob 0 · FR 1/76 | 100% (32/1) · atk 216 · cls 264 · glob 1 · FR 1/76 | 337 | 28s→0s/0s/0s |
| HO3-spread/rate-4-classes-3 | 2% (1/31) | 248 | 99% (32/0) · atk 93 · cls 387 · glob 0 · FR 0/154 | 99% (31/0) · atk 214 · cls 266 · glob 0 · FR 0/153 | 78% (25/7) · atk 223 · cls 252 · glob 12 · FR 0/120 | 263 | 117s→1s/9s/15s |
| HO3-spread/rate-4-classes-5 | 2% (1/31) | 248 | 99% (32/0) · atk 155 · cls 325 · glob 0 · FR 0/154 | 98% (31/1) · atk 214 · cls 265 · glob 1 · FR 0/152 | 70% (22/9) · atk 226 · cls 220 · glob 43 · FR 0/108 | 263 | 117s→1s/7s/20s |
| HO3-spread/rate-4-classes-6 | 2% (1/31) | 248 | 99% (32/0) · atk 186 · cls 293 · glob 1 · FR 0/154 | 94% (30/2) · atk 216 · cls 258 · glob 8 · FR 0/146 | 65% (21/11) · atk 228 · cls 191 · glob 72 · FR 0/100 | 263 | 117s→1s/10s/20s |
| HO3-spread/rate-4-classes-7 | 2% (1/31) | 248 | 89% (28/4) · atk 217 · cls 245 · glob 22 · FR 0/135 | 77% (24/8) · atk 223 · cls 221 · glob 43 · FR 0/117 | 44% (14/18) · atk 234 · cls 167 · glob 97 · FR 0/65 | 263 | 117s→14s/20s/22s |
| HO3-spread/rate-100-classes-12 | 0% (0/32) | 249 | 1% (0/32) · atk 249 · cls 3614 · glob 8169 · FR 0/1 | 1% (0/32) · atk 249 · cls 3614 · glob 8169 · FR 0/1 | 1% (0/32) · atk 249 · cls 3614 · glob 8169 · FR 0/1 | 11783 | 119s→119s/119s/119s |
| HO2-shared/attacker-class-rho-0.25 | 1% (0/33) | 249 | 76% (26/8) · atk 31 · cls 457 · glob 0 · FR 0/126 | 76% (26/8) · atk 220 · cls 268 · glob 0 · FR 0/126 | 75% (25/8) · atk 223 · cls 265 · glob 0 · FR 0/125 | 265 | 115s→13s/13s/13s |
| HO2-shared/attacker-class-rho-0.75 | 1% (0/34) | 249 | 24% (8/27) · atk 31 · cls 476 · glob 0 · FR 0/39 | 24% (8/27) · atk 237 · cls 270 · glob 0 · FR 0/39 | 24% (8/27) · atk 240 · cls 267 · glob 0 · FR 0/39 | 266 | 115s→36s/36s/36s |
| HO2-shared/nat-no-attacker-demand-0.75 | 100% (95/0) | 0 | 32% (30/64) · atk 0 · cls 64 · glob 0 · FR 322/0 | 100% (95/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 100% (95/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 0 | 0s→8s/0s/0s |
| HO2-shared/nat-no-attacker-demand-1.5 | 100% (188/0) | 0 | 17% (31/157) · atk 0 · cls 157 · glob 0 · FR 784/0 | 98% (184/4) · atk 0 · cls 4 · glob 0 · FR 19/0 | 100% (188/0) · atk 0 · cls 0 · glob 0 · FR 1/0 | 0 | 0s→6s/2s/1s |
| HO2-shared/nat-no-attacker-demand-2.5 | 78% (245/68) | 0 | 10% (31/283) · atk 0 · cls 283 · glob 0 · FR 1088/17 | 76% (240/74) · atk 0 · cls 74 · glob 0 · FR 77/49 | 78% (244/70) · atk 0 · cls 70 · glob 0 · FR 175/167 | 68 | 2s→5s/2s/2s |
| HO2-shared/nat-attacker-elsewhere-demand-0.5 | 1% (1/65) | 248 | 46% (30/36) · atk 31 · cls 485 · glob 0 · FR 0/144 | 46% (30/36) · atk 216 · cls 301 · glob 0 · FR 0/144 | 46% (30/36) · atk 218 · cls 298 · glob 0 · FR 0/144 | 297 | 115s→9s/9s/9s |
| HO2-shared/nat-attacker-elsewhere-demand-1.9 | 2% (4/236) | 245 | 13% (31/209) · atk 31 · cls 658 · glob 0 · FR 9/145 | 13% (31/209) · atk 214 · cls 475 · glob 0 · FR 8/145 | 13% (32/208) · atk 216 · cls 472 · glob 0 · FR 3/145 | 471 | 118s→5s/5s/5s |
| HO2-shared/three-nats-no-attacker-demand-1.5 | 100% (191/0) | 0 | 46% (87/103) · atk 0 · cls 103 · glob 0 · FR 517/0 | 99% (189/1) · atk 0 · cls 1 · glob 0 · FR 6/0 | 100% (191/0) · atk 0 · cls 0 · glob 0 · FR 0/0 | 0 | 0s→5s/2s/0s |
| HO2-shared/three-nats-attacker-demand-1 | 2% (3/124) | 246 | 61% (77/50) · atk 31 · cls 499 · glob 0 · FR 1/372 | 61% (77/50) · atk 168 · cls 361 · glob 0 · FR 1/372 | 60% (75/51) · atk 173 · cls 351 · glob 7 · FR 1/363 | 358 | 117s→8s/8s/8s |
| HO2-shared/undeclared-proxy-no-attacker-demand-1.5 | 100% (188/0) | 0 | 17% (31/157) · atk 0 · cls 157 · glob 0 · FR 784/0 | 98% (184/4) · atk 0 · cls 4 · glob 0 · FR 19/0 | 100% (188/0) · atk 0 · cls 0 · glob 0 · FR 1/0 | 0 | 0s→6s/2s/1s |
| HO4-hints/half-legit-missing-farmer-4 | 1% (0/33) | 249 | 100% (34/0) · atk 31 · cls 449 · glob 0 · FR 0/167 | 100% (34/0) · atk 211 · cls 269 · glob 0 · FR 0/167 | 97% (33/1) · atk 215 · cls 265 · glob 1 · FR 0/162 | 265 | 115s→0s/0s/4s |
