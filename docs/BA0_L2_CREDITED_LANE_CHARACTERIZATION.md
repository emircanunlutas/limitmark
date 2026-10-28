# BA0 L2 credited lane: characterization of credit-farming starvation

Status: **characterization only.** Nothing under `defense/` was changed. Base: `8b45d05` (`ba0-n2-progression`). Evidence level: local, virtual time, the real
`JourneyLanes` driven through `enroll` and `decide` on an injected clock. No network, no L1, no real timers. Every number below is reproduced by
`tests/defense-l2-credited-lane-characterization.test.ts` (harness: `tests/support/l2-starvation-sim.ts`) and is exact, not sampled.

## 1. What was measured

Field parameters, read from `BA0_FIELD_V1.l2` (not transcribed): credited bucket capacity 10 at 2/s, unverified 3 at 1/s, K = 3 uses per token, 60 s epoch.
One legitimate client makes 30 valid journeys (render, then POST once) four seconds apart over 120 s (two full filter generations); the farmer renders
(a free, unbudgeted `open` GET that enrolls a credit) and POSTs at 4/s.

| Scenario (120 s, 30 legitimate journeys) | Legitimate completed | Farmer credited admissions | Credited bucket: admitted / shed (bound) |
| --- | --- | --- | --- |
| no farmer (control) | 30 / 30 | 0 | 30 / 0 (250) |
| farmer, render per POST, 4/s exact period | **1 / 30** | 248 of 480 | 249 / 261 (250) |
| farmer, one render per K POSTs, 4/s | **1 / 30** | 248 of 480 (160 renders) | 249 / 261 (250) |
| farmer, fabricated tokens (never enrolled) | 30 / 30 | 0 (122 unverified) | 30 / 0 (250) |
| farmer, one enrolled token reused | 30 / 30 | 3 (K), then 122 unverified | 33 / 0 (250) |

- The earlier exploratory shape (12 journeys, 60 s, farmer 4/s) gives **1 of 12 complete**, i.e. 11 of 12 starved. That reproduces the reported figure.
- The single legitimate admission is at t = 125 ms, inside the initial 10-token burst. The first credited shed is at 4.125 s. After that no legitimate
  mutation is admitted for the rest of both generations. The warm-up does not end the starvation; the burst is just the only thing that got through.
- Reasons: every legitimate refusal is `shed` / `lane_budget` / credited lane (503). There is no L2 error and no ledger refusal.

**Onset follows the farmer's rate against the refill, not the burst.** Single legitimate attempt per journey, farmer render-per-POST:
farmer 1/s: 30/30 · 1.9/s: 30/30 · 2.0/s: 9/30 · 2.1/s: 21/30 · 3/s: 2/30 · 4/s: 1/30 · 8/s and 20/s: 1/30. A farmer that stays under the credited refill takes
nothing from anyone; one at or above it takes whatever its polling reaches first.

### How robust is the 4/s result? (this matters)

A perfectly periodic 250 ms farmer is a **phase lock**: its tick lands on the same millisecond a token accrues (a token every 500 ms), so no gap exists.
That is the worst alignment, and a real client is never that regular, so the lock is reported but not relied on. With 120 single-attempt probes spread over every
phase at steady state, the legitimate client succeeds: no farmer 120, periodic 4/s **0**, 4/s with ±50 ms jitter **20**, 100/s with ±3 ms jitter **1**.

A shed consumes nothing (`lanes.ts:321`, the bucket take fails before the use is committed), so the same token can be retried until its credit ages out (1 to 2 epochs).
Retrying helps only against a slow poller: ±50 ms-jittered 4/s farmer, retry every second up to 5 times, 29/30 complete; a 100/s farmer with the same retry, **0/30**; a 100/s
farmer against a client retrying every 20 ms (a mean of 46.7 attempts per journey), 30/30. The outcome is a race decided by polling rate, with no allocation rule.
Whether the real form client retries at all was not examined.

## 2. Mechanism

1. **Minting is free.** An `open` GET is admitted unconditionally and holds no state (`lanes.ts:294`); after the response is delivered the plane enrolls its token
   (`l2-stage.ts` `Observation.onDelivered`, `lanes.enroll`). Nothing limits how many credits one party mints. Render volume only raises the Bloom false-positive rate;
   at these volumes the filter stays far from its poisoning threshold (asserted).
2. **Credit selects the lane; one global bucket bounds it.** A mutation with a genuine-looking token that has uses left is classified `credited` and takes one token from
   the single credited bucket (`lanes.ts:296-323`). K limits uses *per token* (amplification per render), not requests *per actor*.
3. **No spill, no refund, no actor input** (P1, P3, and the design rule that the sender is never an input). A credited request that finds the bucket empty is shed and
   never touches the unverified bucket, so a legitimate client holding a perfectly genuine token has nowhere else to go.
4. **Allocation is first-come at poll time.** The bucket is doing exactly its job: credited admissions never exceed capacity plus refill times time (249 against a bound
   of 250). What is missing is any rule about *who* gets the 2/s once demand exceeds it.

**Actual starvation versus intended rate limiting.** The limiter working is intended: the farmer's residual mutation is bounded at about 2/s whatever its request rate. The
starvation is the allocation, not the limit: legitimate demand here is 0.25/s, 12.5 % of the refill, and would be served in full (control, and the farmer-at-1/s rows).

## 3. Does it violate a documented guarantee?

No. The repository states this scenario as not claimed, in several independent places:

- `lab/defense/ba0-collapse-run.ts` `NOT_CLAIMED` (pinned by a test): "per-user fairness" and "protection against a stateful automation that renders and then posts, beyond the stated credited-lane bound".
- `defense/README.md` (Claim boundary; "Not implemented in Slice 1": "token-farming protection") and this directory's `BA0_LAYER_DIVERSITY.md` ("per-user fairness ... out of scope and not measured").
- The collapse runner gates `f3_farmer_bounded_by_k_per_render` (the documented bound: credited farmer admissions at most K x renders; here 248 <= 1440 and 248 <= 480), and states the
  rest as "reported: ... it is bounded, not defeated". It excludes the `farm*` phases from the legitimate-journey gates (`ba0-collapse-run.ts:263`), and `canary_post_always_credited`
  says "outside the farmer phases".

| Classification | Verdict |
| --- | --- |
| Reproduced behavior | **Yes**, deterministically, including the earlier 11-of-12. |
| Security vulnerability against a documented guarantee | **No.** The stated bound holds; the contrary guarantee is explicitly not claimed. |
| Intended but undesirable limitation | **Yes** for the rate bound; the allocation is a consequence of the design. |
| Missing fairness guarantee | **Yes.** Availability for a legitimate client with a genuine token is not guaranteed while any actor farms credit at or above the refill. |

Scope of impact: this is the BA0 lab and qualification track in front of a synthetic stand-in (`defense/README.md` states the real application is not protected by it and
production readiness is not claimed). No claim about the production application is made here.

## 4. Remediation alternatives (not implemented)

Any change to L2 is security-critical under `CLAUDE.md`, needs explicit approval, and must go through the reviewed-patch registry; `BA0_FIELD_V1` and its fingerprints must not be edited
(a parameter change is a new versioned set). Ranked by safety, with effectiveness against *this* farmer:

1. **Accept and document (no code).** Zero risk, zero effect. Add the farmer finding to the operator-facing non-claims and alert on credited `lane_budget` sheds that carry a genuine
   credit tag (already counted: `mutation.credited.shed`). Safe, observable, does not restore availability.
2. **Capacity versioning (new threshold set, e.g. a V2).** Raise the credited refill and capacity to a measured multiple of real legitimate demand. Effective only until the farmer's rate
   passes the new refill, and it raises the residual mutation bound, which is the quantity L2 exists to cap. False rejects: unchanged. Operationally trivial; needs calibration data that does not exist yet ("provisional-uncalibrated").
3. **Proportional (randomized) shedding on the credited bucket.** Turns winner-takes-all into a share roughly proportional to demand. Here legitimate success would move from about 3 % to roughly 45 %, but
   it decays as the farmer's rate grows, adds randomness to a deliberately exact, replayable accountant, and needs a new accounting identity. Moderate safety, partial effect.
4. **Price the mint.** A bounded enrollment budget (with a reserved legitimate share) or a client puzzle or challenge at render. Attacks the root cause (free credit). A mint budget alone only moves
   the starvation to the render side; a challenge or puzzle needs client changes and possibly an external service (needs approval). Higher complexity; touches enrollment, P2 retention and the filter sizing.
5. **Actor-keyed sub-budgets (per source or session).** Most effective against a single-source farmer, but it contradicts the stated design rule "the sender is never an input", adds false rejects behind shared
   addresses, and reintroduces identity handling the lab deliberately avoided. Needs an explicit decision to change that rule (the application's own Turnstile path already uses an opaque client key, so the precedent exists elsewhere).
   Highest effect, highest redesign cost.

Rejected: per-token fairness or fair queueing across tokens (the farmer mints tokens, so it gains shares in proportion to the tokens it mints); a dwell time on credit (pre-minting hides it); any refund or spill between lanes (violates P1 and P3 by design).

## 5. Recommendation

**DESIGN DECISION REQUIRED.** Not "fix required": no documented guarantee is breached and the stated bound holds. Not "no defect": the loss of legitimate availability is real and was independently reproduced.
The choice that has to be made first is whether L2 should *promise* availability to legitimate holders of a genuine credit under a credit-minting adversary. If yes, options 4 or 5 are the only ones that address the cause,
and option 5 requires reversing the no-sender-input rule. If no, option 1 (document and alert) closes the gap in the record.

## 6. Limits of this characterization

L2's decision function only: no L1, no async composer (50 ms deadline, 64-slot bulkhead), no HTTP, no real clock jitter. The farmer's and the legitimate client's timing are modeled, not observed on a network. The legitimate client is
single-source from the harness's point of view only; L2 cannot see it. A real client's retry behavior was not inspected. The numbers are properties of these parameters and arrival patterns; they are not a prevalence estimate.


## Errata and qualifications (appended after the V2 shadow evaluation; the results above are unchanged)

See `docs/BA0_L2_V2_SHADOW_EVALUATION.md` section 1.

1. The NOT_CLAIMED list in `lab/defense/ba0-collapse-run.ts` is not individually pinned for the string "protection against a stateful automation that renders and then posts, beyond the stated credited-lane bound". The contract test pins the phrase list containing "per-user fairness", and the collapse-run tests only require that evidence `notClaimed` equals the exported list. "Pinned by a test" above should be read with that limit.
2. "(measured)" means output of a deterministic virtual-time simulation, not a live-plane measurement.
3. The V1 characterization used one legitimate client at a fixed phase; the V2 matrix uses Poisson and periodic arrivals over several seeds.
4. The contention-gate threshold was unspecified in the decision study, and its H1 prediction applied to an ungated per-class ceiling. The shadow evaluation shows ungated ceilings fail the shared-network hypothesis (H2).
