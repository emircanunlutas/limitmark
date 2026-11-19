# Migration review proposal: `workers/ingress-signer/google-id-token.ts` single-flight correction (2026-11-08) — NOT APPROVED

Registry entry: `tests/support/reviewed-migrations.ts`, `reviewId` BASELINE-V2/LABORATORY, `change: added`, `hold: none`, **status PENDING** (no authorization, no scope; it exempts nothing). This is a separate migration event from the other 41 pending entries, created by owner decision D3 (2026-11-08). Nothing in this document approves anything.

## 1. Exact identities
| | git blob | sha256 (line endings normalized to LF) |
|---|---|---|
| Entry as first registered (reviewed in the baseline-v2 file review, still PENDING) | `e3d0272468682d0eb03ed21cdd829cd3f137c703` | `78bf1b131a159654415a32c001e55be8ca7944aa0a4b4d9266f81de9f6c4e07f` |
| This proposal (working tree, committed in the commit that adds this file) | `b21101ddf4359693ce5d12b092ee300507902b18` | `7c5706db44412a60d35d5f466de1277d8eaeb60e7175768a3c3d9881f955f530` |
| Historical blob at all three baselines | absent (added file) | — |

The registry now records the second row. The first row is preserved here (and in git history of the registry) so the review trail shows that the file changed after its first pin. No APPROVED entry was altered: the entry was PENDING before and is PENDING now; no approved review hash was overwritten.

## 2. The change (6 inserted lines, 3 deleted; `git diff` of the file)
```
  return async function getToken(): Promise<string> {
+   // Only the caller that STARTS an acquisition owns it and may clear it; ... (2 comment lines)
+   let started: Promise<string> | undefined;
    try {
      ...
-     inFlight = (async () => {
+     started = inFlight = (async () => {
      ...
-     return await inFlight;
+     return await started;
    } catch {
      cached = undefined;
      throw new Error("google-id-token-acquisition-failed");
    } finally {
-     inFlight = undefined;
+     if (started !== undefined && inFlight === started) inFlight = undefined;
    }
```

## 3. Defect and effect
Before: every call ran `inFlight = undefined` in its `finally`, including calls that merely JOINED an acquisition (or were answered from the cache). A call that finished while another caller's acquisition was still pending therefore detached that acquisition, and the next caller started a second concurrent one. The reachable trigger found and proven by test: the wall clock stepping back makes a stale cached token look valid again, a cache-served caller clears the pending refresh, and the next caller after the clock moves forward starts a duplicate refresh. Ordinary interleavings cannot reach it (reactions to one promise run in registration order with no intervening code), which is why seven of the eight new tests also pass on the old code; the eighth fails on it.
After: only the caller that creates an acquisition clears it, and only if it is still the current one. Everything else — endpoints, audience pattern, assertion lifetime, scope, claim checks, token caching rule, key import (non-extractable), error strings, the `cached = undefined` on failure — is byte-for-byte unchanged.

## 4. Security impact
- No change to token validation, audience restriction, IAM scope, endpoint selection or key custody (stated limits of the owner's approval).
- Fewer concurrent calls to the token endpoints in the clock-step case; no new request, header, secret or log path.
- Failure behavior unchanged: every failure is the fixed `google-id-token-acquisition-failed`; a failed acquisition leaves no stuck state (tested).
- Reachability: used only by `workers/ingress-signer/laboratory-index.ts` (cloud-run-lab signer). It is not reachable from the production signer entry.

## 5. Evidence
`tests/google-id-token-single-flight.test.ts` (8 tests, deterministic: promise gates and condition waits, no timers): shared fetch for simultaneous callers; a third caller joining while the first fetch is pending and a fourth while the ID-token stage is pending; successful completion and cache; rejection with cleanup and a new acquisition that can succeed; rejection followed by callers joining the replacement; a new acquisition after the refresh margin; misconfiguration without any fetch; the clock-step case (**fails on the previous code, passes now**). The existing `tests/google-id-token-provider.test.ts` (4 tests) is unchanged and passes.

## 6. Reviewer independence
Written and reviewed by the same agent. A second reader should compare the three-line behavioral diff in section 2 against the previous blob before any approval; the owner edits the registry (`status`, `authorization`, `scope`) if and when the entry is approved.
