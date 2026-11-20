# Customer origin policy v1

**Status.** Milestone 1 defines a data contract and a deterministic, test-only interpreter. A successful classification identifies an operation and its resource charge. The application still decides who may perform the operation. The fixtures declare expected behavior. Measuring continuity and enforcing admission belong to later work.

## Document and activation identity

A manifest describes one tenant, one deployment and one capacity domain. The table lists all top-level fields. Every field is required and every object has a closed set of members. Reject unknown versions, fields, references, duplicate JSON member names and invalid policies as a whole. A malformed policy cannot select a permissive default.

| Field | Meaning |
| --- | --- |
| `version`, `revision` | Literal `customer-origin-policy-v1` and a positive revision. Bind the selected revision to the SHA-256 digest of its exact UTF-8 JSON bytes, including whitespace. The digest is held outside the document. |
| `tenantId`, `deploymentId` | Identity supplied by trusted provisioning and verified independently of caller-controlled names. |
| `requestProfile`, `unsupported` | Literals `bounded-http-v1` and `deny`. The inventory consists of the operations in this manifest. There are no implicit asset, admin, health or unknown-route exceptions. |
| `domain` | One object with `id`, `backendRef` and `instances: 1`. The backend reference resolves to one fixed, trusted destination. Neither a request nor its route parameters select a backend. |
| `channels`, `classes`, `operations`, `journeys` | Nonempty arrays with unique IDs within each array. They define authenticated sources, capacity allocations, classification rules and ordered success criteria. |
| `capacity` | The domain's finite unit, queue, retained-byte and time budgets. |

Select one complete manifest atomically. A request verified for another tenant, deployment, domain or policy digest has no classification here. The verifier may obtain these bindings from trusted deployment configuration and the authenticated peer. This does not require every existing wire format to carry new fields. An in-flight request retains its verified policy binding. A replacement policy or restart cannot create a second full allocation while earlier work may still occupy the backend. Multiple independent gate instances, shared backends with uncounted work and replicated replay state are outside v1.

## Verified operation classification

1. The verifier supplies a successful result only after authenticating the peer, checking audience and freshness, applying the required replay check, and binding the actual request semantics and complete bounded body. Verification refusal ends processing. The test interpreter receives simulated results at this boundary. It accepts no raw header, priority, class or operation label as authority.
2. Select the configured channel by the exact verified tuple `(principal, audience, scheme, authority)`. That tuple must identify exactly one channel. A channel also has an `id` and `access` of `public` or `operational`. Aliases within an access category may share a principal and audience. Across public and operational channels, both the authenticated principal and its audience must be distinct. Channels may share a hostname. The host alone grants no access.
3. Match the channel ID, exact method, path and query. Check the operation's body conditions against verified facts. On success return `operationId`, `classId` and `costUnits`. The class and channel must have the same access category. Only a matching operational channel can consume an operational reservation.
4. Missing proof, mismatched scope, unknown channel and unsupported operation are distinct terminal results. All have zero entitlement to a queue, reservation or backend dispatch. Reaching a write class confers no business authorization. Session checks, token semantics, idempotency, and business validation remain with the relevant application or admission authority.

Each operation declares `id`, `channel`, `method`, `path`, `queries`, `body`, `classId`, `costUnits` and `effect`. The v1 profile uses the following grammar.

| Dimension | Match and validation rule |
| --- | --- |
| Scheme and authority | Exact configured `http` or `https` and lowercase ASCII hostname, optionally with an explicit decimal port from 1 to 65535. Labels have 1–63 letters, digits or interior hyphens. Compare the complete verified authority, including any port. HTTP in the demonstration represents an authenticated loopback fixture. Transport trust must be established separately. |
| Method and effect | GET and HEAD are reads. POST, PUT, PATCH and DELETE are writes. Each rule names one method. HEAD requires its own rule. |
| Target | Origin-form target, at most 1,024 ASCII characters. Match the root or up to 16 nonempty, case-sensitive segments. A literal segment consists of 1–64 ASCII letters, digits or `._~-`. Exclude the dot and double-dot segments. A template parameter such as `:sku` consumes exactly one valid literal segment. Its name starts with a lowercase letter, followed by up to 31 lowercase letters, digits or hyphens, and occurs once per template. |
| Query | `queries` lists 1–32 distinct exact alternatives. The empty string means the query separator is absent. A nonempty alternative is one `key=value` pair with 1–64 unreserved ASCII characters on each side. An empty separator, extra pair, fragment, percent encoding, backslash, empty segment or trailing slash outside the root is unsupported. Adapters must preserve the signed interpretation through dispatch. |
| Body | `null` requires zero bytes and no media type. Reads require `null`. A write may specify `mediaType`, positive `maxBytes` and boolean `requireSameOrigin`. Match the complete lowercase type/subtype exactly, with no parameters. A body of length zero through the limit can classify under that type. When same-origin is required the single verified Origin must equal the configured scheme and authority. The application decides payload validity. |
| Unsupported features | Unbound request semantics, streams, upgrades, unrepresented query/body formats and customer operations that depend on ambiguous normalization are ineligible for this profile. A hosting adapter must refuse them before supplying verified facts. The policy language defines no path rewrites, wildcards, implicit method conversions or body-dependent privilege selection. |

Validate overlaps before activation. Two rules overlap if they share a channel and method, their query sets intersect, and their path templates can match the same path. Compare segment by segment. A parameter intersects a literal or another parameter at that position. Equal-length templates intersect when every position intersects. Body predicates cannot resolve a route collision. Reordering the document never resolves ambiguity.

## Capacity and retained memory

All numeric limits are finite integers. Each class specifies `reservedUnits`, `maxActiveUnits`, `maxQueued` and `maxWaitMs` as well as its ID and access category. For domain capacity `C = activeUnits`, let `R[c]` be a class reservation and `M[c]` its ceiling.

- The shared pool is `S = C − sum(R[c])` and must be nonnegative. Validate `0 ≤ R[c] ≤ M[c] ≤ R[c] + S`. Ceilings may collectively exceed the total because their shared portions contend for the same pool.
- Each operation has a positive weight no greater than its class ceiling. If its class promises a floor, one operation of that weight must fit wholly within the floor. Charge the entire weight to its own reservation or to shared units. Never lend reservations across classes. Aggregate occupied shared units must fit `S`, and shared occupancy for class `c` must fit `M[c] − R[c]`.
- A waiting request consumes one entry under both its class and the domain `maxQueued`. Queueing is disabled for a class when both its queue and wait limits are zero. A class queue cannot exceed the domain count. A domain with zero queue entries has a zero `maxQueuedBytes` budget. A nonempty queue must at least accommodate one metadata charge.
- Charge each waiter `metadataBytesPerRequest + verified body bytes` against the domain's `maxQueuedBytes`, including empty-body reads. The metadata allowance must cover the complete retained non-body state per request, including headers, identifiers, queue and timer bookkeeping. Charge before retaining. The model permits one owned body copy and caps it at domain `maxBodyBytes` and the operation limit. An adapter that needs additional copies or cannot bound the metadata cannot use these bounds without accounting for them.
- For the active and queued requests owned by this gate, retained request bytes are bounded by `C × (metadataBytesPerRequest + maxBodyBytes) + maxQueuedBytes`. All active requests cost at least one unit. This accounts for gate-owned request state. Verification buffers, application work, sockets, process overhead and response buffering require their own bounds.
- Validate `maxWaitMs + dispatchMarginMs < proofWindowMs` and `maxWaitMs + dispatchMarginMs + executionTimeoutMs ≤ callerBudgetMs` for every class. At admission, clamp to the actual remaining verified proof and caller deadlines. Require the margin again at dispatch. Exhaustion sheds without starting application work. Cancellation while waiting discards the waiter. Once work has started, an ambiguous timeout cannot release its backend charge without confirmed termination or an enforceable execution bound.

The fixture budgets are provisional examples. An operator must establish their values against the backend, its dependencies and other work sharing either resource. A class floor describes units available to that class. It cannot distinguish two eligible customers within the class.

## Customer journeys and decision evidence

Every configured operation occurs in at least one ordered positive journey. A journey specifies its `id`, `steps`, minimum completion in basis points (`minCompletionBps`), end-to-end `p95LimitMs` and `recoveryLimitMs`. Each step names an existing `operationId` and a concrete matching `target`. The operation supplies its channel, method and input constraints. The step supplies the expected HTTP `status`, customer-visible `result` and business `receipt`.

For a read, `receipt: null` requires zero business mutations. For a successful write, the named receipt kind requires exactly one independently attributable mutation with the expected business identity. The demonstration's synthetic receipt is an App mutation observation. A commerce receipt represents an application commit correlated to the order or stock adjustment. An HTTP success alone cannot satisfy a write step.

In a future qualification run, count every started journey in its phase denominator. Count a completion only when all ordered steps, semantic results and receipts match the same journey. Unknown, missing and duplicate observations prevent a success decision. Require positive samples in baseline, contention and recovery. Measure p95 over all attempts with terminal observations and report incomplete attempts explicitly. Recovery requires an observed return to the declared thresholds after contention stops. M1 checks these declarations and example classifications in memory.

## Document limits and fixtures

UTF-8 JSON input is limited to 256 KiB. IDs use one lowercase letter followed by up to 63 lowercase letters, digits or hyphens. The manifest allows up to 16 channels, 32 classes, 128 operations, 32 journeys and 32 steps per journey. Unit and count fields and the revision are bounded by 65,535, byte fields by 1 GiB, and durations by 2,147,483,647 ms. The domain active limit, revision, class ceilings, cost, metadata charge, proof window, dispatch margin, execution timeout and caller budget are positive. Journey targets use 1–10,000 basis points and positive durations. Step statuses range from 200 to 399, and semantic result descriptions contain 1–256 trimmed characters.

The BA0 fixture declares the synthetic application's actual five-step journey, query alternatives and form media type using one representative fixed loopback authority. The storefront uses an independent route vocabulary, separate checkout capacity and separate warehouse credentials on the same hostname. The backend, principal and audience references in both manifests are logical fixture bindings. Both sets of budgets and service objectives are illustrative. [BA0 manifest](../../tests/fixtures/customer-origin-v1/ba0.json) · [Storefront manifest](../../tests/fixtures/customer-origin-v1/storefront.json) · [Conformance tests](../../tests/customer-origin-contract.test.ts)
