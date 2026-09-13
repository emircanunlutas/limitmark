# Phase 5C-R — Trusted Ingress and Strict Admission

Status: architecture decision, not an implementation or launch approval. Reviewed 2026-09-12 against current official documentation and the installed Next.js 16.3.4 guides.

Baseline: `da0b43d7390b518e31ac4cb8048efaa5af1c57c9`, plus the existing uncommitted Phase 5C work. This review adds only this document. No code, configuration, credentials, accounts, deployments, DNS, or provider resources are changed.

## 1. Executive conclusion

**Primary: Cloudflare Worker signed ingress + Vercel platform protection + Vercel-controlled, SQLite-backed Durable Object admission.** This combines B and H, not an edge-issued permission to bypass application checks.

Use one production admission authority, reached by every Vercel instance. Keep client and global rules in that same object; use separate pre/post histories. The public Worker attests request provenance and an IP-derived pseudonym. It cannot grant post-verification admission, call the admission service as Vercel, or bypass Turnstile. Preserve the separate origin bearer, admin authorization, submission-token validation, and PostgreSQL idempotency.

**Fallback: the same signed-ingress boundary, with a single-region Amazon MemoryDB primary behind a small authenticated admission API.** This changes the admission provider, not the ingress policy. It is a planned migration, never an automatic outage fallback. AWS explicitly documents primary consistency surviving failover; ordinary Redis branding does not establish that property. [MemoryDB consistency](https://docs.aws.amazon.com/memorydb/latest/devguide/consistency.html)

The design is safe to implement and test while persistence stays disabled. It is not yet safe to enable public persistence. Required platform configuration, real-path canonicalization tests, old-deployment retirement, and adversarial provider tests remain release gates.

Three limits are deliberately accepted:

- Known origin addresses remain reachable at Vercel's network edge. Platform authentication can prevent application execution, but cannot make Vercel disappear from the Internet or promise zero infrastructure cost.
- IP-derived identity represents a network address, not a person. Distributed attackers, CGNAT, privacy relays, and address changes remain relevant.
- The application protocol sends only a pseudonym, but **raw visitor IP never leaves Cloudflare is not established** for the standard Worker-to-Vercel fetch path. Cloudflare documents automatic visitor-IP headers on some Worker subrequests. No admission store receives raw IP. See section 9.8.

## 2. Why Phase 5C failed

The existing direct-Vercel identity policy cannot be extended merely by reading Cloudflare-looking headers. Verified Proxy Lite recognizes proxies internally but does not document a trustworthy application-visible real-visitor identity. Vercel says Advanced is necessary to expose the real client throughout the application, and Verified Proxy itself does not block direct access. [Verified Proxy guide](https://vercel.com/kb/guide/how-to-setup-verified-proxy)

The Phase 5A origin bearer proves possession of a shared path credential. Combining it with an unsigned visitor header would let a bearer holder choose arbitrary identities. Syntax validation, CF-Ray, Host, Origin, and known egress/header names do not repair that separation.

Atomic execution is also different from durable admission consistency. Upstash documents eventual consistency, asynchronous replication, conflict convergence, and deprecation of its former single-region strong-consistency mode. A successful Lua execution does not establish that its admitted history survives all documented failover/partition behavior. This is a qualification failure, not evidence that ordinary requests always overspend. [Upstash consistency](https://upstash.com/docs/redis/features/consistency)

Phase 5C correctly left the production provider registry empty and proxied persistence closed. Neither a local Redis test nor a synthetic header test could prove the missing platform guarantees.

## 3. Official platform facts and their limits

### Cloudflare and the identity boundary

For ordinary incoming traffic, Cloudflare supplies CF-Connecting-IP. Same-zone Worker subrequests are different: that header reflects x-real-ip, which an upstream Worker can change. Cross-zone Worker requests use a documented sentinel address; non-Cloudflare-zone subrequests can carry the visitor address. Pseudo IPv4 overwrite mode changes the identity-bearing headers. Consequently the signer must be the first approved Worker, not a generic signing endpoint behind arbitrary Workers. [Cloudflare HTTP headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/)

The rules-engine field `cf.worker.upstream_zone` identifies Worker-originated requests; it is empty for non-Worker requests. Reject nonempty values on the public signer ingress. This is a Cloudflare rules-engine check, **not** a client header or an invented `request.cf` property. [Upstream Worker field](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.worker.upstream_zone/)

Worker `request.cf` provides Cloudflare request metadata, but its documented interface is not an authenticated client-IP claim portable to Vercel. Use the Cloudflare-managed incoming address under the restricted entry topology. A newly constructed Request can have modified metadata; accepting arbitrary internal Requests/service bindings would extend the trust boundary. [Worker Request API](https://developers.cloudflare.com/workers/runtime-apis/request/)

Disable both `workers_dev` and `preview_urls` explicitly for the production signer; old versions must not be reachable through alternate signing entrypoints. These settings are separate and configuration-file drift can re-enable them. [workers.dev](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/), [Worker preview URLs](https://developers.cloudflare.com/workers/versions-and-deployments/preview-urls/)

### Vercel platform gates

Current documentation says **Vercel Authentication with All Deployments is available on all plans without an additional charge**, protecting production custom domains and generated URLs. Older pricing assumptions about requiring the Advanced Deployment Protection add-on are not applicable to this method. Authentication happens before Routing Middleware. Use All Deployments, not Standard's production-domain exception. Verify actual account availability before cutover. [Deployment Protection](https://vercel.com/docs/deployment-protection)

Automation bypass supports a server-to-server header. Its secrets work across all deployments in one project, and one selected secret is automatically exposed as a build/runtime system variable. They bypass Deployment Protection, certain system mitigations, and Bot Protection; active attack mitigations remain. Project P therefore uses two independently generated values: system-selected B-public for the public signer and non-environment B-admin for the admin gateway. They are platform access, not route-scoped or application authorization. P is shared by public and admin routes, while unreviewed PR/Preview code belongs in separate project Q. Never use bypass query parameters or request a bypass cookie. [Automation bypass](https://vercel.com/docs/deployment-protection/methods-to-bypass-deployment-protection/protection-bypass-automation)

Vercel also supports original-request-header WAF rules before middleware. Framework route/action-name rules may execute later. A header deny rule is a credible alternative perimeter gate, but does not itself attest visitor identity or replace protecting old deployments. [WAF rule configuration](https://vercel.com/docs/vercel-firewall/vercel-waf/rule-configuration)

The platform overwrites external forwarding headers to resist spoofing; Host/X-Forwarded-Host are routing context, not credentials. Advanced can restore visitor identity, but requires an explicitly reviewed Enterprise onboarding configuration. [Request headers](https://vercel.com/docs/headers/request-headers), [Reverse proxy support](https://vercel.com/docs/security/reverse-proxy)

Vercel OIDC can authenticate calls to a custom API with issuer, audience, subject, project, and environment restrictions. This is useful for **Vercel-to-admission-service authentication**, not visitor identity. Its ordinary claims do not identify an individual deployment, so release-specific authorization is still needed. [Custom API federation](https://vercel.com/docs/oidc/api), [OIDC claims](https://vercel.com/docs/oidc/reference)

### Durable Objects

A Durable Object is a uniquely addressed actor with private transactional, strongly consistent storage. Persistence, not an in-memory map, preserves admission history across eviction/restart. This is the relevant scope of serialization; different objects do not share an atomic transaction. [DO concepts](https://developers.cloudflare.com/durable-objects/concepts/what-are-durable-objects/), [Storage best practices](https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/)

Single-threaded does not mean arbitrary async handlers are atomic. External awaits permit interleaving. Put the complete SQL decision in one synchronous storage transaction and retain storage output gates. [DO concurrency rules](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/), [SQLite transaction API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)

Placement adds latency; location hints are best-effort initial-placement choices, not exact region guarantees. Jurisdiction restrictions differ from hints and can change object identity: choosing the same name in another namespace/jurisdiction does not preserve a quota. [Data location](https://developers.cloudflare.com/durable-objects/reference/data-location/)

## 4. Origin-discovery threat model

Assume the attacker knows every current, preview, branch, historical, and custom hostname, DNS history, certificates, routing metadata, and observable origin IP. They can send arbitrary ordinary headers and continuously probe known endpoints. A Host/Origin value matching the public site is not authentication; SNI is not a secret.

The design must reject an unauthorized request even when addressed perfectly. It assumes TLS endpoint authentication, uncompromised platform runtimes/control planes, protected signing/service credentials, and correct deployed policy. It does not assume attackers cannot visit the legitimate Cloudflare site.

An attacker can always request a legitimate Worker-mediated attempt using their own observed network address. That is intended. They cannot obtain a reusable signed identity artifact from the browser-facing response, request another address by supplying a header, or turn public knowledge of an origin into credential possession.

Distinguish three outcomes:

1. **Network isolation:** origin is not publicly reachable. Not supplied by this Vercel architecture.
2. **Platform isolation:** Vercel rejects before application execution. Supplied by correctly scoped Deployment Protection, except documented operational/verification exceptions.
3. **Application rejection:** origin bearer, signature, or action authorization rejects after some application work. Remains necessary if the platform gate is bypassed, but is not outcome 1 or 2.

## 5. Candidate architecture comparison

Ingress mechanisms and admission stores are separate dimensions. A, B, D, and E do not acquire strict admission merely by authenticating a request. F, G, and H do not authenticate visitors merely by storing counters.

| Candidate | Credible use | Known-origin behavior and principal limitation | Decision |
| --- | --- | --- | --- |
| A. Verified Proxy Advanced | Platform supplies application visitor IP after approved proxy onboarding; pair with a strict store | Does not itself block direct origin. Need platform gate, independent origin authentication, and explicit protection against other tenants' proxy/Worker traffic. Obtain the exact protected-header and ingress-match contract from Vercel | Credible Enterprise alternative, not the selected fallback; public docs alone are too coarse for this app's exact policy |
| B. Worker signed ingress | Attest bounded request + Cloudflare-side pseudonym; Vercel verifies locally | Signature-only design still incurs Vercel application rejection costs. Add platform gate. Captured mutation requires replay protection | Selected ingress mechanism |
| C. Worker + edge DO admission | Strict pre-cost decision before Vercel; signed forwarding | Can reduce Vercel invocation load, but adds edge-to-authority latency and shared trust. A signed `allowed=true` is not independent application admission | Defer edge pre-admission; if later added it is extra shaping, never a replacement for Vercel's post stage |
| D. Edge + global-only application limiter | Useful closed/degraded product policy where visitor identity is unnecessary | With an origin gate it resists direct writes, but all visitors share capacity. With no origin gate a discovered origin bypasses edge shaping | Not selected for strict per-client requirements; no automatic downgrade to it |
| E. Worker-issued opaque browser token | Short-lived admission capability, or continuity token | Stateless bearer is transferable/replayable; random IDs can be farmed. Stateful single-use tokens need the same authority and binding problems as signed ingress | Prefer server-to-server attestation; no browser-visible admission credential |
| F. Redis Cloud / managed Redis | Local Lua atomicity; some configurations improve persistence/replication acknowledgement | Strictness depends on exact product, acknowledgements, failover, eviction, and fencing. Active-active convergence is not a global strict limiter | Standard/asynchronous configurations not qualified; do not reject every Redis-compatible service categorically |
| G. PostgreSQL | One writer + transaction/locks can serialize client/global admission | Strong feasibility control. Using the business DB for pre-Turnstile traffic couples abuse load, connections, availability, and customer-data capacity | Not selected as the intake limiter |
| H. DO application authority | One SQLite-backed object handles both rules in each stage | Strict within one authority; hot-object and Cloudflare failure domain remain. App must authenticate RPC, not expose DO binding to public signer | Selected store/authority |
| I. MemoryDB single-region | Redis/Valkey-compatible primary with documented durable strong consistency across failover | Requires private networking or a small AWS-hosted API, adds provider/operational footprint | Selected fallback store |
| I. DynamoDB single-region transactions | Version-conditional updates of bounded client/global histories in one transaction | Strong regional transaction primitive; exact rolling logs, retries, item bounds, and authoritative time require more protocol work | Credible, not preferred at this scope |
| I. Private-origin hosting behind authenticated tunnel/mTLS | Can eliminate publicly reachable application origin when firewall/hosting enforce it | Requires moving the intake backend or hosting away from ordinary public Vercel ingress. Host secrecy still irrelevant | Escalation option if true network isolation becomes mandatory, not required for the present design |

Redis Cloud documents WAIT/WAITAOF choices and their availability consequences. These deserve provider-specific review, not a claim that a convenient WAIT call universally solves failover. Redis also explicitly warns that ordinary replication plus WAIT is not a CP system. Active-active remote endpoints can lack acknowledged local writes. [Redis Cloud resilience](https://redis.io/docs/latest/operate/rc/resilient-apps/), [Redis Software WAIT caveats](https://redis.io/faq/doc/1od27s187h/considerations-about-the-wait-command-in-redis-enterprise), [Redis replication](https://redis.io/docs/latest/operate/oss_and_stack/management/replication/), [Active-active failover](https://redis.io/docs/latest/operate/rc/databases/active-active/develop/app-failover-active-active/)

For **every** candidate, old builds retain their old behavior. A new gate in new application code does not patch old URLs. Apply project-level protection, revoke stale resource access, and remove vulnerable historical deployments. A known old URL plus a leaked project bypass secret is especially dangerous if that build still has database credentials. None of the proposed stores fixes that.

## 6. Decision matrix

These are ordinal engineering judgments, not measured benchmarks. No weighted total is used. All scores are 1–10, **higher is better**. Complexity means operational simplicity; lock-in means portability; cost means relative affordability for an inquiry-scale workload, whose actual volume is unknown. Cost scores are provisional, not a budget estimate.

To compare complete paths, rows A–E include a strict DO store unless stated otherwise. Rows F/G/I use B's signing design. All scored rows include an appropriate platform origin gate, independent application-origin check, Turnstile, and DB idempotency. The bare mechanisms without those additions would score lower. B+H is the primary, not two separate recommendations.

| Complete candidate | Ingress authenticity | Direct-origin resistance | Visitor integrity | Admission strictness | Failure isolation | Volumetric resistance |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A + DO, after Enterprise contract confirmation | 8 | 8 | 8 | 9 | 6 | 8 |
| B + H, selected primary | 9 | 8 | 8 | 9 | 7 | 8 |
| C, edge pre-DO + independent app post-DO | 9 | 8 | 8 | 9 | 5 | 9 |
| D, origin gate + global-only DO | 7 | 8 | 1 | 9 | 6 | 7 |
| E, stateful single-use browser token + DO | 8 | 8 | 5 | 9 | 6 | 8 |
| B + ordinary Upstash | 9 | 8 | 8 | 3 | 7 | 8 |
| B + Redis Cloud HA/WAIT, not fully qualified | 9 | 8 | 8 | 6 | 7 | 8 |
| B + PostgreSQL, qualified durable writer | 9 | 8 | 8 | 9 | 4 | 7 |
| B + MemoryDB single-region, selected fallback | 9 | 8 | 8 | 9 | 8 | 8 |
| B + DynamoDB regional transactions | 9 | 8 | 8 | 8 | 8 | 8 |

| Complete candidate | User transparency | Vercel compatibility | Operational simplicity | Portability | Cost at small scale | Testability |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A + DO, after Enterprise contract confirmation | 10 | 10 | 7 | 4 | 3 | 6 |
| B + H, selected primary | 9 | 8 | 6 | 6 | 8 | 9 |
| C, edge pre-DO + independent app post-DO | 8 | 8 | 4 | 5 | 7 | 8 |
| D, origin gate + global-only DO | 7 | 9 | 8 | 7 | 8 | 9 |
| E, stateful single-use browser token + DO | 7 | 8 | 4 | 6 | 7 | 8 |
| B + ordinary Upstash | 9 | 9 | 8 | 8 | 9 | 6 |
| B + Redis Cloud HA/WAIT, not fully qualified | 9 | 7 | 4 | 8 | 5 | 6 |
| B + PostgreSQL, qualified durable writer | 8 | 8 | 6 | 9 | 6 | 9 |
| B + MemoryDB single-region, selected fallback | 8 | 6 | 4 | 8 | 4 | 8 |
| B + DynamoDB regional transactions | 8 | 8 | 4 | 4 | 7 | 8 |

Score rationale:

- No origin-resistance 10: Vercel remains public, platform credentials can leak, and configuration matters. Shared endpoint knowledge is not a penalty because it is assumed everywhere.
- No visitor-integrity 10: even a perfect signature signs a network address, and the approved Worker ingress topology is a trust assumption. E scores lower because transferability and token farming weaken address attribution; D has none.
- DO and MemoryDB score 9 for a correctly implemented single authority, not for unlimited availability or immunity to administrative deletion. DynamoDB's transaction is strict, but its exact rolling/time protocol is less direct. Unqualified Redis rows are not launch candidates regardless of their other scores.
- C protects more Vercel capacity before forwarding but creates additional coordination and correlated Cloudflare load. B+H keeps strict pre/post decisions behind application verification, accepting more Vercel work for validly signed abusive traffic.
- PostgreSQL scores poorly for failure isolation when shared with business persistence; a separate database improves that dimension but adds operations/cost. MemoryDB improves admission-provider separation at the price of an API/networking layer.
- A avoids custom signatures but depends on Enterprise provisioning and a platform-specific header contract. B's cryptographic protocol and SQL decision can be tested locally, while platform ingress/failover claims still need provider tests.
- D's poor fairness during starvation hurts user transparency. E adds browser credential lifecycle and recovery behavior. B adds no normal challenge but does add network latency.

Primary selection follows the required properties and smallest defensible authority, not an optimized numerical weighting. If measured singleton load or Cloudflare dependency becomes unacceptable, the fallback becomes preferable even though it costs more.

## 7. Primary recommended architecture

### Public ingress

Run the signer only on the reviewed production public hostname route. Keep the existing exact hostname allowlist; canonicalize `www` to the apex with a safe GET/HEAD redirect, and accept mutations only on `https://limitmark.com`. No redirect of a mutation to another host. Pseudo IPv4 must be off. Reject Worker-mediated entry at the Cloudflare rules layer and reject missing, malformed, sentinel, or multi-valued address input in the signer. No XFF/X-Real-IP fallback.

The Worker strips caller-supplied attestation, identity, origin-secret, internal-provenance, deployment-selection, and Vercel-bypass material, then produces its own signed envelope. It never exposes signatures or origin credentials in responses. The reviewed route forwards to Vercel using the same public Host/SNI and a fixed configured origin relationship; it is not an arbitrary-URL proxy.

Use TLS with certificate verification on both hops and manual redirect handling. The target may be public knowledge. If the real platform requires a different upstream Host, stop the cutover: specify and re-review an exact signed public-to-upstream mapping rather than silently trusting X-Forwarded-Host.

### Platform and environment isolation

Use one **production-only Vercel application project P** for both public and admin routes, with Vercel Authentication / All Deployments and system variables enabled. Put PR/branch preview builds in genuinely separate project Q with separate resources and no Production credentials or persistence rights. Never run unreviewed PR code in P; its automatically injected B-public is one reason this separation is necessary.

The browser never deliberately receives either bypass credential or a bypass cookie. Sanitize both headers and query parameters; reject reserved bypass parameters rather than forwarding them. P may possess B-public at build/runtime and may observe B-admin on an authorized request. Those facts are not application authorization: the origin/signature, Access/`requireAdmin()`, admission, Turnstile, and persistence gates remain independent. Arbitrary code execution inside trusted P is a broader application compromise outside the protection offered by these application-level gates.

Preserve `x-limitmark-origin-secret` as a different credential from the platform bypass and signature key. Origin proof alone never supplies visitor identity. Preserve admin Access JWT validation/allowlist independently; the public signing key confers no admin authorization. The existing admin-hostname route needs an explicit protected forwarding path through the platform gate, not a broad exemption of the entire project. Public-intake disablement must not disable that admin path or its DB access.

**Mandatory provider-integration gate — dedicated admin gateway Worker.** Before enabling Vercel All Deployments protection on shared Production project P, the gateway serving only `admin.limitmark.com` validates the Cloudflare Access JWT against fixed issuer, audience, and identity policy before adding independently revocable B-admin. Its fixed reviewed upstream is P's Production `.vercel.app` target, never a caller-selected destination. B-admin must not be deliberately configured as an application environment variable, but P may observe it at request time. It must never enter browser JavaScript, a URL, cookie, redirect, response header, or browser-test `extraHTTPHeaders`. The admin gateway carries no public signer private key, IP-HMAC key, public origin bearer, admission credential, B-public, or Durable Object binding. Application-side `requireAdmin()` verification remains mandatory and independent.

### Admission service

Vercel calls a separate, narrowly scoped admission Worker over HTTPS. That service alone has the Durable Object binding. The public signer has no binding and no admission-service credentials.

Require a validated Vercel OIDC token for the exact production team/project/environment, plus a release-specific RPC authentication key. The latter is bound server-side to one deployment/release and can be revoked without changing the quota namespace. Verify request-body MAC/freshness for RPC; authenticate before DO access. Public Access JWTs are never accepted here. Runtime OIDC retrieval follows the supported Vercel helper, not a user-selected header or token issuer.

OIDC proves workload scope, not an individual end user, successful Turnstile, or a deployment ID. The release key supplies the deployment authorization that ordinary OIDC claims lack. A malicious production application remains inside the trusted computing base. Separate Workers and scoped deployment credentials reduce accidental/code-specific compromise; they do not survive a full Cloudflare account takeover.

Every production deployment uses the **same initialized authority ID and policy epoch**. The authority has a fixed server-owned policy, not caller-selected keys, limits, namespace, object name, or stage bypass flags. Environment/authority mismatches return unavailable. The admission service must have bounded request sizes, deadlines, JWT-key refresh behavior, and aggregate telemetry.

## 8. Fallback architecture

Keep sections 7 and 9's ingress and environment protections. Replace only the admission service/storage implementation:

`Vercel -> authenticated HTTPS admission API -> AWS Lambda in VPC -> single-region MemoryDB primary`.

Use a dedicated admission cluster, TLS, restrictive ACLs, private network access, no eviction, and a primary-only connection. Keep the complete bounded authority state in one key so one Lua operation can decide the rule set and nonce transition. Never read a replica to decide admission. Multi-Region MemoryDB uses asynchronous propagation/conflict merging and is not qualified by the single-region primary claim. [MemoryDB security](https://docs.aws.amazon.com/memorydb/latest/devguide/memorydb-security.html), [MemoryDB replication](https://docs.aws.amazon.com/memorydb/latest/devguide/replication.html), [MemoryDB Multi-Region](https://docs.aws.amazon.com/memorydb/latest/devguide/multi-region.html)

An AWS-hosted API is preferable to exposing Redis publicly or pretending a management PrivateLink endpoint supplies a Redis data connection. AWS documents the Lambda/VPC integration; it adds another runtime and network boundary to operate. [MemoryDB access](https://docs.aws.amazon.com/memorydb/latest/devguide/accessing-memorydb.html), [Lambda integration](https://docs.aws.amazon.com/memorydb/latest/devguide/LambdaMemoryDB.html)

The conservative fallback algorithm uses Redis TIME, exact timestamp histories, nonce state, and a **single final SET of a bounded serialized authority value**. The script validates and computes the entire next state in memory before that one mutation; any pre-SET error changes nothing. The value includes initialization metadata, both stages, client/global observations, and nonce transitions. Proposed initial maximum: 1 MiB, independently bounded history cardinality and execution time; overflow returns unavailable. A lost response after SET can charge the complete attempt, never just one rule. This retains a singleton bottleneck and rewrites more bytes than indexed SQL; load/cost qualification is mandatory.

Sorted sets are appropriate exact rolling-window data structures, but multiple ZADD/expiry commands introduce an error-path proof obligation: Lua atomic execution is not SQL rollback. They are not the initial fallback specification. Do not optimize into a multi-key script until its partial-error behavior meets the same contract. Supported engine scripting is documented, but a script emulator cannot prove MemoryDB's remote durability. [MemoryDB engines](https://docs.aws.amazon.com/memorydb/latest/devguide/engine-versions.html), [Redis scripting semantics](https://redis.io/docs/latest/develop/programmability/eval-intro/)

History expires logically by the same timestamps; a bounded idempotent maintenance call also prunes idle history via the same atomic replacement. The initialization marker must survive idle cleanup. Do not TTL-expire the whole authority and silently treat a missing key as a fresh budget. Physical cleanup has the same outage/backup-retention qualification as DO storage; this is not a promise of native per-entry Redis TTLs. Exact engine TIME/script/SET semantics and failure behavior require the later fallback qualification tests.

Do not implement this fallback simultaneously with the primary. Do not hot-switch from an unavailable DO to empty MemoryDB: that would reset history and permit extra admissions. A planned outage/cooldown or rigorously fenced state migration is required. It remains subject to the same origin, replay, Turnstile, DB, and stale-release gates.

## 9. Signed-attestation protocol specification

This is a proposed v1 protocol for implementation review, not an existing header contract supplied by Cloudflare or Vercel.

### 9.1 Cryptography and key separation

Use **Ed25519 for ingress signatures**, with the private key only in the production Worker secret store and verification keys in Vercel. This is preferable here to shared HMAC signing: a leaked Vercel verifier configuration or historical deployment does not acquire signing power. Workers document standard Ed25519 and HMAC support. Use supported WebCrypto/Node verification, not a JavaScript byte-comparison implementation or the legacy `NODE-ED25519` variant. [Cloudflare Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)

Use a separate random 256-bit HMAC-SHA-256 key inside Cloudflare for address pseudonymization. Do not derive it from the signing key, origin bearer, platform bypass, or an account identifier. Limiter-client identity is the authenticated pseudonym; Redis/DO never need a raw IP. A signature authenticates what the signer asserts, not the truth of a compromised signer's assertion.

### 9.2 Envelope

Send one dedicated header, conceptually `x-limitmark-ingress`, with a maximum encoded length of 2 KiB. Its wire form is `base64url(payload-bytes).base64url(signature)`, unpadded and canonical. Sign a fixed protocol domain separator followed by the exact payload bytes.

Use a fixed-position, fixed-length JSON array rather than a free-form object with duplicate property names. Re-encode and require exact canonical byte equality. Its fields are:

| Field | Binding/validation |
| --- | --- |
| Version | Literal `lm-ingress-v1`; no algorithm negotiation |
| Signing key ID | Short allowlisted ID; at most two active verification keys |
| Environment | Literal `production` |
| Audience | Exact configured project ID and **target deployment ID** |
| Issued-at | Integer Unix milliseconds; safe-integer bounds |
| Method | Uppercase allowlisted method |
| Scheme and public host | Literal HTTPS and exact approved hostname |
| Path | Exact approved path representation; mutation v1 accepts one literal endpoint |
| Query | Exact bounded query string; mutation v1 requires empty query |
| Content type | Exact permitted value under the v1 encoding rules |
| Content encoding | Literal identity/absent policy; reject compressed mutation bodies |
| Body length and SHA-256 | Exact forwarded bytes for mutations; zero/empty digest for bodyless methods |
| Identity-key version and pseudonym | Fixed approved version and 32-byte HMAC result, base64url |
| Nonce | Worker-generated 128-bit cryptographic random value for each mutation; explicit absent marker for safe reads |

Use explicit maximum lengths for every string and no optional extra fields. Malformed encodings, padding, comma-joined duplicate headers, whitespace variants, unsafe integers, unknown keys, and unknown versions fail closed. If the HTTP platform normalizes indistinguishable duplicate headers to one value, application code cannot count original wire lines. The security requirement is one unambiguous normalized envelope; reject all detectable ambiguity and test actual HTTP/1.1 and HTTP/2 behavior. Do not claim access to raw header multiplicity that the platform discards.

Project/deployment IDs are **public audience values, not secrets**. Compare them to platform configuration, not a caller-provided header. Vercel exposes these system IDs. Audience binding makes a captured envelope for deployment N invalid at deployment N-1 even when both know the same public verification key. [Vercel system variables](https://vercel.com/docs/environment-variables/system-environment-variables)

### 9.3 Address derivation inside Cloudflare

Read only the original platform-managed ingress CF-Connecting-IP in the approved route topology. Validate one address; normalize to canonical binary IPv4/IPv6, including IPv4-mapped IPv6 equivalence. Reject zone identifiers, ports, commas, missing values, pseudo addresses, and the cross-zone Worker sentinel. HMAC a domain-separated encoding of production identity version + address family + address bytes.

Do not aggregate all IPv6 visitors into an assumed /64 by default: delegated prefixes and privacy behavior vary. Full normalized addresses preserve the current semantics but allow address rotation. Do not identify a person or device from the result. No raw-address logging in the Worker, no response reflection, and no fallback to XFF, X-Real-IP, True-Client-IP, CF-Ray, or `request.cf` geolocation.

Reject upstream Worker requests using Cloudflare's rules metadata before the signer. Also reject detectable Worker hints/sentinel values in the signer as supplementary checks. Do not expose a service-binding/RPC signing API to another Worker. If topology changes so an upstream same-zone Worker can modify the address before signing, identity integrity is no longer established; disable intake and re-review.

This trusts Cloudflare's ingress classification and the restricted Worker deployment. It does not let Vercel cryptographically reconstruct the original socket peer independently of Cloudflare.

### 9.4 Mutation/body boundary and Next.js

Use a dedicated Node-runtime Route Handler, proposed `POST /api/public-inquiries`, as the sole public persistence entrypoint. Preserve the current form UX, schema, submission token, corrected-resubmission behavior, and repository logic behind that boundary. The old public Server Action must not retain an independently writable path.

Reason for this narrow boundary change: installed Next.js documentation says Server Actions POST to the route where they are used, can bypass a Proxy matcher that excludes that route, and need their own authorization. Parsed FormData is not the original byte stream. Signing a body's bytes but verifying only selected parsed fields would not verify the signed request.

For v1, use bounded `application/x-www-form-urlencoded` mutation bodies, no files and no content encoding. Set a hard **32,768-byte** limit, matching the existing intended action limit. Worker and Route Handler each read with an explicit byte counter and deadline, reject overflow/partial/truncated bodies, hash the full bytes, and only then parse. Do not trust Content-Length alone. Forward exactly the hashed bytes without multipart reserialization or decompression. Parsing must reject duplicate field names/unknown fields according to the schema policy.

This is bounded buffering, not streaming upload support. Request-body digests cannot safely authorize execution before the final bytes arrive. Large uploads would require a different protocol and are outside this inquiry flow.

The exact public inquiry pathname must bypass Next.js Proxy so the framework's body clone cannot hide an oversized tail. The mutation handler independently verifies the origin bearer and signed envelope against its actual method, URL, headers, byte count, and body digest before schema-dependent provider work. Never trust a client-set `body-verified`/`client-key` internal header. Explicitly preserve same-origin CSRF protection: exact Origin validation and the existing submission-token checks must replace the framework protection lost by moving out of a Server Action.

The installed `proxyClientMaxBodySize` guide warns that overflow truncates buffering and **does not reject the request**. Next.js 16.3.4 testing further demonstrated that the chunk crossing that threshold can be discarded in full, leaving a valid signed prefix visible to the Route Handler. Therefore the exact `/api/public-inquiries` pathname is excluded from Proxy matching; the Route Handler's bounded reader is the authoritative 32,768-byte gate and rejects as soon as byte 32,769 is observed. Built-path tests must cover missing/false lengths, varied chunks, and a valid signed prefix followed by an oversized tail. Preserve Proxy coverage for admin and unrelated paths, plus independent admin Server Action authorization.

Local references inspected: `node_modules/next/dist/docs/01-app/03-api-reference/03-file-conventions/proxy.md`, `01-app/01-getting-started/15-route-handlers.md`, and `01-app/03-api-reference/05-config/01-next-config-js/proxyClientMaxBodySize.md` under the same docs directory.

### 9.5 Canonical routing and forwarding

For the mutation endpoint accept only the literal path, no query, trailing-slash alias, encoded slash/backslash, dot segment, alternate case, Unicode path, method override, or rewrite. Compare actual handler method/path/Host and platform X-Forwarded-Host to the signed values and static policy. Both forwarded hostname values must be consistent; neither supplies authenticity by itself.

Sign safe GET/HEAD requests with their bounded URL representation, but do not grant mutation capability from a GET envelope. No GET may write business data or invoke the submission admission/Turnstile chain. Do not sign a generalized upstream URL, alternate deployment selector, or arbitrary port.

Disable or explicitly constrain client-selected deployment/skew routing for the mutation endpoint. A mismatch between the Worker target deployment and actual Vercel build is an outage, never a reason to ignore the audience. Avoid routing a public POST through Server Action forwarding and then treating the final method/path as unchanged without evidence.

Worker fetch uses `redirect: manual`; never follow a redirect while carrying ingress, origin, bypass, cookie, or service credentials to another host. Cloudflare specifically warns that Worker redirect-following can forward sensitive headers across hostnames. Validate/rewrite only approved browser-facing redirects without exposing credentials. [Request redirect behavior](https://developers.cloudflare.com/workers/runtime-apis/request/)

### 9.6 Freshness and replay

Proposed initial bounds: issued-at may be at most **5 seconds in the future** and at most **30 seconds old** at initial Vercel verification and at authority pre-claim. These are conservative protocol parameters to test, not measured provider clock guarantees. Generate the timestamp after the Worker has read/validated the bounded body, immediately before signing/forwarding.

Timestamp checks alone are insufficient for mutations. The authority atomically claims the signed nonce while admitting pre quota. Only the first successful claim proceeds. A duplicate never receives a second execution authorization, even if it presents the identical envelope. Pre permits last at most 60 seconds in authority time; nonce records remain at least 120 seconds, covering freshness, skew allowance, and in-flight use under those bounds. Post checks the pre permit, same client/request binding, active release, and unused post transition.

The browser is not sent the attestation; an ordinary malicious visitor cannot simply read it from developer tools. TLS substantially reduces capture opportunities but does not address logs, endpoint compromise, or accidental reflection. If a complete signed request is captured, an attacker may race the original. At most one pre-claim wins; this is at-most-one execution authorization, not proof which sender was legitimate. Body binding prevents using it for a changed inquiry. A captured nonce cannot be used again after its history expires because the envelope is then stale.

Allow replay of a still-fresh GET envelope only for explicitly safe reads; it confers no POST rights. Expensive dynamic GETs require their own cost policy, not consumption of the inquiry post budget. Immutable assets can remain outside visitor attestation at the application boundary; the platform gate and independent admin behavior still apply.

### 9.7 Key rotation and clocks

Keep signing and pseudonym key lifecycles separate. A signing-key rotation must not reset any limiter client key. Add the next public key to verifiers/authority policy first; deploy, test, then switch the Worker. Accept at most old/current signing keys for a bounded five-minute rollout interval, with explicit activation/retirement times. After the interval reject the old key at the authority as well as the application. Emergency rotation closes intake first and removes compromised keys without a compatibility exception.

A pseudonym-key rotation changes identity buckets. **Do not live-switch it and give everybody fresh quota.** Initial design uses infrequent planned rotation with intake disabled for at least the maximum history window plus permit/freshness drain (12 minutes for these values), then activates one new identity version everywhere. A future overlapping dual-identity migration needs its own atomic alias/accounting design; it is not v1.

Worker, Vercel, and DO clocks can differ. Reject out-of-range freshness; never let a request select an expiry, clock offset, or grace period. Persistent authority time is nondecreasing; backward observations must not expire history early. Detect inconsistent clock observations and close admission. A large forward jump cannot always be distinguished from genuine idle time: **exactness is defined against the trusted authority clock, not a claim of perfect physical UTC**. Monitor skew and test discontinuities. If perfect real-time bounds under arbitrary provider clock faults are required, this design does not establish them.

Workers' Date.now/performance timers advance with I/O in production, so a CPU-loop timer test is not authoritative. [Workers timers](https://developers.cloudflare.com/workers/runtime-apis/performance/)

### 9.8 Privacy boundary

Only the Worker computes the address pseudonym. The attestation carries no IP; the application identity verifier releases only an authenticated opaque client key to abuse controls. The admission service stores opaque client/nonce/operation identifiers, fixed policy names, and timestamps. No email, inquiry UUID, payload, submission token, Turnstile token, body digest, origin secret, or OIDC token enters quota history. Use a keyed request-binding digest for internal replay binding rather than storing a low-entropy customer-data hash.

**Do not claim that deleting a header in Worker code proves raw IP never reaches Vercel.** Cloudflare documents CF-Connecting-IP propagation on non-Cloudflare-zone Worker subrequests. The Remove visitor IP headers Managed Transform handles specified headers and has special XFF behavior; its availability does not by itself prove the required timing after the signer reads identity and before a particular Worker-origin fetch. [Managed Transform reference](https://developers.cloudflare.com/rules/transform/managed-transforms/reference/)

Qualification must examine the exact origin-bound headers using only synthetic addresses and restricted diagnostics. If the documented routing/transform arrangement cannot preserve trusted signer input while removing every automatically generated visitor-IP header, retain the narrower guarantee: no raw IP in the application identity output, admission store, or application logs; Cloudflare/Vercel may process it as infrastructure metadata. Strict no-IP-beyond-Cloudflare would require a separately proven egress arrangement or platform change. Do not add an unreviewed multi-Worker relay just to claim that property.

Disable header/body/key logging and tracing capture in both providers, redact reserved headers, avoid analytics keyed by pseudonym, and set retention/access policies for infrastructure telemetry. HMAC identity remains pseudonymous, not anonymous. SQLite/PITR backups can retain deleted history beyond live cleanup; include that in retention disclosures.

## 10. Strict admission-store recommendation

| Store | Atomicity/consistency scope | Failover/durability | Practical consequence |
| --- | --- | --- | --- |
| DO, one SQLite object | One transactional authority, globally addressed but not independently writable regional copies | Persisted strongly consistent storage; runtime restarts must not use memory as authority | Best fit; overload/unavailability rejects |
| Upstash single-region | Lua can serialize an operation; documented service model remains eventual | Former strong mode deprecated; connection/session guarantees are insufficient | Not qualified for this contract |
| Redis Cloud HA + WAIT/WAITAOF | Local operation plus explicit replication/persistence acknowledgements | Product/configuration-specific; insufficient evidence here of required fencing across every admitted failover | Conditional candidate, not declared universally unsafe or qualified |
| MemoryDB single-region primary | Strong primary; one script with single-key state replacement | Documented consistency preserved over primary failover | Credible fallback; private networking/API and whole-state rewrite cost |
| PostgreSQL writer | Serializable transaction or deterministic lock ordering plus fresh reads | Engine isolation is not a hosting-provider failover guarantee | Feasible; require durable writer service and bounded connection/lock waits |
| DynamoDB regional transactions | Serializable transaction for bounded conditional item updates | Regional ACID, not cross-region transaction replication | Credible primitive; more exact-window/time protocol engineering |

PostgreSQL implementation feasibility: one global coordination row per stage, acquire it first, then the client row, compute/prune/count and insert all observations in the same transaction. Read time after lock acquisition, not a transaction-start timestamp taken before a long wait. Do not hold a DB transaction during Turnstile. Use a small pool and strict statement/lock deadlines. A single writer serializes the relevant operations; serializable aborts need safe retry/operation identifiers. Hosting must preserve acknowledged commits or enforce a closed recovery interval. [PostgreSQL isolation](https://www.postgresql.org/docs/current/transaction-iso.html), [Replication tradeoffs](https://www.postgresql.org/docs/current/warm-standby.html)

Serverless PostgreSQL can satisfy the storage premise: Neon, for example, describes quorum WAL persistence and a single-primary consensus mechanism. That does not remove cold-start, pool, abuse-I/O, or business-DB coupling. Use a separate admission database if ever selected, and qualify the specific service/plan rather than assuming every serverless PostgreSQL endpoint is identical. [Neon architecture](https://neon.com/blog/architecture-decisions-in-neon)

DynamoDB can atomically commit version-conditional changes to client and global items after bounded reads, retrying conflicts safely. TTL is delayed physical cleanup, not exact expiry. Its transaction guarantees are regional; a global-table replica must not independently admit against partial replicated history. We do not need that distributed write topology. [DynamoDB transactions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html), [DynamoDB TTL](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html)

### DO algorithm and storage

One initialized production authority holds fixed policy, active releases/keys, nonce transitions, and indexed observations. At each stage:

1. Validate bounded input and fixed rule identities before accessing quota state. The service selects the rules; callers cannot invent limits or global keys.
2. In one `transactionSync` callback, obtain the authority timestamp `t`, enforce nondecreasing time, validate the nonce/permit transition, and remove expired relevant observations.
3. Count observations satisfying `t - windowMs < observedAt <= t` for **both** client and global rules. Observations exactly at the lower boundary are expired.
4. If either quota is full, insert no quota observations for either rule. Pruning expired data is not quota consumption. A failed pre attempt does not obtain a permit.
5. Otherwise insert the same unique attempt at timestamp `t` for both rules and perform the nonce/stage transition atomically. Never deduplicate different attempts merely because they have the same timestamp.
6. Release an allowed response only through normal confirmed storage output behavior. Any storage/transport/malformed-response ambiguity produces unavailable at Vercel; do not perform the downstream operation.

All SQL executes synchronously inside that transaction, using bound parameters and bounded result sets. No fetch, Turnstile, logging sink, or other external await belongs inside it. SQL rollback protects against a mid-transaction exception; retain input/output gates rather than opting into concurrency/unconfirmed output. This is a strict per-authority decision, not a cross-object transaction.

### Lifetime, placement, scaling, and recovery

Use indexed logical expiry on every decision and idempotent batched cleanup alarms for idle objects. Alarms are at-least-once and can be retried/delayed; safety must not depend on an alarm firing at an exact instant. Cleanup removes expired data only; it never grants/refunds quota. [DO alarms](https://developers.cloudflare.com/durable-objects/api/alarms/)

Live observations need no more than their rule window plus a bounded cleanup allowance; nonce/permit records use their explicit expiry. Physical deletion during provider outage and backup retention are not instantaneous TTL promises. Closed/unavailable behavior and bounded rows protect capacity if cleanup lags. Do not create unbounded rows for denied, unclaimed nonces.

Keep metadata identifying the initialized authority and policy epoch in durable storage. Missing metadata, unexpected namespace, PITR rollback, or suspected state loss must not bootstrap an empty live limiter automatically. Close intake, revoke in-flight permissions, reconcile, and wait the full maximum window/drain interval before initializing a replacement. Undetectable provider corruption is outside the declared guarantee; an arbitrary rollback cannot be made safe by an in-memory flag.

Use one object near the chosen Vercel execution region via a reviewed location hint/jurisdiction, without promising exact colocated latency. Every geography calls it. A global singleton is a deliberate hot spot: Cloudflare documents a soft 1,000 requests/second limit and overload errors, not unlimited throughput. Different clients' independent objects cannot atomically consume a shared global budget. [DO limits](https://developers.cloudflare.com/durable-objects/platform/limits/)

Do not create an object per anonymous visitor for this application. Under the current caps, accepted histories are modest, but **denied traffic and RPC/JWT checks still cost work**. Load-test realistic denial-heavy traffic; shape earlier at the edge. If throughput outgrows one object, re-evaluate the global contract or use explicitly partitioned escrow capacity. Do not silently shard the same nominal global quota into multiple full-sized budgets.

DOs are available on Free and Paid plans, with SQLite on both, but production should use a reviewed paid budget/limits posture. Requests, duration, and storage/SQL operations contribute to cost. A long-lived busy singleton and attack traffic can be expensive even when most requests deny. No claim of free global coordination or invented traffic volume is made. [DO pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)

Portability: preserve pure policy/conformance tests and an HTTPS admission interface; SQLite transaction logic can inform a PostgreSQL implementation. DO addressing, bindings, alarms, migrations, and consistency machinery are provider-specific. Data migration must preserve or safely drain live quota/replay history.

## 11. Should RateLimitAdapter change?

**Clarify its scope, not weaken its safety properties.** Keep all-or-none client/global consumption, exact authority-time rolling windows, no concurrent overspend, durable accepted history, and unavailable-on-ambiguity. Do not require independently writable low-latency replicas in every region: the application does not need them.

Specify that the contract applies to one named initialized authority/policy epoch shared by all production instances. Provider failover inside that authority must retain admitted state; migration to an empty authority is not a permitted retry. Availability during a partition is not promised. Unknown or lost state requires closure/recovery rather than a fresh budget.

The existing `consume(rules) -> allowed|limited|unavailable` can remain the narrow quota interface. Add a separate admission/replay coordinator with an opaque attempt identity and typed pre/post transitions, or wrap the adapter internally. The remote API should expose fixed-policy `claimPre`/`consumePost`, not an unrestricted arbitrary-rule Redis proxy. Do not overload `allowed` to mean reusable permission for any subsequent HTTP execution.

This is a small justified protocol addition for replay/ambiguous execution, not an invitation to refactor admin, persistence, or UI architecture. Exact-once admission authorization does not imply exact-once business persistence; DB constraints/idempotency remain independent.

## 12. Exact defense-in-depth chain

```text
Public Internet -> Cloudflare public signer + B-public -> shared Vercel P
  -> Next.js origin-bearer check + signed-envelope/body/audience verification
  -> schema + CSRF/submission-token checks
  -> Vercel-authenticated admission Worker -> ONE DO: PRE / Turnstile / POST
  -> PostgreSQL repository: validation, unique/idempotent write, constraints

Admin Internet -> Cloudflare Access -> dedicated admin gateway + B-admin -> same Vercel P
  -> application Access JWT verification + requireAdmin()
  -> independently available admin PostgreSQL repository

admission-rpc.limitmark.com -> Cloudflare admission Worker Custom Domain -> AUTHORITY
```

| Layer | Rejects/reduces | If bypassed, next independent check | Trust/credential | Failure behavior |
| --- | --- | --- | --- | --- |
| CF edge controls | Volumetric patterns, suspicious automation, upstream Worker entry | Signer, origin gate, app admission, Turnstile | Cloudflare configuration/runtime; upstream-Worker rule is part of identity trust | Outage blocks routed traffic; a missed abusive request still reaches strict app controls |
| Worker attestation | Spoofed visitor headers, unsupported host/path/body topology | Origin bearer, app verification, strict global quotas, Turnstile | Worker-only signing key and separate identity HMAC key | Missing/invalid signature denies; Worker fail-open never authorizes origin |
| Vercel platform gate | Known direct-origin traffic without project authorization, before app | App origin/signature checks | Platform policy + dedicated bypass credential | Misconfiguration loses pre-app isolation; application still denies unauthorized writes |
| Origin bearer | Requests lacking independent path credential | Signature, admission, Turnstile | Existing separate origin secret | Missing/malformed/mismatch denies; leak does not forge signature |
| Signature/body verifier | Altered request, wrong audience, stale/forged identity envelope | Replay claim, admission, Turnstile | Public verification keys + exact local routing policy | Fail closed; signer compromise defeats identity, not global admission/Turnstile |
| Schema/CSRF/submission token | Invalid form, cross-origin submission, invalid workflow token | Strict pre quota and Turnstile | App schema and submission-token key; Origin is CSRF context only | Fail closed with preserved safe form state |
| Admission API authentication | Public callers, Preview, wrong release, arbitrary policy selection | DO fixed policy, app Turnstile and DB | Vercel OIDC + release-specific RPC key, not edge signer | Unavailable/invalid denies before DO where possible |
| Strict pre + nonce | Cost-heavy verification volume and captured mutation replay | Turnstile + independent post namespace | DO transaction/state | Denial/unavailability prevents Turnstile |
| Turnstile | Some automated/non-human attempts | Strict post + DB constraints | Independently held Turnstile secret; exact response checks | Reject/unavailable consumes no post quota |
| Strict post | Accepted-write capacity, concurrent client/global overspend | DB idempotency/constraints | Same DO authority, distinct post history | Denial/unavailable prevents DB call |
| DB repository | Duplicate business effects and invalid persistence | Operational recovery/manual reconciliation | Restricted DB role, constraints, repository checks | No blind success or unsafe retry on ambiguous commit |

Independence is qualified: CF WAF, Worker, DO, and Turnstile share a provider; two credentials inside one compromised Worker are not independent against a whole-Worker compromise. Pre/post namespaces in one DO are purpose-separated, not independent infrastructure. Application Turnstile validation, Vercel workload authentication, and PostgreSQL constraints are independent of an attacker merely possessing the edge signing/origin credentials. A full Vercel application compromise can bypass its own checks; this design does not claim otherwise.

The admin chain stays separate: `Cloudflare Access -> protected Vercel forwarding -> application JWT/issuer/audience/expiry/allowlist verification -> admin repository`. Public limiter outage or intake-disabled mode must not disable legitimate admin data access. Admin does not gain authorization from a public attestation or origin bearer.

### Two-stage numbers and starvation

Retain initial pre `30/client/10 min + 300/global/min` and post `5/client/10 min + 100/global/min` as conservative **unvalidated operating defaults**, not measured capacity. Hard-bound configuration centrally at the authority; a quota increase or namespace change requires review. Do not let each deployment independently choose different policy values.

Ten addresses can still spend 30 rejected attempts each and exhaust the 300 pre admissions. They can be denied by Turnstile while preventing new legitimate requests from reaching it. A finite anonymous pre-cost budget cannot promise availability to distinguishable legitimate users before verification. Raising the cap changes the required attack cost, not that fact. Random shards or “reserved legitimate” unauthenticated lanes do not solve it.

The deliberate protection is **cost-safety and verified-write capacity separation**: those failures spend no post quota. Requests already admitted pre may finish through Turnstile and post even while pre is saturated. Newly arriving requests cannot reach verification until pre observations expire. After a burst, global capacity begins returning as observations reach exactly 60 seconds; all burst occupancy clears within 60 seconds of its last admission if there is no continuing attack. The same client's 30 attempts can persist for 10 minutes. A continuing distributed attack can keep pre unavailable indefinitely.

Cloudflare risk-based shaping/challenges and coarse edge rate limits reduce admissions reaching the app; they are not a hard fairness guarantee. Do not remove the global pre budget, silently increase it during an attack, or consume post capacity to pay for rejected verification. No instant reservation scheme can identify “legitimate” anonymous traffic without a new trust signal.

The pre cap bounds normal Siteverify calls under the no-blind-retry policy; it does **not** bound all Vercel/Worker/DO invocations, JWT parsing, rejected RPC work, or total provider charges. Aggregate denial/latency alerts and edge traffic controls are necessary. Actual inquiry volume, NAT concentration, latency, and costs must be measured before tuning.

## 13. Failure and compromise matrix

P = primary; F = MemoryDB fallback with the same ingress. Comparison includes the weaker alternatives where their behavior differs.

| Scenario | P/F outcome and surviving controls | Important alternative/difference |
| --- | --- | --- |
| Cloudflare WAF abuse-rule bypass | A validly routed request can reach pre; signature is not a bot verdict. Strict pre/post, Turnstile, DB remain | C's edge pre may reduce Vercel work; D has no app client isolation |
| Upstream-Worker exclusion fails | Signer may attest a Worker-modified address; global quotas/Turnstile remain. Close intake on detection | This exclusion is an identity trust premise, not an independent layer that can fail with identity unaffected |
| Worker bug | May misbind request/identity or leak headers; Vercel strict parser catches mismatches, but a valid false claim is trusted. Global/post/DB limits remain | A delegates more of this to platform configuration |
| Signing private-key leak only | Attacker can fabricate identity envelopes, but still lacks platform/origin credentials; Worker overwrites supplied signatures on legitimate ingress | With all edge credentials leaked, per-client integrity is lost; no claim HMAC pseudonym key rescues it |
| Whole Worker/edge-secret compromise | Platform/path proof and visitor integrity may all be defeated; attackers can spend global pre/post only through app Turnstile flow | C must not let an edge-signed `allowed` bypass app verification; P signer has no admission binding/credential |
| Origin-secret leak only | Does not forge attestation or bypass platform protection | Old bearer + unsigned-header design would fail here |
| Either P bypass-secret leak | Direct requests can invoke public or admin paths and old builds across P; new code still requires origin/signature or Access/`requireAdmin()` | Revoke that credential immediately; no claim of route scope or pre-app isolation during the leak |
| Direct-origin flood, addresses known | Vercel platform handles/rejects; no valid signature/origin proof can be obtained from host knowledge | Without platform gate, B incurs application rejection work. No store stops packets reaching Vercel |
| Old Vercel deployment | All Deployments protection is still needed, but either P bypass can cross it. Current audience and revoked release RPC keys deny old authority access; remove old DB-capable builds | New application checks cannot secure an old implementation that lacks them |
| Deployment Protection disabled | Origin/signature checks still deny direct writes, but app work/cost increases. Alert; treat as perimeter incident | Signature-only B always has this resource exposure |
| Limiter outage/overload | P DO or F MemoryDB/API failure => unavailable; no Turnstile on pre failure, no DB on post failure | D's global-only limiter also closes; in-memory fallback is forbidden |
| Admission state loss/PITR rewind | Close, revoke permits, drain full history/replay window, reinitialize under operator control | Ordinary eventual stores cannot make lost admitted history safe simply by reconnecting |
| Signed-request replay | Body/audience/freshness verified; one nonce claimant. Duplicate denied; capture can race original | E browser bearers are easier to capture/share unless equally bound/stateful |
| Timestamp manipulation | Signature prevents changing timestamp; bounded checks reject stale/future, DO owns quota time | Compromised signer can choose fresh timestamps; cannot choose DO's quota history time |
| Rotation mistake | Unknown/expired key or audience => outage. Never accept unsigned requests or unlimited key candidates | Pseudonym rotation without drain can reset client quotas; prohibited |
| Cloudflare outage | Public path unavailable; no DNS/unsigned/direct-origin fallback. P authority shares this domain | F isolates the limiter provider but cannot make the same CF public ingress available |
| Vercel outage | No writes; Worker returns controlled error, no automatic mutation replay | Moving pre to C does not restore business persistence |
| DB outage/ambiguous commit | Post may be spent without a successful write; no refund or blind duplicate write. Existing DB idempotency/reconciliation | G couples this outage directly to pre verification as well |
| Compromised Preview config | Separate project, no production private/DB keys; OIDC environment/project denies production authority even if an RPC key was copied | A copied production DB credential can independently authorize direct SQL if the DB accepts that role/network; the limiter cannot protect against it. Copied live production OIDC plus RPC credentials likewise defeats service isolation. Namespace strings do not contain credential theft |
| Stolen admin Access JWT | A valid allowlisted bearer may authorize admin actions until expiry/revocation/session controls; public signatures do not prevent this | Wrong audience/issuer/user/expired JWT denied. MFA does not make an already-stolen bearer un-replayable |
| Stolen Vercel service OIDC token | Still requires active release RPC MAC; revoke release key on incident. Compromise of both allows service calls until blocked | OIDC is not a one-request proof; do not confuse it with a public client identity |
| Admission Worker/account compromise | Fixed authority policy/state can be altered; intake must close. Independent app Turnstile and DB constraints remain if those components are intact | F moves this store/control-plane failure to AWS, but has another API to protect |

Vercel Function OIDC tokens can remain valid for up to two hours; they must never appear in public header dumps. Release-key revocation supplies a faster service cutoff than waiting for bearer expiry. [OIDC lifecycle](https://vercel.com/docs/oidc)

## 14. Ambiguous execution and replay are separate problems

An authority may commit and lose its HTTP response. Initial implementation performs **no automatic retry of a potentially consuming RPC**, no cross-provider fallback, and no worker retry of a mutation fetch. Timeout/connection loss/malformed response => unavailable. The attempt may remain charged; this is an accepted availability consequence, not an overspend or a promise of no charge on failure.

Use a unique operation identifier and one-use state transitions even with retries disabled: infrastructures and callers can duplicate requests. At most one pre execution and one post transition can win. A duplicate must not return an `allowed` result that grants a second Vercel invocation permission to run Siteverify or DB code. If future status lookup/idempotent retry is added, separate “already committed” from “you are the sole execution owner.”

The pre response supplies an opaque, short-lived handle tied to the verified envelope/client/release and held only in the executing Vercel request. After Turnstile success, post consumes that handle once and client/global post quotas atomically. No browser-supplied `verified=true`, edge flag, or origin-secret shortcut is accepted. Turnstile rejection/unavailability never reaches post.

Post admission is not a transaction with PostgreSQL. A crash between post admission and DB loses a permit; a crash after DB commit can lose the response. Do not refund quota on an uncertain failure, and do not remove repository uniqueness/idempotency to make retries easier. A corrected submission obtains a fresh Worker attestation and follows the existing application's resubmission/token lifecycle. Its content is not retained by the limiter.

## 15. User-experience impact

The Worker signature, OIDC calls, origin checks, and nonce claims are invisible. Legitimate users should not see a Vercel login; that indicates a broken gateway/platform credential. Keep Turnstile interaction-only and use managed edge challenges only when risk warrants. No blanket VPN, ASN, privacy-relay, or proxy bans.

The added synchronous authority calls increase submission latency; measure p50/p95/p99 before choosing deadlines. Proposed starting RPC timeout: 2 seconds per stage; tune only with measured provider behavior. Keep form values on recoverable failure, distinguish validation errors from temporary unavailability, and offer a bounded retry indication without exposing which global/client rule denied.

Shared offices/CGNAT can exhaust a five-submission client quota together. Mobile/IPv6 churn can get fresh buckets. Privacy relays share egress and are not evidence of malicious users. The global quota is the robust capacity backstop; the client rule is only a friction/cost heuristic. Review aggregate legitimate-denial rates before changing limits. No fingerprinting or raw-IP analytics are proposed to compensate.

## 16. Implementation phases — all initially closed

1. **Protocol and local conformance:** implement canonical envelope verification, address normalization in a Worker-only module, test vectors, byte limits, and replay state machine. No production provider registry entry or persistence enablement yet.
2. **Local authority:** implement SQLite-backed DO with fixed pre/post policies, initialization sentinel, transactional rule/nonce transitions, deadlines, and failure mapping. Test in workerd/Workers test tooling, including storage restarts. Keep pure-policy tests provider-independent.
3. **Application boundary:** add the narrowly scoped raw-body Route Handler, preserve schema/CSRF/token/repository behavior, and close the old public mutation entry. Preserve admin actions and closed intake. Verify no framework normalization or Proxy truncation bypass.
4. **Service authentication/isolation:** add strict Vercel OIDC verification, bounded JWKS retrieval/cache, release-specific RPC MAC, deployment audience, and exact resource/environment checks. Local/Preview must never construct production clients from copied ordinary settings alone.
5. **Operator-reviewed non-customer sandbox:** only after separate permission, create isolated test resources/projects and test actual Worker/Vercel/DO behavior, platform gate, headers, timing, restarts, and replay. Synthetic data only. No production DB or Turnstile required for ingress/admission qualification.
6. **Production perimeter preparation:** separate production and preview projects; protect/retire every old deployment; stage keys and known fixed routing; verify All Deployments and independent admin path while public intake remains disabled.
7. **Closed production ingress/admission smoke:** after explicit authorization, test real path and strict authority without customer persistence. Failure of any trust premise blocks promotion.
8. **Separate persistence launch review:** only after prior gates and existing tests pass, review actual Turnstile, DB, secrets, retention, and operational readiness. This architecture document is not that authorization.

Do not implement primary and fallback in parallel. Do not introduce a generic plugin/provider abstraction beyond what the admission interface needs. Do not change UI styling or unrelated deferred findings.

## 17. Manual provider/account requirements

- Cloudflare production route with fail-closed behavior; no `passThroughOnException`; public Worker preview/dev entrypoints explicitly disabled. Cloudflare documents fail-closed route behavior for exhausted limits. [Workers limits](https://developers.cloudflare.com/workers/platform/limits/)
- Exact public domain/origin relationship with TLS verification, no unreviewed upstream Worker/service binding, Pseudo IPv4 off, and a deployed upstream-Worker exclusion rule. Preserve narrow certificate/deployment verification behavior; no mutation exceptions.
- Separate production signer and admission Worker permissions/secrets; only the admission service binds the production DO namespace. Separate non-production namespaces/resources and operator initialization authority.
- One shared Production Vercel application project P with All Deployments protection and exact immutable identity; separate Preview project Q and CI trust. Both gateways target P. Inventory generated, branch, custom, historical URLs, protection exceptions, share links, both bypass credentials, and any old DB credentials. Unsafe historical builds must lose effective Production access; latest code and origin URL secrecy do not protect them.
- Resource-level production DB authorization/network restrictions and separate secret distribution remain mandatory. An application environment check cannot stop malicious Preview code that has acquired a usable production DB password and opens its own connection. Use provider-supported workload identity restrictions where available; do not claim admission OIDC also protects a separate password-authenticated DB.
- Distinct B-public, B-admin, application origin bearer, ingress signing, identity HMAC, release RPC, submission-token, Turnstile, database, and admin credentials. B-public may be platform-injected into P; B-admin is not deliberately configured there but can be observed on an authorized request. Neither bypass satisfies application authorization. Never deliberately place secrets in `NEXT_PUBLIC_*`, source, query strings, diagnostics, or browser-visible output.
- Vercel OIDC federation with exact issuer/JWKS endpoint, audience, subject, immutable owner/project checks and production environment. No token-selected issuer/JWKS fetching. Unknown-key refresh is rate-bounded; exhausted cache/network validation fails closed.
- DO Paid plan/budget review, namespace/jurisdiction selection, migration permissions, SQL storage/retention policy, aggregate alerts, and incident ownership. No admission runtime credential may delete/reset the authority.
- For fallback only: AWS account/VPC, authenticated API/Lambda, regional MemoryDB/ACL/TLS/no-eviction settings, restricted administrative operations, and approved regional failover testing.
- Review automatic infrastructure IP/header logging separately from application logs. If literal no-IP-egress is required, obtain a documented supported egress configuration before making that claim.

No requirements above were configured or exercised against real resources in this task.

## 18. Required adversarial tests

### Deterministic protocol and application tests

- Direct-Vercel legacy closed/test mode remains correct; unknown mode is unavailable; no automatic signed-to-direct/global-only fallback.
- Legitimate synthetic first-Worker identity succeeds; missing origin bearer, missing signature, spoofed CF/XFF/X-Real-IP, malformed/multi-hop address, sentinel, and unsupported topology fail.
- IPv4, IPv4-mapped IPv6, compressed/expanded equivalent IPv6; address family/domain separation; identity module output contains only the opaque key.
- Every signed field changed separately; signature/key/algorithm confusion; duplicate/merged headers; padded/noncanonical base64; JSON shape, extra fields, oversized strings, integer overflow; fixed-host/method/path/query/audience mismatch.
- Body changed, truncated, oversized, empty, chunked, false Content-Length, compressed, duplicate form fields, invalid UTF-8 policy, parser discrepancy, and hash computed over different bytes. No provider call before verification.
- Alternate mutation routes, trailing slash, percent encoding, dot segments, RSC/prefetch headers, action headers, method override, rewrite and skew/deployment routing. Old Server Action cannot persist.
- Freshness exact boundaries, future/stale, Worker/Vercel/DO skew, clock rollback/forward jump, signer-key overlap/retirement, pseudonym rotation with preserved/closed budgets.
- Replay before original, after original, concurrent capture race, after response loss, after nonce cleanup, old deployment, wrong release, and stale envelope with a new outer HTTP request.
- OIDC wrong issuer/audience/team/project/environment, expired/not-yet-valid, unsupported alg, malformed JWKS, key rotation/outage, copied RPC credential in Preview, public Access JWT presented as service token.

### Exact authority tests

- Client+global accepted together; either denial leaves the other unconsumed; simultaneous callers cannot exceed either quota; identical timestamps record distinct accepted attempts.
- Exact `(t-window, t]` boundary and cleanup; expired history ignored even if alarm delayed; bounded physical cleanup, bounded denied-state allocation, initialization sentinel, wrong namespace/jurisdiction/epoch.
- Mid-transaction exception rolls back observations and nonce transition; object eviction/restart restores state; no memory fallback; overload/HTTP failure/timeout/malformed/lost response unavailable with no unsafe retry.
- Duplicate pre nonce and duplicate post handle never authorize a second execution; pre lease expiry; post without pre; post for another client/body/release; no caller-selected quota policy.
- Turnstile reject/unavailable consumes pre only; verified request consumes strict post pair; post denial/outage prevents persistence; pre outage prevents Turnstile; no origin/edge bypass flags.
- Idempotent repository write/replay, crash before/after DB commit, corrected legitimate resubmission, preserved form data, and no ambiguous-success/refund behavior.
- Simulate 10 clients x 30 rejected attempts; prove pre starvation, zero post consumption, recovery boundaries, existing pre requests continuing, and sustained distributed exhaustion.
- Privacy assertions over all outbound limiter requests, errors, logs, traces and keys; no raw IP, payload, tokens, secrets, or client-key metric labels.

### Real provider/platform smoke — later, synthetic data only

1. Verify HTTPS certificates and exact Host/SNI mapping, no redirect credential leakage, protected request-byte continuity, platform-derived deployment ID, and bounded timing.
2. Test a normal IPv4 and IPv6 visitor through Cloudflare. Submit spoofed identity headers from an ordinary client, same-zone Worker, cross-zone Worker, alternate Worker URL, and service-binding path where configured; verify expected rejection before signing.
3. Probe known current/historical/generated/custom origins directly with ordinary spoofed headers, correct Host/Origin where transport allows, no credentials, one credential at a time, and synthetic captured attestation. Verify whether denial occurred at platform or application, not just the status code.
4. Verify both gateways target the same P, B-public and B-admin differ, and neither bypass becomes a browser cookie/query/response header. Verify each credential's project-wide behavior, All Deployments, operator/CI access, admin Access path, certificate verification routes, and static assets without treating bypass as POST authorization.
5. Inspect origin-bound headers with synthetic addresses in a restricted temporary diagnostic; report whether raw-IP suppression is actually supported. Do not deploy an all-headers public echo endpoint.
6. Execute actual DO storage transactions with concurrent requests through multiple Vercel instances; verify all-or-none and recorded winners, exact expiry, idle cleanup, restart/deployment continuity, delayed/lost responses, and stale-release denial. Local tests do not prove provider replication/failover.
7. Exercise safe provider failure/latency injection and supported restart scenarios in isolated resources. Cross-region or infrastructure failover claims need provider-supported evidence, not a mock. Never reset live production history for a test.
8. Check dashboards/logs/backups/retention policies for forbidden data, and validate aggregate cost/latency alerts. Load-test denied as well as accepted requests.
9. With synthetic Turnstile/DB adapters, prove pre/post order and no-write failures; only a later authorized test uses real verification/persistence resources.
10. For MemoryDB fallback qualification, additionally run exact Lua against the selected engine, primary failover with concurrent calls, single-key replacement/cardinality bounds, no replica reads, no eviction, expiry/idle-cleanup/clock boundaries, failures before/after SET, and lost-response behavior.

### Repository regression gates for implementation

Run `npm test`, `npm run test:db:required` when an isolated `TEST_DATABASE_URL` is available, local DO integration tests, full Playwright, persistence guard, edge/origin, closed-intake, blocker/admin auth/dashboard/mutation suites, lint, strict typecheck, production build, `npm audit --omit=dev`, and `git diff --check`. Missing DB/provider coverage must be explicitly reported, not counted as a pass. Preserve Production-demo prohibition, Preview non-persistence, and admin availability when public intake is disabled.

This design-only review did not rerun application regressions or claim new provider test results. The Phase 5C report's unresolved test failures/skips remain unresolved by this document.

## 19. Deployment ordering, migration, rollback, telemetry, incidents

### Key generation and custody

Generate signing keys and independent 256-bit symmetric secrets with approved cryptographic tooling, outside source control, only during the later authorized provisioning phase. Record public key IDs/fingerprints and owners, not secret values. Use separate production/sandbox material. Vercel receives only the ingress public keys; the public Worker receives no Turnstile/DB/admission-service credentials.

### Safe cutover ordering

1. Inventory existing deployments and resource credentials. Close public intake. Protect/remove vulnerable old builds and revoke their DB/limiter credentials before new live resources exist.
2. Provision initialized isolated authority and service authorization policy. Deny all production admissions until explicitly activated; do not create permissive bootstrap endpoints.
3. Prepare a protected Vercel candidate with verification keys, independent origin gate, exact resource/environment checks, new mutation boundary, and writes disabled. Preview testing uses its own audience/keys/resources.
4. Record the candidate deployment ID. Configure the Worker to attest the exact approved target and the authority to authorize only reviewed release credentials. Keep public intake closed while testing same-host routing; a target/audience mismatch must fail.
5. Enable the platform perimeter and route the approved Worker, with separate bypass/origin credentials and full sanitization. Preserve a separately tested admin path. Never disable platform/application gates to solve a routing or certificate problem.
6. Promote the Vercel alias and update Worker target audience under closed intake. Cross-platform propagation is not atomic; accept a maintenance interval. Test before opening any mutation flow. Keep the authority ID/history unchanged across releases.
7. Activate only after synthetic trust/admission gates pass and a separate persistence-launch authorization exists. Revoke retired release RPC keys and remove obsolete deployments. Do not keep old vulnerable builds as instant-rollbacks.

Narrow GET/HEAD certificate/deployment verification requirements may need platform-supported handling. Verify them while closed; do not create a broad domain, `/_next`, or method exception just because ACME renewal is awkward. Vercel's reverse-proxy guide describes certificate/cache considerations, but its suggested all-header diagnostic is incompatible with this project's privacy policy.

### Rollback

Disable intake first. Roll back only to a reviewed version that understands the current protocol and authority epoch, with a deliberately reauthorized audience/release. Update routing and Worker signing audience while closed; keep quota state. If no compatible safe rollback exists, remain closed and serve a neutral unavailable form while admin continues independently. Never roll back to unsigned ingress, an empty provider, or demo persistence.

For admission-provider/state migration, stop new pre admissions, drain in-flight work, revoke old permits, and retain closure for the maximum window plus freshness/permit allowance (12 minutes at current values) before starting an empty replacement. No dual independent authorities serving the same global quota. Backup restoration is subject to the same rule.

### Telemetry and synthetic checks

Record only aggregate stage/result counts, verification-failure categories, provider latency histograms, pre/post saturation, cleanup lag, overload, and active protocol/policy version. Never label metrics by client/nonce/body digest. Alert on direct-origin application invocations, signature/audience errors, clock-skew failures, disappearing authority metadata, stale releases, protection drift, and cost spikes.

Synthetic monitors use isolated policy/state or an explicitly budgeted synthetic lane that cannot be selected by public callers. They do not borrow unbounded production capacity or send customer data. Continuously probe a known direct origin as well as the normal Cloudflare path; successful bypass is an incident, not evidence the URL must be renamed.

### Incident actions

- Signing/edge credential leak: close intake, revoke affected keys/bypass credentials, retire exposed Worker versions, review response/log leakage, rotate with no unsigned grace. Global admission and Turnstile remain required during investigation.
- Origin-only leak: rotate that bearer independently; do not rotate pseudonym keys and reset quotas unnecessarily.
- Service credential leak: revoke the release RPC key and its authority authorization; protect/remove affected deployment and DB credentials. Do not wait solely for OIDC expiry.
- State loss: freeze authority, revoke permits, investigate, drain/cool down before replacement. Never “fix” an outage by flushing counters.
- Direct-origin flood: verify platform gate, use Vercel attack support/controls, and inspect aggregate app invocation counts. Do not change DNS to an unprotected path.
- Cloudflare/Vercel/DB outage: controlled unavailability, no automatic bypass; preserve form recovery and independent admin access where its dependencies remain available.

## 20. Remaining unavoidable risks and release blockers

Unavoidable under the selected architecture: public Vercel edge reachability; residual resource/cost exposure; Cloudflare/Vercel control-plane trust; signing-runtime correctness; replay races after capture; IP/NAT unfairness; distributed pre-budget starvation; authority hot spot and cross-provider latency; provider clock assumptions; capacity spent on ambiguous failures; no distributed transaction spanning admission and business writes.

Not yet established and therefore release-blocking until tested/configured:

- The exact deployed first-Worker topology, address provenance, same-host forwarding, body/canonicalization behavior, and audience binding.
- Platform All Deployments coverage/bypass behavior for this project, old-build retirement, credential isolation, and independent admin/verification paths.
- Actual DO transaction/restart/failure/latency behavior and resource/retention controls; no real resource was created here.
- Production OIDC and release-key authorization, copy-to-Preview denial, and authority initialization/epoch protection.
- Existing Phase 5C regression failures/skips, real Turnstile/DB launch gates, and actual operating-volume/cost measurements.

Optional stronger requirement not proven: suppressing every raw-IP-bearing infrastructure header before Vercel. The selected protocol does not need Vercel to read such headers. If literal zero raw-IP egress from Cloudflare is made mandatory, keep launch blocked until a supported egress design is proven; do not mislabel the current proposal.

No architecture can preserve its security if all relevant signing, service, application, and database administrative authorities are compromised. Separate secrets and providers limit specific compromises; they are not independent against a shared administrator or malicious production application.

## 21. Recommended next implementation prompt

> Implement Phase 5C-I1 — closed-path signed ingress and single-authority admission, following PHASE5C_R_ARCHITECTURE.md. Preserve da0b43d and the existing uncommitted Phase 5C work. Do not commit, deploy, change accounts/DNS, create real resources, configure real Turnstile/DB, or enable persistence.
>
> Implement only the primary design: Worker-only Ed25519 signing and separately keyed IP pseudonyms; exact bounded request envelope; one raw-body public POST boundary with preserved schema/CSRF/submission-token/idempotency behavior; independent origin/admin checks; a separate Vercel-OIDC/release-authenticated admission service; and one SQLite-backed Durable Object for atomic pre/post client/global quotas and one-use nonce transitions. Keep the public signer unable to authorize post admission or call the authority as Vercel. Read installed Next.js guides before code changes.
>
> Start with protocol/state-machine tests and local provider integration. No production provider activation until local conformance and an independent adversarial review pass. Reject unknown modes, stale/wrong-audience signatures, Worker-mediated identity ambiguity, malformed/duplicate inputs, uninitialized state, Preview calls, and unavailable/ambiguous provider responses. No retries of possibly consumed operations, no memory/global-only/unsigned fallback, no implicit namespace reset, no raw IP or customer content in limiter traffic/logs.
>
> Retain the existing pre/post thresholds for testing and explicitly demonstrate starvation/recovery. Preserve admin access with intake disabled. Do not implement the MemoryDB fallback or speculative IP-stripping relays. Report the precise platform checks still requiring later authorized smoke tests, including the unproven no-raw-IP-egress claim.
>
> Run the required repository/regression gates and exact local DO storage tests; distinguish emulator evidence from provider guarantees, and report every failure/skip without weakening assertions. Leave all changes uncommitted and public persistence disabled. End with a closed-path implementation verdict, not launch authorization.

## Review-only workspace result

Only `PHASE5C_R_ARCHITECTURE.md` is added by this task. SHA-256 comparison confirmed that all eight pre-existing Phase 5C modified/untracked files are byte-for-byte unchanged. No production code or package changes are made. `git diff --check` passed; the new untracked document also produced no whitespace errors in its no-index check. Final status has five pre-existing modified tracked files and four untracked files, including this report; nothing is staged. The tracked diff remains 37 insertions / 10 deletions. Application/provider tests are deliberately not represented as executed here.

ARCHITECTURE SELECTED — SAFE TO IMPLEMENT
