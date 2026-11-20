# Local origin execution fencing

The local integration covers replacement of a Boundary OS process while one trusted, guarded origin remains live. The origin owns the generation and outstanding-work state. A replacement Boundary starts with admission closed and calls `reconcile()` explicitly. The established request path makes no calls to the provisioning owner.

## Credentials and reconciliation

- A trusted owner provisions a strictly increasing epoch for the fixed backend scope and the origin's random instance ID. The owner and origin share a 32-byte root key. Each Boundary gets only its epoch ticket and derived request key. The origin holds an Ed25519 signing key and the Boundary pins its public key.
- An authenticated loopback claim binds the epoch, a fresh Boundary session ID and a fresh challenge. The origin atomically fences lower epochs on accepting a higher one, even while it returns `409` for outstanding work. A second session cannot take over the same epoch. The Boundary opens only after a signed `204` bound to its session and challenge.
- The origin counts every accepted execution before application work can start. A fenced generation cannot accept additional executions or start previously accepted work that was deferred. Work that already started remains counted until the adapter records completion. A successor gets a readiness acknowledgment only when this count reaches zero. An absent execution ID is never used as termination evidence.

## Execution and settlement

The grant retains M2's monotonic proof cutoff, proof expiry and caller cutoff. Immediately before handing bytes to the upstream socket, the Boundary samples M2's conservative clock and checks those grant fields again. Expiry before the first write settles the reservation as never started.

- The execution envelope authenticates a random execution ID and the exact BA proof under the generation key. The guarded synthetic origin checks the BA/PB proof and then claims the execution before entering the handler. It rejects reused IDs and caps the replay set at 65,536 entries per epoch by default. Once full, the origin requires an explicitly provisioned successor epoch. Fenced epochs are rejected without keeping their replay sets.
- The synthetic handler returns response data after its work settles. The origin adapter then signs terminal evidence for the instance, scope, generation, session, execution ID and exact BA proof. A fenced deferred execution can also be acknowledged once the adapter prevents it from starting. The Boundary verifies this evidence and uses its existing M2 settlement capability. HTTP status, framing, socket close and timeout alone carry no terminal authority. Lost or invalid evidence leaves the local charge held.

## Local process supervision

After the hop guard commits a fresh BA/PB chain, the origin can also sign a distinct never-started receipt for an authenticated execution. An old epoch is permanently fenced. A saturated epoch stays closed to new IDs. During drain, the origin records a refused ID before issuing its receipt, so that ID cannot start when readiness opens. Duplicate IDs in the current epoch and failed hop authentication receive no release authority.

The Stage 4 lab supervisor forks a guarded origin and Boundary children on separate loopback listeners. It passes the origin's root and signing keys only over private IPC. A Boundary receives the activated policy inputs, its generation ticket and derived request key, and the pinned origin verification key. Child process IDs are diagnostic values. The supervisor publishes the candidate's listener only after that child verifies the origin's signed readiness acknowledgment.

The supervisor allows one candidate at a time. Explicit activation withdraws and stops the previous Boundary before issuing the successor claim. In-flight callers may lose delivery. The origin continues counting their work through completion. A drain refusal leaves the candidate closed for an explicit retry. A failed candidate can be replaced with a fresh epoch. Diagnostic IPC exchanges have bounded deadlines and correlated replies. Origin exit withdraws the published endpoint and stops Boundary children.

## Exclusive ownership and origin recovery

Every supervised launch uses the same trusted, local ownership root and canonical backend reference for that backend. Atomic directory creation reserves `<backendRef>.owner` before a child can start. Each acquisition gets a random ownership epoch, which is bound into tickets, execution authentication, and signed acknowledgments. Ordinary requests use the existing data-path protocol without consulting the directory or supervisor.

The supported recovery model is the built-in `process-local-synthetic` origin. Its charged handlers, timeouts, held promises, and in-memory mutations run in one Node child. The fixed entry point launches no worker or subprocess for charged work and delegates no work to an external service. The supervisor confirms termination only from the OS exit event on its original child-process handle. An explicit recovery then starts a fresh origin with fresh keys and instance identity under the existing ownership epoch. The next Boundary requires signed readiness before admission. Socket closure, kill initiation, a recorded PID, and an empty ledger provide no recovery evidence.

A direct supervisor releases its ownership marker on confirmed clean shutdown only after the supported termination condition and child cleanup. A successor can then acquire a new ownership epoch. When exit evidence is missing, the marker stays in place. Contenders refuse ownership regardless of marker age. Do not remove a marker based on age, a PID lookup, or an unreachable port.

## Independent termination witness

The optional Stage 6 witness hosts the supervisor under a trusted launcher. It forks the origin, Boundary and a replaceable owner-session process. The session verifies a witness-signed grant for its backend, previous epoch, new epoch and challenge. The witness receives the claim on that session's private fork channel and performs provisioning and activation itself.

During owner-session rotation the surviving witness verifies exit of the original session, stops the original origin, and verifies its exit on the original fork handle. It retains the marker, rotates the ownership epoch, launches a fresh origin and session, and requires signed origin readiness before publishing a Boundary. Loss of the witness also loses the supervisor.

A separate launcher-owned local pipe lets already established Boundary and origin processes continue serving through witness loss. The pipe is for lifetime control only and conveys no termination evidence. If the witness dies, its saved handles and signing authority are lost. New acquisition fails closed on the retained marker, and closing the launcher's pipe can tear down the old data path without authorizing takeover. A new witness cannot reconstruct termination evidence from socket activity, PIDs, or marker age.

## Production prerequisites

The marker assumes trusted filesystem access and a common namespace, rather than coordinating different machines, unrelated roots, or aliases for the same backend. It preserves exclusion across process restarts on the local filesystem. Host power-loss durability is outside this slice. Takeover requires the original witness to survive and retain its handles. There is no automatic recovery after witness or launcher loss. A production origin that can delegate or detach charged work needs independently verified containment or a durable execution ledger and authoritative reconciliation. The historical process entry points do not provision or activate this protocol. Lost terminal evidence can be recovered for admission by draining and advancing the generation while the same origin lives. There is no per-execution lookup or acknowledgment retry in this slice.
