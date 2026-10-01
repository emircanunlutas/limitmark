import {
  ATTESTATION_POLICY_EPOCH,
  ATTESTATION_TRUST_EPOCH,
  attestationReceiptFromLifecycleReceipt,
  attestationReleaseRowFromAuthority,
  isSafeTime,
  makeLifecycleStatement,
  makeReconciliationStatement,
  type AttestationEnvironment,
} from "../../src/lib/authority-result-attestation";
import {
  ADMISSION_AUTHORITY_ID,
  ADMISSION_POLICY_EPOCH,
  STAGING_ADMISSION_AUTHORITY_ID,
  inspectLifecycleAuthority,
  type DurableStorageLike,
  type LifecycleReceipt,
} from "./authority";
import {
  executeSignedAuthorityInitialization,
  executeSignedAuthorityReleaseRotation,
  isLifecycleRefusal,
  type AuthorityInitializationCommand,
  type AuthorityReleaseRotationCommand,
  type BeforeLifecycleFreshness,
} from "./operator-command";
import type { AuthorityAttestationSigner } from "./authority-attestation-signer";

/**
 * Authority-side producer of FROZEN R06 attestation v2 statements (Slice 2A).
 *
 * ACTIVE since Slice 2C: the Authority Durable Object classes (workers/admission-service/index.ts) are the only importers, and the
 * mailbox/observer relay the envelope bytes it returns without parsing them. The frozen protocol is consumed unchanged; this
 * module only decides WHEN to sign and WHAT durable Authority state to put into a statement.
 *
 * Ordering for a lifecycle mutation (the contract the Slice 2C relay relies on):
 *   target/environment check -> operator authentication -> command validation + expected receipt
 *   -> signer identity check + signer.ready(preliminary Authority time)   [no storage access has happened yet]
 *   -> FRESH Authority clock reading AFTER readiness resolves = final freshness time = receipt.appliedMs
 *   -> final freshness / activation eligibility check on that same reading
 *   -> existing synchronous transaction                                   [NO await between the check and the transaction]
 *   -> transaction has returned -> Authority clock = observedAtMs -> statement -> sign -> canonical envelope bytes.
 * The preliminary readiness time is neither the freshness time nor appliedMs, so a slow signer.ready() cannot carry a command
 * that went stale while waiting into the mutation.
 *
 * Result classes (diagnostic `relayDisposition` is NEVER part of the signed statement):
 *   ATTESTED     positive: a signed APPLIED statement for a durable receipt (or a signed reconciliation snapshot).
 *   REFUSED      the request itself was refused (operator authentication/schema/policy/state, or malformed digest/nonce).
 *   UNAVAILABLE  non-positive, nothing was mutated by this call: signer/configuration/clock/storage-state problem.
 *   AMBIGUOUS    non-positive, the lifecycle transaction DID commit but no signed evidence could be produced. State is
 *                preserved (no rollback, no compensation, no second mutation); the relay maps this to UNCONFIRMED and
 *                recovery runs through attestReconciliation / attestAppliedLifecycle. Never REFUSED.
 */
export type AttestationUnavailableReason =
  | "runtime-config-invalid"
  | "signer-unconfigured"
  | "signer-mismatch"
  | "signer-not-ready"
  | "authority-clock-invalid"
  | "authority-state-unavailable"
  | "receipt-not-found"
  | "history-incomplete"
  | "statement-invalid"
  | "signing-failed";

export type AttestedLifecycleResult =
  | { readonly status: "ATTESTED"; readonly relayDisposition: "APPLIED" | "ALREADY_APPLIED"; readonly envelope: Uint8Array }
  | { readonly status: "REFUSED" }
  | { readonly status: "UNAVAILABLE"; readonly reason: AttestationUnavailableReason }
  | { readonly status: "AMBIGUOUS"; readonly reason: "post-commit-attestation-failed" };

export type AttestedRecoveryResult = Exclude<AttestedLifecycleResult, { status: "AMBIGUOUS" }>;

export type AttestedReconciliationResult =
  | { readonly status: "ATTESTED"; readonly envelope: Uint8Array }
  | { readonly status: "REFUSED" }
  | { readonly status: "UNAVAILABLE"; readonly reason: AttestationUnavailableReason };

/** The identity of the Authority a coordinator serves. A signer for any other identity is refused before readiness. */
export interface AuthorityAttestationIdentity {
  readonly environment: AttestationEnvironment;
  readonly authorityId: string;
  readonly policyEpoch: string;
}
export const PRODUCTION_ATTESTATION_IDENTITY: AuthorityAttestationIdentity = Object.freeze({
  environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH });
export const STAGING_ATTESTATION_IDENTITY: AuthorityAttestationIdentity = Object.freeze({
  environment: "staging", authorityId: STAGING_ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH });

/** Injectable runtime: the signer and the Authority clock. Neither is looked up from a provider or global environment. */
export interface AuthorityAttestationRuntime {
  /** Absent means "signer not configured": every attested operation is UNAVAILABLE before it can touch storage. */
  readonly signer?: AuthorityAttestationSigner;
  /** The Authority's own clock (`Date.now` in the Durable Object). Relay and caller clocks are never consulted. */
  readonly now?: () => number;
}

class AttestationUnavailableError extends Error {
  constructor(readonly reason: AttestationUnavailableReason) { super(reason); }
}

/**
 * THE shared lifecycle attestation path. Converts a durable receipt into the frozen lifecycle APPLIED statement and signs it.
 * Initialize/rotate (post-commit) and read-only recovery all come through here; no caller builds a lifecycle statement itself.
 * `observedAtMs` must be an Authority clock reading taken by the caller after the receipt's transaction returned.
 */
export async function attestLifecycleReceipt(signer: AuthorityAttestationSigner, receipt: LifecycleReceipt, observedAtMs: number): Promise<Uint8Array> {
  const statement = makeLifecycleStatement({
    trustEpoch: ATTESTATION_TRUST_EPOCH,
    environment: receipt.environment,
    authorityId: receipt.authorityId,
    policyEpoch: ATTESTATION_POLICY_EPOCH,
    digest: receipt.digest,
    receipt: attestationReceiptFromLifecycleReceipt(receipt),
    observedAtMs,
    writerKeyFingerprint: signer.writerKeyFingerprint,
  });
  return signer.sign(statement);
}

/** The command layer's positional `nowMs` is only the default for its `finalNow` clock. The coordinator always supplies
 * `finalNow`; were that ever to stop being true, NaN fails the safe-integer freshness check closed instead of reading as time 0. */
const NO_FALLBACK_CLOCK = Number.NaN;

const digestPattern = /^[a-f0-9]{64}$/u;
const noncePattern = /^[a-f0-9]{32}$/u;

export class AuthorityAttestationCoordinator {
  constructor(
    private readonly storage: DurableStorageLike,
    private readonly identity: AuthorityAttestationIdentity,
    private readonly operatorPublicKey: string,
    private readonly runtime: AuthorityAttestationRuntime = {},
  ) {}

  private clock(): number { return (this.runtime.now ?? Date.now)(); }

  /** Signer present and pinned to exactly this Authority, then ready at an explicit Authority time. Touches no storage. */
  private async prepareSigner(nowMs: number): Promise<AuthorityAttestationSigner> {
    const signer = this.runtime.signer;
    if (!signer) throw new AttestationUnavailableError("signer-unconfigured");
    if (signer.environment !== this.identity.environment || signer.authorityId !== this.identity.authorityId ||
        signer.policyEpoch !== this.identity.policyEpoch) throw new AttestationUnavailableError("signer-mismatch");
    if (!isSafeTime(nowMs)) throw new AttestationUnavailableError("authority-clock-invalid");
    try { await signer.ready(nowMs); } catch { throw new AttestationUnavailableError("signer-not-ready"); }
    return signer;
  }

  private async lifecycleMutation(
    execute: (preflight: BeforeLifecycleFreshness, now: () => number) => Promise<{ status: string; receipt?: LifecycleReceipt }>,
    initialStatus: string,
  ): Promise<AttestedLifecycleResult> {
    const prepared: { signer?: AuthorityAttestationSigner } = {};
    let outcome: { status: string; receipt?: LifecycleReceipt };
    try {
      // The reading handed to prepareSigner is preliminary only; the command layer takes its own final reading after this
      // resolves and uses that one for both freshness and appliedMs.
      outcome = await execute(async () => { prepared.signer = await this.prepareSigner(this.clock()); }, () => this.clock());
    } catch (error) {
      if (error instanceof AttestationUnavailableError) return { status: "UNAVAILABLE", reason: error.reason };
      if (isLifecycleRefusal(error)) return { status: "REFUSED" };
      throw error;
    }
    // The synchronous transaction has returned, so signing happens only after commit. (Durable Object output gates keep the
    // response from leaving the object before the write is persisted; that guarantee is not derived from this return alone.)
    // Nothing below may roll back, compensate, retry the mutation or report a refusal; any failure from here on is AMBIGUOUS
    // (committed, evidence not produced).
    try {
      if (!prepared.signer || !outcome.receipt) throw new Error("attestation-missing-receipt");
      const envelope = await attestLifecycleReceipt(prepared.signer, outcome.receipt, this.clock());
      return { status: "ATTESTED", relayDisposition: outcome.status === initialStatus ? "APPLIED" : "ALREADY_APPLIED", envelope };
    } catch {
      return { status: "AMBIGUOUS", reason: "post-commit-attestation-failed" };
    }
  }

  /** Signed initialization. Existing operator-command verification, freshness and transaction are reused unchanged. */
  initialize(command: AuthorityInitializationCommand, signature: string): Promise<AttestedLifecycleResult> {
    return this.lifecycleMutation((preflight, now) => executeSignedAuthorityInitialization(this.storage, command, signature,
      this.operatorPublicKey, NO_FALLBACK_CLOCK, this.identity.environment, now, preflight), "initialized");
  }

  /** Signed rotation. Production only: a staging coordinator refuses before parsing, verifying or touching anything. */
  async rotate(command: AuthorityReleaseRotationCommand, signature: string): Promise<AttestedLifecycleResult> {
    if (this.identity.environment !== "production") return { status: "REFUSED" };
    return this.lifecycleMutation((preflight, now) => executeSignedAuthorityReleaseRotation(this.storage, command, signature,
      this.operatorPublicKey, NO_FALLBACK_CLOCK, "production", now, preflight), "rotated");
  }

  /**
   * Read-only recovery: fresh signed APPLIED evidence for a receipt that is already durable. SELECT-only (no schema creation,
   * no claim/release/clock mutation). Absent, incomplete or unreadable history is non-positive and carries no receipt.
   */
  async attestAppliedLifecycle(digest: string): Promise<AttestedRecoveryResult> {
    if (typeof digest !== "string" || !digestPattern.test(digest)) return { status: "REFUSED" };
    try {
      const signer = await this.prepareSigner(this.clock());
      const observedAtMs = this.clock();
      if (!isSafeTime(observedAtMs)) return { status: "UNAVAILABLE", reason: "authority-clock-invalid" };
      const observation = inspectLifecycleAuthority(this.storage, digest, observedAtMs, this.identity.authorityId, this.identity.policyEpoch);
      if (observation.status === "UNAVAILABLE") return { status: "UNAVAILABLE", reason: "authority-state-unavailable" };
      if (observation.status === "HISTORY_INCOMPLETE") return { status: "UNAVAILABLE", reason: "history-incomplete" };
      if (observation.status !== "EXACT_RECEIPT" || observation.receipt === null) return { status: "UNAVAILABLE", reason: "receipt-not-found" };
      try {
        return { status: "ATTESTED", relayDisposition: "ALREADY_APPLIED", envelope: await attestLifecycleReceipt(signer, observation.receipt, observedAtMs) };
      } catch { return { status: "UNAVAILABLE", reason: "signing-failed" }; }
    } catch (error) {
      if (error instanceof AttestationUnavailableError) return { status: "UNAVAILABLE", reason: error.reason };
      return { status: "UNAVAILABLE", reason: "authority-state-unavailable" };
    }
  }

  /**
   * Authority-signed reconciliation. The caller's nonce is part of the statement the Authority signs; no component after
   * signing can add or replace it. SELECT-only.
   */
  async attestReconciliation(digest: string, nonce: string): Promise<AttestedReconciliationResult> {
    if (typeof digest !== "string" || !digestPattern.test(digest) || typeof nonce !== "string" || !noncePattern.test(nonce)) return { status: "REFUSED" };
    try {
      const signer = await this.prepareSigner(this.clock());
      const observedAtMs = this.clock();
      if (!isSafeTime(observedAtMs)) return { status: "UNAVAILABLE", reason: "authority-clock-invalid" };
      const observation = inspectLifecycleAuthority(this.storage, digest, observedAtMs, this.identity.authorityId, this.identity.policyEpoch);
      if (observation.status === "UNAVAILABLE") return { status: "UNAVAILABLE", reason: "authority-state-unavailable" };
      let statement;
      try {
        statement = makeReconciliationStatement({
          trustEpoch: ATTESTATION_TRUST_EPOCH,
          environment: observation.environment,
          authorityId: observation.authorityId,
          policyEpoch: ATTESTATION_POLICY_EPOCH,
          digest,
          nonce,
          initialized: observation.initialized,
          coverage: observation.coverage,
          status: observation.status,
          receipt: observation.receipt === null ? null : attestationReceiptFromLifecycleReceipt(observation.receipt),
          releases: observation.releases.map(attestationReleaseRowFromAuthority),
          observedAtMs: observation.observedAtMs,
          writerKeyFingerprint: signer.writerKeyFingerprint,
        });
      } catch { return { status: "UNAVAILABLE", reason: "statement-invalid" }; }
      try { return { status: "ATTESTED", envelope: await signer.sign(statement) }; }
      catch { return { status: "UNAVAILABLE", reason: "signing-failed" }; }
    } catch (error) {
      if (error instanceof AttestationUnavailableError) return { status: "UNAVAILABLE", reason: error.reason };
      return { status: "UNAVAILABLE", reason: "authority-state-unavailable" };
    }
  }
}
