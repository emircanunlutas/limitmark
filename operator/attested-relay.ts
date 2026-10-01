/**
 * R06 Slice 2C: the OPAQUE relay vocabulary shared by the executor, dispatch guard, result writer and reconciliation observer.
 *
 * A relay component carries Authority evidence; it never authors it. An ATTESTED result holds `envelope: Uint8Array`, the exact
 * canonical bytes the Authority's signer produced. Nothing in this module (or in any relay) parses, reconstructs, re-serializes,
 * canonicalizes or inspects that envelope beyond "is a non-empty Uint8Array within the protocol's size bound". This module does NOT
 * import the frozen R06 protocol; a source guard keeps every relay module from importing it, so a relay cannot verify, parse or
 * mint signed semantics. Verification belongs to the operator readers (operator/authority-result-reader.ts).
 *
 * `relayDisposition` is relay-local workflow metadata (was the mutation applied now, or already applied). It is NEVER part of
 * the signed statement and no security decision may depend on it.
 *
 * Failure taxonomy of a relayed Authority answer:
 *   ATTESTED     signed evidence exists (the ONLY positive-evidence carrier).
 *   REFUSED      the Authority refused the request itself (authentication/schema/policy/state).
 *   UNAVAILABLE  non-positive; the Authority did not mutate (signer/config/clock/storage-state problem).
 *   AMBIGUOUS    non-positive; the Authority DID commit but could not sign. Never REFUSED; recoverable by reconciliation.
 *   UNCONFIRMED  relay-local: the answer was lost, malformed or unreadable (a transport exception may follow a commit).
 */
export const RELAY_ENVELOPE_MAX_BYTES = 8_192;
export const UNCONFIRMED_INSTRUCTION = "Inspect authoritative state before any retry; the mutation may have committed.";

export type RelayDisposition = "APPLIED" | "ALREADY_APPLIED";
export type LifecycleRelayResult =
  | { readonly status: "ATTESTED"; readonly relayDisposition: RelayDisposition; readonly envelope: Uint8Array }
  | { readonly status: "REFUSED" }
  | { readonly status: "UNAVAILABLE"; readonly reason: string }
  | { readonly status: "AMBIGUOUS"; readonly reason: string }
  | { readonly status: "UNCONFIRMED"; readonly instruction: typeof UNCONFIRMED_INSTRUCTION };
export type ReconciliationRelayResult =
  | { readonly status: "ATTESTED"; readonly envelope: Uint8Array }
  | { readonly status: "REFUSED" }
  | { readonly status: "UNAVAILABLE"; readonly reason: string }
  | { readonly status: "UNCONFIRMED"; readonly instruction: typeof UNCONFIRMED_INSTRUCTION };

const UNCONFIRMED: { readonly status: "UNCONFIRMED"; readonly instruction: typeof UNCONFIRMED_INSTRUCTION } =
  Object.freeze({ status: "UNCONFIRMED", instruction: UNCONFIRMED_INSTRUCTION });
const reasonPattern = /^[a-z0-9-]{1,64}$/u;

/** Transport-level shape only: a non-empty Uint8Array no larger than the protocol maximum. No content inspection. */
export function isOpaqueEnvelope(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array && value.byteLength >= 1 && value.byteLength <= RELAY_ENVELOPE_MAX_BYTES;
}

function exactKeys(value: object, keys: readonly string[]): boolean {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

/** Strict shape check of an Authority lifecycle answer received over RPC. Anything else is UNCONFIRMED (never a refusal). */
export function normalizeLifecycleRelayResult(value: unknown): LifecycleRelayResult {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return UNCONFIRMED;
  const record = value as Record<string, unknown>;
  if (record.status === "ATTESTED" && exactKeys(record, ["status", "relayDisposition", "envelope"]) &&
      (record.relayDisposition === "APPLIED" || record.relayDisposition === "ALREADY_APPLIED") && isOpaqueEnvelope(record.envelope))
    return { status: "ATTESTED", relayDisposition: record.relayDisposition, envelope: record.envelope };
  if (record.status === "REFUSED" && exactKeys(record, ["status"])) return { status: "REFUSED" };
  if ((record.status === "UNAVAILABLE" || record.status === "AMBIGUOUS") && exactKeys(record, ["status", "reason"]) &&
      typeof record.reason === "string" && reasonPattern.test(record.reason))
    return { status: record.status, reason: record.reason };
  return UNCONFIRMED;
}

/** Strict shape check of an Authority reconciliation answer. */
export function normalizeReconciliationRelayResult(value: unknown): ReconciliationRelayResult {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return UNCONFIRMED;
  const record = value as Record<string, unknown>;
  if (record.status === "ATTESTED" && exactKeys(record, ["status", "envelope"]) && isOpaqueEnvelope(record.envelope))
    return { status: "ATTESTED", envelope: record.envelope };
  if (record.status === "REFUSED" && exactKeys(record, ["status"])) return { status: "REFUSED" };
  if (record.status === "UNAVAILABLE" && exactKeys(record, ["status", "reason"]) && typeof record.reason === "string" && reasonPattern.test(record.reason))
    return { status: "UNAVAILABLE", reason: record.reason };
  return UNCONFIRMED;
}

/**
 * The explicit, UNSIGNED diagnostic a relay writes when there is no signed evidence to store. It carries no Authority semantics
 * (no receipt, release, coverage, environment, authority or clock) and can never be positive: readers classify it as
 * UNCONFIRMED. It exists so an operator can see why a result is not signed evidence.
 */
export type UnsignedDiagnosticStatus = "REFUSED" | "UNAVAILABLE" | "UNCONFIRMED";
export type UnsignedDiagnostic = { readonly version: 1; readonly digest: string; readonly nonce?: string; readonly status: UnsignedDiagnosticStatus; readonly reason?: string };
export function unsignedDiagnostic(digest: string, status: UnsignedDiagnosticStatus, reason?: string, nonce?: string): UnsignedDiagnostic {
  return { version: 1, digest, ...(nonce === undefined ? {} : { nonce }), status, ...(reason === undefined ? {} : { reason }) };
}
