import { parseStrictJson } from "./lifecycle-submitter";
import type { LifecycleReceipt } from "../workers/admission-service/authority";
import type { CommandDerivedReceipt } from "../workers/admission-service/operator-command";

/**
 * Result-object helpers that are NOT Authority evidence (R06 Slice 2C).
 *
 * Positive lifecycle and reconciliation acceptance lives ONLY in the signed R06 path (operator/authority-result-reader.ts, over the
 * 2B composers). This module no longer contains any verifier that can return a positive lifecycle or reconciliation result: the
 * legacy unsigned SUCCESS / ALREADY_APPLIED / EXACT_RECEIPT parsers were deleted, not disabled. What remains:
 *   - the shared list of command-derived receipt fields (the one list R07 and the 2B composer use);
 *   - settlement verification: settlement is guard state, not an Authority statement, and stays independent of R06;
 *   - classification of an UNSIGNED relay diagnostic, which can only ever be non-positive.
 */
export type ResultKind = "lifecycle" | "reconciliation" | "settlement";
const digestPattern = /^[a-f0-9]{64}$/u;
const noncePattern = /^[a-f0-9]{32}$/u;
function exact(value: unknown, required: readonly string[], optional: readonly string[] = []): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return required.every((key) => keys.includes(key)) && keys.every((key) => required.includes(key) || optional.includes(key));
}
function safeTime(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) >= 0; }
// Every LifecycleReceipt field; shared by the shape check and the exact expected-receipt comparison.
// Typecheck fails both ways: `satisfies` rejects a listed key that is not a LifecycleReceipt key, and
// `Exhaustive` resolves to `never` (so the assignment below fails) if a LifecycleReceipt key is not listed.
const listedReceiptFields = ["digest", "version", "operation", "environment", "authorityId", "policyEpoch", "keyFingerprint", "sequence", "appliedMs",
  "currentReleaseId", "nextReleaseId", "nextKeyId", "activatesMs", "retiresMs"] as const satisfies readonly (keyof LifecycleReceipt)[];
type Exhaustive<List extends readonly (keyof LifecycleReceipt)[]> = [Exclude<keyof LifecycleReceipt, List[number]>] extends [never] ? List : never;
const receiptFields: Exhaustive<typeof listedReceiptFields> = listedReceiptFields;
// Derived from the exhaustive list: every receipt field except the two the authority assigns when it applies a command.
// Frozen at construction: it is shared (exported below), so no importer may substitute, add or drop a field at runtime.
const commandDerivedFields: readonly (keyof CommandDerivedReceipt)[] =
  Object.freeze(receiptFields.filter((field): field is keyof CommandDerivedReceipt => field !== "sequence" && field !== "appliedMs"));
/** The one shared list of command-derived receipt fields, for verifiers that bind a receipt to an authenticated command.
 * Runtime-frozen; the 2B Production composer compares exactly these fields. */
export const commandDerivedReceiptFields: readonly (keyof CommandDerivedReceipt)[] = commandDerivedFields;

/** Settlement verification. Settlement results are written by the dispatch guard's own ledger and carry no Authority receipt, so
 * they are verified against the caller-known digest/nonce/target and the local clock, exactly as before; R06 does not apply. */
export function verifySettlementResult(bytes: Uint8Array, expected: { digest: string; nonce: string }, nowMs = Date.now(),
  expectedEnvironment: "production" | "staging" = "production",
  expectedAuthorityId: string = "production-public-inquiries-v1") {
  if (!bytes.length || bytes.byteLength > 8_192) throw new Error("result-size");
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("result-bom");
  const value = parseStrictJson(source) as Record<string, unknown>;
  const base = ["version", "digest", "environment", "authorityId", "policyEpoch", "observedAtMs"];
  if (!exact(value, [...base, "nonce", "settled"]) || value.version !== 1 || value.environment !== expectedEnvironment ||
      value.authorityId !== expectedAuthorityId || value.policyEpoch !== "phase5c-i1-epoch-1" ||
      typeof value.digest !== "string" || !digestPattern.test(value.digest) || value.digest !== expected.digest ||
      typeof value.nonce !== "string" || !noncePattern.test(value.nonce) || value.nonce !== expected.nonce ||
      !safeTime(value.observedAtMs) || value.observedAtMs > nowMs + 60_000 || nowMs - value.observedAtMs > 5 * 60_000 ||
      typeof value.settled !== "boolean") throw new Error("result-contract");
  return { status: value.settled ? "SETTLED" : "UNCONFIRMED", digest: value.digest, nonce: value.nonce } as const;
}

/**
 * Classifies bytes that are NOT a signed envelope as the explicit unsigned relay diagnostic (operator/attested-relay.ts) or as
 * nothing. The result type has no positive member: the only status is UNCONFIRMED, and the diagnostic's own `status` is limited to
 * REFUSED / UNAVAILABLE / UNCONFIRMED. A legacy unsigned SUCCESS / ALREADY_APPLIED / EXACT_RECEIPT object, or anything else with a
 * different shape, returns null: it is not even a diagnostic.
 */
export function classifyUnsignedDiagnostic(bytes: Uint8Array, expected: { digest: string; nonce?: string }):
  { status: "UNCONFIRMED"; observation: "UNSIGNED_DIAGNOSTIC"; relayStatus: "REFUSED" | "UNAVAILABLE" | "UNCONFIRMED" } | null {
  try {
    if (!bytes.length || bytes.byteLength > 8_192) return null;
    const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    if (source.charCodeAt(0) === 0xfeff) return null;
    const value = parseStrictJson(source);
    if (!exact(value, ["version", "digest", "status"], ["nonce", "reason"]) || value.version !== 1 || value.digest !== expected.digest ||
        (value.nonce !== undefined && value.nonce !== expected.nonce) || (expected.nonce !== undefined && value.nonce === undefined) ||
        (value.status !== "REFUSED" && value.status !== "UNAVAILABLE" && value.status !== "UNCONFIRMED") ||
        (value.reason !== undefined && (typeof value.reason !== "string" || !/^[a-z0-9-]{1,64}$/u.test(value.reason)))) return null;
    return { status: "UNCONFIRMED", observation: "UNSIGNED_DIAGNOSTIC", relayStatus: value.status };
  } catch { return null; }
}
