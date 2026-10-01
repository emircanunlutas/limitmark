import { parseStrictJson, type LifecycleOperation } from "./lifecycle-submitter";
import { UNAVAILABLE_AUTHORITY_OBSERVATION } from "./lifecycle-observation";
import type { LifecycleReceipt } from "../workers/admission-service/authority";
import type { CommandDerivedReceipt } from "../workers/admission-service/operator-command";

export type ResultKind = "lifecycle" | "reconciliation" | "settlement";
const digestPattern = /^[a-f0-9]{64}$/u;
const noncePattern = /^[a-f0-9]{32}$/u;
function exact(value: unknown, required: readonly string[], optional: readonly string[] = []): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return required.every((key) => keys.includes(key)) && keys.every((key) => required.includes(key) || optional.includes(key));
}
function safeTime(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) >= 0; }
// Mirror authority.ts validRelease/validKeyId (module-private there); tests pin the boundaries.
const releaseIdPattern = /^[A-Za-z0-9_.:-]{1,128}$/u;
const releaseKeyIdPattern = /^[A-Za-z0-9_-]{1,64}$/u;
type ReleaseRow = { release_id: string; key_id: string; activated_ms: number; retired_ms: number | null };
/** Current authority release snapshot (not receipt history). Row shape/domain failures are `result-contract`;
 * states the authority cannot produce are `result-integrity`. Source-proven producer invariants only:
 * initializeAuthority inserts one unretired row; rotateAuthorityRelease deletes the retired row when two exist,
 * then retires the current row at previousRetiresAtMs > activatesAtMs and inserts the unretired next row at
 * activatesAtMs >= last_now_ms >= current.activated_ms. So an initialized snapshot has one or two rows, exactly
 * one unretired, unique release/key ids, retired_ms > activated_ms, and (when two) retired.retired_ms >
 * unretired.activated_ms >= retired.activated_ms. The query is ORDER BY activated_ms only: ties have no defined order. */
function releaseSnapshot(initialized: boolean, releases: unknown[]): void {
  const rows: ReleaseRow[] = [];
  for (const row of releases) {
    if (!exact(row, ["release_id", "key_id", "activated_ms", "retired_ms"]) || typeof row.release_id !== "string" ||
        !releaseIdPattern.test(row.release_id) || typeof row.key_id !== "string" || !releaseKeyIdPattern.test(row.key_id) ||
        !safeTime(row.activated_ms) || (row.retired_ms !== null && !safeTime(row.retired_ms))) throw new Error("result-contract");
    rows.push(row as ReleaseRow);
  }
  const unretired = rows.filter((row) => row.retired_ms === null);
  const retired = rows.filter((row) => row.retired_ms !== null);
  if ((initialized ? rows.length < 1 || rows.length > 2 || unretired.length !== 1 : rows.length > 0) ||
      new Set(rows.map((row) => row.release_id)).size !== rows.length || new Set(rows.map((row) => row.key_id)).size !== rows.length ||
      retired.some((row) => row.retired_ms! <= row.activated_ms) ||
      rows.some((row, index) => index > 0 && row.activated_ms < rows[index - 1].activated_ms) ||
      retired.length === 1 && (retired[0].retired_ms! <= unretired[0].activated_ms || unretired[0].activated_ms < retired[0].activated_ms))
    throw new Error("result-integrity");
}
const lifecycleOperations: readonly LifecycleOperation[] = ["initialize", "rotate-release"];
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
 * Runtime-frozen; it is the same array the Production verifier above uses. */
export const commandDerivedReceiptFields: readonly (keyof CommandDerivedReceipt)[] = commandDerivedFields;
function receipt(value: unknown, digest: string, expectedEnvironment: "production" | "staging", expectedAuthorityId: string,
  expectedKeyFingerprint: string | undefined, expectedOperation: LifecycleOperation | undefined,
  expectedReceipt: Readonly<LifecycleReceipt> | undefined, command?: Readonly<CommandDerivedReceipt>): value is Record<string, unknown> {
  if (!exact(value, receiptFields)) return false;
  return (expectedReceipt === undefined || receiptFields.every((field) => value[field] === expectedReceipt[field])) &&
    (command === undefined || commandDerivedFields.every((field) => value[field] === command[field])) &&
    value.digest === digest && value.version === 1 && lifecycleOperations.includes(value.operation as LifecycleOperation) &&
    (expectedOperation === undefined || value.operation === expectedOperation) && value.environment === expectedEnvironment &&
    value.authorityId === expectedAuthorityId && value.policyEpoch === "phase5c-i1-epoch-1" &&
    typeof value.keyFingerprint === "string" && digestPattern.test(value.keyFingerprint) &&
    (expectedKeyFingerprint === undefined || value.keyFingerprint === expectedKeyFingerprint) &&
    Number.isSafeInteger(value.sequence) && (value.sequence as number) >= 1 && (value.sequence as number) <= 4_096 &&
    safeTime(value.appliedMs) && safeTime(value.activatesMs) && (value.retiresMs === null || safeTime(value.retiresMs)) &&
    [value.currentReleaseId, value.nextReleaseId, value.nextKeyId].every((field) => typeof field === "string" && field.length <= 128);
}

/** Result objects are untrusted transport data until target, nonce, schema and receipt match.
 * `expectedEnvironment`/`expectedAuthorityId` default to Production so every existing
 * (Production) call site is byte-for-byte unchanged; a staging caller passes the
 * distinct staging identity explicitly. `expectedKeyFingerprint`, when supplied,
 * pins every present receipt to that exact full operator public-key fingerprint;
 * omitted (every Production caller), any well-formed fingerprint is accepted as
 * before. Results that legitimately carry no receipt are unaffected.
 * `expectedOperation`, when supplied, requires every present receipt to carry that exact
 * operation; omitted, either lifecycle operation is accepted as before. A reconciliation
 * EXACT_RECEIPT must additionally report `initialized: true` and `coverage: "COMPLETE"`,
 * the only state the authority produces for an exact receipt.
 * `expectedReceipt`, when supplied, must itself be a complete, well-formed receipt for the
 * expected environment/authority (and key fingerprint/operation, when those are supplied), and
 * every present result receipt must equal it in ALL fourteen fields (fieldwise `===`, no partial
 * expectation). It never requires a receipt to exist: receipt-less results are unaffected. It is a
 * caller-intent/state binding, not writer authentication. Omitted (every Production caller),
 * behavior is unchanged. */
export function verifyLifecycleResult(bytes: Uint8Array, kind: ResultKind, expected: { digest?: string; nonce?: string }, nowMs = Date.now(),
  expectedEnvironment: "production" | "staging" = "production",
  expectedAuthorityId: string = "production-public-inquiries-v1",
  expectedKeyFingerprint?: string, expectedOperation?: LifecycleOperation, expectedReceipt?: Readonly<LifecycleReceipt>) {
  return verifyResult(bytes, kind, expected, nowMs, expectedEnvironment, expectedAuthorityId, expectedKeyFingerprint, expectedOperation, expectedReceipt,
    undefined, false);
}

/** Production result verification. A positive result (lifecycle SUCCESS/ALREADY_APPLIED or reconciliation EXACT_RECEIPT)
 * is accepted only when an authenticated command context is supplied: the receipt must then equal that command in every
 * command-derived field (digest, operation, environment, authority, epoch, release/key ids, activation/retirement and the
 * operator-key fingerprint). `sequence` and `appliedMs` are assigned by the authority and are not command-bound. Without a
 * command a positive result is reported as UNCONFIRMED, never as success. Receipt-less diagnostics, including synthetic
 * never-signed digests, stay available and non-positive. The context must come from `authenticateSealedLifecycleArtifact`;
 * it is not a caller-supplied claim. Settlement is not command-authenticated and is unaffected. */
export function verifyProductionLifecycleResult(bytes: Uint8Array, kind: ResultKind, expected: { digest?: string; nonce?: string },
  options: { nowMs?: number; command?: Readonly<CommandDerivedReceipt> } = {}) {
  const command = options.command;
  return verifyResult(bytes, kind, expected, options.nowMs ?? Date.now(), "production", "production-public-inquiries-v1",
    command?.keyFingerprint, command?.operation, undefined, command, true);
}

function verifyResult(bytes: Uint8Array, kind: ResultKind, expected: { digest?: string; nonce?: string }, nowMs: number,
  expectedEnvironment: "production" | "staging", expectedAuthorityId: string, expectedKeyFingerprint: string | undefined,
  expectedOperation: LifecycleOperation | undefined, expectedReceipt: Readonly<LifecycleReceipt> | undefined,
  command: Readonly<CommandDerivedReceipt> | undefined, requireCommand: boolean) {
  if (command !== undefined && (!exact(command, commandDerivedFields) || expected.digest !== command.digest ||
      !receipt({ ...command, sequence: 1, appliedMs: 0 }, command.digest, expectedEnvironment, expectedAuthorityId, expectedKeyFingerprint, expectedOperation, undefined)))
    throw new Error("result-contract");
  if (expectedKeyFingerprint !== undefined && !digestPattern.test(expectedKeyFingerprint)) throw new Error("result-contract");
  if (expectedOperation !== undefined && !lifecycleOperations.includes(expectedOperation)) throw new Error("result-contract");
  const expectedReceiptDigest: unknown = expectedReceipt?.digest;
  if (expectedReceipt !== undefined && (typeof expectedReceiptDigest !== "string" || !digestPattern.test(expectedReceiptDigest) ||
      !receipt(expectedReceipt, expectedReceiptDigest, expectedEnvironment, expectedAuthorityId, expectedKeyFingerprint, expectedOperation, undefined)))
    throw new Error("result-contract");
  if (!bytes.length || bytes.byteLength > 8_192) throw new Error("result-size");
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("result-bom");
  const value = parseStrictJson(source) as Record<string, unknown>;
  const base = ["version", "digest", "environment", "authorityId", "policyEpoch", "observedAtMs"];
  const unavailableReconciliation = kind === "reconciliation" && value?.status === UNAVAILABLE_AUTHORITY_OBSERVATION.status;
  const shape = kind === "lifecycle" ? exact(value, [...base, "status"], ["reason", "receipt"]) :
    kind === "reconciliation" ? unavailableReconciliation ? exact(value, [...base, "nonce", "status"]) :
      exact(value, [...base, "nonce", "status", "initialized", "coverage", "receipt", "releases"]) :
    exact(value, [...base, "nonce", "settled"]);
  if (!shape || value.version !== 1 || value.environment !== expectedEnvironment || value.authorityId !== expectedAuthorityId ||
      value.policyEpoch !== "phase5c-i1-epoch-1" || typeof value.digest !== "string" || !digestPattern.test(value.digest) ||
      expected.digest !== undefined && value.digest !== expected.digest || kind !== "lifecycle" &&
      (typeof value.nonce !== "string" || !noncePattern.test(value.nonce) || value.nonce !== expected.nonce) ||
      !safeTime(value.observedAtMs) || value.observedAtMs > nowMs + 60_000 || nowMs - value.observedAtMs > 5 * 60_000)
    throw new Error("result-contract");
  if (kind === "settlement") {
    if (typeof value.settled !== "boolean") throw new Error("result-contract");
    return { status: value.settled ? "SETTLED" : "UNCONFIRMED", digest: value.digest, nonce: value.nonce } as const;
  }
  if (kind === "reconciliation") {
    if (unavailableReconciliation) {
      if (value.status !== "UNAVAILABLE") throw new Error("result-contract");
      return { status: "UNCONFIRMED", digest: value.digest, observation: "UNAVAILABLE" } as const;
    }
    if (!["EXACT_RECEIPT", "NOT_FOUND", "HISTORY_INCOMPLETE"].includes(String(value.status)) ||
        typeof value.initialized !== "boolean" || !["COMPLETE", "INCOMPLETE"].includes(String(value.coverage)) ||
        !Array.isArray(value.releases) || value.releases.length > 3) throw new Error("result-contract");
  } else if (!["SUCCESS", "ALREADY_APPLIED", "REFUSED", "UNAVAILABLE", "UNCONFIRMED"].includes(String(value.status)) ||
      value.reason !== undefined && (typeof value.reason !== "string" || value.reason.length > 64)) throw new Error("result-contract");
  if (value.receipt !== undefined && value.receipt !== null && !receipt(value.receipt, value.digest, expectedEnvironment, expectedAuthorityId, expectedKeyFingerprint, expectedOperation, expectedReceipt, command)) throw new Error("result-contract");
  if (kind === "reconciliation" && value.status === "EXACT_RECEIPT" && (value.initialized !== true || value.coverage !== "COMPLETE"))
    throw new Error("result-integrity");
  if (kind === "reconciliation" && (value.status === "EXACT_RECEIPT") !== (value.receipt !== null) ||
      kind === "lifecycle" && ["SUCCESS", "ALREADY_APPLIED"].includes(String(value.status)) && !value.receipt)
    throw new Error("result-integrity");
  if (kind === "reconciliation") releaseSnapshot(value.initialized as boolean, value.releases as unknown[]);
  if (value.receipt && (kind === "reconciliation" && value.status === "EXACT_RECEIPT" ||
      kind === "lifecycle" && (value.status === "SUCCESS" || value.status === "ALREADY_APPLIED"))) {
    // The only positive return. Production callers cannot reach it without an authenticated command context.
    if (requireCommand && command === undefined) return { status: "UNCONFIRMED", digest: value.digest, observation: "COMMAND_CONTEXT_REQUIRED" } as const;
    return { status: kind === "lifecycle" && value.status === "ALREADY_APPLIED" ? "ALREADY_APPLIED" : "SUCCESS",
      digest: value.digest, receipt: value.receipt } as const;
  }
  return { status: "UNCONFIRMED", digest: value.digest, observation: value.status } as const;
}
