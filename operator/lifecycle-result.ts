import { parseStrictJson } from "./lifecycle-submitter";
import { UNAVAILABLE_AUTHORITY_OBSERVATION } from "./lifecycle-observation";

export type ResultKind = "lifecycle" | "reconciliation" | "settlement";
const digestPattern = /^[a-f0-9]{64}$/u;
const noncePattern = /^[a-f0-9]{32}$/u;
function exact(value: unknown, required: readonly string[], optional: readonly string[] = []): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return required.every((key) => keys.includes(key)) && keys.every((key) => required.includes(key) || optional.includes(key));
}
function safeTime(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) >= 0; }
function receipt(value: unknown, digest: string, expectedEnvironment: "production" | "staging", expectedAuthorityId: string,
  expectedKeyFingerprint: string | undefined): value is Record<string, unknown> {
  if (!exact(value, ["digest", "version", "operation", "environment", "authorityId", "policyEpoch", "keyFingerprint", "sequence", "appliedMs",
    "currentReleaseId", "nextReleaseId", "nextKeyId", "activatesMs", "retiresMs"])) return false;
  return value.digest === digest && value.version === 1 && ["initialize", "rotate-release"].includes(String(value.operation)) && value.environment === expectedEnvironment &&
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
 * before. Results that legitimately carry no receipt are unaffected. */
export function verifyLifecycleResult(bytes: Uint8Array, kind: ResultKind, expected: { digest?: string; nonce?: string }, nowMs = Date.now(),
  expectedEnvironment: "production" | "staging" = "production",
  expectedAuthorityId: string = "production-public-inquiries-v1",
  expectedKeyFingerprint?: string) {
  if (expectedKeyFingerprint !== undefined && !digestPattern.test(expectedKeyFingerprint)) throw new Error("result-contract");
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
  if (value.receipt !== undefined && value.receipt !== null && !receipt(value.receipt, value.digest, expectedEnvironment, expectedAuthorityId, expectedKeyFingerprint)) throw new Error("result-contract");
  if (kind === "reconciliation" && (value.status === "EXACT_RECEIPT") !== (value.receipt !== null) ||
      kind === "lifecycle" && ["SUCCESS", "ALREADY_APPLIED"].includes(String(value.status)) && !value.receipt)
    throw new Error("result-integrity");
  if (value.receipt && (kind === "reconciliation" && value.status === "EXACT_RECEIPT" ||
      kind === "lifecycle" && (value.status === "SUCCESS" || value.status === "ALREADY_APPLIED")))
    return { status: kind === "lifecycle" && value.status === "ALREADY_APPLIED" ? "ALREADY_APPLIED" : "SUCCESS",
      digest: value.digest, receipt: value.receipt } as const;
  return { status: "UNCONFIRMED", digest: value.digest, observation: value.status } as const;
}
